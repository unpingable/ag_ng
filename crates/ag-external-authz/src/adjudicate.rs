//! Engine driving and decision mapping for one external authorization
//! occurrence.
//!
//! Per request, in order: strict-validate, fail-closed standing-store
//! pre-check, replay guard, derive AG identities, build the single-entry v2
//! catalog under adapter custody, then drive [`CampaignEngineV1`]:
//!
//! ```text
//! CampaignEngineV1::create(store, campaign, occurrence, program,
//!                          expected_work, ResidualSetV1::default(), budget, now)
//!   -> record_proposal(observation_ref, proposal, Initial, observation, obs_resolver, now)
//!   -> require_standing(now)
//!   -> decide_versioned(observation, standing, ExactBasisV2(catalog), None,
//!                       obs_resolver, standing_resolver, max_standing_ttl, now)
//!   -> authorize_versioned(same arguments)
//! ```
//!
//! # Decision mapping (AG condition -> wire decision/code)
//!
//! | AG condition                                   | wire decision   | wire code                          |
//! |------------------------------------------------|-----------------|------------------------------------|
//! | spend committed (`AuthorizationConsumed`)      | `authorized`    | —                                  |
//! | occurrence store path already exists           | `refused`       | `occurrence_already_adjudicated`   |
//! | `KernelErrorV1::StandingAbsent`                | `refused`       | `absent_standing`                  |
//! | `KernelErrorV1::StandingNotCurrent`            | `refused`       | `standing_not_current`             |
//! | `KernelErrorV1::Inadmissible`                  | `refused`       | `inadmissible_exact_work`          |
//! | `KernelErrorV1::ObservationNotCurrent`         | `refused`       | `admissibility_not_current`        |
//! | `KernelErrorV1::ObservationContradiction`      | `refused`       | `contradiction`                    |
//! | `KernelErrorV1::BudgetExhausted`               | `refused`       | `budget_exhausted` (reserved)      |
//! | `ExternalBoundaryErrorV1::Refused`             | `refused`       | `external_boundary_refused` (reserved) |
//! | `ExternalBoundaryErrorV1::Unavailable`         | `indeterminate` | kinds `["external_boundary_unavailable"]` |
//! | store/canonical/unexpected kernel errors       | error response  | `infrastructure` (not a decision)  |
//!
//! Reachability with the shipped in-process fixtures: `authorized`,
//! `absent_standing`, `standing_not_current` (revoked/expired), and
//! `occurrence_already_adjudicated` are reachable. `inadmissible_exact_work`
//! is structurally unreachable (the catalog entry is derived from the same
//! validated request the proposal is built from, and the expected-work
//! digest is the same digest the proposal carries). `contradiction`,
//! `budget_exhausted`, `external_boundary_refused`, and `indeterminate` are
//! mapped but reserved. `admissibility_not_current` is reachable:
//! admissibility is current
//! only while `evaluation_time <= now < evaluation_time + configured maximum
//! age`. The budget has zero retry/probe/escalation limits that the daemon
//! never spends.

#![allow(
    clippy::large_enum_variant,
    reason = "the adjudication outcome returns the complete wire response by value"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ag_app::governed_loop::{
    CampaignEngineErrorV1, CampaignEngineV1, EXACT_WORK_CATALOG_SCHEMA_V2,
    ExactObservationBasisRequirementV1, ExactWorkCatalogEntryV2, ExactWorkCatalogV2,
    VersionedExactWorkCatalogV1,
};
use ag_app::standing_authority::StandingResolverConfigV1;
use ag_campaign::CampaignId;
use ag_campaign::governed::{
    ExactWorkProposalV1, ExternalBoundaryErrorV1, KernelErrorV1, LoopBudgetV1,
    OBSERVATION_RESOLUTION_SCHEMA_V3, ObservationCurrentnessRefV1, ObservationRefV1,
    ObservationResolutionRequestV1, ObservationResolutionV3, ObservationResolverV1, OccurrenceId,
    OccurrenceKeyV1, OccurrenceSnapshotV1, PreconditionBasisRefV1, ProgramBasisRefV1,
    ProposalClassV1, RefusalCodeV1, ResidualSetV1, TypedObservationStatusV1,
    TypedOpaqueObservationBasisV1, VersionedObservationResolutionV1,
};
use ag_primitives::{Digest, JcsDocument};
use ag_store::campaign::CampaignStoreErrorV1;
use serde::Serialize;
use uuid::Uuid;

use crate::custody::{persist_outcome, persist_request, sync_new_occurrence};
use crate::protocol::{
    ADMISSIBILITY_DECISION_CONTINUE, AuthorizationOutcomeV1, ERROR_SCHEMA_V1, ErrorKindV1,
    ExternalAuthorizationErrorV1, ExternalAuthorizationRequestV1, ExternalAuthorizationResponseV1,
    ExternalDecisionV1, IndeterminateDetailV1, REQUEST_SCHEMA_V1, RESPONSE_SCHEMA_V1,
    RefusalDetailV1, bounded_reason,
};
use crate::standing::{StandingStoreResolverV1, load_standing_store};

/// The opaque observation-basis type pinning the declarative-admissibility
/// receipt. AG never interprets it; the v2 catalog requires the exact
/// `(type, identity)` envelope.
pub const OBSERVATION_BASIS_TYPE_V1: &str = "codex.declarative-admissibility-result/v1";

const WORK_DIGEST_DOMAIN_V1: &str = "ag.external-authorization.work/v1";
const CAMPAIGN_DIGEST_DOMAIN_V1: &str = "ag.external-authorization.campaign/v1";
const PROGRAM_DIGEST_DOMAIN_V1: &str = "ag.external-authorization.program/v1";
const PROGRAM_BASIS_PAYLOAD_V1: &[u8] = b"codex-external-actions/v1";
const OBSERVATION_DIGEST_DOMAIN_V1: &str = "ag.external-authorization.observation/v1";
const OBSERVATION_CURRENTNESS_DOMAIN_V1: &str =
    "ag.external-authorization.observation-currentness/v1";

/// Durable budget: the daemon performs no retries, probes, or escalations,
/// so every limit is zero and `budget_exhausted` stays unreachable.
const LOOP_BUDGET_V1: LoopBudgetV1 = LoopBudgetV1 {
    retry_limit: 0,
    retries_used: 0,
    probe_limit: 0,
    probes_used: 0,
    escalation_limit: 0,
    escalations_used: 0,
};

/// Daemon configuration spanning adjudication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfigV1 {
    /// Daemon state directory; per-occurrence campaign stores live at
    /// `<state-dir>/<occurrence-id>/campaign.sqlite`.
    pub state_dir: PathBuf,
    /// Root-owned standing mandate store file.
    pub standing_store: PathBuf,
    /// Exact identity the observation fixture answers with and the engine
    /// is configured to expect.
    pub observation_resolver_id: String,
    /// Exact identity the standing fixture answers with and the engine is
    /// configured to expect.
    pub standing_resolver_id: String,
    /// Maximum standing-answer lifetime the kernel accepts.
    pub max_standing_ttl_ms: u64,
    /// Maximum age of a declarative-admissibility receipt. The exclusive
    /// deadline is `evaluation_time + max_admissibility_age_ms`.
    pub max_admissibility_age_ms: u64,
    /// The standing authority's own answer lease; also the observation
    /// fixture's freshness window.
    pub answer_ttl_ms: u64,
}

impl DaemonConfigV1 {
    /// Configuration validity: explicit resolver identities and a standing
    /// answer lease that never exceeds the kernel's accepted maximum.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason for any invalid field combination.
    pub fn validate(&self) -> Result<(), String> {
        if self.observation_resolver_id.trim().is_empty() {
            return Err("observation resolver id must be explicitly configured".to_owned());
        }
        if self.standing_resolver_id.trim().is_empty() {
            return Err("standing resolver id must be explicitly configured".to_owned());
        }
        if self.answer_ttl_ms == 0 {
            return Err("answer_ttl_ms must be positive".to_owned());
        }
        if self.max_admissibility_age_ms == 0 {
            return Err("max_admissibility_age_ms must be positive".to_owned());
        }
        if self.answer_ttl_ms > self.max_standing_ttl_ms {
            return Err("answer_ttl_ms must not exceed max_standing_ttl_ms".to_owned());
        }
        Ok(())
    }
}

/// The outcome of handling one request: either a real AG decision response
/// or a non-decision error response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdjudicationOutcomeV1 {
    /// A real AG decision (`authorized`, `refused`, or `indeterminate`).
    Decision(ExternalAuthorizationResponseV1),
    /// Not a decision: invalid input or daemon-internal failure.
    Rejected(ExternalAuthorizationErrorV1),
}

/// In-process observation boundary for the exact typed opaque basis derived
/// from the request's admissibility receipt. It never refreshes the receipt:
/// currentness is bounded by the original evaluation time and the configured
/// exclusive expiry.
struct DeclarativeAdmissibilityObservationV1 {
    basis: TypedOpaqueObservationBasisV1,
    resolver_id: String,
    freshness_window_ms: u64,
    evaluated_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

/// Exact content whose digest witnesses one observation-currentness answer.
#[derive(Serialize)]
struct CurrentnessBasisV1<'a> {
    key: &'a OccurrenceKeyV1,
    observation: &'a ObservationRefV1,
    basis: &'a TypedOpaqueObservationBasisV1,
    resolver_id: &'a str,
    resolved_at_unix_ms: u64,
    fresh_until_unix_ms: u64,
}

impl ObservationResolverV1 for DeclarativeAdmissibilityObservationV1 {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        let resolved_at = request.now_unix_ms;
        let fresh_until = resolved_at
            .saturating_add(self.freshness_window_ms)
            .min(self.expires_at_unix_ms);
        let status =
            if self.evaluated_at_unix_ms <= resolved_at && resolved_at < self.expires_at_unix_ms {
                TypedObservationStatusV1::Current
            } else {
                TypedObservationStatusV1::Stale
            };
        let binding =
            self.basis
                .binding_digest()
                .map_err(|error| ExternalBoundaryErrorV1::Unavailable {
                    code: bounded_reason(format!("observation-basis:{error}")),
                })?;
        let currentness_basis = CurrentnessBasisV1 {
            key: request.key,
            observation: request.observation,
            basis: &self.basis,
            resolver_id: &self.resolver_id,
            resolved_at_unix_ms: resolved_at,
            fresh_until_unix_ms: fresh_until,
        };
        let currentness_bytes = JcsDocument::canonicalize(&currentness_basis).map_err(|error| {
            ExternalBoundaryErrorV1::Unavailable {
                code: bounded_reason(format!("observation-currentness:{error}")),
            }
        })?;
        Ok(ObservationResolutionV3 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V3.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(Digest::hash_domain(
                OBSERVATION_CURRENTNESS_DOMAIN_V1,
                currentness_bytes.as_bytes(),
            )),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(binding),
            basis: self.basis.clone(),
            resolver_id: self.resolver_id.clone(),
            subject: request.subject.clone(),
            status,
            resolved_at_unix_ms: resolved_at,
            fresh_until_unix_ms: fresh_until,
        }
        .into())
    }
}

/// All AG identities derived from one validated request.
struct DerivedBasisV1 {
    campaign: CampaignId,
    occurrence: OccurrenceId,
    program: ProgramBasisRefV1,
    work: Digest,
    observation: ObservationRefV1,
    basis: TypedOpaqueObservationBasisV1,
    catalog: ExactWorkCatalogV2,
}

fn reject(
    kind: ErrorKindV1,
    request_id: Option<String>,
    reason: impl Into<String>,
) -> AdjudicationOutcomeV1 {
    AdjudicationOutcomeV1::Rejected(ExternalAuthorizationErrorV1 {
        schema: ERROR_SCHEMA_V1.to_owned(),
        request_id,
        kind,
        reason: bounded_reason(reason),
    })
}

fn invalid_request(
    request: &ExternalAuthorizationRequestV1,
    reason: String,
) -> AdjudicationOutcomeV1 {
    reject(
        ErrorKindV1::InvalidRequest,
        Some(request.request_id.clone()),
        reason,
    )
}

fn persist_decision(
    occurrence_dir: &std::path::Path,
    request: &ExternalAuthorizationRequestV1,
    outcome: AdjudicationOutcomeV1,
) -> AdjudicationOutcomeV1 {
    let AdjudicationOutcomeV1::Decision(response) = &outcome else {
        return outcome;
    };
    if let Err(reason) = persist_outcome(occurrence_dir, response) {
        return reject(
            ErrorKindV1::Infrastructure,
            Some(request.request_id.clone()),
            format!("failed to persist authorization outcome: {reason}"),
        );
    }
    outcome
}

/// Strict semantic validation beyond the decoded wire shape. Every failure
/// here is invalid input — never a refusal, and no adjudication state is
/// created.
fn validate_request(request: &ExternalAuthorizationRequestV1) -> Result<(), String> {
    if request.schema != REQUEST_SCHEMA_V1 {
        return Err(format!("unsupported request schema {}", request.schema));
    }
    if Uuid::parse_str(&request.request_id).is_err() {
        return Err("request_id must be a UUID".to_owned());
    }
    if Uuid::parse_str(&request.occurrence.authorization_occurrence_id).is_err() {
        return Err("authorization_occurrence_id must be a UUID".to_owned());
    }
    if request.action.canonical_json.is_empty() {
        return Err("action.canonical_json must be nonempty".to_owned());
    }
    if Digest::hash_bytes(request.action.canonical_json.as_bytes()) != request.action.action_digest
    {
        return Err("action_digest does not match sha256(action.canonical_json)".to_owned());
    }
    if request.admissibility.decision != ADMISSIBILITY_DECISION_CONTINUE {
        return Err(format!(
            "admissibility.decision must be exactly `{ADMISSIBILITY_DECISION_CONTINUE}`"
        ));
    }
    if request.action.work_schema != request.occurrence.stage.work_schema() {
        return Err(format!(
            "work_schema {} is inconsistent with stage {:?}",
            request.action.work_schema, request.occurrence.stage
        ));
    }
    Ok(())
}

/// Derives every AG identity from the validated request. The catalog entry
/// registers the exact occurrence class for this adjudication only; it is
/// adapter custody and cannot widen authority.
fn derive_basis(request: &ExternalAuthorizationRequestV1) -> DerivedBasisV1 {
    let work = Digest::hash_domain(
        WORK_DIGEST_DOMAIN_V1,
        request.action.canonical_json.as_bytes(),
    );
    let basis = TypedOpaqueObservationBasisV1::new(
        OBSERVATION_BASIS_TYPE_V1.to_owned(),
        request.admissibility.receipt_digest.clone(),
    )
    .expect("the closed basis type is a valid label");
    let occurrence_uuid = Uuid::parse_str(&request.occurrence.authorization_occurrence_id)
        .expect("the occurrence id was validated as a UUID");
    let campaign = CampaignId::from_digest(Digest::hash_domain(
        CAMPAIGN_DIGEST_DOMAIN_V1,
        occurrence_uuid.hyphenated().to_string().as_bytes(),
    ));
    let catalog = ExactWorkCatalogV2 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V2.to_owned(),
        entries: BTreeMap::from([(
            request.action.work_schema.clone(),
            ExactWorkCatalogEntryV2 {
                work_schema: request.action.work_schema.clone(),
                subject: request.subject_digest.clone(),
                scope: request.scope_digest.clone(),
                observation_basis: ExactObservationBasisRequirementV1::TypedBasis(basis.clone()),
            },
        )]),
    };
    DerivedBasisV1 {
        campaign,
        occurrence: OccurrenceId::from_uuid(occurrence_uuid),
        program: ProgramBasisRefV1::from_digest(Digest::hash_domain(
            PROGRAM_DIGEST_DOMAIN_V1,
            PROGRAM_BASIS_PAYLOAD_V1,
        )),
        work,
        observation: ObservationRefV1::from_digest(Digest::hash_domain(
            OBSERVATION_DIGEST_DOMAIN_V1,
            request.admissibility.receipt_digest.as_str().as_bytes(),
        )),
        basis,
        catalog,
    }
}

fn response_skeleton(
    request: &ExternalAuthorizationRequestV1,
    decision: ExternalDecisionV1,
    now_unix_ms: u64,
) -> ExternalAuthorizationResponseV1 {
    ExternalAuthorizationResponseV1 {
        schema: RESPONSE_SCHEMA_V1.to_owned(),
        request_id: request.request_id.clone(),
        occurrence_id: request.occurrence.authorization_occurrence_id.clone(),
        action_digest: request.action.action_digest.as_str().to_owned(),
        admissibility_receipt_digest: request.admissibility.receipt_digest.as_str().to_owned(),
        decision,
        evaluated_at_unix_ms: now_unix_ms,
        authorization: None,
        refusal: None,
        failure: None,
    }
}

fn refused(
    request: &ExternalAuthorizationRequestV1,
    now_unix_ms: u64,
    code: &str,
    reason: impl Into<String>,
) -> AdjudicationOutcomeV1 {
    let mut response = response_skeleton(request, ExternalDecisionV1::Refused, now_unix_ms);
    response.refusal = Some(RefusalDetailV1 {
        code: code.to_owned(),
        reason: bounded_reason(reason),
    });
    AdjudicationOutcomeV1::Decision(response)
}

/// How one kernel refusal maps onto the wire.
enum KernelMappingV1 {
    /// A semantic refusal; carries the durable refusal code to record when
    /// one exists in AG's vocabulary.
    Refused(&'static str, Option<RefusalCodeV1>),
    /// A genuinely unresolved operational state.
    Indeterminate(Vec<String>),
    /// Not a decision: an unexpected kernel condition is a daemon bug.
    Infrastructure,
}

fn map_kernel_error(error: &KernelErrorV1) -> KernelMappingV1 {
    match error {
        KernelErrorV1::StandingAbsent => {
            KernelMappingV1::Refused("absent_standing", Some(RefusalCodeV1::AbsentStanding))
        }
        KernelErrorV1::StandingNotCurrent => KernelMappingV1::Refused(
            "standing_not_current",
            Some(RefusalCodeV1::StandingNotCurrent),
        ),
        KernelErrorV1::Inadmissible => KernelMappingV1::Refused(
            "inadmissible_exact_work",
            Some(RefusalCodeV1::InadmissibleExactWork),
        ),
        KernelErrorV1::ObservationNotCurrent => KernelMappingV1::Refused(
            "admissibility_not_current",
            Some(RefusalCodeV1::StaleObservation),
        ),
        KernelErrorV1::ObservationContradiction => {
            KernelMappingV1::Refused("contradiction", Some(RefusalCodeV1::Contradiction))
        }
        KernelErrorV1::BudgetExhausted(_) => {
            KernelMappingV1::Refused("budget_exhausted", Some(RefusalCodeV1::BudgetExhausted))
        }
        KernelErrorV1::External(ExternalBoundaryErrorV1::Unavailable { .. }) => {
            KernelMappingV1::Indeterminate(vec!["external_boundary_unavailable".to_owned()])
        }
        KernelErrorV1::External(ExternalBoundaryErrorV1::Refused { .. }) => {
            KernelMappingV1::Refused("external_boundary_refused", None)
        }
        _ => KernelMappingV1::Infrastructure,
    }
}

/// Maps an engine failure to a wire outcome, recording a durable
/// non-authorizing refusal fact when AG's vocabulary has one.
fn map_engine_error(
    engine: &mut CampaignEngineV1,
    request: &ExternalAuthorizationRequestV1,
    error: CampaignEngineErrorV1,
    now_unix_ms: u64,
) -> AdjudicationOutcomeV1 {
    let reason = bounded_reason(error.to_string());
    let CampaignEngineErrorV1::Kernel(kernel) = error else {
        return reject(
            ErrorKindV1::Infrastructure,
            Some(request.request_id.clone()),
            format!("campaign engine failed internally: {reason}"),
        );
    };
    match map_kernel_error(&kernel) {
        KernelMappingV1::Refused(code, refusal_code) => {
            if let Some(refusal_code) = refusal_code
                && let Err(error) = engine.record_refusal(refusal_code, None, now_unix_ms)
            {
                return reject(
                    ErrorKindV1::Infrastructure,
                    Some(request.request_id.clone()),
                    format!("failed to durably record refusal: {error}"),
                );
            }
            refused(request, now_unix_ms, code, reason)
        }
        KernelMappingV1::Indeterminate(kinds) => {
            let mut response =
                response_skeleton(request, ExternalDecisionV1::Indeterminate, now_unix_ms);
            response.failure = Some(IndeterminateDetailV1 { kinds, reason });
            AdjudicationOutcomeV1::Decision(response)
        }
        KernelMappingV1::Infrastructure => reject(
            ErrorKindV1::Infrastructure,
            Some(request.request_id.clone()),
            format!("unexpected kernel condition: {reason}"),
        ),
    }
}

/// Drives the exact engine sequence for one adjudication.
fn drive(
    engine: &mut CampaignEngineV1,
    config: &DaemonConfigV1,
    derived: &DerivedBasisV1,
    request: &ExternalAuthorizationRequestV1,
    now_unix_ms: u64,
) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
    let proposal = ExactWorkProposalV1::new(
        derived.campaign.clone(),
        request.subject_digest.clone(),
        request.scope_digest.clone(),
        request.action.work_schema.clone(),
        derived.work.clone(),
        None,
    )?;
    let mut observation = DeclarativeAdmissibilityObservationV1 {
        basis: derived.basis.clone(),
        resolver_id: config.observation_resolver_id.clone(),
        freshness_window_ms: config.answer_ttl_ms,
        evaluated_at_unix_ms: request.admissibility.evaluation_time_unix_ms,
        expires_at_unix_ms: request
            .admissibility
            .evaluation_time_unix_ms
            .saturating_add(config.max_admissibility_age_ms),
    };
    let mut standing = StandingStoreResolverV1::new(
        config.standing_store.clone(),
        StandingResolverConfigV1 {
            resolver_id: config.standing_resolver_id.clone(),
            answer_ttl_ms: config.answer_ttl_ms,
        },
    );
    let catalog = VersionedExactWorkCatalogV1::ExactBasisV2(derived.catalog.clone());
    engine.record_proposal(
        derived.observation.clone(),
        proposal,
        ProposalClassV1::Initial,
        &mut observation,
        &config.observation_resolver_id,
        now_unix_ms,
    )?;
    engine.require_standing(now_unix_ms)?;
    engine.decide_versioned(
        &mut observation,
        &mut standing,
        &catalog,
        None,
        &config.observation_resolver_id,
        &config.standing_resolver_id,
        config.max_standing_ttl_ms,
        now_unix_ms,
    )?;
    engine.authorize_versioned(
        &mut observation,
        &mut standing,
        &catalog,
        None,
        &config.observation_resolver_id,
        &config.standing_resolver_id,
        config.max_standing_ttl_ms,
        now_unix_ms,
    )
}

/// Adjudicates one exact external authorization occurrence.
///
/// Invalid input and daemon-internal failures return
/// [`AdjudicationOutcomeV1::Rejected`] and create no adjudication state;
/// every [`AdjudicationOutcomeV1::Decision`] is backed by a durable
/// per-occurrence campaign store.
#[must_use]
pub fn adjudicate(
    config: &DaemonConfigV1,
    request: &ExternalAuthorizationRequestV1,
    now_unix_ms: u64,
) -> AdjudicationOutcomeV1 {
    if let Err(reason) = validate_request(request) {
        return invalid_request(request, reason);
    }
    // Fail-closed pre-check: an unreadable or malformed standing store is a
    // daemon-internal failure surfaced before any adjudication state exists.
    if let Err(reason) = load_standing_store(&config.standing_store) {
        return reject(
            ErrorKindV1::Infrastructure,
            Some(request.request_id.clone()),
            reason,
        );
    }
    let derived = derive_basis(request);
    // Replay guard: each occurrence id is adjudicated at most once. The
    // per-occurrence directory is created atomically; `CampaignStoreV1`
    // additionally refuses an existing database with `create_new(true)`.
    let occurrence_dir = config
        .state_dir
        .join(derived.occurrence.as_uuid().hyphenated().to_string());
    match std::fs::create_dir(&occurrence_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return refused(
                request,
                now_unix_ms,
                "occurrence_already_adjudicated",
                "this authorization occurrence id was already adjudicated by this daemon",
            );
        }
        Err(error) => {
            return reject(
                ErrorKindV1::Infrastructure,
                Some(request.request_id.clone()),
                format!("cannot create occurrence state directory: {error}"),
            );
        }
    }
    if let Err(reason) = sync_new_occurrence(&config.state_dir)
        .and_then(|()| persist_request(&occurrence_dir, request))
    {
        return reject(
            ErrorKindV1::Infrastructure,
            Some(request.request_id.clone()),
            format!("failed to establish request custody: {reason}"),
        );
    }
    let database = occurrence_dir.join("campaign.sqlite");
    let mut engine = match CampaignEngineV1::create(
        &database,
        derived.campaign.clone(),
        derived.occurrence,
        derived.program.clone(),
        derived.work.clone(),
        ResidualSetV1::default(),
        LOOP_BUDGET_V1,
        now_unix_ms,
    ) {
        Ok(engine) => engine,
        Err(CampaignEngineErrorV1::Store(CampaignStoreErrorV1::AlreadyExists(_))) => {
            return refused(
                request,
                now_unix_ms,
                "occurrence_already_adjudicated",
                "this authorization occurrence id was already adjudicated by this daemon",
            );
        }
        Err(error) => {
            return reject(
                ErrorKindV1::Infrastructure,
                Some(request.request_id.clone()),
                format!("campaign engine creation failed: {error}"),
            );
        }
    };
    let spent = match drive(&mut engine, config, &derived, request, now_unix_ms) {
        Ok(spent) => spent,
        Err(error) => {
            return persist_decision(
                &occurrence_dir,
                request,
                map_engine_error(&mut engine, request, error, now_unix_ms),
            );
        }
    };
    let (Some(issuance), Some(ag_spend), Some(standing)) = (
        spent.issuance(),
        spent.ag_spend(),
        spent.standing_resolution(),
    ) else {
        return reject(
            ErrorKindV1::Infrastructure,
            Some(request.request_id.clone()),
            "authorized snapshot lacks issuance, spend, or standing resolution",
        );
    };
    let mut response = response_skeleton(request, ExternalDecisionV1::Authorized, now_unix_ms);
    response.authorization = Some(AuthorizationOutcomeV1 {
        campaign_id: issuance.key.campaign.to_string(),
        ag_occurrence_id: issuance.key.occurrence.to_string(),
        authorization_ref: ag_spend.authorization.as_str().to_owned(),
        spend_ref: ag_spend.spend.as_str().to_owned(),
        issuance_ref: issuance.issuance.as_str().to_owned(),
        standing_resolution_ref: standing.resolution.as_str().to_owned(),
        mandate_ref: standing.mandate.as_str().to_owned(),
        standing_expires_at_unix_ms: standing.expires_at_unix_ms,
    });
    persist_decision(
        &occurrence_dir,
        request,
        AdjudicationOutcomeV1::Decision(response),
    )
}
