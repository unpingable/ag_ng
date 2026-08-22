#![allow(
    clippy::missing_errors_doc,
    reason = "CampaignEngineErrorV1 is the closed error contract for the production service"
)]
#![allow(
    clippy::wildcard_imports,
    reason = "this composition module intentionally consumes the governed kernel's complete vocabulary"
)]
#![allow(
    clippy::items_after_statements,
    reason = "small transcript-only record types stay adjacent to the decision that uses them"
)]
#![allow(
    clippy::large_enum_variant,
    reason = "recovery returns the exact authoritative snapshot by value"
)]
#![allow(
    clippy::needless_pass_by_value,
    reason = "human disposition inputs are accepted as owned one-use records"
)]

//! Production orchestration service for the canonical AG governed loop.
//!
//! The service composes the pure kernel, authoritative `SQLite` store, fresh
//! observation/standing/admission boundaries, and Docket's custody port.  It
//! never performs physical effect mechanics and never accepts executor output
//! as a campaign transition.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use ag_store::campaign::{
    CampaignCommitReceiptV1, CampaignRefusalHistoryV1, CampaignReplayReportV1,
    CampaignStoreErrorV1, CampaignStoreV1, CampaignTransitionHistoryV1, CampaignTransitionKindV1,
    StoredRuntimeProfileV1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Root-owned exact-work catalog schema.
pub const EXACT_WORK_CATALOG_SCHEMA_V1: &str = "ag.governed-loop.exact-work-catalog/v1";

/// Finite per-workflow precondition over `DecisionBasisV1` atoms.
///
/// The judgment is exactly `required ⊆ basis.atoms` and
/// `forbidden ∩ basis.atoms = ∅`. An omitted precondition is unconditional.
/// This is catalog policy, not evidence health: it is evaluated only over a
/// validated `Current` observation basis, never over the sentinel basis a
/// negative resolution carries for wire completeness.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPreconditionV1 {
    /// Atoms that must all be present in the evidence basis.
    #[serde(default)]
    pub required: BTreeSet<String>,
    /// Atoms that must all be absent from the evidence basis.
    #[serde(default)]
    pub forbidden: BTreeSet<String>,
}

impl WorkPreconditionV1 {
    /// Catalog-definition validity: no atom may be both required and
    /// forbidden, and only frozen v1 basis atoms may be named.
    fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if !self.required.is_disjoint(&self.forbidden) {
            return Err(CampaignEngineErrorV1::InvalidCatalog);
        }
        if self
            .required
            .union(&self.forbidden)
            .any(|atom| !DECISION_BASIS_ATOM_VOCABULARY_V1.contains(&atom.as_str()))
        {
            return Err(CampaignEngineErrorV1::InvalidCatalog);
        }
        Ok(())
    }

    /// The exact predicate over one validated observation basis.
    fn holds_over(&self, basis: &DecisionBasisV1) -> bool {
        self.required.is_subset(&basis.atoms) && self.forbidden.is_disjoint(&basis.atoms)
    }
}

/// One exact admissibility catalog entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWorkCatalogEntryV1 {
    /// Exact typed work schema.
    pub work_schema: String,
    /// Exact governed subject.
    pub subject: Digest,
    /// Exact governed scope.
    pub scope: Digest,
    /// Finite workflow precondition; absent means unconditional.
    #[serde(default)]
    pub precondition: WorkPreconditionV1,
}

/// Root-owned exact admissibility policy basis.
///
/// The catalog carries no asserted policy identity: its policy basis is
/// derived from the exact semantic content (schema and entries), so recorded
/// judgment provenance always identifies the catalog actually evaluated.
/// Callers have no API path to attach an unrelated policy identity, and a
/// stale wire document carrying one fails `deny_unknown_fields` parsing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWorkCatalogV1 {
    /// Exact schema.
    pub schema: String,
    /// Entries keyed by typed work schema.
    pub entries: BTreeMap<String, ExactWorkCatalogEntryV1>,
}

impl ExactWorkCatalogV1 {
    /// Validates exact key/entry agreement and nonempty policy.
    pub fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if self.schema != EXACT_WORK_CATALOG_SCHEMA_V1 || self.entries.is_empty() {
            return Err(CampaignEngineErrorV1::InvalidCatalog);
        }
        if self
            .entries
            .iter()
            .any(|(key, entry)| key != &entry.work_schema || key.is_empty())
        {
            return Err(CampaignEngineErrorV1::InvalidCatalog);
        }
        if self
            .entries
            .values()
            .any(|entry| entry.precondition.validate().is_err())
        {
            return Err(CampaignEngineErrorV1::InvalidCatalog);
        }
        Ok(())
    }

    /// The exact policy identity: canonical digest of the complete semantic
    /// catalog content. Every admission-relevant field (`work_schema`,
    /// `subject`, `scope`, and each entry's `precondition`) participates;
    /// the identity field itself does not exist inside its own preimage.
    /// Deterministic under construction order because entries and atom sets
    /// are ordered maps/sets canonicalized with JCS.
    pub fn policy_basis(&self) -> Result<Digest, CampaignEngineErrorV1> {
        self.validate()?;
        let bytes = JcsDocument::canonicalize(self)
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        Ok(Digest::hash_domain(
            "ag.governed-loop.exact-work-catalog/v1",
            bytes.as_bytes(),
        ))
    }
}

/// AG-owned exact catalog admission policy.
pub struct CatalogAdmissibilityDeciderV1<'a> {
    catalog: &'a ExactWorkCatalogV1,
    policy_basis: Digest,
}

impl<'a> CatalogAdmissibilityDeciderV1<'a> {
    /// Binds one consequence-time decision pass to an exact catalog and its
    /// content-derived policy identity.
    pub fn new(catalog: &'a ExactWorkCatalogV1) -> Result<Self, CampaignEngineErrorV1> {
        let policy_basis = catalog.policy_basis()?;
        Ok(Self {
            catalog,
            policy_basis,
        })
    }
}

impl AdmissibilityDeciderV1 for CatalogAdmissibilityDeciderV1<'_> {
    fn decide_admissibility(
        &mut self,
        request: &AdmissibilityRequestV1<'_>,
    ) -> Result<AdmissionDecisionV1, ExternalBoundaryErrorV1> {
        let admitted = self
            .catalog
            .entries
            .get(request.proposal.work_schema())
            .is_some_and(|entry| {
                entry.subject == *request.proposal.subject()
                    && entry.scope == *request.proposal.scope()
                    && entry.precondition.holds_over(&request.observation.basis)
            });
        #[derive(Serialize)]
        struct DecisionBasis<'a> {
            key: &'a OccurrenceKeyV1,
            observation: &'a ObservationRefV1,
            proposal: &'a ProposalRefV1,
            standing: &'a StandingResolutionRefV1,
            policy: &'a Digest,
            admitted: bool,
        }
        let basis = DecisionBasis {
            key: &request.standing.key,
            observation: &request.observation.observation,
            proposal: &request.standing.proposal,
            standing: &request.standing.resolution,
            policy: &self.policy_basis,
            admitted,
        };
        let bytes = JcsDocument::canonicalize(&basis).map_err(|error| {
            ExternalBoundaryErrorV1::Unavailable {
                code: format!("admission-canonicalization:{error}"),
            }
        })?;
        Ok(AdmissionDecisionV1 {
            decision: AdmissionDecisionRefV1::from_digest(Digest::hash_domain(
                "ag.governed-loop.catalog-admission/v1",
                bytes.as_bytes(),
            )),
            key: request.standing.key.clone(),
            observation: request.observation.observation.clone(),
            proposal: request.standing.proposal.clone(),
            standing_resolution: request.standing.resolution.clone(),
            disposition: if admitted {
                AdmissionDispositionV1::Admitted
            } else {
                AdmissionDispositionV1::Refused
            },
            policy_basis: self.policy_basis.clone(),
        })
    }
}

/// Exact result of polling/reconciling Docket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DocketProgressV1 {
    /// Custody exists but no exact outcome is yet available.
    Pending,
    /// Known settlement was consumed by AG.
    Settled(OccurrenceSnapshotV1),
    /// Exact indeterminate attempt entered/stayed in reconciliation.
    ReconciliationRequired(OccurrenceSnapshotV1),
}

/// Exact restart/recovery result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "record", rename_all = "snake_case")]
pub enum CampaignRecoveryV1 {
    /// No state transition; the named fresh boundary is required.
    ExternalRevalidation(RecoveryRequirementV1),
    /// Spent issuance is authoritatively absent at Docket and may be submitted
    /// again as the same issuance, never respent.
    IssuanceNotAccepted(AgIssuanceV1),
    /// Recovery committed one or more exact transitions.
    Advanced(OccurrenceSnapshotV1),
}

/// Production governed-loop orchestration errors.
#[derive(Debug, Error)]
pub enum CampaignEngineErrorV1 {
    /// Transactional store failure.
    #[error(transparent)]
    Store(#[from] CampaignStoreErrorV1),
    /// Pure kernel refusal.
    #[error(transparent)]
    Kernel(#[from] KernelErrorV1),
    /// External boundary failure.
    #[error(transparent)]
    External(#[from] ExternalBoundaryErrorV1),
    /// Exact-work catalog is malformed.
    #[error("invalid exact-work catalog")]
    InvalidCatalog,
    /// Canonical encoding failed.
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
    /// Docket returned a state that is impossible at this boundary.
    #[error("Docket custody/reconciliation response is not applicable")]
    DocketResponse,
}

/// One production-reachable canonical campaign engine.
pub struct CampaignEngineV1 {
    store: CampaignStoreV1,
}

impl CampaignEngineV1 {
    /// Creates one campaign with one authority-empty occurrence bound to one
    /// exact expected executable-work identity.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        database: &Path,
        campaign: CampaignId,
        occurrence: OccurrenceId,
        program: ProgramBasisRefV1,
        expected_work: Digest,
        residuals: ResidualSetV1,
        budget: LoopBudgetV1,
        now_unix_ms: u64,
    ) -> Result<Self, CampaignEngineErrorV1> {
        let initial = GovernedLoopKernelV1::create_initial(
            campaign,
            occurrence,
            program,
            expected_work,
            residuals,
            budget,
        )?;
        let store = CampaignStoreV1::create(database, &initial, now_unix_ms)?;
        Ok(Self { store })
    }

    /// Creates one campaign whose production boundary profile is committed in
    /// the same transaction as the authority-empty genesis occurrence.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_runtime_profile(
        database: &Path,
        campaign: CampaignId,
        occurrence: OccurrenceId,
        program: ProgramBasisRefV1,
        expected_work: Digest,
        residuals: ResidualSetV1,
        budget: LoopBudgetV1,
        runtime_profile_schema: &str,
        runtime_profile_jcs: &[u8],
        now_unix_ms: u64,
    ) -> Result<Self, CampaignEngineErrorV1> {
        let initial = GovernedLoopKernelV1::create_initial(
            campaign,
            occurrence,
            program,
            expected_work,
            residuals,
            budget,
        )?;
        let store = CampaignStoreV1::create_with_runtime_profile(
            database,
            &initial,
            Some((runtime_profile_schema, runtime_profile_jcs)),
            now_unix_ms,
        )?;
        Ok(Self { store })
    }

    /// Opens an existing campaign without reconstructing freshness or authority.
    pub fn open(database: &Path) -> Result<Self, CampaignEngineErrorV1> {
        Ok(Self {
            store: CampaignStoreV1::open(database)?,
        })
    }

    /// Returns the exact authoritative current occurrence.
    pub fn current(&self) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        Ok(self.store.current()?)
    }

    /// Runs deterministic store replay and accounting verification.
    pub fn replay(&self) -> Result<CampaignReplayReportV1, CampaignEngineErrorV1> {
        Ok(self.store.replay()?)
    }

    /// Returns the verified canonical transition journal without advancing
    /// the campaign or invoking an external boundary.
    pub fn history(&self) -> Result<CampaignTransitionHistoryV1, CampaignEngineErrorV1> {
        Ok(self.store.history()?)
    }

    /// Returns verified durable non-authorizing refusal facts without
    /// advancing the campaign or invoking an external boundary.
    pub fn refusal_history(&self) -> Result<CampaignRefusalHistoryV1, CampaignEngineErrorV1> {
        Ok(self.store.refusal_history()?)
    }

    /// Returns the immutable genesis-bound runtime profile. Raw library
    /// fixtures may omit it; the production CLI refuses such stores.
    pub fn runtime_profile(&self) -> Result<Option<StoredRuntimeProfileV1>, CampaignEngineErrorV1> {
        Ok(self.store.runtime_profile()?)
    }

    /// Records a fresh observation plus exact proposal.
    #[allow(clippy::too_many_arguments)]
    pub fn record_proposal<O: ObservationResolverV1>(
        &mut self,
        observation: ObservationRefV1,
        proposal: ExactWorkProposalV1,
        class: ProposalClassV1,
        resolver: &mut O,
        expected_observation_resolver: &str,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = match GovernedLoopKernelV1::record_proposal(
            &current,
            observation,
            proposal,
            class,
            resolver,
            expected_observation_resolver,
            now_unix_ms,
        ) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("retry")) => {
                return self.halt_for_exhausted_budget(&current, "retry", now_unix_ms);
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::ProposalRecorded,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Enters the explicit standing-required state.
    pub fn require_standing(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = GovernedLoopKernelV1::require_standing(&current)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::StandingRequired,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Resolves observation/current standing and records a positive AG decision.
    #[allow(clippy::too_many_arguments)]
    pub fn decide<O, S>(
        &mut self,
        observation: &mut O,
        standing: &mut S,
        catalog: &ExactWorkCatalogV1,
        controlling_review: Option<&C1RejectedReviewBasisV1>,
        expected_observation_resolver: &str,
        expected_standing_resolver: &str,
        max_standing_ttl_ms: u64,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1>
    where
        O: ObservationResolverV1,
        S: StandingResolverV1,
    {
        let current = self.store.current()?;
        let mut decider = CatalogAdmissibilityDeciderV1::new(catalog)?;
        let successor = GovernedLoopKernelV1::record_admissible(
            &current,
            observation,
            standing,
            &mut decider,
            controlling_review,
            expected_observation_resolver,
            expected_standing_resolver,
            max_standing_ttl_ms,
            now_unix_ms,
        )?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Admissible,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Re-resolves all current premises and durably spends the one AG authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize<O, S>(
        &mut self,
        observation: &mut O,
        standing: &mut S,
        catalog: &ExactWorkCatalogV1,
        controlling_review: Option<&C1RejectedReviewBasisV1>,
        expected_observation_resolver: &str,
        expected_standing_resolver: &str,
        max_standing_ttl_ms: u64,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1>
    where
        O: ObservationResolverV1,
        S: StandingResolverV1,
    {
        let current = self.store.current()?;
        let mut decider = CatalogAdmissibilityDeciderV1::new(catalog)?;
        let successor = GovernedLoopKernelV1::consume_authorization(
            &current,
            observation,
            standing,
            &mut decider,
            controlling_review,
            expected_observation_resolver,
            expected_standing_resolver,
            max_standing_ttl_ms,
            now_unix_ms,
        )?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::AuthorizationConsumed,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Delegates the exact durable issuance to Docket and records its custody.
    pub fn dispatch<D: DocketCustodyPortV1>(
        &mut self,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        if current.program_counter() != ProgramCounterV1::AuthorizationConsumed {
            return Err(KernelErrorV1::IllegalTransition {
                from: current.program_counter(),
                operation: "dispatch",
            }
            .into());
        }
        let issuance = current
            .issuance()
            .cloned()
            .ok_or(CampaignEngineErrorV1::DocketResponse)?;
        let custody = docket.accept_issuance(&issuance)?;
        let successor = GovernedLoopKernelV1::accept_docket_custody(&current, custody)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Polls Docket read-only and consumes only exact custody/settlement evidence.
    pub fn poll_docket<D: DocketCustodyPortV1>(
        &mut self,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let custody = current
            .docket_custody()
            .cloned()
            .ok_or(CampaignEngineErrorV1::DocketResponse)?;
        let response = docket.reconcile_attempt(&custody)?;
        self.apply_docket_progress(&current, response, now_unix_ms)
    }

    /// Opens a distinct authority-empty continuation after settlement,
    /// binding the new occurrence to its own exact expected work.
    pub fn open_continuation(
        &mut self,
        occurrence: OccurrenceId,
        expected_work: Digest,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor =
            GovernedLoopKernelV1::open_continuation(&current, occurrence, expected_work)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::ContinuationOpened,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Records one read-only probe budget fact; probe mechanics stay external.
    pub fn note_probe(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = match GovernedLoopKernelV1::note_probe(&current) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("probe")) => {
                return self.halt_for_exhausted_budget(&current, "probe", now_unix_ms);
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::ProbeNoted,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Safely halts from a non-effecting boundary.
    pub fn halt(
        &mut self,
        reason: HaltReasonRefV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = GovernedLoopKernelV1::halt(&current, reason)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Halted,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Records one bounded escalation and halts.
    pub fn escalate(
        &mut self,
        reason: HaltReasonRefV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = match GovernedLoopKernelV1::escalate(&current, reason) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("escalation")) => {
                return self.halt_for_exhausted_budget(&current, "escalation", now_unix_ms);
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Escalated,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Applies one externally verified human disposition transactionally.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_human_disposition<O, H>(
        &mut self,
        artifact: HumanDispositionV1,
        expected_scope: &HumanAuthorityScopeV1,
        new_occurrence: Option<OccurrenceId>,
        observation: &mut O,
        expected_observation_resolver: &str,
        verifier: &mut H,
        now_unix_ms: u64,
    ) -> Result<HumanDispositionEffectV1, CampaignEngineErrorV1>
    where
        O: ObservationResolverV1,
        H: HumanDispositionVerifierV1,
    {
        let current = self.store.current()?;
        let effect = GovernedLoopKernelV1::apply_human_disposition(
            &current,
            artifact.clone(),
            expected_scope,
            new_occurrence,
            observation,
            expected_observation_resolver,
            verifier,
            now_unix_ms,
        )?;
        self.store
            .commit_human_disposition(&current, &effect, &artifact, now_unix_ms)?;
        Ok(effect)
    }

    /// Applies one authenticated non-reconciliation intervention through the
    /// existing authority-safe campaign law and stores the exact request as
    /// transition evidence.  This path cannot mint AG authority or dispatch.
    pub fn apply_governed_intervention<V: GovernedInterventionVerifierV1>(
        &mut self,
        request: GovernedInterventionRequestV1,
        expected_scope: &GovernedInterventionAuthorityScopeV1,
        verifier: &mut V,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let authenticated = GovernedLoopKernelV1::verify_governed_intervention(
            request,
            expected_scope,
            verifier,
            now_unix_ms,
        )?;
        let kind = match &authenticated.request.intervention {
            GovernedInterventionClassV1::RequestProbe { .. } => {
                CampaignTransitionKindV1::ProbeNoted
            }
            GovernedInterventionClassV1::OpenSuccessor { .. } => {
                CampaignTransitionKindV1::ContinuationOpened
            }
            GovernedInterventionClassV1::HaltContinuation { .. } => {
                CampaignTransitionKindV1::Halted
            }
            GovernedInterventionClassV1::ReconcileAttempt { .. } => {
                return Err(KernelErrorV1::Intervention(
                    "reconciliation requires the read-only Docket path",
                )
                .into());
            }
        };
        let retained = authenticated.clone();
        let effect = match GovernedLoopKernelV1::apply_verified_governed_intervention(
            &current,
            authenticated,
        ) {
            Ok(effect) => effect,
            Err(error) => {
                self.record_verified_intervention_refusal(
                    &current,
                    &retained,
                    intervention_refusal_code(&error),
                    now_unix_ms,
                )?;
                return Err(error.into());
            }
        };
        let GovernedInterventionEffectV1::Transition {
            successor,
            verified: authenticated_evidence,
        } = effect
        else {
            return Err(KernelErrorV1::Intervention("wrong intervention path").into());
        };
        self.store.commit_governed_intervention(
            &current,
            &successor,
            kind,
            &authenticated_evidence,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Authenticates one exact reconciliation request and performs only a
    /// read-only query for its already-consumed Docket attempt.  The request
    /// cannot accept custody or call dispatch; only an exact Docket settlement
    /// may advance the state.
    pub fn request_reconciliation<V, D>(
        &mut self,
        request: GovernedInterventionRequestV1,
        expected_scope: &GovernedInterventionAuthorityScopeV1,
        verifier: &mut V,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1>
    where
        V: GovernedInterventionVerifierV1,
        D: DocketCustodyPortV1,
    {
        let current = self.store.current()?;
        let authenticated = GovernedLoopKernelV1::verify_governed_intervention(
            request,
            expected_scope,
            verifier,
            now_unix_ms,
        )?;
        let retained = authenticated.clone();
        let effect = match GovernedLoopKernelV1::apply_verified_governed_intervention(
            &current,
            authenticated,
        ) {
            Ok(effect) => effect,
            Err(error) => {
                self.record_verified_intervention_refusal(
                    &current,
                    &retained,
                    intervention_refusal_code(&error),
                    now_unix_ms,
                )?;
                return Err(error.into());
            }
        };
        let GovernedInterventionEffectV1::Reconcile(authenticated) = effect else {
            return Err(KernelErrorV1::Intervention(
                "non-reconciliation request used on reconciliation path",
            )
            .into());
        };
        let custody = current
            .docket_custody()
            .cloned()
            .ok_or(CampaignEngineErrorV1::DocketResponse)?;
        match docket.reconcile_attempt(&custody)? {
            DocketIssuanceReconciliationV1::Accepted(returned) => {
                if returned != custody {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                self.record_verified_intervention_refusal(
                    &current,
                    &authenticated,
                    RefusalCodeV1::InterventionOutcomeUnknown,
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::ReconciliationRequired(current))
            }
            DocketIssuanceReconciliationV1::Indeterminate {
                custody: returned,
                indeterminate,
            } => {
                if returned != custody || current.indeterminate() != Some(&indeterminate) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                self.record_verified_intervention_refusal(
                    &current,
                    &authenticated,
                    RefusalCodeV1::InterventionOutcomeUnknown,
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::ReconciliationRequired(current))
            }
            DocketIssuanceReconciliationV1::Settled {
                custody: returned,
                settlement,
            } => {
                if returned != custody {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                let successor =
                    GovernedLoopKernelV1::record_reconciled_settlement(&current, settlement)?;
                self.store.commit_governed_intervention(
                    &current,
                    &successor,
                    CampaignTransitionKindV1::ReconciledSettlement,
                    &authenticated,
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::Settled(successor))
            }
            DocketIssuanceReconciliationV1::NotAccepted => {
                Err(CampaignEngineErrorV1::DocketResponse)
            }
        }
    }

    /// Completes from an authority-empty observation boundary only.
    #[allow(clippy::too_many_arguments)]
    pub fn complete<O: ObservationResolverV1>(
        &mut self,
        observation_ref: ObservationRefV1,
        subject: &Digest,
        terminal_witness: TerminalWitnessRefV1,
        observation: &mut O,
        expected_observation_resolver: &str,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = GovernedLoopKernelV1::complete_from_observation(
            &current,
            observation_ref,
            subject,
            terminal_witness,
            observation,
            expected_observation_resolver,
            now_unix_ms,
        )?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Completed,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Records one typed refusal without changing the current state.
    pub fn record_refusal(
        &mut self,
        code: RefusalCodeV1,
        evidence: Option<Digest>,
        now_unix_ms: u64,
    ) -> Result<Digest, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        Ok(self.store.record_refusal(
            &RefusalOutcomeV1 {
                key: current.key().clone(),
                at_state_digest: current.state_digest().clone(),
                code,
                evidence,
                governed_intervention: None,
            },
            now_unix_ms,
        )?)
    }

    fn record_verified_intervention_refusal(
        &mut self,
        current: &OccurrenceSnapshotV1,
        verified: &VerifiedGovernedInterventionV1,
        code: RefusalCodeV1,
        now_unix_ms: u64,
    ) -> Result<Digest, CampaignEngineErrorV1> {
        Ok(self.store.record_refusal(
            &RefusalOutcomeV1 {
                key: current.key().clone(),
                at_state_digest: current.state_digest().clone(),
                code,
                evidence: Some(verified.request.request.as_digest().clone()),
                governed_intervention: Some(verified.clone()),
            },
            now_unix_ms,
        )?)
    }

    /// Applies the exact restart law without recreating freshness or authority.
    pub fn recover<D: DocketCustodyPortV1>(
        &mut self,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<CampaignRecoveryV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        match current.program_counter() {
            ProgramCounterV1::AuthorizationConsumed => {
                let issuance = current
                    .issuance()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                match docket.reconcile_issuance(&issuance)? {
                    DocketIssuanceReconciliationV1::NotAccepted => {
                        Ok(CampaignRecoveryV1::IssuanceNotAccepted(issuance))
                    }
                    response => {
                        let advanced =
                            self.apply_recovered_issuance(&current, response, now_unix_ms)?;
                        Ok(CampaignRecoveryV1::Advanced(advanced))
                    }
                }
            }
            ProgramCounterV1::Dispatched => {
                let reconciling = GovernedLoopKernelV1::recover_dispatched(&current)?;
                self.store.commit(
                    &current,
                    &reconciling,
                    CampaignTransitionKindV1::RecoveryReconciliation,
                    now_unix_ms,
                )?;
                let custody = reconciling
                    .docket_custody()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let response = docket.reconcile_attempt(&custody)?;
                match self.apply_docket_progress(&reconciling, response, now_unix_ms)? {
                    DocketProgressV1::Pending | DocketProgressV1::ReconciliationRequired(_) => {
                        Ok(CampaignRecoveryV1::Advanced(self.store.current()?))
                    }
                    DocketProgressV1::Settled(snapshot) => {
                        Ok(CampaignRecoveryV1::Advanced(snapshot))
                    }
                }
            }
            ProgramCounterV1::ReconciliationRequired => {
                let custody = current
                    .docket_custody()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let response = docket.reconcile_attempt(&custody)?;
                match self.apply_docket_progress(&current, response, now_unix_ms)? {
                    DocketProgressV1::Pending | DocketProgressV1::ReconciliationRequired(_) => {
                        Ok(CampaignRecoveryV1::Advanced(self.store.current()?))
                    }
                    DocketProgressV1::Settled(snapshot) => {
                        Ok(CampaignRecoveryV1::Advanced(snapshot))
                    }
                }
            }
            _ => Ok(CampaignRecoveryV1::ExternalRevalidation(
                GovernedLoopKernelV1::recovery_requirement(&current),
            )),
        }
    }

    fn apply_recovered_issuance(
        &mut self,
        current: &OccurrenceSnapshotV1,
        response: DocketIssuanceReconciliationV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let (custody, after) = match response {
            DocketIssuanceReconciliationV1::Accepted(custody) => (custody, None),
            DocketIssuanceReconciliationV1::Settled {
                custody,
                settlement,
            } => (custody, Some(Ok(settlement))),
            DocketIssuanceReconciliationV1::Indeterminate {
                custody,
                indeterminate,
            } => (custody, Some(Err(indeterminate))),
            DocketIssuanceReconciliationV1::NotAccepted => {
                return Err(CampaignEngineErrorV1::DocketResponse);
            }
        };
        let dispatched = GovernedLoopKernelV1::accept_docket_custody(current, custody)?;
        self.store.commit(
            current,
            &dispatched,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            now_unix_ms,
        )?;
        match after {
            None => {
                // This path is recovery after process loss.  Custody is known,
                // but its effect outcome is not, so the recovered PC must be
                // explicit reconciliation rather than ordinary dispatch.
                let reconciling = GovernedLoopKernelV1::recover_dispatched(&dispatched)?;
                self.store.commit(
                    &dispatched,
                    &reconciling,
                    CampaignTransitionKindV1::RecoveryReconciliation,
                    now_unix_ms,
                )?;
                Ok(reconciling)
            }
            Some(Ok(settlement)) => {
                let settled = GovernedLoopKernelV1::record_settlement(&dispatched, settlement)?;
                self.store.commit(
                    &dispatched,
                    &settled,
                    CampaignTransitionKindV1::SettlementRecorded,
                    now_unix_ms,
                )?;
                Ok(settled)
            }
            Some(Err(indeterminate)) => {
                let reconciling =
                    GovernedLoopKernelV1::require_reconciliation(&dispatched, indeterminate)?;
                self.store.commit(
                    &dispatched,
                    &reconciling,
                    CampaignTransitionKindV1::ReconciliationRequired,
                    now_unix_ms,
                )?;
                Ok(reconciling)
            }
        }
    }

    fn apply_docket_progress(
        &mut self,
        current: &OccurrenceSnapshotV1,
        response: DocketIssuanceReconciliationV1,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1> {
        match response {
            DocketIssuanceReconciliationV1::NotAccepted => {
                Err(CampaignEngineErrorV1::DocketResponse)
            }
            DocketIssuanceReconciliationV1::Accepted(custody) => {
                if current.docket_custody() != Some(&custody) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                match current.program_counter() {
                    ProgramCounterV1::Dispatched => Ok(DocketProgressV1::Pending),
                    // The exact attempt remains consumed but unsettled.  This
                    // is read-only no-progress, never a downgrade to ordinary
                    // dispatch and never permission to repeat mechanics.
                    ProgramCounterV1::ReconciliationRequired => {
                        Ok(DocketProgressV1::ReconciliationRequired(current.clone()))
                    }
                    _ => Err(CampaignEngineErrorV1::DocketResponse),
                }
            }
            DocketIssuanceReconciliationV1::Settled {
                custody,
                settlement,
            } => {
                if current.docket_custody() != Some(&custody) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                if current.program_counter() == ProgramCounterV1::SettledObservationRequired {
                    return if current.settlement() == Some(&settlement) {
                        Ok(DocketProgressV1::Settled(current.clone()))
                    } else {
                        Err(CampaignEngineErrorV1::DocketResponse)
                    };
                }
                let successor =
                    if current.program_counter() == ProgramCounterV1::ReconciliationRequired {
                        GovernedLoopKernelV1::record_reconciled_settlement(current, settlement)?
                    } else {
                        GovernedLoopKernelV1::record_settlement(current, settlement)?
                    };
                self.store.commit(
                    current,
                    &successor,
                    if current.program_counter() == ProgramCounterV1::ReconciliationRequired {
                        CampaignTransitionKindV1::ReconciledSettlement
                    } else {
                        CampaignTransitionKindV1::SettlementRecorded
                    },
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::Settled(successor))
            }
            DocketIssuanceReconciliationV1::Indeterminate {
                custody,
                indeterminate,
            } => {
                if current.docket_custody() != Some(&custody) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                if current.program_counter() == ProgramCounterV1::ReconciliationRequired {
                    return if current.indeterminate() == Some(&indeterminate) {
                        Ok(DocketProgressV1::ReconciliationRequired(current.clone()))
                    } else {
                        Err(CampaignEngineErrorV1::DocketResponse)
                    };
                }
                let successor =
                    GovernedLoopKernelV1::require_reconciliation(current, indeterminate)?;
                self.store.commit(
                    current,
                    &successor,
                    CampaignTransitionKindV1::ReconciliationRequired,
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::ReconciliationRequired(successor))
            }
        }
    }

    fn halt_for_exhausted_budget(
        &mut self,
        current: &OccurrenceSnapshotV1,
        budget: &'static str,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let body = JcsDocument::canonicalize(&(
            "ag.governed-loop.budget-exhausted/v1",
            current.key(),
            current.state_digest(),
            budget,
        ))
        .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        let reason = HaltReasonRefV1::from_digest(Digest::hash_domain(
            "ag.governed-loop.budget-exhausted/v1",
            body.as_bytes(),
        ));
        let successor = GovernedLoopKernelV1::halt(current, reason)?;
        self.store.commit(
            current,
            &successor,
            CampaignTransitionKindV1::Halted,
            now_unix_ms,
        )?;
        Ok(successor)
    }
}

/// Convenience type for batches of commit receipts returned by future callers.
pub type CampaignCommitBatchV1 = Vec<CampaignCommitReceiptV1>;

fn intervention_refusal_code(error: &KernelErrorV1) -> RefusalCodeV1 {
    match error {
        KernelErrorV1::BudgetExhausted(_) => RefusalCodeV1::BudgetExhausted,
        KernelErrorV1::Intervention(
            "wrong campaign" | "wrong occurrence" | "stale target state" | "wrong issuance"
            | "wrong attempt",
        )
        | KernelErrorV1::OccurrenceMismatch
        | KernelErrorV1::BindingMismatch(_) => RefusalCodeV1::InterventionBindingMismatch,
        _ => RefusalCodeV1::InterventionNotApplicable,
    }
}
