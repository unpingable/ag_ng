#![allow(
    clippy::missing_errors_doc,
    reason = "the closed KernelErrorV1/ExternalBoundaryErrorV1 types are the normative error contract"
)]
#![allow(
    clippy::similar_names,
    reason = "resolver and resolution are deliberately distinct boundary roles"
)]
#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    reason = "the frozen FSM and disposition matches remain explicit and locally auditable"
)]
#![allow(
    clippy::needless_pass_by_value,
    reason = "authority-bearing transition inputs are deliberately accepted as owned records"
)]
#![allow(
    clippy::large_enum_variant,
    reason = "human transition output atomically returns both exact snapshots without hidden indirection"
)]

//! Canonical governed-loop law for exact-work occurrences.
//!
//! This module is the sole production campaign transition kernel.  It is
//! intentionally pure: it records exact references, validates closed state
//! transitions, and creates deterministic AG spends and issuances, but it
//! performs no observation, standing, execution, scheduling, or human-
//! authority I/O.  Those facts enter only through fresh resolver calls.

use core::fmt;
use std::collections::BTreeSet;

use ag_primitives::{Digest, JcsDocument};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::identity::{CampaignId, CampaignLabelError};
use crate::transcript::{is_canonical_wire_label, validate_label};

/// Tests one value against the shared AG/Docket lowercase wire-label grammar.
/// The stable corpus additionally fixes the 128-byte protocol bound.
#[must_use]
pub fn governed_wire_label_is_canonical_v1(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && is_canonical_wire_label(value)
}

/// Wire schema for exact-work proposals.
pub const EXACT_WORK_PROPOSAL_SCHEMA_V1: &str = "ag.governed-loop.exact-work-proposal/v1";
/// Wire schema for one canonical exact effect scope.
pub const CANONICAL_EFFECT_SCOPE_SCHEMA_V1: &str = "ag.governed-loop.canonical-effect-scope/v1";
/// Wire schema for fresh observation records.
pub const OBSERVATION_RESOLUTION_SCHEMA_V1: &str = "ag.governed-loop.observation-resolution/v1";
/// Wire schema for current standing resolutions.
pub const STANDING_RESOLUTION_SCHEMA_V1: &str = "ag.governed-loop.standing-resolution/v1";
/// Wire schema for AG issuances carrying one structured exact effect scope.
pub const AG_ISSUANCE_SCHEMA_V2: &str = "ag.governed-loop.issuance/v2";
/// Wire schema for Docket custody records.
pub const DOCKET_CUSTODY_SCHEMA_V1: &str = "ag.governed-loop.docket-custody/v1";
/// Wire schema for Docket settlements.
pub const DOCKET_SETTLEMENT_SCHEMA_V1: &str = "ag.governed-loop.docket-settlement/v1";
/// Identity domain for the complete exact Docket settlement body.
pub const DOCKET_SETTLEMENT_IDENTITY_DOMAIN_V1: &str = "docket.governed-loop.settlement/v1";
/// Wire schema for external human dispositions.
pub const HUMAN_DISPOSITION_SCHEMA_V1: &str = "ag.governed-loop.human-disposition/v1";
/// Wire schema for exact governed-repair human dispositions.
pub const GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1: &str =
    "ag.governed-loop.governed-repair-disposition/v1";
/// Wire schema for exact governed-repair verifier responses.
pub const GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1: &str =
    "ag.governed-loop.governed-repair-verification/v1";
/// Wire schema for durable, non-authorizing human-decision requests.
pub const HUMAN_DECISION_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.human-decision-request/v1";
/// Wire schema for exact scope-expansion requirements.
pub const SCOPE_EXPANSION_REQUIRED_SCHEMA_V1: &str = "ag.governed-loop.scope-expansion-required/v1";
/// Wire schema for exact readjudication requirements.
pub const READJUDICATION_REQUIRED_SCHEMA_V1: &str = "ag.governed-loop.readjudication-required/v1";
/// Wire schema for a typed pre-spend scope-insufficiency halt marker.
pub const PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1: &str =
    "ag.governed-loop.pre-spend-scope-insufficiency/v1";
/// Wire schema for the durable, non-authorizing pre-spend discovery artifact.
pub const PRE_SPEND_SCOPE_DISCOVERY_SCHEMA_V1: &str =
    "ag.governed-loop.pre-spend-scope-discovery/v1";
/// Wire schema for one explicit AG reconciliation-round request.
pub const RECONCILIATION_ROUND_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.reconciliation-round-request/v1";
/// Wire schema for one Docket reconciliation-round response.
pub const DOCKET_RECONCILIATION_ROUND_RESPONSE_SCHEMA_V1: &str =
    "docket.governed-loop.reconciliation-round-response/v1";
/// Wire schema for one Docket reconciliation-round reservation.
pub const DOCKET_RECONCILIATION_ROUND_RESERVATION_SCHEMA_V1: &str =
    "docket.governed-loop.reconciliation-round-reservation/v1";
/// Wire schema for one completed Docket reconciliation round.
pub const DOCKET_RECONCILIATION_ROUND_COMPLETION_SCHEMA_V1: &str =
    "docket.governed-loop.reconciliation-round-completion/v1";

const STATE_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.state/v1";
const GENESIS_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.genesis/v1";
const PROPOSAL_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.proposal/v1";
const AG_AUTHORIZATION_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.authorization/v1";
const AG_SPEND_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.spend/v1";
const AG_ISSUANCE_DIGEST_DOMAIN_V2: &str = "ag.governed-loop.issuance/v2";
const HUMAN_DECISION_REQUEST_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.human-decision-request/v1";
const HUMAN_DISPOSITION_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.human-disposition/v1";
const RECONCILIATION_ROUND_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.reconciliation-round/v1";
const RECONCILIATION_ROUND_REQUEST_DIGEST_DOMAIN_V1: &str =
    "ag.governed-loop.reconciliation-round-request/v1";

fn digest_value<T: Serialize + ?Sized>(domain: &str, value: &T) -> Digest {
    let document = JcsDocument::canonicalize(value)
        .expect("governed-loop values contain only strict JCS-compatible fields");
    Digest::hash_domain(domain, document.as_bytes())
}

fn validate_canonical_timestamp(value: u64, field: &'static str) -> Result<(), KernelErrorV1> {
    if value > MAX_CANONICAL_JSON_INTEGER_V1 {
        return Err(KernelErrorV1::HumanDecisionRequest(field));
    }
    Ok(())
}

// Canonical cross-office records omit absent optional fields.  When a field is
// present it must contain T; explicit JSON null must not collapse to omission.
fn deserialize_present_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

macro_rules! exact_digest_ref {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            /// Wraps an exact domain-specific digest without rehashing it.
            #[must_use]
            pub const fn from_digest(digest: Digest) -> Self {
                Self(digest)
            }

            /// Returns the exact digest.
            #[must_use]
            pub const fn as_digest(&self) -> &Digest {
                &self.0
            }

            /// Returns the canonical digest text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

exact_digest_ref!(
    /// Exact immutable program/source basis.
    ProgramBasisRefV1
);
exact_digest_ref!(
    /// Exact external observation identity.
    ObservationRefV1
);
exact_digest_ref!(
    /// Exact external observation-currentness witness identity.
    ObservationCurrentnessRefV1
);
exact_digest_ref!(
    /// Exact normalized relevant-precondition basis.
    PreconditionBasisRefV1
);
exact_digest_ref!(
    /// Exact proposal identity.
    ProposalRefV1
);
exact_digest_ref!(
    /// Exact standing-resolution record identity.
    StandingResolutionRefV1
);
exact_digest_ref!(
    /// Exact standing-currentness witness identity.
    StandingCurrentnessRefV1
);
exact_digest_ref!(
    /// Exact external mandate identity.
    MandateRefV1
);
exact_digest_ref!(
    /// Exact positive AG admission-decision identity.
    AdmissionDecisionRefV1
);
exact_digest_ref!(
    /// Exact AG decision-authorization identity.
    AgAuthorizationRefV1
);
exact_digest_ref!(
    /// Exact durable AG authorization-spend identity.
    AgSpendRefV1
);
exact_digest_ref!(
    /// Exact deterministic AG issuance identity.
    AgIssuanceRefV1
);
exact_digest_ref!(
    /// Exact Docket execution-standing identity.
    DocketExecutionStandingRefV1
);
exact_digest_ref!(
    /// Exact Docket custody record identity.
    DocketCustodyRefV1
);
exact_digest_ref!(
    /// Exact Docket execution-attempt identity.
    DocketAttemptRefV1
);
exact_digest_ref!(
    /// Exact executor-local attempt marker.
    ExecutorAttemptMarkerRefV1
);
exact_digest_ref!(
    /// Exact Docket settlement identity.
    SettlementRefV1
);
exact_digest_ref!(
    /// Exact outcome receipt identity.
    ReceiptRefV1
);
exact_digest_ref!(
    /// Exact reconciliation record identity.
    ReconciliationRefV1
);
exact_digest_ref!(
    /// Exact identity of one intentional reconciliation poll.
    ReconciliationRoundRefV1
);
exact_digest_ref!(
    /// Exact canonical AG request for one reconciliation round.
    ReconciliationRoundRequestRefV1
);
exact_digest_ref!(
    /// Exact Docket reservation for one reconciliation round.
    DocketReconciliationReservationRefV1
);
exact_digest_ref!(
    /// Exact Docket completion record for one reconciliation round.
    DocketReconciliationCompletionRefV1
);
exact_digest_ref!(
    /// Exact residual-obligation identity.
    ResidualIdV1
);
exact_digest_ref!(
    /// Exact external residual-discharge authority identity.
    ResidualAuthorityRefV1
);
exact_digest_ref!(
    /// Exact halt reason identity.
    HaltReasonRefV1
);
exact_digest_ref!(
    /// Exact terminal-observation witness identity.
    TerminalWitnessRefV1
);
exact_digest_ref!(
    /// Exact external human-decision identity.
    HumanDecisionIdV1
);
exact_digest_ref!(
    /// Exact human principal/signer identity.
    HumanPrincipalRefV1
);
exact_digest_ref!(
    /// Exact human-disposition nonce identity.
    HumanNonceRefV1
);
exact_digest_ref!(
    /// Exact external verification record for a human disposition.
    HumanVerificationRefV1
);
exact_digest_ref!(
    /// Exact complete Store-validated governed-repair verification receipt.
    GovernedRepairVerificationRefV1
);
exact_digest_ref!(
    /// Exact non-authorizing human-decision request identity.
    HumanDecisionRequestRefV1
);
exact_digest_ref!(
    /// Exact external human-disposition artifact identity.
    HumanDispositionRefV1
);
exact_digest_ref!(
    /// Exact Docket checkpoint identity for a post-spend repair outcome.
    DocketCheckpointRefV1
);
exact_digest_ref!(
    /// Exact Docket sealed-result identity for a post-spend repair outcome.
    DocketSealedResultRefV1
);
exact_digest_ref!(
    /// Exact typed pre-spend scope-insufficiency halt marker.
    PreSpendScopeInsufficiencyRefV1
);
exact_digest_ref!(
    /// Exact durable, non-authorizing pre-spend discovery artifact.
    PreSpendScopeDiscoveryRefV1
);

/// Independently allocated identity of one governed occurrence.
///
/// This UUID is never derived from a stage name, proposal, review, receipt,
/// or effect digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OccurrenceId(Uuid);

impl OccurrenceId {
    /// Allocates a fresh random occurrence identity.
    #[must_use]
    pub fn allocate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps a UUID supplied by a deterministic test or external allocator.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for OccurrenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

/// Authoritative identity of one occurrence within one campaign.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceKeyV1 {
    /// Campaign identity.
    pub campaign: CampaignId,
    /// Independent occurrence identity.
    pub occurrence: OccurrenceId,
}

/// The closed canonical governed-loop program counter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramCounterV1 {
    /// A fresh external observation is required.
    ObservationRequired,
    /// An exact proposal and fresh observation have been recorded.
    ProposalRecorded,
    /// Fresh current standing is required.
    StandingRequired,
    /// Exact work is admitted, but no AG authorization has been spent.
    AdmissiblePendingAuthorization,
    /// The one AG authorization is durably spent and issuance is reconstructible.
    AuthorizationConsumed,
    /// Docket has accepted custody and assigned the one attempt.
    Dispatched,
    /// The exact attempt has an indeterminate outcome and must be reconciled.
    ReconciliationRequired,
    /// A known settlement exists; fresh observation is required to continue.
    SettledObservationRequired,
    /// The occurrence is durably halted and non-effecting.
    Halted,
    /// The campaign is terminally complete.
    Completed,
}

/// Durable bounded retry/probe/escalation accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopBudgetV1 {
    /// Maximum retry occurrences.
    pub retry_limit: u32,
    /// Retry occurrences already opened.
    pub retries_used: u32,
    /// Maximum read-only probes.
    pub probe_limit: u32,
    /// Read-only probes already requested.
    pub probes_used: u32,
    /// Maximum escalations.
    pub escalation_limit: u32,
    /// Escalations already requested.
    pub escalations_used: u32,
}

impl LoopBudgetV1 {
    /// Returns whether one more retry may be classified, without granting it.
    #[must_use]
    pub const fn retry_available(self) -> bool {
        self.retries_used < self.retry_limit
    }

    /// Returns whether one more probe may be recorded, without performing it.
    #[must_use]
    pub const fn probe_available(self) -> bool {
        self.probes_used < self.probe_limit
    }

    /// Returns whether one more escalation may be recorded, without authority.
    #[must_use]
    pub const fn escalation_available(self) -> bool {
        self.escalations_used < self.escalation_limit
    }

    fn validate(self) -> Result<(), KernelErrorV1> {
        if self.retries_used > self.retry_limit
            || self.probes_used > self.probe_limit
            || self.escalations_used > self.escalation_limit
        {
            return Err(KernelErrorV1::InvalidBudget);
        }
        Ok(())
    }
}

/// One exact open residual obligation tracked, but not authored, by AG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualObligationV1 {
    /// External residual identity.
    pub residual: ResidualIdV1,
    /// Exact source/owner identity.
    pub owner: Digest,
    /// Exact subject identity.
    pub subject: Digest,
    /// Exact statement/content digest.
    pub statement: Digest,
}

/// Canonical duplicate-free open residual set, ordered by exact identity.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "Vec<ResidualObligationV1>",
    into = "Vec<ResidualObligationV1>"
)]
pub struct ResidualSetV1(Vec<ResidualObligationV1>);

impl ResidualSetV1 {
    /// Constructs a canonical set, refusing duplicate residual identities.
    pub fn new(mut residuals: Vec<ResidualObligationV1>) -> Result<Self, KernelErrorV1> {
        residuals.sort_by(|left, right| left.residual.cmp(&right.residual));
        if residuals
            .windows(2)
            .any(|pair| pair[0].residual == pair[1].residual)
        {
            return Err(KernelErrorV1::DuplicateResidual);
        }
        Ok(Self(residuals))
    }

    /// Returns the exact canonical obligations.
    #[must_use]
    pub fn as_slice(&self) -> &[ResidualObligationV1] {
        &self.0
    }

    /// Returns whether no obligation remains open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of open obligations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl TryFrom<Vec<ResidualObligationV1>> for ResidualSetV1 {
    type Error = KernelErrorV1;

    fn try_from(value: Vec<ResidualObligationV1>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ResidualSetV1> for Vec<ResidualObligationV1> {
    fn from(value: ResidualSetV1) -> Self {
        value.0
    }
}

/// Exact externally authorized accounting for residual closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactResidualDischargeV1 {
    /// Campaign to which the authority is scoped.
    pub campaign: CampaignId,
    /// Halted occurrence to which the authority is scoped.
    pub occurrence: OccurrenceId,
    /// Exact program basis to which the authority is scoped.
    pub program: ProgramBasisRefV1,
    /// External authority record.
    pub authority: ResidualAuthorityRefV1,
    /// One-use external disposition identity.
    pub disposition: HumanDecisionIdV1,
    /// Complete prior open residual IDs.
    pub before: Vec<ResidualIdV1>,
    /// Exact externally authorized closure set.
    pub authorized: Vec<ResidualIdV1>,
    /// Exact actually closed set.
    pub closed: Vec<ResidualIdV1>,
    /// Exact remaining open set.
    pub after: Vec<ResidualIdV1>,
}

/// Canonical finding set used by the accepted C1 review/repair profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Digest>", into = "Vec<Digest>")]
pub struct CanonicalFindingSetV1(Vec<Digest>);

impl CanonicalFindingSetV1 {
    /// Normalizes ordering and refuses duplicate exact finding identities.
    pub fn new(mut findings: Vec<Digest>) -> Result<Self, KernelErrorV1> {
        findings.sort();
        if findings.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(KernelErrorV1::DuplicateFinding);
        }
        Ok(Self(findings))
    }

    /// Returns the canonical finding identities.
    #[must_use]
    pub fn as_slice(&self) -> &[Digest] {
        &self.0
    }
}

impl TryFrom<Vec<Digest>> for CanonicalFindingSetV1 {
    type Error = KernelErrorV1;

    fn try_from(value: Vec<Digest>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CanonicalFindingSetV1> for Vec<Digest> {
    fn from(value: CanonicalFindingSetV1) -> Self {
        value.0
    }
}

/// Controlling rejected-review basis for the C1 repair profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C1RejectedReviewBasisV1 {
    /// Exact rejected review receipt.
    pub review_receipt: Digest,
    /// Exact review session.
    pub review_session: Digest,
    /// Exact reviewer identity.
    pub reviewer: Digest,
    /// Exact review-history basis.
    pub history: Digest,
    /// Exact canonical rejected finding set.
    pub findings: CanonicalFindingSetV1,
}

/// Repair citation supplied by a C1 exact-work proposal.
pub type C1RepairCitationV1 = C1RejectedReviewBasisV1;

/// Closed operation vocabulary for one exact effect-scope row.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalEffectOperationV1 {
    /// Read exact existing content.
    Read,
    /// Create exact new content.
    Create,
    /// Modify exact existing content.
    Modify,
    /// Delete exact existing content.
    Delete,
    /// Execute the exact named artifact.
    Execute,
}

/// One canonical resource/path row in an exact effect scope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEffectResourceV1 {
    /// Closed deployment-owned resource label.
    pub resource: String,
    /// Exact normalized repository-relative path.
    pub path: String,
    /// Sorted, duplicate-free closed operations.
    pub operations: Vec<CanonicalEffectOperationV1>,
}

/// Structured scope whose canonical digest, not an ambient path pattern,
/// binds proposal, standing, authorization, and issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEffectScopeV1 {
    schema: String,
    effect_class: String,
    resources: Vec<CanonicalEffectResourceV1>,
}

impl CanonicalEffectScopeV1 {
    /// Constructs one closed scope after sorting and validating every exact row.
    pub fn new(
        effect_class: String,
        mut resources: Vec<CanonicalEffectResourceV1>,
    ) -> Result<Self, KernelErrorV1> {
        validate_label("effect class", &effect_class).map_err(KernelErrorV1::Label)?;
        if resources.is_empty() {
            return Err(KernelErrorV1::EffectScope("empty resource set"));
        }
        for row in &mut resources {
            validate_effect_resource(row)?;
            row.operations.sort();
            row.operations.dedup();
        }
        resources.sort();
        if resources
            .windows(2)
            .any(|pair| pair[0].resource == pair[1].resource && pair[0].path == pair[1].path)
        {
            return Err(KernelErrorV1::EffectScope("duplicate resource/path"));
        }
        let scope = Self {
            schema: CANONICAL_EFFECT_SCOPE_SCHEMA_V1.to_owned(),
            effect_class,
            resources,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Revalidates exact decoded scope bytes.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != CANONICAL_EFFECT_SCOPE_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema("canonical effect scope"));
        }
        validate_label("effect class", &self.effect_class).map_err(KernelErrorV1::Label)?;
        if self.resources.is_empty() {
            return Err(KernelErrorV1::EffectScope("empty resource set"));
        }
        let mut normalized = self.resources.clone();
        for row in &mut normalized {
            validate_effect_resource(row)?;
            let before = row.operations.clone();
            row.operations.sort();
            row.operations.dedup();
            if row.operations != before {
                return Err(KernelErrorV1::EffectScope(
                    "operations must be sorted and unique",
                ));
            }
        }
        normalized.sort();
        if normalized != self.resources
            || normalized
                .windows(2)
                .any(|pair| pair[0].resource == pair[1].resource && pair[0].path == pair[1].path)
        {
            return Err(KernelErrorV1::EffectScope(
                "resources must be sorted and unique",
            ));
        }
        Ok(())
    }

    /// Returns the exact effect class.
    #[must_use]
    pub fn effect_class(&self) -> &str {
        &self.effect_class
    }

    /// Returns the exact ordered resource rows.
    #[must_use]
    pub fn resources(&self) -> &[CanonicalEffectResourceV1] {
        &self.resources
    }

    /// Returns the canonical semantic identity of the complete scope.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::hash_domain(
            CANONICAL_EFFECT_SCOPE_SCHEMA_V1,
            self.canonical_document().as_bytes(),
        )
    }

    /// Returns the exact canonical scope bytes shared by AG and Docket.
    ///
    /// # Panics
    ///
    /// Panics only if this already validated, closed Rust value can no longer
    /// be represented by the repository's canonical JSON implementation.
    #[must_use]
    pub fn canonical_document(&self) -> JcsDocument {
        JcsDocument::canonicalize(self)
            .expect("validated canonical effect scopes contain only exact JCS values")
    }

    /// Computes the exact closed union used by an approved scope expansion.
    pub fn exact_union(&self, delta: &Self) -> Result<Self, KernelErrorV1> {
        self.validate()?;
        delta.validate()?;
        if self.effect_class != delta.effect_class {
            return Err(KernelErrorV1::EffectScope("effect class changed"));
        }
        let mut rows = self.resources.clone();
        for incoming in &delta.resources {
            if let Some(existing) = rows
                .iter_mut()
                .find(|row| row.resource == incoming.resource && row.path == incoming.path)
            {
                existing
                    .operations
                    .extend(incoming.operations.iter().copied());
                existing.operations.sort();
                existing.operations.dedup();
            } else {
                rows.push(incoming.clone());
            }
        }
        Self::new(self.effect_class.clone(), rows)
    }

    /// Computes a strict additive union for a newly discovered pre-spend
    /// requirement.  The delta may add operations to an existing exact path,
    /// but it may not repeat an operation already present in the immutable
    /// predecessor scope.
    pub fn exact_additive_union(&self, delta: &Self) -> Result<Self, KernelErrorV1> {
        self.validate()?;
        delta.validate()?;
        if self.effect_class != delta.effect_class {
            return Err(KernelErrorV1::EffectScope("effect class changed"));
        }
        let mut rows = self.resources.clone();
        for incoming in &delta.resources {
            if let Some(existing) = rows
                .iter_mut()
                .find(|row| row.resource == incoming.resource && row.path == incoming.path)
            {
                if incoming
                    .operations
                    .iter()
                    .any(|operation| existing.operations.contains(operation))
                {
                    return Err(KernelErrorV1::EffectScope(
                        "delta repeats an already authorized effect",
                    ));
                }
                existing
                    .operations
                    .extend(incoming.operations.iter().copied());
                existing.operations.sort();
            } else {
                rows.push(incoming.clone());
            }
        }
        let revised = Self::new(self.effect_class.clone(), rows)?;
        if &revised == self {
            return Err(KernelErrorV1::EffectScope(
                "delta does not add an exact effect",
            ));
        }
        Ok(revised)
    }
}

/// Exact closed operation that could not lawfully proceed inside the original
/// effect scope.  It is evidence for a decision request, never permission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedEffectOperationV1 {
    /// Deployment-owned resource label.
    pub resource: String,
    /// Exact normalized repository-relative path.
    pub path: String,
    /// Exact attempted operation.
    pub operation: CanonicalEffectOperationV1,
}

impl BlockedEffectOperationV1 {
    fn validate(&self) -> Result<(), KernelErrorV1> {
        validate_effect_resource(&CanonicalEffectResourceV1 {
            resource: self.resource.clone(),
            path: self.path.clone(),
            operations: vec![self.operation],
        })
    }
}

/// Exact Docket-owned result proving that a post-spend occurrence was sealed
/// before AG asks for human governance.  These references remain evidence and
/// cannot resume or expand the halted occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketGovernedRepairOutcomeRefV1 {
    /// Docket checkpoint that closed execution custody.
    pub checkpoint: DocketCheckpointRefV1,
    /// Docket sealed-result identity.
    pub sealed_result: DocketSealedResultRefV1,
    /// Exact typed Docket outcome body identity.
    pub outcome: Digest,
    /// Exact AG issuance at the custody boundary.
    pub issuance: AgIssuanceRefV1,
    /// Exact Docket custody record identity.
    pub custody: DocketCustodyRefV1,
    /// Exact Docket attempt.
    pub attempt: DocketAttemptRefV1,
    /// Exact append-only executor-effect journal identity.
    pub effect_journal: Digest,
    /// Exact executor binding.
    pub executor_binding: Digest,
    /// Exact executor-result identity.
    pub executor_result: Digest,
    /// Exact executor receipt bound into Docket's sealed checkpoint.
    pub executor_receipt: ReceiptRefV1,
    /// Exact immutable work checkpoint sealed by Docket, when the attempted
    /// work began from one. This is evidence, never authority.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub immutable_work_checkpoint: Option<GovernedRepairCheckpointV1>,
    /// Whether exact authorized effects were already journaled before the
    /// requirement was discovered.
    pub reported_authorized_effects_occurred: bool,
    /// Docket's exact requirement creation time.
    pub created_at_unix_ms: u64,
    /// Exclusive Docket requirement expiry.
    pub expires_at_unix_ms: u64,
    /// Exact Docket idempotency identity for this sealed requirement.
    pub idempotency: Digest,
}

/// Closed class of Docket-owned terminal refusal before execution custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DocketIssuanceRefusalClassV1 {
    /// The authenticated issuance failed Docket's closed semantic validation.
    IssuanceInvalid,
    /// The exact issuance expired before custody.
    IssuanceExpired,
    /// The immutable starting checkpoint failed exact verification.
    CheckpointInvalid,
    /// The exact execution-standing response was negative or malformed.
    StandingInvalid,
    /// Authenticated issuance coordinates contradicted the execution instrument.
    InstrumentSubstitution,
}

/// Exact Docket-owned terminal refusal for an authenticated issuance before
/// custody. This is durable evidence and never an authorization refund,
/// checkpoint authority, or continuation permit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketIssuanceRefusalV1 {
    /// Exact Docket schema.
    pub schema: String,
    /// Domain-separated identity of every following field.
    pub refusal: Digest,
    /// Exact consumed AG issuance.
    pub issuance: AgIssuanceRefV1,
    /// Exact campaign.
    pub campaign: CampaignId,
    /// Exact occurrence.
    pub occurrence: OccurrenceId,
    /// Closed refusal class.
    pub refusal_class: DocketIssuanceRefusalClassV1,
    /// Closed Docket reason label.
    pub reason_code: String,
    /// Exact Docket refusal evidence identity.
    pub evidence: Digest,
    /// Docket consequence time.
    pub refused_at_unix_ms: u64,
}

impl DocketIssuanceRefusalV1 {
    fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != "docket.governed-loop.issuance-refusal/v1"
            || self.reason_code.is_empty()
            || self.reason_code.len() > 256
            || !self.reason_code.bytes().all(|byte| byte.is_ascii_graphic())
            || self.refused_at_unix_ms > MAX_CANONICAL_JSON_INTEGER_V1
            || self.refusal != self.derived_identity()
        {
            return Err(KernelErrorV1::BindingMismatch(
                "Docket issuance refusal substitution",
            ));
        }
        Ok(())
    }

    /// Validates the exact Docket identity and issuance binding.
    pub fn validate_for(&self, issuance: &AgIssuanceV2) -> Result<(), KernelErrorV1> {
        self.validate()?;
        if self.issuance != issuance.issuance
            || self.campaign != issuance.key.campaign
            || self.occurrence != issuance.key.occurrence
        {
            return Err(KernelErrorV1::BindingMismatch(
                "Docket issuance refusal substitution",
            ));
        }
        Ok(())
    }

    /// Validates that this consequence was observed no earlier than AG's
    /// durable authorization spend. Docket does not receive or reinterpret
    /// the spend timestamp; AG enforces chronology when it ingests the sealed
    /// refusal.
    pub fn validate_for_spend(
        &self,
        issuance: &AgIssuanceV2,
        spend: &AgAuthorizationSpendV1,
    ) -> Result<(), KernelErrorV1> {
        self.validate_for(issuance)?;
        if spend.spend != issuance.spend
            || spend.key != issuance.key
            || self.refused_at_unix_ms < spend.consumed_at_unix_ms
        {
            return Err(KernelErrorV1::BindingMismatch(
                "Docket issuance refusal chronology",
            ));
        }
        Ok(())
    }

    /// Returns the mechanically derived Docket refusal identity.
    #[must_use]
    pub fn derived_identity(&self) -> Digest {
        let domain = "docket.governed-loop.issuance-refusal/v1";
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        transcript.extend_from_slice(domain.as_bytes());
        fn field(transcript: &mut Vec<u8>, label: &str, value: &str) {
            transcript.extend_from_slice(&(label.len() as u64).to_be_bytes());
            transcript.extend_from_slice(label.as_bytes());
            transcript.extend_from_slice(&(value.len() as u64).to_be_bytes());
            transcript.extend_from_slice(value.as_bytes());
        }
        field(&mut transcript, "schema", &self.schema);
        field(&mut transcript, "issuance", self.issuance.as_str());
        field(&mut transcript, "campaign", self.campaign.as_str());
        field(&mut transcript, "occurrence", &self.occurrence.to_string());
        field(
            &mut transcript,
            "refusal_class",
            match self.refusal_class {
                DocketIssuanceRefusalClassV1::IssuanceInvalid => "issuance_invalid",
                DocketIssuanceRefusalClassV1::IssuanceExpired => "issuance_expired",
                DocketIssuanceRefusalClassV1::CheckpointInvalid => "checkpoint_invalid",
                DocketIssuanceRefusalClassV1::StandingInvalid => "standing_invalid",
                DocketIssuanceRefusalClassV1::InstrumentSubstitution => "instrument_substitution",
            },
        );
        field(&mut transcript, "reason_code", &self.reason_code);
        field(&mut transcript, "evidence", self.evidence.as_str());
        field(
            &mut transcript,
            "refused_at_unix_ms",
            &self.refused_at_unix_ms.to_string(),
        );
        Digest::hash_bytes(&transcript)
    }
}

impl DocketGovernedRepairOutcomeRefV1 {
    fn validate(&self) -> Result<(), KernelErrorV1> {
        validate_canonical_timestamp(
            self.created_at_unix_ms,
            "Docket outcome creation time is not canonically representable",
        )?;
        validate_canonical_timestamp(
            self.expires_at_unix_ms,
            "Docket outcome expiry is not canonically representable",
        )?;
        if self.created_at_unix_ms >= self.expires_at_unix_ms {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "Docket outcome has an empty validity interval",
            ));
        }
        if let Some(checkpoint) = &self.immutable_work_checkpoint {
            checkpoint.validate()?;
            if checkpoint.docket_checkpoint.as_ref() != Some(&self.checkpoint) {
                return Err(KernelErrorV1::HumanDecisionRequest(
                    "immutable work checkpoint differs from sealed Docket checkpoint",
                ));
            }
        }
        Ok(())
    }
}

/// Immutable evidence-only source checkpoint for one successor proposal.
/// Branch names and ambient paths are deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairCheckpointV1 {
    /// Exact repository identity.
    pub repository: Digest,
    /// Exact full commit object identity.
    pub commit: String,
    /// Exact full tree object identity.
    pub tree: String,
    /// Optional exact dirty-diff/content overlay identity.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub diff_identity: Option<Digest>,
    /// Exact canonical changed-path/content manifest identity.
    pub content_manifest: Digest,
    /// Exact Docket checkpoint when this is a post-spend result.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub docket_checkpoint: Option<DocketCheckpointRefV1>,
}

impl GovernedRepairCheckpointV1 {
    fn validate(&self) -> Result<(), KernelErrorV1> {
        let exact_git_id = |value: &str| {
            value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !exact_git_id(&self.commit) || !exact_git_id(&self.tree) {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "checkpoint commit/tree is not an exact object identity",
            ));
        }
        Ok(())
    }
}

/// Exact bounded scope expansion requested after a fail-closed halt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeExpansionRequiredV1 {
    /// Exact schema.
    pub schema: String,
    /// Immutable originally admitted scope.
    pub original_scope: CanonicalEffectScopeV1,
    /// Mechanically derived original-scope identity.
    pub original_scope_digest: Digest,
    /// Exact requested additive delta; it is not ambient repository scope.
    pub requested_delta: CanonicalEffectScopeV1,
    /// Mechanically derived delta identity.
    pub requested_delta_digest: Digest,
    /// First exact operation that could not lawfully proceed.
    pub blocked_operation: BlockedEffectOperationV1,
    /// Exact reason/evidence identity.
    pub reason: Digest,
    /// Canonical sorted, duplicate-free dependency evidence.
    pub dependency_evidence: Vec<Digest>,
    /// Exact Docket-owned limitations retained without granting authority.
    pub limitations: Vec<Digest>,
    /// Optional Docket-sealed result for a post-spend discovery.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub docket_outcome: Option<DocketGovernedRepairOutcomeRefV1>,
    /// Must be true: the executor reported no unauthorized effect and Docket
    /// found no out-of-scope entry in the reported effect journal. This is not
    /// a claim of complete physical mediation.
    pub no_unauthorized_effect_reported: bool,
}

impl ScopeExpansionRequiredV1 {
    /// Validates exact scope immutability and strictly additive union semantics.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != SCOPE_EXPANSION_REQUIRED_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema("scope expansion requirement"));
        }
        self.original_scope.validate()?;
        self.requested_delta.validate()?;
        self.blocked_operation.validate()?;
        if self.original_scope_digest != self.original_scope.digest()
            || self.requested_delta_digest != self.requested_delta.digest()
        {
            return Err(KernelErrorV1::EffectScope(
                "scope requirement digest mismatch",
            ));
        }
        if self.original_scope.effect_class() != self.requested_delta.effect_class() {
            return Err(KernelErrorV1::EffectScope("effect class changed"));
        }
        let delta_overlaps_original = self.requested_delta.resources().iter().any(|requested| {
            self.original_scope.resources().iter().any(|original| {
                original.resource == requested.resource
                    && original.path == requested.path
                    && requested
                        .operations
                        .iter()
                        .any(|operation| original.operations.contains(operation))
            })
        });
        if delta_overlaps_original {
            return Err(KernelErrorV1::EffectScope(
                "requested delta repeats an already authorized operation",
            ));
        }
        if self.dependency_evidence.is_empty()
            || self
                .dependency_evidence
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.limitations.is_empty()
            || self.limitations.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "dependency evidence must be sorted and unique",
            ));
        }
        if !self.no_unauthorized_effect_reported {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "executor did not report a clean unauthorized-effect boundary",
            ));
        }
        if let Some(outcome) = &self.docket_outcome {
            outcome.validate()?;
        }
        let blocked_in_delta = self.requested_delta.resources().iter().any(|row| {
            row.resource == self.blocked_operation.resource
                && row.path == self.blocked_operation.path
                && row.operations.contains(&self.blocked_operation.operation)
        });
        if !blocked_in_delta {
            return Err(KernelErrorV1::EffectScope(
                "blocked operation absent from exact delta",
            ));
        }
        Ok(())
    }

    /// Returns the one exact successor scope an approval may authorize.
    pub fn successor_scope(&self) -> Result<CanonicalEffectScopeV1, KernelErrorV1> {
        self.original_scope.exact_union(&self.requested_delta)
    }
}

/// Exact bounded request for a new normative decision rather than a path
/// expansion.  Evidence and alternatives are non-authorizing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadjudicationRequiredV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact normative question identity.
    pub question: Digest,
    /// Canonical sorted, duplicate-free evidence census.
    pub evidence_census: Vec<Digest>,
    /// Canonical sorted, duplicate-free diagnostic census.
    pub diagnostic_census: Vec<Digest>,
    /// Canonical sorted, duplicate-free bounded alternatives.
    pub bounded_alternatives: Vec<Digest>,
    /// Canonical sorted, duplicate-free unresolved facts.
    pub unresolved_facts: Vec<Digest>,
    /// Exact Docket-owned limitations retained without granting authority.
    pub limitations: Vec<Digest>,
    /// Exact read-only resources the successor may inspect while seeking a
    /// fresh decision.  It is not repair or mutation authority.
    pub adjudication_scope: CanonicalEffectScopeV1,
    /// Optional Docket-sealed result for a post-spend discovery.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub docket_outcome: Option<DocketGovernedRepairOutcomeRefV1>,
    /// Must be true: the executor reported no unadjudicated effect and Docket
    /// found no such entry in the reported effect journal. This is not a
    /// completeness claim about effects outside the mediated journal.
    pub no_unauthorized_effect_reported: bool,
}

impl ReadjudicationRequiredV1 {
    /// Validates all bounded canonical censuses and the no-effect premise.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != READJUDICATION_REQUIRED_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema("readjudication requirement"));
        }
        self.adjudication_scope.validate()?;
        if self
            .adjudication_scope
            .resources()
            .iter()
            .flat_map(|row| row.operations.iter())
            .any(|operation| *operation != CanonicalEffectOperationV1::Read)
        {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "readjudication scope is not read-only",
            ));
        }
        for values in [
            &self.evidence_census,
            &self.diagnostic_census,
            &self.bounded_alternatives,
            &self.unresolved_facts,
            &self.limitations,
        ] {
            if values.is_empty() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(KernelErrorV1::HumanDecisionRequest(
                    "request census must be sorted and unique",
                ));
            }
        }
        if !self.no_unauthorized_effect_reported {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "executor did not report a clean unadjudicated-effect boundary",
            ));
        }
        if let Some(outcome) = &self.docket_outcome {
            outcome.validate()?;
        }
        Ok(())
    }
}

/// Closed reason a halted occurrence requires fresh human governance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanDecisionRequirementV1 {
    /// Exact additive effect-scope expansion.
    ScopeExpansion(ScopeExpansionRequiredV1),
    /// New normative decision on a bounded unresolved question.
    Readjudication(ReadjudicationRequiredV1),
}

/// Closed disposition classes serialized into each human-decision request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernedRepairDecisionClassV1 {
    /// Approve exactly the requested additive scope delta.
    ApproveExactExpansion,
    /// Reject the exact request.
    Reject,
    /// Require a fresh bounded normative adjudication.
    RequestReadjudication,
}

impl HumanDecisionRequirementV1 {
    fn validate(&self) -> Result<(), KernelErrorV1> {
        match self {
            Self::ScopeExpansion(value) => value.validate(),
            Self::Readjudication(value) => value.validate(),
        }
    }
}

/// Durable, non-authorizing request emitted only for the exact current halted
/// state.  Possession never constitutes a human disposition or standing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDecisionRequestV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact halted occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact halted-state identity.
    pub halted_state_digest: Digest,
    /// Program basis that encountered the decision boundary.
    pub program: ProgramBasisRefV1,
    /// Proposal basis when available.
    pub proposal: Option<ProposalRefV1>,
    /// Closed requested decision.
    pub requirement: HumanDecisionRequirementV1,
    /// Root-owned verifier profile required for any disposition.
    pub required_verifier_profile: Digest,
    /// Exact deployment verifier root that owns the required profile.
    pub required_verifier_root: Digest,
    /// Exact executable identity pinned by that verifier root.
    pub required_verifier_executable: Digest,
    /// Sorted, duplicate-free decision classes offered for this request.
    pub available_decisions: Vec<GovernedRepairDecisionClassV1>,
    /// One exact consequence statement identity per available decision.
    pub decision_consequences: Vec<Digest>,
    /// Explicit sorted, duplicate-free nonclaim identities.
    pub nonclaims: Vec<Digest>,
    /// Stable caller idempotency identity.
    pub idempotency_key: Digest,
    /// Creation time (fact, not standing).
    pub created_at_unix_ms: u64,
    /// Exclusive request expiry.
    pub expires_at_unix_ms: u64,
}

/// Exact non-authorizing inputs used to derive one human-decision request
/// from an already halted occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanDecisionRequestParametersV1 {
    /// Closed decision requirement.
    pub requirement: HumanDecisionRequirementV1,
    /// Root-owned verifier profile.
    pub required_verifier_profile: Digest,
    /// Exact deployment verifier root.
    pub required_verifier_root: Digest,
    /// Exact verifier executable identity.
    pub required_verifier_executable: Digest,
    /// One exact consequence identity per available decision.
    pub decision_consequences: Vec<Digest>,
    /// Explicit nonclaim identities.
    pub nonclaims: Vec<Digest>,
    /// Stable creation idempotency identity.
    pub idempotency_key: Digest,
    /// Creation time.
    pub created_at_unix_ms: u64,
    /// Exclusive expiry.
    pub expires_at_unix_ms: u64,
}

impl HumanDecisionRequestV1 {
    /// Returns its canonical exact identity.
    #[must_use]
    pub fn reference(&self) -> HumanDecisionRequestRefV1 {
        HumanDecisionRequestRefV1::from_digest(digest_value(
            HUMAN_DECISION_REQUEST_DIGEST_DOMAIN_V1,
            self,
        ))
    }

    /// Validates decoded request shape independent of current-state checks.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != HUMAN_DECISION_REQUEST_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema("human decision request"));
        }
        validate_canonical_timestamp(
            self.created_at_unix_ms,
            "human decision request creation time is not canonically representable",
        )?;
        validate_canonical_timestamp(
            self.expires_at_unix_ms,
            "human decision request expiry is not canonically representable",
        )?;
        if self.created_at_unix_ms >= self.expires_at_unix_ms {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "empty validity interval",
            ));
        }
        if self.available_decisions.is_empty()
            || self
                .available_decisions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.decision_consequences.len() != self.available_decisions.len()
            || self.nonclaims.is_empty()
            || self.nonclaims.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "decision vocabulary/consequences/nonclaims are not closed",
            ));
        }
        self.requirement.validate()
    }
}

fn validate_effect_resource(row: &CanonicalEffectResourceV1) -> Result<(), KernelErrorV1> {
    validate_label("effect resource", &row.resource).map_err(KernelErrorV1::Label)?;
    let lowered = row.resource.to_ascii_lowercase();
    if ["branch", "head", "ref"]
        .iter()
        .any(|word| lowered.contains(word))
    {
        return Err(KernelErrorV1::EffectScope("mutable ref resource"));
    }
    if row.operations.is_empty() {
        return Err(KernelErrorV1::EffectScope("empty operation set"));
    }
    let path = row.path.as_bytes();
    if row.path.is_empty()
        || row.path.starts_with('/')
        || row.path.ends_with('/')
        || row.path.contains('\\')
        || row.path.contains('\0')
        || row
            .path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || row.path.chars().any(|ch| {
            matches!(
                ch,
                '*' | '?' | '[' | ']' | '{' | '}' | '!' | '$' | '`' | ';' | '|' | '&'
            )
        })
        || path.iter().any(u8::is_ascii_control)
    {
        return Err(KernelErrorV1::EffectScope("non-exact effect path"));
    }
    Ok(())
}

/// Closed non-authorizing governance terms carried by one exact proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalGovernanceTermsV1 {
    /// Explicit sorted, duplicate-free nonclaim identities.
    pub nonclaims: Vec<Digest>,
    /// Exclusive absolute deadline for fresh consequence-bearing progress.
    pub expires_at_unix_ms: u64,
}

/// Largest integer whose exact value survives the RFC 8785/ECMAScript number
/// representation used by the cross-repository canonical JSON wire.
pub const MAX_CANONICAL_JSON_INTEGER_V1: u64 = ag_primitives::MAX_JCS_SAFE_INTEGER;

/// Generic exact-work proposal; the work payload is an immutable typed digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWorkProposalV1 {
    schema: String,
    campaign: CampaignId,
    subject: Digest,
    effect_scope: CanonicalEffectScopeV1,
    effect_scope_digest: Digest,
    work_schema: String,
    work: Digest,
    nonclaims: Vec<Digest>,
    expires_at_unix_ms: u64,
    repair: Option<C1RepairCitationV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    governed_repair_checkpoint: Option<GovernedRepairCheckpointV1>,
}

impl ExactWorkProposalV1 {
    /// Creates one exact proposal bound to one independently named occurrence.
    pub fn new(
        campaign: CampaignId,
        subject: Digest,
        effect_scope: CanonicalEffectScopeV1,
        work_schema: String,
        work: Digest,
        governance: ProposalGovernanceTermsV1,
        repair: Option<C1RepairCitationV1>,
    ) -> Result<Self, KernelErrorV1> {
        validate_label("exact-work schema", &work_schema).map_err(KernelErrorV1::Label)?;
        effect_scope.validate()?;
        let effect_scope_digest = effect_scope.digest();
        let proposal = Self {
            schema: EXACT_WORK_PROPOSAL_SCHEMA_V1.to_owned(),
            campaign,
            subject,
            effect_scope,
            effect_scope_digest,
            work_schema,
            work,
            nonclaims: governance.nonclaims,
            expires_at_unix_ms: governance.expires_at_unix_ms,
            repair,
            governed_repair_checkpoint: None,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    /// Revalidates a decoded proposal.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != EXACT_WORK_PROPOSAL_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema("exact-work proposal"));
        }
        validate_label("exact-work schema", &self.work_schema).map_err(KernelErrorV1::Label)?;
        if self.nonclaims.is_empty() || self.nonclaims.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(KernelErrorV1::Proposal(
                "nonclaims are empty, duplicated, or non-canonical",
            ));
        }
        if self.expires_at_unix_ms == 0 || self.expires_at_unix_ms > MAX_CANONICAL_JSON_INTEGER_V1 {
            return Err(KernelErrorV1::Proposal(
                "validity deadline is empty or not canonically representable",
            ));
        }
        self.effect_scope.validate()?;
        if let Some(checkpoint) = &self.governed_repair_checkpoint {
            checkpoint.validate()?;
        }
        if self.effect_scope_digest != self.effect_scope.digest() {
            return Err(KernelErrorV1::EffectScope("scope digest mismatch"));
        }
        Ok(())
    }

    /// Returns the exact campaign; occurrence binding is supplied separately
    /// by the authoritative occurrence state.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignId {
        &self.campaign
    }

    /// Returns the exact proposal identity.
    #[must_use]
    pub fn reference(&self) -> ProposalRefV1 {
        ProposalRefV1::from_digest(digest_value(PROPOSAL_DIGEST_DOMAIN_V1, self))
    }

    /// Returns the exact governed subject.
    #[must_use]
    pub const fn subject(&self) -> &Digest {
        &self.subject
    }

    /// Returns the exact governed scope.
    #[must_use]
    pub const fn effect_scope(&self) -> &CanonicalEffectScopeV1 {
        &self.effect_scope
    }

    /// Returns the mechanically derived exact scope digest.
    #[must_use]
    pub const fn scope(&self) -> &Digest {
        &self.effect_scope_digest
    }

    /// Binds an immutable successor checkpoint before proposal identity is
    /// derived.  This evidence grants no standing or effect authority.
    pub fn with_governed_repair_checkpoint(
        mut self,
        checkpoint: GovernedRepairCheckpointV1,
    ) -> Result<Self, KernelErrorV1> {
        checkpoint.validate()?;
        self.governed_repair_checkpoint = Some(checkpoint);
        self.validate()?;
        Ok(self)
    }

    /// Returns the immutable governed-repair checkpoint, when this is a
    /// disposition-constrained successor proposal.
    #[must_use]
    pub const fn governed_repair_checkpoint(&self) -> Option<&GovernedRepairCheckpointV1> {
        self.governed_repair_checkpoint.as_ref()
    }

    /// Derives the one exact pre-spend revised proposal by replacing only the
    /// immutable effect scope.  A post-spend checkpoint cannot be laundered
    /// through this authority-empty path.
    pub fn derive_pre_spend_revision(
        &self,
        revised_scope: CanonicalEffectScopeV1,
    ) -> Result<Self, KernelErrorV1> {
        self.validate()?;
        if self.governed_repair_checkpoint.is_some() {
            return Err(KernelErrorV1::Proposal(
                "pre-spend revision cannot inherit a governed-repair checkpoint",
            ));
        }
        revised_scope.validate()?;
        let mut revised = self.clone();
        revised.effect_scope_digest = revised_scope.digest();
        revised.effect_scope = revised_scope;
        revised.validate()?;
        Ok(revised)
    }

    /// Returns the typed work schema.
    #[must_use]
    pub fn work_schema(&self) -> &str {
        &self.work_schema
    }

    /// Returns the exact work payload digest.
    #[must_use]
    pub const fn work(&self) -> &Digest {
        &self.work
    }

    /// Returns the explicit sorted, duplicate-free nonclaim identities.
    #[must_use]
    pub fn nonclaims(&self) -> &[Digest] {
        &self.nonclaims
    }

    /// Returns the exclusive absolute proposal deadline.
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Returns an optional C1 repair citation.
    #[must_use]
    pub const fn repair(&self) -> Option<&C1RepairCitationV1> {
        self.repair.as_ref()
    }
}

/// Observation status returned by the external observation resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationStatusV1 {
    /// The exact observation remains current and fresh.
    Current,
    /// The observation is too old for consequence.
    Stale,
    /// A newer observation superseded it.
    Superseded,
    /// The observation contradicts the requested exact basis.
    Contradictory,
    /// No observation exists.
    Absent,
}

/// Exact observation/currentness record returned by an external resolver.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationResolutionV1 {
    /// Exact schema.
    pub schema: String,
    /// Occurrence being observed.
    pub key: OccurrenceKeyV1,
    /// Exact observation identity.
    pub observation: ObservationRefV1,
    /// Exact currentness/freshness witness.
    pub currentness: ObservationCurrentnessRefV1,
    /// Exact normalized relevant-precondition basis.
    pub normalized_preconditions: PreconditionBasisRefV1,
    /// Exact observed subject.
    pub subject: Digest,
    /// Resolver status.
    pub status: ObservationStatusV1,
    /// Resolver clock lower bound.
    pub resolved_at_unix_ms: u64,
    /// Exclusive freshness deadline.
    pub fresh_until_unix_ms: u64,
}

/// Exact request made to the external observation resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationResolutionRequestV1<'a> {
    /// Occurrence key.
    pub key: &'a OccurrenceKeyV1,
    /// Exact observation requested.
    pub observation: &'a ObservationRefV1,
    /// Exact expected subject.
    pub subject: &'a Digest,
    /// Consequence-time clock reading supplied by AG's clock boundary.
    pub now_unix_ms: u64,
}

/// External observation-currentness boundary.
pub trait ObservationResolverV1 {
    /// Resolves the exact observation now; the call itself is the live boundary.
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1>;
}

/// Standing status returned by the authoritative Standing/Docket resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StandingStatusV1 {
    /// Exact standing is current.
    Current,
    /// No applicable standing exists.
    Absent,
    /// Applicable standing was revoked.
    Revoked,
    /// A newer standing resolution superseded it.
    Superseded,
    /// Standing expired.
    Expired,
}

/// Historical record of one authoritative current-standing resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentStandingResolutionV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact resolution identity.
    pub resolution: StandingResolutionRefV1,
    /// Exact currentness witness.
    pub currentness: StandingCurrentnessRefV1,
    /// Exact mandate identity.
    pub mandate: MandateRefV1,
    /// Occurrence resolved.
    pub key: OccurrenceKeyV1,
    /// Exact observation basis.
    pub observation: ObservationRefV1,
    /// Exact proposal basis.
    pub proposal: ProposalRefV1,
    /// Exact subject.
    pub subject: Digest,
    /// Exact scope.
    pub scope: Digest,
    /// Resolver status.
    pub status: StandingStatusV1,
    /// Resolver clock lower bound.
    pub resolved_at_unix_ms: u64,
    /// Exclusive standing deadline.
    pub expires_at_unix_ms: u64,
}

/// Request made to the authoritative current-standing boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingResolutionRequestV1<'a> {
    /// Occurrence key.
    pub key: &'a OccurrenceKeyV1,
    /// Exact observation basis.
    pub observation: &'a ObservationRefV1,
    /// Exact proposal basis.
    pub proposal: &'a ProposalRefV1,
    /// Exact subject.
    pub subject: &'a Digest,
    /// Exact scope.
    pub scope: &'a Digest,
    /// Consequence-time clock reading.
    pub now_unix_ms: u64,
}

/// External current-standing boundary; serialized standing cannot implement a call.
pub trait StandingResolverV1 {
    /// Resolves current mandate/standing for exactly this basis.
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV1, ExternalBoundaryErrorV1>;
}

/// Closed result vocabulary for AG's exact-work admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AdmissionDispositionV1 {
    /// Exact work is admitted for possible one-use spend.
    Admitted,
    /// Exact work is refused.
    Refused,
    /// The evidence basis is contradictory.
    Contradiction,
}

/// Historical evidence of one AG admissibility decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecisionV1 {
    /// Exact decision identity.
    pub decision: AdmissionDecisionRefV1,
    /// Exact occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact observation.
    pub observation: ObservationRefV1,
    /// Exact proposal.
    pub proposal: ProposalRefV1,
    /// Exact standing resolution.
    pub standing_resolution: StandingResolutionRefV1,
    /// Closed decision.
    pub disposition: AdmissionDispositionV1,
    /// Exact policy/version basis.
    pub policy_basis: Digest,
}

/// Exact input to AG's application-specific admissibility policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissibilityRequestV1<'a> {
    /// Exact proposal.
    pub proposal: &'a ExactWorkProposalV1,
    /// Fresh observation resolution.
    pub observation: &'a ObservationResolutionV1,
    /// Current standing resolution.
    pub standing: &'a CurrentStandingResolutionV1,
    /// Optional controlling rejected-review basis for C1 repair.
    pub controlling_rejected_review: Option<&'a C1RejectedReviewBasisV1>,
}

/// Application-specific exact-work admissibility boundary owned by AG policy.
pub trait AdmissibilityDeciderV1 {
    /// Decides exact work against the complete exact basis.
    fn decide_admissibility(
        &mut self,
        request: &AdmissibilityRequestV1<'_>,
    ) -> Result<AdmissionDecisionV1, ExternalBoundaryErrorV1>;
}

/// Failure reported by an external resolver/decider without granting authority.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExternalBoundaryErrorV1 {
    /// The external boundary explicitly refused.
    #[error("external boundary refused ({code})")]
    Refused {
        /// Stable refusal code.
        code: String,
        /// Optional exact evidence identity.
        evidence: Option<Digest>,
    },
    /// The external boundary was unavailable; no stale representation is used.
    #[error("external boundary unavailable ({code})")]
    Unavailable {
        /// Stable unavailability code.
        code: String,
    },
}

/// Relationship between a continuation occurrence and its predecessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContinuationClassV1 {
    /// Same exact proposal may be reused only with unchanged fresh preconditions.
    Retry,
    /// Ordinary successor; a new proposal is required.
    Successor,
}

/// Exact typed reason for halting an unspent proposal before governance.  It
/// records discovery eligibility only and grants no observation, standing,
/// spend, issuance, or execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreSpendScopeInsufficiencyV1 {
    /// Exact schema.
    pub schema: String,
    /// Deterministic identity of every other field.
    pub insufficiency: PreSpendScopeInsufficiencyRefV1,
    /// Exact campaign and predecessor occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact recorded predecessor proposal.
    pub proposal: ProposalRefV1,
    /// Exact immutable predecessor scope identity.
    pub original_scope_identity: Digest,
    /// Exact external diagnostic/evidence basis.
    pub diagnostic_basis: Digest,
    /// Exact proposal-recorded state from which the halt was created.
    pub source_state_digest: Digest,
    /// Caller-chosen idempotency identity for this one typed halt.
    pub idempotency_key: Digest,
    /// Consequence time, bounded to the canonical JSON integer range.
    pub recorded_at_unix_ms: u64,
}

#[derive(Serialize)]
struct PreSpendScopeInsufficiencyIdentityBodyV1<'a> {
    schema: &'a str,
    key: &'a OccurrenceKeyV1,
    proposal: &'a ProposalRefV1,
    original_scope_identity: &'a Digest,
    diagnostic_basis: &'a Digest,
    source_state_digest: &'a Digest,
    idempotency_key: &'a Digest,
    recorded_at_unix_ms: u64,
}

impl PreSpendScopeInsufficiencyV1 {
    fn derived_reference(&self) -> PreSpendScopeInsufficiencyRefV1 {
        PreSpendScopeInsufficiencyRefV1::from_digest(digest_value(
            PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1,
            &PreSpendScopeInsufficiencyIdentityBodyV1 {
                schema: &self.schema,
                key: &self.key,
                proposal: &self.proposal,
                original_scope_identity: &self.original_scope_identity,
                diagnostic_basis: &self.diagnostic_basis,
                source_state_digest: &self.source_state_digest,
                idempotency_key: &self.idempotency_key,
                recorded_at_unix_ms: self.recorded_at_unix_ms,
            },
        ))
    }

    /// Revalidates the strict decoded marker without granting authority.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema(
                "pre-spend scope insufficiency",
            ));
        }
        validate_canonical_timestamp(
            self.recorded_at_unix_ms,
            "pre-spend halt time is not canonically representable",
        )?;
        if self.insufficiency != self.derived_reference() {
            return Err(KernelErrorV1::BindingMismatch(
                "pre-spend scope insufficiency identity",
            ));
        }
        Ok(())
    }

    /// Returns the exact marker identity.
    #[must_use]
    pub const fn reference(&self) -> &PreSpendScopeInsufficiencyRefV1 {
        &self.insufficiency
    }
}

/// Exact caller claims required to create one pre-spend discovery and revised
/// authority-empty occurrence.  Every predecessor claim is checked again by
/// the Store inside the committing transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreSpendScopeDiscoveryParametersV1 {
    /// Claimed exact predecessor occurrence.
    pub predecessor: OccurrenceKeyV1,
    /// Claimed exact predecessor proposal.
    pub original_proposal: ProposalRefV1,
    /// Claimed exact immutable predecessor scope identity.
    pub original_scope_identity: Digest,
    /// Claimed exact diagnostic basis pinned by the typed halt.
    pub diagnostic_basis: Digest,
    /// Exact newly discovered additive effects.
    pub requested_delta: CanonicalEffectScopeV1,
    /// Claimed exact original-plus-delta derivation.
    pub claimed_revised_scope: CanonicalEffectScopeV1,
    /// Claimed exact revised proposal identity.
    pub claimed_revised_proposal: ProposalRefV1,
    /// Complete claimed revised proposal record.
    pub exact_revised_proposal: ExactWorkProposalV1,
    /// Distinct revised occurrence identity.
    pub revised_occurrence: OccurrenceId,
    /// One exact idempotency identity.
    pub idempotency_key: Digest,
    /// Consequence time.
    pub recorded_at_unix_ms: u64,
}

/// Durable, non-authorizing record of one exact pre-spend scope discovery and
/// the mechanically derived revised proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreSpendScopeDiscoveryV1 {
    /// Exact schema.
    pub schema: String,
    /// Deterministic identity of every other field.
    pub discovery: PreSpendScopeDiscoveryRefV1,
    /// Caller idempotency identity.
    pub idempotency_key: Digest,
    /// Exact campaign and immutable predecessor occurrence.
    pub predecessor: OccurrenceKeyV1,
    /// Exact typed halt marker consumed by this discovery.
    pub insufficiency: PreSpendScopeInsufficiencyRefV1,
    /// Exact halted-state head.
    pub halted_state_digest: Digest,
    /// Exact pre-halt proposal-recorded head.
    pub source_state_digest: Digest,
    /// Exact immutable predecessor proposal identity and record.
    pub original_proposal: ProposalRefV1,
    /// Complete immutable predecessor proposal.
    pub exact_original_proposal: ExactWorkProposalV1,
    /// Exact immutable predecessor scope and identity.
    pub original_scope: CanonicalEffectScopeV1,
    /// Exact immutable predecessor scope identity.
    pub original_scope_identity: Digest,
    /// Exact newly discovered additive effects and identity.
    pub requested_delta: CanonicalEffectScopeV1,
    /// Exact requested-delta identity.
    pub requested_delta_identity: Digest,
    /// Exact mechanically derived revised scope and identity.
    pub revised_scope: CanonicalEffectScopeV1,
    /// Exact revised-scope identity.
    pub revised_scope_identity: Digest,
    /// Exact mechanically derived revised proposal identity and record.
    pub revised_proposal: ProposalRefV1,
    /// Complete exact revised proposal.
    pub exact_revised_proposal: ExactWorkProposalV1,
    /// Exact external diagnostic/evidence basis.
    pub diagnostic_basis: Digest,
    /// Distinct revised occurrence.
    pub revised_occurrence: OccurrenceId,
    /// Consequence time.
    pub recorded_at_unix_ms: u64,
}

#[derive(Serialize)]
struct PreSpendScopeDiscoveryIdentityBodyV1<'a> {
    schema: &'a str,
    idempotency_key: &'a Digest,
    predecessor: &'a OccurrenceKeyV1,
    insufficiency: &'a PreSpendScopeInsufficiencyRefV1,
    halted_state_digest: &'a Digest,
    source_state_digest: &'a Digest,
    original_proposal: &'a ProposalRefV1,
    exact_original_proposal: &'a ExactWorkProposalV1,
    original_scope: &'a CanonicalEffectScopeV1,
    original_scope_identity: &'a Digest,
    requested_delta: &'a CanonicalEffectScopeV1,
    requested_delta_identity: &'a Digest,
    revised_scope: &'a CanonicalEffectScopeV1,
    revised_scope_identity: &'a Digest,
    revised_proposal: &'a ProposalRefV1,
    exact_revised_proposal: &'a ExactWorkProposalV1,
    diagnostic_basis: &'a Digest,
    revised_occurrence: OccurrenceId,
    recorded_at_unix_ms: u64,
}

impl PreSpendScopeDiscoveryV1 {
    fn derived_reference(&self) -> PreSpendScopeDiscoveryRefV1 {
        PreSpendScopeDiscoveryRefV1::from_digest(digest_value(
            PRE_SPEND_SCOPE_DISCOVERY_SCHEMA_V1,
            &PreSpendScopeDiscoveryIdentityBodyV1 {
                schema: &self.schema,
                idempotency_key: &self.idempotency_key,
                predecessor: &self.predecessor,
                insufficiency: &self.insufficiency,
                halted_state_digest: &self.halted_state_digest,
                source_state_digest: &self.source_state_digest,
                original_proposal: &self.original_proposal,
                exact_original_proposal: &self.exact_original_proposal,
                original_scope: &self.original_scope,
                original_scope_identity: &self.original_scope_identity,
                requested_delta: &self.requested_delta,
                requested_delta_identity: &self.requested_delta_identity,
                revised_scope: &self.revised_scope,
                revised_scope_identity: &self.revised_scope_identity,
                revised_proposal: &self.revised_proposal,
                exact_revised_proposal: &self.exact_revised_proposal,
                diagnostic_basis: &self.diagnostic_basis,
                revised_occurrence: self.revised_occurrence,
                recorded_at_unix_ms: self.recorded_at_unix_ms,
            },
        ))
    }

    /// Revalidates every exact identity and mechanical derivation.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != PRE_SPEND_SCOPE_DISCOVERY_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema("pre-spend scope discovery"));
        }
        validate_canonical_timestamp(
            self.recorded_at_unix_ms,
            "pre-spend discovery time is not canonically representable",
        )?;
        self.exact_original_proposal.validate()?;
        if self.recorded_at_unix_ms >= self.exact_original_proposal.expires_at_unix_ms() {
            return Err(KernelErrorV1::Proposal(
                "expired proposal cannot create pre-spend revision",
            ));
        }
        self.exact_revised_proposal.validate()?;
        self.original_scope.validate()?;
        self.requested_delta.validate()?;
        self.revised_scope.validate()?;
        let derived_scope = self
            .original_scope
            .exact_additive_union(&self.requested_delta)?;
        let derived_proposal = self
            .exact_original_proposal
            .derive_pre_spend_revision(derived_scope.clone())?;
        if self.predecessor.campaign != *self.exact_original_proposal.campaign()
            || self.original_proposal != self.exact_original_proposal.reference()
            || self.original_scope != *self.exact_original_proposal.effect_scope()
            || self.original_scope_identity != self.original_scope.digest()
            || self.requested_delta_identity != self.requested_delta.digest()
            || self.revised_scope != derived_scope
            || self.revised_scope_identity != self.revised_scope.digest()
            || self.exact_revised_proposal != derived_proposal
            || self.revised_proposal != self.exact_revised_proposal.reference()
            || self.discovery != self.derived_reference()
            || self.revised_occurrence == self.predecessor.occurrence
        {
            return Err(KernelErrorV1::BindingMismatch(
                "pre-spend scope discovery derivation",
            ));
        }
        Ok(())
    }

    /// Returns the exact discovery identity.
    #[must_use]
    pub const fn reference(&self) -> &PreSpendScopeDiscoveryRefV1 {
        &self.discovery
    }

    /// Returns the exact revised proposal reference.
    #[must_use]
    pub const fn revised_proposal(&self) -> &ProposalRefV1 {
        &self.revised_proposal
    }

    /// Returns the complete exact revised proposal.
    #[must_use]
    pub const fn exact_revised_proposal(&self) -> &ExactWorkProposalV1 {
        &self.exact_revised_proposal
    }
}

/// Nonauthorizing lineage constraint carried by the fresh revised occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreSpendRevisionConstraintV1 {
    /// Immutable predecessor occurrence.
    predecessor: OccurrenceKeyV1,
    /// Exact discovery artifact.
    discovery: PreSpendScopeDiscoveryRefV1,
    /// Exact proposal that ordinary fresh governance must later record.
    revised_proposal: ProposalRefV1,
    /// Complete exact proposal pinned for hostile revalidation.
    exact_revised_proposal: ExactWorkProposalV1,
}

impl PreSpendRevisionConstraintV1 {
    /// Returns the immutable predecessor key.
    #[must_use]
    pub const fn predecessor(&self) -> &OccurrenceKeyV1 {
        &self.predecessor
    }

    /// Returns the exact discovery artifact reference.
    #[must_use]
    pub const fn discovery(&self) -> &PreSpendScopeDiscoveryRefV1 {
        &self.discovery
    }

    /// Returns the exact revised proposal reference.
    #[must_use]
    pub const fn revised_proposal(&self) -> &ProposalRefV1 {
        &self.revised_proposal
    }

    /// Returns the complete exact revised proposal.
    #[must_use]
    pub const fn exact_revised_proposal(&self) -> &ExactWorkProposalV1 {
        &self.exact_revised_proposal
    }
}

/// Closed externally approved basis for one distinct successor occurrence.
/// It constrains the next proposal but carries no standing or reusable effect
/// authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizedSuccessorBasisV1 {
    /// Human approval of exactly one additive scope delta and exact union.
    ExactScopeExpansion {
        /// Exact request consumed by the decision.
        request: HumanDecisionRequestRefV1,
        /// Exact external disposition.
        disposition: HumanDispositionRefV1,
        /// Immutable original scope.
        original_scope: CanonicalEffectScopeV1,
        /// Exact approved delta.
        approved_delta: CanonicalEffectScopeV1,
        /// Mechanically checked union required of the successor proposal.
        successor_scope: CanonicalEffectScopeV1,
        /// Immutable successor source checkpoint approved by the disposition.
        checkpoint: GovernedRepairCheckpointV1,
    },
    /// Human order to obtain a new normative adjudication under an exact
    /// program basis.  It does not decide that question itself.
    Readjudication {
        /// Exact request consumed by the decision.
        request: HumanDecisionRequestRefV1,
        /// Exact external disposition.
        disposition: HumanDispositionRefV1,
        /// Exact successor program basis.
        successor_program: ProgramBasisRefV1,
        /// Exact read-only scope of the fresh adjudication occurrence.
        adjudication_scope: CanonicalEffectScopeV1,
        /// Immutable successor source checkpoint approved by the disposition.
        checkpoint: GovernedRepairCheckpointV1,
    },
}

/// Exact predecessor basis retained for continuation classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorOccurrenceBasisV1 {
    /// Prior occurrence key.
    pub key: OccurrenceKeyV1,
    /// Prior proposal, when the predecessor reached proposal recording.
    pub proposal: Option<ProposalRefV1>,
    /// Complete immutable proposal contract retained for product projection
    /// and hostile revalidation; its identity must equal `proposal`.
    pub proposal_contract: Option<ExactWorkProposalV1>,
    /// Prior normalized preconditions, when observed.
    pub normalized_preconditions: Option<PreconditionBasisRefV1>,
    /// Exact predecessor scope, when a proposal was present.
    pub effect_scope: Option<CanonicalEffectScopeV1>,
    /// Exact consumed issuance, when execution custody was reached.
    pub issuance: Option<AgIssuanceRefV1>,
    /// Exact Docket custody, when execution custody was reached.
    pub docket_custody: Option<DocketCustodyRefV1>,
    /// Exact Docket attempt, when execution custody was reached.
    pub docket_attempt: Option<DocketAttemptRefV1>,
    /// Exact predecessor state digest.
    pub state_digest: Digest,
    /// Optional exact human-governed successor constraint.  This is lineage
    /// evidence only; fresh observation, standing, and admission remain due.
    pub authorized_successor: Option<AuthorizedSuccessorBasisV1>,
    /// Optional exact pre-spend revision constraint.  This is immutable
    /// lineage and proposal evidence only; it is disjoint from externally
    /// authorized post-spend successor bases.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub pre_spend_revision: Option<PreSpendRevisionConstraintV1>,
}

/// Occurrence linkage; authority never travels through this record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OccurrenceLinkV1 {
    /// First occurrence in the campaign.
    Initial,
    /// Retry of a distinct predecessor.
    RetryOf(OccurrenceKeyV1),
    /// Ordinary successor of a distinct predecessor.
    SuccessorOf(OccurrenceKeyV1),
}

/// Shared durable coordinates present in every program-counter state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceMetaV1 {
    key: OccurrenceKeyV1,
    program: ProgramBasisRefV1,
    residuals: ResidualSetV1,
    budget: LoopBudgetV1,
    used_human_decisions: Vec<HumanDecisionIdV1>,
}

impl OccurrenceMetaV1 {
    /// Returns the exact occurrence key.
    #[must_use]
    pub const fn key(&self) -> &OccurrenceKeyV1 {
        &self.key
    }

    /// Returns the exact program basis.
    #[must_use]
    pub const fn program(&self) -> &ProgramBasisRefV1 {
        &self.program
    }

    /// Returns all open residuals.
    #[must_use]
    pub const fn residuals(&self) -> &ResidualSetV1 {
        &self.residuals
    }

    /// Returns durable budget facts.
    #[must_use]
    pub const fn budget(&self) -> LoopBudgetV1 {
        self.budget
    }

    /// Returns consumed human-decision identities.
    #[must_use]
    pub fn used_human_decisions(&self) -> &[HumanDecisionIdV1] {
        &self.used_human_decisions
    }
}

/// State requiring a fresh observation and proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRequiredV1 {
    meta: OccurrenceMetaV1,
    prior: Option<PriorOccurrenceBasisV1>,
}

/// Exact fresh observation/proposal basis, containing no authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalBasisV1 {
    meta: OccurrenceMetaV1,
    observation: ObservationResolutionV1,
    proposal: ExactWorkProposalV1,
    proposal_ref: ProposalRefV1,
    link: OccurrenceLinkV1,
}

/// Proposal-recorded state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProposalRecordedV1(ProposalBasisV1);

/// Standing-required state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StandingRequiredV1(ProposalBasisV1);

/// Positive decision basis; still contains no consumed AG authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissibleBasisV1 {
    proposal: ProposalBasisV1,
    standing: CurrentStandingResolutionV1,
    decision: AdmissionDecisionV1,
}

/// Admitted-but-unspent state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmissiblePendingAuthorizationV1(AdmissibleBasisV1);

/// Durable one-use AG authorization spend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgAuthorizationSpendV1 {
    /// Exact AG authorization identity.
    pub authorization: AgAuthorizationRefV1,
    /// Exact spend identity.
    pub spend: AgSpendRefV1,
    /// Exact occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact observation.
    pub observation: ObservationRefV1,
    /// Exact proposal.
    pub proposal: ProposalRefV1,
    /// Exact current standing resolution used at spend.
    pub standing_resolution: StandingResolutionRefV1,
    /// Exact positive decision used at spend.
    pub admission_decision: AdmissionDecisionRefV1,
    /// Durable transaction time (a fact, not expiry authority).
    pub consumed_at_unix_ms: u64,
}

/// Deterministic exact issuance reconstructible from authoritative state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuanceV2 {
    /// Exact schema.
    pub schema: String,
    /// Exact deterministic issuance identity.
    pub issuance: AgIssuanceRefV1,
    /// Exact occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact program basis.
    pub program: ProgramBasisRefV1,
    /// Exact proposal.
    pub proposal: ProposalRefV1,
    /// Exact typed work schema selected by AG admission.
    pub work_schema: String,
    /// Exact work payload.
    pub work: Digest,
    /// Explicit immutable nonclaims inherited from the exact proposal.
    pub nonclaims: Vec<Digest>,
    /// Exclusive absolute deadline inherited from the exact proposal.
    pub expires_at_unix_ms: u64,
    /// Exact governed subject.
    pub subject: Digest,
    /// Exact structured governed effect scope.
    pub effect_scope: CanonicalEffectScopeV1,
    /// Mechanically derived identity of `effect_scope`.
    pub effect_scope_digest: Digest,
    /// Immutable governed-repair checkpoint when this is a constrained
    /// successor issuance.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub governed_repair_checkpoint: Option<GovernedRepairCheckpointV1>,
    /// Exact observation.
    pub observation: ObservationRefV1,
    /// Exact standing resolution.
    pub standing_resolution: StandingResolutionRefV1,
    /// Exact positive AG admission decision authorizing this issuance basis.
    pub admission_decision: AdmissionDecisionV1,
    /// Exact mandate reference (evidence only for Docket binding).
    pub mandate: MandateRefV1,
    /// Exact AG spend.
    pub spend: AgSpendRefV1,
}

/// Spent authorization state; only exact Docket custody/reconciliation is legal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConsumedV1 {
    admitted: AdmissibleBasisV1,
    spend: AgAuthorizationSpendV1,
    issuance: AgIssuanceV2,
}

/// Docket's exact custody acceptance for one AG issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketCustodyV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact AG issuance accepted.
    pub issuance: AgIssuanceRefV1,
    /// Exact AG spend echoed only for binding.
    pub ag_spend: AgSpendRefV1,
    /// Docket-owned execution standing consumed for custody.
    pub execution_standing: DocketExecutionStandingRefV1,
    /// Docket's exact currentness record for that standing.
    pub standing_currentness: StandingCurrentnessRefV1,
    /// Docket-owned canonical attempt.
    pub attempt: DocketAttemptRefV1,
    /// Exact executor-local attempt marker.
    pub executor_marker: ExecutorAttemptMarkerRefV1,
    /// Custody acceptance time.
    pub accepted_at_unix_ms: u64,
}

impl DocketCustodyV1 {
    /// Returns the exact canonical custody-record identity.
    #[must_use]
    pub fn reference(&self) -> DocketCustodyRefV1 {
        DocketCustodyRefV1::from_digest(digest_value(DOCKET_CUSTODY_SCHEMA_V1, self))
    }
}

/// Dispatch basis retained after Docket accepts custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchBasisV1 {
    authorized: AuthorizationConsumedV1,
    custody: DocketCustodyV1,
}

/// Dispatched state; no reusable authority remains in AG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DispatchedV1(DispatchBasisV1);

/// Known Docket settlement outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KnownOutcomeV1 {
    /// Exact effect succeeded.
    Success,
    /// Exact effect failed with a known outcome.
    Failure,
}

/// Exact Docket settlement evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketSettlementV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact settlement identity.
    pub settlement: SettlementRefV1,
    /// Exact issuance.
    pub issuance: AgIssuanceRefV1,
    /// Exact attempt.
    pub attempt: DocketAttemptRefV1,
    /// Exact executor marker.
    pub executor_marker: ExecutorAttemptMarkerRefV1,
    /// Exact receipt.
    pub receipt: ReceiptRefV1,
    /// Known outcome.
    pub outcome: KnownOutcomeV1,
    /// Exact Docket-owned cumulative ordered attempt-journal identity. Absent
    /// only in explicitly decoded rejected-R1 historical rows; every R2
    /// production wire and transition requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cumulative_effect_journal_identity: Option<Digest>,
    /// Docket settlement time.
    pub settled_at_unix_ms: u64,
}

#[derive(Serialize)]
struct DocketSettlementIdentityBodyV1<'a> {
    schema: &'a str,
    issuance: &'a AgIssuanceRefV1,
    attempt: &'a DocketAttemptRefV1,
    executor_marker: &'a ExecutorAttemptMarkerRefV1,
    receipt: &'a ReceiptRefV1,
    outcome: KnownOutcomeV1,
    cumulative_effect_journal_identity: &'a Digest,
    settled_at_unix_ms: u64,
}

impl DocketSettlementV1 {
    /// Reproduces the exact Docket settlement identity from every canonical
    /// consequence-bearing field except the identity itself.
    pub fn expected_reference(&self) -> Result<SettlementRefV1, KernelErrorV1> {
        validate_canonical_timestamp(
            self.settled_at_unix_ms,
            "Docket settlement time is not canonically representable",
        )?;
        let journal = self.cumulative_effect_journal_identity.as_ref().ok_or(
            KernelErrorV1::BindingMismatch("R2 cumulative Docket effect journal"),
        )?;
        Ok(SettlementRefV1::from_digest(digest_value(
            DOCKET_SETTLEMENT_IDENTITY_DOMAIN_V1,
            &DocketSettlementIdentityBodyV1 {
                schema: &self.schema,
                issuance: &self.issuance,
                attempt: &self.attempt,
                executor_marker: &self.executor_marker,
                receipt: &self.receipt,
                outcome: self.outcome,
                cumulative_effect_journal_identity: journal,
                settled_at_unix_ms: self.settled_at_unix_ms,
            },
        )))
    }
}

/// Exact caller input used to create or replay one intentional reconciliation
/// round.  This is a non-authorizing idempotency coordinate; the Store derives
/// and persists the complete request before a signer may authenticate it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRoundParametersV1 {
    /// Exact caller state/head cut.
    pub expected_state_digest: Digest,
    /// Caller-selected exact replay identity. It grants no authority.
    pub idempotency: Digest,
}

/// One explicit, canonical AG request for a Docket reconciliation poll.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRoundRequestV1 {
    /// Exact schema.
    pub schema: String,
    /// Complete request identity.
    pub request: ReconciliationRoundRequestRefV1,
    /// Intentional poll occurrence identity.
    pub round: ReconciliationRoundRefV1,
    /// Exact already-spent issuance.
    pub issuance: AgIssuanceRefV1,
    /// Exact Docket attempt.
    pub attempt: DocketAttemptRefV1,
    /// Exact caller-observed AG state before request preparation.
    pub caller_state_digest: Digest,
    /// Immediately preceding completed round, omitted for the first round.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_round: Option<ReconciliationRoundRefV1>,
    /// Result of the immediately preceding completed indeterminate round.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_reconciliation: Option<ReconciliationRefV1>,
    /// Exact non-authorizing replay coordinate.
    pub idempotency: Digest,
}

#[derive(Serialize)]
struct ReconciliationRoundIdentityBodyV1<'a> {
    schema: &'a str,
    issuance: &'a AgIssuanceRefV1,
    attempt: &'a DocketAttemptRefV1,
    caller_state_digest: &'a Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_round: Option<&'a ReconciliationRoundRefV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_reconciliation: Option<&'a ReconciliationRefV1>,
    idempotency: &'a Digest,
}

#[derive(Serialize)]
struct ReconciliationRoundRequestIdentityBodyV1<'a> {
    schema: &'a str,
    round: &'a ReconciliationRoundRefV1,
    issuance: &'a AgIssuanceRefV1,
    attempt: &'a DocketAttemptRefV1,
    caller_state_digest: &'a Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_round: Option<&'a ReconciliationRoundRefV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_reconciliation: Option<&'a ReconciliationRefV1>,
    idempotency: &'a Digest,
}

impl ReconciliationRoundRequestV1 {
    /// Constructs a request with both identities derived from its exact body.
    #[must_use]
    pub fn new(
        issuance: AgIssuanceRefV1,
        attempt: DocketAttemptRefV1,
        caller_state_digest: Digest,
        predecessor_round: Option<ReconciliationRoundRefV1>,
        predecessor_reconciliation: Option<ReconciliationRefV1>,
        idempotency: Digest,
    ) -> Self {
        let schema = RECONCILIATION_ROUND_REQUEST_SCHEMA_V1.to_owned();
        let round = ReconciliationRoundRefV1::from_digest(digest_value(
            RECONCILIATION_ROUND_DIGEST_DOMAIN_V1,
            &ReconciliationRoundIdentityBodyV1 {
                schema: &schema,
                issuance: &issuance,
                attempt: &attempt,
                caller_state_digest: &caller_state_digest,
                predecessor_round: predecessor_round.as_ref(),
                predecessor_reconciliation: predecessor_reconciliation.as_ref(),
                idempotency: &idempotency,
            },
        ));
        let request = ReconciliationRoundRequestRefV1::from_digest(digest_value(
            RECONCILIATION_ROUND_REQUEST_DIGEST_DOMAIN_V1,
            &ReconciliationRoundRequestIdentityBodyV1 {
                schema: &schema,
                round: &round,
                issuance: &issuance,
                attempt: &attempt,
                caller_state_digest: &caller_state_digest,
                predecessor_round: predecessor_round.as_ref(),
                predecessor_reconciliation: predecessor_reconciliation.as_ref(),
                idempotency: &idempotency,
            },
        ));
        Self {
            schema,
            request,
            round,
            issuance,
            attempt,
            caller_state_digest,
            predecessor_round,
            predecessor_reconciliation,
            idempotency,
        }
    }

    /// Strictly validates schema, paired predecessor fields, and both
    /// deterministic identities.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != RECONCILIATION_ROUND_REQUEST_SCHEMA_V1
            || self.predecessor_round.is_some() != self.predecessor_reconciliation.is_some()
        {
            return Err(KernelErrorV1::BindingMismatch(
                "reconciliation round request shape",
            ));
        }
        let expected = Self::new(
            self.issuance.clone(),
            self.attempt.clone(),
            self.caller_state_digest.clone(),
            self.predecessor_round.clone(),
            self.predecessor_reconciliation.clone(),
            self.idempotency.clone(),
        );
        if expected.round != self.round || expected.request != self.request {
            return Err(KernelErrorV1::BindingMismatch(
                "reconciliation round request identity",
            ));
        }
        Ok(())
    }
}

/// Docket's exact durable reservation for one request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketReconciliationRoundReservationV1 {
    /// Exact schema.
    pub schema: String,
    /// Docket reservation identity.
    pub reservation: DocketReconciliationReservationRefV1,
    /// Exact AG request identity.
    pub request: ReconciliationRoundRequestRefV1,
    /// Exact intentional reconciliation round.
    pub round: ReconciliationRoundRefV1,
    /// Exact already-spent issuance.
    pub issuance: AgIssuanceRefV1,
    /// Exact Docket attempt.
    pub attempt: DocketAttemptRefV1,
    /// Caller-observed AG cut authenticated by the request.
    pub caller_state_digest: Digest,
    /// Immediately preceding completed round, when this is a later poll.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_round: Option<ReconciliationRoundRefV1>,
    /// Result of the immediately preceding completed indeterminate round.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_reconciliation: Option<ReconciliationRefV1>,
    /// Exact Docket source cut claimed before crossing the executor boundary.
    pub source_cut: Digest,
    /// Immutable checkpoint identity, when the attempt has one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub checkpoint_identity: Option<Digest>,
    /// Exact executor binding.
    pub executor_binding: Digest,
    /// Canonically representable claim time.
    pub claimed_at_unix_ms: u64,
}

/// Docket's exact completion for one previously committed reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketReconciliationRoundCompletionV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact completion identity.
    pub completion: DocketReconciliationCompletionRefV1,
    /// Exact claimed reservation.
    pub reservation: DocketReconciliationReservationRefV1,
    /// Exact intentional reconciliation round.
    pub round: ReconciliationRoundRefV1,
    /// Exact terminal or indeterminate result identity.
    pub result_identity: Digest,
    /// Canonically representable completion time.
    pub completed_at_unix_ms: u64,
}

#[derive(Serialize)]
struct DocketReconciliationReservationIdentityBasisV1<'a> {
    schema: &'a str,
    request: &'a ReconciliationRoundRequestRefV1,
    round: &'a ReconciliationRoundRefV1,
    issuance: &'a AgIssuanceRefV1,
    attempt: &'a DocketAttemptRefV1,
    caller_state_digest: &'a Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_round: Option<&'a ReconciliationRoundRefV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_reconciliation: Option<&'a ReconciliationRefV1>,
    source_cut: &'a Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_identity: Option<&'a Digest>,
    executor_binding: &'a Digest,
    claimed_at_unix_ms: u64,
}

#[derive(Serialize)]
struct DocketReconciliationCompletionIdentityBasisV1<'a> {
    schema: &'a str,
    reservation: &'a DocketReconciliationReservationRefV1,
    round: &'a ReconciliationRoundRefV1,
    result_identity: &'a Digest,
    completed_at_unix_ms: u64,
}

/// Durable AG observation of the latest round. Prepared and unresolved rounds
/// are not authority and cannot enable a later round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ReconciliationRoundStateV1 {
    /// Docket durably claimed the request, but no completed response is known.
    Unresolved {
        /// Exact authenticated AG request.
        request: ReconciliationRoundRequestV1,
        /// Exact Docket claim.
        reservation: DocketReconciliationRoundReservationV1,
    },
    /// Docket completed the round with another indeterminate observation.
    CompletedIndeterminate {
        /// Exact authenticated AG request.
        request: ReconciliationRoundRequestV1,
        /// Exact Docket claim.
        reservation: DocketReconciliationRoundReservationV1,
        /// Exact Docket completion.
        completion: DocketReconciliationRoundCompletionV1,
    },
}

/// Exact indeterminate-attempt evidence requiring reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndeterminateOutcomeV1 {
    /// Exact issuance.
    pub issuance: AgIssuanceRefV1,
    /// Exact attempt.
    pub attempt: DocketAttemptRefV1,
    /// Exact read-only reconciliation identity.
    pub reconciliation: ReconciliationRefV1,
    /// Exact evidence explaining indeterminacy.
    pub evidence: Digest,
}

/// State requiring exact read-only reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRequiredV1 {
    dispatch: DispatchBasisV1,
    indeterminate: IndeterminateOutcomeV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    reconciliation_round: Option<ReconciliationRoundStateV1>,
}

/// State carrying an exact known settlement and requiring fresh observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettledObservationRequiredV1 {
    dispatch: DispatchBasisV1,
    settlement: DocketSettlementV1,
}

/// Durable authority history retained through halt/completion.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHistoryV1 {
    /// AG spend, once any.
    pub ag_spend: Option<AgSpendRefV1>,
    /// Docket attempt, once any.
    pub docket_attempt: Option<DocketAttemptRefV1>,
    /// Settlement, once any.
    pub settlement: Option<SettlementRefV1>,
    /// Receipt, once any.
    pub receipt: Option<ReceiptRefV1>,
}

/// Durable halted state; it has no effect-producing transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaltedV1 {
    meta: OccurrenceMetaV1,
    source: ProgramCounterV1,
    reason: HaltReasonRefV1,
    prior: PriorOccurrenceBasisV1,
    unresolved_attempt: Option<DocketAttemptRefV1>,
    history: AuthorityHistoryV1,
    /// Exact governed-repair requirement that caused this halt.  This is
    /// durable evidence pinned into the halted-state digest; it is never a
    /// disposition or authority instrument.
    governed_repair_requirement: Option<HumanDecisionRequirementV1>,
    governed_repair_closed: Option<GovernedRepairClosedV1>,
    /// Exact Docket-owned refusal that terminalized a consumed issuance before
    /// custody, when this is that halt class.
    docket_issuance_refusal: Option<DocketIssuanceRefusalV1>,
    /// Exact typed pre-spend scope-insufficiency marker.  Generic and
    /// post-spend halts omit this field, preserving the R3 wire form.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pre_spend_scope_insufficiency: Option<PreSpendScopeInsufficiencyV1>,
}

/// Durable terminal/refused result for one rejected governed-repair request.
/// It grants no authority and permanently closes successor creation from this
/// halted occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairClosedV1 {
    /// Exact rejected request.
    pub request: HumanDecisionRequestRefV1,
    /// Exact external disposition artifact.
    pub disposition: HumanDispositionRefV1,
    /// Exact rejection rationale.
    pub reason: Digest,
    /// Exact residual obligation recording unresolved work.
    pub residual: ResidualIdV1,
}

/// Durable completed state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedV1 {
    meta: OccurrenceMetaV1,
    terminal_observation: ObservationResolutionV1,
    terminal_witness: TerminalWitnessRefV1,
    history: AuthorityHistoryV1,
    proposal_contract: Option<ExactWorkProposalV1>,
}

/// Closed typed state sum for one occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OccurrenceStateV1 {
    /// Fresh observation required.
    ObservationRequired(ObservationRequiredV1),
    /// Proposal recorded, no authority.
    ProposalRecorded(ProposalRecordedV1),
    /// Current standing required, no authority.
    StandingRequired(StandingRequiredV1),
    /// Positive decision recorded, authorization unspent.
    AdmissiblePendingAuthorization(AdmissiblePendingAuthorizationV1),
    /// AG authorization spent.
    AuthorizationConsumed(AuthorizationConsumedV1),
    /// Docket custody accepted.
    Dispatched(DispatchedV1),
    /// Exact attempt reconciliation required.
    ReconciliationRequired(ReconciliationRequiredV1),
    /// Exact known settlement recorded; fresh observation required.
    SettledObservationRequired(SettledObservationRequiredV1),
    /// Halted and non-effecting.
    Halted(HaltedV1),
    /// Terminal.
    Completed(CompletedV1),
}

impl OccurrenceStateV1 {
    /// Returns the program-counter discriminator.
    #[must_use]
    pub const fn program_counter(&self) -> ProgramCounterV1 {
        match self {
            Self::ObservationRequired(_) => ProgramCounterV1::ObservationRequired,
            Self::ProposalRecorded(_) => ProgramCounterV1::ProposalRecorded,
            Self::StandingRequired(_) => ProgramCounterV1::StandingRequired,
            Self::AdmissiblePendingAuthorization(_) => {
                ProgramCounterV1::AdmissiblePendingAuthorization
            }
            Self::AuthorizationConsumed(_) => ProgramCounterV1::AuthorizationConsumed,
            Self::Dispatched(_) => ProgramCounterV1::Dispatched,
            Self::ReconciliationRequired(_) => ProgramCounterV1::ReconciliationRequired,
            Self::SettledObservationRequired(_) => ProgramCounterV1::SettledObservationRequired,
            Self::Halted(_) => ProgramCounterV1::Halted,
            Self::Completed(_) => ProgramCounterV1::Completed,
        }
    }

    /// Returns shared exact coordinates.
    #[must_use]
    pub const fn meta(&self) -> &OccurrenceMetaV1 {
        match self {
            Self::ObservationRequired(value) => &value.meta,
            Self::ProposalRecorded(value) => &value.0.meta,
            Self::StandingRequired(value) => &value.0.meta,
            Self::AdmissiblePendingAuthorization(value) => &value.0.proposal.meta,
            Self::AuthorizationConsumed(value) => &value.admitted.proposal.meta,
            Self::Dispatched(value) => &value.0.authorized.admitted.proposal.meta,
            Self::ReconciliationRequired(value) => {
                &value.dispatch.authorized.admitted.proposal.meta
            }
            Self::SettledObservationRequired(value) => {
                &value.dispatch.authorized.admitted.proposal.meta
            }
            Self::Halted(value) => &value.meta,
            Self::Completed(value) => &value.meta,
        }
    }

    fn meta_mut(&mut self) -> &mut OccurrenceMetaV1 {
        match self {
            Self::ObservationRequired(value) => &mut value.meta,
            Self::ProposalRecorded(value) => &mut value.0.meta,
            Self::StandingRequired(value) => &mut value.0.meta,
            Self::AdmissiblePendingAuthorization(value) => &mut value.0.proposal.meta,
            Self::AuthorizationConsumed(value) => &mut value.admitted.proposal.meta,
            Self::Dispatched(value) => &mut value.0.authorized.admitted.proposal.meta,
            Self::ReconciliationRequired(value) => {
                &mut value.dispatch.authorized.admitted.proposal.meta
            }
            Self::SettledObservationRequired(value) => {
                &mut value.dispatch.authorized.admitted.proposal.meta
            }
            Self::Halted(value) => &mut value.meta,
            Self::Completed(value) => &mut value.meta,
        }
    }

    /// Returns retained authority history, all of which is evidence only.
    #[must_use]
    pub fn authority_history(&self) -> AuthorityHistoryV1 {
        match self {
            Self::AuthorizationConsumed(value) => AuthorityHistoryV1 {
                ag_spend: Some(value.spend.spend.clone()),
                ..AuthorityHistoryV1::default()
            },
            Self::Dispatched(value) => AuthorityHistoryV1 {
                ag_spend: Some(value.0.authorized.spend.spend.clone()),
                docket_attempt: Some(value.0.custody.attempt.clone()),
                ..AuthorityHistoryV1::default()
            },
            Self::ReconciliationRequired(value) => AuthorityHistoryV1 {
                ag_spend: Some(value.dispatch.authorized.spend.spend.clone()),
                docket_attempt: Some(value.dispatch.custody.attempt.clone()),
                ..AuthorityHistoryV1::default()
            },
            Self::SettledObservationRequired(value) => AuthorityHistoryV1 {
                ag_spend: Some(value.dispatch.authorized.spend.spend.clone()),
                docket_attempt: Some(value.dispatch.custody.attempt.clone()),
                settlement: Some(value.settlement.settlement.clone()),
                receipt: Some(value.settlement.receipt.clone()),
            },
            Self::Halted(value) => value.history.clone(),
            Self::Completed(value) => value.history.clone(),
            _ => AuthorityHistoryV1::default(),
        }
    }

    fn proposal_basis(&self) -> Option<&ProposalBasisV1> {
        match self {
            Self::ProposalRecorded(value) => Some(&value.0),
            Self::StandingRequired(value) => Some(&value.0),
            Self::AdmissiblePendingAuthorization(value) => Some(&value.0.proposal),
            Self::AuthorizationConsumed(value) => Some(&value.admitted.proposal),
            Self::Dispatched(value) => Some(&value.0.authorized.admitted.proposal),
            Self::ReconciliationRequired(value) => {
                Some(&value.dispatch.authorized.admitted.proposal)
            }
            Self::SettledObservationRequired(value) => {
                Some(&value.dispatch.authorized.admitted.proposal)
            }
            _ => None,
        }
    }

    fn admissible_basis(&self) -> Option<&AdmissibleBasisV1> {
        match self {
            Self::AdmissiblePendingAuthorization(value) => Some(&value.0),
            Self::AuthorizationConsumed(value) => Some(&value.admitted),
            Self::Dispatched(value) => Some(&value.0.authorized.admitted),
            Self::ReconciliationRequired(value) => Some(&value.dispatch.authorized.admitted),
            Self::SettledObservationRequired(value) => Some(&value.dispatch.authorized.admitted),
            _ => None,
        }
    }

    fn issuance(&self) -> Option<&AgIssuanceV2> {
        match self {
            Self::AuthorizationConsumed(value) => Some(&value.issuance),
            Self::Dispatched(value) => Some(&value.0.authorized.issuance),
            Self::ReconciliationRequired(value) => Some(&value.dispatch.authorized.issuance),
            Self::SettledObservationRequired(value) => Some(&value.dispatch.authorized.issuance),
            _ => None,
        }
    }

    fn docket_custody(&self) -> Option<&DocketCustodyV1> {
        match self {
            Self::Dispatched(value) => Some(&value.0.custody),
            Self::ReconciliationRequired(value) => Some(&value.dispatch.custody),
            Self::SettledObservationRequired(value) => Some(&value.dispatch.custody),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct StateDigestInputV1<'a> {
    prior_state_digest: &'a Digest,
    state: &'a OccurrenceStateV1,
}

/// Authoritative immutable snapshot of one occurrence program-counter state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceSnapshotV1 {
    prior_state_digest: Digest,
    state_digest: Digest,
    state: OccurrenceStateV1,
}

impl OccurrenceSnapshotV1 {
    /// Returns the predecessor state digest.
    #[must_use]
    pub const fn prior_state_digest(&self) -> &Digest {
        &self.prior_state_digest
    }

    /// Returns the authoritative current state digest.
    #[must_use]
    pub const fn state_digest(&self) -> &Digest {
        &self.state_digest
    }

    /// Returns the typed state.
    #[must_use]
    pub const fn state(&self) -> &OccurrenceStateV1 {
        &self.state
    }

    /// Returns the current program counter.
    #[must_use]
    pub const fn program_counter(&self) -> ProgramCounterV1 {
        self.state.program_counter()
    }

    /// Returns the exact occurrence key.
    #[must_use]
    pub const fn key(&self) -> &OccurrenceKeyV1 {
        self.state.meta().key()
    }

    /// Verifies digest and structural invariants without granting authority.
    pub fn validate_integrity(&self) -> Result<(), KernelErrorV1> {
        self.state.meta().budget.validate()?;
        ResidualSetV1::new(self.state.meta().residuals.0.clone())?;
        let expected = state_digest(&self.prior_state_digest, &self.state);
        if expected != self.state_digest {
            return Err(KernelErrorV1::StateDigestMismatch);
        }
        if let OccurrenceStateV1::ObservationRequired(pending) = &self.state
            && let Some(prior) = &pending.prior
            && prior.state_digest != self.prior_state_digest
        {
            return Err(KernelErrorV1::StateInvariant(
                "continuation predecessor digest",
            ));
        }
        validate_state(&self.state)
    }
}

fn state_digest(prior: &Digest, state: &OccurrenceStateV1) -> Digest {
    digest_value(
        STATE_DIGEST_DOMAIN_V1,
        &StateDigestInputV1 {
            prior_state_digest: prior,
            state,
        },
    )
}

fn successor_snapshot(
    prior: &OccurrenceSnapshotV1,
    state: OccurrenceStateV1,
) -> OccurrenceSnapshotV1 {
    let prior_state_digest = prior.state_digest.clone();
    let state_digest = state_digest(&prior_state_digest, &state);
    OccurrenceSnapshotV1 {
        prior_state_digest,
        state_digest,
        state,
    }
}

/// Durable refusal code. A refusal is never a program-counter state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RefusalCodeV1 {
    /// Observation stale or absent.
    StaleObservation,
    /// Observation contradicted the expected exact basis.
    Contradiction,
    /// Standing absent.
    AbsentStanding,
    /// Standing revoked, superseded, expired, or mismatched.
    StandingNotCurrent,
    /// Exact work was inadmissible.
    InadmissibleExactWork,
    /// Retry/probe/escalation budget exhausted.
    BudgetExhausted,
    /// Residual obligations block the requested transition.
    ResidualUnresolved,
    /// External human decision is required.
    HumanDecisionRequired,
    /// Exact profile law was violated.
    ProfileLawViolation,
    /// Recovery found an ambiguous or inconsistent state.
    RecoveryRequired,
}

/// Durable non-authorizing refusal outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalOutcomeV1 {
    /// Exact occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact state digest at refusal.
    pub at_state_digest: Digest,
    /// Closed refusal code.
    pub code: RefusalCodeV1,
    /// Optional exact evidence identity.
    pub evidence: Option<Digest>,
}

/// Canonical recovery requirement derived solely from durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryRequirementV1 {
    /// Fresh observation is required.
    FreshObservation,
    /// Fresh observation and current standing are required.
    FreshObservationAndStanding,
    /// Current standing and a new admission decision are required.
    CurrentStandingAndReadmission,
    /// The exact consumed issuance must be reconciled with Docket.
    ReconcileIssuance,
    /// The exact Docket attempt must be reconciled read-only.
    ReconcileAttempt,
    /// Only an externally verified disposition may proceed.
    ExternalDisposition,
    /// Exact typed pre-spend discovery may create one authority-empty revised
    /// occurrence; this is disjoint from external disposition.
    PreSpendScopeDiscovery,
    /// No legal continuation exists.
    None,
}

/// All pure-kernel refusals.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelErrorV1 {
    /// A transition does not exist in the frozen state machine.
    #[error("illegal governed-loop transition from {from:?} using {operation}")]
    IllegalTransition {
        /// Source state.
        from: ProgramCounterV1,
        /// Attempted operation.
        operation: &'static str,
    },
    /// A record carries a foreign schema.
    #[error("foreign schema for {0}")]
    ForeignSchema(&'static str),
    /// A bounded label is invalid.
    #[error("invalid governed-loop label: {0}")]
    Label(#[from] CampaignLabelError),
    /// Structured effect scope is not exact, closed, or canonical.
    #[error("invalid canonical effect scope ({0})")]
    EffectScope(&'static str),
    /// Exact proposal constraints are not closed or current.
    #[error("invalid exact work proposal ({0})")]
    Proposal(&'static str),
    /// Exact occurrence/campaign binding failed.
    #[error("occurrence binding mismatch")]
    OccurrenceMismatch,
    /// Exact subject/scope/proposal/attempt binding failed.
    #[error("exact basis binding mismatch ({0})")]
    BindingMismatch(&'static str),
    /// Observation is not fresh/current.
    #[error("observation is not fresh/current")]
    ObservationNotCurrent,
    /// Observation contradicts the expected basis.
    #[error("observation contradicts the exact basis")]
    ObservationContradiction,
    /// Standing is absent.
    #[error("current standing is absent")]
    StandingAbsent,
    /// Standing is not current.
    #[error("standing is not current")]
    StandingNotCurrent,
    /// Exact work is refused.
    #[error("exact work is not admissible")]
    Inadmissible,
    /// C1 repair citation is not exact.
    #[error("C1 repair citation does not equal the controlling rejected review basis")]
    AlteredFindingSet,
    /// A retry did not preserve the exact normalized preconditions.
    #[error("retry preconditions changed")]
    RetryPreconditionsChanged,
    /// A retry did not reuse the exact prior proposal.
    #[error("retry proposal basis changed")]
    RetryProposalChanged,
    /// An ordinary successor reused the prior proposal identity.
    #[error("ordinary successor requires a new proposal")]
    SuccessorProposalReused,
    /// A continuation reused an occurrence identity.
    #[error("continuation occurrence identity is not distinct")]
    OccurrenceReused,
    /// A bounded count is exhausted.
    #[error("{0} budget exhausted")]
    BudgetExhausted(&'static str),
    /// Durable budget facts are inconsistent.
    #[error("durable budget counts exceed their limits")]
    InvalidBudget,
    /// Duplicate residual identity.
    #[error("duplicate residual identity")]
    DuplicateResidual,
    /// Duplicate finding identity.
    #[error("duplicate finding identity")]
    DuplicateFinding,
    /// Exact residual accounting failed.
    #[error("exact residual discharge accounting failed")]
    ResidualAccounting,
    /// Open residuals block completion.
    #[error("open residual obligations block completion")]
    ResidualsOpen,
    /// An unresolved attempt blocks the transition.
    #[error("an unresolved execution attempt blocks this transition")]
    UnresolvedAttempt,
    /// Human disposition failed exact binding/currentness/replay checks.
    #[error("human disposition is not applicable ({0})")]
    HumanDisposition(&'static str),
    /// Human-decision request failed exact shape/currentness/idempotency checks.
    #[error("human-decision request is not applicable ({0})")]
    HumanDecisionRequest(&'static str),
    /// State digest is not exact.
    #[error("state digest mismatch")]
    StateDigestMismatch,
    /// State structure is inconsistent.
    #[error("stored state invariant failed ({0})")]
    StateInvariant(&'static str),
    /// An external authority/currentness boundary refused or was unavailable.
    #[error(transparent)]
    External(#[from] ExternalBoundaryErrorV1),
}

impl AgAuthorizationRefV1 {
    /// Derives the one semantic authorization identity for an exact basis.
    #[must_use]
    pub fn for_basis(
        key: &OccurrenceKeyV1,
        observation: &ObservationRefV1,
        proposal: &ProposalRefV1,
        standing: &StandingResolutionRefV1,
    ) -> Self {
        #[derive(Serialize)]
        struct Basis<'a> {
            key: &'a OccurrenceKeyV1,
            observation: &'a ObservationRefV1,
            proposal: &'a ProposalRefV1,
            standing: &'a StandingResolutionRefV1,
        }
        Self::from_digest(digest_value(
            AG_AUTHORIZATION_DIGEST_DOMAIN_V1,
            &Basis {
                key,
                observation,
                proposal,
                standing,
            },
        ))
    }
}

impl AgSpendRefV1 {
    /// Derives the unique spend identity for one AG authorization.
    #[must_use]
    pub fn for_authorization(authorization: &AgAuthorizationRefV1) -> Self {
        Self::from_digest(digest_value(AG_SPEND_DIGEST_DOMAIN_V1, authorization))
    }
}

impl DocketAttemptRefV1 {
    /// Derives the canonical attempt key from the exact AG issuance.
    ///
    /// Docket may retain a separate display/storage identifier, but the
    /// cross-office semantic attempt is one-to-one with this issuance.
    #[must_use]
    pub fn for_issuance(issuance: &AgIssuanceRefV1) -> Self {
        Self::from_digest(digest_value("ag.governed-loop.docket-attempt/v1", issuance))
    }
}

/// Exact mechanics request Docket may hand to one executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorDispatchV1 {
    /// Exact Docket attempt.
    pub attempt: DocketAttemptRefV1,
    /// Executor-local idempotency marker.
    pub marker: ExecutorAttemptMarkerRefV1,
    /// Exact typed work schema.
    pub work_schema: String,
    /// Exact work payload digest.
    pub work: Digest,
    /// Exact subject.
    pub subject: Digest,
    /// Exact scope.
    pub scope: Digest,
}

/// Closed executor outcome class; this value has no AG transition authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutorOutcomeClassV1 {
    /// Mechanics succeeded.
    Success,
    /// Mechanics failed with a known result.
    Failure,
    /// Mechanics outcome is not known safely.
    Indeterminate,
}

/// Authority-neutral executor output bound to one Docket attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorOutcomeV1 {
    /// Exact attempt.
    pub attempt: DocketAttemptRefV1,
    /// Exact executor-local marker.
    pub marker: ExecutorAttemptMarkerRefV1,
    /// Exact mechanics receipt/evidence.
    pub receipt: ReceiptRefV1,
    /// Closed outcome class.
    pub outcome: ExecutorOutcomeClassV1,
}

/// Docket-visible result when reconciling a consumed issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketIssuanceReconciliationV1 {
    /// Docket has no custody record for the exact issuance.
    NotAccepted,
    /// Docket durably refused the exact issuance before custody.
    Refused(DocketIssuanceRefusalV1),
    /// Docket accepted custody and assigned the exact attempt.
    Accepted(DocketCustodyV1),
    /// Docket accepted and has an exact known settlement.
    Settled {
        /// Exact custody basis.
        custody: DocketCustodyV1,
        /// Exact settlement.
        settlement: DocketSettlementV1,
    },
    /// Docket accepted custody but outcome is indeterminate.
    Indeterminate {
        /// Exact custody basis.
        custody: DocketCustodyV1,
        /// Exact indeterminate evidence.
        indeterminate: IndeterminateOutcomeV1,
    },
    /// Docket sealed an exact post-spend scope insufficiency; the executor
    /// reported no unauthorized effect, Docket found no such journal entry,
    /// and AG must halt before producing a request. Physical completeness is
    /// an operational premise rather than a mediated semantic claim.
    GovernedRepairRequired {
        /// Exact custody basis.
        custody: DocketCustodyV1,
        /// Exact Docket-sealed governed-repair result.
        result: DocketSealedGovernedRepairResultV1,
    },
}

/// Closed durable status for one explicit Docket reconciliation round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketReconciliationRoundStatusV1 {
    /// No custody exists. This path invokes no executor.
    NotAccepted,
    /// Docket durably refused the issuance before custody.
    Refused(DocketIssuanceRefusalV1),
    /// A durable claim exists, but completion is not durably known. Docket
    /// must never reinvoke this round implicitly.
    Unresolved(DocketReconciliationRoundReservationV1),
    /// The exact round completed and sealed one exact ordinary response.
    Completed {
        /// Exact reservation claimed before executor entry.
        reservation: DocketReconciliationRoundReservationV1,
        /// Exact durable completion record.
        completion: DocketReconciliationRoundCompletionV1,
        /// Exact reconciliation result produced by this round.
        response: DocketIssuanceReconciliationV1,
    },
}

/// Versioned Docket response bound to one authenticated AG round request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketReconciliationRoundResponseV1 {
    /// Exact response schema.
    pub schema: String,
    /// Exact AG request.
    pub request: ReconciliationRoundRequestRefV1,
    /// Exact intentional poll occurrence.
    pub round: ReconciliationRoundRefV1,
    /// Closed durable response state.
    #[serde(flatten)]
    pub state: DocketReconciliationRoundStatusV1,
}

impl DocketReconciliationRoundResponseV1 {
    /// Strictly validates the closed Docket response against one exact AG
    /// request, including reservation/completion identities and the public
    /// result identity for every completed result class.
    pub fn validate_for_request(
        &self,
        request: &ReconciliationRoundRequestV1,
    ) -> Result<(), KernelErrorV1> {
        request.validate()?;
        if self.schema != DOCKET_RECONCILIATION_ROUND_RESPONSE_SCHEMA_V1
            || self.request != request.request
            || self.round != request.round
        {
            return Err(KernelErrorV1::BindingMismatch(
                "Docket reconciliation round response",
            ));
        }
        match &self.state {
            DocketReconciliationRoundStatusV1::NotAccepted
            | DocketReconciliationRoundStatusV1::Refused(_) => Ok(()),
            DocketReconciliationRoundStatusV1::Unresolved(reservation) => {
                validate_round_reservation(request, reservation)
            }
            DocketReconciliationRoundStatusV1::Completed {
                reservation,
                completion,
                response,
            } => {
                validate_round_completion(request, reservation, completion)?;
                let result_identity = match response {
                    DocketIssuanceReconciliationV1::Settled { settlement, .. } => {
                        if settlement.expected_reference()? != settlement.settlement {
                            return Err(KernelErrorV1::BindingMismatch(
                                "Docket reconciliation settlement identity",
                            ));
                        }
                        settlement.settlement.as_digest()
                    }
                    DocketIssuanceReconciliationV1::Indeterminate { indeterminate, .. } => {
                        indeterminate.reconciliation.as_digest()
                    }
                    DocketIssuanceReconciliationV1::GovernedRepairRequired { result, .. } => {
                        result.validate()?;
                        match result {
                            DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
                                outcome,
                                ..
                            }
                            | DocketSealedGovernedRepairResultV1::ReadjudicationRequired {
                                outcome,
                                ..
                            } => outcome.sealed_result.as_digest(),
                        }
                    }
                    DocketIssuanceReconciliationV1::NotAccepted
                    | DocketIssuanceReconciliationV1::Refused(_)
                    | DocketIssuanceReconciliationV1::Accepted(_) => {
                        return Err(KernelErrorV1::BindingMismatch(
                            "completed Docket reconciliation result class",
                        ));
                    }
                };
                if &completion.result_identity != result_identity {
                    return Err(KernelErrorV1::BindingMismatch(
                        "Docket reconciliation public result identity",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Closed exact Docket-sealed governed-repair result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketSealedGovernedRepairResultV1 {
    /// Exact scope insufficiency.
    ScopeExpansionRequired {
        /// Exact sealed outcome refs.
        outcome: DocketGovernedRepairOutcomeRefV1,
        /// Exact non-authorizing requirement.
        requirement: ScopeExpansionRequiredV1,
    },
    /// Exact normative gap.
    ReadjudicationRequired {
        /// Exact sealed outcome refs.
        outcome: DocketGovernedRepairOutcomeRefV1,
        /// Exact non-authorizing requirement.
        requirement: ReadjudicationRequiredV1,
    },
}

impl DocketSealedGovernedRepairResultV1 {
    /// Revalidates the complete sealed requirement join. The requested delta
    /// (or readjudication census) is checked here before AG can halt, and the
    /// embedded requirement must carry the same exact Docket outcome.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        match self {
            Self::ScopeExpansionRequired {
                outcome,
                requirement,
            } => {
                outcome.validate()?;
                requirement.validate()?;
                if requirement.docket_outcome.as_ref() != Some(outcome) {
                    return Err(KernelErrorV1::BindingMismatch(
                        "sealed scope requirement/outcome",
                    ));
                }
            }
            Self::ReadjudicationRequired {
                outcome,
                requirement,
            } => {
                outcome.validate()?;
                requirement.validate()?;
                if requirement.docket_outcome.as_ref() != Some(outcome) {
                    return Err(KernelErrorV1::BindingMismatch(
                        "sealed readjudication requirement/outcome",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Exact response to first Docket custody submission.  Docket always returns
/// the exact custody even when mechanics immediately seal a governed-repair
/// outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketIssuanceAcceptanceV1 {
    /// Docket durably refused the exact issuance before custody.
    Refused(DocketIssuanceRefusalV1),
    /// Custody accepted; no terminal mechanics result is yet known.
    Custody(DocketCustodyV1),
    /// Custody accepted and an exact scope insufficiency was sealed.
    GovernedRepairRequired {
        /// Exact custody.
        custody: DocketCustodyV1,
        /// Exact Docket-sealed governed-repair result.
        result: DocketSealedGovernedRepairResultV1,
    },
}

/// Narrow execution-custody port owned by Docket.
pub trait DocketCustodyPortV1 {
    /// Accepts one exact AG issuance and delegates one physical attempt.
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceAcceptanceV1, ExternalBoundaryErrorV1>;

    /// Read-only reconciliation of an already consumed exact issuance.
    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1>;

    /// Legacy internal observation seam. Canonical production adapters refuse
    /// this raw form and require an explicit authenticated round.
    fn reconcile_attempt(
        &mut self,
        issuance: &AgIssuanceV2,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1>;

    /// Reconciliation of an exact Docket attempt through one explicit,
    /// Store-persisted and authenticated poll round.
    fn reconcile_round(
        &mut self,
        issuance: &AgIssuanceV2,
        custody: &DocketCustodyV1,
        request: &ReconciliationRoundRequestV1,
    ) -> Result<DocketReconciliationRoundResponseV1, ExternalBoundaryErrorV1> {
        let _ = (issuance, custody, request);
        Err(ExternalBoundaryErrorV1::Unavailable {
            code: "explicit-reconciliation-round-not-implemented".to_owned(),
        })
    }
}

/// Closed external human disposition vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanDispositionKindV1 {
    /// Permit only a new observation-required occurrence.
    ReturnToObservation,
    /// Replace the exact program basis and open a new occurrence.
    ReplaceProgram(ProgramBasisRefV1),
    /// Apply one exact externally authorized residual discharge while halted.
    ExactResidualDisposition(ExactResidualDischargeV1),
    /// Complete only with a fresh terminal observation and empty residual set.
    Terminate {
        /// Exact observation to resolve freshly.
        observation: ObservationRefV1,
        /// Exact terminal subject.
        subject: Digest,
        /// Exact external terminal witness.
        terminal_witness: TerminalWitnessRefV1,
    },
}

/// Authority-safe human disposition artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDispositionV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact campaign.
    pub campaign: CampaignId,
    /// Exact halted occurrence.
    pub occurrence: OccurrenceId,
    /// Exact halted state digest.
    pub halted_state_digest: Digest,
    /// Closed control disposition.
    pub disposition: HumanDispositionKindV1,
    /// One-use external decision identity.
    pub decision: HumanDecisionIdV1,
    /// Exact principal/signer identity.
    pub principal: HumanPrincipalRefV1,
    /// Exact mandate reference.
    pub mandate: MandateRefV1,
    /// Exact replay nonce.
    pub nonce: HumanNonceRefV1,
    /// Exclusive expiry.
    pub expires_at_unix_ms: u64,
}

impl HumanDispositionV1 {
    /// Returns the exact canonical artifact identity.  This is evidence, not
    /// authority; applicability still requires live external verification.
    #[must_use]
    pub fn reference(&self) -> HumanDispositionRefV1 {
        HumanDispositionRefV1::from_digest(digest_value(HUMAN_DISPOSITION_DIGEST_DOMAIN_V1, self))
    }
}

/// Closed externally adjudicated outcomes for one exact governed-repair
/// request.  Successor identity is part of the signed artifact, never supplied
/// as an ambient sibling argument.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernedRepairDispositionKindV1 {
    /// Approve exactly the requested additive delta for one successor.
    ApproveExactExpansion {
        /// Exact request being consumed.
        request: HumanDecisionRequestRefV1,
        /// Distinct successor occurrence.
        successor_occurrence: OccurrenceId,
        /// Exact approved delta; must equal the request delta.
        approved_delta: CanonicalEffectScopeV1,
        /// Exact mechanically derived original-plus-delta union.
        successor_scope: CanonicalEffectScopeV1,
        /// Immutable source checkpoint for the authorized successor proposal.
        checkpoint: GovernedRepairCheckpointV1,
    },
    /// Reject the exact request; the occurrence remains halted.
    Reject {
        /// Exact request being consumed.
        request: HumanDecisionRequestRefV1,
        /// Exact rationale/evidence identity.
        reason: Digest,
    },
    /// Require a fresh normative adjudication in one distinct successor.
    RequestReadjudication {
        /// Exact request being consumed.
        request: HumanDecisionRequestRefV1,
        /// Distinct successor occurrence.
        successor_occurrence: OccurrenceId,
        /// Exact adjudication program basis.
        successor_program: ProgramBasisRefV1,
        /// Immutable source checkpoint for the bounded adjudication successor.
        checkpoint: GovernedRepairCheckpointV1,
    },
}

impl GovernedRepairDispositionKindV1 {
    fn request(&self) -> &HumanDecisionRequestRefV1 {
        match self {
            Self::ApproveExactExpansion { request, .. }
            | Self::Reject { request, .. }
            | Self::RequestReadjudication { request, .. } => request,
        }
    }
}

/// Exact governed-repair human artifact.  It is authority-neutral until a
/// configured verifier checks the exact request, state, scope, decision,
/// profile, signature/currentness evidence, expiry, and one-use boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairDispositionV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact campaign.
    pub campaign: CampaignId,
    /// Exact halted occurrence.
    pub occurrence: OccurrenceId,
    /// Exact halted-state digest.
    pub halted_state_digest: Digest,
    /// Closed exact disposition.
    pub disposition: GovernedRepairDispositionKindV1,
    /// One-use external decision identity.
    pub decision: HumanDecisionIdV1,
    /// Exact principal/signer identity.
    pub principal: HumanPrincipalRefV1,
    /// Exact mandate identity.
    pub mandate: MandateRefV1,
    /// Root-configured verification-profile identity.
    pub verifier_profile: Digest,
    /// Exact replay nonce.
    pub nonce: HumanNonceRefV1,
    /// Exclusive expiry.
    pub expires_at_unix_ms: u64,
}

impl GovernedRepairDispositionV1 {
    /// Returns the exact canonical artifact identity.
    #[must_use]
    pub fn reference(&self) -> HumanDispositionRefV1 {
        HumanDispositionRefV1::from_digest(digest_value(
            "ag.governed-loop.governed-repair-disposition/v1",
            self,
        ))
    }

    /// Returns the exact AG decision request consumed by this artifact.
    #[must_use]
    pub fn request(&self) -> &HumanDecisionRequestRefV1 {
        self.disposition.request()
    }
}

/// Root-owned verifier profile.  Product callers choose a configured profile
/// identifier; disposition files cannot choose expected principal or mandate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedRepairVerifierProfileV1 {
    /// Exact root-owned profile identity.
    pub profile: Digest,
    /// Exact deployment verifier-root identity that owns this profile.
    pub root: Digest,
    /// Exact executable identity pinned by that verifier root.
    pub executable: Digest,
    /// Exact expected principal.
    pub principal: HumanPrincipalRefV1,
    /// Exact expected mandate.
    pub mandate: MandateRefV1,
}

/// Exact response returned by the configured governed-repair verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairVerificationV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact disposition artifact identity.
    pub disposition: HumanDispositionRefV1,
    /// Exact AG request identity.
    pub request: HumanDecisionRequestRefV1,
    /// Exact halted-state identity.
    pub halted_state_digest: Digest,
    /// Exact verifier profile.
    pub verifier_profile: Digest,
    /// Exact deployment verifier root used for this verification.
    pub verifier_root: Digest,
    /// Exact verifier executable measured at consequence time.
    pub verifier_executable: Digest,
    /// Exact cryptographic/current-authority verification record.
    pub verification: HumanVerificationRefV1,
    /// Consequence-time verification instant.
    pub verified_at_unix_ms: u64,
    /// Exclusive verification expiry.
    pub expires_at_unix_ms: u64,
}

impl GovernedRepairVerificationV1 {
    /// Returns the identity of the complete exact verification record, not
    /// merely the nested cryptographic/currentness evidence reference.
    #[must_use]
    pub fn reference(&self) -> GovernedRepairVerificationRefV1 {
        GovernedRepairVerificationRefV1::from_digest(digest_value(
            GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1,
            self,
        ))
    }
}

/// Request to the configured governed-repair verifier.
#[derive(Debug, Eq, PartialEq)]
pub struct GovernedRepairVerificationRequestV1<'a> {
    /// Exact non-authorizing AG decision request.
    pub request: &'a HumanDecisionRequestV1,
    /// Exact external disposition artifact.
    pub artifact: &'a GovernedRepairDispositionV1,
    /// Root-owned expected verifier profile.
    pub expected_profile: &'a GovernedRepairVerifierProfileV1,
    /// Consequence-time clock reading.
    pub now_unix_ms: u64,
}

/// External verifier boundary for governed-repair dispositions.
pub trait GovernedRepairDispositionVerifierV1 {
    /// Verifies exact current authority and returns an exactly bound response.
    fn verify_governed_repair_disposition(
        &mut self,
        request: &GovernedRepairVerificationRequestV1<'_>,
    ) -> Result<GovernedRepairVerificationV1, ExternalBoundaryErrorV1>;
}

/// Result of one exact governed-repair disposition.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "effect", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernedRepairDispositionEffectV1 {
    /// Request was rejected; source remains halted with the decision consumed.
    Rejected {
        /// Updated exact halted snapshot.
        halted: OccurrenceSnapshotV1,
        /// Exact verifier response.
        verification: GovernedRepairVerificationV1,
    },
    /// Source was sealed and one distinct authority-empty successor opened.
    OpenedSuccessor {
        /// Updated halted predecessor with one-use decision consumed.
        halted: OccurrenceSnapshotV1,
        /// New observation-required successor.
        successor: OccurrenceSnapshotV1,
        /// Exact verifier response.
        verification: GovernedRepairVerificationV1,
    },
}

/// Proposal classification at an observation-required boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalClassV1 {
    /// Initial campaign proposal.
    Initial,
    /// Retry of the exact prior proposal under unchanged fresh preconditions.
    Retry,
    /// Ordinary successor proposal.
    Successor,
}

/// Pure canonical governed-loop transition kernel.
#[derive(Clone, Copy, Debug, Default)]
pub struct GovernedLoopKernelV1;

impl GovernedLoopKernelV1 {
    /// Creates a new authority-empty initial occurrence.
    pub fn create_initial(
        campaign: CampaignId,
        occurrence: OccurrenceId,
        program: ProgramBasisRefV1,
        residuals: ResidualSetV1,
        budget: LoopBudgetV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        budget.validate()?;
        let key = OccurrenceKeyV1 {
            campaign,
            occurrence,
        };
        #[derive(Serialize)]
        struct Genesis<'a> {
            key: &'a OccurrenceKeyV1,
            program: &'a ProgramBasisRefV1,
        }
        let prior_state_digest = digest_value(
            GENESIS_DIGEST_DOMAIN_V1,
            &Genesis {
                key: &key,
                program: &program,
            },
        );
        let state = OccurrenceStateV1::ObservationRequired(ObservationRequiredV1 {
            meta: OccurrenceMetaV1 {
                key,
                program,
                residuals,
                budget,
                used_human_decisions: Vec::new(),
            },
            prior: None,
        });
        let state_digest = state_digest(&prior_state_digest, &state);
        let snapshot = OccurrenceSnapshotV1 {
            prior_state_digest,
            state_digest,
            state,
        };
        snapshot.validate_integrity()?;
        Ok(snapshot)
    }

    /// Derives the exact recovery action without reconstructing live authority.
    #[must_use]
    pub fn recovery_requirement(snapshot: &OccurrenceSnapshotV1) -> RecoveryRequirementV1 {
        match snapshot.program_counter() {
            ProgramCounterV1::ObservationRequired
            | ProgramCounterV1::SettledObservationRequired => {
                RecoveryRequirementV1::FreshObservation
            }
            ProgramCounterV1::ProposalRecorded | ProgramCounterV1::StandingRequired => {
                RecoveryRequirementV1::FreshObservationAndStanding
            }
            ProgramCounterV1::AdmissiblePendingAuthorization => {
                RecoveryRequirementV1::CurrentStandingAndReadmission
            }
            ProgramCounterV1::AuthorizationConsumed => RecoveryRequirementV1::ReconcileIssuance,
            ProgramCounterV1::Dispatched | ProgramCounterV1::ReconciliationRequired => {
                RecoveryRequirementV1::ReconcileAttempt
            }
            ProgramCounterV1::Halted => {
                if snapshot
                    .halted()
                    .and_then(HaltedV1::pre_spend_scope_insufficiency)
                    .is_some()
                {
                    RecoveryRequirementV1::PreSpendScopeDiscovery
                } else {
                    RecoveryRequirementV1::ExternalDisposition
                }
            }
            ProgramCounterV1::Completed => RecoveryRequirementV1::None,
        }
    }

    /// Creates one exact non-authorizing decision request for the current
    /// halted state.  This operation performs no effect and grants no standing.
    pub fn create_human_decision_request(
        current: &OccurrenceSnapshotV1,
        parameters: HumanDecisionRequestParametersV1,
    ) -> Result<HumanDecisionRequestV1, KernelErrorV1> {
        let HumanDecisionRequestParametersV1 {
            requirement,
            required_verifier_profile,
            required_verifier_root,
            required_verifier_executable,
            decision_consequences,
            nonclaims,
            idempotency_key,
            created_at_unix_ms,
            expires_at_unix_ms,
        } = parameters;
        current.validate_integrity()?;
        let OccurrenceStateV1::Halted(halted) = current.state() else {
            return Err(illegal(current, "create_human_decision_request"));
        };
        if halted.pre_spend_scope_insufficiency.is_some() {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "pre-spend scope discovery is not a human-disposition route",
            ));
        }
        if halted.governed_repair_closed.is_some() {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "governed repair occurrence is terminally rejected",
            ));
        }
        if let Some(pinned) = &halted.governed_repair_requirement
            && pinned != &requirement
        {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "requirement differs from exact Docket-sealed halt",
            ));
        }
        if halted.source == ProgramCounterV1::Dispatched
            && halted.governed_repair_requirement.is_none()
        {
            return Err(KernelErrorV1::HumanDecisionRequest(
                "post-spend halt lacks exact Docket-sealed requirement",
            ));
        }
        validate_requirement_against_halt(halted, &requirement)?;
        let available_decisions = match &requirement {
            HumanDecisionRequirementV1::ScopeExpansion(_) => vec![
                GovernedRepairDecisionClassV1::ApproveExactExpansion,
                GovernedRepairDecisionClassV1::Reject,
            ],
            HumanDecisionRequirementV1::Readjudication(_) => vec![
                GovernedRepairDecisionClassV1::Reject,
                GovernedRepairDecisionClassV1::RequestReadjudication,
            ],
        };
        let request = HumanDecisionRequestV1 {
            schema: HUMAN_DECISION_REQUEST_SCHEMA_V1.to_owned(),
            key: halted.meta.key.clone(),
            halted_state_digest: current.state_digest.clone(),
            program: halted.meta.program.clone(),
            proposal: halted.prior.proposal.clone(),
            requirement,
            required_verifier_profile,
            required_verifier_root,
            required_verifier_executable,
            available_decisions,
            decision_consequences,
            nonclaims,
            idempotency_key,
            created_at_unix_ms,
            expires_at_unix_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Applies one freshly verified governed-repair disposition.  Approval and
    /// readjudication always open a distinct occurrence and never resume the
    /// halted source occurrence.
    pub fn apply_governed_repair_disposition<V>(
        current: &OccurrenceSnapshotV1,
        request: &HumanDecisionRequestV1,
        artifact: GovernedRepairDispositionV1,
        expected_profile: &GovernedRepairVerifierProfileV1,
        verifier: &mut V,
        now_unix_ms: u64,
    ) -> Result<GovernedRepairDispositionEffectV1, KernelErrorV1>
    where
        V: GovernedRepairDispositionVerifierV1,
    {
        current.validate_integrity()?;
        let OccurrenceStateV1::Halted(halted) = current.state() else {
            return Err(illegal(current, "apply_governed_repair_disposition"));
        };
        if halted.pre_spend_scope_insufficiency.is_some() {
            return Err(KernelErrorV1::HumanDisposition(
                "pre-spend scope discovery is not a human-disposition route",
            ));
        }
        validate_decision_request(current, halted, request, now_unix_ms)?;
        validate_governed_repair_artifact(
            current,
            halted,
            request,
            &artifact,
            expected_profile,
            now_unix_ms,
        )?;
        let verification =
            verifier.verify_governed_repair_disposition(&GovernedRepairVerificationRequestV1 {
                request,
                artifact: &artifact,
                expected_profile,
                now_unix_ms,
            })?;
        validate_governed_repair_verification(
            current,
            request,
            &artifact,
            expected_profile,
            &verification,
            now_unix_ms,
        )?;

        match &artifact.disposition {
            GovernedRepairDispositionKindV1::Reject { reason, .. } => {
                let halted =
                    consume_governed_repair_rejection(current, halted, request, &artifact, reason)?;
                Ok(GovernedRepairDispositionEffectV1::Rejected {
                    halted,
                    verification,
                })
            }
            GovernedRepairDispositionKindV1::ApproveExactExpansion {
                successor_occurrence,
                approved_delta,
                successor_scope,
                checkpoint,
                ..
            } => {
                let HumanDecisionRequirementV1::ScopeExpansion(required) = &request.requirement
                else {
                    return Err(KernelErrorV1::HumanDisposition(
                        "expansion disposition used for readjudication request",
                    ));
                };
                let expected_union = required.successor_scope()?;
                if approved_delta != &required.requested_delta || successor_scope != &expected_union
                {
                    return Err(KernelErrorV1::HumanDisposition(
                        "approved scope is not exact original-plus-requested-delta union",
                    ));
                }
                let authorization = AuthorizedSuccessorBasisV1::ExactScopeExpansion {
                    request: request.reference(),
                    disposition: artifact.reference(),
                    original_scope: required.original_scope.clone(),
                    approved_delta: approved_delta.clone(),
                    successor_scope: successor_scope.clone(),
                    checkpoint: checkpoint.clone(),
                };
                let (halted, successor) = open_governed_repair_successor(
                    current,
                    halted,
                    &artifact,
                    *successor_occurrence,
                    halted.meta.program.clone(),
                    authorization,
                )?;
                Ok(GovernedRepairDispositionEffectV1::OpenedSuccessor {
                    halted,
                    successor,
                    verification,
                })
            }
            GovernedRepairDispositionKindV1::RequestReadjudication {
                successor_occurrence,
                successor_program,
                checkpoint,
                ..
            } => {
                let HumanDecisionRequirementV1::Readjudication(required) = &request.requirement
                else {
                    return Err(KernelErrorV1::HumanDisposition(
                        "readjudication disposition used for scope request",
                    ));
                };
                let authorization = AuthorizedSuccessorBasisV1::Readjudication {
                    request: request.reference(),
                    disposition: artifact.reference(),
                    successor_program: successor_program.clone(),
                    adjudication_scope: required.adjudication_scope.clone(),
                    checkpoint: checkpoint.clone(),
                };
                let (halted, successor) = open_governed_repair_successor(
                    current,
                    halted,
                    &artifact,
                    *successor_occurrence,
                    successor_program.clone(),
                    authorization,
                )?;
                Ok(GovernedRepairDispositionEffectV1::OpenedSuccessor {
                    halted,
                    successor,
                    verification,
                })
            }
        }
    }

    /// Revalidates a governed-repair effect at the persistence membrane.
    /// This does not repeat external verification; it proves that the exact
    /// verified artifact produced only its one legal state transition shape.
    pub fn validate_governed_repair_effect(
        expected: &OccurrenceSnapshotV1,
        request: &HumanDecisionRequestV1,
        artifact: &GovernedRepairDispositionV1,
        effect: &GovernedRepairDispositionEffectV1,
    ) -> Result<(), KernelErrorV1> {
        expected.validate_integrity()?;
        let OccurrenceStateV1::Halted(halted) = expected.state() else {
            return Err(illegal(expected, "validate_governed_repair_effect"));
        };
        if request.key != *expected.key()
            || request.halted_state_digest != *expected.state_digest()
            || artifact.request() != &request.reference()
            || artifact.halted_state_digest != *expected.state_digest()
        {
            return Err(KernelErrorV1::HumanDisposition(
                "persistence effect basis mismatch",
            ));
        }
        let (first, second) = match effect {
            GovernedRepairDispositionEffectV1::Rejected { halted, .. } => (halted, None),
            GovernedRepairDispositionEffectV1::OpenedSuccessor {
                halted, successor, ..
            } => (halted, Some(successor)),
        };
        Self::validate_successor(expected, first)?;
        let before = halted.meta.used_human_decisions();
        let after = first.state().meta().used_human_decisions();
        if after.len() != before.len().saturating_add(1)
            || !after.starts_with(before)
            || after.last() != Some(&artifact.decision)
        {
            return Err(KernelErrorV1::HumanDisposition(
                "decision not consumed exactly once",
            ));
        }
        match (&artifact.disposition, second) {
            (GovernedRepairDispositionKindV1::Reject { .. }, None) => {
                if first.program_counter() != ProgramCounterV1::Halted {
                    return Err(KernelErrorV1::HumanDisposition(
                        "rejection did not remain halted",
                    ));
                }
            }
            (
                GovernedRepairDispositionKindV1::ApproveExactExpansion {
                    successor_occurrence,
                    ..
                }
                | GovernedRepairDispositionKindV1::RequestReadjudication {
                    successor_occurrence,
                    ..
                },
                Some(successor),
            ) => {
                Self::validate_successor(first, successor)?;
                if successor.key().occurrence != *successor_occurrence
                    || successor.key() == expected.key()
                    || successor.program_counter() != ProgramCounterV1::ObservationRequired
                    || successor
                        .prior_occurrence()
                        .and_then(|prior| prior.authorized_successor.as_ref())
                        .is_none()
                {
                    return Err(KernelErrorV1::HumanDisposition(
                        "approved disposition did not open exact governed successor",
                    ));
                }
            }
            _ => {
                return Err(KernelErrorV1::HumanDisposition(
                    "disposition/effect shape mismatch",
                ));
            }
        }
        Ok(())
    }

    /// Validates that two durable snapshots form one closed legal successor.
    ///
    /// This is the persistence membrane: decoded state bytes cannot become an
    /// authoritative successor merely by carrying a self-consistent digest.
    pub fn validate_successor(
        source: &OccurrenceSnapshotV1,
        target: &OccurrenceSnapshotV1,
    ) -> Result<(), KernelErrorV1> {
        source.validate_integrity()?;
        target.validate_integrity()?;
        if target.prior_state_digest != source.state_digest {
            return Err(KernelErrorV1::StateDigestMismatch);
        }
        let same_key = source.key() == target.key();
        match (source.state(), target.state()) {
            (
                OccurrenceStateV1::ObservationRequired(from),
                OccurrenceStateV1::ProposalRecorded(to),
            ) if same_key => validate_recorded_proposal(from, &to.0),
            (
                OccurrenceStateV1::ProposalRecorded(from),
                OccurrenceStateV1::StandingRequired(to),
            ) if same_key && from.0 == to.0 => Ok(()),
            (
                OccurrenceStateV1::StandingRequired(from),
                OccurrenceStateV1::AdmissiblePendingAuthorization(to),
            ) if same_key && same_proposal_basis(&from.0, &to.0.proposal) => {
                validate_admissible_basis(&to.0)
            }
            (
                OccurrenceStateV1::AdmissiblePendingAuthorization(from),
                OccurrenceStateV1::AuthorizationConsumed(to),
            ) if same_key && same_proposal_basis(&from.0.proposal, &to.admitted.proposal) => {
                validate_authorized(to)
            }
            (OccurrenceStateV1::AuthorizationConsumed(from), OccurrenceStateV1::Dispatched(to))
                if same_key && from == &to.0.authorized =>
            {
                validate_custody(&to.0.custody, from)
            }
            (OccurrenceStateV1::AuthorizationConsumed(from), OccurrenceStateV1::Halted(to))
                if same_key
                    && to.source == ProgramCounterV1::AuthorizationConsumed
                    && (to.reason == expired_issuance_halt_reason(from)
                        || to.docket_issuance_refusal.as_ref().is_some_and(|refusal| {
                            refusal
                                .validate_for_spend(&from.issuance, &from.spend)
                                .is_ok()
                                && to.reason
                                    == HaltReasonRefV1::from_digest(Digest::hash_domain(
                                        "ag.governed-loop.docket-issuance-refused/v1",
                                        refusal.refusal.as_str().as_bytes(),
                                    ))
                        })) =>
            {
                validate_halt_successor(source, to)
            }
            (
                OccurrenceStateV1::Dispatched(from),
                OccurrenceStateV1::SettledObservationRequired(to),
            ) if same_key && from.0 == to.dispatch => {
                validate_settlement(&to.settlement, &to.dispatch)
            }
            (
                OccurrenceStateV1::Dispatched(from),
                OccurrenceStateV1::ReconciliationRequired(to),
            ) if same_key && from.0 == to.dispatch => {
                validate_indeterminate(&to.indeterminate, &to.dispatch)?;
                validate_initial_reconciliation_round_successor(source, to)
            }
            (
                OccurrenceStateV1::ReconciliationRequired(from),
                OccurrenceStateV1::ReconciliationRequired(to),
            ) if same_key && from.dispatch == to.dispatch => {
                validate_reconciliation_round_successor(source, from, to)
            }
            (
                OccurrenceStateV1::ReconciliationRequired(from),
                OccurrenceStateV1::SettledObservationRequired(to),
            ) if same_key && from.dispatch == to.dispatch => {
                validate_settlement(&to.settlement, &to.dispatch)
            }
            (
                OccurrenceStateV1::SettledObservationRequired(from),
                OccurrenceStateV1::ObservationRequired(to),
            ) if !same_key => validate_continuation(
                source,
                Some(&from.dispatch.authorized.admitted.proposal.proposal_ref),
                Some(
                    &from
                        .dispatch
                        .authorized
                        .admitted
                        .proposal
                        .observation
                        .normalized_preconditions,
                ),
                to,
                false,
            ),
            (from, OccurrenceStateV1::Halted(to))
                if same_key
                    && (is_safe_halt_source(from.program_counter())
                        || (from.program_counter() == ProgramCounterV1::Dispatched
                            && to.source == ProgramCounterV1::Dispatched
                            && to.unresolved_attempt.is_none())) =>
            {
                validate_halt_successor(source, to)
            }
            (OccurrenceStateV1::Halted(from), OccurrenceStateV1::Halted(to)) if same_key => {
                validate_human_halt_update(from, to)
            }
            (OccurrenceStateV1::Halted(from), OccurrenceStateV1::ObservationRequired(to))
                if !same_key
                    && from.unresolved_attempt.is_none()
                    && from.pre_spend_scope_insufficiency.is_some()
                    && to
                        .prior
                        .as_ref()
                        .and_then(|prior| prior.pre_spend_revision.as_ref())
                        .is_some() =>
            {
                validate_pre_spend_revision_successor(source, from, to)
            }
            (OccurrenceStateV1::Halted(from), OccurrenceStateV1::ObservationRequired(to))
                if !same_key
                    && from.unresolved_attempt.is_none()
                    && from.pre_spend_scope_insufficiency.is_none()
                    && to
                        .prior
                        .as_ref()
                        .and_then(|prior| prior.pre_spend_revision.as_ref())
                        .is_none() =>
            {
                validate_continuation(
                    source,
                    from.prior.proposal.as_ref(),
                    from.prior.normalized_preconditions.as_ref(),
                    to,
                    true,
                )
            }
            (OccurrenceStateV1::Halted(from), OccurrenceStateV1::Completed(to)) if same_key => {
                validate_human_completion(from, to)
            }
            (OccurrenceStateV1::ObservationRequired(from), OccurrenceStateV1::Completed(to))
                if same_key && from.meta == to.meta && to.meta.residuals.is_empty() =>
            {
                Ok(())
            }
            (from, to)
                if same_key
                    && from.program_counter() == to.program_counter()
                    && validate_probe_successor(from, to) =>
            {
                Ok(())
            }
            _ => Err(KernelErrorV1::IllegalTransition {
                from: source.program_counter(),
                operation: "persist decoded successor",
            }),
        }
    }

    /// Records one exact proposal only after a live observation resolution.
    #[allow(clippy::too_many_arguments)]
    pub fn record_proposal<O: ObservationResolverV1>(
        current: &OccurrenceSnapshotV1,
        observation: ObservationRefV1,
        proposal: ExactWorkProposalV1,
        class: ProposalClassV1,
        resolver: &mut O,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::ObservationRequired(pending) = current.state() else {
            return Err(illegal(current, "record_proposal"));
        };
        proposal.validate()?;
        if now_unix_ms >= proposal.expires_at_unix_ms() {
            return Err(KernelErrorV1::Proposal("proposal expired"));
        }
        if proposal.campaign() != &pending.meta.key().campaign {
            return Err(KernelErrorV1::OccurrenceMismatch);
        }
        let resolved = resolve_observation(
            resolver,
            pending.meta.key(),
            &observation,
            proposal.subject(),
            now_unix_ms,
        )?;

        let (link, mut meta) = match (&pending.prior, class) {
            (None, ProposalClassV1::Initial) => (OccurrenceLinkV1::Initial, pending.meta.clone()),
            (None, _) => return Err(KernelErrorV1::BindingMismatch("initial proposal class")),
            (Some(_), ProposalClassV1::Initial) => {
                return Err(KernelErrorV1::BindingMismatch(
                    "continuation proposal class",
                ));
            }
            (Some(prior), ProposalClassV1::Retry) => {
                if prior.authorized_successor.is_some() || prior.pre_spend_revision.is_some() {
                    return Err(KernelErrorV1::HumanDecisionRequest(
                        "governed successor cannot be classified as retry",
                    ));
                }
                if pending.meta.key == prior.key {
                    return Err(KernelErrorV1::OccurrenceReused);
                }
                if !pending.meta.budget.retry_available() {
                    return Err(KernelErrorV1::BudgetExhausted("retry"));
                }
                if prior.proposal.as_ref() != Some(&proposal.reference()) {
                    return Err(KernelErrorV1::RetryProposalChanged);
                }
                if prior.normalized_preconditions.as_ref()
                    != Some(&resolved.normalized_preconditions)
                {
                    return Err(KernelErrorV1::RetryPreconditionsChanged);
                }
                let mut next = pending.meta.clone();
                next.budget.retries_used = next.budget.retries_used.saturating_add(1);
                (OccurrenceLinkV1::RetryOf(prior.key.clone()), next)
            }
            (Some(prior), ProposalClassV1::Successor) => {
                if pending.meta.key == prior.key {
                    return Err(KernelErrorV1::OccurrenceReused);
                }
                if prior.proposal.as_ref() == Some(&proposal.reference()) {
                    return Err(KernelErrorV1::SuccessorProposalReused);
                }
                if let Some(authorization) = &prior.authorized_successor {
                    match authorization {
                        AuthorizedSuccessorBasisV1::ExactScopeExpansion {
                            successor_scope,
                            checkpoint,
                            ..
                        } if proposal.effect_scope() == successor_scope
                            && proposal.governed_repair_checkpoint() == Some(checkpoint) => {}
                        AuthorizedSuccessorBasisV1::Readjudication {
                            successor_program,
                            adjudication_scope,
                            checkpoint,
                            ..
                        } if &pending.meta.program == successor_program
                            && proposal.effect_scope() == adjudication_scope
                            && proposal.governed_repair_checkpoint() == Some(checkpoint) => {}
                        _ => {
                            return Err(KernelErrorV1::HumanDecisionRequest(
                                "successor proposal does not equal disposition constraint",
                            ));
                        }
                    }
                }
                if let Some(constraint) = &prior.pre_spend_revision
                    && (proposal.reference() != constraint.revised_proposal
                        || proposal != constraint.exact_revised_proposal)
                {
                    return Err(KernelErrorV1::Proposal(
                        "proposal does not equal exact pre-spend revision constraint",
                    ));
                }
                (
                    OccurrenceLinkV1::SuccessorOf(prior.key.clone()),
                    pending.meta.clone(),
                )
            }
        };
        meta.residuals = pending.meta.residuals.clone();
        let proposal_ref = proposal.reference();
        let state = OccurrenceStateV1::ProposalRecorded(ProposalRecordedV1(ProposalBasisV1 {
            meta,
            observation: resolved,
            proposal,
            proposal_ref,
            link,
        }));
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Advances a proposal to the explicit standing-required boundary.
    pub fn require_standing(
        current: &OccurrenceSnapshotV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::ProposalRecorded(proposal) = current.state() else {
            return Err(illegal(current, "require_standing"));
        };
        let state = OccurrenceStateV1::StandingRequired(StandingRequiredV1(proposal.0.clone()));
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Re-resolves observation and current standing, then records AG's exact decision.
    #[allow(clippy::too_many_arguments)]
    pub fn record_admissible<O, S, A>(
        current: &OccurrenceSnapshotV1,
        observation_resolver: &mut O,
        standing_resolver: &mut S,
        decider: &mut A,
        controlling_rejected_review: Option<&C1RejectedReviewBasisV1>,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1>
    where
        O: ObservationResolverV1,
        S: StandingResolverV1,
        A: AdmissibilityDeciderV1,
    {
        current.validate_integrity()?;
        let OccurrenceStateV1::StandingRequired(required) = current.state() else {
            return Err(illegal(current, "record_admissible"));
        };
        let (observation, standing, decision) = resolve_admissibility(
            &required.0,
            observation_resolver,
            standing_resolver,
            decider,
            controlling_rejected_review,
            now_unix_ms,
        )?;
        let mut proposal = required.0.clone();
        proposal.observation = observation;
        let state = OccurrenceStateV1::AdmissiblePendingAuthorization(
            AdmissiblePendingAuthorizationV1(AdmissibleBasisV1 {
                proposal,
                standing,
                decision,
            }),
        );
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Re-resolves all consequence-time premises and creates the one durable AG spend.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_authorization<O, S, A>(
        current: &OccurrenceSnapshotV1,
        observation_resolver: &mut O,
        standing_resolver: &mut S,
        decider: &mut A,
        controlling_rejected_review: Option<&C1RejectedReviewBasisV1>,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1>
    where
        O: ObservationResolverV1,
        S: StandingResolverV1,
        A: AdmissibilityDeciderV1,
    {
        current.validate_integrity()?;
        let OccurrenceStateV1::AdmissiblePendingAuthorization(pending) = current.state() else {
            return Err(illegal(current, "consume_authorization"));
        };
        let (observation, standing, decision) = resolve_admissibility(
            &pending.0.proposal,
            observation_resolver,
            standing_resolver,
            decider,
            controlling_rejected_review,
            now_unix_ms,
        )?;
        let mut proposal = pending.0.proposal.clone();
        proposal.observation = observation;
        let admitted = AdmissibleBasisV1 {
            proposal,
            standing,
            decision,
        };
        let authorization = AgAuthorizationRefV1::for_basis(
            admitted.proposal.meta.key(),
            &admitted.proposal.observation.observation,
            &admitted.proposal.proposal_ref,
            &admitted.standing.resolution,
        );
        let spend_ref = AgSpendRefV1::for_authorization(&authorization);
        let spend = AgAuthorizationSpendV1 {
            authorization,
            spend: spend_ref.clone(),
            key: admitted.proposal.meta.key.clone(),
            observation: admitted.proposal.observation.observation.clone(),
            proposal: admitted.proposal.proposal_ref.clone(),
            standing_resolution: admitted.standing.resolution.clone(),
            admission_decision: admitted.decision.decision.clone(),
            consumed_at_unix_ms: now_unix_ms,
        };
        let issuance = build_issuance(&admitted, &spend_ref);
        let state = OccurrenceStateV1::AuthorizationConsumed(AuthorizationConsumedV1 {
            admitted,
            spend,
            issuance,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Records Docket's exact custody acceptance and canonical attempt.
    pub fn accept_docket_custody(
        current: &OccurrenceSnapshotV1,
        custody: DocketCustodyV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::AuthorizationConsumed(authorized) = current.state() else {
            return Err(illegal(current, "accept_docket_custody"));
        };
        validate_custody(&custody, authorized)?;
        let state = OccurrenceStateV1::Dispatched(DispatchedV1(DispatchBasisV1 {
            authorized: authorized.clone(),
            custody,
        }));
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Records an exact known success/failure settlement and requires observation.
    pub fn record_settlement(
        current: &OccurrenceSnapshotV1,
        settlement: DocketSettlementV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::Dispatched(dispatched) = current.state() else {
            return Err(illegal(current, "record_settlement"));
        };
        validate_settlement(&settlement, &dispatched.0)?;
        let state = OccurrenceStateV1::SettledObservationRequired(SettledObservationRequiredV1 {
            dispatch: dispatched.0.clone(),
            settlement,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Records an indeterminate outcome and closes every repeat/continuation path.
    pub fn require_reconciliation(
        current: &OccurrenceSnapshotV1,
        indeterminate: IndeterminateOutcomeV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::Dispatched(dispatched) = current.state() else {
            return Err(illegal(current, "require_reconciliation"));
        };
        validate_indeterminate(&indeterminate, &dispatched.0)?;
        let state = OccurrenceStateV1::ReconciliationRequired(ReconciliationRequiredV1 {
            dispatch: dispatched.0.clone(),
            indeterminate,
            reconciliation_round: None,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Records Docket's conservative claimed/in-flight-or-unknown response.
    /// The round cannot be reinvoked or used as a predecessor for a new poll.
    pub fn record_unresolved_reconciliation_round(
        current: &OccurrenceSnapshotV1,
        request: ReconciliationRoundRequestV1,
        reservation: DocketReconciliationRoundReservationV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        validate_round_reservation(&request, &reservation)?;
        current.validate_integrity()?;
        let (dispatch, indeterminate, prior) = reconciliation_basis(current)?;
        if matches!(
            prior,
            Some(ReconciliationRoundStateV1::Unresolved {
                request: old,
                reservation: old_reservation,
            }) if old == &request && old_reservation == &reservation
        ) {
            return Ok(current.clone());
        }
        validate_round_request_for_current(current, &request, dispatch, prior)?;
        if prior.is_some()
            && !matches!(
                prior,
                Some(ReconciliationRoundStateV1::CompletedIndeterminate { .. })
            )
        {
            return Err(KernelErrorV1::BindingMismatch(
                "unresolved reconciliation preparation",
            ));
        }
        let indeterminate = if current.program_counter() == ProgramCounterV1::Dispatched {
            IndeterminateOutcomeV1 {
                issuance: request.issuance.clone(),
                attempt: request.attempt.clone(),
                reconciliation: ReconciliationRefV1::from_digest(digest_value(
                    "ag.governed-loop.unresolved-reconciliation-round/v1",
                    &(
                        &request.request,
                        &reservation.reservation,
                        &reservation.source_cut,
                    ),
                )),
                evidence: reservation.source_cut.clone(),
            }
        } else {
            indeterminate
                .ok_or(KernelErrorV1::StateInvariant(
                    "reconciliation state missing indeterminate evidence",
                ))?
                .clone()
        };
        let state = OccurrenceStateV1::ReconciliationRequired(ReconciliationRequiredV1 {
            dispatch: dispatch.clone(),
            indeterminate,
            reconciliation_round: Some(ReconciliationRoundStateV1::Unresolved {
                request,
                reservation,
            }),
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Records one completed indeterminate round. This advances the durable AG
    /// cut even when the executor evidence bytes equal a prior observation.
    pub fn record_completed_indeterminate_round(
        current: &OccurrenceSnapshotV1,
        request: ReconciliationRoundRequestV1,
        reservation: DocketReconciliationRoundReservationV1,
        completion: DocketReconciliationRoundCompletionV1,
        indeterminate: IndeterminateOutcomeV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        validate_round_completion(&request, &reservation, &completion)?;
        let (dispatch, _, prior) = reconciliation_basis(current)?;
        if let Some(ReconciliationRoundStateV1::CompletedIndeterminate {
            request: old,
            reservation: old_reservation,
            completion: old_completion,
        }) = prior
            && old == &request
            && old_reservation == &reservation
            && old_completion == &completion
            && current.indeterminate() == Some(&indeterminate)
        {
            return Ok(current.clone());
        }
        validate_round_request_for_current(current, &request, dispatch, prior)?;
        validate_indeterminate(&indeterminate, dispatch)?;
        if completion.result_identity != *indeterminate.reconciliation.as_digest() {
            return Err(KernelErrorV1::BindingMismatch(
                "completed reconciliation result identity",
            ));
        }
        if matches!(prior, Some(ReconciliationRoundStateV1::Unresolved { request: prepared, reservation: prior_reservation }) if prepared != &request || prior_reservation != &reservation)
        {
            return Err(KernelErrorV1::BindingMismatch(
                "completed reconciliation preparation",
            ));
        }
        let state = OccurrenceStateV1::ReconciliationRequired(ReconciliationRequiredV1 {
            dispatch: dispatch.clone(),
            indeterminate,
            reconciliation_round: Some(ReconciliationRoundStateV1::CompletedIndeterminate {
                request,
                reservation,
                completion,
            }),
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Converts a recovered ambiguous dispatched state to explicit reconciliation.
    pub fn recover_dispatched(
        current: &OccurrenceSnapshotV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        let OccurrenceStateV1::Dispatched(dispatched) = current.state() else {
            return Err(illegal(current, "recover_dispatched"));
        };
        let attempt = &dispatched.0.custody.attempt;
        let indeterminate = IndeterminateOutcomeV1 {
            issuance: dispatched.0.authorized.issuance.issuance.clone(),
            attempt: attempt.clone(),
            reconciliation: ReconciliationRefV1::from_digest(digest_value(
                "ag.governed-loop.recovery-reconciliation/v1",
                &(current.state_digest(), attempt),
            )),
            evidence: digest_value(
                "ag.governed-loop.recovery-ambiguity/v1",
                &(current.state_digest(), attempt),
            ),
        };
        Self::require_reconciliation(current, indeterminate)
    }

    /// Records a known result returned by exact read-only reconciliation.
    pub fn record_reconciled_settlement(
        current: &OccurrenceSnapshotV1,
        settlement: DocketSettlementV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::ReconciliationRequired(reconciling) = current.state() else {
            return Err(illegal(current, "record_reconciled_settlement"));
        };
        validate_settlement(&settlement, &reconciling.dispatch)?;
        let state = OccurrenceStateV1::SettledObservationRequired(SettledObservationRequiredV1 {
            dispatch: reconciling.dispatch.clone(),
            settlement,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Opens an authority-empty continuation occurrence after exact settlement.
    pub fn open_continuation(
        current: &OccurrenceSnapshotV1,
        occurrence: OccurrenceId,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::SettledObservationRequired(settled) = current.state() else {
            return Err(illegal(current, "open_continuation"));
        };
        let old_meta = settled.dispatch.authorized.admitted.proposal.meta.clone();
        if occurrence == old_meta.key.occurrence {
            return Err(KernelErrorV1::OccurrenceReused);
        }
        let prior = PriorOccurrenceBasisV1 {
            key: old_meta.key.clone(),
            proposal: Some(
                settled
                    .dispatch
                    .authorized
                    .admitted
                    .proposal
                    .proposal_ref
                    .clone(),
            ),
            proposal_contract: Some(
                settled
                    .dispatch
                    .authorized
                    .admitted
                    .proposal
                    .proposal
                    .clone(),
            ),
            normalized_preconditions: Some(
                settled
                    .dispatch
                    .authorized
                    .admitted
                    .proposal
                    .observation
                    .normalized_preconditions
                    .clone(),
            ),
            effect_scope: Some(
                settled
                    .dispatch
                    .authorized
                    .admitted
                    .proposal
                    .proposal
                    .effect_scope()
                    .clone(),
            ),
            issuance: Some(settled.dispatch.authorized.issuance.issuance.clone()),
            docket_custody: Some(settled.dispatch.custody.reference()),
            docket_attempt: Some(settled.dispatch.custody.attempt.clone()),
            state_digest: current.state_digest.clone(),
            authorized_successor: None,
            pre_spend_revision: None,
        };
        let state = OccurrenceStateV1::ObservationRequired(ObservationRequiredV1 {
            meta: OccurrenceMetaV1 {
                key: OccurrenceKeyV1 {
                    campaign: old_meta.key.campaign.clone(),
                    occurrence,
                },
                program: old_meta.program,
                residuals: old_meta.residuals,
                budget: old_meta.budget,
                used_human_decisions: old_meta.used_human_decisions,
            },
            prior: Some(prior),
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Records one read-only probe request as a non-authorizing durable fact.
    pub fn note_probe(
        current: &OccurrenceSnapshotV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        if !matches!(
            current.program_counter(),
            ProgramCounterV1::SettledObservationRequired | ProgramCounterV1::ObservationRequired
        ) {
            return Err(illegal(current, "note_probe"));
        }
        if !current.state.meta().budget.probe_available() {
            return Err(KernelErrorV1::BudgetExhausted("probe"));
        }
        let mut state = current.state.clone();
        state.meta_mut().budget.probes_used = state.meta().budget.probes_used.saturating_add(1);
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Halts from an authority-safe boundary; dispatched first requires reconciliation.
    pub fn halt_pre_spend_scope_insufficiency(
        current: &OccurrenceSnapshotV1,
        diagnostic_basis: Digest,
        idempotency_key: Digest,
        recorded_at_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::ProposalRecorded(recorded) = current.state() else {
            return Err(illegal(current, "halt_pre_spend_scope_insufficiency"));
        };
        if recorded.0.proposal.governed_repair_checkpoint().is_some() {
            return Err(KernelErrorV1::Proposal(
                "checkpoint-bound successor cannot enter pre-spend revision",
            ));
        }
        validate_canonical_timestamp(
            recorded_at_unix_ms,
            "pre-spend halt time is not canonically representable",
        )?;
        if recorded_at_unix_ms >= recorded.0.proposal.expires_at_unix_ms() {
            return Err(KernelErrorV1::Proposal(
                "expired proposal cannot enter pre-spend revision",
            ));
        }
        let schema = PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1.to_owned();
        let key = recorded.0.meta.key.clone();
        let proposal = recorded.0.proposal_ref.clone();
        let original_scope_identity = recorded.0.proposal.scope().clone();
        let body = PreSpendScopeInsufficiencyIdentityBodyV1 {
            schema: &schema,
            key: &key,
            proposal: &proposal,
            original_scope_identity: &original_scope_identity,
            diagnostic_basis: &diagnostic_basis,
            source_state_digest: current.state_digest(),
            idempotency_key: &idempotency_key,
            recorded_at_unix_ms,
        };
        let insufficiency = PreSpendScopeInsufficiencyRefV1::from_digest(digest_value(
            PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1,
            &body,
        ));
        let marker = PreSpendScopeInsufficiencyV1 {
            schema,
            insufficiency: insufficiency.clone(),
            key,
            proposal,
            original_scope_identity,
            diagnostic_basis,
            source_state_digest: current.state_digest().clone(),
            idempotency_key,
            recorded_at_unix_ms,
        };
        marker.validate()?;
        let state = OccurrenceStateV1::Halted(HaltedV1 {
            meta: recorded.0.meta.clone(),
            source: ProgramCounterV1::ProposalRecorded,
            reason: HaltReasonRefV1::from_digest(digest_value(
                PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1,
                &insufficiency,
            )),
            prior: current_prior_basis(current),
            unresolved_attempt: None,
            history: AuthorityHistoryV1::default(),
            governed_repair_requirement: None,
            governed_repair_closed: None,
            docket_issuance_refusal: None,
            pre_spend_scope_insufficiency: Some(marker),
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Creates one exact non-authorizing pre-spend discovery and a distinct
    /// observation-required revised occurrence.  Every claim is derived again
    /// from the typed halted predecessor.
    pub fn create_pre_spend_scope_discovery(
        current: &OccurrenceSnapshotV1,
        parameters: PreSpendScopeDiscoveryParametersV1,
    ) -> Result<(PreSpendScopeDiscoveryV1, OccurrenceSnapshotV1), KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::Halted(halted) = current.state() else {
            return Err(illegal(current, "create_pre_spend_scope_discovery"));
        };
        let Some(marker) = halted.pre_spend_scope_insufficiency.as_ref() else {
            return Err(KernelErrorV1::BindingMismatch(
                "halt is not typed pre-spend scope insufficiency",
            ));
        };
        marker.validate()?;
        validate_canonical_timestamp(
            parameters.recorded_at_unix_ms,
            "pre-spend discovery time is not canonically representable",
        )?;
        if halted.source != ProgramCounterV1::ProposalRecorded
            || halted.unresolved_attempt.is_some()
            || halted.governed_repair_requirement.is_some()
            || halted.governed_repair_closed.is_some()
            || halted.docket_issuance_refusal.is_some()
            || halted.history != AuthorityHistoryV1::default()
            || halted.prior.issuance.is_some()
            || halted.prior.docket_custody.is_some()
            || halted.prior.docket_attempt.is_some()
            || halted.prior.authorized_successor.is_some()
            || halted.prior.pre_spend_revision.is_some()
        {
            return Err(KernelErrorV1::BindingMismatch(
                "pre-spend discovery predecessor has consequence authority",
            ));
        }
        let original =
            halted
                .prior
                .proposal_contract
                .as_ref()
                .ok_or(KernelErrorV1::BindingMismatch(
                    "pre-spend discovery missing original proposal",
                ))?;
        let original_ref = original.reference();
        let original_scope = original.effect_scope().clone();
        if parameters.recorded_at_unix_ms >= original.expires_at_unix_ms() {
            return Err(KernelErrorV1::Proposal(
                "expired proposal cannot create pre-spend revision",
            ));
        }
        let revised_scope = original_scope.exact_additive_union(&parameters.requested_delta)?;
        let revised_proposal = original.derive_pre_spend_revision(revised_scope.clone())?;
        let revised_proposal_ref = revised_proposal.reference();
        if parameters.predecessor != halted.meta.key
            || parameters.original_proposal != original_ref
            || parameters.original_scope_identity != original_scope.digest()
            || parameters.diagnostic_basis != marker.diagnostic_basis
            || parameters.claimed_revised_scope != revised_scope
            || parameters.claimed_revised_proposal != revised_proposal_ref
            || parameters.exact_revised_proposal != revised_proposal
            || parameters.revised_occurrence == halted.meta.key.occurrence
        {
            return Err(KernelErrorV1::BindingMismatch(
                "pre-spend discovery caller claims",
            ));
        }
        let placeholder = PreSpendScopeDiscoveryRefV1::from_digest(Digest::hash_domain(
            "ag.governed-loop.pre-spend-scope-discovery-placeholder/v1",
            b"identity is replaced before validation",
        ));
        let mut discovery = PreSpendScopeDiscoveryV1 {
            schema: PRE_SPEND_SCOPE_DISCOVERY_SCHEMA_V1.to_owned(),
            discovery: placeholder,
            idempotency_key: parameters.idempotency_key,
            predecessor: halted.meta.key.clone(),
            insufficiency: marker.insufficiency.clone(),
            halted_state_digest: current.state_digest.clone(),
            source_state_digest: marker.source_state_digest.clone(),
            original_proposal: original_ref,
            exact_original_proposal: original.clone(),
            original_scope,
            original_scope_identity: parameters.original_scope_identity,
            requested_delta: parameters.requested_delta,
            requested_delta_identity: Digest::hash_domain(
                "ag.governed-loop.pre-spend-delta-placeholder/v1",
                b"identity is replaced before validation",
            ),
            revised_scope,
            revised_scope_identity: Digest::hash_domain(
                "ag.governed-loop.pre-spend-revised-scope-placeholder/v1",
                b"identity is replaced before validation",
            ),
            revised_proposal: revised_proposal_ref,
            exact_revised_proposal: revised_proposal,
            diagnostic_basis: parameters.diagnostic_basis,
            revised_occurrence: parameters.revised_occurrence,
            recorded_at_unix_ms: parameters.recorded_at_unix_ms,
        };
        discovery.requested_delta_identity = discovery.requested_delta.digest();
        discovery.revised_scope_identity = discovery.revised_scope.digest();
        discovery.discovery = discovery.derived_reference();
        discovery.validate()?;

        let prior = PriorOccurrenceBasisV1 {
            key: halted.meta.key.clone(),
            proposal: Some(discovery.original_proposal.clone()),
            proposal_contract: Some(discovery.exact_original_proposal.clone()),
            normalized_preconditions: None,
            effect_scope: Some(discovery.original_scope.clone()),
            issuance: None,
            docket_custody: None,
            docket_attempt: None,
            state_digest: current.state_digest.clone(),
            authorized_successor: None,
            pre_spend_revision: Some(PreSpendRevisionConstraintV1 {
                predecessor: halted.meta.key.clone(),
                discovery: discovery.discovery.clone(),
                revised_proposal: discovery.revised_proposal.clone(),
                exact_revised_proposal: discovery.exact_revised_proposal.clone(),
            }),
        };
        let successor_state = OccurrenceStateV1::ObservationRequired(ObservationRequiredV1 {
            meta: OccurrenceMetaV1 {
                key: OccurrenceKeyV1 {
                    campaign: halted.meta.key.campaign.clone(),
                    occurrence: discovery.revised_occurrence,
                },
                program: halted.meta.program.clone(),
                residuals: halted.meta.residuals.clone(),
                budget: halted.meta.budget,
                used_human_decisions: halted.meta.used_human_decisions.clone(),
            },
            prior: Some(prior),
        });
        let successor = successor_snapshot(current, successor_state);
        successor.validate_integrity()?;
        Self::validate_successor(current, &successor)?;
        Ok((discovery, successor))
    }

    /// Halts from an authority-safe boundary; dispatched first requires reconciliation.
    pub fn halt(
        current: &OccurrenceSnapshotV1,
        reason: HaltReasonRefV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let source = current.program_counter();
        if !matches!(
            source,
            ProgramCounterV1::ObservationRequired
                | ProgramCounterV1::ProposalRecorded
                | ProgramCounterV1::StandingRequired
                | ProgramCounterV1::AdmissiblePendingAuthorization
                | ProgramCounterV1::ReconciliationRequired
                | ProgramCounterV1::SettledObservationRequired
        ) {
            return Err(illegal(current, "halt"));
        }
        let prior = current_prior_basis(current);
        let unresolved_attempt = match current.state() {
            OccurrenceStateV1::ReconciliationRequired(value) => {
                Some(value.dispatch.custody.attempt.clone())
            }
            _ => None,
        };
        let state = OccurrenceStateV1::Halted(HaltedV1 {
            meta: current.state.meta().clone(),
            source,
            reason,
            prior,
            unresolved_attempt,
            history: current.state.authority_history(),
            governed_repair_requirement: None,
            governed_repair_closed: None,
            docket_issuance_refusal: None,
            pre_spend_scope_insufficiency: None,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Durably halts a spent issuance that expired before Docket custody.
    /// The spend remains in authority history and can never be restored.
    pub fn halt_expired_issuance(
        current: &OccurrenceSnapshotV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::AuthorizationConsumed(authorized) = current.state() else {
            return Err(illegal(current, "halt_expired_issuance"));
        };
        if now_unix_ms < authorized.issuance.expires_at_unix_ms {
            return Err(KernelErrorV1::BindingMismatch("issuance has not expired"));
        }
        let state = OccurrenceStateV1::Halted(HaltedV1 {
            meta: authorized.admitted.proposal.meta.clone(),
            source: ProgramCounterV1::AuthorizationConsumed,
            reason: expired_issuance_halt_reason(authorized),
            prior: current_prior_basis(current),
            unresolved_attempt: None,
            history: current.state.authority_history(),
            governed_repair_requirement: None,
            governed_repair_closed: None,
            docket_issuance_refusal: None,
            pre_spend_scope_insufficiency: None,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Durably terminalizes one exact Docket refusal before custody. The AG
    /// spend remains consumed; neither refusal possession nor halt grants a
    /// successor or retry authority.
    pub fn halt_docket_issuance_refusal(
        current: &OccurrenceSnapshotV1,
        refusal: DocketIssuanceRefusalV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::AuthorizationConsumed(authorized) = current.state() else {
            return Err(illegal(current, "halt_docket_issuance_refusal"));
        };
        refusal.validate_for_spend(&authorized.issuance, &authorized.spend)?;
        let reason = HaltReasonRefV1::from_digest(Digest::hash_domain(
            "ag.governed-loop.docket-issuance-refused/v1",
            refusal.refusal.as_str().as_bytes(),
        ));
        let mut meta = authorized.admitted.proposal.meta.clone();
        let mut residuals = meta.residuals.as_slice().to_vec();
        residuals.push(docket_issuance_refusal_residual(&refusal));
        meta.residuals = ResidualSetV1::new(residuals)?;
        let state = OccurrenceStateV1::Halted(HaltedV1 {
            meta,
            source: ProgramCounterV1::AuthorizationConsumed,
            reason,
            prior: current_prior_basis(current),
            unresolved_attempt: None,
            history: current.state.authority_history(),
            governed_repair_requirement: None,
            governed_repair_closed: None,
            docket_issuance_refusal: Some(refusal),
            pre_spend_scope_insufficiency: None,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Seals an exact Docket post-spend governed-repair outcome into Halted.
    /// The result may arrive directly after dispatch or during read-only
    /// reconciliation after a crash/unknown result. In either case it must
    /// equal the exact retained custody/attempt/issuance and terminalizes that
    /// attempt rather than leaving reusable execution authority.
    pub fn halt_from_docket_governed_repair(
        current: &OccurrenceSnapshotV1,
        outcome: &DocketGovernedRepairOutcomeRefV1,
        requirement: &HumanDecisionRequirementV1,
        reason: HaltReasonRefV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let dispatch = match current.state() {
            OccurrenceStateV1::Dispatched(value) => &value.0,
            OccurrenceStateV1::ReconciliationRequired(value) => &value.dispatch,
            _ => return Err(illegal(current, "halt_from_docket_governed_repair")),
        };
        requirement.validate()?;
        let embedded = match requirement {
            HumanDecisionRequirementV1::ScopeExpansion(value) => value.docket_outcome.as_ref(),
            HumanDecisionRequirementV1::Readjudication(value) => value.docket_outcome.as_ref(),
        };
        if embedded != Some(outcome)
            || outcome.issuance != dispatch.authorized.issuance.issuance
            || outcome.custody != dispatch.custody.reference()
            || outcome.attempt != dispatch.custody.attempt
        {
            return Err(KernelErrorV1::BindingMismatch(
                "sealed Docket governed repair outcome",
            ));
        }
        let state = OccurrenceStateV1::Halted(HaltedV1 {
            meta: dispatch.authorized.admitted.proposal.meta.clone(),
            source: current.program_counter(),
            reason,
            prior: current_prior_basis(current),
            unresolved_attempt: None,
            history: current.state.authority_history(),
            governed_repair_requirement: Some(requirement.clone()),
            governed_repair_closed: None,
            docket_issuance_refusal: None,
            pre_spend_scope_insufficiency: None,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Records one bounded escalation and halts; the count is fact, not authority.
    pub fn escalate(
        current: &OccurrenceSnapshotV1,
        reason: HaltReasonRefV1,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        if !current.state.meta().budget.escalation_available() {
            return Err(KernelErrorV1::BudgetExhausted("escalation"));
        }
        let source = current.program_counter();
        if !matches!(
            source,
            ProgramCounterV1::ObservationRequired
                | ProgramCounterV1::ProposalRecorded
                | ProgramCounterV1::StandingRequired
                | ProgramCounterV1::AdmissiblePendingAuthorization
                | ProgramCounterV1::ReconciliationRequired
                | ProgramCounterV1::SettledObservationRequired
        ) {
            return Err(illegal(current, "escalate"));
        }
        let mut meta = current.state.meta().clone();
        meta.budget.escalations_used = meta.budget.escalations_used.saturating_add(1);
        let unresolved_attempt = match current.state() {
            OccurrenceStateV1::ReconciliationRequired(value) => {
                Some(value.dispatch.custody.attempt.clone())
            }
            _ => None,
        };
        let state = OccurrenceStateV1::Halted(HaltedV1 {
            meta,
            source,
            reason,
            prior: current_prior_basis(current),
            unresolved_attempt,
            history: current.state.authority_history(),
            governed_repair_requirement: None,
            governed_repair_closed: None,
            docket_issuance_refusal: None,
            pre_spend_scope_insufficiency: None,
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Completes directly from observation-required on a fresh terminal observation.
    pub fn complete_from_observation<O: ObservationResolverV1>(
        current: &OccurrenceSnapshotV1,
        observation: ObservationRefV1,
        subject: &Digest,
        terminal_witness: TerminalWitnessRefV1,
        resolver: &mut O,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
        current.validate_integrity()?;
        let OccurrenceStateV1::ObservationRequired(pending) = current.state() else {
            return Err(illegal(current, "complete_from_observation"));
        };
        if !pending.meta.residuals.is_empty() {
            return Err(KernelErrorV1::ResidualsOpen);
        }
        let terminal = resolve_observation(
            resolver,
            pending.meta.key(),
            &observation,
            subject,
            now_unix_ms,
        )?;
        let state = OccurrenceStateV1::Completed(CompletedV1 {
            meta: pending.meta.clone(),
            terminal_observation: terminal,
            terminal_witness,
            history: current.state.authority_history(),
            proposal_contract: current.proposal_contract().cloned(),
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }
}

impl OccurrenceSnapshotV1 {
    /// Returns the exact recorded proposal, when any.
    #[must_use]
    pub fn proposal(&self) -> Option<&ExactWorkProposalV1> {
        self.state.proposal_basis().map(|basis| &basis.proposal)
    }

    /// Returns the complete immutable proposal contract retained by an active,
    /// halted, or completed occurrence. Authority-empty shells return `None`.
    #[must_use]
    pub fn proposal_contract(&self) -> Option<&ExactWorkProposalV1> {
        match &self.state {
            OccurrenceStateV1::Halted(value) => value.prior.proposal_contract.as_ref(),
            OccurrenceStateV1::Completed(value) => value.proposal_contract.as_ref(),
            _ => self.proposal(),
        }
    }

    /// Returns the exact historical observation basis, when any.
    #[must_use]
    pub fn observation(&self) -> Option<&ObservationResolutionV1> {
        self.state.proposal_basis().map(|basis| &basis.observation)
    }

    /// Returns the exact current-standing resolution retained by an admitted
    /// transition snapshot. Later terminal projections expose its identity
    /// through history; the Store keeps this exact earlier record available
    /// as product evidence.
    #[must_use]
    pub fn standing_resolution(&self) -> Option<&CurrentStandingResolutionV1> {
        self.state.admissible_basis().map(|basis| &basis.standing)
    }

    /// Returns the exact AG admission decision retained by an admitted
    /// transition snapshot.
    #[must_use]
    pub fn admission_decision(&self) -> Option<&AdmissionDecisionV1> {
        self.state.admissible_basis().map(|basis| &basis.decision)
    }

    /// Returns the exact AG spend, once consumed.
    #[must_use]
    pub fn ag_spend(&self) -> Option<&AgAuthorizationSpendV1> {
        match &self.state {
            OccurrenceStateV1::AuthorizationConsumed(value) => Some(&value.spend),
            OccurrenceStateV1::Dispatched(value) => Some(&value.0.authorized.spend),
            OccurrenceStateV1::ReconciliationRequired(value) => {
                Some(&value.dispatch.authorized.spend)
            }
            OccurrenceStateV1::SettledObservationRequired(value) => {
                Some(&value.dispatch.authorized.spend)
            }
            _ => None,
        }
    }

    /// Returns the deterministic AG issuance, once authorization is spent.
    #[must_use]
    pub fn issuance(&self) -> Option<&AgIssuanceV2> {
        match &self.state {
            OccurrenceStateV1::AuthorizationConsumed(value) => Some(&value.issuance),
            OccurrenceStateV1::Dispatched(value) => Some(&value.0.authorized.issuance),
            OccurrenceStateV1::ReconciliationRequired(value) => {
                Some(&value.dispatch.authorized.issuance)
            }
            OccurrenceStateV1::SettledObservationRequired(value) => {
                Some(&value.dispatch.authorized.issuance)
            }
            _ => None,
        }
    }

    /// Returns Docket custody, once accepted.
    #[must_use]
    pub fn docket_custody(&self) -> Option<&DocketCustodyV1> {
        match &self.state {
            OccurrenceStateV1::Dispatched(value) => Some(&value.0.custody),
            OccurrenceStateV1::ReconciliationRequired(value) => Some(&value.dispatch.custody),
            OccurrenceStateV1::SettledObservationRequired(value) => Some(&value.dispatch.custody),
            _ => None,
        }
    }

    /// Returns the exact known settlement, once consumed.
    #[must_use]
    pub fn settlement(&self) -> Option<&DocketSettlementV1> {
        match &self.state {
            OccurrenceStateV1::SettledObservationRequired(value) => Some(&value.settlement),
            _ => None,
        }
    }

    /// Returns the exact indeterminate record, when reconciliation is required.
    #[must_use]
    pub fn indeterminate(&self) -> Option<&IndeterminateOutcomeV1> {
        match &self.state {
            OccurrenceStateV1::ReconciliationRequired(value) => Some(&value.indeterminate),
            _ => None,
        }
    }

    /// Returns the latest durable reconciliation-round state, when present.
    #[must_use]
    pub fn reconciliation_round(&self) -> Option<&ReconciliationRoundStateV1> {
        match &self.state {
            OccurrenceStateV1::ReconciliationRequired(value) => value.reconciliation_round.as_ref(),
            _ => None,
        }
    }

    /// Returns the exact fresh observation that closed this occurrence.
    #[must_use]
    pub fn terminal_observation(&self) -> Option<&ObservationResolutionV1> {
        match &self.state {
            OccurrenceStateV1::Completed(value) => Some(&value.terminal_observation),
            _ => None,
        }
    }

    /// Returns the exact externally owned witness reference that closed this
    /// occurrence. The reference is evidence only and carries no live authority.
    #[must_use]
    pub fn terminal_witness(&self) -> Option<&TerminalWitnessRefV1> {
        match &self.state {
            OccurrenceStateV1::Completed(value) => Some(&value.terminal_witness),
            _ => None,
        }
    }

    /// Returns the prior occurrence basis for a not-yet-proposed continuation.
    #[must_use]
    pub fn prior_occurrence(&self) -> Option<&PriorOccurrenceBasisV1> {
        match &self.state {
            OccurrenceStateV1::ObservationRequired(value) => value.prior.as_ref(),
            _ => None,
        }
    }

    /// Returns the exact pre-spend revision constraint carried by an
    /// authority-empty revised occurrence.
    #[must_use]
    pub fn pre_spend_revision_constraint(&self) -> Option<&PreSpendRevisionConstraintV1> {
        self.prior_occurrence()
            .and_then(|prior| prior.pre_spend_revision.as_ref())
    }

    /// Returns halted details, when halted.
    #[must_use]
    pub fn halted(&self) -> Option<&HaltedV1> {
        match &self.state {
            OccurrenceStateV1::Halted(value) => Some(value),
            _ => None,
        }
    }
}

impl HaltedV1 {
    /// Returns the state from which the halt occurred.
    #[must_use]
    pub const fn source(&self) -> ProgramCounterV1 {
        self.source
    }

    /// Returns the exact halt reason.
    #[must_use]
    pub const fn reason(&self) -> &HaltReasonRefV1 {
        &self.reason
    }

    /// Returns the unresolved attempt, when one exists.
    #[must_use]
    pub const fn unresolved_attempt(&self) -> Option<&DocketAttemptRefV1> {
        self.unresolved_attempt.as_ref()
    }

    /// Returns the exact Docket-sealed requirement pinned into this halt.
    #[must_use]
    pub const fn governed_repair_requirement(&self) -> Option<&HumanDecisionRequirementV1> {
        self.governed_repair_requirement.as_ref()
    }

    /// Returns the terminal governed-repair rejection, when present.
    #[must_use]
    pub const fn governed_repair_closed(&self) -> Option<&GovernedRepairClosedV1> {
        self.governed_repair_closed.as_ref()
    }

    /// Returns the typed pre-spend insufficiency marker, when this is the
    /// exact pre-spend discovery halt class.
    #[must_use]
    pub const fn pre_spend_scope_insufficiency(&self) -> Option<&PreSpendScopeInsufficiencyV1> {
        self.pre_spend_scope_insufficiency.as_ref()
    }

    /// Returns the exact Docket refusal when this halt terminalized a consumed
    /// issuance before custody.
    #[must_use]
    pub const fn docket_issuance_refusal(&self) -> Option<&DocketIssuanceRefusalV1> {
        self.docket_issuance_refusal.as_ref()
    }
}

/// Enforces exact C1 rejected-review identity and finding-set equality.
pub fn validate_exact_c1_repair(
    citation: &C1RepairCitationV1,
    controlling: &C1RejectedReviewBasisV1,
) -> Result<(), KernelErrorV1> {
    if citation != controlling {
        return Err(KernelErrorV1::AlteredFindingSet);
    }
    Ok(())
}

fn illegal(current: &OccurrenceSnapshotV1, operation: &'static str) -> KernelErrorV1 {
    KernelErrorV1::IllegalTransition {
        from: current.program_counter(),
        operation,
    }
}

fn resolve_observation<O: ObservationResolverV1>(
    resolver: &mut O,
    key: &OccurrenceKeyV1,
    observation: &ObservationRefV1,
    subject: &Digest,
    now_unix_ms: u64,
) -> Result<ObservationResolutionV1, KernelErrorV1> {
    validate_canonical_timestamp(
        now_unix_ms,
        "observation consequence time is not canonically representable",
    )?;
    let resolved = resolver.resolve_observation(&ObservationResolutionRequestV1 {
        key,
        observation,
        subject,
        now_unix_ms,
    })?;
    if resolved.schema != OBSERVATION_RESOLUTION_SCHEMA_V1 {
        return Err(KernelErrorV1::ForeignSchema("observation resolution"));
    }
    if &resolved.key != key {
        return Err(KernelErrorV1::OccurrenceMismatch);
    }
    if &resolved.observation != observation {
        return Err(KernelErrorV1::BindingMismatch("observation"));
    }
    if &resolved.subject != subject {
        return Err(KernelErrorV1::BindingMismatch("observation subject"));
    }
    validate_canonical_timestamp(
        resolved.resolved_at_unix_ms,
        "observation resolution time is not canonically representable",
    )?;
    validate_canonical_timestamp(
        resolved.fresh_until_unix_ms,
        "observation freshness time is not canonically representable",
    )?;
    if resolved.resolved_at_unix_ms > now_unix_ms || now_unix_ms >= resolved.fresh_until_unix_ms {
        return Err(KernelErrorV1::ObservationNotCurrent);
    }
    match resolved.status {
        ObservationStatusV1::Current => Ok(resolved),
        ObservationStatusV1::Contradictory => Err(KernelErrorV1::ObservationContradiction),
        ObservationStatusV1::Stale
        | ObservationStatusV1::Superseded
        | ObservationStatusV1::Absent => Err(KernelErrorV1::ObservationNotCurrent),
    }
}

fn resolve_standing<S: StandingResolverV1>(
    resolver: &mut S,
    basis: &ProposalBasisV1,
    observation: &ObservationResolutionV1,
    now_unix_ms: u64,
) -> Result<CurrentStandingResolutionV1, KernelErrorV1> {
    validate_canonical_timestamp(
        now_unix_ms,
        "standing consequence time is not canonically representable",
    )?;
    let resolved = resolver.resolve_standing(&StandingResolutionRequestV1 {
        key: basis.meta.key(),
        observation: &observation.observation,
        proposal: &basis.proposal_ref,
        subject: basis.proposal.subject(),
        scope: basis.proposal.scope(),
        now_unix_ms,
    })?;
    if resolved.schema != STANDING_RESOLUTION_SCHEMA_V1 {
        return Err(KernelErrorV1::ForeignSchema("standing resolution"));
    }
    if resolved.key != basis.meta.key {
        return Err(KernelErrorV1::OccurrenceMismatch);
    }
    if resolved.observation != observation.observation {
        return Err(KernelErrorV1::BindingMismatch("standing observation"));
    }
    if resolved.proposal != basis.proposal_ref {
        return Err(KernelErrorV1::BindingMismatch("standing proposal"));
    }
    if resolved.subject != *basis.proposal.subject() {
        return Err(KernelErrorV1::BindingMismatch("standing subject"));
    }
    if resolved.scope != *basis.proposal.scope() {
        return Err(KernelErrorV1::BindingMismatch("standing scope"));
    }
    validate_canonical_timestamp(
        resolved.resolved_at_unix_ms,
        "standing resolution time is not canonically representable",
    )?;
    validate_canonical_timestamp(
        resolved.expires_at_unix_ms,
        "standing expiry is not canonically representable",
    )?;
    if resolved.resolved_at_unix_ms > now_unix_ms || now_unix_ms >= resolved.expires_at_unix_ms {
        return Err(KernelErrorV1::StandingNotCurrent);
    }
    match resolved.status {
        StandingStatusV1::Current => Ok(resolved),
        StandingStatusV1::Absent => Err(KernelErrorV1::StandingAbsent),
        StandingStatusV1::Revoked | StandingStatusV1::Superseded | StandingStatusV1::Expired => {
            Err(KernelErrorV1::StandingNotCurrent)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_admissibility<O, S, A>(
    basis: &ProposalBasisV1,
    observation_resolver: &mut O,
    standing_resolver: &mut S,
    decider: &mut A,
    controlling_rejected_review: Option<&C1RejectedReviewBasisV1>,
    now_unix_ms: u64,
) -> Result<
    (
        ObservationResolutionV1,
        CurrentStandingResolutionV1,
        AdmissionDecisionV1,
    ),
    KernelErrorV1,
>
where
    O: ObservationResolverV1,
    S: StandingResolverV1,
    A: AdmissibilityDeciderV1,
{
    if now_unix_ms >= basis.proposal.expires_at_unix_ms() {
        return Err(KernelErrorV1::Proposal("proposal expired"));
    }
    let observation = resolve_observation(
        observation_resolver,
        basis.meta.key(),
        &basis.observation.observation,
        basis.proposal.subject(),
        now_unix_ms,
    )?;
    if observation.normalized_preconditions != basis.observation.normalized_preconditions {
        return Err(KernelErrorV1::ObservationNotCurrent);
    }
    let standing = resolve_standing(standing_resolver, basis, &observation, now_unix_ms)?;
    match (&basis.proposal.repair, controlling_rejected_review) {
        (Some(citation), Some(controlling)) => validate_exact_c1_repair(citation, controlling)?,
        (Some(_), None) => return Err(KernelErrorV1::AlteredFindingSet),
        (None, _) => {}
    }
    let decision = decider.decide_admissibility(&AdmissibilityRequestV1 {
        proposal: &basis.proposal,
        observation: &observation,
        standing: &standing,
        controlling_rejected_review,
    })?;
    if decision.key != basis.meta.key
        || decision.observation != observation.observation
        || decision.proposal != basis.proposal_ref
        || decision.standing_resolution != standing.resolution
    {
        return Err(KernelErrorV1::BindingMismatch("admission decision"));
    }
    match decision.disposition {
        AdmissionDispositionV1::Admitted => Ok((observation, standing, decision)),
        AdmissionDispositionV1::Refused => Err(KernelErrorV1::Inadmissible),
        AdmissionDispositionV1::Contradiction => Err(KernelErrorV1::ObservationContradiction),
    }
}

fn build_issuance(admitted: &AdmissibleBasisV1, spend: &AgSpendRefV1) -> AgIssuanceV2 {
    #[derive(Serialize)]
    struct IssuanceBody<'a> {
        key: &'a OccurrenceKeyV1,
        program: &'a ProgramBasisRefV1,
        proposal: &'a ProposalRefV1,
        work_schema: &'a str,
        work: &'a Digest,
        nonclaims: &'a [Digest],
        expires_at_unix_ms: u64,
        subject: &'a Digest,
        effect_scope: &'a CanonicalEffectScopeV1,
        effect_scope_digest: &'a Digest,
        #[serde(skip_serializing_if = "Option::is_none")]
        governed_repair_checkpoint: Option<&'a GovernedRepairCheckpointV1>,
        observation: &'a ObservationRefV1,
        standing_resolution: &'a StandingResolutionRefV1,
        admission_decision: &'a AdmissionDecisionV1,
        mandate: &'a MandateRefV1,
        spend: &'a AgSpendRefV1,
    }
    let basis = IssuanceBody {
        key: admitted.proposal.meta.key(),
        program: admitted.proposal.meta.program(),
        proposal: &admitted.proposal.proposal_ref,
        work_schema: admitted.proposal.proposal.work_schema(),
        work: admitted.proposal.proposal.work(),
        nonclaims: admitted.proposal.proposal.nonclaims(),
        expires_at_unix_ms: admitted.proposal.proposal.expires_at_unix_ms(),
        subject: admitted.proposal.proposal.subject(),
        effect_scope: admitted.proposal.proposal.effect_scope(),
        effect_scope_digest: admitted.proposal.proposal.scope(),
        governed_repair_checkpoint: admitted.proposal.proposal.governed_repair_checkpoint(),
        observation: &admitted.proposal.observation.observation,
        standing_resolution: &admitted.standing.resolution,
        admission_decision: &admitted.decision,
        mandate: &admitted.standing.mandate,
        spend,
    };
    let issuance = AgIssuanceRefV1::from_digest(digest_value(AG_ISSUANCE_DIGEST_DOMAIN_V2, &basis));
    AgIssuanceV2 {
        schema: AG_ISSUANCE_SCHEMA_V2.to_owned(),
        issuance,
        key: basis.key.clone(),
        program: basis.program.clone(),
        proposal: basis.proposal.clone(),
        work_schema: basis.work_schema.to_owned(),
        work: basis.work.clone(),
        nonclaims: basis.nonclaims.to_vec(),
        expires_at_unix_ms: basis.expires_at_unix_ms,
        subject: basis.subject.clone(),
        effect_scope: basis.effect_scope.clone(),
        effect_scope_digest: basis.effect_scope_digest.clone(),
        governed_repair_checkpoint: basis.governed_repair_checkpoint.cloned(),
        observation: basis.observation.clone(),
        standing_resolution: basis.standing_resolution.clone(),
        admission_decision: basis.admission_decision.clone(),
        mandate: basis.mandate.clone(),
        spend: basis.spend.clone(),
    }
}

fn validate_custody(
    custody: &DocketCustodyV1,
    authorized: &AuthorizationConsumedV1,
) -> Result<(), KernelErrorV1> {
    validate_canonical_timestamp(
        custody.accepted_at_unix_ms,
        "Docket custody time is not canonically representable",
    )?;
    if custody.schema != DOCKET_CUSTODY_SCHEMA_V1 {
        return Err(KernelErrorV1::ForeignSchema("Docket custody"));
    }
    if custody.issuance != authorized.issuance.issuance {
        return Err(KernelErrorV1::BindingMismatch("custody issuance"));
    }
    if custody.ag_spend != authorized.spend.spend {
        return Err(KernelErrorV1::BindingMismatch("custody AG spend"));
    }
    if custody.execution_standing.as_digest() == authorized.spend.spend.as_digest()
        || custody.execution_standing.as_digest() == authorized.spend.authorization.as_digest()
    {
        return Err(KernelErrorV1::BindingMismatch(
            "Docket standing substituted an AG instrument",
        ));
    }
    if custody.attempt != DocketAttemptRefV1::for_issuance(&custody.issuance) {
        return Err(KernelErrorV1::BindingMismatch("canonical Docket attempt"));
    }
    if custody.executor_marker.as_digest() == custody.execution_standing.as_digest()
        || custody.executor_marker.as_digest() == authorized.spend.spend.as_digest()
        || custody.executor_marker.as_digest() == authorized.spend.authorization.as_digest()
        || custody.executor_marker.as_digest() == custody.attempt.as_digest()
    {
        return Err(KernelErrorV1::BindingMismatch(
            "executor marker substituted an authority/attempt instrument",
        ));
    }
    Ok(())
}

fn validate_settlement(
    settlement: &DocketSettlementV1,
    dispatch: &DispatchBasisV1,
) -> Result<(), KernelErrorV1> {
    validate_canonical_timestamp(
        settlement.settled_at_unix_ms,
        "Docket settlement time is not canonically representable",
    )?;
    if settlement.schema != DOCKET_SETTLEMENT_SCHEMA_V1 {
        return Err(KernelErrorV1::ForeignSchema("Docket settlement"));
    }
    if settlement.issuance != dispatch.authorized.issuance.issuance {
        return Err(KernelErrorV1::BindingMismatch("settlement issuance"));
    }
    if settlement.attempt != dispatch.custody.attempt {
        return Err(KernelErrorV1::BindingMismatch("settlement attempt"));
    }
    if settlement.executor_marker != dispatch.custody.executor_marker {
        return Err(KernelErrorV1::BindingMismatch("settlement executor marker"));
    }
    if settlement.cumulative_effect_journal_identity.is_some() {
        if settlement.settlement != settlement.expected_reference()? {
            return Err(KernelErrorV1::BindingMismatch(
                "complete Docket settlement identity",
            ));
        }
    } else {
        // Decoder-only rejected-R1 historical law. Production Docket intake
        // requires the R2 field before this kernel boundary.
        let outcome = match settlement.outcome {
            KnownOutcomeV1::Success => "success",
            KnownOutcomeV1::Failure => "failure",
        };
        let legacy = Digest::hash_domain(
            DOCKET_SETTLEMENT_IDENTITY_DOMAIN_V1,
            format!(
                "{}:{}:{}:{outcome}",
                settlement.issuance.as_str(),
                settlement.attempt.as_str(),
                settlement.receipt.as_str()
            )
            .as_bytes(),
        );
        if settlement.settlement.as_digest() != &legacy {
            return Err(KernelErrorV1::BindingMismatch(
                "rejected-R1 historical Docket settlement identity",
            ));
        }
    }
    Ok(())
}

fn validate_indeterminate(
    indeterminate: &IndeterminateOutcomeV1,
    dispatch: &DispatchBasisV1,
) -> Result<(), KernelErrorV1> {
    if indeterminate.issuance != dispatch.authorized.issuance.issuance {
        return Err(KernelErrorV1::BindingMismatch("indeterminate issuance"));
    }
    if indeterminate.attempt != dispatch.custody.attempt {
        return Err(KernelErrorV1::BindingMismatch("indeterminate attempt"));
    }
    Ok(())
}

fn validate_round_reservation(
    request: &ReconciliationRoundRequestV1,
    reservation: &DocketReconciliationRoundReservationV1,
) -> Result<(), KernelErrorV1> {
    request.validate()?;
    if reservation.schema != DOCKET_RECONCILIATION_ROUND_RESERVATION_SCHEMA_V1
        || reservation.request != request.request
        || reservation.round != request.round
        || reservation.issuance != request.issuance
        || reservation.attempt != request.attempt
        || reservation.caller_state_digest != request.caller_state_digest
        || reservation.predecessor_round != request.predecessor_round
        || reservation.predecessor_reconciliation != request.predecessor_reconciliation
    {
        return Err(KernelErrorV1::BindingMismatch(
            "Docket reconciliation round reservation",
        ));
    }
    validate_canonical_timestamp(
        reservation.claimed_at_unix_ms,
        "reconciliation reservation time is not canonically representable",
    )?;
    let expected = DocketReconciliationReservationRefV1::from_digest(digest_value(
        "docket.governed-loop.reconciliation-round-reservation/v1",
        &DocketReconciliationReservationIdentityBasisV1 {
            schema: &reservation.schema,
            request: &reservation.request,
            round: &reservation.round,
            issuance: &reservation.issuance,
            attempt: &reservation.attempt,
            caller_state_digest: &reservation.caller_state_digest,
            predecessor_round: reservation.predecessor_round.as_ref(),
            predecessor_reconciliation: reservation.predecessor_reconciliation.as_ref(),
            source_cut: &reservation.source_cut,
            checkpoint_identity: reservation.checkpoint_identity.as_ref(),
            executor_binding: &reservation.executor_binding,
            claimed_at_unix_ms: reservation.claimed_at_unix_ms,
        },
    ));
    if reservation.reservation != expected {
        return Err(KernelErrorV1::BindingMismatch(
            "Docket reconciliation reservation identity",
        ));
    }
    Ok(())
}

fn validate_round_completion(
    request: &ReconciliationRoundRequestV1,
    reservation: &DocketReconciliationRoundReservationV1,
    completion: &DocketReconciliationRoundCompletionV1,
) -> Result<(), KernelErrorV1> {
    validate_round_reservation(request, reservation)?;
    if completion.schema != DOCKET_RECONCILIATION_ROUND_COMPLETION_SCHEMA_V1
        || completion.reservation != reservation.reservation
        || completion.round != request.round
    {
        return Err(KernelErrorV1::BindingMismatch(
            "Docket reconciliation round completion",
        ));
    }
    validate_canonical_timestamp(
        completion.completed_at_unix_ms,
        "reconciliation completion time is not canonically representable",
    )?;
    let expected = DocketReconciliationCompletionRefV1::from_digest(digest_value(
        "docket.governed-loop.reconciliation-round-completion/v1",
        &DocketReconciliationCompletionIdentityBasisV1 {
            schema: &completion.schema,
            reservation: &completion.reservation,
            round: &completion.round,
            result_identity: &completion.result_identity,
            completed_at_unix_ms: completion.completed_at_unix_ms,
        },
    ));
    if completion.completion != expected {
        return Err(KernelErrorV1::BindingMismatch(
            "Docket reconciliation completion identity",
        ));
    }
    Ok(())
}

fn validate_initial_reconciliation_round_successor(
    source: &OccurrenceSnapshotV1,
    target: &ReconciliationRequiredV1,
) -> Result<(), KernelErrorV1> {
    let Some(round) = &target.reconciliation_round else {
        // Existing non-round paths (initial executor result and restart
        // recovery observation) remain legal historical/current cuts.
        return Ok(());
    };
    let (request, reservation, completion) = match round {
        ReconciliationRoundStateV1::Unresolved {
            request,
            reservation,
        } => (request, reservation, None),
        ReconciliationRoundStateV1::CompletedIndeterminate {
            request,
            reservation,
            completion,
        } => (request, reservation, Some(completion)),
    };
    if request.caller_state_digest != *source.state_digest()
        || request.predecessor_round.is_some()
        || request.predecessor_reconciliation.is_some()
    {
        return Err(KernelErrorV1::BindingMismatch(
            "initial reconciliation round source",
        ));
    }
    validate_round_reservation(request, reservation)?;
    if let Some(completion) = completion {
        validate_round_completion(request, reservation, completion)?;
    }
    Ok(())
}

fn validate_reconciliation_round_successor(
    source_snapshot: &OccurrenceSnapshotV1,
    source: &ReconciliationRequiredV1,
    target: &ReconciliationRequiredV1,
) -> Result<(), KernelErrorV1> {
    validate_indeterminate(&target.indeterminate, &target.dispatch)?;
    let Some(target_round) = &target.reconciliation_round else {
        return Err(KernelErrorV1::BindingMismatch(
            "reconciliation successor lost round state",
        ));
    };
    let (request, reservation, completion) = match target_round {
        ReconciliationRoundStateV1::Unresolved {
            request,
            reservation,
        } => (request, reservation, None),
        ReconciliationRoundStateV1::CompletedIndeterminate {
            request,
            reservation,
            completion,
        } => (request, reservation, Some(completion)),
    };
    validate_round_reservation(request, reservation)?;
    if let Some(completion) = completion {
        validate_round_completion(request, reservation, completion)?;
    }
    match &source.reconciliation_round {
        None => {
            if request.caller_state_digest != *source_snapshot.state_digest()
                || request.predecessor_round.is_some()
                || request.predecessor_reconciliation.is_some()
            {
                return Err(KernelErrorV1::BindingMismatch(
                    "first reconciliation successor round",
                ));
            }
        }
        Some(ReconciliationRoundStateV1::Unresolved {
            request: old_request,
            reservation: old_reservation,
        }) => {
            if request != old_request || reservation != old_reservation || completion.is_none() {
                return Err(KernelErrorV1::BindingMismatch(
                    "unresolved reconciliation completion",
                ));
            }
        }
        Some(ReconciliationRoundStateV1::CompletedIndeterminate {
            request: predecessor,
            ..
        }) => {
            if request.caller_state_digest != *source_snapshot.state_digest()
                || request.predecessor_round.as_ref() != Some(&predecessor.round)
                || request.predecessor_reconciliation.as_ref()
                    != Some(&source.indeterminate.reconciliation)
            {
                return Err(KernelErrorV1::BindingMismatch(
                    "later reconciliation successor round",
                ));
            }
        }
    }
    Ok(())
}

type ReconciliationBasis<'a> = (
    &'a DispatchBasisV1,
    Option<&'a IndeterminateOutcomeV1>,
    Option<&'a ReconciliationRoundStateV1>,
);

fn reconciliation_basis(
    current: &OccurrenceSnapshotV1,
) -> Result<ReconciliationBasis<'_>, KernelErrorV1> {
    match current.state() {
        OccurrenceStateV1::Dispatched(value) => Ok((&value.0, None, None)),
        OccurrenceStateV1::ReconciliationRequired(value) => Ok((
            &value.dispatch,
            Some(&value.indeterminate),
            value.reconciliation_round.as_ref(),
        )),
        _ => Err(illegal(current, "record_reconciliation_round")),
    }
}

fn validate_round_request_for_current(
    current: &OccurrenceSnapshotV1,
    request: &ReconciliationRoundRequestV1,
    dispatch: &DispatchBasisV1,
    prior: Option<&ReconciliationRoundStateV1>,
) -> Result<(), KernelErrorV1> {
    request.validate()?;
    if request.issuance != dispatch.authorized.issuance.issuance
        || request.attempt != dispatch.custody.attempt
    {
        return Err(KernelErrorV1::BindingMismatch(
            "reconciliation round current cut",
        ));
    }
    if let Some(ReconciliationRoundStateV1::Unresolved {
        request: prior_request,
        ..
    }) = prior
    {
        if prior_request == request {
            return Ok(());
        }
        return Err(KernelErrorV1::BindingMismatch(
            "unresolved reconciliation round cannot enable a later poll",
        ));
    }
    if request.caller_state_digest != *current.state_digest() {
        return Err(KernelErrorV1::BindingMismatch(
            "reconciliation round caller cut",
        ));
    }
    match prior {
        None => {
            if request.predecessor_round.is_some() || request.predecessor_reconciliation.is_some() {
                return Err(KernelErrorV1::BindingMismatch(
                    "first reconciliation round predecessor",
                ));
            }
        }
        Some(ReconciliationRoundStateV1::CompletedIndeterminate {
            request: predecessor,
            ..
        }) => {
            let Some(indeterminate) = current.indeterminate() else {
                return Err(KernelErrorV1::StateInvariant(
                    "completed reconciliation round without indeterminate state",
                ));
            };
            if request.predecessor_round.as_ref() != Some(&predecessor.round)
                || request.predecessor_reconciliation.as_ref()
                    != Some(&indeterminate.reconciliation)
            {
                return Err(KernelErrorV1::BindingMismatch(
                    "later reconciliation round predecessor",
                ));
            }
        }
        Some(ReconciliationRoundStateV1::Unresolved { .. }) => {
            unreachable!("unresolved prior returned or refused before caller-cut validation")
        }
    }
    Ok(())
}

fn current_prior_basis(current: &OccurrenceSnapshotV1) -> PriorOccurrenceBasisV1 {
    PriorOccurrenceBasisV1 {
        key: current.key().clone(),
        proposal: current
            .state
            .proposal_basis()
            .map(|basis| basis.proposal_ref.clone()),
        proposal_contract: current
            .state
            .proposal_basis()
            .map(|basis| basis.proposal.clone()),
        normalized_preconditions: current
            .state
            .proposal_basis()
            .map(|basis| basis.observation.normalized_preconditions.clone()),
        effect_scope: current
            .state
            .proposal_basis()
            .map(|basis| basis.proposal.effect_scope().clone()),
        issuance: current.issuance().map(|value| value.issuance.clone()),
        docket_custody: current.docket_custody().map(DocketCustodyV1::reference),
        docket_attempt: current.docket_custody().map(|value| value.attempt.clone()),
        state_digest: current.state_digest.clone(),
        authorized_successor: None,
        pre_spend_revision: None,
    }
}

fn expired_issuance_halt_reason(authorized: &AuthorizationConsumedV1) -> HaltReasonRefV1 {
    HaltReasonRefV1::from_digest(digest_value(
        "ag.governed-loop.expired-unaccepted-issuance/v1",
        &(
            &authorized.issuance.issuance,
            authorized.issuance.expires_at_unix_ms,
            &authorized.spend.spend,
        ),
    ))
}

fn validate_requirement_against_halt(
    halted: &HaltedV1,
    requirement: &HumanDecisionRequirementV1,
) -> Result<(), KernelErrorV1> {
    requirement.validate()?;
    let docket_outcome = match requirement {
        HumanDecisionRequirementV1::ScopeExpansion(value) => {
            if halted.prior.effect_scope.as_ref() != Some(&value.original_scope) {
                return Err(KernelErrorV1::HumanDecisionRequest(
                    "original scope differs from halted proposal",
                ));
            }
            value.docket_outcome.as_ref()
        }
        HumanDecisionRequirementV1::Readjudication(value) => value.docket_outcome.as_ref(),
    };
    match docket_outcome {
        None if halted.prior.docket_attempt.is_some() => Err(KernelErrorV1::HumanDecisionRequest(
            "post-spend request lacks sealed Docket outcome",
        )),
        Some(_) if halted.prior.docket_attempt.is_none() => Err(
            KernelErrorV1::HumanDecisionRequest("pre-spend request claims Docket outcome"),
        ),
        Some(outcome) => {
            if halted.prior.issuance.as_ref() != Some(&outcome.issuance)
                || halted.prior.docket_custody.as_ref() != Some(&outcome.custody)
                || halted.prior.docket_attempt.as_ref() != Some(&outcome.attempt)
            {
                return Err(KernelErrorV1::HumanDecisionRequest(
                    "Docket outcome differs from halted custody/attempt",
                ));
            }
            Ok(())
        }
        None => Ok(()),
    }
}

fn validate_decision_request(
    current: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    request: &HumanDecisionRequestV1,
    now_unix_ms: u64,
) -> Result<(), KernelErrorV1> {
    validate_canonical_timestamp(
        now_unix_ms,
        "decision consequence time is not canonically representable",
    )?;
    request.validate()?;
    if request.key != halted.meta.key
        || request.halted_state_digest != current.state_digest
        || request.program != halted.meta.program
        || request.proposal != halted.prior.proposal
    {
        return Err(KernelErrorV1::HumanDecisionRequest(
            "wrong halted occurrence/state/program/proposal",
        ));
    }
    if now_unix_ms >= request.expires_at_unix_ms {
        return Err(KernelErrorV1::HumanDecisionRequest("expired"));
    }
    validate_requirement_against_halt(halted, &request.requirement)
}

fn validate_governed_repair_artifact(
    current: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    request: &HumanDecisionRequestV1,
    artifact: &GovernedRepairDispositionV1,
    profile: &GovernedRepairVerifierProfileV1,
    now_unix_ms: u64,
) -> Result<(), KernelErrorV1> {
    validate_canonical_timestamp(
        now_unix_ms,
        "disposition consequence time is not canonically representable",
    )?;
    validate_canonical_timestamp(
        artifact.expires_at_unix_ms,
        "governed repair disposition expiry is not canonically representable",
    )?;
    if artifact.schema != GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1 {
        return Err(KernelErrorV1::ForeignSchema("governed repair disposition"));
    }
    if artifact.campaign != halted.meta.key.campaign
        || artifact.occurrence != halted.meta.key.occurrence
        || artifact.halted_state_digest != current.state_digest
        || artifact.disposition.request() != &request.reference()
    {
        return Err(KernelErrorV1::HumanDisposition(
            "wrong campaign/occurrence/state/request",
        ));
    }
    if artifact.principal != profile.principal
        || artifact.mandate != profile.mandate
        || artifact.verifier_profile != profile.profile
        || request.required_verifier_profile != profile.profile
        || request.required_verifier_root != profile.root
        || request.required_verifier_executable != profile.executable
    {
        return Err(KernelErrorV1::HumanDisposition("wrong verifier profile"));
    }
    match &artifact.disposition {
        GovernedRepairDispositionKindV1::ApproveExactExpansion { checkpoint, .. }
        | GovernedRepairDispositionKindV1::RequestReadjudication { checkpoint, .. } => {
            checkpoint.validate()?;
            if let Some(outcome) = match &request.requirement {
                HumanDecisionRequirementV1::ScopeExpansion(value) => value.docket_outcome.as_ref(),
                HumanDecisionRequirementV1::Readjudication(value) => value.docket_outcome.as_ref(),
            } {
                if checkpoint.docket_checkpoint.as_ref() != Some(&outcome.checkpoint) {
                    return Err(KernelErrorV1::HumanDisposition(
                        "successor checkpoint differs from sealed Docket checkpoint",
                    ));
                }
                if let Some(sealed_work) = &outcome.immutable_work_checkpoint
                    && checkpoint != sealed_work
                {
                    return Err(KernelErrorV1::HumanDisposition(
                        "successor checkpoint differs from immutable work checkpoint sealed by Docket",
                    ));
                }
            }
        }
        GovernedRepairDispositionKindV1::Reject { .. } => {}
    }
    if now_unix_ms >= artifact.expires_at_unix_ms
        || artifact.expires_at_unix_ms > request.expires_at_unix_ms
    {
        return Err(KernelErrorV1::HumanDisposition("expired"));
    }
    if halted
        .meta
        .used_human_decisions
        .contains(&artifact.decision)
    {
        return Err(KernelErrorV1::HumanDisposition("replayed decision"));
    }
    let decision_class = match &artifact.disposition {
        GovernedRepairDispositionKindV1::ApproveExactExpansion { .. } => {
            GovernedRepairDecisionClassV1::ApproveExactExpansion
        }
        GovernedRepairDispositionKindV1::Reject { .. } => GovernedRepairDecisionClassV1::Reject,
        GovernedRepairDispositionKindV1::RequestReadjudication { .. } => {
            GovernedRepairDecisionClassV1::RequestReadjudication
        }
    };
    if !request.available_decisions.contains(&decision_class) {
        return Err(KernelErrorV1::HumanDisposition(
            "decision class not offered by request",
        ));
    }
    if let GovernedRepairDispositionKindV1::ApproveExactExpansion {
        successor_occurrence,
        ..
    }
    | GovernedRepairDispositionKindV1::RequestReadjudication {
        successor_occurrence,
        ..
    } = &artifact.disposition
        && *successor_occurrence == halted.meta.key.occurrence
    {
        return Err(KernelErrorV1::OccurrenceReused);
    }
    Ok(())
}

fn validate_governed_repair_verification(
    current: &OccurrenceSnapshotV1,
    request: &HumanDecisionRequestV1,
    artifact: &GovernedRepairDispositionV1,
    profile: &GovernedRepairVerifierProfileV1,
    verification: &GovernedRepairVerificationV1,
    now_unix_ms: u64,
) -> Result<(), KernelErrorV1> {
    validate_canonical_timestamp(
        now_unix_ms,
        "verification consequence time is not canonically representable",
    )?;
    validate_canonical_timestamp(
        verification.verified_at_unix_ms,
        "verification time is not canonically representable",
    )?;
    validate_canonical_timestamp(
        verification.expires_at_unix_ms,
        "verification expiry is not canonically representable",
    )?;
    if verification.schema != GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1 {
        return Err(KernelErrorV1::ForeignSchema("governed repair verification"));
    }
    if verification.disposition != artifact.reference()
        || verification.request != request.reference()
        || verification.halted_state_digest != current.state_digest
        || verification.verifier_profile != profile.profile
        || verification.verifier_root != profile.root
        || verification.verifier_executable != profile.executable
        || verification.verified_at_unix_ms > now_unix_ms
        || now_unix_ms >= verification.expires_at_unix_ms
        || verification.expires_at_unix_ms > artifact.expires_at_unix_ms
    {
        return Err(KernelErrorV1::HumanDisposition(
            "verification response not exact/current",
        ));
    }
    Ok(())
}

fn consume_governed_repair_decision(
    current: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    artifact: &GovernedRepairDispositionV1,
) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
    let mut consumed = halted.clone();
    consumed
        .meta
        .used_human_decisions
        .push(artifact.decision.clone());
    let next = successor_snapshot(current, OccurrenceStateV1::Halted(consumed));
    next.validate_integrity()?;
    Ok(next)
}

fn consume_governed_repair_rejection(
    current: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    request: &HumanDecisionRequestV1,
    artifact: &GovernedRepairDispositionV1,
    reason: &Digest,
) -> Result<OccurrenceSnapshotV1, KernelErrorV1> {
    if halted.governed_repair_closed.is_some() {
        return Err(KernelErrorV1::HumanDisposition(
            "governed repair occurrence already closed",
        ));
    }
    let residual = ResidualIdV1::from_digest(digest_value(
        "ag.governed-loop.rejected-repair-residual/v1",
        &(request.reference(), artifact.reference(), reason),
    ));
    let mut obligations = halted.meta.residuals.as_slice().to_vec();
    obligations.push(ResidualObligationV1 {
        residual: residual.clone(),
        owner: artifact.mandate.as_digest().clone(),
        subject: request.reference().as_digest().clone(),
        statement: reason.clone(),
    });
    let mut consumed = halted.clone();
    consumed.meta.residuals = ResidualSetV1::new(obligations)?;
    consumed
        .meta
        .used_human_decisions
        .push(artifact.decision.clone());
    consumed.governed_repair_closed = Some(GovernedRepairClosedV1 {
        request: request.reference(),
        disposition: artifact.reference(),
        reason: reason.clone(),
        residual,
    });
    let next = successor_snapshot(current, OccurrenceStateV1::Halted(consumed));
    next.validate_integrity()?;
    Ok(next)
}

fn open_governed_repair_successor(
    current: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    artifact: &GovernedRepairDispositionV1,
    occurrence: OccurrenceId,
    program: ProgramBasisRefV1,
    authorized_successor: AuthorizedSuccessorBasisV1,
) -> Result<(OccurrenceSnapshotV1, OccurrenceSnapshotV1), KernelErrorV1> {
    if halted.unresolved_attempt.is_some() || halted.governed_repair_closed.is_some() {
        return Err(KernelErrorV1::UnresolvedAttempt);
    }
    let halted_snapshot = consume_governed_repair_decision(current, halted, artifact)?;
    let prior = PriorOccurrenceBasisV1 {
        key: halted.meta.key.clone(),
        proposal: halted.prior.proposal.clone(),
        proposal_contract: halted.prior.proposal_contract.clone(),
        normalized_preconditions: halted.prior.normalized_preconditions.clone(),
        effect_scope: halted.prior.effect_scope.clone(),
        issuance: halted.prior.issuance.clone(),
        docket_custody: halted.prior.docket_custody.clone(),
        docket_attempt: halted.prior.docket_attempt.clone(),
        state_digest: halted_snapshot.state_digest.clone(),
        authorized_successor: Some(authorized_successor),
        pre_spend_revision: None,
    };
    let state = OccurrenceStateV1::ObservationRequired(ObservationRequiredV1 {
        meta: OccurrenceMetaV1 {
            key: OccurrenceKeyV1 {
                campaign: halted.meta.key.campaign.clone(),
                occurrence,
            },
            program,
            residuals: halted_snapshot.state.meta().residuals.clone(),
            budget: halted_snapshot.state.meta().budget,
            used_human_decisions: halted_snapshot.state.meta().used_human_decisions.clone(),
        },
        prior: Some(prior),
    });
    let successor = successor_snapshot(&halted_snapshot, state);
    successor.validate_integrity()?;
    Ok((halted_snapshot, successor))
}

fn validate_recorded_proposal(
    from: &ObservationRequiredV1,
    to: &ProposalBasisV1,
) -> Result<(), KernelErrorV1> {
    if from.meta.key != to.meta.key
        || from.meta.program != to.meta.program
        || from.meta.residuals != to.meta.residuals
        || from.meta.used_human_decisions != to.meta.used_human_decisions
    {
        return Err(KernelErrorV1::StateInvariant(
            "proposal transition metadata",
        ));
    }
    match (&from.prior, &to.link) {
        (None, OccurrenceLinkV1::Initial) if from.meta.budget == to.meta.budget => Ok(()),
        (Some(prior), OccurrenceLinkV1::RetryOf(linked))
            if linked == &prior.key
                && prior.authorized_successor.is_none()
                && prior.pre_spend_revision.is_none()
                && prior.key != from.meta.key
                && prior.proposal.as_ref() == Some(&to.proposal_ref)
                && prior.normalized_preconditions.as_ref()
                    == Some(&to.observation.normalized_preconditions)
                && to.meta.budget.retries_used
                    == from.meta.budget.retries_used.saturating_add(1)
                && to.meta.budget.retry_limit == from.meta.budget.retry_limit
                && to.meta.budget.probe_limit == from.meta.budget.probe_limit
                && to.meta.budget.probes_used == from.meta.budget.probes_used
                && to.meta.budget.escalation_limit == from.meta.budget.escalation_limit
                && to.meta.budget.escalations_used == from.meta.budget.escalations_used =>
        {
            Ok(())
        }
        (Some(prior), OccurrenceLinkV1::SuccessorOf(linked))
            if linked == &prior.key
                && prior.key != from.meta.key
                && prior.proposal.as_ref() != Some(&to.proposal_ref)
                && match &prior.authorized_successor {
                    None => true,
                    Some(AuthorizedSuccessorBasisV1::ExactScopeExpansion {
                        successor_scope,
                        checkpoint,
                        ..
                    }) => {
                        to.proposal.effect_scope() == successor_scope
                            && to.proposal.governed_repair_checkpoint() == Some(checkpoint)
                    }
                    Some(AuthorizedSuccessorBasisV1::Readjudication {
                        successor_program,
                        adjudication_scope,
                        checkpoint,
                        ..
                    }) => {
                        &to.meta.program == successor_program
                            && to.proposal.effect_scope() == adjudication_scope
                            && to.proposal.governed_repair_checkpoint() == Some(checkpoint)
                    }
                }
                && match &prior.pre_spend_revision {
                    None => true,
                    Some(constraint) => {
                        to.proposal_ref == constraint.revised_proposal
                            && to.proposal == constraint.exact_revised_proposal
                    }
                }
                && from.meta.budget == to.meta.budget =>
        {
            Ok(())
        }
        _ => Err(KernelErrorV1::StateInvariant(
            "proposal continuation classification",
        )),
    }
}

fn same_proposal_basis(left: &ProposalBasisV1, right: &ProposalBasisV1) -> bool {
    left.meta == right.meta
        && left.proposal == right.proposal
        && left.proposal_ref == right.proposal_ref
        && left.link == right.link
        && left.observation.schema == right.observation.schema
        && left.observation.key == right.observation.key
        && left.observation.observation == right.observation.observation
        && left.observation.normalized_preconditions == right.observation.normalized_preconditions
        && left.observation.subject == right.observation.subject
        && right.observation.status == ObservationStatusV1::Current
}

fn validate_continuation(
    source: &OccurrenceSnapshotV1,
    expected_proposal: Option<&ProposalRefV1>,
    expected_preconditions: Option<&PreconditionBasisRefV1>,
    target: &ObservationRequiredV1,
    allow_program_replacement: bool,
) -> Result<(), KernelErrorV1> {
    let source_meta = source.state.meta();
    let prior = target
        .prior
        .as_ref()
        .ok_or(KernelErrorV1::StateInvariant("missing continuation prior"))?;
    if target.meta.key == source_meta.key
        || target.meta.key.campaign != source_meta.key.campaign
        || prior.key != source_meta.key
        || prior.state_digest != source.state_digest
        || prior.proposal.as_ref() != expected_proposal
        || prior.normalized_preconditions.as_ref() != expected_preconditions
        || target.meta.residuals != source_meta.residuals
        || target.meta.budget != source_meta.budget
        || target.meta.used_human_decisions != source_meta.used_human_decisions
        || (!allow_program_replacement && target.meta.program != source_meta.program)
    {
        return Err(KernelErrorV1::StateInvariant("continuation linkage"));
    }
    Ok(())
}

fn validate_pre_spend_revision_successor(
    source: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    target: &ObservationRequiredV1,
) -> Result<(), KernelErrorV1> {
    let marker =
        halted
            .pre_spend_scope_insufficiency
            .as_ref()
            .ok_or(KernelErrorV1::StateInvariant(
                "missing pre-spend insufficiency marker",
            ))?;
    marker.validate()?;
    let prior = target
        .prior
        .as_ref()
        .ok_or(KernelErrorV1::StateInvariant("missing pre-spend prior"))?;
    let constraint = prior
        .pre_spend_revision
        .as_ref()
        .ok_or(KernelErrorV1::StateInvariant(
            "missing pre-spend revision constraint",
        ))?;
    constraint.exact_revised_proposal.validate()?;
    let original = halted
        .prior
        .proposal_contract
        .as_ref()
        .ok_or(KernelErrorV1::StateInvariant(
            "pre-spend revision lacks original proposal",
        ))?;
    let mechanically_revised = original
        .derive_pre_spend_revision(constraint.exact_revised_proposal.effect_scope().clone())?;
    if halted.source != ProgramCounterV1::ProposalRecorded
        || halted.history != AuthorityHistoryV1::default()
        || halted.governed_repair_requirement.is_some()
        || halted.governed_repair_closed.is_some()
        || halted.docket_issuance_refusal.is_some()
        || prior.key != halted.meta.key
        || prior.state_digest != source.state_digest
        || prior.proposal != halted.prior.proposal
        || prior.proposal_contract != halted.prior.proposal_contract
        || prior.normalized_preconditions.is_some()
        || prior.effect_scope != halted.prior.effect_scope
        || prior.issuance.is_some()
        || prior.docket_custody.is_some()
        || prior.docket_attempt.is_some()
        || prior.authorized_successor.is_some()
        || constraint.predecessor != halted.meta.key
        || constraint.revised_proposal != constraint.exact_revised_proposal.reference()
        || constraint.exact_revised_proposal == *original
        || constraint.exact_revised_proposal != mechanically_revised
        || constraint.exact_revised_proposal.campaign() != &halted.meta.key.campaign
        || target.meta.key.campaign != halted.meta.key.campaign
        || target.meta.key.occurrence == halted.meta.key.occurrence
        || target.meta.program != halted.meta.program
        || target.meta.residuals != halted.meta.residuals
        || target.meta.budget != halted.meta.budget
        || target.meta.used_human_decisions != halted.meta.used_human_decisions
    {
        return Err(KernelErrorV1::StateInvariant(
            "pre-spend revision successor linkage",
        ));
    }
    Ok(())
}

const fn is_safe_halt_source(source: ProgramCounterV1) -> bool {
    matches!(
        source,
        ProgramCounterV1::ObservationRequired
            | ProgramCounterV1::ProposalRecorded
            | ProgramCounterV1::StandingRequired
            | ProgramCounterV1::AdmissiblePendingAuthorization
            | ProgramCounterV1::ReconciliationRequired
            | ProgramCounterV1::SettledObservationRequired
    )
}

fn budget_same_or_one_escalation(left: LoopBudgetV1, right: LoopBudgetV1) -> bool {
    left.retry_limit == right.retry_limit
        && left.retries_used == right.retries_used
        && left.probe_limit == right.probe_limit
        && left.probes_used == right.probes_used
        && left.escalation_limit == right.escalation_limit
        && (left.escalations_used == right.escalations_used
            || left.escalations_used.saturating_add(1) == right.escalations_used)
}

fn validate_halt_successor(
    source: &OccurrenceSnapshotV1,
    to: &HaltedV1,
) -> Result<(), KernelErrorV1> {
    let from = source.state();
    let from_meta = from.meta();
    let expected_unresolved = match from {
        OccurrenceStateV1::ReconciliationRequired(value) => {
            Some(value.dispatch.custody.attempt.clone())
        }
        _ => None,
    };
    let expected_unresolved = if from.program_counter() == ProgramCounterV1::Dispatched
        || to.governed_repair_requirement.is_some()
    {
        None
    } else {
        expected_unresolved
    };
    let governed_source = matches!(
        from.program_counter(),
        ProgramCounterV1::Dispatched | ProgramCounterV1::ReconciliationRequired
    );
    let residuals_match = if let Some(refusal) = &to.docket_issuance_refusal {
        let mut expected = from_meta.residuals.as_slice().to_vec();
        expected.push(docket_issuance_refusal_residual(refusal));
        ResidualSetV1::new(expected)? == to.meta.residuals
    } else {
        to.meta.residuals == from_meta.residuals
    };
    let pre_spend_marker_valid = if let Some(marker) = &to.pre_spend_scope_insufficiency {
        marker.validate()?;
        let Some(proposal) = from.proposal_basis() else {
            return Err(KernelErrorV1::StateInvariant(
                "pre-spend halt without proposal basis",
            ));
        };
        from.program_counter() == ProgramCounterV1::ProposalRecorded
            && marker.key == from_meta.key
            && marker.proposal == proposal.proposal_ref
            && marker.original_scope_identity == *proposal.proposal.scope()
            && marker.source_state_digest == source.state_digest
            && to.reason
                == HaltReasonRefV1::from_digest(digest_value(
                    PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1,
                    &marker.insufficiency,
                ))
            && to.history == AuthorityHistoryV1::default()
            && to.governed_repair_requirement.is_none()
            && to.governed_repair_closed.is_none()
            && to.docket_issuance_refusal.is_none()
    } else {
        true
    };
    if to.source != from.program_counter()
        || to.meta.key != from_meta.key
        || to.meta.program != from_meta.program
        || !residuals_match
        || to.meta.used_human_decisions != from_meta.used_human_decisions
        || !budget_same_or_one_escalation(from_meta.budget, to.meta.budget)
        || to.prior.key != from_meta.key
        || to.prior.state_digest != source.state_digest
        || to.prior.effect_scope
            != from
                .proposal_basis()
                .map(|basis| basis.proposal.effect_scope().clone())
        || to.prior.issuance != from.issuance().map(|value| value.issuance.clone())
        || to.prior.docket_custody != from.docket_custody().map(DocketCustodyV1::reference)
        || to.prior.docket_attempt != from.docket_custody().map(|value| value.attempt.clone())
        || to.prior.authorized_successor.is_some()
        || to.prior.pre_spend_revision.is_some()
        || to.unresolved_attempt != expected_unresolved
        || to.history != from.authority_history()
        || (from.program_counter() == ProgramCounterV1::Dispatched
            && to.governed_repair_requirement.is_none())
        || (!governed_source && to.governed_repair_requirement.is_some())
        || !pre_spend_marker_valid
    {
        return Err(KernelErrorV1::StateInvariant("halt transition"));
    }
    Ok(())
}

fn docket_issuance_refusal_residual(refusal: &DocketIssuanceRefusalV1) -> ResidualObligationV1 {
    ResidualObligationV1 {
        residual: ResidualIdV1::from_digest(digest_value(
            "ag.governed-loop.docket-issuance-refusal-residual/v1",
            &(refusal.refusal.clone(), refusal.issuance.clone()),
        )),
        owner: refusal.evidence.clone(),
        subject: refusal.issuance.as_digest().clone(),
        statement: refusal.refusal.clone(),
    }
}

fn exactly_one_appended<T: Eq>(before: &[T], after: &[T]) -> bool {
    after.len() == before.len().saturating_add(1) && after.starts_with(before)
}

fn validate_human_halt_update(from: &HaltedV1, to: &HaltedV1) -> Result<(), KernelErrorV1> {
    if from.pre_spend_scope_insufficiency.is_some() || to.pre_spend_scope_insufficiency.is_some() {
        return Err(KernelErrorV1::StateInvariant(
            "typed pre-spend halt cannot be updated by human disposition",
        ));
    }
    let residual_update_valid = match (&from.governed_repair_closed, &to.governed_repair_closed) {
        (None, Some(closed)) => {
            to.meta.residuals.len() == from.meta.residuals.len().saturating_add(1)
                && from.meta.residuals.as_slice().iter().all(|item| {
                    to.meta
                        .residuals
                        .as_slice()
                        .iter()
                        .any(|after| after == item)
                })
                && to
                    .meta
                    .residuals
                    .as_slice()
                    .iter()
                    .any(|item| item.residual == closed.residual)
        }
        (left, right) if left == right => to.meta.residuals.as_slice().iter().all(|item| {
            from.meta
                .residuals
                .as_slice()
                .iter()
                .any(|prior| prior == item)
        }),
        _ => false,
    };
    if from.source != to.source
        || from.reason != to.reason
        || from.prior != to.prior
        || from.unresolved_attempt != to.unresolved_attempt
        || from.history != to.history
        || from.governed_repair_requirement != to.governed_repair_requirement
        || from.docket_issuance_refusal != to.docket_issuance_refusal
        || from.meta.key != to.meta.key
        || from.meta.program != to.meta.program
        || from.meta.budget != to.meta.budget
        || !exactly_one_appended(
            &from.meta.used_human_decisions,
            &to.meta.used_human_decisions,
        )
        || !residual_update_valid
    {
        return Err(KernelErrorV1::StateInvariant("human halt update"));
    }
    Ok(())
}

fn validate_human_completion(from: &HaltedV1, to: &CompletedV1) -> Result<(), KernelErrorV1> {
    if from.unresolved_attempt.is_some()
        || !from.meta.residuals.is_empty()
        || !to.meta.residuals.is_empty()
        || from.meta.key != to.meta.key
        || from.meta.program != to.meta.program
        || from.meta.budget != to.meta.budget
        || !exactly_one_appended(
            &from.meta.used_human_decisions,
            &to.meta.used_human_decisions,
        )
        || from.history != to.history
    {
        return Err(KernelErrorV1::StateInvariant("human completion"));
    }
    Ok(())
}

fn validate_probe_successor(from: &OccurrenceStateV1, to: &OccurrenceStateV1) -> bool {
    let before = from.meta();
    let after = to.meta();
    if before.key != after.key
        || before.program != after.program
        || before.residuals != after.residuals
        || before.used_human_decisions != after.used_human_decisions
        || before.budget.retry_limit != after.budget.retry_limit
        || before.budget.retries_used != after.budget.retries_used
        || before.budget.probe_limit != after.budget.probe_limit
        || before.budget.probes_used.saturating_add(1) != after.budget.probes_used
        || before.budget.escalation_limit != after.budget.escalation_limit
        || before.budget.escalations_used != after.budget.escalations_used
    {
        return false;
    }
    let mut normalized = to.clone();
    *normalized.meta_mut() = before.clone();
    &normalized == from
}

fn validate_state(state: &OccurrenceStateV1) -> Result<(), KernelErrorV1> {
    let meta = state.meta();
    let used: BTreeSet<_> = meta.used_human_decisions.iter().collect();
    if used.len() != meta.used_human_decisions.len() {
        return Err(KernelErrorV1::StateInvariant(
            "duplicate consumed human decision",
        ));
    }
    if let Some(basis) = state.proposal_basis() {
        basis.proposal.validate()?;
        if basis.proposal.campaign() != &meta.key.campaign
            || basis.observation.key != meta.key
            || basis.proposal_ref != basis.proposal.reference()
            || basis.observation.subject != *basis.proposal.subject()
            || basis.observation.status != ObservationStatusV1::Current
        {
            return Err(KernelErrorV1::StateInvariant("proposal basis"));
        }
        match &basis.link {
            OccurrenceLinkV1::Initial => {}
            OccurrenceLinkV1::RetryOf(prior) | OccurrenceLinkV1::SuccessorOf(prior) => {
                if prior == &meta.key || prior.campaign != meta.key.campaign {
                    return Err(KernelErrorV1::StateInvariant("occurrence link"));
                }
            }
        }
    }
    match state {
        OccurrenceStateV1::ObservationRequired(value) => {
            if let Some(prior) = &value.prior {
                validate_prior_basis(prior)?;
                if prior.key == value.meta.key || prior.key.campaign != value.meta.key.campaign {
                    return Err(KernelErrorV1::StateInvariant("continuation prior"));
                }
            }
        }
        OccurrenceStateV1::AdmissiblePendingAuthorization(value) => {
            validate_admissible_basis(&value.0)?;
        }
        OccurrenceStateV1::AuthorizationConsumed(value) => {
            validate_authorized(value)?;
        }
        OccurrenceStateV1::Dispatched(value) => {
            validate_authorized(&value.0.authorized)?;
            validate_custody(&value.0.custody, &value.0.authorized)?;
        }
        OccurrenceStateV1::ReconciliationRequired(value) => {
            validate_authorized(&value.dispatch.authorized)?;
            validate_custody(&value.dispatch.custody, &value.dispatch.authorized)?;
            validate_indeterminate(&value.indeterminate, &value.dispatch)?;
            if let Some(round) = &value.reconciliation_round {
                match round {
                    ReconciliationRoundStateV1::Unresolved {
                        request,
                        reservation,
                    } => validate_round_reservation(request, reservation)?,
                    ReconciliationRoundStateV1::CompletedIndeterminate {
                        request,
                        reservation,
                        completion,
                    } => {
                        validate_round_completion(request, reservation, completion)?;
                    }
                }
            }
        }
        OccurrenceStateV1::SettledObservationRequired(value) => {
            validate_authorized(&value.dispatch.authorized)?;
            validate_custody(&value.dispatch.custody, &value.dispatch.authorized)?;
            validate_settlement(&value.settlement, &value.dispatch)?;
        }
        OccurrenceStateV1::Halted(value) => {
            validate_prior_basis(&value.prior)?;
            if value.prior.key != value.meta.key {
                return Err(KernelErrorV1::StateInvariant("halted prior key"));
            }
            if value.unresolved_attempt.is_some()
                != (matches!(value.source, ProgramCounterV1::ReconciliationRequired)
                    && value.governed_repair_requirement.is_none())
            {
                return Err(KernelErrorV1::StateInvariant("halted unresolved attempt"));
            }
            if value.governed_repair_requirement.is_some()
                && !matches!(
                    value.source,
                    ProgramCounterV1::Dispatched | ProgramCounterV1::ReconciliationRequired
                )
            {
                return Err(KernelErrorV1::StateInvariant(
                    "halted governed-repair source",
                ));
            }
            if let Some(requirement) = &value.governed_repair_requirement {
                requirement.validate()?;
                validate_requirement_against_halt(value, requirement)?;
            }
            if let Some(refusal) = &value.docket_issuance_refusal {
                refusal.validate()?;
                if value.source != ProgramCounterV1::AuthorizationConsumed
                    || value.governed_repair_requirement.is_some()
                    || value.governed_repair_closed.is_some()
                    || value.unresolved_attempt.is_some()
                    || value.prior.issuance.as_ref() != Some(&refusal.issuance)
                    || value.meta.key.campaign != refusal.campaign
                    || value.meta.key.occurrence != refusal.occurrence
                {
                    return Err(KernelErrorV1::StateInvariant(
                        "halted Docket issuance refusal binding",
                    ));
                }
            }
            if let Some(marker) = &value.pre_spend_scope_insufficiency {
                marker.validate()?;
                if value.source != ProgramCounterV1::ProposalRecorded
                    || value.meta.key != marker.key
                    || value.prior.proposal.as_ref() != Some(&marker.proposal)
                    || value
                        .prior
                        .effect_scope
                        .as_ref()
                        .map(CanonicalEffectScopeV1::digest)
                        != Some(marker.original_scope_identity.clone())
                    || value.prior.state_digest != marker.source_state_digest
                    || value.reason
                        != HaltReasonRefV1::from_digest(digest_value(
                            PRE_SPEND_SCOPE_INSUFFICIENCY_SCHEMA_V1,
                            &marker.insufficiency,
                        ))
                    || value.history != AuthorityHistoryV1::default()
                    || value.governed_repair_requirement.is_some()
                    || value.governed_repair_closed.is_some()
                    || value.docket_issuance_refusal.is_some()
                    || value.unresolved_attempt.is_some()
                {
                    return Err(KernelErrorV1::StateInvariant(
                        "halted pre-spend scope insufficiency binding",
                    ));
                }
            }
        }
        OccurrenceStateV1::Completed(value) => {
            if let Some(proposal) = &value.proposal_contract {
                proposal.validate()?;
                if proposal.campaign() != &value.meta.key.campaign {
                    return Err(KernelErrorV1::StateInvariant("completed proposal contract"));
                }
            }
            if !value.meta.residuals.is_empty()
                || value.terminal_observation.key != value.meta.key
                || value.terminal_observation.status != ObservationStatusV1::Current
            {
                return Err(KernelErrorV1::StateInvariant("completion clearance"));
            }
        }
        OccurrenceStateV1::ProposalRecorded(_) | OccurrenceStateV1::StandingRequired(_) => {}
    }
    Ok(())
}

fn validate_prior_basis(prior: &PriorOccurrenceBasisV1) -> Result<(), KernelErrorV1> {
    if prior.authorized_successor.is_some() && prior.pre_spend_revision.is_some() {
        return Err(KernelErrorV1::StateInvariant(
            "pre-spend and post-spend successor constraints overlap",
        ));
    }
    match (
        prior.proposal.as_ref(),
        prior.proposal_contract.as_ref(),
        prior.effect_scope.as_ref(),
    ) {
        (None, None, None) if prior.normalized_preconditions.is_none() => {}
        (Some(reference), Some(proposal), Some(scope)) => {
            proposal.validate()?;
            if proposal.reference() != *reference
                || proposal.effect_scope() != scope
                || proposal.campaign() != &prior.key.campaign
            {
                return Err(KernelErrorV1::StateInvariant(
                    "prior proposal contract substitution",
                ));
            }
        }
        _ => {
            return Err(KernelErrorV1::StateInvariant(
                "prior proposal contract shape",
            ));
        }
    }
    if prior.issuance.is_some() && prior.proposal.is_none() {
        return Err(KernelErrorV1::StateInvariant(
            "prior issuance without proposal contract",
        ));
    }
    if let Some(constraint) = &prior.pre_spend_revision {
        constraint.exact_revised_proposal.validate()?;
        if constraint.predecessor != prior.key
            || constraint.revised_proposal != constraint.exact_revised_proposal.reference()
            || constraint.exact_revised_proposal.campaign() != &prior.key.campaign
            || prior.proposal.is_none()
            || prior.issuance.is_some()
            || prior.docket_custody.is_some()
            || prior.docket_attempt.is_some()
            || prior.normalized_preconditions.is_some()
        {
            return Err(KernelErrorV1::StateInvariant(
                "pre-spend revision constraint",
            ));
        }
    }
    Ok(())
}

fn validate_admissible_basis(value: &AdmissibleBasisV1) -> Result<(), KernelErrorV1> {
    if value.standing.schema != STANDING_RESOLUTION_SCHEMA_V1
        || value.standing.key != value.proposal.meta.key
        || value.standing.observation != value.proposal.observation.observation
        || value.standing.proposal != value.proposal.proposal_ref
        || value.standing.subject != *value.proposal.proposal.subject()
        || value.standing.scope != *value.proposal.proposal.scope()
        || value.standing.status != StandingStatusV1::Current
        || value.decision.key != value.proposal.meta.key
        || value.decision.observation != value.proposal.observation.observation
        || value.decision.proposal != value.proposal.proposal_ref
        || value.decision.standing_resolution != value.standing.resolution
        || value.decision.disposition != AdmissionDispositionV1::Admitted
    {
        return Err(KernelErrorV1::StateInvariant("admissible basis"));
    }
    Ok(())
}

fn validate_authorized(value: &AuthorizationConsumedV1) -> Result<(), KernelErrorV1> {
    validate_admissible_basis(&value.admitted)?;
    let expected_authorization = AgAuthorizationRefV1::for_basis(
        value.admitted.proposal.meta.key(),
        &value.admitted.proposal.observation.observation,
        &value.admitted.proposal.proposal_ref,
        &value.admitted.standing.resolution,
    );
    if value.spend.authorization != expected_authorization
        || value.spend.spend != AgSpendRefV1::for_authorization(&expected_authorization)
        || value.spend.key != value.admitted.proposal.meta.key
        || value.spend.observation != value.admitted.proposal.observation.observation
        || value.spend.proposal != value.admitted.proposal.proposal_ref
        || value.spend.standing_resolution != value.admitted.standing.resolution
        || value.spend.admission_decision != value.admitted.decision.decision
    {
        return Err(KernelErrorV1::StateInvariant("AG authorization spend"));
    }
    let expected_issuance = build_issuance(&value.admitted, &value.spend.spend);
    if value.issuance != expected_issuance {
        return Err(KernelErrorV1::StateInvariant("AG issuance"));
    }
    Ok(())
}
