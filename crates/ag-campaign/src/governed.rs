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
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::identity::{CampaignId, CampaignLabelError};
use crate::transcript::validate_label;

/// Wire schema for exact-work proposals.
pub const EXACT_WORK_PROPOSAL_SCHEMA_V1: &str = "ag.governed-loop.exact-work-proposal/v1";
/// Wire schema for fresh observation records.
pub const OBSERVATION_RESOLUTION_SCHEMA_V1: &str = "ag.governed-loop.observation-resolution/v1";
/// Wire schema for current standing resolutions.
pub const STANDING_RESOLUTION_SCHEMA_V1: &str = "ag.governed-loop.standing-resolution/v1";
/// Wire schema for AG issuances.
pub const AG_ISSUANCE_SCHEMA_V1: &str = "ag.governed-loop.issuance/v1";
/// Wire schema for Docket custody records.
pub const DOCKET_CUSTODY_SCHEMA_V1: &str = "ag.governed-loop.docket-custody/v1";
/// Wire schema for Docket settlements.
pub const DOCKET_SETTLEMENT_SCHEMA_V1: &str = "ag.governed-loop.docket-settlement/v1";
/// Wire schema for external human dispositions.
pub const HUMAN_DISPOSITION_SCHEMA_V1: &str = "ag.governed-loop.human-disposition/v1";

const STATE_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.state/v1";
const GENESIS_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.genesis/v1";
const PROPOSAL_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.proposal/v1";
const AG_AUTHORIZATION_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.authorization/v1";
const AG_SPEND_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.spend/v1";
const AG_ISSUANCE_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.issuance/v1";

fn digest_value<T: Serialize + ?Sized>(domain: &str, value: &T) -> Digest {
    let document = JcsDocument::canonicalize(value)
        .expect("governed-loop values contain only strict JCS-compatible fields");
    Digest::hash_domain(domain, document.as_bytes())
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

    fn ids(&self) -> BTreeSet<ResidualIdV1> {
        self.0.iter().map(|item| item.residual.clone()).collect()
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

/// Generic exact-work proposal; the work payload is an immutable typed digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWorkProposalV1 {
    schema: String,
    campaign: CampaignId,
    subject: Digest,
    scope: Digest,
    work_schema: String,
    work: Digest,
    repair: Option<C1RepairCitationV1>,
}

impl ExactWorkProposalV1 {
    /// Creates one exact proposal bound to one independently named occurrence.
    pub fn new(
        campaign: CampaignId,
        subject: Digest,
        scope: Digest,
        work_schema: String,
        work: Digest,
        repair: Option<C1RepairCitationV1>,
    ) -> Result<Self, KernelErrorV1> {
        validate_label("exact-work schema", &work_schema).map_err(KernelErrorV1::Label)?;
        let proposal = Self {
            schema: EXACT_WORK_PROPOSAL_SCHEMA_V1.to_owned(),
            campaign,
            subject,
            scope,
            work_schema,
            work,
            repair,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    /// Revalidates a decoded proposal.
    pub fn validate(&self) -> Result<(), KernelErrorV1> {
        if self.schema != EXACT_WORK_PROPOSAL_SCHEMA_V1 {
            return Err(KernelErrorV1::ForeignSchema("exact-work proposal"));
        }
        validate_label("exact-work schema", &self.work_schema).map_err(KernelErrorV1::Label)
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
    pub const fn scope(&self) -> &Digest {
        &self.scope
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

    /// Returns an optional C1 repair citation.
    #[must_use]
    pub const fn repair(&self) -> Option<&C1RepairCitationV1> {
        self.repair.as_ref()
    }
}

/// Observation status returned by the external observation resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
pub enum ContinuationClassV1 {
    /// Same exact proposal may be reused only with unchanged fresh preconditions.
    Retry,
    /// Ordinary successor; a new proposal is required.
    Successor,
}

/// Exact predecessor basis retained for continuation classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorOccurrenceBasisV1 {
    /// Prior occurrence key.
    pub key: OccurrenceKeyV1,
    /// Prior proposal, when the predecessor reached proposal recording.
    pub proposal: Option<ProposalRefV1>,
    /// Prior normalized preconditions, when observed.
    pub normalized_preconditions: Option<PreconditionBasisRefV1>,
    /// Exact predecessor state digest.
    pub state_digest: Digest,
}

/// Occurrence linkage; authority never travels through this record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
pub struct AgIssuanceV1 {
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
    /// Exact governed subject.
    pub subject: Digest,
    /// Exact governed scope.
    pub scope: Digest,
    /// Exact observation.
    pub observation: ObservationRefV1,
    /// Exact standing resolution.
    pub standing_resolution: StandingResolutionRefV1,
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
    issuance: AgIssuanceV1,
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
#[serde(rename_all = "snake_case")]
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
    /// Docket settlement time.
    pub settled_at_unix_ms: u64,
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
}

/// Durable completed state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedV1 {
    meta: OccurrenceMetaV1,
    terminal_observation: ObservationResolutionV1,
    terminal_witness: TerminalWitnessRefV1,
    history: AuthorityHistoryV1,
}

/// Closed typed state sum for one occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
}

/// Narrow execution-custody port owned by Docket.
pub trait DocketCustodyPortV1 {
    /// Accepts one exact AG issuance and delegates one physical attempt.
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1>;

    /// Read-only reconciliation of an already consumed exact issuance.
    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1>;

    /// Read-only reconciliation of an exact Docket attempt.
    fn reconcile_attempt(
        &mut self,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1>;
}

/// Closed external human disposition vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Root-owned expected human authority scope for one halted boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanAuthorityScopeV1 {
    /// Expected principal/signer.
    pub principal: HumanPrincipalRefV1,
    /// Expected mandate.
    pub mandate: MandateRefV1,
}

/// Request to the external human-disposition verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanDispositionVerificationRequestV1<'a> {
    /// Exact artifact.
    pub artifact: &'a HumanDispositionV1,
    /// Root-owned expected scope.
    pub expected_scope: &'a HumanAuthorityScopeV1,
    /// Consequence-time clock reading.
    pub now_unix_ms: u64,
}

/// External signature/mandate/current-authority verifier.
pub trait HumanDispositionVerifierV1 {
    /// Verifies the exact artifact now and returns an exact verification record.
    fn verify_human_disposition(
        &mut self,
        request: &HumanDispositionVerificationRequestV1<'_>,
    ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1>;
}

/// Result of an applicable human disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanDispositionEffectV1 {
    /// Same occurrence changed while remaining current (residual disposition or completion).
    Updated {
        /// Authoritative successor snapshot.
        snapshot: OccurrenceSnapshotV1,
        /// Exact external verification record.
        verification: HumanVerificationRefV1,
    },
    /// Halted source records decision consumption and a distinct occurrence opens.
    OpenedOccurrence {
        /// Updated halted predecessor with the decision durably consumed.
        halted: OccurrenceSnapshotV1,
        /// New authority-empty observation-required occurrence.
        successor: OccurrenceSnapshotV1,
        /// Exact external verification record.
        verification: HumanVerificationRefV1,
    },
}

/// Proposal classification at an observation-required boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    pub const fn recovery_requirement(snapshot: &OccurrenceSnapshotV1) -> RecoveryRequirementV1 {
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
            ProgramCounterV1::Halted => RecoveryRequirementV1::ExternalDisposition,
            ProgramCounterV1::Completed => RecoveryRequirementV1::None,
        }
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
                validate_indeterminate(&to.indeterminate, &to.dispatch)
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
                if same_key && is_safe_halt_source(from.program_counter()) =>
            {
                validate_halt_successor(from, to)
            }
            (OccurrenceStateV1::Halted(from), OccurrenceStateV1::Halted(to)) if same_key => {
                validate_human_halt_update(from, to)
            }
            (OccurrenceStateV1::Halted(from), OccurrenceStateV1::ObservationRequired(to))
                if !same_key && from.unresolved_attempt.is_none() =>
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
            state_digest: current.state_digest.clone(),
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
        });
        let next = successor_snapshot(current, state);
        next.validate_integrity()?;
        Ok(next)
    }

    /// Applies an exactly bound, externally verified, one-use human disposition.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_human_disposition<O, H>(
        current: &OccurrenceSnapshotV1,
        artifact: HumanDispositionV1,
        expected_scope: &HumanAuthorityScopeV1,
        new_occurrence: Option<OccurrenceId>,
        observation_resolver: &mut O,
        verifier: &mut H,
        now_unix_ms: u64,
    ) -> Result<HumanDispositionEffectV1, KernelErrorV1>
    where
        O: ObservationResolverV1,
        H: HumanDispositionVerifierV1,
    {
        current.validate_integrity()?;
        let OccurrenceStateV1::Halted(halted) = current.state() else {
            return Err(illegal(current, "apply_human_disposition"));
        };
        validate_human_artifact(current, halted, &artifact, expected_scope, now_unix_ms)?;
        let verification =
            verifier.verify_human_disposition(&HumanDispositionVerificationRequestV1 {
                artifact: &artifact,
                expected_scope,
                now_unix_ms,
            })?;

        match &artifact.disposition {
            HumanDispositionKindV1::ReturnToObservation => {
                if halted.unresolved_attempt.is_some() {
                    return Err(KernelErrorV1::UnresolvedAttempt);
                }
                let occurrence = new_occurrence.ok_or(KernelErrorV1::HumanDisposition(
                    "new occurrence is required",
                ))?;
                open_from_halt(
                    current,
                    halted,
                    &artifact,
                    occurrence,
                    halted.meta.program.clone(),
                    verification,
                )
            }
            HumanDispositionKindV1::ReplaceProgram(program) => {
                if halted.unresolved_attempt.is_some() {
                    return Err(KernelErrorV1::UnresolvedAttempt);
                }
                if program == &halted.meta.program {
                    return Err(KernelErrorV1::HumanDisposition(
                        "replacement program must differ",
                    ));
                }
                let occurrence = new_occurrence.ok_or(KernelErrorV1::HumanDisposition(
                    "new occurrence is required",
                ))?;
                open_from_halt(
                    current,
                    halted,
                    &artifact,
                    occurrence,
                    program.clone(),
                    verification,
                )
            }
            HumanDispositionKindV1::ExactResidualDisposition(discharge) => {
                if new_occurrence.is_some() {
                    return Err(KernelErrorV1::HumanDisposition(
                        "residual disposition remains halted",
                    ));
                }
                let after = apply_exact_discharge(halted, discharge, &artifact.decision)?;
                let mut next_halted = halted.clone();
                next_halted.meta.residuals = after;
                next_halted
                    .meta
                    .used_human_decisions
                    .push(artifact.decision.clone());
                let next = successor_snapshot(current, OccurrenceStateV1::Halted(next_halted));
                next.validate_integrity()?;
                Ok(HumanDispositionEffectV1::Updated {
                    snapshot: next,
                    verification,
                })
            }
            HumanDispositionKindV1::Terminate {
                observation,
                subject,
                terminal_witness,
            } => {
                if new_occurrence.is_some() {
                    return Err(KernelErrorV1::HumanDisposition(
                        "termination does not open an occurrence",
                    ));
                }
                if halted.unresolved_attempt.is_some() {
                    return Err(KernelErrorV1::UnresolvedAttempt);
                }
                if !halted.meta.residuals.is_empty() {
                    return Err(KernelErrorV1::ResidualsOpen);
                }
                let terminal = resolve_observation(
                    observation_resolver,
                    halted.meta.key(),
                    observation,
                    subject,
                    now_unix_ms,
                )?;
                let mut meta = halted.meta.clone();
                meta.used_human_decisions.push(artifact.decision.clone());
                let state = OccurrenceStateV1::Completed(CompletedV1 {
                    meta,
                    terminal_observation: terminal,
                    terminal_witness: terminal_witness.clone(),
                    history: halted.history.clone(),
                });
                let next = successor_snapshot(current, state);
                next.validate_integrity()?;
                Ok(HumanDispositionEffectV1::Updated {
                    snapshot: next,
                    verification,
                })
            }
        }
    }
}

impl OccurrenceSnapshotV1 {
    /// Returns the exact recorded proposal, when any.
    #[must_use]
    pub fn proposal(&self) -> Option<&ExactWorkProposalV1> {
        self.state.proposal_basis().map(|basis| &basis.proposal)
    }

    /// Returns the exact historical observation basis, when any.
    #[must_use]
    pub fn observation(&self) -> Option<&ObservationResolutionV1> {
        self.state.proposal_basis().map(|basis| &basis.observation)
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
    pub fn issuance(&self) -> Option<&AgIssuanceV1> {
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

    /// Returns the prior occurrence basis for a not-yet-proposed continuation.
    #[must_use]
    pub fn prior_occurrence(&self) -> Option<&PriorOccurrenceBasisV1> {
        match &self.state {
            OccurrenceStateV1::ObservationRequired(value) => value.prior.as_ref(),
            _ => None,
        }
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

fn build_issuance(admitted: &AdmissibleBasisV1, spend: &AgSpendRefV1) -> AgIssuanceV1 {
    #[derive(Serialize)]
    struct IssuanceBody<'a> {
        key: &'a OccurrenceKeyV1,
        program: &'a ProgramBasisRefV1,
        proposal: &'a ProposalRefV1,
        work_schema: &'a str,
        work: &'a Digest,
        subject: &'a Digest,
        scope: &'a Digest,
        observation: &'a ObservationRefV1,
        standing_resolution: &'a StandingResolutionRefV1,
        mandate: &'a MandateRefV1,
        spend: &'a AgSpendRefV1,
    }
    let basis = IssuanceBody {
        key: admitted.proposal.meta.key(),
        program: admitted.proposal.meta.program(),
        proposal: &admitted.proposal.proposal_ref,
        work_schema: admitted.proposal.proposal.work_schema(),
        work: admitted.proposal.proposal.work(),
        subject: admitted.proposal.proposal.subject(),
        scope: admitted.proposal.proposal.scope(),
        observation: &admitted.proposal.observation.observation,
        standing_resolution: &admitted.standing.resolution,
        mandate: &admitted.standing.mandate,
        spend,
    };
    let issuance = AgIssuanceRefV1::from_digest(digest_value(AG_ISSUANCE_DIGEST_DOMAIN_V1, &basis));
    AgIssuanceV1 {
        schema: AG_ISSUANCE_SCHEMA_V1.to_owned(),
        issuance,
        key: basis.key.clone(),
        program: basis.program.clone(),
        proposal: basis.proposal.clone(),
        work_schema: basis.work_schema.to_owned(),
        work: basis.work.clone(),
        subject: basis.subject.clone(),
        scope: basis.scope.clone(),
        observation: basis.observation.clone(),
        standing_resolution: basis.standing_resolution.clone(),
        mandate: basis.mandate.clone(),
        spend: basis.spend.clone(),
    }
}

fn validate_custody(
    custody: &DocketCustodyV1,
    authorized: &AuthorizationConsumedV1,
) -> Result<(), KernelErrorV1> {
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

fn current_prior_basis(current: &OccurrenceSnapshotV1) -> PriorOccurrenceBasisV1 {
    PriorOccurrenceBasisV1 {
        key: current.key().clone(),
        proposal: current
            .state
            .proposal_basis()
            .map(|basis| basis.proposal_ref.clone()),
        normalized_preconditions: current
            .state
            .proposal_basis()
            .map(|basis| basis.observation.normalized_preconditions.clone()),
        state_digest: current.state_digest.clone(),
    }
}

fn validate_human_artifact(
    current: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    artifact: &HumanDispositionV1,
    expected_scope: &HumanAuthorityScopeV1,
    now_unix_ms: u64,
) -> Result<(), KernelErrorV1> {
    if artifact.schema != HUMAN_DISPOSITION_SCHEMA_V1 {
        return Err(KernelErrorV1::ForeignSchema("human disposition"));
    }
    if artifact.campaign != halted.meta.key.campaign {
        return Err(KernelErrorV1::HumanDisposition("wrong campaign"));
    }
    if artifact.occurrence != halted.meta.key.occurrence {
        return Err(KernelErrorV1::HumanDisposition("wrong occurrence"));
    }
    if artifact.halted_state_digest != current.state_digest {
        return Err(KernelErrorV1::HumanDisposition("wrong halted-state digest"));
    }
    if now_unix_ms >= artifact.expires_at_unix_ms {
        return Err(KernelErrorV1::HumanDisposition("expired"));
    }
    if artifact.principal != expected_scope.principal {
        return Err(KernelErrorV1::HumanDisposition("wrong principal"));
    }
    if artifact.mandate != expected_scope.mandate {
        return Err(KernelErrorV1::HumanDisposition("wrong mandate"));
    }
    if halted
        .meta
        .used_human_decisions
        .contains(&artifact.decision)
    {
        return Err(KernelErrorV1::HumanDisposition("replayed decision"));
    }
    Ok(())
}

fn open_from_halt(
    current: &OccurrenceSnapshotV1,
    halted: &HaltedV1,
    artifact: &HumanDispositionV1,
    occurrence: OccurrenceId,
    program: ProgramBasisRefV1,
    verification: HumanVerificationRefV1,
) -> Result<HumanDispositionEffectV1, KernelErrorV1> {
    if occurrence == halted.meta.key.occurrence {
        return Err(KernelErrorV1::OccurrenceReused);
    }
    let mut consumed_halt = halted.clone();
    consumed_halt
        .meta
        .used_human_decisions
        .push(artifact.decision.clone());
    let halted_snapshot =
        successor_snapshot(current, OccurrenceStateV1::Halted(consumed_halt.clone()));
    halted_snapshot.validate_integrity()?;
    let prior = PriorOccurrenceBasisV1 {
        key: consumed_halt.meta.key.clone(),
        proposal: consumed_halt.prior.proposal.clone(),
        normalized_preconditions: consumed_halt.prior.normalized_preconditions.clone(),
        state_digest: halted_snapshot.state_digest.clone(),
    };
    let state = OccurrenceStateV1::ObservationRequired(ObservationRequiredV1 {
        meta: OccurrenceMetaV1 {
            key: OccurrenceKeyV1 {
                campaign: consumed_halt.meta.key.campaign.clone(),
                occurrence,
            },
            program,
            residuals: consumed_halt.meta.residuals.clone(),
            budget: consumed_halt.meta.budget,
            used_human_decisions: consumed_halt.meta.used_human_decisions.clone(),
        },
        prior: Some(prior),
    });
    let successor = successor_snapshot(&halted_snapshot, state);
    successor.validate_integrity()?;
    Ok(HumanDispositionEffectV1::OpenedOccurrence {
        halted: halted_snapshot,
        successor,
        verification,
    })
}

fn sorted_unique_ids(values: &[ResidualIdV1]) -> Option<BTreeSet<ResidualIdV1>> {
    let set: BTreeSet<_> = values.iter().cloned().collect();
    (set.len() == values.len()).then_some(set)
}

fn apply_exact_discharge(
    halted: &HaltedV1,
    discharge: &ExactResidualDischargeV1,
    decision: &HumanDecisionIdV1,
) -> Result<ResidualSetV1, KernelErrorV1> {
    if discharge.campaign != halted.meta.key.campaign
        || discharge.occurrence != halted.meta.key.occurrence
        || discharge.program != halted.meta.program
        || &discharge.disposition != decision
    {
        return Err(KernelErrorV1::ResidualAccounting);
    }
    let before = sorted_unique_ids(&discharge.before).ok_or(KernelErrorV1::ResidualAccounting)?;
    let authorized =
        sorted_unique_ids(&discharge.authorized).ok_or(KernelErrorV1::ResidualAccounting)?;
    let closed = sorted_unique_ids(&discharge.closed).ok_or(KernelErrorV1::ResidualAccounting)?;
    let after = sorted_unique_ids(&discharge.after).ok_or(KernelErrorV1::ResidualAccounting)?;
    if before != halted.meta.residuals.ids()
        || authorized != closed
        || !closed.is_disjoint(&after)
        || before != closed.union(&after).cloned().collect()
    {
        return Err(KernelErrorV1::ResidualAccounting);
    }
    let remaining = halted
        .meta
        .residuals
        .as_slice()
        .iter()
        .filter(|residual| after.contains(&residual.residual))
        .cloned()
        .collect();
    ResidualSetV1::new(remaining)
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

fn validate_halt_successor(from: &OccurrenceStateV1, to: &HaltedV1) -> Result<(), KernelErrorV1> {
    let from_meta = from.meta();
    let expected_unresolved = match from {
        OccurrenceStateV1::ReconciliationRequired(value) => {
            Some(value.dispatch.custody.attempt.clone())
        }
        _ => None,
    };
    if to.source != from.program_counter()
        || to.meta.key != from_meta.key
        || to.meta.program != from_meta.program
        || to.meta.residuals != from_meta.residuals
        || to.meta.used_human_decisions != from_meta.used_human_decisions
        || !budget_same_or_one_escalation(from_meta.budget, to.meta.budget)
        || to.prior.key != from_meta.key
        || to.unresolved_attempt != expected_unresolved
        || to.history != from.authority_history()
    {
        return Err(KernelErrorV1::StateInvariant("halt transition"));
    }
    Ok(())
}

fn exactly_one_appended<T: Eq>(before: &[T], after: &[T]) -> bool {
    after.len() == before.len().saturating_add(1) && after.starts_with(before)
}

fn validate_human_halt_update(from: &HaltedV1, to: &HaltedV1) -> Result<(), KernelErrorV1> {
    let retained_exact = to.meta.residuals.as_slice().iter().all(|item| {
        from.meta
            .residuals
            .as_slice()
            .iter()
            .any(|prior| prior == item)
    });
    if from.source != to.source
        || from.reason != to.reason
        || from.prior != to.prior
        || from.unresolved_attempt != to.unresolved_attempt
        || from.history != to.history
        || from.meta.key != to.meta.key
        || from.meta.program != to.meta.program
        || from.meta.budget != to.meta.budget
        || !exactly_one_appended(
            &from.meta.used_human_decisions,
            &to.meta.used_human_decisions,
        )
        || !retained_exact
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
            if let Some(prior) = &value.prior
                && (prior.key == value.meta.key || prior.key.campaign != value.meta.key.campaign)
            {
                return Err(KernelErrorV1::StateInvariant("continuation prior"));
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
        }
        OccurrenceStateV1::SettledObservationRequired(value) => {
            validate_authorized(&value.dispatch.authorized)?;
            validate_custody(&value.dispatch.custody, &value.dispatch.authorized)?;
            validate_settlement(&value.settlement, &value.dispatch)?;
        }
        OccurrenceStateV1::Halted(value) => {
            if value.prior.key != value.meta.key {
                return Err(KernelErrorV1::StateInvariant("halted prior key"));
            }
            if value.unresolved_attempt.is_some()
                != matches!(value.source, ProgramCounterV1::ReconciliationRequired)
            {
                return Err(KernelErrorV1::StateInvariant("halted unresolved attempt"));
            }
        }
        OccurrenceStateV1::Completed(value) => {
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
