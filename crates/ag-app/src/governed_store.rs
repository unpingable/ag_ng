#![allow(
    clippy::missing_errors_doc,
    reason = "CampaignStoreErrorV1 is the closed error contract for every public store operation"
)]
#![allow(
    clippy::too_many_lines,
    reason = "transaction and replay routines intentionally keep the full atomic accounting cut visible"
)]
#![allow(
    clippy::large_enum_variant,
    reason = "transition evidence is serialized immediately and retains the exact artifact by value"
)]

//! Crate-private transactional authoritative store for canonical AG governed-loop state.
//!
//! One `SQLite` transaction advances the campaign pointer, occurrence snapshot,
//! transition chain, and all spend/attempt/settlement accounting.  External
//! effects never happen in this module.  A decoded snapshot is accepted only
//! when the pure governed-loop kernel proves it is a legal successor of the
//! exact compare-and-swap predecessor.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::governed_product::{
    ADMISSION_DECISION_ARTIFACT_SCHEMA_V1, AdmissionDecisionArtifactV1,
    COMPLETION_OBSERVATION_ARTIFACT_SCHEMA_V1, CompletionObservationArtifactV1,
    DOCKET_CHECKPOINT_ARTIFACT_SCHEMA_V1, DOCKET_INDETERMINATE_ARTIFACT_SCHEMA_V1,
    DocketCheckpointArtifactV1, DocketIndeterminateArtifactV1,
    EFFECT_JOURNAL_REFERENCE_ARTIFACT_SCHEMA_V1, EffectJournalReferenceArtifactV1,
    OBSERVATION_RESOLUTION_ARTIFACT_SCHEMA_V1, ObservationResolutionArtifactV1,
    RESIDUAL_STATE_ARTIFACT_SCHEMA_V1, ResidualStateArtifactV1,
    STANDING_RESOLUTION_ARTIFACT_SCHEMA_V1, SUCCESSOR_BINDING_ARTIFACT_SCHEMA_V1,
    StandingResolutionArtifactV1, SuccessorBindingArtifactV1, TERMINAL_WITNESS_ARTIFACT_SCHEMA_V1,
    TerminalWitnessArtifactV1,
};

use ag_campaign::CampaignId;
use ag_campaign::governed::{
    AG_ISSUANCE_SCHEMA_V2, AgAuthorizationRefV1, AgAuthorizationSpendV1, AgIssuanceV2,
    AgSpendRefV1, DOCKET_SETTLEMENT_SCHEMA_V1, DocketGovernedRepairOutcomeRefV1,
    DocketIssuanceRefusalV1, DocketSealedGovernedRepairResultV1, DocketSettlementV1,
    GovernedLoopKernelV1, GovernedRepairDispositionEffectV1, GovernedRepairDispositionV1,
    GovernedRepairDispositionVerifierV1, GovernedRepairVerificationRequestV1,
    GovernedRepairVerificationV1, GovernedRepairVerifierProfileV1, HumanDecisionRequestRefV1,
    HumanDecisionRequestV1, HumanDecisionRequirementV1, HumanDispositionKindV1,
    HumanDispositionRefV1, HumanDispositionV1, HumanPrincipalRefV1, HumanVerificationRefV1,
    MandateRefV1, OccurrenceKeyV1, OccurrenceSnapshotV1, ProgramCounterV1, RefusalOutcomeV1,
};
use ag_primitives::{Digest, JcsDocument};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current governed-loop campaign-store schema version.
pub const CAMPAIGN_STORE_SCHEMA_VERSION: u32 = 4;
/// `SQLite` application identifier for this exact store family (`AGC1`).
pub const CAMPAIGN_STORE_APPLICATION_ID: u32 = 0x4147_4331;
/// Human-readable exact store schema identity.
pub const CAMPAIGN_STORE_SCHEMA_NAME: &str = "ag-governed-loop-campaign-store/v4";

const EVENT_DOMAIN_V1: &str = "ag.governed-loop.store-event/v1";
const EVENT_GENESIS_DOMAIN_V1: &str = "ag.governed-loop.store-event-genesis/v1";
const REFUSAL_DOMAIN_V1: &str = "ag.governed-loop.store-refusal/v1";
const CAMPAIGN_STORE_V1_SCHEMA_NAME: &str = "ag-governed-loop-campaign-store/v1";
const CAMPAIGN_STORE_V1_SCHEMA_DIGEST: &str =
    "sha256:59e4ea222f522947eaee892e29c5eea3816ad13faf91576ca7ad9be20057bbf1";
const CAMPAIGN_STORE_V2_SCHEMA_NAME: &str = "ag-governed-loop-campaign-store/v2";
const CAMPAIGN_STORE_V2_SCHEMA_DIGEST: &str =
    "sha256:2f4d24faf67da2cae9ef7e63c3987172fbc47e067ae0c9d078a68abd04895f20";
const CAMPAIGN_STORE_V3_SCHEMA_NAME: &str = "ag-governed-loop-campaign-store/v3";
const CAMPAIGN_STORE_V3_SCHEMA_DIGEST: &str =
    "sha256:20a0fa1300ffbf0531a892509f0ed22169253ffab277259740cae899fe5948dd";
const GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1: &str =
    "ag.governed-loop.governed-repair-verifier-root/v1";
const GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1: &str =
    "ag.governed-loop.governed-repair-verifier-catalog/v1";
const GOVERNED_REPAIR_VERIFICATION_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.governed-repair-verification-request/v1";

const V2_ADDITIVE_SCHEMA_SQL: &str = r"
CREATE TABLE human_decision_requests (
    request_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    halted_state_digest TEXT NOT NULL,
    request_jcs BLOB NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    consumed_by_decision_id TEXT UNIQUE,
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;
CREATE TABLE governed_repair_dispositions (
    decision_id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    halted_state_digest TEXT NOT NULL,
    disposition_id TEXT NOT NULL UNIQUE,
    verification_jcs BLOB NOT NULL,
    artifact_jcs BLOB NOT NULL,
    consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms >= 0),
    FOREIGN KEY (request_id) REFERENCES human_decision_requests(request_id),
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;

CREATE TABLE governed_repair_verifier_root (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    config_identity TEXT NOT NULL UNIQUE,
    config_jcs BLOB NOT NULL
) STRICT;
CREATE TABLE product_creation_request (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_identity TEXT NOT NULL UNIQUE,
    request_jcs BLOB NOT NULL
) STRICT;
";

const SCHEMA_SQL: &str = r"
CREATE TABLE store_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_id INTEGER NOT NULL,
    schema_name TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    schema_digest TEXT NOT NULL
) STRICT;

CREATE TABLE campaigns (
    campaign_id TEXT PRIMARY KEY,
    current_occurrence_id TEXT NOT NULL,
    current_state_digest TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    event_count INTEGER NOT NULL CHECK (event_count > 0),
    event_head_digest TEXT NOT NULL
) STRICT;

CREATE TABLE occurrences (
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    program_basis TEXT NOT NULL,
    program_counter TEXT NOT NULL,
    prior_state_digest TEXT NOT NULL,
    state_digest TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    snapshot_jcs BLOB NOT NULL,
    PRIMARY KEY (campaign_id, occurrence_id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
) STRICT;

CREATE TABLE transitions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL,
    source_occurrence_id TEXT,
    successor_occurrence_id TEXT NOT NULL,
    transition_kind TEXT NOT NULL,
    predecessor_state_digest TEXT NOT NULL,
    successor_state_digest TEXT NOT NULL,
    successor_snapshot_jcs BLOB NOT NULL,
    evidence_jcs BLOB NOT NULL,
    evidence_digest TEXT NOT NULL,
    previous_event_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE,
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms >= 0),
    UNIQUE (campaign_id, predecessor_state_digest),
    UNIQUE (campaign_id, successor_state_digest),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
) STRICT;

CREATE INDEX transitions_by_campaign_sequence
    ON transitions(campaign_id, sequence);

CREATE TABLE ag_authorization_spends (
    spend_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    issuance_id TEXT NOT NULL UNIQUE,
    spend_jcs BLOB NOT NULL,
    issuance_jcs BLOB NOT NULL,
    transition_state_digest TEXT NOT NULL UNIQUE,
    UNIQUE (campaign_id, occurrence_id),
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;

CREATE TABLE docket_attempts (
    issuance_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    custody_jcs BLOB NOT NULL,
    transition_state_digest TEXT NOT NULL UNIQUE,
    UNIQUE (campaign_id, occurrence_id),
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;

CREATE TABLE docket_settlements (
    attempt_id TEXT PRIMARY KEY,
    settlement_id TEXT NOT NULL UNIQUE,
    receipt_id TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    settlement_jcs BLOB NOT NULL,
    transition_state_digest TEXT NOT NULL UNIQUE,
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;

CREATE TABLE human_dispositions (
    decision_id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    halted_state_digest TEXT NOT NULL,
    verification_ref TEXT NOT NULL,
    artifact_jcs BLOB NOT NULL,
    consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms >= 0),
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;

CREATE TABLE human_decision_requests (
    request_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    halted_state_digest TEXT NOT NULL,
    request_jcs BLOB NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    consumed_by_decision_id TEXT UNIQUE,
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;

CREATE TABLE governed_repair_dispositions (
    decision_id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    halted_state_digest TEXT NOT NULL,
    disposition_id TEXT NOT NULL UNIQUE,
    verification_receipt_ref TEXT NOT NULL UNIQUE,
    verification_record_id TEXT NOT NULL UNIQUE,
    verification_jcs BLOB NOT NULL,
    artifact_jcs BLOB NOT NULL,
    consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms >= 0),
    FOREIGN KEY (request_id) REFERENCES human_decision_requests(request_id),
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;

CREATE TABLE governed_repair_verification_identities (
    identity TEXT PRIMARY KEY,
    identity_class TEXT NOT NULL CHECK (identity_class IN ('receipt','record')),
    verification_record_id TEXT NOT NULL,
    verification_jcs BLOB NOT NULL
) STRICT;

CREATE TABLE issuance_signing_reservations (
    issuance_id TEXT PRIMARY KEY,
    spend_id TEXT NOT NULL UNIQUE,
    transition_state_digest TEXT NOT NULL UNIQUE,
    reservation_id TEXT NOT NULL UNIQUE,
    issuance_jcs BLOB NOT NULL,
    FOREIGN KEY (issuance_id) REFERENCES ag_authorization_spends(issuance_id),
    FOREIGN KEY (spend_id) REFERENCES ag_authorization_spends(spend_id)
) STRICT;

CREATE TABLE governed_repair_verifier_root (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    config_identity TEXT NOT NULL UNIQUE,
    config_jcs BLOB NOT NULL
) STRICT;

CREATE TABLE product_creation_request (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_identity TEXT NOT NULL UNIQUE,
    request_jcs BLOB NOT NULL
) STRICT;

CREATE TABLE residual_discharges (
    decision_id TEXT PRIMARY KEY,
    authority_ref TEXT NOT NULL,
    before_jcs BLOB NOT NULL,
    closed_jcs BLOB NOT NULL,
    after_jcs BLOB NOT NULL,
    FOREIGN KEY (decision_id) REFERENCES human_dispositions(decision_id)
) STRICT;

CREATE TABLE refusals (
    refusal_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    refusal_jcs BLOB NOT NULL,
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms >= 0),
    FOREIGN KEY (campaign_id, occurrence_id)
        REFERENCES occurrences(campaign_id, occurrence_id)
) STRICT;
";

/// Exact semantic transition kind stored in the authoritative journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignTransitionKindV1 {
    /// Initial occurrence creation.
    CampaignCreated,
    /// Fresh observation and exact proposal recorded.
    ProposalRecorded,
    /// Explicit standing gate entered.
    StandingRequired,
    /// Positive exact-work decision recorded.
    Admissible,
    /// One AG authorization durably spent and issuance sealed.
    AuthorizationConsumed,
    /// Docket accepted execution custody.
    DocketCustodyAccepted,
    /// Known settlement recorded.
    SettlementRecorded,
    /// Indeterminate attempt entered reconciliation.
    ReconciliationRequired,
    /// Read-only reconciliation produced exact settlement.
    ReconciledSettlement,
    /// Distinct continuation occurrence opened.
    ContinuationOpened,
    /// Read-only probe budget fact recorded.
    ProbeNoted,
    /// Safe halt recorded.
    Halted,
    /// Exact Docket-sealed governed-repair outcome pinned into a halt.
    DocketGovernedRepairHalted,
    /// Exact Docket pre-custody refusal terminalized a consumed issuance.
    DocketIssuanceRefused,
    /// Escalation budget fact and halt recorded.
    Escalated,
    /// Ambiguous restarted dispatch entered reconciliation.
    RecoveryReconciliation,
    /// Exact external human disposition consumed.
    HumanDisposition,
    /// Terminal completion recorded.
    Completed,
}

impl CampaignTransitionKindV1 {
    /// Returns the stable wire tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CampaignCreated => "campaign_created",
            Self::ProposalRecorded => "proposal_recorded",
            Self::StandingRequired => "standing_required",
            Self::Admissible => "admissible",
            Self::AuthorizationConsumed => "authorization_consumed",
            Self::DocketCustodyAccepted => "docket_custody_accepted",
            Self::SettlementRecorded => "settlement_recorded",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::ReconciledSettlement => "reconciled_settlement",
            Self::ContinuationOpened => "continuation_opened",
            Self::ProbeNoted => "probe_noted",
            Self::Halted => "halted",
            Self::DocketGovernedRepairHalted => "docket_governed_repair_halted",
            Self::DocketIssuanceRefused => "docket_issuance_refused",
            Self::Escalated => "escalated",
            Self::RecoveryReconciliation => "recovery_reconciliation",
            Self::HumanDisposition => "human_disposition",
            Self::Completed => "completed",
        }
    }

    fn parse(value: &str) -> Result<Self, CampaignStoreErrorV1> {
        match value {
            "campaign_created" => Ok(Self::CampaignCreated),
            "proposal_recorded" => Ok(Self::ProposalRecorded),
            "standing_required" => Ok(Self::StandingRequired),
            "admissible" => Ok(Self::Admissible),
            "authorization_consumed" => Ok(Self::AuthorizationConsumed),
            "docket_custody_accepted" => Ok(Self::DocketCustodyAccepted),
            "settlement_recorded" => Ok(Self::SettlementRecorded),
            "reconciliation_required" => Ok(Self::ReconciliationRequired),
            "reconciled_settlement" => Ok(Self::ReconciledSettlement),
            "continuation_opened" => Ok(Self::ContinuationOpened),
            "probe_noted" => Ok(Self::ProbeNoted),
            "halted" => Ok(Self::Halted),
            "docket_governed_repair_halted" => Ok(Self::DocketGovernedRepairHalted),
            "docket_issuance_refused" => Ok(Self::DocketIssuanceRefused),
            "escalated" => Ok(Self::Escalated),
            "recovery_reconciliation" => Ok(Self::RecoveryReconciliation),
            "human_disposition" => Ok(Self::HumanDisposition),
            "completed" => Ok(Self::Completed),
            _ => Err(CampaignStoreErrorV1::Corrupt(
                "unknown transition kind".to_owned(),
            )),
        }
    }
}

/// Stable read-only ordered event record exposed by the product service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignEventV1 {
    /// Monotone `SQLite` journal sequence.
    pub sequence: u64,
    /// Exact transition kind.
    pub kind: CampaignTransitionKindV1,
    /// Source occurrence, absent only for genesis.
    pub source_occurrence: Option<String>,
    /// Successor occurrence.
    pub successor_occurrence: String,
    /// Exact predecessor state.
    pub predecessor_state_digest: Digest,
    /// Exact successor state.
    pub successor_state_digest: Digest,
    /// Exact event-chain identity.
    pub event_digest: Digest,
    /// Durable record time.
    pub recorded_at_unix_ms: u64,
}

/// Exact current durable head counters for stable product views.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignHeadV1 {
    /// Exact current revision.
    pub revision: u64,
    /// Exact event count/last sequence.
    pub event_count: u64,
    /// Exact current state.
    pub state_digest: Digest,
    /// Exact event-chain head.
    pub event_head: Digest,
}

/// One coherent read-only product projection acquired under a single `SQLite`
/// read transaction. The current snapshot, head counters, consequence time,
/// and open decision request therefore all describe the same durable cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignStateReadV1 {
    /// Exact authoritative current occurrence at this cut.
    pub current: OccurrenceSnapshotV1,
    /// Exact campaign head at this cut.
    pub head: CampaignHeadV1,
    /// Sole unconsumed and unexpired request for the current state, if any.
    pub open_human_decision_request: Option<HumanDecisionRequestRefV1>,
    /// Latest consequence timestamp in the transition journal at this cut.
    pub last_recorded_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum CampaignTransitionEvidenceV1 {
    None,
    ProductGenesis {
        product_creation: Option<Digest>,
        verifier_root: Option<Digest>,
    },
    HumanDisposition {
        artifact: HumanDispositionV1,
        verification: HumanVerificationRefV1,
    },
    GovernedRepairDisposition {
        request: HumanDecisionRequestV1,
        artifact: GovernedRepairDispositionV1,
        verification: GovernedRepairVerificationV1,
    },
    DocketGovernedRepairHalt {
        result: DocketSealedGovernedRepairResultV1,
    },
    DocketIssuanceRefusal {
        refusal: DocketIssuanceRefusalV1,
    },
}

#[derive(Clone, Copy)]
enum DirectArtifactKindV1 {
    HumanDecisionRequest,
    GovernedRepairDisposition,
    AgSpend,
    AgIssuance,
    DocketSettlement,
    ProductCreation,
    GovernedRepairVerifierRoot,
    Refusal,
}

/// Closed Store-to-product artifact taxonomy used to project a complete
/// occurrence lifecycle without exposing Store internals.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum StoreLifecycleArtifactKindV1 {
    ObservationResolution,
    StandingResolution,
    AdmissionDecision,
    AgAuthorizationSpend,
    AgIssuance,
    DocketCustody,
    DocketSettlement,
    DocketGovernedRepairResult,
    GovernedRepairDisposition,
    GovernedRepairVerification,
    HumanDecisionRequest,
    DocketCheckpointReference,
    EffectJournalReference,
    DocketIndeterminateOutcome,
    SuccessorBinding,
    ResidualState,
    CompletionObservation,
    TerminalWitness,
    HistoricalHumanDisposition,
    DocketIssuanceRefusal,
    Refusal,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct StoreLifecycleArtifactLinkV1 {
    pub kind: StoreLifecycleArtifactKindV1,
    pub identity: Digest,
}

#[derive(Serialize)]
struct StoreEventDigestInputV1<'a> {
    campaign: &'a CampaignId,
    source_occurrence: Option<&'a str>,
    successor_occurrence: &'a str,
    transition_kind: &'a str,
    predecessor_state_digest: &'a Digest,
    successor_state_digest: &'a Digest,
    evidence_digest: &'a Digest,
    previous_event_digest: &'a Digest,
    recorded_at_unix_ms: u64,
}

/// Receipt for one committed compare-and-swap transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignCommitReceiptV1 {
    /// New campaign revision.
    pub revision: u64,
    /// Exact predecessor state digest.
    pub predecessor_state_digest: Digest,
    /// Exact successor state digest.
    pub successor_state_digest: Digest,
    /// Exact chained store-event identity.
    pub event_digest: Digest,
}

/// Process-local, one-use proof that this exact Store opened and measured its
/// pinned verifier root and the kernel accepted the exact verifier response.
/// Fields are private; decoded records or caller-built verification values
/// cannot cross the persistence membrane.
///
/// The type is crate-private and has no caller-visible constructor. External
/// API-boundary tests defend that the product root is the only production
/// path that can obtain and consume this witness.
pub struct StoreVerifiedGovernedRepairEffectV1 {
    store_file: StoreFileIdentityV1,
    expected: OccurrenceSnapshotV1,
    request: HumanDecisionRequestV1,
    effect: GovernedRepairDispositionEffectV1,
    artifact: GovernedRepairDispositionV1,
    recorded_at_unix_ms: u64,
}

/// Process-local, non-serializable one-use permission to authenticate the
/// exact issuance produced by this Store's already-consumed AG spend.
///
/// The value is intentionally neither `Clone` nor `Copy`; the production
/// signer must consume it. Raw issuance records remain evidence and cannot be
/// substituted for this Store-owned boundary.
///
/// The type is crate-private and has no caller-visible constructor. External
/// API-boundary tests defend that decoded issuance evidence cannot mint it.
pub struct StoreIssuanceSigningPermitV1 {
    store_file: StoreFileIdentityV1,
    spend: AgSpendRefV1,
    issuance: AgIssuanceV2,
}

impl StoreIssuanceSigningPermitV1 {
    /// Consumes the one-use Store permission and returns the exact issuance to
    /// the production authentication boundary.
    #[must_use]
    pub fn into_issuance(self) -> AgIssuanceV2 {
        let Self {
            store_file,
            spend,
            issuance,
        } = self;
        let _ = (store_file, spend);
        issuance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoreFileIdentityV1 {
    device: u64,
    inode: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreVerifierRootWireV1 {
    schema: String,
    verifier_label: String,
    executable: PathBuf,
    executable_identity: Digest,
    catalog: StoreVerifierCatalogWireV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreVerifierCatalogWireV1 {
    schema: String,
    profiles: Vec<StoreVerifierProfileWireV1>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreVerifierProfileWireV1 {
    profile: Digest,
    principal: HumanPrincipalRefV1,
    mandate: MandateRefV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct StoreVerifierCommandRequestV1<'a> {
    schema: &'static str,
    request: &'a HumanDecisionRequestV1,
    artifact: &'a GovernedRepairDispositionV1,
    expected_profile: &'a Digest,
    expected_root: &'a Digest,
    expected_executable: &'a Digest,
    expected_principal: &'a HumanPrincipalRefV1,
    expected_mandate: &'a MandateRefV1,
    now_unix_ms: u64,
}

struct ExactStoreVerificationV1(Option<GovernedRepairVerificationV1>);

impl GovernedRepairDispositionVerifierV1 for ExactStoreVerificationV1 {
    fn verify_governed_repair_disposition(
        &mut self,
        _request: &GovernedRepairVerificationRequestV1<'_>,
    ) -> Result<GovernedRepairVerificationV1, ag_campaign::governed::ExternalBoundaryErrorV1> {
        self.0.take().ok_or_else(
            || ag_campaign::governed::ExternalBoundaryErrorV1::Unavailable {
                code: "store verifier response already consumed".to_owned(),
            },
        )
    }
}

/// Read-only replay/consistency result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignReplayReportV1 {
    /// Exact campaign.
    pub campaign: CampaignId,
    /// Number of committed state transitions including genesis.
    pub transitions: u64,
    /// Number of durable AG spends.
    pub ag_spends: u64,
    /// Number of Docket attempts.
    pub docket_attempts: u64,
    /// Number of known settlements.
    pub settlements: u64,
    /// Number of consumed human dispositions.
    pub human_dispositions: u64,
    /// Number of durable non-authorizing governed-repair requests.
    pub human_decision_requests: u64,
    /// Number of consumed governed-repair dispositions.
    pub governed_repair_dispositions: u64,
    /// Current authoritative state digest.
    pub current_state_digest: Digest,
}

/// Transactional campaign-store failures.
#[derive(Debug, Error)]
pub enum CampaignStoreErrorV1 {
    /// Store already exists.
    #[error("campaign store already exists: {0}")]
    AlreadyExists(PathBuf),
    /// Store does not exist.
    #[error("campaign store does not exist: {0}")]
    Missing(PathBuf),
    /// `SQLite` failure.
    #[error("campaign SQLite failure: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Filesystem failure.
    #[error("campaign store I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// Canonical encoding/decoding failure.
    #[error("campaign canonical record failure: {0}")]
    Canonical(String),
    /// Pure kernel refused the transition.
    #[error("campaign kernel refused transition: {0}")]
    Kernel(#[from] ag_campaign::governed::KernelErrorV1),
    /// Compare-and-swap predecessor is stale.
    #[error("stale campaign predecessor: expected {expected}, authoritative {authoritative}")]
    StalePredecessor {
        /// Presented expected state digest.
        expected: Digest,
        /// Authoritative state digest.
        authoritative: Digest,
    },
    /// Campaign or occurrence binding differs.
    #[error("campaign/occurrence binding mismatch")]
    BindingMismatch,
    /// Store identity/schema is not exact.
    #[error("campaign store identity mismatch")]
    StoreIdentity,
    /// Durable state is inconsistent or tampered.
    #[error("corrupt campaign store: {0}")]
    Corrupt(String),
    /// A human disposition was replayed or substituted.
    #[error("human disposition replay/substitution")]
    HumanDispositionReplay,
    /// A decision request or governed-repair disposition was replayed or
    /// substituted.
    #[error("governed repair request/disposition replay or substitution")]
    GovernedRepairReplay,
    /// This exact issuance already crossed the one-use authentication seam.
    /// Callers must reconcile Docket custody instead of signing again.
    #[error("issuance signing already reserved; reconcile exact issuance")]
    IssuanceSigningAlreadyReserved,
    /// The deployment-pinned governed-repair verifier refused or was not
    /// available through the exact measured executable.
    #[error("governed repair verifier failure: {0}")]
    GovernedRepairVerifier(String),
}

/// One authoritative `SQLite` campaign store.
pub struct CampaignStoreV1 {
    path: PathBuf,
    connection: Connection,
}

impl CampaignStoreV1 {
    /// Creates a new store around one kernel-produced initial occurrence.
    #[cfg(test)]
    pub fn create(
        path: &Path,
        initial: &OccurrenceSnapshotV1,
        recorded_at_unix_ms: u64,
    ) -> Result<Self, CampaignStoreErrorV1> {
        Self::create_with_product_records(path, initial, recorded_at_unix_ms, None, None)
    }

    /// Creates genesis and optional immutable product/verifier roots in the
    /// same `SQLite` transaction; no rootless partial campaign can be observed.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_product_records(
        path: &Path,
        initial: &OccurrenceSnapshotV1,
        recorded_at_unix_ms: u64,
        product_creation: Option<(&Digest, &Digest, &[u8])>,
        verifier_root: Option<(&Digest, &[u8])>,
    ) -> Result<Self, CampaignStoreErrorV1> {
        initial.validate_integrity()?;
        if initial.program_counter() != ProgramCounterV1::ObservationRequired
            || initial.prior_occurrence().is_some()
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "genesis must be an initial observation-required occurrence".to_owned(),
            ));
        }
        if path.exists() {
            return Err(CampaignStoreErrorV1::AlreadyExists(path.to_owned()));
        }
        let parent = path.parent().ok_or_else(|| {
            CampaignStoreErrorV1::Corrupt("database path has no parent".to_owned())
        })?;
        if !parent.is_dir() {
            return Err(CampaignStoreErrorV1::Missing(parent.to_owned()));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_connection(&connection)?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(SCHEMA_SQL)?;
        let schema_digest =
            Digest::hash_domain("ag.governed-loop.store-schema/v1", SCHEMA_SQL.as_bytes());
        transaction.execute(
            "INSERT INTO store_identity
             (singleton, application_id, schema_name, schema_version, schema_digest)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                i64::from(CAMPAIGN_STORE_APPLICATION_ID),
                CAMPAIGN_STORE_SCHEMA_NAME,
                i64::from(CAMPAIGN_STORE_SCHEMA_VERSION),
                schema_digest.as_str(),
            ],
        )?;
        transaction.pragma_update(None, "application_id", CAMPAIGN_STORE_APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", CAMPAIGN_STORE_SCHEMA_VERSION)?;

        let snapshot_jcs = encode(initial)?;
        let campaign = &initial.key().campaign;
        let occurrence = initial.key().occurrence.to_string();
        let previous_event_digest =
            Digest::hash_domain(EVENT_GENESIS_DOMAIN_V1, campaign.as_str().as_bytes());
        let evidence = CampaignTransitionEvidenceV1::ProductGenesis {
            product_creation: product_creation.map(|(_, identity, _)| identity.clone()),
            verifier_root: verifier_root.map(|(identity, _)| identity.clone()),
        };
        let evidence_jcs = encode(&evidence)?;
        let evidence_digest = Digest::hash_domain(EVENT_DOMAIN_V1, &evidence_jcs);
        let event_digest = store_event_digest(
            campaign,
            None,
            &occurrence,
            CampaignTransitionKindV1::CampaignCreated,
            initial.prior_state_digest(),
            initial.state_digest(),
            &evidence_digest,
            &previous_event_digest,
            recorded_at_unix_ms,
        );
        transaction.execute(
            "INSERT INTO campaigns
             (campaign_id, current_occurrence_id, current_state_digest, revision,
              event_count, event_head_digest)
             VALUES (?1, ?2, ?3, 1, 1, ?4)",
            params![
                campaign.as_str(),
                occurrence,
                initial.state_digest().as_str(),
                event_digest.as_str(),
            ],
        )?;
        insert_occurrence(&transaction, initial, 1, &snapshot_jcs)?;
        transaction.execute(
            "INSERT INTO transitions
             (campaign_id, source_occurrence_id, successor_occurrence_id,
              transition_kind, predecessor_state_digest, successor_state_digest,
              successor_snapshot_jcs, evidence_jcs, evidence_digest,
              previous_event_digest, event_digest, recorded_at_unix_ms)
             VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                campaign.as_str(),
                initial.key().occurrence.to_string(),
                CampaignTransitionKindV1::CampaignCreated.as_str(),
                initial.prior_state_digest().as_str(),
                initial.state_digest().as_str(),
                snapshot_jcs,
                evidence_jcs,
                evidence_digest.as_str(),
                previous_event_digest.as_str(),
                event_digest.as_str(),
                to_i64(recorded_at_unix_ms)?,
            ],
        )?;
        if let Some((idempotency, identity, bytes)) = product_creation {
            transaction.execute(
                "INSERT INTO product_creation_request
                 (singleton,idempotency_key,request_identity,request_jcs)
                 VALUES (1,?1,?2,?3)",
                params![idempotency.as_str(), identity.as_str(), bytes],
            )?;
        }
        if let Some((identity, bytes)) = verifier_root {
            transaction.execute(
                "INSERT INTO governed_repair_verifier_root
                 (singleton,config_identity,config_jcs) VALUES (1,?1,?2)",
                params![identity.as_str(), bytes],
            )?;
        }
        transaction.commit()?;
        let store = Self {
            path: path.to_owned(),
            connection,
        };
        store.verify_identity()?;
        store.replay()?;
        Ok(store)
    }

    /// Opens an existing authoritative store for mutation.
    pub fn open(path: &Path) -> Result<Self, CampaignStoreErrorV1> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| CampaignStoreErrorV1::Missing(path.to_owned()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CampaignStoreErrorV1::Missing(path.to_owned()));
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_connection(&connection)?;
        migrate_v1_to_v2_if_safe(&mut connection)?;
        migrate_v2_to_v3_if_safe(&mut connection)?;
        migrate_v3_to_v4_if_safe(&mut connection)?;
        let store = Self {
            path: path.to_owned(),
            connection,
        };
        store.verify_identity()?;
        store.replay()?;
        Ok(store)
    }

    /// Returns the store path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the authoritative current snapshot.
    pub fn current(&self) -> Result<OccurrenceSnapshotV1, CampaignStoreErrorV1> {
        let bytes: Vec<u8> = self.connection.query_row(
            "SELECT o.snapshot_jcs
             FROM campaigns c JOIN occurrences o
               ON o.campaign_id=c.campaign_id
              AND o.occurrence_id=c.current_occurrence_id",
            [],
            |row| row.get(0),
        )?;
        let snapshot: OccurrenceSnapshotV1 = decode(&bytes)?;
        snapshot.validate_integrity()?;
        if encode(&snapshot)? != bytes {
            return Err(CampaignStoreErrorV1::Corrupt(
                "current occurrence bytes do not round-trip exactly".to_owned(),
            ));
        }
        Ok(snapshot)
    }

    /// Reads the product-facing current state as one coherent `SQLite` snapshot.
    ///
    /// The deferred transaction establishes its read snapshot with the joined
    /// head/current query and retains that exact cut while resolving the open
    /// decision request. Concurrent writers may commit before or after this
    /// read, but cannot produce a mixed product projection.
    pub fn campaign_state_read(
        &self,
        now_unix_ms: u64,
    ) -> Result<CampaignStateReadV1, CampaignStoreErrorV1> {
        let transaction = self.connection.unchecked_transaction()?;
        let row: (i64, i64, String, String, Vec<u8>, i64) = transaction.query_row(
            "SELECT c.revision,c.event_count,c.current_state_digest,
                    c.event_head_digest,o.snapshot_jcs,
                    (SELECT MAX(recorded_at_unix_ms) FROM transitions)
             FROM campaigns c JOIN occurrences o
               ON o.campaign_id=c.campaign_id
              AND o.occurrence_id=c.current_occurrence_id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        let current: OccurrenceSnapshotV1 = decode(&row.4)?;
        current.validate_integrity()?;
        let head = CampaignHeadV1 {
            revision: to_u64(row.0)?,
            event_count: to_u64(row.1)?,
            state_digest: Digest::parse(&row.2)
                .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
            event_head: Digest::parse(&row.3)
                .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
        };
        if current.state_digest() != &head.state_digest {
            return Err(CampaignStoreErrorV1::Corrupt(
                "coherent state read head/current mismatch".to_owned(),
            ));
        }
        let open_human_decision_request = open_human_decision_request_record_on(
            &transaction,
            current.state_digest(),
            now_unix_ms,
        )?
        .map(|request| request.reference());
        let last_recorded_at_unix_ms = to_u64(row.5)?;
        transaction.commit()?;
        Ok(CampaignStateReadV1 {
            current,
            head,
            open_human_decision_request,
            last_recorded_at_unix_ms,
        })
    }

    /// Returns the latest durable consequence timestamp in the ordered event
    /// journal.  Product-owned clocks must not move behind this cut after a
    /// process restart.
    pub fn last_recorded_at_unix_ms(&self) -> Result<u64, CampaignStoreErrorV1> {
        let value: i64 = self.connection.query_row(
            "SELECT MAX(recorded_at_unix_ms) FROM transitions",
            [],
            |row| row.get(0),
        )?;
        to_u64(value)
    }

    /// Returns the exact pinned verifier-root identity and canonical bytes.
    pub fn governed_repair_verifier_root(
        &self,
    ) -> Result<Option<(Digest, Vec<u8>)>, CampaignStoreErrorV1> {
        let value: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT config_identity,config_jcs FROM governed_repair_verifier_root WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        value
            .map(|(identity, bytes)| {
                let identity = Digest::parse(&identity)
                    .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
                Ok((identity, bytes))
            })
            .transpose()
    }

    /// Opens and remeasures the immutable verifier root pinned at campaign
    /// creation, obtains one current exact response, and seals the resulting
    /// kernel effect to this Store file.  The returned witness is process-local
    /// and cannot be decoded or caller-constructed.
    pub fn verify_governed_repair_disposition(
        &self,
        expected_state_digest: &Digest,
        request_ref: &HumanDecisionRequestRefV1,
        artifact: GovernedRepairDispositionV1,
        now_unix_ms: u64,
    ) -> Result<StoreVerifiedGovernedRepairEffectV1, CampaignStoreErrorV1> {
        let expected = self.current()?;
        if expected.state_digest() != expected_state_digest {
            return Err(CampaignStoreErrorV1::StalePredecessor {
                expected: expected_state_digest.clone(),
                authoritative: expected.state_digest().clone(),
            });
        }
        let request = self
            .human_decision_request(request_ref)?
            .ok_or(CampaignStoreErrorV1::GovernedRepairReplay)?;
        if request.reference() != *request_ref {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let (root_identity, root_bytes) =
            self.governed_repair_verifier_root()?.ok_or_else(|| {
                CampaignStoreErrorV1::GovernedRepairVerifier(
                    "no verifier root is pinned".to_owned(),
                )
            })?;
        let root: StoreVerifierRootWireV1 = serde_json::from_slice(&root_bytes)
            .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))?;
        let canonical = JcsDocument::canonicalize(&root)
            .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))?;
        if canonical.as_bytes() != root_bytes
            || root.schema != GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1
            || root.verifier_label.is_empty()
            || !root.executable.is_absolute()
            || root.catalog.schema != GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1
            || root.catalog.profiles.is_empty()
            || root
                .catalog
                .profiles
                .windows(2)
                .any(|pair| pair[0].profile >= pair[1].profile)
            || Digest::hash_domain(
                GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1,
                canonical.as_bytes(),
            ) != root_identity
        {
            return Err(CampaignStoreErrorV1::GovernedRepairVerifier(
                "pinned verifier root is not exact/canonical".to_owned(),
            ));
        }
        let profile_row = root
            .catalog
            .profiles
            .iter()
            .find(|row| row.profile == artifact.verifier_profile)
            .ok_or_else(|| {
                CampaignStoreErrorV1::GovernedRepairVerifier(
                    "artifact profile is not root-configured".to_owned(),
                )
            })?;
        let profile = GovernedRepairVerifierProfileV1 {
            profile: profile_row.profile.clone(),
            root: root_identity.clone(),
            executable: root.executable_identity.clone(),
            principal: profile_row.principal.clone(),
            mandate: profile_row.mandate.clone(),
        };
        let mut program = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&root.executable)?;
        let mut executable_bytes = Vec::new();
        program.read_to_end(&mut executable_bytes)?;
        program.seek(SeekFrom::Start(0))?;
        if Digest::hash_bytes(&executable_bytes) != root.executable_identity {
            return Err(CampaignStoreErrorV1::GovernedRepairVerifier(
                "verifier executable identity mismatch".to_owned(),
            ));
        }
        let verification = run_store_verifier(
            program,
            &StoreVerifierCommandRequestV1 {
                schema: GOVERNED_REPAIR_VERIFICATION_REQUEST_SCHEMA_V1,
                request: &request,
                artifact: &artifact,
                expected_profile: &profile.profile,
                expected_root: &profile.root,
                expected_executable: &profile.executable,
                expected_principal: &profile.principal,
                expected_mandate: &profile.mandate,
                now_unix_ms,
            },
        )?;
        let mut verifier = ExactStoreVerificationV1(Some(verification));
        let effect = GovernedLoopKernelV1::apply_governed_repair_disposition(
            &expected,
            &request,
            artifact.clone(),
            &profile,
            &mut verifier,
            now_unix_ms,
        )?;
        GovernedLoopKernelV1::validate_governed_repair_effect(
            &expected, &request, &artifact, &effect,
        )?;
        Ok(StoreVerifiedGovernedRepairEffectV1 {
            store_file: store_file_identity(&self.path)?,
            expected,
            request,
            effect,
            artifact,
            recorded_at_unix_ms: now_unix_ms,
        })
    }

    /// Returns the exact pinned product creation tuple.
    pub fn product_creation_request(
        &self,
    ) -> Result<Option<(Digest, Digest, Vec<u8>)>, CampaignStoreErrorV1> {
        let value: Option<(String, String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT idempotency_key,request_identity,request_jcs
                 FROM product_creation_request WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        value
            .map(|(key, identity, bytes)| {
                Ok((
                    Digest::parse(&key)
                        .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
                    Digest::parse(&identity)
                        .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
                    bytes,
                ))
            })
            .transpose()
    }

    /// Returns the sole exact unconsumed and unexpired decision request for
    /// one halted-state identity.  Historical expired requests remain durable
    /// evidence but are not projected as an open product transition.
    fn open_human_decision_request_record_for_state(
        &self,
        state: &Digest,
        now_unix_ms: u64,
    ) -> Result<Option<HumanDecisionRequestV1>, CampaignStoreErrorV1> {
        open_human_decision_request_record_on(&self.connection, state, now_unix_ms)
    }

    /// Returns the sole exact unconsumed and unexpired request reference for
    /// one halted state.  The full canonical request remains retrievable by
    /// [`Self::human_decision_request`].
    pub fn open_human_decision_request_for_state(
        &self,
        state: &Digest,
        now_unix_ms: u64,
    ) -> Result<Option<HumanDecisionRequestRefV1>, CampaignStoreErrorV1> {
        Ok(self
            .open_human_decision_request_record_for_state(state, now_unix_ms)?
            .map(|request| request.reference()))
    }

    /// Retrieves one exact request by its stable outer idempotency identity.
    /// The returned value is validated and its canonical bytes are checked
    /// against the durable row before it can be used for replay comparison.
    pub fn human_decision_request_by_idempotency(
        &self,
        idempotency: &Digest,
    ) -> Result<Option<HumanDecisionRequestV1>, CampaignStoreErrorV1> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT request_jcs FROM human_decision_requests WHERE idempotency_key=?1",
                params![idempotency.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let value: HumanDecisionRequestV1 = decode(&bytes)?;
                value.validate()?;
                if value.idempotency_key != *idempotency || encode(&value)? != bytes {
                    return Err(CampaignStoreErrorV1::Corrupt(
                        "human decision request idempotency lookup mismatch".to_owned(),
                    ));
                }
                Ok(value)
            })
            .transpose()
    }

    /// Loads one historical/current occurrence snapshot.
    pub fn occurrence(
        &self,
        key: &OccurrenceKeyV1,
    ) -> Result<Option<OccurrenceSnapshotV1>, CampaignStoreErrorV1> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT snapshot_jcs FROM occurrences
                 WHERE campaign_id=?1 AND occurrence_id=?2",
                params![key.campaign.as_str(), key.occurrence.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let snapshot: OccurrenceSnapshotV1 = decode(&bytes)?;
                snapshot.validate_integrity()?;
                Ok(snapshot)
            })
            .transpose()
    }

    /// Lists occurrences in stable UUID order after an optional exclusive
    /// cursor.  The bounded limit must be in `1..=1000`.
    pub fn list_occurrences(
        &self,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<OccurrenceSnapshotV1>, CampaignStoreErrorV1> {
        if limit == 0 || limit > 1000 {
            return Err(CampaignStoreErrorV1::Corrupt(
                "occurrence page limit outside 1..=1000".to_owned(),
            ));
        }
        let cursor = after
            .map(|value| {
                uuid::Uuid::parse_str(value)
                    .map(|uuid| uuid.hyphenated().to_string())
                    .map_err(|_| {
                        CampaignStoreErrorV1::Corrupt("invalid occurrence UUID cursor".to_owned())
                    })
            })
            .transpose()?
            .unwrap_or_default();
        let mut statement = self.connection.prepare(
            "SELECT snapshot_jcs FROM occurrences
             WHERE occurrence_id>?1 ORDER BY occurrence_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![cursor, i64::from(limit)], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| {
            let snapshot: OccurrenceSnapshotV1 = decode(&row?)?;
            snapshot.validate_integrity()?;
            Ok(snapshot)
        })
        .collect()
    }

    /// Lists ordered campaign events after an exclusive numeric cursor.
    pub fn list_events(
        &self,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<CampaignEventV1>, CampaignStoreErrorV1> {
        if limit == 0 || limit > 1000 {
            return Err(CampaignStoreErrorV1::Corrupt(
                "event page limit outside 1..=1000".to_owned(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT sequence,transition_kind,source_occurrence_id,
                    successor_occurrence_id,predecessor_state_digest,
                    successor_state_digest,event_digest,recorded_at_unix_ms
             FROM transitions WHERE sequence>?1 ORDER BY sequence LIMIT ?2",
        )?;
        let rows =
            statement.query_map(params![to_i64(after_sequence)?, i64::from(limit)], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?;
        rows.map(|row| {
            let row = row?;
            Ok(CampaignEventV1 {
                sequence: to_u64(row.0)?,
                kind: CampaignTransitionKindV1::parse(&row.1)?,
                source_occurrence: row.2,
                successor_occurrence: row.3,
                predecessor_state_digest: Digest::parse(&row.4)
                    .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
                successor_state_digest: Digest::parse(&row.5)
                    .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
                event_digest: Digest::parse(&row.6)
                    .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
                recorded_at_unix_ms: to_u64(row.7)?,
            })
        })
        .collect()
    }

    /// Returns one exact durable artifact by its domain-specific identity.
    pub fn artifact_bytes(
        &self,
        identity: &Digest,
    ) -> Result<Option<Vec<u8>>, CampaignStoreErrorV1> {
        // Artifact reads are consequence-adjacent product projections.  A
        // connection may outlive an unauthorized external SQLite mutation, so
        // re-establish the complete event/materialization correspondence at
        // the read cut rather than relying on the validation performed when
        // this process originally opened the Store.
        self.replay()?;
        let mut found = None;
        for (table, id, bytes, kind) in [
            (
                "human_decision_requests",
                "request_id",
                "request_jcs",
                DirectArtifactKindV1::HumanDecisionRequest,
            ),
            (
                "governed_repair_dispositions",
                "disposition_id",
                "artifact_jcs",
                DirectArtifactKindV1::GovernedRepairDisposition,
            ),
            (
                "ag_authorization_spends",
                "spend_id",
                "spend_jcs",
                DirectArtifactKindV1::AgSpend,
            ),
            (
                "ag_authorization_spends",
                "issuance_id",
                "issuance_jcs",
                DirectArtifactKindV1::AgIssuance,
            ),
            (
                "docket_settlements",
                "settlement_id",
                "settlement_jcs",
                DirectArtifactKindV1::DocketSettlement,
            ),
            (
                "product_creation_request",
                "request_identity",
                "request_jcs",
                DirectArtifactKindV1::ProductCreation,
            ),
            (
                "governed_repair_verifier_root",
                "config_identity",
                "config_jcs",
                DirectArtifactKindV1::GovernedRepairVerifierRoot,
            ),
            (
                "refusals",
                "refusal_id",
                "refusal_jcs",
                DirectArtifactKindV1::Refusal,
            ),
        ] {
            let query = format!("SELECT {bytes} FROM {table} WHERE {id}=?1");
            let value: Option<Vec<u8>> = self
                .connection
                .query_row(&query, params![identity.as_str()], |row| row.get(0))
                .optional()?;
            if let Some(bytes) = value {
                validate_direct_artifact_bytes(kind, identity, &bytes)?;
                merge_exact_artifact_bytes(&mut found, bytes)?;
            }
        }

        // Custody is keyed materially by issuance for exactly-once storage,
        // but product consumers address the complete record by the semantic
        // custody identity.  Legacy human dispositions similarly retain the
        // decision key in their table while exposing an artifact reference.
        for (query, record_kind) in [
            (
                "SELECT custody_jcs FROM docket_attempts ORDER BY attempt_id",
                "custody",
            ),
            (
                "SELECT artifact_jcs FROM human_dispositions ORDER BY decision_id",
                "human_disposition",
            ),
        ] {
            let mut statement = self.connection.prepare(query)?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let bytes = row?;
                let matches = if record_kind == "custody" {
                    let custody: ag_campaign::governed::DocketCustodyV1 =
                        decode_exact_artifact(&bytes, "Docket custody")?;
                    custody.reference().as_digest() == identity
                } else {
                    let artifact: HumanDispositionV1 =
                        decode_exact_artifact(&bytes, "human disposition")?;
                    artifact.reference().as_digest() == identity
                };
                if matches {
                    merge_exact_artifact_bytes(&mut found, bytes)?;
                }
            }
        }

        // Known-settlement journal references are Docket-owned identities
        // surfaced by AG as exact correspondence artifacts.
        let mut statement = self
            .connection
            .prepare("SELECT settlement_jcs FROM docket_settlements ORDER BY settlement_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let settlement: DocketSettlementV1 = decode_exact_artifact(&row?, "Docket settlement")?;
            if settlement.cumulative_effect_journal_identity.as_ref() == Some(identity) {
                merge_exact_artifact_bytes(
                    &mut found,
                    encode(&effect_journal_reference_artifact_for_settlement(
                        &settlement,
                    ))?,
                )?;
            }
        }

        // Complete proposal/observation/standing/decision/successor-lineage
        // records remain in the immutable transition chain after the current
        // occurrence projection advances beyond their source state.
        let mut statement = self
            .connection
            .prepare("SELECT successor_snapshot_jcs FROM transitions ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let snapshot: OccurrenceSnapshotV1 = decode(&row?)?;
            snapshot.validate_integrity()?;
            if let Some(proposal) = snapshot.proposal_contract()
                && proposal.reference().as_digest() == identity
            {
                merge_exact_artifact_bytes(&mut found, encode(proposal)?)?;
            }
            if let Some(observation) = snapshot.observation() {
                let artifact = ObservationResolutionArtifactV1 {
                    schema: OBSERVATION_RESOLUTION_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: observation.clone(),
                };
                if &product_artifact_identity(artifact.identity())? == identity {
                    merge_exact_artifact_bytes(&mut found, encode(&artifact)?)?;
                }
            }
            if let Some(standing) = snapshot.standing_resolution() {
                let artifact = StandingResolutionArtifactV1 {
                    schema: STANDING_RESOLUTION_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: standing.clone(),
                };
                if &product_artifact_identity(artifact.identity())? == identity {
                    merge_exact_artifact_bytes(&mut found, encode(&artifact)?)?;
                }
            }
            if let Some(decision) = snapshot.admission_decision() {
                let artifact = AdmissionDecisionArtifactV1 {
                    schema: ADMISSION_DECISION_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: decision.clone(),
                };
                if &product_artifact_identity(artifact.identity())? == identity {
                    merge_exact_artifact_bytes(&mut found, encode(&artifact)?)?;
                }
            }
            if let Some(indeterminate) = snapshot.indeterminate() {
                let artifact = DocketIndeterminateArtifactV1 {
                    schema: DOCKET_INDETERMINATE_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: indeterminate.clone(),
                };
                if &product_artifact_identity(artifact.identity())? == identity {
                    merge_exact_artifact_bytes(&mut found, encode(&artifact)?)?;
                }
            }
            if let Some(successor) = successor_binding_artifact(&snapshot)
                && &successor_binding_identity(&successor)? == identity
            {
                merge_exact_artifact_bytes(&mut found, encode(&successor)?)?;
            }
            let residual = residual_state_artifact(&snapshot);
            if &residual_state_identity(&residual)? == identity {
                merge_exact_artifact_bytes(&mut found, encode(&residual)?)?;
            }
            if let Some(completion) = completion_observation_artifact(&snapshot)
                && &completion_observation_identity(&completion)? == identity
            {
                merge_exact_artifact_bytes(&mut found, encode(&completion)?)?;
            }
            if let Some(witness) = terminal_witness_artifact(&snapshot)
                && &terminal_witness_identity(&witness)? == identity
            {
                merge_exact_artifact_bytes(&mut found, encode(&witness)?)?;
            }
        }

        // Docket's complete sealed result is transition evidence.  The
        // halted-state projection intentionally carries only the typed
        // requirement, so exact artifact retrieval must use this durable
        // evidence record rather than synthesize bytes from state.
        let mut statement = self
            .connection
            .prepare("SELECT evidence_jcs FROM transitions ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let evidence: CampaignTransitionEvidenceV1 = decode(&row?)?;
            if let CampaignTransitionEvidenceV1::DocketGovernedRepairHalt { ref result } = evidence
            {
                let (outcome, _) = governed_repair_result_parts(result);
                if outcome.sealed_result.as_digest() == identity {
                    merge_exact_artifact_bytes(&mut found, encode(result)?)?;
                }
                if outcome.checkpoint.as_digest() == identity {
                    merge_exact_artifact_bytes(
                        &mut found,
                        encode(&docket_checkpoint_artifact(outcome))?,
                    )?;
                }
                if &outcome.effect_journal == identity {
                    merge_exact_artifact_bytes(
                        &mut found,
                        encode(&effect_journal_reference_artifact(outcome))?,
                    )?;
                }
            }
            if let CampaignTransitionEvidenceV1::DocketIssuanceRefusal { ref refusal } = evidence
                && &refusal.refusal == identity
            {
                merge_exact_artifact_bytes(&mut found, encode(&refusal)?)?;
            }
        }

        // External receipt and complete-record identities are each unique and
        // both resolve to the same exact Store-validated verification bytes.
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT verification_jcs FROM governed_repair_verification_identities
                 WHERE identity=?1",
                params![identity.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(bytes) = bytes {
            let verification: GovernedRepairVerificationV1 = decode(&bytes)?;
            if encode(&verification)? != bytes
                || (verification.verification.as_digest() != identity
                    && verification.reference().as_digest() != identity)
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "governed repair verification identity/bytes mismatch".to_owned(),
                ));
            }
            merge_exact_artifact_bytes(&mut found, bytes)?;
        }
        Ok(found)
    }

    /// Returns the closed product artifact inventory for one occurrence by
    /// walking the exact immutable transition chain. This is a read-only
    /// projection; it creates no lifecycle authority.
    pub(crate) fn lifecycle_artifact_links(
        &self,
        key: &OccurrenceKeyV1,
    ) -> Result<Vec<StoreLifecycleArtifactLinkV1>, CampaignStoreErrorV1> {
        self.replay()?;
        let mut links = Vec::new();
        let mut statement = self.connection.prepare(
            "SELECT successor_snapshot_jcs,evidence_jcs FROM transitions
             WHERE campaign_id=?1 AND successor_occurrence_id=?2 ORDER BY sequence",
        )?;
        let rows = statement.query_map(
            params![key.campaign.as_str(), key.occurrence.to_string()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        for row in rows {
            let (snapshot_bytes, evidence_bytes) = row?;
            let snapshot: OccurrenceSnapshotV1 = decode(&snapshot_bytes)?;
            snapshot.validate_integrity()?;
            if let Some(observation) = snapshot.observation() {
                let artifact = ObservationResolutionArtifactV1 {
                    schema: OBSERVATION_RESOLUTION_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: observation.clone(),
                };
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::ObservationResolution,
                    identity: product_artifact_identity(artifact.identity())?,
                });
            }
            if let Some(spend) = snapshot.ag_spend() {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::AgAuthorizationSpend,
                    identity: spend.spend.as_digest().clone(),
                });
            }
            if let Some(issuance) = snapshot.issuance() {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::AgIssuance,
                    identity: issuance.issuance.as_digest().clone(),
                });
            }
            if let Some(custody) = snapshot.docket_custody() {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::DocketCustody,
                    identity: custody.reference().as_digest().clone(),
                });
            }
            if let Some(settlement) = snapshot.settlement() {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::DocketSettlement,
                    identity: settlement.settlement.as_digest().clone(),
                });
                if let Some(journal) = &settlement.cumulative_effect_journal_identity {
                    links.push(StoreLifecycleArtifactLinkV1 {
                        kind: StoreLifecycleArtifactKindV1::EffectJournalReference,
                        identity: journal.clone(),
                    });
                }
            }
            if let Some(standing) = snapshot.standing_resolution() {
                let artifact = StandingResolutionArtifactV1 {
                    schema: STANDING_RESOLUTION_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: standing.clone(),
                };
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::StandingResolution,
                    identity: product_artifact_identity(artifact.identity())?,
                });
            }
            if let Some(decision) = snapshot.admission_decision() {
                let artifact = AdmissionDecisionArtifactV1 {
                    schema: ADMISSION_DECISION_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: decision.clone(),
                };
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::AdmissionDecision,
                    identity: product_artifact_identity(artifact.identity())?,
                });
            }
            if let Some(indeterminate) = snapshot.indeterminate() {
                let artifact = DocketIndeterminateArtifactV1 {
                    schema: DOCKET_INDETERMINATE_ARTIFACT_SCHEMA_V1.to_owned(),
                    state_digest: snapshot.state_digest().clone(),
                    record: indeterminate.clone(),
                };
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::DocketIndeterminateOutcome,
                    identity: product_artifact_identity(artifact.identity())?,
                });
            }
            if let Some(successor) = successor_binding_artifact(&snapshot) {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::SuccessorBinding,
                    identity: successor_binding_identity(&successor)?,
                });
            }
            let residual = residual_state_artifact(&snapshot);
            links.push(StoreLifecycleArtifactLinkV1 {
                kind: StoreLifecycleArtifactKindV1::ResidualState,
                identity: residual_state_identity(&residual)?,
            });
            if let Some(completion) = completion_observation_artifact(&snapshot) {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::CompletionObservation,
                    identity: completion_observation_identity(&completion)?,
                });
            }
            if let Some(witness) = terminal_witness_artifact(&snapshot) {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind: StoreLifecycleArtifactKindV1::TerminalWitness,
                    identity: terminal_witness_identity(&witness)?,
                });
            }

            let evidence: CampaignTransitionEvidenceV1 = decode(&evidence_bytes)?;
            match evidence {
                CampaignTransitionEvidenceV1::GovernedRepairDisposition {
                    request,
                    artifact,
                    verification,
                } => {
                    links.extend([
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::HumanDecisionRequest,
                            identity: request.reference().as_digest().clone(),
                        },
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::GovernedRepairDisposition,
                            identity: artifact.reference().as_digest().clone(),
                        },
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::GovernedRepairVerification,
                            identity: verification.verification.as_digest().clone(),
                        },
                    ]);
                }
                CampaignTransitionEvidenceV1::DocketGovernedRepairHalt { result } => {
                    let (outcome, _) = governed_repair_result_parts(&result);
                    links.extend([
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::DocketGovernedRepairResult,
                            identity: outcome.sealed_result.as_digest().clone(),
                        },
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::AgIssuance,
                            identity: outcome.issuance.as_digest().clone(),
                        },
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::DocketCustody,
                            identity: outcome.custody.as_digest().clone(),
                        },
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::DocketCheckpointReference,
                            identity: outcome.checkpoint.as_digest().clone(),
                        },
                        StoreLifecycleArtifactLinkV1 {
                            kind: StoreLifecycleArtifactKindV1::EffectJournalReference,
                            identity: outcome.effect_journal.clone(),
                        },
                    ]);
                }
                CampaignTransitionEvidenceV1::HumanDisposition { artifact, .. } => {
                    links.push(StoreLifecycleArtifactLinkV1 {
                        kind: StoreLifecycleArtifactKindV1::HistoricalHumanDisposition,
                        identity: artifact.reference().as_digest().clone(),
                    });
                }
                CampaignTransitionEvidenceV1::DocketIssuanceRefusal { refusal } => {
                    links.push(StoreLifecycleArtifactLinkV1 {
                        kind: StoreLifecycleArtifactKindV1::DocketIssuanceRefusal,
                        identity: refusal.refusal,
                    });
                }
                CampaignTransitionEvidenceV1::None
                | CampaignTransitionEvidenceV1::ProductGenesis { .. } => {}
            }
        }
        // Requests and no-state-change refusals are durable occurrence
        // artifacts even after expiry or after later state movement; they do
        // not necessarily have a dedicated transition row.
        for (query, kind) in [
            (
                "SELECT request_id FROM human_decision_requests
                 WHERE campaign_id=?1 AND occurrence_id=?2 ORDER BY request_id",
                StoreLifecycleArtifactKindV1::HumanDecisionRequest,
            ),
            (
                "SELECT refusal_id FROM refusals
                 WHERE campaign_id=?1 AND occurrence_id=?2 ORDER BY refusal_id",
                StoreLifecycleArtifactKindV1::Refusal,
            ),
        ] {
            let mut records = self.connection.prepare(query)?;
            let identities = records.query_map(
                params![key.campaign.as_str(), key.occurrence.to_string()],
                |row| row.get::<_, String>(0),
            )?;
            for identity in identities {
                links.push(StoreLifecycleArtifactLinkV1 {
                    kind,
                    identity: parse_digest(&identity?)?,
                });
            }
        }
        links.sort();
        links.dedup();
        Ok(links)
    }

    /// Appends one exact non-authorizing human-decision request under an exact
    /// current-state CAS.  Repeating the same idempotency key is legal only
    /// when the complete canonical request bytes are identical.
    pub fn record_human_decision_request(
        &mut self,
        expected_state_digest: &Digest,
        request: &HumanDecisionRequestV1,
    ) -> Result<HumanDecisionRequestRefV1, CampaignStoreErrorV1> {
        request.validate()?;
        let request_ref = request.reference();
        let request_jcs = encode(request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let head = campaign_head(&transaction)?;
        if head.state_digest != expected_state_digest.as_str()
            || head.campaign != request.key.campaign.as_str()
            || head.occurrence != request.key.occurrence.to_string()
            || request.halted_state_digest != *expected_state_digest
        {
            let authoritative = Digest::parse(&head.state_digest)
                .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
            return Err(CampaignStoreErrorV1::StalePredecessor {
                expected: expected_state_digest.clone(),
                authoritative,
            });
        }
        let existing: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT request_id, request_jcs FROM human_decision_requests
                 WHERE idempotency_key=?1",
                params![request.idempotency_key.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((identity, bytes)) = existing {
            if identity == request_ref.as_str() && bytes == request_jcs {
                transaction.commit()?;
                return Ok(request_ref);
            }
            return Err(CampaignStoreErrorV1::GovernedRepairReplay);
        }
        {
            let mut statement = transaction.prepare(
                "SELECT request_jcs FROM human_decision_requests
                 WHERE halted_state_digest=?1 AND consumed_by_decision_id IS NULL",
            )?;
            let rows = statement
                .query_map(params![request.halted_state_digest.as_str()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?;
            for row in rows {
                let prior: HumanDecisionRequestV1 = decode(&row?)?;
                prior.validate()?;
                if request.created_at_unix_ms < prior.expires_at_unix_ms {
                    return Err(CampaignStoreErrorV1::GovernedRepairReplay);
                }
            }
        }
        transaction.execute(
            "INSERT INTO human_decision_requests
             (request_id, idempotency_key, campaign_id, occurrence_id,
              halted_state_digest, request_jcs, created_at_unix_ms,
              consumed_by_decision_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            params![
                request_ref.as_str(),
                request.idempotency_key.as_str(),
                request.key.campaign.as_str(),
                request.key.occurrence.to_string(),
                request.halted_state_digest.as_str(),
                request_jcs,
                to_i64(request.created_at_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(request_ref)
    }

    /// Retrieves one exact durable non-authorizing decision request.
    pub fn human_decision_request(
        &self,
        request: &HumanDecisionRequestRefV1,
    ) -> Result<Option<HumanDecisionRequestV1>, CampaignStoreErrorV1> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT request_jcs FROM human_decision_requests WHERE request_id=?1",
                params![request.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let value: HumanDecisionRequestV1 = decode(&bytes)?;
                value.validate()?;
                if value.reference() != *request || encode(&value)? != bytes {
                    return Err(CampaignStoreErrorV1::Corrupt(
                        "human decision request identity/canonical bytes mismatch".to_owned(),
                    ));
                }
                Ok(value)
            })
            .transpose()
    }

    /// Retrieves one exact durable governed-repair disposition artifact.
    pub fn governed_repair_disposition(
        &self,
        identity: &HumanDispositionRefV1,
    ) -> Result<Option<GovernedRepairDispositionV1>, CampaignStoreErrorV1> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT artifact_jcs FROM governed_repair_dispositions WHERE disposition_id=?1",
                params![identity.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let value: GovernedRepairDispositionV1 = decode(&bytes)?;
                if value.reference() != *identity {
                    return Err(CampaignStoreErrorV1::Corrupt(
                        "governed-repair disposition identity mismatch".to_owned(),
                    ));
                }
                Ok(value)
            })
            .transpose()
    }

    /// Retrieves the complete Store-validated verification receipt for one
    /// exact governed-repair disposition.
    pub fn governed_repair_verification_for_disposition(
        &self,
        disposition: &HumanDispositionRefV1,
    ) -> Result<Option<GovernedRepairVerificationV1>, CampaignStoreErrorV1> {
        self.replay()?;
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT verification_jcs FROM governed_repair_dispositions WHERE disposition_id=?1",
                params![disposition.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let value: GovernedRepairVerificationV1 = decode(&bytes)?;
                if value.disposition != *disposition || encode(&value)? != bytes {
                    return Err(CampaignStoreErrorV1::Corrupt(
                        "governed-repair verification identity mismatch".to_owned(),
                    ));
                }
                Ok(value)
            })
            .transpose()
    }

    /// Retrieves one complete verifier response by its unique exact identity.
    /// Same nested evidence under a different request/profile/time envelope is
    /// a different verification record and cannot alias this lookup.
    #[cfg(test)]
    pub fn governed_repair_verification(
        &self,
        identity: &ag_campaign::governed::GovernedRepairVerificationRefV1,
    ) -> Result<Option<GovernedRepairVerificationV1>, CampaignStoreErrorV1> {
        self.replay()?;
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT verification_jcs FROM governed_repair_verification_identities
                 WHERE identity=?1 AND identity_class='record'",
                params![identity.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let value: GovernedRepairVerificationV1 = decode(&bytes)?;
                if value.reference() != *identity || encode(&value)? != bytes {
                    return Err(CampaignStoreErrorV1::Corrupt(
                        "governed-repair verification record identity mismatch".to_owned(),
                    ));
                }
                Ok(value)
            })
            .transpose()
    }

    /// Retrieves the uniquely bound complete verification record for one
    /// external verifier receipt. Exact repeats are therefore idempotent
    /// reads; a receipt cannot name changed complete bytes.
    #[cfg(test)]
    pub fn governed_repair_verification_by_receipt(
        &self,
        receipt: &HumanVerificationRefV1,
    ) -> Result<Option<GovernedRepairVerificationV1>, CampaignStoreErrorV1> {
        self.replay()?;
        let row: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT verification_record_id,verification_jcs
                 FROM governed_repair_verification_identities
                 WHERE identity=?1 AND identity_class='receipt'",
                params![receipt.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(record, bytes)| {
            let value: GovernedRepairVerificationV1 = decode(&bytes)?;
            if value.verification != *receipt
                || value.reference().as_str() != record
                || encode(&value)? != bytes
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "verifier receipt is rebound to changed verification bytes".to_owned(),
                ));
            }
            Ok(value)
        })
        .transpose()
    }

    /// Mints one process-local signing permission from this Store's exact
    /// current authorization-consumed cut. It cannot be created from decoded
    /// issuance bytes, and later states cannot be signed as fresh issuances.
    pub fn issuance_signing_permit(
        &mut self,
    ) -> Result<StoreIssuanceSigningPermitV1, CampaignStoreErrorV1> {
        self.replay()?;
        let current = self.current()?;
        if current.program_counter() != ProgramCounterV1::AuthorizationConsumed {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let spend = current
            .ag_spend()
            .ok_or(CampaignStoreErrorV1::BindingMismatch)?;
        let issuance = current
            .issuance()
            .ok_or(CampaignStoreErrorV1::BindingMismatch)?;
        if spend.spend != issuance.spend || spend.key != issuance.key {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let stored: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT spend_jcs,issuance_jcs FROM ag_authorization_spends
                 WHERE spend_id=?1 AND issuance_id=?2",
                params![spend.spend.as_str(), issuance.issuance.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((stored_spend, stored_issuance)) = stored else {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        };
        if stored_spend != encode(spend)? || stored_issuance != encode(issuance)? {
            return Err(CampaignStoreErrorV1::Corrupt(
                "signing permit basis differs from spend journal".to_owned(),
            ));
        }
        let issuance_jcs = encode(issuance)?;
        let reservation_id = Digest::hash_domain(
            "ag.governed-loop.issuance-signing-reservation/v1",
            &issuance_jcs,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT spend_id,transition_state_digest,issuance_jcs
                 FROM issuance_signing_reservations WHERE issuance_id=?1",
                params![issuance.issuance.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((reserved_spend, reserved_state, reserved_issuance)) = existing {
            if reserved_spend != spend.spend.as_str()
                || reserved_state != current.state_digest().as_str()
                || reserved_issuance != issuance_jcs
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "issuance signing reservation changed under one identity".to_owned(),
                ));
            }
            return Err(CampaignStoreErrorV1::IssuanceSigningAlreadyReserved);
        }
        transaction.execute(
            "INSERT INTO issuance_signing_reservations
             (issuance_id,spend_id,transition_state_digest,reservation_id,issuance_jcs)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                issuance.issuance.as_str(),
                spend.spend.as_str(),
                current.state_digest().as_str(),
                reservation_id.as_str(),
                issuance_jcs,
            ],
        )?;
        transaction.commit()?;
        Ok(StoreIssuanceSigningPermitV1 {
            store_file: store_file_identity(&self.path)?,
            spend: spend.spend.clone(),
            issuance: issuance.clone(),
        })
    }

    /// Commits one non-human kernel successor with exact CAS semantics.
    pub fn commit(
        &mut self,
        expected: &OccurrenceSnapshotV1,
        successor: &OccurrenceSnapshotV1,
        kind: CampaignTransitionKindV1,
        recorded_at_unix_ms: u64,
    ) -> Result<CampaignCommitReceiptV1, CampaignStoreErrorV1> {
        if kind == CampaignTransitionKindV1::HumanDisposition
            || kind == CampaignTransitionKindV1::DocketGovernedRepairHalted
            || kind == CampaignTransitionKindV1::DocketIssuanceRefused
            || kind == CampaignTransitionKindV1::CampaignCreated
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "special transition requires its exact store API".to_owned(),
            ));
        }
        validate_transition_kind(expected, successor, kind)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = write_transition(
            &transaction,
            expected,
            successor,
            kind,
            &CampaignTransitionEvidenceV1::None,
            recorded_at_unix_ms,
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Atomically records one exact Docket refusal before custody. The
    /// issuance spend remains consumed and the refusal bytes are retained as
    /// replayable transition evidence.
    pub fn commit_docket_issuance_refusal(
        &mut self,
        expected: &OccurrenceSnapshotV1,
        successor: &OccurrenceSnapshotV1,
        refusal: &DocketIssuanceRefusalV1,
        recorded_at_unix_ms: u64,
    ) -> Result<CampaignCommitReceiptV1, CampaignStoreErrorV1> {
        let issuance = expected
            .issuance()
            .ok_or(CampaignStoreErrorV1::BindingMismatch)?;
        let spend = expected
            .ag_spend()
            .ok_or(CampaignStoreErrorV1::BindingMismatch)?;
        refusal.validate_for_spend(issuance, spend)?;
        if recorded_at_unix_ms < refusal.refused_at_unix_ms {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let reconstructed =
            GovernedLoopKernelV1::halt_docket_issuance_refusal(expected, refusal.clone())?;
        if reconstructed != *successor
            || successor
                .halted()
                .and_then(|halted| halted.docket_issuance_refusal())
                != Some(refusal)
        {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = write_transition(
            &transaction,
            expected,
            successor,
            CampaignTransitionKindV1::DocketIssuanceRefused,
            &CampaignTransitionEvidenceV1::DocketIssuanceRefusal {
                refusal: refusal.clone(),
            },
            recorded_at_unix_ms,
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Atomically records one Docket-governed post-spend halt with the exact
    /// sealed outcome and pinned requirement. The result may arrive directly
    /// from dispatch or through read-only reconciliation of the same consumed
    /// custody/attempt.
    pub fn commit_docket_governed_repair_halt(
        &mut self,
        expected: &OccurrenceSnapshotV1,
        successor: &OccurrenceSnapshotV1,
        result: &DocketSealedGovernedRepairResultV1,
        recorded_at_unix_ms: u64,
    ) -> Result<CampaignCommitReceiptV1, CampaignStoreErrorV1> {
        result.validate()?;
        let (outcome, requirement) = governed_repair_result_parts(result);
        let halted = successor
            .halted()
            .ok_or(CampaignStoreErrorV1::BindingMismatch)?;
        if halted.governed_repair_requirement() != Some(&requirement) {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let reconstructed = GovernedLoopKernelV1::halt_from_docket_governed_repair(
            expected,
            outcome,
            &requirement,
            halted.reason().clone(),
        )?;
        if reconstructed != *successor {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = write_transition(
            &transaction,
            expected,
            successor,
            CampaignTransitionKindV1::DocketGovernedRepairHalted,
            &CampaignTransitionEvidenceV1::DocketGovernedRepairHalt {
                result: result.clone(),
            },
            recorded_at_unix_ms,
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Atomically consumes one exact persisted request and one freshly
    /// verified governed-repair disposition.  Approval/readjudication writes
    /// the consumed halt and distinct successor in the same `SQLite` cut.
    pub fn commit_verified_governed_repair_disposition(
        &mut self,
        verified: StoreVerifiedGovernedRepairEffectV1,
    ) -> Result<
        (
            GovernedRepairDispositionEffectV1,
            Vec<CampaignCommitReceiptV1>,
        ),
        CampaignStoreErrorV1,
    > {
        let StoreVerifiedGovernedRepairEffectV1 {
            store_file,
            expected,
            request,
            effect,
            artifact,
            recorded_at_unix_ms,
        } = verified;
        if store_file_identity(&self.path)? != store_file {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        GovernedLoopKernelV1::validate_governed_repair_effect(
            &expected, &request, &artifact, &effect,
        )?;
        if request.halted_state_digest != *expected.state_digest()
            || request.key != *expected.key()
            || artifact.halted_state_digest != *expected.state_digest()
            || artifact.campaign != expected.key().campaign
            || artifact.occurrence != expected.key().occurrence
        {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let (verification, first, second) = match &effect {
            GovernedRepairDispositionEffectV1::Rejected {
                halted,
                verification,
            } => (verification, halted, None),
            GovernedRepairDispositionEffectV1::OpenedSuccessor {
                halted,
                successor,
                verification,
            } => (verification, halted, Some(successor)),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request_ref = request.reference();
        let found: Option<(Vec<u8>, Option<String>)> = transaction
            .query_row(
                "SELECT request_jcs, consumed_by_decision_id
                 FROM human_decision_requests WHERE request_id=?1",
                params![request_ref.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((stored_request, consumed)) = found else {
            return Err(CampaignStoreErrorV1::GovernedRepairReplay);
        };
        if stored_request != encode(&request)? || consumed.is_some() {
            return Err(CampaignStoreErrorV1::GovernedRepairReplay);
        }
        let changed = transaction.execute(
            "UPDATE human_decision_requests SET consumed_by_decision_id=?1
             WHERE request_id=?2 AND consumed_by_decision_id IS NULL",
            params![artifact.decision.as_str(), request_ref.as_str()],
        )?;
        if changed != 1 {
            return Err(CampaignStoreErrorV1::GovernedRepairReplay);
        }
        let verification_record = verification.reference();
        if verification.verification.as_str() == verification_record.as_str() {
            return Err(CampaignStoreErrorV1::GovernedRepairReplay);
        }
        let verification_jcs = encode(verification)?;
        // Receipt references and complete verification-record identities share
        // one namespace. Inserting both identities in this same transaction
        // makes cross-column collisions impossible, not merely duplicate
        // receipts or duplicate records within their separate columns.
        transaction.execute(
            "INSERT INTO governed_repair_verification_identities
             (identity,identity_class,verification_record_id,verification_jcs)
             VALUES (?1,'receipt',?2,?3), (?2,'record',?2,?3)",
            params![
                verification.verification.as_str(),
                verification_record.as_str(),
                verification_jcs,
            ],
        )?;
        transaction.execute(
            "INSERT INTO governed_repair_dispositions
             (decision_id, nonce, request_id, campaign_id, occurrence_id,
              halted_state_digest, disposition_id, verification_receipt_ref,
              verification_record_id, verification_jcs, artifact_jcs,
              consumed_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                artifact.decision.as_str(),
                artifact.nonce.as_str(),
                request_ref.as_str(),
                artifact.campaign.as_str(),
                artifact.occurrence.to_string(),
                artifact.halted_state_digest.as_str(),
                artifact.reference().as_str(),
                verification.verification.as_str(),
                verification_record.as_str(),
                encode(verification)?,
                encode(&artifact)?,
                to_i64(recorded_at_unix_ms)?,
            ],
        )?;
        let evidence = CampaignTransitionEvidenceV1::GovernedRepairDisposition {
            request: request.clone(),
            artifact: artifact.clone(),
            verification: verification.clone(),
        };
        let mut receipts = vec![write_transition(
            &transaction,
            &expected,
            first,
            CampaignTransitionKindV1::HumanDisposition,
            &evidence,
            recorded_at_unix_ms,
        )?];
        if let Some(second) = second {
            receipts.push(write_transition(
                &transaction,
                first,
                second,
                CampaignTransitionKindV1::HumanDisposition,
                &evidence,
                recorded_at_unix_ms,
            )?);
        }
        transaction.commit()?;
        Ok((effect, receipts))
    }

    /// Records a durable non-authorizing refusal without changing the PC.
    pub fn record_refusal(
        &mut self,
        refusal: &RefusalOutcomeV1,
        recorded_at_unix_ms: u64,
    ) -> Result<Digest, CampaignStoreErrorV1> {
        let current = self.current()?;
        if refusal.key != *current.key() || refusal.at_state_digest != *current.state_digest() {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
        let bytes = encode(refusal)?;
        let refusal_id = Digest::hash_domain(REFUSAL_DOMAIN_V1, &bytes);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO refusals
             (refusal_id, campaign_id, occurrence_id, state_digest,
              refusal_jcs, recorded_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                refusal_id.as_str(),
                refusal.key.campaign.as_str(),
                refusal.key.occurrence.to_string(),
                refusal.at_state_digest.as_str(),
                bytes,
                to_i64(recorded_at_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(refusal_id)
    }

    /// Reconstructs an exact issuance solely from the authoritative spend journal.
    #[cfg(test)]
    pub fn issuance(
        &self,
        issuance: &ag_campaign::governed::AgIssuanceRefV1,
    ) -> Result<Option<AgIssuanceV2>, CampaignStoreErrorV1> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT issuance_jcs FROM ag_authorization_spends WHERE issuance_id=?1",
                params![issuance.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        bytes.map(|bytes| decode(&bytes)).transpose()
    }

    /// Returns exact accounting counts `(spends, attempts, settlements)`.
    #[cfg(test)]
    pub fn accounting_counts(&self) -> Result<(u64, u64, u64), CampaignStoreErrorV1> {
        Ok((
            table_count(&self.connection, "ag_authorization_spends")?,
            table_count(&self.connection, "docket_attempts")?,
            table_count(&self.connection, "docket_settlements")?,
        ))
    }

    /// Performs deterministic transition replay and exact journal accounting.
    pub fn replay(&self) -> Result<CampaignReplayReportV1, CampaignStoreErrorV1> {
        self.verify_identity()?;
        // Replay compares the append-only transition journal with several
        // materialized/accounting tables.  In WAL mode, independent SELECTs
        // outside a transaction may observe different committed cuts when a
        // concurrent process wins a transition between those SELECTs.  That
        // is a valid CAS race, not store corruption.  Hold one deferred read
        // transaction so every replay input is resolved from the same exact
        // SQLite snapshot.
        let transaction = self.connection.unchecked_transaction()?;
        let report = replay_store(&transaction)?;
        transaction.commit()?;
        Ok(report)
    }

    fn verify_identity(&self) -> Result<(), CampaignStoreErrorV1> {
        let application_id: u32 =
            self.connection
                .query_row("PRAGMA application_id", [], |row| row.get(0))?;
        let user_version: u32 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let identity: (u32, String, u32, String) = self.connection.query_row(
            "SELECT application_id, schema_name, schema_version, schema_digest
             FROM store_identity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        let expected_digest =
            Digest::hash_domain("ag.governed-loop.store-schema/v1", SCHEMA_SQL.as_bytes());
        if application_id != CAMPAIGN_STORE_APPLICATION_ID
            || user_version != CAMPAIGN_STORE_SCHEMA_VERSION
            || identity.0 != CAMPAIGN_STORE_APPLICATION_ID
            || identity.1 != CAMPAIGN_STORE_SCHEMA_NAME
            || identity.2 != CAMPAIGN_STORE_SCHEMA_VERSION
            || identity.3 != expected_digest.as_str()
        {
            return Err(CampaignStoreErrorV1::StoreIdentity);
        }
        Ok(())
    }
}

fn configure_connection(connection: &Connection) -> Result<(), CampaignStoreErrorV1> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(CampaignStoreErrorV1::Corrupt(
            "SQLite refused WAL journal mode".to_owned(),
        ));
    }
    Ok(())
}

fn migrate_v1_to_v2_if_safe(connection: &mut Connection) -> Result<(), CampaignStoreErrorV1> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != 1 {
        return Ok(());
    }
    let identity: (u32, String, u32, String) = connection.query_row(
        "SELECT application_id, schema_name, schema_version, schema_digest
         FROM store_identity WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if identity.0 != CAMPAIGN_STORE_APPLICATION_ID
        || identity.1 != CAMPAIGN_STORE_V1_SCHEMA_NAME
        || identity.2 != 1
        || identity.3 != CAMPAIGN_STORE_V1_SCHEMA_DIGEST
    {
        return Err(CampaignStoreErrorV1::StoreIdentity);
    }
    // V1 proposal/issuance snapshots contain opaque scope digests and cannot
    // honestly be upgraded to V2 structured scopes.  Only an authority-empty
    // genesis can be migrated mechanically; all later V1 stores fail closed.
    let event_count: i64 =
        connection.query_row("SELECT event_count FROM campaigns", [], |row| row.get(0))?;
    let spend_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM ag_authorization_spends", [], |row| {
            row.get(0)
        })?;
    if event_count != 1 || spend_count != 0 {
        return Err(CampaignStoreErrorV1::StoreIdentity);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(V2_ADDITIVE_SCHEMA_SQL)?;
    transaction.execute(
        "UPDATE store_identity SET schema_name=?1, schema_version=?2,
         schema_digest=?3 WHERE singleton=1",
        params![
            CAMPAIGN_STORE_V2_SCHEMA_NAME,
            2_i64,
            CAMPAIGN_STORE_V2_SCHEMA_DIGEST,
        ],
    )?;
    transaction.pragma_update(None, "user_version", 2_u32)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v2_to_v3_if_safe(connection: &mut Connection) -> Result<(), CampaignStoreErrorV1> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != 2 {
        return Ok(());
    }
    let identity: (u32, String, u32, String) = connection.query_row(
        "SELECT application_id, schema_name, schema_version, schema_digest
         FROM store_identity WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if identity.0 != CAMPAIGN_STORE_APPLICATION_ID
        || identity.1 != CAMPAIGN_STORE_V2_SCHEMA_NAME
        || identity.2 != 2
        || identity.3 != CAMPAIGN_STORE_V2_SCHEMA_DIGEST
    {
        return Err(CampaignStoreErrorV1::StoreIdentity);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "ALTER TABLE governed_repair_dispositions
             ADD COLUMN verification_receipt_ref TEXT;
         ALTER TABLE governed_repair_dispositions
             ADD COLUMN verification_record_id TEXT;
         CREATE UNIQUE INDEX governed_repair_dispositions_verification_receipt_ref
             ON governed_repair_dispositions(verification_receipt_ref)
             WHERE verification_receipt_ref IS NOT NULL;
         CREATE UNIQUE INDEX governed_repair_dispositions_verification_record_id
             ON governed_repair_dispositions(verification_record_id)
             WHERE verification_record_id IS NOT NULL;",
    )?;
    let mut rows = Vec::new();
    {
        let mut statement = transaction
            .prepare("SELECT decision_id,verification_jcs FROM governed_repair_dispositions")?;
        let found = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in found {
            rows.push(row?);
        }
    }
    for (decision, bytes) in rows {
        let verification: GovernedRepairVerificationV1 = decode(&bytes)?;
        if encode(&verification)? != bytes {
            return Err(CampaignStoreErrorV1::StoreIdentity);
        }
        transaction.execute(
            "UPDATE governed_repair_dispositions
             SET verification_receipt_ref=?1, verification_record_id=?2
             WHERE decision_id=?3 AND verification_receipt_ref IS NULL
               AND verification_record_id IS NULL",
            params![
                verification.verification.as_str(),
                verification.reference().as_str(),
                decision
            ],
        )?;
    }
    let missing: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM governed_repair_dispositions
         WHERE verification_receipt_ref IS NULL OR verification_record_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    if missing != 0 {
        return Err(CampaignStoreErrorV1::StoreIdentity);
    }
    transaction.execute(
        "UPDATE store_identity SET schema_name=?1, schema_version=?2,
         schema_digest=?3 WHERE singleton=1",
        params![
            CAMPAIGN_STORE_V3_SCHEMA_NAME,
            3_i64,
            CAMPAIGN_STORE_V3_SCHEMA_DIGEST,
        ],
    )?;
    transaction.pragma_update(None, "user_version", 3_u32)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v3_to_v4_if_safe(connection: &mut Connection) -> Result<(), CampaignStoreErrorV1> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != 3 {
        return Ok(());
    }
    let identity: (u32, String, u32, String) = connection.query_row(
        "SELECT application_id, schema_name, schema_version, schema_digest
         FROM store_identity WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if identity.0 != CAMPAIGN_STORE_APPLICATION_ID
        || identity.1 != CAMPAIGN_STORE_V3_SCHEMA_NAME
        || identity.2 != 3
        || identity.3 != CAMPAIGN_STORE_V3_SCHEMA_DIGEST
    {
        return Err(CampaignStoreErrorV1::StoreIdentity);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE governed_repair_verification_identities (
             identity TEXT PRIMARY KEY,
             identity_class TEXT NOT NULL CHECK (identity_class IN ('receipt','record')),
             verification_record_id TEXT NOT NULL,
             verification_jcs BLOB NOT NULL
         ) STRICT;
         CREATE TABLE issuance_signing_reservations (
             issuance_id TEXT PRIMARY KEY,
             spend_id TEXT NOT NULL UNIQUE,
             transition_state_digest TEXT NOT NULL UNIQUE,
             reservation_id TEXT NOT NULL UNIQUE,
             issuance_jcs BLOB NOT NULL,
             FOREIGN KEY (issuance_id) REFERENCES ag_authorization_spends(issuance_id),
             FOREIGN KEY (spend_id) REFERENCES ag_authorization_spends(spend_id)
         ) STRICT;",
    )?;
    let mut rows = Vec::new();
    {
        let mut statement = transaction.prepare(
            "SELECT verification_receipt_ref,verification_record_id,verification_jcs
             FROM governed_repair_dispositions ORDER BY decision_id",
        )?;
        let found = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in found {
            rows.push(row?);
        }
    }
    for (receipt, record, bytes) in rows {
        if receipt == record {
            return Err(CampaignStoreErrorV1::StoreIdentity);
        }
        let verification: GovernedRepairVerificationV1 =
            decode_exact_artifact(&bytes, "governed repair verification migration")?;
        if verification.verification.as_str() != receipt
            || verification.reference().as_str() != record
        {
            return Err(CampaignStoreErrorV1::StoreIdentity);
        }
        transaction.execute(
            "INSERT INTO governed_repair_verification_identities
             (identity,identity_class,verification_record_id,verification_jcs)
             VALUES (?1,'receipt',?2,?3), (?2,'record',?2,?3)",
            params![receipt, record, bytes],
        )?;
    }
    let schema_digest =
        Digest::hash_domain("ag.governed-loop.store-schema/v1", SCHEMA_SQL.as_bytes());
    transaction.execute(
        "UPDATE store_identity SET schema_name=?1, schema_version=?2,
         schema_digest=?3 WHERE singleton=1",
        params![
            CAMPAIGN_STORE_SCHEMA_NAME,
            i64::from(CAMPAIGN_STORE_SCHEMA_VERSION),
            schema_digest.as_str(),
        ],
    )?;
    transaction.pragma_update(None, "user_version", CAMPAIGN_STORE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CampaignStoreErrorV1> {
    JcsDocument::canonicalize(value)
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CampaignStoreErrorV1> {
    JcsDocument::from_canonical_bytes(bytes)
        .and_then(|document| document.decode())
        .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))
}

fn to_i64(value: u64) -> Result<i64, CampaignStoreErrorV1> {
    i64::try_from(value)
        .map_err(|_| CampaignStoreErrorV1::Corrupt("integer exceeds SQLite range".to_owned()))
}

fn to_u64(value: i64) -> Result<u64, CampaignStoreErrorV1> {
    u64::try_from(value)
        .map_err(|_| CampaignStoreErrorV1::Corrupt("negative durable counter".to_owned()))
}

fn pc_tag(value: ProgramCounterV1) -> &'static str {
    match value {
        ProgramCounterV1::ObservationRequired => "observation_required",
        ProgramCounterV1::ProposalRecorded => "proposal_recorded",
        ProgramCounterV1::StandingRequired => "standing_required",
        ProgramCounterV1::AdmissiblePendingAuthorization => "admissible_pending_authorization",
        ProgramCounterV1::AuthorizationConsumed => "authorization_consumed",
        ProgramCounterV1::Dispatched => "dispatched",
        ProgramCounterV1::ReconciliationRequired => "reconciliation_required",
        ProgramCounterV1::SettledObservationRequired => "settled_observation_required",
        ProgramCounterV1::Halted => "halted",
        ProgramCounterV1::Completed => "completed",
    }
}

fn insert_occurrence(
    transaction: &Transaction<'_>,
    snapshot: &OccurrenceSnapshotV1,
    revision: u64,
    snapshot_jcs: &[u8],
) -> Result<(), CampaignStoreErrorV1> {
    transaction.execute(
        "INSERT INTO occurrences
         (campaign_id, occurrence_id, program_basis, program_counter,
          prior_state_digest, state_digest, revision, snapshot_jcs)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            snapshot.key().campaign.as_str(),
            snapshot.key().occurrence.to_string(),
            snapshot.state().meta().program().as_str(),
            pc_tag(snapshot.program_counter()),
            snapshot.prior_state_digest().as_str(),
            snapshot.state_digest().as_str(),
            to_i64(revision)?,
            snapshot_jcs,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn store_event_digest(
    campaign: &CampaignId,
    source_occurrence: Option<&str>,
    successor_occurrence: &str,
    kind: CampaignTransitionKindV1,
    predecessor: &Digest,
    successor: &Digest,
    evidence: &Digest,
    previous: &Digest,
    recorded_at_unix_ms: u64,
) -> Digest {
    let input = StoreEventDigestInputV1 {
        campaign,
        source_occurrence,
        successor_occurrence,
        transition_kind: kind.as_str(),
        predecessor_state_digest: predecessor,
        successor_state_digest: successor,
        evidence_digest: evidence,
        previous_event_digest: previous,
        recorded_at_unix_ms,
    };
    let bytes =
        JcsDocument::canonicalize(&input).expect("store event input is strict JCS-compatible");
    Digest::hash_domain(EVENT_DOMAIN_V1, bytes.as_bytes())
}

#[derive(Debug)]
struct CampaignHeadRow {
    campaign: String,
    occurrence: String,
    state_digest: String,
    revision: u64,
    event_count: u64,
    event_head: String,
}

fn campaign_head(transaction: &Transaction<'_>) -> Result<CampaignHeadRow, CampaignStoreErrorV1> {
    let raw: (String, String, String, i64, i64, String) = transaction.query_row(
        "SELECT campaign_id, current_occurrence_id, current_state_digest,
                revision, event_count, event_head_digest
         FROM campaigns",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    Ok(CampaignHeadRow {
        campaign: raw.0,
        occurrence: raw.1,
        state_digest: raw.2,
        revision: to_u64(raw.3)?,
        event_count: to_u64(raw.4)?,
        event_head: raw.5,
    })
}

fn write_transition(
    transaction: &Transaction<'_>,
    expected: &OccurrenceSnapshotV1,
    successor: &OccurrenceSnapshotV1,
    kind: CampaignTransitionKindV1,
    evidence: &CampaignTransitionEvidenceV1,
    recorded_at_unix_ms: u64,
) -> Result<CampaignCommitReceiptV1, CampaignStoreErrorV1> {
    GovernedLoopKernelV1::validate_successor(expected, successor)?;
    if expected.program_counter() == ProgramCounterV1::AuthorizationConsumed
        && successor.program_counter() == ProgramCounterV1::Halted
        && kind != CampaignTransitionKindV1::DocketIssuanceRefused
        && expected
            .issuance()
            .is_none_or(|issuance| recorded_at_unix_ms < issuance.expires_at_unix_ms)
    {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    if expected.key().campaign != successor.key().campaign {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    let head = campaign_head(transaction)?;
    if head.campaign != expected.key().campaign.as_str()
        || head.occurrence != expected.key().occurrence.to_string()
    {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    let authoritative = Digest::parse(&head.state_digest)
        .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
    if &authoritative != expected.state_digest() {
        return Err(CampaignStoreErrorV1::StalePredecessor {
            expected: expected.state_digest().clone(),
            authoritative,
        });
    }
    validate_transition_kind(expected, successor, kind)?;

    let snapshot_jcs = encode(successor)?;
    let evidence_jcs = encode(evidence)?;
    let evidence_digest = Digest::hash_domain(EVENT_DOMAIN_V1, &evidence_jcs);
    let previous_event_digest = Digest::parse(&head.event_head)
        .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
    let source_occurrence = expected.key().occurrence.to_string();
    let successor_occurrence = successor.key().occurrence.to_string();
    let event_digest = store_event_digest(
        &expected.key().campaign,
        Some(&source_occurrence),
        &successor_occurrence,
        kind,
        expected.state_digest(),
        successor.state_digest(),
        &evidence_digest,
        &previous_event_digest,
        recorded_at_unix_ms,
    );

    if expected.key() == successor.key() {
        let changed = transaction.execute(
            "UPDATE occurrences
             SET program_basis=?1, program_counter=?2, prior_state_digest=?3,
                 state_digest=?4, revision=revision+1, snapshot_jcs=?5
             WHERE campaign_id=?6 AND occurrence_id=?7 AND state_digest=?8",
            params![
                successor.state().meta().program().as_str(),
                pc_tag(successor.program_counter()),
                successor.prior_state_digest().as_str(),
                successor.state_digest().as_str(),
                snapshot_jcs,
                successor.key().campaign.as_str(),
                successor.key().occurrence.to_string(),
                expected.state_digest().as_str(),
            ],
        )?;
        if changed != 1 {
            return Err(CampaignStoreErrorV1::StalePredecessor {
                expected: expected.state_digest().clone(),
                authoritative: Digest::parse(&head.state_digest)
                    .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
            });
        }
    } else {
        insert_occurrence(transaction, successor, 1, &snapshot_jcs)?;
    }

    account_new_facts(transaction, expected, successor)?;
    transaction.execute(
        "INSERT INTO transitions
         (campaign_id, source_occurrence_id, successor_occurrence_id,
          transition_kind, predecessor_state_digest, successor_state_digest,
          successor_snapshot_jcs, evidence_jcs, evidence_digest,
          previous_event_digest, event_digest, recorded_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            expected.key().campaign.as_str(),
            source_occurrence,
            successor_occurrence,
            kind.as_str(),
            expected.state_digest().as_str(),
            successor.state_digest().as_str(),
            snapshot_jcs,
            evidence_jcs,
            evidence_digest.as_str(),
            previous_event_digest.as_str(),
            event_digest.as_str(),
            to_i64(recorded_at_unix_ms)?,
        ],
    )?;
    let next_revision = head.revision.saturating_add(1);
    let next_event_count = head.event_count.saturating_add(1);
    let changed = transaction.execute(
        "UPDATE campaigns
         SET current_occurrence_id=?1, current_state_digest=?2,
             revision=?3, event_count=?4, event_head_digest=?5
         WHERE campaign_id=?6 AND revision=?7 AND current_state_digest=?8",
        params![
            successor.key().occurrence.to_string(),
            successor.state_digest().as_str(),
            to_i64(next_revision)?,
            to_i64(next_event_count)?,
            event_digest.as_str(),
            successor.key().campaign.as_str(),
            to_i64(head.revision)?,
            expected.state_digest().as_str(),
        ],
    )?;
    if changed != 1 {
        return Err(CampaignStoreErrorV1::StalePredecessor {
            expected: expected.state_digest().clone(),
            authoritative: Digest::parse(&head.state_digest)
                .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?,
        });
    }
    Ok(CampaignCommitReceiptV1 {
        revision: next_revision,
        predecessor_state_digest: expected.state_digest().clone(),
        successor_state_digest: successor.state_digest().clone(),
        event_digest,
    })
}

fn account_new_facts(
    transaction: &Transaction<'_>,
    expected: &OccurrenceSnapshotV1,
    successor: &OccurrenceSnapshotV1,
) -> Result<(), CampaignStoreErrorV1> {
    if expected.ag_spend().is_none()
        && let (Some(spend), Some(issuance)) = (successor.ag_spend(), successor.issuance())
    {
        transaction.execute(
            "INSERT INTO ag_authorization_spends
             (spend_id, authorization_id, campaign_id, occurrence_id, issuance_id,
              spend_jcs, issuance_jcs, transition_state_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                spend.spend.as_str(),
                spend.authorization.as_str(),
                spend.key.campaign.as_str(),
                spend.key.occurrence.to_string(),
                issuance.issuance.as_str(),
                encode(spend)?,
                encode(issuance)?,
                successor.state_digest().as_str(),
            ],
        )?;
    }
    if expected.docket_custody().is_none()
        && let Some(custody) = successor.docket_custody()
    {
        transaction.execute(
            "INSERT INTO docket_attempts
             (issuance_id, attempt_id, campaign_id, occurrence_id,
              custody_jcs, transition_state_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                custody.issuance.as_str(),
                custody.attempt.as_str(),
                successor.key().campaign.as_str(),
                successor.key().occurrence.to_string(),
                encode(custody)?,
                successor.state_digest().as_str(),
            ],
        )?;
    }
    if expected.settlement().is_none()
        && let Some(settlement) = successor.settlement()
    {
        transaction.execute(
            "INSERT INTO docket_settlements
             (attempt_id, settlement_id, receipt_id, campaign_id, occurrence_id,
              settlement_jcs, transition_state_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                settlement.attempt.as_str(),
                settlement.settlement.as_str(),
                settlement.receipt.as_str(),
                successor.key().campaign.as_str(),
                successor.key().occurrence.to_string(),
                encode(settlement)?,
                successor.state_digest().as_str(),
            ],
        )?;
    }
    Ok(())
}

fn validate_transition_kind(
    source: &OccurrenceSnapshotV1,
    target: &OccurrenceSnapshotV1,
    kind: CampaignTransitionKindV1,
) -> Result<(), CampaignStoreErrorV1> {
    use CampaignTransitionKindV1 as K;
    use ProgramCounterV1 as P;
    let pair = (source.program_counter(), target.program_counter());
    let valid = match kind {
        K::CampaignCreated => false,
        K::ProposalRecorded => pair == (P::ObservationRequired, P::ProposalRecorded),
        K::StandingRequired => pair == (P::ProposalRecorded, P::StandingRequired),
        K::Admissible => pair == (P::StandingRequired, P::AdmissiblePendingAuthorization),
        K::AuthorizationConsumed => {
            pair == (P::AdmissiblePendingAuthorization, P::AuthorizationConsumed)
        }
        K::DocketCustodyAccepted => pair == (P::AuthorizationConsumed, P::Dispatched),
        K::SettlementRecorded => pair == (P::Dispatched, P::SettledObservationRequired),
        K::ReconciliationRequired | K::RecoveryReconciliation => {
            pair == (P::Dispatched, P::ReconciliationRequired)
        }
        K::ReconciledSettlement => {
            pair == (P::ReconciliationRequired, P::SettledObservationRequired)
        }
        K::ContinuationOpened => {
            pair == (P::SettledObservationRequired, P::ObservationRequired)
                && source.key() != target.key()
        }
        K::ProbeNoted => {
            (pair == (P::ObservationRequired, P::ObservationRequired)
                || pair == (P::SettledObservationRequired, P::SettledObservationRequired))
                && source.key() == target.key()
        }
        K::Halted | K::Escalated => {
            target.program_counter() == P::Halted
                && source.program_counter() != P::Dispatched
                && target.halted().is_some_and(|halted| {
                    halted.governed_repair_requirement().is_none()
                        && halted.docket_issuance_refusal().is_none()
                })
        }
        K::DocketGovernedRepairHalted => {
            matches!(pair, (P::Dispatched | P::ReconciliationRequired, P::Halted))
                && target
                    .halted()
                    .is_some_and(|halted| halted.governed_repair_requirement().is_some())
        }
        K::DocketIssuanceRefused => {
            pair == (P::AuthorizationConsumed, P::Halted)
                && target
                    .halted()
                    .is_some_and(|halted| halted.docket_issuance_refusal().is_some())
        }
        K::HumanDisposition => {
            source.program_counter() == P::Halted
                && matches!(
                    target.program_counter(),
                    P::Halted | P::ObservationRequired | P::Completed
                )
        }
        K::Completed => pair == (P::ObservationRequired, P::Completed),
    };
    if !valid {
        return Err(CampaignStoreErrorV1::Corrupt(format!(
            "transition kind {} does not describe {:?}->{:?}",
            kind.as_str(),
            pair.0,
            pair.1
        )));
    }
    Ok(())
}

fn validate_human_transition_evidence(
    source: &OccurrenceSnapshotV1,
    target: &OccurrenceSnapshotV1,
    artifact: &HumanDispositionV1,
) -> Result<(), CampaignStoreErrorV1> {
    if source.program_counter() != ProgramCounterV1::Halted {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    let original = artifact.halted_state_digest == *source.state_digest();
    let second_open = artifact.halted_state_digest == *source.prior_state_digest()
        && target.program_counter() == ProgramCounterV1::ObservationRequired;
    if !original && !second_open {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    if original {
        match &artifact.disposition {
            HumanDispositionKindV1::ReturnToObservation
            | HumanDispositionKindV1::ReplaceProgram(_) => {
                if target.program_counter() != ProgramCounterV1::Halted
                    || target.state().meta().program() != source.state().meta().program()
                    || target.state().meta().residuals() != source.state().meta().residuals()
                {
                    return Err(CampaignStoreErrorV1::BindingMismatch);
                }
            }
            HumanDispositionKindV1::ExactResidualDisposition(discharge) => {
                validate_residual_disposition(source, target, artifact, discharge)?;
            }
            HumanDispositionKindV1::Terminate { .. } => {
                if target.program_counter() != ProgramCounterV1::Completed
                    || !source.state().meta().residuals().is_empty()
                {
                    return Err(CampaignStoreErrorV1::BindingMismatch);
                }
            }
        }
    } else {
        let expected_program = match &artifact.disposition {
            HumanDispositionKindV1::ReturnToObservation => source.state().meta().program(),
            HumanDispositionKindV1::ReplaceProgram(program) => program,
            _ => return Err(CampaignStoreErrorV1::BindingMismatch),
        };
        if target.state().meta().program() != expected_program
            || target.state().meta().residuals() != source.state().meta().residuals()
            || source.state().meta().used_human_decisions().last() != Some(&artifact.decision)
        {
            return Err(CampaignStoreErrorV1::BindingMismatch);
        }
    }
    Ok(())
}

fn validate_residual_disposition(
    source: &OccurrenceSnapshotV1,
    target: &OccurrenceSnapshotV1,
    artifact: &HumanDispositionV1,
    discharge: &ag_campaign::governed::ExactResidualDischargeV1,
) -> Result<(), CampaignStoreErrorV1> {
    if target.program_counter() != ProgramCounterV1::Halted
        || discharge.campaign != source.key().campaign
        || discharge.occurrence != source.key().occurrence
        || &discharge.program != source.state().meta().program()
        || discharge.disposition != artifact.decision
    {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    let unique = |values: &[ag_campaign::governed::ResidualIdV1]| {
        let set = values.iter().cloned().collect::<BTreeSet<_>>();
        (set.len() == values.len()).then_some(set)
    };
    let before = unique(&discharge.before).ok_or(CampaignStoreErrorV1::BindingMismatch)?;
    let authorized = unique(&discharge.authorized).ok_or(CampaignStoreErrorV1::BindingMismatch)?;
    let closed = unique(&discharge.closed).ok_or(CampaignStoreErrorV1::BindingMismatch)?;
    let after = unique(&discharge.after).ok_or(CampaignStoreErrorV1::BindingMismatch)?;
    let source_ids = source
        .state()
        .meta()
        .residuals()
        .as_slice()
        .iter()
        .map(|item| item.residual.clone())
        .collect::<BTreeSet<_>>();
    let target_ids = target
        .state()
        .meta()
        .residuals()
        .as_slice()
        .iter()
        .map(|item| item.residual.clone())
        .collect::<BTreeSet<_>>();
    if before != source_ids
        || authorized != closed
        || !closed.is_disjoint(&after)
        || before != closed.union(&after).cloned().collect()
        || after != target_ids
    {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    Ok(())
}

#[derive(Debug)]
struct StoredTransitionRow {
    source_occurrence: Option<String>,
    successor_occurrence: String,
    kind: CampaignTransitionKindV1,
    predecessor: Digest,
    successor: Digest,
    snapshot: OccurrenceSnapshotV1,
    snapshot_jcs: Vec<u8>,
    evidence: CampaignTransitionEvidenceV1,
    evidence_jcs: Vec<u8>,
    evidence_digest: Digest,
    previous_event: Digest,
    event: Digest,
    recorded_at_unix_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedSpendRow {
    authorization: String,
    campaign: String,
    occurrence: String,
    issuance: String,
    spend_jcs: Vec<u8>,
    issuance_jcs: Vec<u8>,
    transition: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedAttemptRow {
    issuance: String,
    campaign: String,
    occurrence: String,
    custody_jcs: Vec<u8>,
    transition: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedSettlementRow {
    attempt: String,
    receipt: String,
    campaign: String,
    occurrence: String,
    settlement_jcs: Vec<u8>,
    transition: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedHumanRow {
    nonce: String,
    campaign: String,
    occurrence: String,
    halted_state_digest: String,
    verification: String,
    artifact_jcs: Vec<u8>,
    consumed_at_unix_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedGovernedRepairRow {
    nonce: String,
    request: String,
    campaign: String,
    occurrence: String,
    halted_state_digest: String,
    disposition: String,
    verification_receipt: String,
    verification_record: String,
    verification_jcs: Vec<u8>,
    artifact_jcs: Vec<u8>,
    consumed_at_unix_ms: u64,
}

fn replay_store(connection: &Connection) -> Result<CampaignReplayReportV1, CampaignStoreErrorV1> {
    let product_records = verify_product_records(connection)?;
    let campaign_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM campaigns", [], |row| row.get(0))?;
    if campaign_count != 1 {
        return Err(CampaignStoreErrorV1::Corrupt(
            "store must contain exactly one campaign".to_owned(),
        ));
    }
    let (campaign_text, current_occurrence, current_digest_text, revision, event_count, head_text): (
        String,
        String,
        String,
        i64,
        i64,
        String,
    ) = connection.query_row(
        "SELECT campaign_id, current_occurrence_id, current_state_digest,
                revision, event_count, event_head_digest FROM campaigns",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    let campaign_digest = Digest::parse(&campaign_text)
        .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
    let campaign = CampaignId::from_digest(campaign_digest);
    let current_digest = Digest::parse(&current_digest_text)
        .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
    let head = Digest::parse(&head_text)
        .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;

    let mut statement = connection.prepare(
        "SELECT source_occurrence_id, successor_occurrence_id, transition_kind,
                predecessor_state_digest, successor_state_digest,
                successor_snapshot_jcs, evidence_jcs, evidence_digest,
                previous_event_digest, event_digest, recorded_at_unix_ms
         FROM transitions WHERE campaign_id=?1 ORDER BY sequence",
    )?;
    let rows = statement.query_map(params![campaign.as_str()], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, i64>(10)?,
        ))
    })?;
    let mut transitions = Vec::new();
    for row in rows {
        let raw = row?;
        let snapshot: OccurrenceSnapshotV1 = decode(&raw.5)?;
        let evidence: CampaignTransitionEvidenceV1 = decode(&raw.6)?;
        transitions.push(StoredTransitionRow {
            source_occurrence: raw.0,
            successor_occurrence: raw.1,
            kind: CampaignTransitionKindV1::parse(&raw.2)?,
            predecessor: parse_digest(&raw.3)?,
            successor: parse_digest(&raw.4)?,
            snapshot,
            snapshot_jcs: raw.5,
            evidence,
            evidence_jcs: raw.6,
            evidence_digest: parse_digest(&raw.7)?,
            previous_event: parse_digest(&raw.8)?,
            event: parse_digest(&raw.9)?,
            recorded_at_unix_ms: to_u64(raw.10)?,
        });
    }
    if transitions.is_empty() {
        return Err(CampaignStoreErrorV1::Corrupt(
            "transition journal is empty".to_owned(),
        ));
    }

    let mut previous_snapshot: Option<OccurrenceSnapshotV1> = None;
    let mut previous_event =
        Digest::hash_domain(EVENT_GENESIS_DOMAIN_V1, campaign.as_str().as_bytes());
    let mut latest_occurrences: BTreeMap<String, OccurrenceSnapshotV1> = BTreeMap::new();
    let mut spends = BTreeMap::new();
    let mut attempts = BTreeMap::new();
    let mut settlements = BTreeMap::new();
    let mut human_decisions = BTreeSet::new();
    let mut human_artifacts = BTreeMap::new();
    let mut governed_repair_artifacts = BTreeMap::new();

    for (index, row) in transitions.iter().enumerate() {
        row.snapshot.validate_integrity()?;
        if encode(&row.snapshot)? != row.snapshot_jcs || encode(&row.evidence)? != row.evidence_jcs
        {
            return Err(CampaignStoreErrorV1::Corrupt(format!(
                "transition {} canonical bytes do not round-trip exactly",
                index + 1
            )));
        }
        if row.snapshot.key().campaign != campaign
            || row.successor_occurrence != row.snapshot.key().occurrence.to_string()
            || row.predecessor != *row.snapshot.prior_state_digest()
            || row.successor != *row.snapshot.state_digest()
        {
            return Err(CampaignStoreErrorV1::Corrupt(format!(
                "transition {} snapshot binding failed",
                index + 1
            )));
        }
        let expected_evidence_digest = Digest::hash_domain(EVENT_DOMAIN_V1, &row.evidence_jcs);
        if row.evidence_digest != expected_evidence_digest || row.previous_event != previous_event {
            return Err(CampaignStoreErrorV1::Corrupt(format!(
                "transition {} evidence/event chain failed",
                index + 1
            )));
        }
        let expected_event = store_event_digest(
            &campaign,
            row.source_occurrence.as_deref(),
            &row.successor_occurrence,
            row.kind,
            &row.predecessor,
            &row.successor,
            &row.evidence_digest,
            &row.previous_event,
            row.recorded_at_unix_ms,
        );
        if row.event != expected_event {
            return Err(CampaignStoreErrorV1::Corrupt(format!(
                "transition {} event digest failed",
                index + 1
            )));
        }
        if index == 0 {
            if row.kind != CampaignTransitionKindV1::CampaignCreated
                || row.source_occurrence.is_some()
                || row.snapshot.program_counter() != ProgramCounterV1::ObservationRequired
                || row.snapshot.prior_occurrence().is_some()
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "invalid campaign genesis transition".to_owned(),
                ));
            }
            match &row.evidence {
                CampaignTransitionEvidenceV1::ProductGenesis {
                    product_creation,
                    verifier_root,
                } if (product_creation.clone(), verifier_root.clone()) == product_records => {}
                CampaignTransitionEvidenceV1::None if product_records == (None, None) => {}
                _ => {
                    return Err(CampaignStoreErrorV1::Corrupt(
                        "genesis product/verifier roots differ from materialized records"
                            .to_owned(),
                    ));
                }
            }
        } else {
            let prior = previous_snapshot.as_ref().ok_or_else(|| {
                CampaignStoreErrorV1::Corrupt("missing replay predecessor".to_owned())
            })?;
            if row.source_occurrence.as_deref() != Some(prior.key().occurrence.to_string().as_str())
            {
                return Err(CampaignStoreErrorV1::Corrupt(format!(
                    "transition {} source occurrence failed",
                    index + 1
                )));
            }
            GovernedLoopKernelV1::validate_successor(prior, &row.snapshot)?;
            validate_transition_kind(prior, &row.snapshot, row.kind)?;
            validate_replayed_evidence(
                prior,
                &row.snapshot,
                row.kind,
                &row.evidence,
                row.recorded_at_unix_ms,
            )?;
            for decision in row
                .snapshot
                .state()
                .meta()
                .used_human_decisions()
                .iter()
                .filter(|decision| {
                    !prior
                        .state()
                        .meta()
                        .used_human_decisions()
                        .contains(decision)
                })
            {
                if !human_decisions.insert(decision.as_str().to_owned()) {
                    return Err(CampaignStoreErrorV1::Corrupt(
                        "human decision appears twice in replay".to_owned(),
                    ));
                }
            }
        }
        if let Some(spend) = row.snapshot.ag_spend() {
            if let Some(issuance) = row.snapshot.issuance() {
                spends
                    .entry(spend.spend.as_str().to_owned())
                    .or_insert(ExpectedSpendRow {
                        authorization: spend.authorization.as_str().to_owned(),
                        campaign: spend.key.campaign.as_str().to_owned(),
                        occurrence: spend.key.occurrence.to_string(),
                        issuance: issuance.issuance.as_str().to_owned(),
                        spend_jcs: encode(spend)?,
                        issuance_jcs: encode(issuance)?,
                        transition: row.successor.as_str().to_owned(),
                    });
            } else {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "AG spend lacks exact issuance".to_owned(),
                ));
            }
        }
        if let Some(custody) = row.snapshot.docket_custody() {
            attempts
                .entry(custody.attempt.as_str().to_owned())
                .or_insert(ExpectedAttemptRow {
                    issuance: custody.issuance.as_str().to_owned(),
                    campaign: row.snapshot.key().campaign.as_str().to_owned(),
                    occurrence: row.snapshot.key().occurrence.to_string(),
                    custody_jcs: encode(custody)?,
                    transition: row.successor.as_str().to_owned(),
                });
        }
        if let Some(settlement) = row.snapshot.settlement() {
            settlements
                .entry(settlement.settlement.as_str().to_owned())
                .or_insert(ExpectedSettlementRow {
                    attempt: settlement.attempt.as_str().to_owned(),
                    receipt: settlement.receipt.as_str().to_owned(),
                    campaign: row.snapshot.key().campaign.as_str().to_owned(),
                    occurrence: row.snapshot.key().occurrence.to_string(),
                    settlement_jcs: encode(settlement)?,
                    transition: row.successor.as_str().to_owned(),
                });
        }
        if let CampaignTransitionEvidenceV1::HumanDisposition {
            artifact,
            verification,
        } = &row.evidence
        {
            let expected = ExpectedHumanRow {
                nonce: artifact.nonce.as_str().to_owned(),
                campaign: artifact.campaign.as_str().to_owned(),
                occurrence: artifact.occurrence.to_string(),
                halted_state_digest: artifact.halted_state_digest.as_str().to_owned(),
                verification: verification.as_str().to_owned(),
                artifact_jcs: encode(artifact)?,
                consumed_at_unix_ms: row.recorded_at_unix_ms,
            };
            if let Some(prior) =
                human_artifacts.insert(artifact.decision.as_str().to_owned(), expected)
                && prior != human_artifacts[artifact.decision.as_str()]
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "human disposition evidence changed across one transaction".to_owned(),
                ));
            }
        }
        if let CampaignTransitionEvidenceV1::GovernedRepairDisposition {
            request,
            artifact,
            verification,
        } = &row.evidence
        {
            if &request.reference() != artifact.request()
                || verification.request != request.reference()
                || verification.disposition != artifact.reference()
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "governed repair evidence binding mismatch".to_owned(),
                ));
            }
            let expected = ExpectedGovernedRepairRow {
                nonce: artifact.nonce.as_str().to_owned(),
                request: request.reference().as_str().to_owned(),
                campaign: artifact.campaign.as_str().to_owned(),
                occurrence: artifact.occurrence.to_string(),
                halted_state_digest: artifact.halted_state_digest.as_str().to_owned(),
                disposition: artifact.reference().as_str().to_owned(),
                verification_receipt: verification.verification.as_str().to_owned(),
                verification_record: verification.reference().as_str().to_owned(),
                verification_jcs: encode(verification)?,
                artifact_jcs: encode(artifact)?,
                consumed_at_unix_ms: row.recorded_at_unix_ms,
            };
            if let Some(prior) =
                governed_repair_artifacts.insert(artifact.decision.as_str().to_owned(), expected)
                && prior != governed_repair_artifacts[artifact.decision.as_str()]
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "governed repair evidence changed across atomic transition".to_owned(),
                ));
            }
        }
        if let CampaignTransitionEvidenceV1::DocketIssuanceRefusal { refusal } = &row.evidence
            && row
                .snapshot
                .halted()
                .and_then(|halted| halted.docket_issuance_refusal())
                != Some(refusal)
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "Docket issuance refusal evidence changed across replay".to_owned(),
            ));
        }
        latest_occurrences.insert(row.successor_occurrence.clone(), row.snapshot.clone());
        previous_event = row.event.clone();
        previous_snapshot = Some(row.snapshot.clone());
    }

    let final_snapshot = previous_snapshot
        .ok_or_else(|| CampaignStoreErrorV1::Corrupt("missing final replay snapshot".to_owned()))?;
    if final_snapshot.key().occurrence.to_string() != current_occurrence
        || final_snapshot.state_digest() != &current_digest
        || previous_event != head
        || to_u64(event_count)?
            != u64::try_from(transitions.len()).map_err(|_| {
                CampaignStoreErrorV1::Corrupt("transition count overflow".to_owned())
            })?
        || to_u64(revision)? != to_u64(event_count)?
    {
        return Err(CampaignStoreErrorV1::Corrupt(
            "campaign head does not equal replay result".to_owned(),
        ));
    }

    verify_occurrence_materialization(connection, &campaign, &latest_occurrences)?;
    verify_spend_accounting(connection, &spends)?;
    verify_attempt_accounting(connection, &attempts)?;
    verify_settlement_accounting(connection, &settlements)?;
    let accounted_human_decisions = human_artifacts
        .keys()
        .chain(governed_repair_artifacts.keys())
        .cloned()
        .collect();
    if human_decisions != accounted_human_decisions {
        return Err(CampaignStoreErrorV1::Corrupt(
            "human decision accounting differs from transition evidence".to_owned(),
        ));
    }
    verify_human_artifacts(connection, &human_artifacts)?;
    verify_governed_repair_artifacts(connection, &governed_repair_artifacts)?;
    verify_governed_repair_verification_namespace(connection, &governed_repair_artifacts)?;
    verify_issuance_signing_reservations(connection, &spends)?;
    verify_refusals(connection, &campaign, &transitions)?;
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(CampaignStoreErrorV1::Corrupt(format!(
            "SQLite quick_check: {quick_check}"
        )));
    }

    Ok(CampaignReplayReportV1 {
        campaign,
        transitions: u64::try_from(transitions.len())
            .map_err(|_| CampaignStoreErrorV1::Corrupt("transition count overflow".to_owned()))?,
        ag_spends: u64::try_from(spends.len())
            .map_err(|_| CampaignStoreErrorV1::Corrupt("spend count overflow".to_owned()))?,
        docket_attempts: u64::try_from(attempts.len())
            .map_err(|_| CampaignStoreErrorV1::Corrupt("attempt count overflow".to_owned()))?,
        settlements: u64::try_from(settlements.len())
            .map_err(|_| CampaignStoreErrorV1::Corrupt("settlement count overflow".to_owned()))?,
        human_dispositions: u64::try_from(human_decisions.len()).map_err(|_| {
            CampaignStoreErrorV1::Corrupt("human decision count overflow".to_owned())
        })?,
        human_decision_requests: table_count(connection, "human_decision_requests")?,
        governed_repair_dispositions: u64::try_from(governed_repair_artifacts.len()).map_err(
            |_| {
                CampaignStoreErrorV1::Corrupt(
                    "governed repair disposition count overflow".to_owned(),
                )
            },
        )?,
        current_state_digest: current_digest,
    })
}

fn verify_product_records(
    connection: &Connection,
) -> Result<(Option<Digest>, Option<Digest>), CampaignStoreErrorV1> {
    let mut identities = Vec::with_capacity(2);
    for (table, identity_column, bytes_column, domain) in [
        (
            "product_creation_request",
            "request_identity",
            "request_jcs",
            "ag.governed-loop.product-create/v1",
        ),
        (
            "governed_repair_verifier_root",
            "config_identity",
            "config_jcs",
            "ag.governed-loop.governed-repair-verifier-root/v1",
        ),
    ] {
        let query =
            format!("SELECT {identity_column},{bytes_column} FROM {table} WHERE singleton=1");
        let record: Option<(String, Vec<u8>)> = connection
            .query_row(&query, [], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        if let Some((identity, bytes)) = record {
            let identity = Digest::parse(&identity)
                .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
            if identity != Digest::hash_domain(domain, &bytes) {
                return Err(CampaignStoreErrorV1::Corrupt(format!(
                    "{table} identity mismatch"
                )));
            }
            identities.push(Some(identity));
        } else {
            identities.push(None);
        }
    }
    Ok((identities.remove(0), identities.remove(0)))
}

fn validate_replayed_evidence(
    source: &OccurrenceSnapshotV1,
    target: &OccurrenceSnapshotV1,
    kind: CampaignTransitionKindV1,
    evidence: &CampaignTransitionEvidenceV1,
    recorded_at_unix_ms: u64,
) -> Result<(), CampaignStoreErrorV1> {
    match (kind, evidence) {
        (
            CampaignTransitionKindV1::DocketGovernedRepairHalted,
            CampaignTransitionEvidenceV1::DocketGovernedRepairHalt { result },
        ) => {
            result.validate()?;
            let (outcome, requirement) = governed_repair_result_parts(result);
            let halted = target.halted().ok_or_else(|| {
                CampaignStoreErrorV1::Corrupt(
                    "Docket governed-repair evidence target is not halted".to_owned(),
                )
            })?;
            if halted.governed_repair_requirement() != Some(&requirement) {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "Docket governed-repair pinned requirement mismatch".to_owned(),
                ));
            }
            let reconstructed = GovernedLoopKernelV1::halt_from_docket_governed_repair(
                source,
                outcome,
                &requirement,
                halted.reason().clone(),
            )?;
            if reconstructed != *target {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "Docket governed-repair transition reconstruction mismatch".to_owned(),
                ));
            }
            Ok(())
        }
        (
            CampaignTransitionKindV1::DocketIssuanceRefused,
            CampaignTransitionEvidenceV1::DocketIssuanceRefusal { refusal },
        ) => {
            let issuance = source.issuance().ok_or_else(|| {
                CampaignStoreErrorV1::Corrupt(
                    "Docket refusal source lacks exact issuance".to_owned(),
                )
            })?;
            let spend = source
                .ag_spend()
                .ok_or(CampaignStoreErrorV1::BindingMismatch)?;
            refusal.validate_for_spend(issuance, spend)?;
            if recorded_at_unix_ms < refusal.refused_at_unix_ms {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "Docket issuance refusal predates its recorded transition".to_owned(),
                ));
            }
            let reconstructed =
                GovernedLoopKernelV1::halt_docket_issuance_refusal(source, refusal.clone())?;
            if reconstructed != *target {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "Docket issuance-refusal transition reconstruction mismatch".to_owned(),
                ));
            }
            Ok(())
        }
        (
            CampaignTransitionKindV1::HumanDisposition,
            CampaignTransitionEvidenceV1::HumanDisposition { artifact, .. },
        ) => {
            if artifact.campaign != source.key().campaign {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "human evidence campaign mismatch".to_owned(),
                ));
            }
            let is_second_open_transition = artifact.halted_state_digest
                == *source.prior_state_digest()
                && source.program_counter() == ProgramCounterV1::Halted
                && target.program_counter() == ProgramCounterV1::ObservationRequired;
            if artifact.halted_state_digest != *source.state_digest() && !is_second_open_transition
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "human evidence halted digest mismatch".to_owned(),
                ));
            }
            validate_human_transition_evidence(source, target, artifact)
        }
        (
            CampaignTransitionKindV1::HumanDisposition,
            CampaignTransitionEvidenceV1::GovernedRepairDisposition {
                request,
                artifact,
                verification,
            },
        ) => {
            if request.key.campaign != source.key().campaign
                || artifact.campaign != source.key().campaign
                || artifact.request() != &request.reference()
                || verification.request != request.reference()
                || verification.disposition != artifact.reference()
                || verification.verifier_profile != request.required_verifier_profile
                || verification.verifier_root != request.required_verifier_root
                || verification.verifier_executable != request.required_verifier_executable
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "governed repair transition evidence binding mismatch".to_owned(),
                ));
            }
            let original = request.halted_state_digest == *source.state_digest();
            let second_open = request.halted_state_digest == *source.prior_state_digest()
                && source.program_counter() == ProgramCounterV1::Halted
                && target.program_counter() == ProgramCounterV1::ObservationRequired;
            if !original && !second_open {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "governed repair halted digest mismatch".to_owned(),
                ));
            }
            Ok(())
        }
        (CampaignTransitionKindV1::HumanDisposition, _) => Err(CampaignStoreErrorV1::Corrupt(
            "human transition lacks exact disposition evidence".to_owned(),
        )),
        (CampaignTransitionKindV1::DocketGovernedRepairHalted, _) => {
            Err(CampaignStoreErrorV1::Corrupt(
                "Docket governed-repair halt lacks exact evidence".to_owned(),
            ))
        }
        (CampaignTransitionKindV1::DocketIssuanceRefused, _) => Err(CampaignStoreErrorV1::Corrupt(
            "Docket issuance refusal lacks exact evidence".to_owned(),
        )),
        (_, CampaignTransitionEvidenceV1::None) => Ok(()),
        (_, CampaignTransitionEvidenceV1::ProductGenesis { .. }) => {
            Err(CampaignStoreErrorV1::Corrupt(
                "non-genesis transition carries genesis root evidence".to_owned(),
            ))
        }
        (_, _) => Err(CampaignStoreErrorV1::Corrupt(
            "non-human transition carries human authority evidence".to_owned(),
        )),
    }
}

fn verify_occurrence_materialization(
    connection: &Connection,
    campaign: &CampaignId,
    expected: &BTreeMap<String, OccurrenceSnapshotV1>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT occurrence_id, program_basis, program_counter,
                prior_state_digest, state_digest, snapshot_jcs
         FROM occurrences WHERE campaign_id=?1 ORDER BY occurrence_id",
    )?;
    let rows = statement.query_map(params![campaign.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let (occurrence, program, pc, prior_digest, digest, bytes) = row?;
        let snapshot: OccurrenceSnapshotV1 = decode(&bytes)?;
        let expected_snapshot = expected
            .get(&occurrence)
            .ok_or_else(|| CampaignStoreErrorV1::Corrupt("unreplayed occurrence row".to_owned()))?;
        if &snapshot != expected_snapshot
            || program != snapshot.state().meta().program().as_str()
            || pc != pc_tag(snapshot.program_counter())
            || prior_digest != snapshot.prior_state_digest().as_str()
            || digest != snapshot.state_digest().as_str()
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "occurrence materialization differs from replay".to_owned(),
            ));
        }
        seen.insert(occurrence);
    }
    if seen != expected.keys().cloned().collect() {
        return Err(CampaignStoreErrorV1::Corrupt(
            "occurrence materialization is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn verify_spend_accounting(
    connection: &Connection,
    expected: &BTreeMap<String, ExpectedSpendRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT spend_id,authorization_id,campaign_id,occurrence_id,issuance_id,
                spend_jcs,issuance_jcs,transition_state_digest
         FROM ag_authorization_spends ORDER BY spend_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExpectedSpendRow {
                authorization: row.get(1)?,
                campaign: row.get(2)?,
                occurrence: row.get(3)?,
                issuance: row.get(4)?,
                spend_jcs: row.get(5)?,
                issuance_jcs: row.get(6)?,
                transition: row.get(7)?,
            },
        ))
    })?;
    let actual: BTreeMap<_, _> = rows.collect::<Result<_, _>>()?;
    if &actual != expected {
        return Err(CampaignStoreErrorV1::Corrupt(
            "AG spend accounting differs from replay".to_owned(),
        ));
    }
    Ok(())
}

fn verify_attempt_accounting(
    connection: &Connection,
    expected: &BTreeMap<String, ExpectedAttemptRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT attempt_id,issuance_id,campaign_id,occurrence_id,custody_jcs,
                transition_state_digest
         FROM docket_attempts ORDER BY attempt_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExpectedAttemptRow {
                issuance: row.get(1)?,
                campaign: row.get(2)?,
                occurrence: row.get(3)?,
                custody_jcs: row.get(4)?,
                transition: row.get(5)?,
            },
        ))
    })?;
    let actual: BTreeMap<_, _> = rows.collect::<Result<_, _>>()?;
    if &actual != expected {
        return Err(CampaignStoreErrorV1::Corrupt(
            "Docket attempt accounting differs from replay".to_owned(),
        ));
    }
    Ok(())
}

fn verify_settlement_accounting(
    connection: &Connection,
    expected: &BTreeMap<String, ExpectedSettlementRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT settlement_id,attempt_id,receipt_id,campaign_id,occurrence_id,
                settlement_jcs,transition_state_digest
         FROM docket_settlements ORDER BY settlement_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExpectedSettlementRow {
                attempt: row.get(1)?,
                receipt: row.get(2)?,
                campaign: row.get(3)?,
                occurrence: row.get(4)?,
                settlement_jcs: row.get(5)?,
                transition: row.get(6)?,
            },
        ))
    })?;
    let actual: BTreeMap<_, _> = rows.collect::<Result<_, _>>()?;
    if &actual != expected {
        return Err(CampaignStoreErrorV1::Corrupt(
            "Docket settlement accounting differs from replay".to_owned(),
        ));
    }
    Ok(())
}

fn verify_human_artifacts(
    connection: &Connection,
    expected: &BTreeMap<String, ExpectedHumanRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT decision_id,nonce,campaign_id,occurrence_id,halted_state_digest,
                verification_ref,artifact_jcs,consumed_at_unix_ms
         FROM human_dispositions ORDER BY decision_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExpectedHumanRow {
                nonce: row.get(1)?,
                campaign: row.get(2)?,
                occurrence: row.get(3)?,
                halted_state_digest: row.get(4)?,
                verification: row.get(5)?,
                artifact_jcs: row.get(6)?,
                consumed_at_unix_ms: to_u64(row.get(7)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?,
            },
        ))
    })?;
    let actual: BTreeMap<_, _> = rows.collect::<Result<_, _>>()?;
    if &actual != expected {
        return Err(CampaignStoreErrorV1::Corrupt(
            "human disposition materialization differs from replay".to_owned(),
        ));
    }
    verify_residual_discharge_accounting(connection, expected)?;
    Ok(())
}

fn verify_governed_repair_artifacts(
    connection: &Connection,
    expected: &BTreeMap<String, ExpectedGovernedRepairRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT decision_id,nonce,request_id,campaign_id,occurrence_id,
                halted_state_digest,disposition_id,verification_receipt_ref,
                verification_record_id,verification_jcs,artifact_jcs,
                consumed_at_unix_ms
         FROM governed_repair_dispositions ORDER BY decision_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExpectedGovernedRepairRow {
                nonce: row.get(1)?,
                request: row.get(2)?,
                campaign: row.get(3)?,
                occurrence: row.get(4)?,
                halted_state_digest: row.get(5)?,
                disposition: row.get(6)?,
                verification_receipt: row.get(7)?,
                verification_record: row.get(8)?,
                verification_jcs: row.get(9)?,
                artifact_jcs: row.get(10)?,
                consumed_at_unix_ms: to_u64(row.get(11)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        11,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?,
            },
        ))
    })?;
    let actual: BTreeMap<_, _> = rows.collect::<Result<_, _>>()?;
    if &actual != expected {
        return Err(CampaignStoreErrorV1::Corrupt(
            "governed repair disposition materialization differs from replay".to_owned(),
        ));
    }

    let mut statement = connection.prepare(
        "SELECT request_id,idempotency_key,campaign_id,occurrence_id,
                halted_state_digest,request_jcs,created_at_unix_ms,
                consumed_by_decision_id
         FROM human_decision_requests ORDER BY request_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let (identity, idempotency, campaign, occurrence, halted, bytes, created, consumed) = row?;
        let request: HumanDecisionRequestV1 = decode(&bytes)?;
        request.validate()?;
        if identity != request.reference().as_str()
            || idempotency != request.idempotency_key.as_str()
            || campaign != request.key.campaign.as_str()
            || occurrence != request.key.occurrence.to_string()
            || halted != request.halted_state_digest.as_str()
            || to_u64(created)? != request.created_at_unix_ms
            || !seen.insert(identity.clone())
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "human decision request materialization mismatch".to_owned(),
            ));
        }
        if let Some(decision) = consumed {
            let Some(disposition) = expected.get(&decision) else {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "request consumed without exact governed repair evidence".to_owned(),
                ));
            };
            if disposition.request != identity {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "request consumed by substituted disposition".to_owned(),
                ));
            }
        }
    }
    if expected
        .values()
        .any(|disposition| !seen.contains(&disposition.request))
    {
        return Err(CampaignStoreErrorV1::Corrupt(
            "governed repair disposition lacks durable request".to_owned(),
        ));
    }
    Ok(())
}

fn verify_governed_repair_verification_namespace(
    connection: &Connection,
    expected: &BTreeMap<String, ExpectedGovernedRepairRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut wanted = BTreeMap::new();
    for row in expected.values() {
        for (identity, class) in [
            (&row.verification_receipt, "receipt"),
            (&row.verification_record, "record"),
        ] {
            if wanted
                .insert(
                    identity.clone(),
                    (
                        class.to_owned(),
                        row.verification_record.clone(),
                        row.verification_jcs.clone(),
                    ),
                )
                .is_some()
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "verification receipt/record identity is reused".to_owned(),
                ));
            }
        }
    }
    let mut statement = connection.prepare(
        "SELECT identity,identity_class,verification_record_id,verification_jcs
         FROM governed_repair_verification_identities ORDER BY identity",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            (
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ),
        ))
    })?;
    let actual: BTreeMap<_, _> = rows.collect::<Result<_, _>>()?;
    if actual != wanted {
        return Err(CampaignStoreErrorV1::Corrupt(
            "verification identity namespace differs from replay".to_owned(),
        ));
    }
    Ok(())
}

fn verify_issuance_signing_reservations(
    connection: &Connection,
    spends: &BTreeMap<String, ExpectedSpendRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT issuance_id,spend_id,transition_state_digest,reservation_id,issuance_jcs
         FROM issuance_signing_reservations ORDER BY issuance_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    for row in rows {
        let (issuance, spend, transition, reservation, bytes) = row?;
        let Some(expected) = spends.get(&spend) else {
            return Err(CampaignStoreErrorV1::Corrupt(
                "issuance signing reservation lacks a replayed spend".to_owned(),
            ));
        };
        let expected_reservation = Digest::hash_domain(
            "ag.governed-loop.issuance-signing-reservation/v1",
            &expected.issuance_jcs,
        );
        if issuance != expected.issuance
            || transition != expected.transition
            || bytes != expected.issuance_jcs
            || reservation != expected_reservation.as_str()
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "issuance signing reservation differs from replayed spend".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_residual_discharge_accounting(
    connection: &Connection,
    humans: &BTreeMap<String, ExpectedHumanRow>,
) -> Result<(), CampaignStoreErrorV1> {
    let mut expected = BTreeMap::new();
    for (decision, human) in humans {
        let artifact: HumanDispositionV1 = decode(&human.artifact_jcs)?;
        if let HumanDispositionKindV1::ExactResidualDisposition(discharge) = artifact.disposition {
            expected.insert(
                decision.clone(),
                (
                    discharge.authority.as_str().to_owned(),
                    encode(&discharge.before)?,
                    encode(&discharge.closed)?,
                    encode(&discharge.after)?,
                ),
            );
        }
    }
    let mut statement = connection.prepare(
        "SELECT decision_id,authority_ref,before_jcs,closed_jcs,after_jcs
         FROM residual_discharges ORDER BY decision_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            (
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ),
        ))
    })?;
    let actual: BTreeMap<_, _> = rows.collect::<Result<_, _>>()?;
    if actual != expected {
        return Err(CampaignStoreErrorV1::Corrupt(
            "residual discharge accounting differs from replay".to_owned(),
        ));
    }
    Ok(())
}

fn verify_refusals(
    connection: &Connection,
    campaign: &CampaignId,
    transitions: &[StoredTransitionRow],
) -> Result<(), CampaignStoreErrorV1> {
    let valid_states: BTreeSet<_> = transitions
        .iter()
        .map(|transition| transition.successor.as_str().to_owned())
        .collect();
    let mut statement = connection.prepare(
        "SELECT refusal_id, campaign_id, occurrence_id, state_digest, refusal_jcs
         FROM refusals ORDER BY refusal_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    for row in rows {
        let (id, campaign_id, occurrence, state_digest, bytes) = row?;
        let refusal: RefusalOutcomeV1 = decode(&bytes)?;
        let expected_id = Digest::hash_domain(REFUSAL_DOMAIN_V1, &bytes);
        if id != expected_id.as_str()
            || campaign_id != campaign.as_str()
            || campaign_id != refusal.key.campaign.as_str()
            || occurrence != refusal.key.occurrence.to_string()
            || state_digest != refusal.at_state_digest.as_str()
            || !valid_states.contains(&state_digest)
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "refusal materialization mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

fn parse_digest(value: &str) -> Result<Digest, CampaignStoreErrorV1> {
    Digest::parse(value).map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))
}

fn product_artifact_identity<E: std::fmt::Display>(
    result: Result<Digest, E>,
) -> Result<Digest, CampaignStoreErrorV1> {
    result.map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))
}

fn decode_exact_artifact<T>(bytes: &[u8], label: &str) -> Result<T, CampaignStoreErrorV1>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let value: T = decode(bytes)?;
    if encode(&value)? != bytes {
        return Err(CampaignStoreErrorV1::Corrupt(format!(
            "{label} artifact does not round-trip as exact canonical bytes"
        )));
    }
    Ok(value)
}

fn validate_direct_artifact_bytes(
    kind: DirectArtifactKindV1,
    identity: &Digest,
    bytes: &[u8],
) -> Result<(), CampaignStoreErrorV1> {
    match kind {
        DirectArtifactKindV1::HumanDecisionRequest => {
            let value: HumanDecisionRequestV1 =
                decode_exact_artifact(bytes, "human decision request")?;
            value.validate()?;
            if value.reference().as_digest() != identity {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "human decision request artifact identity mismatch".to_owned(),
                ));
            }
        }
        DirectArtifactKindV1::GovernedRepairDisposition => {
            let value: GovernedRepairDispositionV1 =
                decode_exact_artifact(bytes, "governed repair disposition")?;
            if value.reference().as_digest() != identity {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "governed repair disposition artifact identity mismatch".to_owned(),
                ));
            }
        }
        DirectArtifactKindV1::AgSpend => {
            let value: AgAuthorizationSpendV1 = decode_exact_artifact(bytes, "AG spend")?;
            let authorization = AgAuthorizationRefV1::for_basis(
                &value.key,
                &value.observation,
                &value.proposal,
                &value.standing_resolution,
            );
            if value.authorization != authorization
                || value.spend != AgSpendRefV1::for_authorization(&authorization)
                || value.spend.as_digest() != identity
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "AG spend artifact identity mismatch".to_owned(),
                ));
            }
        }
        DirectArtifactKindV1::AgIssuance => {
            let value: AgIssuanceV2 = decode_exact_artifact(bytes, "AG issuance")?;
            value.effect_scope.validate()?;
            let mut body = serde_json::to_value(&value)
                .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))?;
            let fields = body.as_object_mut().ok_or_else(|| {
                CampaignStoreErrorV1::Corrupt("AG issuance is not an object".to_owned())
            })?;
            if fields.remove("schema").is_none() || fields.remove("issuance").is_none() {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "AG issuance identity basis is incomplete".to_owned(),
                ));
            }
            let body = JcsDocument::canonicalize(&body)
                .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))?;
            let expected = Digest::hash_domain(AG_ISSUANCE_SCHEMA_V2, body.as_bytes());
            if value.schema != AG_ISSUANCE_SCHEMA_V2
                || value.effect_scope_digest != value.effect_scope.digest()
                || value.issuance.as_digest() != &expected
                || value.issuance.as_digest() != identity
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "AG issuance artifact identity mismatch".to_owned(),
                ));
            }
        }
        DirectArtifactKindV1::DocketSettlement => {
            let value: DocketSettlementV1 = decode_exact_artifact(bytes, "Docket settlement")?;
            if value.schema != DOCKET_SETTLEMENT_SCHEMA_V1
                || (value.cumulative_effect_journal_identity.is_some()
                    && value
                        .expected_reference()
                        .map_err(CampaignStoreErrorV1::Kernel)?
                        != value.settlement)
                || value.settlement.as_digest() != identity
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "Docket settlement artifact identity mismatch".to_owned(),
                ));
            }
        }
        DirectArtifactKindV1::ProductCreation => {
            JcsDocument::from_canonical_bytes(bytes)
                .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))?;
            if Digest::hash_domain("ag.governed-loop.product-create/v1", bytes) != *identity {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "product creation artifact identity mismatch".to_owned(),
                ));
            }
        }
        DirectArtifactKindV1::GovernedRepairVerifierRoot => {
            let root: StoreVerifierRootWireV1 =
                decode_exact_artifact(bytes, "governed repair verifier root")?;
            if root.schema != GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1
                || root.verifier_label.is_empty()
                || !root.executable.is_absolute()
                || root.catalog.schema != GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1
                || root.catalog.profiles.is_empty()
                || root
                    .catalog
                    .profiles
                    .windows(2)
                    .any(|pair| pair[0].profile >= pair[1].profile)
                || Digest::hash_domain(GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1, bytes) != *identity
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "governed repair verifier-root artifact identity mismatch".to_owned(),
                ));
            }
        }
        DirectArtifactKindV1::Refusal => {
            let _: RefusalOutcomeV1 = decode_exact_artifact(bytes, "refusal")?;
            if Digest::hash_domain(REFUSAL_DOMAIN_V1, bytes) != *identity {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "refusal artifact identity mismatch".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn merge_exact_artifact_bytes(
    found: &mut Option<Vec<u8>>,
    candidate: Vec<u8>,
) -> Result<(), CampaignStoreErrorV1> {
    if let Some(existing) = found {
        if existing != &candidate {
            return Err(CampaignStoreErrorV1::Corrupt(
                "one artifact identity resolves to changed canonical bytes".to_owned(),
            ));
        }
    } else {
        *found = Some(candidate);
    }
    Ok(())
}

fn governed_repair_result_parts(
    result: &DocketSealedGovernedRepairResultV1,
) -> (
    &DocketGovernedRepairOutcomeRefV1,
    HumanDecisionRequirementV1,
) {
    match result {
        DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
            outcome,
            requirement,
        } => (
            outcome,
            HumanDecisionRequirementV1::ScopeExpansion(requirement.clone()),
        ),
        DocketSealedGovernedRepairResultV1::ReadjudicationRequired {
            outcome,
            requirement,
        } => (
            outcome,
            HumanDecisionRequirementV1::Readjudication(requirement.clone()),
        ),
    }
}

fn docket_checkpoint_artifact(
    outcome: &DocketGovernedRepairOutcomeRefV1,
) -> DocketCheckpointArtifactV1 {
    DocketCheckpointArtifactV1 {
        schema: DOCKET_CHECKPOINT_ARTIFACT_SCHEMA_V1.to_owned(),
        checkpoint: outcome.checkpoint.clone(),
        sealed_result: outcome.sealed_result.clone(),
        immutable_work_checkpoint: outcome.immutable_work_checkpoint.clone(),
    }
}

fn effect_journal_reference_artifact(
    outcome: &DocketGovernedRepairOutcomeRefV1,
) -> EffectJournalReferenceArtifactV1 {
    EffectJournalReferenceArtifactV1 {
        schema: EFFECT_JOURNAL_REFERENCE_ARTIFACT_SCHEMA_V1.to_owned(),
        effect_journal: outcome.effect_journal.clone(),
    }
}

fn effect_journal_reference_artifact_for_settlement(
    settlement: &DocketSettlementV1,
) -> EffectJournalReferenceArtifactV1 {
    EffectJournalReferenceArtifactV1 {
        schema: EFFECT_JOURNAL_REFERENCE_ARTIFACT_SCHEMA_V1.to_owned(),
        effect_journal: settlement
            .cumulative_effect_journal_identity
            .clone()
            .expect("R2 settlement journal checked before product projection"),
    }
}

fn successor_binding_artifact(
    snapshot: &OccurrenceSnapshotV1,
) -> Option<SuccessorBindingArtifactV1> {
    let prior = snapshot.prior_occurrence()?;
    let binding = prior.authorized_successor.clone()?;
    Some(SuccessorBindingArtifactV1 {
        schema: SUCCESSOR_BINDING_ARTIFACT_SCHEMA_V1.to_owned(),
        predecessor: prior.key.clone(),
        successor: snapshot.key().clone(),
        binding,
    })
}

fn successor_binding_identity(
    artifact: &SuccessorBindingArtifactV1,
) -> Result<Digest, CampaignStoreErrorV1> {
    artifact
        .identity()
        .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))
}

fn residual_state_artifact(snapshot: &OccurrenceSnapshotV1) -> ResidualStateArtifactV1 {
    ResidualStateArtifactV1 {
        schema: RESIDUAL_STATE_ARTIFACT_SCHEMA_V1.to_owned(),
        key: snapshot.key().clone(),
        state_digest: snapshot.state_digest().clone(),
        residuals: snapshot.state().meta().residuals().clone(),
    }
}

fn residual_state_identity(
    artifact: &ResidualStateArtifactV1,
) -> Result<Digest, CampaignStoreErrorV1> {
    artifact
        .identity()
        .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))
}

fn completion_observation_artifact(
    snapshot: &OccurrenceSnapshotV1,
) -> Option<CompletionObservationArtifactV1> {
    snapshot
        .terminal_observation()
        .map(|record| CompletionObservationArtifactV1 {
            schema: COMPLETION_OBSERVATION_ARTIFACT_SCHEMA_V1.to_owned(),
            state_digest: snapshot.state_digest().clone(),
            record: record.clone(),
        })
}

fn completion_observation_identity(
    artifact: &CompletionObservationArtifactV1,
) -> Result<Digest, CampaignStoreErrorV1> {
    artifact
        .identity()
        .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))
}

fn terminal_witness_artifact(snapshot: &OccurrenceSnapshotV1) -> Option<TerminalWitnessArtifactV1> {
    snapshot
        .terminal_witness()
        .map(|witness| TerminalWitnessArtifactV1 {
            schema: TERMINAL_WITNESS_ARTIFACT_SCHEMA_V1.to_owned(),
            key: snapshot.key().clone(),
            state_digest: snapshot.state_digest().clone(),
            witness: witness.clone(),
        })
}

fn terminal_witness_identity(
    artifact: &TerminalWitnessArtifactV1,
) -> Result<Digest, CampaignStoreErrorV1> {
    artifact
        .identity()
        .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))
}

fn open_human_decision_request_record_on(
    connection: &Connection,
    state: &Digest,
    now_unix_ms: u64,
) -> Result<Option<HumanDecisionRequestV1>, CampaignStoreErrorV1> {
    let mut statement = connection.prepare(
        "SELECT request_jcs FROM human_decision_requests
         WHERE halted_state_digest=?1 AND consumed_by_decision_id IS NULL
         ORDER BY created_at_unix_ms, request_id",
    )?;
    let rows = statement.query_map(params![state.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
    let mut open = None;
    for row in rows {
        let bytes = row?;
        let request: HumanDecisionRequestV1 = decode(&bytes)?;
        request.validate()?;
        if request.halted_state_digest != *state {
            return Err(CampaignStoreErrorV1::Corrupt(
                "human decision request state index mismatch".to_owned(),
            ));
        }
        if request.created_at_unix_ms <= now_unix_ms
            && now_unix_ms < request.expires_at_unix_ms
            && open.replace(request).is_some()
        {
            return Err(CampaignStoreErrorV1::Corrupt(
                "multiple open decision requests for one halted state".to_owned(),
            ));
        }
    }
    Ok(open)
}

fn store_file_identity(path: &Path) -> Result<StoreFileIdentityV1, CampaignStoreErrorV1> {
    let metadata = path.metadata()?;
    Ok(StoreFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn run_store_verifier<I>(
    program: File,
    input: &I,
) -> Result<GovernedRepairVerificationV1, CampaignStoreErrorV1>
where
    I: Serialize + ?Sized,
{
    let body = JcsDocument::canonicalize(input)
        .map_err(|error| CampaignStoreErrorV1::Canonical(error.to_string()))?;
    let descriptor: OwnedFd = program.into();
    let original_flags = rustix::io::fcntl_getfd(&descriptor).map_err(|error| {
        CampaignStoreErrorV1::GovernedRepairVerifier(format!(
            "read verifier descriptor flags: {error}"
        ))
    })?;
    let mut inherited_flags = original_flags;
    inherited_flags.remove(rustix::io::FdFlags::CLOEXEC);
    rustix::io::fcntl_setfd(&descriptor, inherited_flags).map_err(|error| {
        CampaignStoreErrorV1::GovernedRepairVerifier(format!(
            "prepare retained verifier descriptor: {error}"
        ))
    })?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
    let spawn_result = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    rustix::io::fcntl_setfd(&descriptor, original_flags).map_err(|error| {
        CampaignStoreErrorV1::GovernedRepairVerifier(format!(
            "restore verifier descriptor flags: {error}"
        ))
    })?;
    let mut child = spawn_result.map_err(|error| {
        CampaignStoreErrorV1::GovernedRepairVerifier(format!("spawn verifier: {error}"))
    })?;
    child
        .stdin
        .take()
        .ok_or_else(|| {
            CampaignStoreErrorV1::GovernedRepairVerifier(
                "verifier child stdin unavailable".to_owned(),
            )
        })?
        .write_all(body.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(CampaignStoreErrorV1::GovernedRepairVerifier(
            detail.chars().take(512).collect(),
        ));
    }
    JcsDocument::parse(&output.stdout)
        .and_then(|document| document.decode::<GovernedRepairVerificationV1>())
        .map_err(|error| CampaignStoreErrorV1::GovernedRepairVerifier(error.to_string()))
}

fn table_count(connection: &Connection, table: &str) -> Result<u64, CampaignStoreErrorV1> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection.query_row(&sql, [], |row| row.get(0))?;
    to_u64(count)
}
