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

//! Transactional authoritative store for canonical AG governed-loop state.
//!
//! One `SQLite` transaction advances the campaign pointer, occurrence snapshot,
//! transition chain, and all spend/attempt/settlement accounting.  External
//! effects never happen in this module.  A decoded snapshot is accepted only
//! when the pure governed-loop kernel proves it is a legal successor of the
//! exact compare-and-swap predecessor.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ag_campaign::CampaignId;
use ag_campaign::governed::{
    AgIssuanceRefV1, AgIssuanceV1, GovernedLoopKernelV1, HumanDispositionEffectV1,
    HumanDispositionKindV1, HumanDispositionV1, HumanVerificationRefV1, OccurrenceKeyV1,
    OccurrenceSnapshotV1, ProgramCounterV1, RefusalOutcomeV1,
};
use ag_primitives::{Digest, JcsDocument};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current governed-loop campaign-store schema version.
pub const CAMPAIGN_STORE_SCHEMA_VERSION: u32 = 1;
/// `SQLite` application identifier for this exact store family (`AGC1`).
pub const CAMPAIGN_STORE_APPLICATION_ID: u32 = 0x4147_4331;
/// Human-readable exact store schema identity.
pub const CAMPAIGN_STORE_SCHEMA_NAME: &str = "ag-governed-loop-campaign-store/v1";

const EVENT_DOMAIN_V1: &str = "ag.governed-loop.store-event/v1";
const EVENT_GENESIS_DOMAIN_V1: &str = "ag.governed-loop.store-event-genesis/v1";
const REFUSAL_DOMAIN_V1: &str = "ag.governed-loop.store-refusal/v1";

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
    fn as_str(self) -> &'static str {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CampaignTransitionEvidenceV1 {
    None,
    HumanDisposition {
        artifact: HumanDispositionV1,
        verification: HumanVerificationRefV1,
    },
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
}

/// One authoritative `SQLite` campaign store.
pub struct CampaignStoreV1 {
    path: PathBuf,
    connection: Connection,
}

impl CampaignStoreV1 {
    /// Creates a new store around one kernel-produced initial occurrence.
    pub fn create(
        path: &Path,
        initial: &OccurrenceSnapshotV1,
        recorded_at_unix_ms: u64,
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
        let evidence = CampaignTransitionEvidenceV1::None;
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
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_connection(&connection)?;
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

    /// Returns the sole campaign identity in this store.
    pub fn campaign_id(&self) -> Result<CampaignId, CampaignStoreErrorV1> {
        let text: String =
            self.connection
                .query_row("SELECT campaign_id FROM campaigns", [], |row| row.get(0))?;
        let digest = Digest::parse(&text)
            .map_err(|error| CampaignStoreErrorV1::Corrupt(error.to_string()))?;
        Ok(CampaignId::from_digest(digest))
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
        Ok(snapshot)
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

    /// Commits one non-human kernel successor with exact CAS semantics.
    pub fn commit(
        &mut self,
        expected: &OccurrenceSnapshotV1,
        successor: &OccurrenceSnapshotV1,
        kind: CampaignTransitionKindV1,
        recorded_at_unix_ms: u64,
    ) -> Result<CampaignCommitReceiptV1, CampaignStoreErrorV1> {
        if kind == CampaignTransitionKindV1::HumanDisposition
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

    /// Atomically consumes one exact human disposition and applies its closed effect.
    pub fn commit_human_disposition(
        &mut self,
        expected: &OccurrenceSnapshotV1,
        effect: &HumanDispositionEffectV1,
        artifact: &HumanDispositionV1,
        recorded_at_unix_ms: u64,
    ) -> Result<Vec<CampaignCommitReceiptV1>, CampaignStoreErrorV1> {
        let (verification, first, second) = match effect {
            HumanDispositionEffectV1::Updated {
                snapshot,
                verification,
            } => (verification, snapshot, None),
            HumanDispositionEffectV1::OpenedOccurrence {
                halted,
                successor,
                verification,
            } => (verification, halted, Some(successor)),
        };
        validate_human_store_binding(expected, first, second, artifact)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_human_disposition(&transaction, artifact, verification, recorded_at_unix_ms)?;
        let evidence = CampaignTransitionEvidenceV1::HumanDisposition {
            artifact: artifact.clone(),
            verification: verification.clone(),
        };
        let mut receipts = vec![write_transition(
            &transaction,
            expected,
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
        Ok(receipts)
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
    pub fn issuance(
        &self,
        issuance: &AgIssuanceRefV1,
    ) -> Result<Option<AgIssuanceV1>, CampaignStoreErrorV1> {
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
        replay_store(&self.connection)
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
        K::Halted | K::Escalated => target.program_counter() == P::Halted,
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

fn insert_human_disposition(
    transaction: &Transaction<'_>,
    artifact: &HumanDispositionV1,
    verification: &HumanVerificationRefV1,
    consumed_at_unix_ms: u64,
) -> Result<(), CampaignStoreErrorV1> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM human_dispositions WHERE decision_id=?1 OR nonce=?2
         )",
        params![artifact.decision.as_str(), artifact.nonce.as_str()],
        |row| row.get(0),
    )?;
    if exists {
        return Err(CampaignStoreErrorV1::HumanDispositionReplay);
    }
    transaction.execute(
        "INSERT INTO human_dispositions
         (decision_id, nonce, campaign_id, occurrence_id, halted_state_digest,
          verification_ref, artifact_jcs, consumed_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            artifact.decision.as_str(),
            artifact.nonce.as_str(),
            artifact.campaign.as_str(),
            artifact.occurrence.to_string(),
            artifact.halted_state_digest.as_str(),
            verification.as_str(),
            encode(artifact)?,
            to_i64(consumed_at_unix_ms)?,
        ],
    )?;
    if let HumanDispositionKindV1::ExactResidualDisposition(discharge) = &artifact.disposition {
        transaction.execute(
            "INSERT INTO residual_discharges
             (decision_id, authority_ref, before_jcs, closed_jcs, after_jcs)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                artifact.decision.as_str(),
                discharge.authority.as_str(),
                encode(&discharge.before)?,
                encode(&discharge.closed)?,
                encode(&discharge.after)?,
            ],
        )?;
    }
    Ok(())
}

fn validate_human_store_binding(
    expected: &OccurrenceSnapshotV1,
    first: &OccurrenceSnapshotV1,
    second: Option<&OccurrenceSnapshotV1>,
    artifact: &HumanDispositionV1,
) -> Result<(), CampaignStoreErrorV1> {
    GovernedLoopKernelV1::validate_successor(expected, first)?;
    if artifact.campaign != expected.key().campaign
        || artifact.occurrence != expected.key().occurrence
        || artifact.halted_state_digest != *expected.state_digest()
    {
        return Err(CampaignStoreErrorV1::BindingMismatch);
    }
    let before = expected.state().meta().used_human_decisions();
    let after = first.state().meta().used_human_decisions();
    if after.len() != before.len().saturating_add(1)
        || !after.starts_with(before)
        || after.last() != Some(&artifact.decision)
    {
        return Err(CampaignStoreErrorV1::HumanDispositionReplay);
    }
    validate_human_transition_evidence(expected, first, artifact)?;
    match (&artifact.disposition, second) {
        (
            HumanDispositionKindV1::ReturnToObservation | HumanDispositionKindV1::ReplaceProgram(_),
            Some(successor),
        ) => {
            if first.program_counter() != ProgramCounterV1::Halted
                || successor.program_counter() != ProgramCounterV1::ObservationRequired
            {
                return Err(CampaignStoreErrorV1::BindingMismatch);
            }
            GovernedLoopKernelV1::validate_successor(first, successor)?;
            validate_human_transition_evidence(first, successor, artifact)?;
        }
        (HumanDispositionKindV1::ExactResidualDisposition(_), None) => {
            if first.program_counter() != ProgramCounterV1::Halted {
                return Err(CampaignStoreErrorV1::BindingMismatch);
            }
        }
        (HumanDispositionKindV1::Terminate { .. }, None) => {
            if first.program_counter() != ProgramCounterV1::Completed {
                return Err(CampaignStoreErrorV1::BindingMismatch);
            }
        }
        _ => return Err(CampaignStoreErrorV1::BindingMismatch),
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
    evidence: CampaignTransitionEvidenceV1,
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

fn replay_store(connection: &Connection) -> Result<CampaignReplayReportV1, CampaignStoreErrorV1> {
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
        transitions.push(StoredTransitionRow {
            source_occurrence: raw.0,
            successor_occurrence: raw.1,
            kind: CampaignTransitionKindV1::parse(&raw.2)?,
            predecessor: parse_digest(&raw.3)?,
            successor: parse_digest(&raw.4)?,
            snapshot: decode(&raw.5)?,
            evidence: decode(&raw.6)?,
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

    for (index, row) in transitions.iter().enumerate() {
        row.snapshot.validate_integrity()?;
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
        let evidence_jcs = encode(&row.evidence)?;
        let expected_evidence_digest = Digest::hash_domain(EVENT_DOMAIN_V1, &evidence_jcs);
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
                || !matches!(row.evidence, CampaignTransitionEvidenceV1::None)
            {
                return Err(CampaignStoreErrorV1::Corrupt(
                    "invalid campaign genesis transition".to_owned(),
                ));
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
            validate_replayed_evidence(prior, &row.snapshot, row.kind, &row.evidence)?;
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
    if human_decisions != human_artifacts.keys().cloned().collect() {
        return Err(CampaignStoreErrorV1::Corrupt(
            "human decision accounting differs from transition evidence".to_owned(),
        ));
    }
    verify_human_artifacts(connection, &human_artifacts)?;
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
        current_state_digest: current_digest,
    })
}

fn validate_replayed_evidence(
    source: &OccurrenceSnapshotV1,
    target: &OccurrenceSnapshotV1,
    kind: CampaignTransitionKindV1,
    evidence: &CampaignTransitionEvidenceV1,
) -> Result<(), CampaignStoreErrorV1> {
    match (kind, evidence) {
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
        (CampaignTransitionKindV1::HumanDisposition, _) => Err(CampaignStoreErrorV1::Corrupt(
            "human transition lacks exact disposition evidence".to_owned(),
        )),
        (_, CampaignTransitionEvidenceV1::None) => Ok(()),
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

fn table_count(connection: &Connection, table: &str) -> Result<u64, CampaignStoreErrorV1> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection.query_row(&sql, [], |row| row.get(0))?;
    to_u64(count)
}
