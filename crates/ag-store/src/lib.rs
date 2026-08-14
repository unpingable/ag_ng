//! Fenced `SQLite` event storage, immutable blobs, and coherent backup cuts.
//!
//! A [`Store`] is deliberately a single-authoritative-writer object. Opening a
//! second writer for the same database fails before `SQLite` is touched. Every
//! state transition appends a domain-separated chained event and updates its
//! materialized state in the same `BEGIN IMMEDIATE` transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ag_primitives::{AuthorityDomainId, Digest, EpochId, JcsDocument};
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

mod offline_backup;

pub use offline_backup::{
    BackupPublicationBodyV1, BackupPublicationComponentV1, BackupPublicationV1,
    OfflineBackupCoordinatorV1, OfflineBackupParticipantV1, capture_publication_component,
    publish_backup_staging, restore_backup_evidence, verify_backup_publication,
    write_backup_publication,
};

/// Current database schema version.
pub const STORE_SCHEMA_VERSION: u32 = 2;

/// Canonical schema name stored in every database.
pub const STORE_SCHEMA_NAME: &str = "ag-store-event-v1";

/// All participants required for a coherent v1 system backup.
pub const REQUIRED_BACKUP_PARTICIPANTS: [BackupParticipantV1; 3] = [
    BackupParticipantV1::Agd,
    BackupParticipantV1::AgEffectd,
    BackupParticipantV1::AgProviderd,
];

const SCHEMA_SQL: &str = r"
CREATE TABLE store_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_id INTEGER NOT NULL,
    application_name TEXT NOT NULL,
    schema_name TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    schema_digest TEXT NOT NULL
) STRICT;

CREATE TABLE writer_fence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    writer_id TEXT NOT NULL,
    principal_digest TEXT NOT NULL,
    process_nonce TEXT NOT NULL,
    claimed_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE store_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    activation_jcs BLOB NOT NULL,
    activation_digest TEXT NOT NULL,
    activated_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE chain_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    digest TEXT NOT NULL
) STRICT;

CREATE TABLE events (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    event_id TEXT NOT NULL UNIQUE,
    entity_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    occurred_at_unix_ms INTEGER NOT NULL,
    previous_digest TEXT NOT NULL,
    payload_jcs BLOB NOT NULL,
    payload_digest TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE
) STRICT;

CREATE INDEX events_by_entity ON events(entity_id, sequence);

CREATE TABLE materialized_state (
    entity_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision > 0),
    state_jcs BLOB NOT NULL,
    state_digest TEXT NOT NULL,
    last_event_sequence INTEGER NOT NULL UNIQUE,
    last_event_digest TEXT NOT NULL,
    FOREIGN KEY(last_event_sequence) REFERENCES events(sequence)
) STRICT;

CREATE TABLE blobs (
    digest TEXT PRIMARY KEY,
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    installed_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE backup_cuts (
    cut_id TEXT PRIMARY KEY,
    authority_domain TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    quiescence_barrier_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('preparing', 'prepared', 'sealed', 'released', 'aborted')),
    begin_request_digest TEXT NOT NULL,
    begin_event_sequence INTEGER NOT NULL UNIQUE,
    begin_event_digest TEXT NOT NULL UNIQUE,
    manifest_digest TEXT,
    seal_event_sequence INTEGER UNIQUE,
    seal_event_digest TEXT UNIQUE,
    release_bundle_digest TEXT,
    release_event_sequence INTEGER UNIQUE,
    release_event_digest TEXT UNIQUE,
    abort_reason TEXT,
    abort_event_sequence INTEGER UNIQUE,
    abort_event_digest TEXT UNIQUE,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY(begin_event_sequence) REFERENCES events(sequence),
    FOREIGN KEY(seal_event_sequence) REFERENCES events(sequence),
    FOREIGN KEY(release_event_sequence) REFERENCES events(sequence),
    FOREIGN KEY(abort_event_sequence) REFERENCES events(sequence),
    CHECK (state NOT IN ('sealed', 'released') OR manifest_digest IS NOT NULL),
    CHECK (state NOT IN ('preparing', 'prepared') OR manifest_digest IS NULL),
    CHECK ((state = 'released') = (release_bundle_digest IS NOT NULL)),
    CHECK ((state = 'aborted') = (abort_reason IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX one_active_backup_cut
ON backup_cuts((1)) WHERE state IN ('preparing', 'prepared', 'sealed');

CREATE TABLE backup_participants (
    cut_id TEXT NOT NULL,
    participant TEXT NOT NULL CHECK (participant IN ('agd', 'ag-effectd', 'ag-providerd')),
    component_identity TEXT NOT NULL,
    checkpoint_jcs BLOB,
    checkpoint_digest TEXT,
    prepared_event_sequence INTEGER UNIQUE,
    prepared_event_digest TEXT UNIQUE,
    PRIMARY KEY(cut_id, participant),
    FOREIGN KEY(cut_id) REFERENCES backup_cuts(cut_id),
    FOREIGN KEY(prepared_event_sequence) REFERENCES events(sequence),
    CHECK ((checkpoint_jcs IS NULL) = (checkpoint_digest IS NULL)),
    CHECK ((checkpoint_jcs IS NULL) = (prepared_event_sequence IS NULL)),
    CHECK ((checkpoint_jcs IS NULL) = (prepared_event_digest IS NULL))
) STRICT;
";

/// A validated lower-case domain-separated SHA-256 digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StoreDigestV1(Digest);

impl StoreDigestV1 {
    /// Hash bytes with an unambiguous domain separator and length.
    #[must_use]
    pub fn hash(domain: &str, bytes: &[u8]) -> Self {
        Self(Digest::hash_domain(domain, bytes))
    }

    /// Return the exact wire/storage representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the workspace-wide digest value without rehashing it.
    #[must_use]
    pub fn as_digest(&self) -> &Digest {
        &self.0
    }

    /// Remove the store-specific semantic wrapper without changing bytes.
    #[must_use]
    pub fn into_digest(self) -> Digest {
        self.0
    }
}

impl From<Digest> for StoreDigestV1 {
    fn from(value: Digest) -> Self {
        Self(value)
    }
}

impl fmt::Display for StoreDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for StoreDigestV1 {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Digest::parse(value)
            .map(Self)
            .map_err(|_| StoreError::InvalidDigest(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for StoreDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Digest::deserialize(deserializer).map(Self)
    }
}

/// Exact application and schema identity expected by a store opener.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreIdentityV1 {
    /// `SQLite` application ID; must fit its signed 32-bit pragma representation.
    pub application_id: u32,
    /// Stable component-specific application name.
    pub application_name: String,
    /// Exact schema family name.
    pub schema_name: String,
    /// Exact schema version; no automatic migration occurs.
    pub schema_version: u32,
    /// Digest of the exact schema DDL.
    pub schema_digest: StoreDigestV1,
}

impl StoreIdentityV1 {
    /// Construct an identity for the schema compiled into this crate.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero/out-of-range application ID or malformed
    /// application name.
    pub fn current(
        application_id: u32,
        application_name: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let identity = Self {
            application_id,
            application_name: application_name.into(),
            schema_name: STORE_SCHEMA_NAME.to_owned(),
            schema_version: STORE_SCHEMA_VERSION,
            schema_digest: StoreDigestV1::hash("ag-store-schema-v2", SCHEMA_SQL.as_bytes()),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.application_id == 0 || self.application_id > i32::MAX as u32 {
            return Err(StoreError::InvalidIdentity(
                "application_id must be in 1..=i32::MAX".to_owned(),
            ));
        }
        validate_identifier("application_name", &self.application_name, 128)?;
        validate_identifier("schema_name", &self.schema_name, 128)?;
        if self.schema_version == 0 || self.schema_version > i32::MAX as u32 {
            return Err(StoreError::InvalidIdentity(
                "schema_version must be in 1..=i32::MAX".to_owned(),
            ));
        }
        let compiled_digest = StoreDigestV1::hash("ag-store-schema-v2", SCHEMA_SQL.as_bytes());
        if self.schema_name != STORE_SCHEMA_NAME
            || self.schema_version != STORE_SCHEMA_VERSION
            || self.schema_digest != compiled_digest
        {
            return Err(StoreError::InvalidIdentity(
                "schema identity does not match the schema compiled into ag-store".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Durable identity of the process claiming the writer fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterIdentityV1 {
    /// Stable writer instance ID.
    pub writer_id: String,
    /// Digest of the canonical daemon principal.
    pub principal_digest: Digest,
    /// Per-process start nonce, not a PID.
    pub process_nonce: String,
    /// Caller-observed claim time.
    pub claimed_at_unix_ms: i64,
}

impl WriterIdentityV1 {
    fn validate(&self) -> Result<(), StoreError> {
        validate_identifier("writer_id", &self.writer_id, 192)?;
        validate_identifier("process_nonce", &self.process_nonce, 192)
    }
}

/// Authority-bearing deployment identity enrolled on the first daemon open.
///
/// This identity is deliberately separate from [`WriterIdentityV1`]. Writers
/// are process-lifecycle claims and change on every restart; activation is the
/// durable authority context which must reproduce exactly on every restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreActivationIdentityV1 {
    /// Exact activation record schema.
    pub schema: String,
    /// Installation authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Active revocation epoch.
    pub epoch: EpochId,
    /// Digest of the exact descriptor-bound daemon configuration bytes.
    pub config_identity: Digest,
    /// Digest of the exact configured security-profile identifier.
    pub security_profile_identity: Digest,
    /// Exact component build identity selected by the daemon build.
    pub build_identity: Digest,
    /// Compiler-owned target catalog identity when the component has one.
    pub authority_catalog_identity: Option<Digest>,
}

impl StoreActivationIdentityV1 {
    /// Canonical schema identifier for an activation identity.
    pub const SCHEMA: &'static str = "ag-store-activation-identity-v1";

    fn validate(&self) -> Result<(), StoreError> {
        if self.schema != Self::SCHEMA {
            return Err(StoreError::InvalidActivationIdentity(
                "unsupported activation identity schema".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Immutable enrollment record recovered from a component store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreActivationRecordV1 {
    /// Exact enrolled authority/build/config identity.
    pub identity: StoreActivationIdentityV1,
    /// Domain-separated digest of the canonical identity bytes.
    pub activation_digest: StoreDigestV1,
    /// Caller-observed enrollment time from the first writer claim.
    pub activated_at_unix_ms: i64,
}

/// Exact filesystem custody required while preparing a daemon database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseFileCustodyV1 {
    /// Required numeric owner.
    pub uid: u32,
    /// Required numeric group.
    pub gid: u32,
    /// Required Unix permission and special-mode bits.
    pub mode: u32,
}

/// Opaque proof that one exact database inode was opened or exclusively created.
///
/// The retained descriptor and private inode snapshot prevent callers from
/// asserting that an arbitrary pathname was absent. Only [`prepare_database`]
/// can construct this token.
pub struct PreparedDatabaseV1 {
    path: PathBuf,
    file: File,
    created_new: bool,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Open or exclusively create a database inode under exact filesystem custody.
///
/// Existing metadata drift is never repaired. A newly created inode receives
/// the configured mode through the retained descriptor before it is measured.
/// If another creator wins the absence-to-create race, this call fails instead
/// of opening that creator's file.
///
/// # Errors
///
/// Returns an error for an unsafe path, a symlink or non-regular/multiply-linked
/// file, owner/group/mode mismatch, a creation race, or filesystem failure.
pub fn prepare_database(
    path: impl AsRef<Path>,
    custody: DatabaseFileCustodyV1,
) -> Result<PreparedDatabaseV1, StoreError> {
    if custody.mode & !0o7777 != 0 {
        return Err(StoreError::InvalidIdentity(
            "database custody mode contains unsupported bits".to_owned(),
        ));
    }
    prepare_database_internal(path.as_ref(), Some(custody))
}

impl PreparedDatabaseV1 {
    fn revalidate(&self) -> Result<(), StoreError> {
        let descriptor = self.file.metadata()?;
        let pathname = fs::symlink_metadata(&self.path)?;
        let metadata_matches = |metadata: &fs::Metadata| {
            metadata.file_type().is_file()
                && metadata.nlink() == 1
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.uid() == self.uid
                && metadata.gid() == self.gid
                && metadata.mode() & 0o7777 == self.mode
        };
        if !metadata_matches(&descriptor) || !metadata_matches(&pathname) {
            return Err(StoreError::PreparedDatabaseDrift(self.path.clone()));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| StoreError::InvalidIdentity("database path has no parent".to_owned()))?;
        if fs::canonicalize(parent)? != parent {
            return Err(StoreError::PreparedDatabaseDrift(self.path.clone()));
        }
        Ok(())
    }

    fn revalidate_uninitialized(&self) -> Result<(), StoreError> {
        self.revalidate()?;
        if self.created_new && self.file.metadata()?.len() != 0 {
            return Err(StoreError::PreparedDatabaseDrift(self.path.clone()));
        }
        Ok(())
    }
}

/// Current append-only event chain head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainHeadV1 {
    /// Last committed sequence; zero is the genesis head.
    pub sequence: u64,
    /// Digest of the last event or the identity-bound genesis digest.
    pub digest: StoreDigestV1,
}

/// Caller-provided event and state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewEventV1<T> {
    /// Globally unique, caller-generated event ID.
    pub event_id: String,
    /// Stable entity whose state is replaced.
    pub entity_id: String,
    /// Versioned semantic event kind.
    pub event_kind: String,
    /// Timestamp treated as evidence, not generated by the store.
    pub occurred_at_unix_ms: i64,
    /// Event-specific payload.
    pub payload: T,
}

/// Receipt for a chained event and its atomic materialized-state revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventReceiptV1 {
    /// Monotonic chain sequence.
    pub sequence: u64,
    /// Exact event ID.
    pub event_id: String,
    /// Digest of the predecessor head.
    pub previous_digest: StoreDigestV1,
    /// Digest of this event.
    pub event_digest: StoreDigestV1,
    /// Resulting entity-state revision.
    pub entity_revision: u64,
    /// Digest of the resulting canonical state.
    pub state_digest: StoreDigestV1,
}

/// A decoded materialized state and its binding receipt data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedStateV1<T> {
    /// Entity ID.
    pub entity_id: String,
    /// Monotonic entity-local revision.
    pub revision: u64,
    /// Decoded state value.
    pub state: T,
    /// Digest of canonical state bytes.
    pub state_digest: StoreDigestV1,
    /// Chain sequence of the transition that installed it.
    pub last_event_sequence: u64,
    /// Chain digest of the transition that installed it.
    pub last_event_digest: StoreDigestV1,
}

/// Immutable content-addressed blob descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobDescriptorV1 {
    /// Workspace-wide SHA-256 digest over the exact blob bytes.
    pub digest: Digest,
    /// Exact byte length.
    pub byte_length: u64,
}

/// Result of installing a blob without replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobInstallResult {
    /// New immutable bytes were atomically installed.
    Installed,
    /// Identical immutable bytes already existed and were verified.
    AlreadyPresent,
}

/// Required backup component.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupParticipantV1 {
    /// Governor judgment/control store.
    Agd,
    /// Privileged effect broker store.
    AgEffectd,
    /// Provider custody/accounting store.
    AgProviderd,
}

impl BackupParticipantV1 {
    /// Stable filesystem/wire spelling used by backup publications.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agd => "agd",
            Self::AgEffectd => "ag-effectd",
            Self::AgProviderd => "ag-providerd",
        }
    }
}

impl FromStr for BackupParticipantV1 {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agd" => Ok(Self::Agd),
            "ag-effectd" => Ok(Self::AgEffectd),
            "ag-providerd" => Ok(Self::AgProviderd),
            _ => Err(StoreError::Corrupt(format!(
                "unknown backup participant {value:?}"
            ))),
        }
    }
}

/// Registration fixed when a backup cut starts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupParticipantRegistrationV1 {
    /// Component role.
    pub participant: BackupParticipantV1,
    /// Exact daemon/component instance identity.
    pub component_identity: Digest,
}

/// Request that creates a distributed quiescence barrier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginBackupCutV1 {
    /// Globally unique cut ID.
    pub cut_id: String,
    /// Installation authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Active authority epoch.
    pub epoch: EpochId,
    /// Globally unique barrier ID.
    pub quiescence_barrier_id: String,
    /// Exactly one registration for each required participant.
    pub participants: Vec<BackupParticipantRegistrationV1>,
    /// Caller-observed start timestamp.
    pub created_at_unix_ms: i64,
}

impl BeginBackupCutV1 {
    fn validate(&self) -> Result<(), StoreError> {
        validate_identifier("cut_id", &self.cut_id, 192)?;
        validate_identifier("quiescence_barrier_id", &self.quiescence_barrier_id, 192)?;
        let roles: BTreeSet<_> = self
            .participants
            .iter()
            .map(|registration| registration.participant)
            .collect();
        let required: BTreeSet<_> = REQUIRED_BACKUP_PARTICIPANTS.into_iter().collect();
        if self.participants.len() != required.len() || roles != required {
            return Err(StoreError::InvalidBackupParticipants);
        }
        let component_identities: BTreeSet<_> = self
            .participants
            .iter()
            .map(|registration| &registration.component_identity)
            .collect();
        if component_identities.len() != required.len() {
            return Err(StoreError::InvalidBackupParticipants);
        }
        Ok(())
    }
}

/// A participant's immutable prepared boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCheckpointV1 {
    /// Component role.
    pub participant: BackupParticipantV1,
    /// Must match the registration made at cut start.
    pub component_identity: Digest,
    /// Prepared event-chain head.
    pub chain_head: ChainHeadV1,
    /// Root of the component's exact blob catalog.
    pub blob_root: StoreDigestV1,
    /// Exact active configuration identity.
    pub config_identity: Digest,
    /// Exact database/schema identity.
    pub schema_identity: Digest,
    /// Exact security-profile identity.
    pub profile_identity: Digest,
    /// Exact component build identity.
    pub build_identity: Digest,
    /// Explicit offline quiescence attestation for this participant and barrier.
    pub quiescence_attestation: QuiescenceBarrierAttestationV1,
}

/// The only quiescence mechanism implemented by the v1 coordinator.
///
/// A live daemon handshake is intentionally absent. Holding a stopped-service
/// writer fence and recording this declaration must not be presented as proof
/// of a live distributed protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceBoundaryV1 {
    /// All three daemon units are stopped and the coordinator owns every
    /// component store's exclusive writer fence.
    OfflineServicesStopped,
}

/// Exact operator/service attestation of one component's cross-daemon boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuiescenceBarrierAttestationV1 {
    /// Exact attestation schema.
    pub schema: String,
    /// Cut receiving this attestation.
    pub cut_id: String,
    /// Installation authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Active authority epoch.
    pub epoch: EpochId,
    /// Shared barrier identity.
    pub quiescence_barrier_id: String,
    /// Component whose durable boundary was inspected.
    pub participant: BackupParticipantV1,
    /// Implemented boundary mechanism.
    pub boundary: QuiescenceBoundaryV1,
    /// Digest of the exact terminal/indeterminate/reconciliation inventory.
    pub boundary_summary: Digest,
    /// Canonical principal that made the offline declaration.
    pub attesting_principal: Digest,
    /// Attestation timestamp treated as evidence.
    pub attested_at_unix_ms: i64,
}

impl QuiescenceBarrierAttestationV1 {
    fn validate_for(
        &self,
        cut_id: &str,
        authority_domain: &AuthorityDomainId,
        epoch: EpochId,
        barrier_id: &str,
        participant: BackupParticipantV1,
    ) -> Result<(), StoreError> {
        if self.schema != "ag-store-offline-quiescence-attestation-v1"
            || self.cut_id != cut_id
            || &self.authority_domain != authority_domain
            || self.epoch != epoch
            || self.quiescence_barrier_id != barrier_id
            || self.participant != participant
            || self.boundary != QuiescenceBoundaryV1::OfflineServicesStopped
        {
            return Err(StoreError::InvalidQuiescenceAttestation(participant));
        }
        Ok(())
    }
}

/// Prepared checkpoint plus its locally committed event receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedParticipantV1 {
    /// Exact prepared component checkpoint.
    pub checkpoint: BackupCheckpointV1,
    /// Chain sequence of the preparation event in the coordinator store.
    pub prepared_event_sequence: u64,
    /// Digest of that preparation event.
    pub prepared_event_digest: StoreDigestV1,
}

/// Canonical coherent cut, built only after every participant prepares.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCutManifestV1 {
    /// Schema marker.
    pub version: String,
    /// Exact cut ID.
    pub cut_id: String,
    /// Installation authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Authority epoch.
    pub epoch: EpochId,
    /// Shared quiescence barrier ID.
    pub quiescence_barrier_id: String,
    /// All three prepared participants, sorted by role.
    pub participants: Vec<PreparedParticipantV1>,
}

/// Concise protocol spelling for the exact coherent backup manifest.
pub type BackupCutV1 = BackupCutManifestV1;

/// Durable backup-cut state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCutStateV1 {
    /// Waiting for one or more participant checkpoints.
    Preparing,
    /// Every participant prepared; ordinary mutation remains blocked.
    Prepared,
    /// Exact manifest sealed; mutation remains fenced during physical capture.
    Sealed,
    /// Verified backup bundle published; mutation may resume.
    Released,
    /// Barrier durably abandoned; mutation may resume.
    Aborted,
}

impl BackupCutStateV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Prepared => "prepared",
            Self::Sealed => "sealed",
            Self::Released => "released",
            Self::Aborted => "aborted",
        }
    }
}

impl FromStr for BackupCutStateV1 {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "preparing" => Ok(Self::Preparing),
            "prepared" => Ok(Self::Prepared),
            "sealed" => Ok(Self::Sealed),
            "released" => Ok(Self::Released),
            "aborted" => Ok(Self::Aborted),
            _ => Err(StoreError::Corrupt(format!(
                "unknown backup state {value:?}"
            ))),
        }
    }
}

/// Public summary of a durable backup cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCutRecordV1 {
    /// Cut ID.
    pub cut_id: String,
    /// Current lifecycle state.
    pub state: BackupCutStateV1,
    /// Number of participants durably prepared.
    pub prepared_participants: u8,
    /// Manifest digest after sealing.
    pub manifest_digest: Option<StoreDigestV1>,
    /// Exact published bundle digest after release.
    pub release_bundle_digest: Option<Digest>,
    /// Stable abort reason after aborting.
    pub abort_reason: Option<String>,
}

/// Exact physical database snapshot produced while a coherent cut remains
/// sealed. The database descriptor covers the standalone `SQLite` file emitted
/// by `SQLite`'s online-backup API; a live WAL file is never part of it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedDatabaseCaptureV1 {
    /// Exact capture-record schema.
    pub schema: String,
    /// Coherent cut whose fence remained active for this capture.
    pub cut_id: String,
    /// Component represented by this database.
    pub participant: BackupParticipantV1,
    /// Component identity registered when the cut began.
    pub component_identity: Digest,
    /// Exact sealed three-store manifest identity.
    pub manifest_digest: StoreDigestV1,
    /// Locally sealed manifest. Its participant checkpoints must agree across
    /// every component capture even though local preparation event receipts
    /// necessarily belong to different event chains.
    pub cut_manifest: BackupCutManifestV1,
    /// Store/application/schema identity embedded in the database.
    pub store_identity: StoreIdentityV1,
    /// Event head present in the snapshot, including local cut events.
    pub captured_chain_head: ChainHeadV1,
    /// Verified immutable-object catalog root paired with this database.
    pub blob_root: StoreDigestV1,
    /// Exact standalone `SQLite` file bytes.
    pub database: BlobDescriptorV1,
}

/// Exact three-component backup bundle body. Construction rejects any set of
/// individually valid captures that never represented one joint system cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoherentBackupBundleBodyV1 {
    /// Exact bundle schema.
    pub schema: String,
    /// Shared cut identity.
    pub cut_id: String,
    /// Shared authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Shared authority epoch.
    pub epoch: EpochId,
    /// Shared cross-daemon quiescence barrier.
    pub quiescence_barrier_id: String,
    /// Exactly one sealed physical capture per required component, sorted by role.
    pub components: Vec<SealedDatabaseCaptureV1>,
}

/// Digest-bound publication manifest for exactly one coherent three-store
/// database/object cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoherentBackupBundleV1 {
    digest: Digest,
    body: CoherentBackupBundleBodyV1,
}

impl CoherentBackupBundleV1 {
    /// Validates and binds exactly three still-sealed component captures.
    ///
    /// # Errors
    ///
    /// Returns an error unless roles, cut/domain/epoch/barrier, component
    /// registrations, blob roots, database descriptors, and all three
    /// participant checkpoint bodies agree exactly.
    pub fn new(mut components: Vec<SealedDatabaseCaptureV1>) -> Result<Self, StoreError> {
        validate_coherent_captures(&components)?;
        components.sort_by_key(|capture| capture.participant);
        let first = components
            .first()
            .ok_or(StoreError::IncoherentBackupBundle)?;
        let body = CoherentBackupBundleBodyV1 {
            schema: "ag-store-coherent-backup-bundle-v1".to_owned(),
            cut_id: first.cut_manifest.cut_id.clone(),
            authority_domain: first.cut_manifest.authority_domain.clone(),
            epoch: first.cut_manifest.epoch,
            quiescence_barrier_id: first.cut_manifest.quiescence_barrier_id.clone(),
            components,
        };
        let digest = digest_jcs("ag-store-coherent-backup-bundle-v1", &body)?.into_digest();
        Ok(Self { digest, body })
    }

    /// Returns the exact bundle identity supplied to every cut-release call.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the exact sorted publication body.
    #[must_use]
    pub const fn body(&self) -> &CoherentBackupBundleBodyV1 {
        &self.body
    }

    /// Revalidates all cross-capture bindings and the publication digest.
    ///
    /// # Errors
    ///
    /// Returns an error if any decoded field, component set, checkpoint, or
    /// digest differs from the originally constructed bundle.
    pub fn verify(&self) -> Result<(), StoreError> {
        validate_coherent_captures(&self.body.components)?;
        if self.body.schema != "ag-store-coherent-backup-bundle-v1"
            || self
                .body
                .components
                .iter()
                .map(|capture| capture.participant)
                .ne(REQUIRED_BACKUP_PARTICIPANTS)
            || self.body.components.first().is_none_or(|first| {
                self.body.cut_id != first.cut_manifest.cut_id
                    || self.body.authority_domain != first.cut_manifest.authority_domain
                    || self.body.epoch != first.cut_manifest.epoch
                    || self.body.quiescence_barrier_id != first.cut_manifest.quiescence_barrier_id
            })
            || digest_jcs("ag-store-coherent-backup-bundle-v1", &self.body)?.as_digest()
                != &self.digest
        {
            return Err(StoreError::IncoherentBackupBundle);
        }
        Ok(())
    }
}

/// Errors returned by the durable store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Underlying filesystem operation failed.
    #[error("store I/O failed: {0}")]
    Io(#[from] io::Error),
    /// `SQLite` operation failed.
    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Another authoritative writer currently owns the sidecar fence.
    #[error("another authoritative writer owns {0}")]
    WriterFenced(PathBuf),
    /// Persisted and expected application/schema identities differ.
    #[error("store identity mismatch: expected {expected:?}, found {actual:?}")]
    IdentityMismatch {
        /// Identity supplied by this binary.
        expected: Box<StoreIdentityV1>,
        /// Identity persisted in the database.
        actual: Box<StoreIdentityV1>,
    },
    /// No activation was enrolled before an existing store was presented to a daemon.
    #[error(
        "existing store has no durable activation identity; explicit offline enrollment is required"
    )]
    ActivationIdentityMissing,
    /// A generic opener attempted to bypass an already enrolled activation.
    #[error("store has a durable activation identity; an exact activated open is required")]
    ActivationIdentityRequired,
    /// The durable authority/config/profile/build activation differs from startup.
    #[error("store activation identity mismatch: expected {expected:?}, found {actual:?}")]
    ActivationIdentityMismatch {
        /// Identity supplied by this daemon startup.
        expected: Box<StoreActivationIdentityV1>,
        /// Identity durably enrolled on the first activated open.
        actual: Box<StoreActivationIdentityV1>,
    },
    /// An activation identity is malformed or uses an unsupported schema.
    #[error("invalid store activation identity: {0}")]
    InvalidActivationIdentity(String),
    /// An existing file was not already an AG store and may not be initialized online.
    #[error("existing database is not an initialized AG store: {0}")]
    UnrecognizedExistingDatabase(PathBuf),
    /// The database pathname or retained descriptor no longer names the prepared inode.
    #[error("prepared database inode or custody changed before SQLite open: {0}")]
    PreparedDatabaseDrift(PathBuf),
    /// A database inode does not satisfy the exact requested filesystem custody.
    #[error("database filesystem custody mismatch: {0}")]
    DatabaseCustodyMismatch(PathBuf),
    /// Application/schema identity is malformed.
    #[error("invalid store identity: {0}")]
    InvalidIdentity(String),
    /// A stable identifier is malformed.
    #[error("invalid {field}: {reason}")]
    InvalidIdentifier {
        /// Field name.
        field: &'static str,
        /// Validation failure.
        reason: String,
    },
    /// Digest text is malformed.
    #[error("invalid digest {0:?}")]
    InvalidDigest(String),
    /// JCS serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    Canonicalization(String),
    /// Stored JSON could not be decoded.
    #[error("stored JSON is invalid: {0}")]
    InvalidStoredJson(String),
    /// Caller expected a different entity revision.
    #[error("entity revision conflict for {entity_id}: expected {expected}, actual {actual}")]
    RevisionConflict {
        /// Entity ID.
        entity_id: String,
        /// Caller expected revision.
        expected: u64,
        /// Durable revision.
        actual: u64,
    },
    /// Event ID already exists.
    #[error("event ID {0:?} already exists")]
    DuplicateEvent(String),
    /// A prepared backup barrier rejects ordinary mutation.
    #[error("backup cut {0:?} currently blocks ordinary mutation")]
    BackupBarrierActive(String),
    /// Backup registrations are not exactly agd/effectd/providerd.
    #[error("backup cut must register exactly agd, ag-effectd, and ag-providerd")]
    InvalidBackupParticipants,
    /// Backup cut does not exist.
    #[error("backup cut {0:?} does not exist")]
    BackupCutNotFound(String),
    /// Another backup barrier is already active.
    #[error("another backup cut is already active")]
    BackupCutAlreadyActive,
    /// Reuse of an ID did not reproduce the original request.
    #[error("backup cut ID {0:?} was reused with different content")]
    BackupCutConflict(String),
    /// Requested lifecycle action is invalid in the current state.
    #[error("cannot {action} backup cut while state is {state:?}")]
    InvalidBackupTransition {
        /// Attempted action.
        action: &'static str,
        /// Durable state.
        state: BackupCutStateV1,
    },
    /// Participant was not registered or presented a different component identity.
    #[error("backup participant registration mismatch for {0:?}")]
    BackupParticipantMismatch(BackupParticipantV1),
    /// A checkpoint did not carry the exact supported offline barrier attestation.
    #[error("invalid offline quiescence attestation for {0:?}")]
    InvalidQuiescenceAttestation(BackupParticipantV1),
    /// An offline plan's schema identity does not match the opened component store.
    #[error("backup schema identity mismatch for {0:?}")]
    BackupSchemaIdentityMismatch(BackupParticipantV1),
    /// A retry supplied different checkpoint bytes.
    #[error("backup participant {0:?} was already prepared differently")]
    BackupCheckpointConflict(BackupParticipantV1),
    /// Not every required participant has prepared.
    #[error("backup cut is not fully prepared")]
    BackupNotPrepared,
    /// Supplied manifest is not the exact manifest constructed from durable facts.
    #[error("backup manifest does not match durable prepared checkpoints")]
    BackupManifestMismatch,
    /// Physical capture was attempted outside the still-fenced sealed state.
    #[error("backup cut {0:?} must remain sealed during physical capture")]
    BackupCaptureRequiresSealed(String),
    /// Capture outputs are immutable and never replace an existing path.
    #[error("backup capture destination already exists: {0}")]
    BackupCaptureDestinationExists(PathBuf),
    /// Three physical captures do not represent one exact joint system cut.
    #[error("backup component captures do not form one coherent three-store bundle")]
    IncoherentBackupBundle,
    /// Database/object publication bytes do not represent one coherent cut.
    #[error("backup publication is not one coherent immutable three-store cut")]
    IncoherentBackupPublication,
    /// Immutable publications and restore evidence never replace an existing path.
    #[error("backup publication destination already exists: {0}")]
    BackupPublicationDestinationExists(PathBuf),
    /// Blob bytes or size do not match their descriptor.
    #[error("blob mismatch: expected {expected:?}, observed {actual:?}")]
    BlobMismatch {
        /// Expected descriptor.
        expected: BlobDescriptorV1,
        /// Observed descriptor.
        actual: BlobDescriptorV1,
    },
    /// A caller-selected custody read bound is smaller than the exact blob.
    #[error("blob {digest} has {actual} bytes, exceeding read bound {maximum}")]
    BlobReadLimitExceeded {
        /// Exact blob identity.
        digest: Digest,
        /// Catalogued byte length.
        actual: u64,
        /// Caller bound.
        maximum: u64,
    },
    /// Persisted chain, state, or catalog is inconsistent.
    #[error("store corruption detected: {0}")]
    Corrupt(String),
}

/// Single-authoritative-writer database and immutable blob store.
pub struct Store {
    connection: Connection,
    identity: StoreIdentityV1,
    activation: Option<StoreActivationRecordV1>,
    database_path: PathBuf,
    blob_root: PathBuf,
    _writer_lock: Flock<File>,
}

impl Store {
    /// Open or initialize a fenced store.
    ///
    /// This does not migrate a database. Any application/schema identity drift
    /// is an error requiring an explicit offline upgrade path.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths, a live writer fence, identity drift,
    /// unavailable WAL/full-sync behavior, or filesystem/SQLite failure.
    pub fn open(
        database_path: impl AsRef<Path>,
        blob_root: impl AsRef<Path>,
        identity: StoreIdentityV1,
        writer: &WriterIdentityV1,
    ) -> Result<Self, StoreError> {
        identity.validate()?;
        writer.validate()?;
        let prepared_database = prepare_database_internal(database_path.as_ref(), None)?;
        Self::open_prepared_internal(prepared_database, blob_root, identity, None, writer)
    }

    /// Open or initialize a daemon store with a fail-closed activation identity.
    ///
    /// A new database enrolls `activation` atomically with its schema and
    /// genesis head. An existing database must already contain the same exact
    /// identity. Missing or drifted activation is never repaired or replaced
    /// by this online path.
    ///
    /// # Errors
    ///
    /// Returns an error for every [`Self::open`] failure, a missing durable
    /// activation on an existing database, malformed activation evidence, or
    /// any authority/config/profile/build/catalog drift.
    pub fn open_activated(
        database_path: impl AsRef<Path>,
        blob_root: impl AsRef<Path>,
        identity: StoreIdentityV1,
        activation: &StoreActivationIdentityV1,
        writer: &WriterIdentityV1,
    ) -> Result<Self, StoreError> {
        identity.validate()?;
        activation.validate()?;
        writer.validate()?;
        let prepared_database = prepare_database_internal(database_path.as_ref(), None)?;
        Self::open_prepared_internal(
            prepared_database,
            blob_root,
            identity,
            Some(activation),
            writer,
        )
    }

    /// Open a daemon store using an opaque descriptor-bound database token.
    ///
    /// Schema and activation enrollment is permitted only when the consumed
    /// token proves that its preparation call exclusively created this exact
    /// inode. An existing empty, unrelated, or unactivated database fails
    /// closed without online initialization.
    ///
    /// # Errors
    ///
    /// Returns an error for every [`Self::open_activated`] failure or when the
    /// prepared path, inode, owner, group, mode, type, or link count drifted.
    pub fn open_activated_prepared(
        prepared_database: PreparedDatabaseV1,
        blob_root: impl AsRef<Path>,
        identity: StoreIdentityV1,
        activation: &StoreActivationIdentityV1,
        writer: &WriterIdentityV1,
    ) -> Result<Self, StoreError> {
        identity.validate()?;
        activation.validate()?;
        writer.validate()?;
        Self::open_prepared_internal(
            prepared_database,
            blob_root,
            identity,
            Some(activation),
            writer,
        )
    }

    fn open_prepared_internal(
        prepared_database: PreparedDatabaseV1,
        blob_root: impl AsRef<Path>,
        identity: StoreIdentityV1,
        activation: Option<&StoreActivationIdentityV1>,
        writer: &WriterIdentityV1,
    ) -> Result<Self, StoreError> {
        prepared_database.revalidate_uninitialized()?;
        let database_path = prepared_database.path.clone();
        let blob_root = absolute_normalized_path(blob_root.as_ref())?;
        create_and_validate_directory(&blob_root)?;

        let lock_path = writer_lock_path(&database_path)?;
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)?;
        let writer_lock = match Flock::lock(writer_lock, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((_file, Errno::EAGAIN)) => return Err(StoreError::WriterFenced(lock_path)),
            Err((_file, error)) => {
                return Err(StoreError::Io(io::Error::from_raw_os_error(error as i32)));
            }
        };

        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        prepared_database.revalidate_uninitialized()?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        let expected_activation =
            activation.map(|activation| (activation, writer.claimed_at_unix_ms));
        let activation = if prepared_database.created_new {
            configure_mutating_connection_pragmas(&connection)?;
            initialize_or_validate(&mut connection, &identity, expected_activation, true)?
        } else {
            let activation =
                initialize_or_validate(&mut connection, &identity, expected_activation, false)?;
            configure_mutating_connection_pragmas(&connection)?;
            activation
        };
        prepared_database.revalidate()?;
        claim_writer(&mut connection, writer)?;
        drop(prepared_database);

        Ok(Self {
            connection,
            identity,
            activation,
            database_path,
            blob_root,
            _writer_lock: writer_lock,
        })
    }

    /// Exact persisted application/schema identity.
    #[must_use]
    pub fn identity(&self) -> &StoreIdentityV1 {
        &self.identity
    }

    /// Durable authority/config/profile/build activation, when enrolled.
    ///
    /// Stores opened for offline tooling may intentionally be unactivated;
    /// daemon startup uses [`Self::open_activated`] and therefore always
    /// returns `Some` here.
    #[must_use]
    pub fn activation(&self) -> Option<&StoreActivationRecordV1> {
        self.activation.as_ref()
    }

    /// Database path used to derive the writer fence.
    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    /// Current event-chain head.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted head cannot be read or decoded.
    pub fn chain_head(&self) -> Result<ChainHeadV1, StoreError> {
        chain_head_from_connection(&self.connection)
    }

    /// Append an event and replace one materialized state atomically.
    ///
    /// `expected_revision == 0` creates a new entity. Any other value is an
    /// optimistic exact-state precondition.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid IDs, revision conflict, an active backup
    /// barrier, non-canonical state, or failed durable commit.
    pub fn append_event<P: Serialize, S: Serialize>(
        &mut self,
        event: NewEventV1<P>,
        state: &S,
        expected_revision: u64,
    ) -> Result<EventReceiptV1, StoreError> {
        validate_event(&event)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_no_backup_barrier(&transaction)?;
        let receipt = append_event_in_transaction(&transaction, event, state, expected_revision)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Appends two events for two distinct materialized entities in one
    /// durable transaction.
    ///
    /// This is used for authority-bound indexes whose lookup record must never
    /// exist without its referenced state (or vice versa). Event-chain order
    /// is the argument order. The operation cannot update the same entity
    /// twice because the second expected revision would depend on the first.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate entities, invalid events, revision
    /// conflicts, an active backup barrier, canonicalization failure, or a
    /// failed transaction. Either both events commit or neither does.
    #[allow(clippy::too_many_arguments)]
    pub fn append_distinct_event_pair<P1, S1, P2, S2>(
        &mut self,
        first_event: NewEventV1<P1>,
        first_state: &S1,
        first_expected_revision: u64,
        second_event: NewEventV1<P2>,
        second_state: &S2,
        second_expected_revision: u64,
    ) -> Result<(EventReceiptV1, EventReceiptV1), StoreError>
    where
        P1: Serialize,
        S1: Serialize,
        P2: Serialize,
        S2: Serialize,
    {
        validate_event(&first_event)?;
        validate_event(&second_event)?;
        if first_event.entity_id == second_event.entity_id {
            return Err(StoreError::InvalidIdentifier {
                field: "event_pair",
                reason: "paired events must update distinct entities".to_owned(),
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_no_backup_barrier(&transaction)?;
        let first = append_event_in_transaction(
            &transaction,
            first_event,
            first_state,
            first_expected_revision,
        )?;
        let second = append_event_in_transaction(
            &transaction,
            second_event,
            second_state,
            second_expected_revision,
        )?;
        transaction.commit()?;
        Ok((first, second))
    }

    /// Decode the current materialized state for an entity.
    ///
    /// # Errors
    ///
    /// Returns an error for database failure, corrupt metadata, or a state that
    /// cannot be decoded as `T`.
    pub fn materialized_state<T: serde::de::DeserializeOwned>(
        &self,
        entity_id: &str,
    ) -> Result<Option<MaterializedStateV1<T>>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT revision, state_jcs, state_digest, last_event_sequence, last_event_digest
                 FROM materialized_state WHERE entity_id = ?1",
                [entity_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((revision, state_jcs, state_digest, sequence, event_digest)) = row else {
            return Ok(None);
        };
        let state = serde_json::from_slice(&state_jcs)
            .map_err(|error| StoreError::InvalidStoredJson(error.to_string()))?;
        Ok(Some(MaterializedStateV1 {
            entity_id: entity_id.to_owned(),
            revision: to_u64(revision, "materialized revision")?,
            state,
            state_digest: StoreDigestV1::from_str(&state_digest)?,
            last_event_sequence: to_u64(sequence, "materialized event sequence")?,
            last_event_digest: StoreDigestV1::from_str(&event_digest)?,
        }))
    }

    /// List materialized entity IDs with an exact literal prefix.
    ///
    /// Results use deterministic bytewise ordering. The hard 10,000-row cap
    /// keeps an inspection request from becoming an unbounded allocation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid prefix/limit or database failure.
    pub fn entity_ids(&self, prefix: &str, limit: u32) -> Result<Vec<String>, StoreError> {
        self.entity_ids_after(prefix, None, limit)
    }

    /// List a deterministic page of materialized entity IDs after a cursor.
    ///
    /// The cursor is an exact entity ID from a prior page and is excluded from
    /// the result. Both comparison and ordering are bytewise, so callers can
    /// safely walk a prefix without a fixed global row limit.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid prefix, cursor, or page limit, or for a
    /// database failure.
    pub fn entity_ids_after(
        &self,
        prefix: &str,
        after_exclusive: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        validate_identifier("entity_prefix", prefix, 256)?;
        if let Some(cursor) = after_exclusive {
            validate_identifier("entity_cursor", cursor, 256)?;
            if !cursor.starts_with(prefix) {
                return Err(StoreError::InvalidIdentifier {
                    field: "entity_cursor",
                    reason: "must have the requested literal prefix".to_owned(),
                });
            }
        }
        if limit == 0 || limit > 10_000 {
            return Err(StoreError::InvalidIdentifier {
                field: "entity_limit",
                reason: "must be in 1..=10000".to_owned(),
            });
        }
        let mut statement = self.connection.prepare(
            "SELECT entity_id FROM materialized_state
             WHERE substr(entity_id, 1, length(?1)) = ?1
               AND (?2 IS NULL OR entity_id COLLATE BINARY > ?2)
             ORDER BY entity_id COLLATE BINARY
             LIMIT ?3",
        )?;
        let rows = statement
            .query_map(params![prefix, after_exclusive, i64::from(limit)], |row| {
                row.get(0)
            })?;
        let mut entity_ids = Vec::new();
        for row in rows {
            entity_ids.push(row?);
        }
        Ok(entity_ids)
    }

    /// Verify every event link, payload digest, state digest, final head, and
    /// current materialized-state pointer.
    ///
    /// # Errors
    ///
    /// Returns an error at the first corrupt chain, canonical document, state
    /// binding, digest, or database read.
    #[allow(clippy::too_many_lines)]
    pub fn verify_chain(&self) -> Result<ChainHeadV1, StoreError> {
        let mut expected_previous = genesis_digest(&self.identity)?;
        let mut expected_sequence = 1_u64;
        let mut statement = self.connection.prepare(
            "SELECT sequence, event_id, entity_id, event_kind, occurred_at_unix_ms,
                    previous_digest, payload_jcs, payload_digest, state_digest, event_digest
             FROM events ORDER BY sequence",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let sequence = to_u64(row.get::<_, i64>(0)?, "event sequence")?;
            if sequence != expected_sequence {
                return Err(StoreError::Corrupt(format!(
                    "event sequence gap: expected {expected_sequence}, found {sequence}"
                )));
            }
            let event_id: String = row.get(1)?;
            let entity_id: String = row.get(2)?;
            let event_kind: String = row.get(3)?;
            let occurred_at_unix_ms: i64 = row.get(4)?;
            let previous_digest = StoreDigestV1::from_str(&row.get::<_, String>(5)?)?;
            let payload_jcs: Vec<u8> = row.get(6)?;
            verify_canonical_stored_json(&payload_jcs, "event payload")?;
            let payload_digest = StoreDigestV1::from_str(&row.get::<_, String>(7)?)?;
            let state_digest = StoreDigestV1::from_str(&row.get::<_, String>(8)?)?;
            let event_digest = StoreDigestV1::from_str(&row.get::<_, String>(9)?)?;

            if previous_digest != expected_previous {
                return Err(StoreError::Corrupt(format!(
                    "event {sequence} predecessor does not match chain"
                )));
            }
            let actual_payload = StoreDigestV1::hash("ag-store-event-payload-v1", &payload_jcs);
            if actual_payload != payload_digest {
                return Err(StoreError::Corrupt(format!(
                    "event {sequence} payload digest mismatch"
                )));
            }
            let input = EventHashInputV1 {
                sequence,
                event_id: &event_id,
                entity_id: &entity_id,
                event_kind: &event_kind,
                occurred_at_unix_ms,
                previous_digest: &previous_digest,
                payload_digest: &payload_digest,
                state_digest: &state_digest,
            };
            let actual_event = event_digest_for(&input)?;
            if actual_event != event_digest {
                return Err(StoreError::Corrupt(format!(
                    "event {sequence} digest mismatch"
                )));
            }
            expected_previous = event_digest;
            expected_sequence += 1;
        }
        drop(rows);
        drop(statement);

        let head = self.chain_head()?;
        if head.sequence != expected_sequence - 1 || head.digest != expected_previous {
            return Err(StoreError::Corrupt(
                "persisted chain head does not match event chain".to_owned(),
            ));
        }

        let mut states = self.connection.prepare(
            "SELECT entity_id, state_jcs, state_digest, last_event_sequence, last_event_digest
             FROM materialized_state",
        )?;
        let mut rows = states.query([])?;
        while let Some(row) = rows.next()? {
            let entity_id: String = row.get(0)?;
            let state_jcs: Vec<u8> = row.get(1)?;
            verify_canonical_stored_json(&state_jcs, "materialized state")?;
            let state_digest = StoreDigestV1::from_str(&row.get::<_, String>(2)?)?;
            let sequence: i64 = row.get(3)?;
            let event_digest = StoreDigestV1::from_str(&row.get::<_, String>(4)?)?;
            if StoreDigestV1::hash("ag-store-materialized-state-v1", &state_jcs) != state_digest {
                return Err(StoreError::Corrupt(format!(
                    "materialized state digest mismatch for {entity_id:?}"
                )));
            }
            let linked: Option<(String, String, String)> = self
                .connection
                .query_row(
                    "SELECT entity_id, state_digest, event_digest FROM events WHERE sequence = ?1",
                    [sequence],
                    |event| Ok((event.get(0)?, event.get(1)?, event.get(2)?)),
                )
                .optional()?;
            if linked
                != Some((
                    entity_id.clone(),
                    state_digest.to_string(),
                    event_digest.to_string(),
                ))
            {
                return Err(StoreError::Corrupt(format!(
                    "materialized state event binding mismatch for {entity_id:?}"
                )));
            }
        }
        Ok(head)
    }

    /// Atomically install exact immutable bytes and catalog them.
    ///
    /// # Errors
    ///
    /// Returns an error for digest/size mismatch, mutable or linked existing
    /// files, an active backup barrier, or failed durable installation.
    pub fn install_blob<R: Read>(
        &mut self,
        descriptor: &BlobDescriptorV1,
        reader: &mut R,
        installed_at_unix_ms: i64,
    ) -> Result<BlobInstallResult, StoreError> {
        if let Some(catalog_size) = self
            .connection
            .query_row(
                "SELECT byte_length FROM blobs WHERE digest = ?1",
                [descriptor.digest.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            if to_u64(catalog_size, "blob byte length")? != descriptor.byte_length {
                return Err(StoreError::Corrupt(format!(
                    "catalog size disagrees with descriptor for {}",
                    descriptor.digest
                )));
            }
            verify_blob_file(&self.blob_path(&descriptor.digest), descriptor)?;
            return Ok(BlobInstallResult::AlreadyPresent);
        }

        let active = active_backup_cut(&self.connection)?;
        if let Some(cut_id) = active {
            return Err(StoreError::BackupBarrierActive(cut_id));
        }

        let destination = self.blob_path(&descriptor.digest);
        let parent = destination.parent().ok_or_else(|| {
            StoreError::Corrupt("blob destination has no parent directory".to_owned())
        })?;
        create_and_validate_directory(parent)?;

        if destination.exists() {
            verify_blob_file(&destination, descriptor)?;
        } else {
            let mut temporary = NamedTempFile::new_in(parent)?;
            let actual =
                copy_and_hash_blob(reader, temporary.as_file_mut(), descriptor.byte_length)?;
            if actual != *descriptor {
                return Err(StoreError::BlobMismatch {
                    expected: descriptor.clone(),
                    actual,
                });
            }
            temporary.as_file().sync_all()?;
            let mut permissions = temporary.as_file().metadata()?.permissions();
            permissions.set_readonly(true);
            temporary.as_file().set_permissions(permissions)?;
            match temporary.persist_noclobber(&destination) {
                Ok(file) => file.sync_all()?,
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    verify_blob_file(&destination, descriptor)?;
                }
                Err(error) => return Err(StoreError::Io(error.error)),
            }
            File::open(parent)?.sync_all()?;
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_no_backup_barrier(&transaction)?;
        transaction.execute(
            "INSERT OR IGNORE INTO blobs(digest, byte_length, installed_at_unix_ms)
             VALUES (?1, ?2, ?3)",
            params![
                descriptor.digest.as_str(),
                to_i64(descriptor.byte_length, "blob byte length")?,
                installed_at_unix_ms
            ],
        )?;
        let stored_size: i64 = transaction.query_row(
            "SELECT byte_length FROM blobs WHERE digest = ?1",
            [descriptor.digest.as_str()],
            |row| row.get(0),
        )?;
        if to_u64(stored_size, "blob byte length")? != descriptor.byte_length {
            return Err(StoreError::Corrupt(format!(
                "concurrent blob catalog mismatch for {}",
                descriptor.digest
            )));
        }
        transaction.commit()?;
        Ok(BlobInstallResult::Installed)
    }

    /// Reads one exact immutable blob after verifying catalog membership,
    /// regular-file/link/mode custody, size, and content digest.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent/corrupt blob or one larger than the
    /// caller's explicit memory bound.
    pub fn read_blob(&self, digest: &Digest, maximum_bytes: u64) -> Result<Vec<u8>, StoreError> {
        let byte_length = self
            .connection
            .query_row(
                "SELECT byte_length FROM blobs WHERE digest = ?1",
                [digest.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::Corrupt(format!("blob {digest} is not catalogued")))?;
        let byte_length = to_u64(byte_length, "blob byte length")?;
        if byte_length > maximum_bytes {
            return Err(StoreError::BlobReadLimitExceeded {
                digest: digest.clone(),
                actual: byte_length,
                maximum: maximum_bytes,
            });
        }
        let descriptor = BlobDescriptorV1 {
            digest: digest.clone(),
            byte_length,
        };
        let path = self.blob_path(digest);
        verify_blob_file(&path, &descriptor)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let capacity = usize::try_from(byte_length)
            .map_err(|_| StoreError::Corrupt("blob length does not fit memory".to_owned()))?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)?;
        if Digest::hash_bytes(&bytes) != *digest || bytes.len() as u64 != byte_length {
            return Err(StoreError::BlobMismatch {
                expected: descriptor,
                actual: BlobDescriptorV1 {
                    digest: Digest::hash_bytes(&bytes),
                    byte_length: bytes.len() as u64,
                },
            });
        }
        Ok(bytes)
    }

    /// Compute a deterministic root over the exact sorted blob catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when any cataloged blob is absent, mutable, linked, or
    /// digest-inconsistent, or when the catalog cannot be read.
    pub fn blob_root(&self) -> Result<StoreDigestV1, StoreError> {
        digest_jcs("ag-store-blob-root-v1", &self.blob_catalog()?)
    }

    /// Return the exact sorted immutable-object catalog after reverifying
    /// every file's type, link count, length, and content digest.
    ///
    /// This is the finite capture list paired with [`Self::blob_root`]. A
    /// backup publisher must reproduce every descriptor exactly; walking the
    /// object directory is not a substitute for this authoritative catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when the catalog cannot be read or any referenced
    /// object has been removed, linked, made mutable, resized, or altered.
    pub fn blob_catalog(&self) -> Result<Vec<BlobDescriptorV1>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT digest, byte_length FROM blobs ORDER BY digest")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut descriptors = Vec::new();
        for row in rows {
            let (digest, size) = row?;
            let descriptor = BlobDescriptorV1 {
                digest: Digest::parse(&digest)
                    .map_err(|_| StoreError::InvalidDigest(digest.clone()))?,
                byte_length: to_u64(size, "blob byte length")?,
            };
            verify_blob_file(&self.blob_path(&descriptor.digest), &descriptor)?;
            descriptors.push(descriptor);
        }
        Ok(descriptors)
    }

    /// Capture one standalone `SQLite` database while the exact distributed cut
    /// remains sealed and ordinary mutation is fenced.
    ///
    /// The destination is created without replacement, synchronized, made
    /// read-only, and bound to the sealed manifest, post-seal event head, and
    /// verified immutable-object root. Callers must still copy every object in
    /// that root and publish all three component captures atomically before
    /// releasing the cut with the resulting bundle digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the cut is not sealed, the participant was not
    /// registered, the destination is unsafe or already exists, source
    /// integrity changes during capture, `SQLite` cannot make a standalone
    /// backup, or durable filesystem synchronization fails.
    pub fn capture_sealed_database(
        &self,
        cut_id: &str,
        participant: BackupParticipantV1,
        destination: &Path,
    ) -> Result<SealedDatabaseCaptureV1, StoreError> {
        validate_identifier("cut_id", cut_id, 192)?;
        let cut = self.backup_cut(cut_id)?;
        if cut.state != BackupCutStateV1::Sealed {
            return Err(StoreError::BackupCaptureRequiresSealed(cut_id.to_owned()));
        }
        let manifest_digest = cut
            .manifest_digest
            .ok_or_else(|| StoreError::Corrupt("sealed cut lacks manifest digest".to_owned()))?;
        let cut_manifest = self.build_backup_manifest(cut_id)?;
        if digest_jcs("ag-store-backup-manifest-v1", &cut_manifest)? != manifest_digest {
            return Err(StoreError::Corrupt(
                "sealed manifest digest does not match participant records".to_owned(),
            ));
        }
        let component_identity = self
            .connection
            .query_row(
                "SELECT component_identity FROM backup_participants
                 WHERE cut_id = ?1 AND participant = ?2",
                params![cut_id, participant.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(StoreError::BackupParticipantMismatch(participant))?;
        let component_identity = Digest::parse(&component_identity)
            .map_err(|_| StoreError::InvalidDigest(component_identity))?;

        let destination = absolute_normalized_path(destination)?;
        let parent = destination.parent().ok_or_else(|| {
            StoreError::InvalidIdentity("capture destination has no parent directory".to_owned())
        })?;
        create_and_validate_directory(parent)?;
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(StoreError::BackupCaptureDestinationExists(destination));
        }

        let captured_chain_head = self.verify_chain()?;
        let blob_root = self.blob_root()?;
        let temporary = NamedTempFile::new_in(parent)?;
        {
            let mut destination_connection = Connection::open_with_flags(
                temporary.path(),
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            let backup =
                rusqlite::backup::Backup::new(&self.connection, &mut destination_connection)?;
            backup.run_to_completion(256, std::time::Duration::from_millis(1), None)?;
            drop(backup);
            // The source is deliberately WAL-backed, but a sealed publication
            // is one standalone immutable database file. Normalize the copied
            // header while this private destination is still writable so a
            // read-only verifier never needs to create WAL/SHM sidecars.
            let captured_journal: String =
                destination_connection
                    .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
            if !captured_journal.eq_ignore_ascii_case("delete") {
                return Err(StoreError::Corrupt(format!(
                    "captured SQLite refused standalone journal mode: {captured_journal:?}"
                )));
            }
            let quick_check: String =
                destination_connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
            if quick_check != "ok" {
                return Err(StoreError::Corrupt(format!(
                    "captured SQLite quick_check returned {quick_check:?}"
                )));
            }
        }
        if self.verify_chain()? != captured_chain_head || self.blob_root()? != blob_root {
            return Err(StoreError::Corrupt(
                "sealed store changed during physical capture".to_owned(),
            ));
        }

        temporary.as_file().sync_all()?;
        let byte_length = temporary.as_file().metadata()?.len();
        let mut capture_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(temporary.path())?;
        let database = hash_blob_reader(&mut capture_file, byte_length)?;
        let mut permissions = temporary.as_file().metadata()?.permissions();
        permissions.set_readonly(true);
        temporary.as_file().set_permissions(permissions)?;
        match temporary.persist_noclobber(&destination) {
            Ok(file) => file.sync_all()?,
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StoreError::BackupCaptureDestinationExists(destination));
            }
            Err(error) => return Err(StoreError::Io(error.error)),
        }
        File::open(parent)?.sync_all()?;

        Ok(SealedDatabaseCaptureV1 {
            schema: "ag-store-sealed-database-capture-v1".to_owned(),
            cut_id: cut_id.to_owned(),
            participant,
            component_identity,
            manifest_digest,
            cut_manifest,
            store_identity: self.identity.clone(),
            captured_chain_head,
            blob_root,
            database,
        })
    }

    /// Begin a coherent backup barrier and register exactly three participants.
    /// Exact retries return the original begin receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid participant set, conflicting retry,
    /// existing active cut, or failed durable transition.
    pub fn begin_backup_cut(
        &mut self,
        request: &BeginBackupCutV1,
    ) -> Result<EventReceiptV1, StoreError> {
        request.validate()?;
        let request_digest = digest_jcs("ag-store-backup-begin-request-v1", request)?;
        if let Some((stored_digest, sequence)) = self
            .connection
            .query_row(
                "SELECT begin_request_digest, begin_event_sequence FROM backup_cuts WHERE cut_id = ?1",
                [&request.cut_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            if stored_digest != request_digest.as_str() {
                return Err(StoreError::BackupCutConflict(request.cut_id.clone()));
            }
            return event_receipt_by_sequence(&self.connection, sequence);
        }
        if active_backup_cut(&self.connection)?.is_some() {
            return Err(StoreError::BackupCutAlreadyActive);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if active_backup_cut(&transaction)?.is_some() {
            return Err(StoreError::BackupCutAlreadyActive);
        }

        // Foreign keys require the backup row before participants, while the
        // backup row requires the begin event. Append the event first; all work
        // remains invisible until the same transaction commits.
        let state = BackupCutMaterializedV1 {
            cut_id: &request.cut_id,
            state: BackupCutStateV1::Preparing,
            prepared_participants: 0,
            manifest_digest: None,
            release_bundle_digest: None,
            abort_reason: None,
        };
        let receipt = append_event_in_transaction(
            &transaction,
            NewEventV1 {
                event_id: format!("backup:{}:begin", request.cut_id),
                entity_id: backup_entity_id(&request.cut_id),
                event_kind: "backup-cut.begin.v1".to_owned(),
                occurred_at_unix_ms: request.created_at_unix_ms,
                payload: request,
            },
            &state,
            0,
        )?;
        transaction.execute(
            "INSERT INTO backup_cuts(
                cut_id, authority_domain, epoch, quiescence_barrier_id, state,
                begin_request_digest, begin_event_sequence, begin_event_digest,
                created_at_unix_ms, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, 'preparing', ?5, ?6, ?7, ?8, ?8)",
            params![
                request.cut_id,
                request.authority_domain.as_str(),
                to_i64(request.epoch.get(), "backup epoch")?,
                request.quiescence_barrier_id,
                request_digest.as_str(),
                to_i64(receipt.sequence, "event sequence")?,
                receipt.event_digest.as_str(),
                request.created_at_unix_ms
            ],
        )?;
        for registration in &request.participants {
            transaction.execute(
                "INSERT INTO backup_participants(cut_id, participant, component_identity)
                 VALUES (?1, ?2, ?3)",
                params![
                    request.cut_id,
                    registration.participant.as_str(),
                    registration.component_identity.as_str()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(receipt)
    }

    /// Durably prepare one participant checkpoint. Exact retries are
    /// idempotent; a changed retry is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for registration/checkpoint mismatch, invalid cut state,
    /// or failed durable transition.
    #[allow(clippy::too_many_lines)]
    pub fn prepare_backup_participant(
        &mut self,
        cut_id: &str,
        checkpoint: &BackupCheckpointV1,
        occurred_at_unix_ms: i64,
    ) -> Result<EventReceiptV1, StoreError> {
        let (authority_domain, epoch, barrier): (String, i64, String) = self
            .connection
            .query_row(
                "SELECT authority_domain, epoch, quiescence_barrier_id
                 FROM backup_cuts WHERE cut_id = ?1",
                [cut_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| StoreError::BackupCutNotFound(cut_id.to_owned()))?;
        let authority_domain = AuthorityDomainId::new(authority_domain)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        let epoch = EpochId::new(to_u64(epoch, "backup epoch")?)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        checkpoint.quiescence_attestation.validate_for(
            cut_id,
            &authority_domain,
            epoch,
            &barrier,
            checkpoint.participant,
        )?;
        let checkpoint_jcs = jcs(checkpoint)?;
        let checkpoint_digest =
            StoreDigestV1::hash("ag-store-backup-checkpoint-v1", &checkpoint_jcs);
        if let Some((registered_identity, prior_digest, prior_sequence)) = self
            .connection
            .query_row(
                "SELECT component_identity, checkpoint_digest, prepared_event_sequence
                 FROM backup_participants WHERE cut_id = ?1 AND participant = ?2",
                params![cut_id, checkpoint.participant.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if registered_identity != checkpoint.component_identity.as_str() {
                return Err(StoreError::BackupParticipantMismatch(
                    checkpoint.participant,
                ));
            }
            if let Some(prior_digest) = prior_digest {
                if prior_digest != checkpoint_digest.as_str() {
                    return Err(StoreError::BackupCheckpointConflict(checkpoint.participant));
                }
                return event_receipt_by_sequence(
                    &self.connection,
                    prior_sequence.ok_or_else(|| {
                        StoreError::Corrupt("prepared checkpoint lacks event sequence".to_owned())
                    })?,
                );
            }
        } else {
            return Err(StoreError::BackupParticipantMismatch(
                checkpoint.participant,
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = backup_state_in_transaction(&transaction, cut_id)?;
        if !matches!(
            state,
            BackupCutStateV1::Preparing | BackupCutStateV1::Prepared
        ) {
            return Err(StoreError::InvalidBackupTransition {
                action: "prepare participant",
                state,
            });
        }
        let already_prepared: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM backup_participants
             WHERE cut_id = ?1 AND checkpoint_digest IS NOT NULL",
            [cut_id],
            |row| row.get(0),
        )?;
        let resulting_count = to_u64(already_prepared, "prepared participant count")? + 1;
        let resulting_state = if resulting_count == REQUIRED_BACKUP_PARTICIPANTS.len() as u64 {
            BackupCutStateV1::Prepared
        } else {
            BackupCutStateV1::Preparing
        };
        let current_revision = materialized_revision(&transaction, &backup_entity_id(cut_id))?;
        let materialized = BackupCutMaterializedV1 {
            cut_id,
            state: resulting_state,
            prepared_participants: u8::try_from(resulting_count).map_err(|_| {
                StoreError::Corrupt("prepared participant count does not fit u8".to_owned())
            })?,
            manifest_digest: None,
            release_bundle_digest: None,
            abort_reason: None,
        };
        let receipt = append_event_in_transaction(
            &transaction,
            NewEventV1 {
                event_id: format!(
                    "backup:{cut_id}:prepared:{}",
                    checkpoint.participant.as_str()
                ),
                entity_id: backup_entity_id(cut_id),
                event_kind: "backup-cut.participant-prepared.v1".to_owned(),
                occurred_at_unix_ms,
                payload: checkpoint,
            },
            &materialized,
            current_revision,
        )?;
        let changed = transaction.execute(
            "UPDATE backup_participants
             SET checkpoint_jcs = ?3, checkpoint_digest = ?4,
                 prepared_event_sequence = ?5, prepared_event_digest = ?6
             WHERE cut_id = ?1 AND participant = ?2 AND checkpoint_digest IS NULL",
            params![
                cut_id,
                checkpoint.participant.as_str(),
                checkpoint_jcs,
                checkpoint_digest.as_str(),
                to_i64(receipt.sequence, "event sequence")?,
                receipt.event_digest.as_str()
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::BackupCheckpointConflict(checkpoint.participant));
        }
        transaction.execute(
            "UPDATE backup_cuts SET state = ?2, updated_at_unix_ms = ?3 WHERE cut_id = ?1",
            params![cut_id, resulting_state.as_str(), occurred_at_unix_ms],
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Construct the only sealable manifest from durable prepared facts.
    ///
    /// # Errors
    ///
    /// Returns an error unless every required participant has prepared exact,
    /// decodable facts for the requested cut.
    pub fn build_backup_manifest(&self, cut_id: &str) -> Result<BackupCutManifestV1, StoreError> {
        build_backup_manifest_from_connection(&self.connection, cut_id)
    }

    /// Seal the exact manifest built from all three prepared participants.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed manifest, invalid lifecycle state, or
    /// failed durable transition.
    pub fn seal_backup_cut(
        &mut self,
        manifest: &BackupCutManifestV1,
        occurred_at_unix_ms: i64,
    ) -> Result<EventReceiptV1, StoreError> {
        let manifest_digest = digest_jcs("ag-store-backup-manifest-v1", manifest)?;
        let (state, stored_digest, sequence) = self
            .connection
            .query_row(
                "SELECT state, manifest_digest, seal_event_sequence
                 FROM backup_cuts WHERE cut_id = ?1",
                [&manifest.cut_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::BackupCutNotFound(manifest.cut_id.clone()))?;
        BackupCutStateV1::from_str(&state)?;
        if stored_digest.is_some() {
            if stored_digest.as_deref() != Some(manifest_digest.as_str()) {
                return Err(StoreError::BackupManifestMismatch);
            }
            return event_receipt_by_sequence(
                &self.connection,
                sequence.ok_or_else(|| {
                    StoreError::Corrupt("sealed cut lacks event sequence".to_owned())
                })?,
            );
        }

        let expected = self.build_backup_manifest(&manifest.cut_id)?;
        if jcs(&expected)? != jcs(manifest)? {
            return Err(StoreError::BackupManifestMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = backup_state_in_transaction(&transaction, &manifest.cut_id)?;
        if state != BackupCutStateV1::Prepared {
            return Err(StoreError::InvalidBackupTransition {
                action: "seal",
                state,
            });
        }
        let current_revision =
            materialized_revision(&transaction, &backup_entity_id(&manifest.cut_id))?;
        let materialized = BackupCutMaterializedV1 {
            cut_id: &manifest.cut_id,
            state: BackupCutStateV1::Sealed,
            prepared_participants: required_backup_participant_count(),
            manifest_digest: Some(&manifest_digest),
            release_bundle_digest: None,
            abort_reason: None,
        };
        let receipt = append_event_in_transaction(
            &transaction,
            NewEventV1 {
                event_id: format!("backup:{}:sealed", manifest.cut_id),
                entity_id: backup_entity_id(&manifest.cut_id),
                event_kind: "backup-cut.sealed.v1".to_owned(),
                occurred_at_unix_ms,
                payload: manifest,
            },
            &materialized,
            current_revision,
        )?;
        transaction.execute(
            "UPDATE backup_cuts
             SET state = 'sealed', manifest_digest = ?2,
                 seal_event_sequence = ?3, seal_event_digest = ?4,
                 updated_at_unix_ms = ?5
             WHERE cut_id = ?1",
            params![
                manifest.cut_id,
                manifest_digest.as_str(),
                to_i64(receipt.sequence, "event sequence")?,
                receipt.event_digest.as_str(),
                occurred_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Release a sealed barrier only after the exact verified backup bundle is
    /// durably published. Exact retries are idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed retry, an unsealed cut, or failed durable
    /// transition.
    pub fn release_backup_cut(
        &mut self,
        cut_id: &str,
        bundle_digest: &Digest,
        occurred_at_unix_ms: i64,
    ) -> Result<EventReceiptV1, StoreError> {
        let (state, stored_bundle, sequence) = self
            .connection
            .query_row(
                "SELECT state, release_bundle_digest, release_event_sequence
                 FROM backup_cuts WHERE cut_id = ?1",
                [cut_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::BackupCutNotFound(cut_id.to_owned()))?;
        let state = BackupCutStateV1::from_str(&state)?;
        if state == BackupCutStateV1::Released {
            if stored_bundle.as_deref() != Some(bundle_digest.as_str()) {
                return Err(StoreError::BackupCutConflict(cut_id.to_owned()));
            }
            return event_receipt_by_sequence(
                &self.connection,
                sequence.ok_or_else(|| {
                    StoreError::Corrupt("released cut lacks event sequence".to_owned())
                })?,
            );
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = backup_state_in_transaction(&transaction, cut_id)?;
        if state != BackupCutStateV1::Sealed {
            return Err(StoreError::InvalidBackupTransition {
                action: "release",
                state,
            });
        }
        let manifest_digest: String = transaction.query_row(
            "SELECT manifest_digest FROM backup_cuts WHERE cut_id = ?1",
            [cut_id],
            |row| row.get(0),
        )?;
        let manifest_digest = StoreDigestV1::from_str(&manifest_digest)?;
        let current_revision = materialized_revision(&transaction, &backup_entity_id(cut_id))?;
        let materialized = BackupCutMaterializedV1 {
            cut_id,
            state: BackupCutStateV1::Released,
            prepared_participants: required_backup_participant_count(),
            manifest_digest: Some(&manifest_digest),
            release_bundle_digest: Some(bundle_digest),
            abort_reason: None,
        };
        let payload = BackupReleasePayloadV1 {
            cut_id,
            bundle_digest,
        };
        let receipt = append_event_in_transaction(
            &transaction,
            NewEventV1 {
                event_id: format!("backup:{cut_id}:released"),
                entity_id: backup_entity_id(cut_id),
                event_kind: "backup-cut.released.v1".to_owned(),
                occurred_at_unix_ms,
                payload,
            },
            &materialized,
            current_revision,
        )?;
        transaction.execute(
            "UPDATE backup_cuts
             SET state = 'released', release_bundle_digest = ?2,
                 release_event_sequence = ?3, release_event_digest = ?4,
                 updated_at_unix_ms = ?5
             WHERE cut_id = ?1",
            params![
                cut_id,
                bundle_digest.as_str(),
                to_i64(receipt.sequence, "event sequence")?,
                receipt.event_digest.as_str(),
                occurred_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Abort an unreleased barrier, including a failed post-seal capture. Exact
    /// retries with the same reason are idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or changed reason, a released cut, or
    /// failed durable transition.
    pub fn abort_backup_cut(
        &mut self,
        cut_id: &str,
        reason: &str,
        occurred_at_unix_ms: i64,
    ) -> Result<EventReceiptV1, StoreError> {
        validate_identifier("abort_reason", reason, 256)?;
        let (state, stored_reason, sequence) = self
            .connection
            .query_row(
                "SELECT state, abort_reason, abort_event_sequence FROM backup_cuts WHERE cut_id = ?1",
                [cut_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::BackupCutNotFound(cut_id.to_owned()))?;
        let state = BackupCutStateV1::from_str(&state)?;
        if state == BackupCutStateV1::Aborted {
            if stored_reason.as_deref() != Some(reason) {
                return Err(StoreError::BackupCutConflict(cut_id.to_owned()));
            }
            return event_receipt_by_sequence(
                &self.connection,
                sequence.ok_or_else(|| {
                    StoreError::Corrupt("aborted cut lacks event sequence".to_owned())
                })?,
            );
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = backup_state_in_transaction(&transaction, cut_id)?;
        if !matches!(
            state,
            BackupCutStateV1::Preparing | BackupCutStateV1::Prepared | BackupCutStateV1::Sealed
        ) {
            return Err(StoreError::InvalidBackupTransition {
                action: "abort",
                state,
            });
        }
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM backup_participants
             WHERE cut_id = ?1 AND checkpoint_digest IS NOT NULL",
            [cut_id],
            |row| row.get(0),
        )?;
        let current_revision = materialized_revision(&transaction, &backup_entity_id(cut_id))?;
        let manifest_digest = transaction
            .query_row(
                "SELECT manifest_digest FROM backup_cuts WHERE cut_id = ?1",
                [cut_id],
                |row| row.get::<_, Option<String>>(0),
            )?
            .map(|digest| StoreDigestV1::from_str(&digest))
            .transpose()?;
        let materialized = BackupCutMaterializedV1 {
            cut_id,
            state: BackupCutStateV1::Aborted,
            prepared_participants: u8::try_from(count).map_err(|_| {
                StoreError::Corrupt("prepared participant count does not fit u8".to_owned())
            })?,
            manifest_digest: manifest_digest.as_ref(),
            release_bundle_digest: None,
            abort_reason: Some(reason),
        };
        let payload = BackupAbortPayloadV1 { cut_id, reason };
        let receipt = append_event_in_transaction(
            &transaction,
            NewEventV1 {
                event_id: format!("backup:{cut_id}:aborted"),
                entity_id: backup_entity_id(cut_id),
                event_kind: "backup-cut.aborted.v1".to_owned(),
                occurred_at_unix_ms,
                payload,
            },
            &materialized,
            current_revision,
        )?;
        transaction.execute(
            "UPDATE backup_cuts
             SET state = 'aborted', abort_reason = ?2,
                 abort_event_sequence = ?3, abort_event_digest = ?4,
                 updated_at_unix_ms = ?5
             WHERE cut_id = ?1",
            params![
                cut_id,
                reason,
                to_i64(receipt.sequence, "event sequence")?,
                receipt.event_digest.as_str(),
                occurred_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Fetch a backup-cut lifecycle summary.
    ///
    /// # Errors
    ///
    /// Returns an error if the cut is absent or its durable record is corrupt.
    pub fn backup_cut(&self, cut_id: &str) -> Result<BackupCutRecordV1, StoreError> {
        backup_cut_from_connection(&self.connection, cut_id)
    }

    /// Return the active cut ID, if ordinary mutations are fenced.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be inspected.
    pub fn active_backup_cut(&self) -> Result<Option<String>, StoreError> {
        active_backup_cut(&self.connection)
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        let hex = digest
            .as_str()
            .strip_prefix("sha256:")
            .expect("workspace Digest always has the strict algorithm prefix");
        self.blob_root.join(&hex[..2]).join(&hex[2..])
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EventHashInputV1<'a> {
    sequence: u64,
    event_id: &'a str,
    entity_id: &'a str,
    event_kind: &'a str,
    occurred_at_unix_ms: i64,
    previous_digest: &'a StoreDigestV1,
    payload_digest: &'a StoreDigestV1,
    state_digest: &'a StoreDigestV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BackupCutMaterializedV1<'a> {
    cut_id: &'a str,
    state: BackupCutStateV1,
    prepared_participants: u8,
    manifest_digest: Option<&'a StoreDigestV1>,
    release_bundle_digest: Option<&'a Digest>,
    abort_reason: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BackupAbortPayloadV1<'a> {
    cut_id: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BackupReleasePayloadV1<'a> {
    cut_id: &'a str,
    bundle_digest: &'a Digest,
}

fn initialize_or_validate(
    connection: &mut Connection,
    expected: &StoreIdentityV1,
    expected_activation: Option<(&StoreActivationIdentityV1, i64)>,
    allow_initialization: bool,
) -> Result<Option<StoreActivationRecordV1>, StoreError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'store_identity')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        if !allow_initialization {
            let path = connection
                .path()
                .map_or_else(|| PathBuf::from("<unknown>"), PathBuf::from);
            return Err(StoreError::UnrecognizedExistingDatabase(path));
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_SQL)?;
        transaction.pragma_update(None, "application_id", expected.application_id)?;
        transaction.pragma_update(None, "user_version", expected.schema_version)?;
        transaction.execute(
            "INSERT INTO store_identity(
                singleton, application_id, application_name, schema_name, schema_version, schema_digest
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                expected.application_id,
                expected.application_name,
                expected.schema_name,
                expected.schema_version,
                expected.schema_digest.as_str()
            ],
        )?;
        let genesis = genesis_digest(expected)?;
        transaction.execute(
            "INSERT INTO chain_head(singleton, sequence, digest) VALUES (1, 0, ?1)",
            [genesis.as_str()],
        )?;
        if let Some((activation, activated_at_unix_ms)) = expected_activation {
            insert_activation(&transaction, activation, activated_at_unix_ms)?;
        }
        transaction.commit()?;
    }

    let pragma_application: u32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let pragma_version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let actual = connection.query_row(
        "SELECT application_id, application_name, schema_name, schema_version, schema_digest
         FROM store_identity WHERE singleton = 1",
        [],
        |row| {
            let digest: String = row.get(4)?;
            Ok(StoreIdentityV1 {
                application_id: row.get(0)?,
                application_name: row.get(1)?,
                schema_name: row.get(2)?,
                schema_version: row.get(3)?,
                schema_digest: StoreDigestV1::from_str(&digest).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        digest.len(),
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
            })
        },
    )?;
    if &actual != expected
        || pragma_application != expected.application_id
        || pragma_version != expected.schema_version
    {
        return Err(StoreError::IdentityMismatch {
            expected: Box::new(expected.clone()),
            actual: Box::new(actual),
        });
    }

    let actual_activation = load_activation(connection)?;
    match (expected_activation, actual_activation) {
        (None, None) if allow_initialization => Ok(None),
        (_, None) => Err(StoreError::ActivationIdentityMissing),
        (Some((expected, _)), Some(actual)) if &actual.identity != expected => {
            Err(StoreError::ActivationIdentityMismatch {
                expected: Box::new(expected.clone()),
                actual: Box::new(actual.identity),
            })
        }
        (None, Some(_)) => Err(StoreError::ActivationIdentityRequired),
        (Some(_), Some(actual)) => Ok(Some(actual)),
    }
}

fn configure_mutating_connection_pragmas(connection: &Connection) -> Result<(), StoreError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::Corrupt(format!(
            "SQLite refused WAL journal mode and returned {journal_mode:?}"
        )));
    }
    Ok(())
}

fn insert_activation(
    transaction: &Transaction<'_>,
    identity: &StoreActivationIdentityV1,
    activated_at_unix_ms: i64,
) -> Result<(), StoreError> {
    identity.validate()?;
    let identity_jcs = jcs(identity)?;
    let activation_digest = StoreDigestV1::hash("ag-store-activation-identity-v1", &identity_jcs);
    transaction.execute(
        "INSERT INTO store_activation(
            singleton, activation_jcs, activation_digest, activated_at_unix_ms
         ) VALUES (1, ?1, ?2, ?3)",
        params![
            identity_jcs,
            activation_digest.as_str(),
            activated_at_unix_ms
        ],
    )?;
    Ok(())
}

fn load_activation(connection: &Connection) -> Result<Option<StoreActivationRecordV1>, StoreError> {
    let row: Option<(Vec<u8>, String, i64)> = connection
        .query_row(
            "SELECT activation_jcs, activation_digest, activated_at_unix_ms
             FROM store_activation WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((identity_jcs, stored_digest, activated_at_unix_ms)) = row else {
        return Ok(None);
    };
    verify_canonical_stored_json(&identity_jcs, "store activation identity")?;
    let identity: StoreActivationIdentityV1 = serde_json::from_slice(&identity_jcs)
        .map_err(|error| StoreError::InvalidStoredJson(error.to_string()))?;
    identity.validate()?;
    let stored_digest = StoreDigestV1::from_str(&stored_digest)?;
    let actual_digest = StoreDigestV1::hash("ag-store-activation-identity-v1", &identity_jcs);
    if stored_digest != actual_digest {
        return Err(StoreError::Corrupt(
            "store activation digest does not match canonical identity bytes".to_owned(),
        ));
    }
    Ok(Some(StoreActivationRecordV1 {
        identity,
        activation_digest: stored_digest,
        activated_at_unix_ms,
    }))
}

fn claim_writer(connection: &mut Connection, writer: &WriterIdentityV1) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO writer_fence(
            singleton, generation, writer_id, principal_digest, process_nonce, claimed_at_unix_ms
         ) VALUES (1, 1, ?1, ?2, ?3, ?4)
         ON CONFLICT(singleton) DO UPDATE SET
            generation = generation + 1,
            writer_id = excluded.writer_id,
            principal_digest = excluded.principal_digest,
            process_nonce = excluded.process_nonce,
            claimed_at_unix_ms = excluded.claimed_at_unix_ms",
        params![
            writer.writer_id,
            writer.principal_digest.as_str(),
            writer.process_nonce,
            writer.claimed_at_unix_ms
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn validate_event<T>(event: &NewEventV1<T>) -> Result<(), StoreError> {
    validate_identifier("event_id", &event.event_id, 256)?;
    validate_identifier("entity_id", &event.entity_id, 256)?;
    validate_identifier("event_kind", &event.event_kind, 192)
}

#[allow(clippy::too_many_lines)]
fn append_event_in_transaction<P: Serialize, S: Serialize>(
    transaction: &Transaction<'_>,
    event: NewEventV1<P>,
    state: &S,
    expected_revision: u64,
) -> Result<EventReceiptV1, StoreError> {
    validate_event(&event)?;
    if transaction
        .query_row(
            "SELECT 1 FROM events WHERE event_id = ?1",
            [&event.event_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(StoreError::DuplicateEvent(event.event_id));
    }
    let head = chain_head_from_connection(transaction)?;
    let actual_revision = materialized_revision(transaction, &event.entity_id)?;
    if actual_revision != expected_revision {
        return Err(StoreError::RevisionConflict {
            entity_id: event.entity_id,
            expected: expected_revision,
            actual: actual_revision,
        });
    }
    let entity_revision = actual_revision
        .checked_add(1)
        .ok_or_else(|| StoreError::Corrupt("entity revision overflow".to_owned()))?;
    let sequence = head
        .sequence
        .checked_add(1)
        .ok_or_else(|| StoreError::Corrupt("event sequence overflow".to_owned()))?;
    let payload_jcs = jcs(&event.payload)?;
    let state_jcs = jcs(state)?;
    let payload_digest = StoreDigestV1::hash("ag-store-event-payload-v1", &payload_jcs);
    let state_digest = StoreDigestV1::hash("ag-store-materialized-state-v1", &state_jcs);
    let input = EventHashInputV1 {
        sequence,
        event_id: &event.event_id,
        entity_id: &event.entity_id,
        event_kind: &event.event_kind,
        occurred_at_unix_ms: event.occurred_at_unix_ms,
        previous_digest: &head.digest,
        payload_digest: &payload_digest,
        state_digest: &state_digest,
    };
    let event_digest = event_digest_for(&input)?;
    transaction.execute(
        "INSERT INTO events(
            sequence, event_id, entity_id, event_kind, occurred_at_unix_ms,
            previous_digest, payload_jcs, payload_digest, state_digest, event_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            to_i64(sequence, "event sequence")?,
            event.event_id,
            event.entity_id,
            event.event_kind,
            event.occurred_at_unix_ms,
            head.digest.as_str(),
            payload_jcs,
            payload_digest.as_str(),
            state_digest.as_str(),
            event_digest.as_str()
        ],
    )?;
    transaction.execute(
        "INSERT INTO materialized_state(
            entity_id, revision, state_jcs, state_digest, last_event_sequence, last_event_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(entity_id) DO UPDATE SET
            revision = excluded.revision,
            state_jcs = excluded.state_jcs,
            state_digest = excluded.state_digest,
            last_event_sequence = excluded.last_event_sequence,
            last_event_digest = excluded.last_event_digest",
        params![
            event.entity_id,
            to_i64(entity_revision, "entity revision")?,
            state_jcs,
            state_digest.as_str(),
            to_i64(sequence, "event sequence")?,
            event_digest.as_str()
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE chain_head SET sequence = ?1, digest = ?2
         WHERE singleton = 1 AND sequence = ?3 AND digest = ?4",
        params![
            to_i64(sequence, "event sequence")?,
            event_digest.as_str(),
            to_i64(head.sequence, "event sequence")?,
            head.digest.as_str()
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::Corrupt(
            "event-chain CAS unexpectedly failed under writer fence".to_owned(),
        ));
    }
    Ok(EventReceiptV1 {
        sequence,
        event_id: event.event_id,
        previous_digest: head.digest,
        event_digest,
        entity_revision,
        state_digest,
    })
}

fn event_digest_for(input: &EventHashInputV1<'_>) -> Result<StoreDigestV1, StoreError> {
    digest_jcs("ag-store-event-v1", input)
}

fn chain_head_from_connection(connection: &Connection) -> Result<ChainHeadV1, StoreError> {
    let (sequence, digest): (i64, String) = connection.query_row(
        "SELECT sequence, digest FROM chain_head WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(ChainHeadV1 {
        sequence: to_u64(sequence, "chain-head sequence")?,
        digest: StoreDigestV1::from_str(&digest)?,
    })
}

fn read_store_identity(connection: &Connection) -> Result<StoreIdentityV1, StoreError> {
    let identity = connection.query_row(
        "SELECT application_id, application_name, schema_name, schema_version, schema_digest
         FROM store_identity WHERE singleton = 1",
        [],
        |row| {
            let digest: String = row.get(4)?;
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
                digest,
            ))
        },
    )?;
    let identity = StoreIdentityV1 {
        application_id: identity.0,
        application_name: identity.1,
        schema_name: identity.2,
        schema_version: identity.3,
        schema_digest: StoreDigestV1::from_str(&identity.4)?,
    };
    identity.validate()?;
    let pragma_application: u32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let pragma_version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if pragma_application != identity.application_id || pragma_version != identity.schema_version {
        return Err(StoreError::Corrupt(
            "SQLite pragma identity disagrees with stored identity".to_owned(),
        ));
    }
    Ok(identity)
}

#[allow(clippy::too_many_lines)]
fn verify_chain_connection(
    connection: &Connection,
    identity: &StoreIdentityV1,
) -> Result<ChainHeadV1, StoreError> {
    let mut expected_previous = genesis_digest(identity)?;
    let mut expected_sequence = 1_u64;
    let mut statement = connection.prepare(
        "SELECT sequence, event_id, entity_id, event_kind, occurred_at_unix_ms,
                previous_digest, payload_jcs, payload_digest, state_digest, event_digest
         FROM events ORDER BY sequence",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let sequence = to_u64(row.get::<_, i64>(0)?, "event sequence")?;
        if sequence != expected_sequence {
            return Err(StoreError::Corrupt(format!(
                "event sequence gap: expected {expected_sequence}, found {sequence}"
            )));
        }
        let event_id: String = row.get(1)?;
        let entity_id: String = row.get(2)?;
        let event_kind: String = row.get(3)?;
        let occurred_at_unix_ms: i64 = row.get(4)?;
        let previous_digest = StoreDigestV1::from_str(&row.get::<_, String>(5)?)?;
        let payload_jcs: Vec<u8> = row.get(6)?;
        verify_canonical_stored_json(&payload_jcs, "event payload")?;
        let payload_digest = StoreDigestV1::from_str(&row.get::<_, String>(7)?)?;
        let state_digest = StoreDigestV1::from_str(&row.get::<_, String>(8)?)?;
        let event_digest = StoreDigestV1::from_str(&row.get::<_, String>(9)?)?;
        if previous_digest != expected_previous {
            return Err(StoreError::Corrupt(format!(
                "event {sequence} predecessor does not match chain"
            )));
        }
        if StoreDigestV1::hash("ag-store-event-payload-v1", &payload_jcs) != payload_digest {
            return Err(StoreError::Corrupt(format!(
                "event {sequence} payload digest mismatch"
            )));
        }
        let input = EventHashInputV1 {
            sequence,
            event_id: &event_id,
            entity_id: &entity_id,
            event_kind: &event_kind,
            occurred_at_unix_ms,
            previous_digest: &previous_digest,
            payload_digest: &payload_digest,
            state_digest: &state_digest,
        };
        if event_digest_for(&input)? != event_digest {
            return Err(StoreError::Corrupt(format!(
                "event {sequence} digest mismatch"
            )));
        }
        expected_previous = event_digest;
        expected_sequence += 1;
    }
    drop(rows);
    drop(statement);

    let head = chain_head_from_connection(connection)?;
    if head.sequence != expected_sequence - 1 || head.digest != expected_previous {
        return Err(StoreError::Corrupt(
            "persisted chain head does not match event chain".to_owned(),
        ));
    }
    let mut states = connection.prepare(
        "SELECT entity_id, state_jcs, state_digest, last_event_sequence, last_event_digest
         FROM materialized_state",
    )?;
    let mut rows = states.query([])?;
    while let Some(row) = rows.next()? {
        let entity_id: String = row.get(0)?;
        let state_jcs: Vec<u8> = row.get(1)?;
        verify_canonical_stored_json(&state_jcs, "materialized state")?;
        let state_digest = StoreDigestV1::from_str(&row.get::<_, String>(2)?)?;
        let sequence: i64 = row.get(3)?;
        let event_digest = StoreDigestV1::from_str(&row.get::<_, String>(4)?)?;
        if StoreDigestV1::hash("ag-store-materialized-state-v1", &state_jcs) != state_digest {
            return Err(StoreError::Corrupt(format!(
                "materialized state digest mismatch for {entity_id:?}"
            )));
        }
        let linked: Option<(String, String, String)> = connection
            .query_row(
                "SELECT entity_id, state_digest, event_digest FROM events WHERE sequence = ?1",
                [sequence],
                |event| Ok((event.get(0)?, event.get(1)?, event.get(2)?)),
            )
            .optional()?;
        if linked
            != Some((
                entity_id.clone(),
                state_digest.to_string(),
                event_digest.to_string(),
            ))
        {
            return Err(StoreError::Corrupt(format!(
                "materialized state event binding mismatch for {entity_id:?}"
            )));
        }
    }
    Ok(head)
}

fn materialized_revision(connection: &Connection, entity_id: &str) -> Result<u64, StoreError> {
    let revision = connection
        .query_row(
            "SELECT revision FROM materialized_state WHERE entity_id = ?1",
            [entity_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    to_u64(revision, "materialized revision")
}

fn event_receipt_by_sequence(
    connection: &Connection,
    sequence: i64,
) -> Result<EventReceiptV1, StoreError> {
    let (event_id, entity_id, previous, event_digest, state_digest): (
        String,
        String,
        String,
        String,
        String,
    ) = connection.query_row(
        "SELECT event_id, entity_id, previous_digest, event_digest, state_digest
         FROM events WHERE sequence = ?1",
        [sequence],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let entity_revision: i64 = connection.query_row(
        "SELECT COUNT(*) FROM events WHERE entity_id = ?1 AND sequence <= ?2",
        params![entity_id, sequence],
        |row| row.get(0),
    )?;
    Ok(EventReceiptV1 {
        sequence: to_u64(sequence, "event sequence")?,
        event_id,
        previous_digest: StoreDigestV1::from_str(&previous)?,
        event_digest: StoreDigestV1::from_str(&event_digest)?,
        entity_revision: to_u64(entity_revision, "entity revision")?,
        state_digest: StoreDigestV1::from_str(&state_digest)?,
    })
}

fn active_backup_cut(connection: &Connection) -> Result<Option<String>, StoreError> {
    connection
        .query_row(
            "SELECT cut_id FROM backup_cuts WHERE state IN ('preparing', 'prepared', 'sealed')",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)
}

fn ensure_no_backup_barrier(connection: &Connection) -> Result<(), StoreError> {
    if let Some(cut_id) = active_backup_cut(connection)? {
        return Err(StoreError::BackupBarrierActive(cut_id));
    }
    Ok(())
}

fn backup_state_in_transaction(
    transaction: &Transaction<'_>,
    cut_id: &str,
) -> Result<BackupCutStateV1, StoreError> {
    let state = transaction
        .query_row(
            "SELECT state FROM backup_cuts WHERE cut_id = ?1",
            [cut_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StoreError::BackupCutNotFound(cut_id.to_owned()))?;
    BackupCutStateV1::from_str(&state)
}

fn build_backup_manifest_from_connection(
    connection: &Connection,
    cut_id: &str,
) -> Result<BackupCutManifestV1, StoreError> {
    let (authority_domain, epoch, barrier, state): (String, i64, String, String) = connection
        .query_row(
            "SELECT authority_domain, epoch, quiescence_barrier_id, state
             FROM backup_cuts WHERE cut_id = ?1",
            [cut_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::BackupCutNotFound(cut_id.to_owned()))?;
    let state = BackupCutStateV1::from_str(&state)?;
    if !matches!(
        state,
        BackupCutStateV1::Prepared | BackupCutStateV1::Sealed | BackupCutStateV1::Released
    ) {
        return Err(StoreError::BackupNotPrepared);
    }
    let mut statement = connection.prepare(
        "SELECT participant, checkpoint_jcs, prepared_event_sequence, prepared_event_digest
         FROM backup_participants WHERE cut_id = ?1 ORDER BY participant",
    )?;
    let rows = statement.query_map([cut_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<Vec<u8>>>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut by_role = BTreeMap::new();
    for row in rows {
        let (role, checkpoint_jcs, sequence, receipt_digest) = row?;
        let role = BackupParticipantV1::from_str(&role)?;
        let checkpoint_jcs = checkpoint_jcs.ok_or(StoreError::BackupNotPrepared)?;
        let checkpoint: BackupCheckpointV1 = serde_json::from_slice(&checkpoint_jcs)
            .map_err(|error| StoreError::InvalidStoredJson(error.to_string()))?;
        if checkpoint.participant != role {
            return Err(StoreError::Corrupt(
                "checkpoint participant disagrees with table key".to_owned(),
            ));
        }
        by_role.insert(
            role,
            PreparedParticipantV1 {
                checkpoint,
                prepared_event_sequence: to_u64(
                    sequence.ok_or(StoreError::BackupNotPrepared)?,
                    "prepared event sequence",
                )?,
                prepared_event_digest: StoreDigestV1::from_str(
                    &receipt_digest.ok_or(StoreError::BackupNotPrepared)?,
                )?,
            },
        );
    }
    let participants: Vec<_> = REQUIRED_BACKUP_PARTICIPANTS
        .into_iter()
        .map(|role| by_role.remove(&role).ok_or(StoreError::BackupNotPrepared))
        .collect::<Result<_, _>>()?;
    if !by_role.is_empty() {
        return Err(StoreError::InvalidBackupParticipants);
    }
    Ok(BackupCutManifestV1 {
        version: "backup-cut/v1".to_owned(),
        cut_id: cut_id.to_owned(),
        authority_domain: AuthorityDomainId::parse(&authority_domain).map_err(|error| {
            StoreError::Corrupt(format!("invalid stored authority domain: {error}"))
        })?,
        epoch: EpochId::new(to_u64(epoch, "backup epoch")?)
            .map_err(|error| StoreError::Corrupt(format!("invalid stored epoch: {error}")))?,
        quiescence_barrier_id: barrier,
        participants,
    })
}

fn backup_cut_from_connection(
    connection: &Connection,
    cut_id: &str,
) -> Result<BackupCutRecordV1, StoreError> {
    let row = connection
        .query_row(
            "SELECT state, manifest_digest, release_bundle_digest, abort_reason,
                    (SELECT COUNT(*) FROM backup_participants p
                     WHERE p.cut_id = backup_cuts.cut_id AND checkpoint_digest IS NOT NULL)
             FROM backup_cuts WHERE cut_id = ?1",
            [cut_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::BackupCutNotFound(cut_id.to_owned()))?;
    Ok(BackupCutRecordV1 {
        cut_id: cut_id.to_owned(),
        state: BackupCutStateV1::from_str(&row.0)?,
        prepared_participants: u8::try_from(row.4).map_err(|_| {
            StoreError::Corrupt("prepared participant count does not fit u8".to_owned())
        })?,
        manifest_digest: row
            .1
            .map(|digest| StoreDigestV1::from_str(&digest))
            .transpose()?,
        release_bundle_digest: row
            .2
            .map(|digest| {
                Digest::parse(&digest).map_err(|_| StoreError::InvalidDigest(digest.clone()))
            })
            .transpose()?,
        abort_reason: row.3,
    })
}

fn verify_blob_file(path: &Path, expected: &BlobDescriptorV1) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.mode() & 0o222 != 0 {
        return Err(StoreError::Corrupt(format!(
            "blob {} is not an immutable, singly-linked regular file",
            expected.digest
        )));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let actual = hash_blob_reader(&mut file, expected.byte_length)?;
    if actual != *expected {
        return Err(StoreError::BlobMismatch {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

fn copy_and_hash_blob<R: Read>(
    reader: &mut R,
    destination: &mut File,
    expected_size: u64,
) -> Result<BlobDescriptorV1, StoreError> {
    let mut hasher = Sha256::new();
    let mut actual_size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let maximum_observed = expected_size.saturating_add(1);
        let remaining = maximum_observed.saturating_sub(actual_size);
        if remaining == 0 {
            break;
        }
        let read_bound = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = reader.read(&mut buffer[..read_bound])?;
        if read == 0 {
            break;
        }
        actual_size = actual_size
            .checked_add(read as u64)
            .ok_or_else(|| StoreError::Corrupt("blob byte count overflow".to_owned()))?;
        hasher.update(&buffer[..read]);
        io::Write::write_all(destination, &buffer[..read])?;
        if actual_size > expected_size {
            break;
        }
    }
    Ok(BlobDescriptorV1 {
        digest: digest_from_hasher(hasher),
        byte_length: actual_size,
    })
}

fn hash_blob_reader<R: Read>(
    reader: &mut R,
    expected_size: u64,
) -> Result<BlobDescriptorV1, StoreError> {
    let mut hasher = Sha256::new();
    let mut actual_size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let maximum_observed = expected_size.saturating_add(1);
        let remaining = maximum_observed.saturating_sub(actual_size);
        if remaining == 0 {
            break;
        }
        let read_bound = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = reader.read(&mut buffer[..read_bound])?;
        if read == 0 {
            break;
        }
        actual_size = actual_size
            .checked_add(read as u64)
            .ok_or_else(|| StoreError::Corrupt("blob byte count overflow".to_owned()))?;
        hasher.update(&buffer[..read]);
        if actual_size > expected_size {
            break;
        }
    }
    Ok(BlobDescriptorV1 {
        digest: digest_from_hasher(hasher),
        byte_length: actual_size,
    })
}

fn digest_from_hasher(hasher: Sha256) -> Digest {
    let digest = hasher.finalize();
    Digest::parse(&format!("sha256:{digest:x}"))
        .expect("SHA-256 output is a valid canonical digest")
}

fn digest_jcs<T: Serialize>(domain: &str, value: &T) -> Result<StoreDigestV1, StoreError> {
    Ok(StoreDigestV1::hash(domain, &jcs(value)?))
}

fn jcs<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    JcsDocument::canonicalize(value)
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| StoreError::Canonicalization(error.to_string()))
}

fn verify_canonical_stored_json(bytes: &[u8], label: &str) -> Result<(), StoreError> {
    JcsDocument::from_canonical_bytes(bytes).map_err(|error| {
        StoreError::Corrupt(format!("{label} is not strict canonical JSON: {error}"))
    })?;
    Ok(())
}

fn genesis_digest(identity: &StoreIdentityV1) -> Result<StoreDigestV1, StoreError> {
    digest_jcs("ag-store-event-chain-genesis-v1", identity)
}

fn backup_entity_id(cut_id: &str) -> String {
    format!("backup-cut:{cut_id}")
}

fn validate_coherent_captures(captures: &[SealedDatabaseCaptureV1]) -> Result<(), StoreError> {
    if captures.len() != REQUIRED_BACKUP_PARTICIPANTS.len() {
        return Err(StoreError::IncoherentBackupBundle);
    }
    let first = captures.first().ok_or(StoreError::IncoherentBackupBundle)?;
    let expected_checkpoints = checkpoint_bodies(&first.cut_manifest)?;
    let mut captured_roles = BTreeSet::new();
    let mut store_identities = BTreeSet::new();
    for capture in captures {
        capture.store_identity.validate()?;
        if capture.schema != "ag-store-sealed-database-capture-v1"
            || capture.database.byte_length == 0
            || capture.cut_id != capture.cut_manifest.cut_id
            || capture.cut_manifest.version != "backup-cut/v1"
            || capture.cut_manifest.cut_id != first.cut_manifest.cut_id
            || capture.cut_manifest.authority_domain != first.cut_manifest.authority_domain
            || capture.cut_manifest.epoch != first.cut_manifest.epoch
            || capture.cut_manifest.quiescence_barrier_id
                != first.cut_manifest.quiescence_barrier_id
            || digest_jcs("ag-store-backup-manifest-v1", &capture.cut_manifest)?
                != capture.manifest_digest
            || !captured_roles.insert(capture.participant)
            || !store_identities.insert((
                capture.store_identity.application_id,
                capture.store_identity.application_name.clone(),
            ))
        {
            return Err(StoreError::IncoherentBackupBundle);
        }
        let checkpoints = checkpoint_bodies(&capture.cut_manifest)?;
        if checkpoints != expected_checkpoints {
            return Err(StoreError::IncoherentBackupBundle);
        }
        let own = checkpoints
            .get(&capture.participant)
            .ok_or(StoreError::IncoherentBackupBundle)?;
        if own.component_identity != capture.component_identity
            || own.blob_root != capture.blob_root
            || capture.captured_chain_head.sequence < own.chain_head.sequence
        {
            return Err(StoreError::IncoherentBackupBundle);
        }
    }
    if captured_roles != REQUIRED_BACKUP_PARTICIPANTS.into_iter().collect() {
        return Err(StoreError::IncoherentBackupBundle);
    }
    Ok(())
}

fn checkpoint_bodies(
    manifest: &BackupCutManifestV1,
) -> Result<BTreeMap<BackupParticipantV1, BackupCheckpointV1>, StoreError> {
    if manifest.participants.len() != REQUIRED_BACKUP_PARTICIPANTS.len() {
        return Err(StoreError::IncoherentBackupBundle);
    }
    let mut checkpoints = BTreeMap::new();
    for prepared in &manifest.participants {
        let role = prepared.checkpoint.participant;
        if checkpoints
            .insert(role, prepared.checkpoint.clone())
            .is_some()
        {
            return Err(StoreError::IncoherentBackupBundle);
        }
    }
    if checkpoints.keys().copied().collect::<BTreeSet<_>>()
        != REQUIRED_BACKUP_PARTICIPANTS.into_iter().collect()
    {
        return Err(StoreError::IncoherentBackupBundle);
    }
    Ok(checkpoints)
}

const fn required_backup_participant_count() -> u8 {
    // The fixed protocol set is deliberately tiny and compile-time known.
    3
}

fn validate_identifier(field: &'static str, value: &str, maximum: usize) -> Result<(), StoreError> {
    if value.is_empty() {
        return Err(StoreError::InvalidIdentifier {
            field,
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > maximum {
        return Err(StoreError::InvalidIdentifier {
            field,
            reason: format!("exceeds {maximum} bytes"),
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(StoreError::InvalidIdentifier {
            field,
            reason: "contains non-canonical characters".to_owned(),
        });
    }
    Ok(())
}

fn absolute_normalized_path(path: &Path) -> Result<PathBuf, StoreError> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(StoreError::InvalidIdentity(
            "store paths may not contain dot components".to_owned(),
        ));
    }
    Ok(path)
}

fn prepare_database_internal(
    path: &Path,
    custody: Option<DatabaseFileCustodyV1>,
) -> Result<PreparedDatabaseV1, StoreError> {
    let path = absolute_normalized_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        StoreError::InvalidIdentity("database path must have a parent".to_owned())
    })?;
    create_and_validate_directory(parent)?;

    let mut existing_options = OpenOptions::new();
    existing_options
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let (file, created_new) = match existing_options.open(&path) {
        Ok(file) => (file, false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut create_options = OpenOptions::new();
            let file = create_options
                .read(true)
                .write(true)
                .create_new(true)
                .mode(custody.map_or(0o600, |expected| expected.mode))
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)?;
            (file, true)
        }
        Err(error) => return Err(error.into()),
    };

    if created_new {
        let mode = custody.map_or(0o600, |expected| expected.mode);
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(StoreError::DatabaseCustodyMismatch(path));
    }
    let observed_mode = metadata.mode() & 0o7777;
    if let Some(expected) = custody
        && (metadata.uid() != expected.uid
            || metadata.gid() != expected.gid
            || observed_mode != expected.mode)
    {
        return Err(StoreError::DatabaseCustodyMismatch(path));
    }
    let pathname = fs::symlink_metadata(&path)?;
    if !pathname.file_type().is_file()
        || pathname.nlink() != 1
        || pathname.dev() != metadata.dev()
        || pathname.ino() != metadata.ino()
    {
        return Err(StoreError::PreparedDatabaseDrift(path));
    }

    let prepared = PreparedDatabaseV1 {
        path,
        file,
        created_new,
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: observed_mode,
    };
    prepared.revalidate()?;
    Ok(prepared)
}

fn create_and_validate_directory(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || fs::canonicalize(path)? != path {
        return Err(StoreError::InvalidIdentity(format!(
            "store directory must be an absolute canonical directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn writer_lock_path(database_path: &Path) -> Result<PathBuf, StoreError> {
    let file_name = database_path
        .file_name()
        .ok_or_else(|| StoreError::InvalidIdentity("database path must name a file".to_owned()))?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".writer.lock");
    Ok(database_path.with_file_name(lock_name))
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| {
        StoreError::Corrupt(format!(
            "{field} exceeds SQLite's signed integer representation"
        ))
    })
}

fn to_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("{field} is negative")))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use tempfile::TempDir;

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct TestState {
        value: String,
    }

    struct Fixture {
        temp: TempDir,
        database: PathBuf,
        blobs: PathBuf,
        identity: StoreIdentityV1,
    }

    impl Fixture {
        fn new() -> Self {
            Self::new_for(0x4147_0001, "test-agd")
        }

        fn new_for(application_id: u32, application_name: &str) -> Self {
            let temp = tempfile::tempdir().unwrap();
            Self {
                database: temp.path().join("store.sqlite3"),
                blobs: temp.path().join("blobs"),
                identity: StoreIdentityV1::current(application_id, application_name).unwrap(),
                temp,
            }
        }

        fn writer(label: &str) -> WriterIdentityV1 {
            WriterIdentityV1 {
                writer_id: format!("writer:{label}"),
                principal_digest: Digest::hash_domain("principal", label.as_bytes()),
                process_nonce: format!("nonce:{label}"),
                claimed_at_unix_ms: 1,
            }
        }

        fn activation(label: &str) -> StoreActivationIdentityV1 {
            StoreActivationIdentityV1 {
                schema: StoreActivationIdentityV1::SCHEMA.to_owned(),
                authority_domain: AuthorityDomainId::new(format!("domain:{label}")).unwrap(),
                epoch: EpochId::new(7).unwrap(),
                config_identity: Digest::hash_domain("config", label.as_bytes()),
                security_profile_identity: Digest::hash_domain("profile", b"production"),
                build_identity: Digest::hash_domain("build", b"test-build"),
                authority_catalog_identity: None,
            }
        }

        fn database_custody(&self) -> DatabaseFileCustodyV1 {
            let metadata = fs::metadata(self.temp.path()).unwrap();
            DatabaseFileCustodyV1 {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o600,
            }
        }

        fn open(&self, label: &str) -> Store {
            Store::open(
                &self.database,
                &self.blobs,
                self.identity.clone(),
                &Self::writer(label),
            )
            .unwrap()
        }

        fn open_activated(
            &self,
            writer_label: &str,
            activation: &StoreActivationIdentityV1,
        ) -> Result<Store, StoreError> {
            Store::open_activated(
                &self.database,
                &self.blobs,
                self.identity.clone(),
                activation,
                &Self::writer(writer_label),
            )
        }
    }

    fn event(id: &str, entity: &str, value: &str) -> NewEventV1<TestState> {
        NewEventV1 {
            event_id: id.to_owned(),
            entity_id: entity.to_owned(),
            event_kind: "test.changed.v1".to_owned(),
            occurred_at_unix_ms: 10,
            payload: TestState {
                value: value.to_owned(),
            },
        }
    }

    #[test]
    fn activated_store_reopens_only_with_exact_durable_identity() {
        let fixture = Fixture::new();
        let activation = Fixture::activation("stable");
        let store = fixture
            .open_activated("first", &activation)
            .expect("enroll activation");
        let enrolled = store.activation().expect("activation record").clone();
        assert_eq!(enrolled.identity, activation);
        drop(store);

        let reopened = fixture
            .open_activated("second", &activation)
            .expect("reopen exact activation");
        assert_eq!(reopened.activation(), Some(&enrolled));
    }

    #[test]
    fn prepared_database_supports_normal_new_and_exact_reopen() {
        let fixture = Fixture::new();
        let activation = Fixture::activation("prepared");
        let prepared = prepare_database(&fixture.database, fixture.database_custody())
            .expect("prepare absent database");
        let store = Store::open_activated_prepared(
            prepared,
            &fixture.blobs,
            fixture.identity.clone(),
            &activation,
            &Fixture::writer("prepared-first"),
        )
        .expect("initialize exact newly-created inode");
        drop(store);

        let prepared = prepare_database(&fixture.database, fixture.database_custody())
            .expect("prepare existing database");
        let reopened = Store::open_activated_prepared(
            prepared,
            &fixture.blobs,
            fixture.identity.clone(),
            &activation,
            &Fixture::writer("prepared-second"),
        )
        .expect("reopen initialized inode");
        assert_eq!(reopened.activation().unwrap().identity, activation);
    }

    #[test]
    fn preexisting_empty_database_is_never_initialized() {
        let fixture = Fixture::new();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&fixture.database)
            .expect("attacker creates empty file");

        let error = Store::open(
            &fixture.database,
            &fixture.blobs,
            fixture.identity.clone(),
            &Fixture::writer("empty-existing"),
        )
        .err()
        .expect("existing empty file must fail");
        assert!(matches!(error, StoreError::UnrecognizedExistingDatabase(_)));
        assert_eq!(fs::metadata(&fixture.database).unwrap().len(), 0);
    }

    #[test]
    fn unrelated_sqlite_database_is_rejected_without_ag_schema_installation() {
        let fixture = Fixture::new();
        let unrelated = Connection::open(&fixture.database).expect("create unrelated SQLite");
        unrelated
            .execute("CREATE TABLE unrelated(value TEXT)", [])
            .expect("create unrelated schema");
        drop(unrelated);

        let error = Store::open(
            &fixture.database,
            &fixture.blobs,
            fixture.identity.clone(),
            &Fixture::writer("unrelated-existing"),
        )
        .err()
        .expect("unrelated SQLite must fail");
        assert!(matches!(error, StoreError::UnrecognizedExistingDatabase(_)));
        let connection = Connection::open(&fixture.database).expect("reinspect unrelated SQLite");
        let ag_tables: u32 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'store_identity'",
                [],
                |row| row.get(0),
            )
            .expect("inspect schema");
        assert_eq!(ag_tables, 0);
    }

    #[test]
    fn prepared_path_inode_substitution_is_rejected() {
        let fixture = Fixture::new();
        let prepared = prepare_database(&fixture.database, fixture.database_custody())
            .expect("prepare database");
        let displaced = fixture.temp.path().join("displaced.sqlite3");
        fs::rename(&fixture.database, &displaced).expect("displace prepared inode");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&fixture.database)
            .expect("substitute same-custody inode");

        let error = Store::open_activated_prepared(
            prepared,
            &fixture.blobs,
            fixture.identity.clone(),
            &Fixture::activation("substitution"),
            &Fixture::writer("substitution"),
        )
        .err()
        .expect("path substitution must fail");
        assert!(matches!(error, StoreError::PreparedDatabaseDrift(_)));
    }

    #[test]
    fn every_authority_activation_drift_fails_closed() {
        let fixture = Fixture::new();
        let activation = Fixture::activation("stable");
        drop(
            fixture
                .open_activated("first", &activation)
                .expect("enroll activation"),
        );

        let mut hostile = Vec::new();
        let mut changed = activation.clone();
        changed.authority_domain = AuthorityDomainId::new("domain:attacker").unwrap();
        hostile.push(changed);
        let mut changed = activation.clone();
        changed.epoch = EpochId::new(8).unwrap();
        hostile.push(changed);
        let mut changed = activation.clone();
        changed.config_identity = Digest::hash_domain("config", b"attacker");
        hostile.push(changed);
        let mut changed = activation.clone();
        changed.security_profile_identity = Digest::hash_domain("profile", b"development");
        hostile.push(changed);
        let mut changed = activation.clone();
        changed.build_identity = Digest::hash_domain("build", b"attacker-build");
        hostile.push(changed);
        let mut changed = activation.clone();
        changed.authority_catalog_identity = Some(Digest::hash_domain("catalog", b"attacker"));
        hostile.push(changed);

        for (index, changed) in hostile.iter().enumerate() {
            let error = fixture
                .open_activated(&format!("hostile-{index}"), changed)
                .err()
                .expect("activation drift must fail");
            assert!(
                matches!(error, StoreError::ActivationIdentityMismatch { .. }),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn existing_unactivated_store_is_not_silently_enrolled() {
        let fixture = Fixture::new();
        drop(fixture.open("offline-initializer"));
        let generic_error = Store::open(
            &fixture.database,
            &fixture.blobs,
            fixture.identity.clone(),
            &Fixture::writer("generic-reopen"),
        )
        .err()
        .expect("generic reopen must reject missing activation");
        assert!(matches!(
            generic_error,
            StoreError::ActivationIdentityMissing
        ));
        let error = fixture
            .open_activated("daemon", &Fixture::activation("late"))
            .err()
            .expect("online startup must not enroll an existing store");
        assert!(matches!(error, StoreError::ActivationIdentityMissing));
    }

    #[test]
    fn generic_store_open_cannot_bypass_an_enrolled_activation() {
        let fixture = Fixture::new();
        let activation = Fixture::activation("stable");
        drop(
            fixture
                .open_activated("daemon", &activation)
                .expect("enroll activation"),
        );
        let error = Store::open(
            &fixture.database,
            &fixture.blobs,
            fixture.identity.clone(),
            &Fixture::writer("generic-bypass"),
        )
        .err()
        .expect("generic open must not bypass activation");
        assert!(matches!(error, StoreError::ActivationIdentityRequired));
    }

    #[test]
    fn activation_digest_tampering_is_detected_before_writer_claim() {
        let fixture = Fixture::new();
        let activation = Fixture::activation("stable");
        drop(
            fixture
                .open_activated("first", &activation)
                .expect("enroll activation"),
        );
        let connection = Connection::open(&fixture.database).expect("open database directly");
        connection
            .execute(
                "UPDATE store_activation SET activation_digest = ?1 WHERE singleton = 1",
                [Digest::hash_domain("attacker", b"forged").as_str()],
            )
            .expect("tamper activation digest");
        drop(connection);

        let error = fixture
            .open_activated("second", &activation)
            .err()
            .expect("tampering must fail");
        assert!(matches!(error, StoreError::Corrupt(_)));
    }

    #[test]
    fn internally_consistent_activation_replacement_still_fails_expected_identity() {
        let fixture = Fixture::new();
        let activation = Fixture::activation("stable");
        drop(
            fixture
                .open_activated("first", &activation)
                .expect("enroll activation"),
        );
        let attacker = Fixture::activation("attacker");
        let attacker_jcs = jcs(&attacker).expect("canonical attacker identity");
        let attacker_digest = StoreDigestV1::hash("ag-store-activation-identity-v1", &attacker_jcs);
        let connection = Connection::open(&fixture.database).expect("open database directly");
        connection
            .execute(
                "UPDATE store_activation
                 SET activation_jcs = ?1, activation_digest = ?2
                 WHERE singleton = 1",
                params![attacker_jcs, attacker_digest.as_str()],
            )
            .expect("replace activation record");
        drop(connection);

        let error = fixture
            .open_activated("second", &activation)
            .err()
            .expect("replacement must fail");
        assert!(matches!(
            error,
            StoreError::ActivationIdentityMismatch { .. }
        ));
    }

    #[test]
    fn distinct_event_pair_commits_both_or_neither() {
        let fixture = Fixture::new();
        let mut store = fixture.open("pair");
        let first_state = TestState {
            value: "first".to_owned(),
        };
        let second_state = TestState {
            value: "second".to_owned(),
        };
        let head = store.chain_head().unwrap();
        assert!(matches!(
            store.append_distinct_event_pair(
                event("pair-first-failed", "pair:first", "first"),
                &first_state,
                0,
                event("pair-second-failed", "pair:second", "second"),
                &second_state,
                1,
            ),
            Err(StoreError::RevisionConflict { .. })
        ));
        assert!(
            store
                .materialized_state::<TestState>("pair:first")
                .unwrap()
                .is_none()
        );
        assert_eq!(store.chain_head().unwrap(), head);

        store
            .append_distinct_event_pair(
                event("pair-first", "pair:first", "first"),
                &first_state,
                0,
                event("pair-second", "pair:second", "second"),
                &second_state,
                0,
            )
            .unwrap();
        assert_eq!(
            store
                .materialized_state::<TestState>("pair:first")
                .unwrap()
                .unwrap()
                .state,
            first_state
        );
        assert_eq!(
            store
                .materialized_state::<TestState>("pair:second")
                .unwrap()
                .unwrap()
                .state,
            second_state
        );
    }

    #[test]
    fn exact_identity_is_required_on_reopen() {
        let fixture = Fixture::new();
        drop(fixture.open("first"));

        let mut wrong = fixture.identity.clone();
        wrong.application_name = "other-component".to_owned();
        let result = Store::open(
            &fixture.database,
            &fixture.blobs,
            wrong,
            &Fixture::writer("second"),
        );
        assert!(matches!(result, Err(StoreError::IdentityMismatch { .. })));
    }

    #[test]
    fn writer_fence_rejects_second_live_writer_and_releases_on_drop() {
        let fixture = Fixture::new();
        let activation = Fixture::activation("writer-fence");
        let first = fixture.open_activated("first", &activation).unwrap();
        let second = fixture.open_activated("second", &activation);
        assert!(matches!(second, Err(StoreError::WriterFenced(_))));
        drop(first);
        fixture.open_activated("third", &activation).unwrap();
    }

    #[test]
    fn event_and_materialized_state_commit_together() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let first_state = TestState {
            value: "one".to_owned(),
        };
        let first = store
            .append_event(event("event:1", "entity:1", "one"), &first_state, 0)
            .unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.entity_revision, 1);

        let second_state = TestState {
            value: "two".to_owned(),
        };
        let second = store
            .append_event(event("event:2", "entity:1", "two"), &second_state, 1)
            .unwrap();
        assert_eq!(second.previous_digest, first.event_digest);
        assert_eq!(second.entity_revision, 2);

        let state: MaterializedStateV1<TestState> =
            store.materialized_state("entity:1").unwrap().unwrap();
        assert_eq!(state.state, second_state);
        assert_eq!(state.revision, 2);
        assert_eq!(store.verify_chain().unwrap().sequence, 2);
    }

    #[test]
    fn revision_conflict_rolls_back_event_append() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let state = TestState {
            value: "one".to_owned(),
        };
        store
            .append_event(event("event:1", "entity:1", "one"), &state, 0)
            .unwrap();
        let result = store.append_event(event("event:2", "entity:1", "two"), &state, 0);
        assert!(matches!(result, Err(StoreError::RevisionConflict { .. })));
        assert_eq!(store.chain_head().unwrap().sequence, 1);
    }

    #[test]
    fn entity_listing_is_literal_bounded_and_deterministic() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let state = TestState {
            value: "state".to_owned(),
        };
        for (event_id, entity_id) in [
            ("event:3", "proposal:z"),
            ("event:1", "proposal:a"),
            ("event:2", "proposal:_literal"),
            ("event:4", "session:a"),
        ] {
            store
                .append_event(event(event_id, entity_id, "value"), &state, 0)
                .unwrap();
        }
        assert_eq!(
            store.entity_ids("proposal:", 2).unwrap(),
            ["proposal:_literal", "proposal:a"]
        );
        assert_eq!(
            store
                .entity_ids_after("proposal:", Some("proposal:_literal"), 2)
                .unwrap(),
            ["proposal:a", "proposal:z"]
        );
        assert_eq!(
            store
                .entity_ids_after("proposal:", Some("proposal:z"), 2)
                .unwrap(),
            Vec::<String>::new()
        );
        assert!(matches!(
            store.entity_ids_after("proposal:", Some("session:a"), 2),
            Err(StoreError::InvalidIdentifier {
                field: "entity_cursor",
                ..
            })
        ));
        assert!(matches!(
            store.entity_ids("proposal:", 0),
            Err(StoreError::InvalidIdentifier {
                field: "entity_limit",
                ..
            })
        ));
    }

    #[test]
    fn immutable_blob_install_verifies_existing_content() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let bytes = b"immutable artifact";
        let descriptor = BlobDescriptorV1 {
            digest: Digest::hash_bytes(bytes),
            byte_length: bytes.len() as u64,
        };
        assert_eq!(
            store
                .install_blob(&descriptor, &mut Cursor::new(bytes), 10)
                .unwrap(),
            BlobInstallResult::Installed
        );
        assert_eq!(
            store
                .install_blob(&descriptor, &mut Cursor::new(bytes), 11)
                .unwrap(),
            BlobInstallResult::AlreadyPresent
        );
        assert_ne!(store.blob_root().unwrap(), StoreDigestV1::hash("x", b""));
    }

    #[test]
    fn blob_reads_reverify_exact_custody_and_enforce_the_callers_bound() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let bytes = b"bounded admitted artifact";
        let descriptor = BlobDescriptorV1 {
            digest: Digest::hash_bytes(bytes),
            byte_length: bytes.len() as u64,
        };
        store
            .install_blob(&descriptor, &mut Cursor::new(bytes), 10)
            .unwrap();

        assert_eq!(
            store
                .read_blob(&descriptor.digest, descriptor.byte_length)
                .unwrap(),
            bytes
        );
        assert!(matches!(
            store.read_blob(&descriptor.digest, descriptor.byte_length - 1),
            Err(StoreError::BlobReadLimitExceeded {
                digest,
                actual,
                maximum,
            }) if digest == descriptor.digest
                && actual == descriptor.byte_length
                && maximum == descriptor.byte_length - 1
        ));

        let path = store.blob_path(&descriptor.digest);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.read_blob(&descriptor.digest, descriptor.byte_length),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn blob_mismatch_is_never_cataloged() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let descriptor = BlobDescriptorV1 {
            digest: Digest::hash_bytes(b"right"),
            byte_length: 5,
        };
        let result = store.install_blob(&descriptor, &mut Cursor::new(b"wrong"), 10);
        assert!(matches!(result, Err(StoreError::BlobMismatch { .. })));
        assert_eq!(
            store.blob_root().unwrap(),
            StoreDigestV1::hash("ag-store-blob-root-v1", b"[]")
        );

        let mut oversized = Cursor::new(vec![b'x'; 1024 * 1024]);
        let result = store.install_blob(&descriptor, &mut oversized, 11);
        assert!(matches!(result, Err(StoreError::BlobMismatch { .. })));
        assert_eq!(oversized.position(), descriptor.byte_length + 1);
    }

    fn begin_request() -> BeginBackupCutV1 {
        BeginBackupCutV1 {
            cut_id: "cut:1".to_owned(),
            authority_domain: AuthorityDomainId::new("domain:1").unwrap(),
            epoch: EpochId::new(7).unwrap(),
            quiescence_barrier_id: "barrier:1".to_owned(),
            participants: REQUIRED_BACKUP_PARTICIPANTS
                .into_iter()
                .map(|participant| BackupParticipantRegistrationV1 {
                    participant,
                    component_identity: Digest::hash_domain(
                        "component",
                        participant.as_str().as_bytes(),
                    ),
                })
                .collect(),
            created_at_unix_ms: 100,
        }
    }

    fn checkpoint(
        participant: BackupParticipantV1,
        registration: &BackupParticipantRegistrationV1,
    ) -> BackupCheckpointV1 {
        let digest = |name: &str| Digest::hash_domain(name, participant.as_str().as_bytes());
        BackupCheckpointV1 {
            participant,
            component_identity: registration.component_identity.clone(),
            chain_head: ChainHeadV1 {
                sequence: 12,
                digest: digest("head").into(),
            },
            blob_root: digest("blobs").into(),
            config_identity: digest("config"),
            schema_identity: digest("schema"),
            profile_identity: digest("profile"),
            build_identity: digest("build"),
            quiescence_attestation: quiescence_attestation(participant),
        }
    }

    fn quiescence_attestation(participant: BackupParticipantV1) -> QuiescenceBarrierAttestationV1 {
        QuiescenceBarrierAttestationV1 {
            schema: "ag-store-offline-quiescence-attestation-v1".to_owned(),
            cut_id: "cut:1".to_owned(),
            authority_domain: AuthorityDomainId::new("domain:1").unwrap(),
            epoch: EpochId::new(7).unwrap(),
            quiescence_barrier_id: "barrier:1".to_owned(),
            participant,
            boundary: QuiescenceBoundaryV1::OfflineServicesStopped,
            boundary_summary: Digest::hash_domain("boundary", participant.as_str().as_bytes()),
            attesting_principal: Digest::hash_domain("attester", participant.as_str().as_bytes()),
            attested_at_unix_ms: 99,
        }
    }

    #[test]
    fn backup_cut_fences_mutation_and_seals_only_exact_three_store_cut() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let request = begin_request();
        let begin = store.begin_backup_cut(&request).unwrap();
        assert_eq!(store.begin_backup_cut(&request).unwrap(), begin);
        assert_eq!(store.active_backup_cut().unwrap().as_deref(), Some("cut:1"));

        let state = TestState {
            value: "blocked".to_owned(),
        };
        assert!(matches!(
            store.append_event(event("event:blocked", "entity:1", "x"), &state, 0),
            Err(StoreError::BackupBarrierActive(cut)) if cut == "cut:1"
        ));

        for registration in &request.participants {
            let checkpoint = checkpoint(registration.participant, registration);
            let receipt = store
                .prepare_backup_participant("cut:1", &checkpoint, 101)
                .unwrap();
            assert_eq!(
                store
                    .prepare_backup_participant("cut:1", &checkpoint, 999)
                    .unwrap(),
                receipt
            );
        }
        assert_eq!(
            store.backup_cut("cut:1").unwrap().state,
            BackupCutStateV1::Prepared
        );

        let manifest = store.build_backup_manifest("cut:1").unwrap();
        assert_eq!(manifest.participants.len(), 3);
        let sealed = store.seal_backup_cut(&manifest, 102).unwrap();
        assert_eq!(store.seal_backup_cut(&manifest, 999).unwrap(), sealed);
        assert_eq!(store.active_backup_cut().unwrap().as_deref(), Some("cut:1"));
        assert!(matches!(
            store.append_event(event("event:still-blocked", "entity:1", "x"), &state, 0),
            Err(StoreError::BackupBarrierActive(_))
        ));

        let bundle_digest = Digest::hash_domain("backup-bundle/v1", b"bundle");
        let released = store
            .release_backup_cut("cut:1", &bundle_digest, 103)
            .unwrap();
        assert_eq!(
            store
                .release_backup_cut("cut:1", &bundle_digest, 999)
                .unwrap(),
            released
        );
        assert!(store.active_backup_cut().unwrap().is_none());
        assert_eq!(
            store.backup_cut("cut:1").unwrap().release_bundle_digest,
            Some(bundle_digest)
        );

        store
            .append_event(event("event:after", "entity:1", "ok"), &state, 0)
            .unwrap();
        store.verify_chain().unwrap();
    }

    #[test]
    fn changed_manifest_and_changed_checkpoint_retry_are_rejected() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let request = begin_request();
        store.begin_backup_cut(&request).unwrap();
        for registration in &request.participants {
            let checkpoint = checkpoint(registration.participant, registration);
            store
                .prepare_backup_participant("cut:1", &checkpoint, 101)
                .unwrap();
        }
        let mut changed = store.build_backup_manifest("cut:1").unwrap();
        changed.epoch = EpochId::new(changed.epoch.get() + 1).unwrap();
        assert!(matches!(
            store.seal_backup_cut(&changed, 102),
            Err(StoreError::BackupManifestMismatch)
        ));

        let registration = &request.participants[0];
        let mut changed_checkpoint = checkpoint(registration.participant, registration);
        changed_checkpoint.chain_head.sequence += 1;
        assert!(matches!(
            store.prepare_backup_participant("cut:1", &changed_checkpoint, 103),
            Err(StoreError::BackupCheckpointConflict(_))
        ));
    }

    #[test]
    fn physical_database_capture_requires_and_binds_the_sealed_cut() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let destination = fixture.temp.path().join("capture/agd.sqlite3");
        let request = begin_request();
        store.begin_backup_cut(&request).unwrap();
        assert!(matches!(
            store.capture_sealed_database(
                "cut:1",
                BackupParticipantV1::Agd,
                &destination,
            ),
            Err(StoreError::BackupCaptureRequiresSealed(cut)) if cut == "cut:1"
        ));
        for registration in &request.participants {
            store
                .prepare_backup_participant(
                    "cut:1",
                    &checkpoint(registration.participant, registration),
                    101,
                )
                .unwrap();
        }
        let manifest = store.build_backup_manifest("cut:1").unwrap();
        store.seal_backup_cut(&manifest, 102).unwrap();

        let capture = store
            .capture_sealed_database("cut:1", BackupParticipantV1::Agd, &destination)
            .unwrap();
        assert_eq!(capture.cut_id, "cut:1");
        assert_eq!(capture.participant, BackupParticipantV1::Agd);
        assert_eq!(capture.captured_chain_head, store.chain_head().unwrap());
        assert_eq!(capture.blob_root, store.blob_root().unwrap());
        let bytes = fs::read(&destination).unwrap();
        assert_eq!(capture.database.byte_length, bytes.len() as u64);
        assert_eq!(capture.database.digest, Digest::hash_bytes(&bytes));
        assert!(fs::metadata(&destination).unwrap().permissions().readonly());
        assert!(!destination.with_extension("sqlite3-wal").exists());
        assert!(matches!(
            store.capture_sealed_database(
                "cut:1",
                BackupParticipantV1::Agd,
                &destination,
            ),
            Err(StoreError::BackupCaptureDestinationExists(path)) if path == destination
        ));
        assert_eq!(
            store.backup_cut("cut:1").unwrap().state,
            BackupCutStateV1::Sealed
        );
    }

    #[test]
    fn coherent_bundle_rejects_three_snapshots_that_never_shared_one_cut() {
        let fixtures = [
            Fixture::new_for(0x4147_0101, "test-agd"),
            Fixture::new_for(0x4147_0102, "test-ag-effectd"),
            Fixture::new_for(0x4147_0103, "test-ag-providerd"),
        ];
        let roles = REQUIRED_BACKUP_PARTICIPANTS;
        let mut stores: Vec<_> = fixtures
            .iter()
            .enumerate()
            .map(|(index, fixture)| fixture.open(&format!("component-{index}")))
            .collect();
        let request = begin_request();
        for store in &mut stores {
            store.begin_backup_cut(&request).unwrap();
        }
        let checkpoints: Vec<_> = stores
            .iter()
            .zip(roles)
            .map(|(store, participant)| {
                let registration = request
                    .participants
                    .iter()
                    .find(|candidate| candidate.participant == participant)
                    .unwrap();
                let digest =
                    |name: &str| Digest::hash_domain(name, participant.as_str().as_bytes());
                BackupCheckpointV1 {
                    participant,
                    component_identity: registration.component_identity.clone(),
                    chain_head: store.chain_head().unwrap(),
                    blob_root: store.blob_root().unwrap(),
                    config_identity: digest("config"),
                    schema_identity: Digest::from_serializable(store.identity()).unwrap(),
                    profile_identity: digest("profile"),
                    build_identity: digest("build"),
                    quiescence_attestation: quiescence_attestation(participant),
                }
            })
            .collect();
        for store in &mut stores {
            for checkpoint in &checkpoints {
                store
                    .prepare_backup_participant("cut:1", checkpoint, 101)
                    .unwrap();
            }
            let manifest = store.build_backup_manifest("cut:1").unwrap();
            store.seal_backup_cut(&manifest, 102).unwrap();
        }
        let captures: Vec<_> = stores
            .iter()
            .zip(fixtures.iter())
            .zip(roles)
            .map(|((store, fixture), participant)| {
                store
                    .capture_sealed_database(
                        "cut:1",
                        participant,
                        &fixture.temp.path().join("capture.sqlite3"),
                    )
                    .unwrap()
            })
            .collect();

        let mut inconsistent = captures.clone();
        inconsistent[1].cut_manifest.participants[0]
            .checkpoint
            .quiescence_attestation
            .boundary_summary = Digest::hash_bytes(b"a state that never jointly existed");
        inconsistent[1].manifest_digest =
            digest_jcs("ag-store-backup-manifest-v1", &inconsistent[1].cut_manifest).unwrap();
        assert!(matches!(
            CoherentBackupBundleV1::new(inconsistent),
            Err(StoreError::IncoherentBackupBundle)
        ));

        let bundle = CoherentBackupBundleV1::new(captures).unwrap();
        bundle.verify().unwrap();
        for store in &mut stores {
            store
                .release_backup_cut("cut:1", bundle.digest(), 103)
                .unwrap();
        }
    }

    #[test]
    fn abort_is_durable_idempotent_and_releases_barrier() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        store.begin_backup_cut(&begin_request()).unwrap();
        let receipt = store
            .abort_backup_cut("cut:1", "operator_cancelled", 101)
            .unwrap();
        assert_eq!(
            store
                .abort_backup_cut("cut:1", "operator_cancelled", 999)
                .unwrap(),
            receipt
        );
        assert!(store.active_backup_cut().unwrap().is_none());
        assert_eq!(
            store.backup_cut("cut:1").unwrap().state,
            BackupCutStateV1::Aborted
        );
    }

    #[test]
    fn abort_after_seal_invalidates_cut_and_releases_barrier() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let request = begin_request();
        store.begin_backup_cut(&request).unwrap();
        for registration in &request.participants {
            store
                .prepare_backup_participant(
                    "cut:1",
                    &checkpoint(registration.participant, registration),
                    101,
                )
                .unwrap();
        }
        let manifest = store.build_backup_manifest("cut:1").unwrap();
        store.seal_backup_cut(&manifest, 102).unwrap();
        store
            .abort_backup_cut("cut:1", "capture_failed", 103)
            .unwrap();
        let record = store.backup_cut("cut:1").unwrap();
        assert_eq!(record.state, BackupCutStateV1::Aborted);
        assert!(record.manifest_digest.is_some());
        assert!(store.active_backup_cut().unwrap().is_none());
    }

    #[test]
    fn backup_requires_exact_participant_set() {
        let fixture = Fixture::new();
        let mut store = fixture.open("writer");
        let mut request = begin_request();
        request.participants.pop();
        assert!(matches!(
            store.begin_backup_cut(&request),
            Err(StoreError::InvalidBackupParticipants)
        ));
    }
}
