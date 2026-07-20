//! Closed managed-Git-reference observation, preparation, and commit runtime.
//!
//! This module is deliberately not a command runner. It admits one strict,
//! self-contained Git bundle, invokes one descriptor-pinned Git executable
//! through a fixed plumbing vocabulary, and can mutate only the configured
//! non-checked-out reference after a durable preparation checkpoint exists.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd as _;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ag_effect::executor::{
    EXECUTION_RECEIPT_SCHEMA_V1, EffectSuccessV1, ExecutionFailureCodeV1, ExecutionFailureV1,
    ExecutionIndeterminateCodeV1, ExecutionIndeterminateV1, ExecutionOutcomeV1, ExecutionPhaseV1,
    ExecutionReceiptV1,
};
use ag_effect::{
    CanonicalEffectV1, GitObjectFormatV1, MANAGED_POINTER_CANDIDATE_PREPARATION_SCHEMA_V1,
    MANAGED_POINTER_COMPLETE_INPUTS_SCHEMA_V1, MANAGED_POINTER_EXACT_BASIS_SCHEMA_V1,
    MANAGED_POINTER_PREPARATION_EFFECTS_SCHEMA_V1, MANAGED_POINTER_PREPARATION_STANDING_SCHEMA_V1,
    MANAGED_POINTER_PREPARED_CANDIDATE_SCHEMA_V1, MANAGED_POINTER_PROMOTION_SCHEMA_V2,
    ManagedPointerCandidatePreparationReceiptV1, ManagedPointerCandidateRatificationV1,
    ManagedPointerCompleteInputsV1, ManagedPointerExactBasisV1, ManagedPointerPreparationEffectsV1,
    ManagedPointerPreparationStandingReceiptV1, PreparedManagedPointerCandidateV1, TargetId,
    TargetObservationV1,
};
use ag_primitives::{AuthorityDomain, Digest, Epoch};
use ag_store::Store;
use rustix::fd::OwnedFd;
use rustix::fs::{FileType, Gid, MemfdFlags, Mode, OFlags, ResolveFlags, SealFlags, Uid};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{
    EffectTargetConfigV1, EffectdConfigV1, validate_managed_pointer_enrollment_inputs,
    validate_security_profile,
};

const BUNDLE_MAGIC_V2: &[u8] = b"# v2 git bundle\n";
const BUNDLE_CANDIDATE_REF: &str = "refs/heads/ag-candidate";
const PACK_MAGIC: &[u8] = b"PACK";
const PACK_VERSION_V2: u32 = 2;
const MAX_PACK_OBJECTS: u32 = 1_000_000;
const MAX_GIT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_REPOSITORY_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_GIT_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Versioned digest of the exact built-in Git launch contract.
pub const MANAGED_POINTER_LAUNCH_PROFILE_SCHEMA_V2: &str =
    "ag.managed-pointer.git-launch-profile/v2";

/// Versioned descriptor-bound repository identity contract.
pub const MANAGED_REPOSITORY_IDENTITY_SCHEMA_V1: &str = "ag.managed-pointer.repository-identity/v1";

/// Versioned identity for one descriptor-opened repository state cut.
pub const MANAGED_REPOSITORY_STATE_SCHEMA_V1: &str = "ag.managed-pointer.repository-state/v1";

/// Versioned preparation checkpoint with candidate ratification and live-standing evidence.
pub const MANAGED_POINTER_PREPARATION_SCHEMA_V2: &str = "ag.managed-pointer.preparation/v2";

/// Versioned helper evidence emitted after a commit attempt.
pub const MANAGED_POINTER_COMMIT_EVIDENCE_SCHEMA_V1: &str = "ag.managed-pointer.commit-evidence/v1";

/// Versioned independent post-CAS evidence retained with the terminal step.
pub const MANAGED_POINTER_POSTSTATE_EVIDENCE_SCHEMA_V1: &str =
    "ag.managed-pointer.poststate-evidence/v1";

/// Versioned complete explanation emitted only after a durable activation.
pub const MANAGED_POINTER_ACTIVATION_RECEIPT_SCHEMA_V1: &str =
    "ag.managed-pointer.activation-receipt/v1";

/// Versioned fresh target-preflight evidence used only for live broker readiness.
pub const MANAGED_POINTER_READINESS_SCHEMA_V1: &str = "ag.managed-pointer.production-readiness/v1";

/// Strict offline request for measuring one initial governed Git head.
pub const MANAGED_POINTER_GENESIS_REQUEST_SCHEMA_V1: &str = "ag.managed-pointer.genesis-request/v1";

/// Inspectable, non-authorizing measurement reviewed before enrollment.
pub const MANAGED_POINTER_GENESIS_MEASUREMENT_SCHEMA_V1: &str =
    "ag.managed-pointer.genesis-measurement/v1";

/// Receipt for a fresh measurement that exactly matched the reviewed one.
pub const MANAGED_POINTER_GENESIS_ENROLLMENT_RECEIPT_SCHEMA_V1: &str =
    "ag.managed-pointer.genesis-enrollment-receipt/v1";

/// Evidence emitted only when a live, non-serializable promotion standing is
/// minted from exact ratification and a fresh basis observation.
pub const MANAGED_POINTER_PROMOTION_STANDING_RECEIPT_SCHEMA_V1: &str =
    "ag.managed-pointer.promotion-standing-receipt/v1";

/// Operator-selected facts for one offline managed-pointer enrollment.
///
/// The request deliberately contains no genesis object, tree, repository
/// identity, helper digest, or launch-profile digest. Those values can only be
/// supplied by the closed descriptor-bound measurement implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerGenesisRequestV1 {
    /// Exact request schema.
    pub schema: String,
    /// Security profile whose fixed Git launch contract will be enrolled.
    pub security_profile: String,
    /// Opaque target ID used by the effect catalog.
    pub target: String,
    /// Root beneath which the repository must resolve.
    pub allowed_root: PathBuf,
    /// Exact repository strictly beneath `allowed_root`.
    pub repository: PathBuf,
    /// Existing loose branch ref to govern.
    pub reference: String,
    /// Numeric non-root repository owner.
    pub uid: u32,
    /// Numeric non-root repository group.
    pub gid: u32,
    /// Broker-controlled promotion staging root.
    pub staging_root: PathBuf,
    /// Maximum lifetime of one compiled promotion authority.
    pub promotion_ttl_ms: u64,
    /// Exact root-owned Git executable to pin.
    pub helper: PathBuf,
}

/// Exact not-yet-activated effectd authority into which genesis will enroll.
///
/// The template digest binds every peer, custody, limit, and pre-existing
/// target field. Database and object-store paths make the required empty-store
/// observation explicit instead of treating a target measurement as reusable
/// across authority domains.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerGenesisContextV1 {
    /// Authority domain of the final effectd configuration.
    pub authority_domain: String,
    /// Nonzero revocation epoch of the final effectd configuration.
    pub epoch: String,
    /// Digest of the exact root-owned effectd template bytes.
    pub effectd_config_template: Digest,
    /// Database that must not exist before enrollment or first activation.
    pub effectd_database: PathBuf,
    /// Empty object store belonging to that database.
    pub effectd_object_store: PathBuf,
}

impl ManagedPointerGenesisContextV1 {
    fn validate(&self) -> Result<(), ManagedPointerError> {
        if AuthorityDomain::parse(&self.authority_domain).is_err()
            || Epoch::parse(&self.epoch).is_err()
            || !normalized_absolute_path(&self.effectd_database)
            || !normalized_absolute_path(&self.effectd_object_store)
        {
            return Err(ManagedPointerError::GenesisMeasurementInvalid);
        }
        Ok(())
    }
}

impl ManagedPointerGenesisRequestV1 {
    /// Validate every operator-selected enrollment field before observation.
    ///
    /// # Errors
    ///
    /// Returns an error for schema, path, target, owner, ref, profile, helper,
    /// staging, or lifetime inputs outside the managed-pointer contract.
    pub fn validate(&self) -> Result<(), ManagedPointerError> {
        if self.schema != MANAGED_POINTER_GENESIS_REQUEST_SCHEMA_V1 {
            return Err(ManagedPointerError::GenesisMeasurementInvalid);
        }
        validate_security_profile(&self.security_profile)
            .map_err(|_| ManagedPointerError::GenesisMeasurementInvalid)?;
        validate_managed_pointer_enrollment_inputs(
            &self.target,
            &self.allowed_root,
            &self.repository,
            &self.reference,
            self.uid,
            self.gid,
            &self.staging_root,
            self.promotion_ttl_ms,
            &self.helper,
        )
        .map_err(|_| ManagedPointerError::GenesisMeasurementInvalid)
    }

    fn identity(&self) -> Result<Digest, ManagedPointerError> {
        self.validate()?;
        Ok(Digest::from_serializable(self)?)
    }
}

/// Exact descriptor-bound observation reviewed before a target enters config.
///
/// This document is evidence only. It neither changes the target nor creates
/// daemon standing. Enrollment requires a second live measurement to match it
/// byte-for-byte.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerGenesisMeasurementV1 {
    /// Exact measurement schema.
    pub schema: String,
    /// Exact authority, template, and empty-store destination for enrollment.
    pub context: ManagedPointerGenesisContextV1,
    /// Complete operator-selected request.
    pub request: ManagedPointerGenesisRequestV1,
    /// Canonical identity of `request`.
    pub request_identity: Digest,
    /// Profile identity used by the fixed launch contract.
    pub security_profile_identity: Digest,
    /// Exact Git executable bytes.
    pub helper_executable: Digest,
    /// Exact code-derived helper launch profile.
    pub helper_launch_profile: Digest,
    /// Full descriptor-bound repository layout.
    pub repository_layout: ManagedRepositoryIdentityEvidenceV1,
    /// Identity of `repository_layout` copied into effectd config.
    pub repository_identity: Digest,
    /// Full exact managed-ref state.
    pub state: ManagedRepositoryStateEvidenceV1,
    /// Identity of `state` copied into effectd config.
    pub activation_genesis_state: Digest,
    /// Exact commit initially selected by the governed ref.
    pub activation_genesis_object: String,
    /// Exact tree reached from the genesis commit.
    pub activation_genesis_tree: String,
    /// Descriptor metadata for the admitted staging root.
    pub staging_root_node: ManagedFilesystemNodeEvidenceV1,
}

impl ManagedPointerGenesisMeasurementV1 {
    /// Verify all internal identities and config-bound projections.
    ///
    /// # Errors
    ///
    /// Returns an error for any substituted request, evidence, helper,
    /// repository, ref, owner, object, tree, or state identity.
    pub fn verify(&self) -> Result<(), ManagedPointerError> {
        self.context.validate()?;
        self.request.validate()?;
        let request_identity = self.request.identity()?;
        let security_profile_identity = Digest::hash_domain(
            "ag-security-profile-identity-v1",
            self.request.security_profile.as_bytes(),
        );
        let helper_launch_profile = managed_pointer_launch_profile_identity(
            &security_profile_identity,
            &self.helper_executable,
        )?;
        let repository_identity = self.repository_layout.identity()?;
        let state_identity = self.state.identity()?;
        if self.schema != MANAGED_POINTER_GENESIS_MEASUREMENT_SCHEMA_V1
            || self.request_identity != request_identity
            || self.security_profile_identity != security_profile_identity
            || self.helper_launch_profile != helper_launch_profile
            || self.repository_identity != repository_identity
            || self.state.repository_identity != repository_identity
            || self.activation_genesis_state != state_identity
            || self.activation_genesis_object != self.state.current_object
            || self.activation_genesis_tree != self.state.current_tree
            || !self.state.clean
            || self.state.reference_checked_out
            || self.repository_layout.allowed_root != utf8_path(&self.request.allowed_root)?
            || self.repository_layout.repository != utf8_path(&self.request.repository)?
            || self.repository_layout.uid != self.request.uid
            || self.repository_layout.gid != self.request.gid
            || self.state.reference.name != self.request.reference
            || self.state.reference.uid != self.request.uid
            || self.state.reference.gid != self.request.gid
            || self.staging_root_node.name != "staging-root"
            || self.staging_root_node.inode == 0
            || self.staging_root_node.link_count == 0
        {
            return Err(ManagedPointerError::GenesisMeasurementInvalid);
        }
        Ok(())
    }

    /// Compute the identity of a verified reviewed measurement.
    ///
    /// # Errors
    ///
    /// Returns an error when verification or canonical encoding fails.
    pub fn identity(&self) -> Result<Digest, ManagedPointerError> {
        self.verify()?;
        Ok(Digest::from_serializable(self)?)
    }
}

/// Non-authorizing record that a fresh live observation matched review and
/// produced one complete effectd configuration and exact systemd drop-in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerGenesisEnrollmentReceiptV1 {
    /// Exact receipt schema.
    pub schema: String,
    /// Authority domain receiving the final configuration.
    pub authority_domain: String,
    /// Revocation epoch receiving the final configuration.
    pub epoch: String,
    /// Enrolled target ID.
    pub target: String,
    /// Identity of the reviewed and freshly reproduced measurement.
    pub measurement: Digest,
    /// Exact genesis object copied into target configuration.
    pub activation_genesis_object: String,
    /// Exact genesis tree copied into target configuration.
    pub activation_genesis_tree: String,
    /// Exact genesis state copied into target configuration.
    pub activation_genesis_state: Digest,
    /// Exact repository identity copied into target configuration.
    pub repository_identity: Digest,
    /// Digest of the complete no-overwrite final effectd configuration.
    pub effectd_config: Digest,
    /// Absolute final effectd configuration path committed by the receipt.
    pub effectd_config_path: String,
    /// Digest of the exact target-derived systemd unit drop-in.
    pub effectd_unit_drop_in: Digest,
    /// Absolute final systemd drop-in path committed by the receipt.
    pub effectd_unit_drop_in_path: String,
    /// Absolute receipt path published before deployment artifacts.
    pub receipt_path: String,
}

impl ManagedPointerGenesisEnrollmentReceiptV1 {
    /// Validate the closed receipt shape and path commitments.
    ///
    /// # Errors
    ///
    /// Returns an error for schema drift, invalid authority context, an
    /// unnormalized path, or a target inconsistent with the reviewed request.
    pub fn verify(
        &self,
        reviewed: &ManagedPointerGenesisMeasurementV1,
    ) -> Result<(), ManagedPointerError> {
        reviewed.verify()?;
        if self.schema != MANAGED_POINTER_GENESIS_ENROLLMENT_RECEIPT_SCHEMA_V1
            || self.authority_domain != reviewed.context.authority_domain
            || self.epoch != reviewed.context.epoch
            || self.target != reviewed.request.target
            || self.measurement != reviewed.identity()?
            || self.activation_genesis_object != reviewed.activation_genesis_object
            || self.activation_genesis_tree != reviewed.activation_genesis_tree
            || self.activation_genesis_state != reviewed.activation_genesis_state
            || self.repository_identity != reviewed.repository_identity
            || !normalized_absolute_path(Path::new(&self.effectd_config_path))
            || !normalized_absolute_path(Path::new(&self.effectd_unit_drop_in_path))
            || !normalized_absolute_path(Path::new(&self.receipt_path))
            || self.effectd_config_path == self.effectd_unit_drop_in_path
            || self.effectd_config_path == self.receipt_path
            || self.effectd_unit_drop_in_path == self.receipt_path
        {
            return Err(ManagedPointerError::GenesisMeasurementInvalid);
        }
        Ok(())
    }

    /// Compute the identity of a verified enrollment receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when verification or canonical encoding fails.
    pub fn identity(
        &self,
        reviewed: &ManagedPointerGenesisMeasurementV1,
    ) -> Result<Digest, ManagedPointerError> {
        self.verify(reviewed)?;
        Ok(Digest::from_serializable(self)?)
    }
}

/// Exact descriptor metadata for one named node in the enrolled repository layout.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFilesystemNodeEvidenceV1 {
    /// Stable role or repository-relative path for this node.
    pub name: String,
    /// Filesystem device observed through the retained descriptor.
    pub device: u64,
    /// Filesystem inode observed through the retained descriptor.
    pub inode: u64,
    /// Numeric owner.
    pub uid: u32,
    /// Numeric group.
    pub gid: u32,
    /// File type and permission bits from `stat(2)`.
    pub mode: u32,
    /// Exact hard-link count.
    pub link_count: u64,
}

/// Exact authority and attempt bindings copied into an execution receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerExecutionContextV1 {
    /// Canonical proposal digest.
    pub proposal: Digest,
    /// Burned independent authorization digest.
    pub authorization: Digest,
    /// Store-unique one-shot attempt.
    pub attempt: Digest,
    /// Canonical effect position.
    pub effect_index: u32,
}

/// Broker context from which one bounded preparation standing may be minted.
/// The resulting live value is deliberately non-cloneable and non-serializable.
pub(crate) struct ManagedPointerPreparationStandingContextV1 {
    pub authority_domain: AuthorityDomain,
    pub epoch: Epoch,
    pub catalog_identity: Digest,
    pub security_profile_identity: Digest,
    pub max_artifact_bytes: u64,
    pub now_unix_ms: u64,
}

/// Live target-scoped preparation authority. Persisted bytes expose only its
/// receipt, which cannot recreate this value after restart.
pub(crate) struct ManagedPointerPreparationStandingV1 {
    receipt: ManagedPointerPreparationStandingReceiptV1,
}

/// Candidate plus the broker observation compiled into canonical effect bytes.
pub(crate) struct ManagedPointerPreparedObservationV1 {
    pub observation: TargetObservationV1,
    pub candidate: PreparedManagedPointerCandidateV1,
}

/// Durable evidence that live promotion standing was constructed and consumed.
/// It records the bridge; it is not itself standing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerPromotionStandingReceiptV1 {
    /// Receipt schema.
    pub schema: String,
    /// Exact canonical proposal.
    pub proposal: Digest,
    /// Burned independent authorization.
    pub authorization: Digest,
    /// Candidate-and-basis ratification record.
    pub candidate_ratification: Digest,
    /// Exact prepared candidate.
    pub candidate: Digest,
    /// Ratified exact basis.
    pub exact_basis: Digest,
    /// Fresh live basis observed immediately before authority burn.
    pub current_basis: Digest,
    /// Standing issue time.
    pub issued_at_unix_ms: u64,
    /// Exclusive canonical promotion expiry.
    pub expires_at_unix_ms: u64,
    /// One-use broker nonce.
    pub nonce: String,
}

impl ManagedPointerPromotionStandingReceiptV1 {
    fn identity(&self) -> Result<Digest, ManagedPointerError> {
        if self.schema != MANAGED_POINTER_PROMOTION_STANDING_RECEIPT_SCHEMA_V1
            || self.nonce.is_empty()
            || self.issued_at_unix_ms >= self.expires_at_unix_ms
            || self.exact_basis != self.current_basis
        {
            return Err(ManagedPointerError::PromotionStandingMismatch);
        }
        Ok(Digest::from_serializable(self)?)
    }
}

/// Live single-use promotion authority. It has no serialization or clone path
/// and is consumed by reversible preparation.
pub(crate) struct ManagedPointerPromotionStandingV1 {
    receipt: ManagedPointerPromotionStandingReceiptV1,
}

fn require_preparation_standing(
    standing: Option<ManagedPointerPreparationStandingV1>,
) -> Result<ManagedPointerPreparationStandingV1, ManagedPointerError> {
    standing.ok_or(ManagedPointerError::PreparationStandingAbsent)
}

/// Durable evidence returned after all reversible preparation completed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerPreparationEvidenceV1 {
    /// Evidence schema.
    pub schema: String,
    /// Exact proposal, authorization, attempt, and effect-index context.
    pub execution: ManagedPointerExecutionContextV1,
    /// Exact one-shot operation in the ratified effect.
    pub operation_id: Digest,
    /// Exact prepared candidate ratified for this operation.
    pub prepared_candidate: Digest,
    /// Exact candidate-and-basis ratification record.
    pub candidate_ratification: Digest,
    /// Evidence preimage for the consumed live promotion standing.
    pub promotion_standing: ManagedPointerPromotionStandingReceiptV1,
    /// Exact candidate bundle.
    pub artifact: Digest,
    /// Exact PACK section extracted from the strict bundle.
    pub candidate_pack: Digest,
    /// Git object-database checksum returned by the fixed `index-pack` import.
    pub imported_pack_checksum: String,
    /// Descriptor-derived evidence that the target pack and index are durable.
    pub object_import_evidence: Digest,
    /// Full preimage behind `object_import_evidence`.
    pub imported_pack_evidence: ImportedPackEvidenceV1,
    /// Descriptor-bound repository identity.
    pub repository_identity: Digest,
    /// Full descriptor-bound layout preimage behind `repository_identity`.
    pub repository_layout: ManagedRepositoryIdentityEvidenceV1,
    /// Full ratified layout, loose-ref inode/content, and target-state cut.
    pub prestate: ManagedRepositoryStateEvidenceV1,
    /// Commit observed at the managed ref.
    pub expected_object: String,
    /// Tree reached from the observed commit.
    pub expected_tree: String,
    /// Candidate commit validated in isolated staging.
    pub new_object: String,
    /// Candidate tree validated in isolated staging.
    pub expected_post_tree: String,
}

/// Exact evidence behind a successful managed-reference commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerCommitEvidenceV1 {
    /// Evidence schema.
    pub schema: String,
    /// Exact execution context copied from the durable checkpoint.
    pub execution: ManagedPointerExecutionContextV1,
    /// Durable preparation checkpoint which armed the commit boundary.
    pub preparation_checkpoint: Digest,
    /// Exact ratified one-shot operation.
    pub operation_id: Digest,
    /// Digest of the exact helper request/context/effect tuple.
    pub request_digest: Digest,
    /// Commit observed before the CAS.
    pub previous_object: String,
    /// Tree observed before the CAS.
    pub previous_tree: String,
    /// Commit independently read back after the CAS.
    pub installed_object: String,
    /// Tree independently read back after the CAS.
    pub installed_tree: String,
    /// Confirms the loose ref and its containing directories were synced.
    pub reference_fsynced: bool,
}

/// Full descriptor-derived evidence for the imported immutable pack and index.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedPackEvidenceV1 {
    /// Evidence schema.
    pub schema: String,
    /// Object-database checksum returned by exact `index-pack`.
    pub pack_checksum: String,
    /// Digest of the ratified PACK bytes.
    pub candidate_pack_digest: Digest,
    /// Digest of the installed pack file.
    pub pack_file_digest: Digest,
    /// Exact installed pack size.
    pub pack_file_size: u64,
    /// Digest of the installed index file.
    pub index_file_digest: Digest,
    /// Exact installed index size.
    pub index_file_size: u64,
    /// Owner under which import occurred.
    pub target_uid: u32,
    /// Group under which import occurred.
    pub target_gid: u32,
    /// Pack file was synced.
    pub pack_fsynced: bool,
    /// Index file was synced.
    pub index_fsynced: bool,
    /// Pack and object directories were synced.
    pub object_directories_fsynced: bool,
}

/// Full state identity binding the stable layout and the current loose ref inode/content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRepositoryStateEvidenceV1 {
    /// State-evidence schema.
    pub schema: String,
    /// Exact stable repository layout identity.
    pub repository_identity: Digest,
    /// Exact loose managed-ref descriptor metadata.
    pub reference: ManagedFilesystemNodeEvidenceV1,
    /// Commit named directly by the loose ref bytes and confirmed by Git.
    pub current_object: String,
    /// Tree reached from the current commit.
    pub current_tree: String,
    /// Exact clean-worktree result under the closed observer.
    pub clean: bool,
    /// Whether the managed ref is attached to a worktree.
    pub reference_checked_out: bool,
}

impl ManagedRepositoryStateEvidenceV1 {
    pub(crate) fn identity(&self) -> Result<Digest, ManagedPointerError> {
        Ok(Digest::from_serializable(self)?)
    }
}

/// Full independent state evidence produced only after ref and directory fsync.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerPoststateEvidenceV1 {
    /// Evidence schema.
    pub schema: String,
    /// Exact proposal, authorization, attempt, and effect position.
    pub execution: ManagedPointerExecutionContextV1,
    /// Durable checkpoint which armed the one ref CAS.
    pub preparation_checkpoint: Digest,
    /// Stable descriptor-bound repository layout.
    pub repository_layout: ManagedRepositoryIdentityEvidenceV1,
    /// Exact post-CAS loose-ref inode/content and target state.
    pub state: ManagedRepositoryStateEvidenceV1,
}

/// Complete, non-authorizing explanation of one verified managed-ref activation.
///
/// This record is created only after the ref CAS, ref/directory durability
/// sync, and final exact post-state readback all succeed. Persisted bytes are
/// historical evidence; they cannot reconstruct promotion standing or make a
/// divergent live ref current.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPointerActivationReceiptV1 {
    /// Exact receipt schema.
    pub schema: String,
    /// Exact canonical effect identity.
    pub effect: Digest,
    /// Exact proposal, accepted authorization, attempt, and effect position.
    pub execution: ManagedPointerExecutionContextV1,
    /// Configured managed-pointer target.
    pub target: TargetId,
    /// Exact managed Git ref.
    pub reference: String,
    /// One-shot operation selected by canonical bytes.
    pub operation_id: Digest,
    /// Exact prepared candidate selected by ratification.
    pub prepared_candidate: Digest,
    /// Candidate-and-basis ratification identity.
    pub candidate_ratification: Digest,
    /// Exact ratified basis identity.
    pub exact_basis: Digest,
    /// Exact admitted candidate artifact.
    pub artifact: Digest,
    /// Exact PACK bytes imported before the pointer boundary.
    pub candidate_pack: Digest,
    /// Durable preparation checkpoint which armed the CAS.
    pub preparation_checkpoint: Digest,
    /// Descriptor-bound repository identity.
    pub repository_identity: Digest,
    /// Exact object selected before activation.
    pub previous_object: String,
    /// Exact tree selected before activation.
    pub previous_tree: String,
    /// Exact object selected after activation.
    pub installed_object: String,
    /// Exact tree selected after activation.
    pub installed_tree: String,
    /// Full evidence behind the ref CAS and durability assertion.
    pub commit: ManagedPointerCommitEvidenceV1,
    /// Full independently observed durable post-state.
    pub poststate: ManagedPointerPoststateEvidenceV1,
}

impl ManagedPointerActivationReceiptV1 {
    /// Verifies every activation explanation binding against canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for schema drift, substituted evidence, a foreign
    /// proposal/authorization/attempt, or any pre/post/durability mismatch.
    pub fn verify(&self, effect: &CanonicalEffectV1) -> Result<(), ManagedPointerError> {
        let fields = CanonicalPointerFieldsV1::from_effect(effect)?;
        let effect_identity = Digest::from_serializable(effect)?;
        let expected_request = Digest::from_serializable(&(
            "ag.managed-pointer.commit-request/v1",
            &self.execution,
            &self.preparation_checkpoint,
            effect,
        ))?;
        if self.schema != MANAGED_POINTER_ACTIVATION_RECEIPT_SCHEMA_V1
            || self.effect != effect_identity
            || self.target != *fields.target
            || self.reference != fields.reference
            || self.operation_id != *fields.operation_id
            || self.prepared_candidate != *fields.prepared_candidate
            || self.exact_basis != *fields.exact_basis
            || self.artifact != *fields.artifact
            || self.candidate_pack != *fields.candidate_pack_digest
            || self.repository_identity != *fields.repository_identity
            || self.previous_object != fields.expected_object
            || self.previous_tree != fields.expected_tree
            || self.installed_object != fields.new_object
            || self.installed_tree != fields.expected_post_tree
            || self.commit.execution != self.execution
            || self.poststate.execution != self.execution
            || self.commit.schema != MANAGED_POINTER_COMMIT_EVIDENCE_SCHEMA_V1
            || self.poststate.schema != MANAGED_POINTER_POSTSTATE_EVIDENCE_SCHEMA_V1
            || self.poststate.state.schema != MANAGED_REPOSITORY_STATE_SCHEMA_V1
            || self.commit.operation_id != self.operation_id
            || self.commit.request_digest != expected_request
            || self.commit.preparation_checkpoint != self.preparation_checkpoint
            || self.poststate.preparation_checkpoint != self.preparation_checkpoint
            || self.commit.previous_object != self.previous_object
            || self.commit.previous_tree != self.previous_tree
            || self.commit.installed_object != self.installed_object
            || self.commit.installed_tree != self.installed_tree
            || !self.commit.reference_fsynced
            || self.poststate.repository_layout.identity()? != self.repository_identity
            || self.poststate.state.repository_identity != self.repository_identity
            || self.poststate.state.current_object != self.installed_object
            || self.poststate.state.current_tree != self.installed_tree
            || self.poststate.state.reference.name != fields.reference
            || self.poststate.state.reference.uid != fields.uid
            || self.poststate.state.reference.gid != fields.gid
            || self.poststate.state.reference.link_count != 1
            || !FileType::from_raw_mode(self.poststate.state.reference.mode).is_file()
            || self.poststate.state.reference.mode & 0o022 != 0
            || !self.poststate.state.clean
            || self.poststate.state.reference_checked_out
        {
            return Err(ManagedPointerError::BindingMismatch);
        }
        Ok(())
    }

    /// Computes the identity of a fully verified activation explanation.
    ///
    /// # Errors
    ///
    /// Returns an error if verification or canonical encoding fails.
    pub fn identity(&self, effect: &CanonicalEffectV1) -> Result<Digest, ManagedPointerError> {
        self.verify(effect)?;
        Ok(Digest::from_serializable(self)?)
    }
}

/// Terminal runtime result plus exact evidence preimages for broker custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedPointerCommitResultV1 {
    /// Exact step receipt bound to proposal, authorization, attempt, and effect.
    pub receipt: ExecutionReceiptV1,
    /// Full commit receipt preimage, present only for a verified success.
    pub commit_evidence: Option<ManagedPointerCommitEvidenceV1>,
    /// Full independent poststate preimage, present only for a verified success.
    pub poststate_evidence: Option<ManagedPointerPoststateEvidenceV1>,
    /// Complete activation explanation, present only for a verified durable success.
    pub activation_receipt: Option<ManagedPointerActivationReceiptV1>,
}

struct ManagedPointerCommitSuccessV1 {
    success: EffectSuccessV1,
    commit_evidence: ManagedPointerCommitEvidenceV1,
    poststate_evidence: ManagedPointerPoststateEvidenceV1,
    activation_receipt: ManagedPointerActivationReceiptV1,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitFailpointV1 {
    None,
    BeforeCas,
    AfterCas,
}

enum CommitErrorV1 {
    Failed(ManagedPointerError),
    Indeterminate {
        detail: String,
        phase: ExecutionPhaseV1,
        evidence: Option<Digest>,
    },
}

impl ManagedPointerPreparationEvidenceV1 {
    /// Computes the durable checkpoint consumed by the promotion state machine.
    ///
    /// # Errors
    ///
    /// Returns an error when strict canonical encoding fails.
    pub fn checkpoint(&self) -> Result<Digest, ManagedPointerError> {
        if self.schema != MANAGED_POINTER_PREPARATION_SCHEMA_V2 {
            return Err(ManagedPointerError::BindingMismatch);
        }
        Ok(Digest::from_serializable(self)?)
    }
}

/// Descriptor and target facts used to derive the enrolled repository identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRepositoryIdentityEvidenceV1 {
    /// Identity schema.
    pub schema: String,
    /// Exact configured allowed root.
    pub allowed_root: String,
    /// Exact configured repository path.
    pub repository: String,
    /// Whether the repository has no worktree.
    pub bare: bool,
    /// Repository object format.
    pub object_format: GitObjectFormatV1,
    /// Exact descriptor metadata for the configured allowed root.
    pub allowed_root_node: ManagedFilesystemNodeEvidenceV1,
    /// Exact descriptor metadata for the repository root.
    pub repository_node: ManagedFilesystemNodeEvidenceV1,
    /// Exact descriptor metadata for the Git directory.
    pub git_directory_node: ManagedFilesystemNodeEvidenceV1,
    /// Exact descriptor metadata for the bounded local configuration file.
    pub config_node: ManagedFilesystemNodeEvidenceV1,
    /// Exact descriptor metadata for the object directory.
    pub objects_node: ManagedFilesystemNodeEvidenceV1,
    /// Exact descriptor metadata for the pack directory used by `index-pack`.
    pub pack_directory_node: ManagedFilesystemNodeEvidenceV1,
    /// Every descriptor-opened directory from `refs` through the managed ref's parent.
    pub reference_ancestry: Vec<ManagedFilesystemNodeEvidenceV1>,
    /// Device and inode of the repository root.
    pub repository_device: u64,
    /// Repository inode.
    pub repository_inode: u64,
    /// Device and inode of the Git directory.
    pub git_directory_device: u64,
    /// Git-directory inode.
    pub git_directory_inode: u64,
    /// Numeric repository owner.
    pub uid: u32,
    /// Numeric repository group.
    pub gid: u32,
    /// Exact bounded local repository configuration.
    pub config_digest: Digest,
}

impl ManagedRepositoryIdentityEvidenceV1 {
    /// Computes the identity enrolled in the root-owned effect catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when strict canonical encoding fails.
    pub fn identity(&self) -> Result<Digest, ManagedPointerError> {
        if self.schema != MANAGED_REPOSITORY_IDENTITY_SCHEMA_V1
            || self.repository_node.device != self.repository_device
            || self.repository_node.inode != self.repository_inode
            || self.git_directory_node.device != self.git_directory_device
            || self.git_directory_node.inode != self.git_directory_inode
            || self.repository_node.uid != self.uid
            || self.repository_node.gid != self.gid
            || self.reference_ancestry.is_empty()
            || [
                &self.allowed_root_node,
                &self.repository_node,
                &self.git_directory_node,
                &self.config_node,
                &self.objects_node,
                &self.pack_directory_node,
            ]
            .iter()
            .any(|node| node.inode == 0 || node.link_count == 0)
        {
            return Err(ManagedPointerError::BindingMismatch);
        }
        Ok(Digest::from_serializable(self)?)
    }
}

/// Non-cloneable, exact preparation retained until the one permitted commit.
pub struct PreparedManagedPointerV1 {
    effect: CanonicalEffectV1,
    context: ManagedPointerExecutionContextV1,
    target: TargetId,
    pack: File,
    _stage: StagingDirectoryV1,
    /// Exact reversible-preparation evidence.
    pub evidence: ManagedPointerPreparationEvidenceV1,
    /// Digest durably installed before commit may proceed.
    pub checkpoint: Digest,
}

impl core::fmt::Debug for PreparedManagedPointerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedManagedPointerV1")
            .field("target", &self.target)
            .field("evidence", &self.evidence)
            .field("checkpoint", &self.checkpoint)
            .finish_non_exhaustive()
    }
}

/// The closed managed-pointer runtime retained by `ag-effectd`.
pub struct ManagedPointerRuntimeV1 {
    targets: BTreeMap<TargetId, ManagedPointerTargetV1>,
    security_profile_identity: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedPointerActivationHeadV1 {
    pub(crate) object: String,
    pub(crate) tree: String,
    pub(crate) state_identity: Digest,
}

struct ManagedPointerTargetV1 {
    allowed_root: PathBuf,
    repository: PathBuf,
    reference: String,
    activation_genesis_object: String,
    activation_genesis_tree: String,
    activation_genesis_state: Digest,
    repository_identity: Digest,
    uid: u32,
    gid: u32,
    staging_root: PathBuf,
    production_staging_custody: bool,
    promotion_ttl_ms: u64,
    git: Mutex<PinnedGitV1>,
    launch_profile: Digest,
}

struct PinnedGitV1 {
    path: PathBuf,
    source: File,
    snapshot: File,
    executable: Digest,
    device: u64,
    inode: u64,
    size: u64,
    gid: u32,
    mode: u32,
}

trait ManagedPointerClockV1 {
    fn now_unix_ms(&self) -> Result<u64, ManagedPointerError>;
}

struct SystemManagedPointerClockV1;

impl ManagedPointerClockV1 for SystemManagedPointerClockV1 {
    fn now_unix_ms(&self) -> Result<u64, ManagedPointerError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagedPointerError::ClockUnavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ManagedPointerError::ClockUnavailable)
    }
}

#[derive(Clone, Copy)]
struct CommitLaunchGuardV1<'a> {
    clock: &'a dyn ManagedPointerClockV1,
    expires_unix_ms: u64,
}

/// Strict managed-pointer runtime failures. No variant contains candidate data.
#[derive(Debug, Error)]
pub enum ManagedPointerError {
    /// An offline genesis request or measurement has invalid or substituted bindings.
    #[error("managed-pointer genesis measurement is invalid")]
    GenesisMeasurementInvalid,
    /// The live target no longer equals the independently reviewed measurement.
    #[error("managed-pointer genesis changed after review")]
    GenesisMeasurementDrift,
    /// The configured target is absent or has the wrong family.
    #[error("managed-pointer target is unavailable")]
    TargetUnavailable,
    /// Candidate preparation was attempted without live bounded standing.
    #[error("managed-pointer preparation standing is absent")]
    PreparationStandingAbsent,
    /// Preparation standing does not cover target, epoch, profile, or time.
    #[error("managed-pointer preparation standing scope mismatch")]
    PreparationStandingScopeMismatch,
    /// Preparation input or charged quarantine work exceeds standing.
    #[error("managed-pointer preparation budget exceeded")]
    PreparationBudgetExceeded,
    /// Quarantine preparation altered the protected authoritative projection.
    #[error("managed-pointer preparation changed protected authoritative state")]
    ProtectedProjectionChanged,
    /// Ratification and fresh basis could not mint exact promotion standing.
    #[error("managed-pointer promotion standing mismatch")]
    PromotionStandingMismatch,
    /// Configuration or canonical bytes disagree with the retained target.
    #[error("managed-pointer binding mismatch")]
    BindingMismatch,
    /// The configured Git executable changed or is unsafe.
    #[error("pinned Git executable mismatch")]
    GitIdentityMismatch,
    /// The configured launch-profile digest is not the code-derived contract.
    #[error("managed-pointer launch profile mismatch")]
    LaunchProfileMismatch,
    /// The trusted wall clock could not be refreshed before the pointer CAS.
    #[error("managed-pointer trusted clock is unavailable")]
    ClockUnavailable,
    /// The trusted clock reached expiry before the CAS helper was spawned.
    #[error("managed-pointer promotion expired immediately before ref CAS")]
    PromotionExpiredBeforeCas,
    /// The helper process could not be confined below the no-new-privileges floor.
    #[error("managed-pointer helper privilege floor is unavailable")]
    PrivilegeFloorUnavailable,
    /// Repository resolution, metadata, or descriptor identity is unsafe.
    #[error("unsafe managed repository: {0}")]
    UnsafeRepository(String),
    /// Candidate bundle is not the strict, self-contained v2 contract.
    #[error("invalid managed-pointer bundle: {0}")]
    InvalidBundle(String),
    /// Managed ref, tree, owner, identity, or cleanliness drifted.
    #[error("managed-pointer prestate drift: {0}")]
    PrestateDrift(String),
    /// Exact artifact custody is unavailable or contradictory.
    #[error("managed-pointer artifact custody failed: {0}")]
    Artifact(String),
    /// A fixed Git plumbing operation failed.
    #[error("closed Git operation {operation} failed: {detail}")]
    Git {
        /// Stable built-in operation name.
        operation: &'static str,
        /// Sanitized bounded diagnostic.
        detail: String,
    },
    /// Local filesystem operation failed.
    #[error("managed-pointer local I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Store custody operation failed.
    #[error("managed-pointer store custody failed: {0}")]
    Store(#[from] ag_store::StoreError),
    /// Strict evidence encoding failed.
    #[error("managed-pointer evidence encoding failed: {0}")]
    Canonical(#[from] ag_primitives::JcsError),
}

/// Measure one initial managed-pointer head through the same closed Git and
/// descriptor machinery used by the effect broker.
///
/// This operation is read-only with respect to the repository and creates no
/// authority. A non-bare cleanliness check uses one automatically removed
/// private directory under the staging root. Production and high-assurance
/// requests also require the final root-owned staging custody that effectd
/// will attest at activation.
///
/// # Errors
///
/// Returns an error for an invalid request, unsafe helper/repository/staging
/// custody, a dirty or checked-out managed ref, Git failure, or evidence that
/// cannot be encoded and verified exactly.
pub fn measure_managed_pointer_genesis(
    request: &ManagedPointerGenesisRequestV1,
    context: &ManagedPointerGenesisContextV1,
) -> Result<ManagedPointerGenesisMeasurementV1, ManagedPointerError> {
    request.validate()?;
    context.validate()?;
    let security_profile_identity = Digest::hash_domain(
        "ag-security-profile-identity-v1",
        request.security_profile.as_bytes(),
    );
    let git = PinnedGitV1::measure(&request.helper)?;
    let helper_executable = git.executable.clone();
    let helper_launch_profile =
        managed_pointer_launch_profile_identity(&security_profile_identity, &helper_executable)?;
    let staging = open_absolute_directory(&request.staging_root)?;
    let staging_stat = rustix::fs::fstat(&staging).map_err(errno_to_io)?;
    if request.security_profile == "development" {
        if !FileType::from_raw_mode(staging_stat.st_mode).is_dir()
            || staging_stat.st_uid != nix::unistd::geteuid().as_raw()
            || staging_stat.st_mode & 0o022 != 0
        {
            return Err(ManagedPointerError::UnsafeRepository(
                "development staging root is not private caller custody".to_owned(),
            ));
        }
    } else {
        validate_production_staging_custody(
            FileType::from_raw_mode(staging_stat.st_mode).is_dir(),
            staging_stat.st_uid,
            staging_stat.st_gid,
            staging_stat.st_mode,
        )?;
    }
    let target = ManagedPointerTargetV1 {
        allowed_root: request.allowed_root.clone(),
        repository: request.repository.clone(),
        reference: request.reference.clone(),
        // Genesis is the output of this observation, so these retained fields
        // are deliberately unusable while measurement is in progress.
        activation_genesis_object: String::new(),
        activation_genesis_tree: String::new(),
        activation_genesis_state: Digest::hash_bytes(b"unenrolled-genesis"),
        repository_identity: Digest::hash_bytes(b"unenrolled-repository"),
        uid: request.uid,
        gid: request.gid,
        staging_root: request.staging_root.clone(),
        production_staging_custody: request.security_profile != "development",
        promotion_ttl_ms: request.promotion_ttl_ms,
        git: Mutex::new(git),
        launch_profile: helper_launch_profile.clone(),
    };
    let repository = target.open_repository()?;
    let state = target.observe_repository_state(&repository)?;
    if !state.clean || state.reference_checked_out {
        return Err(ManagedPointerError::PrestateDrift(
            "genesis ref is checked out or the repository worktree is dirty".to_owned(),
        ));
    }
    let repository_layout = repository.identity_evidence.clone();
    let repository_identity = repository_layout.identity()?;
    if state.evidence.repository_identity != repository_identity {
        return Err(ManagedPointerError::GenesisMeasurementInvalid);
    }
    let measurement = ManagedPointerGenesisMeasurementV1 {
        schema: MANAGED_POINTER_GENESIS_MEASUREMENT_SCHEMA_V1.to_owned(),
        context: context.clone(),
        request: request.clone(),
        request_identity: request.identity()?,
        security_profile_identity,
        helper_executable,
        helper_launch_profile,
        repository_layout,
        repository_identity,
        activation_genesis_state: state.evidence.identity()?,
        activation_genesis_object: state.current_object,
        activation_genesis_tree: state.current_tree,
        state: state.evidence,
        staging_root_node: node_evidence("staging-root", &staging_stat),
    };
    measurement.verify()?;
    Ok(measurement)
}

/// Require a fresh live measurement to equal the reviewed measurement and
/// derive the exact target record accepted by effectd config v2.
///
/// # Errors
///
/// Returns an error if the reviewed document is invalid, belongs to another
/// request, or any helper, staging, repository, ref, object, tree, metadata,
/// or state evidence changed after review.
pub fn enroll_managed_pointer_genesis(
    request: &ManagedPointerGenesisRequestV1,
    context: &ManagedPointerGenesisContextV1,
    reviewed: &ManagedPointerGenesisMeasurementV1,
) -> Result<(EffectTargetConfigV1, Digest), ManagedPointerError> {
    reviewed.verify()?;
    context.validate()?;
    if &reviewed.request != request || &reviewed.context != context {
        return Err(ManagedPointerError::GenesisMeasurementInvalid);
    }
    let reviewed_identity = reviewed.identity()?;
    let fresh = measure_managed_pointer_genesis(request, context)?;
    if fresh != *reviewed || fresh.identity()? != reviewed_identity {
        return Err(ManagedPointerError::GenesisMeasurementDrift);
    }
    let target = EffectTargetConfigV1::ManagedPointer {
        id: request.target.clone(),
        allowed_root: request.allowed_root.clone(),
        repository: request.repository.clone(),
        reference: request.reference.clone(),
        activation_genesis_object: reviewed.activation_genesis_object.clone(),
        activation_genesis_tree: reviewed.activation_genesis_tree.clone(),
        activation_genesis_state: reviewed.activation_genesis_state.clone(),
        repository_identity: reviewed.repository_identity.clone(),
        uid: request.uid,
        gid: request.gid,
        staging_root: request.staging_root.clone(),
        promotion_ttl_ms: request.promotion_ttl_ms,
        helper: request.helper.clone(),
        helper_executable: reviewed.helper_executable.clone(),
        helper_launch_profile: reviewed.helper_launch_profile.clone(),
    };
    Ok((target, reviewed_identity))
}

impl ManagedPointerRuntimeV1 {
    /// Pins all configured managed-pointer Git executables and verifies the
    /// code-derived launch profile before any authority-bearing use.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate/invalid targets, executable drift, or a
    /// launch-profile digest not produced by this exact implementation.
    pub fn from_config(config: &EffectdConfigV1) -> Result<Self, ManagedPointerError> {
        let security_profile_identity = Digest::hash_domain(
            "ag-security-profile-identity-v1",
            config.security_profile.as_bytes(),
        );
        let mut targets = BTreeMap::new();
        for configured in &config.targets {
            let EffectTargetConfigV1::ManagedPointer {
                id,
                allowed_root,
                repository,
                reference,
                activation_genesis_object,
                activation_genesis_tree,
                activation_genesis_state,
                repository_identity,
                uid,
                gid,
                staging_root,
                promotion_ttl_ms,
                helper,
                helper_executable,
                helper_launch_profile,
            } = configured
            else {
                continue;
            };
            let target =
                TargetId::parse(id.clone()).map_err(|_| ManagedPointerError::BindingMismatch)?;
            let git = PinnedGitV1::open(helper, helper_executable)?;
            let launch_profile = managed_pointer_launch_profile_identity(
                &security_profile_identity,
                &git.executable,
            )?;
            if launch_profile != *helper_launch_profile {
                return Err(ManagedPointerError::LaunchProfileMismatch);
            }
            let entry = ManagedPointerTargetV1 {
                allowed_root: allowed_root.clone(),
                repository: repository.clone(),
                reference: reference.clone(),
                activation_genesis_object: activation_genesis_object.clone(),
                activation_genesis_tree: activation_genesis_tree.clone(),
                activation_genesis_state: activation_genesis_state.clone(),
                repository_identity: repository_identity.clone(),
                uid: *uid,
                gid: *gid,
                staging_root: staging_root.clone(),
                production_staging_custody: config.security_profile != "development",
                promotion_ttl_ms: *promotion_ttl_ms,
                git: Mutex::new(git),
                launch_profile,
            };
            if targets.insert(target, entry).is_some() {
                return Err(ManagedPointerError::BindingMismatch);
            }
        }
        Ok(Self {
            targets,
            security_profile_identity,
        })
    }

    /// Returns the security-profile identity bound into this runtime.
    #[must_use]
    pub fn security_profile_identity(&self) -> &Digest {
        &self.security_profile_identity
    }

    /// Return every exact reviewed activation genesis. The order is canonical
    /// and no filesystem state is consulted.
    pub(crate) fn activation_geneses(&self) -> BTreeMap<TargetId, ManagedPointerActivationHeadV1> {
        self.targets
            .iter()
            .map(|(target, runtime)| {
                (
                    target.clone(),
                    ManagedPointerActivationHeadV1 {
                        object: runtime.activation_genesis_object.clone(),
                        tree: runtime.activation_genesis_tree.clone(),
                        state_identity: runtime.activation_genesis_state.clone(),
                    },
                )
            })
            .collect()
    }

    /// Require every configured target to equal its exact genesis before an
    /// effectd authority store is created for the first time.
    ///
    /// This closes the avoidable interval in which a stale reviewed config
    /// could initialize an immutable store and only then fail live activation.
    /// The ordinary post-store governed-history check remains mandatory
    /// because an external target owner can still race this observation.
    ///
    /// # Errors
    ///
    /// Returns an error for helper, repository, layout, ref, object, tree,
    /// cleanliness, checked-out-state, or exact state-identity drift.
    pub fn require_configured_genesis(&self) -> Result<(), ManagedPointerError> {
        for (target, expected) in self.activation_geneses() {
            self.require_activation_state(&target, &expected)?;
        }
        Ok(())
    }

    /// Require one enrolled target to select the exact object and tree derived
    /// from governed genesis plus ordered terminal activation history.
    pub(crate) fn require_activation_state(
        &self,
        target: &TargetId,
        expected: &ManagedPointerActivationHeadV1,
    ) -> Result<(), ManagedPointerError> {
        let runtime = self
            .targets
            .get(target)
            .ok_or(ManagedPointerError::TargetUnavailable)?;
        let repository = runtime.open_repository()?;
        runtime.require_enrolled_repository(&repository)?;
        let state = runtime.observe_repository_state(&repository)?;
        if !state.clean
            || state.reference_checked_out
            || state.current_object != expected.object
            || state.current_tree != expected.tree
            || state.evidence.identity()? != expected.state_identity
        {
            return Err(ManagedPointerError::PrestateDrift(
                "live target does not match exact governed activation history".to_owned(),
            ));
        }
        Ok(())
    }

    /// Revalidate the static helper, staging-root, repository-layout, owner,
    /// and launch-profile cut used by a live production activation value.
    ///
    /// This method creates no standing and performs no governed-target write.
    /// Its digest is process-lifecycle evidence only.
    pub(crate) fn production_readiness(&self) -> Result<Digest, ManagedPointerError> {
        #[derive(Serialize)]
        struct TargetReadinessV1<'a> {
            target: &'a TargetId,
            helper_executable: Digest,
            helper_launch_profile: &'a Digest,
            activation_genesis_object: &'a str,
            activation_genesis_tree: &'a str,
            activation_genesis_state: &'a Digest,
            staging_root: String,
            staging_device: u64,
            staging_inode: u64,
            repository_identity: Digest,
        }

        let landlock_abi = if self.targets.is_empty() {
            None
        } else {
            let version = crate::exact_exec::landlock_abi_version()?;
            if version < 3 {
                return Err(ManagedPointerError::UnsafeRepository(
                    "Landlock ABI 3 or newer is required for descriptor-bound Git mutation"
                        .to_owned(),
                ));
            }
            Some(version)
        };
        let mut evidence = Vec::with_capacity(self.targets.len());
        for (target, runtime) in &self.targets {
            let mut git = runtime
                .git
                .lock()
                .map_err(|_| ManagedPointerError::GitIdentityMismatch)?;
            git.revalidate()?;
            let helper_executable = git.executable.clone();
            drop(git);

            let staging = open_absolute_directory(&runtime.staging_root)?;
            let staging_stat = rustix::fs::fstat(&staging).map_err(errno_to_io)?;
            validate_production_staging_custody(
                FileType::from_raw_mode(staging_stat.st_mode).is_dir(),
                staging_stat.st_uid,
                staging_stat.st_gid,
                staging_stat.st_mode,
            )?;

            let repository = runtime.open_repository()?;
            runtime.require_enrolled_repository(&repository)?;
            let state = runtime.observe_repository_state(&repository)?;
            if !state.clean || state.reference_checked_out {
                return Err(ManagedPointerError::PrestateDrift(
                    "production target is dirty or its managed ref is checked out".to_owned(),
                ));
            }
            evidence.push(TargetReadinessV1 {
                target,
                helper_executable,
                helper_launch_profile: &runtime.launch_profile,
                activation_genesis_object: &runtime.activation_genesis_object,
                activation_genesis_tree: &runtime.activation_genesis_tree,
                activation_genesis_state: &runtime.activation_genesis_state,
                staging_root: utf8_path(&runtime.staging_root)?,
                staging_device: staging_stat.st_dev,
                staging_inode: staging_stat.st_ino,
                repository_identity: repository.identity_evidence.identity()?,
            });
        }
        Ok(Digest::from_serializable(&(
            MANAGED_POINTER_READINESS_SCHEMA_V1,
            &self.security_profile_identity,
            landlock_abi,
            evidence,
        ))?)
    }

    /// Mints one non-serializable, target-scoped preparation standing from the
    /// active broker context. Only its receipt can cross a durable boundary.
    pub(crate) fn preparation_standing(
        &self,
        target: &TargetId,
        context: ManagedPointerPreparationStandingContextV1,
    ) -> Result<ManagedPointerPreparationStandingV1, ManagedPointerError> {
        let target_runtime = self
            .targets
            .get(target)
            .ok_or(ManagedPointerError::TargetUnavailable)?;
        if context.security_profile_identity != self.security_profile_identity
            || context.max_artifact_bytes == 0
        {
            return Err(ManagedPointerError::PreparationStandingScopeMismatch);
        }
        let quarantine_budget_bytes = context
            .max_artifact_bytes
            .checked_mul(2)
            .ok_or(ManagedPointerError::PreparationBudgetExceeded)?;
        let expires_at_unix_ms = context
            .now_unix_ms
            .checked_add(target_runtime.promotion_ttl_ms)
            .ok_or(ManagedPointerError::PreparationStandingScopeMismatch)?;
        let receipt = ManagedPointerPreparationStandingReceiptV1 {
            schema: MANAGED_POINTER_PREPARATION_STANDING_SCHEMA_V1.to_owned(),
            authority_domain: context.authority_domain,
            epoch: context.epoch,
            target: target.clone(),
            catalog_identity: context.catalog_identity,
            security_profile_identity: context.security_profile_identity,
            issued_at_unix_ms: context.now_unix_ms,
            expires_at_unix_ms,
            max_artifact_bytes: context.max_artifact_bytes,
            quarantine_budget_bytes,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        receipt
            .identity()
            .map_err(|_| ManagedPointerError::PreparationStandingScopeMismatch)?;
        Ok(ManagedPointerPreparationStandingV1 { receipt })
    }

    /// Consumes live preparation standing, performs the existing strict
    /// quarantine preparation, and proves the protected repository projection
    /// was identical before and after it.
    pub(crate) fn prepare_candidate_from_store(
        &self,
        standing: Option<ManagedPointerPreparationStandingV1>,
        store: &Store,
        artifact: &Digest,
        now_unix_ms: u64,
    ) -> Result<ManagedPointerPreparedObservationV1, ManagedPointerError> {
        let standing = require_preparation_standing(standing)?;
        let receipt = &standing.receipt;
        receipt
            .identity()
            .map_err(|_| ManagedPointerError::PreparationStandingScopeMismatch)?;
        if now_unix_ms < receipt.issued_at_unix_ms
            || now_unix_ms >= receipt.expires_at_unix_ms
            || receipt.security_profile_identity != self.security_profile_identity
        {
            return Err(ManagedPointerError::PreparationStandingScopeMismatch);
        }
        let bytes = store.read_blob(artifact, receipt.max_artifact_bytes)?;
        self.prepare_candidate_bytes(standing, artifact, &bytes, now_unix_ms)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_candidate_bytes(
        &self,
        standing: ManagedPointerPreparationStandingV1,
        artifact: &Digest,
        bytes: &[u8],
        now_unix_ms: u64,
    ) -> Result<ManagedPointerPreparedObservationV1, ManagedPointerError> {
        let receipt = standing.receipt;
        let target_runtime = self
            .targets
            .get(&receipt.target)
            .ok_or(ManagedPointerError::TargetUnavailable)?;
        let artifact_byte_length = u64::try_from(bytes.len())
            .map_err(|_| ManagedPointerError::PreparationBudgetExceeded)?;
        if now_unix_ms < receipt.issued_at_unix_ms
            || now_unix_ms >= receipt.expires_at_unix_ms
            || artifact_byte_length == 0
            || artifact_byte_length > receipt.max_artifact_bytes
            || Digest::hash_bytes(bytes) != *artifact
        {
            return Err(ManagedPointerError::PreparationBudgetExceeded);
        }

        let before_repository = target_runtime.open_repository()?;
        target_runtime.require_enrolled_repository(&before_repository)?;
        let before = target_runtime.observe_repository_state(&before_repository)?;
        if !before.clean || before.reference_checked_out {
            return Err(ManagedPointerError::PrestateDrift(
                "candidate basis is dirty or checked out".to_owned(),
            ));
        }
        let mut staged = target_runtime.stage_candidate(artifact, bytes, before.object_format)?;
        let pack_byte_length = staged.pack.metadata()?.len();
        let charged_quarantine_bytes = artifact_byte_length
            .checked_add(pack_byte_length)
            .ok_or(ManagedPointerError::PreparationBudgetExceeded)?;
        if charged_quarantine_bytes > receipt.quarantine_budget_bytes {
            return Err(ManagedPointerError::PreparationBudgetExceeded);
        }

        let after_repository = target_runtime.open_repository()?;
        target_runtime.require_enrolled_repository(&after_repository)?;
        let after = target_runtime.observe_repository_state(&after_repository)?;
        let before_repository_identity = before_repository.identity_evidence.identity()?;
        let after_repository_identity = after_repository.identity_evidence.identity()?;
        let before_prestate_identity = before.evidence.identity()?;
        let after_prestate_identity = after.evidence.identity()?;
        if before_repository_identity != after_repository_identity
            || before_prestate_identity != after_prestate_identity
            || before.current_object != after.current_object
            || before.current_tree != after.current_tree
            || before.clean != after.clean
            || before.reference_checked_out != after.reference_checked_out
        {
            return Err(ManagedPointerError::ProtectedProjectionChanged);
        }

        let exact_basis = ManagedPointerExactBasisV1 {
            schema: MANAGED_POINTER_EXACT_BASIS_SCHEMA_V1.to_owned(),
            authority_domain: receipt.authority_domain.clone(),
            epoch: receipt.epoch,
            target: receipt.target.clone(),
            catalog_identity: receipt.catalog_identity.clone(),
            security_profile_identity: receipt.security_profile_identity.clone(),
            reference: target_runtime.reference.clone(),
            repository_identity: before_repository_identity,
            prestate_identity: before_prestate_identity,
            repository_device: before_repository.identity_evidence.repository_device,
            repository_inode: before_repository.identity_evidence.repository_inode,
            git_directory_device: before_repository.identity_evidence.git_directory_device,
            git_directory_inode: before_repository.identity_evidence.git_directory_inode,
            uid: before_repository.identity_evidence.uid,
            gid: before_repository.identity_evidence.gid,
            object_format: before.object_format,
            current_object: before.current_object.clone(),
            current_tree: before.current_tree.clone(),
        };
        let exact_basis_identity = exact_basis
            .identity()
            .map_err(|_| ManagedPointerError::BindingMismatch)?;
        let git = target_runtime
            .git
            .lock()
            .map_err(|_| ManagedPointerError::GitIdentityMismatch)?;
        let complete_inputs = ManagedPointerCompleteInputsV1 {
            schema: MANAGED_POINTER_COMPLETE_INPUTS_SCHEMA_V1.to_owned(),
            exact_basis: exact_basis_identity.clone(),
            artifact: artifact.clone(),
            artifact_byte_length,
            candidate_pack_digest: staged.pack_digest.clone(),
            candidate_object: staged.candidate_object.clone(),
            candidate_tree: staged.candidate_tree.clone(),
            candidate_parent: staged.candidate_parent.clone(),
            staging_root: utf8_path(&target_runtime.staging_root)?,
            helper_executable: git.executable.clone(),
            helper_launch_profile: target_runtime.launch_profile.clone(),
            max_artifact_bytes: receipt.max_artifact_bytes,
            quarantine_budget_bytes: receipt.quarantine_budget_bytes,
        };
        drop(git);
        let complete_inputs_identity = complete_inputs
            .identity(before.object_format)
            .map_err(|_| ManagedPointerError::BindingMismatch)?;
        let effects = ManagedPointerPreparationEffectsV1 {
            schema: MANAGED_POINTER_PREPARATION_EFFECTS_SCHEMA_V1.to_owned(),
            candidate_custody_bytes: artifact_byte_length,
            charged_quarantine_bytes,
            target_object_database_bytes: 0,
            authoritative_pointer_writes: 0,
            network_requests: 0,
        };
        let standing_identity = receipt
            .identity()
            .map_err(|_| ManagedPointerError::PreparationStandingScopeMismatch)?;
        let preparation_receipt = ManagedPointerCandidatePreparationReceiptV1 {
            schema: MANAGED_POINTER_CANDIDATE_PREPARATION_SCHEMA_V1.to_owned(),
            standing: standing_identity,
            exact_basis: exact_basis_identity,
            complete_inputs: complete_inputs_identity,
            artifact: artifact.clone(),
            protected_prestate: exact_basis
                .identity()
                .map_err(|_| ManagedPointerError::BindingMismatch)?,
            protected_poststate: exact_basis
                .identity()
                .map_err(|_| ManagedPointerError::BindingMismatch)?,
            effects,
        };
        let candidate = PreparedManagedPointerCandidateV1 {
            schema: MANAGED_POINTER_PREPARED_CANDIDATE_SCHEMA_V1.to_owned(),
            preparation_standing: receipt,
            exact_basis,
            complete_inputs,
            preparation_receipt,
        };
        candidate
            .identity()
            .map_err(|_| ManagedPointerError::BindingMismatch)?;
        let observation = target_observation(&before_repository, &before, &staged)?;
        // Keep the candidate pack alive through observation construction; the
        // staging guard removes quarantine residue when this function returns.
        staged.pack.rewind()?;
        Ok(ManagedPointerPreparedObservationV1 {
            observation,
            candidate,
        })
    }

    /// Observes the exact target and validates one artifact-bearing candidate
    /// in broker-owned staging without writing the governed repository.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown targets, artifact substitution, unsafe
    /// repository resolution, or a malformed/non-self-contained bundle.
    pub fn observe_candidate_bytes(
        &self,
        target: &TargetId,
        artifact: &Digest,
        bytes: &[u8],
    ) -> Result<TargetObservationV1, ManagedPointerError> {
        let target_runtime = self
            .targets
            .get(target)
            .ok_or(ManagedPointerError::TargetUnavailable)?;
        if Digest::hash_bytes(bytes) != *artifact {
            return Err(ManagedPointerError::Artifact(
                "candidate bytes differ from the admitted digest".to_owned(),
            ));
        }
        let repository = target_runtime.open_repository()?;
        let state = target_runtime.observe_repository_state(&repository)?;
        let staged = target_runtime.stage_candidate(artifact, bytes, state.object_format)?;
        target_observation(&repository, &state, &staged)
    }

    /// Loads exact artifact bytes from broker custody and performs the same
    /// read-only candidate observation.
    ///
    /// # Errors
    ///
    /// Returns an error for store custody, size, target, repository, or bundle
    /// validation failures.
    pub fn observe_candidate_from_store(
        &self,
        store: &Store,
        target: &TargetId,
        artifact: &Digest,
        maximum_bytes: u64,
    ) -> Result<TargetObservationV1, ManagedPointerError> {
        let bytes = store.read_blob(artifact, maximum_bytes)?;
        self.observe_candidate_bytes(target, artifact, &bytes)
    }

    /// Re-observes live target state for an exact canonical promotion. The
    /// candidate facts are copied from the canonical effect; no artifact is
    /// reinterpreted during reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-promotion effect, catalog/runtime mismatch,
    /// or an unsafe/unobservable repository.
    pub fn observe_canonical(
        &self,
        effect: &CanonicalEffectV1,
    ) -> Result<TargetObservationV1, ManagedPointerError> {
        let fields = CanonicalPointerFieldsV1::from_effect(effect)?;
        let target_runtime = self
            .targets
            .get(fields.target)
            .ok_or(ManagedPointerError::TargetUnavailable)?;
        target_runtime.verify_canonical_bindings(&fields)?;
        let repository = target_runtime.open_repository()?;
        let state = target_runtime.observe_repository_state(&repository)?;
        Ok(TargetObservationV1::ManagedPointer {
            current_object: state.current_object,
            current_tree: state.current_tree,
            candidate_object: fields.new_object.to_owned(),
            candidate_tree: fields.expected_post_tree.to_owned(),
            candidate_parent: fields.expected_object.to_owned(),
            candidate_pack_digest: fields.candidate_pack_digest.to_owned(),
            object_format: fields.object_format,
            repository_identity: repository.identity_evidence.identity()?,
            prestate_identity: state.evidence.identity()?,
            repository_device: repository.identity_evidence.repository_device,
            repository_inode: repository.identity_evidence.repository_inode,
            git_directory_device: repository.identity_evidence.git_directory_device,
            git_directory_inode: repository.identity_evidence.git_directory_inode,
            repository_uid: repository.identity_evidence.uid,
            repository_gid: repository.identity_evidence.gid,
            clean: state.clean,
            reference_checked_out: state.reference_checked_out,
        })
    }

    /// Reconstructs live single-use promotion standing from exact persisted
    /// candidate history, candidate-and-basis ratification, and a fresh target
    /// observation. The returned value cannot survive restart.
    pub(crate) fn promotion_standing(
        &self,
        context: &ManagedPointerExecutionContextV1,
        effect: &CanonicalEffectV1,
        candidate: &PreparedManagedPointerCandidateV1,
        ratification: &ManagedPointerCandidateRatificationV1,
        now_unix_ms: u64,
    ) -> Result<ManagedPointerPromotionStandingV1, ManagedPointerError> {
        let fields = CanonicalPointerFieldsV1::from_effect(effect)?;
        let candidate_identity = candidate
            .identity()
            .map_err(|_| ManagedPointerError::PromotionStandingMismatch)?;
        let exact_basis = candidate
            .exact_basis
            .identity()
            .map_err(|_| ManagedPointerError::PromotionStandingMismatch)?;
        let complete_inputs = candidate
            .complete_inputs
            .identity(candidate.exact_basis.object_format)
            .map_err(|_| ManagedPointerError::PromotionStandingMismatch)?;
        let preparation_receipt = candidate
            .preparation_receipt
            .identity()
            .map_err(|_| ManagedPointerError::PromotionStandingMismatch)?;
        ratification
            .verify_bindings(&context.proposal, candidate, &context.authorization)
            .map_err(|_| ManagedPointerError::PromotionStandingMismatch)?;
        if candidate_identity != *fields.prepared_candidate
            || exact_basis != *fields.exact_basis
            || complete_inputs != *fields.complete_inputs
            || preparation_receipt != *fields.candidate_preparation_receipt
            || candidate.exact_basis.target != *fields.target
            || candidate.exact_basis.repository_identity != *fields.repository_identity
            || candidate.exact_basis.prestate_identity != *fields.prestate_identity
            || candidate.exact_basis.current_object != fields.expected_object
            || candidate.exact_basis.current_tree != fields.expected_tree
            || candidate.complete_inputs.artifact != *fields.artifact
            || candidate.complete_inputs.candidate_pack_digest != *fields.candidate_pack_digest
            || candidate.complete_inputs.candidate_object != fields.new_object
            || candidate.complete_inputs.candidate_tree != fields.expected_post_tree
            || now_unix_ms >= fields.expires_unix_ms
        {
            return Err(ManagedPointerError::PromotionStandingMismatch);
        }
        let target_runtime = self
            .targets
            .get(fields.target)
            .ok_or(ManagedPointerError::TargetUnavailable)?;
        target_runtime.verify_canonical_bindings(&fields)?;
        let repository = target_runtime.open_repository()?;
        target_runtime.require_canonical_repository(&fields, &repository)?;
        let state = target_runtime.observe_repository_state(&repository)?;
        require_exact_prestate(&fields, &state)?;
        let current_basis = ManagedPointerExactBasisV1 {
            schema: MANAGED_POINTER_EXACT_BASIS_SCHEMA_V1.to_owned(),
            authority_domain: candidate.exact_basis.authority_domain.clone(),
            epoch: candidate.exact_basis.epoch,
            target: fields.target.clone(),
            catalog_identity: candidate.exact_basis.catalog_identity.clone(),
            security_profile_identity: candidate.exact_basis.security_profile_identity.clone(),
            reference: fields.reference.to_owned(),
            repository_identity: repository.identity_evidence.identity()?,
            prestate_identity: state.evidence.identity()?,
            repository_device: repository.identity_evidence.repository_device,
            repository_inode: repository.identity_evidence.repository_inode,
            git_directory_device: repository.identity_evidence.git_directory_device,
            git_directory_inode: repository.identity_evidence.git_directory_inode,
            uid: repository.identity_evidence.uid,
            gid: repository.identity_evidence.gid,
            object_format: state.object_format,
            current_object: state.current_object,
            current_tree: state.current_tree,
        }
        .identity()
        .map_err(|_| ManagedPointerError::PromotionStandingMismatch)?;
        if current_basis != exact_basis {
            return Err(ManagedPointerError::PromotionStandingMismatch);
        }
        let candidate_ratification = ratification
            .identity()
            .map_err(|_| ManagedPointerError::PromotionStandingMismatch)?;
        let receipt = ManagedPointerPromotionStandingReceiptV1 {
            schema: MANAGED_POINTER_PROMOTION_STANDING_RECEIPT_SCHEMA_V1.to_owned(),
            proposal: context.proposal.clone(),
            authorization: context.authorization.clone(),
            candidate_ratification,
            candidate: candidate_identity,
            exact_basis,
            current_basis,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: fields.expires_unix_ms,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        receipt.identity()?;
        Ok(ManagedPointerPromotionStandingV1 { receipt })
    }

    /// Performs all reversible promotion work, revalidates the exact
    /// descriptor-bound prestate, and returns the non-cloneable value that may
    /// cross the ref-CAS boundary only after its checkpoint is durable.
    ///
    /// # Errors
    ///
    /// Returns an exact known-failure execution receipt. Preparation never
    /// returns success or changes the managed ref; it may import and durably
    /// sync unreachable candidate objects before producing its checkpoint.
    #[allow(clippy::needless_pass_by_value, clippy::result_large_err)]
    #[cfg(test)]
    pub fn prepare(
        &self,
        context: ManagedPointerExecutionContextV1,
        effect: &CanonicalEffectV1,
        artifact_bytes: &[u8],
        now_unix_ms: u64,
    ) -> Result<PreparedManagedPointerV1, ExecutionReceiptV1> {
        let standing = test_promotion_standing(&context, effect, now_unix_ms)
            .map_err(|error| failure_receipt(&context, effect, &error))?;
        self.prepare_inner(
            standing,
            context.clone(),
            effect,
            artifact_bytes,
            now_unix_ms,
        )
        .map_err(|error| failure_receipt(&context, effect, &error))
    }

    /// Loads and rehashes the exact candidate bundle from effectd custody
    /// before entering reversible preparation.
    ///
    /// # Errors
    ///
    /// Returns an exact known-failure receipt for missing, oversized,
    /// substituted, or otherwise invalid custody bytes.
    #[allow(clippy::result_large_err)]
    pub(crate) fn prepare_from_store(
        &self,
        standing: ManagedPointerPromotionStandingV1,
        store: &Store,
        context: &ManagedPointerExecutionContextV1,
        effect: &CanonicalEffectV1,
        maximum_bytes: u64,
        now_unix_ms: u64,
    ) -> Result<PreparedManagedPointerV1, ExecutionReceiptV1> {
        let fields = match CanonicalPointerFieldsV1::from_effect(effect) {
            Ok(fields) => fields,
            Err(error) => return Err(failure_receipt(context, effect, &error)),
        };
        let bytes = match store.read_blob(fields.artifact, maximum_bytes) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(receipt_with_outcome(
                    context,
                    effect,
                    ExecutionOutcomeV1::Failed {
                        failure: ExecutionFailureV1 {
                            code: ExecutionFailureCodeV1::ArtifactUnavailable,
                            phase: ExecutionPhaseV1::ArtifactLoad,
                            detail: "exact promotion artifact is unavailable".to_owned(),
                            source_code: Some(error.to_string()),
                            evidence: None,
                        },
                    },
                ));
            }
        };
        self.prepare_inner(standing, context.clone(), effect, &bytes, now_unix_ms)
            .map_err(|error| failure_receipt(context, effect, &error))
    }

    fn prepare_inner(
        &self,
        standing: ManagedPointerPromotionStandingV1,
        context: ManagedPointerExecutionContextV1,
        effect: &CanonicalEffectV1,
        artifact_bytes: &[u8],
        now_unix_ms: u64,
    ) -> Result<PreparedManagedPointerV1, ManagedPointerError> {
        let fields = CanonicalPointerFieldsV1::from_effect(effect)?;
        let standing_receipt = standing.receipt;
        if standing_receipt.proposal != context.proposal
            || standing_receipt.authorization != context.authorization
            || standing_receipt.candidate != *fields.prepared_candidate
            || standing_receipt.exact_basis != *fields.exact_basis
            || standing_receipt.current_basis != *fields.exact_basis
            || now_unix_ms < standing_receipt.issued_at_unix_ms
            || now_unix_ms >= standing_receipt.expires_at_unix_ms
        {
            return Err(ManagedPointerError::PromotionStandingMismatch);
        }
        standing_receipt.identity()?;
        let target_runtime = self
            .targets
            .get(fields.target)
            .ok_or(ManagedPointerError::TargetUnavailable)?;
        target_runtime.verify_canonical_bindings(&fields)?;
        if now_unix_ms >= fields.expires_unix_ms {
            return Err(ManagedPointerError::PrestateDrift(
                "promotion authority is expired".to_owned(),
            ));
        }
        if Digest::hash_bytes(artifact_bytes) != *fields.artifact {
            return Err(ManagedPointerError::Artifact(
                "candidate bytes differ from the canonical artifact".to_owned(),
            ));
        }
        let repository = target_runtime.open_repository()?;
        target_runtime.require_canonical_repository(&fields, &repository)?;
        let state = target_runtime.observe_repository_state(&repository)?;
        require_exact_prestate(&fields, &state)?;
        let mut staged = target_runtime.stage_candidate(
            fields.artifact,
            artifact_bytes,
            fields.object_format,
        )?;
        if staged.candidate_object != fields.new_object
            || staged.candidate_tree != fields.expected_post_tree
            || staged.candidate_parent != fields.expected_object
            || staged.pack_digest != *fields.candidate_pack_digest
            || staged.object_format != fields.object_format
        {
            return Err(ManagedPointerError::Artifact(
                "staged bundle facts differ from the canonical effect".to_owned(),
            ));
        }
        // Reopen after staging so a slow bundle cannot hide target drift.
        let revalidated_repository = target_runtime.open_repository()?;
        target_runtime.require_canonical_repository(&fields, &revalidated_repository)?;
        let revalidated = target_runtime.observe_repository_state(&revalidated_repository)?;
        require_exact_prestate(&fields, &revalidated)?;
        let imported = target_runtime.import_pack(
            &revalidated_repository,
            &mut staged.pack,
            fields.object_format,
            fields.candidate_pack_digest,
        )?;
        target_runtime.verify_imported_candidate(
            &revalidated_repository,
            fields.new_object,
            fields.expected_post_tree,
            fields.object_format,
        )?;
        // Importing unreachable objects is reversible preparation. Prove the
        // authoritative ref and worktree prestate again before issuing the
        // checkpoint which may arm the only CAS.
        let checkpoint_repository = target_runtime.open_repository()?;
        target_runtime.require_canonical_repository(&fields, &checkpoint_repository)?;
        let checkpoint_state = target_runtime.observe_repository_state(&checkpoint_repository)?;
        require_exact_prestate(&fields, &checkpoint_state)?;
        let object_import_evidence = Digest::from_serializable(&imported)?;
        let evidence = ManagedPointerPreparationEvidenceV1 {
            schema: MANAGED_POINTER_PREPARATION_SCHEMA_V2.to_owned(),
            execution: context.clone(),
            operation_id: fields.operation_id.clone(),
            prepared_candidate: fields.prepared_candidate.clone(),
            candidate_ratification: standing_receipt.candidate_ratification.clone(),
            promotion_standing: standing_receipt,
            artifact: fields.artifact.clone(),
            candidate_pack: fields.candidate_pack_digest.clone(),
            imported_pack_checksum: imported.pack_checksum.clone(),
            object_import_evidence,
            imported_pack_evidence: imported,
            repository_identity: fields.repository_identity.clone(),
            repository_layout: checkpoint_repository.identity_evidence.clone(),
            prestate: checkpoint_state.evidence.clone(),
            expected_object: fields.expected_object.to_owned(),
            expected_tree: fields.expected_tree.to_owned(),
            new_object: fields.new_object.to_owned(),
            expected_post_tree: fields.expected_post_tree.to_owned(),
        };
        let checkpoint = evidence.checkpoint()?;
        Ok(PreparedManagedPointerV1 {
            effect: effect.clone(),
            context,
            target: fields.target.clone(),
            pack: staged.pack,
            _stage: staged.stage,
            evidence,
            checkpoint,
        })
    }

    /// Consumes one prepared promotion and crosses the exact ref-CAS boundary
    /// at most once. The returned receipt always binds the preparation's
    /// proposal, authorization, attempt, effect index, and canonical effect.
    #[must_use]
    pub(crate) fn commit(
        &self,
        prepared: PreparedManagedPointerV1,
        now_unix_ms: u64,
    ) -> ManagedPointerCommitResultV1 {
        self.commit_inner(prepared, now_unix_ms, CommitFailpointV1::None)
    }

    fn commit_inner(
        &self,
        prepared: PreparedManagedPointerV1,
        now_unix_ms: u64,
        failpoint: CommitFailpointV1,
    ) -> ManagedPointerCommitResultV1 {
        self.commit_inner_with_clock(
            prepared,
            now_unix_ms,
            failpoint,
            &SystemManagedPointerClockV1,
        )
    }

    fn commit_inner_with_clock(
        &self,
        mut prepared: PreparedManagedPointerV1,
        now_unix_ms: u64,
        failpoint: CommitFailpointV1,
        clock: &dyn ManagedPointerClockV1,
    ) -> ManagedPointerCommitResultV1 {
        let effect = prepared.effect.clone();
        let context = prepared.context.clone();
        let (outcome, commit_evidence, poststate_evidence, activation_receipt) =
            match self.try_commit(&mut prepared, now_unix_ms, failpoint, clock) {
                Ok(success) => (
                    ExecutionOutcomeV1::Succeeded {
                        success: success.success,
                    },
                    Some(success.commit_evidence),
                    Some(success.poststate_evidence),
                    Some(success.activation_receipt),
                ),
                Err(CommitErrorV1::Failed(error)) => (failure_outcome(&error), None, None, None),
                Err(CommitErrorV1::Indeterminate {
                    detail,
                    phase,
                    evidence,
                }) => (
                    ExecutionOutcomeV1::Indeterminate {
                        envelope: ExecutionIndeterminateV1 {
                            code: ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                            phase,
                            detail,
                            source_code: Some("managed_pointer_commit_ambiguous".to_owned()),
                            evidence,
                        },
                    },
                    None,
                    None,
                    None,
                ),
            };
        ManagedPointerCommitResultV1 {
            receipt: receipt_with_outcome(&context, &effect, outcome),
            commit_evidence,
            poststate_evidence,
            activation_receipt,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn try_commit(
        &self,
        prepared: &mut PreparedManagedPointerV1,
        now_unix_ms: u64,
        failpoint: CommitFailpointV1,
        clock: &dyn ManagedPointerClockV1,
    ) -> Result<ManagedPointerCommitSuccessV1, CommitErrorV1> {
        let fields = CanonicalPointerFieldsV1::from_effect(&prepared.effect)
            .map_err(CommitErrorV1::Failed)?;
        let target_runtime = self
            .targets
            .get(&prepared.target)
            .ok_or(ManagedPointerError::TargetUnavailable)
            .map_err(CommitErrorV1::Failed)?;
        target_runtime
            .verify_canonical_bindings(&fields)
            .map_err(CommitErrorV1::Failed)?;
        if now_unix_ms >= fields.expires_unix_ms {
            return Err(CommitErrorV1::Failed(ManagedPointerError::PrestateDrift(
                "promotion authority expired before commit".to_owned(),
            )));
        }
        prepared
            .evidence
            .promotion_standing
            .identity()
            .map_err(CommitErrorV1::Failed)?;
        if prepared.evidence.execution != prepared.context
            || prepared
                .evidence
                .checkpoint()
                .map_err(CommitErrorV1::Failed)?
                != prepared.checkpoint
            || prepared.evidence.operation_id != *fields.operation_id
            || prepared.evidence.prepared_candidate != *fields.prepared_candidate
            || prepared.evidence.candidate_ratification
                != prepared.evidence.promotion_standing.candidate_ratification
            || prepared.evidence.promotion_standing.candidate != *fields.prepared_candidate
            || prepared.evidence.promotion_standing.exact_basis != *fields.exact_basis
            || prepared.evidence.repository_identity != *fields.repository_identity
            || prepared
                .evidence
                .repository_layout
                .identity()
                .map_err(CommitErrorV1::Failed)?
                != *fields.repository_identity
            || prepared
                .evidence
                .prestate
                .identity()
                .map_err(CommitErrorV1::Failed)?
                != *fields.prestate_identity
            || Digest::from_serializable(&prepared.evidence.imported_pack_evidence)
                .map_err(ManagedPointerError::from)
                .map_err(CommitErrorV1::Failed)?
                != prepared.evidence.object_import_evidence
        {
            return Err(CommitErrorV1::Failed(ManagedPointerError::BindingMismatch));
        }
        let observed_pack = hash_file(&mut prepared.pack).map_err(CommitErrorV1::Failed)?;
        if observed_pack != *fields.candidate_pack_digest {
            return Err(CommitErrorV1::Failed(ManagedPointerError::Artifact(
                "prepared PACK changed before commit".to_owned(),
            )));
        }
        let repository = target_runtime
            .open_repository()
            .map_err(CommitErrorV1::Failed)?;
        target_runtime
            .require_canonical_repository(&fields, &repository)
            .map_err(CommitErrorV1::Failed)?;
        target_runtime
            .verify_imported_candidate(
                &repository,
                fields.new_object,
                fields.expected_post_tree,
                fields.object_format,
            )
            .map_err(CommitErrorV1::Failed)?;
        let before_cas_repository =
            target_runtime
                .open_repository()
                .map_err(|error| CommitErrorV1::Indeterminate {
                    detail: format!("target could not be revalidated after object import: {error}"),
                    phase: ExecutionPhaseV1::PrestateCheck,
                    evidence: None,
                })?;
        target_runtime
            .require_canonical_repository(&fields, &before_cas_repository)
            .map_err(CommitErrorV1::Failed)?;
        let before_cas = target_runtime
            .observe_repository_state(&before_cas_repository)
            .map_err(CommitErrorV1::Failed)?;
        require_exact_prestate(&fields, &before_cas).map_err(CommitErrorV1::Failed)?;
        if failpoint == CommitFailpointV1::BeforeCas {
            return Err(CommitErrorV1::Failed(ManagedPointerError::Git {
                operation: "test-before-cas",
                detail: "injected before the commit boundary".to_owned(),
            }));
        }

        let mut cas_environment = GitEnvironmentV1::default();
        cas_environment
            .descriptor_path("GIT_DIR", &before_cas_repository.git_directory, None)
            .map_err(CommitErrorV1::Failed)?;
        cas_environment
            // `git update-ref` also transacts `HEAD.lock` when a bare
            // repository's HEAD symbolically selects the managed ref. The
            // UAPI cannot admit that one not-yet-created file without its
            // parent, so the fixed update-ref child receives the exact
            // descriptor-opened Git directory and no other target root.
            .admit_write_root(&before_cas_repository.git_directory)
            .map_err(CommitErrorV1::Failed)?;
        let cas = target_runtime.run_git_update_ref(
            &[
                OsString::from("--no-deref"),
                OsString::from(fields.reference),
                OsString::from(fields.new_object),
                OsString::from(fields.expected_object),
            ],
            &cas_environment,
            CommitLaunchGuardV1 {
                clock,
                expires_unix_ms: fields.expires_unix_ms,
            },
        );
        let cas_output = match cas {
            Ok(output) => output,
            Err(error @ ManagedPointerError::PromotionExpiredBeforeCas) => {
                return Err(CommitErrorV1::Failed(error));
            }
            Err(error) => {
                return Err(CommitErrorV1::Indeterminate {
                    detail: format!("ref CAS transport failed: {error}"),
                    phase: ExecutionPhaseV1::PointerCas,
                    evidence: None,
                });
            }
        };
        if !cas_output.status.success() {
            return self.classify_cas_rejection(
                target_runtime,
                &fields,
                sanitized_git_diagnostic(&cas_output.stderr),
            );
        }
        if failpoint == CommitFailpointV1::AfterCas {
            return Err(CommitErrorV1::Indeterminate {
                detail: "injected crash after the ref commit boundary".to_owned(),
                phase: ExecutionPhaseV1::PointerCas,
                evidence: None,
            });
        }
        let post_repository =
            target_runtime
                .open_repository()
                .map_err(|error| CommitErrorV1::Indeterminate {
                    detail: format!("target could not be reopened after ref CAS: {error}"),
                    phase: ExecutionPhaseV1::PointerCas,
                    evidence: None,
                })?;
        target_runtime
            .require_canonical_repository(&fields, &post_repository)
            .map_err(|error| CommitErrorV1::Indeterminate {
                detail: format!("target identity changed after ref CAS: {error}"),
                phase: ExecutionPhaseV1::PointerCas,
                evidence: None,
            })?;
        let post_before_sync = target_runtime
            .observe_repository_state(&post_repository)
            .map_err(|error| CommitErrorV1::Indeterminate {
                detail: format!("post-CAS readback failed: {error}"),
                phase: ExecutionPhaseV1::PointerCas,
                evidence: None,
            })?;
        if !exact_poststate(&fields, &post_before_sync) {
            return Err(CommitErrorV1::Indeterminate {
                detail: "post-CAS state contradicts the ratified poststate".to_owned(),
                phase: ExecutionPhaseV1::PointerCas,
                evidence: None,
            });
        }
        sync_reference(
            &post_repository.git_directory,
            fields.reference,
            target_runtime.uid,
            target_runtime.gid,
        )
        .map_err(|error| CommitErrorV1::Indeterminate {
            detail: format!("ref committed but durability sync failed: {error}"),
            phase: ExecutionPhaseV1::DirectorySync,
            evidence: None,
        })?;
        // The fsync path is itself a window in which an external target-owner
        // writer could move the ref. Reopen and independently observe the
        // durable state; success evidence is derived only from this final cut.
        let durable_repository =
            target_runtime
                .open_repository()
                .map_err(|error| CommitErrorV1::Indeterminate {
                    detail: format!("durable target could not be reopened after ref sync: {error}"),
                    phase: ExecutionPhaseV1::DirectorySync,
                    evidence: None,
                })?;
        target_runtime
            .require_canonical_repository(&fields, &durable_repository)
            .map_err(|error| CommitErrorV1::Indeterminate {
                detail: format!("durable target identity changed after ref sync: {error}"),
                phase: ExecutionPhaseV1::DirectorySync,
                evidence: None,
            })?;
        let durable_post = target_runtime
            .observe_repository_state(&durable_repository)
            .map_err(|error| CommitErrorV1::Indeterminate {
                detail: format!("durable poststate readback failed: {error}"),
                phase: ExecutionPhaseV1::DirectorySync,
                evidence: None,
            })?;
        if !exact_poststate(&fields, &durable_post) {
            return Err(CommitErrorV1::Indeterminate {
                detail: "durable poststate contradicts the ratified poststate".to_owned(),
                phase: ExecutionPhaseV1::DirectorySync,
                evidence: None,
            });
        }
        let request_digest = Digest::from_serializable(&(
            "ag.managed-pointer.commit-request/v1",
            &prepared.context,
            &prepared.checkpoint,
            &prepared.effect,
        ))
        .map_err(ManagedPointerError::from)
        .map_err(CommitErrorV1::Failed)?;
        let commit_evidence = ManagedPointerCommitEvidenceV1 {
            schema: MANAGED_POINTER_COMMIT_EVIDENCE_SCHEMA_V1.to_owned(),
            execution: prepared.context.clone(),
            preparation_checkpoint: prepared.checkpoint.clone(),
            operation_id: fields.operation_id.clone(),
            request_digest,
            previous_object: fields.expected_object.to_owned(),
            previous_tree: fields.expected_tree.to_owned(),
            installed_object: durable_post.current_object.clone(),
            installed_tree: durable_post.current_tree.clone(),
            reference_fsynced: true,
        };
        let evidence = Digest::from_serializable(&commit_evidence)
            .map_err(ManagedPointerError::from)
            .map_err(|error| CommitErrorV1::Indeterminate {
                detail: format!("post-CAS evidence could not be encoded: {error}"),
                phase: ExecutionPhaseV1::ReceiptValidation,
                evidence: None,
            })?;
        let poststate_evidence_record = ManagedPointerPoststateEvidenceV1 {
            schema: MANAGED_POINTER_POSTSTATE_EVIDENCE_SCHEMA_V1.to_owned(),
            execution: prepared.context.clone(),
            preparation_checkpoint: prepared.checkpoint.clone(),
            repository_layout: durable_repository.identity_evidence.clone(),
            state: durable_post.evidence.clone(),
        };
        let poststate_evidence = Digest::from_serializable(&poststate_evidence_record)
            .map_err(ManagedPointerError::from)
            .map_err(|error| CommitErrorV1::Indeterminate {
                detail: format!("poststate evidence could not be encoded: {error}"),
                phase: ExecutionPhaseV1::ReceiptValidation,
                evidence: Some(evidence.clone()),
            })?;
        let activation_receipt = ManagedPointerActivationReceiptV1 {
            schema: MANAGED_POINTER_ACTIVATION_RECEIPT_SCHEMA_V1.to_owned(),
            effect: Digest::from_serializable(&prepared.effect)
                .map_err(ManagedPointerError::from)
                .map_err(CommitErrorV1::Failed)?,
            execution: prepared.context.clone(),
            target: fields.target.clone(),
            reference: fields.reference.to_owned(),
            operation_id: fields.operation_id.clone(),
            prepared_candidate: fields.prepared_candidate.clone(),
            candidate_ratification: prepared.evidence.candidate_ratification.clone(),
            exact_basis: fields.exact_basis.clone(),
            artifact: fields.artifact.clone(),
            candidate_pack: fields.candidate_pack_digest.clone(),
            preparation_checkpoint: prepared.checkpoint.clone(),
            repository_identity: fields.repository_identity.clone(),
            previous_object: fields.expected_object.to_owned(),
            previous_tree: fields.expected_tree.to_owned(),
            installed_object: fields.new_object.to_owned(),
            installed_tree: fields.expected_post_tree.to_owned(),
            commit: commit_evidence.clone(),
            poststate: poststate_evidence_record.clone(),
        };
        activation_receipt
            .identity(&prepared.effect)
            .map_err(|error| CommitErrorV1::Indeterminate {
                detail: format!("activation receipt could not be verified: {error}"),
                phase: ExecutionPhaseV1::ReceiptValidation,
                evidence: Some(evidence.clone()),
            })?;
        Ok(ManagedPointerCommitSuccessV1 {
            success: EffectSuccessV1::ManagedPointerPromotion {
                operation_id: fields.operation_id.clone(),
                candidate_pack_digest: fields.candidate_pack_digest.clone(),
                preparation_checkpoint: prepared.checkpoint.clone(),
                previous_object: fields.expected_object.to_owned(),
                previous_tree: fields.expected_tree.to_owned(),
                installed_object: fields.new_object.to_owned(),
                installed_tree: fields.expected_post_tree.to_owned(),
                evidence,
                poststate_evidence,
            },
            commit_evidence,
            poststate_evidence: poststate_evidence_record,
            activation_receipt,
        })
    }

    #[allow(clippy::unused_self)]
    fn classify_cas_rejection(
        &self,
        target: &ManagedPointerTargetV1,
        fields: &CanonicalPointerFieldsV1<'_>,
        detail: String,
    ) -> Result<ManagedPointerCommitSuccessV1, CommitErrorV1> {
        match target
            .open_repository()
            .and_then(|repository| target.observe_repository_state(&repository))
        {
            Ok(state) if exact_prestate(fields, &state) => {
                Err(CommitErrorV1::Failed(ManagedPointerError::Git {
                    operation: "update-ref",
                    detail,
                }))
            }
            _ => Err(CommitErrorV1::Indeterminate {
                detail: "ref CAS rejected but exact prestate cannot be proven".to_owned(),
                phase: ExecutionPhaseV1::PointerCas,
                evidence: None,
            }),
        }
    }
}

struct StagedCandidateV1 {
    stage: StagingDirectoryV1,
    pack: File,
    candidate_object: String,
    candidate_tree: String,
    candidate_parent: String,
    pack_digest: Digest,
    object_format: GitObjectFormatV1,
}

impl ManagedPointerTargetV1 {
    #[allow(clippy::too_many_lines)]
    fn stage_candidate(
        &self,
        artifact: &Digest,
        bytes: &[u8],
        repository_format: GitObjectFormatV1,
    ) -> Result<StagedCandidateV1, ManagedPointerError> {
        if Digest::hash_bytes(bytes) != *artifact {
            return Err(ManagedPointerError::Artifact(
                "candidate bytes differ from the admitted digest".to_owned(),
            ));
        }
        let bundle = parse_strict_bundle(bytes)?;
        if bundle.object_format != repository_format {
            return Err(ManagedPointerError::InvalidBundle(
                "bundle and repository object formats differ".to_owned(),
            ));
        }
        let stage =
            StagingDirectoryV1::create(&self.staging_root, self.production_staging_custody)?;
        self.initialize_staging(&stage, repository_format)?;
        let mut pack = File::from(
            rustix::fs::openat2(
                &stage.directory,
                "candidate.pack",
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(errno_to_io)?,
        );
        pack.write_all(bundle.pack)?;
        pack.sync_all()?;
        pack.seek(SeekFrom::Start(0))?;
        let mut environment = GitEnvironmentV1::default();
        environment.writable_descriptor_path("GIT_DIR", &stage.directory, None)?;
        let maximum = format!("--max-input-size={}", bundle.pack.len());
        self.run_git_checked(
            GitOperationV1::IndexPack,
            &[OsString::from("--stdin"), OsString::from(maximum)],
            &environment,
            Some(reopen_read_only(&pack)?),
            true,
        )?;
        let mut environment = GitEnvironmentV1::default();
        environment.descriptor_path("GIT_DIR", &stage.directory, None)?;
        let object_kind = self.run_git_checked(
            GitOperationV1::CatFile,
            &[OsString::from("-t"), OsString::from(&bundle.candidate)],
            &environment,
            None,
            true,
        )?;
        if object_kind != b"commit\n" {
            return Err(ManagedPointerError::InvalidBundle(
                "candidate tip is not a commit".to_owned(),
            ));
        }
        let parents = self.run_git_checked(
            GitOperationV1::RevList,
            &[
                OsString::from("--parents"),
                OsString::from("--max-count=1"),
                OsString::from(&bundle.candidate),
            ],
            &environment,
            None,
            true,
        )?;
        let parent_line = std::str::from_utf8(&parents)
            .map_err(|_| {
                ManagedPointerError::InvalidBundle("parent output is not UTF-8".to_owned())
            })?
            .strip_suffix('\n')
            .ok_or_else(|| {
                ManagedPointerError::InvalidBundle("parent output is malformed".to_owned())
            })?;
        let mut parent_fields = parent_line.split(' ');
        let observed_candidate = parent_fields.next().unwrap_or_default();
        let candidate_parent = parent_fields.next().unwrap_or_default();
        if observed_candidate != bundle.candidate
            || candidate_parent.is_empty()
            || parent_fields.next().is_some()
        {
            return Err(ManagedPointerError::InvalidBundle(
                "candidate must have exactly one parent".to_owned(),
            ));
        }
        let parent_kind = self.run_git_checked(
            GitOperationV1::CatFile,
            &[OsString::from("-t"), OsString::from(candidate_parent)],
            &environment,
            None,
            true,
        )?;
        if parent_kind != b"commit\n" {
            return Err(ManagedPointerError::InvalidBundle(
                "candidate parent is absent from the self-contained bundle".to_owned(),
            ));
        }
        let candidate_tree = canonical_object_output(
            &self.run_git_checked(
                GitOperationV1::RevParse,
                &[
                    OsString::from("--verify"),
                    OsString::from(format!("{}^{{tree}}", bundle.candidate)),
                ],
                &environment,
                None,
                true,
            )?,
            repository_format,
        )?;
        self.run_git_checked(
            GitOperationV1::Fsck,
            &[
                OsString::from("--strict"),
                OsString::from("--no-reflogs"),
                OsString::from(&bundle.candidate),
            ],
            &environment,
            None,
            true,
        )?;
        let tree_entries = self.run_git_checked(
            GitOperationV1::LsTree,
            &[
                OsString::from("-r"),
                OsString::from("-z"),
                OsString::from(&bundle.candidate),
            ],
            &environment,
            None,
            true,
        )?;
        if tree_entries
            .split(|byte| *byte == 0)
            .any(|entry| entry.starts_with(b"160000 "))
        {
            return Err(ManagedPointerError::InvalidBundle(
                "gitlinks are outside the promotion contract".to_owned(),
            ));
        }
        pack.seek(SeekFrom::Start(0))?;
        Ok(StagedCandidateV1 {
            stage,
            pack,
            candidate_object: bundle.candidate,
            candidate_tree,
            candidate_parent: candidate_parent.to_owned(),
            pack_digest: bundle.pack_digest,
            object_format: repository_format,
        })
    }

    fn import_pack(
        &self,
        repository: &OpenRepositoryV1,
        pack: &mut File,
        object_format: GitObjectFormatV1,
        candidate_pack_digest: &Digest,
    ) -> Result<ImportedPackEvidenceV1, ManagedPointerError> {
        if hash_file(pack)? != *candidate_pack_digest {
            return Err(ManagedPointerError::Artifact(
                "prepared PACK changed before object import".to_owned(),
            ));
        }
        pack.seek(SeekFrom::Start(0))?;
        let pack_size = pack.metadata()?.len();
        let mut environment = GitEnvironmentV1::default();
        environment.descriptor_path("GIT_DIR", &repository.git_directory, None)?;
        environment.descriptor_path("GIT_OBJECT_DIRECTORY", &repository.objects, None)?;
        environment.admit_write_root(&repository.pack_directory)?;
        let output = self.run_git(
            GitOperationV1::IndexPack,
            &[
                OsString::from("--stdin"),
                OsString::from(format!("--max-input-size={pack_size}")),
            ],
            &environment,
            Some(reopen_read_only(pack)?),
            true,
        )?;
        if !output.status.success() {
            return Err(ManagedPointerError::Git {
                operation: "index-pack",
                detail: sanitized_git_diagnostic(&output.stderr),
            });
        }
        let pack_checksum = parse_index_pack_output(&output.stdout, object_format)?;
        let pack_name = format!("pack-{pack_checksum}.pack");
        let index_name = format!("pack-{pack_checksum}.idx");
        let (pack_digest, imported_pack_size) = sync_imported_object_file(
            &repository.pack_directory,
            Path::new(&pack_name),
            self.uid,
            self.gid,
        )?;
        let (index_digest, index_size) = sync_imported_object_file(
            &repository.pack_directory,
            Path::new(&index_name),
            self.uid,
            self.gid,
        )?;
        if pack_digest != *candidate_pack_digest || imported_pack_size != pack_size {
            return Err(ManagedPointerError::Artifact(
                "target object database contains a different imported PACK".to_owned(),
            ));
        }
        rustix::fs::fsync(&repository.pack_directory).map_err(errno_to_io)?;
        rustix::fs::fsync(&repository.objects).map_err(errno_to_io)?;
        Ok(ImportedPackEvidenceV1 {
            schema: "ag.managed-pointer.object-import/v1".to_owned(),
            pack_checksum,
            candidate_pack_digest: candidate_pack_digest.clone(),
            pack_file_digest: pack_digest,
            pack_file_size: imported_pack_size,
            index_file_digest: index_digest,
            index_file_size: index_size,
            target_uid: self.uid,
            target_gid: self.gid,
            pack_fsynced: true,
            index_fsynced: true,
            object_directories_fsynced: true,
        })
    }

    fn verify_imported_candidate(
        &self,
        repository: &OpenRepositoryV1,
        candidate: &str,
        expected_tree: &str,
        object_format: GitObjectFormatV1,
    ) -> Result<(), ManagedPointerError> {
        let mut environment = GitEnvironmentV1::default();
        environment.descriptor_path("GIT_DIR", &repository.git_directory, None)?;
        let kind = self.run_git_checked(
            GitOperationV1::CatFile,
            &[OsString::from("-t"), OsString::from(candidate)],
            &environment,
            None,
            true,
        )?;
        if kind != b"commit\n" {
            return Err(ManagedPointerError::Artifact(
                "imported candidate is not a commit".to_owned(),
            ));
        }
        let tree = canonical_object_output(
            &self.run_git_checked(
                GitOperationV1::RevParse,
                &[
                    OsString::from("--verify"),
                    OsString::from(format!("{candidate}^{{tree}}")),
                ],
                &environment,
                None,
                true,
            )?,
            object_format,
        )?;
        if tree != expected_tree {
            return Err(ManagedPointerError::Artifact(
                "imported candidate tree differs from canonical poststate".to_owned(),
            ));
        }
        Ok(())
    }
}

fn parse_index_pack_output(
    output: &[u8],
    object_format: GitObjectFormatV1,
) -> Result<String, ManagedPointerError> {
    let text = std::str::from_utf8(output)
        .map_err(|_| ManagedPointerError::Git {
            operation: "index-pack",
            detail: "index-pack output is not UTF-8".to_owned(),
        })?
        .strip_suffix('\n')
        .and_then(|line| line.strip_prefix("pack\t"))
        .ok_or_else(|| ManagedPointerError::Git {
            operation: "index-pack",
            detail: "index-pack output has the wrong framing".to_owned(),
        })?;
    let expected = match object_format {
        GitObjectFormatV1::Sha1 => 40,
        GitObjectFormatV1::Sha256 => 64,
    };
    if text.len() != expected
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ManagedPointerError::Git {
            operation: "index-pack",
            detail: "index-pack checksum is not canonical".to_owned(),
        });
    }
    Ok(text.to_owned())
}

fn sync_imported_object_file(
    parent: &OwnedFd,
    name: &Path,
    uid: u32,
    gid: u32,
) -> Result<(Digest, u64), ManagedPointerError> {
    let descriptor = rustix::fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(errno_to_io)?;
    let stat = rustix::fs::fstat(&descriptor).map_err(errno_to_io)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_mode & 0o022 != 0
    {
        return Err(ManagedPointerError::UnsafeRepository(
            "imported object file has unsafe metadata".to_owned(),
        ));
    }
    let mut file = File::from(descriptor);
    let size = u64::try_from(stat.st_size).map_err(|_| {
        ManagedPointerError::Artifact("imported object file has negative size".to_owned())
    })?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(size)
            .map_err(|_| ManagedPointerError::Artifact("object size overflow".to_owned()))?,
    );
    Read::by_ref(&mut file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != size {
        return Err(ManagedPointerError::Artifact(
            "imported object file changed during read".to_owned(),
        ));
    }
    file.sync_all()?;
    Ok((Digest::hash_bytes(&bytes), size))
}

fn target_observation(
    repository: &OpenRepositoryV1,
    state: &RepositoryStateV1,
    staged: &StagedCandidateV1,
) -> Result<TargetObservationV1, ManagedPointerError> {
    Ok(TargetObservationV1::ManagedPointer {
        current_object: state.current_object.clone(),
        current_tree: state.current_tree.clone(),
        candidate_object: staged.candidate_object.clone(),
        candidate_tree: staged.candidate_tree.clone(),
        candidate_parent: staged.candidate_parent.clone(),
        candidate_pack_digest: staged.pack_digest.clone(),
        object_format: staged.object_format,
        repository_identity: repository.identity_evidence.identity()?,
        prestate_identity: state.evidence.identity()?,
        repository_device: repository.identity_evidence.repository_device,
        repository_inode: repository.identity_evidence.repository_inode,
        git_directory_device: repository.identity_evidence.git_directory_device,
        git_directory_inode: repository.identity_evidence.git_directory_inode,
        repository_uid: repository.identity_evidence.uid,
        repository_gid: repository.identity_evidence.gid,
        clean: state.clean,
        reference_checked_out: state.reference_checked_out,
    })
}

struct CanonicalPointerFieldsV1<'a> {
    schema: &'a str,
    operation_id: &'a Digest,
    prepared_candidate: &'a Digest,
    exact_basis: &'a Digest,
    complete_inputs: &'a Digest,
    candidate_preparation_receipt: &'a Digest,
    target: &'a TargetId,
    allowed_root: &'a str,
    repository: &'a str,
    reference: &'a str,
    repository_identity: &'a Digest,
    prestate_identity: &'a Digest,
    repository_device: u64,
    repository_inode: u64,
    git_directory_device: u64,
    git_directory_inode: u64,
    uid: u32,
    gid: u32,
    staging_root: &'a str,
    artifact: &'a Digest,
    candidate_pack_digest: &'a Digest,
    object_format: GitObjectFormatV1,
    expected_object: &'a str,
    expected_tree: &'a str,
    new_object: &'a str,
    expected_post_tree: &'a str,
    expires_unix_ms: u64,
    helper_executable: &'a Digest,
    helper_launch_profile: &'a Digest,
}

impl<'a> CanonicalPointerFieldsV1<'a> {
    fn from_effect(effect: &'a CanonicalEffectV1) -> Result<Self, ManagedPointerError> {
        let CanonicalEffectV1::ManagedPointerPromotion {
            schema,
            operation_id,
            prepared_candidate,
            exact_basis,
            complete_inputs,
            candidate_preparation_receipt,
            target,
            allowed_root,
            repository,
            reference,
            repository_identity,
            prestate_identity,
            repository_device,
            repository_inode,
            git_directory_device,
            git_directory_inode,
            uid,
            gid,
            staging_root,
            artifact,
            candidate_pack_digest,
            object_format,
            expected_object,
            expected_tree,
            new_object,
            expected_post_tree,
            expires_unix_ms,
            helper_executable,
            helper_launch_profile,
        } = effect
        else {
            return Err(ManagedPointerError::TargetUnavailable);
        };
        Ok(Self {
            schema,
            operation_id,
            prepared_candidate,
            exact_basis,
            complete_inputs,
            candidate_preparation_receipt,
            target,
            allowed_root,
            repository,
            reference,
            repository_identity,
            prestate_identity,
            repository_device: *repository_device,
            repository_inode: *repository_inode,
            git_directory_device: *git_directory_device,
            git_directory_inode: *git_directory_inode,
            uid: *uid,
            gid: *gid,
            staging_root,
            artifact,
            candidate_pack_digest,
            object_format: *object_format,
            expected_object,
            expected_tree,
            new_object,
            expected_post_tree,
            expires_unix_ms: *expires_unix_ms,
            helper_executable,
            helper_launch_profile,
        })
    }
}

impl ManagedPointerTargetV1 {
    fn require_enrolled_repository(
        &self,
        repository: &OpenRepositoryV1,
    ) -> Result<(), ManagedPointerError> {
        let evidence = &repository.identity_evidence;
        if evidence.identity()? != self.repository_identity
            || evidence.uid != self.uid
            || evidence.gid != self.gid
        {
            return Err(ManagedPointerError::PrestateDrift(
                "descriptor-bound repository differs from its enrollment".to_owned(),
            ));
        }
        Ok(())
    }

    fn verify_canonical_bindings(
        &self,
        fields: &CanonicalPointerFieldsV1<'_>,
    ) -> Result<(), ManagedPointerError> {
        let git = self
            .git
            .lock()
            .map_err(|_| ManagedPointerError::GitIdentityMismatch)?;
        let repository_relative = self
            .repository
            .strip_prefix(&self.allowed_root)
            .map_err(|_| ManagedPointerError::BindingMismatch)?;
        let matches = fields.schema == MANAGED_POINTER_PROMOTION_SCHEMA_V2
            && fields.allowed_root == utf8_path(&self.allowed_root)?
            && fields.repository == utf8_path(repository_relative)?
            && fields.reference == self.reference
            && fields.repository_identity == &self.repository_identity
            && fields.uid == self.uid
            && fields.gid == self.gid
            && fields.staging_root == utf8_path(&self.staging_root)?
            && fields.helper_executable == &git.executable
            && fields.helper_launch_profile == &self.launch_profile
            && fields.expires_unix_ms > 0
            && self.promotion_ttl_ms > 0;
        drop(git);
        if !matches {
            return Err(ManagedPointerError::BindingMismatch);
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn require_canonical_repository(
        &self,
        fields: &CanonicalPointerFieldsV1<'_>,
        repository: &OpenRepositoryV1,
    ) -> Result<(), ManagedPointerError> {
        let evidence = &repository.identity_evidence;
        if evidence.identity()? != *fields.repository_identity
            || evidence.repository_device != fields.repository_device
            || evidence.repository_inode != fields.repository_inode
            || evidence.git_directory_device != fields.git_directory_device
            || evidence.git_directory_inode != fields.git_directory_inode
            || evidence.uid != fields.uid
            || evidence.gid != fields.gid
            || evidence.object_format != fields.object_format
        {
            return Err(ManagedPointerError::PrestateDrift(
                "descriptor-bound repository identity differs from canonical prestate".to_owned(),
            ));
        }
        Ok(())
    }
}

fn exact_prestate(fields: &CanonicalPointerFieldsV1<'_>, state: &RepositoryStateV1) -> bool {
    state.object_format == fields.object_format
        && state
            .evidence
            .identity()
            .is_ok_and(|identity| identity == *fields.prestate_identity)
        && state.current_object == fields.expected_object
        && state.current_tree == fields.expected_tree
        && state.clean
        && !state.reference_checked_out
}

fn exact_poststate(fields: &CanonicalPointerFieldsV1<'_>, state: &RepositoryStateV1) -> bool {
    state.object_format == fields.object_format
        && state.current_object == fields.new_object
        && state.current_tree == fields.expected_post_tree
        && state.clean
        && !state.reference_checked_out
}

fn require_exact_prestate(
    fields: &CanonicalPointerFieldsV1<'_>,
    state: &RepositoryStateV1,
) -> Result<(), ManagedPointerError> {
    if exact_prestate(fields, state) {
        Ok(())
    } else {
        Err(ManagedPointerError::PrestateDrift(
            "layout, loose-ref inode/content, commit, tree, cleanliness, object format, or checked-out state drifted"
                .to_owned(),
        ))
    }
}

fn receipt_with_outcome(
    context: &ManagedPointerExecutionContextV1,
    effect: &CanonicalEffectV1,
    outcome: ExecutionOutcomeV1,
) -> ExecutionReceiptV1 {
    ExecutionReceiptV1 {
        schema: EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
        proposal: context.proposal.clone(),
        authorization: context.authorization.clone(),
        attempt: context.attempt.clone(),
        effect_index: context.effect_index,
        effect: effect.clone(),
        outcome,
    }
}

fn failure_receipt(
    context: &ManagedPointerExecutionContextV1,
    effect: &CanonicalEffectV1,
    error: &ManagedPointerError,
) -> ExecutionReceiptV1 {
    receipt_with_outcome(context, effect, failure_outcome(error))
}

fn failure_outcome(error: &ManagedPointerError) -> ExecutionOutcomeV1 {
    let (code, phase, source_code) = match error {
        ManagedPointerError::Artifact(_) => (
            ExecutionFailureCodeV1::ArtifactDigestMismatch,
            ExecutionPhaseV1::ArtifactLoad,
            Some("managed_pointer_artifact".to_owned()),
        ),
        ManagedPointerError::Store(_) => (
            ExecutionFailureCodeV1::ArtifactUnavailable,
            ExecutionPhaseV1::ArtifactLoad,
            Some("effectd_store_custody".to_owned()),
        ),
        ManagedPointerError::GitIdentityMismatch => (
            ExecutionFailureCodeV1::HelperIdentityMismatch,
            ExecutionPhaseV1::HelperIdentity,
            Some("git_executable_identity".to_owned()),
        ),
        ManagedPointerError::LaunchProfileMismatch => (
            ExecutionFailureCodeV1::HelperIdentityMismatch,
            ExecutionPhaseV1::HelperIdentity,
            Some("git_launch_profile".to_owned()),
        ),
        ManagedPointerError::PrivilegeFloorUnavailable => (
            ExecutionFailureCodeV1::HelperIdentityMismatch,
            ExecutionPhaseV1::HelperIdentity,
            Some("git_no_new_privileges".to_owned()),
        ),
        ManagedPointerError::ClockUnavailable => (
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::PrestateCheck,
            Some("managed_pointer_clock".to_owned()),
        ),
        ManagedPointerError::PromotionExpiredBeforeCas => (
            ExecutionFailureCodeV1::PrestateDrift,
            ExecutionPhaseV1::PrestateCheck,
            Some("managed_pointer_expired_before_cas".to_owned()),
        ),
        ManagedPointerError::Git { operation, .. } => (
            ExecutionFailureCodeV1::BackendRejected,
            if *operation == "update-ref" {
                ExecutionPhaseV1::PointerCas
            } else {
                ExecutionPhaseV1::Staging
            },
            Some((*operation).to_owned()),
        ),
        ManagedPointerError::Io(_) => (
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::Staging,
            Some("managed_pointer_io".to_owned()),
        ),
        ManagedPointerError::TargetUnavailable
        | ManagedPointerError::GenesisMeasurementInvalid
        | ManagedPointerError::GenesisMeasurementDrift
        | ManagedPointerError::PreparationStandingAbsent
        | ManagedPointerError::PreparationStandingScopeMismatch
        | ManagedPointerError::PreparationBudgetExceeded
        | ManagedPointerError::ProtectedProjectionChanged
        | ManagedPointerError::PromotionStandingMismatch
        | ManagedPointerError::BindingMismatch
        | ManagedPointerError::UnsafeRepository(_)
        | ManagedPointerError::InvalidBundle(_)
        | ManagedPointerError::PrestateDrift(_)
        | ManagedPointerError::Canonical(_) => (
            ExecutionFailureCodeV1::PrestateDrift,
            ExecutionPhaseV1::PrestateCheck,
            Some("managed_pointer_precondition".to_owned()),
        ),
    };
    ExecutionOutcomeV1::Failed {
        failure: ExecutionFailureV1 {
            code,
            phase,
            detail: error.to_string(),
            source_code,
            evidence: None,
        },
    }
}

fn hash_file(file: &mut File) -> Result<Digest, ManagedPointerError> {
    file.seek(SeekFrom::Start(0))?;
    let size = file.metadata()?.len();
    let mut bytes = Vec::with_capacity(
        usize::try_from(size)
            .map_err(|_| ManagedPointerError::Artifact("PACK size overflow".to_owned()))?,
    );
    Read::by_ref(file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)?;
    file.seek(SeekFrom::Start(0))?;
    if bytes.len() as u64 != size {
        return Err(ManagedPointerError::Artifact(
            "prepared PACK changed during descriptor read".to_owned(),
        ));
    }
    Ok(Digest::hash_bytes(&bytes))
}

fn reopen_read_only(file: &File) -> Result<File, ManagedPointerError> {
    let before = rustix::fs::fstat(file).map_err(errno_to_io)?;
    let reopened = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    let after = rustix::fs::fstat(&reopened).map_err(errno_to_io)?;
    if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
        return Err(ManagedPointerError::Artifact(
            "read-only pack reopen changed descriptor identity".to_owned(),
        ));
    }
    Ok(reopened)
}

fn sync_reference(
    git_directory: &OwnedFd,
    reference: &str,
    uid: u32,
    gid: u32,
) -> Result<(), ManagedPointerError> {
    let relative = Path::new(reference);
    let reference_file = open_safe_reference(git_directory, reference, uid, gid)?;
    rustix::fs::fsync(&reference_file).map_err(errno_to_io)?;
    let mut current = relative.parent();
    while let Some(directory) = current {
        if directory.as_os_str().is_empty() {
            break;
        }
        let opened = open_directory_beneath(git_directory, directory)?;
        rustix::fs::fsync(&opened).map_err(errno_to_io)?;
        current = directory.parent();
    }
    rustix::fs::fsync(git_directory).map_err(errno_to_io)?;
    Ok(())
}

fn open_safe_reference(
    git_directory: &OwnedFd,
    reference: &str,
    uid: u32,
    gid: u32,
) -> Result<OwnedFd, ManagedPointerError> {
    let relative = Path::new(reference);
    if !reference.starts_with("refs/heads/") || relative.parent().is_none() {
        return Err(ManagedPointerError::BindingMismatch);
    }
    let mut current = relative.parent();
    while let Some(directory) = current {
        if directory.as_os_str().is_empty() {
            break;
        }
        let opened = open_directory_beneath(git_directory, directory)?;
        require_directory_owner(
            &rustix::fs::fstat(&opened).map_err(errno_to_io)?,
            uid,
            gid,
            "reference ancestry",
        )?;
        current = directory.parent();
    }
    let reference_file = rustix::fs::openat2(
        git_directory,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(errno_to_io)?;
    let reference_stat = rustix::fs::fstat(&reference_file).map_err(errno_to_io)?;
    if !FileType::from_raw_mode(reference_stat.st_mode).is_file()
        || reference_stat.st_nlink != 1
        || reference_stat.st_uid != uid
        || reference_stat.st_gid != gid
        || reference_stat.st_mode & 0o022 != 0
    {
        return Err(ManagedPointerError::UnsafeRepository(
            "managed reference has unsafe metadata".to_owned(),
        ));
    }
    Ok(reference_file)
}

fn read_loose_reference(
    git_directory: &OwnedFd,
    reference: &str,
    uid: u32,
    gid: u32,
    object_format: GitObjectFormatV1,
) -> Result<(String, ManagedFilesystemNodeEvidenceV1), ManagedPointerError> {
    let descriptor = open_safe_reference(git_directory, reference, uid, gid)?;
    let before = rustix::fs::fstat(&descriptor).map_err(errno_to_io)?;
    let expected_size = match object_format {
        GitObjectFormatV1::Sha1 => 41_u64,
        GitObjectFormatV1::Sha256 => 65_u64,
    };
    if u64::try_from(before.st_size).ok() != Some(expected_size) {
        return Err(ManagedPointerError::PrestateDrift(
            "managed loose ref does not contain one canonical object ID".to_owned(),
        ));
    }
    let mut file = File::from(descriptor);
    let capacity = usize::try_from(expected_size)
        .map_err(|_| ManagedPointerError::Artifact("candidate is too large".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(expected_size.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = rustix::fs::fstat(&file).map_err(errno_to_io)?;
    if bytes.len() as u64 != expected_size
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(ManagedPointerError::PrestateDrift(
            "managed loose ref changed during descriptor read".to_owned(),
        ));
    }
    Ok((
        canonical_object_output(&bytes, object_format)?,
        node_evidence(reference, &after),
    ))
}

#[derive(Clone, Copy, Debug)]
enum GitOperationV1 {
    Init,
    IndexPack,
    CatFile,
    RevParse,
    RevList,
    LsTree,
    Fsck,
    DiffIndex,
    DiffFiles,
    LsFiles,
    UpdateRef,
}

impl GitOperationV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::IndexPack => "index-pack",
            Self::CatFile => "cat-file",
            Self::RevParse => "rev-parse",
            Self::RevList => "rev-list",
            Self::LsTree => "ls-tree",
            Self::Fsck => "fsck",
            Self::DiffIndex => "diff-index",
            Self::DiffFiles => "diff-files",
            Self::LsFiles => "ls-files",
            Self::UpdateRef => "update-ref",
        }
    }
}

#[derive(Debug)]
struct GitOutputV1 {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct ReapingGitChildV1 {
    child: Child,
    reaped: bool,
}

impl ReapingGitChildV1 {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, std::io::Error> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn kill_and_reap(&mut self) {
        let _ = self.child.kill();
        if self.child.wait().is_ok() {
            self.reaped = true;
        }
    }
}

impl Drop for ReapingGitChildV1 {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill_and_reap();
        }
    }
}

#[derive(Default)]
struct GitEnvironmentV1 {
    values: Vec<(&'static str, OsString)>,
    retained_descriptors: Vec<OwnedFd>,
    writable_roots: Vec<OwnedFd>,
}

impl GitEnvironmentV1 {
    fn insert(&mut self, key: &'static str, value: impl Into<OsString>) {
        self.values.push((key, value.into()));
    }

    fn descriptor_path(
        &mut self,
        key: &'static str,
        descriptor: &OwnedFd,
        suffix: Option<&str>,
    ) -> Result<(), ManagedPointerError> {
        let inherited = rustix::io::fcntl_dupfd_cloexec(descriptor, 3).map_err(errno_to_io)?;
        let mut value = format!("/proc/self/fd/{}", inherited.as_raw_fd());
        if let Some(suffix) = suffix {
            value.push('/');
            value.push_str(suffix);
        }
        self.retained_descriptors.push(inherited);
        self.insert(key, value);
        Ok(())
    }

    fn writable_descriptor_path(
        &mut self,
        key: &'static str,
        descriptor: &OwnedFd,
        suffix: Option<&str>,
    ) -> Result<(), ManagedPointerError> {
        self.descriptor_path(key, descriptor, suffix)?;
        self.admit_write_root(descriptor)
    }

    fn admit_write_root(&mut self, descriptor: &OwnedFd) -> Result<(), ManagedPointerError> {
        self.writable_roots
            .push(rustix::io::fcntl_dupfd_cloexec(descriptor, 3).map_err(errno_to_io)?);
        Ok(())
    }
}

impl ManagedPointerTargetV1 {
    #[allow(clippy::too_many_lines)]
    fn run_git(
        &self,
        operation: GitOperationV1,
        arguments: &[OsString],
        environment: &GitEnvironmentV1,
        stdin: Option<File>,
        target_owner: bool,
    ) -> Result<GitOutputV1, ManagedPointerError> {
        self.run_git_inner(operation, arguments, environment, stdin, target_owner, None)
    }

    fn run_git_update_ref(
        &self,
        arguments: &[OsString],
        environment: &GitEnvironmentV1,
        commit_guard: CommitLaunchGuardV1<'_>,
    ) -> Result<GitOutputV1, ManagedPointerError> {
        self.run_git_inner(
            GitOperationV1::UpdateRef,
            arguments,
            environment,
            None,
            true,
            Some(commit_guard),
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_git_inner(
        &self,
        operation: GitOperationV1,
        arguments: &[OsString],
        environment: &GitEnvironmentV1,
        stdin: Option<File>,
        target_owner: bool,
        commit_guard: Option<CommitLaunchGuardV1<'_>>,
    ) -> Result<GitOutputV1, ManagedPointerError> {
        let mut git = self
            .git
            .lock()
            .map_err(|_| ManagedPointerError::GitIdentityMismatch)?;
        git.revalidate()?;
        let mut command = Command::new(format!("/proc/self/fd/{}", git.snapshot.as_raw_fd()));
        command
            .env_clear()
            .current_dir("/")
            .stdin(stdin.map_or_else(Stdio::null, Stdio::from))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("LC_ALL", "C")
            .env("HOME", "/nonexistent")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_LITERAL_PATHSPECS", "1")
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .env("GIT_ALLOW_PROTOCOL", "")
            .env("GIT_EXEC_PATH", "/dev/null")
            .env("GIT_ASKPASS", "/dev/null")
            .env("SSH_ASKPASS", "/dev/null")
            .arg("--no-pager")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("-c")
            .arg("maintenance.auto=false")
            .arg("-c")
            .arg("core.fsync=reference")
            .arg("-c")
            .arg("core.sharedRepository=0600")
            .arg("-c")
            .arg("pack.writeReverseIndex=false")
            .arg("-c")
            .arg("core.logAllRefUpdates=false")
            .arg("-c")
            .arg("protocol.allow=never")
            .arg(operation.as_str())
            .args(arguments);
        for (key, value) in &environment.values {
            command.env(key, value);
        }
        if target_owner {
            let effective_user = nix::unistd::geteuid().as_raw();
            let effective_group = nix::unistd::getegid().as_raw();
            if effective_user == 0 {
                let supplementary = nix::unistd::getgroups().map_err(|error| {
                    ManagedPointerError::UnsafeRepository(format!(
                        "could not inspect broker supplementary groups: {error}"
                    ))
                })?;
                if !supplementary.is_empty() {
                    return Err(ManagedPointerError::UnsafeRepository(
                        "root broker has supplementary groups and cannot safely enter target identity"
                            .to_owned(),
                    ));
                }
                command.gid(self.gid).uid(self.uid);
            } else if effective_user != self.uid || effective_group != self.gid {
                return Err(ManagedPointerError::UnsafeRepository(
                    "unprivileged broker cannot enter the configured target identity".to_owned(),
                ));
            }
        }
        nix::sys::prctl::set_no_new_privs()
            .map_err(|_| ManagedPointerError::PrivilegeFloorUnavailable)?;
        if !nix::sys::prctl::get_no_new_privs()
            .map_err(|_| ManagedPointerError::PrivilegeFloorUnavailable)?
        {
            return Err(ManagedPointerError::PrivilegeFloorUnavailable);
        }
        if let Some(guard) = commit_guard
            && guard.clock.now_unix_ms()? >= guard.expires_unix_ms
        {
            return Err(ManagedPointerError::PromotionExpiredBeforeCas);
        }
        let mut child = ReapingGitChildV1::new(spawn_with_exact_descriptors(
            &mut command,
            &environment.retained_descriptors,
            &environment.writable_roots,
        )?);
        let stdout = child
            .child
            .stdout
            .take()
            .ok_or_else(|| ManagedPointerError::Git {
                operation: operation.as_str(),
                detail: "stdout pipe unavailable".to_owned(),
            })?;
        let stderr = child
            .child
            .stderr
            .take()
            .ok_or_else(|| ManagedPointerError::Git {
                operation: operation.as_str(),
                detail: "stderr pipe unavailable".to_owned(),
            })?;
        let stdout_reader = thread::spawn(move || read_bounded_output(stdout));
        let stderr_reader = thread::spawn(move || read_bounded_output(stderr));
        let deadline = Instant::now() + GIT_COMMAND_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill_and_reap();
                return Err(ManagedPointerError::Git {
                    operation: operation.as_str(),
                    detail: "operation exceeded its fixed deadline".to_owned(),
                });
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| ManagedPointerError::Git {
                operation: operation.as_str(),
                detail: "stdout reader failed".to_owned(),
            })??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| ManagedPointerError::Git {
                operation: operation.as_str(),
                detail: "stderr reader failed".to_owned(),
            })??;
        Ok(GitOutputV1 {
            status,
            stdout,
            stderr,
        })
    }

    fn run_git_checked(
        &self,
        operation: GitOperationV1,
        arguments: &[OsString],
        environment: &GitEnvironmentV1,
        stdin: Option<File>,
        target_owner: bool,
    ) -> Result<Vec<u8>, ManagedPointerError> {
        let output = self.run_git(operation, arguments, environment, stdin, target_owner)?;
        if !output.status.success() {
            return Err(ManagedPointerError::Git {
                operation: operation.as_str(),
                detail: sanitized_git_diagnostic(&output.stderr),
            });
        }
        Ok(output.stdout)
    }
}

fn spawn_with_exact_descriptors(
    command: &mut Command,
    admitted: &[OwnedFd],
    writable_roots: &[OwnedFd],
) -> Result<Child, ManagedPointerError> {
    let inherited = admitted.iter().map(OwnedFd::as_raw_fd).collect::<Vec<_>>();
    let writable_roots = writable_roots
        .iter()
        .map(OwnedFd::as_raw_fd)
        .collect::<Vec<_>>();
    crate::exact_exec::configure_exact_inherited_fds(command, &inherited, &writable_roots, 3)?;
    command.spawn().map_err(ManagedPointerError::Io)
}

fn read_bounded_output(mut reader: impl Read) -> Result<Vec<u8>, std::io::Error> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(retained);
        }
        if retained.len() < MAX_GIT_OUTPUT_BYTES {
            let remaining = MAX_GIT_OUTPUT_BYTES - retained.len();
            retained.extend_from_slice(&buffer[..count.min(remaining)]);
        }
        if retained.len() == MAX_GIT_OUTPUT_BYTES && count > 0 {
            // Continue draining to avoid deadlocking the child, but retain a
            // deterministic marker so parsers reject a truncated response.
            if !retained.ends_with(b"\n[ag-output-truncated]") {
                let marker = b"\n[ag-output-truncated]";
                let start = retained.len().saturating_sub(marker.len());
                retained.truncate(start);
                retained.extend_from_slice(marker);
            }
        }
    }
}

fn sanitized_git_diagnostic(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let single_line = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    single_line.trim().chars().take(512).collect()
}

fn errno_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

impl PinnedGitV1 {
    fn open(path: &Path, expected: &Digest) -> Result<Self, ManagedPointerError> {
        Self::open_inner(path, Some(expected))
    }

    fn measure(path: &Path) -> Result<Self, ManagedPointerError> {
        Self::open_inner(path, None)
    }

    fn open_inner(path: &Path, expected: Option<&Digest>) -> Result<Self, ManagedPointerError> {
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = source.metadata()?;
        if !pinned_git_metadata_is_safe(&metadata) {
            return Err(ManagedPointerError::GitIdentityMismatch);
        }
        require_no_security_capability(&source)?;
        let bytes = read_exact_git_bytes(&mut source, metadata.len())?;
        let executable = Digest::hash_bytes(&bytes);
        if expected.is_some_and(|expected| executable != *expected) {
            return Err(ManagedPointerError::GitIdentityMismatch);
        }
        let mut snapshot = sealed_executable_snapshot(&bytes)?;
        if read_exact_git_digest(&mut snapshot, metadata.len())? != executable {
            return Err(ManagedPointerError::GitIdentityMismatch);
        }
        Ok(Self {
            path: path.to_owned(),
            source,
            snapshot,
            executable,
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        })
    }

    fn revalidate(&mut self) -> Result<(), ManagedPointerError> {
        let reopened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)?;
        let reopened_metadata = reopened.metadata()?;
        let retained_metadata = self.source.metadata()?;
        if !pinned_git_metadata_is_safe(&reopened_metadata)
            || !pinned_git_metadata_is_safe(&retained_metadata)
            || reopened_metadata.dev() != self.device
            || reopened_metadata.ino() != self.inode
            || reopened_metadata.len() != self.size
            || reopened_metadata.gid() != self.gid
            || reopened_metadata.mode() & 0o7777 != self.mode
            || retained_metadata.dev() != self.device
            || retained_metadata.ino() != self.inode
            || retained_metadata.len() != self.size
            || retained_metadata.gid() != self.gid
            || retained_metadata.mode() & 0o7777 != self.mode
        {
            return Err(ManagedPointerError::GitIdentityMismatch);
        }
        require_no_security_capability(&reopened)?;
        require_no_security_capability(&self.source)?;
        if read_exact_git_digest(&mut self.source, self.size)? != self.executable
            || read_exact_git_digest(&mut self.snapshot, self.size)? != self.executable
        {
            return Err(ManagedPointerError::GitIdentityMismatch);
        }
        let required_seals =
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
        let observed_seals = rustix::fs::fcntl_get_seals(&self.snapshot)
            .map_err(|_| ManagedPointerError::GitIdentityMismatch)?;
        if !observed_seals.contains(required_seals) {
            return Err(ManagedPointerError::GitIdentityMismatch);
        }
        Ok(())
    }
}

fn pinned_git_metadata_is_safe(metadata: &fs::Metadata) -> bool {
    pinned_git_metadata_values_are_safe(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.nlink(),
        metadata.mode(),
        metadata.len(),
    )
}

fn pinned_git_metadata_values_are_safe(
    is_file: bool,
    uid: u32,
    link_count: u64,
    mode: u32,
    size: u64,
) -> bool {
    is_file
        && uid == 0
        && link_count == 1
        && mode & (0o7000 | 0o022) == 0
        && mode & 0o111 != 0
        && size > 0
        && size <= MAX_GIT_EXECUTABLE_BYTES
}

fn require_no_security_capability(file: &File) -> Result<(), ManagedPointerError> {
    let mut one_byte = [0_u8; 1];
    match rustix::fs::fgetxattr(file, "security.capability", &mut one_byte[..]) {
        Err(rustix::io::Errno::NODATA) => Ok(()),
        _ => Err(ManagedPointerError::GitIdentityMismatch),
    }
}

fn read_exact_git_bytes(file: &mut File, size: u64) -> Result<Vec<u8>, ManagedPointerError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(size).map_err(|_| ManagedPointerError::GitIdentityMismatch)?,
    );
    Read::by_ref(file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)?;
    file.seek(SeekFrom::Start(0))?;
    if bytes.len() as u64 != size {
        return Err(ManagedPointerError::GitIdentityMismatch);
    }
    Ok(bytes)
}

fn read_exact_git_digest(file: &mut File, size: u64) -> Result<Digest, ManagedPointerError> {
    Ok(Digest::hash_bytes(&read_exact_git_bytes(file, size)?))
}

fn sealed_executable_snapshot(bytes: &[u8]) -> Result<File, ManagedPointerError> {
    let descriptor = rustix::fs::memfd_create(
        "ag-managed-pointer-git",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(errno_to_io)?;
    let mut snapshot = File::from(descriptor);
    snapshot.write_all(bytes)?;
    snapshot.sync_all()?;
    rustix::fs::fchmod(&snapshot, Mode::from_raw_mode(0o555)).map_err(errno_to_io)?;
    let seals = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    rustix::fs::fcntl_add_seals(&snapshot, seals).map_err(errno_to_io)?;
    if !rustix::fs::fcntl_get_seals(&snapshot)
        .map_err(errno_to_io)?
        .contains(seals)
    {
        return Err(ManagedPointerError::GitIdentityMismatch);
    }
    snapshot.seek(SeekFrom::Start(0))?;
    Ok(snapshot)
}

/// Computes the only accepted fixed Git launch-profile digest.
///
/// # Errors
///
/// Returns an error if the profile cannot be represented as strict JCS.
pub fn managed_pointer_launch_profile_identity(
    security_profile_identity: &Digest,
    git_executable: &Digest,
) -> Result<Digest, ManagedPointerError> {
    #[derive(Serialize)]
    struct LaunchProfile<'a> {
        schema: &'static str,
        security_profile_identity: &'a Digest,
        git_executable: &'a Digest,
        executable_transport: &'static str,
        source_custody: &'static str,
        privilege_floor: &'static str,
        environment: [&'static str; 14],
        operations: [&'static str; 11],
        fixed_config: [&'static str; 9],
        candidate_ref: &'static str,
        bundle_version: u8,
        pack_version: u8,
        network: &'static str,
        credentials: &'static str,
        descriptor_inheritance: &'static str,
        mutation_confinement: &'static str,
        null_device_custody: &'static str,
        object_durability: &'static str,
        boundary: &'static str,
    }
    Ok(Digest::from_serializable(&LaunchProfile {
        schema: MANAGED_POINTER_LAUNCH_PROFILE_SCHEMA_V2,
        security_profile_identity,
        git_executable,
        executable_transport: "sealed-memfd-proc-self-fd",
        source_custody: "root-owned-single-link-no-special-bits-no-security-capability",
        privilege_floor: "no-new-privileges-asserted-before-spawn",
        environment: [
            "LC_ALL=C",
            "HOME=/nonexistent",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_ATTR_NOSYSTEM=1",
            "GIT_TERMINAL_PROMPT=0",
            "GIT_OPTIONAL_LOCKS=0",
            "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_LITERAL_PATHSPECS=1",
            "GIT_PROTOCOL_FROM_USER=0",
            "GIT_ALLOW_PROTOCOL=",
            "GIT_EXEC_PATH=/dev/null",
            "GIT_ASKPASS=/dev/null",
            "SSH_ASKPASS=/dev/null",
        ],
        operations: [
            "init",
            "index-pack",
            "cat-file",
            "rev-parse",
            "rev-list",
            "ls-tree",
            "fsck",
            "diff-index",
            "diff-files",
            "ls-files",
            "update-ref",
        ],
        fixed_config: [
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "gc.auto=0",
            "maintenance.auto=false",
            "core.fsync=reference",
            "core.sharedRepository=0600",
            "pack.writeReverseIndex=false",
            "core.logAllRefUpdates=false",
            "protocol.allow=never",
        ],
        candidate_ref: BUNDLE_CANDIDATE_REF,
        bundle_version: 2,
        pack_version: 2,
        network: "forbidden",
        credentials: "none",
        descriptor_inheritance: "close-range-cloexec-then-exact-admitted-fds",
        mutation_confinement: "landlock-abi-3-descriptor-rooted-write-set",
        null_device_custody: "exact-root-owned-char-1-3-mode-0666-write-only-landlock-rule",
        object_durability: "descriptor-fsync-pack-index-packdir-objectsdir",
        boundary: "durable-unreachable-object-import-then-single-update-ref-cas",
    })?)
}

#[derive(Debug)]
struct StrictBundleV1<'a> {
    candidate: String,
    object_format: GitObjectFormatV1,
    pack: &'a [u8],
    pack_digest: Digest,
}

fn parse_strict_bundle(bytes: &[u8]) -> Result<StrictBundleV1<'_>, ManagedPointerError> {
    if !bytes.starts_with(BUNDLE_MAGIC_V2) {
        return Err(ManagedPointerError::InvalidBundle(
            "bundle v2 magic is absent".to_owned(),
        ));
    }
    let header = &bytes[BUNDLE_MAGIC_V2.len()..];
    let end = header
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or_else(|| ManagedPointerError::InvalidBundle("header is not terminated".to_owned()))?;
    let header_line = &header[..end];
    if header_line.is_empty()
        || header_line.contains(&b'\r')
        || header_line.contains(&b'\n')
        || header_line.starts_with(b"-")
        || header_line.starts_with(b"@")
    {
        return Err(ManagedPointerError::InvalidBundle(
            "bundle must advertise one tip and no prerequisites or capabilities".to_owned(),
        ));
    }
    let text = std::str::from_utf8(header_line)
        .map_err(|_| ManagedPointerError::InvalidBundle("header is not UTF-8".to_owned()))?;
    let (candidate, reference) = text.split_once(' ').ok_or_else(|| {
        ManagedPointerError::InvalidBundle("advertisement is malformed".to_owned())
    })?;
    if reference != BUNDLE_CANDIDATE_REF {
        return Err(ManagedPointerError::InvalidBundle(
            "candidate advertisement has the wrong ref".to_owned(),
        ));
    }
    let object_format = match candidate.len() {
        40 => GitObjectFormatV1::Sha1,
        64 => GitObjectFormatV1::Sha256,
        _ => {
            return Err(ManagedPointerError::InvalidBundle(
                "candidate object has the wrong width".to_owned(),
            ));
        }
    };
    if !candidate
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ManagedPointerError::InvalidBundle(
            "candidate object is not canonical lowercase hex".to_owned(),
        ));
    }
    let pack_offset = BUNDLE_MAGIC_V2.len() + end + 2;
    let pack = &bytes[pack_offset..];
    if pack.len() < 12 || &pack[..4] != PACK_MAGIC {
        return Err(ManagedPointerError::InvalidBundle(
            "self-contained PACK is absent".to_owned(),
        ));
    }
    let pack_version = u32::from_be_bytes(pack[4..8].try_into().expect("four-byte slice"));
    let object_count = u32::from_be_bytes(pack[8..12].try_into().expect("four-byte slice"));
    if pack_version != PACK_VERSION_V2 || object_count == 0 || object_count > MAX_PACK_OBJECTS {
        return Err(ManagedPointerError::InvalidBundle(
            "PACK version or object count is outside policy".to_owned(),
        ));
    }
    Ok(StrictBundleV1 {
        candidate: candidate.to_owned(),
        object_format,
        pack,
        pack_digest: Digest::hash_bytes(pack),
    })
}

struct OpenRepositoryV1 {
    _allowed_root: OwnedFd,
    repository: OwnedFd,
    git_directory: OwnedFd,
    objects: OwnedFd,
    pack_directory: OwnedFd,
    _refs: OwnedFd,
    bare: bool,
    identity_evidence: ManagedRepositoryIdentityEvidenceV1,
}

#[derive(Clone, Debug)]
struct RepositoryStateV1 {
    object_format: GitObjectFormatV1,
    current_object: String,
    current_tree: String,
    clean: bool,
    reference_checked_out: bool,
    evidence: ManagedRepositoryStateEvidenceV1,
}

impl ManagedPointerTargetV1 {
    #[allow(clippy::too_many_lines)]
    fn open_repository(&self) -> Result<OpenRepositoryV1, ManagedPointerError> {
        let root = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(errno_to_io)?;
        let allowed_relative = self.allowed_root.strip_prefix("/").map_err(|_| {
            ManagedPointerError::UnsafeRepository("allowed root is not absolute".to_owned())
        })?;
        let allowed_root = open_directory_beneath(&root, allowed_relative)?;
        let allowed_stat = rustix::fs::fstat(&allowed_root).map_err(errno_to_io)?;
        if !FileType::from_raw_mode(allowed_stat.st_mode).is_dir()
            || allowed_stat.st_mode & 0o022 != 0
        {
            return Err(ManagedPointerError::UnsafeRepository(
                "allowed root is writable by group or other".to_owned(),
            ));
        }
        let repository_relative =
            self.repository
                .strip_prefix(&self.allowed_root)
                .map_err(|_| {
                    ManagedPointerError::UnsafeRepository(
                        "repository is outside the configured allowed root".to_owned(),
                    )
                })?;
        if repository_relative.as_os_str().is_empty() {
            return Err(ManagedPointerError::UnsafeRepository(
                "repository must be strictly beneath the allowed root".to_owned(),
            ));
        }
        let repository = open_directory_beneath(&allowed_root, repository_relative)?;
        let repository_stat = rustix::fs::fstat(&repository).map_err(errno_to_io)?;
        require_directory_owner(&repository_stat, self.uid, self.gid, "repository root")?;

        let (git_directory, bare) =
            match open_optional_directory_beneath(&repository, Path::new(".git"))? {
                Some(git_directory) => (git_directory, false),
                None => (rustix::io::dup(&repository).map_err(errno_to_io)?, true),
            };
        let git_stat = rustix::fs::fstat(&git_directory).map_err(errno_to_io)?;
        require_directory_owner(&git_stat, self.uid, self.gid, "Git directory")?;
        let objects = open_directory_beneath(&git_directory, Path::new("objects"))?;
        let objects_stat = rustix::fs::fstat(&objects).map_err(errno_to_io)?;
        require_directory_owner(&objects_stat, self.uid, self.gid, "object directory")?;
        // This descriptor check must precede `index-pack`: Git resolves this
        // name itself, so detecting a symlink after invocation would be an
        // out-of-target write followed by a dishonest known failure.
        let pack_directory = open_directory_beneath(&objects, Path::new("pack"))?;
        let pack_stat = rustix::fs::fstat(&pack_directory).map_err(errno_to_io)?;
        require_directory_owner(&pack_stat, self.uid, self.gid, "pack directory")?;
        let refs = open_directory_beneath(&git_directory, Path::new("refs"))?;
        let refs_stat = rustix::fs::fstat(&refs).map_err(errno_to_io)?;
        require_directory_owner(&refs_stat, self.uid, self.gid, "reference directory")?;
        let reference_ancestry =
            reference_ancestry_evidence(&git_directory, &self.reference, self.uid, self.gid)?;
        reject_entry(&git_directory, Path::new("worktrees"), "linked worktrees")?;
        reject_entry(
            &git_directory,
            Path::new("commondir"),
            "common-directory indirection",
        )?;
        reject_entry(
            &git_directory,
            Path::new("config.worktree"),
            "per-worktree configuration",
        )?;
        reject_entry(
            &git_directory,
            &Path::new("logs").join(&self.reference),
            "managed-reference reflog",
        )?;
        reject_entry(
            &git_directory,
            Path::new("objects/info/alternates"),
            "object alternates",
        )?;
        reject_entry(
            &git_directory,
            Path::new("objects/info/http-alternates"),
            "HTTP object alternates",
        )?;
        reject_entry(&git_directory, Path::new("shallow"), "shallow repositories")?;
        let (config_digest, config_node, config_bytes) = read_regular_digest_and_node(
            &git_directory,
            Path::new("config"),
            MAX_REPOSITORY_CONFIG_BYTES,
            self.uid,
            self.gid,
        )?;
        validate_closed_repository_config(&config_bytes)?;

        let mut environment = GitEnvironmentV1::default();
        environment.descriptor_path("GIT_DIR", &git_directory, None)?;
        let format_output = self.run_git_checked(
            GitOperationV1::RevParse,
            &[OsString::from("--show-object-format")],
            &environment,
            None,
            true,
        )?;
        let object_format = parse_object_format(&format_output)?;
        let identity_evidence = ManagedRepositoryIdentityEvidenceV1 {
            schema: MANAGED_REPOSITORY_IDENTITY_SCHEMA_V1.to_owned(),
            allowed_root: utf8_path(&self.allowed_root)?,
            repository: utf8_path(&self.repository)?,
            bare,
            object_format,
            allowed_root_node: node_evidence("allowed-root", &allowed_stat),
            repository_node: node_evidence("repository", &repository_stat),
            git_directory_node: node_evidence("git-directory", &git_stat),
            config_node,
            objects_node: node_evidence("objects", &objects_stat),
            pack_directory_node: node_evidence("objects/pack", &pack_stat),
            reference_ancestry,
            repository_device: repository_stat.st_dev,
            repository_inode: repository_stat.st_ino,
            git_directory_device: git_stat.st_dev,
            git_directory_inode: git_stat.st_ino,
            uid: repository_stat.st_uid,
            gid: repository_stat.st_gid,
            config_digest,
        };
        Ok(OpenRepositoryV1 {
            _allowed_root: allowed_root,
            repository,
            git_directory,
            objects,
            pack_directory,
            _refs: refs,
            bare,
            identity_evidence,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn observe_repository_state(
        &self,
        repository: &OpenRepositoryV1,
    ) -> Result<RepositoryStateV1, ManagedPointerError> {
        let (direct_object, initial_reference) = read_loose_reference(
            &repository.git_directory,
            &self.reference,
            self.uid,
            self.gid,
            repository.identity_evidence.object_format,
        )?;
        let mut environment = GitEnvironmentV1::default();
        environment.descriptor_path("GIT_DIR", &repository.git_directory, None)?;
        let current_object = canonical_object_output(
            &self.run_git_checked(
                GitOperationV1::RevParse,
                &[
                    OsString::from("--verify"),
                    OsString::from(format!("{}^{{commit}}", self.reference)),
                ],
                &environment,
                None,
                true,
            )?,
            repository.identity_evidence.object_format,
        )?;
        if direct_object != current_object {
            return Err(ManagedPointerError::PrestateDrift(
                "loose ref bytes and Git resolution disagree".to_owned(),
            ));
        }
        let current_tree = canonical_object_output(
            &self.run_git_checked(
                GitOperationV1::RevParse,
                &[
                    OsString::from("--verify"),
                    OsString::from(format!("{current_object}^{{tree}}")),
                ],
                &environment,
                None,
                true,
            )?,
            repository.identity_evidence.object_format,
        )?;
        let tree_entries = self.run_git_checked(
            GitOperationV1::LsTree,
            &[
                OsString::from("-r"),
                OsString::from("-z"),
                OsString::from(&current_object),
            ],
            &environment,
            None,
            true,
        )?;
        if tree_entries
            .split(|byte| *byte == 0)
            .any(|entry| entry.starts_with(b"160000 "))
        {
            return Err(ManagedPointerError::UnsafeRepository(
                "gitlinks in the existing target are outside the promotion contract".to_owned(),
            ));
        }

        let (clean, reference_checked_out) = if repository.bare {
            (true, false)
        } else {
            let head = read_regular_bytes(&repository.git_directory, Path::new("HEAD"), 4096)?;
            let expected_head = format!("ref: {}\n", self.reference);
            let reference_checked_out = head == expected_head.as_bytes();
            // Check the independently checked-out worktree while the managed
            // ref itself remains a separate, non-checked-out pointer.
            let checkout_object = canonical_object_output(
                &self.run_git_checked(
                    GitOperationV1::RevParse,
                    &[OsString::from("--verify"), OsString::from("HEAD^{commit}")],
                    &environment,
                    None,
                    true,
                )?,
                repository.identity_evidence.object_format,
            )?;
            (
                self.observe_clean_worktree(repository, &checkout_object)?,
                reference_checked_out,
            )
        };
        let (final_direct_object, final_reference) = read_loose_reference(
            &repository.git_directory,
            &self.reference,
            self.uid,
            self.gid,
            repository.identity_evidence.object_format,
        )?;
        if final_direct_object != current_object || final_reference != initial_reference {
            return Err(ManagedPointerError::PrestateDrift(
                "managed loose ref changed during exact observation".to_owned(),
            ));
        }
        let repository_identity = repository.identity_evidence.identity()?;
        let evidence = ManagedRepositoryStateEvidenceV1 {
            schema: MANAGED_REPOSITORY_STATE_SCHEMA_V1.to_owned(),
            repository_identity,
            reference: final_reference,
            current_object: current_object.clone(),
            current_tree: current_tree.clone(),
            clean,
            reference_checked_out,
        };
        Ok(RepositoryStateV1 {
            object_format: repository.identity_evidence.object_format,
            current_object,
            current_tree,
            clean,
            reference_checked_out,
            evidence,
        })
    }

    fn observe_clean_worktree(
        &self,
        repository: &OpenRepositoryV1,
        current_object: &str,
    ) -> Result<bool, ManagedPointerError> {
        let stage =
            StagingDirectoryV1::create(&self.staging_root, self.production_staging_custody)?;
        self.initialize_staging(&stage, repository.identity_evidence.object_format)?;
        let mut environment = GitEnvironmentV1::default();
        environment.descriptor_path("GIT_DIR", &stage.directory, None)?;
        environment.descriptor_path("GIT_OBJECT_DIRECTORY", &repository.objects, None)?;
        environment.descriptor_path("GIT_INDEX_FILE", &repository.git_directory, Some("index"))?;
        environment.descriptor_path("GIT_WORK_TREE", &repository.repository, None)?;
        let index = self.run_git(
            GitOperationV1::DiffIndex,
            &[
                OsString::from("--quiet"),
                OsString::from("--cached"),
                OsString::from("--no-ext-diff"),
                OsString::from("--no-textconv"),
                OsString::from(current_object),
                OsString::from("--"),
            ],
            &environment,
            None,
            true,
        )?;
        if !exit_is_clean_or_dirty(index.status)? {
            return Ok(false);
        }
        let files = self.run_git(
            GitOperationV1::DiffFiles,
            &[
                OsString::from("--quiet"),
                OsString::from("--no-ext-diff"),
                OsString::from("--no-textconv"),
                OsString::from("--ignore-submodules=dirty"),
                OsString::from("--"),
            ],
            &environment,
            None,
            true,
        )?;
        if !exit_is_clean_or_dirty(files.status)? {
            return Ok(false);
        }
        let others = self.run_git_checked(
            GitOperationV1::LsFiles,
            &[
                OsString::from("--others"),
                OsString::from("--directory"),
                OsString::from("--no-empty-directory"),
                OsString::from("--"),
            ],
            &environment,
            None,
            true,
        )?;
        Ok(index.status.success() && files.status.success() && others.is_empty())
    }

    fn initialize_staging(
        &self,
        stage: &StagingDirectoryV1,
        format: GitObjectFormatV1,
    ) -> Result<(), ManagedPointerError> {
        let stage_fd = &stage.directory;
        let stage_stat = rustix::fs::fstat(stage_fd).map_err(errno_to_io)?;
        rustix::fs::fchmod(stage_fd, Mode::from_raw_mode(0o700)).map_err(errno_to_io)?;
        if stage_stat.st_uid != self.uid || stage_stat.st_gid != self.gid {
            rustix::fs::fchown(
                stage_fd,
                Some(Uid::from_raw(self.uid)),
                Some(Gid::from_raw(self.gid)),
            )
            .map_err(errno_to_io)?;
        }
        let handed_off = rustix::fs::fstat(stage_fd).map_err(errno_to_io)?;
        if !FileType::from_raw_mode(handed_off.st_mode).is_dir()
            || handed_off.st_uid != self.uid
            || handed_off.st_gid != self.gid
            || handed_off.st_mode & 0o7777 != 0o700
        {
            return Err(ManagedPointerError::UnsafeRepository(
                "staging custody transfer did not reach the configured target identity".to_owned(),
            ));
        }
        let mut environment = GitEnvironmentV1::default();
        environment.writable_descriptor_path("GIT_DIR", stage_fd, None)?;
        self.run_git_checked(
            GitOperationV1::Init,
            &[
                OsString::from("--bare"),
                OsString::from("--quiet"),
                OsString::from("--template="),
                OsString::from(format!("--object-format={}", object_format_name(format))),
            ],
            &environment,
            None,
            true,
        )?;
        Ok(())
    }
}

fn open_absolute_directory(path: &Path) -> Result<OwnedFd, ManagedPointerError> {
    let root = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno_to_io)?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| ManagedPointerError::UnsafeRepository("path is not absolute".to_owned()))?;
    open_directory_beneath(&root, relative)
}

fn open_directory_beneath(
    parent: &OwnedFd,
    relative: &Path,
) -> Result<OwnedFd, ManagedPointerError> {
    rustix::fs::openat2(
        parent,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        ManagedPointerError::UnsafeRepository(format!(
            "descriptor directory resolution failed: {error}"
        ))
    })
}

fn open_optional_directory_beneath(
    parent: &OwnedFd,
    relative: &Path,
) -> Result<Option<OwnedFd>, ManagedPointerError> {
    match rustix::fs::openat2(
        parent,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(file) => Ok(Some(file)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(ManagedPointerError::UnsafeRepository(format!(
            "descriptor directory resolution failed: {error}"
        ))),
    }
}

fn require_directory_owner(
    stat: &rustix::fs::Stat,
    uid: u32,
    gid: u32,
    label: &str,
) -> Result<(), ManagedPointerError> {
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_mode & 0o022 != 0
    {
        return Err(ManagedPointerError::UnsafeRepository(format!(
            "{label} has the wrong type, owner, or write policy"
        )));
    }
    Ok(())
}

fn node_evidence(
    name: impl Into<String>,
    stat: &rustix::fs::Stat,
) -> ManagedFilesystemNodeEvidenceV1 {
    ManagedFilesystemNodeEvidenceV1 {
        name: name.into(),
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
        link_count: stat.st_nlink,
    }
}

fn reference_ancestry_evidence(
    git_directory: &OwnedFd,
    reference: &str,
    uid: u32,
    gid: u32,
) -> Result<Vec<ManagedFilesystemNodeEvidenceV1>, ManagedPointerError> {
    let reference_path = Path::new(reference);
    let parent = reference_path
        .parent()
        .ok_or(ManagedPointerError::BindingMismatch)?;
    if !reference.starts_with("refs/heads/") {
        return Err(ManagedPointerError::BindingMismatch);
    }
    let mut ancestry = Vec::new();
    let mut relative = PathBuf::new();
    for component in parent.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(ManagedPointerError::BindingMismatch);
        };
        relative.push(component);
        let opened = open_directory_beneath(git_directory, &relative)?;
        let stat = rustix::fs::fstat(&opened).map_err(errno_to_io)?;
        require_directory_owner(&stat, uid, gid, "managed-ref ancestry")?;
        ancestry.push(node_evidence(utf8_path(&relative)?, &stat));
    }
    if ancestry.first().is_none_or(|node| node.name != "refs") {
        return Err(ManagedPointerError::BindingMismatch);
    }
    Ok(ancestry)
}

fn reject_entry(parent: &OwnedFd, relative: &Path, label: &str) -> Result<(), ManagedPointerError> {
    match rustix::fs::openat2(
        parent,
        relative,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(_) => Err(ManagedPointerError::UnsafeRepository(format!(
            "{label} are outside the managed-pointer contract"
        ))),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(ManagedPointerError::UnsafeRepository(format!(
            "could not inspect forbidden {label}: {error}"
        ))),
    }
}

fn read_regular_digest_and_node(
    parent: &OwnedFd,
    relative: &Path,
    maximum: u64,
    uid: u32,
    gid: u32,
) -> Result<(Digest, ManagedFilesystemNodeEvidenceV1, Vec<u8>), ManagedPointerError> {
    let descriptor = rustix::fs::openat2(
        parent,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        ManagedPointerError::UnsafeRepository(format!("could not open exact config: {error}"))
    })?;
    let before = rustix::fs::fstat(&descriptor).map_err(errno_to_io)?;
    let size = u64::try_from(before.st_size).map_err(|_| {
        ManagedPointerError::UnsafeRepository("config has a negative size".to_owned())
    })?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_nlink != 1
        || before.st_uid != uid
        || before.st_gid != gid
        || before.st_mode & 0o022 != 0
        || size > maximum
    {
        return Err(ManagedPointerError::UnsafeRepository(
            "config type, custody, link count, or size is unsafe".to_owned(),
        ));
    }
    let mut file = File::from(descriptor);
    let mut bytes =
        Vec::with_capacity(usize::try_from(size).map_err(|_| {
            ManagedPointerError::UnsafeRepository("config size overflow".to_owned())
        })?);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = rustix::fs::fstat(&file).map_err(errno_to_io)?;
    if bytes.len() as u64 != size
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(ManagedPointerError::UnsafeRepository(
            "config changed during descriptor read".to_owned(),
        ));
    }
    Ok((
        Digest::hash_bytes(&bytes),
        node_evidence(utf8_path(relative)?, &after),
        bytes,
    ))
}

fn validate_closed_repository_config(bytes: &[u8]) -> Result<(), ManagedPointerError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        ManagedPointerError::UnsafeRepository("repository config is not UTF-8".to_owned())
    })?;
    let mut section = "";
    for line in text.lines() {
        if line
            .chars()
            .any(|character| character.is_control() && character != '\t')
        {
            return Err(ManagedPointerError::UnsafeRepository(
                "repository config contains control bytes".to_owned(),
            ));
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let closing = header.find(']').ok_or_else(|| {
                ManagedPointerError::UnsafeRepository(
                    "repository config section is malformed".to_owned(),
                )
            })?;
            let trailing = header[closing + 1..].trim_start();
            if !trailing.is_empty() && !trailing.starts_with('#') && !trailing.starts_with(';') {
                return Err(ManagedPointerError::UnsafeRepository(
                    "repository config section has trailing syntax".to_owned(),
                ));
            }
            let name = header[..closing]
                .split(|character: char| character.is_ascii_whitespace() || character == '"')
                .next()
                .unwrap_or_default();
            let name = name.split('.').next().unwrap_or_default();
            if name.eq_ignore_ascii_case("include") || name.eq_ignore_ascii_case("includeif") {
                return Err(ManagedPointerError::UnsafeRepository(
                    "repository config includes external configuration".to_owned(),
                ));
            }
            if name.eq_ignore_ascii_case("filter") {
                return Err(ManagedPointerError::UnsafeRepository(
                    "repository config declares a command-bearing content filter".to_owned(),
                ));
            }
            section = if name.eq_ignore_ascii_case("extensions") {
                "extensions"
            } else {
                "other"
            };
            continue;
        }
        let key_end = line
            .find(|character: char| character == '=' || character.is_ascii_whitespace())
            .unwrap_or(line.len());
        let key = &line[..key_end];
        if key.is_empty() {
            return Err(ManagedPointerError::UnsafeRepository(
                "repository config key is malformed".to_owned(),
            ));
        }
        if section == "extensions" && !key.eq_ignore_ascii_case("objectformat") {
            return Err(ManagedPointerError::UnsafeRepository(format!(
                "repository extension {key} is outside the closed configuration contract"
            )));
        }
    }
    Ok(())
}

fn read_regular_bytes(
    parent: &OwnedFd,
    relative: &Path,
    maximum: u64,
) -> Result<Vec<u8>, ManagedPointerError> {
    let descriptor = rustix::fs::openat2(
        parent,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        ManagedPointerError::UnsafeRepository(format!("could not open exact file: {error}"))
    })?;
    let before = rustix::fs::fstat(&descriptor).map_err(errno_to_io)?;
    let size = u64::try_from(before.st_size).map_err(|_| {
        ManagedPointerError::UnsafeRepository("file has a negative size".to_owned())
    })?;
    if !FileType::from_raw_mode(before.st_mode).is_file() || before.st_nlink != 1 || size > maximum
    {
        return Err(ManagedPointerError::UnsafeRepository(
            "file type, link count, or size is unsafe".to_owned(),
        ));
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(
        usize::try_from(size)
            .map_err(|_| ManagedPointerError::UnsafeRepository("file size overflow".to_owned()))?,
    );
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = rustix::fs::fstat(&file).map_err(errno_to_io)?;
    if bytes.len() as u64 != size
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(ManagedPointerError::UnsafeRepository(
            "file changed during descriptor read".to_owned(),
        ));
    }
    Ok(bytes)
}

fn parse_object_format(output: &[u8]) -> Result<GitObjectFormatV1, ManagedPointerError> {
    match output {
        b"sha1\n" => Ok(GitObjectFormatV1::Sha1),
        b"sha256\n" => Ok(GitObjectFormatV1::Sha256),
        _ => Err(ManagedPointerError::UnsafeRepository(
            "Git returned an unsupported object format".to_owned(),
        )),
    }
}

fn object_format_name(format: GitObjectFormatV1) -> &'static str {
    match format {
        GitObjectFormatV1::Sha1 => "sha1",
        GitObjectFormatV1::Sha256 => "sha256",
    }
}

fn canonical_object_output(
    output: &[u8],
    format: GitObjectFormatV1,
) -> Result<String, ManagedPointerError> {
    let value = std::str::from_utf8(output)
        .map_err(|_| ManagedPointerError::PrestateDrift("object output is not UTF-8".to_owned()))?
        .strip_suffix('\n')
        .ok_or_else(|| {
            ManagedPointerError::PrestateDrift("object output is not newline-terminated".to_owned())
        })?;
    let expected = match format {
        GitObjectFormatV1::Sha1 => 40,
        GitObjectFormatV1::Sha256 => 64,
    };
    if value.len() != expected
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ManagedPointerError::PrestateDrift(
            "object output is not canonical".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn exit_is_clean_or_dirty(status: ExitStatus) -> Result<bool, ManagedPointerError> {
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(ManagedPointerError::Git {
            operation: "dirty-check",
            detail: "Git returned an operational dirty-check failure".to_owned(),
        }),
    }
}

fn utf8_path(path: &Path) -> Result<String, ManagedPointerError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(ManagedPointerError::BindingMismatch)
}

fn normalized_absolute_path(path: &Path) -> bool {
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && normalized == path
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn validate_production_staging_custody(
    is_directory: bool,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), ManagedPointerError> {
    if !is_directory || uid != 0 || gid != 0 || mode & 0o7777 != 0o700 {
        return Err(ManagedPointerError::UnsafeRepository(
            "production staging root is not exact root-owned mode 0700 custody".to_owned(),
        ));
    }
    Ok(())
}

struct StagingDirectoryV1 {
    root: OwnedFd,
    name: String,
    directory: OwnedFd,
}

impl StagingDirectoryV1 {
    fn create(root: &Path, production_custody: bool) -> Result<Self, ManagedPointerError> {
        let root_directory = open_absolute_directory(root)?;
        let root_stat = rustix::fs::fstat(&root_directory).map_err(errno_to_io)?;
        let safe = if production_custody {
            validate_production_staging_custody(
                FileType::from_raw_mode(root_stat.st_mode).is_dir(),
                root_stat.st_uid,
                root_stat.st_gid,
                root_stat.st_mode,
            )
            .is_ok()
        } else {
            FileType::from_raw_mode(root_stat.st_mode).is_dir()
                && root_stat.st_uid == nix::unistd::geteuid().as_raw()
                && root_stat.st_mode & 0o022 == 0
        };
        if !safe {
            return Err(ManagedPointerError::UnsafeRepository(
                "staging root is not a broker-owned private directory".to_owned(),
            ));
        }
        for _ in 0..32 {
            let name = format!(".ag-promotion-{}", uuid::Uuid::new_v4());
            match rustix::fs::mkdirat(&root_directory, name.as_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let directory = open_directory_beneath(&root_directory, Path::new(&name))?;
                    let stat = rustix::fs::fstat(&directory).map_err(errno_to_io)?;
                    if !FileType::from_raw_mode(stat.st_mode).is_dir()
                        || stat.st_uid != root_stat.st_uid
                        || stat.st_gid != root_stat.st_gid
                        || stat.st_mode & 0o7777 != 0o700
                    {
                        return Err(ManagedPointerError::UnsafeRepository(
                            "new staging directory custody differs from its descriptor-bound root"
                                .to_owned(),
                        ));
                    }
                    return Ok(Self {
                        root: root_directory,
                        name,
                        directory,
                    });
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(ManagedPointerError::Io(errno_to_io(error))),
            }
        }
        Err(ManagedPointerError::UnsafeRepository(
            "could not allocate a unique staging directory".to_owned(),
        ))
    }
}

impl Drop for StagingDirectoryV1 {
    fn drop(&mut self) {
        // Stay anchored to the retained, custody-validated root descriptor.
        // A later pathname replacement must never redirect cleanup into an
        // unrelated tree. Failure leaks a quarantined directory safely.
        let anchored = format!("/proc/self/fd/{}/{}", self.root.as_raw_fd(), self.name);
        let _ = fs::remove_dir_all(anchored);
    }
}

#[cfg(test)]
fn test_promotion_standing(
    context: &ManagedPointerExecutionContextV1,
    effect: &CanonicalEffectV1,
    now_unix_ms: u64,
) -> Result<ManagedPointerPromotionStandingV1, ManagedPointerError> {
    let fields = CanonicalPointerFieldsV1::from_effect(effect)?;
    let receipt = ManagedPointerPromotionStandingReceiptV1 {
        schema: MANAGED_POINTER_PROMOTION_STANDING_RECEIPT_SCHEMA_V1.to_owned(),
        proposal: context.proposal.clone(),
        authorization: context.authorization.clone(),
        candidate_ratification: Digest::hash_bytes(b"test-candidate-ratification"),
        candidate: fields.prepared_candidate.clone(),
        exact_basis: fields.exact_basis.clone(),
        current_basis: fields.exact_basis.clone(),
        issued_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: fields
            .expires_unix_ms
            .min(now_unix_ms.saturating_add(60_000)),
        nonce: "managed-pointer-unit-test-standing".to_owned(),
    };
    receipt.identity()?;
    Ok(ManagedPointerPromotionStandingV1 { receipt })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::process::Output;

    use tempfile::TempDir;

    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct RepositorySnapshotNodeV1 {
        path: String,
        file_type: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        device: u64,
        inode: u64,
        length: u64,
        mtime: i64,
        mtime_nsec: i64,
        content: Option<Digest>,
    }

    fn repository_snapshot(root: &Path) -> Vec<RepositorySnapshotNodeV1> {
        fn visit(root: &Path, path: &Path, nodes: &mut Vec<RepositorySnapshotNodeV1>) {
            let mut entries = fs::read_dir(path)
                .expect("snapshot directory")
                .map(|entry| entry.expect("snapshot entry").path())
                .collect::<Vec<_>>();
            entries.sort();
            for entry in entries {
                let metadata = fs::symlink_metadata(&entry).expect("snapshot metadata");
                let content = if metadata.file_type().is_file() {
                    Some(Digest::hash_bytes(
                        &fs::read(&entry).expect("snapshot content"),
                    ))
                } else if metadata.file_type().is_symlink() {
                    Some(Digest::hash_bytes(
                        fs::read_link(&entry)
                            .expect("snapshot link")
                            .to_string_lossy()
                            .as_bytes(),
                    ))
                } else {
                    None
                };
                nodes.push(RepositorySnapshotNodeV1 {
                    path: entry
                        .strip_prefix(root)
                        .expect("snapshot relative path")
                        .to_string_lossy()
                        .into_owned(),
                    file_type: metadata.mode() & libc::S_IFMT,
                    mode: metadata.mode() & 0o7777,
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    links: metadata.nlink(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    length: metadata.len(),
                    mtime: metadata.mtime(),
                    mtime_nsec: metadata.mtime_nsec(),
                    content,
                });
                if metadata.file_type().is_dir() {
                    visit(root, &entry, nodes);
                }
            }
        }

        let mut nodes = Vec::new();
        visit(root, root, &mut nodes);
        nodes
    }

    fn assert_staging_root_empty(path: &Path) {
        assert_eq!(
            fs::read_dir(path).expect("staging root").count(),
            0,
            "genesis observation left staging residue"
        );
    }

    #[test]
    fn strict_bundle_parser_rejects_prerequisites_extra_refs_and_noncanonical_ids() {
        let oid = "1".repeat(40);
        let mut valid = format!("# v2 git bundle\n{oid} {BUNDLE_CANDIDATE_REF}\n\n").into_bytes();
        valid.extend_from_slice(b"PACK\0\0\0\x02\0\0\0\x01payload");
        let parsed = parse_strict_bundle(&valid).expect("strict bundle");
        assert_eq!(parsed.candidate, oid);
        assert_eq!(parsed.object_format, GitObjectFormatV1::Sha1);
        assert_eq!(parsed.pack_digest, Digest::hash_bytes(parsed.pack));

        let prerequisite = format!(
            "# v2 git bundle\n-{oid} base\n{oid} {BUNDLE_CANDIDATE_REF}\n\nPACK\0\0\0\x02\0\0\0\x01x"
        );
        assert!(parse_strict_bundle(prerequisite.as_bytes()).is_err());

        let extra = format!(
            "# v2 git bundle\n{oid} {BUNDLE_CANDIDATE_REF}\n{oid} refs/heads/other\n\nPACK\0\0\0\x02\0\0\0\x01x"
        );
        assert!(parse_strict_bundle(extra.as_bytes()).is_err());

        let uppercase = format!(
            "# v2 git bundle\n{} {BUNDLE_CANDIDATE_REF}\n\nPACK\0\0\0\x02\0\0\0\x01x",
            "A".repeat(40)
        );
        assert!(parse_strict_bundle(uppercase.as_bytes()).is_err());
    }

    #[test]
    fn repository_config_rejects_external_and_worktree_indirection() {
        validate_closed_repository_config(
            b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n",
        )
        .expect("ordinary bounded local config");
        for hostile in [
            b"[include]\n\tpath = /tmp/foreign\n".as_slice(),
            b"[includeIf \"gitdir:/srv/**\"]\n\tpath = /tmp/foreign\n".as_slice(),
            b"[filter \"hostile\"]\n\tclean = /bin/false\n".as_slice(),
            b"[extensions]\n\tworktreeConfig = true\n".as_slice(),
            b"[extensions]\n\trefStorage = reftable\n".as_slice(),
        ] {
            assert!(matches!(
                validate_closed_repository_config(hostile),
                Err(ManagedPointerError::UnsafeRepository(_))
            ));
        }
    }

    #[test]
    fn launch_profile_is_deterministic_and_binds_security_and_git() {
        let security = Digest::hash_bytes(b"development");
        let git = Digest::hash_bytes(b"git");
        let profile = managed_pointer_launch_profile_identity(&security, &git).expect("profile");
        assert_eq!(
            profile,
            managed_pointer_launch_profile_identity(&security, &git).expect("same profile")
        );
        assert_ne!(
            profile,
            managed_pointer_launch_profile_identity(&Digest::hash_bytes(b"production"), &git)
                .expect("other profile")
        );
        assert_ne!(
            profile,
            managed_pointer_launch_profile_identity(&security, &Digest::hash_bytes(b"other git"))
                .expect("other git profile")
        );
    }

    struct GitFixtureV1 {
        directory: TempDir,
        runtime: ManagedPointerRuntimeV1,
        target: TargetId,
        bundle: Vec<u8>,
        artifact: Digest,
        expected_object: String,
        new_object: String,
        sentinel: PathBuf,
    }

    fn plain_git(arguments: &[&OsStr]) -> Output {
        let output = Command::new("/usr/bin/git")
            .env_clear()
            .env("LC_ALL", "C")
            .args(arguments)
            .output()
            .expect("fixture git");
        assert!(
            output.status.success(),
            "fixture git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn output_line(output: Output) -> String {
        String::from_utf8(output.stdout)
            .expect("fixture UTF-8")
            .trim_end()
            .to_owned()
    }

    // The fixture deliberately assembles the complete hostile repository,
    // pinned helper, bundle, and enrolled identities in one auditable setup.
    #[allow(clippy::too_many_lines)]
    fn fixture() -> GitFixtureV1 {
        let directory = tempfile::tempdir().expect("temporary root");
        let allowed_root = directory.path().join("allowed");
        let repository = allowed_root.join("target");
        let staging_root = directory.path().join("staging");
        fs::create_dir(&allowed_root).expect("allowed root");
        fs::create_dir(&staging_root).expect("staging root");
        fs::set_permissions(&allowed_root, fs::Permissions::from_mode(0o700)).expect("root mode");
        fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700))
            .expect("staging mode");
        plain_git(&[
            OsStr::new("init"),
            OsStr::new("--quiet"),
            repository.as_os_str(),
        ]);
        plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("config"),
            OsStr::new("user.name"),
            OsStr::new("fixture"),
        ]);
        plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("config"),
            OsStr::new("user.email"),
            OsStr::new("fixture@example.invalid"),
        ]);
        fs::write(repository.join("base.txt"), b"base\n").expect("base");
        fs::write(repository.join(".gitattributes"), b"*.txt filter=hostile\n")
            .expect("attributes");
        plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("add"),
            OsStr::new("base.txt"),
            OsStr::new(".gitattributes"),
        ]);
        plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("commit"),
            OsStr::new("--quiet"),
            OsStr::new("-m"),
            OsStr::new("base"),
        ]);
        // Test hosts commonly use a collaborative 0002 umask. Production
        // enrollment intentionally refuses group-writable authority roots,
        // so make the fixture express that reviewed ownership policy exactly.
        for authority_directory in [
            repository.clone(),
            repository.join(".git"),
            repository.join(".git/objects"),
            repository.join(".git/refs"),
            repository.join(".git/refs/heads"),
        ] {
            fs::set_permissions(authority_directory, fs::Permissions::from_mode(0o700))
                .expect("authority directory mode");
        }
        let expected_object = output_line(plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("rev-parse"),
            OsStr::new("HEAD"),
        ]));
        let expected_tree = output_line(plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("rev-parse"),
            OsStr::new("HEAD^{tree}"),
        ]));
        plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("-c"),
            OsStr::new("core.logAllRefUpdates=false"),
            OsStr::new("branch"),
            OsStr::new("managed"),
            OsStr::new(&expected_object),
        ]);
        fs::set_permissions(
            repository.join(".git/refs/heads/managed"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("managed reference mode");

        let source = allowed_root.join("source");
        plain_git(&[
            OsStr::new("clone"),
            OsStr::new("--quiet"),
            repository.as_os_str(),
            source.as_os_str(),
        ]);
        plain_git(&[
            OsStr::new("-C"),
            source.as_os_str(),
            OsStr::new("config"),
            OsStr::new("user.name"),
            OsStr::new("fixture"),
        ]);
        plain_git(&[
            OsStr::new("-C"),
            source.as_os_str(),
            OsStr::new("config"),
            OsStr::new("user.email"),
            OsStr::new("fixture@example.invalid"),
        ]);
        plain_git(&[
            OsStr::new("-C"),
            source.as_os_str(),
            OsStr::new("checkout"),
            OsStr::new("--quiet"),
            OsStr::new("-b"),
            OsStr::new("ag-candidate"),
        ]);
        fs::write(source.join("candidate.txt"), b"candidate\n").expect("candidate");
        plain_git(&[
            OsStr::new("-C"),
            source.as_os_str(),
            OsStr::new("add"),
            OsStr::new("candidate.txt"),
        ]);
        plain_git(&[
            OsStr::new("-C"),
            source.as_os_str(),
            OsStr::new("commit"),
            OsStr::new("--quiet"),
            OsStr::new("-m"),
            OsStr::new("candidate"),
        ]);
        let new_object = output_line(plain_git(&[
            OsStr::new("-C"),
            source.as_os_str(),
            OsStr::new("rev-parse"),
            OsStr::new("HEAD"),
        ]));
        let bundle_path = directory.path().join("candidate.bundle");
        plain_git(&[
            OsStr::new("-C"),
            source.as_os_str(),
            OsStr::new("bundle"),
            OsStr::new("create"),
            bundle_path.as_os_str(),
            OsStr::new("refs/heads/ag-candidate"),
        ]);
        let bundle = fs::read(&bundle_path).expect("bundle bytes");
        let artifact = Digest::hash_bytes(&bundle);
        fs::set_permissions(
            repository.join(".git/objects/pack"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("pack directory mode");

        // Install a repository-controlled hook after fixture setup. The fixed
        // hooks path must make it unreachable even though the exact config and
        // filesystem state are enrolled below.
        let sentinel = directory.path().join("executed-sentinel");
        fs::set_permissions(
            repository.join(".git/config"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("config mode");
        let hook = repository.join(".git/hooks/reference-transaction");
        fs::write(
            &hook,
            format!("#!/bin/sh\ntouch {}\nexit 1\n", sentinel.display()),
        )
        .expect("hostile hook");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("hook mode");
        let _ = fs::remove_file(&sentinel);

        let git_path = PathBuf::from("/usr/bin/git");
        let git_identity = Digest::hash_bytes(&fs::read(&git_path).expect("Git bytes"));
        let security_profile_identity =
            Digest::hash_domain("ag-security-profile-identity-v1", b"development");
        let launch_profile =
            managed_pointer_launch_profile_identity(&security_profile_identity, &git_identity)
                .expect("launch profile");
        let target_id = TargetId::parse("repository-main").expect("target id");
        let uid = fs::metadata(&repository).expect("repo metadata").uid();
        let gid = fs::metadata(&repository).expect("repo metadata").gid();
        let mut target_runtime = ManagedPointerTargetV1 {
            allowed_root,
            repository,
            reference: "refs/heads/managed".to_owned(),
            activation_genesis_object: expected_object.clone(),
            activation_genesis_tree: expected_tree,
            activation_genesis_state: Digest::hash_bytes(b"genesis state"),
            repository_identity: Digest::hash_bytes(b"placeholder"),
            uid,
            gid,
            staging_root,
            production_staging_custody: false,
            promotion_ttl_ms: 60_000,
            git: Mutex::new(PinnedGitV1::open(&git_path, &git_identity).expect("pin Git")),
            launch_profile,
        };
        let repository_handle = target_runtime
            .open_repository()
            .expect("measure repository");
        target_runtime.repository_identity = repository_handle
            .identity_evidence
            .identity()
            .expect("repository identity");
        drop(repository_handle);
        let runtime = ManagedPointerRuntimeV1 {
            targets: BTreeMap::from([(target_id.clone(), target_runtime)]),
            security_profile_identity,
        };
        GitFixtureV1 {
            directory,
            runtime,
            target: target_id,
            bundle,
            artifact,
            expected_object,
            new_object,
            sentinel,
        }
    }

    fn canonical_effect(fixture: &GitFixtureV1) -> CanonicalEffectV1 {
        let observation = fixture
            .runtime
            .observe_candidate_bytes(&fixture.target, &fixture.artifact, &fixture.bundle)
            .expect("candidate observation");
        let TargetObservationV1::ManagedPointer {
            current_object,
            current_tree,
            candidate_object,
            candidate_tree,
            candidate_pack_digest,
            object_format,
            repository_identity,
            repository_device,
            repository_inode,
            git_directory_device,
            git_directory_inode,
            repository_uid,
            repository_gid,
            clean,
            reference_checked_out,
            prestate_identity,
            ..
        } = observation
        else {
            panic!("pointer observation");
        };
        assert!(clean);
        assert!(!reference_checked_out);
        let target = &fixture.runtime.targets[&fixture.target];
        let git = target.git.lock().expect("Git pin");
        CanonicalEffectV1::ManagedPointerPromotion {
            schema: MANAGED_POINTER_PROMOTION_SCHEMA_V2.to_owned(),
            operation_id: Digest::hash_bytes(b"operation"),
            prepared_candidate: Digest::hash_bytes(b"prepared-candidate"),
            exact_basis: Digest::hash_bytes(b"exact-basis"),
            complete_inputs: Digest::hash_bytes(b"complete-inputs"),
            candidate_preparation_receipt: Digest::hash_bytes(b"candidate-preparation"),
            target: fixture.target.clone(),
            allowed_root: utf8_path(&target.allowed_root).expect("allowed root"),
            repository: utf8_path(
                target
                    .repository
                    .strip_prefix(&target.allowed_root)
                    .expect("relative repository"),
            )
            .expect("repository"),
            reference: target.reference.clone(),
            repository_identity,
            repository_device,
            repository_inode,
            git_directory_device,
            git_directory_inode,
            uid: repository_uid,
            gid: repository_gid,
            prestate_identity,
            staging_root: utf8_path(&target.staging_root).expect("staging root"),
            artifact: fixture.artifact.clone(),
            candidate_pack_digest,
            object_format,
            expected_object: current_object,
            expected_tree: current_tree,
            new_object: candidate_object,
            expected_post_tree: candidate_tree,
            expires_unix_ms: 4_102_444_800_000,
            helper_executable: git.executable.clone(),
            helper_launch_profile: target.launch_profile.clone(),
        }
    }

    fn context() -> ManagedPointerExecutionContextV1 {
        ManagedPointerExecutionContextV1 {
            proposal: Digest::hash_bytes(b"proposal"),
            authorization: Digest::hash_bytes(b"authorization"),
            attempt: Digest::hash_bytes(b"attempt"),
            effect_index: 0,
        }
    }

    fn expect_precondition_failure(receipt: &ExecutionReceiptV1) {
        assert!(
            matches!(
                &receipt.outcome,
                ExecutionOutcomeV1::Failed {
                    failure: ExecutionFailureV1 {
                        code: ExecutionFailureCodeV1::PrestateDrift,
                        ..
                    }
                }
            ),
            "unexpected refusal: {:?}",
            receipt.outcome
        );
    }

    fn managed_ref(fixture: &GitFixtureV1) -> String {
        let repository = &fixture.runtime.targets[&fixture.target].repository;
        output_line(plain_git(&[
            OsStr::new("-C"),
            repository.as_os_str(),
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("refs/heads/managed"),
        ]))
    }

    #[test]
    fn bounded_candidate_preparation_preserves_the_authoritative_projection() {
        let fixture = fixture();
        let standing = fixture
            .runtime
            .preparation_standing(
                &fixture.target,
                ManagedPointerPreparationStandingContextV1 {
                    authority_domain: AuthorityDomain::parse("test-host").expect("domain"),
                    epoch: Epoch::parse("1").expect("epoch"),
                    catalog_identity: Digest::hash_bytes(b"catalog"),
                    security_profile_identity: fixture.runtime.security_profile_identity.clone(),
                    max_artifact_bytes: u64::try_from(fixture.bundle.len()).expect("bundle length"),
                    now_unix_ms: 1,
                },
            )
            .expect("preparation standing");
        let prepared = fixture
            .runtime
            .prepare_candidate_bytes(standing, &fixture.artifact, &fixture.bundle, 1)
            .expect("bounded candidate preparation");
        prepared.candidate.identity().expect("candidate identity");
        assert_eq!(
            prepared.candidate.preparation_receipt.protected_prestate,
            prepared.candidate.preparation_receipt.protected_poststate
        );
        assert_eq!(managed_ref(&fixture), fixture.expected_object);
    }

    #[test]
    fn production_staging_custody_is_exact_and_privilege_independent_to_test() {
        validate_production_staging_custody(true, 0, 0, libc::S_IFDIR | 0o700)
            .expect("exact production custody");
        for hostile in [
            (false, 0, 0, libc::S_IFREG | 0o700),
            (true, 1, 0, libc::S_IFDIR | 0o700),
            (true, 0, 1, libc::S_IFDIR | 0o700),
            (true, 0, 0, libc::S_IFDIR | 0o750),
            (true, 0, 0, libc::S_IFDIR | 0o1700),
            (true, 0, 0, libc::S_IFDIR | 0o2700),
        ] {
            assert!(matches!(
                validate_production_staging_custody(hostile.0, hostile.1, hostile.2, hostile.3),
                Err(ManagedPointerError::UnsafeRepository(_))
            ));
        }
    }

    #[test]
    fn candidate_preparation_requires_live_scope_and_budget_standing() {
        assert!(matches!(
            require_preparation_standing(None),
            Err(ManagedPointerError::PreparationStandingAbsent)
        ));

        let fixture = fixture();
        let wrong_profile = fixture.runtime.preparation_standing(
            &fixture.target,
            ManagedPointerPreparationStandingContextV1 {
                authority_domain: AuthorityDomain::parse("test-host").expect("domain"),
                epoch: Epoch::parse("1").expect("epoch"),
                catalog_identity: Digest::hash_bytes(b"catalog"),
                security_profile_identity: Digest::hash_bytes(b"wrong-profile"),
                max_artifact_bytes: 1,
                now_unix_ms: 1,
            },
        );
        assert!(matches!(
            wrong_profile,
            Err(ManagedPointerError::PreparationStandingScopeMismatch)
        ));

        let standing = fixture
            .runtime
            .preparation_standing(
                &fixture.target,
                ManagedPointerPreparationStandingContextV1 {
                    authority_domain: AuthorityDomain::parse("test-host").expect("domain"),
                    epoch: Epoch::parse("1").expect("epoch"),
                    catalog_identity: Digest::hash_bytes(b"catalog"),
                    security_profile_identity: fixture.runtime.security_profile_identity.clone(),
                    max_artifact_bytes: u64::try_from(fixture.bundle.len() - 1)
                        .expect("bounded fixture"),
                    now_unix_ms: 1,
                },
            )
            .expect("bounded standing");
        assert!(matches!(
            fixture.runtime.prepare_candidate_bytes(
                standing,
                &fixture.artifact,
                &fixture.bundle,
                1,
            ),
            Err(ManagedPointerError::PreparationBudgetExceeded)
        ));
        assert_eq!(managed_ref(&fixture), fixture.expected_object);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn exact_fd_git_path_prepares_and_commits_without_repo_commands() {
        let fixture = fixture();
        let effect = canonical_effect(&fixture);
        let prepared = fixture
            .runtime
            .prepare(context(), &effect, &fixture.bundle, 1)
            .expect("reversible preparation");
        assert_eq!(prepared.evidence.execution, context());
        let mut legacy_evidence = prepared.evidence.clone();
        legacy_evidence.schema = "ag.managed-pointer.preparation/v1".to_owned();
        assert!(matches!(
            legacy_evidence.checkpoint(),
            Err(ManagedPointerError::BindingMismatch)
        ));
        let receipt = fixture.runtime.commit(prepared, 2);
        assert!(
            matches!(
                &receipt.receipt.outcome,
                ExecutionOutcomeV1::Succeeded {
                    success: EffectSuccessV1::ManagedPointerPromotion { .. }
                }
            ),
            "unexpected promotion outcome: {:?}",
            receipt.receipt.outcome
        );
        let activation = receipt
            .activation_receipt
            .as_ref()
            .expect("durable activation explanation");
        activation
            .identity(&effect)
            .expect("activation receipt binds canonical effect");
        assert_eq!(activation.previous_object, fixture.expected_object);
        assert_eq!(activation.installed_object, fixture.new_object);
        assert!(activation.commit.reference_fsynced);
        let mut substituted_activation = activation.clone();
        substituted_activation.installed_tree = "substituted-tree".to_owned();
        assert!(matches!(
            substituted_activation.verify(&effect),
            Err(ManagedPointerError::BindingMismatch)
        ));
        let mut substituted_request = activation.clone();
        substituted_request.commit.request_digest = Digest::hash_bytes(b"substituted request");
        assert!(matches!(
            substituted_request.verify(&effect),
            Err(ManagedPointerError::BindingMismatch)
        ));
        for mutate_schema in [
            |receipt: &mut ManagedPointerActivationReceiptV1| {
                receipt.commit.schema = "foreign.commit".to_owned();
            },
            |receipt: &mut ManagedPointerActivationReceiptV1| {
                receipt.poststate.schema = "foreign.poststate".to_owned();
            },
            |receipt: &mut ManagedPointerActivationReceiptV1| {
                receipt.poststate.state.schema = "foreign.state".to_owned();
            },
        ] {
            let mut substituted_schema = activation.clone();
            mutate_schema(&mut substituted_schema);
            assert!(matches!(
                substituted_schema.verify(&effect),
                Err(ManagedPointerError::BindingMismatch)
            ));
        }
        let observed = fixture
            .runtime
            .observe_canonical(&effect)
            .expect("poststate observation");
        assert!(matches!(
            observed,
            TargetObservationV1::ManagedPointer {
                current_object,
                candidate_object,
                clean: true,
                reference_checked_out: false,
                ..
            } if current_object == fixture.new_object && candidate_object == fixture.new_object
        ));
        let target = &fixture.runtime.targets[&fixture.target];
        let reference_metadata = fs::metadata(target.repository.join(".git/refs/heads/managed"))
            .expect("committed reference metadata");
        assert_eq!(reference_metadata.uid(), target.uid);
        assert_eq!(reference_metadata.gid(), target.gid);
        assert_eq!(reference_metadata.mode() & 0o022, 0);
        let mut imported_objects = 0;
        for entry in fs::read_dir(target.repository.join(".git/objects/pack"))
            .expect("imported object directory")
        {
            let entry = entry.expect("imported object entry");
            if matches!(
                entry.path().extension().and_then(OsStr::to_str),
                Some("pack" | "idx")
            ) {
                let metadata = entry.metadata().expect("imported object metadata");
                assert_eq!(metadata.uid(), target.uid);
                assert_eq!(metadata.gid(), target.gid);
                assert_eq!(metadata.mode() & 0o022, 0);
                imported_objects += 1;
            }
        }
        assert_eq!(imported_objects, 2);
        assert!(
            !fixture.sentinel.exists(),
            "repository-controlled command executed"
        );
        assert!(
            nix::sys::prctl::get_no_new_privs().expect("read no-new-privileges state"),
            "helper launch must establish no-new-privileges before exec"
        );
        let governed_head = ManagedPointerActivationHeadV1 {
            object: activation.installed_object.clone(),
            tree: activation.installed_tree.clone(),
            state_identity: activation
                .poststate
                .state
                .identity()
                .expect("durable state identity"),
        };
        let reference = target.repository.join(".git/refs/heads/managed");
        let replacement = target.repository.join(".git/refs/heads/.ag-replacement");
        fs::write(
            &replacement,
            format!("{}\n", activation.installed_object).as_bytes(),
        )
        .expect("same-byte replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
            .expect("replacement mode");
        fs::rename(&replacement, &reference).expect("replace loose ref inode");
        assert!(matches!(
            fixture
                .runtime
                .require_activation_state(&fixture.target, &governed_head),
            Err(ManagedPointerError::PrestateDrift(_))
        ));
    }

    struct FixedManagedPointerClockV1(u64);

    impl ManagedPointerClockV1 for FixedManagedPointerClockV1 {
        fn now_unix_ms(&self) -> Result<u64, ManagedPointerError> {
            Ok(self.0)
        }
    }

    #[test]
    fn refreshed_clock_refuses_expiry_immediately_before_pointer_cas() {
        let fixture = fixture();
        let mut effect = canonical_effect(&fixture);
        let CanonicalEffectV1::ManagedPointerPromotion {
            expires_unix_ms, ..
        } = &mut effect
        else {
            panic!("managed-pointer effect");
        };
        *expires_unix_ms = 50;
        let prepared = fixture
            .runtime
            .prepare(context(), &effect, &fixture.bundle, 1)
            .expect("preparation before expiry");
        let receipt = fixture.runtime.commit_inner_with_clock(
            prepared,
            2,
            CommitFailpointV1::None,
            &FixedManagedPointerClockV1(50),
        );
        expect_precondition_failure(&receipt.receipt);
        assert_eq!(managed_ref(&fixture), fixture.expected_object);
        assert!(!fixture.sentinel.exists());
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn helper_custody_requires_exact_root_owned_sealed_executable() {
        assert!(pinned_git_metadata_values_are_safe(true, 0, 1, 0o100755, 1));
        for unsafe_metadata in [
            (false, 0, 1, 0o100755, 1),
            (true, 1_000, 1, 0o100755, 1),
            (true, 0, 2, 0o100755, 1),
            (true, 0, 1, 0o100775, 1),
            (true, 0, 1, 0o104755, 1),
            (true, 0, 1, 0o102755, 1),
            (true, 0, 1, 0o101755, 1),
            (true, 0, 1, 0o100644, 1),
            (true, 0, 1, 0o100755, 0),
            (true, 0, 1, 0o100755, MAX_GIT_EXECUTABLE_BYTES + 1),
        ] {
            assert!(!pinned_git_metadata_values_are_safe(
                unsafe_metadata.0,
                unsafe_metadata.1,
                unsafe_metadata.2,
                unsafe_metadata.3,
                unsafe_metadata.4,
            ));
        }

        let git_path = Path::new("/usr/bin/git");
        let identity = Digest::hash_bytes(&fs::read(git_path).expect("Git bytes"));
        let mut pinned = PinnedGitV1::open(git_path, &identity).expect("trusted Git helper");
        let required_seals =
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
        assert!(
            rustix::fs::fcntl_get_seals(&pinned.snapshot)
                .expect("snapshot seals")
                .contains(required_seals)
        );
        assert!(
            pinned.snapshot.write_all(b"substitute").is_err(),
            "sealed snapshot must reject byte substitution"
        );
        pinned.revalidate().expect("sealed exact helper");

        let directory = TempDir::new().expect("untrusted helper directory");
        let copied = directory.path().join("git");
        fs::copy(git_path, &copied).expect("copy Git");
        fs::set_permissions(&copied, fs::Permissions::from_mode(0o755)).expect("copied Git mode");
        assert!(matches!(
            PinnedGitV1::open(&copied, &identity),
            Err(ManagedPointerError::GitIdentityMismatch)
        ));
    }

    #[test]
    fn failpoints_keep_pre_boundary_failure_separate_from_post_cas_uncertainty() {
        let before = fixture();
        let before_effect = canonical_effect(&before);
        let before_prepared = before
            .runtime
            .prepare(context(), &before_effect, &before.bundle, 1)
            .expect("preparation");
        let before_receipt =
            before
                .runtime
                .commit_inner(before_prepared, 2, CommitFailpointV1::BeforeCas);
        assert!(matches!(
            before_receipt.receipt.outcome,
            ExecutionOutcomeV1::Failed { .. }
        ));
        let before_observed = before
            .runtime
            .observe_canonical(&before_effect)
            .expect("prestate");
        assert!(matches!(
            before_observed,
            TargetObservationV1::ManagedPointer { current_object, .. }
                if current_object == before.expected_object
        ));

        let after = fixture();
        let after_effect = canonical_effect(&after);
        let after_prepared = after
            .runtime
            .prepare(context(), &after_effect, &after.bundle, 1)
            .expect("preparation");
        let after_receipt =
            after
                .runtime
                .commit_inner(after_prepared, 2, CommitFailpointV1::AfterCas);
        assert!(matches!(
            after_receipt.receipt.outcome,
            ExecutionOutcomeV1::Indeterminate { .. }
        ));
        let after_observed = after
            .runtime
            .observe_canonical(&after_effect)
            .expect("poststate");
        assert!(matches!(
            after_observed,
            TargetObservationV1::ManagedPointer { current_object, .. }
                if current_object == after.new_object
        ));
    }

    #[test]
    fn substituted_artifact_and_prestate_drift_refuse_before_pointer_mutation() {
        let artifact = fixture();
        let artifact_effect = canonical_effect(&artifact);
        let mut substituted = artifact.bundle.clone();
        *substituted.last_mut().expect("nonempty bundle") ^= 1;
        let artifact_receipt = artifact
            .runtime
            .prepare(context(), &artifact_effect, &substituted, 1)
            .expect_err("substituted artifact must refuse");
        assert!(matches!(
            &artifact_receipt.outcome,
            ExecutionOutcomeV1::Failed {
                failure: ExecutionFailureV1 {
                    code: ExecutionFailureCodeV1::ArtifactDigestMismatch,
                    ..
                }
            }
        ));
        assert_eq!(managed_ref(&artifact), artifact.expected_object);

        let dirty = fixture();
        let dirty_effect = canonical_effect(&dirty);
        let dirty_repository = &dirty.runtime.targets[&dirty.target].repository;
        fs::write(dirty_repository.join("base.txt"), b"unratified change\n")
            .expect("dirty worktree");
        let dirty_receipt = dirty
            .runtime
            .prepare(context(), &dirty_effect, &dirty.bundle, 1)
            .expect_err("dirty checkout must refuse");
        expect_precondition_failure(&dirty_receipt);
        assert_eq!(managed_ref(&dirty), dirty.expected_object);
        assert!(!dirty.sentinel.exists());

        let identity = fixture();
        let identity_effect = canonical_effect(&identity);
        let identity_repository = &identity.runtime.targets[&identity.target].repository;
        let mut config = OpenOptions::new()
            .append(true)
            .open(identity_repository.join(".git/config"))
            .expect("repository config");
        writeln!(config, "[ag-test]\n\tdrift = true").expect("identity drift");
        config.sync_all().expect("config sync");
        let identity_receipt = identity
            .runtime
            .prepare(context(), &identity_effect, &identity.bundle, 1)
            .expect_err("repository identity drift must refuse");
        expect_precondition_failure(&identity_receipt);
        assert_eq!(managed_ref(&identity), identity.expected_object);

        let base = fixture();
        let base_effect = canonical_effect(&base);
        let base_repository = &base.runtime.targets[&base.target].repository;
        let tree_expression = format!("{}^{{tree}}", base.expected_object);
        let drift_object = output_line(plain_git(&[
            OsStr::new("-C"),
            base_repository.as_os_str(),
            OsStr::new("commit-tree"),
            OsStr::new(&tree_expression),
            OsStr::new("-p"),
            OsStr::new(&base.expected_object),
            OsStr::new("-m"),
            OsStr::new("foreign base drift"),
        ]));
        fs::write(
            base_repository.join(".git/refs/heads/managed"),
            format!("{drift_object}\n"),
        )
        .expect("drift managed ref");
        fs::set_permissions(
            base_repository.join(".git/refs/heads/managed"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("drift reference mode");
        let base_receipt = base
            .runtime
            .prepare(context(), &base_effect, &base.bundle, 1)
            .expect_err("base drift must refuse");
        expect_precondition_failure(&base_receipt);
        assert_eq!(managed_ref(&base), drift_object);
        assert!(!base.sentinel.exists());
    }

    fn genesis_request(
        fixture: &GitFixtureV1,
    ) -> (
        ManagedPointerGenesisRequestV1,
        ManagedPointerGenesisContextV1,
    ) {
        let target = &fixture.runtime.targets[&fixture.target];
        (
            ManagedPointerGenesisRequestV1 {
                schema: MANAGED_POINTER_GENESIS_REQUEST_SCHEMA_V1.to_owned(),
                security_profile: "development".to_owned(),
                target: fixture.target.as_str().to_owned(),
                allowed_root: target.allowed_root.clone(),
                repository: target.repository.clone(),
                reference: target.reference.clone(),
                uid: target.uid,
                gid: target.gid,
                staging_root: target.staging_root.clone(),
                promotion_ttl_ms: target.promotion_ttl_ms,
                helper: PathBuf::from("/usr/bin/git"),
            },
            ManagedPointerGenesisContextV1 {
                authority_domain: "domain:genesis-test".to_owned(),
                epoch: "1".to_owned(),
                effectd_config_template: Digest::hash_bytes(b"effectd template"),
                effectd_database: fixture.directory.path().join("effectd.db"),
                effectd_object_store: fixture.directory.path().join("effectd-objects"),
            },
        )
    }

    #[test]
    fn genesis_measurement_is_read_only_and_directly_derives_exact_target() {
        let fixture = fixture();
        let (request, context) = genesis_request(&fixture);
        let reference = request.repository.join(".git").join(&request.reference);
        let before = fs::metadata(&reference).expect("reference metadata");
        let repository_before = repository_snapshot(&request.repository);
        assert_staging_root_empty(&request.staging_root);
        let measurement =
            measure_managed_pointer_genesis(&request, &context).expect("exact measurement");
        measurement.verify().expect("verified measurement");
        assert_eq!(repository_snapshot(&request.repository), repository_before);
        assert_staging_root_empty(&request.staging_root);
        let after = fs::metadata(&reference).expect("reference metadata after measurement");
        assert_eq!(before.dev(), after.dev());
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.mtime(), after.mtime());
        assert_eq!(before.mtime_nsec(), after.mtime_nsec());
        assert_eq!(
            measurement.activation_genesis_object,
            fixture.expected_object
        );

        let (target, identity) = enroll_managed_pointer_genesis(&request, &context, &measurement)
            .expect("fresh exact enrollment");
        assert_eq!(repository_snapshot(&request.repository), repository_before);
        assert_staging_root_empty(&request.staging_root);
        assert_eq!(
            identity,
            measurement.identity().expect("measurement identity")
        );
        assert!(matches!(
            target,
            EffectTargetConfigV1::ManagedPointer {
                id,
                activation_genesis_object,
                activation_genesis_state,
                repository_identity,
                ..
            } if id == request.target
                && activation_genesis_object == fixture.expected_object
                && activation_genesis_state == measurement.activation_genesis_state
                && repository_identity == measurement.repository_identity
        ));
    }

    #[test]
    fn genesis_enrollment_refuses_same_value_ref_inode_replacement_after_review() {
        let fixture = fixture();
        let (request, context) = genesis_request(&fixture);
        let measurement =
            measure_managed_pointer_genesis(&request, &context).expect("reviewed measurement");
        let reference = request.repository.join(".git").join(&request.reference);
        let replacement = reference.with_extension("ag-genesis-replacement");
        fs::write(&replacement, fs::read(&reference).expect("reference bytes"))
            .expect("replacement reference");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
            .expect("replacement mode");
        fs::rename(&replacement, &reference).expect("replace same-value reference inode");
        let repository_before_refusal = repository_snapshot(&request.repository);
        assert_staging_root_empty(&request.staging_root);

        assert!(matches!(
            enroll_managed_pointer_genesis(&request, &context, &measurement),
            Err(ManagedPointerError::GenesisMeasurementDrift)
        ));
        assert_eq!(
            repository_snapshot(&request.repository),
            repository_before_refusal
        );
        assert_staging_root_empty(&request.staging_root);
        assert_eq!(managed_ref(&fixture), fixture.expected_object);
    }
}
