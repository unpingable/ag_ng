//! Linux effect execution at the broker's narrow authority membrane.
//!
//! This module intentionally has no command runner. Managed pointers are
//! delegated to an independently pinned helper, and systemd operations are
//! delegated to a typed D-Bus capability. Managed files are handled directly
//! through directory file descriptors and Linux `openat2`/`renameat2`. When
//! `openat2` returns `ENOSYS` inside an otherwise admitted sandbox, the same
//! no-symlink traversal is performed one normal component at a time with
//! `openat`.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Component, Path};

use ag_primitives::Digest;
use rustix::fd::OwnedFd;
use rustix::fs::{self, FileType, Gid, Mode, OFlags, RenameFlags, ResolveFlags, Uid};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CanonicalEffectV1, GitObjectFormatV1, MANAGED_POINTER_PROMOTION_SCHEMA_V2, SystemdUnitActionV1,
};

/// Canonical schema emitted for terminal execution receipts.
pub const EXECUTION_RECEIPT_SCHEMA_V1: &str = "ag.effect.execution-receipt/v1";
/// Canonical schema emitted by the authority-neutral Docket executor adapter.
pub const DOCKET_EXECUTION_RECEIPT_SCHEMA_V1: &str =
    "ag.effect.docket-custodied-execution-receipt/v1";

const STAGE_PREFIX: &str = ".ag-stage-";
const QUARANTINE_PREFIX: &str = ".ag-quarantine-";

/// A consumed authorization and durable attempt identity.
///
/// The value is deliberately not `Clone` and is consumed by
/// [`EffectExecutorV1::execute_once`]. The caller must construct it only after
/// durably burning the authorization and reserving `attempt` under a unique
/// store constraint.
#[derive(Debug, Eq, PartialEq)]
pub struct BurnedExecutionPermitV1 {
    proposal: Digest,
    authorization: Digest,
    attempt: Digest,
    effect_index: u32,
    preparation_checkpoint: Option<Digest>,
}

impl BurnedExecutionPermitV1 {
    /// Builds the one-shot value corresponding to an already durable attempt.
    #[must_use]
    pub fn from_durable_burn(
        proposal: Digest,
        authorization: Digest,
        attempt: Digest,
        effect_index: u32,
    ) -> Self {
        Self {
            proposal,
            authorization,
            attempt,
            effect_index,
            preparation_checkpoint: None,
        }
    }

    /// Builds the one-shot commit permit for a promotion whose reversible
    /// preparation checkpoint was durably persisted before commit was armed.
    #[must_use]
    pub fn from_durable_preparation(
        proposal: Digest,
        authorization: Digest,
        attempt: Digest,
        effect_index: u32,
        preparation_checkpoint: Digest,
    ) -> Self {
        Self {
            proposal,
            authorization,
            attempt,
            effect_index,
            preparation_checkpoint: Some(preparation_checkpoint),
        }
    }
}

/// One exact Docket-custodied physical attempt.
///
/// This consuming value is mechanics-only.  `executor_marker` is neither an
/// AG decision authorization nor Docket execution standing, and this value
/// exposes no campaign transition operation.
#[derive(Debug, Eq, PartialEq)]
pub struct DocketCustodiedExecutionPermitV1 {
    work: Digest,
    executor_marker: Digest,
    attempt: Digest,
    effect_index: u32,
    preparation_checkpoint: Option<Digest>,
}

impl DocketCustodiedExecutionPermitV1 {
    /// Constructs the consuming mechanics permit for an already durable
    /// Docket attempt and executor-local idempotency marker.
    #[must_use]
    pub fn from_docket_custody(
        work: Digest,
        executor_marker: Digest,
        attempt: Digest,
        effect_index: u32,
    ) -> Self {
        Self {
            work,
            executor_marker,
            attempt,
            effect_index,
            preparation_checkpoint: None,
        }
    }

    /// Constructs the consuming mechanics permit for an already prepared
    /// managed-pointer attempt.
    #[must_use]
    pub fn from_docket_preparation(
        work: Digest,
        executor_marker: Digest,
        attempt: Digest,
        effect_index: u32,
        preparation_checkpoint: Digest,
    ) -> Self {
        Self {
            work,
            executor_marker,
            attempt,
            effect_index,
            preparation_checkpoint: Some(preparation_checkpoint),
        }
    }
}

trait ExecutionCoordinatesV1 {
    fn attempt(&self) -> &Digest;
    fn effect_index(&self) -> u32;
    fn preparation_checkpoint(&self) -> Option<&Digest>;
}

impl ExecutionCoordinatesV1 for BurnedExecutionPermitV1 {
    fn attempt(&self) -> &Digest {
        &self.attempt
    }

    fn effect_index(&self) -> u32 {
        self.effect_index
    }

    fn preparation_checkpoint(&self) -> Option<&Digest> {
        self.preparation_checkpoint.as_ref()
    }
}

impl ExecutionCoordinatesV1 for DocketCustodiedExecutionPermitV1 {
    fn attempt(&self) -> &Digest {
        &self.attempt
    }

    fn effect_index(&self) -> u32 {
        self.effect_index
    }

    fn preparation_checkpoint(&self) -> Option<&Digest> {
        self.preparation_checkpoint.as_ref()
    }
}

/// File-executor limits and trust requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedFilePolicyV1 {
    /// Maximum admitted or existing managed-file size.
    pub max_content_bytes: u64,
    /// Required numeric owner of stable path ancestors such as `/` and `/tmp`.
    pub trusted_ancestor_uid: u32,
    /// Required numeric owner of the final parent directory.
    pub trusted_parent_uid: u32,
    /// Reject group- or world-writable final parent directories.
    pub require_private_parent_writes: bool,
}

impl Default for ManagedFilePolicyV1 {
    fn default() -> Self {
        Self {
            max_content_bytes: 64 * 1024 * 1024,
            trusted_ancestor_uid: 0,
            trusted_parent_uid: 0,
            require_private_parent_writes: true,
        }
    }
}

/// Content-addressed artifact custody available to the effect broker.
pub trait ArtifactSourceV1: Send + Sync {
    /// Loads exact admitted bytes. The source must not interpret the bytes as a
    /// path, command, or template.
    ///
    /// # Errors
    ///
    /// Returns a typed custody error when exact bytes are unavailable.
    fn load(&self, digest: &Digest) -> Result<Vec<u8>, ArtifactReadErrorV1>;
}

/// A typed custody-read failure that occurs before an effect can begin.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[error("artifact read failed ({code}): {detail}")]
#[serde(deny_unknown_fields)]
pub struct ArtifactReadErrorV1 {
    /// Stable implementation-specific error code.
    pub code: String,
    /// Sanitized diagnostic.
    pub detail: String,
}

impl ArtifactReadErrorV1 {
    /// Creates a sanitized artifact-read error.
    #[must_use]
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

/// Result envelope used by effect capabilities with an external commit point.
///
/// `Failed` is a contractual assertion that no requested effect occurred.
/// Anything else must be returned as `Indeterminate`; callers never infer a
/// semantic failure from a transport error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityOutcomeV1<T> {
    /// The typed operation completed.
    Succeeded(T),
    /// The capability knows that no effect occurred.
    Failed(CapabilityFailureV1),
    /// The capability cannot prove whether the effect occurred.
    Indeterminate(CapabilityIndeterminateV1),
}

/// Known, no-effect failure from a pinned capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFailureV1 {
    /// Stable backend error code.
    pub code: String,
    /// Sanitized diagnostic.
    pub detail: String,
    /// Optional backend evidence in broker custody.
    pub evidence: Option<Digest>,
}

/// Unknown external effect outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityIndeterminateV1 {
    /// Stable backend envelope code.
    pub code: String,
    /// Sanitized diagnostic.
    pub detail: String,
    /// Optional backend evidence in broker custody.
    pub evidence: Option<Digest>,
}

/// The exact pinned-helper identities observed before invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedHelperIdentityV1 {
    /// Digest of the opened executable bytes, not its path.
    pub executable: Digest,
    /// Digest of the exact argv/environment/descriptor/sandbox profile.
    pub launch_profile: Digest,
}

/// Exact reversible preparation request understood by the managed-pointer helper.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerPreparationRequestV1 {
    /// Exact managed-promotion schema.
    pub schema: String,
    /// Broker-derived single-use operation identity.
    pub operation_id: Digest,
    /// Descriptor-opened allowed target root.
    pub allowed_root: String,
    /// Repository path beneath the allowed root.
    pub repository: String,
    /// Exact non-checked-out managed ref.
    pub reference: String,
    /// Expected repository configuration/object-format identity.
    pub repository_identity: Digest,
    /// Expected repository device.
    pub repository_device: u64,
    /// Expected repository inode.
    pub repository_inode: u64,
    /// Expected Git-directory device.
    pub git_directory_device: u64,
    /// Expected Git-directory inode.
    pub git_directory_inode: u64,
    /// Target owner UID under which mutation is permitted.
    pub uid: u32,
    /// Target owner GID under which mutation is permitted.
    pub gid: u32,
    /// Broker-owned staging root outside the repository.
    pub staging_root: String,
    /// Exact admitted candidate bundle.
    pub artifact: Digest,
    /// Exact normalized candidate pack.
    pub candidate_pack_digest: Digest,
    /// Closed Git object format.
    pub object_format: GitObjectFormatV1,
    /// Expected current commit.
    pub expected_object: String,
    /// Expected current tree.
    pub expected_tree: String,
    /// Candidate commit to install.
    pub new_object: String,
    /// Expected tree reached by the candidate commit.
    pub expected_post_tree: String,
    /// Exclusive broker-clock expiry.
    pub expires_unix_ms: u64,
}

/// Exact helper evidence returned after reversible preparation and object import.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerPreparationSuccessV1 {
    /// Digest of the complete canonical preparation request.
    pub request_digest: Digest,
    /// Exact operation prepared.
    pub operation_id: Digest,
    /// Candidate artifact consumed.
    pub artifact: Digest,
    /// Normalized candidate pack imported under target-owner custody.
    pub candidate_pack_digest: Digest,
    /// Current commit revalidated before preparation.
    pub current_object: String,
    /// Current tree revalidated before preparation.
    pub current_tree: String,
    /// Candidate commit proven present after object import.
    pub candidate_object: String,
    /// Candidate tree proven present after object import.
    pub candidate_tree: String,
    /// Durable checkpoint that must be burned before ref CAS.
    pub preparation_checkpoint: Digest,
    /// Exact object-import evidence retained by the broker.
    pub evidence: Digest,
}

/// Exact request understood by the managed-pointer commit helper.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerCasRequestV1 {
    /// Exact managed-promotion schema.
    pub schema: String,
    /// Broker-derived single-use operation identity.
    pub operation_id: Digest,
    /// Durable reversible-preparation checkpoint.
    pub preparation_checkpoint: Digest,
    /// Descriptor-opened allowed target root.
    pub allowed_root: String,
    /// Canonically resolved repository beneath the allowed root.
    pub repository: String,
    /// Exact reference name.
    pub reference: String,
    /// Expected repository/object-format identity.
    pub repository_identity: Digest,
    /// Exact descriptor-bound repository layout and prestate identity.
    pub prestate_identity: Digest,
    /// Expected repository device.
    pub repository_device: u64,
    /// Expected repository inode.
    pub repository_inode: u64,
    /// Expected Git-directory device.
    pub git_directory_device: u64,
    /// Expected Git-directory inode.
    pub git_directory_inode: u64,
    /// Target owner UID under which mutation is permitted.
    pub uid: u32,
    /// Target owner GID under which mutation is permitted.
    pub gid: u32,
    /// Broker-owned staging root containing the prepared operation.
    pub staging_root: String,
    /// Exact admitted candidate bundle.
    pub artifact: Digest,
    /// Exact normalized candidate pack.
    pub candidate_pack_digest: Digest,
    /// Closed Git object format.
    pub object_format: GitObjectFormatV1,
    /// Expected current commit.
    pub expected_object: String,
    /// Expected current tree.
    pub expected_tree: String,
    /// Exact candidate commit.
    pub new_object: String,
    /// Expected tree reached by the candidate commit.
    pub expected_post_tree: String,
    /// Exclusive broker-clock expiry.
    pub expires_unix_ms: u64,
}

/// Helper evidence after a successful pointer compare-and-swap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerCasSuccessV1 {
    /// Digest of the complete canonical compare-and-swap request.
    pub request_digest: Digest,
    /// Exact operation which crossed the ref boundary.
    pub operation_id: Digest,
    /// Durable preparation checkpoint consumed by the helper.
    pub preparation_checkpoint: Digest,
    /// Repository identity actually checked by the helper.
    pub repository_identity: Digest,
    /// Repository layout and prestate identity actually checked by the helper.
    pub prestate_identity: Digest,
    /// Repository device checked by the helper.
    pub repository_device: u64,
    /// Repository inode checked by the helper.
    pub repository_inode: u64,
    /// Git-directory device checked by the helper.
    pub git_directory_device: u64,
    /// Git-directory inode checked by the helper.
    pub git_directory_inode: u64,
    /// Exact candidate pack consumed by the operation.
    pub candidate_pack_digest: Digest,
    /// Old object actually compared by the helper.
    pub previous_object: String,
    /// Old tree independently observed by the helper.
    pub previous_tree: String,
    /// New object actually installed by the helper.
    pub installed_object: String,
    /// New tree independently observed after ref CAS.
    pub installed_tree: String,
    /// Durable ref-CAS evidence in broker custody.
    pub evidence: Digest,
    /// Independent poststate-read evidence in broker custody.
    pub poststate_evidence: Digest,
}

/// Independently pinned, closed managed-pointer capability.
pub trait PinnedPointerHelperV1: Send + Sync {
    /// Opens and hashes the exact helper executable and launch profile without
    /// invoking it.
    fn identity(&self) -> CapabilityOutcomeV1<PinnedHelperIdentityV1>;

    /// Stages and imports only the exact candidate objects while the managed
    /// ref remains unchanged. Candidate bytes arrive through this typed call,
    /// never through a pathname, environment, or argv field.
    fn prepare(
        &self,
        request: &PointerPreparationRequestV1,
        artifact: &[u8],
    ) -> CapabilityOutcomeV1<PointerPreparationSuccessV1>;

    /// Performs exactly one Git-reference compare-and-swap. No arbitrary argv,
    /// environment, command, ref glob, or repository discovery is accepted.
    fn compare_and_swap(
        &self,
        request: &PointerCasRequestV1,
    ) -> CapabilityOutcomeV1<PointerCasSuccessV1>;
}

/// Exact systemd state checked immediately before a unit operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitRequestV1 {
    /// Exact escaped unit name from the root-owned target catalog.
    pub unit: String,
    /// Closed D-Bus operation.
    pub action: SystemdUnitActionV1,
    /// Expected `ActiveState`.
    pub expected_active_state: String,
    /// Expected `UnitFileState`.
    pub expected_unit_file_state: String,
}

/// Successful typed systemd unit operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitSuccessV1 {
    /// Exact unit whose properties were checked and operation was invoked.
    pub unit: String,
    /// Exact closed operation accepted by the backend.
    pub action: SystemdUnitActionV1,
    /// `ActiveState` observed immediately before the operation.
    pub previous_active_state: String,
    /// `UnitFileState` observed immediately before the operation.
    pub previous_unit_file_state: String,
    /// `ActiveState` observed after the D-Bus operation was accepted.
    pub resulting_active_state: String,
    /// `UnitFileState` observed after the operation was accepted.
    pub resulting_unit_file_state: String,
    /// D-Bus transaction/job receipt in broker custody.
    pub evidence: Digest,
}

/// Exact systemd manager-reload request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdManagerReloadRequestV1 {
    /// Expected local D-Bus machine identity.
    pub machine_identity: String,
    /// Expected broker-observed manager generation.
    pub expected_generation: u64,
}

/// Successful systemd manager reload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdManagerReloadSuccessV1 {
    /// Machine identity checked by the backend.
    pub machine_identity: String,
    /// Generation observed after reload completion.
    pub resulting_generation: u64,
    /// D-Bus transaction receipt in broker custody.
    pub evidence: Digest,
}

/// Closed systemd capability. Implementations speak D-Bus directly; this API
/// deliberately cannot carry shell text, `systemctl` argv, or arbitrary method
/// names.
pub trait SystemdDbusBackendV1: Send + Sync {
    /// Performs one typed unit action after checking both expected properties.
    fn unit_action(
        &self,
        request: &SystemdUnitRequestV1,
    ) -> CapabilityOutcomeV1<SystemdUnitSuccessV1>;

    /// Reloads the local manager after checking machine and generation.
    fn reload_manager(
        &self,
        request: &SystemdManagerReloadRequestV1,
    ) -> CapabilityOutcomeV1<SystemdManagerReloadSuccessV1>;
}

/// Terminal receipt body returned for every execution attempt accepted by the
/// executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceiptV1 {
    /// Receipt schema.
    pub schema: String,
    /// Exact canonical proposal whose authorization was burned.
    pub proposal: Digest,
    /// Exact burned authorization record.
    pub authorization: Digest,
    /// Store-unique attempt identity.
    pub attempt: Digest,
    /// Effect position in canonical execution order.
    pub effect_index: u32,
    /// Exact canonical effect consumed by this attempt.
    pub effect: CanonicalEffectV1,
    /// Terminal result; callers must not reinterpret one class as another.
    pub outcome: ExecutionOutcomeV1,
}

/// Exact terminal mechanics receipt for a Docket-custodied attempt.
///
/// No field in this record is campaign authority.  In particular, the
/// executor marker is only the adapter's idempotency identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketEffectExecutionReceiptV1 {
    /// Receipt schema.
    pub schema: String,
    /// Exact Docket-bound work identity.
    pub work: Digest,
    /// Executor-local idempotency marker for the exact Docket attempt.
    pub executor_marker: Digest,
    /// Docket-owned execution-attempt identity.
    pub attempt: Digest,
    /// Effect position in the exact work plan.
    pub effect_index: u32,
    /// Exact canonical effect consumed by this attempt.
    pub effect: CanonicalEffectV1,
    /// Terminal result; callers must not reinterpret one class as another.
    pub outcome: ExecutionOutcomeV1,
}

impl DocketEffectExecutionReceiptV1 {
    /// Computes the identity of the exact canonical receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt cannot be represented as canonical JCS.
    pub fn digest(&self) -> Result<Digest, ExecutionReceiptError> {
        Digest::from_serializable(self)
            .map_err(|error| ExecutionReceiptError::Canonical(error.to_string()))
    }

    /// Verifies exact work/marker/attempt/effect bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionReceiptError::BindingMismatch`] for any substitution.
    pub fn verify_bindings(
        &self,
        work: &Digest,
        executor_marker: &Digest,
        attempt: &Digest,
        effect_index: u32,
        effect: &CanonicalEffectV1,
    ) -> Result<(), ExecutionReceiptError> {
        if self.schema != DOCKET_EXECUTION_RECEIPT_SCHEMA_V1
            || &self.work != work
            || &self.executor_marker != executor_marker
            || &self.attempt != attempt
            || self.effect_index != effect_index
            || &self.effect != effect
        {
            return Err(ExecutionReceiptError::BindingMismatch);
        }
        Ok(())
    }
}

impl ExecutionReceiptV1 {
    /// Computes the digest of the exact canonical receipt bytes for durable
    /// event-store installation.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt cannot be represented as canonical JCS.
    pub fn digest(&self) -> Result<Digest, ExecutionReceiptError> {
        Digest::from_serializable(self)
            .map_err(|error| ExecutionReceiptError::Canonical(error.to_string()))
    }

    /// Verifies that a runner returned a receipt for the exact permit and
    /// canonical effect it was asked to consume.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionReceiptError::BindingMismatch`] if any schema,
    /// proposal, authorization, attempt, index, or effect field differs.
    pub fn verify_bindings(
        &self,
        proposal: &Digest,
        authorization: &Digest,
        attempt: &Digest,
        effect_index: u32,
        effect: &CanonicalEffectV1,
    ) -> Result<(), ExecutionReceiptError> {
        if self.schema != EXECUTION_RECEIPT_SCHEMA_V1
            || &self.proposal != proposal
            || &self.authorization != authorization
            || &self.attempt != attempt
            || self.effect_index != effect_index
            || &self.effect != effect
        {
            return Err(ExecutionReceiptError::BindingMismatch);
        }
        Ok(())
    }
}

/// Receipt canonicalization error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExecutionReceiptError {
    /// Receipt could not be represented as JCS.
    #[error("execution receipt canonicalization failed: {0}")]
    Canonical(String),
    /// Runner returned a receipt for a different authority/effect context.
    #[error("execution receipt does not bind the exact execution permit")]
    BindingMismatch,
}

/// Strictly separated terminal execution classes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionOutcomeV1 {
    /// The effect and its durability boundary completed.
    Succeeded {
        /// Effect-specific durable evidence.
        success: EffectSuccessV1,
    },
    /// A known failure occurred before any requested effect.
    Failed {
        /// Typed no-effect failure.
        failure: ExecutionFailureV1,
    },
    /// An external commit point may have been crossed.
    Indeterminate {
        /// Typed reconciliation envelope.
        envelope: ExecutionIndeterminateV1,
    },
}

/// Effect-specific success evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectSuccessV1 {
    /// Atomic managed-file create or replacement.
    ManagedFilePut {
        /// Content observed before the atomic operation.
        previous_content: Option<Digest>,
        /// Exact installed content.
        installed_content: Digest,
        /// Recoverable old entry retained after replacement.
        quarantine_name: Option<String>,
        /// Confirms the file was synced before rename.
        content_fsynced: bool,
        /// Confirms the parent directory was synced after rename/quarantine.
        directory_fsynced: bool,
    },
    /// Managed-file entry moved atomically into quarantine.
    ManagedFileDelete {
        /// Exact removed content.
        previous_content: Digest,
        /// Recoverable quarantine entry.
        quarantine_name: String,
        /// Confirms the parent directory was synced after rename.
        directory_fsynced: bool,
    },
    /// Managed-pointer helper compare-and-swap.
    ManagedPointerPromotion {
        /// Broker-derived operation identity.
        operation_id: Digest,
        /// Exact normalized candidate pack.
        candidate_pack_digest: Digest,
        /// Durable preparation checkpoint consumed before CAS.
        preparation_checkpoint: Digest,
        /// Previous pointer value.
        previous_object: String,
        /// Previous tree value.
        previous_tree: String,
        /// Installed pointer value.
        installed_object: String,
        /// Installed tree value.
        installed_tree: String,
        /// Durable helper CAS receipt.
        evidence: Digest,
        /// Independent poststate observation receipt.
        poststate_evidence: Digest,
    },
    /// Typed systemd unit operation.
    SystemdUnit {
        /// Resulting active state.
        resulting_active_state: String,
        /// Resulting unit-file state.
        resulting_unit_file_state: String,
        /// D-Bus receipt.
        evidence: Digest,
    },
    /// Typed systemd manager reload.
    SystemdManagerReload {
        /// Resulting manager generation.
        resulting_generation: u64,
        /// D-Bus receipt.
        evidence: Digest,
    },
}

/// Known no-effect failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFailureV1 {
    /// Stable closed failure family.
    pub code: ExecutionFailureCodeV1,
    /// Last phase known not to have crossed the effect commit point.
    pub phase: ExecutionPhaseV1,
    /// Sanitized diagnostic.
    pub detail: String,
    /// Lossless native capability/custody code, when the failure came from an
    /// injected boundary.
    pub source_code: Option<String>,
    /// Optional evidence in broker custody.
    pub evidence: Option<Digest>,
}

/// Closed no-effect failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionFailureCodeV1 {
    /// Custody bytes could not be loaded.
    ArtifactUnavailable,
    /// Custody bytes did not match their admitted digest.
    ArtifactDigestMismatch,
    /// Catalog path did not meet the executor's exact path grammar.
    InvalidManagedPath,
    /// Target or trusted parent was a symlink, non-regular, or unsafe object.
    UnsafeTarget,
    /// Broker execution observation differs from ratified prestate.
    PrestateDrift,
    /// Catalogued ownership or mode is invalid or could not be installed.
    MetadataRejected,
    /// Pinned helper could not be identified without invoking it.
    HelperUnavailable,
    /// Exact executable bytes or launch profile differ from the proposal.
    HelperIdentityMismatch,
    /// The closed backend refused before making the effect.
    BackendRejected,
    /// Local I/O failed before the atomic commit point.
    LocalIoBeforeCommit,
}

/// Unknown-outcome reconciliation envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIndeterminateV1 {
    /// Stable uncertainty family.
    pub code: ExecutionIndeterminateCodeV1,
    /// Last execution phase reached.
    pub phase: ExecutionPhaseV1,
    /// Sanitized diagnostic.
    pub detail: String,
    /// Lossless native capability code, when uncertainty came from an injected
    /// boundary.
    pub source_code: Option<String>,
    /// Optional backend evidence.
    pub evidence: Option<Digest>,
}

/// Closed uncertainty categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionIndeterminateCodeV1 {
    /// A backend transport or job boundary could not establish an outcome.
    BackendOutcomeUnknown,
    /// A successful backend response contradicted its typed request.
    BackendContractViolation,
    /// An atomic filesystem mutation occurred but its directory sync failed.
    DurabilityAfterCommit,
    /// A race was detected after mutation and rollback could not be proven.
    RollbackUnproven,
}

/// Execution phases suitable for audit and reconciliation routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhaseV1 {
    /// Broker validation of the runner's returned receipt bindings.
    ReceiptValidation,
    /// Artifact custody read.
    ArtifactLoad,
    /// Trusted parent resolution.
    ParentResolution,
    /// Immediate target-prestate validation.
    PrestateCheck,
    /// Staging content under broker-only ownership and permissions.
    Staging,
    /// Reversible managed-pointer bundle validation and staging.
    PromotionPreparation,
    /// Import of immutable candidate objects before the managed ref is armed.
    PromotionObjectImport,
    /// Atomic rename or compare-and-swap.
    Commit,
    /// Transfer of a committed managed file to its final owner and mode.
    MetadataTransfer,
    /// Old entry quarantine.
    Quarantine,
    /// Filesystem durability barrier.
    DirectorySync,
    /// Helper executable/profile verification.
    HelperIdentity,
    /// Managed-pointer helper invocation.
    PointerCas,
    /// Independent managed-pointer ref and tree verification after CAS.
    PromotionPoststateVerification,
    /// Typed systemd D-Bus operation.
    SystemdDbus,
}

/// Closed executor. It exposes one consuming execution operation and no retry
/// method, command runner, shell, or arbitrary backend dispatch.
pub struct EffectExecutorV1<'a> {
    artifacts: &'a dyn ArtifactSourceV1,
    pointer_helper: &'a dyn PinnedPointerHelperV1,
    systemd: &'a dyn SystemdDbusBackendV1,
    file_policy: ManagedFilePolicyV1,
    #[cfg(test)]
    managed_file_post_transfer_hook: Option<&'a dyn Fn(&str)>,
}

impl<'a> EffectExecutorV1<'a> {
    /// Constructs a broker executor from its three narrow capabilities.
    #[must_use]
    pub fn new(
        artifacts: &'a dyn ArtifactSourceV1,
        pointer_helper: &'a dyn PinnedPointerHelperV1,
        systemd: &'a dyn SystemdDbusBackendV1,
        file_policy: ManagedFilePolicyV1,
    ) -> Self {
        Self {
            artifacts,
            pointer_helper,
            systemd,
            file_policy,
            #[cfg(test)]
            managed_file_post_transfer_hook: None,
        }
    }

    #[cfg(test)]
    fn with_managed_file_post_transfer_hook(mut self, hook: &'a dyn Fn(&str)) -> Self {
        self.managed_file_post_transfer_hook = Some(hook);
        self
    }

    /// Performs only the reversible preparation portion of one canonical
    /// managed-pointer effect. The returned checkpoint is data until the
    /// broker durably transitions `Preparing` through `CommitMayProceed`.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn prepare_pointer(
        &self,
        effect: &CanonicalEffectV1,
    ) -> CapabilityOutcomeV1<PointerPreparationSuccessV1> {
        let CanonicalEffectV1::ManagedPointerPromotion {
            schema,
            operation_id,
            allowed_root,
            repository,
            reference,
            repository_identity,
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
            ..
        } = effect
        else {
            return CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
                code: "not_managed_pointer_promotion".to_owned(),
                detail: "promotion preparation received another effect family".to_owned(),
                evidence: None,
            });
        };
        if schema != MANAGED_POINTER_PROMOTION_SCHEMA_V2 {
            return CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
                code: "promotion_schema_mismatch".to_owned(),
                detail: "canonical effect names an unsupported promotion contract".to_owned(),
                evidence: None,
            });
        }

        let bytes = match self.artifacts.load(artifact) {
            Ok(bytes) => bytes,
            Err(error) => {
                return CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
                    code: error.code,
                    detail: error.detail,
                    evidence: None,
                });
            }
        };
        if Digest::hash_bytes(&bytes) != *artifact {
            return CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
                code: "artifact_digest_mismatch".to_owned(),
                detail: "artifact source returned bytes outside canonical custody".to_owned(),
                evidence: None,
            });
        }
        match self.pointer_helper.identity() {
            CapabilityOutcomeV1::Succeeded(identity)
                if identity.executable == *helper_executable
                    && identity.launch_profile == *helper_launch_profile => {}
            CapabilityOutcomeV1::Succeeded(_) => {
                return CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
                    code: "helper_identity_mismatch".to_owned(),
                    detail: "opened helper bytes or profile differ from canonical proposal"
                        .to_owned(),
                    evidence: None,
                });
            }
            CapabilityOutcomeV1::Failed(error) => return CapabilityOutcomeV1::Failed(error),
            CapabilityOutcomeV1::Indeterminate(error) => {
                return CapabilityOutcomeV1::Indeterminate(error);
            }
        }

        let request = PointerPreparationRequestV1 {
            schema: schema.clone(),
            operation_id: operation_id.clone(),
            allowed_root: allowed_root.clone(),
            repository: repository.clone(),
            reference: reference.clone(),
            repository_identity: repository_identity.clone(),
            repository_device: *repository_device,
            repository_inode: *repository_inode,
            git_directory_device: *git_directory_device,
            git_directory_inode: *git_directory_inode,
            uid: *uid,
            gid: *gid,
            staging_root: staging_root.clone(),
            artifact: artifact.clone(),
            candidate_pack_digest: candidate_pack_digest.clone(),
            object_format: *object_format,
            expected_object: expected_object.clone(),
            expected_tree: expected_tree.clone(),
            new_object: new_object.clone(),
            expected_post_tree: expected_post_tree.clone(),
            expires_unix_ms: *expires_unix_ms,
        };
        let request_digest = match Digest::from_serializable(&request) {
            Ok(digest) => digest,
            Err(error) => {
                return CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
                    code: "preparation_request_canonicalization_failed".to_owned(),
                    detail: error.to_string(),
                    evidence: None,
                });
            }
        };
        match self.pointer_helper.prepare(&request, &bytes) {
            CapabilityOutcomeV1::Succeeded(result)
                if result.request_digest == request_digest
                    && result.operation_id == *operation_id
                    && result.artifact == *artifact
                    && result.candidate_pack_digest == *candidate_pack_digest
                    && result.current_object == *expected_object
                    && result.current_tree == *expected_tree
                    && result.candidate_object == *new_object
                    && result.candidate_tree == *expected_post_tree =>
            {
                CapabilityOutcomeV1::Succeeded(result)
            }
            CapabilityOutcomeV1::Succeeded(result) => {
                CapabilityOutcomeV1::Indeterminate(CapabilityIndeterminateV1 {
                    code: "preparation_contract_violation".to_owned(),
                    detail: "helper preparation evidence contradicts canonical promotion"
                        .to_owned(),
                    evidence: Some(result.evidence),
                })
            }
            CapabilityOutcomeV1::Failed(error) => CapabilityOutcomeV1::Failed(error),
            CapabilityOutcomeV1::Indeterminate(error) => CapabilityOutcomeV1::Indeterminate(error),
        }
    }

    /// Consumes one already-burned permit and returns a terminal typed receipt.
    /// There is no automatic retry path. An indeterminate receipt requires
    /// reconciliation, never reinvocation.
    #[must_use]
    pub fn execute_once(
        &self,
        permit: BurnedExecutionPermitV1,
        effect: &CanonicalEffectV1,
    ) -> ExecutionReceiptV1 {
        let outcome = self.execute_permitted(&permit, effect);
        ExecutionReceiptV1 {
            schema: EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
            proposal: permit.proposal,
            authorization: permit.authorization,
            attempt: permit.attempt,
            effect_index: permit.effect_index,
            effect: effect.clone(),
            outcome,
        }
    }

    /// Executes one exact effect as mechanics for an already Docket-custodied
    /// attempt.  The returned receipt carries no campaign authority.
    #[must_use]
    pub fn execute_docket_custodied_once(
        &self,
        permit: DocketCustodiedExecutionPermitV1,
        effect: &CanonicalEffectV1,
    ) -> DocketEffectExecutionReceiptV1 {
        let outcome = self.execute_permitted(&permit, effect);
        DocketEffectExecutionReceiptV1 {
            schema: DOCKET_EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
            work: permit.work,
            executor_marker: permit.executor_marker,
            attempt: permit.attempt,
            effect_index: permit.effect_index,
            effect: effect.clone(),
            outcome,
        }
    }

    fn execute_permitted(
        &self,
        permit: &impl ExecutionCoordinatesV1,
        effect: &CanonicalEffectV1,
    ) -> ExecutionOutcomeV1 {
        let promotion = matches!(effect, CanonicalEffectV1::ManagedPointerPromotion { .. });
        let checkpoint_binding_valid = promotion == permit.preparation_checkpoint().is_some();
        if checkpoint_binding_valid {
            match effect {
                CanonicalEffectV1::ManagedFilePut {
                    path,
                    expected_content,
                    content,
                    mode,
                    uid,
                    gid,
                    ..
                } => self.execute_file_put(
                    permit,
                    path,
                    expected_content.as_ref(),
                    content,
                    *mode,
                    *uid,
                    *gid,
                ),
                CanonicalEffectV1::ManagedFileDelete {
                    path,
                    expected_content,
                    ..
                } => self.execute_file_delete(permit, path, expected_content),
                CanonicalEffectV1::ManagedPointerPromotion { .. } => {
                    self.execute_pointer(permit, effect)
                }
                CanonicalEffectV1::SystemdUnit {
                    unit,
                    action,
                    expected_active_state,
                    expected_unit_file_state,
                    ..
                } => self.execute_systemd_unit(
                    unit,
                    *action,
                    expected_active_state,
                    expected_unit_file_state,
                ),
                CanonicalEffectV1::SystemdManagerReload {
                    machine_identity,
                    expected_generation,
                    ..
                } => self.execute_systemd_manager(machine_identity, *expected_generation),
            }
        } else {
            failure(
                ExecutionFailureCodeV1::BackendRejected,
                ExecutionPhaseV1::ReceiptValidation,
                "execution permit preparation checkpoint does not match effect family",
                None,
            )
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn execute_file_put(
        &self,
        permit: &impl ExecutionCoordinatesV1,
        path: &str,
        expected_content: Option<&Digest>,
        desired_content: &Digest,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> ExecutionOutcomeV1 {
        let bytes = match self.artifacts.load(desired_content) {
            Ok(bytes) => bytes,
            Err(error) => {
                return failure_with_source(
                    ExecutionFailureCodeV1::ArtifactUnavailable,
                    ExecutionPhaseV1::ArtifactLoad,
                    error.detail,
                    Some(error.code),
                    None,
                );
            }
        };
        if u64::try_from(bytes.len())
            .map_or(true, |length| length > self.file_policy.max_content_bytes)
        {
            return failure(
                ExecutionFailureCodeV1::ArtifactUnavailable,
                ExecutionPhaseV1::ArtifactLoad,
                "admitted content exceeds the managed-file limit",
                None,
            );
        }
        if Digest::hash_bytes(&bytes) != *desired_content {
            return failure(
                ExecutionFailureCodeV1::ArtifactDigestMismatch,
                ExecutionPhaseV1::ArtifactLoad,
                "artifact source returned bytes with a different digest",
                None,
            );
        }

        let (parent, name) = match secure_parent(path, self.file_policy) {
            Ok(value) => value,
            Err(error) => return error.into_outcome(),
        };
        let observed =
            match observe_entry(&parent, name.as_str(), self.file_policy.max_content_bytes) {
                Ok(value) => value,
                Err(error) => return error.into_outcome(),
            };
        if observed.as_ref().map(|value| &value.digest) != expected_content {
            return failure(
                ExecutionFailureCodeV1::PrestateDrift,
                ExecutionPhaseV1::PrestateCheck,
                "managed-file content differs from the ratified prestate",
                None,
            );
        }

        if mode & !0o0777 != 0 || uid == u32::MAX || gid == u32::MAX {
            return failure(
                ExecutionFailureCodeV1::MetadataRejected,
                ExecutionPhaseV1::Staging,
                "catalogued mode includes special bits or uid/gid is outside the accepted range",
                None,
            );
        }

        let names = InternalNames::new(permit);
        if let Err(error) = ensure_internal_names_absent(&parent, &names) {
            return error.into_outcome();
        }
        let staged = match stage_content(
            &parent,
            &names.stage,
            &bytes,
            desired_content,
            self.file_policy.max_content_bytes,
        ) {
            Ok(staged) => staged,
            Err(error) => return error.into_outcome(),
        };

        if expected_content.is_none() {
            match fs::renameat_with(
                &parent,
                names.stage.as_str(),
                &parent,
                name.as_str(),
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {}
                Err(Errno::EXIST | Errno::NOENT) => {
                    let cleanup =
                        fs::unlinkat(&parent, names.stage.as_str(), rustix::fs::AtFlags::empty());
                    return if cleanup.is_ok() {
                        failure(
                            ExecutionFailureCodeV1::PrestateDrift,
                            ExecutionPhaseV1::Commit,
                            "target appeared during atomic create",
                            None,
                        )
                    } else {
                        indeterminate(
                            ExecutionIndeterminateCodeV1::RollbackUnproven,
                            ExecutionPhaseV1::Commit,
                            "atomic create did not commit, but staging cleanup failed",
                            None,
                        )
                    };
                }
                Err(error) => {
                    let _ =
                        fs::unlinkat(&parent, names.stage.as_str(), rustix::fs::AtFlags::empty());
                    return failure(
                        ExecutionFailureCodeV1::LocalIoBeforeCommit,
                        ExecutionPhaseV1::Commit,
                        error.to_string(),
                        None,
                    );
                }
            }
            if let Err(outcome) = self.finalize_committed_file(
                &staged,
                &parent,
                name.as_str(),
                path,
                FileMetadata { uid, gid, mode },
            ) {
                return outcome;
            }
            return success(EffectSuccessV1::ManagedFilePut {
                previous_content: None,
                installed_content: desired_content.clone(),
                quarantine_name: None,
                content_fsynced: true,
                directory_fsynced: true,
            });
        }

        if let Err(error) = fs::renameat_with(
            &parent,
            names.stage.as_str(),
            &parent,
            name.as_str(),
            RenameFlags::EXCHANGE,
        ) {
            let _ = fs::unlinkat(&parent, names.stage.as_str(), rustix::fs::AtFlags::empty());
            return failure(
                if matches!(error, Errno::NOENT) {
                    ExecutionFailureCodeV1::PrestateDrift
                } else {
                    ExecutionFailureCodeV1::LocalIoBeforeCommit
                },
                ExecutionPhaseV1::Commit,
                error.to_string(),
                None,
            );
        }

        if let Err(reason) = verify_named_staged_file(
            &staged,
            &parent,
            name.as_str(),
            FileMetadata {
                uid: staged.broker_uid,
                gid: staged.broker_gid,
                mode: 0o600,
            },
        ) {
            return rollback_exchange(
                &parent,
                name.as_str(),
                names.stage.as_str(),
                format!("committed staging inode failed exact verification: {reason}").as_str(),
            );
        }

        let displaced = observe_entry(
            &parent,
            names.stage.as_str(),
            self.file_policy.max_content_bytes,
        );
        if displaced
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .map(|value| &value.digest)
            != expected_content
        {
            return rollback_exchange(
                &parent,
                name.as_str(),
                names.stage.as_str(),
                "entry changed during atomic replacement",
            );
        }

        if let Err(error) = fs::renameat_with(
            &parent,
            names.stage.as_str(),
            &parent,
            names.quarantine.as_str(),
            RenameFlags::NOREPLACE,
        ) {
            return indeterminate(
                ExecutionIndeterminateCodeV1::RollbackUnproven,
                ExecutionPhaseV1::Quarantine,
                format!("replacement committed but quarantine rename failed: {error}"),
                None,
            );
        }
        if let Err(outcome) = self.finalize_committed_file(
            &staged,
            &parent,
            name.as_str(),
            path,
            FileMetadata { uid, gid, mode },
        ) {
            return outcome;
        }
        success(EffectSuccessV1::ManagedFilePut {
            previous_content: expected_content.cloned(),
            installed_content: desired_content.clone(),
            quarantine_name: Some(names.quarantine),
            content_fsynced: true,
            directory_fsynced: true,
        })
    }

    #[allow(clippy::result_large_err)]
    fn finalize_committed_file(
        &self,
        staged: &StagedFile,
        parent: &OwnedFd,
        target_name: &str,
        target_path: &str,
        metadata: FileMetadata,
    ) -> Result<(), ExecutionOutcomeV1> {
        if u64::try_from(staged.content_len)
            .map_or(true, |length| length > self.file_policy.max_content_bytes)
        {
            return Err(post_commit_drift(
                "committed staging inode exceeds the managed-file limit",
            ));
        }
        verify_named_staged_file(
            staged,
            parent,
            target_name,
            FileMetadata {
                uid: staged.broker_uid,
                gid: staged.broker_gid,
                mode: 0o600,
            },
        )
        .map_err(|reason| {
            post_commit_drift(format!(
                "committed staging inode failed broker-owned verification: {reason}"
            ))
        })?;

        fs::fchmod(&staged.file, Mode::empty()).map_err(|error| {
            post_commit_metadata_error(format!(
                "could not revoke staging access before ownership transfer: {error}"
            ))
        })?;
        fs::fchown(
            &staged.file,
            Some(Uid::from_raw(metadata.uid)),
            Some(Gid::from_raw(metadata.gid)),
        )
        .map_err(|error| {
            post_commit_metadata_error(format!("could not install final owner: {error}"))
        })?;
        fs::fchmod(&staged.file, Mode::from_raw_mode(metadata.mode)).map_err(|error| {
            post_commit_metadata_error(format!("could not install final mode: {error}"))
        })?;

        #[cfg(test)]
        if let Some(hook) = self.managed_file_post_transfer_hook {
            hook(target_path);
        }
        #[cfg(not(test))]
        let _ = target_path;

        verify_named_staged_file(staged, parent, target_name, metadata).map_err(|reason| {
            post_commit_drift(format!(
                "managed file changed after ownership transfer: {reason}"
            ))
        })?;
        fs::fsync(&staged.file).map_err(|error| {
            indeterminate(
                ExecutionIndeterminateCodeV1::DurabilityAfterCommit,
                ExecutionPhaseV1::DirectorySync,
                error.to_string(),
                None,
            )
        })?;
        verify_named_staged_file(staged, parent, target_name, metadata).map_err(|reason| {
            post_commit_drift(format!(
                "managed file changed during its durability barrier: {reason}"
            ))
        })?;
        fs::fsync(parent).map_err(|error| {
            indeterminate(
                ExecutionIndeterminateCodeV1::DurabilityAfterCommit,
                ExecutionPhaseV1::DirectorySync,
                error.to_string(),
                None,
            )
        })?;
        verify_named_staged_file(staged, parent, target_name, metadata).map_err(|reason| {
            post_commit_drift(format!(
                "managed file changed before terminal verification: {reason}"
            ))
        })?;
        Ok(())
    }

    fn execute_file_delete(
        &self,
        permit: &impl ExecutionCoordinatesV1,
        path: &str,
        expected_content: &Digest,
    ) -> ExecutionOutcomeV1 {
        let (parent, name) = match secure_parent(path, self.file_policy) {
            Ok(value) => value,
            Err(error) => return error.into_outcome(),
        };
        let observed =
            match observe_entry(&parent, name.as_str(), self.file_policy.max_content_bytes) {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return failure(
                        ExecutionFailureCodeV1::PrestateDrift,
                        ExecutionPhaseV1::PrestateCheck,
                        "managed-file target is absent",
                        None,
                    );
                }
                Err(error) => return error.into_outcome(),
            };
        if observed.digest != *expected_content {
            return failure(
                ExecutionFailureCodeV1::PrestateDrift,
                ExecutionPhaseV1::PrestateCheck,
                "managed-file content differs from the ratified prestate",
                None,
            );
        }

        let names = InternalNames::new(permit);
        if let Err(error) = ensure_internal_names_absent(&parent, &names) {
            return error.into_outcome();
        }
        if let Err(error) = fs::renameat_with(
            &parent,
            name.as_str(),
            &parent,
            names.quarantine.as_str(),
            RenameFlags::NOREPLACE,
        ) {
            return failure(
                if matches!(error, Errno::NOENT) {
                    ExecutionFailureCodeV1::PrestateDrift
                } else {
                    ExecutionFailureCodeV1::LocalIoBeforeCommit
                },
                ExecutionPhaseV1::Commit,
                error.to_string(),
                None,
            );
        }

        let displaced = observe_entry(
            &parent,
            names.quarantine.as_str(),
            self.file_policy.max_content_bytes,
        );
        if displaced
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .map(|value| &value.digest)
            != Some(expected_content)
        {
            return rollback_delete(
                &parent,
                name.as_str(),
                names.quarantine.as_str(),
                "entry changed during atomic quarantine",
            );
        }
        if let Err(error) = fs::fsync(&parent) {
            return indeterminate(
                ExecutionIndeterminateCodeV1::DurabilityAfterCommit,
                ExecutionPhaseV1::DirectorySync,
                error.to_string(),
                None,
            );
        }
        success(EffectSuccessV1::ManagedFileDelete {
            previous_content: expected_content.clone(),
            quarantine_name: names.quarantine,
            directory_fsynced: true,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn execute_pointer(
        &self,
        permit: &impl ExecutionCoordinatesV1,
        effect: &CanonicalEffectV1,
    ) -> ExecutionOutcomeV1 {
        let CanonicalEffectV1::ManagedPointerPromotion {
            schema,
            operation_id,
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
            ..
        } = effect
        else {
            return failure(
                ExecutionFailureCodeV1::BackendRejected,
                ExecutionPhaseV1::ReceiptValidation,
                "pointer executor received another effect family",
                None,
            );
        };
        if schema != MANAGED_POINTER_PROMOTION_SCHEMA_V2 {
            return failure(
                ExecutionFailureCodeV1::BackendRejected,
                ExecutionPhaseV1::ReceiptValidation,
                "canonical effect names an unsupported promotion contract",
                None,
            );
        }
        let Some(preparation_checkpoint) = permit.preparation_checkpoint() else {
            return failure(
                ExecutionFailureCodeV1::BackendRejected,
                ExecutionPhaseV1::ReceiptValidation,
                "promotion commit lacks a durable preparation checkpoint",
                None,
            );
        };
        let identity = match self.pointer_helper.identity() {
            CapabilityOutcomeV1::Succeeded(identity) => identity,
            CapabilityOutcomeV1::Failed(error) => {
                return failure_with_source(
                    ExecutionFailureCodeV1::HelperUnavailable,
                    ExecutionPhaseV1::HelperIdentity,
                    error.detail,
                    Some(error.code),
                    error.evidence,
                );
            }
            CapabilityOutcomeV1::Indeterminate(error) => {
                return indeterminate_with_source(
                    ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                    ExecutionPhaseV1::HelperIdentity,
                    error.detail,
                    Some(error.code),
                    error.evidence,
                );
            }
        };
        if identity.executable != *helper_executable
            || identity.launch_profile != *helper_launch_profile
        {
            return failure(
                ExecutionFailureCodeV1::HelperIdentityMismatch,
                ExecutionPhaseV1::HelperIdentity,
                "opened helper bytes or launch profile differ from canonical proposal",
                None,
            );
        }

        let request = PointerCasRequestV1 {
            schema: schema.clone(),
            operation_id: operation_id.clone(),
            preparation_checkpoint: preparation_checkpoint.clone(),
            allowed_root: allowed_root.clone(),
            repository: repository.clone(),
            reference: reference.clone(),
            repository_identity: repository_identity.clone(),
            prestate_identity: prestate_identity.clone(),
            repository_device: *repository_device,
            repository_inode: *repository_inode,
            git_directory_device: *git_directory_device,
            git_directory_inode: *git_directory_inode,
            uid: *uid,
            gid: *gid,
            staging_root: staging_root.clone(),
            artifact: artifact.clone(),
            candidate_pack_digest: candidate_pack_digest.clone(),
            object_format: *object_format,
            expected_object: expected_object.clone(),
            expected_tree: expected_tree.clone(),
            new_object: new_object.clone(),
            expected_post_tree: expected_post_tree.clone(),
            expires_unix_ms: *expires_unix_ms,
        };
        let request_digest = match Digest::from_serializable(&request) {
            Ok(digest) => digest,
            Err(error) => {
                return failure(
                    ExecutionFailureCodeV1::BackendRejected,
                    ExecutionPhaseV1::ReceiptValidation,
                    error.to_string(),
                    None,
                );
            }
        };
        match self.pointer_helper.compare_and_swap(&request) {
            CapabilityOutcomeV1::Succeeded(result)
                if result.request_digest == request_digest
                    && result.operation_id == *operation_id
                    && result.preparation_checkpoint == *preparation_checkpoint
                    && result.repository_identity == *repository_identity
                    && result.prestate_identity == *prestate_identity
                    && result.repository_device == *repository_device
                    && result.repository_inode == *repository_inode
                    && result.git_directory_device == *git_directory_device
                    && result.git_directory_inode == *git_directory_inode
                    && result.candidate_pack_digest == *candidate_pack_digest
                    && result.previous_object == *expected_object
                    && result.previous_tree == *expected_tree
                    && result.installed_object == *new_object
                    && result.installed_tree == *expected_post_tree =>
            {
                success(EffectSuccessV1::ManagedPointerPromotion {
                    operation_id: operation_id.clone(),
                    candidate_pack_digest: candidate_pack_digest.clone(),
                    preparation_checkpoint: preparation_checkpoint.clone(),
                    previous_object: result.previous_object,
                    previous_tree: result.previous_tree,
                    installed_object: result.installed_object,
                    installed_tree: result.installed_tree,
                    evidence: result.evidence,
                    poststate_evidence: result.poststate_evidence,
                })
            }
            CapabilityOutcomeV1::Succeeded(result) => indeterminate(
                ExecutionIndeterminateCodeV1::BackendContractViolation,
                ExecutionPhaseV1::PromotionPoststateVerification,
                "helper success evidence contradicts the exact CAS request",
                Some(result.evidence),
            ),
            CapabilityOutcomeV1::Failed(error) => failure_with_source(
                ExecutionFailureCodeV1::BackendRejected,
                ExecutionPhaseV1::PointerCas,
                error.detail,
                Some(error.code),
                error.evidence,
            ),
            CapabilityOutcomeV1::Indeterminate(error) => indeterminate_with_source(
                ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                ExecutionPhaseV1::PointerCas,
                error.detail,
                Some(error.code),
                error.evidence,
            ),
        }
    }

    fn execute_systemd_unit(
        &self,
        unit: &str,
        action: SystemdUnitActionV1,
        expected_active_state: &str,
        expected_unit_file_state: &str,
    ) -> ExecutionOutcomeV1 {
        let request = SystemdUnitRequestV1 {
            unit: unit.to_owned(),
            action,
            expected_active_state: expected_active_state.to_owned(),
            expected_unit_file_state: expected_unit_file_state.to_owned(),
        };
        match self.systemd.unit_action(&request) {
            CapabilityOutcomeV1::Succeeded(result)
                if result.unit == unit
                    && result.action == action
                    && result.previous_active_state == expected_active_state
                    && result.previous_unit_file_state == expected_unit_file_state =>
            {
                success(EffectSuccessV1::SystemdUnit {
                    resulting_active_state: result.resulting_active_state,
                    resulting_unit_file_state: result.resulting_unit_file_state,
                    evidence: result.evidence,
                })
            }
            CapabilityOutcomeV1::Succeeded(result) => indeterminate(
                ExecutionIndeterminateCodeV1::BackendContractViolation,
                ExecutionPhaseV1::SystemdDbus,
                "systemd success evidence contradicts the exact unit request",
                Some(result.evidence),
            ),
            CapabilityOutcomeV1::Failed(error) => failure_with_source(
                ExecutionFailureCodeV1::BackendRejected,
                ExecutionPhaseV1::SystemdDbus,
                error.detail,
                Some(error.code),
                error.evidence,
            ),
            CapabilityOutcomeV1::Indeterminate(error) => indeterminate_with_source(
                ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                ExecutionPhaseV1::SystemdDbus,
                error.detail,
                Some(error.code),
                error.evidence,
            ),
        }
    }

    fn execute_systemd_manager(
        &self,
        machine_identity: &str,
        expected_generation: u64,
    ) -> ExecutionOutcomeV1 {
        let request = SystemdManagerReloadRequestV1 {
            machine_identity: machine_identity.to_owned(),
            expected_generation,
        };
        match self.systemd.reload_manager(&request) {
            CapabilityOutcomeV1::Succeeded(result)
                if result.machine_identity == machine_identity
                    && result.resulting_generation >= expected_generation =>
            {
                success(EffectSuccessV1::SystemdManagerReload {
                    resulting_generation: result.resulting_generation,
                    evidence: result.evidence,
                })
            }
            CapabilityOutcomeV1::Succeeded(result) => indeterminate(
                ExecutionIndeterminateCodeV1::BackendContractViolation,
                ExecutionPhaseV1::SystemdDbus,
                "systemd success evidence contradicts the exact manager request",
                Some(result.evidence),
            ),
            CapabilityOutcomeV1::Failed(error) => failure_with_source(
                ExecutionFailureCodeV1::BackendRejected,
                ExecutionPhaseV1::SystemdDbus,
                error.detail,
                Some(error.code),
                error.evidence,
            ),
            CapabilityOutcomeV1::Indeterminate(error) => indeterminate_with_source(
                ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                ExecutionPhaseV1::SystemdDbus,
                error.detail,
                Some(error.code),
                error.evidence,
            ),
        }
    }
}

#[derive(Debug)]
struct ObservedFile {
    digest: Digest,
}

#[derive(Debug)]
struct StagedFile {
    file: File,
    sealed: fs::Stat,
    digest: Digest,
    content_len: usize,
    broker_uid: u32,
    broker_gid: u32,
}

#[derive(Clone, Copy, Debug)]
struct FileMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Debug)]
struct InternalNames {
    stage: String,
    quarantine: String,
}

impl InternalNames {
    fn new(permit: &impl ExecutionCoordinatesV1) -> Self {
        let suffix = permit
            .attempt()
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(permit.attempt().as_str());
        Self {
            stage: format!("{STAGE_PREFIX}{suffix}-{}", permit.effect_index()),
            quarantine: format!("{QUARANTINE_PREFIX}{suffix}-{}", permit.effect_index()),
        }
    }
}

#[derive(Debug)]
struct LocalExecutionError {
    code: ExecutionFailureCodeV1,
    phase: ExecutionPhaseV1,
    detail: String,
}

impl LocalExecutionError {
    fn new(
        code: ExecutionFailureCodeV1,
        phase: ExecutionPhaseV1,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            phase,
            detail: detail.into(),
        }
    }

    fn into_outcome(self) -> ExecutionOutcomeV1 {
        failure(self.code, self.phase, self.detail, None)
    }
}

#[allow(clippy::too_many_lines)]
fn secure_parent(
    raw_path: &str,
    policy: ManagedFilePolicyV1,
) -> Result<(OwnedFd, String), LocalExecutionError> {
    let path = Path::new(raw_path);
    let exact_segments = raw_path.strip_prefix('/').is_some_and(|tail| {
        !tail.is_empty()
            && tail
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
    });
    if !path.is_absolute() || !exact_segments {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::InvalidManagedPath,
            ExecutionPhaseV1::ParentResolution,
            "managed-file path must be absolute with exact non-empty components",
        ));
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || components
            .clone()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::InvalidManagedPath,
            ExecutionPhaseV1::ParentResolution,
            "managed-file path contains a non-normal component",
        ));
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && *value != "." && *value != "..")
        .ok_or_else(|| {
            LocalExecutionError::new(
                ExecutionFailureCodeV1::InvalidManagedPath,
                ExecutionPhaseV1::ParentResolution,
                "managed-file path has no UTF-8 file name",
            )
        })?;
    if name.starts_with(STAGE_PREFIX) || name.starts_with(QUARANTINE_PREFIX) {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::InvalidManagedPath,
            ExecutionPhaseV1::ParentResolution,
            "managed target collides with the broker's internal namespace",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::InvalidManagedPath,
            ExecutionPhaseV1::ParentResolution,
            "managed-file path has no parent",
        )
    })?;

    let root = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::ParentResolution,
            error.to_string(),
        )
    })?;
    validate_managed_ancestor(&root, policy, parent == Path::new("/"))?;
    let mut parent_fd = root;
    let relative = parent.strip_prefix("/").map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::InvalidManagedPath,
            ExecutionPhaseV1::ParentResolution,
            error.to_string(),
        )
    })?;
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            return Err(LocalExecutionError::new(
                ExecutionFailureCodeV1::InvalidManagedPath,
                ExecutionPhaseV1::ParentResolution,
                "managed parent contains a non-normal component",
            ));
        };
        let next = open_beneath(
            &parent_fd,
            Path::new(*component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            LocalExecutionError::new(
                ExecutionFailureCodeV1::UnsafeTarget,
                ExecutionPhaseV1::ParentResolution,
                error.to_string(),
            )
        })?;
        validate_managed_ancestor(&next, policy, index + 1 == components.len())?;
        parent_fd = next;
    }
    Ok((parent_fd, name.to_owned()))
}

fn validate_managed_ancestor(
    directory: &OwnedFd,
    policy: ManagedFilePolicyV1,
    final_parent: bool,
) -> Result<(), LocalExecutionError> {
    let stat = fs::fstat(directory).map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::ParentResolution,
            error.to_string(),
        )
    })?;
    let shared_writes = stat.st_mode & 0o022 != 0;
    let protected_sticky_root = !final_parent
        && stat.st_uid == policy.trusted_ancestor_uid
        && stat.st_mode & 0o1000 != 0
        && stat.st_mode & 0o002 != 0;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || (stat.st_uid != policy.trusted_ancestor_uid && stat.st_uid != policy.trusted_parent_uid)
        || (policy.require_private_parent_writes && shared_writes && !protected_sticky_root)
        || (final_parent && stat.st_uid != policy.trusted_parent_uid)
    {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::UnsafeTarget,
            ExecutionPhaseV1::ParentResolution,
            "managed path has an untrusted or rename-capable ancestor",
        ));
    }
    Ok(())
}

fn observe_entry(
    parent: &OwnedFd,
    name: &str,
    max_content_bytes: u64,
) -> Result<Option<ObservedFile>, LocalExecutionError> {
    let fd = match open_beneath(
        parent,
        Path::new(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(LocalExecutionError::new(
                ExecutionFailureCodeV1::UnsafeTarget,
                ExecutionPhaseV1::PrestateCheck,
                error.to_string(),
            ));
        }
    };
    let before = fs::fstat(&fd).map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::PrestateCheck,
            error.to_string(),
        )
    })?;
    if !FileType::from_raw_mode(before.st_mode).is_file() || before.st_nlink != 1 {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::UnsafeTarget,
            ExecutionPhaseV1::PrestateCheck,
            "managed target is not a singly linked regular file",
        ));
    }
    let length = u64::try_from(before.st_size).map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::UnsafeTarget,
            ExecutionPhaseV1::PrestateCheck,
            error.to_string(),
        )
    })?;
    if length > max_content_bytes {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::UnsafeTarget,
            ExecutionPhaseV1::PrestateCheck,
            "managed target exceeds the configured size limit",
        ));
    }
    let mut file = File::from(fd);
    let capacity = usize::try_from(length).map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::UnsafeTarget,
            ExecutionPhaseV1::PrestateCheck,
            error.to_string(),
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max_content_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LocalExecutionError::new(
                ExecutionFailureCodeV1::LocalIoBeforeCommit,
                ExecutionPhaseV1::PrestateCheck,
                error.to_string(),
            )
        })?;
    let after = fs::fstat(&file).map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::PrestateCheck,
            error.to_string(),
        )
    })?;
    if u64::try_from(bytes.len()).map_or(true, |actual| {
        actual != length || actual > max_content_bytes
    }) || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::PrestateDrift,
            ExecutionPhaseV1::PrestateCheck,
            "managed target changed during exact descriptor observation",
        ));
    }
    Ok(Some(ObservedFile {
        digest: Digest::hash_bytes(&bytes),
    }))
}

fn open_beneath(
    parent: &OwnedFd,
    relative: &Path,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    validate_relative(relative)?;
    let attempted = fs::openat2(
        parent,
        relative,
        flags,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    );
    finish_open_beneath(parent, relative, flags, mode, attempted)
}

fn finish_open_beneath(
    parent: &OwnedFd,
    relative: &Path,
    flags: OFlags,
    mode: Mode,
    attempted: Result<OwnedFd, Errno>,
) -> Result<OwnedFd, Errno> {
    validate_relative(relative)?;
    match attempted {
        Err(Errno::NOSYS) => open_beneath_with_openat(parent, relative, flags, mode),
        result => result,
    }
}

fn open_beneath_with_openat(
    parent: &OwnedFd,
    relative: &Path,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(component) => Ok(component),
            _ => Err(Errno::INVAL),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(Errno::INVAL);
    }

    let mut current = None;
    for (index, component) in components.iter().enumerate() {
        let directory = current.as_ref().unwrap_or(parent);
        let final_component = index + 1 == components.len();
        let opened = if final_component {
            fs::openat(directory, *component, flags, mode)?
        } else {
            fs::openat(
                directory,
                *component,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?
        };
        current = Some(opened);
    }
    current.ok_or(Errno::INVAL)
}

fn validate_relative(relative: &Path) -> Result<(), Errno> {
    let raw = relative.as_os_str().as_bytes();
    if raw.is_empty()
        || raw
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Errno::INVAL);
    }
    Ok(())
}

fn ensure_internal_names_absent(
    parent: &OwnedFd,
    names: &InternalNames,
) -> Result<(), LocalExecutionError> {
    for name in [&names.stage, &names.quarantine] {
        match fs::statat(parent, name.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {}
            Ok(_) => {
                return Err(LocalExecutionError::new(
                    ExecutionFailureCodeV1::PrestateDrift,
                    ExecutionPhaseV1::Staging,
                    "attempt staging or quarantine name already exists",
                ));
            }
            Err(error) => {
                return Err(LocalExecutionError::new(
                    ExecutionFailureCodeV1::LocalIoBeforeCommit,
                    ExecutionPhaseV1::Staging,
                    error.to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn stage_content(
    parent: &OwnedFd,
    stage_name: &str,
    bytes: &[u8],
    digest: &Digest,
    max_content_bytes: u64,
) -> Result<StagedFile, LocalExecutionError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > max_content_bytes) {
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::ArtifactUnavailable,
            ExecutionPhaseV1::Staging,
            "staged content exceeds the managed-file limit",
        ));
    }
    let fd = fs::openat(
        parent,
        stage_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::Staging,
            error.to_string(),
        )
    })?;
    let mut file = File::from(fd);
    let staged = file.write_all(bytes).map_err(|error| {
        LocalExecutionError::new(
            ExecutionFailureCodeV1::LocalIoBeforeCommit,
            ExecutionPhaseV1::Staging,
            error.to_string(),
        )
    });
    let staged = staged.and_then(|()| {
        fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|error| {
            LocalExecutionError::new(
                ExecutionFailureCodeV1::LocalIoBeforeCommit,
                ExecutionPhaseV1::Staging,
                error.to_string(),
            )
        })
    });
    let staged = staged.and_then(|()| {
        fs::fsync(&file).map_err(|error| {
            LocalExecutionError::new(
                ExecutionFailureCodeV1::LocalIoBeforeCommit,
                ExecutionPhaseV1::Staging,
                error.to_string(),
            )
        })
    });
    if let Err(error) = staged {
        drop(file);
        let _ = fs::unlinkat(parent, stage_name, rustix::fs::AtFlags::empty());
        return Err(error);
    }
    let sealed = match fs::fstat(&file) {
        Ok(sealed) => sealed,
        Err(error) => {
            drop(file);
            let _ = fs::unlinkat(parent, stage_name, rustix::fs::AtFlags::empty());
            return Err(LocalExecutionError::new(
                ExecutionFailureCodeV1::LocalIoBeforeCommit,
                ExecutionPhaseV1::Staging,
                error.to_string(),
            ));
        }
    };
    let staged = StagedFile {
        file,
        sealed,
        digest: digest.clone(),
        content_len: bytes.len(),
        broker_uid: sealed.st_uid,
        broker_gid: sealed.st_gid,
    };
    if let Err(reason) = verify_named_staged_file(
        &staged,
        parent,
        stage_name,
        FileMetadata {
            uid: staged.broker_uid,
            gid: staged.broker_gid,
            mode: 0o600,
        },
    ) {
        drop(staged);
        let _ = fs::unlinkat(parent, stage_name, rustix::fs::AtFlags::empty());
        return Err(LocalExecutionError::new(
            ExecutionFailureCodeV1::PrestateDrift,
            ExecutionPhaseV1::Staging,
            reason,
        ));
    }
    Ok(staged)
}

fn verify_named_staged_file(
    staged: &StagedFile,
    parent: &OwnedFd,
    name: &str,
    metadata: FileMetadata,
) -> Result<(), String> {
    let before = fs::fstat(&staged.file).map_err(|error| error.to_string())?;
    validate_staged_stat(staged, &before, metadata)?;
    let bytes = read_exact_staged_bytes(&staged.file, staged.content_len)?;
    let after = fs::fstat(&staged.file).map_err(|error| error.to_string())?;
    validate_staged_stat(staged, &after, metadata)?;
    if !same_observed_state(&before, &after) {
        return Err("retained staging descriptor changed during exact read".to_owned());
    }
    if Digest::hash_bytes(&bytes) != staged.digest {
        return Err("retained staging descriptor has unexpected content".to_owned());
    }
    let named = fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    if !same_observed_state(&after, &named) {
        return Err("directory entry does not bind the retained staging descriptor".to_owned());
    }
    Ok(())
}

fn validate_staged_stat(
    staged: &StagedFile,
    stat: &fs::Stat,
    metadata: FileMetadata,
) -> Result<(), String> {
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_dev != staged.sealed.st_dev
        || stat.st_ino != staged.sealed.st_ino
        || stat.st_uid != metadata.uid
        || stat.st_gid != metadata.gid
        || stat.st_mode & 0o7777 != metadata.mode
        || usize::try_from(stat.st_size).ok() != Some(staged.content_len)
        || stat.st_mtime != staged.sealed.st_mtime
        || stat.st_mtime_nsec != staged.sealed.st_mtime_nsec
    {
        return Err("staging inode content identity or metadata changed".to_owned());
    }
    Ok(())
}

fn read_exact_staged_bytes(file: &File, expected_len: usize) -> Result<Vec<u8>, String> {
    let read_limit = expected_len
        .checked_add(1)
        .ok_or_else(|| "staging content length cannot be bounded".to_owned())?;
    let mut bytes = Vec::with_capacity(expected_len);
    let mut chunk = [0_u8; 8192];
    while bytes.len() < read_limit {
        let remaining = read_limit - bytes.len();
        let chunk_limit = remaining.min(chunk.len());
        let count = file
            .read_at(
                &mut chunk[..chunk_limit],
                u64::try_from(bytes.len()).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    if bytes.len() != expected_len {
        return Err("retained staging descriptor has an unexpected length".to_owned());
    }
    Ok(bytes)
}

fn same_observed_state(left: &fs::Stat, right: &fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_nlink == right.st_nlink
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn post_commit_metadata_error(detail: impl Into<String>) -> ExecutionOutcomeV1 {
    indeterminate(
        ExecutionIndeterminateCodeV1::RollbackUnproven,
        ExecutionPhaseV1::MetadataTransfer,
        detail,
        None,
    )
}

fn post_commit_drift(detail: impl Into<String>) -> ExecutionOutcomeV1 {
    indeterminate(
        ExecutionIndeterminateCodeV1::RollbackUnproven,
        ExecutionPhaseV1::MetadataTransfer,
        detail,
        None,
    )
}

fn rollback_exchange(
    parent: &OwnedFd,
    target: &str,
    stage: &str,
    reason: &str,
) -> ExecutionOutcomeV1 {
    if fs::renameat_with(parent, stage, parent, target, RenameFlags::EXCHANGE).is_err() {
        return indeterminate(
            ExecutionIndeterminateCodeV1::RollbackUnproven,
            ExecutionPhaseV1::Commit,
            format!("{reason}; exchange rollback failed"),
            None,
        );
    }
    if let Err(error) = fs::fsync(parent) {
        return indeterminate(
            ExecutionIndeterminateCodeV1::RollbackUnproven,
            ExecutionPhaseV1::DirectorySync,
            format!("{reason}; rollback directory sync failed: {error}"),
            None,
        );
    }
    if fs::unlinkat(parent, stage, rustix::fs::AtFlags::empty()).is_err()
        || fs::fsync(parent).is_err()
    {
        return indeterminate(
            ExecutionIndeterminateCodeV1::RollbackUnproven,
            ExecutionPhaseV1::DirectorySync,
            format!("{reason}; rollback succeeded but staging cleanup was not durable"),
            None,
        );
    }
    failure(
        ExecutionFailureCodeV1::PrestateDrift,
        ExecutionPhaseV1::Commit,
        reason,
        None,
    )
}

fn rollback_delete(
    parent: &OwnedFd,
    target: &str,
    quarantine: &str,
    reason: &str,
) -> ExecutionOutcomeV1 {
    if fs::renameat_with(parent, quarantine, parent, target, RenameFlags::NOREPLACE).is_err() {
        return indeterminate(
            ExecutionIndeterminateCodeV1::RollbackUnproven,
            ExecutionPhaseV1::Quarantine,
            format!("{reason}; quarantine rollback failed"),
            None,
        );
    }
    if let Err(error) = fs::fsync(parent) {
        return indeterminate(
            ExecutionIndeterminateCodeV1::RollbackUnproven,
            ExecutionPhaseV1::DirectorySync,
            format!("{reason}; rollback directory sync failed: {error}"),
            None,
        );
    }
    failure(
        ExecutionFailureCodeV1::PrestateDrift,
        ExecutionPhaseV1::Commit,
        reason,
        None,
    )
}

fn success(success: EffectSuccessV1) -> ExecutionOutcomeV1 {
    ExecutionOutcomeV1::Succeeded { success }
}

fn failure(
    code: ExecutionFailureCodeV1,
    phase: ExecutionPhaseV1,
    detail: impl Into<String>,
    evidence: Option<Digest>,
) -> ExecutionOutcomeV1 {
    failure_with_source(code, phase, detail, None, evidence)
}

fn failure_with_source(
    code: ExecutionFailureCodeV1,
    phase: ExecutionPhaseV1,
    detail: impl Into<String>,
    source_code: Option<String>,
    evidence: Option<Digest>,
) -> ExecutionOutcomeV1 {
    ExecutionOutcomeV1::Failed {
        failure: ExecutionFailureV1 {
            code,
            phase,
            detail: detail.into(),
            source_code,
            evidence,
        },
    }
}

fn indeterminate(
    code: ExecutionIndeterminateCodeV1,
    phase: ExecutionPhaseV1,
    detail: impl Into<String>,
    evidence: Option<Digest>,
) -> ExecutionOutcomeV1 {
    indeterminate_with_source(code, phase, detail, None, evidence)
}

fn indeterminate_with_source(
    code: ExecutionIndeterminateCodeV1,
    phase: ExecutionPhaseV1,
    detail: impl Into<String>,
    source_code: Option<String>,
    evidence: Option<Digest>,
) -> ExecutionOutcomeV1 {
    ExecutionOutcomeV1::Indeterminate {
        envelope: ExecutionIndeterminateV1 {
            code,
            phase,
            detail: detail.into(),
            source_code,
            evidence,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use tempfile::TempDir;

    use super::*;
    use crate::TargetId;

    struct OneArtifact {
        digest: Digest,
        bytes: Vec<u8>,
    }

    impl ArtifactSourceV1 for OneArtifact {
        fn load(&self, digest: &Digest) -> Result<Vec<u8>, ArtifactReadErrorV1> {
            if *digest == self.digest {
                Ok(self.bytes.clone())
            } else {
                Err(ArtifactReadErrorV1::new("missing", "not in custody"))
            }
        }
    }

    struct UnusedPointer;

    impl PinnedPointerHelperV1 for UnusedPointer {
        fn identity(&self) -> CapabilityOutcomeV1<PinnedHelperIdentityV1> {
            panic!("pointer helper must not be invoked by a file effect")
        }

        fn prepare(
            &self,
            _request: &PointerPreparationRequestV1,
            _artifact: &[u8],
        ) -> CapabilityOutcomeV1<PointerPreparationSuccessV1> {
            panic!("pointer helper must not be invoked by a file effect")
        }

        fn compare_and_swap(
            &self,
            _request: &PointerCasRequestV1,
        ) -> CapabilityOutcomeV1<PointerCasSuccessV1> {
            panic!("pointer helper must not be invoked by a file effect")
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PointerContradictionV1 {
        None,
        PreparationRequest,
        CasRequest,
        PrestateIdentity,
        Poststate,
    }

    struct ExactPointer {
        executable: Digest,
        launch_profile: Digest,
        contradiction: PointerContradictionV1,
    }

    impl PinnedPointerHelperV1 for ExactPointer {
        fn identity(&self) -> CapabilityOutcomeV1<PinnedHelperIdentityV1> {
            CapabilityOutcomeV1::Succeeded(PinnedHelperIdentityV1 {
                executable: self.executable.clone(),
                launch_profile: self.launch_profile.clone(),
            })
        }

        fn prepare(
            &self,
            request: &PointerPreparationRequestV1,
            artifact: &[u8],
        ) -> CapabilityOutcomeV1<PointerPreparationSuccessV1> {
            if Digest::hash_bytes(artifact) != request.artifact {
                return CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
                    code: "fixture_artifact_mismatch".to_owned(),
                    detail: "fixture received different artifact bytes".to_owned(),
                    evidence: None,
                });
            }
            CapabilityOutcomeV1::Succeeded(PointerPreparationSuccessV1 {
                request_digest: if self.contradiction == PointerContradictionV1::PreparationRequest
                {
                    Digest::hash_bytes(b"different preparation request")
                } else {
                    Digest::from_serializable(request).expect("canonical request")
                },
                operation_id: request.operation_id.clone(),
                artifact: request.artifact.clone(),
                candidate_pack_digest: request.candidate_pack_digest.clone(),
                current_object: request.expected_object.clone(),
                current_tree: request.expected_tree.clone(),
                candidate_object: request.new_object.clone(),
                candidate_tree: request.expected_post_tree.clone(),
                preparation_checkpoint: Digest::hash_bytes(b"preparation-checkpoint"),
                evidence: Digest::hash_bytes(b"object-import-evidence"),
            })
        }

        fn compare_and_swap(
            &self,
            request: &PointerCasRequestV1,
        ) -> CapabilityOutcomeV1<PointerCasSuccessV1> {
            CapabilityOutcomeV1::Succeeded(PointerCasSuccessV1 {
                request_digest: if self.contradiction == PointerContradictionV1::CasRequest {
                    Digest::hash_bytes(b"different CAS request")
                } else {
                    Digest::from_serializable(request).expect("canonical request")
                },
                operation_id: request.operation_id.clone(),
                preparation_checkpoint: request.preparation_checkpoint.clone(),
                repository_identity: request.repository_identity.clone(),
                prestate_identity: if self.contradiction == PointerContradictionV1::PrestateIdentity
                {
                    Digest::hash_bytes(b"different prestate layout identity")
                } else {
                    request.prestate_identity.clone()
                },
                repository_device: request.repository_device,
                repository_inode: request.repository_inode,
                git_directory_device: request.git_directory_device,
                git_directory_inode: request.git_directory_inode,
                candidate_pack_digest: request.candidate_pack_digest.clone(),
                previous_object: request.expected_object.clone(),
                previous_tree: request.expected_tree.clone(),
                installed_object: request.new_object.clone(),
                installed_tree: if self.contradiction == PointerContradictionV1::Poststate {
                    "f".repeat(request.expected_post_tree.len())
                } else {
                    request.expected_post_tree.clone()
                },
                evidence: Digest::hash_bytes(b"ref-cas-evidence"),
                poststate_evidence: Digest::hash_bytes(b"poststate-evidence"),
            })
        }
    }

    struct UnusedSystemd;

    impl SystemdDbusBackendV1 for UnusedSystemd {
        fn unit_action(
            &self,
            _request: &SystemdUnitRequestV1,
        ) -> CapabilityOutcomeV1<SystemdUnitSuccessV1> {
            panic!("systemd backend must not be invoked by a file effect")
        }

        fn reload_manager(
            &self,
            _request: &SystemdManagerReloadRequestV1,
        ) -> CapabilityOutcomeV1<SystemdManagerReloadSuccessV1> {
            panic!("systemd backend must not be invoked by a file effect")
        }
    }

    struct ContradictingSystemd;

    impl SystemdDbusBackendV1 for ContradictingSystemd {
        fn unit_action(
            &self,
            request: &SystemdUnitRequestV1,
        ) -> CapabilityOutcomeV1<SystemdUnitSuccessV1> {
            CapabilityOutcomeV1::Succeeded(SystemdUnitSuccessV1 {
                unit: "different.service".to_owned(),
                action: request.action,
                previous_active_state: request.expected_active_state.clone(),
                previous_unit_file_state: request.expected_unit_file_state.clone(),
                resulting_active_state: "active".to_owned(),
                resulting_unit_file_state: "enabled".to_owned(),
                evidence: Digest::hash_bytes(b"contradictory-systemd-receipt"),
            })
        }

        fn reload_manager(
            &self,
            _request: &SystemdManagerReloadRequestV1,
        ) -> CapabilityOutcomeV1<SystemdManagerReloadSuccessV1> {
            panic!("manager reload is not part of this specimen")
        }
    }

    fn policy(directory: &TempDir) -> ManagedFilePolicyV1 {
        let metadata = fs::metadata(directory.path()).expect("temp directory metadata");
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(directory.path(), permissions).expect("secure test parent");
        ManagedFilePolicyV1 {
            max_content_bytes: 1024 * 1024,
            trusted_ancestor_uid: fs::metadata("/").expect("root metadata").uid(),
            trusted_parent_uid: metadata.uid(),
            require_private_parent_writes: true,
        }
    }

    fn permit(label: &[u8]) -> BurnedExecutionPermitV1 {
        BurnedExecutionPermitV1::from_durable_burn(
            Digest::hash_bytes(b"proposal"),
            Digest::hash_bytes(b"authorization"),
            Digest::hash_bytes(label),
            0,
        )
    }

    fn file_put(path: &Path, expected: Option<Digest>, content: Digest) -> CanonicalEffectV1 {
        let metadata = fs::metadata(path.parent().expect("parent")).expect("parent metadata");
        CanonicalEffectV1::ManagedFilePut {
            target: TargetId::parse("managed.test").expect("target"),
            path: path.to_str().expect("UTF-8 test path").to_owned(),
            expected_content: expected,
            content,
            mode: 0o640,
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }

    fn pointer_promotion(artifact: Digest) -> CanonicalEffectV1 {
        CanonicalEffectV1::ManagedPointerPromotion {
            schema: MANAGED_POINTER_PROMOTION_SCHEMA_V2.to_owned(),
            operation_id: Digest::hash_bytes(b"operation"),
            prepared_candidate: Digest::hash_bytes(b"prepared-candidate"),
            exact_basis: Digest::hash_bytes(b"exact-basis"),
            complete_inputs: Digest::hash_bytes(b"complete-inputs"),
            candidate_preparation_receipt: Digest::hash_bytes(b"candidate-preparation"),
            target: TargetId::parse("release.main").expect("target"),
            allowed_root: "/srv/governed".to_owned(),
            repository: "service.git".to_owned(),
            reference: "refs/heads/main".to_owned(),
            repository_identity: Digest::hash_bytes(b"repository"),
            prestate_identity: Digest::hash_bytes(b"prestate-layout-identity"),
            repository_device: 8,
            repository_inode: 101,
            git_directory_device: 8,
            git_directory_inode: 102,
            uid: 1200,
            gid: 1200,
            staging_root: "/var/lib/ag-effectd/promotion-stage".to_owned(),
            artifact,
            candidate_pack_digest: Digest::hash_bytes(b"normalized-pack"),
            object_format: GitObjectFormatV1::Sha1,
            expected_object: "1".repeat(40),
            expected_tree: "2".repeat(40),
            new_object: "3".repeat(40),
            expected_post_tree: "4".repeat(40),
            expires_unix_ms: 20_000,
            helper_executable: Digest::hash_bytes(b"helper-executable"),
            helper_launch_profile: Digest::hash_bytes(b"helper-profile"),
        }
    }

    fn fallback_test_root(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open fallback test root")
    }

    #[test]
    fn openat_fallback_opens_nested_file_and_preserves_create_mode() {
        let directory = TempDir::new().expect("temp directory");
        let nested = directory.path().join("one/two");
        fs::create_dir_all(&nested).expect("nested directories");
        fs::write(nested.join("existing"), b"exact bytes").expect("nested file");
        let root = fallback_test_root(directory.path());

        let opened = finish_open_beneath(
            &root,
            Path::new("one/two/existing"),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            Err(Errno::NOSYS),
        )
        .expect("component fallback opens nested file");
        let mut opened = File::from(opened);
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).expect("read nested file");
        assert_eq!(bytes, b"exact bytes");

        let created = finish_open_beneath(
            &root,
            Path::new("one/two/created"),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
            Err(Errno::NOSYS),
        )
        .expect("component fallback creates exact file");
        let stat = rustix::fs::fstat(&created).expect("created file metadata");
        assert!(FileType::from_raw_mode(stat.st_mode).is_file());
        assert_eq!(stat.st_mode & 0o7777, 0o600);
    }

    #[test]
    fn openat_fallback_refuses_intermediate_and_final_symlinks() {
        let directory = TempDir::new().expect("temp directory");
        let inside = directory.path().join("inside");
        let outside = directory.path().join("outside");
        fs::create_dir(&inside).expect("inside directory");
        fs::create_dir(&outside).expect("outside directory");
        fs::write(outside.join("sentinel"), b"outside").expect("outside sentinel");
        symlink(&outside, directory.path().join("intermediate-link"))
            .expect("intermediate symlink");
        symlink(outside.join("sentinel"), inside.join("final-link")).expect("final symlink");
        let root = fallback_test_root(directory.path());
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;

        assert!(
            finish_open_beneath(
                &root,
                Path::new("intermediate-link/sentinel"),
                flags,
                Mode::empty(),
                Err(Errno::NOSYS),
            )
            .is_err()
        );
        assert!(
            finish_open_beneath(
                &root,
                Path::new("inside/final-link"),
                flags,
                Mode::empty(),
                Err(Errno::NOSYS),
            )
            .is_err()
        );
        assert_eq!(
            fs::read(outside.join("sentinel")).expect("sentinel"),
            b"outside"
        );
    }

    #[test]
    fn openat_fallback_refuses_non_normal_paths_and_other_errors() {
        let directory = TempDir::new().expect("temp directory");
        fs::create_dir(directory.path().join("inside")).expect("inside directory");
        let root = fallback_test_root(directory.path());

        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        for hostile in [
            "",
            "/inside/file",
            "inside/../outside",
            "./inside/file",
            "inside//file",
            "inside/file/",
        ] {
            assert_eq!(
                finish_open_beneath(
                    &root,
                    Path::new(hostile),
                    flags,
                    Mode::empty(),
                    Err(Errno::NOSYS),
                )
                .unwrap_err(),
                Errno::INVAL
            );
            assert_eq!(
                open_beneath(&root, Path::new(hostile), flags, Mode::empty()).unwrap_err(),
                Errno::INVAL
            );
        }
        assert_eq!(
            finish_open_beneath(
                &root,
                Path::new("inside/file"),
                flags,
                Mode::empty(),
                Err(Errno::PERM),
            )
            .unwrap_err(),
            Errno::PERM
        );
    }

    #[test]
    fn runner_receipt_must_bind_every_permit_field_and_exact_effect() {
        let effect = CanonicalEffectV1::SystemdManagerReload {
            target: TargetId::parse("manager").expect("target"),
            machine_identity: "machine-1".to_owned(),
            expected_generation: 7,
        };
        let proposal = Digest::hash_bytes(b"proposal");
        let authorization = Digest::hash_bytes(b"authorization");
        let attempt = Digest::hash_bytes(b"attempt");
        let receipt = ExecutionReceiptV1 {
            schema: EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
            proposal: proposal.clone(),
            authorization: authorization.clone(),
            attempt: attempt.clone(),
            effect_index: 0,
            effect: effect.clone(),
            outcome: indeterminate(
                ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                ExecutionPhaseV1::ReceiptValidation,
                "test",
                None,
            ),
        };
        receipt
            .verify_bindings(&proposal, &authorization, &attempt, 0, &effect)
            .expect("exact binding");
        assert!(matches!(
            receipt.verify_bindings(&proposal, &authorization, &attempt, 1, &effect),
            Err(ExecutionReceiptError::BindingMismatch)
        ));
    }

    #[test]
    fn managed_pointer_requires_durable_preparation_and_validates_poststate() {
        let bytes = b"exact git bundle".to_vec();
        let artifact = Digest::hash_bytes(&bytes);
        let source = OneArtifact {
            digest: artifact.clone(),
            bytes,
        };
        let effect = pointer_promotion(artifact);
        let exact = ExactPointer {
            executable: Digest::hash_bytes(b"helper-executable"),
            launch_profile: Digest::hash_bytes(b"helper-profile"),
            contradiction: PointerContradictionV1::None,
        };
        let executor = EffectExecutorV1::new(
            &source,
            &exact,
            &UnusedSystemd,
            ManagedFilePolicyV1::default(),
        );
        let preparation = match executor.prepare_pointer(&effect) {
            CapabilityOutcomeV1::Succeeded(preparation) => preparation,
            other => panic!("unexpected preparation result: {other:?}"),
        };
        let receipt = executor.execute_once(
            BurnedExecutionPermitV1::from_durable_preparation(
                Digest::hash_bytes(b"proposal"),
                Digest::hash_bytes(b"authorization"),
                Digest::hash_bytes(b"attempt"),
                0,
                preparation.preparation_checkpoint.clone(),
            ),
            &effect,
        );
        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Succeeded {
                success: EffectSuccessV1::ManagedPointerPromotion { .. }
            }
        ));

        let without_checkpoint = executor.execute_once(permit(b"missing-checkpoint"), &effect);
        assert!(matches!(
            without_checkpoint.outcome,
            ExecutionOutcomeV1::Failed {
                failure: ExecutionFailureV1 {
                    phase: ExecutionPhaseV1::ReceiptValidation,
                    ..
                }
            }
        ));
    }

    #[test]
    fn contradictory_pointer_poststate_or_prestate_identity_is_indeterminate_never_success() {
        let bytes = b"exact git bundle".to_vec();
        let artifact = Digest::hash_bytes(&bytes);
        let source = OneArtifact {
            digest: artifact.clone(),
            bytes,
        };
        let effect = pointer_promotion(artifact);
        let contradicting = ExactPointer {
            executable: Digest::hash_bytes(b"helper-executable"),
            launch_profile: Digest::hash_bytes(b"helper-profile"),
            contradiction: PointerContradictionV1::Poststate,
        };
        let executor = EffectExecutorV1::new(
            &source,
            &contradicting,
            &UnusedSystemd,
            ManagedFilePolicyV1::default(),
        );
        let checkpoint = match executor.prepare_pointer(&effect) {
            CapabilityOutcomeV1::Succeeded(preparation) => preparation.preparation_checkpoint,
            other => panic!("unexpected preparation result: {other:?}"),
        };
        let receipt = executor.execute_once(
            BurnedExecutionPermitV1::from_durable_preparation(
                Digest::hash_bytes(b"proposal"),
                Digest::hash_bytes(b"authorization"),
                Digest::hash_bytes(b"attempt"),
                0,
                checkpoint,
            ),
            &effect,
        );
        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::BackendContractViolation,
                    phase: ExecutionPhaseV1::PromotionPoststateVerification,
                    ..
                }
            }
        ));

        let contradicting_prestate = ExactPointer {
            executable: Digest::hash_bytes(b"helper-executable"),
            launch_profile: Digest::hash_bytes(b"helper-profile"),
            contradiction: PointerContradictionV1::PrestateIdentity,
        };
        let executor = EffectExecutorV1::new(
            &source,
            &contradicting_prestate,
            &UnusedSystemd,
            ManagedFilePolicyV1::default(),
        );
        let checkpoint = match executor.prepare_pointer(&effect) {
            CapabilityOutcomeV1::Succeeded(preparation) => preparation.preparation_checkpoint,
            other => panic!("unexpected preparation result: {other:?}"),
        };
        let receipt = executor.execute_once(
            BurnedExecutionPermitV1::from_durable_preparation(
                Digest::hash_bytes(b"proposal"),
                Digest::hash_bytes(b"authorization"),
                Digest::hash_bytes(b"attempt-with-wrong-prestate-identity"),
                0,
                checkpoint,
            ),
            &effect,
        );
        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::BackendContractViolation,
                    phase: ExecutionPhaseV1::PromotionPoststateVerification,
                    ..
                }
            }
        ));
    }

    #[test]
    fn pointer_helper_success_must_bind_the_complete_typed_request() {
        let bytes = b"exact git bundle".to_vec();
        let artifact = Digest::hash_bytes(&bytes);
        let source = OneArtifact {
            digest: artifact.clone(),
            bytes,
        };
        let effect = pointer_promotion(artifact);
        let contradicting_preparation = ExactPointer {
            executable: Digest::hash_bytes(b"helper-executable"),
            launch_profile: Digest::hash_bytes(b"helper-profile"),
            contradiction: PointerContradictionV1::PreparationRequest,
        };
        let executor = EffectExecutorV1::new(
            &source,
            &contradicting_preparation,
            &UnusedSystemd,
            ManagedFilePolicyV1::default(),
        );
        assert!(matches!(
            executor.prepare_pointer(&effect),
            CapabilityOutcomeV1::Indeterminate(CapabilityIndeterminateV1 { .. })
        ));

        let contradicting_cas = ExactPointer {
            executable: Digest::hash_bytes(b"helper-executable"),
            launch_profile: Digest::hash_bytes(b"helper-profile"),
            contradiction: PointerContradictionV1::CasRequest,
        };
        let executor = EffectExecutorV1::new(
            &source,
            &contradicting_cas,
            &UnusedSystemd,
            ManagedFilePolicyV1::default(),
        );
        let checkpoint = match executor.prepare_pointer(&effect) {
            CapabilityOutcomeV1::Succeeded(preparation) => preparation.preparation_checkpoint,
            other => panic!("unexpected preparation result: {other:?}"),
        };
        let receipt = executor.execute_once(
            BurnedExecutionPermitV1::from_durable_preparation(
                Digest::hash_bytes(b"proposal"),
                Digest::hash_bytes(b"authorization"),
                Digest::hash_bytes(b"attempt"),
                0,
                checkpoint,
            ),
            &effect,
        );
        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::BackendContractViolation,
                    ..
                }
            }
        ));
    }

    #[test]
    fn symlink_swap_is_refused_without_following_it() {
        let directory = TempDir::new().expect("temp directory");
        let target = directory.path().join("managed.conf");
        let outside = directory.path().join("outside");
        fs::write(&target, b"ratified old").expect("initial managed file");
        fs::write(&outside, b"do not touch").expect("outside sentinel");
        let expected = Digest::hash_bytes(b"ratified old");
        fs::remove_file(&target).expect("simulate swap");
        symlink(&outside, &target).expect("install hostile symlink");

        let desired = Digest::hash_bytes(b"new");
        let source = OneArtifact {
            digest: desired.clone(),
            bytes: b"new".to_vec(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory));
        let receipt = executor.execute_once(
            permit(b"symlink"),
            &file_put(&target, Some(expected), desired),
        );

        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Failed {
                failure: ExecutionFailureV1 {
                    code: ExecutionFailureCodeV1::UnsafeTarget,
                    ..
                }
            }
        ));
        assert_eq!(
            fs::read(&outside).expect("outside remains"),
            b"do not touch"
        );
        assert!(
            fs::symlink_metadata(&target)
                .expect("symlink remains")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn hard_link_alias_is_refused_without_mutating_either_name() {
        let directory = TempDir::new().expect("temp directory");
        let target = directory.path().join("managed.conf");
        let alias = directory.path().join("external-alias");
        fs::write(&target, b"ratified old").expect("initial managed file");
        fs::hard_link(&target, &alias).expect("hostile hard-link alias");

        let desired = Digest::hash_bytes(b"new");
        let source = OneArtifact {
            digest: desired.clone(),
            bytes: b"new".to_vec(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory));
        let receipt = executor.execute_once(
            permit(b"hard-link"),
            &file_put(&target, Some(Digest::hash_bytes(b"ratified old")), desired),
        );

        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Failed {
                failure: ExecutionFailureV1 {
                    code: ExecutionFailureCodeV1::UnsafeTarget,
                    phase: ExecutionPhaseV1::PrestateCheck,
                    ..
                }
            }
        ));
        assert_eq!(fs::read(&target).expect("target remains"), b"ratified old");
        assert_eq!(fs::read(&alias).expect("alias remains"), b"ratified old");
    }

    #[test]
    fn writable_non_sticky_ancestor_cannot_redirect_managed_parent() {
        let directory = TempDir::new().expect("temp directory");
        let rename_capable = directory.path().join("rename-capable");
        let final_parent = rename_capable.join("final-parent");
        fs::create_dir(&rename_capable).expect("writable ancestor");
        fs::create_dir(&final_parent).expect("final parent");
        fs::set_permissions(&rename_capable, fs::Permissions::from_mode(0o777))
            .expect("make ancestor rename-capable");
        fs::set_permissions(&final_parent, fs::Permissions::from_mode(0o700))
            .expect("protect final parent");
        let target = final_parent.join("managed.conf");
        let desired = Digest::hash_bytes(b"new");
        let source = OneArtifact {
            digest: desired.clone(),
            bytes: b"new".to_vec(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory));
        let receipt = executor.execute_once(
            permit(b"rename-capable-ancestor"),
            &file_put(&target, None, desired),
        );
        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Failed {
                failure: ExecutionFailureV1 {
                    code: ExecutionFailureCodeV1::UnsafeTarget,
                    phase: ExecutionPhaseV1::ParentResolution,
                    ..
                }
            }
        ));
        assert!(!target.exists());
    }

    #[test]
    fn prestate_drift_never_installs_staged_content() {
        let directory = TempDir::new().expect("temp directory");
        let target = directory.path().join("managed.conf");
        fs::write(&target, b"different").expect("drifted managed file");
        let desired = Digest::hash_bytes(b"new");
        let source = OneArtifact {
            digest: desired.clone(),
            bytes: b"new".to_vec(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory));
        let effect = file_put(&target, Some(Digest::hash_bytes(b"ratified old")), desired);
        let receipt = executor.execute_once(permit(b"drift"), &effect);

        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Failed {
                failure: ExecutionFailureV1 {
                    code: ExecutionFailureCodeV1::PrestateDrift,
                    ..
                }
            }
        ));
        assert_eq!(fs::read(&target).expect("target remains"), b"different");
        assert_eq!(
            fs::read_dir(directory.path()).expect("list parent").count(),
            1
        );
    }

    #[test]
    fn replay_has_no_second_effect_surface() {
        let directory = TempDir::new().expect("temp directory");
        let target = directory.path().join("managed.conf");
        let desired = Digest::hash_bytes(b"installed once");
        let source = OneArtifact {
            digest: desired.clone(),
            bytes: b"installed once".to_vec(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory));
        let effect = file_put(&target, None, desired);

        let first = executor.execute_once(permit(b"once"), &effect);
        assert!(matches!(
            first.outcome,
            ExecutionOutcomeV1::Succeeded { .. }
        ));
        let replay = executor.execute_once(permit(b"second durable id"), &effect);
        assert!(matches!(
            replay.outcome,
            ExecutionOutcomeV1::Failed {
                failure: ExecutionFailureV1 {
                    code: ExecutionFailureCodeV1::PrestateDrift,
                    ..
                }
            }
        ));
        assert_eq!(
            fs::read(&target).expect("installed target"),
            b"installed once"
        );
    }

    #[test]
    fn replacement_is_atomic_and_retains_ratified_prestate() {
        let directory = TempDir::new().expect("temp directory");
        let target = directory.path().join("managed.conf");
        fs::write(&target, b"old bytes").expect("managed file");
        let previous = Digest::hash_bytes(b"old bytes");
        let desired = Digest::hash_bytes(b"new bytes");
        let source = OneArtifact {
            digest: desired.clone(),
            bytes: b"new bytes".to_vec(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory));
        let effect = file_put(&target, Some(previous), desired);

        let receipt = executor.execute_once(permit(b"replace"), &effect);
        let quarantine = match receipt.outcome {
            ExecutionOutcomeV1::Succeeded {
                success:
                    EffectSuccessV1::ManagedFilePut {
                        quarantine_name: Some(quarantine_name),
                        content_fsynced: true,
                        directory_fsynced: true,
                        ..
                    },
            } => quarantine_name,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert_eq!(fs::read(&target).expect("new target"), b"new bytes");
        assert_eq!(
            fs::read(directory.path().join(quarantine)).expect("old quarantine"),
            b"old bytes"
        );
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[test]
    fn mutation_after_final_metadata_transfer_is_indeterminate() {
        let directory = TempDir::new().expect("temp directory");
        let target = directory.path().join("managed.conf");
        let desired = Digest::hash_bytes(b"ratified bytes");
        let source = OneArtifact {
            digest: desired.clone(),
            bytes: b"ratified bytes".to_vec(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let mutate_after_transfer = |committed_path: &str| {
            fs::write(committed_path, b"hostile post-transfer mutation")
                .expect("final owner can attempt mutation");
        };
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory))
            .with_managed_file_post_transfer_hook(&mutate_after_transfer);

        let receipt = executor.execute_once(
            permit(b"post-transfer-mutation"),
            &file_put(&target, None, desired),
        );

        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::RollbackUnproven,
                    phase: ExecutionPhaseV1::MetadataTransfer,
                    ..
                }
            }
        ));
        assert_eq!(
            fs::read(&target).expect("committed target remains inspectable"),
            b"hostile post-transfer mutation"
        );
    }

    #[test]
    fn delete_is_an_atomic_recoverable_quarantine() {
        let directory = TempDir::new().expect("temp directory");
        let target = directory.path().join("managed.conf");
        fs::write(&target, b"old").expect("managed file");
        let expected = Digest::hash_bytes(b"old");
        let source = OneArtifact {
            digest: Digest::hash_bytes(b"unused"),
            bytes: Vec::new(),
        };
        let pointer = UnusedPointer;
        let systemd = UnusedSystemd;
        let executor = EffectExecutorV1::new(&source, &pointer, &systemd, policy(&directory));
        let effect = CanonicalEffectV1::ManagedFileDelete {
            target: TargetId::parse("managed.test").expect("target"),
            path: target.to_str().expect("UTF-8 test path").to_owned(),
            expected_content: expected,
        };

        let receipt = executor.execute_once(permit(b"delete"), &effect);
        let quarantine = match receipt.outcome {
            ExecutionOutcomeV1::Succeeded {
                success:
                    EffectSuccessV1::ManagedFileDelete {
                        quarantine_name, ..
                    },
            } => quarantine_name,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert!(!target.exists());
        assert_eq!(
            fs::read(directory.path().join(quarantine)).expect("quarantine bytes"),
            b"old"
        );
    }

    #[test]
    fn systemd_success_for_another_unit_is_indeterminate_not_success() {
        let source = OneArtifact {
            digest: Digest::hash_bytes(b"unused"),
            bytes: Vec::new(),
        };
        let pointer = UnusedPointer;
        let systemd = ContradictingSystemd;
        let executor =
            EffectExecutorV1::new(&source, &pointer, &systemd, ManagedFilePolicyV1::default());
        let effect = CanonicalEffectV1::SystemdUnit {
            target: TargetId::parse("service.web").expect("target"),
            unit: "web.service".to_owned(),
            action: SystemdUnitActionV1::Restart,
            expected_active_state: "active".to_owned(),
            expected_unit_file_state: "enabled".to_owned(),
        };

        let receipt = executor.execute_once(permit(b"systemd-contract"), &effect);
        assert!(matches!(
            receipt.outcome,
            ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::BackendContractViolation,
                    phase: ExecutionPhaseV1::SystemdDbus,
                    ..
                }
            }
        ));
    }
}
