//! Closed, broker-owned effect proposals and their authorization lifecycle.
//!
//! An [`ProposalIntentV1`] is untrusted input.  It contains no observed target
//! state and is never ratifiable.  Only [`EffectCompilerV1`] can combine an
//! intent with the effect broker's catalog and observations to produce a
//! [`CanonicalEffectProposalV1`].  Persistence and authorization of those
//! bytes remain responsibilities of the effect broker.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use ag_primitives::{AuthorityDomain, Digest, Epoch, PrincipalChainV1, PrincipalV1 as Principal};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Linux exact-effect execution through narrow injected capabilities.
#[cfg(target_os = "linux")]
pub mod executor;

/// The schema version emitted by this crate.
pub const EFFECT_SCHEMA_V1: &str = "ag.effect/v1";

/// The exact root-owned effect-catalog contract consumed by this compiler.
pub const EFFECT_CATALOG_SCHEMA_V1: &str = "ag.effect-catalog/v1";

/// The closed managed-reference promotion contract.
pub const MANAGED_POINTER_PROMOTION_SCHEMA_V1: &str = "ag.managed-pointer-promotion/v1";

/// The exact bounded host-mandate schema.
pub const HOST_MANDATE_SCHEMA_V1: &str = "ag.host-mandate/v1";

/// Exact operator reconciliation evidence schema.
pub const RECONCILIATION_EVIDENCE_SCHEMA_V1: &str = "ag.reconciliation-evidence/v1";

/// Exact broker-owned reconciliation record schema.
pub const RECONCILIATION_RECORD_SCHEMA_V1: &str = "ag.reconciliation-record/v1";

/// A root-owned identifier naming an entry in the effect target catalog.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TargetId(String);

impl TargetId {
    /// Parses a conservative target identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is empty, oversized, or contains path
    /// separators or characters outside the closed identifier alphabet.
    pub fn parse(value: impl Into<String>) -> Result<Self, EffectError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if !valid {
            return Err(EffectError::InvalidTargetId(value));
        }
        Ok(Self(value))
    }

    /// Returns the catalog key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An unprivileged governor's requested effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectIntentV1 {
    /// Promote one admitted Git bundle through a catalogued managed ref.
    ManagedPointerPromotion {
        /// Catalog entry.
        target: TargetId,
        /// Exact candidate bundle already held in governed custody.
        artifact: Digest,
    },
    /// Install admitted bytes at a catalogued managed-file target.
    ManagedFilePut {
        /// Catalog entry.
        target: TargetId,
        /// Content-addressed admitted artifact.
        content: Digest,
    },
    /// Quarantine and remove a catalogued managed file.
    ManagedFileDelete {
        /// Catalog entry.
        target: TargetId,
    },
    /// Invoke one closed systemd operation on a catalogued unit.
    SystemdUnit {
        /// Catalog entry.
        target: TargetId,
        /// Closed operation.
        action: SystemdUnitActionV1,
    },
    /// Ask systemd to reload its manager configuration.
    SystemdManagerReload {
        /// Catalogued manager endpoint.
        target: TargetId,
    },
}

impl EffectIntentV1 {
    /// Returns the catalog target named by the intent.
    #[must_use]
    pub fn target(&self) -> &TargetId {
        match self {
            Self::ManagedPointerPromotion { target, .. }
            | Self::ManagedFilePut { target, .. }
            | Self::ManagedFileDelete { target }
            | Self::SystemdUnit { target, .. }
            | Self::SystemdManagerReload { target } => target,
        }
    }

    /// Returns the coarse closed effect family requested by this untrusted
    /// intent. This classification does not imply that the request is
    /// catalogued, admitted, canonical, or authorized.
    #[must_use]
    pub fn family(&self) -> EffectFamilyV1 {
        match self {
            Self::ManagedPointerPromotion { .. } => EffectFamilyV1::CodePromotion,
            Self::ManagedFilePut { .. } | Self::ManagedFileDelete { .. } => {
                EffectFamilyV1::ManagedFile
            }
            Self::SystemdUnit { .. } | Self::SystemdManagerReload { .. } => EffectFamilyV1::Systemd,
        }
    }
}

/// Closed systemd unit operations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemdUnitActionV1 {
    /// Start the unit.
    Start,
    /// Stop the unit.
    Stop,
    /// Restart the unit.
    Restart,
    /// Reload the unit.
    Reload,
    /// Enable the unit.
    Enable,
    /// Disable the unit.
    Disable,
}

/// Untrusted proposal input accepted by the broker proposal socket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalIntentV1 {
    /// Schema identifier.
    pub schema: String,
    /// Caller-generated correlation identifier.  It is not authority.
    pub intent_id: String,
    /// Authority domain in which judgment occurred.
    pub authority_domain: AuthorityDomain,
    /// Revocation epoch observed by the governor.
    pub epoch: Epoch,
    /// Authenticated proposer chain.
    pub proposer: PrincipalChainV1,
    /// Digest of the governor's admitted judgment record.
    pub judgment: Digest,
    /// Content references already placed in governed custody.
    pub admitted_artifacts: BTreeSet<Digest>,
    /// Requested effects, in execution order.
    pub effects: Vec<EffectIntentV1>,
}

impl ProposalIntentV1 {
    /// Performs shape checks that do not imply admission.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign schema, an empty intent or effect list,
    /// or an effect payload absent from the admitted artifact set.
    pub fn validate_shape(&self) -> Result<(), EffectError> {
        if self.schema != EFFECT_SCHEMA_V1 {
            return Err(EffectError::UnknownSchema(self.schema.clone()));
        }
        if self.intent_id.is_empty() || self.effects.is_empty() {
            return Err(EffectError::MalformedIntent);
        }
        for effect in &self.effects {
            let required = match effect {
                EffectIntentV1::ManagedPointerPromotion { artifact, .. } => Some(artifact),
                EffectIntentV1::ManagedFilePut { content, .. } => Some(content),
                EffectIntentV1::ManagedFileDelete { .. }
                | EffectIntentV1::SystemdUnit { .. }
                | EffectIntentV1::SystemdManagerReload { .. } => None,
            };
            if let Some(required) = required
                && !self.admitted_artifacts.contains(required)
            {
                return Err(EffectError::ArtifactNotAdmitted(required.clone()));
            }
        }
        Ok(())
    }

    /// Computes the semantic subject used by the four-family effect crossing.
    /// The correlation ID and judgment reference are excluded to avoid a
    /// circular commitment; domain, epoch, proposer, artifacts, and requested
    /// effects are all bound.
    ///
    /// # Errors
    ///
    /// Returns an error if strict canonical encoding of the subject fails.
    pub fn judgment_subject_digest(&self) -> Result<Digest, EffectError> {
        #[derive(Serialize)]
        struct JudgmentSubject<'a> {
            schema: &'a str,
            authority_domain: &'a AuthorityDomain,
            epoch: &'a Epoch,
            proposer: &'a PrincipalChainV1,
            admitted_artifacts: &'a BTreeSet<Digest>,
            effects: &'a [EffectIntentV1],
        }
        digest_serializable(&JudgmentSubject {
            schema: EFFECT_SCHEMA_V1,
            authority_domain: &self.authority_domain,
            epoch: &self.epoch,
            proposer: &self.proposer,
            admitted_artifacts: &self.admitted_artifacts,
            effects: &self.effects,
        })
    }
}

/// Root-owned, versioned target catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectCatalogV1 {
    /// Exact catalog schema interpreted by the compiler and executor.
    pub schema: String,
    /// Digest of the complete root-owned catalog bytes.
    pub identity: Digest,
    /// Catalog entries by opaque ID.
    pub targets: BTreeMap<TargetId, TargetDefinitionV1>,
}

/// Trusted target definitions. Paths enter the system only through this type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetDefinitionV1 {
    /// A Git reference maintained through a pinned helper.
    ManagedPointer {
        /// Descriptor-opened root beneath which the repository must remain.
        allowed_root: String,
        /// Canonical repository path beneath `allowed_root`.
        repository: String,
        /// Exact reference name.
        reference: String,
        /// Identity of the repository configuration/object format.
        repository_identity: Digest,
        /// Numeric owner under which the closed helper must execute.
        uid: u32,
        /// Numeric group under which the closed helper must execute.
        gid: u32,
        /// Broker-owned staging root outside the governed repository.
        staging_root: String,
        /// Exclusive validity interval beginning at canonical compilation.
        promotion_ttl_ms: u64,
        /// Exact executable bytes used as helper.
        helper_executable: Digest,
        /// Exact helper launch profile.
        helper_launch_profile: Digest,
    },
    /// A regular file controlled by atomic broker replacement.
    ManagedFile {
        /// Canonically resolved destination path.
        path: String,
        /// Expected Unix mode after installation.
        mode: u32,
        /// Numeric owner.
        uid: u32,
        /// Numeric group.
        gid: u32,
    },
    /// A systemd unit reached through the system bus.
    SystemdUnit {
        /// Exact escaped unit name.
        unit: String,
        /// Operations enabled for this target.
        allowed_actions: BTreeSet<SystemdUnitActionV1>,
    },
    /// The local systemd manager.
    SystemdManager,
}

/// Broker observations made immediately before canonical compilation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetObservationV1 {
    /// Current Git reference and object-store identity.
    ManagedPointer {
        /// Commit currently named by the managed ref.
        current_object: String,
        /// Tree reached from the current commit.
        current_tree: String,
        /// Commit advertised by the exact candidate artifact.
        candidate_object: String,
        /// Tree reached from the candidate commit.
        candidate_tree: String,
        /// Sole parent observed on the candidate commit.
        candidate_parent: String,
        /// Exact normalized pack produced from the candidate bundle.
        candidate_pack_digest: Digest,
        /// Closed repository object format.
        object_format: GitObjectFormatV1,
        /// Repository identity observed by the pinned helper.
        repository_identity: Digest,
        /// Exact descriptor-bound repository layout and prestate identity.
        prestate_identity: Digest,
        /// Device containing the opened repository directory.
        repository_device: u64,
        /// Inode of the opened repository directory.
        repository_inode: u64,
        /// Device containing the opened Git directory.
        git_directory_device: u64,
        /// Inode of the opened Git directory.
        git_directory_inode: u64,
        /// Numeric owner observed on the repository root.
        repository_uid: u32,
        /// Numeric group observed on the repository root.
        repository_gid: u32,
        /// True only when index and worktree observations contain no change.
        clean: bool,
        /// True when the managed ref is checked out by any attached worktree.
        reference_checked_out: bool,
    },
    /// Current file state.
    ManagedFile {
        /// Digest of current bytes, or absent.
        current_content: Option<Digest>,
        /// True only for a non-symlink regular file.
        regular_file: bool,
    },
    /// Current systemd unit state.
    SystemdUnit {
        /// `ActiveState` property.
        active_state: String,
        /// `UnitFileState` property.
        unit_file_state: String,
    },
    /// Manager identity and reload generation.
    SystemdManager {
        /// D-Bus machine identity.
        machine_identity: String,
        /// Broker-observed manager generation.
        generation: u64,
    },
}

/// Closed terminal classification supported by operator reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationClassificationV1 {
    /// Broker observation proves the ratified effect reached its desired state.
    Applied,
    /// Broker observation proves the ratified prestate remains in place.
    NotApplied,
    /// Broker observation proves neither ratified prestate nor poststate.
    Foreign,
}

/// Closed Git object formats supported by managed-reference promotion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectFormatV1 {
    /// Forty-character SHA-1 object names.
    Sha1,
    /// Sixty-four-character SHA-256 object names.
    Sha256,
}

impl GitObjectFormatV1 {
    const fn object_name_length(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

/// Exact evidence an operator submits after independently investigating an
/// indeterminate execution boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationEvidenceV1 {
    /// Evidence schema.
    pub schema: String,
    /// Exact canonical proposal.
    pub proposal: Digest,
    /// Exact one-shot execution attempt.
    pub attempt: Digest,
    /// Exact uncertainty envelope which opened reconciliation.
    pub uncertainty_envelope: Digest,
    /// Every durably committed step receipt in order.
    pub step_receipts: Vec<Digest>,
    /// Target poststate independently re-observed by effectd.
    pub observed_poststate: BTreeMap<TargetId, TargetObservationV1>,
    /// Terminal outcome asserted by the operator and re-derived by effectd.
    pub classification: ReconciliationClassificationV1,
}

/// Broker-owned, operator-authenticated reconciliation bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRecordV1 {
    /// Record schema.
    pub schema: String,
    /// Exact submitted evidence verified against broker custody and live state.
    pub evidence: ReconciliationEvidenceV1,
    /// Ratifier reconstructed from the signed effect-admin peer.
    pub ratifier: PrincipalChainV1,
    /// Digest of the exact signed admin request accepted by effectd.
    pub signed_request: Digest,
}

impl ReconciliationRecordV1 {
    /// Computes the exact terminal reconciliation receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be represented as strict JCS.
    pub fn digest(&self) -> Result<Digest, EffectError> {
        digest_serializable(self)
    }
}

/// Effect bytes compiled and owned by the broker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
// This is an exact serialized contract: boxing only the promotion family would
// change its canonical JCS shape and therefore its ratification digest.
#[allow(clippy::large_enum_variant)]
pub enum CanonicalEffectV1 {
    /// Exact Git ref compare-and-swap.
    ManagedPointerPromotion {
        /// Exact managed-promotion contract.
        schema: String,
        /// Broker-derived, proposal-scoped single-use operation identity.
        operation_id: Digest,
        /// Target catalog ID.
        target: TargetId,
        /// Descriptor-opened root beneath which the repository must remain.
        allowed_root: String,
        /// Canonical repository path beneath the allowed root.
        repository: String,
        /// Exact ref.
        reference: String,
        /// Repository configuration/object-format identity.
        repository_identity: Digest,
        /// Exact descriptor-bound repository layout and prestate identity.
        prestate_identity: Digest,
        /// Repository device observed during compilation.
        repository_device: u64,
        /// Repository inode observed during compilation.
        repository_inode: u64,
        /// Git-directory device observed during compilation.
        git_directory_device: u64,
        /// Git-directory inode observed during compilation.
        git_directory_inode: u64,
        /// Expected repository owner.
        uid: u32,
        /// Expected repository group.
        gid: u32,
        /// Broker-owned staging root outside the target repository.
        staging_root: String,
        /// Exact admitted candidate bundle.
        artifact: Digest,
        /// Exact normalized candidate pack derived from the bundle.
        candidate_pack_digest: Digest,
        /// Closed object format used by every bound object name.
        object_format: GitObjectFormatV1,
        /// Expected old commit.
        expected_object: String,
        /// Expected old tree.
        expected_tree: String,
        /// Desired candidate commit.
        new_object: String,
        /// Expected tree reached from the desired commit.
        expected_post_tree: String,
        /// Exclusive broker-clock expiry for this exact operation.
        expires_unix_ms: u64,
        /// Exact executable bytes for the helper.
        helper_executable: Digest,
        /// Exact launch profile for the helper.
        helper_launch_profile: Digest,
    },
    /// Atomic regular-file installation.
    ManagedFilePut {
        /// Target catalog ID.
        target: TargetId,
        /// Canonical destination.
        path: String,
        /// Expected prior content.
        expected_content: Option<Digest>,
        /// Admitted new content.
        content: Digest,
        /// Final mode.
        mode: u32,
        /// Final owner.
        uid: u32,
        /// Final group.
        gid: u32,
    },
    /// Quarantined regular-file removal.
    ManagedFileDelete {
        /// Target catalog ID.
        target: TargetId,
        /// Canonical destination.
        path: String,
        /// Exact content expected before removal.
        expected_content: Digest,
    },
    /// Exact systemd unit operation.
    SystemdUnit {
        /// Target catalog ID.
        target: TargetId,
        /// Exact unit.
        unit: String,
        /// Exact action.
        action: SystemdUnitActionV1,
        /// Prior `ActiveState`.
        expected_active_state: String,
        /// Prior `UnitFileState`.
        expected_unit_file_state: String,
    },
    /// Exact systemd manager reload.
    SystemdManagerReload {
        /// Target catalog ID.
        target: TargetId,
        /// Expected D-Bus machine identity.
        machine_identity: String,
        /// Expected manager generation.
        expected_generation: u64,
    },
}

impl CanonicalEffectV1 {
    /// Returns this effect's family.
    #[must_use]
    pub fn family(&self) -> EffectFamilyV1 {
        match self {
            Self::ManagedPointerPromotion { .. } => EffectFamilyV1::CodePromotion,
            Self::ManagedFilePut { .. } | Self::ManagedFileDelete { .. } => {
                EffectFamilyV1::ManagedFile
            }
            Self::SystemdUnit { .. } | Self::SystemdManagerReload { .. } => EffectFamilyV1::Systemd,
        }
    }

    /// Returns the catalog target.
    #[must_use]
    pub fn target(&self) -> &TargetId {
        match self {
            Self::ManagedPointerPromotion { target, .. }
            | Self::ManagedFilePut { target, .. }
            | Self::ManagedFileDelete { target, .. }
            | Self::SystemdUnit { target, .. }
            | Self::SystemdManagerReload { target, .. } => target,
        }
    }
}

/// A canonical proposal body. Its enclosing digest is over these exact JCS bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalProposalBodyV1 {
    /// Schema identifier.
    pub schema: String,
    /// Broker-generated proposal identifier.
    pub proposal_id: String,
    /// Digest of the untrusted source intent.
    pub intent_digest: Digest,
    /// Effectd-observed signed governor principal/key binding.
    pub governor_authentication: Digest,
    /// Authority domain.
    pub authority_domain: AuthorityDomain,
    /// Revocation epoch.
    pub epoch: Epoch,
    /// Broker clock used to derive every bounded effect expiry.
    pub compiled_at_unix_ms: u64,
    /// Authenticated proposer chain copied from verified peer context.
    pub proposer: PrincipalChainV1,
    /// Exact versioned catalog contract.
    pub catalog_schema: String,
    /// Broker catalog identity.
    pub catalog_identity: Digest,
    /// Exact broker security profile under which compilation occurred.
    pub security_profile_identity: Digest,
    /// Admission judgment reference.
    pub judgment: Digest,
    /// Canonical effects, in the only permitted execution order.
    pub effects: Vec<CanonicalEffectV1>,
}

/// Canonical, broker-compiled bytes that may be persisted and ratified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEffectProposalV1 {
    digest: Digest,
    body: CanonicalProposalBodyV1,
}

impl CanonicalEffectProposalV1 {
    /// Digest displayed and referenced by ratification.
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Canonical body shown directly through the effect-plane inspection API.
    #[must_use]
    pub fn body(&self) -> &CanonicalProposalBodyV1 {
        &self.body
    }

    /// Recomputes the JCS digest and rejects altered bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the canonical body cannot be encoded or no
    /// longer matches the broker-owned digest.
    pub fn verify_digest(&self) -> Result<(), EffectError> {
        let digest = digest_serializable(&self.body)?;
        if digest != self.digest {
            return Err(EffectError::CanonicalDigestMismatch);
        }
        Ok(())
    }
}

/// The only component allowed to produce canonical proposal objects.
#[derive(Clone, Debug)]
pub struct EffectCompilerV1 {
    catalog: EffectCatalogV1,
    security_profile_identity: Digest,
}

impl EffectCompilerV1 {
    /// Creates a compiler from a verified, root-owned catalog.
    #[must_use]
    pub fn new(catalog: EffectCatalogV1, security_profile_identity: Digest) -> Self {
        Self {
            catalog,
            security_profile_identity,
        }
    }

    /// Compiles intent plus broker-owned target observations into ratifiable bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the intent is malformed, a target or observation
    /// is missing or mismatched, or the broker-owned body cannot be
    /// canonically encoded.
    pub fn compile(
        &self,
        broker_proposal_id: String,
        intent: &ProposalIntentV1,
        authenticated_proposer: &PrincipalChainV1,
        governor_authentication: Digest,
        compiled_at_unix_ms: u64,
        observations: &BTreeMap<TargetId, TargetObservationV1>,
    ) -> Result<CanonicalEffectProposalV1, EffectError> {
        intent.validate_shape()?;
        if self.catalog.schema != EFFECT_CATALOG_SCHEMA_V1 {
            return Err(EffectError::UnknownCatalogSchema(
                self.catalog.schema.clone(),
            ));
        }
        if broker_proposal_id.is_empty()
            || &intent.proposer != authenticated_proposer
            || intent.authority_domain != *authenticated_proposer.authority_domain()
            || intent.epoch != authenticated_proposer.epoch()
        {
            return Err(EffectError::MalformedIntent);
        }
        let mut effects = Vec::with_capacity(intent.effects.len());
        for (index, requested) in intent.effects.iter().enumerate() {
            let definition = self
                .catalog
                .targets
                .get(requested.target())
                .ok_or_else(|| EffectError::UnknownTarget(requested.target().clone()))?;
            let observation = observations
                .get(requested.target())
                .ok_or_else(|| EffectError::MissingObservation(requested.target().clone()))?;
            let operation_id =
                if let EffectIntentV1::ManagedPointerPromotion { target, artifact } = requested {
                    let index = u32::try_from(index).map_err(|_| EffectError::MalformedIntent)?;
                    Some(digest_serializable(&(
                        "ag.effect.managed-pointer-operation/v1",
                        &intent.authority_domain,
                        intent.epoch,
                        &broker_proposal_id,
                        index,
                        target,
                        artifact,
                    ))?)
                } else {
                    None
                };
            effects.push(compile_one(
                requested,
                definition,
                observation,
                operation_id,
                compiled_at_unix_ms,
            )?);
        }

        let body = CanonicalProposalBodyV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            proposal_id: broker_proposal_id,
            intent_digest: digest_serializable(intent)?,
            governor_authentication,
            authority_domain: intent.authority_domain.clone(),
            epoch: intent.epoch,
            compiled_at_unix_ms,
            proposer: authenticated_proposer.clone(),
            catalog_schema: self.catalog.schema.clone(),
            catalog_identity: self.catalog.identity.clone(),
            security_profile_identity: self.security_profile_identity.clone(),
            judgment: intent.judgment.clone(),
            effects,
        };
        let digest = digest_serializable(&body)?;
        Ok(CanonicalEffectProposalV1 { digest, body })
    }
}

#[allow(clippy::too_many_lines)]
fn compile_one(
    intent: &EffectIntentV1,
    definition: &TargetDefinitionV1,
    observation: &TargetObservationV1,
    operation_id: Option<Digest>,
    compiled_at_unix_ms: u64,
) -> Result<CanonicalEffectV1, EffectError> {
    match (intent, definition, observation) {
        (
            EffectIntentV1::ManagedPointerPromotion { target, artifact },
            TargetDefinitionV1::ManagedPointer {
                allowed_root,
                repository,
                reference,
                repository_identity,
                uid,
                gid,
                staging_root,
                promotion_ttl_ms,
                helper_executable,
                helper_launch_profile,
            },
            TargetObservationV1::ManagedPointer {
                current_object,
                current_tree,
                candidate_object,
                candidate_tree,
                candidate_parent,
                candidate_pack_digest,
                object_format,
                repository_identity: observed_identity,
                prestate_identity,
                repository_device,
                repository_inode,
                git_directory_device,
                git_directory_inode,
                repository_uid,
                repository_gid,
                clean,
                reference_checked_out,
            },
        ) => {
            if repository_identity != observed_identity
                || uid != repository_uid
                || gid != repository_gid
                || *repository_inode == 0
                || *git_directory_inode == 0
            {
                return Err(EffectError::TargetIdentityMismatch(target.clone()));
            }
            if !clean {
                return Err(EffectError::PromotionTargetDirty(target.clone()));
            }
            if *reference_checked_out {
                return Err(EffectError::PromotionReferenceCheckedOut(target.clone()));
            }
            validate_git_object(current_object, *object_format)?;
            validate_git_object(current_tree, *object_format)?;
            validate_git_object(candidate_object, *object_format)?;
            validate_git_object(candidate_tree, *object_format)?;
            validate_git_object(candidate_parent, *object_format)?;
            if candidate_parent != current_object {
                return Err(EffectError::PromotionBaseMismatch(target.clone()));
            }
            if !is_canonical_absolute_root(allowed_root)
                || !is_canonical_relative_path(repository)
                || !is_canonical_git_reference(reference)
                || !is_canonical_absolute_root(staging_root)
                || Path::new(staging_root).starts_with(Path::new(allowed_root))
                || *uid == u32::MAX
                || *gid == u32::MAX
                || *promotion_ttl_ms == 0
            {
                return Err(EffectError::InvalidPromotionDefinition(target.clone()));
            }
            let expires_unix_ms = compiled_at_unix_ms
                .checked_add(*promotion_ttl_ms)
                .ok_or(EffectError::PromotionExpiryOverflow)?;
            let operation_id = operation_id.ok_or(EffectError::MalformedIntent)?;
            Ok(CanonicalEffectV1::ManagedPointerPromotion {
                schema: MANAGED_POINTER_PROMOTION_SCHEMA_V1.to_owned(),
                operation_id,
                target: target.clone(),
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
                expected_object: current_object.clone(),
                expected_tree: current_tree.clone(),
                new_object: candidate_object.clone(),
                expected_post_tree: candidate_tree.clone(),
                expires_unix_ms,
                helper_executable: helper_executable.clone(),
                helper_launch_profile: helper_launch_profile.clone(),
            })
        }
        (
            EffectIntentV1::ManagedFilePut { target, content },
            TargetDefinitionV1::ManagedFile {
                path,
                mode,
                uid,
                gid,
            },
            TargetObservationV1::ManagedFile {
                current_content,
                regular_file,
            },
        ) => {
            if !regular_file {
                return Err(EffectError::UnsafeTarget(target.clone()));
            }
            Ok(CanonicalEffectV1::ManagedFilePut {
                target: target.clone(),
                path: path.clone(),
                expected_content: current_content.clone(),
                content: content.clone(),
                mode: *mode,
                uid: *uid,
                gid: *gid,
            })
        }
        (
            EffectIntentV1::ManagedFileDelete { target },
            TargetDefinitionV1::ManagedFile { path, .. },
            TargetObservationV1::ManagedFile {
                current_content: Some(current_content),
                regular_file: true,
            },
        ) => Ok(CanonicalEffectV1::ManagedFileDelete {
            target: target.clone(),
            path: path.clone(),
            expected_content: current_content.clone(),
        }),
        (
            EffectIntentV1::SystemdUnit { target, action },
            TargetDefinitionV1::SystemdUnit {
                unit,
                allowed_actions,
            },
            TargetObservationV1::SystemdUnit {
                active_state,
                unit_file_state,
            },
        ) => {
            if !allowed_actions.contains(action) {
                return Err(EffectError::ActionNotAllowed(target.clone()));
            }
            Ok(CanonicalEffectV1::SystemdUnit {
                target: target.clone(),
                unit: unit.clone(),
                action: *action,
                expected_active_state: active_state.clone(),
                expected_unit_file_state: unit_file_state.clone(),
            })
        }
        (
            EffectIntentV1::SystemdManagerReload { target },
            TargetDefinitionV1::SystemdManager,
            TargetObservationV1::SystemdManager {
                machine_identity,
                generation,
            },
        ) => Ok(CanonicalEffectV1::SystemdManagerReload {
            target: target.clone(),
            machine_identity: machine_identity.clone(),
            expected_generation: *generation,
        }),
        _ => Err(EffectError::TargetKindMismatch(intent.target().clone())),
    }
}

fn validate_git_object(value: &str, object_format: GitObjectFormatV1) -> Result<(), EffectError> {
    if value.len() != object_format.object_name_length()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(EffectError::InvalidGitObject(value.to_owned()));
    }
    Ok(())
}

fn is_canonical_absolute_root(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && path != Path::new("/")
        && !value.ends_with('/')
        && !value[1..].contains("//")
        && !value.contains("/./")
        && !value.ends_with("/.")
        && !value.bytes().any(|byte| byte == 0)
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn is_canonical_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && !value.starts_with("./")
        && !value.ends_with('/')
        && !value.ends_with("/.")
        && !value.contains("//")
        && !value.contains("/./")
        && !value.bytes().any(|byte| byte == 0)
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_canonical_git_reference(value: &str) -> bool {
    value.starts_with("refs/")
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.as_bytes().ends_with(b".lock")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && value.bytes().all(|byte| {
            !byte.is_ascii_control()
                && !matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, EffectError> {
    let bytes =
        serde_jcs::to_vec(value).map_err(|error| EffectError::Canonical(error.to_string()))?;
    Ok(Digest::hash_bytes(&bytes))
}

/// Coarse effect families used only for closed grant matching.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectFamilyV1 {
    /// Managed Git ref promotion.
    CodePromotion,
    /// Managed file operations.
    ManagedFile,
    /// Closed systemd operations.
    Systemd,
}

/// Exact authorization evidence accepted for a persisted proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RatificationV1 {
    /// A human inspected and ratified exactly one canonical digest.
    HumanExact {
        /// Exact canonical proposal digest.
        proposal: Digest,
        /// Authenticated ratifier chain terminating at the effect broker.
        ratifier: PrincipalChainV1,
        /// Broker challenge displayed with the proposal.
        challenge: String,
        /// Digest of the exact signed effect-admin request accepted by effectd.
        signed_request: Digest,
    },
    /// A previously human-issued bounded grant for host effects.
    BoundedMandate {
        /// Grant identity stored by the broker.
        mandate: Digest,
        /// Exact canonical proposal digest selected under the mandate.
        proposal: Digest,
        /// Service principal exercising the grant.
        actor: Principal,
    },
    /// A verifier-derived authority path restricted to code promotion.
    DerivedCodePromotion {
        /// Exact canonical proposal digest.
        proposal: Digest,
        /// Independently owned verifier executable identity.
        verifier_executable: Digest,
        /// Exact verifier launch profile.
        verifier_launch_profile: Digest,
        /// Verifier receipt in broker custody.
        verifier_receipt: Digest,
        /// Scoped adapter principal chain.
        adapter: PrincipalChainV1,
    },
}

impl RatificationV1 {
    /// Returns the proposal digest authorized by the record.
    #[must_use]
    pub fn proposal(&self) -> &Digest {
        match self {
            Self::HumanExact { proposal, .. }
            | Self::BoundedMandate { proposal, .. }
            | Self::DerivedCodePromotion { proposal, .. } => proposal,
        }
    }
}

/// Body of a human-installed bounded host-effect mandate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostMandateBodyV1 {
    /// Exact mandate schema.
    pub schema: String,
    /// Authority domain.
    pub authority_domain: AuthorityDomain,
    /// Epoch in which it is valid.
    pub epoch: Epoch,
    /// Service principal allowed to exercise it.
    pub grantee: Principal,
    /// Closed allowed target set.
    pub targets: BTreeSet<TargetId>,
    /// Closed allowed effect families. Code promotion is rejected.
    pub families: BTreeSet<EffectFamilyV1>,
    /// Inclusive expiry in Unix milliseconds.
    pub expires_unix_ms: u64,
    /// Maximum successful selections.
    pub max_uses: u32,
}

/// Digest-bound, human-installed authority grant for closed host effects.
/// Code promotion is structurally excluded from this authority path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostMandateV1 {
    digest: Digest,
    body: HostMandateBodyV1,
}

impl HostMandateV1 {
    /// Constructs and digest-binds a structurally valid mandate body.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign schema, empty scope, zero uses,
    /// authority-context mismatch, or any attempt to include code promotion.
    pub fn new(body: HostMandateBodyV1) -> Result<Self, EffectError> {
        validate_host_mandate_body(&body)?;
        let digest = digest_serializable(&(HOST_MANDATE_SCHEMA_V1, &body))?;
        Ok(Self { digest, body })
    }

    /// Returns the exact mandate identity stored and burned by the broker.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the human-installed mandate scope.
    #[must_use]
    pub const fn body(&self) -> &HostMandateBodyV1 {
        &self.body
    }

    /// Recomputes both structural validation and exact mandate identity.
    ///
    /// # Errors
    ///
    /// Returns an error if decoded bytes are structurally invalid or no
    /// longer match the digest installed by the broker.
    pub fn verify_digest(&self) -> Result<(), EffectError> {
        validate_host_mandate_body(&self.body)?;
        if digest_serializable(&(HOST_MANDATE_SCHEMA_V1, &self.body))? != self.digest {
            return Err(EffectError::MandateDigestMismatch);
        }
        Ok(())
    }

    /// Checks the grant against canonical effects and authenticated context.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor, authority context, expiry, use count,
    /// target set, or closed family set does not cover the exact proposal.
    /// Code promotion always returns its distinct authority-path error.
    pub fn permits(
        &self,
        proposal: &CanonicalEffectProposalV1,
        actor: &Principal,
        now_unix_ms: u64,
        uses: u32,
    ) -> Result<(), EffectError> {
        self.verify_digest()?;
        if &self.body.grantee != actor
            || self.body.authority_domain != proposal.body.authority_domain
            || self.body.epoch != proposal.body.epoch
            || now_unix_ms > self.body.expires_unix_ms
            || uses >= self.body.max_uses
        {
            return Err(EffectError::MandateNotApplicable);
        }
        for effect in &proposal.body.effects {
            if effect.family() == EffectFamilyV1::CodePromotion {
                return Err(EffectError::PromotionRequiresSeparateAuthority);
            }
            if !self.body.targets.contains(effect.target())
                || !self.body.families.contains(&effect.family())
            {
                return Err(EffectError::MandateNotApplicable);
            }
        }
        Ok(())
    }
}

fn validate_host_mandate_body(body: &HostMandateBodyV1) -> Result<(), EffectError> {
    if body.schema != HOST_MANDATE_SCHEMA_V1
        || body.targets.is_empty()
        || body.families.is_empty()
        || body.max_uses == 0
        || body.families.contains(&EffectFamilyV1::CodePromotion)
        || body.grantee.authority_domain() != &body.authority_domain
        || body.grantee.epoch() != body.epoch
    {
        return Err(EffectError::InvalidHostMandate);
    }
    Ok(())
}

/// Durable proposal lifecycle. There is deliberately no automatic retry edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalStateV1 {
    /// Intent was received; canonical compilation has not completed.
    Received,
    /// Canonical bytes are persisted and await authority.
    Ready {
        /// Persisted canonical digest.
        proposal: Digest,
    },
    /// Semantic judgment refused this proposal.
    Refused {
        /// Lossless refusal record.
        refusal: Digest,
    },
    /// Evaluation could not determine a semantic result.
    Indeterminate {
        /// Operational envelope.
        envelope: Digest,
    },
    /// Authority evidence was accepted and durably burned before execution.
    AuthorizationBurned {
        /// Canonical proposal.
        proposal: Digest,
        /// Ratification/mandate/derived record.
        authorization: Digest,
        /// Exact closed family selected from the canonical proposal.
        family: EffectFamilyV1,
    },
    /// A code-promotion attempt is performing reversible preparation only.
    Preparing {
        /// Canonical proposal.
        proposal: Digest,
        /// Durable attempt identity.
        attempt: Digest,
    },
    /// The one permitted execution attempt began.
    Executing {
        /// Canonical proposal.
        proposal: Digest,
        /// Durable attempt identity.
        attempt: Digest,
        /// Durable proof that promotion preparation completed before its
        /// commit boundary was armed. Absent for non-promotion families.
        preparation_checkpoint: Option<Digest>,
    },
    /// Effect execution completed successfully.
    Succeeded {
        /// Exact effect receipt.
        receipt: Digest,
    },
    /// Effect execution returned a known failure. It is not retryable.
    Failed {
        /// Exact failure receipt.
        receipt: Digest,
    },
    /// Outcome is not safely knowable; operator reconciliation is required.
    ReconciliationRequired {
        /// Evidence envelope describing the uncertain boundary.
        envelope: Digest,
    },
    /// Reconciliation recorded the observed terminal state.
    Reconciled {
        /// Operator-authenticated reconciliation receipt.
        receipt: Digest,
    },
}

/// Events driving [`ProposalStateV1`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalEventV1 {
    /// Broker persisted canonical bytes.
    Compiled {
        /// Exact broker-owned proposal digest.
        proposal: Digest,
    },
    /// Kernel returned a semantic refusal.
    Refused {
        /// Lossless semantic refusal identity.
        refusal: Digest,
    },
    /// Evaluation was operationally indeterminate.
    Indeterminate {
        /// Non-semantic operational evidence envelope.
        envelope: Digest,
    },
    /// Broker durably consumed exact authority.
    BurnAuthorization {
        /// Canonical proposal.
        proposal: Digest,
        /// Authorization record.
        authorization: Digest,
        /// Exact family of the canonical effect whose authority was burned.
        family: EffectFamilyV1,
    },
    /// Begin reversible preparation for one code-promotion attempt.
    BeginPreparation {
        /// Durable attempt identity.
        attempt: Digest,
    },
    /// Durably attest that promotion preparation is complete and the helper
    /// may enter its externally visible ref-CAS boundary.
    CommitMayProceed {
        /// Exact preparation checkpoint returned by the closed helper.
        checkpoint: Digest,
    },
    /// Promotion preparation failed while the managed ref was proven intact.
    PreparationFailed {
        /// Exact known-failure receipt.
        receipt: Digest,
    },
    /// Broker restart abandoned reversible preparation with a proven intact ref.
    PreparationAbandoned {
        /// Exact no-effect abandonment receipt.
        receipt: Digest,
    },
    /// Preparation state cannot prove the target remained at either known
    /// boundary and therefore requires explicit reconciliation.
    PreparationIndeterminate {
        /// Exact uncertainty envelope.
        envelope: Digest,
    },
    /// Begin the only execution attempt for a non-promotion effect family.
    BeginExecution {
        /// Durable attempt identity.
        attempt: Digest,
    },
    /// Broker restarted after burning authority but before durably beginning
    /// an attempt. No effect occurred, and the authorization is not reusable.
    ExecutionAbandoned {
        /// Durable no-effect abandonment receipt.
        receipt: Digest,
    },
    /// Complete successfully.
    ExecutionSucceeded {
        /// Exact terminal execution receipt.
        receipt: Digest,
    },
    /// Complete with a known failure.
    ExecutionFailed {
        /// Exact known-failure receipt.
        receipt: Digest,
    },
    /// Mark the outcome unknowable.
    ExecutionIndeterminate {
        /// Evidence requiring explicit reconciliation.
        envelope: Digest,
    },
    /// Operator completes reconciliation.
    Reconciled {
        /// Operator-authenticated reconciliation receipt.
        receipt: Digest,
    },
}

impl ProposalStateV1 {
    /// Applies one legal durable transition.
    ///
    /// # Errors
    ///
    /// Returns an error for every retry, digest mismatch, post-terminal, or
    /// otherwise absent lifecycle edge.
    pub fn apply(self, event: ProposalEventV1) -> Result<Self, EffectError> {
        match (self, event) {
            (Self::Received, ProposalEventV1::Compiled { proposal }) => {
                Ok(Self::Ready { proposal })
            }
            (Self::Received, ProposalEventV1::Refused { refusal }) => Ok(Self::Refused { refusal }),
            (Self::Received, ProposalEventV1::Indeterminate { envelope }) => {
                Ok(Self::Indeterminate { envelope })
            }
            (
                Self::Ready { proposal: expected },
                ProposalEventV1::BurnAuthorization {
                    proposal,
                    authorization,
                    family,
                },
            ) if expected == proposal => Ok(Self::AuthorizationBurned {
                proposal,
                authorization,
                family,
            }),
            (
                Self::AuthorizationBurned {
                    proposal,
                    family: EffectFamilyV1::CodePromotion,
                    ..
                },
                ProposalEventV1::BeginPreparation { attempt },
            ) => Ok(Self::Preparing { proposal, attempt }),
            (
                Self::AuthorizationBurned {
                    proposal, family, ..
                },
                ProposalEventV1::BeginExecution { attempt },
            ) if family != EffectFamilyV1::CodePromotion => Ok(Self::Executing {
                proposal,
                attempt,
                preparation_checkpoint: None,
            }),
            (
                Self::Preparing { proposal, attempt },
                ProposalEventV1::CommitMayProceed { checkpoint },
            ) => Ok(Self::Executing {
                proposal,
                attempt,
                preparation_checkpoint: Some(checkpoint),
            }),
            (Self::AuthorizationBurned { .. }, ProposalEventV1::ExecutionAbandoned { receipt })
            | (Self::Preparing { .. }, ProposalEventV1::PreparationFailed { receipt })
            | (Self::Preparing { .. }, ProposalEventV1::PreparationAbandoned { receipt })
            | (Self::Executing { .. }, ProposalEventV1::ExecutionFailed { receipt }) => {
                Ok(Self::Failed { receipt })
            }
            (Self::Preparing { .. }, ProposalEventV1::PreparationIndeterminate { envelope })
            | (Self::Executing { .. }, ProposalEventV1::ExecutionIndeterminate { envelope }) => {
                Ok(Self::ReconciliationRequired { envelope })
            }
            (Self::Executing { .. }, ProposalEventV1::ExecutionSucceeded { receipt }) => {
                Ok(Self::Succeeded { receipt })
            }
            (Self::ReconciliationRequired { .. }, ProposalEventV1::Reconciled { receipt }) => {
                Ok(Self::Reconciled { receipt })
            }
            (state, event) => Err(EffectError::InvalidTransition {
                state: format!("{state:?}"),
                event: format!("{event:?}"),
            }),
        }
    }
}

/// Closed effect-model errors.
#[derive(Clone, Debug, Error, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "code",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EffectError {
    /// Catalog identifier is malformed.
    #[error("invalid target identifier: {0}")]
    InvalidTargetId(String),
    /// Version is not recognized.
    #[error("unknown effect schema: {0}")]
    UnknownSchema(String),
    /// Root-owned catalog contract is not recognized.
    #[error("unknown effect catalog schema: {0}")]
    UnknownCatalogSchema(String),
    /// Intent is structurally invalid.
    #[error("malformed proposal intent")]
    MalformedIntent,
    /// An artifact was not among admitted custody references.
    #[error("artifact was not admitted: {0}")]
    ArtifactNotAdmitted(Digest),
    /// Target is not in the root-owned catalog.
    #[error("unknown target: {0:?}")]
    UnknownTarget(TargetId),
    /// Target has no broker observation.
    #[error("missing broker observation: {0:?}")]
    MissingObservation(TargetId),
    /// Catalog target kind and intent differ.
    #[error("target kind does not match intent: {0:?}")]
    TargetKindMismatch(TargetId),
    /// Target identity changed during preparation.
    #[error("target identity mismatch: {0:?}")]
    TargetIdentityMismatch(TargetId),
    /// Managed repository contains worktree or index changes.
    #[error("managed-pointer target is dirty: {0:?}")]
    PromotionTargetDirty(TargetId),
    /// Managed ref is attached to a checked-out worktree.
    #[error("managed pointer names a checked-out ref: {0:?}")]
    PromotionReferenceCheckedOut(TargetId),
    /// Candidate commit is not based directly on the observed managed ref.
    #[error("managed-pointer candidate has the wrong base: {0:?}")]
    PromotionBaseMismatch(TargetId),
    /// Root-owned promotion definition is empty or unbounded.
    #[error("invalid managed-pointer definition: {0:?}")]
    InvalidPromotionDefinition(TargetId),
    /// Broker-clock expiry cannot be represented without wrapping.
    #[error("managed-pointer expiry overflow")]
    PromotionExpiryOverflow,
    /// A path resolved to a symlink or non-regular object.
    #[error("unsafe target object: {0:?}")]
    UnsafeTarget(TargetId),
    /// Requested closed operation was not enabled in the catalog.
    #[error("action not allowed for target: {0:?}")]
    ActionNotAllowed(TargetId),
    /// Git object name was not exact SHA-1/SHA-256 hex.
    #[error("invalid Git object identity: {0}")]
    InvalidGitObject(String),
    /// JCS serialization failed.
    #[error("canonical serialization failed: {0}")]
    Canonical(String),
    /// Canonical body no longer matches its digest.
    #[error("canonical proposal digest mismatch")]
    CanonicalDigestMismatch,
    /// Bounded mandate does not cover this exact context.
    #[error("bounded mandate does not apply")]
    MandateNotApplicable,
    /// Host mandate scope is empty, incoherent, foreign, or includes promotion.
    #[error("invalid bounded host mandate")]
    InvalidHostMandate,
    /// Host mandate body no longer matches its installed digest.
    #[error("bounded host mandate digest mismatch")]
    MandateDigestMismatch,
    /// Code promotion cannot travel through a host-effect mandate.
    #[error("code promotion requires human exact or derived authority")]
    PromotionRequiresSeparateAuthority,
    /// Proposal lifecycle edge is forbidden.
    #[error("invalid proposal transition from {state} using {event}")]
    InvalidTransition {
        /// Prior state.
        state: String,
        /// Attempted event.
        event: String,
    },
}

impl EffectError {
    /// Returns whether this compiler error is a semantic refusal attributable
    /// to the submitted intent and current broker-owned target/catalog facts.
    /// Internal custody, observation, canonicalization, mandate, and lifecycle
    /// failures are deliberately excluded; callers must keep those
    /// operationally indeterminate.
    #[must_use]
    pub const fn is_semantic_compilation_refusal(&self) -> bool {
        matches!(
            self,
            Self::InvalidTargetId(_)
                | Self::UnknownSchema(_)
                | Self::MalformedIntent
                | Self::ArtifactNotAdmitted(_)
                | Self::UnknownTarget(_)
                | Self::TargetKindMismatch(_)
                | Self::TargetIdentityMismatch(_)
                | Self::PromotionTargetDirty(_)
                | Self::PromotionReferenceCheckedOut(_)
                | Self::PromotionBaseMismatch(_)
                | Self::UnsafeTarget(_)
                | Self::ActionNotAllowed(_)
                | Self::InvalidGitObject(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposer(domain: &AuthorityDomain, epoch: Epoch, label: &[u8]) -> PrincipalChainV1 {
        let proposer_id = ag_primitives::PrincipalId::new(Digest::hash_bytes(label));
        PrincipalChainV1::new(
            domain.clone(),
            epoch,
            vec![ag_primitives::PrincipalChainNodeV1::root(
                proposer_id,
                ag_primitives::PrincipalKindV1::Operator,
            )],
        )
        .expect("proposer chain")
    }

    fn try_compile_with_governor_source(
        source: Digest,
        regular_file: bool,
    ) -> Result<CanonicalEffectProposalV1, EffectError> {
        let domain = AuthorityDomain::parse("test-host").expect("domain");
        let epoch = Epoch::parse("1").expect("epoch");
        let proposer = proposer(&domain, epoch, b"proposer");
        let target = TargetId::parse("managed-config").expect("target");
        let content = Digest::hash_bytes(b"new content");
        let catalog = EffectCatalogV1 {
            schema: EFFECT_CATALOG_SCHEMA_V1.to_owned(),
            identity: Digest::hash_bytes(b"catalog"),
            targets: BTreeMap::from([(
                target.clone(),
                TargetDefinitionV1::ManagedFile {
                    path: "/etc/example/config".to_owned(),
                    mode: 0o640,
                    uid: 0,
                    gid: 0,
                },
            )]),
        };
        let intent = ProposalIntentV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            intent_id: "intent-1".to_owned(),
            authority_domain: domain,
            epoch,
            proposer,
            judgment: Digest::hash_bytes(b"judgment"),
            admitted_artifacts: BTreeSet::from([content.clone()]),
            effects: vec![EffectIntentV1::ManagedFilePut {
                target: target.clone(),
                content,
            }],
        };
        let observations = BTreeMap::from([(
            target,
            TargetObservationV1::ManagedFile {
                current_content: None,
                regular_file,
            },
        )]);
        EffectCompilerV1::new(catalog, Digest::hash_bytes(b"security-profile")).compile(
            "proposal-1".to_owned(),
            &intent,
            &intent.proposer,
            source,
            1_000,
            &observations,
        )
    }

    fn compile_with_governor_source(source: Digest) -> CanonicalEffectProposalV1 {
        try_compile_with_governor_source(source, true).expect("compile")
    }

    fn try_compile_promotion(
        clean: bool,
        reference_checked_out: bool,
        candidate_parent: String,
        compiled_at_unix_ms: u64,
        promotion_ttl_ms: u64,
    ) -> Result<CanonicalEffectProposalV1, EffectError> {
        let domain = AuthorityDomain::parse("promotion-host").expect("domain");
        let epoch = Epoch::parse("7").expect("epoch");
        let proposer = proposer(&domain, epoch, b"promotion-proposer");
        let target = TargetId::parse("release.main").expect("target");
        let artifact = Digest::hash_bytes(b"exact candidate bundle");
        let catalog = EffectCatalogV1 {
            schema: EFFECT_CATALOG_SCHEMA_V1.to_owned(),
            identity: Digest::hash_bytes(b"promotion-catalog"),
            targets: BTreeMap::from([(
                target.clone(),
                TargetDefinitionV1::ManagedPointer {
                    allowed_root: "/srv/governed".to_owned(),
                    repository: "service.git".to_owned(),
                    reference: "refs/heads/main".to_owned(),
                    repository_identity: Digest::hash_bytes(b"repository-identity"),
                    uid: 1200,
                    gid: 1200,
                    staging_root: "/var/lib/ag-effectd/promotion-stage".to_owned(),
                    promotion_ttl_ms,
                    helper_executable: Digest::hash_bytes(b"helper-executable"),
                    helper_launch_profile: Digest::hash_bytes(b"helper-profile"),
                },
            )]),
        };
        let intent = ProposalIntentV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            intent_id: "candidate-1".to_owned(),
            authority_domain: domain,
            epoch,
            proposer,
            judgment: Digest::hash_bytes(b"promotion-judgment"),
            admitted_artifacts: BTreeSet::from([artifact.clone()]),
            effects: vec![EffectIntentV1::ManagedPointerPromotion {
                target: target.clone(),
                artifact,
            }],
        };
        let observations = BTreeMap::from([(
            target,
            TargetObservationV1::ManagedPointer {
                current_object: "1".repeat(40),
                current_tree: "2".repeat(40),
                candidate_object: "3".repeat(40),
                candidate_tree: "4".repeat(40),
                candidate_parent,
                candidate_pack_digest: Digest::hash_bytes(b"normalized-pack"),
                object_format: GitObjectFormatV1::Sha1,
                repository_identity: Digest::hash_bytes(b"repository-identity"),
                prestate_identity: Digest::hash_bytes(b"prestate-layout-identity"),
                repository_device: 8,
                repository_inode: 101,
                git_directory_device: 8,
                git_directory_inode: 102,
                repository_uid: 1200,
                repository_gid: 1200,
                clean,
                reference_checked_out,
            },
        )]);
        EffectCompilerV1::new(catalog, Digest::hash_bytes(b"effectd-security-profile")).compile(
            "proposal-promotion-1".to_owned(),
            &intent,
            &intent.proposer,
            Digest::hash_bytes(b"governor-authentication"),
            compiled_at_unix_ms,
            &observations,
        )
    }

    #[test]
    fn target_ids_are_not_paths() {
        assert!(TargetId::parse("web.production").is_ok());
        assert!(TargetId::parse("../../etc/shadow").is_err());
        assert!(TargetId::parse("unit/name").is_err());
    }

    #[test]
    fn compiler_refusal_classification_never_launders_operational_failure() {
        let target = TargetId::parse("managed-config").expect("target");
        assert!(EffectError::UnsafeTarget(target.clone()).is_semantic_compilation_refusal());
        assert!(EffectError::UnknownTarget(target).is_semantic_compilation_refusal());
        assert!(
            !EffectError::MissingObservation(TargetId::parse("managed-config").expect("target"))
                .is_semantic_compilation_refusal()
        );
        assert!(
            !EffectError::Canonical("allocator failure".to_owned())
                .is_semantic_compilation_refusal()
        );
        assert!(
            !EffectError::InvalidTransition {
                state: "ready".to_owned(),
                event: "retry".to_owned(),
            }
            .is_semantic_compilation_refusal()
        );
    }

    #[test]
    fn non_regular_managed_file_observation_is_not_ratifiable_as_absent() {
        assert!(matches!(
            try_compile_with_governor_source(Digest::hash_bytes(b"source"), false),
            Err(EffectError::UnsafeTarget(_))
        ));
    }

    #[test]
    fn no_execution_retry_edge_exists() {
        let receipt = Digest::hash_bytes(b"failure");
        let state = ProposalStateV1::Failed {
            receipt: receipt.clone(),
        };
        assert!(
            state
                .apply(ProposalEventV1::BeginExecution {
                    attempt: Digest::hash_bytes(b"second attempt"),
                })
                .is_err()
        );
    }

    #[test]
    fn promotion_cannot_use_host_mandate() {
        let target = TargetId::parse("release").expect("valid target");
        let family = EffectIntentV1::ManagedPointerPromotion {
            target,
            artifact: Digest::hash_bytes(b"candidate-bundle"),
        }
        .family();
        assert_eq!(family, EffectFamilyV1::CodePromotion);
        assert_ne!(family, EffectFamilyV1::ManagedFile);
    }

    #[test]
    fn promotion_compilation_binds_broker_derived_operation_and_exact_poststate() {
        let proposal = try_compile_promotion(true, false, "1".repeat(40), 10_000, 5_000)
            .expect("promotion compiles");
        assert_eq!(proposal.body().compiled_at_unix_ms, 10_000);
        assert_eq!(proposal.body().catalog_schema, EFFECT_CATALOG_SCHEMA_V1);
        assert_eq!(
            proposal.body().security_profile_identity,
            Digest::hash_bytes(b"effectd-security-profile")
        );
        let CanonicalEffectV1::ManagedPointerPromotion {
            schema,
            operation_id,
            artifact,
            candidate_pack_digest,
            prestate_identity,
            expected_object,
            expected_tree,
            new_object,
            expected_post_tree,
            expires_unix_ms,
            ..
        } = &proposal.body().effects[0]
        else {
            panic!("expected managed pointer")
        };
        assert_eq!(schema, MANAGED_POINTER_PROMOTION_SCHEMA_V1);
        assert_ne!(operation_id, artifact);
        assert_eq!(artifact, &Digest::hash_bytes(b"exact candidate bundle"));
        assert_eq!(
            candidate_pack_digest,
            &Digest::hash_bytes(b"normalized-pack")
        );
        assert_eq!(
            prestate_identity,
            &Digest::hash_bytes(b"prestate-layout-identity")
        );
        assert_eq!(expected_object, &"1".repeat(40));
        assert_eq!(expected_tree, &"2".repeat(40));
        assert_eq!(new_object, &"3".repeat(40));
        assert_eq!(expected_post_tree, &"4".repeat(40));
        assert_eq!(*expires_unix_ms, 15_000);
    }

    #[test]
    fn promotion_refuses_dirty_checked_out_wrong_base_and_expiry_overflow() {
        assert!(matches!(
            try_compile_promotion(false, false, "1".repeat(40), 1, 1),
            Err(EffectError::PromotionTargetDirty(_))
        ));
        assert!(matches!(
            try_compile_promotion(true, true, "1".repeat(40), 1, 1),
            Err(EffectError::PromotionReferenceCheckedOut(_))
        ));
        assert!(matches!(
            try_compile_promotion(true, false, "9".repeat(40), 1, 1),
            Err(EffectError::PromotionBaseMismatch(_))
        ));
        assert_eq!(
            try_compile_promotion(true, false, "1".repeat(40), 1, u64::MAX),
            Err(EffectError::PromotionExpiryOverflow)
        );
    }

    #[test]
    fn promotion_requires_preparation_checkpoint_before_execution() {
        let proposal = Digest::hash_bytes(b"proposal");
        let authorization = Digest::hash_bytes(b"authorization");
        let attempt = Digest::hash_bytes(b"attempt");
        let checkpoint = Digest::hash_bytes(b"checkpoint");
        let burned = ProposalStateV1::Ready {
            proposal: proposal.clone(),
        }
        .apply(ProposalEventV1::BurnAuthorization {
            proposal: proposal.clone(),
            authorization,
            family: EffectFamilyV1::CodePromotion,
        })
        .expect("burn promotion authority");
        assert!(
            burned
                .clone()
                .apply(ProposalEventV1::BeginExecution {
                    attempt: attempt.clone(),
                })
                .is_err()
        );
        let preparing = burned
            .apply(ProposalEventV1::BeginPreparation {
                attempt: attempt.clone(),
            })
            .expect("begin reversible preparation");
        assert_eq!(
            preparing
                .clone()
                .apply(ProposalEventV1::CommitMayProceed {
                    checkpoint: checkpoint.clone(),
                })
                .expect("arm commit"),
            ProposalStateV1::Executing {
                proposal,
                attempt,
                preparation_checkpoint: Some(checkpoint),
            }
        );
        assert!(matches!(
            preparing
                .apply(ProposalEventV1::PreparationIndeterminate {
                    envelope: Digest::hash_bytes(b"preparation-uncertainty"),
                })
                .expect("poison uncertain preparation"),
            ProposalStateV1::ReconciliationRequired { .. }
        ));
    }

    #[test]
    fn canonical_bytes_bind_the_signed_governor_source() {
        let first_source = Digest::hash_bytes(b"agd-principal-key-a");
        let second_source = Digest::hash_bytes(b"agd-principal-key-b");
        let first = compile_with_governor_source(first_source.clone());
        let second = compile_with_governor_source(second_source);
        assert_eq!(first.body().governor_authentication, first_source);
        assert_ne!(first.digest(), second.digest());
    }
}
