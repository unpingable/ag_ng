//! Stable principals and enforceable principal-chain separation.

use core::fmt;
use core::str::FromStr;
use std::collections::HashSet;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    AuthorityDomainId, Digest, EpochId, InferenceBudgetV1, InferenceEnvelopeV1, JcsDocument,
    LifecycleNonce,
};

const MAX_NAME_LENGTH: usize = 128;

macro_rules! strict_name_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validates and constructs a ", $description, ".")]
            ///
            /// # Errors
            ///
            /// Returns an error when the identifier is empty, too long, or
            /// outside the canonical lowercase identifier alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, PrincipalNameError> {
                let value = value.into();
                validate_name(stringify!($name), &value)?;
                Ok(Self(value))
            }

            #[doc = concat!("Parses a ", $description, ".")]
            ///
            /// # Errors
            ///
            /// Returns an error unless `value` is a canonical identifier.
            pub fn parse(value: &str) -> Result<Self, PrincipalNameError> {
                Self::new(value)
            }

            /// Returns the canonical text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = PrincipalNameError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct NameVisitor;

                impl Visitor<'_> for NameVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a bounded canonical principal identifier")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::parse(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(NameVisitor)
            }
        }
    };
}

strict_name_type!(EnrollmentId, "stable enrollment identifier");
strict_name_type!(RoleId, "configured role identifier");
strict_name_type!(ProjectId, "project identifier");
strict_name_type!(SessionId, "session identifier");
strict_name_type!(SystemdUnitIdentity, "systemd unit identity");
strict_name_type!(BootIdentity, "host boot identity");
strict_name_type!(CgroupIdentity, "cgroup identity");

/// Alias documenting a digest that commits to a complete worker input set.
pub type InputSetIdentity = Digest;

/// An exact executable identity.
///
/// A path is deliberately absent: pathname admission is neither byte identity
/// nor a defense against replacement between check and launch.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentityV1 {
    /// SHA-256 of the exact executable bytes.
    pub sha256: Digest,
    /// Exact byte length.
    pub size: u64,
    /// Optional platform build identity, additionally bound when available.
    pub build_identity: Option<Digest>,
}

impl ExecutableIdentityV1 {
    /// Constructs an exact executable identity.
    #[must_use]
    pub const fn new(sha256: Digest, size: u64, build_identity: Option<Digest>) -> Self {
        Self {
            sha256,
            size,
            build_identity,
        }
    }
}

/// Identity of an admitted helper or service launch profile.
///
/// `profile_digest` commits to the argv template, sanitized environment,
/// UID/GID policy, namespace and mount setup, seccomp/Landlock rules,
/// cgroup/rlimits, working directory, and descriptor-role table.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchProfileIdentityV1 {
    /// Digest of the exact launch profile.
    pub profile_digest: Digest,
    /// Digest of the exact helper protocol/schema accepted by that profile.
    pub protocol_schema_digest: Digest,
}

impl LaunchProfileIdentityV1 {
    /// Constructs a pinned launch-profile identity.
    #[must_use]
    pub const fn new(profile_digest: Digest, protocol_schema_digest: Digest) -> Self {
        Self {
            profile_digest,
            protocol_schema_digest,
        }
    }
}

/// Peer credentials observed at an authenticated local transport boundary.
///
/// These observations help bind a live connection, but they are never a stable
/// principal by themselves.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCredentialObservationV1 {
    /// Observed effective UID.
    pub uid: u32,
    /// Observed effective GID.
    pub gid: u32,
    /// Observed process ID.
    pub pid: u32,
    /// Observed cgroup/unit membership identity.
    pub cgroup: CgroupIdentity,
}

/// Provider access bound into one worker-session principal.
///
/// The constrained variant contains only configured, credential-free policy.
/// Provider credentials and arbitrary network endpoints are structurally
/// absent.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerProviderRouteV1 {
    /// The worker has no provider channel or inference capability.
    Offline,
    /// The worker may use exactly one constrained provider policy envelope.
    Constrained {
        /// Exact root-owned provider-policy revision.
        provider_policy_digest: Digest,
        /// Closed endpoint/model/method/protocol envelope.
        envelope: InferenceEnvelopeV1,
        /// Maximum cumulative provider use.
        budget: InferenceBudgetV1,
    },
}

/// Current lifecycle state of an enrolled operator or service principal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalEnrollmentStateV1 {
    /// The enrollment may currently authenticate.
    Active,
    /// The enrollment was revoked and cannot authenticate.
    Revoked,
}

/// A human/operator principal enrolled into one authority epoch.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPrincipalV1 {
    /// Authority domain in which this principal exists.
    pub authority_domain: AuthorityDomainId,
    /// Authority epoch in which this principal exists.
    pub epoch: EpochId,
    /// Stable enrollment record identity.
    pub enrollment_id: EnrollmentId,
    /// Configured role, used only after enrollment authentication.
    pub configured_role: RoleId,
    /// Exact enrollment-policy revision.
    pub enrollment_policy_digest: Digest,
    /// Distinguishes reenrollment under the same human account.
    pub enrollment_lifecycle_nonce: LifecycleNonce,
    /// Current authenticated lifecycle state.
    pub enrollment_state: PrincipalEnrollmentStateV1,
    /// Credential observations bound during authentication.
    pub observed_credentials: HostCredentialObservationV1,
}

/// An AG-ng daemon instance principal.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonPrincipalV1 {
    /// Authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Authority epoch.
    pub epoch: EpochId,
    /// Closed configured component role.
    pub configured_role: RoleId,
    /// Expected service-manager unit identity.
    pub service_unit: SystemdUnitIdentity,
    /// Exact executable bytes/build identity.
    pub executable: ExecutableIdentityV1,
    /// Exact launch and protocol profile.
    pub launch_profile: LaunchProfileIdentityV1,
    /// Unique nonce for this service activation.
    pub service_instance_nonce: LifecycleNonce,
    /// Host boot identity.
    pub boot_identity: BootIdentity,
    /// Credentials observed on the authenticated connection.
    pub observed_credentials: HostCredentialObservationV1,
}

/// An independently enrolled service such as Nightshift.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePrincipalV1 {
    /// Authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Authority epoch.
    pub epoch: EpochId,
    /// Stable service enrollment.
    pub enrollment_id: EnrollmentId,
    /// Closed configured service role.
    pub configured_role: RoleId,
    /// Expected service-manager unit identity.
    pub service_unit: SystemdUnitIdentity,
    /// Exact executable bytes/build identity.
    pub executable: ExecutableIdentityV1,
    /// Exact launch and protocol profile.
    pub launch_profile: LaunchProfileIdentityV1,
    /// Unique nonce for this service activation.
    pub service_instance_nonce: LifecycleNonce,
    /// Host boot identity.
    pub boot_identity: BootIdentity,
    /// Current enrollment state.
    pub enrollment_state: PrincipalEnrollmentStateV1,
    /// Credentials observed on the authenticated connection.
    pub observed_credentials: HostCredentialObservationV1,
}

/// A contained, transient worker session principal.
///
/// Recycled Linux UID/PID values are not sufficient identities by themselves.
/// They remain bound observations inside the full principal identity, whose
/// non-reusability comes from the session nonce, launcher lineage, admitted
/// executable/profile, workspace, key policy, and exact input set.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSessionPrincipalV1 {
    /// Authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Authority epoch.
    pub epoch: EpochId,
    /// Governed project.
    pub project: ProjectId,
    /// Session record identifier.
    pub session_id: SessionId,
    /// Unique nonce for this session lifecycle.
    pub session_nonce: LifecycleNonce,
    /// Exact daemon instance that launched the worker.
    pub launcher: PrincipalId,
    /// Exact worker executable identity.
    pub executable: ExecutableIdentityV1,
    /// Exact containment/launch profile.
    pub launch_profile: LaunchProfileIdentityV1,
    /// Exact proposal-workspace construction identity.
    pub proposal_workspace_identity: Digest,
    /// Exact deployment security-profile identity.
    pub security_profile_identity: Digest,
    /// Exact reviewed candidate signing-key binding, excluding this principal ID.
    pub candidate_ingress_key_identity: Digest,
    /// Exclusive end of this principal's lifetime, Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Maximum candidate bytes accepted across worker output sinks.
    pub output_budget_bytes: u64,
    /// Explicit constrained provider route or reviewed offline mode.
    pub provider_route: WorkerProviderRouteV1,
    /// Digest of the complete admitted input set.
    pub input_set_digest: Digest,
    /// Transient host credential observations.
    pub observed_credentials: HostCredentialObservationV1,
}

/// Closed principal variants admitted by AG-ng v1.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "principal_kind",
    content = "principal",
    rename_all = "snake_case"
)]
pub enum PrincipalV1 {
    /// Human/operator enrollment.
    Operator(OperatorPrincipalV1),
    /// AG-ng daemon instance.
    Daemon(DaemonPrincipalV1),
    /// Independently enrolled local service.
    Service(ServicePrincipalV1),
    /// Contained worker session.
    WorkerSession(Box<WorkerSessionPrincipalV1>),
}

impl PrincipalV1 {
    /// Returns this principal's stable, kind-separated identity digest.
    ///
    /// # Panics
    ///
    /// This cannot panic for a value constructed through the public API: all
    /// principal fields have strict integer-only JCS representations.
    #[must_use]
    pub fn id(&self) -> PrincipalId {
        let document = JcsDocument::canonicalize(self)
            .expect("principal schemas contain only strict JCS-compatible values");
        PrincipalId::new(Digest::hash_domain(
            "ag-ng/principal/v1",
            document.as_bytes(),
        ))
    }

    /// Returns the closed principal kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKindV1 {
        match self {
            Self::Operator(_) => PrincipalKindV1::Operator,
            Self::Daemon(_) => PrincipalKindV1::Daemon,
            Self::Service(_) => PrincipalKindV1::Service,
            Self::WorkerSession(_) => PrincipalKindV1::WorkerSession,
        }
    }

    /// Returns the principal authority domain.
    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainId {
        match self {
            Self::Operator(value) => &value.authority_domain,
            Self::Daemon(value) => &value.authority_domain,
            Self::Service(value) => &value.authority_domain,
            Self::WorkerSession(value) => &value.authority_domain,
        }
    }

    /// Returns the principal authority epoch.
    #[must_use]
    pub const fn epoch(&self) -> EpochId {
        match self {
            Self::Operator(value) => value.epoch,
            Self::Daemon(value) => value.epoch,
            Self::Service(value) => value.epoch,
            Self::WorkerSession(value) => value.epoch,
        }
    }
}

/// Compatibility alias for the closed v1 principal family.
pub type Principal = PrincipalV1;

/// Stable digest identity of a fully bound principal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(Digest);

impl PrincipalId {
    /// Wraps an exact kind-separated principal digest.
    #[must_use]
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

macro_rules! principal_id_method {
    ($type:ty, $variant:ident) => {
        impl $type {
            /// Returns the stable, fully bound principal identity.
            #[must_use]
            pub fn id(&self) -> PrincipalId {
                PrincipalV1::$variant(self.clone()).id()
            }
        }
    };
}

principal_id_method!(OperatorPrincipalV1, Operator);
principal_id_method!(DaemonPrincipalV1, Daemon);
principal_id_method!(ServicePrincipalV1, Service);
impl WorkerSessionPrincipalV1 {
    /// Returns the stable, fully bound principal identity.
    #[must_use]
    pub fn id(&self) -> PrincipalId {
        PrincipalV1::WorkerSession(Box::new(self.clone())).id()
    }
}

/// Closed principal-kind tag retained in a lineage chain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKindV1 {
    /// Human/operator principal.
    Operator,
    /// AG daemon principal.
    Daemon,
    /// Independently enrolled service.
    Service,
    /// Contained worker session.
    WorkerSession,
}

/// One node in a linear authenticated launch/delegation chain.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalChainNodeV1 {
    /// Exact principal identity at this node.
    pub principal_id: PrincipalId,
    /// Closed kind used by the independence predicate.
    pub kind: PrincipalKindV1,
    /// Immediate parent, absent only for the stable root.
    pub parent: Option<PrincipalId>,
}

impl PrincipalChainNodeV1 {
    /// Constructs a root node.
    #[must_use]
    pub const fn root(principal_id: PrincipalId, kind: PrincipalKindV1) -> Self {
        Self {
            principal_id,
            kind,
            parent: None,
        }
    }

    /// Constructs a node directly descended from `parent`.
    #[must_use]
    pub const fn child(
        principal_id: PrincipalId,
        kind: PrincipalKindV1,
        parent: PrincipalId,
    ) -> Self {
        Self {
            principal_id,
            kind,
            parent: Some(parent),
        }
    }
}

/// A validated linear principal lineage from stable root to active leaf.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PrincipalChainV1 {
    authority_domain: AuthorityDomainId,
    epoch: EpochId,
    nodes: Vec<PrincipalChainNodeV1>,
}

impl PrincipalChainV1 {
    /// Validates and constructs a principal chain.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalChainError`] for an empty chain, transient root,
    /// broken parent link, or repeated principal.
    pub fn new(
        authority_domain: AuthorityDomainId,
        epoch: EpochId,
        nodes: Vec<PrincipalChainNodeV1>,
    ) -> Result<Self, PrincipalChainError> {
        validate_chain(&nodes)?;
        Ok(Self {
            authority_domain,
            epoch,
            nodes,
        })
    }

    /// Returns the authority domain shared by the chain.
    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainId {
        &self.authority_domain
    }

    /// Returns the authority epoch shared by the chain.
    #[must_use]
    pub const fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Returns the immutable ordered nodes.
    #[must_use]
    pub fn nodes(&self) -> &[PrincipalChainNodeV1] {
        &self.nodes
    }

    /// Returns the stable root node.
    #[must_use]
    pub fn root(&self) -> &PrincipalChainNodeV1 {
        &self.nodes[0]
    }

    /// Returns the active leaf node.
    ///
    /// # Panics
    ///
    /// This cannot panic because [`Self::new`] and deserialization both reject
    /// empty chains.
    #[must_use]
    pub fn leaf(&self) -> &PrincipalChainNodeV1 {
        self.nodes.last().expect("validated chains are nonempty")
    }

    /// Returns a digest committing to the complete ordered chain.
    ///
    /// # Panics
    ///
    /// This cannot panic for a validated chain because its schema contains
    /// only strict integer-only JCS values.
    #[must_use]
    pub fn id(&self) -> Digest {
        let document = JcsDocument::canonicalize(&PrincipalChainWire::from(self))
            .expect("principal-chain schemas contain only strict JCS-compatible values");
        Digest::hash_domain("ag-ng/principal-chain/v1", document.as_bytes())
    }

    /// Applies the default v1 independence predicate.
    #[must_use]
    pub fn independent_from(&self, ratifier: &Self) -> bool {
        self.satisfies(
            ratifier,
            PrincipalSeparationPredicateV1::DistinctRootsNoSharedLineage,
        )
        .is_ok()
    }

    /// Evaluates the exact named proposer/ratifier separation predicate.
    ///
    /// `self` is the proposing chain and `ratifier` is the purportedly
    /// independent chain. This direction matters for the descendant check.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalSeparationFailure`] with the first stable failed
    /// condition in the named predicate.
    pub fn satisfies(
        &self,
        ratifier: &Self,
        predicate: PrincipalSeparationPredicateV1,
    ) -> Result<(), PrincipalSeparationFailure> {
        match predicate {
            PrincipalSeparationPredicateV1::DistinctRootsNoSharedLineage => {
                self.check_distinct_roots_no_shared_lineage(ratifier)
            }
        }
    }

    fn check_distinct_roots_no_shared_lineage(
        &self,
        ratifier: &Self,
    ) -> Result<(), PrincipalSeparationFailure> {
        if self.authority_domain != ratifier.authority_domain || self.epoch != ratifier.epoch {
            return Err(PrincipalSeparationFailure::AuthorityContextMismatch);
        }
        if self.root().principal_id == ratifier.root().principal_id {
            return Err(PrincipalSeparationFailure::SameStableRoot);
        }
        if ratifier
            .nodes
            .iter()
            .any(|node| node.principal_id == self.leaf().principal_id)
        {
            return Err(PrincipalSeparationFailure::RatifierDescendsFromProposer);
        }

        let proposer_workers: HashSet<&PrincipalId> = self
            .nodes
            .iter()
            .filter(|node| node.kind == PrincipalKindV1::WorkerSession)
            .map(|node| &node.principal_id)
            .collect();
        if ratifier.nodes.iter().any(|node| {
            node.kind == PrincipalKindV1::WorkerSession
                && proposer_workers.contains(&node.principal_id)
        }) {
            return Err(PrincipalSeparationFailure::SharedWorkerAncestor);
        }

        let proposer_nodes: HashSet<&PrincipalId> =
            self.nodes.iter().map(|node| &node.principal_id).collect();
        if ratifier
            .nodes
            .iter()
            .any(|node| proposer_nodes.contains(&node.principal_id))
        {
            return Err(PrincipalSeparationFailure::SharedPrincipal);
        }
        Ok(())
    }
}

impl Serialize for PrincipalChainV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PrincipalChainWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PrincipalChainV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PrincipalChainOwnedWire::deserialize(deserializer)?;
        Self::new(wire.authority_domain, wire.epoch, wire.nodes).map_err(de::Error::custom)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PrincipalChainWireRef<'a> {
    authority_domain: &'a AuthorityDomainId,
    epoch: EpochId,
    nodes: &'a [PrincipalChainNodeV1],
}

impl<'a> From<&'a PrincipalChainV1> for PrincipalChainWireRef<'a> {
    fn from(value: &'a PrincipalChainV1) -> Self {
        Self {
            authority_domain: &value.authority_domain,
            epoch: value.epoch,
            nodes: &value.nodes,
        }
    }
}

// The short alias keeps call sites in `id` readable while serialization still
// borrows rather than cloning a potentially long chain.
type PrincipalChainWire<'a> = PrincipalChainWireRef<'a>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalChainOwnedWire {
    authority_domain: AuthorityDomainId,
    epoch: EpochId,
    nodes: Vec<PrincipalChainNodeV1>,
}

/// The v1 named independence rule stored by a ratifier grant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalSeparationPredicateV1 {
    /// Same authority context, distinct stable roots, no shared principal or
    /// worker lineage, and no ratifier descended from the proposer leaf.
    DistinctRootsNoSharedLineage,
}

/// A malformed principal chain.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PrincipalChainError {
    /// Chains must contain a stable root.
    #[error("principal chain must not be empty")]
    Empty,
    /// A transient worker cannot be a stable root.
    #[error("worker-session principal cannot be a stable chain root")]
    WorkerRoot,
    /// The root incorrectly names a parent.
    #[error("principal-chain root must not name a parent")]
    RootHasParent,
    /// A child does not point to the immediately preceding node.
    #[error("principal-chain parent mismatch at node {index}")]
    ParentMismatch {
        /// Failing node index.
        index: usize,
    },
    /// The same principal appears twice, permitting cyclic/replayed lineage.
    #[error("principal-chain repeats a principal at node {index}")]
    DuplicatePrincipal {
        /// Failing node index.
        index: usize,
    },
}

/// A failed proposer/ratifier independence check.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PrincipalSeparationFailure {
    /// Cross-domain or cross-epoch chains cannot establish local independence.
    #[error("principal chains belong to different authority domains or epochs")]
    AuthorityContextMismatch,
    /// Both chains descend from the same stable root.
    #[error("proposer and ratifier share the same stable principal root")]
    SameStableRoot,
    /// The ratifier chain descends from the exact proposer leaf.
    #[error("ratifier principal chain descends from the proposer")]
    RatifierDescendsFromProposer,
    /// Both chains contain the same worker-session ancestor.
    #[error("proposer and ratifier share a worker-session ancestor")]
    SharedWorkerAncestor,
    /// Both chains share some other identity despite differently labeled roots.
    #[error("proposer and ratifier share a principal in their lineage")]
    SharedPrincipal,
}

/// A strict principal-name validation error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PrincipalNameError {
    /// Empty names are forbidden.
    #[error("{kind} must not be empty")]
    Empty {
        /// Identifier family.
        kind: &'static str,
    },
    /// Names are bounded at protocol boundaries.
    #[error("{kind} exceeds {maximum} bytes (got {actual})")]
    TooLong {
        /// Identifier family.
        kind: &'static str,
        /// Maximum admitted length.
        maximum: usize,
        /// Actual length.
        actual: usize,
    },
    /// Name is outside the canonical lowercase identifier alphabet.
    #[error("{kind} is not a canonical lowercase AG-ng identifier")]
    NonCanonical {
        /// Identifier family.
        kind: &'static str,
    },
}

fn validate_name(kind: &'static str, value: &str) -> Result<(), PrincipalNameError> {
    if value.is_empty() {
        return Err(PrincipalNameError::Empty { kind });
    }
    if value.len() > MAX_NAME_LENGTH {
        return Err(PrincipalNameError::TooLong {
            kind,
            maximum: MAX_NAME_LENGTH,
            actual: value.len(),
        });
    }
    let bytes = value.as_bytes();
    let endpoint = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let admitted = |byte: u8| endpoint(byte) || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/');
    if !endpoint(bytes[0])
        || !endpoint(bytes[bytes.len() - 1])
        || !bytes.iter().copied().all(admitted)
    {
        return Err(PrincipalNameError::NonCanonical { kind });
    }
    Ok(())
}

fn validate_chain(nodes: &[PrincipalChainNodeV1]) -> Result<(), PrincipalChainError> {
    let Some(root) = nodes.first() else {
        return Err(PrincipalChainError::Empty);
    };
    if root.kind == PrincipalKindV1::WorkerSession {
        return Err(PrincipalChainError::WorkerRoot);
    }
    if root.parent.is_some() {
        return Err(PrincipalChainError::RootHasParent);
    }

    let mut seen = HashSet::new();
    for (index, node) in nodes.iter().enumerate() {
        if !seen.insert(&node.principal_id) {
            return Err(PrincipalChainError::DuplicatePrincipal { index });
        }
        if index > 0 && node.parent.as_ref() != Some(&nodes[index - 1].principal_id) {
            return Err(PrincipalChainError::ParentMismatch { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InferenceMethodId, ModelId, ProviderEndpointId};

    fn digest(label: &str) -> Digest {
        Digest::hash_bytes(label.as_bytes())
    }

    fn principal_id(label: &str) -> PrincipalId {
        PrincipalId::new(digest(label))
    }

    fn domain() -> AuthorityDomainId {
        AuthorityDomainId::new("site:prod").unwrap()
    }

    fn epoch() -> EpochId {
        EpochId::new(3).unwrap()
    }

    fn chain(root: &str, worker: &str) -> PrincipalChainV1 {
        let root_id = principal_id(root);
        PrincipalChainV1::new(
            domain(),
            epoch(),
            vec![
                PrincipalChainNodeV1::root(root_id.clone(), PrincipalKindV1::Daemon),
                PrincipalChainNodeV1::child(
                    principal_id(worker),
                    PrincipalKindV1::WorkerSession,
                    root_id,
                ),
            ],
        )
        .unwrap()
    }

    fn worker_principal() -> WorkerSessionPrincipalV1 {
        WorkerSessionPrincipalV1 {
            authority_domain: domain(),
            epoch: epoch(),
            project: ProjectId::new("project-alpha").unwrap(),
            session_id: SessionId::new("session-1").unwrap(),
            session_nonce: LifecycleNonce::new([3; 16]),
            launcher: principal_id("agd-launcher"),
            executable: ExecutableIdentityV1::new(digest("worker-exe"), 128, None),
            launch_profile: LaunchProfileIdentityV1::new(
                digest("worker-profile"),
                digest("worker-protocol"),
            ),
            proposal_workspace_identity: digest("proposal-workspace"),
            security_profile_identity: digest("security-profile"),
            candidate_ingress_key_identity: digest("candidate-ingress-key-identity"),
            expires_at_unix_ms: 20_000,
            output_budget_bytes: 4096,
            provider_route: WorkerProviderRouteV1::Constrained {
                provider_policy_digest: digest("provider-policy"),
                envelope: InferenceEnvelopeV1 {
                    endpoint: ProviderEndpointId::new("fixture:primary").unwrap(),
                    model: ModelId::new("fixture-model").unwrap(),
                    method: InferenceMethodId::new("complete").unwrap(),
                    protocol_digest: digest("provider-protocol"),
                },
                budget: InferenceBudgetV1 {
                    requests: 2,
                    input_bytes: 1024,
                    output_bytes: 2048,
                    cost_microunits: 10,
                },
            },
            input_set_digest: digest("input-set"),
            observed_credentials: HostCredentialObservationV1 {
                uid: 900,
                gid: 901,
                pid: 902,
                cgroup: CgroupIdentity::new("worker-1.scope").unwrap(),
            },
        }
    }

    #[test]
    fn executable_and_launch_identity_roundtrip_strictly() {
        let identity = ExecutableIdentityV1::new(digest("exe"), 42, Some(digest("build")));
        let launch = LaunchProfileIdentityV1::new(digest("profile"), digest("schema"));
        let json = serde_json::to_string(&(identity.clone(), launch.clone())).unwrap();
        let decoded: (ExecutableIdentityV1, LaunchProfileIdentityV1) =
            serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, (identity, launch));
    }

    #[test]
    fn principal_id_binds_kind_and_every_observation() {
        let credentials = HostCredentialObservationV1 {
            uid: 900,
            gid: 900,
            pid: 111,
            cgroup: CgroupIdentity::new("worker-1.scope").unwrap(),
        };
        let daemon = DaemonPrincipalV1 {
            authority_domain: domain(),
            epoch: epoch(),
            configured_role: RoleId::new("agd").unwrap(),
            service_unit: SystemdUnitIdentity::new("agd.service").unwrap(),
            executable: ExecutableIdentityV1::new(digest("agd"), 10, None),
            launch_profile: LaunchProfileIdentityV1::new(digest("launch"), digest("schema")),
            service_instance_nonce: LifecycleNonce::new([1; 16]),
            boot_identity: BootIdentity::new("00000000-0000-0000-0000-000000000001").unwrap(),
            observed_credentials: credentials,
        };
        let original = daemon.id();
        let mut reused_uid = daemon;
        reused_uid.service_instance_nonce = LifecycleNonce::new([2; 16]);
        assert_ne!(original, reused_uid.id());
    }

    #[test]
    fn worker_principal_id_binds_workspace_profile_expiry_budgets_and_route() {
        let worker = worker_principal();
        let original = worker.id();

        let mut changed = worker.clone();
        changed.proposal_workspace_identity = digest("other-workspace");
        assert_ne!(changed.id(), original);

        let mut changed = worker.clone();
        changed.security_profile_identity = digest("other-profile");
        assert_ne!(changed.id(), original);

        let mut changed = worker.clone();
        changed.candidate_ingress_key_identity = digest("other-ingress-key-identity");
        assert_ne!(changed.id(), original);

        let mut changed = worker.clone();
        changed.expires_at_unix_ms += 1;
        assert_ne!(changed.id(), original);

        let mut changed = worker.clone();
        changed.output_budget_bytes += 1;
        assert_ne!(changed.id(), original);

        let mut changed = worker;
        changed.provider_route = WorkerProviderRouteV1::Offline;
        assert_ne!(changed.id(), original);
    }

    #[test]
    fn worker_provider_route_roundtrips_strictly() {
        let worker = worker_principal();
        let json = serde_json::to_value(&worker).unwrap();
        assert_eq!(
            serde_json::from_value::<WorkerSessionPrincipalV1>(json.clone()).unwrap(),
            worker
        );
        let mut with_unknown = json;
        with_unknown["provider_route"]["credential"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<WorkerSessionPrincipalV1>(with_unknown).is_err());
    }

    #[test]
    fn chain_constructor_rejects_worker_root_bad_parent_and_replay() {
        assert_eq!(
            PrincipalChainV1::new(
                domain(),
                epoch(),
                vec![PrincipalChainNodeV1::root(
                    principal_id("worker"),
                    PrincipalKindV1::WorkerSession,
                )],
            )
            .unwrap_err(),
            PrincipalChainError::WorkerRoot
        );

        let root = principal_id("root");
        let wrong = PrincipalChainV1::new(
            domain(),
            epoch(),
            vec![
                PrincipalChainNodeV1::root(root, PrincipalKindV1::Daemon),
                PrincipalChainNodeV1::child(
                    principal_id("leaf"),
                    PrincipalKindV1::Service,
                    principal_id("wrong"),
                ),
            ],
        );
        assert!(matches!(
            wrong,
            Err(PrincipalChainError::ParentMismatch { index: 1 })
        ));
    }

    #[test]
    fn chain_deserialization_revalidates_structure() {
        let root = principal_id("root");
        let valid = chain("root", "worker");
        let mut json = serde_json::to_value(&valid).unwrap();
        json["nodes"][1]["parent"] = serde_json::to_value(principal_id("forged")).unwrap();
        assert!(serde_json::from_value::<PrincipalChainV1>(json).is_err());
        assert_eq!(valid.root().principal_id, root);
    }

    #[test]
    fn independence_requires_distinct_stable_lineage() {
        let proposal = chain("agd-root", "worker-a");
        let independent = PrincipalChainV1::new(
            domain(),
            epoch(),
            vec![PrincipalChainNodeV1::root(
                principal_id("nightshift-root"),
                PrincipalKindV1::Service,
            )],
        )
        .unwrap();
        assert!(proposal.independent_from(&independent));

        let shared_root = chain("agd-root", "worker-b");
        assert_eq!(
            proposal
                .satisfies(
                    &shared_root,
                    PrincipalSeparationPredicateV1::DistinctRootsNoSharedLineage,
                )
                .unwrap_err(),
            PrincipalSeparationFailure::SameStableRoot
        );
    }

    #[test]
    fn relabeling_a_shared_worker_cannot_create_independence() {
        let proposal = chain("agd-root", "worker-a");
        let other_root = principal_id("nightshift-root");
        let shared_worker = proposal.leaf().principal_id.clone();
        let ratifier = PrincipalChainV1::new(
            domain(),
            epoch(),
            vec![
                PrincipalChainNodeV1::root(other_root.clone(), PrincipalKindV1::Service),
                PrincipalChainNodeV1::child(
                    shared_worker,
                    PrincipalKindV1::WorkerSession,
                    other_root,
                ),
            ],
        )
        .unwrap();
        assert!(!proposal.independent_from(&ratifier));
        assert!(matches!(
            proposal.satisfies(
                &ratifier,
                PrincipalSeparationPredicateV1::DistinctRootsNoSharedLineage
            ),
            Err(PrincipalSeparationFailure::RatifierDescendsFromProposer
                | PrincipalSeparationFailure::SharedWorkerAncestor)
        ));
    }

    #[test]
    fn foreign_epoch_is_not_independence_evidence() {
        let proposal = chain("agd-root", "worker-a");
        let foreign = PrincipalChainV1::new(
            domain(),
            EpochId::new(4).unwrap(),
            vec![PrincipalChainNodeV1::root(
                principal_id("nightshift-root"),
                PrincipalKindV1::Service,
            )],
        )
        .unwrap();
        assert_eq!(
            proposal
                .satisfies(
                    &foreign,
                    PrincipalSeparationPredicateV1::DistinctRootsNoSharedLineage
                )
                .unwrap_err(),
            PrincipalSeparationFailure::AuthorityContextMismatch
        );
    }
}
