//! Root-owned daemon configuration and startup validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use ag_effect::{SystemdUnitActionV1, TargetId};
use ag_primitives::{
    AuthorityDomain, Digest, Epoch, ExecutableIdentityV1, InferenceBudgetV1,
    InferenceEnvelopeV1, PrincipalKindV1, ProjectId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::rpc_auth::{
    RpcAuthError, RpcPeerEnrollmentV1, RpcPeerKeyPolicyV1, RpcSigningIdentityConfigV1,
};

/// Maximum exact bytes accepted by every TOML configuration loader.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const PROVIDER_RPC_STRUCTURAL_RESERVE_BYTES: u64 = 128 * 1024;
// Candidate content occurs once in the worker proof on each RPC wire. This
// reserve covers the complete signed principal/session/intent envelopes around
// that one canonical base64 value.
const WORKER_RPC_STRUCTURAL_RESERVE_BYTES: u64 = 128 * 1024;
const PROVIDER_MAX_DEADLINE_MS: u64 = 1_800_000;
const PROVIDER_MIN_EVENT_STREAM_BYTES: u64 = 4 * 1024;
const MAX_PROMOTION_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const MANAGED_FILE_CANDIDATE_SEMANTIC_V1: &str = "managed_file_content_v1";
const MANAGED_POINTER_CANDIDATE_SEMANTIC_V1: &str = "git_bundle_promotion_v1";

/// Store paths common to every daemon.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfigV1 {
    /// `SQLite` database path.
    pub database: PathBuf,
    /// Content-addressed object root.
    pub object_store: PathBuf,
    /// Exact filesystem custody expected before and after opening the store.
    pub store_custody: StoreCustodyConfigV1,
}

/// Exact owner, group, and mode for one filesystem node.
///
/// Directory modes include the set-group-ID bit when it is part of the
/// deployment contract. Runtime validation compares all permission and
/// special bits exactly; values are never inferred from the process umask.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemNodeCustodyV1 {
    /// Numeric owner expected from site enrollment.
    pub uid: u32,
    /// Numeric group expected from site enrollment.
    pub gid: u32,
    /// Exact Unix permission and special bits.
    pub mode: u32,
}

/// Store filesystem custody policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCustodyConfigV1 {
    /// Immediate parent of the database and writer-lock files.
    pub database_parent: FilesystemNodeCustodyV1,
    /// Content-addressed object-store root.
    pub object_store: FilesystemNodeCustodyV1,
    /// `SQLite` database file.
    pub database: FilesystemNodeCustodyV1,
    /// Single-writer lock file adjacent to the database.
    pub writer_lock: FilesystemNodeCustodyV1,
}

/// Filesystem custody policy for one listening Unix socket.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketCustodyConfigV1 {
    /// Pre-created immediate parent. Its exact mode includes the mandatory
    /// set-group-ID bit used to establish the socket's configured group.
    pub parent: FilesystemNodeCustodyV1,
    /// Final socket node after bind and mode installation.
    pub node: FilesystemNodeCustodyV1,
}

/// Stable peer enrollment plus optional kernel lifecycle expectations.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicyV1 {
    /// Canonical configured role.
    pub role: String,
    /// Exact numeric UID for an optional `SO_PEERCRED` defense-in-depth check.
    pub uid: u32,
    /// Exact numeric GID for an optional `SO_PEERCRED` defense-in-depth check.
    pub gid: u32,
    /// Legacy executable observation; not a stable identity or signed-RPC prerequisite.
    pub executable_identity: Option<Digest>,
    /// Legacy cgroup observation; not a stable identity or signed-RPC prerequisite.
    pub cgroup_contains: Option<String>,
    /// Stable enrolled root of the principal chain.
    pub stable_principal_root: Digest,
    /// Closed principal kind for this role.
    pub principal_kind: PrincipalKindV1,
    /// Cryptographic key enrollment which establishes the peer identity.
    pub rpc_key: RpcPeerKeyPolicyV1,
}

impl PeerPolicyV1 {
    /// Reconstructs the cryptographic peer enrollment from root-owned policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid clock-skew policy or inconsistent
    /// signed-principal binding.
    pub fn rpc_enrollment(&self) -> Result<RpcPeerEnrollmentV1, RpcAuthError> {
        RpcPeerEnrollmentV1::new(self.rpc_key.principal.clone(), self.rpc_key.clone())
    }
}

/// Optional kernel-credential constraint for one cryptographically enrolled
/// daemon reached by one role-specific `agctl` profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgctlSocketPeerCheckV1 {
    /// Record `SO_PEERCRED` only. The Ed25519 enrollment remains the identity.
    ObserveOnly,
    /// Require an exact UID/GID as defense in depth in addition to Ed25519.
    RequireUidGid {
        /// Expected kernel UID.
        uid: u32,
        /// Expected kernel primary GID.
        gid: u32,
    },
}

/// One stable daemon enrollment used by a role-specific CLI profile.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgctlDaemonPeerV1 {
    /// Exact Ed25519 principal, verification key, and skew policy.
    pub rpc_key: RpcPeerKeyPolicyV1,
    /// Explicit non-authoritative kernel observation policy.
    pub socket_peer: AgctlSocketPeerCheckV1,
}

/// Role-specific CLI resource limits.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgctlLimitsV1 {
    /// Maximum strict local frame.
    pub max_control_frame_bytes: u32,
    /// Maximum unexpired local-RPC proofs retained in this process.
    pub rpc_replay_capacity: u32,
}

/// One closed command plane for an `agctl` process and signing identity.
///
/// The tagged variants deliberately cannot deserialize the other plane's
/// socket or daemon enrollment.  Selecting a command profile is therefore an
/// enrollment decision, not a command-line convenience switch.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgctlCommandProfileV1 {
    /// Proposal ingress and governor health only.
    Proposer {
        /// Governor control socket.
        agd_socket: PathBuf,
        /// Governor daemon enrollment.
        agd_peer: AgctlDaemonPeerV1,
        /// Maximum exact intent document read from disk.
        max_intent_file_bytes: u64,
    },
    /// Direct effect-broker inspection and administration only.
    EffectAdmin {
        /// Direct effect-broker inspection/admin socket.
        effectd_admin_socket: PathBuf,
        /// Effect-broker daemon enrollment.
        effectd_peer: AgctlDaemonPeerV1,
    },
}

/// Root-owned, single-role `agctl` configuration.
///
/// Each proposer or effect administrator has its own signing identity and
/// exactly one daemon enrollment. Daemon configuration is not reused because
/// it also carries authority-bearing catalogs and service policy which the
/// CLI neither needs nor should parse.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgctlConfigV1 {
    /// Exact config schema.
    pub schema: String,
    /// `development`, `production`, or `high_assurance`.
    pub security_profile: String,
    /// Local role-specific Ed25519 identity loaded from an explicit credential.
    pub rpc_signing_identity: RpcSigningIdentityConfigV1,
    /// Exactly one authorized command plane and daemon enrollment.
    pub command_profile: AgctlCommandProfileV1,
    /// Explicit bounds; there are no implicit production defaults.
    pub limits: AgctlLimitsV1,
}

/// Governor resource limits.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgdLimitsV1 {
    /// Maximum strict local frame.
    pub max_control_frame_bytes: u32,
    /// Maximum unexpired signed-RPC nonces retained in memory.
    pub max_rpc_replay_entries: u32,
    /// Maximum ingested artifact.
    pub max_artifact_bytes: u64,
    /// Maximum simultaneously live sessions.
    pub max_active_sessions: u32,
    /// Maximum batch duration.
    pub max_session_seconds: u64,
}

/// Root-reviewed launch substrate for contained generic workers.
///
/// This configuration names exact executable bytes and fixed argument vectors;
/// it is not a command runner. The optional provider policy is credential-free
/// and remains fail-closed at
/// launch until the separate live request/response proxy is implemented.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLauncherConfigV1 {
    /// Stable daemon-chain root independently mirrored in effectd's agd peer
    /// enrollment. The live agd signing principal is the leaf when distinct.
    pub governor_principal_root: Digest,
    /// Exact skew policy under which workers verify the governor's one-shot
    /// challenge. Effectd requires this complete policy to equal its enrolled
    /// `agd_peer.rpc_key` before accepting durable worker proof.
    pub governor_challenge_maximum_clock_skew_ms: u64,
    /// Parent beneath which `agd` creates one independent proposal workspace
    /// for each non-reusable session.
    pub workspace_root: PathBuf,
    /// Exact expected custody of the already-created workspace root.
    pub workspace_root_custody: FilesystemNodeCustodyV1,
    /// Absolute path of the reviewed Bubblewrap executable.
    pub sandbox_executable: PathBuf,
    /// Exact bytes expected at `sandbox_executable`.
    pub sandbox_identity: ExecutableIdentityV1,
    /// Runtime roots admitted read-only into the otherwise empty sandbox.
    pub runtime_roots: Vec<PathBuf>,
    /// Closed set of workers selectable by identifier.
    pub profiles: Vec<WorkerProfileConfigV1>,
}

/// One fixed executable-to-candidate mapping reviewed in root-owned policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProfileConfigV1 {
    /// Closed selector accepted by the control API.
    pub profile_id: String,
    /// Governed project bound into the transient principal.
    pub project: String,
    /// Absolute worker executable locator, revalidated against the retained
    /// descriptor immediately before launch.
    pub executable: PathBuf,
    /// Exact executable bytes approved for this profile.
    pub executable_identity: ExecutableIdentityV1,
    /// Exact arguments following the fixed sandbox executable name. No shell
    /// or implicit `PATH` interpretation occurs.
    pub fixed_arguments: Vec<String>,
    /// Closed effect family to which accepted candidate bytes are mapped by
    /// `agd`; the worker never receives or selects this value.
    pub candidate_effect: WorkerCandidateEffectV1,
    /// Only catalog target to which accepted candidate bytes are mapped by
    /// `agd`; the worker never receives or selects this value.
    pub candidate_target: String,
    /// Closed semantic label required on the candidate frame.
    pub candidate_semantic_type: String,
    /// Exclusive wall-clock runtime limit.
    pub timeout_ms: u64,
    /// Exact cumulative candidate-output bound.
    pub output_budget_bytes: u64,
    /// Optional root-enrolled provider policy. This is inert until the
    /// governor's worker/session proxy contract is available; launch refuses
    /// rather than silently treating this as an offline profile.
    #[serde(default)]
    pub provider_access: Option<WorkerProviderProfileConfigV1>,
}

/// Credential-free provider envelope and cumulative budget enrolled for one
/// fixed worker profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProviderProfileConfigV1 {
    /// Exact digest of the independently enrolled providerd policy.
    pub provider_policy_digest: Digest,
    /// Closed endpoint/model/method/protocol selection.
    pub envelope: InferenceEnvelopeV1,
    /// Maximum cumulative provider use for the worker session.
    pub budget: InferenceBudgetV1,
}

/// Closed interpretation of one worker candidate selected by reviewed policy.
/// This is deliberately not a generic command or caller-selected effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerCandidateEffectV1 {
    /// Candidate bytes are the complete content of one managed file.
    ManagedFilePut,
    /// Candidate bytes are one versioned Git-bundle promotion artifact.
    ManagedPointerPromotion,
}

impl WorkerCandidateEffectV1 {
    /// Returns the only candidate semantic admitted for this closed mapping.
    #[must_use]
    pub const fn semantic_type(self) -> &'static str {
        match self {
            Self::ManagedFilePut => MANAGED_FILE_CANDIDATE_SEMANTIC_V1,
            Self::ManagedPointerPromotion => MANAGED_POINTER_CANDIDATE_SEMANTIC_V1,
        }
    }
}

/// `agd` configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgdConfigV1 {
    /// Exact config schema.
    pub schema: String,
    /// `development`, `production`, or `high_assurance`.
    pub security_profile: String,
    /// Authority domain.
    pub authority_domain: String,
    /// Revocation epoch.
    pub epoch: String,
    /// Store paths.
    #[serde(flatten)]
    pub store: StoreConfigV1,
    /// Operator control socket.
    pub control_socket: PathBuf,
    /// Exact parent and final-node custody for the control socket.
    pub control_socket_custody: SocketCustodyConfigV1,
    /// Effect broker proposal socket.
    pub effectd_proposal_socket: PathBuf,
    /// Provider broker socket.
    pub providerd_socket: PathBuf,
    /// Local Ed25519 identity loaded from a systemd credential.
    pub rpc_signing_identity: RpcSigningIdentityConfigV1,
    /// Exact original proposal signer accepted on the governor ingress.
    pub proposer_peer: PeerPolicyV1,
    /// Authenticated effect-broker policy for outbound responses.
    pub effectd_peer: PeerPolicyV1,
    /// Optional closed worker catalog. Absence disables worker launch without
    /// affecting the existing external proposer path.
    #[serde(default)]
    pub worker_launcher: Option<WorkerLauncherConfigV1>,
    /// Resource limits.
    pub limits: AgdLimitsV1,
}

/// Effect-broker resource limits.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectdLimitsV1 {
    /// Maximum strict local frame.
    pub max_control_frame_bytes: u32,
    /// Maximum unexpired signed-RPC nonces retained in memory.
    pub max_rpc_replay_entries: u32,
    /// Maximum effects in one proposal.
    pub max_plan_steps: u32,
    /// Maximum ready proposals retained.
    pub max_ready_proposals: u32,
    /// Maximum decoded size of one transferred admitted artifact.
    pub max_artifact_bytes: u64,
}

/// One root-owned effect target.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum EffectTargetConfigV1 {
    /// Git managed-ref target.
    ManagedPointer {
        /// Opaque catalog ID.
        id: String,
        /// Root beneath which the repository must resolve.
        allowed_root: PathBuf,
        /// Canonically resolved repository strictly beneath `allowed_root`.
        repository: PathBuf,
        /// Exact ref.
        reference: String,
        /// Exact reviewed object selected before this authority store has any
        /// successful activation history for the target.
        activation_genesis_object: String,
        /// Exact tree selected by `activation_genesis_object`.
        activation_genesis_tree: String,
        /// Exact descriptor-bound state identity of the reviewed genesis ref.
        activation_genesis_state: Digest,
        /// Repository configuration identity.
        repository_identity: Digest,
        /// Numeric target owner under which Git mutation executes.
        uid: u32,
        /// Numeric target group under which Git mutation executes.
        gid: u32,
        /// Broker-controlled root for staging the exact candidate bundle.
        staging_root: PathBuf,
        /// Maximum lifetime of broker-compiled promotion authority.
        promotion_ttl_ms: u64,
        /// Pinned Git executable used by the closed internal adapter.
        helper: PathBuf,
        /// Exact Git executable bytes.
        helper_executable: Digest,
        /// Exact fixed Git operation, argv, environment, and descriptor profile.
        helper_launch_profile: Digest,
    },
    /// Managed regular file.
    ManagedFile {
        /// Opaque catalog ID.
        id: String,
        /// Exact absolute destination.
        path: PathBuf,
        /// Final Unix mode.
        mode: u32,
        /// Final owner.
        uid: u32,
        /// Final group.
        gid: u32,
    },
    /// Closed systemd unit.
    SystemdUnit {
        /// Opaque catalog ID.
        id: String,
        /// Escaped unit name.
        unit: String,
        /// Closed allowed operations.
        allowed_actions: Vec<SystemdUnitActionV1>,
    },
    /// systemd manager reload endpoint.
    SystemdManager {
        /// Opaque catalog ID.
        id: String,
    },
}

/// `ag-effectd` configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectdConfigV1 {
    /// Exact config schema.
    pub schema: String,
    /// Security profile.
    pub security_profile: String,
    /// Authority domain.
    pub authority_domain: String,
    /// Revocation epoch.
    pub epoch: String,
    /// Store paths.
    #[serde(flatten)]
    pub store: StoreConfigV1,
    /// Governor-facing socket.
    pub proposal_socket: PathBuf,
    /// Exact parent and final-node custody for the proposal socket.
    pub proposal_socket_custody: SocketCustodyConfigV1,
    /// Direct inspection/admin socket.
    pub admin_socket: PathBuf,
    /// Exact parent and final-node custody for the admin socket.
    pub admin_socket_custody: SocketCustodyConfigV1,
    /// Local Ed25519 identity loaded from a systemd credential.
    pub rpc_signing_identity: RpcSigningIdentityConfigV1,
    /// Exact governor service identity allowed to submit intent.
    pub agd_peer: PeerPolicyV1,
    /// Exact original proposer enrollment independently verified from the
    /// forwarded proposer-to-governor exchange.
    pub proposer_peer: PeerPolicyV1,
    /// Exact operator CLI/service identity allowed to inspect/ratify.
    pub admin_peer: PeerPolicyV1,
    /// Resource limits.
    pub limits: EffectdLimitsV1,
    /// Root-owned catalog.
    pub targets: Vec<EffectTargetConfigV1>,
}

/// Provider limits.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLimitsV1 {
    /// Maximum strict local frame.
    pub max_control_frame_bytes: u32,
    /// Maximum unexpired signed-RPC nonces retained in memory.
    pub max_rpc_replay_entries: u32,
    /// Maximum in-flight calls.
    pub max_concurrent_requests: u32,
    /// Hard provider HTTP request/response deadline. This must leave time for
    /// durable custody and the signed local-RPC response.
    pub provider_deadline_ms: u64,
    /// Maximum exact request bytes.
    pub max_request_bytes: u64,
    /// Maximum canonical complete event-stream custody bytes. This is the
    /// accounting domain, before its base64 local-wire encoding.
    pub max_response_bytes: u64,
}

/// Root-owned worst-case policy for one exact provider model/deployment.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderModelPolicyConfigV1 {
    /// Exact model/deployment identifier admitted in capability envelopes.
    pub id: String,
    /// Maximum canonical complete event-stream custody bytes reserved for one
    /// dispatch. This includes status, sanitized headers, terminal marker, and
    /// the canonical base64 representation of the exact provider body.
    pub max_event_stream_bytes: u64,
    /// Nonzero root-owned worst-case price reserved before network dispatch.
    pub worst_case_cost_microunits: u64,
}

/// One fixed local command transport owned by `ag-providerd`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCommandConfigV1 {
    /// Closed argument/output adapter (`codex`, `claude-code`, or `kimi-code`).
    pub adapter: String,
    /// Whether the fixed adapter must pass the capability model as an explicit
    /// command argument or invoke the operator-enrolled provider default.
    pub model_argument: ProviderCommandModelArgumentV1,
    /// Absolute executable path measured by deployment qualification.
    pub executable: PathBuf,
    /// Absolute fixed working directory; never selected by a request.
    pub working_directory: PathBuf,
    /// Closed, root-owned child environment. The provider daemon's own
    /// environment (including its credential directory) is never inherited.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

/// Root-owned model-selection behavior for a command-backed provider.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCommandModelArgumentV1 {
    /// Pass the exact capability model through the adapter's fixed model flag.
    Required,
    /// Omit a model flag and use the operator-enrolled command default.
    Omit,
}

/// Redirect handling for an enrolled cleartext-local endpoint.
///
/// V1 deliberately admits only refusal. A redirect is returned as provider
/// evidence and is never followed to a target outside the enrolled origin.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLocalRedirectPolicyV1 {
    /// Do not follow redirects.
    Deny,
}

/// Explicit provider transport and authentication policy.
///
/// The tagged shape prevents an omitted credential from silently turning a
/// remote API into an unauthenticated route, and prevents a request from
/// selecting an executable or network destination.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderTransportConfigV1 {
    /// Credentialed remote HTTPS API. The credential is a protected filename,
    /// never secret material embedded in configuration.
    CredentialedHttpsApi {
        /// Exact root-owned HTTPS endpoint.
        url: String,
        /// Credential filename beneath the daemon credential directory.
        credential_name: String,
        /// Closed header receiving the credential.
        credential_header: String,
        /// Constant non-secret prefix prepended to the credential.
        credential_prefix: String,
    },
    /// Credentialless cleartext endpoint on an operator-enrolled local origin.
    LocalHttp {
        /// Exact root-owned HTTP endpoint.
        url: String,
        /// Closed origins which may receive this request.
        allowed_origins: Vec<String>,
        /// Explicit redirect disposition.
        redirect_policy: ProviderLocalRedirectPolicyV1,
    },
    /// Fixed command route using the executable's separately mounted login.
    Command {
        /// Closed executable/adapter/environment policy.
        command: ProviderCommandConfigV1,
    },
}

/// One closed provider backend.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEndpointConfigV1 {
    /// Root-owned endpoint ID referenced by capabilities.
    pub id: String,
    /// Exact transport and authentication variant.
    pub transport: ProviderTransportConfigV1,
    /// Root-owned constant non-secret headers required by the protocol adapter.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Closed model/deployment policies, including broker-owned reservations.
    pub models: Vec<ProviderModelPolicyConfigV1>,
    /// Exact protocol adapter.
    pub protocol: String,
    /// Closed inference method IDs mapped to POST for this adapter.
    pub methods: Vec<String>,
}

/// `ag-providerd` configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderdConfigV1 {
    /// Exact config schema.
    pub schema: String,
    /// Security profile.
    pub security_profile: String,
    /// Authority domain.
    pub authority_domain: String,
    /// Revocation epoch.
    pub epoch: String,
    /// Store paths.
    #[serde(flatten)]
    pub store: StoreConfigV1,
    /// Provider socket.
    pub socket: PathBuf,
    /// Exact parent and final-node custody for the provider socket.
    pub socket_custody: SocketCustodyConfigV1,
    /// Local Ed25519 identity loaded from a systemd credential.
    pub rpc_signing_identity: RpcSigningIdentityConfigV1,
    /// Exact governor/worker proxy identity.
    pub caller_peer: PeerPolicyV1,
    /// Resource limits.
    pub limits: ProviderLimitsV1,
    /// Closed endpoints.
    pub endpoints: Vec<ProviderEndpointConfigV1>,
}

/// Configuration failures are fatal before socket readiness.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Read failed.
    #[error("cannot read configuration {path}: {source}")]
    Read {
        /// Config path.
        path: PathBuf,
        /// I/O failure.
        source: std::io::Error,
    },
    /// TOML schema failed.
    #[error("invalid configuration {path}: {message}")]
    Decode {
        /// Config path.
        path: PathBuf,
        /// Decoder message.
        message: String,
    },
    /// Production file ownership/mode is unsafe.
    #[error("configuration file is not root-owned and non-writable by group/other: {0}")]
    UnsafeOwnership(PathBuf),
    /// Configuration is not one protected regular file opened without symlinks.
    #[error("configuration is not a protected regular file: {0}")]
    UnsafeConfigFile(PathBuf),
    /// Configuration exceeds the fixed parser input bound.
    #[error("configuration exceeds the {MAX_CONFIG_BYTES}-byte bound: {0}")]
    ConfigTooLarge(PathBuf),
    /// Required path is not absolute or is otherwise unsafe.
    #[error("unsafe configured path: {0}")]
    UnsafePath(PathBuf),
    /// Peer policy lacks a usable role or cryptographic enrollment.
    #[error("invalid cryptographic peer policy for role {0}")]
    WeakPeerPolicy(String),
    /// Local signing identity configuration is unsafe.
    #[error("invalid local RPC signing identity configuration")]
    InvalidSigningIdentity,
    /// Config schema does not match daemon.
    #[error("unsupported configuration schema: {0}")]
    Schema(String),
    /// Bounds are zero or internally inconsistent.
    #[error("invalid configured resource limit: {0}")]
    InvalidLimit(&'static str),
    /// One provider entry is unsupported or internally inconsistent.
    #[error("invalid provider {provider}: {reason}")]
    InvalidProvider {
        /// Non-secret root-owned provider identifier.
        provider: String,
        /// Closed diagnostic reason which never includes credentials.
        reason: &'static str,
    },
    /// A filesystem custody policy is internally unsafe.
    #[error("invalid filesystem custody policy: {0}")]
    InvalidCustody(&'static str),
    /// Security profile is not one of the closed supported profiles.
    #[error("unsupported security profile: {0}")]
    SecurityProfile(String),
    /// Two separately authenticated local-RPC roles collapse to one identity.
    #[error("configured RPC principals are not distinct")]
    RpcPrincipalCollision,
    /// Separately held local-RPC roles reuse one verification key.
    #[error("configured RPC roles do not have separately held keys")]
    RpcKeyCollision,
    /// Separately authenticated roles collapse to one stable chain root.
    #[error("configured RPC roles do not have distinct stable roots")]
    RpcRootCollision,
    /// A peer is configured with a principal kind inappropriate for its
    /// closed protocol role.
    #[error("configured RPC peer has the wrong principal kind for role {0}")]
    UnexpectedPrincipalKind(String),
    /// Authority domain or epoch is not a canonical nonzero identifier.
    #[error("invalid authority domain or epoch")]
    InvalidAuthorityContext,
    /// A target family has no installed production observer/executor in this
    /// build and therefore cannot be configured honestly.
    #[error("configured effect target backend is unavailable: {0}")]
    UnsupportedTargetBackend(&'static str),
}

/// Strictly loads a TOML file and optionally enforces root custody.
///
/// The path is opened once with `O_NOFOLLOW`; ownership, mode, type, link
/// count, and bounded content are all taken from that same descriptor.
///
/// # Errors
///
/// Returns an error for an unsafe, oversized, unreadable, non-UTF-8, or
/// schema-invalid configuration file.
pub fn load_config<T: DeserializeOwned>(
    path: &Path,
    require_root_custody: bool,
) -> Result<T, ConfigError> {
    load_config_with_identity(path, require_root_custody).map(|loaded| loaded.config)
}

/// One strictly loaded configuration plus the digest of the exact bytes read
/// from the already validated descriptor.
#[derive(Clone, Debug)]
pub struct LoadedConfigV1<T> {
    /// Strictly decoded configuration.
    pub config: T,
    /// Digest of the exact bounded bytes accepted by the decoder.
    pub exact_bytes_digest: Digest,
}

/// Strictly loads a TOML file and preserves its exact descriptor-bound digest.
///
/// Daemons pass the returned digest to store startup, avoiding a second
/// pathname read when constructing their durable writer identity.
///
/// # Errors
///
/// Returns an error for an unsafe, oversized, unreadable, non-UTF-8, or
/// schema-invalid configuration file.
pub fn load_config_with_identity<T: DeserializeOwned>(
    path: &Path,
    require_root_custody: bool,
) -> Result<LoadedConfigV1<T>, ConfigError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(ConfigError::UnsafeConfigFile(path.to_owned()));
    }
    if require_root_custody && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0) {
        return Err(ConfigError::UnsafeOwnership(path.to_owned()));
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::ConfigTooLarge(path.to_owned()));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::ConfigTooLarge(path.to_owned()));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| ConfigError::Decode {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let config = toml::from_str(text).map_err(|error| ConfigError::Decode {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    Ok(LoadedConfigV1 {
        config,
        exact_bytes_digest: Digest::hash_bytes(&bytes),
    })
}

fn validate_absolute(paths: &[&Path]) -> Result<(), ConfigError> {
    for path in paths {
        let normalized: PathBuf = path.components().collect();
        if !path.is_absolute()
            || normalized != *path
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(ConfigError::UnsafePath((*path).to_owned()));
        }
    }
    Ok(())
}

fn validate_directory_custody(
    policy: &FilesystemNodeCustodyV1,
    field: &'static str,
    require_setgid: bool,
) -> Result<(), ConfigError> {
    let mode = policy.mode;
    if mode & !0o2777 != 0
        || mode & 0o700 != 0o700
        || mode & 0o022 != 0
        || ((mode & 0o2000 != 0) != require_setgid)
    {
        return Err(ConfigError::InvalidCustody(field));
    }
    Ok(())
}

fn validate_regular_file_custody(
    policy: &FilesystemNodeCustodyV1,
    field: &'static str,
) -> Result<(), ConfigError> {
    if policy.mode & !0o777 != 0 || policy.mode & 0o600 != 0o600 || policy.mode & 0o022 != 0 {
        return Err(ConfigError::InvalidCustody(field));
    }
    Ok(())
}

fn validate_store_custody(policy: &StoreCustodyConfigV1) -> Result<(), ConfigError> {
    validate_directory_custody(&policy.database_parent, "store database parent", false)?;
    validate_directory_custody(&policy.object_store, "store object root", false)?;
    validate_regular_file_custody(&policy.database, "store database")?;
    validate_regular_file_custody(&policy.writer_lock, "store writer lock")?;
    Ok(())
}

fn validate_socket_custody(policy: &SocketCustodyConfigV1) -> Result<(), ConfigError> {
    validate_directory_custody(&policy.parent, "socket parent", true)?;
    if policy.node.mode & !0o777 != 0
        || policy.node.mode & 0o600 != 0o600
        || policy.node.mode & 0o002 != 0
        || policy.node.gid != policy.parent.gid
    {
        return Err(ConfigError::InvalidCustody("socket node"));
    }
    Ok(())
}

fn validate_peer(peer: &PeerPolicyV1) -> Result<(), ConfigError> {
    if peer.role.is_empty() || peer.rpc_key.validate().is_err() {
        return Err(ConfigError::WeakPeerPolicy(peer.role.clone()));
    }
    Ok(())
}

fn validate_signer(signer: &RpcSigningIdentityConfigV1) -> Result<(), ConfigError> {
    signer
        .validate()
        .map_err(|_| ConfigError::InvalidSigningIdentity)
}

pub(crate) fn validate_security_profile(profile: &str) -> Result<(), ConfigError> {
    if matches!(profile, "development" | "production" | "high_assurance") {
        Ok(())
    } else {
        Err(ConfigError::SecurityProfile(profile.to_owned()))
    }
}

fn validate_authority_context(domain: &str, epoch: &str) -> Result<(), ConfigError> {
    AuthorityDomain::parse(domain)
        .and_then(|_| Epoch::parse(epoch).map(|_| ()))
        .map_err(|_| ConfigError::InvalidAuthorityContext)
}

fn validate_peer_kind(
    peer: &PeerPolicyV1,
    admitted: &[PrincipalKindV1],
) -> Result<(), ConfigError> {
    if admitted.contains(&peer.principal_kind) {
        Ok(())
    } else {
        Err(ConfigError::UnexpectedPrincipalKind(peer.role.clone()))
    }
}

fn validate_separate_roles(
    signer: &RpcSigningIdentityConfigV1,
    peers: &[&PeerPolicyV1],
) -> Result<(), ConfigError> {
    for (index, peer) in peers.iter().enumerate() {
        if signer.principal == peer.rpc_key.principal
            || signer.public_key == peer.rpc_key.public_key
            || signer.principal == peer.stable_principal_root
        {
            return Err(if signer.public_key == peer.rpc_key.public_key {
                ConfigError::RpcKeyCollision
            } else {
                ConfigError::RpcPrincipalCollision
            });
        }
        for other in &peers[..index] {
            if peer.rpc_key.public_key == other.rpc_key.public_key {
                return Err(ConfigError::RpcKeyCollision);
            }
            if peer.rpc_key.principal == other.rpc_key.principal {
                return Err(ConfigError::RpcPrincipalCollision);
            }
            if peer.stable_principal_root == other.stable_principal_root {
                return Err(ConfigError::RpcRootCollision);
            }
        }
    }
    Ok(())
}

fn validate_agctl_daemon_peer(
    name: &'static str,
    peer: &AgctlDaemonPeerV1,
) -> Result<(), ConfigError> {
    peer.rpc_key
        .validate()
        .map_err(|_| ConfigError::WeakPeerPolicy(name.to_owned()))
}

fn validate_agctl_separate_caller(
    signer: &RpcSigningIdentityConfigV1,
    peer: &AgctlDaemonPeerV1,
) -> Result<(), ConfigError> {
    if signer.principal == peer.rpc_key.principal {
        return Err(ConfigError::RpcPrincipalCollision);
    }
    if signer.public_key == peer.rpc_key.public_key {
        return Err(ConfigError::RpcKeyCollision);
    }
    Ok(())
}

fn validate_worker_launcher(
    launcher: &WorkerLauncherConfigV1,
    limits: &AgdLimitsV1,
) -> Result<(), ConfigError> {
    validate_absolute(&[&launcher.workspace_root, &launcher.sandbox_executable])?;
    validate_directory_custody(
        &launcher.workspace_root_custody,
        "worker workspace root",
        false,
    )?;
    if launcher.sandbox_identity.size == 0
        || launcher.governor_challenge_maximum_clock_skew_ms == 0
        || launcher.governor_challenge_maximum_clock_skew_ms > 300_000
        // Multi-worker scheduling is deliberately outside this vertical
        // slice. One live worker keeps deadline-critical polling isolated
        // from every potentially blocking authority operation.
        || limits.max_active_sessions != 1
        || launcher.runtime_roots != [PathBuf::from("/usr")]
        || launcher.profiles.is_empty()
        || launcher.profiles.len() > 1024
    {
        return Err(ConfigError::InvalidLimit("worker launcher"));
    }
    let mut runtime_roots = BTreeSet::new();
    for root in &launcher.runtime_roots {
        validate_absolute(&[root])?;
        if root != Path::new("/usr") || !runtime_roots.insert(root.clone()) {
            return Err(ConfigError::UnsafePath(root.clone()));
        }
    }

    let mut profile_ids = BTreeSet::new();
    for profile in &launcher.profiles {
        validate_absolute(&[&profile.executable])?;
        let expected_semantic_type = profile.candidate_effect.semantic_type();
        if !valid_policy_token(&profile.profile_id)
            || !profile_ids.insert(profile.profile_id.clone())
            || ProjectId::parse(&profile.project).is_err()
            || TargetId::parse(profile.candidate_target.clone()).is_err()
            || !valid_policy_token(&profile.candidate_semantic_type)
            || profile.candidate_semantic_type != expected_semantic_type
            || profile.executable_identity.size == 0
            || profile.fixed_arguments.len() > 64
            || profile.fixed_arguments.iter().any(|argument| {
                argument.is_empty() || argument.len() > 4096 || argument.as_bytes().contains(&0)
            })
            || profile.timeout_ms == 0
            || profile.timeout_ms > limits.max_session_seconds.saturating_mul(1000)
            // The one-shot challenge is delivered before release. A profile
            // cannot outlive the exact agd enrollment policy effectd checks.
            || profile.timeout_ms > launcher.governor_challenge_maximum_clock_skew_ms
            || profile.output_budget_bytes == 0
            || profile.output_budget_bytes > limits.max_artifact_bytes
            || profile
                .provider_access
                .as_ref()
                .is_some_and(|provider| !valid_worker_provider_profile(provider))
            || profile
                .output_budget_bytes
                .div_ceil(3)
                .checked_mul(4)
                .and_then(|encoded| encoded.checked_add(WORKER_RPC_STRUCTURAL_RESERVE_BYTES))
                .is_none_or(|wire_bound| wire_bound > u64::from(limits.max_control_frame_bytes))
        {
            return Err(ConfigError::InvalidLimit("worker profile"));
        }
    }
    Ok(())
}

fn valid_worker_provider_profile(profile: &WorkerProviderProfileConfigV1) -> bool {
    profile.budget.requests > 0
}

fn valid_policy_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_managed_git_ref(reference: &str) -> bool {
    let Some(relative) = reference.strip_prefix("refs/heads/") else {
        return false;
    };
    !relative.is_empty()
        && reference.len() <= 256
        && !relative.contains("..")
        && !relative.contains("@{")
        && relative.split('/').all(|component| {
            !component.is_empty()
                && !component.starts_with('.')
                && !component.ends_with('.')
                && !std::path::Path::new(component)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("lock"))
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

// Keep every authority-bearing target field explicit at this configuration
// boundary; hiding them in a loosely validated options bag would be worse.
#[allow(clippy::too_many_arguments)]
fn validate_managed_pointer_target(
    id: &str,
    allowed_root: &Path,
    repository: &Path,
    reference: &str,
    activation_genesis_object: &str,
    activation_genesis_tree: &str,
    uid: u32,
    gid: u32,
    staging_root: &Path,
    promotion_ttl_ms: u64,
    helper: &Path,
) -> Result<(), ConfigError> {
    validate_managed_pointer_enrollment_inputs(
        id,
        allowed_root,
        repository,
        reference,
        uid,
        gid,
        staging_root,
        promotion_ttl_ms,
        helper,
    )?;
    if !valid_git_object_name(activation_genesis_object)
        || !valid_git_object_name(activation_genesis_tree)
        || activation_genesis_object.len() != activation_genesis_tree.len()
    {
        return Err(ConfigError::InvalidLimit("managed-pointer target"));
    }
    Ok(())
}

/// Validate the operator-selected portion of a managed-pointer enrollment
/// before any live repository measurement is attempted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_managed_pointer_enrollment_inputs(
    id: &str,
    allowed_root: &Path,
    repository: &Path,
    reference: &str,
    uid: u32,
    gid: u32,
    staging_root: &Path,
    promotion_ttl_ms: u64,
    helper: &Path,
) -> Result<(), ConfigError> {
    validate_absolute(&[allowed_root, repository, staging_root, helper])?;
    let repository_relative = repository
        .strip_prefix(allowed_root)
        .map_err(|_| ConfigError::UnsafePath(repository.to_owned()))?;
    if TargetId::parse(id.to_owned()).is_err()
        || allowed_root == Path::new("/")
        || repository_relative.as_os_str().is_empty()
        || staging_root == Path::new("/")
        || staging_root.starts_with(allowed_root)
        || repository.starts_with(staging_root)
        || helper.starts_with(allowed_root)
        || helper.starts_with(staging_root)
        || !valid_managed_git_ref(reference)
        || uid == 0
        || gid == 0
        || uid == u32::MAX
        || gid == u32::MAX
        || promotion_ttl_ms == 0
        || promotion_ttl_ms > MAX_PROMOTION_TTL_MS
    {
        return Err(ConfigError::InvalidLimit("managed-pointer target"));
    }
    Ok(())
}

fn valid_git_object_name(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

impl AgctlConfigV1 {
    /// Validates the role-specific CLI's fail-closed endpoint and identity policy.
    ///
    /// # Errors
    ///
    /// Returns an error for schema/profile/path/limit drift, unsafe signing
    /// configuration, or a collapsed daemon/caller principal or key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != "ag.config.agctl.v1" {
            return Err(ConfigError::Schema(self.schema.clone()));
        }
        validate_security_profile(&self.security_profile)?;
        validate_signer(&self.rpc_signing_identity)?;
        let max_intent_file_bytes = match &self.command_profile {
            AgctlCommandProfileV1::Proposer {
                agd_socket,
                agd_peer,
                max_intent_file_bytes,
            } => {
                validate_absolute(&[agd_socket])?;
                validate_agctl_daemon_peer("agd", agd_peer)?;
                validate_agctl_separate_caller(&self.rpc_signing_identity, agd_peer)?;
                Some(*max_intent_file_bytes)
            }
            AgctlCommandProfileV1::EffectAdmin {
                effectd_admin_socket,
                effectd_peer,
            } => {
                validate_absolute(&[effectd_admin_socket])?;
                validate_agctl_daemon_peer("ag-effectd", effectd_peer)?;
                validate_agctl_separate_caller(&self.rpc_signing_identity, effectd_peer)?;
                None
            }
        };
        if self.limits.max_control_frame_bytes < 4096
            // One call records both the server challenge and response proof.
            || self.limits.rpc_replay_capacity < 2
            || self.limits.rpc_replay_capacity > 1_000_000
            || max_intent_file_bytes.is_some_and(|maximum| {
                maximum == 0
                    || maximum
                        .checked_add(65_536)
                        .is_none_or(|bound| bound > u64::from(self.limits.max_control_frame_bytes))
            })
        {
            return Err(ConfigError::InvalidLimit("agctl limits"));
        }
        Ok(())
    }
}

impl AgdConfigV1 {
    /// Validates the governor startup contract.
    ///
    /// # Errors
    ///
    /// Returns an error for schema, path, signing, peer-enrollment, or resource
    /// limit violations.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != "ag.config.agd.v1" {
            return Err(ConfigError::Schema(self.schema.clone()));
        }
        validate_security_profile(&self.security_profile)?;
        validate_authority_context(&self.authority_domain, &self.epoch)?;
        validate_absolute(&[
            &self.store.database,
            &self.store.object_store,
            &self.control_socket,
            &self.effectd_proposal_socket,
            &self.providerd_socket,
        ])?;
        validate_store_custody(&self.store.store_custody)?;
        validate_socket_custody(&self.control_socket_custody)?;
        validate_signer(&self.rpc_signing_identity)?;
        validate_peer(&self.proposer_peer)?;
        validate_peer(&self.effectd_peer)?;
        validate_peer_kind(
            &self.proposer_peer,
            &[PrincipalKindV1::Operator, PrincipalKindV1::Service],
        )?;
        validate_peer_kind(&self.effectd_peer, &[PrincipalKindV1::Daemon])?;
        validate_separate_roles(
            &self.rpc_signing_identity,
            &[&self.proposer_peer, &self.effectd_peer],
        )?;
        if self.limits.max_control_frame_bytes == 0
            || self.limits.max_rpc_replay_entries == 0
            || self.limits.max_active_sessions == 0
            || self.limits.max_session_seconds == 0
        {
            return Err(ConfigError::InvalidLimit("agd limits"));
        }
        if let Some(launcher) = &self.worker_launcher {
            if self.security_profile != "development" {
                return Err(ConfigError::InvalidLimit(
                    "worker launcher is development-only until production isolation is attested",
                ));
            }
            validate_worker_launcher(launcher, &self.limits)?;
        }
        Ok(())
    }
}

impl EffectdConfigV1 {
    /// Validates the privileged broker startup contract.
    ///
    /// # Errors
    ///
    /// Returns an error for schema, path, signing, peer, limit, target mode,
    /// helper path, or closed systemd-unit violations.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != "ag.config.effectd.v2" {
            return Err(ConfigError::Schema(self.schema.clone()));
        }
        validate_security_profile(&self.security_profile)?;
        validate_authority_context(&self.authority_domain, &self.epoch)?;
        validate_absolute(&[
            &self.store.database,
            &self.store.object_store,
            &self.proposal_socket,
            &self.admin_socket,
        ])?;
        validate_store_custody(&self.store.store_custody)?;
        validate_socket_custody(&self.proposal_socket_custody)?;
        validate_socket_custody(&self.admin_socket_custody)?;
        validate_signer(&self.rpc_signing_identity)?;
        validate_peer(&self.agd_peer)?;
        validate_peer(&self.proposer_peer)?;
        validate_peer(&self.admin_peer)?;
        validate_peer_kind(&self.agd_peer, &[PrincipalKindV1::Daemon])?;
        validate_peer_kind(
            &self.proposer_peer,
            &[PrincipalKindV1::Operator, PrincipalKindV1::Service],
        )?;
        validate_peer_kind(
            &self.admin_peer,
            &[PrincipalKindV1::Operator, PrincipalKindV1::Service],
        )?;
        validate_separate_roles(
            &self.rpc_signing_identity,
            &[&self.agd_peer, &self.proposer_peer, &self.admin_peer],
        )?;
        if self.limits.max_control_frame_bytes == 0
            || self.limits.max_rpc_replay_entries == 0
            || self.limits.max_plan_steps != 1
            || self.limits.max_ready_proposals == 0
            || self.limits.max_artifact_bytes == 0
        {
            return Err(ConfigError::InvalidLimit("effectd limits"));
        }
        for target in &self.targets {
            match target {
                EffectTargetConfigV1::ManagedPointer {
                    id,
                    allowed_root,
                    repository,
                    reference,
                    activation_genesis_object,
                    activation_genesis_tree,
                    uid,
                    gid,
                    staging_root,
                    promotion_ttl_ms,
                    helper,
                    ..
                } => validate_managed_pointer_target(
                    id,
                    allowed_root,
                    repository,
                    reference,
                    activation_genesis_object,
                    activation_genesis_tree,
                    *uid,
                    *gid,
                    staging_root,
                    *promotion_ttl_ms,
                    helper,
                )?,
                EffectTargetConfigV1::ManagedFile { path, mode, .. } => {
                    validate_absolute(&[path])?;
                    if mode & !0o0777 != 0 {
                        return Err(ConfigError::InvalidLimit(
                            "managed-file modes cannot include special bits",
                        ));
                    }
                }
                EffectTargetConfigV1::SystemdUnit { unit, .. } => {
                    if !valid_unit(unit) {
                        return Err(ConfigError::UnsafePath(PathBuf::from(unit)));
                    }
                    return Err(ConfigError::UnsupportedTargetBackend("systemd_unit"));
                }
                EffectTargetConfigV1::SystemdManager { .. } => {
                    return Err(ConfigError::UnsupportedTargetBackend("systemd_manager"));
                }
            }
        }
        Ok(())
    }
}

impl ProviderdConfigV1 {
    /// Validates provider daemon startup.
    ///
    /// # Errors
    ///
    /// Returns an error for schema, path, signing, peer, frame/response limit,
    /// endpoint, credential-header, model, method, or adapter violations.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != "ag.config.providerd.v2" {
            return Err(ConfigError::Schema(self.schema.clone()));
        }
        validate_security_profile(&self.security_profile)?;
        validate_authority_context(&self.authority_domain, &self.epoch)?;
        validate_absolute(&[&self.store.database, &self.store.object_store, &self.socket])?;
        validate_store_custody(&self.store.store_custody)?;
        validate_socket_custody(&self.socket_custody)?;
        validate_signer(&self.rpc_signing_identity)?;
        validate_peer(&self.caller_peer)?;
        // The original v1 path admitted only the governor daemon. A fixed,
        // independently enrolled service is also a valid terminal ingress:
        // it remains pinned by UID/GID and signed-RPC identity, and providerd
        // binds every capability use to that authenticated principal.
        // Dynamic worker sessions remain excluded.
        validate_peer_kind(
            &self.caller_peer,
            &[PrincipalKindV1::Daemon, PrincipalKindV1::Service],
        )?;
        validate_separate_roles(&self.rpc_signing_identity, &[&self.caller_peer])?;
        if self.limits.max_control_frame_bytes == 0
            || self.limits.max_rpc_replay_entries == 0
            || self.limits.max_concurrent_requests == 0
            || self.limits.provider_deadline_ms == 0
            || self.limits.max_request_bytes == 0
            || self.limits.max_response_bytes == 0
        {
            return Err(ConfigError::InvalidLimit("providerd limits"));
        }
        if self.limits.provider_deadline_ms > PROVIDER_MAX_DEADLINE_MS {
            return Err(ConfigError::InvalidLimit(
                "provider deadline exceeds the bounded inference maximum",
            ));
        }
        let request_wire = canonical_base64_encoded_length(self.limits.max_request_bytes)
            .and_then(|encoded| encoded.checked_add(PROVIDER_RPC_STRUCTURAL_RESERVE_BYTES));
        let response_wire = canonical_base64_encoded_length(self.limits.max_response_bytes)
            .and_then(|encoded| encoded.checked_add(PROVIDER_RPC_STRUCTURAL_RESERVE_BYTES));
        let frame_bound = u64::from(self.limits.max_control_frame_bytes);
        if request_wire.is_none_or(|bound| bound > frame_bound)
            || response_wire.is_none_or(|bound| bound > frame_bound)
        {
            return Err(ConfigError::InvalidLimit(
                "canonical base64 provider content must fit one signed control frame",
            ));
        }
        let mut endpoint_ids = BTreeSet::new();
        for endpoint in &self.endpoints {
            let provider = if endpoint.id.is_empty() {
                "<empty>".to_owned()
            } else {
                endpoint.id.clone()
            };
            if endpoint.id.is_empty() {
                return Err(ConfigError::InvalidProvider {
                    provider,
                    reason: "provider id is empty",
                });
            }
            match &endpoint.transport {
                ProviderTransportConfigV1::CredentialedHttpsApi {
                    url,
                    credential_name,
                    credential_header,
                    ..
                } => {
                    if !valid_https_url(url) {
                        return Err(ConfigError::InvalidProvider {
                            provider,
                            reason: "remote API requires an exact HTTPS URL",
                        });
                    }
                    if !valid_credential_name(credential_name)
                        || !matches!(credential_header.as_str(), "authorization" | "x-api-key")
                    {
                        return Err(ConfigError::InvalidProvider {
                            provider,
                            reason:
                                "remote API requires an enrolled credential and supported header",
                        });
                    }
                }
                ProviderTransportConfigV1::LocalHttp {
                    url,
                    allowed_origins,
                    redirect_policy: ProviderLocalRedirectPolicyV1::Deny,
                } => {
                    let Some(origin) = local_http_origin(url) else {
                        return Err(ConfigError::InvalidProvider {
                            provider,
                            reason: "local HTTP route requires an exact cleartext HTTP URL",
                        });
                    };
                    let origins_valid = !allowed_origins.is_empty()
                        && allowed_origins.iter().all(|candidate| {
                            local_http_origin(candidate).is_some_and(|value| value == candidate)
                        })
                        && allowed_origins.iter().collect::<BTreeSet<_>>().len()
                            == allowed_origins.len();
                    if !origins_valid || !allowed_origins.iter().any(|item| item == origin) {
                        return Err(ConfigError::InvalidProvider {
                            provider,
                            reason: "local HTTP endpoint origin is not in its operator allowlist",
                        });
                    }
                }
                ProviderTransportConfigV1::Command { command } => {
                    if !valid_provider_command(command) {
                        return Err(ConfigError::InvalidProvider {
                            provider,
                            reason: "command route is not a supported fixed executable policy",
                        });
                    }
                    if endpoint.protocol != "opaque_json_v1"
                        || endpoint.methods.as_slice() != ["command.complete"]
                    {
                        return Err(ConfigError::InvalidProvider {
                            provider,
                            reason: "command route requires the fixed command.complete protocol",
                        });
                    }
                }
            }
            if endpoint.models.is_empty() || endpoint.methods.is_empty() {
                return Err(ConfigError::InvalidProvider {
                    provider,
                    reason: "provider requires at least one model and method",
                });
            }
            if endpoint.headers.iter().any(|(name, value)| {
                !matches!(name.as_str(), "anthropic-version")
                    || value.is_empty()
                    || value.len() > 512
                    || value.contains(['\r', '\n', '\0'])
            }) {
                return Err(ConfigError::InvalidProvider {
                    provider,
                    reason: "provider headers are outside the closed non-secret allowlist",
                });
            }
            if !endpoint_ids.insert(&endpoint.id) {
                return Err(ConfigError::InvalidProvider {
                    provider,
                    reason: "duplicate provider id",
                });
            }
            let mut models = BTreeSet::new();
            for model in &endpoint.models {
                if model.id.is_empty() {
                    return Err(ConfigError::InvalidProvider {
                        provider,
                        reason: "model id is empty",
                    });
                }
                if !models.insert(&model.id) {
                    return Err(ConfigError::InvalidProvider {
                        provider,
                        reason: "duplicate backend model id",
                    });
                }
                if model.max_event_stream_bytes < PROVIDER_MIN_EVENT_STREAM_BYTES
                    || model.max_event_stream_bytes > self.limits.max_response_bytes
                    || model.worst_case_cost_microunits == 0
                {
                    return Err(ConfigError::InvalidProvider {
                        provider,
                        reason: "model resource policy is outside configured bounds",
                    });
                }
            }
        }
        Ok(())
    }
}

fn canonical_base64_encoded_length(decoded: u64) -> Option<u64> {
    decoded.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

fn valid_credential_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn authority_end(value: &str) -> usize {
    value.find(['/', '?', '#']).unwrap_or(value.len())
}

fn valid_authority(authority: &str) -> bool {
    !authority.is_empty()
        && !authority.contains('@')
        && !authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

fn valid_https_url(url: &str) -> bool {
    let Some(remainder) = url.strip_prefix("https://") else {
        return false;
    };
    valid_authority(&remainder[..authority_end(remainder)])
}

fn local_http_origin(url: &str) -> Option<&str> {
    let remainder = url.strip_prefix("http://")?;
    let end = authority_end(remainder);
    valid_authority(&remainder[..end]).then_some(&url[.."http://".len() + end])
}

fn valid_provider_command(command: &ProviderCommandConfigV1) -> bool {
    matches!(
        command.adapter.as_str(),
        "codex" | "claude-code" | "kimi-code"
    ) && command.executable.is_absolute()
        && (command.model_argument == ProviderCommandModelArgumentV1::Required
            || command.adapter == "codex")
        && command.working_directory.is_absolute()
        && command.executable.components().collect::<PathBuf>() == command.executable
        && command.working_directory.components().collect::<PathBuf>() == command.working_directory
        && command.environment.iter().all(|(name, value)| {
            matches!(
                name.as_str(),
                "HOME"
                    | "PATH"
                    | "TMPDIR"
                    | "LANG"
                    | "LC_ALL"
                    | "XDG_CONFIG_HOME"
                    | "CODEX_HOME"
                    | "CLAUDE_CONFIG_DIR"
                    | "KIMI_CONFIG_DIR"
            ) && !value.is_empty()
                && value.len() <= 4096
                && !value.contains(['\r', '\n', '\0'])
        })
}

fn valid_unit(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 256
        && unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'-' | b'\\')
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn production_daemon_examples_are_strict_and_valid() {
        let agd: AgdConfigV1 = toml::from_str(include_str!("../../../config/agd.example.toml"))
            .expect("agd example must decode strictly");
        agd.validate().expect("agd example must validate");

        let effectd: EffectdConfigV1 =
            toml::from_str(include_str!("../../../config/effectd.example.toml"))
                .expect("effectd example must decode strictly");
        effectd.validate().expect("effectd example must validate");

        let providerd: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("providerd example must decode strictly");
        providerd
            .validate()
            .expect("providerd example must validate");
    }

    #[test]
    fn daemon_socket_custody_requires_exact_sgid_parent_policy() {
        let mut config: AgdConfigV1 =
            toml::from_str(include_str!("../../../config/agd.example.toml"))
                .expect("strict agd example");
        config.control_socket_custody.parent.mode = 0o750;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidCustody("socket parent"))
        ));

        let mut config: AgdConfigV1 =
            toml::from_str(include_str!("../../../config/agd.example.toml"))
                .expect("strict agd example");
        config.control_socket_custody.node.gid += 1;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidCustody("socket node"))
        ));
    }

    #[test]
    fn provider_limits_account_for_base64_wire_expansion_and_rpc_deadline() {
        let mut config: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("strict provider example");
        config.limits.max_request_bytes = 1024;
        config.limits.max_response_bytes = 3 * 1024 * 1024;
        config.endpoints[0].models[0].max_event_stream_bytes = PROVIDER_MIN_EVENT_STREAM_BYTES;
        // Raw bytes plus the structural reserve would fit, but canonical
        // padded base64 does not. This is the former integer-array/raw-size
        // accounting bug expressed as a hostile configuration.
        config.limits.max_control_frame_bytes = 3 * 1024 * 1024 + 128 * 1024;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit(
                "canonical base64 provider content must fit one signed control frame"
            ))
        ));

        let mut config: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("strict provider example");
        config.limits.provider_deadline_ms = PROVIDER_MAX_DEADLINE_MS + 1;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit(
                "provider deadline exceeds the bounded inference maximum"
            ))
        ));
    }

    #[test]
    fn provider_model_policy_requires_nonzero_broker_owned_cost() {
        let mut config: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("strict provider example");
        config.endpoints[0].models[0].worst_case_cost_microunits = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidProvider {
                provider,
                reason: "model resource policy is outside configured bounds"
            }) if provider == "primary"
        ));
    }

    #[test]
    fn provider_caller_may_be_a_fixed_service_but_not_a_dynamic_or_human_principal() {
        let mut config: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("strict provider example");
        config.caller_peer.principal_kind = PrincipalKindV1::Service;
        config.validate().expect("fixed service caller");

        for rejected in [PrincipalKindV1::WorkerSession, PrincipalKindV1::Operator] {
            config.caller_peer.principal_kind = rejected;
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnexpectedPrincipalKind(_))
            ));
        }
    }

    #[test]
    fn worker_provider_profile_is_closed_and_requires_a_request_budget() {
        let mut profile = serde_json::json!({
            "profile_id": "fixture",
            "project": "fixture",
            "executable": "/usr/bin/fixture-worker",
            "executable_identity": {
                "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 1,
                "build_identity": null
            },
            "fixed_arguments": [],
            "candidate_effect": "managed_file_put",
            "candidate_target": "fixture.target",
            "candidate_semantic_type": "managed_file_content_v1",
            "timeout_ms": 1000,
            "output_budget_bytes": 1024,
            "provider_access": null
        });
        serde_json::from_value::<WorkerProfileConfigV1>(profile.clone())
            .expect("the documented offline worker profile must decode");

        profile.as_object_mut().expect("profile object").insert(
            "provider_route".to_owned(),
            serde_json::json!({
                "endpoint": "primary",
                "model": "production-model",
                "method": "responses.create"
            }),
        );
        assert!(
            serde_json::from_value::<WorkerProfileConfigV1>(profile.clone()).is_err(),
            "a provider-looking profile field must refuse until the live worker/session contract exists"
        );

        profile.as_object_mut().expect("profile object").remove("provider_route");
        profile.as_object_mut().expect("profile object").insert(
            "provider_access".to_owned(),
            serde_json::json!({
                "provider_policy_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "envelope": {
                    "endpoint": "primary", "model": "production-model",
                    "method": "responses.create",
                    "protocol_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                },
                "budget": {"requests": 1, "input_bytes": 4096,
                    "output_bytes": 4096, "cost_microunits": 1000}
            }),
        );
        serde_json::from_value::<WorkerProfileConfigV1>(profile.clone())
            .expect("closed provider policy must decode");
        profile["provider_access"]["budget"]["requests"] = serde_json::json!(0);
        let profile: WorkerProfileConfigV1 = serde_json::from_value(profile)
            .expect("zero budget is a semantic validation failure");
        assert!(!valid_worker_provider_profile(
            profile.provider_access.as_ref().expect("provider policy")
        ));
    }

    #[test]
    fn provider_transport_policy_is_explicit_for_local_http_and_commands() {
        let mut local: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("strict provider example");
        let endpoint = &mut local.endpoints[0];
        endpoint.transport = ProviderTransportConfigV1::LocalHttp {
            url: "http://ollama:11434/api/chat".to_owned(),
            allowed_origins: vec!["http://ollama:11434".to_owned()],
            redirect_policy: ProviderLocalRedirectPolicyV1::Deny,
        };
        local.validate().expect("explicit local HTTP endpoint");
        local.endpoints[0].transport = ProviderTransportConfigV1::LocalHttp {
            url: "http://other:11434/api/chat".to_owned(),
            allowed_origins: vec!["http://ollama:11434".to_owned()],
            redirect_policy: ProviderLocalRedirectPolicyV1::Deny,
        };
        assert!(matches!(
            local.validate(),
            Err(ConfigError::InvalidProvider {
                provider,
                reason: "local HTTP endpoint origin is not in its operator allowlist"
            }) if provider == "primary"
        ));

        let mut command: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("strict provider example");
        let endpoint = &mut command.endpoints[0];
        endpoint.protocol = "opaque_json_v1".to_owned();
        endpoint.methods = vec!["command.complete".to_owned()];
        endpoint.transport = ProviderTransportConfigV1::Command {
            command: ProviderCommandConfigV1 {
                adapter: "claude-code".to_owned(),
                model_argument: ProviderCommandModelArgumentV1::Required,
                executable: PathBuf::from("/opt/claude/claude"),
                working_directory: PathBuf::from("/var/empty"),
                environment: BTreeMap::new(),
            },
        };
        command.validate().expect("fixed command endpoint");
        if let ProviderTransportConfigV1::Command { command: route } =
            &mut command.endpoints[0].transport
        {
            route.model_argument = ProviderCommandModelArgumentV1::Omit;
        }
        assert!(matches!(
            command.validate(),
            Err(ConfigError::InvalidProvider {
                provider,
                reason: "command route is not a supported fixed executable policy"
            }) if provider == "primary"
        ));
        let ProviderTransportConfigV1::Command { command: route } =
            &mut command.endpoints[0].transport
        else {
            unreachable!()
        };
        route.model_argument = ProviderCommandModelArgumentV1::Required;
        route.executable = PathBuf::from("relative");
        assert!(matches!(
            command.validate(),
            Err(ConfigError::InvalidProvider {
                provider,
                reason: "command route is not a supported fixed executable policy"
            }) if provider == "primary"
        ));
    }

    #[test]
    fn provider_credential_name_is_one_bounded_mount_entry() {
        let mut config: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml"))
                .expect("strict provider example");
        for hostile in ["", ".", "..", "nested/key", "key\nname"] {
            let ProviderTransportConfigV1::CredentialedHttpsApi {
                credential_name, ..
            } = &mut config.endpoints[0].transport
            else {
                unreachable!()
            };
            *credential_name = hostile.to_owned();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidProvider {
                    provider,
                    reason: "remote API requires an enrolled credential and supported header"
                }) if provider == "primary"
            ));
        }
    }

    #[test]
    fn effectd_rejects_relabelled_shared_proposer_and_ratifier_credentials() {
        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../config/effectd.example.toml"))
                .expect("strict effectd example");
        config.admin_peer.rpc_key.public_key = config.proposer_peer.rpc_key.public_key.clone();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::RpcKeyCollision)
        ));

        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../config/effectd.example.toml"))
                .expect("strict effectd example");
        config.admin_peer.stable_principal_root =
            config.proposer_peer.stable_principal_root.clone();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::RpcRootCollision)
        ));
    }

    fn managed_pointer_target() -> EffectTargetConfigV1 {
        EffectTargetConfigV1::ManagedPointer {
            id: "repository.main".to_owned(),
            allowed_root: PathBuf::from("/srv/agent-governor/repositories"),
            repository: PathBuf::from("/srv/agent-governor/repositories/service.git"),
            reference: "refs/heads/main".to_owned(),
            activation_genesis_object: "1111111111111111111111111111111111111111".to_owned(),
            activation_genesis_tree: "2222222222222222222222222222222222222222".to_owned(),
            activation_genesis_state: Digest::hash_bytes(b"genesis state"),
            repository_identity: Digest::hash_bytes(b"repository identity"),
            uid: 1000,
            gid: 1000,
            staging_root: PathBuf::from("/var/lib/agent-governor/effectd/promotion-stage"),
            promotion_ttl_ms: 15 * 60 * 1_000,
            helper: PathBuf::from("/usr/bin/git"),
            helper_executable: Digest::hash_bytes(b"git executable"),
            helper_launch_profile: Digest::hash_bytes(b"closed git launch profile"),
        }
    }

    #[test]
    fn managed_pointer_enrollment_is_closed_and_path_bounded() {
        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../config/effectd.example.toml"))
                .expect("strict effectd example");
        let mut legacy = config.clone();
        legacy.schema = "ag.config.effectd.v1".to_owned();
        assert!(matches!(
            legacy.validate(),
            Err(ConfigError::Schema(schema)) if schema == "ag.config.effectd.v1"
        ));
        config.targets.push(managed_pointer_target());
        config.validate().expect("closed managed-pointer target");

        let mut malformed_genesis = managed_pointer_target();
        let EffectTargetConfigV1::ManagedPointer {
            activation_genesis_object,
            ..
        } = &mut malformed_genesis
        else {
            unreachable!("fixture is a managed pointer")
        };
        *activation_genesis_object = "ABCDEF".to_owned();
        config.targets.pop();
        config.targets.push(malformed_genesis);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit("managed-pointer target"))
        ));
        config.targets.pop();
        config.targets.push(managed_pointer_target());

        let mut outside_root = managed_pointer_target();
        let EffectTargetConfigV1::ManagedPointer { repository, .. } = &mut outside_root else {
            unreachable!("fixture is a managed pointer")
        };
        *repository = PathBuf::from("/srv/other/service.git");
        config.targets.pop();
        config.targets.push(outside_root);
        assert!(matches!(config.validate(), Err(ConfigError::UnsafePath(_))));

        let mut staging_inside_allowed_root = managed_pointer_target();
        let EffectTargetConfigV1::ManagedPointer { staging_root, .. } =
            &mut staging_inside_allowed_root
        else {
            unreachable!("fixture is a managed pointer")
        };
        *staging_root = PathBuf::from("/srv/agent-governor/repositories/promotion-stage");
        config.targets.pop();
        config.targets.push(staging_inside_allowed_root);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit("managed-pointer target"))
        ));

        let mut unsafe_ref = managed_pointer_target();
        let EffectTargetConfigV1::ManagedPointer { reference, .. } = &mut unsafe_ref else {
            unreachable!("fixture is a managed pointer")
        };
        *reference = "refs/heads/main.lock".to_owned();
        config.targets.pop();
        config.targets.push(unsafe_ref);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit("managed-pointer target"))
        ));

        let mut unbounded = managed_pointer_target();
        let EffectTargetConfigV1::ManagedPointer {
            promotion_ttl_ms, ..
        } = &mut unbounded
        else {
            unreachable!("fixture is a managed pointer")
        };
        *promotion_ttl_ms = MAX_PROMOTION_TTL_MS + 1;
        config.targets.pop();
        config.targets.push(unbounded);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit("managed-pointer target"))
        ));
    }

    #[test]
    fn static_proposer_enrollment_cannot_impersonate_a_worker_session() {
        let mut agd: AgdConfigV1 = toml::from_str(include_str!("../../../config/agd.example.toml"))
            .expect("strict agd example");
        agd.proposer_peer.principal_kind = PrincipalKindV1::WorkerSession;
        assert!(matches!(
            agd.validate(),
            Err(ConfigError::UnexpectedPrincipalKind(_))
        ));

        let mut effectd: EffectdConfigV1 =
            toml::from_str(include_str!("../../../config/effectd.example.toml"))
                .expect("strict effectd example");
        effectd.proposer_peer.principal_kind = PrincipalKindV1::WorkerSession;
        assert!(matches!(
            effectd.validate(),
            Err(ConfigError::UnexpectedPrincipalKind(_))
        ));
    }

    #[test]
    fn unit_names_cannot_be_bus_paths_or_arguments() {
        assert!(valid_unit("nginx.service"));
        assert!(!valid_unit("nginx.service --now"));
        assert!(!valid_unit("../../unit"));
    }

    #[test]
    fn relative_paths_are_rejected() {
        assert!(validate_absolute(&[Path::new("var/lib/ag")]).is_err());
    }

    #[test]
    fn config_loader_rejects_symlinks_and_oversized_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("config.toml");
        fs::write(
            &target,
            "database = '/tmp/db'\nobject_store = '/tmp/objects'\n",
        )
        .expect("write config");
        let link = directory.path().join("config-link.toml");
        symlink(&target, &link).expect("symlink");
        assert!(load_config::<StoreConfigV1>(&link, false).is_err());

        let oversized = directory.path().join("oversized.toml");
        fs::write(
            &oversized,
            vec![b' '; usize::try_from(MAX_CONFIG_BYTES).expect("config bound fits usize") + 1],
        )
        .expect("write oversized config");
        assert!(matches!(
            load_config::<StoreConfigV1>(&oversized, false),
            Err(ConfigError::ConfigTooLarge(_))
        ));
    }

    #[test]
    fn config_identity_covers_the_exact_descriptor_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("config.toml");
        let bytes = include_bytes!("../../../config/agd.example.toml");
        fs::write(&path, bytes).expect("write config");

        let loaded: LoadedConfigV1<AgdConfigV1> =
            load_config_with_identity(&path, false).expect("load config");
        assert_eq!(loaded.exact_bytes_digest, Digest::hash_bytes(bytes));
    }

    #[test]
    fn production_agctl_example_is_strict_and_valid() {
        let config: AgctlConfigV1 =
            toml::from_str(include_str!("../../../config/agctl.example.toml"))
                .expect("strict example");
        config.validate().expect("valid example");
        assert!(matches!(
            config.command_profile,
            AgctlCommandProfileV1::EffectAdmin { .. }
        ));

        let proposer: AgctlConfigV1 =
            toml::from_str(include_str!("../../../config/agctl-proposer.example.toml"))
                .expect("strict proposer example");
        proposer.validate().expect("valid proposer example");
        assert!(matches!(
            proposer.command_profile,
            AgctlCommandProfileV1::Proposer { .. }
        ));

        let with_unknown = format!(
            "{}\nunknown_limit = 1\n",
            include_str!("../../../config/agctl.example.toml")
        );
        assert!(toml::from_str::<AgctlConfigV1>(&with_unknown).is_err());
    }

    #[test]
    fn agctl_profiles_reject_opposite_plane_fields() {
        let effect_admin_with_agd = include_str!("../../../config/agctl.example.toml").replace(
            "role = \"effect_admin\"",
            "role = \"effect_admin\"\nagd_socket = \"/run/agent-governor/agd/control.sock\"",
        );
        assert!(toml::from_str::<AgctlConfigV1>(&effect_admin_with_agd).is_err());

        let proposer_with_effectd =
            include_str!("../../../config/agctl-proposer.example.toml").replace(
                "role = \"proposer\"",
                "role = \"proposer\"\neffectd_admin_socket = \"/run/agent-governor/effectd/admin/admin.sock\"",
            );
        assert!(toml::from_str::<AgctlConfigV1>(&proposer_with_effectd).is_err());
    }

    #[test]
    fn agctl_rejects_collapsed_caller_and_daemon_principals() {
        let mut config: AgctlConfigV1 =
            toml::from_str(include_str!("../../../config/agctl.example.toml"))
                .expect("strict example");
        let AgctlCommandProfileV1::EffectAdmin { effectd_peer, .. } = &mut config.command_profile
        else {
            panic!("effect-admin example changed role");
        };
        effectd_peer.rpc_key.principal = config.rpc_signing_identity.principal.clone();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::RpcPrincipalCollision)
        ));
    }

    #[test]
    fn agctl_rejects_keys_shared_across_roles() {
        let mut config: AgctlConfigV1 =
            toml::from_str(include_str!("../../../config/agctl.example.toml"))
                .expect("strict example");
        let AgctlCommandProfileV1::EffectAdmin { effectd_peer, .. } = &mut config.command_profile
        else {
            panic!("effect-admin example changed role");
        };
        effectd_peer.rpc_key.public_key = config.rpc_signing_identity.public_key.clone();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::RpcKeyCollision)
        ));
    }
}
