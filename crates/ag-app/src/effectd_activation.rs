//! Fresh, non-serializable production readiness for the effect broker.
//!
//! A serializable receipt is diagnostic evidence only. The live value is rebuilt on
//! every daemon start from the enrolled store, current process state, current
//! mount namespace, and strict effective systemd properties.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek as _, SeekFrom};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_primitives::Digest;
use ag_store::{Store, StoreActivationIdentityV1};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(test)]
use crate::config::EffectTargetConfigV1;
use crate::config::EffectdConfigV1;
use crate::doctor::{required_effectd_capabilities, required_effectd_write_paths};
use crate::managed_pointer::ManagedPointerRuntimeV1;

/// Exact readiness receipt schema.
pub const EFFECTD_ACTIVATION_RECEIPT_SCHEMA_V1: &str = "ag.effectd.live-activation-receipt/v1";
/// Non-authorizing current-process activation-status schema.
pub const EFFECTD_ACTIVATION_STATUS_SCHEMA_V1: &str = "ag.effectd.live-activation-status/v1";

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const PROC_STATUS: &str = "/proc/self/status";
const PROC_MOUNTINFO: &str = "/proc/self/mountinfo";
const PROC_CGROUP: &str = "/proc/self/cgroup";
const MAX_SYSTEMCTL_BYTES: usize = 1024 * 1024;
const MAX_PROC_BYTES: usize = 4 * 1024 * 1024;
const MAX_SYSTEMCTL_EXECUTABLE_BYTES: u64 = 32 * 1024 * 1024;
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const EFFECTD_UNIT_PROPERTIES: &[&str] = &[
    "Id",
    "MainPID",
    "ControlGroup",
    "InvocationID",
    "User",
    "Group",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "PrivateNetwork",
    "RestrictAddressFamilies",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "SupplementaryGroups",
    "Environment",
    "EnvironmentFiles",
    "PassEnvironment",
    "UnsetEnvironment",
    "UMask",
    "SecureBits",
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "PrivateDevices",
    "DevicePolicy",
    "PrivateMounts",
    "ProtectClock",
    "ProtectHostname",
    "ProtectKernelTunables",
    "ProtectControlGroups",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectProc",
    "ProcSubset",
    "RestrictNamespaces",
    "RestrictSUIDSGID",
    "MemoryDenyWriteExecute",
    "LockPersonality",
    "KeyringMode",
    "RemoveIPC",
    "RestrictRealtime",
    "SystemCallArchitectures",
    "SystemCallErrorNumber",
    "LimitCORE",
    "LimitNOFILE",
    "TasksMax",
    "DynamicUser",
    "ReadWritePaths",
    "ReadOnlyPaths",
    "BindPaths",
    "BindReadOnlyPaths",
    "TemporaryFileSystem",
    "RootDirectory",
    "RootImage",
    "StateDirectory",
    "StateDirectoryMode",
    "RuntimeDirectory",
    "CacheDirectory",
    "LogsDirectory",
    "ConfigurationDirectory",
];

/// Exact current-process evidence behind one readiness decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectdProcessActivationEvidenceV1 {
    /// Exact PID which must equal the systemd unit's `MainPID`.
    pub process_id: u32,
    /// Exact unified cgroup path shared with the effective unit.
    pub control_group: String,
    /// Effective user.
    pub effective_uid: u32,
    /// Effective group.
    pub effective_gid: u32,
    /// Supplementary groups; readiness requires this to be empty.
    pub supplementary_groups: Vec<u32>,
    /// Kernel no-new-privileges bit from both proc and `prctl`.
    pub no_new_privileges: bool,
    /// Inheritable capability mask.
    pub capability_inheritable: u64,
    /// Permitted capability mask.
    pub capability_permitted: u64,
    /// Effective capability mask.
    pub capability_effective: u64,
    /// Bounding capability mask.
    pub capability_bounding: u64,
    /// Ambient capability mask.
    pub capability_ambient: u64,
    /// Digest of the exact bounded proc status bytes.
    pub proc_status: Digest,
    /// Digest of the exact bounded unified cgroup evidence.
    pub proc_cgroup: Digest,
}

/// Serializable explanation of one successful live readiness construction.
///
/// This value cannot enable authority. Only [`EffectdLiveActivationV1`], which
/// has no clone or serialization path, is accepted by the broker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectdActivationReceiptV1 {
    /// Exact receipt schema.
    pub schema: String,
    /// Exact enrolled store activation identity.
    pub store_activation: StoreActivationIdentityV1,
    /// Store's domain-separated activation digest.
    pub store_activation_digest: String,
    /// Exact compiler-owned target catalog.
    pub catalog_identity: Digest,
    /// Exact configured security profile.
    pub security_profile_identity: Digest,
    /// Exact safe `/usr/bin/systemctl` bytes used for the fixed observation.
    pub systemctl_executable: Digest,
    /// Exact bounded output of the fixed effective-unit query.
    pub systemctl_output: Digest,
    /// Strict complete effective property map for `ag-effectd.service`.
    pub effective_unit: BTreeMap<String, String>,
    /// Closed capability names derived from the configured target catalog.
    pub required_capabilities: Vec<String>,
    /// Closed writable-root set derived from configuration.
    pub required_write_paths: Vec<String>,
    /// Exact current-process evidence.
    pub process: EffectdProcessActivationEvidenceV1,
    /// Fresh exact helper/staging/repository/ref target preflight.
    pub target_readiness: Digest,
    /// Digest of exact bounded mount-namespace evidence.
    pub mountinfo: Digest,
    /// Trusted local observation time.
    pub observed_at_unix_ms: u64,
    /// Process-lifecycle nonce; evidence from a prior start cannot reconstruct standing.
    pub process_nonce: String,
}

/// Inspectable current-process activation state. Neither variant is standing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectdActivationStatusV1 {
    /// Fresh live evidence remains valid for this process and current target cut.
    Ready {
        /// Exact status schema.
        schema: String,
        /// Full diagnostic receipt whose bytes cannot reconstruct standing.
        receipt: Box<EffectdActivationReceiptV1>,
    },
    /// Readiness is absent or current revalidation refused it.
    NotReady {
        /// Exact status schema.
        schema: String,
        /// Stable lifecycle phase in which readiness failed.
        phase: String,
        /// Stable typed refusal/failure code.
        code: String,
        /// Bounded operator-facing detail.
        detail: String,
    },
}

impl EffectdActivationReceiptV1 {
    /// Return the strict receipt identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported or structurally incomplete record.
    pub fn identity(&self) -> Result<Digest, EffectdActivationError> {
        if self.schema != EFFECTD_ACTIVATION_RECEIPT_SCHEMA_V1
            || self.process_nonce.is_empty()
            || self.required_capabilities.is_empty()
            || self.required_write_paths.is_empty()
            || self.observed_at_unix_ms == 0
        {
            return Err(EffectdActivationError::ReceiptMismatch);
        }
        Ok(Digest::from_serializable(self)?)
    }
}

/// Fresh non-serializable broker-readiness standing.
pub struct EffectdLiveActivationV1 {
    receipt: EffectdActivationReceiptV1,
    identity: Digest,
}

impl core::fmt::Debug for EffectdLiveActivationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EffectdLiveActivationV1")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl EffectdLiveActivationV1 {
    /// Construct current-process production readiness from live observations.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when any store, process, capability, unit,
    /// namespace, path, or platform binding is unavailable or differs.
    pub fn attest(
        config: &EffectdConfigV1,
        catalog_identity: &Digest,
        store: &Store,
    ) -> Result<Self, EffectdActivationError> {
        let activation = store
            .activation()
            .ok_or(EffectdActivationError::StoreActivationUnavailable)?;
        let security_profile_identity = Digest::hash_domain(
            "ag-security-profile-identity-v1",
            config.security_profile.as_bytes(),
        );
        if activation.identity.authority_catalog_identity.as_ref() != Some(catalog_identity)
            || activation.identity.security_profile_identity != security_profile_identity
        {
            return Err(EffectdActivationError::StoreActivationMismatch);
        }

        let required_capabilities = required_effectd_capabilities(config);
        let required_mask = capability_mask(&required_capabilities)?;
        let status_bytes = read_bounded_file(Path::new(PROC_STATUS), MAX_PROC_BYTES as u64)?;
        let cgroup_bytes = read_bounded_file(Path::new(PROC_CGROUP), 64 * 1024)?;
        let control_group = parse_unified_control_group(&cgroup_bytes)?;
        let process = process_evidence(&status_bytes, &cgroup_bytes, control_group, required_mask)?;

        let write_paths =
            required_effectd_write_paths(config).map_err(EffectdActivationError::UnitMismatch)?;
        reject_broad_write_paths(&write_paths)?;
        let expected_write_paths = utf8_paths(&write_paths)?;

        let (systemctl_executable, mut systemctl) = open_safe_systemctl()?;
        let output = query_effective_unit(&systemctl)?;
        let effective_unit = parse_effective_unit(&output)?;
        validate_effective_unit(
            &effective_unit,
            &required_capabilities,
            &expected_write_paths,
            &process,
        )?;
        let retained_systemctl = hash_safe_systemctl_file(&mut systemctl)?;
        let (installed_systemctl, _) = open_safe_systemctl()?;
        if retained_systemctl != systemctl_executable || installed_systemctl != systemctl_executable
        {
            return Err(EffectdActivationError::SystemctlIdentityMismatch);
        }

        let mountinfo = read_bounded_file(Path::new(PROC_MOUNTINFO), MAX_PROC_BYTES as u64)?;
        let mounts = parse_mountinfo(&mountinfo)?;
        validate_mount_namespace(&mounts, &write_paths)?;
        let target_readiness = ManagedPointerRuntimeV1::from_config(config)
            .and_then(|runtime| runtime.production_readiness())
            .map_err(|error| EffectdActivationError::TargetReadiness(error.to_string()))?;

        let receipt = EffectdActivationReceiptV1 {
            schema: EFFECTD_ACTIVATION_RECEIPT_SCHEMA_V1.to_owned(),
            store_activation: activation.identity.clone(),
            store_activation_digest: activation.activation_digest.to_string(),
            catalog_identity: catalog_identity.clone(),
            security_profile_identity,
            systemctl_executable,
            systemctl_output: Digest::hash_bytes(&output),
            effective_unit,
            required_capabilities: required_capabilities
                .into_iter()
                .map(str::to_owned)
                .collect(),
            required_write_paths: expected_write_paths.into_iter().collect(),
            process,
            target_readiness,
            mountinfo: Digest::hash_bytes(&mountinfo),
            observed_at_unix_ms: now_unix_ms()?,
            process_nonce: uuid::Uuid::new_v4().to_string(),
        };
        let identity = receipt.identity()?;
        Ok(Self { receipt, identity })
    }

    /// Borrow diagnostic evidence without transferring live standing.
    #[must_use]
    pub fn receipt(&self) -> &EffectdActivationReceiptV1 {
        &self.receipt
    }

    /// Exact receipt identity.
    #[must_use]
    pub fn identity(&self) -> &Digest {
        &self.identity
    }

    /// Consume the live standing and retain only its non-authorizing
    /// diagnostic receipt after broker activation.
    pub(crate) fn into_receipt(self) -> EffectdActivationReceiptV1 {
        self.receipt
    }

    /// Verify that this live value belongs to the exact broker construction.
    pub(crate) fn verify_for(
        &self,
        config: &EffectdConfigV1,
        catalog_identity: &Digest,
        store: &Store,
    ) -> Result<(), EffectdActivationError> {
        let enrolled = store
            .activation()
            .ok_or(EffectdActivationError::StoreActivationUnavailable)?;
        let profile = Digest::hash_domain(
            "ag-security-profile-identity-v1",
            config.security_profile.as_bytes(),
        );
        if self.receipt.catalog_identity != *catalog_identity
            || self.receipt.security_profile_identity != profile
            || self.receipt.store_activation != enrolled.identity
            || self.receipt.store_activation_digest != enrolled.activation_digest.to_string()
            || self.receipt.identity()? != self.identity
        {
            return Err(EffectdActivationError::ReceiptMismatch);
        }
        Ok(())
    }
}

/// Closed activation/readiness failures. Diagnostics never carry authority.
#[derive(Debug, Error)]
pub enum EffectdActivationError {
    /// Store has no durable activation identity.
    #[error("effectd store activation is unavailable")]
    StoreActivationUnavailable,
    /// Store catalog/profile differs from the live configuration.
    #[error("effectd store activation differs from the live broker context")]
    StoreActivationMismatch,
    /// Broker process identity or supplementary groups are unsafe.
    #[error("effectd process identity is not production-shaped")]
    ProcessIdentityMismatch,
    /// Capability or no-new-privileges evidence differs.
    #[error("effectd process privilege floor differs from the closed target-derived contract")]
    ProcessPrivilegeMismatch,
    /// Fixed systemctl executable is unsafe or changed around observation.
    #[error("fixed systemctl executable identity is unsafe or changed")]
    SystemctlIdentityMismatch,
    /// Effective unit output is unavailable or malformed.
    #[error("effective effectd unit evidence is unavailable: {0}")]
    UnitUnavailable(String),
    /// Effective unit properties differ from the closed contract.
    #[error("effective effectd unit differs from the closed contract: {0}")]
    UnitMismatch(String),
    /// Current mount namespace does not make exactly required roots usable.
    #[error("effectd mount namespace differs from the closed contract: {0}")]
    MountNamespaceMismatch(String),
    /// Pinned helper, staging custody, repository, owner, or ref preflight failed.
    #[error("managed-pointer production target readiness failed: {0}")]
    TargetReadiness(String),
    /// A bounded local evidence read failed.
    #[error("effectd activation evidence I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Strict evidence encoding failed.
    #[error("effectd activation evidence encoding failed: {0}")]
    Canonical(#[from] ag_primitives::JcsError),
    /// Receipt bytes do not satisfy their schema or broker context.
    #[error("effectd live activation receipt mismatch")]
    ReceiptMismatch,
    /// Trusted wall-clock observation failed.
    #[error("effectd activation clock is unavailable")]
    ClockUnavailable,
}

impl EffectdActivationError {
    /// Stable machine-facing classification for inspection and logs.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::StoreActivationUnavailable => "store_activation_unavailable",
            Self::StoreActivationMismatch => "store_activation_mismatch",
            Self::ProcessIdentityMismatch => "process_identity_mismatch",
            Self::ProcessPrivilegeMismatch => "process_privilege_mismatch",
            Self::SystemctlIdentityMismatch => "systemctl_identity_mismatch",
            Self::UnitUnavailable(_) => "unit_evidence_unavailable",
            Self::UnitMismatch(_) => "unit_profile_mismatch",
            Self::MountNamespaceMismatch(_) => "mount_namespace_mismatch",
            Self::TargetReadiness(_) => "target_readiness_mismatch",
            Self::Io(_) => "evidence_io_failure",
            Self::Canonical(_) => "evidence_encoding_failure",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::ClockUnavailable => "clock_unavailable",
        }
    }

    /// Stable phase containing the failed observation.
    #[must_use]
    pub const fn phase(&self) -> &'static str {
        match self {
            Self::StoreActivationUnavailable | Self::StoreActivationMismatch => "store_activation",
            Self::ProcessIdentityMismatch | Self::ProcessPrivilegeMismatch => "process",
            Self::SystemctlIdentityMismatch | Self::UnitUnavailable(_) | Self::UnitMismatch(_) => {
                "service_unit"
            }
            Self::MountNamespaceMismatch(_) => "mount_namespace",
            Self::TargetReadiness(_) => "target_preflight",
            Self::Io(_) | Self::Canonical(_) => "evidence",
            Self::ReceiptMismatch => "receipt_validation",
            Self::ClockUnavailable => "clock",
        }
    }
}

fn process_evidence(
    status_bytes: &[u8],
    cgroup_bytes: &[u8],
    control_group: String,
    required_mask: u64,
) -> Result<EffectdProcessActivationEvidenceV1, EffectdActivationError> {
    let fields = parse_proc_status(status_bytes)?;
    let effective_user_id = nix::unistd::geteuid().as_raw();
    let effective_group_id = nix::unistd::getegid().as_raw();
    let supplementary_groups: Vec<u32> = nix::unistd::getgroups()
        .map_err(|error| {
            EffectdActivationError::UnitUnavailable(format!(
                "supplementary groups cannot be inspected: {error}"
            ))
        })?
        .into_iter()
        .map(nix::unistd::Gid::as_raw)
        .collect();
    if effective_user_id != 0 || effective_group_id != 0 || !supplementary_groups.is_empty() {
        return Err(EffectdActivationError::ProcessIdentityMismatch);
    }
    let prctl_no_new_privileges = nix::sys::prctl::get_no_new_privs()
        .map_err(|_| EffectdActivationError::ProcessPrivilegeMismatch)?;
    let evidence = EffectdProcessActivationEvidenceV1 {
        process_id: std::process::id(),
        control_group,
        effective_uid: effective_user_id,
        effective_gid: effective_group_id,
        supplementary_groups,
        no_new_privileges: fields.no_new_privileges && prctl_no_new_privileges,
        capability_inheritable: fields.capability_inheritable,
        capability_permitted: fields.capability_permitted,
        capability_effective: fields.capability_effective,
        capability_bounding: fields.capability_bounding,
        capability_ambient: fields.capability_ambient,
        proc_status: Digest::hash_bytes(status_bytes),
        proc_cgroup: Digest::hash_bytes(cgroup_bytes),
    };
    if !evidence.no_new_privileges
        || evidence.capability_inheritable != 0
        || evidence.capability_ambient != 0
        || evidence.capability_permitted != required_mask
        || evidence.capability_effective != required_mask
        || evidence.capability_bounding != required_mask
    {
        return Err(EffectdActivationError::ProcessPrivilegeMismatch);
    }
    Ok(evidence)
}

fn parse_unified_control_group(bytes: &[u8]) -> Result<String, EffectdActivationError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| EffectdActivationError::ProcessIdentityMismatch)?;
    if text.contains(['\0', '\r']) {
        return Err(EffectdActivationError::ProcessIdentityMismatch);
    }
    let mut lines = text.lines();
    let line = lines
        .next()
        .ok_or(EffectdActivationError::ProcessIdentityMismatch)?;
    if lines.next().is_some() {
        return Err(EffectdActivationError::ProcessIdentityMismatch);
    }
    let group = line
        .strip_prefix("0::")
        .ok_or(EffectdActivationError::ProcessIdentityMismatch)?;
    if group.is_empty()
        || !group.starts_with('/')
        || group.contains("//")
        || group
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(EffectdActivationError::ProcessIdentityMismatch);
    }
    Ok(group.to_owned())
}

struct ProcStatusV1 {
    no_new_privileges: bool,
    capability_inheritable: u64,
    capability_permitted: u64,
    capability_effective: u64,
    capability_bounding: u64,
    capability_ambient: u64,
}

fn parse_proc_status(bytes: &[u8]) -> Result<ProcStatusV1, EffectdActivationError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| EffectdActivationError::ProcessPrivilegeMismatch)?;
    if text.contains('\0') || text.contains('\r') {
        return Err(EffectdActivationError::ProcessPrivilegeMismatch);
    }
    let mut selected = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if [
            "NoNewPrivs",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
        ]
        .contains(&key)
            && selected.insert(key, value.trim()).is_some()
        {
            return Err(EffectdActivationError::ProcessPrivilegeMismatch);
        }
    }
    let number = |name: &str| -> Result<u64, EffectdActivationError> {
        let value = selected
            .get(name)
            .ok_or(EffectdActivationError::ProcessPrivilegeMismatch)?;
        if value.is_empty()
            || value.len() > 16
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EffectdActivationError::ProcessPrivilegeMismatch);
        }
        u64::from_str_radix(value, 16).map_err(|_| EffectdActivationError::ProcessPrivilegeMismatch)
    };
    let no_new_privileges = match selected.get("NoNewPrivs").copied() {
        Some("1") => true,
        Some("0") => false,
        _ => return Err(EffectdActivationError::ProcessPrivilegeMismatch),
    };
    Ok(ProcStatusV1 {
        no_new_privileges,
        capability_inheritable: number("CapInh")?,
        capability_permitted: number("CapPrm")?,
        capability_effective: number("CapEff")?,
        capability_bounding: number("CapBnd")?,
        capability_ambient: number("CapAmb")?,
    })
}

fn capability_mask(capabilities: &BTreeSet<&str>) -> Result<u64, EffectdActivationError> {
    capabilities.iter().try_fold(0_u64, |mask, capability| {
        let bit = match *capability {
            "cap_chown" => 0,
            "cap_dac_override" => 1,
            "cap_dac_read_search" => 2,
            "cap_fowner" => 3,
            "cap_setgid" => 6,
            "cap_setuid" => 7,
            _ => return Err(EffectdActivationError::ProcessPrivilegeMismatch),
        };
        Ok(mask | (1_u64 << bit))
    })
}

fn query_effective_unit(systemctl: &File) -> Result<Vec<u8>, EffectdActivationError> {
    let mut command = Command::new(format!("/proc/self/fd/{}", systemctl.as_raw_fd()));
    configure_effective_unit_query(&mut command);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::exact_exec::configure_exact_inherited_fds(&mut command, &[], &[], 1)
        .map_err(|error| EffectdActivationError::UnitUnavailable(error.to_string()))?;
    let mut child = command
        .spawn()
        .map_err(|error| EffectdActivationError::UnitUnavailable(error.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        EffectdActivationError::UnitUnavailable("systemctl stdout is unavailable".to_owned())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        EffectdActivationError::UnitUnavailable("systemctl stderr is unavailable".to_owned())
    })?;
    let stdout_reader = thread::spawn(move || read_bounded_stream(stdout, MAX_SYSTEMCTL_BYTES));
    let stderr_reader = thread::spawn(move || read_bounded_stream(stderr, 64 * 1024));
    let deadline = Instant::now() + SYSTEMCTL_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| EffectdActivationError::UnitUnavailable(error.to_string()))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(EffectdActivationError::UnitUnavailable(
                "fixed systemctl query exceeded its deadline".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_reader.join().map_err(|_| {
        EffectdActivationError::UnitUnavailable("systemctl stdout reader failed".to_owned())
    })??;
    let _stderr = stderr_reader.join().map_err(|_| {
        EffectdActivationError::UnitUnavailable("systemctl stderr reader failed".to_owned())
    })??;
    if !status.success() {
        return Err(EffectdActivationError::UnitUnavailable(
            "fixed systemctl show exited unsuccessfully".to_owned(),
        ));
    }
    Ok(stdout)
}

fn configure_effective_unit_query(command: &mut Command) {
    // systemd 252 suppresses empty properties from `show` unless `--all` is
    // explicit. Empty Exec* and EnvironmentFiles values are part of the
    // closed property cut, so omission must not be confused with absence.
    command.args(["show", "--no-pager", "--all"]);
    for property in EFFECTD_UNIT_PROPERTIES {
        command.arg(format!("--property={property}"));
    }
    command.args(["--", "ag-effectd.service"]);
}

fn read_bounded_stream(
    mut stream: impl Read,
    maximum: usize,
) -> Result<Vec<u8>, EffectdActivationError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(count) > maximum {
            return Err(EffectdActivationError::UnitUnavailable(
                "fixed systemctl output exceeded its bound".to_owned(),
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn parse_effective_unit(bytes: &[u8]) -> Result<BTreeMap<String, String>, EffectdActivationError> {
    if bytes.len() > MAX_SYSTEMCTL_BYTES {
        return Err(EffectdActivationError::UnitUnavailable(
            "effective unit output exceeded its bound".to_owned(),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        EffectdActivationError::UnitUnavailable("effective unit output is not UTF-8".to_owned())
    })?;
    if text.contains(['\0', '\r']) {
        return Err(EffectdActivationError::UnitUnavailable(
            "effective unit output contains forbidden control bytes".to_owned(),
        ));
    }
    let allowed: BTreeSet<&str> = EFFECTD_UNIT_PROPERTIES.iter().copied().collect();
    let mut properties = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            EffectdActivationError::UnitUnavailable("effective unit property lacks '='".to_owned())
        })?;
        if !allowed.contains(key)
            || properties
                .insert(key.to_owned(), value.to_owned())
                .is_some()
        {
            return Err(EffectdActivationError::UnitUnavailable(
                "effective unit properties are duplicate or unexpected".to_owned(),
            ));
        }
    }
    if properties.len() != allowed.len() {
        return Err(EffectdActivationError::UnitUnavailable(
            "effective unit property cut is incomplete".to_owned(),
        ));
    }
    Ok(properties)
}

fn validate_effective_unit(
    properties: &BTreeMap<String, String>,
    required_capabilities: &BTreeSet<&str>,
    required_write_paths: &BTreeSet<String>,
    process: &EffectdProcessActivationEvidenceV1,
) -> Result<(), EffectdActivationError> {
    validate_effectd_static_unit(properties, required_capabilities, required_write_paths)?;
    let value = |key: &str| properties.get(key).map_or("", String::as_str);
    let main_pid = value("MainPID")
        .parse::<u32>()
        .map_err(|_| EffectdActivationError::UnitMismatch("MainPID is invalid".to_owned()))?;
    if main_pid != process.process_id {
        return Err(EffectdActivationError::UnitMismatch(
            "effective MainPID does not identify this process".to_owned(),
        ));
    }
    if value("ControlGroup") != process.control_group {
        return Err(EffectdActivationError::UnitMismatch(
            "effective ControlGroup does not identify this process".to_owned(),
        ));
    }
    let invocation_id = value("InvocationID");
    if invocation_id.len() != 32
        || !invocation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(EffectdActivationError::UnitMismatch(
            "effective InvocationID is not canonical".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_effectd_static_unit(
    properties: &BTreeMap<String, String>,
    required_capabilities: &BTreeSet<&str>,
    required_write_paths: &BTreeSet<String>,
) -> Result<(), EffectdActivationError> {
    let value = |key: &str| properties.get(key).map_or("", String::as_str);
    validate_exec_command(
        "ExecStart",
        value("ExecStart"),
        "/usr/bin/ag-effectd --config /etc/agent-governor/effectd.toml",
    )?;
    validate_exec_command(
        "ExecStartPre",
        value("ExecStartPre"),
        "/usr/bin/ag-effectd --config /etc/agent-governor/effectd.toml --check-config",
    )?;
    let capabilities: BTreeSet<&str> = value("CapabilityBoundingSet")
        .split_ascii_whitespace()
        .collect();
    let write_paths = parse_write_paths(value("ReadWritePaths"))?;
    let read_only_paths = parse_write_paths(value("ReadOnlyPaths"))?;
    for (property, expected) in [
        ("Id", "ag-effectd.service"),
        ("User", "root"),
        ("Group", "root"),
        ("PrivateNetwork", "yes"),
        ("RestrictAddressFamilies", "AF_UNIX"),
        ("AmbientCapabilities", ""),
        ("SupplementaryGroups", ""),
        ("Environment", ""),
        ("EnvironmentFiles", ""),
        ("PassEnvironment", ""),
        ("UnsetEnvironment", ""),
        ("UMask", "0077"),
        ("SecureBits", ""),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateDevices", "yes"),
        ("DevicePolicy", "closed"),
        ("PrivateMounts", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectHostname", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectProc", "invisible"),
        ("ProcSubset", "pid"),
        ("RestrictNamespaces", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("MemoryDenyWriteExecute", "yes"),
        ("LockPersonality", "yes"),
        ("KeyringMode", "private"),
        ("RemoveIPC", "yes"),
        ("RestrictRealtime", "yes"),
        ("SystemCallArchitectures", "native"),
        ("SystemCallErrorNumber", "EPERM"),
        ("LimitCORE", "0"),
        ("LimitNOFILE", "4096"),
        ("TasksMax", "128"),
        ("DynamicUser", "no"),
        ("StateDirectory", "agent-governor/effectd"),
        ("StateDirectoryMode", "0700"),
    ] {
        if value(property) != expected {
            return Err(EffectdActivationError::UnitMismatch(format!(
                "effective property {property} differs from the closed profile"
            )));
        }
    }
    for property in [
        "ExecStartPost",
        "ExecCondition",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
        "BindPaths",
        "BindReadOnlyPaths",
        "TemporaryFileSystem",
        "RootDirectory",
        "RootImage",
        "RuntimeDirectory",
        "CacheDirectory",
        "LogsDirectory",
        "ConfigurationDirectory",
    ] {
        if !value(property).is_empty() {
            return Err(EffectdActivationError::UnitMismatch(format!(
                "effective property {property} must be empty"
            )));
        }
    }
    if capabilities != *required_capabilities {
        return Err(EffectdActivationError::UnitMismatch(
            "effective CapabilityBoundingSet differs from the target-derived set".to_owned(),
        ));
    }
    if read_only_paths != BTreeSet::from(["/run".to_owned()]) {
        return Err(EffectdActivationError::UnitMismatch(
            "effective ReadOnlyPaths must be exactly /run".to_owned(),
        ));
    }
    if write_paths != *required_write_paths {
        return Err(EffectdActivationError::UnitMismatch(
            "effective ReadWritePaths differs from the target-derived set".to_owned(),
        ));
    }
    Ok(())
}

fn validate_exec_command(
    property: &str,
    value: &str,
    expected_argv: &str,
) -> Result<(), EffectdActivationError> {
    if value.matches("{ path=").count() != 1 {
        return Err(EffectdActivationError::UnitMismatch(format!(
            "effective {property} does not contain exactly one executable"
        )));
    }
    let rest = value.strip_prefix("{ path=").ok_or_else(|| {
        EffectdActivationError::UnitMismatch(format!("effective {property} has unsupported syntax"))
    })?;
    let (path, rest) = rest.split_once(" ; argv[]=").ok_or_else(|| {
        EffectdActivationError::UnitMismatch(format!("effective {property} lacks exact argv"))
    })?;
    let (argv, rest) = rest.split_once(" ; ignore_errors=").ok_or_else(|| {
        EffectdActivationError::UnitMismatch(format!("effective {property} lacks error policy"))
    })?;
    let ignore_errors = rest.split_once(" ;").map_or(rest, |(value, _)| value);
    if path != "/usr/bin/ag-effectd"
        || !canonical_absolute(Path::new(path))
        || argv != expected_argv
        || ignore_errors != "no"
    {
        return Err(EffectdActivationError::UnitMismatch(format!(
            "effective {property} differs from the closed profile"
        )));
    }
    Ok(())
}

fn parse_write_paths(value: &str) -> Result<BTreeSet<String>, EffectdActivationError> {
    let mut paths = BTreeSet::new();
    for raw in value.split_ascii_whitespace() {
        if raw.starts_with(['-', '+', '!']) || raw.contains(['"', '\'', '\\']) {
            return Err(EffectdActivationError::UnitMismatch(
                "ReadWritePaths contains optional or opaque syntax".to_owned(),
            ));
        }
        let path = PathBuf::from(raw);
        if !canonical_absolute(&path) || !paths.insert(raw.to_owned()) {
            return Err(EffectdActivationError::UnitMismatch(
                "ReadWritePaths is duplicate or noncanonical".to_owned(),
            ));
        }
    }
    Ok(paths)
}

fn utf8_paths(paths: &BTreeSet<PathBuf>) -> Result<BTreeSet<String>, EffectdActivationError> {
    paths
        .iter()
        .map(|path| {
            path.to_str().map(str::to_owned).ok_or_else(|| {
                EffectdActivationError::UnitMismatch(
                    "required writable path is not UTF-8".to_owned(),
                )
            })
        })
        .collect()
}

fn reject_broad_write_paths(paths: &BTreeSet<PathBuf>) -> Result<(), EffectdActivationError> {
    const FORBIDDEN: [&str; 22] = [
        "/",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/media",
        "/mnt",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/run/user",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/usr/local",
        "/var",
        "/var/lib",
        "/var/run",
        "/var/tmp",
        "/lost+found",
    ];
    if paths.iter().any(|path| {
        FORBIDDEN
            .iter()
            .any(|forbidden| path == Path::new(forbidden))
    }) {
        return Err(EffectdActivationError::UnitMismatch(
            "configured writable root is unacceptably broad".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountV1 {
    point: PathBuf,
    mount_options: BTreeSet<String>,
    super_options: BTreeSet<String>,
}

fn parse_mountinfo(bytes: &[u8]) -> Result<Vec<MountV1>, EffectdActivationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        EffectdActivationError::MountNamespaceMismatch("mountinfo is not UTF-8".to_owned())
    })?;
    if text.contains(['\0', '\r']) {
        return Err(EffectdActivationError::MountNamespaceMismatch(
            "mountinfo contains forbidden control bytes".to_owned(),
        ));
    }
    let mut mounts = Vec::new();
    let mut ids = BTreeSet::new();
    let mut points = BTreeSet::new();
    for line in text.lines() {
        let (before, after) = line.split_once(" - ").ok_or_else(|| {
            EffectdActivationError::MountNamespaceMismatch(
                "mountinfo line lacks separator".to_owned(),
            )
        })?;
        let fields: Vec<_> = before.split_ascii_whitespace().collect();
        let after_fields: Vec<_> = after.split_ascii_whitespace().collect();
        if fields.len() < 6 || after_fields.len() < 3 {
            return Err(EffectdActivationError::MountNamespaceMismatch(
                "mountinfo line is incomplete".to_owned(),
            ));
        }
        let id = fields[0].parse::<u64>().map_err(|_| {
            EffectdActivationError::MountNamespaceMismatch(
                "mountinfo contains an invalid mount ID".to_owned(),
            )
        })?;
        let point = PathBuf::from(decode_mount_field(fields[4])?);
        if id == 0
            || !ids.insert(id)
            || !points.insert(point.clone())
            || !canonical_absolute(&point)
        {
            return Err(EffectdActivationError::MountNamespaceMismatch(
                "mount ID or visible mount point is duplicate or noncanonical".to_owned(),
            ));
        }
        mounts.push(MountV1 {
            point,
            mount_options: fields[5].split(',').map(str::to_owned).collect(),
            super_options: after_fields[2].split(',').map(str::to_owned).collect(),
        });
    }
    if mounts.is_empty() {
        return Err(EffectdActivationError::MountNamespaceMismatch(
            "mountinfo contains no mounts".to_owned(),
        ));
    }
    Ok(mounts)
}

fn decode_mount_field(value: &str) -> Result<String, EffectdActivationError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 3 >= bytes.len() {
            return Err(EffectdActivationError::MountNamespaceMismatch(
                "mountinfo has a truncated escape".to_owned(),
            ));
        }
        let escape = &bytes[index + 1..index + 4];
        decoded.push(match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => {
                return Err(EffectdActivationError::MountNamespaceMismatch(
                    "mountinfo has an unsupported escape".to_owned(),
                ));
            }
        });
        index += 4;
    }
    String::from_utf8(decoded).map_err(|_| {
        EffectdActivationError::MountNamespaceMismatch(
            "decoded mount point is not UTF-8".to_owned(),
        )
    })
}

fn validate_mount_namespace(
    mounts: &[MountV1],
    required_write_paths: &BTreeSet<PathBuf>,
) -> Result<(), EffectdActivationError> {
    for required in required_write_paths {
        let mount = covering_mount(mounts, required)?;
        if !mount.mount_options.contains("rw") || !mount.super_options.contains("rw") {
            return Err(EffectdActivationError::MountNamespaceMismatch(format!(
                "required root {} is not writable in the live namespace",
                required.display()
            )));
        }
    }
    for protected in ["/", "/usr", "/boot", "/etc", "/srv"] {
        let mount = covering_mount(mounts, Path::new(protected))?;
        if !mount.mount_options.contains("ro") {
            return Err(EffectdActivationError::MountNamespaceMismatch(format!(
                "protected root {protected} is not read-only in the live namespace"
            )));
        }
    }
    for mount in mounts {
        if mount.mount_options.contains("rw")
            && !mount_is_admitted_writable(mount, required_write_paths)
        {
            return Err(EffectdActivationError::MountNamespaceMismatch(format!(
                "unexpected writable mount {} is outside the closed process profile",
                mount.point.display()
            )));
        }
    }
    Ok(())
}

fn mount_is_admitted_writable(mount: &MountV1, required: &BTreeSet<PathBuf>) -> bool {
    const PRIVATE_API_ROOTS: [&str; 5] = ["/dev", "/proc", "/sys", "/tmp", "/var/tmp"];
    PRIVATE_API_ROOTS
        .iter()
        .any(|root| mount.point == Path::new(root) || mount.point.starts_with(root))
        || required
            .iter()
            .any(|root| mount.point == *root || mount.point.starts_with(root))
}

fn covering_mount<'a>(
    mounts: &'a [MountV1],
    path: &Path,
) -> Result<&'a MountV1, EffectdActivationError> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.point))
        .max_by_key(|mount| mount.point.components().count())
        .ok_or_else(|| {
            EffectdActivationError::MountNamespaceMismatch(format!(
                "no mount covers {}",
                path.display()
            ))
        })
}

fn canonical_absolute(path: &Path) -> bool {
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && path == normalized
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn open_safe_systemctl() -> Result<(Digest, File), EffectdActivationError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(SYSTEMCTL)
        .map_err(|_| EffectdActivationError::SystemctlIdentityMismatch)?;
    let digest = hash_safe_systemctl_file(&mut file)?;
    Ok((digest, file))
}

fn hash_safe_systemctl_file(file: &mut File) -> Result<Digest, EffectdActivationError> {
    file.seek(SeekFrom::Start(0))?;
    let before = file
        .metadata()
        .map_err(|_| EffectdActivationError::SystemctlIdentityMismatch)?;
    if !before.file_type().is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & (0o7000 | 0o022) != 0
        || before.mode() & 0o111 == 0
        || before.len() == 0
        || before.len() > MAX_SYSTEMCTL_EXECUTABLE_BYTES
    {
        return Err(EffectdActivationError::SystemctlIdentityMismatch);
    }
    let bytes = read_bounded(file, before.len())?;
    let after = file
        .metadata()
        .map_err(|_| EffectdActivationError::SystemctlIdentityMismatch)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(EffectdActivationError::SystemctlIdentityMismatch);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(Digest::hash_bytes(&bytes))
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, EffectdActivationError> {
    let mut file = File::open(path)?;
    read_bounded(&mut file, maximum)
}

fn read_bounded(file: &mut File, maximum: u64) -> Result<Vec<u8>, EffectdActivationError> {
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(EffectdActivationError::UnitUnavailable(
            "activation evidence exceeded its fixed bound".to_owned(),
        ));
    }
    Ok(bytes)
}

fn now_unix_ms() -> Result<u64, EffectdActivationError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EffectdActivationError::ClockUnavailable)?;
    u64::try_from(duration.as_millis()).map_err(|_| EffectdActivationError::ClockUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required_capabilities() -> BTreeSet<&'static str> {
        BTreeSet::from([
            "cap_chown",
            "cap_dac_override",
            "cap_dac_read_search",
            "cap_fowner",
            "cap_setgid",
            "cap_setuid",
        ])
    }

    fn unit_show() -> String {
        [
            "Id=ag-effectd.service",
            "MainPID=4242",
            "ControlGroup=/system.slice/ag-effectd.service",
            "InvocationID=11111111111111111111111111111111",
            "User=root",
            "Group=root",
            "ExecStart={ path=/usr/bin/ag-effectd ; argv[]=/usr/bin/ag-effectd --config /etc/agent-governor/effectd.toml ; ignore_errors=no ; }",
            "ExecStartPre={ path=/usr/bin/ag-effectd ; argv[]=/usr/bin/ag-effectd --config /etc/agent-governor/effectd.toml --check-config ; ignore_errors=no ; }",
            "ExecStartPost=",
            "ExecCondition=",
            "ExecReload=",
            "ExecStop=",
            "ExecStopPost=",
            "PrivateNetwork=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_setgid cap_setuid",
            "AmbientCapabilities=",
            "SupplementaryGroups=",
            "Environment=",
            "EnvironmentFiles=",
            "PassEnvironment=",
            "UnsetEnvironment=",
            "UMask=0077",
            "SecureBits=",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "DevicePolicy=closed",
            "PrivateMounts=yes",
            "ProtectClock=yes",
            "ProtectHostname=yes",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "RestrictNamespaces=yes",
            "RestrictSUIDSGID=yes",
            "MemoryDenyWriteExecute=yes",
            "LockPersonality=yes",
            "KeyringMode=private",
            "RemoveIPC=yes",
            "RestrictRealtime=yes",
            "SystemCallArchitectures=native",
            "SystemCallErrorNumber=EPERM",
            "LimitCORE=0",
            "LimitNOFILE=4096",
            "TasksMax=128",
            "DynamicUser=no",
            "ReadWritePaths=/state /objects /run/ag/proposal /run/ag/admin /srv/repo /stage",
            "ReadOnlyPaths=/run",
            "BindPaths=",
            "BindReadOnlyPaths=",
            "TemporaryFileSystem=",
            "RootDirectory=",
            "RootImage=",
            "StateDirectory=agent-governor/effectd",
            "StateDirectoryMode=0700",
            "RuntimeDirectory=",
            "CacheDirectory=",
            "LogsDirectory=",
            "ConfigurationDirectory=",
        ]
        .join("\n")
    }

    fn process_fixture() -> EffectdProcessActivationEvidenceV1 {
        EffectdProcessActivationEvidenceV1 {
            process_id: 4242,
            control_group: "/system.slice/ag-effectd.service".to_owned(),
            effective_uid: 0,
            effective_gid: 0,
            supplementary_groups: Vec::new(),
            no_new_privileges: true,
            capability_inheritable: 0,
            capability_permitted: 0xcf,
            capability_effective: 0xcf,
            capability_bounding: 0xcf,
            capability_ambient: 0,
            proc_status: Digest::hash_bytes(b"status"),
            proc_cgroup: Digest::hash_bytes(b"cgroup"),
        }
    }

    #[test]
    fn effective_unit_parser_and_validator_refuse_substitution() {
        let required_paths = BTreeSet::from([
            "/objects".to_owned(),
            "/run/ag/admin".to_owned(),
            "/run/ag/proposal".to_owned(),
            "/srv/repo".to_owned(),
            "/stage".to_owned(),
            "/state".to_owned(),
        ]);
        let parsed = parse_effective_unit(unit_show().as_bytes()).expect("strict unit");
        validate_effective_unit(
            &parsed,
            &required_capabilities(),
            &required_paths,
            &process_fixture(),
        )
        .expect("closed unit contract");

        for hostile in [
            unit_show().replace("MainPID=4242", "MainPID=4243"),
            unit_show().replace("--config /etc/agent-governor/effectd.toml ;", "--version ;"),
            unit_show().replace(
                "ExecStartPost=",
                "ExecStartPost={ path=/bin/sh ; argv[]=/bin/sh ; ignore_errors=no ; }",
            ),
            unit_show().replace("ProtectSystem=strict", "ProtectSystem=full"),
            unit_show().replace("Environment=", "Environment=LD_PRELOAD=/tmp/hostile.so"),
            unit_show().replace("UMask=0077", "UMask=0022"),
            unit_show().replace("DevicePolicy=closed", "DevicePolicy=auto"),
            unit_show().replace("SystemCallErrorNumber=EPERM", "SystemCallErrorNumber="),
            unit_show().replace("LimitNOFILE=4096", "LimitNOFILE=infinity"),
            unit_show().replace("AmbientCapabilities=", "AmbientCapabilities=cap_sys_admin"),
            unit_show().replace(" cap_setuid", ""),
            unit_show().replace("/srv/repo", "-/srv/repo"),
            unit_show().replace(" /stage", " /stage /srv"),
            unit_show().replace("ReadOnlyPaths=/run", "ReadOnlyPaths="),
            unit_show().replace("BindPaths=", "BindPaths=/opt:/srv/repo"),
            unit_show().replace(
                "StateDirectory=agent-governor/effectd",
                "StateDirectory=effectd-extra",
            ),
        ] {
            let parsed = parse_effective_unit(hostile.as_bytes()).expect("structural unit");
            assert!(
                validate_effective_unit(
                    &parsed,
                    &required_capabilities(),
                    &required_paths,
                    &process_fixture(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn effective_unit_query_requests_empty_properties() {
        let mut command = Command::new(SYSTEMCTL);
        configure_effective_unit_query(&mut command);
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();

        assert_eq!(&arguments[..3], ["show", "--no-pager", "--all"]);
        assert_eq!(
            &arguments[arguments.len() - 2..],
            ["--", "ag-effectd.service"]
        );
        assert_eq!(arguments.len(), EFFECTD_UNIT_PROPERTIES.len() + 5);
        for property in EFFECTD_UNIT_PROPERTIES {
            assert!(arguments.contains(&format!("--property={property}")));
        }
    }

    #[test]
    fn proc_status_parser_requires_exact_closed_masks() {
        let mask = capability_mask(&required_capabilities()).expect("mask");
        let status = format!(
            "Name:\tag-effectd\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t{mask:016x}\nCapEff:\t{mask:016x}\nCapBnd:\t{mask:016x}\nCapAmb:\t0000000000000000\n"
        );
        assert_eq!(
            parse_unified_control_group(b"0::/system.slice/ag-effectd.service\n")
                .expect("unified cgroup"),
            "/system.slice/ag-effectd.service"
        );
        assert!(parse_unified_control_group(b"1:name=/legacy\n0::/system.slice/x\n").is_err());
        let parsed = parse_proc_status(status.as_bytes()).expect("strict proc status");
        assert!(parsed.no_new_privileges);
        assert_eq!(parsed.capability_effective, mask);

        assert!(
            parse_proc_status(
                status
                    .replace("NoNewPrivs:\t1", "NoNewPrivs:\t0\nNoNewPrivs:\t1")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_proc_status(
                status
                    .replace(&format!("CapEff:\t{mask:016x}"), "CapEff:\tnot-hex")
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn mount_namespace_requires_rw_exceptions_and_ro_protected_roots() {
        let mountinfo = b"1 0 8:1 / / ro - ext4 /dev/root ro\n\
2 1 8:1 /usr /usr ro - ext4 /dev/root ro\n\
3 1 8:1 /boot /boot ro - ext4 /dev/root ro\n\
4 1 8:1 /etc /etc ro - ext4 /dev/root ro\n\
5 1 8:1 /srv /srv ro - ext4 /dev/root ro\n\
6 1 8:1 /state /state rw - ext4 /dev/root rw\n";
        let mounts = parse_mountinfo(mountinfo).expect("strict mountinfo");
        validate_mount_namespace(&mounts, &BTreeSet::from([PathBuf::from("/state")]))
            .expect("closed mount namespace");
        assert!(
            validate_mount_namespace(&mounts, &BTreeSet::from([PathBuf::from("/missing")]))
                .is_err()
        );
        let writable_etc = parse_mountinfo(
            std::str::from_utf8(mountinfo)
                .unwrap()
                .replace("/etc /etc ro", "/etc /etc rw")
                .as_bytes(),
        )
        .expect("hostile mountinfo");
        assert!(
            validate_mount_namespace(&writable_etc, &BTreeSet::from([PathBuf::from("/state")]))
                .is_err()
        );
        let unexpected = parse_mountinfo(
            [
                std::str::from_utf8(mountinfo).unwrap(),
                "7 1 8:1 /opt /opt rw - ext4 /dev/root rw\n",
            ]
            .concat()
            .as_bytes(),
        )
        .expect("structural extra mount");
        assert!(
            validate_mount_namespace(&unexpected, &BTreeSet::from([PathBuf::from("/state")]))
                .is_err()
        );
        assert!(
            parse_mountinfo(
                [
                    std::str::from_utf8(mountinfo).unwrap(),
                    "7 1 8:1 /state /state ro - ext4 /dev/root ro\n",
                ]
                .concat()
                .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn target_catalog_changes_capability_contract() {
        let pointer = EffectTargetConfigV1::ManagedPointer {
            id: "repo".to_owned(),
            allowed_root: PathBuf::from("/srv/repos"),
            repository: PathBuf::from("/srv/repos/service.git"),
            reference: "refs/heads/main".to_owned(),
            activation_genesis_object: "1111111111111111111111111111111111111111".to_owned(),
            activation_genesis_tree: "2222222222222222222222222222222222222222".to_owned(),
            activation_genesis_state: Digest::hash_bytes(b"genesis state"),
            repository_identity: Digest::hash_bytes(b"repo"),
            uid: 1000,
            gid: 1000,
            staging_root: PathBuf::from("/var/lib/agent-governor/effectd/stage"),
            promotion_ttl_ms: 1,
            helper: PathBuf::from("/usr/bin/git"),
            helper_executable: Digest::hash_bytes(b"git"),
            helper_launch_profile: Digest::hash_bytes(b"profile"),
        };
        assert!(matches!(
            pointer,
            EffectTargetConfigV1::ManagedPointer { .. }
        ));
        assert_eq!(capability_mask(&required_capabilities()).unwrap(), 0xcf);
    }
}
