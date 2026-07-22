//! Read-only deployment diagnostics for the three daemon authority planes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ag_primitives::Digest;
use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::config::{
    AgdConfigV1, EffectTargetConfigV1, EffectdConfigV1, FilesystemNodeCustodyV1, LoadedConfigV1,
    ProviderdConfigV1, SocketCustodyConfigV1, StoreConfigV1, load_config_with_identity,
};
use crate::custody::{CustodyError, CustodyNodeKindV1, validate_node};
use crate::effectd_activation::{EFFECTD_UNIT_PROPERTIES, validate_effectd_static_unit};

/// Canonical schema emitted by `agctl doctor`.
pub const DOCTOR_REPORT_SCHEMA_V1: &str = "ag.doctor-report/v1";

const MAX_SYSTEMD_SHOW_BYTES: usize = 1024 * 1024;
const MAX_SYSTEMD_STDERR_BYTES: usize = 64 * 1024;
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEMD_PROPERTIES: &[&str] = EFFECTD_UNIT_PROPERTIES;
const UNIT_IDS: [&str; 3] = ["agd.service", "ag-effectd.service", "ag-providerd.service"];

/// Explicit production configuration paths inspected by doctor.
#[derive(Clone, Debug)]
pub struct DoctorConfigPathsV1 {
    /// Governor configuration.
    pub agd: PathBuf,
    /// Effect broker configuration.
    pub effectd: PathBuf,
    /// Provider broker configuration.
    pub providerd: PathBuf,
}

/// Closed outcome for one diagnostic check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorCheckStatusV1 {
    /// The evidence was available and matched the enrolled requirement.
    Pass,
    /// The evidence was available and contradicted the requirement.
    Fail,
    /// The required evidence could not be obtained or safely interpreted.
    Unavailable,
}

/// One stable, machine-readable diagnostic result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheckV1 {
    /// Stable check identifier.
    pub id: String,
    /// Daemon or cross-plane scope.
    pub component: String,
    /// Closed result.
    pub status: DoctorCheckStatusV1,
    /// Terminal-safe, non-secret evidence summary.
    pub detail: String,
}

/// Complete three-plane deployment report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReportV1 {
    /// Exact report schema.
    pub schema: String,
    /// True only when every emitted required check passed.
    pub ready: bool,
    /// Stable ordered checks. An unavailable check is never a pass.
    pub checks: Vec<DoctorCheckV1>,
}

impl DoctorReportV1 {
    fn new(mut checks: Vec<DoctorCheckV1>) -> Self {
        checks.sort_by(|left, right| left.id.cmp(&right.id));
        let ready = checks
            .iter()
            .all(|check| check.status == DoctorCheckStatusV1::Pass);
        Self {
            schema: DOCTOR_REPORT_SCHEMA_V1.to_owned(),
            ready,
            checks,
        }
    }
}

#[derive(Clone, Debug)]
struct LoadedDaemonConfigsV1 {
    agd: Option<AgdConfigV1>,
    effectd: Option<EffectdConfigV1>,
    providerd: Option<ProviderdConfigV1>,
}

/// Inspects configuration, filesystem custody, executable bytes, and effective
/// systemd properties without loading a signing or provider credential.
///
/// The effective-unit query is a single fixed invocation of
/// `/usr/bin/systemctl show`; no configured string can become a command,
/// property name, or unit argument.
#[must_use]
pub fn diagnose_host(paths: &DoctorConfigPathsV1) -> DoctorReportV1 {
    let mut checks = Vec::new();
    let configs = LoadedDaemonConfigsV1 {
        agd: load_daemon_config("agd", &paths.agd, AgdConfigV1::validate, &mut checks),
        effectd: load_daemon_config(
            "ag-effectd",
            &paths.effectd,
            EffectdConfigV1::validate,
            &mut checks,
        ),
        providerd: load_daemon_config(
            "ag-providerd",
            &paths.providerd,
            ProviderdConfigV1::validate,
            &mut checks,
        ),
    };

    inspect_cross_plane_enrollment(&configs, &mut checks);
    inspect_filesystem(&configs, &mut checks);
    inspect_executables(&configs, &mut checks);

    match query_systemd() {
        Ok(bytes) => match parse_systemd_show(&bytes) {
            Ok(units) => inspect_systemd(&configs, &units, &mut checks),
            Err(error) => add_systemd_unavailable(&mut checks, &error),
        },
        Err(error) => add_systemd_unavailable(&mut checks, &error.to_string()),
    }
    DoctorReportV1::new(checks)
}

fn load_daemon_config<T>(
    component: &str,
    path: &Path,
    validate: impl FnOnce(&T) -> Result<(), crate::config::ConfigError>,
    checks: &mut Vec<DoctorCheckV1>,
) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    let loaded: LoadedConfigV1<T> = match load_config_with_identity(path, true) {
        Ok(loaded) => loaded,
        Err(error) => {
            checks.push(check(
                format!("{component}.config"),
                component,
                DoctorCheckStatusV1::Fail,
                format!("strict root-custody load failed: {error}"),
            ));
            return None;
        }
    };
    if let Err(error) = validate(&loaded.config) {
        checks.push(check(
            format!("{component}.config"),
            component,
            DoctorCheckStatusV1::Fail,
            format!("schema validation failed: {error}"),
        ));
        return None;
    }
    checks.push(check(
        format!("{component}.config"),
        component,
        DoctorCheckStatusV1::Pass,
        format!("validated exact bytes {}", loaded.exact_bytes_digest),
    ));
    Some(loaded.config)
}

fn inspect_cross_plane_enrollment(
    configs: &LoadedDaemonConfigsV1,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let (Some(agd), Some(effectd), Some(providerd)) =
        (&configs.agd, &configs.effectd, &configs.providerd)
    else {
        checks.push(check(
            "cross-plane.authority-context",
            "cross-plane",
            DoctorCheckStatusV1::Unavailable,
            "all three validated configurations are required",
        ));
        checks.push(check(
            "cross-plane.daemon-enrollment",
            "cross-plane",
            DoctorCheckStatusV1::Unavailable,
            "all three validated configurations are required",
        ));
        checks.push(check(
            "cross-plane.service-unit-observations",
            "cross-plane",
            DoctorCheckStatusV1::Unavailable,
            "all three validated configurations are required",
        ));
        return;
    };

    let context_matches = agd.authority_domain == effectd.authority_domain
        && agd.authority_domain == providerd.authority_domain
        && agd.epoch == effectd.epoch
        && agd.epoch == providerd.epoch;
    checks.push(boolean_check(
        "cross-plane.authority-context",
        "cross-plane",
        context_matches,
        "authority domain and epoch agree",
        "authority domain or epoch differs across stores",
    ));

    let agd_to_effectd = agd.effectd_peer.rpc_key.principal
        == effectd.rpc_signing_identity.principal
        && agd.effectd_peer.rpc_key.key_id == effectd.rpc_signing_identity.key_id
        && agd.effectd_peer.rpc_key.public_key == effectd.rpc_signing_identity.public_key;
    let effectd_to_agd = effectd.agd_peer.rpc_key.principal == agd.rpc_signing_identity.principal
        && effectd.agd_peer.rpc_key.key_id == agd.rpc_signing_identity.key_id
        && effectd.agd_peer.rpc_key.public_key == agd.rpc_signing_identity.public_key;
    let provider_to_agd = providerd.caller_peer.rpc_key.principal
        == agd.rpc_signing_identity.principal
        && providerd.caller_peer.rpc_key.key_id == agd.rpc_signing_identity.key_id
        && providerd.caller_peer.rpc_key.public_key == agd.rpc_signing_identity.public_key;
    checks.push(boolean_check(
        "cross-plane.daemon-enrollment",
        "cross-plane",
        agd_to_effectd && effectd_to_agd && provider_to_agd,
        "daemon signing identities match every opposite-plane enrollment",
        "daemon signing identity and opposite-plane enrollment differ",
    ));
    let service_units_match = effectd.agd_peer.cgroup_contains.as_deref() == Some("agd.service")
        && providerd.caller_peer.cgroup_contains.as_deref() == Some("agd.service")
        && agd.effectd_peer.cgroup_contains.as_deref() == Some("ag-effectd.service");
    checks.push(boolean_check(
        "cross-plane.service-unit-observations",
        "cross-plane",
        service_units_match,
        "configured daemon peer observations name the fixed service units",
        "configured daemon peer observation names a different or absent service unit",
    ));
}

fn inspect_filesystem(configs: &LoadedDaemonConfigsV1, checks: &mut Vec<DoctorCheckV1>) {
    if let Some(config) = &configs.agd {
        inspect_store("agd", &config.store, checks);
        inspect_socket(
            "agd.socket.control",
            "agd",
            &config.control_socket,
            &config.control_socket_custody,
            checks,
        );
    } else {
        add_component_unavailable("agd", "filesystem", checks);
    }
    if let Some(config) = &configs.effectd {
        inspect_store("ag-effectd", &config.store, checks);
        inspect_socket(
            "ag-effectd.socket.proposal",
            "ag-effectd",
            &config.proposal_socket,
            &config.proposal_socket_custody,
            checks,
        );
        inspect_socket(
            "ag-effectd.socket.admin",
            "ag-effectd",
            &config.admin_socket,
            &config.admin_socket_custody,
            checks,
        );
    } else {
        add_component_unavailable("ag-effectd", "filesystem", checks);
    }
    if let Some(config) = &configs.providerd {
        inspect_store("ag-providerd", &config.store, checks);
        inspect_socket(
            "ag-providerd.socket.provider",
            "ag-providerd",
            &config.socket,
            &config.socket_custody,
            checks,
        );
    } else {
        add_component_unavailable("ag-providerd", "filesystem", checks);
    }
}

fn inspect_store(component: &str, store: &StoreConfigV1, checks: &mut Vec<DoctorCheckV1>) {
    let Some(parent) = store.database.parent() else {
        checks.push(check(
            format!("{component}.store.database-parent"),
            component,
            DoctorCheckStatusV1::Fail,
            "database path has no parent",
        ));
        return;
    };
    inspect_node(
        format!("{component}.store.database-parent"),
        component,
        parent,
        &store.store_custody.database_parent,
        CustodyNodeKindV1::Directory,
        checks,
    );
    inspect_node(
        format!("{component}.store.object-root"),
        component,
        &store.object_store,
        &store.store_custody.object_store,
        CustodyNodeKindV1::Directory,
        checks,
    );
    inspect_node(
        format!("{component}.store.database"),
        component,
        &store.database,
        &store.store_custody.database,
        CustodyNodeKindV1::RegularFile,
        checks,
    );
    let lock = writer_lock_path(&store.database);
    inspect_node(
        format!("{component}.store.writer-lock"),
        component,
        &lock,
        &store.store_custody.writer_lock,
        CustodyNodeKindV1::RegularFile,
        checks,
    );
}

fn inspect_socket(
    id: &str,
    component: &str,
    path: &Path,
    custody: &SocketCustodyConfigV1,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let Some(parent) = path.parent() else {
        checks.push(check(
            format!("{id}.parent"),
            component,
            DoctorCheckStatusV1::Fail,
            "socket path has no parent",
        ));
        return;
    };
    inspect_node(
        format!("{id}.parent"),
        component,
        parent,
        &custody.parent,
        CustodyNodeKindV1::Directory,
        checks,
    );
    inspect_node(
        id.to_owned(),
        component,
        path,
        &custody.node,
        CustodyNodeKindV1::UnixSocket,
        checks,
    );
}

fn inspect_node(
    id: String,
    component: &str,
    path: &Path,
    policy: &FilesystemNodeCustodyV1,
    kind: CustodyNodeKindV1,
    checks: &mut Vec<DoctorCheckV1>,
) {
    match validate_node(path, policy, kind) {
        Ok(()) => checks.push(check(
            id,
            component,
            DoctorCheckStatusV1::Pass,
            format!(
                "{} matches enrolled type, owner, group, and mode",
                path.display()
            ),
        )),
        Err(error) => checks.push(check(
            id,
            component,
            custody_error_status(&error),
            error.to_string(),
        )),
    }
}

fn custody_error_status(error: &CustodyError) -> DoctorCheckStatusV1 {
    match error {
        CustodyError::Io { source, .. }
            if !matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            DoctorCheckStatusV1::Unavailable
        }
        CustodyError::UnsafePath(_)
        | CustodyError::UnsafeAncestor(_)
        | CustodyError::CustodyMismatch(_)
        | CustodyError::Io { .. } => DoctorCheckStatusV1::Fail,
    }
}

fn writer_lock_path(database: &Path) -> PathBuf {
    let mut name = database.file_name().unwrap_or_default().to_os_string();
    name.push(".writer.lock");
    database.with_file_name(name)
}

fn inspect_executables(configs: &LoadedDaemonConfigsV1, checks: &mut Vec<DoctorCheckV1>) {
    let mut agd_digests = BTreeSet::new();
    if let Some(config) = &configs.effectd
        && let Some(digest) = &config.agd_peer.executable_identity
    {
        agd_digests.insert(digest.clone());
    }
    if let Some(config) = &configs.providerd
        && let Some(digest) = &config.caller_peer.executable_identity
    {
        agd_digests.insert(digest.clone());
    }
    inspect_enrolled_executable("agd", Path::new("/usr/bin/agd"), &agd_digests, checks);

    let mut effectd_digests = BTreeSet::new();
    if let Some(config) = &configs.agd
        && let Some(digest) = &config.effectd_peer.executable_identity
    {
        effectd_digests.insert(digest.clone());
    }
    inspect_enrolled_executable(
        "ag-effectd",
        Path::new("/usr/bin/ag-effectd"),
        &effectd_digests,
        checks,
    );
}

fn inspect_enrolled_executable(
    component: &str,
    path: &Path,
    enrolled: &BTreeSet<Digest>,
    checks: &mut Vec<DoctorCheckV1>,
) {
    if enrolled.is_empty() {
        return;
    }
    if enrolled.len() != 1 {
        checks.push(check(
            format!("{component}.executable.identity"),
            component,
            DoctorCheckStatusV1::Fail,
            "opposite-plane executable enrollments disagree",
        ));
        return;
    }
    let expected = enrolled.first().expect("nonempty enrolled digest set");
    match hash_executable(path) {
        Ok(observed) => checks.push(boolean_check(
            format!("{component}.executable.identity"),
            component,
            observed == *expected,
            format!("installed bytes match {expected}"),
            format!("installed bytes {observed} do not match {expected}"),
        )),
        Err(error) => checks.push(check(
            format!("{component}.executable.identity"),
            component,
            DoctorCheckStatusV1::Unavailable,
            error,
        )),
    }
}

fn hash_executable(path: &Path) -> Result<Digest, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let before = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        return Err(format!(
            "{} is not a single-link regular executable",
            path.display()
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|error| format!("cannot reinspect {}: {error}", path.display()))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(format!("{} changed while it was hashed", path.display()));
    }
    Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| format!("cannot construct executable digest: {error}"))
}

#[derive(Debug, Error)]
enum SystemdQueryErrorV1 {
    #[error("fixed systemctl show invocation failed: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("fixed systemctl {stream} pipe is unavailable")]
    PipeUnavailable { stream: &'static str },
    #[error("fixed systemctl process ID {process_id} cannot identify its process group")]
    ProcessIdOutOfRange { process_id: u32 },
    #[error("fixed systemctl {stream} reader could not start: {source}")]
    ReaderSpawn {
        stream: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("fixed systemctl {stream} read failed: {source}")]
    Read {
        stream: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("fixed systemctl {stream} output exceeded its diagnostic bound")]
    OutputTooLarge { stream: &'static str },
    #[error("fixed systemctl {stream} reader failed")]
    ReaderFailed { stream: &'static str },
    #[error("fixed systemctl show status polling failed: {0}")]
    Poll(#[source] std::io::Error),
    #[error("fixed systemctl show exceeded its {milliseconds} ms deadline")]
    DeadlineExceeded { milliseconds: u128 },
    #[error("fixed systemctl show termination after its deadline failed: {0}")]
    Termination(#[source] std::io::Error),
    #[error("systemctl show exited unsuccessfully: {detail}")]
    Unsuccessful { detail: String },
}

#[derive(Debug)]
struct BoundedSystemdOutputV1 {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct ReapingSystemdChildV1 {
    child: Child,
    process_group: Pid,
    armed: bool,
}

impl ReapingSystemdChildV1 {
    fn terminate(&mut self) -> std::io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        let group_error = match killpg(self.process_group, Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => None,
            Err(error) => Some(std::io::Error::from_raw_os_error(error as i32)),
        };
        if self.child.try_wait()?.is_none()
            && let Err(error) = self.child.kill()
            && self.child.try_wait()?.is_none()
        {
            return Err(error);
        }
        let wait_result = self.child.wait().map(|_| ());
        if let Some(error) = group_error {
            return Err(error);
        }
        wait_result
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReapingSystemdChildV1 {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn read_bounded_systemd_stream(
    mut stream: impl Read,
    maximum: usize,
    stream_name: &'static str,
) -> Result<Vec<u8>, SystemdQueryErrorV1> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|source| SystemdQueryErrorV1::Read {
                stream: stream_name,
                source,
            })?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(count) > maximum {
            return Err(SystemdQueryErrorV1::OutputTooLarge {
                stream: stream_name,
            });
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn run_bounded_systemd_command(
    command: &mut Command,
    timeout: Duration,
) -> Result<BoundedSystemdOutputV1, SystemdQueryErrorV1> {
    let mut spawned = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(SystemdQueryErrorV1::Spawn)?;
    let process_id = spawned.id();
    let Ok(process_group) = i32::try_from(process_id) else {
        let _ = spawned.kill();
        let _ = spawned.wait();
        return Err(SystemdQueryErrorV1::ProcessIdOutOfRange { process_id });
    };
    let mut child = ReapingSystemdChildV1 {
        child: spawned,
        process_group: Pid::from_raw(process_group),
        armed: true,
    };
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or(SystemdQueryErrorV1::PipeUnavailable { stream: "stdout" })?;
    let stderr = child
        .child
        .stderr
        .take()
        .ok_or(SystemdQueryErrorV1::PipeUnavailable { stream: "stderr" })?;
    let stdout_reader = thread::Builder::new()
        .name("agctl-doctor-systemctl-stdout".to_owned())
        .spawn(move || read_bounded_systemd_stream(stdout, MAX_SYSTEMD_SHOW_BYTES, "stdout"))
        .map_err(|source| SystemdQueryErrorV1::ReaderSpawn {
            stream: "stdout",
            source,
        })?;
    let stderr_reader = thread::Builder::new()
        .name("agctl-doctor-systemctl-stderr".to_owned())
        .spawn(move || read_bounded_systemd_stream(stderr, MAX_SYSTEMD_STDERR_BYTES, "stderr"))
        .map_err(|source| SystemdQueryErrorV1::ReaderSpawn {
            stream: "stderr",
            source,
        })?;
    let deadline = Instant::now() + timeout;
    let mut status = None;
    loop {
        let readers_finished = stdout_reader.is_finished() && stderr_reader.is_finished();
        if readers_finished && status.is_none() {
            status = child.child.try_wait().map_err(SystemdQueryErrorV1::Poll)?;
        }
        if readers_finished && status.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            child
                .terminate()
                .map_err(SystemdQueryErrorV1::Termination)?;
            return Err(SystemdQueryErrorV1::DeadlineExceeded {
                milliseconds: timeout.as_millis(),
            });
        }
        thread::sleep(Duration::from_millis(10).min(deadline.saturating_duration_since(now)));
    }
    let status = status.expect("completed process status was checked above");
    child.disarm();
    let stdout = stdout_reader
        .join()
        .map_err(|_| SystemdQueryErrorV1::ReaderFailed { stream: "stdout" })??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| SystemdQueryErrorV1::ReaderFailed { stream: "stderr" })??;
    Ok(BoundedSystemdOutputV1 {
        status,
        stdout,
        stderr,
    })
}

fn query_systemd() -> Result<Vec<u8>, SystemdQueryErrorV1> {
    let mut command = Command::new(SYSTEMCTL);
    command.args(["show", "--no-pager"]);
    for property in SYSTEMD_PROPERTIES {
        command.arg(format!("--property={property}"));
    }
    command
        .args([
            "--",
            "agd.service",
            "ag-effectd.service",
            "ag-providerd.service",
        ])
        .env_clear();
    let output = run_bounded_systemd_command(&mut command, SYSTEMCTL_TIMEOUT)?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(SystemdQueryErrorV1::Unsuccessful {
            detail: terminal_safe(message.trim()),
        });
    }
    Ok(output.stdout)
}

#[derive(Clone, Debug)]
struct SystemdUnitShowV1 {
    properties: BTreeMap<String, String>,
}

impl SystemdUnitShowV1 {
    fn get(&self, key: &str) -> &str {
        self.properties.get(key).map_or("", String::as_str)
    }
}

fn parse_systemd_show(bytes: &[u8]) -> Result<BTreeMap<String, SystemdUnitShowV1>, String> {
    if bytes.len() > MAX_SYSTEMD_SHOW_BYTES {
        return Err("systemctl output exceeds the fixed parser bound".to_owned());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "systemctl output is not UTF-8")?;
    if text.contains('\r') || text.contains('\0') {
        return Err("systemctl output contains forbidden control bytes".to_owned());
    }
    let allowed: BTreeSet<&str> = SYSTEMD_PROPERTIES.iter().copied().collect();
    let mut units = BTreeMap::new();
    let mut current: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if current.is_empty() {
                continue;
            }
            if current.len() != allowed.len() {
                return Err("systemctl unit block has a missing property".to_owned());
            }
            let id = current
                .get("Id")
                .ok_or_else(|| "systemctl unit block lacks Id".to_owned())?
                .clone();
            if !UNIT_IDS.contains(&id.as_str()) {
                return Err(format!("systemctl returned unexpected unit {id}"));
            }
            if units
                .insert(
                    id,
                    SystemdUnitShowV1 {
                        properties: std::mem::take(&mut current),
                    },
                )
                .is_some()
            {
                return Err("systemctl returned a duplicate unit block".to_owned());
            }
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "systemctl property line lacks '='".to_owned())?;
        if !allowed.contains(key) {
            return Err(format!("systemctl returned unexpected property {key}"));
        }
        if current.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("systemctl returned duplicate property {key}"));
        }
    }
    if units.len() != UNIT_IDS.len() {
        return Err("systemctl did not return every fixed daemon unit".to_owned());
    }
    Ok(units)
}

fn inspect_systemd(
    configs: &LoadedDaemonConfigsV1,
    units: &BTreeMap<String, SystemdUnitShowV1>,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let effectd_capabilities = configs.effectd.as_ref().map(required_effectd_capabilities);
    let specifications = [
        (
            "agd",
            "agd.service",
            "ag-governor",
            "ag-governor",
            "/usr/bin/agd",
            Some(BTreeSet::new()),
            false,
        ),
        (
            "ag-effectd",
            "ag-effectd.service",
            "root",
            "root",
            "/usr/bin/ag-effectd",
            effectd_capabilities,
            false,
        ),
        (
            "ag-providerd",
            "ag-providerd.service",
            "ag-provider",
            "ag-provider",
            "/usr/bin/ag-providerd",
            Some(BTreeSet::new()),
            true,
        ),
    ];

    for (component, unit_id, user, group, executable, expected_capabilities, needs_network) in
        specifications
    {
        let unit = units
            .get(unit_id)
            .expect("strict parser returned every fixed unit");
        inspect_systemd_unit(
            unit,
            &ExpectedUnitV1 {
                component,
                unit_id,
                user,
                group,
                executable,
                capabilities: expected_capabilities,
                needs_network,
            },
            checks,
        );
    }

    inspect_configured_unit_bindings(configs, checks);
    inspect_effectd_write_paths(
        configs.effectd.as_ref(),
        &units["ag-effectd.service"],
        checks,
    );
    inspect_effectd_activation_profile(
        configs.effectd.as_ref(),
        &units["ag-effectd.service"],
        checks,
    );
}

struct ExpectedUnitV1<'a> {
    component: &'a str,
    unit_id: &'a str,
    user: &'a str,
    group: &'a str,
    executable: &'a str,
    capabilities: Option<BTreeSet<&'a str>>,
    needs_network: bool,
}

fn inspect_systemd_unit(
    unit: &SystemdUnitShowV1,
    expected: &ExpectedUnitV1<'_>,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let component = expected.component;
    checks.push(boolean_check(
        format!("{component}.systemd.unit"),
        component,
        unit.get("Id") == expected.unit_id,
        format!("effective unit is {}", expected.unit_id),
        format!(
            "effective unit is {}, expected {}",
            unit.get("Id"),
            expected.unit_id
        ),
    ));
    checks.push(boolean_check(
        format!("{component}.systemd.user"),
        component,
        unit.get("User") == expected.user && unit.get("Group") == expected.group,
        format!(
            "effective service identity is {}:{}",
            expected.user, expected.group
        ),
        format!(
            "effective service identity is {}:{}, expected {}:{}",
            unit.get("User"),
            unit.get("Group"),
            expected.user,
            expected.group
        ),
    ));
    match exec_start_path(unit.get("ExecStart")) {
        Ok(path) => checks.push(boolean_check(
            format!("{component}.systemd.exec-start"),
            component,
            path == Path::new(expected.executable),
            format!("effective ExecStart is {}", expected.executable),
            format!(
                "effective ExecStart is {}, expected {}",
                path.display(),
                expected.executable
            ),
        )),
        Err(error) => checks.push(check(
            format!("{component}.systemd.exec-start"),
            component,
            DoctorCheckStatusV1::Unavailable,
            error,
        )),
    }
    inspect_systemd_privilege_floor(unit, expected, checks);

    let expected_families = if expected.needs_network {
        BTreeSet::from(["AF_UNIX", "AF_INET", "AF_INET6"])
    } else {
        BTreeSet::from(["AF_UNIX"])
    };
    let network_matches = if expected.needs_network {
        unit.get("PrivateNetwork") == "no"
            && words(unit.get("RestrictAddressFamilies")) == expected_families
    } else {
        unit.get("PrivateNetwork") == "yes"
            && words(unit.get("RestrictAddressFamilies")) == expected_families
    };
    checks.push(boolean_check(
        format!("{component}.systemd.network"),
        component,
        network_matches,
        if expected.needs_network {
            "provider network is enabled only for AF_UNIX/AF_INET/AF_INET6"
        } else {
            "network namespace is private and restricted to AF_UNIX"
        },
        if expected.needs_network {
            "provider network is disabled or its address-family bound drifted"
        } else {
            "network access is enabled or its address-family bound drifted"
        },
    ));
}

fn inspect_systemd_privilege_floor(
    unit: &SystemdUnitShowV1,
    expected: &ExpectedUnitV1<'_>,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let component = expected.component;
    match &expected.capabilities {
        Some(capabilities) => checks.push(boolean_check(
            format!("{component}.systemd.capability-bound"),
            component,
            &words(unit.get("CapabilityBoundingSet")) == capabilities,
            "effective capability bound is exact",
            format!(
                "unexpected effective capability bound: {}",
                unit.get("CapabilityBoundingSet")
            ),
        )),
        None => checks.push(check(
            format!("{component}.systemd.capability-bound"),
            component,
            DoctorCheckStatusV1::Unavailable,
            "validated component configuration is required to derive the capability bound",
        )),
    }
    checks.push(boolean_check(
        format!("{component}.systemd.ambient-capabilities"),
        component,
        words(unit.get("AmbientCapabilities")).is_empty(),
        "effective ambient capability set is empty",
        format!(
            "unexpected effective ambient capabilities: {}",
            unit.get("AmbientCapabilities")
        ),
    ));
    checks.push(boolean_check(
        format!("{component}.systemd.supplementary-groups"),
        component,
        words(unit.get("SupplementaryGroups")).is_empty(),
        "effective supplementary group set is empty",
        format!(
            "unexpected effective supplementary groups: {}",
            unit.get("SupplementaryGroups")
        ),
    ));
    checks.push(boolean_check(
        format!("{component}.systemd.no-new-privileges"),
        component,
        unit.get("NoNewPrivileges") == "yes",
        "effective NoNewPrivileges is enabled",
        format!(
            "effective NoNewPrivileges is {}, expected yes",
            unit.get("NoNewPrivileges")
        ),
    ));
    checks.push(boolean_check(
        format!("{component}.systemd.protect-system"),
        component,
        unit.get("ProtectSystem") == "strict",
        "effective ProtectSystem is strict",
        format!(
            "effective ProtectSystem is {}, expected strict",
            unit.get("ProtectSystem")
        ),
    ));
}

fn inspect_configured_unit_bindings(
    configs: &LoadedDaemonConfigsV1,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let entries = [
        (
            "agd",
            configs
                .agd
                .as_ref()
                .map(|config| config.rpc_signing_identity.private_key_credential.as_path()),
            "agd.service",
        ),
        (
            "ag-effectd",
            configs
                .effectd
                .as_ref()
                .map(|config| config.rpc_signing_identity.private_key_credential.as_path()),
            "ag-effectd.service",
        ),
        (
            "ag-providerd",
            configs
                .providerd
                .as_ref()
                .map(|config| config.rpc_signing_identity.private_key_credential.as_path()),
            "ag-providerd.service",
        ),
    ];
    for (component, credential, unit) in entries {
        let Some(credential) = credential else {
            checks.push(check(
                format!("{component}.systemd.credential-unit"),
                component,
                DoctorCheckStatusV1::Unavailable,
                "validated component configuration is unavailable",
            ));
            continue;
        };
        let expected_prefix = PathBuf::from(format!("/run/credentials/{unit}"));
        checks.push(boolean_check(
            format!("{component}.systemd.credential-unit"),
            component,
            credential.parent() == Some(expected_prefix.as_path()),
            format!("credential path is bound to {unit}"),
            format!("credential path is not bound to {unit}"),
        ));
    }
}

fn inspect_effectd_write_paths(
    config: Option<&EffectdConfigV1>,
    unit: &SystemdUnitShowV1,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let Some(config) = config else {
        checks.push(check(
            "ag-effectd.systemd.read-write-paths",
            "ag-effectd",
            DoctorCheckStatusV1::Unavailable,
            "validated effectd configuration is unavailable",
        ));
        return;
    };
    let parsed = match parse_read_write_paths(unit.get("ReadWritePaths")) {
        Ok(paths) => paths,
        Err(error) => {
            checks.push(check(
                "ag-effectd.systemd.read-write-paths",
                "ag-effectd",
                DoctorCheckStatusV1::Unavailable,
                error,
            ));
            return;
        }
    };
    let required = match required_effectd_write_paths(config) {
        Ok(required) => required,
        Err(error) => {
            checks.push(check(
                "ag-effectd.systemd.read-write-paths",
                "ag-effectd",
                DoctorCheckStatusV1::Unavailable,
                error,
            ));
            return;
        }
    };
    checks.push(boolean_check(
        "ag-effectd.systemd.read-write-paths",
        "ag-effectd",
        parsed == required,
        "effective writable paths exactly equal the closed configured effectd set",
        format!(
            "effective writable paths differ from the closed configured effectd set: observed={parsed:?}, required={required:?}"
        ),
    ));
}

fn inspect_effectd_activation_profile(
    config: Option<&EffectdConfigV1>,
    unit: &SystemdUnitShowV1,
    checks: &mut Vec<DoctorCheckV1>,
) {
    let Some(config) = config else {
        checks.push(check(
            "ag-effectd.systemd.activation-profile",
            "ag-effectd",
            DoctorCheckStatusV1::Unavailable,
            "validated effectd configuration is required for the static activation profile",
        ));
        return;
    };
    let paths = required_effectd_write_paths(config).and_then(|paths| {
        paths
            .into_iter()
            .map(|path| {
                path.into_os_string().into_string().map_err(|_| {
                    "effectd writable path is not UTF-8 for live profile parity".to_owned()
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()
    });
    let result = paths.and_then(|paths| {
        validate_effectd_static_unit(
            &unit.properties,
            &required_effectd_capabilities(config),
            &paths,
        )
        .map_err(|error| error.to_string())
    });
    match result {
        Ok(()) => checks.push(check(
            "ag-effectd.systemd.activation-profile",
            "ag-effectd",
            DoctorCheckStatusV1::Pass,
            "effective static unit properties match the live activation profile",
        )),
        Err(error) => checks.push(check(
            "ag-effectd.systemd.activation-profile",
            "ag-effectd",
            DoctorCheckStatusV1::Fail,
            error,
        )),
    }
}

/// Derive the exact effective `ReadWritePaths=` set from effectd config.
///
/// # Errors
///
/// Returns an error if any required database, socket, or target path lacks a
/// normalized absolute parent or root.
pub fn required_effectd_write_paths(config: &EffectdConfigV1) -> Result<BTreeSet<PathBuf>, String> {
    let mut required = BTreeSet::new();
    insert_parent(&mut required, &config.store.database, "effectd database")?;
    insert_normalized_absolute(
        &mut required,
        &config.store.object_store,
        "effectd object store",
    )?;
    insert_parent(
        &mut required,
        &config.proposal_socket,
        "effectd proposal socket",
    )?;
    insert_parent(&mut required, &config.admin_socket, "effectd admin socket")?;
    for target in &config.targets {
        match target {
            EffectTargetConfigV1::ManagedFile { path, .. } => {
                insert_parent(&mut required, path, "managed-file target")?;
            }
            EffectTargetConfigV1::ManagedPointer {
                repository,
                staging_root,
                ..
            } => {
                insert_normalized_absolute(
                    &mut required,
                    repository,
                    "managed-pointer repository",
                )?;
                insert_normalized_absolute(
                    &mut required,
                    staging_root,
                    "managed-pointer staging root",
                )?;
            }
            EffectTargetConfigV1::SystemdUnit { .. }
            | EffectTargetConfigV1::SystemdManager { .. } => {}
        }
    }
    Ok(required)
}

/// Derive the exact effective capability set from effectd's target catalog.
#[must_use]
pub fn required_effectd_capabilities(config: &EffectdConfigV1) -> BTreeSet<&'static str> {
    let mut capabilities = BTreeSet::from([
        "cap_chown",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_fowner",
    ]);
    if config
        .targets
        .iter()
        .any(|target| matches!(target, EffectTargetConfigV1::ManagedPointer { .. }))
    {
        capabilities.insert("cap_setgid");
        capabilities.insert("cap_setuid");
    }
    capabilities
}

fn insert_parent(paths: &mut BTreeSet<PathBuf>, path: &Path, label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent"))?;
    insert_normalized_absolute(paths, parent, label)
}

fn insert_normalized_absolute(
    paths: &mut BTreeSet<PathBuf>,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute()
        || path != normalized
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(format!("{label} path is not canonical and absolute"));
    }
    paths.insert(normalized);
    Ok(())
}

fn parse_read_write_paths(value: &str) -> Result<BTreeSet<PathBuf>, String> {
    let mut paths = BTreeSet::new();
    for raw in value.split_ascii_whitespace() {
        if raw.starts_with(['-', '+', '!']) || raw.contains(['"', '\'', '\\']) {
            return Err("unsupported effective ReadWritePaths syntax".to_owned());
        }
        let path = PathBuf::from(raw);
        let normalized: PathBuf = path.components().collect();
        if !path.is_absolute()
            || path != normalized
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err("effective ReadWritePaths contains a noncanonical path".to_owned());
        }
        paths.insert(path);
    }
    Ok(paths)
}

fn exec_start_path(value: &str) -> Result<PathBuf, String> {
    let marker = "path=";
    let positions: Vec<_> = value.match_indices(marker).collect();
    if positions.len() != 1 {
        return Err("effective ExecStart does not contain exactly one path".to_owned());
    }
    let rest = &value[positions[0].0 + marker.len()..];
    let end = rest
        .find(" ;")
        .ok_or_else(|| "effective ExecStart path has unsupported syntax".to_owned())?;
    let path = PathBuf::from(&rest[..end]);
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute()
        || path != normalized
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("effective ExecStart path is not canonical and absolute".to_owned());
    }
    Ok(path)
}

fn words(value: &str) -> BTreeSet<&str> {
    value.split_ascii_whitespace().collect()
}

fn add_systemd_unavailable(checks: &mut Vec<DoctorCheckV1>, detail: &str) {
    for component in ["agd", "ag-effectd", "ag-providerd"] {
        checks.push(check(
            format!("{component}.systemd.effective-properties"),
            component,
            DoctorCheckStatusV1::Unavailable,
            detail,
        ));
    }
}

fn add_component_unavailable(component: &str, family: &str, checks: &mut Vec<DoctorCheckV1>) {
    checks.push(check(
        format!("{component}.{family}"),
        component,
        DoctorCheckStatusV1::Unavailable,
        "validated component configuration is unavailable",
    ));
}

fn boolean_check(
    id: impl Into<String>,
    component: &str,
    passes: bool,
    pass_detail: impl Into<String>,
    fail_detail: impl Into<String>,
) -> DoctorCheckV1 {
    check(
        id,
        component,
        if passes {
            DoctorCheckStatusV1::Pass
        } else {
            DoctorCheckStatusV1::Fail
        },
        if passes {
            pass_detail.into()
        } else {
            fail_detail.into()
        },
    )
}

fn check(
    id: impl Into<String>,
    component: &str,
    status: DoctorCheckStatusV1,
    detail: impl Into<String>,
) -> DoctorCheckV1 {
    DoctorCheckV1 {
        id: id.into(),
        component: component.to_owned(),
        status,
        detail: terminal_safe(&detail.into()),
    }
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .take(2048)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnitBlockV1<'a> {
        id: &'a str,
        user: &'a str,
        group: &'a str,
        executable: &'a str,
        private_network: &'a str,
        families: &'a str,
        capabilities: &'a str,
        write_paths: &'a str,
    }

    fn unit_block(unit: &UnitBlockV1<'_>) -> String {
        let effectd = unit.id == "ag-effectd.service";
        let mut properties: BTreeMap<&str, String> = SYSTEMD_PROPERTIES
            .iter()
            .map(|property| (*property, String::new()))
            .collect();
        properties.insert("Id", unit.id.to_owned());
        properties.insert("MainPID", "4242".to_owned());
        properties.insert("ControlGroup", format!("/system.slice/{}", unit.id));
        properties.insert(
            "InvocationID",
            "11111111111111111111111111111111".to_owned(),
        );
        properties.insert("User", unit.user.to_owned());
        properties.insert("Group", unit.group.to_owned());
        let argv = if effectd {
            "/usr/bin/ag-effectd --config /etc/agent-governor/effectd.toml"
        } else {
            unit.executable
        };
        properties.insert(
            "ExecStart",
            format!(
                "{{ path={} ; argv[]={argv} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
                unit.executable
            ),
        );
        if effectd {
            properties.insert(
                "ExecStartPre",
                "{ path=/usr/bin/ag-effectd ; argv[]=/usr/bin/ag-effectd --config /etc/agent-governor/effectd.toml --check-config ; ignore_errors=no ; }".to_owned(),
            );
        }
        properties.insert("PrivateNetwork", unit.private_network.to_owned());
        properties.insert("RestrictAddressFamilies", unit.families.to_owned());
        properties.insert("CapabilityBoundingSet", unit.capabilities.to_owned());
        properties.insert("UMask", "0077".to_owned());
        properties.insert("DevicePolicy", "closed".to_owned());
        properties.insert("ProtectClock", "yes".to_owned());
        properties.insert("ProtectHostname", "yes".to_owned());
        properties.insert("KeyringMode", "private".to_owned());
        properties.insert("RemoveIPC", "yes".to_owned());
        properties.insert("RestrictRealtime", "yes".to_owned());
        properties.insert("SystemCallArchitectures", "native".to_owned());
        properties.insert("SystemCallErrorNumber", "EPERM".to_owned());
        properties.insert("LimitCORE", "0".to_owned());
        properties.insert("LimitNOFILE", "4096".to_owned());
        properties.insert("TasksMax", "128".to_owned());
        properties.insert("NoNewPrivileges", "yes".to_owned());
        properties.insert("ProtectSystem", "strict".to_owned());
        properties.insert("ReadWritePaths", unit.write_paths.to_owned());
        if effectd {
            for property in [
                "ProtectHome",
                "PrivateTmp",
                "PrivateDevices",
                "PrivateMounts",
                "ProtectKernelTunables",
                "ProtectControlGroups",
                "ProtectKernelModules",
                "ProtectKernelLogs",
                "RestrictNamespaces",
                "RestrictSUIDSGID",
                "MemoryDenyWriteExecute",
                "LockPersonality",
            ] {
                properties.insert(property, "yes".to_owned());
            }
            properties.insert("ProtectProc", "invisible".to_owned());
            properties.insert("ProcSubset", "pid".to_owned());
            properties.insert("DynamicUser", "no".to_owned());
            properties.insert("ReadOnlyPaths", "/run".to_owned());
            properties.insert("StateDirectory", "agent-governor/effectd".to_owned());
            properties.insert("StateDirectoryMode", "0700".to_owned());
        }
        let mut output = String::new();
        for property in SYSTEMD_PROPERTIES {
            output.push_str(property);
            output.push('=');
            output.push_str(&properties[*property]);
            output.push('\n');
        }
        output
    }

    fn valid_show() -> String {
        [
            unit_block(&UnitBlockV1 {
                id: "agd.service",
                user: "ag-governor",
                group: "ag-governor",
                executable: "/usr/bin/agd",
                private_network: "yes",
                families: "AF_UNIX",
                capabilities: "",
                write_paths: "",
            }),
            unit_block(&UnitBlockV1 {
                id: "ag-effectd.service",
                user: "root",
                group: "root",
                executable: "/usr/bin/ag-effectd",
                private_network: "yes",
                families: "AF_UNIX",
                capabilities: "cap_chown cap_dac_override cap_dac_read_search cap_fowner",
                write_paths: "/var/lib/agent-governor/effectd /var/lib/agent-governor/effectd/objects /run/agent-governor/effectd/proposal /run/agent-governor/effectd/admin /etc/example-service",
            }),
            unit_block(&UnitBlockV1 {
                id: "ag-providerd.service",
                user: "ag-provider",
                group: "ag-provider",
                executable: "/usr/bin/ag-providerd",
                private_network: "no",
                families: "AF_UNIX AF_INET AF_INET6",
                capabilities: "",
                write_paths: "",
            }),
        ]
        .join("\n")
    }

    fn replace_unit_property(
        show: &str,
        unit_id: &str,
        property: &str,
        replacement: &str,
    ) -> String {
        let mut current_unit = "";
        let property_prefix = format!("{property}=");
        let mut replaced = false;
        let mut output = show
            .lines()
            .map(|line| {
                if let Some(id) = line.strip_prefix("Id=") {
                    current_unit = id;
                }
                if current_unit == unit_id && line.starts_with(&property_prefix) {
                    replaced = true;
                    format!("{property}={replacement}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(replaced, "missing {property} for {unit_id}");
        if show.ends_with('\n') {
            output.push('\n');
        }
        output
    }

    fn example_configs() -> LoadedDaemonConfigsV1 {
        LoadedDaemonConfigsV1 {
            agd: Some(
                toml::from_str(include_str!("../../../config/agd.example.toml"))
                    .expect("agd example"),
            ),
            effectd: Some(
                toml::from_str(include_str!("../../../config/effectd.example.toml"))
                    .expect("effectd example"),
            ),
            providerd: Some(
                toml::from_str(include_str!("../../../config/providerd.example.toml"))
                    .expect("providerd example"),
            ),
        }
    }

    fn inspect_fake_systemd(show: &str) -> Vec<DoctorCheckV1> {
        inspect_fake_systemd_with_configs(show, &example_configs())
    }

    fn inspect_fake_systemd_with_configs(
        show: &str,
        configs: &LoadedDaemonConfigsV1,
    ) -> Vec<DoctorCheckV1> {
        let units = parse_systemd_show(show.as_bytes()).expect("strict fake systemd evidence");
        let mut checks = Vec::new();
        inspect_systemd(configs, &units, &mut checks);
        checks
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

    fn status(checks: &[DoctorCheckV1], id: &str) -> DoctorCheckStatusV1 {
        checks
            .iter()
            .find(|check| check.id == id)
            .unwrap_or_else(|| panic!("missing check {id}"))
            .status
    }

    #[test]
    fn strict_systemd_parser_accepts_only_the_fixed_complete_cut() {
        let units = parse_systemd_show(valid_show().as_bytes()).expect("valid fixed show output");
        assert_eq!(units.len(), 3);
        assert_eq!(units["agd.service"].get("User"), "ag-governor");
        assert_eq!(
            exec_start_path(units["ag-effectd.service"].get("ExecStart")).expect("exec path"),
            Path::new("/usr/bin/ag-effectd")
        );
    }

    #[test]
    fn systemd_parser_rejects_duplicate_unknown_missing_and_extra_units() {
        let duplicate = valid_show().replacen("User=ag-governor", "User=x\nUser=ag-governor", 1);
        assert!(parse_systemd_show(duplicate.as_bytes()).is_err());

        let unknown = valid_show().replacen("User=ag-governor", "Environment=HOSTILE", 1);
        assert!(parse_systemd_show(unknown.as_bytes()).is_err());

        let missing = valid_show().replacen("User=ag-governor\n", "", 1);
        assert!(parse_systemd_show(missing.as_bytes()).is_err());

        let extra = format!(
            "{}\n{}",
            valid_show(),
            unit_block(&UnitBlockV1 {
                id: "ssh.service",
                user: "root",
                group: "root",
                executable: "/usr/sbin/sshd",
                private_network: "no",
                families: "AF_INET",
                capabilities: "CAP_NET_BIND_SERVICE",
                write_paths: "",
            })
        );
        assert!(parse_systemd_show(extra.as_bytes()).is_err());
    }

    #[test]
    fn systemd_parser_rejects_control_bytes_and_oversized_output() {
        assert!(parse_systemd_show(b"Id=agd.service\r\n").is_err());
        assert!(parse_systemd_show(b"Id=agd.service\0").is_err());
        assert!(parse_systemd_show(&vec![b'x'; MAX_SYSTEMD_SHOW_BYTES + 1]).is_err());
    }

    #[test]
    fn hostile_effect_and_provider_network_properties_fail_closed() {
        let effect_network =
            replace_unit_property(&valid_show(), "ag-effectd.service", "PrivateNetwork", "no");
        assert_eq!(
            status(
                &inspect_fake_systemd(&effect_network),
                "ag-effectd.systemd.network"
            ),
            DoctorCheckStatusV1::Fail
        );

        let provider_network = replace_unit_property(
            &valid_show(),
            "ag-providerd.service",
            "PrivateNetwork",
            "yes",
        );
        assert_eq!(
            status(
                &inspect_fake_systemd(&provider_network),
                "ag-providerd.systemd.network"
            ),
            DoctorCheckStatusV1::Fail
        );
    }

    #[test]
    fn hostile_privilege_floor_properties_fail_closed() {
        let cases = [
            (
                "AmbientCapabilities=",
                "AmbientCapabilities=cap_sys_admin",
                "agd.systemd.ambient-capabilities",
            ),
            (
                "SupplementaryGroups=",
                "SupplementaryGroups=wheel",
                "agd.systemd.supplementary-groups",
            ),
            (
                "NoNewPrivileges=yes",
                "NoNewPrivileges=no",
                "agd.systemd.no-new-privileges",
            ),
            (
                "ProtectSystem=strict",
                "ProtectSystem=full",
                "agd.systemd.protect-system",
            ),
        ];
        for (from, to, check_id) in cases {
            let hostile = valid_show().replacen(from, to, 1);
            assert_eq!(
                status(&inspect_fake_systemd(&hostile), check_id),
                DoctorCheckStatusV1::Fail,
                "{check_id} accepted hostile effective-unit evidence"
            );
        }
    }

    #[test]
    fn managed_pointer_derives_exact_effectd_capabilities_and_write_paths() {
        let mut configs = example_configs();
        configs
            .effectd
            .as_mut()
            .expect("effectd example")
            .targets
            .push(managed_pointer_target());
        let show = valid_show()
            .replace(
                "CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner",
                "CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_setgid cap_setuid",
            )
            .replace(
                "ReadWritePaths=/var/lib/agent-governor/effectd /var/lib/agent-governor/effectd/objects /run/agent-governor/effectd/proposal /run/agent-governor/effectd/admin /etc/example-service",
                "ReadWritePaths=/var/lib/agent-governor/effectd /var/lib/agent-governor/effectd/objects /run/agent-governor/effectd/proposal /run/agent-governor/effectd/admin /etc/example-service /srv/agent-governor/repositories/service.git /var/lib/agent-governor/effectd/promotion-stage",
            );
        let checks = inspect_fake_systemd_with_configs(&show, &configs);
        assert_eq!(
            status(&checks, "ag-effectd.systemd.capability-bound"),
            DoctorCheckStatusV1::Pass
        );
        assert_eq!(
            status(&checks, "ag-effectd.systemd.read-write-paths"),
            DoctorCheckStatusV1::Pass
        );

        let missing_owner_transition = show.replace(" cap_setgid cap_setuid", "");
        assert_eq!(
            status(
                &inspect_fake_systemd_with_configs(&missing_owner_transition, &configs),
                "ag-effectd.systemd.capability-bound"
            ),
            DoctorCheckStatusV1::Fail
        );
    }

    #[test]
    fn hostile_capability_and_write_scope_properties_fail_closed() {
        let capabilities = valid_show().replace(
            "CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner",
            "CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_sys_admin",
        );
        assert_eq!(
            status(
                &inspect_fake_systemd(&capabilities),
                "ag-effectd.systemd.capability-bound"
            ),
            DoctorCheckStatusV1::Fail
        );

        let missing_target = valid_show().replace(
            "ReadWritePaths=/var/lib/agent-governor/effectd /var/lib/agent-governor/effectd/objects /run/agent-governor/effectd/proposal /run/agent-governor/effectd/admin /etc/example-service",
            "ReadWritePaths=/var/lib/agent-governor/effectd /var/lib/agent-governor/effectd/objects /run/agent-governor/effectd/proposal /run/agent-governor/effectd/admin",
        );
        assert_eq!(
            status(
                &inspect_fake_systemd(&missing_target),
                "ag-effectd.systemd.read-write-paths"
            ),
            DoctorCheckStatusV1::Fail
        );

        let overbroad = valid_show().replace(
            "ReadWritePaths=/var/lib/agent-governor/effectd /var/lib/agent-governor/effectd/objects /run/agent-governor/effectd/proposal /run/agent-governor/effectd/admin /etc/example-service",
            "ReadWritePaths=/var/lib/agent-governor/effectd /var/lib/agent-governor/effectd/objects /run/agent-governor/effectd/proposal /run/agent-governor/effectd/admin /etc/example-service /etc",
        );
        assert_eq!(
            status(
                &inspect_fake_systemd(&overbroad),
                "ag-effectd.systemd.read-write-paths"
            ),
            DoctorCheckStatusV1::Fail
        );
    }

    #[test]
    fn writable_path_parser_rejects_ambiguous_or_noncanonical_syntax() {
        assert!(parse_read_write_paths("/etc/example /var/lib/agent").is_ok());
        assert!(parse_read_write_paths("-/etc/example").is_err());
        assert!(parse_read_write_paths("+/etc/example").is_err());
        assert!(parse_read_write_paths("!/etc/example").is_err());
        assert!(parse_read_write_paths("/etc/../root").is_err());
        assert!(parse_read_write_paths("\"/path with spaces\"").is_err());
    }

    #[test]
    fn exec_start_parser_rejects_multiple_relative_and_opaque_paths() {
        assert!(exec_start_path("{ path=/usr/bin/agd ; argv[]=/usr/bin/agd }").is_ok());
        assert!(exec_start_path("{ path=agd ; argv[]=agd }").is_err());
        assert!(exec_start_path("{ argv[]=/usr/bin/agd }").is_err());
        assert!(exec_start_path("{ path=/usr/bin/a ; path=/usr/bin/b ; }").is_err());
    }

    #[test]
    fn unavailable_is_never_reported_as_ready() {
        let report = DoctorReportV1::new(vec![check(
            "agd.systemd",
            "agd",
            DoctorCheckStatusV1::Unavailable,
            "no systemd evidence",
        )]);
        assert!(!report.ready);
    }

    #[test]
    fn hung_systemd_query_has_a_typed_bounded_refusal() {
        let mut command = Command::new("/bin/sleep");
        command.arg("60").env_clear();
        let started = Instant::now();
        let error = run_bounded_systemd_command(&mut command, Duration::from_millis(20))
            .expect_err("sleep must exceed the diagnostic deadline");
        assert!(matches!(
            &error,
            SystemdQueryErrorV1::DeadlineExceeded { milliseconds: 20 }
        ));
        assert!(started.elapsed() < Duration::from_secs(5));

        let detail = error.to_string();
        let mut checks = Vec::new();
        add_systemd_unavailable(&mut checks, &detail);
        assert_eq!(checks.len(), 3);
        assert!(checks.iter().all(|check| {
            check.status == DoctorCheckStatusV1::Unavailable && check.detail == detail
        }));
    }

    fn process_is_live(process_id: u32) -> bool {
        let stat = match std::fs::read_to_string(format!("/proc/{process_id}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
            Err(error) => panic!("cannot inspect descendant {process_id}: {error}"),
        };
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.chars().next())
            .expect("proc stat must contain a process state");
        !matches!(state, 'Z' | 'X')
    }

    #[test]
    fn descendant_holding_systemd_pipes_cannot_extend_the_deadline() {
        let fixture = tempfile::tempdir().expect("temporary directory");
        let descendant_pid = fixture.path().join("descendant.pid");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "/bin/sleep 60 & descendant=$!; printf '%s\\n' \"$descendant\" > \"$1\"; exit 0",
                "agctl-doctor-deadline-test",
            ])
            .arg(&descendant_pid)
            .env_clear();

        let started = Instant::now();
        let error = run_bounded_systemd_command(&mut command, Duration::from_millis(100))
            .expect_err("the inherited pipes must remain open until the group is terminated");
        assert!(matches!(
            error,
            SystemdQueryErrorV1::DeadlineExceeded { milliseconds: 100 }
        ));
        assert!(started.elapsed() < Duration::from_secs(2));

        let process_id: u32 = std::fs::read_to_string(&descendant_pid)
            .expect("descendant PID record")
            .trim()
            .parse()
            .expect("numeric descendant PID");
        let retirement_deadline = Instant::now() + Duration::from_secs(2);
        while process_is_live(process_id) && Instant::now() < retirement_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !process_is_live(process_id),
            "descendant {process_id} remained live after process-group termination"
        );
    }
}
