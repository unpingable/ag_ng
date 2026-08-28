//! Unix-socket daemon: startup custody checks and the connection loop.
//!
//! Custody is same-UID local only; there is no cryptographic authentication
//! on this transport. At startup the daemon fails closed on any custody
//! violation:
//!
//! - `--socket`: absolute path whose parent directory is owned by the
//!   effective UID; an existing symlink or non-socket node is refused, a
//!   stale euid-owned socket is replaced; the bound socket is mode `0600`.
//! - `--state-dir`: an existing directory owned by the effective UID with
//!   mode exactly `0700`.
//! - `--standing-store`: a regular file (never a symlink) owned by the
//!   effective UID.
//!
//! Each connection carries exactly one request frame and one response frame.
//! Malformed frames, unknown schemas, and unknown fields fail the connection
//! closed with a best-effort `ag.external-authorization-error:v1` response —
//! never a decision.

use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use ag_protocol::strict_json_from_slice;
use thiserror::Error;

use crate::adjudicate::{AdjudicationOutcomeV1, DaemonConfigV1, adjudicate};
use crate::framing::{read_request_frame, write_response_frame};
use crate::protocol::{
    ERROR_SCHEMA_V1, ErrorKindV1, ExternalAuthorizationErrorV1, ExternalAuthorizationRequestV1,
    bounded_reason,
};

/// Startup custody or runtime failures.
#[derive(Debug, Error)]
pub enum DaemonErrorV1 {
    /// A custody check failed; the daemon refuses to start.
    #[error("custody violation: {0}")]
    Custody(String),
    /// Configuration is invalid.
    #[error("invalid configuration: {0}")]
    Configuration(String),
    /// I/O failure.
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
}

fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// Validates the daemon state directory: existing, euid-owned directory with
/// mode exactly `0700`, never a symlink.
///
/// # Errors
///
/// Returns [`DaemonErrorV1::Custody`] on any violation.
pub fn validate_state_dir(path: &Path) -> Result<(), DaemonErrorV1> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(DaemonErrorV1::Custody(format!(
            "state directory {} must be a real directory, not a symlink",
            path.display()
        )));
    }
    if metadata.uid() != effective_uid() {
        return Err(DaemonErrorV1::Custody(format!(
            "state directory {} is not owned by the effective uid",
            path.display()
        )));
    }
    if metadata.mode() & 0o7777 != 0o700 {
        return Err(DaemonErrorV1::Custody(format!(
            "state directory {} must have mode exactly 0700",
            path.display()
        )));
    }
    Ok(())
}

/// Validates the root-owned standing store path: a regular euid-owned file,
/// never a symlink.
///
/// # Errors
///
/// Returns [`DaemonErrorV1::Custody`] on any violation.
pub fn validate_standing_store(path: &Path) -> Result<(), DaemonErrorV1> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(DaemonErrorV1::Custody(format!(
            "standing store {} must be a regular file, not a symlink",
            path.display()
        )));
    }
    if metadata.uid() != effective_uid() {
        return Err(DaemonErrorV1::Custody(format!(
            "standing store {} is not owned by the effective uid",
            path.display()
        )));
    }
    Ok(())
}

/// Binds the daemon socket under an euid-owned parent directory, replacing
/// only a stale euid-owned socket, and installs mode `0600`.
///
/// # Errors
///
/// Returns [`DaemonErrorV1::Custody`] for a relative path, a foreign-owned
/// parent, an existing symlink, or an occupied non-socket path; returns
/// [`DaemonErrorV1::Io`] for bind/permission failures.
pub fn bind_socket(path: &Path) -> Result<UnixListener, DaemonErrorV1> {
    if !path.is_absolute() {
        return Err(DaemonErrorV1::Custody(format!(
            "socket path {} must be absolute",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        DaemonErrorV1::Custody(format!("socket path {} has no parent", path.display()))
    })?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(DaemonErrorV1::Custody(format!(
            "socket parent {} must be a real directory, not a symlink",
            parent.display()
        )));
    }
    if parent_metadata.uid() != effective_uid() {
        return Err(DaemonErrorV1::Custody(format!(
            "socket parent {} is not owned by the effective uid",
            parent.display()
        )));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(DaemonErrorV1::Custody(format!(
                "refusing symlink socket path {}",
                path.display()
            )));
        }
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == effective_uid() => {
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(DaemonErrorV1::Custody(format!(
                "refusing occupied non-socket path {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serializes and frames one response body, best-effort.
fn send_frame(stream: &mut UnixStream, body: &impl serde::Serialize) {
    let payload = match serde_json::to_vec(body) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize response; closing connection");
            return;
        }
    };
    if let Err(error) = write_response_frame(stream, &payload) {
        tracing::warn!(%error, "failed to write response frame; closing connection");
    }
}

fn invalid_frame_error(reason: impl Into<String>) -> ExternalAuthorizationErrorV1 {
    ExternalAuthorizationErrorV1 {
        schema: ERROR_SCHEMA_V1.to_owned(),
        request_id: None,
        kind: ErrorKindV1::InvalidRequest,
        reason: bounded_reason(reason),
    }
}

/// Handles one short-lived connection: reads exactly one request frame,
/// adjudicates, writes exactly one response frame, and returns. Malformed
/// input fails the connection closed with a best-effort error response and
/// never records a decision.
pub fn handle_connection(stream: &mut UnixStream, config: &DaemonConfigV1, now_unix_ms: u64) {
    let frame = match read_request_frame(stream) {
        Ok(frame) => frame,
        Err(error) => {
            send_frame(
                stream,
                &invalid_frame_error(format!("invalid request frame: {error}")),
            );
            return;
        }
    };
    let request: ExternalAuthorizationRequestV1 = match strict_json_from_slice(&frame) {
        Ok(request) => request,
        Err(error) => {
            send_frame(
                stream,
                &invalid_frame_error(format!("invalid request: {error}")),
            );
            return;
        }
    };
    match adjudicate(config, &request, now_unix_ms) {
        AdjudicationOutcomeV1::Decision(response) => send_frame(stream, &response),
        AdjudicationOutcomeV1::Rejected(error) => send_frame(stream, &error),
    }
}

/// Current wall-clock time in milliseconds since the Unix epoch.
#[must_use]
pub fn now_unix_ms() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Serves connections until the listener fails or the process is stopped.
/// Individual connection errors are logged and never stop the loop.
///
/// # Errors
///
/// Returns only listener-level accept failures that make further serving
/// impossible.
pub fn serve(listener: &UnixListener, config: &DaemonConfigV1) -> Result<(), DaemonErrorV1> {
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => handle_connection(&mut stream, config, now_unix_ms()),
            Err(error) => {
                tracing::warn!(%error, "accept failed; continuing");
            }
        }
    }
    Ok(())
}

/// Validates the complete startup custody and configuration envelope.
///
/// # Errors
///
/// Returns the first custody or configuration violation.
pub fn validate_startup(
    socket: &Path,
    state_dir: &Path,
    standing_store: &Path,
    config: &DaemonConfigV1,
) -> Result<(), DaemonErrorV1> {
    config.validate().map_err(DaemonErrorV1::Configuration)?;
    validate_state_dir(state_dir)?;
    validate_standing_store(standing_store)?;
    if socket == PathBuf::new() {
        return Err(DaemonErrorV1::Custody(
            "socket path must be nonempty".to_owned(),
        ));
    }
    Ok(())
}
