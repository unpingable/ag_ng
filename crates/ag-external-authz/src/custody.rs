//! Durable custody for one external authorization request and its decision.
//!
//! The request is synced before the governed engine starts. A decision is
//! written to a synced temporary file and atomically published only after the
//! engine transition is durable. Missing `outcome.json` therefore means
//! outcome unknown; it never licenses another occurrence or effect.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use ag_primitives::Digest;
use ag_protocol::strict_json_from_slice;

use crate::protocol::{ExternalAuthorizationRequestV1, ExternalAuthorizationResponseV1};

/// Durable original request filename within one occurrence directory.
pub const REQUEST_FILE_V1: &str = "request.json";
/// Durable adjudication outcome filename within one occurrence directory.
pub const OUTCOME_FILE_V1: &str = "outcome.json";
const OUTCOME_TEMP_FILE_V1: &str = ".outcome.json.tmp";

fn bounded_io(context: &str, error: impl std::fmt::Display) -> String {
    crate::protocol::bounded_reason(format!("{context}: {error}"))
}

/// SHA-256 of the exact serialized authorization request bytes.
///
/// # Errors
///
/// Returns an error only if the closed request type cannot be serialized.
pub fn request_digest(request: &ExternalAuthorizationRequestV1) -> Result<Digest, String> {
    serde_json::to_vec(request)
        .map(|bytes| Digest::hash_bytes(&bytes))
        .map_err(|error| bounded_io("cannot serialize authorization request", error))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| bounded_io("cannot sync custody directory", error))
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| bounded_io("cannot create custody record", error))?;
    file.write_all(bytes)
        .map_err(|error| bounded_io("cannot write custody record", error))?;
    file.sync_all()
        .map_err(|error| bounded_io("cannot sync custody record", error))
}

/// Syncs the new occurrence directory into its parent state directory.
///
/// # Errors
///
/// Returns a bounded I/O diagnostic when the directory entry cannot be made
/// durable.
pub fn sync_new_occurrence(state_dir: &Path) -> Result<(), String> {
    sync_directory(state_dir)
}

/// Persists and syncs the exact request before adjudication begins.
///
/// # Errors
///
/// Refuses overwrite and reports serialization or I/O failures.
pub fn persist_request(
    occurrence_dir: &Path,
    request: &ExternalAuthorizationRequestV1,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(request)
        .map_err(|error| bounded_io("cannot serialize authorization request", error))?;
    write_new_synced(&occurrence_dir.join(REQUEST_FILE_V1), &bytes)?;
    sync_directory(occurrence_dir)
}

/// Atomically publishes and syncs one exact durable decision.
///
/// # Errors
///
/// Refuses overwrite and reports serialization or I/O failures. A failure
/// leaves the occurrence in outcome-unknown state.
pub fn persist_outcome(
    occurrence_dir: &Path,
    outcome: &ExternalAuthorizationResponseV1,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(outcome)
        .map_err(|error| bounded_io("cannot serialize authorization outcome", error))?;
    let temporary = occurrence_dir.join(OUTCOME_TEMP_FILE_V1);
    write_new_synced(&temporary, &bytes)?;
    std::fs::rename(&temporary, occurrence_dir.join(OUTCOME_FILE_V1))
        .map_err(|error| bounded_io("cannot publish authorization outcome", error))?;
    sync_directory(occurrence_dir)
}

fn read_strict<T: serde::de::DeserializeOwned + serde::Serialize>(
    path: &Path,
) -> Result<Option<T>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(bounded_io("cannot inspect custody record", error)),
    };
    if !metadata.file_type().is_file() {
        return Err(bounded_io(
            "invalid custody record",
            format!("{} is not a regular file", path.display()),
        ));
    }
    let bytes =
        std::fs::read(path).map_err(|error| bounded_io("cannot read custody record", error))?;
    strict_json_from_slice(&bytes)
        .map(Some)
        .map_err(|error| bounded_io("custody record is not strict JSON", error))
}

/// Reads the exact original request, when present.
///
/// # Errors
///
/// Refuses non-regular or malformed records.
pub fn load_request(
    occurrence_dir: &Path,
) -> Result<Option<ExternalAuthorizationRequestV1>, String> {
    read_strict(&occurrence_dir.join(REQUEST_FILE_V1))
}

/// Reads the exact durable decision, when present.
///
/// # Errors
///
/// Refuses non-regular or malformed records.
pub fn load_outcome(
    occurrence_dir: &Path,
) -> Result<Option<ExternalAuthorizationResponseV1>, String> {
    read_strict(&occurrence_dir.join(OUTCOME_FILE_V1))
}
