//! Domain-separated transcript digests for campaign records.

use ag_primitives::{Digest, JcsDocument};
use serde::Serialize;

/// Hashes the exact canonical transcript of `value` under `domain`.
///
/// All campaign schemas are strict integer-only JCS values, so canonicalization
/// cannot fail for a validated value.
pub(crate) fn transcript_digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Digest {
    let document = JcsDocument::canonicalize(value)
        .expect("campaign schemas contain only strict JCS-compatible values");
    Digest::hash_domain(domain, document.as_bytes())
}

/// Validates a bounded free-text label: non-empty, at most 128 bytes, and free
/// of ASCII control characters.
pub(crate) fn validate_label(
    kind: &'static str,
    value: &str,
) -> Result<(), crate::CampaignLabelError> {
    if value.is_empty() {
        return Err(crate::CampaignLabelError::Empty { kind });
    }
    if value.len() > 128 {
        return Err(crate::CampaignLabelError::TooLong {
            kind,
            actual: value.len(),
        });
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(crate::CampaignLabelError::ControlCharacter { kind });
    }
    Ok(())
}

/// Validates a repository-local path prefix: absolute, normalized, and free of
/// parent-directory components.
pub(crate) fn validate_path_prefix(value: &str) -> Result<(), crate::CampaignLabelError> {
    validate_label("path prefix", value)?;
    if !value.starts_with('/') || value.split('/').any(|component| component == "..") {
        return Err(crate::CampaignLabelError::NonCanonicalPath);
    }
    Ok(())
}
