//! Domain-separated transcript digests for campaign records.

use ag_primitives::{Digest, JcsDocument};
use serde::Serialize;

const MAX_LABEL_BYTES: usize = 128;
pub(crate) const MAX_PATH_PREFIX_BYTES: usize = 256;

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
    if value.len() > MAX_LABEL_BYTES {
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
    if value.is_empty() {
        return Err(crate::CampaignLabelError::Empty {
            kind: "path prefix",
        });
    }
    if value.len() > MAX_PATH_PREFIX_BYTES {
        return Err(crate::CampaignLabelError::PathTooLong {
            actual: value.len(),
        });
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(crate::CampaignLabelError::ControlCharacter {
            kind: "path prefix",
        });
    }
    if !value.starts_with('/') || value.split('/').any(|component| component == "..") {
        return Err(crate::CampaignLabelError::NonCanonicalPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_PATH_PREFIX_BYTES, validate_path_prefix};

    fn ascii_path(byte_length: usize) -> String {
        assert!(byte_length >= 2);
        format!("/{}", "a".repeat(byte_length - 1))
    }

    #[test]
    fn path_prefix_capacity_has_exact_utf8_byte_boundaries() {
        for byte_length in [127, 128, 129, 130, 255, 256] {
            let path = ascii_path(byte_length);
            assert_eq!(path.len(), byte_length);
            validate_path_prefix(&path).expect("path at or below the bound must validate");
        }

        let overlong = ascii_path(257);
        assert_eq!(overlong.len(), MAX_PATH_PREFIX_BYTES + 1);
        assert_eq!(
            validate_path_prefix(&overlong)
                .expect_err("path above the bound must refuse")
                .to_string(),
            "path prefix exceeds 256 bytes (got 257)"
        );
    }

    #[test]
    fn path_prefix_capacity_counts_utf8_bytes_not_characters() {
        let accepted = format!("/{}a", "é".repeat(127));
        assert_eq!(accepted.chars().count(), 129);
        assert_eq!(accepted.len(), 256);
        validate_path_prefix(&accepted).expect("256 UTF-8 bytes must validate");

        let refused = format!("/{}", "é".repeat(128));
        assert_eq!(refused.chars().count(), 129);
        assert_eq!(refused.len(), 257);
        assert_eq!(
            validate_path_prefix(&refused)
                .expect_err("257 UTF-8 bytes must refuse")
                .to_string(),
            "path prefix exceeds 256 bytes (got 257)"
        );
    }
}
