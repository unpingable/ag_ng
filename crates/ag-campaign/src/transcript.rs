//! Shared bounded-label validation for governed-loop records.

const MAX_LABEL_BYTES: usize = 128;

/// Returns whether a label belongs to the shared AG/Docket wire grammar:
/// lowercase ASCII alphanumeric segments separated by one of `-._/:`.
pub(crate) fn is_canonical_wire_label(value: &str) -> bool {
    let mut prior_separator = true;
    for byte in value.bytes() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            prior_separator = false;
        } else if matches!(byte, b'-' | b'.' | b'_' | b'/' | b':') && !prior_separator {
            prior_separator = true;
        } else {
            return false;
        }
    }
    !prior_separator
}

/// Validates the bounded shared AG/Docket canonical label grammar.
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
    if !is_canonical_wire_label(value) {
        return Err(crate::CampaignLabelError::NonCanonical { kind });
    }
    Ok(())
}
