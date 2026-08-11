//! Shared bounded-label validation for governed-loop records.

const MAX_LABEL_BYTES: usize = 128;

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
