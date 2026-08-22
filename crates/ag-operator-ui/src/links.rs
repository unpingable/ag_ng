//! Versioned, navigation-only Phosphor-ng deep links.
//!
//! These paths carry public canonical identifiers only. They are locators for
//! operator context: they are not capabilities, standing, authorization, or
//! proof that Maude and one governed occurrence are related.

use ag_campaign::governed::OccurrenceId;
use ag_primitives::Digest;

/// Version of the semantic Phosphor-ng deep-link contract.
pub const PHOSPHOR_DEEP_LINK_SCHEMA_V1: &str = "phosphor-ng.deep-link/v1";

/// Exact canonical identities addressed by one read-only runtime link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedRuntimeLinkV1 {
    /// Exact AG campaign identity.
    pub campaign: Digest,
    /// Exact independently allocated occurrence identity.
    pub occurrence: OccurrenceId,
    /// Exact proposal identity when the linking source recorded it.
    pub proposal: Option<Digest>,
}

impl GovernedRuntimeLinkV1 {
    /// Builds the canonical relative path. All path values are percent encoded.
    #[must_use]
    pub fn relative_path(&self) -> String {
        let mut path = format!(
            "/phosphor-ng/campaigns/{}/occurrences/{}",
            encode_segment(self.campaign.as_str()),
            self.occurrence
        );
        if let Some(proposal) = &self.proposal {
            path.push_str("/proposals/");
            path.push_str(&encode_segment(proposal.as_str()));
        }
        path
    }

    /// Parses exactly one canonical Phosphor-ng occurrence/proposal path.
    ///
    /// # Errors
    ///
    /// Returns a visible refusal for malformed escaping, noncanonical IDs, or
    /// any extra path component.
    pub fn parse_path(path: &str) -> Result<Option<Self>, String> {
        let segments = path
            .strip_prefix('/')
            .unwrap_or(path)
            .split('/')
            .collect::<Vec<_>>();
        if segments.first() != Some(&"phosphor-ng") {
            return Ok(None);
        }
        if !matches!(segments.len(), 5 | 7)
            || segments[1] != "campaigns"
            || segments[3] != "occurrences"
            || (segments.len() == 7 && segments[5] != "proposals")
        {
            return Err("malformed Phosphor-ng semantic path".to_owned());
        }
        let campaign_text = decode_segment(segments[2])?;
        if encode_segment(&campaign_text) != segments[2] {
            return Err("campaign identity path encoding is not canonical".to_owned());
        }
        let campaign = Digest::parse(&campaign_text)
            .map_err(|error| format!("invalid canonical campaign identity: {error}"))?;
        let occurrence = serde_json::from_value::<OccurrenceId>(serde_json::Value::String(
            segments[4].to_owned(),
        ))
        .map_err(|error| format!("invalid canonical occurrence identity: {error}"))?;
        if occurrence.to_string() != segments[4] {
            return Err(
                "occurrence identity is not canonical lowercase hyphenated UUID".to_owned(),
            );
        }
        let proposal = if segments.len() == 7 {
            let proposal_text = decode_segment(segments[6])?;
            if encode_segment(&proposal_text) != segments[6] {
                return Err("proposal identity path encoding is not canonical".to_owned());
            }
            Some(
                Digest::parse(&proposal_text)
                    .map_err(|error| format!("invalid canonical proposal identity: {error}"))?,
            )
        } else {
            None
        };
        Ok(Some(Self {
            campaign,
            occurrence,
            proposal,
        }))
    }
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use core::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn decode_segment(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes
                .get(index + 1..index + 3)
                .ok_or_else(|| "truncated percent escape in semantic path".to_owned())?;
            let high = hex_value(pair[0])?;
            let low = hex_value(pair[1])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "semantic path identity is not UTF-8".to_owned())
}

fn hex_value(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid percent escape in semantic path".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::hash_domain("phosphor-ng-link-test/v1", label.as_bytes())
    }

    fn occurrence(value: &str) -> OccurrenceId {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).unwrap()
    }

    #[test]
    fn exact_occurrence_and_proposal_link_round_trip() {
        let link = GovernedRuntimeLinkV1 {
            campaign: Digest::parse(&format!("sha256:{}", "00".repeat(32))).unwrap(),
            occurrence: occurrence("00000000-0000-0000-0000-00000000002a"),
            proposal: Some(Digest::parse(&format!("sha256:{}", "11".repeat(32))).unwrap()),
        };
        let path = link.relative_path();
        assert_eq!(
            path,
            format!(
                "/phosphor-ng/campaigns/sha256%3A{}/occurrences/00000000-0000-0000-0000-00000000002a/proposals/sha256%3A{}",
                "00".repeat(32),
                "11".repeat(32)
            )
        );
        assert_eq!(
            GovernedRuntimeLinkV1::parse_path(&path).unwrap(),
            Some(link)
        );
    }

    #[test]
    fn link_contains_identities_only_and_never_authority_material() {
        let path = GovernedRuntimeLinkV1 {
            campaign: digest("campaign"),
            occurrence: occurrence("00000000-0000-0000-0000-000000000001"),
            proposal: None,
        }
        .relative_path();
        for forbidden in [
            "authorization",
            "spend",
            "issuance",
            "signature",
            "token",
            "secret",
        ] {
            assert!(!path.contains(forbidden));
        }
        assert!(!path.contains('?'));
        assert!(!path.contains('#'));
    }

    #[test]
    fn malformed_or_noncanonical_paths_refuse() {
        assert!(
            GovernedRuntimeLinkV1::parse_path("/campaign/locator")
                .unwrap()
                .is_none()
        );
        for path in [
            "/phosphor-ng/campaigns/not-a-digest/occurrences/nope",
            "/phosphor-ng/campaigns/sha256%ZZ/occurrences/00000000-0000-0000-0000-000000000001",
            "/phosphor-ng/campaigns/sha256%3A00/occurrences/00000000-0000-0000-0000-000000000001/extra/x",
        ] {
            assert!(GovernedRuntimeLinkV1::parse_path(path).is_err());
        }
        let unescaped = format!(
            "/phosphor-ng/campaigns/sha256:{}/occurrences/00000000-0000-0000-0000-000000000001",
            "00".repeat(32)
        );
        assert!(GovernedRuntimeLinkV1::parse_path(&unescaped).is_err());
    }
}
