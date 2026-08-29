//! Exact validation of the Codex declarative-admissibility receipt transcript.
//!
//! The canonical owner is Codex external-reviewer's receipt v1 law. Its
//! transcript is canonical JSON over exactly evaluation_time (Unix seconds),
//! evidence_used in supplied order, profile_id, and profile_revision. Each
//! evidence object contains fact_id, qualifier_id, qualifier_revision,
//! receipt_id, and requirement_id; optional provenance is explicit JSON null.
//!
//! AG's wire admits only complete provenance and carries time in milliseconds.
//! Exact reconstruction therefore requires a whole-second millisecond value;
//! AG divides it by 1000 and serializes every provenance value as present.

use ag_primitives::{Digest, JcsDocument};
use serde::Serialize;

use crate::protocol::AdmissibilityDescriptorV1;

#[derive(Serialize)]
struct EvidenceTranscriptV1<'a> {
    fact_id: &'a str,
    qualifier_id: Option<&'a str>,
    qualifier_revision: Option<&'a str>,
    receipt_id: Option<&'a str>,
    requirement_id: &'a str,
}

#[derive(Serialize)]
struct ReceiptTranscriptV1<'a> {
    evaluation_time: i64,
    evidence_used: Vec<EvidenceTranscriptV1<'a>>,
    profile_id: &'a str,
    profile_revision: &'a str,
}

/// Recomputes the exact Codex receipt digest from AG's wire descriptor.
///
/// # Errors
///
/// Rejects sub-second wire values, times outside Codex's signed seconds
/// domain, or an unexpected canonicalization failure.
pub fn computed_receipt_digest(descriptor: &AdmissibilityDescriptorV1) -> Result<Digest, String> {
    if descriptor.evaluation_time_unix_ms % 1_000 != 0 {
        return Err(
            "admissibility evaluation_time_unix_ms is not an exact whole-second receipt time"
                .to_owned(),
        );
    }
    let evaluation_time =
        i64::try_from(descriptor.evaluation_time_unix_ms / 1_000).map_err(|_| {
            "admissibility evaluation time exceeds the canonical receipt domain".to_owned()
        })?;
    let transcript = ReceiptTranscriptV1 {
        evaluation_time,
        evidence_used: descriptor
            .evidence_used
            .iter()
            .map(|used| EvidenceTranscriptV1 {
                fact_id: &used.fact_id,
                qualifier_id: Some(&used.qualifier_id),
                qualifier_revision: Some(&used.qualifier_revision),
                receipt_id: Some(used.receipt_id.as_str()),
                requirement_id: &used.requirement_id,
            })
            .collect(),
        profile_id: &descriptor.profile_id,
        profile_revision: &descriptor.profile_revision,
    };
    let canonical = JcsDocument::canonicalize(&transcript).map_err(|error| {
        format!("cannot canonicalize admissibility receipt transcript: {error}")
    })?;
    Ok(Digest::hash_bytes(canonical.as_bytes()))
}

/// Validates the supplied receipt identity before AG creates any custody.
pub fn validate_receipt_digest(descriptor: &AdmissibilityDescriptorV1) -> Result<(), String> {
    let expected = computed_receipt_digest(descriptor)?;
    if descriptor.receipt_digest == expected {
        Ok(())
    } else {
        Err("admissibility receipt digest does not match its exact transcript".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::EvidenceUsedV1;

    fn descriptor() -> AdmissibilityDescriptorV1 {
        AdmissibilityDescriptorV1 {
            profile_id: "profile-1".to_owned(),
            profile_revision: "rev-A".to_owned(),
            decision: "continue".to_owned(),
            evaluation_time_unix_ms: 42_000,
            evidence_used: vec![EvidenceUsedV1 {
                requirement_id: "req-1".to_owned(),
                fact_id: "fact-1".to_owned(),
                receipt_id: Digest::parse(&format!("sha256:{}", "d".repeat(64))).unwrap(),
                qualifier_id: "qualifier-1".to_owned(),
                qualifier_revision: "rev-1".to_owned(),
            }],
            receipt_digest: Digest::parse(
                "sha256:83575654d4213cd12350a6b4b10a94d7a6f925c7fd540ac3cba15af9417d8c82",
            )
            .unwrap(),
        }
    }

    #[test]
    fn cross_boundary_vector_matches_codex_canonical_owner() {
        let descriptor = descriptor();
        assert_eq!(
            computed_receipt_digest(&descriptor).unwrap(),
            descriptor.receipt_digest
        );
        assert_eq!(validate_receipt_digest(&descriptor), Ok(()));
    }

    #[test]
    fn every_bound_field_substitution_is_rejected() {
        let original = descriptor();
        let mut substitutions = Vec::new();

        let mut changed = original.clone();
        changed.profile_id.push_str("-other");
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.profile_revision.push_str("-other");
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.evaluation_time_unix_ms += 1_000;
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.evidence_used[0].requirement_id.push_str("-other");
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.evidence_used[0].fact_id.push_str("-other");
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.evidence_used[0].receipt_id = Digest::hash_bytes(b"other-receipt");
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.evidence_used[0].qualifier_id.push_str("-other");
        substitutions.push(changed);
        let mut changed = original.clone();
        changed.evidence_used[0]
            .qualifier_revision
            .push_str("-other");
        substitutions.push(changed);
        let mut changed = original.clone();
        changed
            .evidence_used
            .push(original.evidence_used[0].clone());
        substitutions.push(changed);

        for changed in substitutions {
            assert!(validate_receipt_digest(&changed).is_err(), "{changed:?}");
        }
    }

    #[test]
    fn subsecond_wire_time_cannot_reconstruct_the_receipt() {
        let mut changed = descriptor();
        changed.evaluation_time_unix_ms += 1;
        assert!(
            validate_receipt_digest(&changed)
                .unwrap_err()
                .contains("whole-second")
        );
    }

    #[test]
    fn evidence_order_is_bound_by_the_transcript() {
        let mut original = descriptor();
        let mut second = original.evidence_used[0].clone();
        second.requirement_id = "req-2".to_owned();
        second.fact_id = "fact-2".to_owned();
        original.evidence_used.push(second);
        original.receipt_digest = computed_receipt_digest(&original).unwrap();

        let mut reordered = original.clone();
        reordered.evidence_used.reverse();
        assert!(validate_receipt_digest(&reordered).is_err());
    }
}
