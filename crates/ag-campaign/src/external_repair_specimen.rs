//! Strict, non-authorizing records for historical repair-boundary specimens.
//!
//! These records let AG reason about immutable facts produced outside AG
//! without pretending that the records are AG standing. Parsing establishes
//! canonical bytes and internal consistency only. There is deliberately no
//! conversion from a specimen to a proposal, standing, authorization, or
//! executable effect.

#![allow(
    missing_docs,
    reason = "closed fixture fields mirror immutable external specimen schemas"
)]

use std::collections::BTreeSet;

use ag_primitives::{Digest, JcsDocument, JcsError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// AG's semantic digest domain for an immutable external repair specimen.
pub const NQ_C1_SPECIMEN_DIGEST_DOMAIN_V1: &str = "ag.campaign.external-repair-specimen/nq-c1/v1";

/// The only authority interpretation accepted for these historical records.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSpecimenAuthorityUseV1 {
    /// The record can support observation and review, but cannot mint standing.
    HistoricalEvidenceOnly,
}

/// The mutually exclusive boundary classification established by a specimen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalRepairBoundaryV1 {
    /// A frozen candidate and evidence packet were independently rejected.
    RejectedCandidate,
    /// Scope discovery happened before spend, so no authority was consumed.
    ScopeDiscoveryBeforeSpend,
    /// A bounded authorization was spent before another missing path surfaced.
    ConsumedRepairHardStop,
    /// The observed scope requires architectural readjudication, not repair.
    ArchitecturalReadjudicationRequired,
}

/// Exact byte and AG-domain identities of one canonical specimen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalSpecimenIdentityV1 {
    /// SHA-256 of the exact canonical file bytes.
    pub exact_bytes: Digest,
    /// AG's domain-separated semantic identity over those same bytes.
    pub ag_semantic: Digest,
}

/// One path and the SHA-256 of the exact bytes committed at that path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathDigestV1 {
    /// Normalized repository-relative path.
    pub path: String,
    /// Exact byte digest at the recorded cut.
    pub digest: Digest,
}

/// Immutable external NQ C1 records used to test the governed repair boundary.
///
/// The schema tag closes the set of meanings. A caller cannot combine a
/// pre-spend observation with a post-spend checkpoint or mark an architecture
/// readjudication as bounded repair.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "schema", deny_unknown_fields)]
pub enum NqC1ImmutableSpecimenV1 {
    /// The exact independently rejected, immutable candidate cut.
    #[serde(rename = "nq.c1_gen5_live_c2.rejected_candidate_specimen.v1")]
    RejectedCandidate {
        /// Records never constitute standing.
        authority_use: ExternalSpecimenAuthorityUseV1,
        candidate_basis_identity: Digest,
        candidate_commit: String,
        candidate_manifest_identity: Digest,
        candidate_tag_object: String,
        candidate_tree: String,
        defect_ids: Vec<String>,
        evidence_commit: String,
        evidence_packet_identity: Digest,
        evidence_tag_object: String,
        evidence_tree: String,
        fresh_review_required: bool,
        gen4_active_commit: String,
        proposed_claim_identity: Digest,
        review_artifact_identity: Digest,
        review_timestamp: String,
        reviewer_identity: String,
        reviewer_identity_assurance: String,
        runtime_artifact_identity: Digest,
        verdict: String,
    },
    /// The first scope census: discovery before any spend or source attempt.
    #[serde(rename = "nq.c1_gen5_live_c2.scope_discovery_pre_spend_specimen.v1")]
    ScopeDiscoveryPreSpend {
        /// Records never constitute standing.
        authority_use: ExternalSpecimenAuthorityUseV1,
        authorization_consumed: bool,
        authorization_expiry: String,
        authorization_start: String,
        authorized_path_count: u64,
        authorized_paths: Vec<String>,
        discovered_missing_path: String,
        independent_rejection_identity: Digest,
        predecessor_candidate_commit: String,
        predecessor_candidate_tree: String,
        source_mutation_attempted: bool,
    },
    /// The second scope census: one spent occurrence and its exact checkpoint.
    #[serde(rename = "nq.c1_gen5_live_c2.consumed_repair_hard_stop_specimen.v1")]
    ConsumedRepairHardStop {
        /// Records never constitute standing.
        authority_use: ExternalSpecimenAuthorityUseV1,
        authorization_consumed: bool,
        authorization_consumed_at: String,
        authorization_expiry: String,
        authorization_reusable: bool,
        authorization_start: String,
        authorized_path_count: u64,
        authorized_paths: Vec<String>,
        changed_paths: Vec<PathDigestV1>,
        checkpoint_commit: String,
        checkpoint_tree: String,
        diff_identity: Digest,
        next_missing_path: String,
        predecessor_candidate_commit: String,
        predecessor_candidate_tree: String,
        tests_or_builds_run: bool,
    },
    /// Scope evidence that is structurally outside bounded repair admission.
    #[serde(rename = "nq.c1_gen5_live_c2.architectural_readjudication_specimen.v1")]
    ArchitecturalReadjudication {
        /// Records never constitute standing.
        authority_use: ExternalSpecimenAuthorityUseV1,
        additional_diagnostic_path_count: u64,
        architecture_required: bool,
        core_path_count: u64,
        diagnostic_file_count: u64,
        diagnostic_reference_count: u64,
        existing_source_scope_admissible: bool,
        overlap_path_count: u64,
    },
}

impl NqC1ImmutableSpecimenV1 {
    /// Parses the repository fixture form: canonical JCS followed by one LF.
    ///
    /// The exact-byte identity covers the LF-terminated file. The AG semantic
    /// identity covers only the JCS body, so file transport identity and AG's
    /// typed semantic identity remain explicitly distinct.
    ///
    /// # Errors
    ///
    /// Refuses a missing or repeated trailing LF and every error documented by
    /// [`Self::parse_canonical`].
    pub fn parse_fixture_file(
        input: &[u8],
    ) -> Result<(Self, ExternalSpecimenIdentityV1), ExternalSpecimenErrorV1> {
        let body = input
            .strip_suffix(b"\n")
            .ok_or(ExternalSpecimenErrorV1::FixtureLineEnding)?;
        if body.ends_with(b"\n") || body.ends_with(b"\r") {
            return Err(ExternalSpecimenErrorV1::FixtureLineEnding);
        }
        let (specimen, mut identity) = Self::parse_canonical(body)?;
        identity.exact_bytes = Digest::hash_bytes(input);
        Ok((specimen, identity))
    }

    /// Parses one exact JCS record and verifies its semantic invariants.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical JSON, unknown/duplicate fields, malformed digests,
    /// inconsistent counts, non-normalized paths, or a record whose state
    /// contradicts its closed schema classification.
    pub fn parse_canonical(
        input: &[u8],
    ) -> Result<(Self, ExternalSpecimenIdentityV1), ExternalSpecimenErrorV1> {
        let document = JcsDocument::from_canonical_bytes(input)?;
        let specimen: Self = document.decode()?;
        specimen.validate()?;
        let identity = ExternalSpecimenIdentityV1 {
            exact_bytes: document.digest(),
            ag_semantic: Digest::hash_domain(NQ_C1_SPECIMEN_DIGEST_DOMAIN_V1, input),
        };
        Ok((specimen, identity))
    }

    /// Returns the one closed boundary classification.
    #[must_use]
    pub const fn boundary(&self) -> ExternalRepairBoundaryV1 {
        match self {
            Self::RejectedCandidate { .. } => ExternalRepairBoundaryV1::RejectedCandidate,
            Self::ScopeDiscoveryPreSpend { .. } => {
                ExternalRepairBoundaryV1::ScopeDiscoveryBeforeSpend
            }
            Self::ConsumedRepairHardStop { .. } => ExternalRepairBoundaryV1::ConsumedRepairHardStop,
            Self::ArchitecturalReadjudication { .. } => {
                ExternalRepairBoundaryV1::ArchitecturalReadjudicationRequired
            }
        }
    }

    /// These records are evidence only; no variant can carry AG authority.
    #[must_use]
    pub const fn can_mint_authority(&self) -> bool {
        false
    }

    fn validate(&self) -> Result<(), ExternalSpecimenErrorV1> {
        match self {
            Self::RejectedCandidate { .. } => self.validate_rejected_candidate(),
            Self::ScopeDiscoveryPreSpend { .. } => self.validate_pre_spend_discovery(),
            Self::ConsumedRepairHardStop { .. } => self.validate_consumed_hard_stop(),
            Self::ArchitecturalReadjudication { .. } => self.validate_readjudication(),
        }
    }

    fn validate_rejected_candidate(&self) -> Result<(), ExternalSpecimenErrorV1> {
        let Self::RejectedCandidate {
            candidate_commit,
            candidate_tag_object,
            candidate_tree,
            defect_ids,
            evidence_commit,
            evidence_tag_object,
            evidence_tree,
            fresh_review_required,
            gen4_active_commit,
            review_timestamp,
            reviewer_identity,
            reviewer_identity_assurance,
            verdict,
            ..
        } = self
        else {
            unreachable!("variant-dispatched validator")
        };
        validate_git_object("candidate_commit", candidate_commit)?;
        validate_git_object("candidate_tag_object", candidate_tag_object)?;
        validate_git_object("candidate_tree", candidate_tree)?;
        validate_git_object("evidence_commit", evidence_commit)?;
        validate_git_object("evidence_tag_object", evidence_tag_object)?;
        validate_git_object("evidence_tree", evidence_tree)?;
        validate_git_object("gen4_active_commit", gen4_active_commit)?;
        validate_labels("defect_ids", defect_ids)?;
        require(*fresh_review_required, "fresh_review_required")?;
        require(verdict == "REJECTED_REPAIR_ELIGIBLE", "verdict")?;
        validate_label("review_timestamp", review_timestamp)?;
        validate_label("reviewer_identity", reviewer_identity)?;
        validate_label("reviewer_identity_assurance", reviewer_identity_assurance)
    }

    fn validate_pre_spend_discovery(&self) -> Result<(), ExternalSpecimenErrorV1> {
        let Self::ScopeDiscoveryPreSpend {
            authorization_consumed,
            authorization_expiry,
            authorization_start,
            authorized_path_count,
            authorized_paths,
            discovered_missing_path,
            predecessor_candidate_commit,
            predecessor_candidate_tree,
            source_mutation_attempted,
            ..
        } = self
        else {
            unreachable!("variant-dispatched validator")
        };
        require(!authorization_consumed, "authorization_consumed")?;
        require(!source_mutation_attempted, "source_mutation_attempted")?;
        validate_git_object("predecessor_candidate_commit", predecessor_candidate_commit)?;
        validate_git_object("predecessor_candidate_tree", predecessor_candidate_tree)?;
        validate_window(authorization_start, authorization_expiry)?;
        validate_paths(authorized_paths, *authorized_path_count)?;
        validate_path(discovered_missing_path)?;
        require(
            !authorized_paths.contains(discovered_missing_path),
            "discovered_missing_path",
        )
    }

    fn validate_consumed_hard_stop(&self) -> Result<(), ExternalSpecimenErrorV1> {
        let Self::ConsumedRepairHardStop {
            authorization_consumed,
            authorization_consumed_at,
            authorization_expiry,
            authorization_reusable,
            authorization_start,
            authorized_path_count,
            authorized_paths,
            changed_paths,
            checkpoint_commit,
            checkpoint_tree,
            next_missing_path,
            predecessor_candidate_commit,
            predecessor_candidate_tree,
            tests_or_builds_run,
            ..
        } = self
        else {
            unreachable!("variant-dispatched validator")
        };
        require(*authorization_consumed, "authorization_consumed")?;
        require(!authorization_reusable, "authorization_reusable")?;
        require(!tests_or_builds_run, "tests_or_builds_run")?;
        validate_window(authorization_start, authorization_expiry)?;
        validate_label("authorization_consumed_at", authorization_consumed_at)?;
        validate_paths(authorized_paths, *authorized_path_count)?;
        validate_path(next_missing_path)?;
        require(
            !authorized_paths.contains(next_missing_path),
            "next_missing_path",
        )?;
        validate_git_object("checkpoint_commit", checkpoint_commit)?;
        validate_git_object("checkpoint_tree", checkpoint_tree)?;
        validate_git_object("predecessor_candidate_commit", predecessor_candidate_commit)?;
        validate_git_object("predecessor_candidate_tree", predecessor_candidate_tree)?;
        let mut prior = None;
        for changed in changed_paths {
            validate_path(&changed.path)?;
            require(
                authorized_paths.contains(&changed.path),
                "changed_path_outside_authorized_paths",
            )?;
            if prior.as_ref().is_some_and(|path| path >= &changed.path) {
                return Err(ExternalSpecimenErrorV1::PathOrder);
            }
            prior = Some(changed.path.clone());
        }
        Ok(())
    }

    fn validate_readjudication(&self) -> Result<(), ExternalSpecimenErrorV1> {
        let Self::ArchitecturalReadjudication {
            additional_diagnostic_path_count,
            architecture_required,
            core_path_count,
            diagnostic_file_count,
            diagnostic_reference_count,
            existing_source_scope_admissible,
            overlap_path_count,
            ..
        } = self
        else {
            unreachable!("variant-dispatched validator")
        };
        require(*architecture_required, "architecture_required")?;
        require(
            !existing_source_scope_admissible,
            "existing_source_scope_admissible",
        )?;
        require(*core_path_count > 0, "core_path_count")?;
        require(
            *diagnostic_reference_count > 0,
            "diagnostic_reference_count",
        )?;
        require(
            overlap_path_count + additional_diagnostic_path_count == *diagnostic_file_count,
            "diagnostic_path_partition",
        )
    }
}

/// A strict external-specimen parsing or invariant failure.
#[derive(Debug, Error)]
pub enum ExternalSpecimenErrorV1 {
    /// Strict JCS parsing, canonicality, or typed decoding failed.
    #[error(transparent)]
    Jcs(#[from] JcsError),
    /// Fixture files use exactly one trailing line feed outside the JCS body.
    #[error("external specimen fixture must end in exactly one LF")]
    FixtureLineEnding,
    /// A required scalar invariant failed.
    #[error("external specimen invariant failed: {0}")]
    Invariant(&'static str),
    /// A repository-relative path is malformed.
    #[error("external specimen path is not normalized: {0}")]
    Path(String),
    /// A path list is not strictly sorted and duplicate-free.
    #[error("external specimen path list is not strictly ordered")]
    PathOrder,
    /// A path count disagrees with the actual closed list.
    #[error("external specimen path count is {actual}, expected {expected}")]
    PathCount { expected: u64, actual: usize },
    /// A Git object name is not exact lowercase SHA-1 text.
    #[error("external specimen Git object {field} is not 40 lowercase hex characters")]
    GitObject { field: &'static str },
}

fn require(condition: bool, field: &'static str) -> Result<(), ExternalSpecimenErrorV1> {
    if condition {
        Ok(())
    } else {
        Err(ExternalSpecimenErrorV1::Invariant(field))
    }
}

fn validate_label(field: &'static str, value: &str) -> Result<(), ExternalSpecimenErrorV1> {
    require(!value.is_empty() && value.trim() == value, field)
}

fn validate_labels(field: &'static str, values: &[String]) -> Result<(), ExternalSpecimenErrorV1> {
    require(!values.is_empty(), field)?;
    let unique: BTreeSet<_> = values.iter().collect();
    require(unique.len() == values.len(), field)?;
    values
        .iter()
        .try_for_each(|value| validate_label(field, value))
}

fn validate_git_object(field: &'static str, value: &str) -> Result<(), ExternalSpecimenErrorV1> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ExternalSpecimenErrorV1::GitObject { field })
    }
}

fn validate_window(start: &str, expiry: &str) -> Result<(), ExternalSpecimenErrorV1> {
    validate_label("authorization_start", start)?;
    validate_label("authorization_expiry", expiry)?;
    require(start < expiry, "authorization_window")
}

fn validate_paths(paths: &[String], expected: u64) -> Result<(), ExternalSpecimenErrorV1> {
    if u64::try_from(paths.len()) != Ok(expected) {
        return Err(ExternalSpecimenErrorV1::PathCount {
            expected,
            actual: paths.len(),
        });
    }
    let mut prior = None;
    for path in paths {
        validate_path(path)?;
        if prior.is_some_and(|prior: &String| prior >= path) {
            return Err(ExternalSpecimenErrorV1::PathOrder);
        }
        prior = Some(path);
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ExternalSpecimenErrorV1> {
    let valid = !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..");
    if valid {
        Ok(())
    } else {
        Err(ExternalSpecimenErrorV1::Path(path.to_owned()))
    }
}
