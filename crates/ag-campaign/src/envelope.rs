//! The authority-neutral runtime-envelope seam toward the execution sidecar.
//!
//! An envelope is exact dispatch evidence: it binds the campaign, stage,
//! role, consumed standing digest, exact basis, allowed paths, evidence
//! contract, expiry, and nonce. Rendering one requires a
//! [`ConsumedStandingV1`] token, which only the ledger's burn produces, so an
//! envelope cannot exist before the standing consumption is recorded. The
//! sidecar executes mechanics only; this module verifies its runtime receipt
//! against the exact envelope.

use ag_primitives::{Digest, LifecycleNonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{CampaignId, CampaignLabelError, WorkerRoleV1};
use crate::ledger::{ConsumedStandingV1, check_evidence_contract};
use crate::stage::{
    EvidenceArtifactV1, EvidenceContractV1, PathGrantV1, STAGE_RECEIPT_SCHEMA_V1, StageId,
    StageKindV1, StageProposalV1, StageReceiptV1,
};
use crate::transcript::transcript_digest;

/// Transcript digest domain for runtime envelopes.
pub const RUNTIME_ENVELOPE_DOMAIN_V1: &str = "ag.campaign.runtime-envelope/v1";
/// Wire schema of a runtime envelope.
pub const RUNTIME_ENVELOPE_SCHEMA_V1: &str = "ag.campaign.runtime-envelope/v1";
/// Transcript digest domain for sidecar runtime receipts.
pub const RUNTIME_RECEIPT_DOMAIN_V1: &str = "ag.campaign.runtime-receipt/v1";
/// Wire schema of a sidecar runtime receipt.
pub const RUNTIME_RECEIPT_SCHEMA_V1: &str = "ag.campaign.runtime-receipt/v1";

/// The exact, digest-bound runtime execution envelope for the sidecar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEnvelopeV1 {
    schema: String,
    campaign: CampaignId,
    stage: StageId,
    role: WorkerRoleV1,
    standing_digest: Digest,
    consumption_digest: Digest,
    basis_commit: Digest,
    basis_tree: Digest,
    allowed_paths: Vec<PathGrantV1>,
    evidence: EvidenceContractV1,
    expiry_unix: u64,
    nonce: LifecycleNonce,
}

impl RuntimeEnvelopeV1 {
    /// Renders the exact runtime envelope for one consumed standing.
    ///
    /// The consumed-standing token is the only way to reach this constructor,
    /// which is the burn-before-effect seam: the consumption is durably
    /// recorded before any envelope exists. The envelope carries evidence
    /// only; it authorizes nothing by itself.
    #[must_use]
    pub fn render(
        consumed: &ConsumedStandingV1,
        proposal: &StageProposalV1,
        nonce: LifecycleNonce,
    ) -> Self {
        let allowed_paths = match proposal.kind() {
            StageKindV1::Operator(scope) => scope.grants.clone(),
            StageKindV1::Review(scope) => scope.read_paths.clone(),
        };
        Self {
            schema: RUNTIME_ENVELOPE_SCHEMA_V1.to_owned(),
            campaign: consumed.campaign().clone(),
            stage: consumed.stage().clone(),
            role: proposal.role(),
            standing_digest: consumed.standing_digest().clone(),
            consumption_digest: consumed.consumption_digest().clone(),
            basis_commit: proposal.basis().base_commit.clone(),
            basis_tree: proposal.basis().base_tree.clone(),
            allowed_paths,
            evidence: proposal.evidence().clone(),
            expiry_unix: consumed.expiry_unix(),
            nonce,
        }
    }

    /// Returns the exact envelope identity.
    #[must_use]
    pub fn digest(&self) -> Digest {
        transcript_digest(RUNTIME_ENVELOPE_DOMAIN_V1, self)
    }

    /// Revalidates a deserialized envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLabelError`] for a foreign schema, zero expiry, or a
    /// noncanonical path grant.
    pub fn validate(&self) -> Result<(), CampaignLabelError> {
        if self.schema != RUNTIME_ENVELOPE_SCHEMA_V1 {
            return Err(CampaignLabelError::ForeignSchema {
                kind: "runtime envelope",
            });
        }
        if self.expiry_unix == 0 {
            return Err(CampaignLabelError::NotAdmitted {
                kind: "envelope expiry",
            });
        }
        for grant in &self.allowed_paths {
            grant.validate()?;
        }
        Ok(())
    }

    /// Returns the campaign identity.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignId {
        &self.campaign
    }

    /// Returns the stage identity.
    #[must_use]
    pub const fn stage(&self) -> &StageId {
        &self.stage
    }

    /// Returns the worker role.
    #[must_use]
    pub const fn role(&self) -> WorkerRoleV1 {
        self.role
    }

    /// Returns the consumed standing digest.
    #[must_use]
    pub const fn standing_digest(&self) -> &Digest {
        &self.standing_digest
    }

    /// Returns the consumption digest proving burn-before-effect.
    #[must_use]
    pub const fn consumption_digest(&self) -> &Digest {
        &self.consumption_digest
    }

    /// Returns the exact basis commit digest.
    #[must_use]
    pub const fn basis_commit(&self) -> &Digest {
        &self.basis_commit
    }

    /// Returns the exact basis tree digest.
    #[must_use]
    pub const fn basis_tree(&self) -> &Digest {
        &self.basis_tree
    }

    /// Returns the exact allowed path grants.
    #[must_use]
    pub fn allowed_paths(&self) -> &[PathGrantV1] {
        &self.allowed_paths
    }

    /// Returns the stage evidence contract.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceContractV1 {
        &self.evidence
    }

    /// Returns the expiry as a Unix timestamp in seconds.
    #[must_use]
    pub const fn expiry_unix(&self) -> u64 {
        self.expiry_unix
    }

    /// Returns the one-use dispatch nonce.
    #[must_use]
    pub const fn nonce(&self) -> &LifecycleNonce {
        &self.nonce
    }
}

/// The closed sidecar outcome vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarOutcomeV1 {
    /// Mechanics completed and produced the contracted artifacts.
    Completed,
    /// Mechanics failed; no artifacts are claimed.
    Failed,
    /// The sidecar refused the envelope.
    Refused,
}

/// The sidecar's runtime receipt answering one exact envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarRuntimeReceiptV1 {
    /// Exact wire schema.
    pub schema: String,
    /// Digest of the envelope this receipt answers.
    pub envelope_digest: Digest,
    /// Campaign identity.
    pub campaign: CampaignId,
    /// Stage identity.
    pub stage: StageId,
    /// Consumed standing digest echoed from the envelope.
    pub standing_digest: Digest,
    /// One-use dispatch nonce echoed from the envelope.
    pub nonce: LifecycleNonce,
    /// Closed outcome vocabulary.
    pub outcome: SidecarOutcomeV1,
    /// Observed post-execution tree, when reported.
    pub post_tree: Option<Digest>,
    /// Produced evidence artifacts.
    pub artifacts: Vec<EvidenceArtifactV1>,
}

impl SidecarRuntimeReceiptV1 {
    /// Returns the exact receipt identity.
    #[must_use]
    pub fn id(&self) -> Digest {
        transcript_digest(RUNTIME_RECEIPT_DOMAIN_V1, self)
    }
}

/// A rejected sidecar runtime receipt.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SidecarVerificationErrorV1 {
    /// The receipt schema is foreign.
    #[error("sidecar receipt carries a foreign schema")]
    Schema,
    /// The receipt answers a different envelope.
    #[error("sidecar receipt answers a different envelope")]
    EnvelopeMismatch,
    /// The receipt names a different campaign.
    #[error("sidecar receipt names a different campaign")]
    CampaignMismatch,
    /// The receipt names a different stage.
    #[error("sidecar receipt names a different stage")]
    StageMismatch,
    /// The receipt echoes a different standing digest.
    #[error("sidecar receipt echoes a different standing digest")]
    StandingMismatch,
    /// The receipt echoes a different nonce.
    #[error("sidecar receipt echoes a different nonce")]
    NonceMismatch,
    /// A completed outcome lacks a contracted artifact or carries foreign
    /// artifacts.
    #[error("sidecar artifacts do not satisfy the envelope evidence contract")]
    EvidenceContractViolation,
    /// A completed reviewer-role envelope must not report a mutation tree.
    #[error("reviewer-role execution cannot report a post-mutation tree")]
    ReviewerMutation,
}

/// A verified sidecar execution: the receipt bound to its exact envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSidecarExecutionV1 {
    envelope_digest: Digest,
    outcome: SidecarOutcomeV1,
    post_tree: Option<Digest>,
    artifacts: Vec<EvidenceArtifactV1>,
    receipt_digest: Digest,
}

impl VerifiedSidecarExecutionV1 {
    /// Returns the answered envelope digest.
    #[must_use]
    pub const fn envelope_digest(&self) -> &Digest {
        &self.envelope_digest
    }

    /// Returns the verified outcome.
    #[must_use]
    pub const fn outcome(&self) -> SidecarOutcomeV1 {
        self.outcome
    }

    /// Returns the verified post-execution tree, when any.
    #[must_use]
    pub const fn post_tree(&self) -> Option<&Digest> {
        self.post_tree.as_ref()
    }

    /// Returns the verified artifacts.
    #[must_use]
    pub fn artifacts(&self) -> &[EvidenceArtifactV1] {
        &self.artifacts
    }

    /// Returns the verified receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }
}

/// Verifies a sidecar runtime receipt against the exact envelope it answers.
///
/// This is the typed-field form: the receipt must bind the envelope's
/// transcript digest. Kept for in-domain verification; the cross-repository
/// artifact rule uses [`verify_sidecar_receipt_against`] with the envelope
/// file-bytes digest.
///
/// # Errors
///
/// Returns a typed [`SidecarVerificationErrorV1`] for any identity mismatch,
/// a foreign schema, an unsatisfied evidence contract on a completed outcome,
/// or a reviewer-role mutation claim.
pub fn verify_sidecar_receipt(
    envelope: &RuntimeEnvelopeV1,
    receipt: &SidecarRuntimeReceiptV1,
) -> Result<VerifiedSidecarExecutionV1, SidecarVerificationErrorV1> {
    verify_sidecar_receipt_against(envelope, &envelope.digest(), receipt)
}

/// Verifies a sidecar runtime receipt against an explicit envelope digest.
///
/// Cross-repository artifact rule: artifact digests bind the exact artifact
/// file bytes, so the caller passes the digest of the envelope artifact as
/// received (SHA-256 over its bytes); every other check is identical to
/// [`verify_sidecar_receipt`]. No party re-canonicalizes across
/// implementations.
///
/// # Errors
///
/// Returns a typed [`SidecarVerificationErrorV1`] as in
/// [`verify_sidecar_receipt`]; [`SidecarVerificationErrorV1::EnvelopeMismatch`]
/// when the receipt answers a different envelope artifact digest.
pub fn verify_sidecar_receipt_against(
    envelope: &RuntimeEnvelopeV1,
    envelope_digest: &Digest,
    receipt: &SidecarRuntimeReceiptV1,
) -> Result<VerifiedSidecarExecutionV1, SidecarVerificationErrorV1> {
    if receipt.schema != RUNTIME_RECEIPT_SCHEMA_V1 {
        return Err(SidecarVerificationErrorV1::Schema);
    }
    if receipt.envelope_digest != *envelope_digest {
        return Err(SidecarVerificationErrorV1::EnvelopeMismatch);
    }
    if receipt.campaign != *envelope.campaign() {
        return Err(SidecarVerificationErrorV1::CampaignMismatch);
    }
    if receipt.stage != *envelope.stage() {
        return Err(SidecarVerificationErrorV1::StageMismatch);
    }
    if receipt.standing_digest != *envelope.standing_digest() {
        return Err(SidecarVerificationErrorV1::StandingMismatch);
    }
    if receipt.nonce != *envelope.nonce() {
        return Err(SidecarVerificationErrorV1::NonceMismatch);
    }
    if receipt.outcome == SidecarOutcomeV1::Completed {
        check_evidence_contract(envelope.evidence(), &receipt.artifacts)
            .map_err(|_| SidecarVerificationErrorV1::EvidenceContractViolation)?;
        if envelope.role() == WorkerRoleV1::Reviewer && receipt.post_tree.is_some() {
            return Err(SidecarVerificationErrorV1::ReviewerMutation);
        }
    }
    Ok(VerifiedSidecarExecutionV1 {
        envelope_digest: receipt.envelope_digest.clone(),
        outcome: receipt.outcome,
        post_tree: receipt.post_tree.clone(),
        artifacts: receipt.artifacts.clone(),
        receipt_digest: receipt.id(),
    })
}

/// Builds the worker stage receipt from a verified completed execution.
///
/// Returns `None` for a non-completed outcome: a failed or refused execution
/// produces no stage receipt (the caller records a refusal instead).
#[must_use]
pub fn stage_receipt_from_execution(
    envelope: &RuntimeEnvelopeV1,
    proposal: &StageProposalV1,
    verified: &VerifiedSidecarExecutionV1,
) -> Option<StageReceiptV1> {
    if verified.outcome != SidecarOutcomeV1::Completed {
        return None;
    }
    Some(StageReceiptV1 {
        schema: STAGE_RECEIPT_SCHEMA_V1.to_owned(),
        campaign: envelope.campaign().clone(),
        stage: envelope.stage().clone(),
        stage_seq: proposal.stage_seq(),
        role: envelope.role(),
        standing: envelope.standing_digest().clone(),
        // The ledger-facing receipt binds the in-domain typed envelope
        // identity recorded at dispatch; the cross-repository file-bytes
        // binding (verified.envelope_digest) is enforced at the seam and
        // does not replace the in-domain identity.
        envelope: envelope.digest(),
        basis: proposal.basis().clone(),
        post_tree: verified.post_tree.clone(),
        artifacts: verified.artifacts.clone(),
    })
}
