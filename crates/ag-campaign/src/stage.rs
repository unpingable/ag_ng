//! Stage projection: basis, scope, evidence contract, proposals, standing
//! records, receipts, verdicts, and residuals.

use core::fmt;

use ag_kernel::NonEmpty;
use ag_primitives::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{CampaignId, CampaignLabelError, WorkerRoleV1};
use crate::transcript::{transcript_digest, validate_label, validate_path_prefix};

/// Transcript digest domain for stage proposals.
pub const STAGE_PROPOSAL_DOMAIN_V1: &str = "ag.campaign.stage-proposal/v1";
/// Wire schema of a stage proposal.
pub const STAGE_PROPOSAL_SCHEMA_V1: &str = "ag.campaign.stage-proposal/v1";
/// Transcript digest domain for stage receipts (worker and verdict receipts).
pub const STAGE_RECEIPT_DOMAIN_V1: &str = "ag.campaign.stage-receipt/v1";
/// Wire schema of a worker stage receipt.
pub const STAGE_RECEIPT_SCHEMA_V1: &str = "ag.campaign.stage-receipt/v1";
/// Wire schema of a reviewer verdict receipt.
pub const VERDICT_RECEIPT_SCHEMA_V1: &str = "ag.campaign.verdict-receipt/v1";
/// Foreign-owned schema of Docket campaign-stage standing. The digest is an
/// opaque identity recorded and verified by equality only.
pub const DOCKET_STANDING_SCHEMA_V1: &str = "gwr:campaign-stage-standing:v1";
/// Internal digest domain for campaign residuals.
pub const RESIDUAL_DOMAIN_V1: &str = "ag.campaign.residual/v1";

/// The exact identity of one proposed stage: its proposal transcript digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StageId(Digest);

impl StageId {
    /// Wraps an already-derived stage identity digest.
    #[must_use]
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    #[must_use]
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }

    /// Returns the canonical digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for StageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An exact reviewer finding identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FindingId(String);

impl FindingId {
    /// Validates and constructs a finding identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLabelError`] for an empty, overlong, or
    /// control-character-bearing identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, CampaignLabelError> {
        let value = value.into();
        validate_label("finding ID", &value)?;
        Ok(Self(value))
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for FindingId {
    type Error = CampaignLabelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FindingId> for String {
    fn from(value: FindingId) -> Self {
        value.0
    }
}

/// The exact basis a stage starts from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageBasisV1 {
    /// Governed repository identity.
    pub repository: String,
    /// Exact base commit digest.
    pub base_commit: Digest,
    /// Exact base tree digest.
    pub base_tree: Digest,
}

impl StageBasisV1 {
    /// Validates the basis fields.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLabelError`] for a noncanonical repository identity.
    pub fn validate(&self) -> Result<(), CampaignLabelError> {
        validate_label("repository", &self.repository)
    }
}

/// One exact repository path grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathGrantV1 {
    /// Governed repository identity.
    pub repository: String,
    /// Absolute, normalized path prefix within the repository.
    pub path_prefix: String,
}

impl PathGrantV1 {
    /// Validates the grant fields.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLabelError`] for a noncanonical repository or path.
    pub fn validate(&self) -> Result<(), CampaignLabelError> {
        validate_label("repository", &self.repository)?;
        validate_path_prefix(&self.path_prefix)
    }
}

/// The bounded mutation scope of an operator stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationScopeV1 {
    /// Every admitted mutation path grant; must be non-empty.
    pub grants: Vec<PathGrantV1>,
}

/// The read-only scope of a reviewer stage. There is no mutation vocabulary
/// on this type: reviewer stages cannot carry mutation effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewScopeV1 {
    /// The executed subject stage under review.
    pub subject_stage: StageId,
    /// Every admitted read path grant; must be non-empty.
    pub read_paths: Vec<PathGrantV1>,
}

/// The exactly-one-role stage kind. The role is the variant, so a stage
/// cannot carry two roles or none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageKindV1 {
    /// Operator stage with a bounded mutation scope.
    Operator(MutationScopeV1),
    /// Reviewer stage with a read-only scope over a subject stage.
    Review(ReviewScopeV1),
}

impl StageKindV1 {
    /// Returns the role this kind carries.
    #[must_use]
    pub const fn role(&self) -> WorkerRoleV1 {
        match self {
            Self::Operator(_) => WorkerRoleV1::Operator,
            Self::Review(_) => WorkerRoleV1::Reviewer,
        }
    }
}

/// One required evidence artifact schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequirementV1 {
    /// Exact required artifact schema.
    pub schema: String,
}

/// The evidence contract a stage receipt must satisfy exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceContractV1 {
    /// Every required artifact; must be non-empty with unique schemas.
    pub required: Vec<EvidenceRequirementV1>,
}

/// One produced evidence artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactV1 {
    /// Exact artifact schema.
    pub schema: String,
    /// Exact artifact content digest.
    pub digest: Digest,
}

/// The provenance of a proposed bounded repair: the exact finding identifiers
/// and the exact rejected review receipt digest it answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairProvenanceV1 {
    /// Exact finding identifiers cited; non-empty by construction.
    pub finding_ids: NonEmpty<FindingId>,
    /// Exact digest of the rejected verdict receipt being repaired.
    pub rejected_review: Digest,
}

/// A rejected stage proposal.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StageProposalError {
    /// The schema is not exactly [`STAGE_PROPOSAL_SCHEMA_V1`].
    #[error("stage proposal schema must be exactly `{STAGE_PROPOSAL_SCHEMA_V1}`")]
    Schema,
    /// Stage sequence numbers are nonzero.
    #[error("stage sequence must be nonzero")]
    ZeroSequence,
    /// The basis is not canonical.
    #[error("invalid stage basis: {0}")]
    Basis(CampaignLabelError),
    /// A scope grant is not canonical or the scope is empty.
    #[error("invalid stage scope: {0}")]
    Scope(CampaignLabelError),
    /// The evidence contract is empty or has duplicate schemas.
    #[error("invalid evidence contract: {0}")]
    Evidence(CampaignLabelError),
    /// A repair proposal needs its provenance; a non-repair proposal forbids it.
    #[error("repair provenance mismatch for the stage kind")]
    RepairProvenance,
}

fn validate_grants(grants: &[PathGrantV1]) -> Result<(), CampaignLabelError> {
    if grants.is_empty() {
        return Err(CampaignLabelError::Empty {
            kind: "stage scope",
        });
    }
    for grant in grants {
        grant.validate()?;
    }
    Ok(())
}

fn validate_evidence(evidence: &EvidenceContractV1) -> Result<(), CampaignLabelError> {
    if evidence.required.is_empty() {
        return Err(CampaignLabelError::Empty {
            kind: "evidence contract",
        });
    }
    for (index, requirement) in evidence.required.iter().enumerate() {
        validate_label("evidence schema", &requirement.schema)?;
        if evidence.required[index + 1..]
            .iter()
            .any(|other| other.schema == requirement.schema)
        {
            return Err(CampaignLabelError::Duplicate {
                kind: "evidence contract",
            });
        }
    }
    Ok(())
}

/// A proposed stage: a request for Docket admission, never an admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageProposalV1 {
    schema: String,
    campaign: CampaignId,
    stage_seq: u64,
    kind: StageKindV1,
    basis: StageBasisV1,
    evidence: EvidenceContractV1,
    repair: Option<RepairProvenanceV1>,
}

impl StageProposalV1 {
    /// Proposes an operator stage.
    ///
    /// # Errors
    ///
    /// Returns [`StageProposalError`] for a zero sequence, noncanonical basis
    /// or scope, or an invalid evidence contract.
    pub fn operator(
        campaign: &CampaignId,
        stage_seq: u64,
        basis: StageBasisV1,
        scope: MutationScopeV1,
        evidence: EvidenceContractV1,
    ) -> Result<Self, StageProposalError> {
        Self::build(
            campaign,
            stage_seq,
            StageKindV1::Operator(scope),
            basis,
            evidence,
            None,
        )
    }

    /// Proposes a reviewer stage over an executed subject stage.
    ///
    /// # Errors
    ///
    /// Returns [`StageProposalError`] as in [`Self::operator`].
    pub fn review(
        campaign: &CampaignId,
        stage_seq: u64,
        basis: StageBasisV1,
        scope: ReviewScopeV1,
        evidence: EvidenceContractV1,
    ) -> Result<Self, StageProposalError> {
        Self::build(
            campaign,
            stage_seq,
            StageKindV1::Review(scope),
            basis,
            evidence,
            None,
        )
    }

    /// Proposes a bounded repair stage citing exact findings and the exact
    /// rejected review receipt digest.
    ///
    /// # Errors
    ///
    /// Returns [`StageProposalError`] as in [`Self::operator`]. The finding
    /// set is non-empty by construction.
    pub fn repair(
        campaign: &CampaignId,
        stage_seq: u64,
        basis: StageBasisV1,
        scope: MutationScopeV1,
        evidence: EvidenceContractV1,
        finding_ids: NonEmpty<FindingId>,
        rejected_review: Digest,
    ) -> Result<Self, StageProposalError> {
        Self::build(
            campaign,
            stage_seq,
            StageKindV1::Operator(scope),
            basis,
            evidence,
            Some(RepairProvenanceV1 {
                finding_ids,
                rejected_review,
            }),
        )
    }

    fn build(
        campaign: &CampaignId,
        stage_seq: u64,
        kind: StageKindV1,
        basis: StageBasisV1,
        evidence: EvidenceContractV1,
        repair: Option<RepairProvenanceV1>,
    ) -> Result<Self, StageProposalError> {
        let proposal = Self {
            schema: STAGE_PROPOSAL_SCHEMA_V1.to_owned(),
            campaign: campaign.clone(),
            stage_seq,
            kind,
            basis,
            evidence,
            repair,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    /// Revalidates a deserialized proposal.
    ///
    /// # Errors
    ///
    /// Returns the same failures as the constructors, plus
    /// [`StageProposalError::Schema`] for a foreign schema.
    pub fn validate(&self) -> Result<(), StageProposalError> {
        if self.schema != STAGE_PROPOSAL_SCHEMA_V1 {
            return Err(StageProposalError::Schema);
        }
        if self.stage_seq == 0 {
            return Err(StageProposalError::ZeroSequence);
        }
        self.basis.validate().map_err(StageProposalError::Basis)?;
        match &self.kind {
            StageKindV1::Operator(scope) => {
                validate_grants(&scope.grants).map_err(StageProposalError::Scope)?;
            }
            StageKindV1::Review(scope) => {
                validate_grants(&scope.read_paths).map_err(StageProposalError::Scope)?;
            }
        }
        validate_evidence(&self.evidence).map_err(StageProposalError::Evidence)?;
        if matches!(self.kind, StageKindV1::Review(_)) && self.repair.is_some() {
            return Err(StageProposalError::RepairProvenance);
        }
        Ok(())
    }

    /// Returns the exact stage identity: the proposal transcript digest.
    #[must_use]
    pub fn id(&self) -> StageId {
        StageId(transcript_digest(STAGE_PROPOSAL_DOMAIN_V1, self))
    }

    /// Returns the campaign this stage belongs to. Exactly one, always.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignId {
        &self.campaign
    }

    /// Returns the nonzero stage sequence within the campaign.
    #[must_use]
    pub const fn stage_seq(&self) -> u64 {
        self.stage_seq
    }

    /// Returns the stage kind; its variant is the stage's exactly one role.
    #[must_use]
    pub const fn kind(&self) -> &StageKindV1 {
        &self.kind
    }

    /// Returns the stage role.
    #[must_use]
    pub const fn role(&self) -> WorkerRoleV1 {
        self.kind.role()
    }

    /// Returns the exact stage basis.
    #[must_use]
    pub const fn basis(&self) -> &StageBasisV1 {
        &self.basis
    }

    /// Returns the stage evidence contract.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceContractV1 {
        &self.evidence
    }

    /// Returns the repair provenance for a repair stage.
    #[must_use]
    pub const fn repair_provenance(&self) -> Option<&RepairProvenanceV1> {
        self.repair.as_ref()
    }
}

/// A Docket-issued campaign-stage standing record.
///
/// The standing digest is an opaque upstream identity under
/// [`DOCKET_STANDING_SCHEMA_V1`]: it is recorded and verified by equality,
/// never recomputed across canonicalizations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketStandingV1 {
    /// Exact upstream schema; anything else is not that record.
    pub schema: String,
    /// The stage this standing admits.
    pub stage: StageId,
    /// Opaque standing identity.
    pub standing_digest: Digest,
    /// Standing expiry as a Unix timestamp in seconds.
    pub expiry_unix: u64,
}

impl DocketStandingV1 {
    /// Validates the standing record shape.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLabelError::ForeignSchema`] for a foreign schema and
    /// [`CampaignLabelError::NotAdmitted`] for a zero expiry.
    pub fn validate(&self) -> Result<(), CampaignLabelError> {
        if self.schema != DOCKET_STANDING_SCHEMA_V1 {
            return Err(CampaignLabelError::ForeignSchema {
                kind: "Docket standing",
            });
        }
        if self.expiry_unix == 0 {
            return Err(CampaignLabelError::NotAdmitted {
                kind: "standing expiry",
            });
        }
        Ok(())
    }
}

/// A worker execution receipt for one operator stage. Evidence, not
/// authority; it cannot admit any stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageReceiptV1 {
    /// Exact wire schema.
    pub schema: String,
    /// Campaign identity.
    pub campaign: CampaignId,
    /// Executed stage identity.
    pub stage: StageId,
    /// Stage sequence.
    pub stage_seq: u64,
    /// Worker role; must be the operator role.
    pub role: WorkerRoleV1,
    /// Consumed standing digest this execution burned.
    pub standing: Digest,
    /// Exact runtime envelope digest the execution answered.
    pub envelope: Digest,
    /// Exact basis the execution started from.
    pub basis: StageBasisV1,
    /// Observed post-execution tree, when the executor reports one.
    pub post_tree: Option<Digest>,
    /// Produced evidence artifacts satisfying the stage evidence contract.
    pub artifacts: Vec<EvidenceArtifactV1>,
}

impl StageReceiptV1 {
    /// Returns the exact receipt identity.
    #[must_use]
    pub fn id(&self) -> Digest {
        transcript_digest(STAGE_RECEIPT_DOMAIN_V1, self)
    }

    /// Validates the receipt shape.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLabelError`] for a foreign schema, a non-operator
    /// role, a zero sequence, or a noncanonical basis.
    pub fn validate(&self) -> Result<(), CampaignLabelError> {
        if self.schema != STAGE_RECEIPT_SCHEMA_V1 {
            return Err(CampaignLabelError::ForeignSchema {
                kind: "stage receipt",
            });
        }
        if self.role != WorkerRoleV1::Operator {
            return Err(CampaignLabelError::NotAdmitted {
                kind: "stage receipt role",
            });
        }
        if self.stage_seq == 0 {
            return Err(CampaignLabelError::NotAdmitted {
                kind: "stage sequence",
            });
        }
        self.basis.validate()
    }
}

/// The closed reviewer verdict vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictV1 {
    /// The reviewed work is accepted.
    Accept,
    /// The reviewed work is rejected with exact findings.
    Reject,
}

/// One exact reviewer finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingV1 {
    /// Exact finding identifier.
    pub finding_id: FindingId,
    /// Bounded finding statement.
    pub statement: String,
}

/// A rejected verdict receipt.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VerdictReceiptError {
    /// The schema is not exactly [`VERDICT_RECEIPT_SCHEMA_V1`].
    #[error("verdict receipt schema must be exactly `{VERDICT_RECEIPT_SCHEMA_V1}`")]
    Schema,
    /// A rejection must name at least one exact finding.
    #[error("a rejecting verdict requires at least one finding")]
    RejectWithoutFindings,
    /// An acceptance cannot carry findings.
    #[error("an accepting verdict cannot carry findings")]
    AcceptWithFindings,
    /// Finding identifiers must be unique within one verdict.
    #[error("duplicate finding identifier in verdict")]
    DuplicateFinding,
    /// A finding statement or the basis is not canonical.
    #[error("invalid verdict content: {0}")]
    Content(#[from] CampaignLabelError),
}

/// A reviewer verdict receipt over one executed stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictReceiptV1 {
    schema: String,
    campaign: CampaignId,
    review_stage: StageId,
    subject_stage: StageId,
    subject_receipt: Digest,
    reviewer: Digest,
    verdict: VerdictV1,
    findings: Vec<FindingV1>,
    basis_observed: StageBasisV1,
}

impl VerdictReceiptV1 {
    /// Creates a verdict receipt.
    ///
    /// # Errors
    ///
    /// Returns [`VerdictReceiptError`] when an acceptance carries findings, a
    /// rejection carries none, finding identifiers repeat, or any content is
    /// noncanonical.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign: &CampaignId,
        review_stage: StageId,
        subject_stage: StageId,
        subject_receipt: Digest,
        reviewer: Digest,
        verdict: VerdictV1,
        findings: Vec<FindingV1>,
        basis_observed: StageBasisV1,
    ) -> Result<Self, VerdictReceiptError> {
        let receipt = Self {
            schema: VERDICT_RECEIPT_SCHEMA_V1.to_owned(),
            campaign: campaign.clone(),
            review_stage,
            subject_stage,
            subject_receipt,
            reviewer,
            verdict,
            findings,
            basis_observed,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Revalidates a deserialized verdict receipt.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::new`], plus
    /// [`VerdictReceiptError::Schema`] for a foreign schema.
    pub fn validate(&self) -> Result<(), VerdictReceiptError> {
        if self.schema != VERDICT_RECEIPT_SCHEMA_V1 {
            return Err(VerdictReceiptError::Schema);
        }
        match self.verdict {
            VerdictV1::Accept if !self.findings.is_empty() => {
                return Err(VerdictReceiptError::AcceptWithFindings);
            }
            VerdictV1::Reject if self.findings.is_empty() => {
                return Err(VerdictReceiptError::RejectWithoutFindings);
            }
            _ => {}
        }
        for (index, finding) in self.findings.iter().enumerate() {
            validate_label("finding statement", &finding.statement)?;
            if self.findings[index + 1..]
                .iter()
                .any(|other| other.finding_id == finding.finding_id)
            {
                return Err(VerdictReceiptError::DuplicateFinding);
            }
        }
        self.basis_observed.validate()?;
        Ok(())
    }

    /// Returns the exact verdict receipt identity (a stage-receipt-family
    /// transcript digest).
    #[must_use]
    pub fn id(&self) -> Digest {
        transcript_digest(STAGE_RECEIPT_DOMAIN_V1, self)
    }

    /// Returns the campaign identity.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignId {
        &self.campaign
    }

    /// Returns the review stage that produced this verdict.
    #[must_use]
    pub const fn review_stage(&self) -> &StageId {
        &self.review_stage
    }

    /// Returns the executed subject stage under review.
    #[must_use]
    pub const fn subject_stage(&self) -> &StageId {
        &self.subject_stage
    }

    /// Returns the exact reviewed stage receipt digest.
    #[must_use]
    pub const fn subject_receipt(&self) -> &Digest {
        &self.subject_receipt
    }

    /// Returns the reviewer principal identity.
    #[must_use]
    pub const fn reviewer(&self) -> &Digest {
        &self.reviewer
    }

    /// Returns the verdict.
    #[must_use]
    pub const fn verdict(&self) -> VerdictV1 {
        self.verdict
    }

    /// Returns the exact findings.
    #[must_use]
    pub fn findings(&self) -> &[FindingV1] {
        &self.findings
    }

    /// Returns the basis the reviewer observed.
    #[must_use]
    pub const fn basis_observed(&self) -> &StageBasisV1 {
        &self.basis_observed
    }
}

/// A bounded campaign residual: an obligation recorded but not discharged.
/// Residuals only accumulate; nothing in this layer discharges or erases one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignResidualV1 {
    /// Book-local residual identifier.
    pub residual_id: String,
    /// The stage the residual attaches to, when any.
    pub stage: Option<StageId>,
    /// Bounded residual statement.
    pub statement: String,
}

impl CampaignResidualV1 {
    /// Validates the residual shape.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLabelError`] for a noncanonical identifier or
    /// statement.
    pub fn validate(&self) -> Result<(), CampaignLabelError> {
        validate_label("residual ID", &self.residual_id)?;
        validate_label("residual statement", &self.statement)
    }

    /// Returns the exact residual identity.
    #[must_use]
    pub fn id(&self) -> Digest {
        transcript_digest(RESIDUAL_DOMAIN_V1, self)
    }
}
