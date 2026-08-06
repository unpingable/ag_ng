//! Campaign orchestration office semantics for Agent Governor NG.
//!
//! This crate adds campaign vocabulary — exact campaign identity, the stage
//! projection, worker-role separation, digest-bound Docket standing records,
//! stage and verdict receipts, bounded repairs, residuals, campaign
//! recomposition, and the authority-neutral runtime-envelope seam — without
//! owning or minting any authority. A campaign grants no authority: a proposed
//! stage is a request for Docket admission, Docket standing digests are opaque
//! identities verified by equality only, and every receipt is evidence, never
//! a capability.
//!
//! The doctrine for this layer lives in
//! `docs/campaign-orchestration-office.md`.

#![forbid(unsafe_code)]

mod identity;
mod stage;
mod transcript;

pub use identity::{
    CAMPAIGN_IDENTITY_DOMAIN_V1, CAMPAIGN_INTENT_SCHEMA_V1, CampaignId, CampaignIntentError,
    CampaignIntentV1, CampaignLabelError, WorkerRoleV1,
};
pub use stage::{
    CampaignResidualV1, DOCKET_STANDING_SCHEMA_V1, DocketStandingV1, EvidenceArtifactV1,
    EvidenceContractV1, EvidenceRequirementV1, FindingId, FindingV1, MutationScopeV1,
    PathGrantV1, RESIDUAL_DOMAIN_V1, RepairProvenanceV1, ReviewScopeV1, STAGE_PROPOSAL_DOMAIN_V1,
    STAGE_PROPOSAL_SCHEMA_V1, STAGE_RECEIPT_DOMAIN_V1, STAGE_RECEIPT_SCHEMA_V1, StageBasisV1,
    StageId, StageKindV1, StageProposalError, StageProposalV1, StageReceiptV1,
    VERDICT_RECEIPT_SCHEMA_V1, VerdictReceiptError, VerdictReceiptV1, VerdictV1,
};
