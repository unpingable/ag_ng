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

mod envelope;
mod identity;
mod ledger;
mod recomposition;
mod stage;
mod transcript;

pub use envelope::{
    RUNTIME_ENVELOPE_DOMAIN_V1, RUNTIME_ENVELOPE_SCHEMA_V1, RUNTIME_RECEIPT_DOMAIN_V1,
    RUNTIME_RECEIPT_SCHEMA_V1, RuntimeEnvelopeV1, SidecarOutcomeV1, SidecarRuntimeReceiptV1,
    SidecarVerificationErrorV1, VerifiedSidecarExecutionV1, stage_receipt_from_execution,
    verify_sidecar_receipt, verify_sidecar_receipt_against,
};
pub use identity::{
    CAMPAIGN_IDENTITY_DOMAIN_V1, CAMPAIGN_INTENT_SCHEMA_V1, CampaignId, CampaignIntentError,
    CampaignIntentV1, CampaignLabelError, WorkerRoleV1,
};
pub use ledger::{
    CampaignEventV1, CampaignLedgerV1, CampaignStatusV1, CandidateActionRefusalV1,
    CandidateActionV1, ConsumedStandingV1, ConsumptionRecordV1, DispatchRecordV1, LedgerErrorV1,
    ProhibitionV1, REFUSAL_DOMAIN_V1, RecordedRefusalV1, STANDING_CONSUMPTION_DOMAIN_V1,
    StageStateV1, StandingStateV1, consumption_digest,
};
pub use recomposition::{
    ACCOUNTING_DOMAIN_V1, AccountingKindV1, CampaignAccountingPlanV1, CampaignDispositionsV1,
    CampaignObstructionV1, CampaignRecompositionReceiptV1, CampaignRecompositionRefusalV1,
    PlanRefusalV1, PresentedReceiptV1, RECOMPOSITION_RECEIPT_DOMAIN_V1,
    RECOMPOSITION_RECEIPT_SCHEMA_V1, RequiredReceiptV1, plan_from_ledger, present_from_ledger,
    recompose_campaign,
};
pub use stage::{
    CampaignResidualV1, DOCKET_STANDING_SCHEMA_V1, DocketStandingV1, EvidenceArtifactV1,
    EvidenceContractV1, EvidenceRequirementV1, FindingId, FindingV1, MutationScopeV1, PathGrantV1,
    RESIDUAL_DOMAIN_V1, RepairProvenanceV1, ReviewScopeV1, STAGE_PROPOSAL_DOMAIN_V1,
    STAGE_PROPOSAL_SCHEMA_V1, STAGE_RECEIPT_DOMAIN_V1, STAGE_RECEIPT_SCHEMA_V1, StageBasisV1,
    StageId, StageKindV1, StageProposalError, StageProposalV1, StageReceiptV1,
    VERDICT_RECEIPT_SCHEMA_V1, VerdictReceiptError, VerdictReceiptV1, VerdictV1,
};
