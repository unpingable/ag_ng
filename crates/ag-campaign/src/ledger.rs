//! The campaign ledger: lifecycle enforcement over exact recorded evidence.
//!
//! The ledger is caller-owned and in-memory, like the kernel's decision
//! ledger; durability is the store layer's replay of the exact event
//! sequence. Every transition is an event, and replay re-applies the same
//! validations, so a tampered log refuses rather than reinterpretation.

use std::collections::BTreeMap;

use ag_primitives::{AuthorityDomainId, Digest, EpochId, LifecycleNonce, LifecycleOrigin};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{
    CampaignId, CampaignIntentError, CampaignIntentV1, CampaignLabelError, WorkerRoleV1,
};
use crate::stage::{
    CampaignResidualV1, DocketStandingV1, EvidenceArtifactV1, EvidenceContractV1, FindingId,
    PathGrantV1, RepairProvenanceV1, StageBasisV1, StageId, StageKindV1, StageProposalError,
    StageProposalV1, StageReceiptV1, VerdictReceiptError, VerdictReceiptV1, VerdictV1,
};
use crate::transcript::transcript_digest;

/// Internal digest domain for standing-consumption records.
pub const STANDING_CONSUMPTION_DOMAIN_V1: &str = "ag.campaign.standing-consumption/v1";
/// Internal digest domain for recorded campaign refusals.
pub const REFUSAL_DOMAIN_V1: &str = "ag.campaign.refusal/v1";

#[derive(Serialize)]
struct ConsumptionTranscriptV1<'a> {
    campaign: &'a CampaignId,
    stage: &'a StageId,
    standing: &'a Digest,
}

/// Computes the exact consumption digest binding one standing burn to one
/// campaign and stage.
#[must_use]
pub fn consumption_digest(campaign: &CampaignId, stage: &StageId, standing: &Digest) -> Digest {
    transcript_digest(
        STANDING_CONSUMPTION_DOMAIN_V1,
        &ConsumptionTranscriptV1 {
            campaign,
            stage,
            standing,
        },
    )
}

/// The closed vocabulary of prohibited future-authority actions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateActionV1 {
    /// Candidate standing for the campaign.
    CandidateStanding,
    /// Qualification standing for the campaign.
    QualificationStanding,
    /// A campaign freeze marker.
    CampaignFreeze,
}

/// A recorded refusal of a prohibited future-authority action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateActionRefusalV1 {
    /// The refused action.
    pub action: CandidateActionV1,
    /// The exact refusal digest recorded in the ledger.
    pub refusal_digest: Digest,
}

/// A recorded campaign refusal. Refusals are evidence kept for exact
/// accounting; a refusal is not an escalation channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedRefusalV1 {
    /// Book-local refusal identifier.
    pub refusal_id: String,
    /// Bounded refusal statement.
    pub statement: String,
    /// Digest of the record this refusal answers.
    pub context: Digest,
}

impl RecordedRefusalV1 {
    /// Returns the exact refusal identity.
    #[must_use]
    pub fn id(&self) -> Digest {
        transcript_digest(REFUSAL_DOMAIN_V1, self)
    }
}

/// The live standing posture of one stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandingStateV1 {
    /// No standing has been recorded for the stage.
    Absent,
    /// Standing is admitted and not yet consumed.
    Unconsumed,
    /// Standing has been consumed exactly once.
    Consumed,
    /// Standing lapsed unconsumed past its expiry.
    Expired,
    /// Admission was refused and the refusal was recorded.
    Refused,
}

/// The candidate/freeze/qualification prohibition marker. There is exactly
/// one value: those actions are prohibited pending distinct future authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProhibitionV1 {
    /// Prohibited; requires distinct future authority that does not exist.
    ProhibitedPendingDistinctFutureAuthority,
}

/// The durable record of one exact standing consumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumptionRecordV1 {
    /// Consumed stage.
    pub stage: StageId,
    /// Consumed standing digest.
    pub standing_digest: Digest,
    /// Exact consumption digest.
    pub consumption_digest: Digest,
    /// Consumption time as a Unix timestamp in seconds.
    pub consumed_at_unix: u64,
}

/// The durable record of one runtime-envelope dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchRecordV1 {
    /// Dispatched stage.
    pub stage: StageId,
    /// Exact runtime envelope digest.
    pub envelope: Digest,
    /// Consumption digest the dispatch burned.
    pub consumption_digest: Digest,
    /// Exact allowed path grants rendered into the envelope.
    pub allowed_paths: Vec<PathGrantV1>,
}

/// The full lifecycle state of one proposed stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageStateV1 {
    proposal: StageProposalV1,
    admission: Option<DocketStandingV1>,
    standing_refused: bool,
    consumption: Option<ConsumptionRecordV1>,
    dispatch: Option<DispatchRecordV1>,
    receipt: Option<StageReceiptV1>,
    verdict: Option<VerdictReceiptV1>,
}

impl StageStateV1 {
    /// Returns the stage proposal.
    #[must_use]
    pub const fn proposal(&self) -> &StageProposalV1 {
        &self.proposal
    }

    /// Returns the recorded Docket standing, when admitted.
    #[must_use]
    pub const fn admission(&self) -> Option<&DocketStandingV1> {
        self.admission.as_ref()
    }

    /// Returns whether admission refusal was recorded.
    #[must_use]
    pub const fn standing_refused(&self) -> bool {
        self.standing_refused
    }

    /// Returns the standing consumption record, when consumed.
    #[must_use]
    pub const fn consumption(&self) -> Option<&ConsumptionRecordV1> {
        self.consumption.as_ref()
    }

    /// Returns the dispatch record, when dispatched.
    #[must_use]
    pub const fn dispatch(&self) -> Option<&DispatchRecordV1> {
        self.dispatch.as_ref()
    }

    /// Returns the worker execution receipt, when recorded.
    #[must_use]
    pub const fn receipt(&self) -> Option<&StageReceiptV1> {
        self.receipt.as_ref()
    }

    /// Returns the verdict this stage produced (review stage) or received
    /// (operator stage), when recorded.
    #[must_use]
    pub const fn verdict(&self) -> Option<&VerdictReceiptV1> {
        self.verdict.as_ref()
    }

    /// Returns whether the stage reached its terminal recorded state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.verdict.is_some()
    }
}

/// Every durable campaign transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignEventV1 {
    /// Genesis: the human-authorized intent created the campaign.
    CampaignCreated {
        /// The exact intent.
        intent: CampaignIntentV1,
        /// Derived campaign identity.
        campaign: CampaignId,
    },
    /// A stage was proposed (a request for Docket admission).
    StageProposed {
        /// The exact proposal.
        proposal: StageProposalV1,
    },
    /// Docket admission was recorded for a stage.
    StageAdmitted {
        /// Admitted stage.
        stage: StageId,
        /// The opaque standing record.
        standing: DocketStandingV1,
        /// Recording time as a Unix timestamp in seconds.
        recorded_at_unix: u64,
    },
    /// A Docket admission refusal was recorded for a stage.
    StandingRefused {
        /// Refused stage.
        stage: StageId,
        /// Digest of the refusal statement.
        statement: Digest,
    },
    /// Standing was consumed exactly once (burn before effect).
    StandingConsumed {
        /// Consumption record.
        consumption: ConsumptionRecordV1,
    },
    /// A runtime envelope was dispatched against a consumption.
    DispatchRecorded {
        /// Dispatch record.
        dispatch: DispatchRecordV1,
    },
    /// A worker execution receipt was recorded.
    StageReceiptRecorded {
        /// The exact receipt.
        receipt: StageReceiptV1,
    },
    /// A reviewer verdict receipt was recorded.
    VerdictRecorded {
        /// The exact verdict receipt.
        verdict: VerdictReceiptV1,
    },
    /// A bounded residual was recorded.
    ResidualRecorded {
        /// The residual.
        residual: CampaignResidualV1,
    },
    /// A refusal was recorded for exact accounting.
    RefusalRecorded {
        /// The refusal.
        refusal: RecordedRefusalV1,
    },
    /// A prohibited future-authority action was refused.
    CandidateActionRefused {
        /// The refused action.
        action: CandidateActionV1,
        /// Exact refusal digest.
        refusal_digest: Digest,
    },
    /// The campaign was halted with an exact reason digest.
    CampaignHalted {
        /// Digest of the halt reason/evidence.
        reason: Digest,
    },
    /// The campaign was resumed after the halt resolved.
    CampaignResumed,
}

/// A rejected campaign ledger transition.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LedgerErrorV1 {
    /// The intent is invalid.
    #[error("invalid campaign intent: {0}")]
    InvalidIntent(#[from] CampaignIntentError),
    /// A record failed shape validation.
    #[error("invalid campaign record: {0}")]
    InvalidRecord(#[from] CampaignLabelError),
    /// A stage proposal is invalid.
    #[error("invalid stage proposal: {0}")]
    InvalidProposal(#[from] StageProposalError),
    /// A verdict receipt is invalid.
    #[error("invalid verdict receipt: {0}")]
    InvalidVerdict(#[from] VerdictReceiptError),
    /// The event log does not begin with exactly one creation event.
    #[error("a campaign ledger must begin with exactly one creation event")]
    GenesisEvent,
    /// A record names a different campaign.
    #[error("record belongs to a different campaign")]
    CampaignMismatch,
    /// The stage is unknown to this campaign.
    #[error("unknown stage {stage}")]
    StageUnknown {
        /// The unknown stage.
        stage: StageId,
    },
    /// The stage was already proposed.
    #[error("stage {stage} is already proposed")]
    DuplicateStage {
        /// The duplicated stage.
        stage: StageId,
    },
    /// The stage sequence number is already used.
    #[error("stage sequence {sequence} is already used")]
    DuplicateStageSequence {
        /// The duplicated sequence.
        sequence: u64,
    },
    /// The campaign is halted.
    #[error("the campaign is halted")]
    Halted,
    /// The campaign is not halted.
    #[error("the campaign is not halted")]
    NotHalted,
    /// Resume is blocked by an in-flight consumed stage.
    #[error("resume is blocked: stage {stage} has a consumed standing without its terminal record")]
    ResumeBlocked {
        /// The in-flight stage.
        stage: StageId,
    },
    /// Standing names a different stage.
    #[error("standing names a different stage")]
    StandingStageMismatch,
    /// Standing is expired at the supplied time.
    #[error("standing is expired")]
    StandingExpired,
    /// The stage is already admitted.
    #[error("stage is already admitted")]
    AlreadyAdmitted,
    /// The stage is not admitted.
    #[error("stage has no admitted standing")]
    NotAdmitted,
    /// Admission refusal was already recorded for the stage.
    #[error("stage admission was already refused")]
    AlreadyRefused,
    /// The standing was already consumed.
    #[error("standing was already consumed")]
    AlreadyConsumed,
    /// The stage has no recorded consumption.
    #[error("no standing consumption is recorded for the stage")]
    ConsumptionMissing,
    /// A recorded consumption digest does not match the exact transcript.
    #[error("consumption digest does not match the exact standing consumption transcript")]
    ConsumptionDigestMismatch,
    /// The stage was already dispatched.
    #[error("stage was already dispatched")]
    AlreadyDispatched,
    /// The stage has no recorded dispatch.
    #[error("no envelope dispatch is recorded for the stage")]
    DispatchMissing,
    /// A receipt names a different envelope than the recorded dispatch.
    #[error("receipt envelope does not match the recorded dispatch")]
    EnvelopeMismatch,
    /// A receipt names a different standing than the recorded consumption.
    #[error("receipt standing does not match the recorded consumption")]
    StandingMismatch,
    /// A receipt presents a historical standing as current.
    #[error("historical standing presented as current standing")]
    HistoricalStandingAsCurrent,
    /// A receipt basis differs from the proposed exact basis.
    #[error("receipt basis differs from the proposed stage basis")]
    BasisMismatch,
    /// A receipt sequence differs from the proposed stage sequence.
    #[error("receipt stage sequence differs from the proposal")]
    StageSequenceMismatch,
    /// A verdict is already recorded for the subject stage.
    #[error("a verdict is already recorded for the subject stage")]
    VerdictAlreadyRecorded,
    /// A receipt is already recorded for the stage.
    #[error("a receipt is already recorded for the stage")]
    ReceiptAlreadyRecorded,
    /// A receipt or verdict role does not match the stage kind.
    #[error("role does not match the stage kind")]
    RoleMismatch,
    /// The reviewer principal is not the campaign's reviewer.
    #[error("verdict reviewer is not the campaign reviewer principal")]
    ReviewerIdentity,
    /// Receipt artifacts do not satisfy the stage evidence contract exactly.
    #[error("receipt artifacts do not satisfy the stage evidence contract")]
    EvidenceContractViolation,
    /// The verdict's subject stage has no recorded execution receipt.
    #[error("verdict subject stage has no recorded execution receipt")]
    SubjectNotExecuted,
    /// The verdict names a different subject receipt than recorded.
    #[error("verdict subject receipt digest does not match the recorded receipt")]
    SubjectReceiptMismatch,
    /// Reviewer output arrived after a later receipt mutated the repository.
    #[error("reviewer output after repository mutation")]
    ReviewAfterMutation,
    /// A repair cites a finding identity absent from the rejected verdict.
    #[error("repair cites an altered finding identity")]
    AlteredFindingIdentity,
    /// A repair cites an unknown or non-rejected review receipt.
    #[error("repair cites an unknown or non-rejected review receipt")]
    RejectedReviewUnknown,
    /// A review stage names an unknown subject stage.
    #[error("review stage names an unknown subject stage")]
    ReviewSubjectUnknown,
    /// A residual identifier is already recorded.
    #[error("residual identifier is already recorded")]
    DuplicateResidual,
    /// A duplicate refusal identifier is recorded.
    #[error("refusal identifier is already recorded")]
    DuplicateRefusal,
}

/// A point-in-time campaign status projection. Reading it has no effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignStatusV1 {
    /// Human authorization instrument identity.
    pub human_authorization: Digest,
    /// Campaign identity.
    pub campaign: CampaignId,
    /// The first non-terminal stage, when any.
    pub current_stage: Option<StageId>,
    /// The current stage's standing posture.
    pub current_standing: StandingStateV1,
    /// The current stage's role.
    pub worker_role: Option<WorkerRoleV1>,
    /// The current stage's exact basis.
    pub basis: Option<StageBasisV1>,
    /// Digests of all open residuals.
    pub open_residuals: Vec<Digest>,
    /// The most recent adjudication (verdict or refusal) digest.
    pub last_adjudication: Option<Digest>,
    /// The halt reason digest, when halted.
    pub halt_reason: Option<Digest>,
    /// The candidate/freeze/qualification prohibition marker.
    pub candidate_freeze_qualification: ProhibitionV1,
}

/// Token proving one standing consumption was recorded before dispatch.
///
/// Constructible only by [`CampaignLedgerV1::consume_standing`]. It is
/// process-local evidence flow, deliberately not serializable: the durable
/// record is the [`ConsumptionRecordV1`] event.
#[derive(Clone, Debug)]
pub struct ConsumedStandingV1 {
    campaign: CampaignId,
    consumption: ConsumptionRecordV1,
    expiry_unix: u64,
}

impl ConsumedStandingV1 {
    pub(crate) const fn new(
        campaign: CampaignId,
        consumption: ConsumptionRecordV1,
        expiry_unix: u64,
    ) -> Self {
        Self {
            campaign,
            consumption,
            expiry_unix,
        }
    }

    /// Returns the campaign identity.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignId {
        &self.campaign
    }

    /// Returns the consumed stage.
    #[must_use]
    pub const fn stage(&self) -> &StageId {
        &self.consumption.stage
    }

    /// Returns the consumed standing digest.
    #[must_use]
    pub const fn standing_digest(&self) -> &Digest {
        &self.consumption.standing_digest
    }

    /// Returns the exact consumption digest.
    #[must_use]
    pub const fn consumption_digest(&self) -> &Digest {
        &self.consumption.consumption_digest
    }

    /// Returns the standing expiry as a Unix timestamp in seconds.
    #[must_use]
    pub const fn expiry_unix(&self) -> u64 {
        self.expiry_unix
    }
}

fn campaign_origin(campaign: &CampaignId) -> LifecycleOrigin {
    let raw = campaign.as_digest().raw_bytes();
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&raw[..16]);
    LifecycleOrigin::new(
        AuthorityDomainId::new("ag.campaign")
            .expect("the campaign authority-domain label is canonical"),
        EpochId::new(1).expect("epoch one is nonzero"),
        LifecycleNonce::new(nonce),
    )
}

/// The campaign ledger: exact lifecycle state over recorded events.
#[derive(Clone, Debug)]
pub struct CampaignLedgerV1 {
    origin: LifecycleOrigin,
    campaign: CampaignId,
    intent: CampaignIntentV1,
    stages: BTreeMap<StageId, StageStateV1>,
    stage_order: Vec<StageId>,
    receipt_order: Vec<StageId>,
    residuals: Vec<CampaignResidualV1>,
    refusals: Vec<RecordedRefusalV1>,
    candidate_refusals: Vec<CandidateActionRefusalV1>,
    halted: Option<Digest>,
    events: Vec<CampaignEventV1>,
}

impl CampaignLedgerV1 {
    /// Creates a campaign from its human-authorized intent.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerErrorV1::InvalidIntent`] for an invalid intent.
    pub fn create(intent: CampaignIntentV1) -> Result<Self, LedgerErrorV1> {
        intent.validate()?;
        let campaign = intent.campaign_id();
        let mut ledger = Self {
            origin: campaign_origin(&campaign),
            campaign: campaign.clone(),
            intent: intent.clone(),
            stages: BTreeMap::new(),
            stage_order: Vec::new(),
            receipt_order: Vec::new(),
            residuals: Vec::new(),
            refusals: Vec::new(),
            candidate_refusals: Vec::new(),
            halted: None,
            events: Vec::new(),
        };
        ledger
            .events
            .push(CampaignEventV1::CampaignCreated { intent, campaign });
        Ok(ledger)
    }

    /// Replays an exact event sequence, re-applying every validation.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerErrorV1::GenesisEvent`] unless the first event is the
    /// creation event, and any transition error a tampered log triggers.
    pub fn from_events(events: Vec<CampaignEventV1>) -> Result<Self, LedgerErrorV1> {
        let mut events = events.into_iter();
        let Some(CampaignEventV1::CampaignCreated { intent, campaign }) = events.next() else {
            return Err(LedgerErrorV1::GenesisEvent);
        };
        if intent.campaign_id() != campaign {
            return Err(LedgerErrorV1::CampaignMismatch);
        }
        let mut ledger = Self::create(intent)?;
        for event in events {
            ledger.apply(event)?;
        }
        Ok(ledger)
    }

    /// Returns the campaign-scoped deterministic lifecycle origin.
    #[must_use]
    pub const fn origin(&self) -> &LifecycleOrigin {
        &self.origin
    }

    /// Returns the campaign identity.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignId {
        &self.campaign
    }

    /// Returns the human-authorized intent.
    #[must_use]
    pub const fn intent(&self) -> &CampaignIntentV1 {
        &self.intent
    }

    /// Returns the recorded event sequence.
    #[must_use]
    pub fn events(&self) -> &[CampaignEventV1] {
        &self.events
    }

    /// Returns the stage state, when the stage is known.
    #[must_use]
    pub fn stage(&self, stage: &StageId) -> Option<&StageStateV1> {
        self.stages.get(stage)
    }

    /// Returns every stage in proposal order.
    #[must_use]
    pub fn stage_order(&self) -> &[StageId] {
        &self.stage_order
    }

    /// Returns the open residuals. Residuals only accumulate here.
    #[must_use]
    pub fn residuals(&self) -> &[CampaignResidualV1] {
        &self.residuals
    }

    /// Returns the recorded refusals.
    #[must_use]
    pub fn refusals(&self) -> &[RecordedRefusalV1] {
        &self.refusals
    }

    /// Returns the recorded prohibited-action refusals.
    #[must_use]
    pub fn candidate_refusals(&self) -> &[CandidateActionRefusalV1] {
        &self.candidate_refusals
    }

    /// Returns the halt reason digest, when halted.
    #[must_use]
    pub const fn halted(&self) -> Option<&Digest> {
        self.halted.as_ref()
    }

    /// Proposes a stage: a request for Docket admission, never an admission.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LedgerErrorV1`] for a foreign campaign, an invalid or
    /// duplicate proposal, an unknown review subject, an unknown or altered
    /// repair citation, or a halted campaign.
    pub fn propose_stage(&mut self, proposal: StageProposalV1) -> Result<StageId, LedgerErrorV1> {
        let stage = proposal.id();
        self.apply(CampaignEventV1::StageProposed { proposal })?;
        Ok(stage)
    }

    /// Records Docket admission for a proposed stage. The standing digest is
    /// opaque: recorded, and later verified by equality only.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LedgerErrorV1`] for an unknown stage, a halted
    /// campaign, a foreign or mismatched standing, expiry, or double
    /// admission.
    pub fn admit_stage(
        &mut self,
        stage: &StageId,
        standing: DocketStandingV1,
        now_unix: u64,
    ) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::StageAdmitted {
            stage: stage.clone(),
            standing,
            recorded_at_unix: now_unix,
        })
    }

    /// Records a Docket admission refusal for a proposed stage.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LedgerErrorV1`] for an unknown stage or a stage
    /// already admitted or already refused.
    pub fn refuse_standing(
        &mut self,
        stage: &StageId,
        statement: Digest,
    ) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::StandingRefused {
            stage: stage.clone(),
            statement,
        })
    }

    /// Consumes a stage's standing exactly once and returns the dispatch
    /// token. This is the burn-before-effect boundary: only the returned
    /// [`ConsumedStandingV1`] can render a runtime envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LedgerErrorV1`] for an unadmitted, expired, or
    /// already-consumed stage, or a halted campaign.
    pub fn consume_standing(
        &mut self,
        stage: &StageId,
        now_unix: u64,
    ) -> Result<ConsumedStandingV1, LedgerErrorV1> {
        let entry = self
            .stages
            .get(stage)
            .ok_or_else(|| LedgerErrorV1::StageUnknown {
                stage: stage.clone(),
            })?;
        let admission = entry.admission().ok_or(LedgerErrorV1::NotAdmitted)?;
        let consumption = ConsumptionRecordV1 {
            stage: stage.clone(),
            standing_digest: admission.standing_digest.clone(),
            consumption_digest: consumption_digest(
                &self.campaign,
                stage,
                &admission.standing_digest,
            ),
            consumed_at_unix: now_unix,
        };
        let expiry = admission.expiry_unix;
        self.apply(CampaignEventV1::StandingConsumed {
            consumption: consumption.clone(),
        })?;
        Ok(ConsumedStandingV1::new(
            self.campaign.clone(),
            consumption,
            expiry,
        ))
    }

    /// Records the exact runtime-envelope dispatch burning one consumption.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LedgerErrorV1`] when the token does not name this
    /// stage's recorded consumption, or the stage was already dispatched.
    pub fn record_dispatch(
        &mut self,
        consumed: &ConsumedStandingV1,
        envelope: &Digest,
        allowed_paths: Vec<PathGrantV1>,
    ) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::DispatchRecorded {
            dispatch: DispatchRecordV1 {
                stage: consumed.stage().clone(),
                envelope: envelope.clone(),
                consumption_digest: consumed.consumption_digest().clone(),
                allowed_paths,
            },
        })
    }

    /// Records a worker execution receipt. This transitions only the named
    /// stage; it cannot admit any stage, including the next one.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LedgerErrorV1`] for burn-before-effect violations
    /// (no consumption, no dispatch), standing or envelope mismatches, a
    /// historical standing presented as current, basis or role mismatches, or
    /// evidence-contract violations.
    pub fn record_stage_receipt(&mut self, receipt: StageReceiptV1) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::StageReceiptRecorded { receipt })
    }

    /// Records a reviewer verdict receipt.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LedgerErrorV1`] for an unexecuted subject, an altered
    /// subject receipt identity, a foreign reviewer principal, or reviewer
    /// output after a later repository mutation.
    pub fn record_verdict(&mut self, verdict: VerdictReceiptV1) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::VerdictRecorded { verdict })
    }

    /// Records a bounded residual. Residuals only accumulate.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerErrorV1::DuplicateResidual`] for a repeated identifier
    /// and [`LedgerErrorV1::InvalidRecord`] for a noncanonical residual.
    pub fn record_residual(&mut self, residual: CampaignResidualV1) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::ResidualRecorded { residual })
    }

    /// Records a refusal for exact accounting.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerErrorV1::DuplicateRefusal`] for a repeated identifier.
    pub fn record_refusal(&mut self, refusal: RecordedRefusalV1) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::RefusalRecorded { refusal })
    }

    /// Refuses a prohibited future-authority action and records the refusal.
    /// There is no admission path: this always refuses.
    #[must_use]
    pub fn refuse_prohibited_action(
        &mut self,
        action: CandidateActionV1,
    ) -> CandidateActionRefusalV1 {
        #[derive(Serialize)]
        struct ProhibitedActionTranscriptV1<'a> {
            campaign: &'a CampaignId,
            action: CandidateActionV1,
            law: &'static str,
        }
        let refusal_digest = transcript_digest(
            REFUSAL_DOMAIN_V1,
            &ProhibitedActionTranscriptV1 {
                campaign: &self.campaign,
                action,
                law: "candidate, freeze, and qualification actions require distinct future authority",
            },
        );
        self.events.push(CampaignEventV1::CandidateActionRefused {
            action,
            refusal_digest: refusal_digest.clone(),
        });
        let refusal = CandidateActionRefusalV1 {
            action,
            refusal_digest,
        };
        self.candidate_refusals.push(refusal.clone());
        refusal
    }

    /// Halts the campaign with an exact reason digest.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerErrorV1::Halted`] when already halted.
    pub fn halt(&mut self, reason: Digest) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::CampaignHalted { reason })
    }

    /// Resumes a halted campaign once no consumed stage is missing its
    /// terminal record.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerErrorV1::NotHalted`] when running, or
    /// [`LedgerErrorV1::ResumeBlocked`] while a consumed stage lacks its
    /// terminal record.
    pub fn resume(&mut self) -> Result<(), LedgerErrorV1> {
        self.apply(CampaignEventV1::CampaignResumed)
    }

    /// Projects the point-in-time status. This read has no effect.
    #[must_use]
    pub fn status(&self, now_unix: u64) -> CampaignStatusV1 {
        let current = self
            .stage_order
            .iter()
            .find(|stage| !self.stages[*stage].is_terminal());
        let (current_standing, worker_role, basis) = match current {
            Some(stage) => {
                let entry = &self.stages[stage];
                (
                    Self::standing_state(entry, now_unix),
                    Some(entry.proposal().role()),
                    Some(entry.proposal().basis().clone()),
                )
            }
            None => (StandingStateV1::Absent, None, None),
        };
        CampaignStatusV1 {
            human_authorization: self.intent.human_authorization().clone(),
            campaign: self.campaign.clone(),
            current_stage: current.cloned(),
            current_standing,
            worker_role,
            basis,
            open_residuals: self.residuals.iter().map(CampaignResidualV1::id).collect(),
            last_adjudication: self.last_adjudication(),
            halt_reason: self.halted.clone(),
            candidate_freeze_qualification: ProhibitionV1::ProhibitedPendingDistinctFutureAuthority,
        }
    }

    fn standing_state(state: &StageStateV1, now_unix: u64) -> StandingStateV1 {
        if state.standing_refused() {
            return StandingStateV1::Refused;
        }
        let Some(admission) = state.admission() else {
            return StandingStateV1::Absent;
        };
        if state.consumption().is_some() {
            return StandingStateV1::Consumed;
        }
        if admission.expiry_unix <= now_unix {
            return StandingStateV1::Expired;
        }
        StandingStateV1::Unconsumed
    }

    fn last_adjudication(&self) -> Option<Digest> {
        for event in self.events.iter().rev() {
            match event {
                CampaignEventV1::VerdictRecorded { verdict } => return Some(verdict.id()),
                CampaignEventV1::RefusalRecorded { refusal } => return Some(refusal.id()),
                CampaignEventV1::CandidateActionRefused { refusal_digest, .. } => {
                    return Some(refusal_digest.clone());
                }
                _ => {}
            }
        }
        None
    }

    fn apply(&mut self, event: CampaignEventV1) -> Result<(), LedgerErrorV1> {
        match &event {
            CampaignEventV1::CampaignCreated { .. } => return Err(LedgerErrorV1::GenesisEvent),
            CampaignEventV1::StageProposed { proposal } => self.apply_proposal(proposal)?,
            CampaignEventV1::StageAdmitted {
                stage,
                standing,
                recorded_at_unix,
            } => self.apply_admission(stage, standing, *recorded_at_unix)?,
            CampaignEventV1::StandingRefused { stage, .. } => {
                let state = self.stage_mut(stage)?;
                if state.admission.is_some() {
                    return Err(LedgerErrorV1::AlreadyAdmitted);
                }
                if state.standing_refused {
                    return Err(LedgerErrorV1::AlreadyRefused);
                }
                state.standing_refused = true;
            }
            CampaignEventV1::StandingConsumed { consumption } => {
                self.apply_consumption(consumption)?;
            }
            CampaignEventV1::DispatchRecorded { dispatch } => self.apply_dispatch(dispatch)?,
            CampaignEventV1::StageReceiptRecorded { receipt } => self.apply_receipt(receipt)?,
            CampaignEventV1::VerdictRecorded { verdict } => self.apply_verdict(verdict)?,
            CampaignEventV1::ResidualRecorded { residual } => {
                residual.validate()?;
                if self
                    .residuals
                    .iter()
                    .any(|recorded| recorded.residual_id == residual.residual_id)
                {
                    return Err(LedgerErrorV1::DuplicateResidual);
                }
                self.residuals.push(residual.clone());
            }
            CampaignEventV1::RefusalRecorded { refusal } => {
                if self
                    .refusals
                    .iter()
                    .any(|recorded| recorded.refusal_id == refusal.refusal_id)
                {
                    return Err(LedgerErrorV1::DuplicateRefusal);
                }
                self.refusals.push(refusal.clone());
            }
            CampaignEventV1::CandidateActionRefused {
                action,
                refusal_digest,
            } => {
                self.candidate_refusals.push(CandidateActionRefusalV1 {
                    action: *action,
                    refusal_digest: refusal_digest.clone(),
                });
            }
            CampaignEventV1::CampaignHalted { reason } => {
                if self.halted.is_some() {
                    return Err(LedgerErrorV1::Halted);
                }
                self.halted = Some(reason.clone());
            }
            CampaignEventV1::CampaignResumed => {
                if self.halted.is_none() {
                    return Err(LedgerErrorV1::NotHalted);
                }
                for stage in &self.stage_order {
                    let state = &self.stages[stage];
                    let in_flight = match state.consumption() {
                        None => false,
                        Some(_) if state.is_terminal() => false,
                        Some(_) => match state.proposal().kind() {
                            StageKindV1::Operator(_) => state.receipt().is_none(),
                            StageKindV1::Review(_) => true,
                        },
                    };
                    if in_flight {
                        return Err(LedgerErrorV1::ResumeBlocked {
                            stage: stage.clone(),
                        });
                    }
                }
                self.halted = None;
            }
        }
        self.events.push(event);
        Ok(())
    }

    fn apply_proposal(&mut self, proposal: &StageProposalV1) -> Result<(), LedgerErrorV1> {
        self.require_running()?;
        proposal.validate()?;
        if proposal.campaign() != &self.campaign {
            return Err(LedgerErrorV1::CampaignMismatch);
        }
        let stage = proposal.id();
        if self.stages.contains_key(&stage) {
            return Err(LedgerErrorV1::DuplicateStage { stage });
        }
        if let StageKindV1::Review(scope) = proposal.kind()
            && !self.stages.contains_key(&scope.subject_stage)
        {
            return Err(LedgerErrorV1::ReviewSubjectUnknown);
        }
        if let Some(repair) = proposal.repair_provenance() {
            self.check_repair_provenance(repair)?;
        }
        self.stages.insert(
            stage.clone(),
            StageStateV1 {
                proposal: proposal.clone(),
                admission: None,
                standing_refused: false,
                consumption: None,
                dispatch: None,
                receipt: None,
                verdict: None,
            },
        );
        self.stage_order.push(stage);
        Ok(())
    }

    fn check_repair_provenance(&self, repair: &RepairProvenanceV1) -> Result<(), LedgerErrorV1> {
        let rejected = self.events.iter().find_map(|event| match event {
            CampaignEventV1::VerdictRecorded { verdict }
                if verdict.id() == repair.rejected_review =>
            {
                Some(verdict)
            }
            _ => None,
        });
        let Some(rejected) = rejected else {
            return Err(LedgerErrorV1::RejectedReviewUnknown);
        };
        if rejected.verdict() != VerdictV1::Reject {
            return Err(LedgerErrorV1::RejectedReviewUnknown);
        }
        let known: Vec<&FindingId> = rejected
            .findings()
            .iter()
            .map(|finding| &finding.finding_id)
            .collect();
        for cited in repair.finding_ids.iter() {
            if !known.contains(&cited) {
                return Err(LedgerErrorV1::AlteredFindingIdentity);
            }
        }
        Ok(())
    }

    fn apply_admission(
        &mut self,
        stage: &StageId,
        standing: &DocketStandingV1,
        now_unix: u64,
    ) -> Result<(), LedgerErrorV1> {
        self.require_running()?;
        standing.validate()?;
        if standing.stage != *stage {
            return Err(LedgerErrorV1::StandingStageMismatch);
        }
        if standing.expiry_unix <= now_unix {
            return Err(LedgerErrorV1::StandingExpired);
        }
        let entry = self.stage_mut(stage)?;
        if entry.admission.is_some() {
            return Err(LedgerErrorV1::AlreadyAdmitted);
        }
        if entry.standing_refused {
            return Err(LedgerErrorV1::AlreadyRefused);
        }
        entry.admission = Some(standing.clone());
        Ok(())
    }

    fn apply_consumption(
        &mut self,
        consumption: &ConsumptionRecordV1,
    ) -> Result<(), LedgerErrorV1> {
        self.require_running()?;
        let expected = consumption_digest(
            &self.campaign,
            &consumption.stage,
            &consumption.standing_digest,
        );
        let state = self.stage_mut(&consumption.stage)?;
        let Some(admission) = &state.admission else {
            return Err(LedgerErrorV1::NotAdmitted);
        };
        if admission.standing_digest != consumption.standing_digest {
            return Err(LedgerErrorV1::HistoricalStandingAsCurrent);
        }
        if expected != consumption.consumption_digest {
            return Err(LedgerErrorV1::ConsumptionDigestMismatch);
        }
        if admission.expiry_unix <= consumption.consumed_at_unix {
            return Err(LedgerErrorV1::StandingExpired);
        }
        if state.consumption.is_some() {
            return Err(LedgerErrorV1::AlreadyConsumed);
        }
        state.consumption = Some(consumption.clone());
        Ok(())
    }

    fn apply_dispatch(&mut self, dispatch: &DispatchRecordV1) -> Result<(), LedgerErrorV1> {
        self.require_running()?;
        for path in &dispatch.allowed_paths {
            path.validate()?;
        }
        let state = self.stage_mut(&dispatch.stage)?;
        let Some(consumption) = &state.consumption else {
            return Err(LedgerErrorV1::ConsumptionMissing);
        };
        if consumption.consumption_digest != dispatch.consumption_digest {
            return Err(LedgerErrorV1::ConsumptionDigestMismatch);
        }
        if state.dispatch.is_some() {
            return Err(LedgerErrorV1::AlreadyDispatched);
        }
        state.dispatch = Some(dispatch.clone());
        Ok(())
    }

    fn apply_receipt(&mut self, receipt: &StageReceiptV1) -> Result<(), LedgerErrorV1> {
        receipt.validate()?;
        if receipt.campaign != self.campaign {
            return Err(LedgerErrorV1::CampaignMismatch);
        }
        let stage = receipt.stage.clone();
        let entry = self.stage_mut(&stage)?;
        if entry.proposal.role() != receipt.role {
            return Err(LedgerErrorV1::RoleMismatch);
        }
        if receipt.stage_seq != entry.proposal.stage_seq() {
            return Err(LedgerErrorV1::StageSequenceMismatch);
        }
        if receipt.basis != *entry.proposal.basis() {
            return Err(LedgerErrorV1::BasisMismatch);
        }
        let Some(consumption) = &entry.consumption else {
            return Err(LedgerErrorV1::ConsumptionMissing);
        };
        if consumption.standing_digest != receipt.standing {
            let historical = self.stages.values().any(|other| {
                other
                    .admission
                    .as_ref()
                    .is_some_and(|admission| admission.standing_digest == receipt.standing)
            });
            return Err(if historical {
                LedgerErrorV1::HistoricalStandingAsCurrent
            } else {
                LedgerErrorV1::StandingMismatch
            });
        }
        let Some(dispatch) = &entry.dispatch else {
            return Err(LedgerErrorV1::DispatchMissing);
        };
        if dispatch.envelope != receipt.envelope {
            return Err(LedgerErrorV1::EnvelopeMismatch);
        }
        check_evidence_contract(entry.proposal.evidence(), &receipt.artifacts)?;
        if entry.receipt.is_some() {
            return Err(LedgerErrorV1::ReceiptAlreadyRecorded);
        }
        entry.receipt = Some(receipt.clone());
        self.receipt_order.push(stage);
        Ok(())
    }

    fn apply_verdict(&mut self, verdict: &VerdictReceiptV1) -> Result<(), LedgerErrorV1> {
        verdict.validate()?;
        if verdict.campaign() != &self.campaign {
            return Err(LedgerErrorV1::CampaignMismatch);
        }
        if verdict.reviewer() != self.intent.reviewer_principal() {
            return Err(LedgerErrorV1::ReviewerIdentity);
        }
        let review_stage = verdict.review_stage().clone();
        let subject_stage = verdict.subject_stage().clone();
        {
            let review_entry = self
                .stage(&review_stage)
                .ok_or(LedgerErrorV1::StageUnknown {
                    stage: review_stage.clone(),
                })?;
            if !matches!(review_entry.proposal().kind(), StageKindV1::Review(_)) {
                return Err(LedgerErrorV1::RoleMismatch);
            }
            if review_entry.consumption().is_none() {
                return Err(LedgerErrorV1::ConsumptionMissing);
            }
        }
        let (subject_receipt_id, subject_repository, subject_terminal) = {
            let subject_entry = self
                .stage(&subject_stage)
                .ok_or(LedgerErrorV1::StageUnknown {
                    stage: subject_stage.clone(),
                })?;
            match subject_entry.receipt() {
                None => return Err(LedgerErrorV1::SubjectNotExecuted),
                Some(receipt) => (
                    receipt.id(),
                    receipt.basis.repository.clone(),
                    subject_entry.is_terminal(),
                ),
            }
        };
        if subject_receipt_id != *verdict.subject_receipt() {
            return Err(LedgerErrorV1::SubjectReceiptMismatch);
        }
        if subject_terminal {
            return Err(LedgerErrorV1::VerdictAlreadyRecorded);
        }
        // Reviewer output after repository mutation: any receipt recorded
        // after the subject receipt on the same repository fences the review.
        let subject_position = self
            .receipt_order
            .iter()
            .position(|stage| stage == &subject_stage);
        for (position, stage) in self.receipt_order.iter().enumerate() {
            if Some(position) <= subject_position {
                continue;
            }
            if let Some(later_receipt) = self.stages[stage].receipt()
                && later_receipt.basis.repository == subject_repository
            {
                return Err(LedgerErrorV1::ReviewAfterMutation);
            }
        }
        if let Some(state) = self.stages.get_mut(&review_stage) {
            state.verdict = Some(verdict.clone());
        }
        if let Some(state) = self.stages.get_mut(&subject_stage) {
            state.verdict = Some(verdict.clone());
        }
        Ok(())
    }

    fn require_running(&self) -> Result<(), LedgerErrorV1> {
        if self.halted.is_some() {
            return Err(LedgerErrorV1::Halted);
        }
        Ok(())
    }

    fn stage_mut(&mut self, stage: &StageId) -> Result<&mut StageStateV1, LedgerErrorV1> {
        self.stages
            .get_mut(stage)
            .ok_or_else(|| LedgerErrorV1::StageUnknown {
                stage: stage.clone(),
            })
    }
}

/// Checks that produced artifacts satisfy the evidence contract exactly:
/// every required schema present exactly once, and no foreign artifacts.
pub(crate) fn check_evidence_contract(
    contract: &EvidenceContractV1,
    artifacts: &[EvidenceArtifactV1],
) -> Result<(), LedgerErrorV1> {
    for requirement in &contract.required {
        let matches = artifacts
            .iter()
            .filter(|artifact| artifact.schema == requirement.schema)
            .count();
        if matches != 1 {
            return Err(LedgerErrorV1::EvidenceContractViolation);
        }
    }
    for artifact in artifacts {
        if !contract
            .required
            .iter()
            .any(|requirement| requirement.schema == artifact.schema)
        {
            return Err(LedgerErrorV1::EvidenceContractViolation);
        }
    }
    Ok(())
}
