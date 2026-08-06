//! S-3: campaign recomposition wiring over `ag-kernel`'s `recompose()`.
//!
//! This module is an adapter, not a parallel engine. It translates exact
//! campaign records — stage receipts, standing consumptions, verdict
//! receipts, adjudications, residuals, refusals, and protected identities —
//! into [`BoundaryManifest`] requirements and [`BoundarySlice`] presentations,
//! delegates all boundary accounting to the kernel, and issues a durable
//! [`CampaignRecompositionReceiptV1`]. Campaign-law consistency (standing
//! without consumption, worker output without review, and the like) is
//! checked before the kernel call and refuses with typed
//! [`PlanRefusalV1`] failures.
//!
//! A rejected verdict is presented as an obstructed boundary unless an
//! accepted bounded repair cites its exact receipt digest; the repair loop is
//! itself a required boundary, so the rejection stays accounted.

use ag_kernel::{
    BoundaryManifest, BoundaryRequirement, BoundarySlice, NativeJudgment, NonEmpty, PathVerdict,
    RecompositionRefusal, recompose,
};
use ag_primitives::{Digest, LifecycleOrigin};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{CampaignId, WorkerRoleV1};
use crate::ledger::{CampaignLedgerV1, StageStateV1};
use crate::stage::{CampaignResidualV1, StageId, StageKindV1, VerdictV1};
use crate::transcript::transcript_digest;

/// Transcript digest domain for the campaign recomposition receipt.
pub const RECOMPOSITION_RECEIPT_DOMAIN_V1: &str = "ag.campaign.recomposition-receipt/v1";
/// Wire schema of the campaign recomposition receipt.
pub const RECOMPOSITION_RECEIPT_SCHEMA_V1: &str = "ag.campaign.recomposition-receipt/v1";
/// Internal digest domain for accounting transcripts and boundary identities.
pub const ACCOUNTING_DOMAIN_V1: &str = "ag.campaign.accounting/v1";

/// The closed vocabulary of accounted campaign records.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingKindV1 {
    /// The root human authorization instrument identity.
    RootHumanAuthorization,
    /// A proposed stage.
    StageProposal,
    /// A Docket admission of an operator stage.
    Admission,
    /// A one-use standing consumption.
    StandingConsumption,
    /// A worker execution receipt.
    WorkerExecutionReceipt,
    /// A verified sidecar handoff (the dispatched exact envelope).
    VerifiedHandoff,
    /// A Docket admission of a reviewer stage.
    ReviewAdmission,
    /// A reviewer verdict receipt.
    VerdictReceipt,
    /// The adjudication of one stage by its verdict.
    Adjudication,
    /// A bounded repair loop citation.
    RepairLoop,
    /// A recorded refusal.
    Refusal,
    /// A bounded residual.
    Residual,
    /// An external-action check (a prohibited-action refusal).
    ExternalActionCheck,
    /// A protected principal identity.
    ProtectedIdentity,
}

#[derive(Serialize)]
struct AccountingTranscriptV1<'a, T: Serialize> {
    kind: AccountingKindV1,
    record: &'a T,
}

#[derive(Serialize)]
struct BoundaryTranscriptV1<'a> {
    kind: AccountingKindV1,
    expected: &'a Digest,
}

fn accounting_digest<T: Serialize>(kind: AccountingKindV1, record: &T) -> Digest {
    transcript_digest(
        ACCOUNTING_DOMAIN_V1,
        &AccountingTranscriptV1 { kind, record },
    )
}

fn boundary_id(kind: AccountingKindV1, expected: &Digest) -> Digest {
    transcript_digest(
        ACCOUNTING_DOMAIN_V1,
        &BoundaryTranscriptV1 { kind, expected },
    )
}

/// One required recomposition boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredReceiptV1 {
    /// The accounted record kind.
    pub kind: AccountingKindV1,
    /// The stable boundary identity.
    pub boundary_id: Digest,
    /// The exact expected record digest.
    pub expected_digest: Digest,
}

/// The daemon-created accounting plan: all and only the required boundaries
/// of one campaign's recorded history, with the kernel manifest built from
/// exactly those requirements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignAccountingPlanV1 {
    /// Campaign identity.
    pub campaign: CampaignId,
    /// Campaign-scoped lifecycle origin.
    pub origin: LifecycleOrigin,
    /// Every required boundary; non-empty by construction.
    pub requirements: NonEmpty<RequiredReceiptV1>,
    /// The kernel boundary manifest over exactly these requirements.
    pub manifest: BoundaryManifest,
}

/// A campaign-law consistency failure detected before kernel accounting.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PlanRefusalV1 {
    /// Standing was admitted but never consumed.
    #[error("stage {stage} has admitted standing without consumption")]
    StandingWithoutConsumption {
        /// The incomplete stage.
        stage: StageId,
    },
    /// A consumption exists without an admitted stage.
    #[error("stage {stage} has a standing consumption without an admitted stage")]
    ConsumptionWithoutAdmission {
        /// The inconsistent stage.
        stage: StageId,
    },
    /// A worker receipt exists without a reviewer verdict.
    #[error("stage {stage} has worker output without review")]
    WorkerOutputWithoutReview {
        /// The unreviewed stage.
        stage: StageId,
    },
    /// A repair stage progressed without admitted repair standing.
    #[error("repair stage {stage} progressed without admitted repair standing")]
    RepairWithoutAdmittedStanding {
        /// The repair stage.
        stage: StageId,
    },
    /// A stage stopped between burn and terminal record.
    #[error("stage {stage} has an ambiguous incomplete effect")]
    AmbiguousIncompleteEffect {
        /// The ambiguous stage.
        stage: StageId,
    },
    /// A consumption names a different standing than the admission.
    #[error("stage {stage} presents a historical identity as current standing")]
    HistoricalStandingAsCurrent {
        /// The inconsistent stage.
        stage: StageId,
    },
    /// A dispatch rendered paths beyond the proposed scope.
    #[error("stage {stage} dispatched a broadened path scope")]
    BroadenedPathScope {
        /// The broadened stage.
        stage: StageId,
    },
    /// A proposed stage reached neither admission nor recorded refusal.
    #[error("stage {stage} was proposed but reached neither admission nor recorded refusal")]
    AdmissionUndecided {
        /// The undecided stage.
        stage: StageId,
    },
}

/// A family-native obstruction carried by a presented campaign slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignObstructionV1 {
    /// The obstructed record kind.
    pub kind: AccountingKindV1,
    /// Bounded obstruction statement.
    pub detail: String,
}

/// The lossless recomposition refusal: the kernel's accounting failures over
/// campaign obstructions.
pub type CampaignRecompositionRefusalV1 = RecompositionRefusal<CampaignObstructionV1>;

/// One presented campaign receipt for recomposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentedReceiptV1 {
    /// The boundary this receipt claims.
    pub boundary_id: Digest,
    /// The exact presented record digest.
    pub receipt_digest: Digest,
    /// The boundary obstruction verdict; clean means exactly no obstructions.
    pub verdict: PathVerdict<CampaignObstructionV1>,
}

impl PresentedReceiptV1 {
    /// Presents a clean receipt for one required boundary.
    #[must_use]
    pub fn clean(required: &RequiredReceiptV1) -> Self {
        Self {
            boundary_id: required.boundary_id.clone(),
            receipt_digest: required.expected_digest.clone(),
            verdict: PathVerdict::clean(),
        }
    }
}

fn push_requirement(
    requirements: &mut Vec<RequiredReceiptV1>,
    kind: AccountingKindV1,
    expected: Digest,
) {
    let boundary_id = boundary_id(kind, &expected);
    // A bit-identical record (same kind, same exact digest) is one accounted
    // fact; recording it twice under two local names must not fork the
    // manifest.
    if requirements
        .iter()
        .any(|required| required.boundary_id == boundary_id)
    {
        return;
    }
    requirements.push(RequiredReceiptV1 {
        kind,
        boundary_id,
        expected_digest: expected,
    });
}

/// Builds the exact accounting plan from the recorded campaign history,
/// refusing on any campaign-law inconsistency.
///
/// # Errors
///
/// Returns a typed [`PlanRefusalV1`] for standing without consumption,
/// consumption without admitted stage, worker output without review, repair
/// progression without admitted repair standing, ambiguous incomplete
/// effects, historical standing presented as current, broadened dispatch
/// scope, or a proposed stage with neither admission nor recorded refusal.
///
/// # Panics
///
/// Panics only if the internally constructed requirement set is empty or
/// carries duplicate boundary identities; both are excluded by construction
/// (the root authorization and protected-identity boundaries are always
/// present, and requirements are deduplicated by boundary identity).
#[allow(clippy::too_many_lines)]
pub fn plan_from_ledger(
    ledger: &CampaignLedgerV1,
) -> Result<CampaignAccountingPlanV1, PlanRefusalV1> {
    let mut requirements = Vec::new();

    push_requirement(
        &mut requirements,
        AccountingKindV1::RootHumanAuthorization,
        accounting_digest(
            AccountingKindV1::RootHumanAuthorization,
            ledger.intent().human_authorization(),
        ),
    );
    for (role, principal) in [
        ("human_authorization", ledger.intent().human_authorization()),
        ("operator", ledger.intent().operator_principal()),
        ("reviewer", ledger.intent().reviewer_principal()),
    ] {
        push_requirement(
            &mut requirements,
            AccountingKindV1::ProtectedIdentity,
            accounting_digest(AccountingKindV1::ProtectedIdentity, &(role, principal)),
        );
    }

    for stage in ledger.stage_order() {
        let state = ledger
            .stage(stage)
            .ok_or(PlanRefusalV1::AmbiguousIncompleteEffect {
                stage: stage.clone(),
            })?;
        plan_stage(&mut requirements, state)?;
    }

    for refusal in ledger.refusals() {
        push_requirement(
            &mut requirements,
            AccountingKindV1::Refusal,
            accounting_digest(AccountingKindV1::Refusal, refusal),
        );
    }
    for check in ledger.candidate_refusals() {
        push_requirement(
            &mut requirements,
            AccountingKindV1::ExternalActionCheck,
            accounting_digest(AccountingKindV1::ExternalActionCheck, check),
        );
    }
    for residual in ledger.residuals() {
        push_requirement(
            &mut requirements,
            AccountingKindV1::Residual,
            accounting_digest(AccountingKindV1::Residual, residual),
        );
    }

    let requirements = NonEmpty::from_vec(requirements).expect(
        "a plan always contains the root human authorization and protected identity boundaries",
    );
    let manifest_requirements = requirements
        .iter()
        .map(|required| {
            BoundaryRequirement::new(
                required.boundary_id.clone(),
                required.expected_digest.clone(),
            )
        })
        .collect();
    let manifest = BoundaryManifest::new(
        ledger.origin().clone(),
        ledger.campaign().as_digest().clone(),
        manifest_requirements,
    )
    .expect("plan requirements are non-empty with deduplicated boundary identities");
    Ok(CampaignAccountingPlanV1 {
        campaign: ledger.campaign().clone(),
        origin: ledger.origin().clone(),
        requirements,
        manifest,
    })
}

fn plan_stage(
    requirements: &mut Vec<RequiredReceiptV1>,
    state: &StageStateV1,
) -> Result<(), PlanRefusalV1> {
    let proposal = state.proposal();
    let stage_id = proposal.id();
    push_requirement(
        requirements,
        AccountingKindV1::StageProposal,
        accounting_digest(AccountingKindV1::StageProposal, proposal),
    );
    if let Some(repair) = proposal.repair_provenance() {
        push_requirement(
            requirements,
            AccountingKindV1::RepairLoop,
            accounting_digest(AccountingKindV1::RepairLoop, repair),
        );
    }

    let Some(admission) = state.admission() else {
        if state.standing_refused() {
            return Ok(());
        }
        return if proposal.repair_provenance().is_some() {
            Err(PlanRefusalV1::RepairWithoutAdmittedStanding { stage: stage_id })
        } else {
            Err(PlanRefusalV1::AdmissionUndecided { stage: stage_id })
        };
    };
    let admission_kind = match proposal.role() {
        WorkerRoleV1::Operator => AccountingKindV1::Admission,
        WorkerRoleV1::Reviewer => AccountingKindV1::ReviewAdmission,
    };
    push_requirement(
        requirements,
        admission_kind,
        accounting_digest(admission_kind, admission),
    );

    let Some(consumption) = state.consumption() else {
        return Err(PlanRefusalV1::StandingWithoutConsumption { stage: stage_id });
    };
    if consumption.standing_digest != admission.standing_digest {
        return Err(PlanRefusalV1::HistoricalStandingAsCurrent { stage: stage_id });
    }
    push_requirement(
        requirements,
        AccountingKindV1::StandingConsumption,
        accounting_digest(AccountingKindV1::StandingConsumption, consumption),
    );

    if proposal.repair_provenance().is_some()
        && state.admission().is_none()
        && state.consumption().is_some()
    {
        return Err(PlanRefusalV1::RepairWithoutAdmittedStanding { stage: stage_id });
    }

    match proposal.kind() {
        StageKindV1::Operator(scope) => {
            let Some(dispatch) = state.dispatch() else {
                return Err(PlanRefusalV1::AmbiguousIncompleteEffect { stage: stage_id });
            };
            if dispatch.allowed_paths != scope.grants {
                return Err(PlanRefusalV1::BroadenedPathScope { stage: stage_id });
            }
            push_requirement(
                requirements,
                AccountingKindV1::VerifiedHandoff,
                accounting_digest(AccountingKindV1::VerifiedHandoff, dispatch),
            );
            let Some(receipt) = state.receipt() else {
                return Err(PlanRefusalV1::AmbiguousIncompleteEffect { stage: stage_id });
            };
            push_requirement(
                requirements,
                AccountingKindV1::WorkerExecutionReceipt,
                accounting_digest(AccountingKindV1::WorkerExecutionReceipt, receipt),
            );
            if state.verdict().is_none() {
                return Err(PlanRefusalV1::WorkerOutputWithoutReview { stage: stage_id });
            }
        }
        StageKindV1::Review(_) => {
            let Some(verdict) = state.verdict() else {
                return Err(PlanRefusalV1::AmbiguousIncompleteEffect { stage: stage_id });
            };
            push_requirement(
                requirements,
                AccountingKindV1::VerdictReceipt,
                accounting_digest(AccountingKindV1::VerdictReceipt, verdict),
            );
            push_requirement(
                requirements,
                AccountingKindV1::Adjudication,
                accounting_digest(
                    AccountingKindV1::Adjudication,
                    &(verdict.subject_stage(), verdict.id(), verdict.verdict()),
                ),
            );
        }
    }
    Ok(())
}

/// Derives the presented receipts from the recorded history: exactly one
/// presentation per recorded artifact, with rejected verdicts obstructed
/// unless an accepted bounded repair cites them.
#[must_use]
pub fn present_from_ledger(ledger: &CampaignLedgerV1) -> Vec<PresentedReceiptV1> {
    let mut presented = Vec::new();
    let Ok(plan) = plan_from_ledger(ledger) else {
        return presented;
    };
    let accepted_repairs: Vec<Digest> = ledger
        .stage_order()
        .iter()
        .filter_map(|stage| {
            let state = ledger.stage(stage)?;
            let repair = state.proposal().repair_provenance()?;
            let verdict = state.verdict()?;
            (verdict.verdict() == VerdictV1::Accept).then(|| repair.rejected_review.clone())
        })
        .collect();
    for requirement in plan.requirements.iter() {
        let mut receipt = PresentedReceiptV1::clean(requirement);
        if requirement.kind == AccountingKindV1::VerdictReceipt {
            for stage in ledger.stage_order() {
                let Some(state) = ledger.stage(stage) else {
                    continue;
                };
                let Some(verdict) = state.verdict() else {
                    continue;
                };
                if !matches!(state.proposal().kind(), StageKindV1::Review(_)) {
                    continue;
                }
                let expected = accounting_digest(AccountingKindV1::VerdictReceipt, verdict);
                if expected == requirement.expected_digest
                    && verdict.verdict() == VerdictV1::Reject
                    && !accepted_repairs.contains(&verdict.id())
                {
                    receipt.verdict = PathVerdict::obstructed(
                        verdict.id(),
                        CampaignObstructionV1 {
                            kind: AccountingKindV1::VerdictReceipt,
                            detail: "rejected verdict without an accepted bounded repair"
                                .to_owned(),
                        },
                    );
                }
            }
        }
        presented.push(receipt);
    }
    presented
}

/// The independent campaign dispositions. No flag implies another; in
/// particular an accepted slice is not campaign discharge, and candidate and
/// qualification standing are pinned to `false` pending distinct future
/// authority. The seven independent flags are the required vocabulary;
/// collapsing them into an enum would encode exactly the implications this
/// type exists to refuse.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDispositionsV1 {
    /// Every proposed operator stage has a recorded execution receipt.
    pub operational_execution_completed: bool,
    /// Every executed operator stage was accepted by review.
    pub review_accepted: bool,
    /// The kernel recomposed the exact presented slices.
    pub slice_accepted: bool,
    /// Every proposed stage reached its terminal record and the campaign is
    /// not halted.
    pub campaign_completed: bool,
    /// The campaign completed with no open residuals.
    pub campaign_discharged: bool,
    /// Always `false`: requires distinct future authority.
    pub candidate_standing: bool,
    /// Always `false`: requires distinct future authority.
    pub qualification_standing: bool,
}

/// The durable campaign recomposition receipt. Evidence, not authority: it
/// changes no standing and discharges nothing by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRecompositionReceiptV1 {
    schema: String,
    campaign: CampaignId,
    origin: LifecycleOrigin,
    manifest_digest: Digest,
    accounted_boundaries: u64,
    dispositions: CampaignDispositionsV1,
    open_residuals: Vec<Digest>,
}

impl CampaignRecompositionReceiptV1 {
    /// Returns the exact receipt identity.
    #[must_use]
    pub fn id(&self) -> Digest {
        transcript_digest(RECOMPOSITION_RECEIPT_DOMAIN_V1, self)
    }

    /// Returns the exact wire schema.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the campaign identity.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignId {
        &self.campaign
    }

    /// Returns the campaign-scoped lifecycle origin.
    #[must_use]
    pub const fn origin(&self) -> &LifecycleOrigin {
        &self.origin
    }

    /// Returns the digest of the exact kernel boundary manifest.
    #[must_use]
    pub const fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    /// Returns the number of accounted boundaries.
    #[must_use]
    pub const fn accounted_boundaries(&self) -> u64 {
        self.accounted_boundaries
    }

    /// Returns the independent dispositions.
    #[must_use]
    pub const fn dispositions(&self) -> &CampaignDispositionsV1 {
        &self.dispositions
    }

    /// Returns the open residual digests carried by this receipt.
    #[must_use]
    pub fn open_residuals(&self) -> &[Digest] {
        &self.open_residuals
    }
}

fn dispositions(ledger: &CampaignLedgerV1, slice_accepted: bool) -> CampaignDispositionsV1 {
    let mut operator_stages = 0_u64;
    let mut executed = true;
    let mut accepted = true;
    let mut all_terminal = !ledger.stage_order().is_empty() && ledger.halted().is_none();
    for stage in ledger.stage_order() {
        let Some(state) = ledger.stage(stage) else {
            all_terminal = false;
            continue;
        };
        if !state.is_terminal() {
            all_terminal = false;
        }
        if matches!(state.proposal().kind(), StageKindV1::Operator(_)) {
            operator_stages += 1;
            if state.receipt().is_none() {
                executed = false;
            }
            match state.verdict() {
                Some(verdict) if verdict.verdict() == VerdictV1::Accept => {}
                _ => accepted = false,
            }
        }
    }
    let campaign_completed = all_terminal;
    CampaignDispositionsV1 {
        operational_execution_completed: operator_stages > 0 && executed,
        review_accepted: operator_stages > 0 && executed && accepted,
        slice_accepted,
        campaign_completed,
        campaign_discharged: campaign_completed && ledger.residuals().is_empty(),
        candidate_standing: false,
        qualification_standing: false,
    }
}

/// Recomposes one campaign: translates the plan and presented receipts into
/// kernel boundary accounting and issues the durable receipt on admission.
///
/// The returned judgment is total: admission carries the receipt, refusal
/// carries the kernel's lossless failures (missing, duplicated, unaccounted,
/// foreign-origin, rewritten, or obstructed boundaries).
#[must_use]
pub fn recompose_campaign(
    plan: &CampaignAccountingPlanV1,
    presented: &[PresentedReceiptV1],
    ledger: &CampaignLedgerV1,
) -> NativeJudgment<CampaignRecompositionReceiptV1, CampaignRecompositionRefusalV1> {
    let slices: Vec<BoundarySlice<CampaignObstructionV1>> = presented
        .iter()
        .map(|receipt| {
            BoundarySlice::new(
                plan.origin.clone(),
                receipt.boundary_id.clone(),
                receipt.receipt_digest.clone(),
                receipt.verdict.clone(),
            )
        })
        .collect();
    match recompose(&plan.manifest, &slices) {
        NativeJudgment::Admit(witness) => {
            let accounted = witness.boundaries().len();
            NativeJudgment::Admit(CampaignRecompositionReceiptV1 {
                schema: RECOMPOSITION_RECEIPT_SCHEMA_V1.to_owned(),
                campaign: plan.campaign.clone(),
                origin: plan.origin.clone(),
                manifest_digest: transcript_digest(ACCOUNTING_DOMAIN_V1, &plan.manifest),
                accounted_boundaries: u64::try_from(accounted).unwrap_or(u64::MAX),
                dispositions: dispositions(ledger, true),
                open_residuals: ledger
                    .residuals()
                    .iter()
                    .map(CampaignResidualV1::id)
                    .collect(),
            })
        }
        NativeJudgment::Refuse(refusal) => NativeJudgment::Refuse(refusal),
    }
}
