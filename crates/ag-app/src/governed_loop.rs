#![allow(
    clippy::missing_errors_doc,
    reason = "CampaignEngineErrorV1 is the closed error contract for the production service"
)]
#![allow(
    clippy::wildcard_imports,
    reason = "this composition module intentionally consumes the governed kernel's complete vocabulary"
)]
#![allow(
    clippy::items_after_statements,
    reason = "small transcript-only record types stay adjacent to the decision that uses them"
)]
#![allow(
    clippy::large_enum_variant,
    reason = "recovery returns the exact authoritative snapshot by value"
)]
#![allow(
    clippy::needless_pass_by_value,
    reason = "human disposition inputs are accepted as owned one-use records"
)]

//! Production orchestration service for the canonical AG governed loop.
//!
//! The service composes the pure kernel, authoritative `SQLite` store, fresh
//! observation/standing/admission boundaries, and Docket's custody port.  It
//! never performs physical effect mechanics and never accepts executor output
//! as a campaign transition.

use std::collections::BTreeMap;
use std::path::Path;

use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use ag_store::campaign::{
    CampaignCommitReceiptV1, CampaignReplayReportV1, CampaignStoreErrorV1, CampaignStoreV1,
    CampaignTransitionKindV1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Root-owned exact-work catalog schema.
pub const EXACT_WORK_CATALOG_SCHEMA_V1: &str = "ag.governed-loop.exact-work-catalog/v1";

/// One exact admissibility catalog entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWorkCatalogEntryV1 {
    /// Exact typed work schema.
    pub work_schema: String,
    /// Exact governed subject.
    pub subject: Digest,
    /// Exact governed scope.
    pub scope: Digest,
}

/// Root-owned exact admissibility policy basis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWorkCatalogV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact versioned policy identity.
    pub policy_basis: Digest,
    /// Entries keyed by typed work schema.
    pub entries: BTreeMap<String, ExactWorkCatalogEntryV1>,
}

impl ExactWorkCatalogV1 {
    /// Validates exact key/entry agreement and nonempty policy.
    pub fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if self.schema != EXACT_WORK_CATALOG_SCHEMA_V1 || self.entries.is_empty() {
            return Err(CampaignEngineErrorV1::InvalidCatalog);
        }
        if self
            .entries
            .iter()
            .any(|(key, entry)| key != &entry.work_schema || key.is_empty())
        {
            return Err(CampaignEngineErrorV1::InvalidCatalog);
        }
        Ok(())
    }

    /// Returns the exact catalog transcript digest.
    pub fn digest(&self) -> Result<Digest, CampaignEngineErrorV1> {
        self.validate()?;
        let bytes = JcsDocument::canonicalize(self)
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        Ok(Digest::hash_domain(
            "ag.governed-loop.exact-work-catalog/v1",
            bytes.as_bytes(),
        ))
    }
}

/// AG-owned exact catalog admission policy.
pub struct CatalogAdmissibilityDeciderV1<'a> {
    catalog: &'a ExactWorkCatalogV1,
}

impl<'a> CatalogAdmissibilityDeciderV1<'a> {
    /// Binds one consequence-time decision pass to an exact catalog.
    pub fn new(catalog: &'a ExactWorkCatalogV1) -> Result<Self, CampaignEngineErrorV1> {
        catalog.validate()?;
        Ok(Self { catalog })
    }
}

impl AdmissibilityDeciderV1 for CatalogAdmissibilityDeciderV1<'_> {
    fn decide_admissibility(
        &mut self,
        request: &AdmissibilityRequestV1<'_>,
    ) -> Result<AdmissionDecisionV1, ExternalBoundaryErrorV1> {
        let admitted = self
            .catalog
            .entries
            .get(request.proposal.work_schema())
            .is_some_and(|entry| {
                entry.subject == *request.proposal.subject()
                    && entry.scope == *request.proposal.scope()
            });
        #[derive(Serialize)]
        struct DecisionBasis<'a> {
            key: &'a OccurrenceKeyV1,
            observation: &'a ObservationRefV1,
            proposal: &'a ProposalRefV1,
            standing: &'a StandingResolutionRefV1,
            policy: &'a Digest,
            admitted: bool,
        }
        let basis = DecisionBasis {
            key: &request.standing.key,
            observation: &request.observation.observation,
            proposal: &request.standing.proposal,
            standing: &request.standing.resolution,
            policy: &self.catalog.policy_basis,
            admitted,
        };
        let bytes = JcsDocument::canonicalize(&basis).map_err(|error| {
            ExternalBoundaryErrorV1::Unavailable {
                code: format!("admission-canonicalization:{error}"),
            }
        })?;
        Ok(AdmissionDecisionV1 {
            decision: AdmissionDecisionRefV1::from_digest(Digest::hash_domain(
                "ag.governed-loop.catalog-admission/v1",
                bytes.as_bytes(),
            )),
            key: request.standing.key.clone(),
            observation: request.observation.observation.clone(),
            proposal: request.standing.proposal.clone(),
            standing_resolution: request.standing.resolution.clone(),
            disposition: if admitted {
                AdmissionDispositionV1::Admitted
            } else {
                AdmissionDispositionV1::Refused
            },
            policy_basis: self.catalog.policy_basis.clone(),
        })
    }
}

/// Exact result of polling/reconciling Docket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DocketProgressV1 {
    /// Custody exists but no exact outcome is yet available.
    Pending,
    /// Known settlement was consumed by AG.
    Settled(OccurrenceSnapshotV1),
    /// Exact indeterminate attempt entered/stayed in reconciliation.
    ReconciliationRequired(OccurrenceSnapshotV1),
}

/// Exact restart/recovery result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "record", rename_all = "snake_case")]
pub enum CampaignRecoveryV1 {
    /// No state transition; the named fresh boundary is required.
    ExternalRevalidation(RecoveryRequirementV1),
    /// Spent issuance is authoritatively absent at Docket and may be submitted
    /// again as the same issuance, never respent.
    IssuanceNotAccepted(AgIssuanceV1),
    /// Recovery committed one or more exact transitions.
    Advanced(OccurrenceSnapshotV1),
}

/// Production governed-loop orchestration errors.
#[derive(Debug, Error)]
pub enum CampaignEngineErrorV1 {
    /// Transactional store failure.
    #[error(transparent)]
    Store(#[from] CampaignStoreErrorV1),
    /// Pure kernel refusal.
    #[error(transparent)]
    Kernel(#[from] KernelErrorV1),
    /// External boundary failure.
    #[error(transparent)]
    External(#[from] ExternalBoundaryErrorV1),
    /// Exact-work catalog is malformed.
    #[error("invalid exact-work catalog")]
    InvalidCatalog,
    /// Canonical encoding failed.
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
    /// Docket returned a state that is impossible at this boundary.
    #[error("Docket custody/reconciliation response is not applicable")]
    DocketResponse,
}

/// One production-reachable canonical campaign engine.
pub struct CampaignEngineV1 {
    store: CampaignStoreV1,
}

impl CampaignEngineV1 {
    /// Creates one campaign with one authority-empty occurrence.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        database: &Path,
        campaign: CampaignId,
        occurrence: OccurrenceId,
        program: ProgramBasisRefV1,
        residuals: ResidualSetV1,
        budget: LoopBudgetV1,
        now_unix_ms: u64,
    ) -> Result<Self, CampaignEngineErrorV1> {
        let initial =
            GovernedLoopKernelV1::create_initial(campaign, occurrence, program, residuals, budget)?;
        let store = CampaignStoreV1::create(database, &initial, now_unix_ms)?;
        Ok(Self { store })
    }

    /// Opens an existing campaign without reconstructing freshness or authority.
    pub fn open(database: &Path) -> Result<Self, CampaignEngineErrorV1> {
        Ok(Self {
            store: CampaignStoreV1::open(database)?,
        })
    }

    /// Returns the exact authoritative current occurrence.
    pub fn current(&self) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        Ok(self.store.current()?)
    }

    /// Runs deterministic store replay and accounting verification.
    pub fn replay(&self) -> Result<CampaignReplayReportV1, CampaignEngineErrorV1> {
        Ok(self.store.replay()?)
    }

    /// Records a fresh observation plus exact proposal.
    #[allow(clippy::too_many_arguments)]
    pub fn record_proposal<O: ObservationResolverV1>(
        &mut self,
        observation: ObservationRefV1,
        proposal: ExactWorkProposalV1,
        class: ProposalClassV1,
        resolver: &mut O,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = match GovernedLoopKernelV1::record_proposal(
            &current,
            observation,
            proposal,
            class,
            resolver,
            now_unix_ms,
        ) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("retry")) => {
                return self.halt_for_exhausted_budget(&current, "retry", now_unix_ms);
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::ProposalRecorded,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Enters the explicit standing-required state.
    pub fn require_standing(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = GovernedLoopKernelV1::require_standing(&current)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::StandingRequired,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Resolves observation/current standing and records a positive AG decision.
    #[allow(clippy::too_many_arguments)]
    pub fn decide<O, S>(
        &mut self,
        observation: &mut O,
        standing: &mut S,
        catalog: &ExactWorkCatalogV1,
        controlling_review: Option<&C1RejectedReviewBasisV1>,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1>
    where
        O: ObservationResolverV1,
        S: StandingResolverV1,
    {
        let current = self.store.current()?;
        let mut decider = CatalogAdmissibilityDeciderV1::new(catalog)?;
        let successor = GovernedLoopKernelV1::record_admissible(
            &current,
            observation,
            standing,
            &mut decider,
            controlling_review,
            now_unix_ms,
        )?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Admissible,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Re-resolves all current premises and durably spends the one AG authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize<O, S>(
        &mut self,
        observation: &mut O,
        standing: &mut S,
        catalog: &ExactWorkCatalogV1,
        controlling_review: Option<&C1RejectedReviewBasisV1>,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1>
    where
        O: ObservationResolverV1,
        S: StandingResolverV1,
    {
        let current = self.store.current()?;
        let mut decider = CatalogAdmissibilityDeciderV1::new(catalog)?;
        let successor = GovernedLoopKernelV1::consume_authorization(
            &current,
            observation,
            standing,
            &mut decider,
            controlling_review,
            now_unix_ms,
        )?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::AuthorizationConsumed,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Delegates the exact durable issuance to Docket and records its custody.
    pub fn dispatch<D: DocketCustodyPortV1>(
        &mut self,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        if current.program_counter() != ProgramCounterV1::AuthorizationConsumed {
            return Err(KernelErrorV1::IllegalTransition {
                from: current.program_counter(),
                operation: "dispatch",
            }
            .into());
        }
        let issuance = current
            .issuance()
            .cloned()
            .ok_or(CampaignEngineErrorV1::DocketResponse)?;
        let custody = docket.accept_issuance(&issuance)?;
        let successor = GovernedLoopKernelV1::accept_docket_custody(&current, custody)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Polls Docket read-only and consumes only exact custody/settlement evidence.
    pub fn poll_docket<D: DocketCustodyPortV1>(
        &mut self,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let custody = current
            .docket_custody()
            .cloned()
            .ok_or(CampaignEngineErrorV1::DocketResponse)?;
        let response = docket.reconcile_attempt(&custody)?;
        self.apply_docket_progress(&current, response, now_unix_ms)
    }

    /// Opens a distinct authority-empty continuation after settlement.
    pub fn open_continuation(
        &mut self,
        occurrence: OccurrenceId,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = GovernedLoopKernelV1::open_continuation(&current, occurrence)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::ContinuationOpened,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Records one read-only probe budget fact; probe mechanics stay external.
    pub fn note_probe(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = match GovernedLoopKernelV1::note_probe(&current) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("probe")) => {
                return self.halt_for_exhausted_budget(&current, "probe", now_unix_ms);
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::ProbeNoted,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Safely halts from a non-effecting boundary.
    pub fn halt(
        &mut self,
        reason: HaltReasonRefV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = GovernedLoopKernelV1::halt(&current, reason)?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Halted,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Records one bounded escalation and halts.
    pub fn escalate(
        &mut self,
        reason: HaltReasonRefV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = match GovernedLoopKernelV1::escalate(&current, reason) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("escalation")) => {
                return self.halt_for_exhausted_budget(&current, "escalation", now_unix_ms);
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Escalated,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Applies one externally verified human disposition transactionally.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_human_disposition<O, H>(
        &mut self,
        artifact: HumanDispositionV1,
        expected_scope: &HumanAuthorityScopeV1,
        new_occurrence: Option<OccurrenceId>,
        observation: &mut O,
        verifier: &mut H,
        now_unix_ms: u64,
    ) -> Result<HumanDispositionEffectV1, CampaignEngineErrorV1>
    where
        O: ObservationResolverV1,
        H: HumanDispositionVerifierV1,
    {
        let current = self.store.current()?;
        let effect = GovernedLoopKernelV1::apply_human_disposition(
            &current,
            artifact.clone(),
            expected_scope,
            new_occurrence,
            observation,
            verifier,
            now_unix_ms,
        )?;
        self.store
            .commit_human_disposition(&current, &effect, &artifact, now_unix_ms)?;
        Ok(effect)
    }

    /// Completes from an authority-empty observation boundary only.
    #[allow(clippy::too_many_arguments)]
    pub fn complete<O: ObservationResolverV1>(
        &mut self,
        observation_ref: ObservationRefV1,
        subject: &Digest,
        terminal_witness: TerminalWitnessRefV1,
        observation: &mut O,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let successor = GovernedLoopKernelV1::complete_from_observation(
            &current,
            observation_ref,
            subject,
            terminal_witness,
            observation,
            now_unix_ms,
        )?;
        self.store.commit(
            &current,
            &successor,
            CampaignTransitionKindV1::Completed,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Records one typed refusal without changing the current state.
    pub fn record_refusal(
        &mut self,
        code: RefusalCodeV1,
        evidence: Option<Digest>,
        now_unix_ms: u64,
    ) -> Result<Digest, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        Ok(self.store.record_refusal(
            &RefusalOutcomeV1 {
                key: current.key().clone(),
                at_state_digest: current.state_digest().clone(),
                code,
                evidence,
            },
            now_unix_ms,
        )?)
    }

    /// Applies the exact restart law without recreating freshness or authority.
    pub fn recover<D: DocketCustodyPortV1>(
        &mut self,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<CampaignRecoveryV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        match current.program_counter() {
            ProgramCounterV1::AuthorizationConsumed => {
                let issuance = current
                    .issuance()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                match docket.reconcile_issuance(&issuance)? {
                    DocketIssuanceReconciliationV1::NotAccepted => {
                        Ok(CampaignRecoveryV1::IssuanceNotAccepted(issuance))
                    }
                    response => {
                        let advanced =
                            self.apply_recovered_issuance(&current, response, now_unix_ms)?;
                        Ok(CampaignRecoveryV1::Advanced(advanced))
                    }
                }
            }
            ProgramCounterV1::Dispatched => {
                let reconciling = GovernedLoopKernelV1::recover_dispatched(&current)?;
                self.store.commit(
                    &current,
                    &reconciling,
                    CampaignTransitionKindV1::RecoveryReconciliation,
                    now_unix_ms,
                )?;
                let custody = reconciling
                    .docket_custody()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let response = docket.reconcile_attempt(&custody)?;
                match self.apply_docket_progress(&reconciling, response, now_unix_ms)? {
                    DocketProgressV1::Pending | DocketProgressV1::ReconciliationRequired(_) => {
                        Ok(CampaignRecoveryV1::Advanced(self.store.current()?))
                    }
                    DocketProgressV1::Settled(snapshot) => {
                        Ok(CampaignRecoveryV1::Advanced(snapshot))
                    }
                }
            }
            ProgramCounterV1::ReconciliationRequired => {
                let custody = current
                    .docket_custody()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let response = docket.reconcile_attempt(&custody)?;
                match self.apply_docket_progress(&current, response, now_unix_ms)? {
                    DocketProgressV1::Pending | DocketProgressV1::ReconciliationRequired(_) => {
                        Ok(CampaignRecoveryV1::Advanced(self.store.current()?))
                    }
                    DocketProgressV1::Settled(snapshot) => {
                        Ok(CampaignRecoveryV1::Advanced(snapshot))
                    }
                }
            }
            _ => Ok(CampaignRecoveryV1::ExternalRevalidation(
                GovernedLoopKernelV1::recovery_requirement(&current),
            )),
        }
    }

    fn apply_recovered_issuance(
        &mut self,
        current: &OccurrenceSnapshotV1,
        response: DocketIssuanceReconciliationV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let (custody, after) = match response {
            DocketIssuanceReconciliationV1::Accepted(custody) => (custody, None),
            DocketIssuanceReconciliationV1::Settled {
                custody,
                settlement,
            } => (custody, Some(Ok(settlement))),
            DocketIssuanceReconciliationV1::Indeterminate {
                custody,
                indeterminate,
            } => (custody, Some(Err(indeterminate))),
            DocketIssuanceReconciliationV1::NotAccepted => {
                return Err(CampaignEngineErrorV1::DocketResponse);
            }
        };
        let dispatched = GovernedLoopKernelV1::accept_docket_custody(current, custody)?;
        self.store.commit(
            current,
            &dispatched,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            now_unix_ms,
        )?;
        match after {
            None => {
                // This path is recovery after process loss.  Custody is known,
                // but its effect outcome is not, so the recovered PC must be
                // explicit reconciliation rather than ordinary dispatch.
                let reconciling = GovernedLoopKernelV1::recover_dispatched(&dispatched)?;
                self.store.commit(
                    &dispatched,
                    &reconciling,
                    CampaignTransitionKindV1::RecoveryReconciliation,
                    now_unix_ms,
                )?;
                Ok(reconciling)
            }
            Some(Ok(settlement)) => {
                let settled = GovernedLoopKernelV1::record_settlement(&dispatched, settlement)?;
                self.store.commit(
                    &dispatched,
                    &settled,
                    CampaignTransitionKindV1::SettlementRecorded,
                    now_unix_ms,
                )?;
                Ok(settled)
            }
            Some(Err(indeterminate)) => {
                let reconciling =
                    GovernedLoopKernelV1::require_reconciliation(&dispatched, indeterminate)?;
                self.store.commit(
                    &dispatched,
                    &reconciling,
                    CampaignTransitionKindV1::ReconciliationRequired,
                    now_unix_ms,
                )?;
                Ok(reconciling)
            }
        }
    }

    fn apply_docket_progress(
        &mut self,
        current: &OccurrenceSnapshotV1,
        response: DocketIssuanceReconciliationV1,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1> {
        match response {
            DocketIssuanceReconciliationV1::NotAccepted => {
                Err(CampaignEngineErrorV1::DocketResponse)
            }
            DocketIssuanceReconciliationV1::Accepted(custody) => {
                if current.docket_custody() != Some(&custody) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                match current.program_counter() {
                    ProgramCounterV1::Dispatched => Ok(DocketProgressV1::Pending),
                    // The exact attempt remains consumed but unsettled.  This
                    // is read-only no-progress, never a downgrade to ordinary
                    // dispatch and never permission to repeat mechanics.
                    ProgramCounterV1::ReconciliationRequired => {
                        Ok(DocketProgressV1::ReconciliationRequired(current.clone()))
                    }
                    _ => Err(CampaignEngineErrorV1::DocketResponse),
                }
            }
            DocketIssuanceReconciliationV1::Settled {
                custody,
                settlement,
            } => {
                if current.docket_custody() != Some(&custody) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                if current.program_counter() == ProgramCounterV1::SettledObservationRequired {
                    return if current.settlement() == Some(&settlement) {
                        Ok(DocketProgressV1::Settled(current.clone()))
                    } else {
                        Err(CampaignEngineErrorV1::DocketResponse)
                    };
                }
                let successor =
                    if current.program_counter() == ProgramCounterV1::ReconciliationRequired {
                        GovernedLoopKernelV1::record_reconciled_settlement(current, settlement)?
                    } else {
                        GovernedLoopKernelV1::record_settlement(current, settlement)?
                    };
                self.store.commit(
                    current,
                    &successor,
                    if current.program_counter() == ProgramCounterV1::ReconciliationRequired {
                        CampaignTransitionKindV1::ReconciledSettlement
                    } else {
                        CampaignTransitionKindV1::SettlementRecorded
                    },
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::Settled(successor))
            }
            DocketIssuanceReconciliationV1::Indeterminate {
                custody,
                indeterminate,
            } => {
                if current.docket_custody() != Some(&custody) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                if current.program_counter() == ProgramCounterV1::ReconciliationRequired {
                    return if current.indeterminate() == Some(&indeterminate) {
                        Ok(DocketProgressV1::ReconciliationRequired(current.clone()))
                    } else {
                        Err(CampaignEngineErrorV1::DocketResponse)
                    };
                }
                let successor =
                    GovernedLoopKernelV1::require_reconciliation(current, indeterminate)?;
                self.store.commit(
                    current,
                    &successor,
                    CampaignTransitionKindV1::ReconciliationRequired,
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::ReconciliationRequired(successor))
            }
        }
    }

    fn halt_for_exhausted_budget(
        &mut self,
        current: &OccurrenceSnapshotV1,
        budget: &'static str,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let body = JcsDocument::canonicalize(&(
            "ag.governed-loop.budget-exhausted/v1",
            current.key(),
            current.state_digest(),
            budget,
        ))
        .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        let reason = HaltReasonRefV1::from_digest(Digest::hash_domain(
            "ag.governed-loop.budget-exhausted/v1",
            body.as_bytes(),
        ));
        let successor = GovernedLoopKernelV1::halt(current, reason)?;
        self.store.commit(
            current,
            &successor,
            CampaignTransitionKindV1::Halted,
            now_unix_ms,
        )?;
        Ok(successor)
    }
}

/// Convenience type for batches of commit receipts returned by future callers.
pub type CampaignCommitBatchV1 = Vec<CampaignCommitReceiptV1>;
