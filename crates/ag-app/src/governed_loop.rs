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

use crate::governed_store::{
    CampaignReplayReportV1, CampaignStoreErrorV1, CampaignStoreV1, CampaignTransitionKindV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
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
    /// Exact Docket-sealed post-spend governed-repair requirement was halted.
    GovernedRepairRequired {
        /// Exact halted snapshot.
        halted: OccurrenceSnapshotV1,
        /// Exact typed requirement from the sealed Docket outcome.
        requirement: HumanDecisionRequirementV1,
    },
}

/// Exact restart/recovery result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "record", rename_all = "snake_case")]
pub enum CampaignRecoveryV1 {
    /// No state transition; the named fresh boundary is required.
    ExternalRevalidation(RecoveryRequirementV1),
    /// Spent issuance is authoritatively absent at Docket and may be submitted
    /// again as the same issuance, never respent.
    IssuanceNotAccepted(AgIssuanceV2),
    /// Recovery committed one or more exact transitions.
    Advanced(OccurrenceSnapshotV1),
}

/// Result of one exact typed pre-spend insufficiency halt commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreSpendScopeInsufficiencyCommitV1 {
    /// Exact durable halted snapshot.
    pub halted: OccurrenceSnapshotV1,
    /// Whether this was an exact replay of the already committed request.
    pub replayed: bool,
}

/// Result of one exact pre-spend discovery/revision commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreSpendScopeDiscoveryCommitV1 {
    /// Exact durable discovery artifact.
    pub discovery: PreSpendScopeDiscoveryV1,
    /// Immutable typed halted predecessor.
    pub predecessor: OccurrenceSnapshotV1,
    /// Distinct authority-empty revised occurrence.
    pub successor: OccurrenceSnapshotV1,
    /// Whether this was an exact replay of the already committed request.
    pub replayed: bool,
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
    /// The stable product legality projection refused an operation at the
    /// exact reported state before any consequence boundary was crossed.
    #[error("product operation is not allowed: {0}")]
    OperationNotAllowed(String),
    /// Docket returned a state that is impossible at this boundary.
    #[error("Docket custody/reconciliation response is not applicable")]
    DocketResponse,
}

/// One production-reachable canonical campaign engine.
pub struct CampaignEngineV1 {
    store: CampaignStoreV1,
}

impl CampaignEngineV1 {
    /// Returns the authoritative store path for stable read-only product views.
    #[must_use]
    pub fn store_path(&self) -> &Path {
        self.store.path()
    }

    /// Creates one campaign with one authority-empty occurrence.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
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

    /// Creates the canonical engine while atomically pinning product genesis
    /// and deployment verifier-root records.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_with_product_records(
        database: &Path,
        campaign: CampaignId,
        occurrence: OccurrenceId,
        program: ProgramBasisRefV1,
        residuals: ResidualSetV1,
        budget: LoopBudgetV1,
        now_unix_ms: u64,
        product_creation: (&Digest, &Digest, &[u8]),
        verifier_root: Option<(&Digest, &[u8])>,
    ) -> Result<Self, CampaignEngineErrorV1> {
        let initial =
            GovernedLoopKernelV1::create_initial(campaign, occurrence, program, residuals, budget)?;
        let store = CampaignStoreV1::create_with_product_records(
            database,
            &initial,
            now_unix_ms,
            Some(product_creation),
            verifier_root,
        )?;
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

    /// Loads the authoritative current occurrence only when it still matches
    /// the exact caller-observed product state. Product legality projection is
    /// advisory until this lower-layer check binds the caller CAS to the
    /// engine operation that may cross an external or durable boundary.
    fn current_at(
        &self,
        expected_state_digest: &Digest,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        if current.state_digest() != expected_state_digest {
            return Err(CampaignStoreErrorV1::StalePredecessor {
                expected: expected_state_digest.clone(),
                authoritative: current.state_digest().clone(),
            }
            .into());
        }
        Ok(current)
    }

    /// Runs deterministic store replay and accounting verification.
    pub fn replay(&self) -> Result<CampaignReplayReportV1, CampaignEngineErrorV1> {
        Ok(self.store.replay()?)
    }

    /// Records a fresh observation plus exact proposal.
    #[allow(clippy::too_many_arguments)]
    pub fn record_proposal<O: ObservationResolverV1>(
        &mut self,
        expected_state_digest: &Digest,
        observation: ObservationRefV1,
        proposal: ExactWorkProposalV1,
        class: ProposalClassV1,
        resolver: &mut O,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
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
                return self.halt_for_exhausted_budget(
                    expected_state_digest,
                    &current,
                    "retry",
                    now_unix_ms,
                );
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            expected_state_digest,
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
        expected_state_digest: &Digest,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        let successor = GovernedLoopKernelV1::require_standing(&current)?;
        self.store.commit(
            expected_state_digest,
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
        expected_state_digest: &Digest,
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
        let current = self.current_at(expected_state_digest)?;
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
            expected_state_digest,
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
        expected_state_digest: &Digest,
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
        let current = self.current_at(expected_state_digest)?;
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
            expected_state_digest,
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
        expected_state_digest: &Digest,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
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
        if now_unix_ms >= issuance.expires_at_unix_ms {
            return match docket.reconcile_issuance(&issuance)? {
                DocketIssuanceReconciliationV1::NotAccepted => {
                    let halted =
                        GovernedLoopKernelV1::halt_expired_issuance(&current, now_unix_ms)?;
                    self.store.commit(
                        expected_state_digest,
                        &current,
                        &halted,
                        CampaignTransitionKindV1::Halted,
                        now_unix_ms,
                    )?;
                    Ok(halted)
                }
                DocketIssuanceReconciliationV1::Refused(refusal) => self
                    .apply_docket_issuance_refusal(
                        expected_state_digest,
                        &current,
                        refusal,
                        now_unix_ms,
                    ),
                response => self.apply_recovered_issuance(
                    expected_state_digest,
                    &current,
                    response,
                    now_unix_ms,
                ),
            };
        }
        let acceptance = docket.accept_issuance(&issuance)?;
        let (custody, governed_result) = match acceptance {
            DocketIssuanceAcceptanceV1::Refused(refusal) => {
                return self.apply_docket_issuance_refusal(
                    expected_state_digest,
                    &current,
                    refusal,
                    now_unix_ms,
                );
            }
            DocketIssuanceAcceptanceV1::Custody(custody) => (custody, None),
            DocketIssuanceAcceptanceV1::GovernedRepairRequired { custody, result } => {
                (custody, Some(result))
            }
        };
        let successor = GovernedLoopKernelV1::accept_docket_custody(&current, custody)?;
        self.store.commit(
            expected_state_digest,
            &current,
            &successor,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            now_unix_ms,
        )?;
        if let Some(result) = governed_result {
            let DocketProgressV1::GovernedRepairRequired { halted, .. } = self
                .apply_sealed_governed_repair(
                    successor.state_digest(),
                    &successor,
                    result,
                    now_unix_ms,
                )?
            else {
                return Err(CampaignEngineErrorV1::DocketResponse);
            };
            Ok(halted)
        } else {
            Ok(successor)
        }
    }

    /// Polls Docket read-only and consumes only exact custody/settlement evidence.
    pub fn poll_docket<D: DocketCustodyPortV1>(
        &mut self,
        expected_state_digest: &Digest,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        let custody = current
            .docket_custody()
            .cloned()
            .ok_or(CampaignEngineErrorV1::DocketResponse)?;
        let issuance = current
            .issuance()
            .cloned()
            .ok_or(CampaignEngineErrorV1::DocketResponse)?;
        let response = docket.reconcile_attempt(&issuance, &custody)?;
        self.apply_docket_progress(expected_state_digest, &current, response, now_unix_ms)
    }

    /// Opens a distinct authority-empty continuation after settlement.
    pub fn open_continuation(
        &mut self,
        expected_state_digest: &Digest,
        occurrence: OccurrenceId,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        let successor = GovernedLoopKernelV1::open_continuation(&current, occurrence)?;
        self.store.commit(
            expected_state_digest,
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
        expected_state_digest: &Digest,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        let successor = match GovernedLoopKernelV1::note_probe(&current) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("probe")) => {
                return self.halt_for_exhausted_budget(
                    expected_state_digest,
                    &current,
                    "probe",
                    now_unix_ms,
                );
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            expected_state_digest,
            &current,
            &successor,
            CampaignTransitionKindV1::ProbeNoted,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Safely halts from a non-effecting boundary.
    pub fn halt_pre_spend_scope_insufficiency(
        &mut self,
        expected_state_digest: &Digest,
        diagnostic_basis: Digest,
        idempotency_key: Digest,
        now_unix_ms: u64,
    ) -> Result<PreSpendScopeInsufficiencyCommitV1, CampaignEngineErrorV1> {
        // The Store, not this advisory read, performs the authoritative
        // caller-cut comparison in the committing transaction.  Reading the
        // current snapshot here also permits exact idempotent replay after the
        // campaign head has advanced.
        let current = if let Some(stored) = self
            .store
            .pre_spend_scope_insufficiency_by_idempotency(&idempotency_key)?
        {
            stored.source
        } else {
            self.store.current()?
        };
        let (halted, replayed) = self.store.commit_pre_spend_scope_insufficiency(
            expected_state_digest,
            &current,
            diagnostic_basis,
            idempotency_key,
            now_unix_ms,
        )?;
        Ok(PreSpendScopeInsufficiencyCommitV1 { halted, replayed })
    }

    /// Records one exact non-authorizing discovery and creates one distinct
    /// authority-empty revised occurrence.  Exact replay returns the original
    /// artifact/successor; changed bytes under one idempotency identity refuse.
    pub fn record_pre_spend_scope_discovery(
        &mut self,
        expected_state_digest: &Digest,
        parameters: PreSpendScopeDiscoveryParametersV1,
    ) -> Result<PreSpendScopeDiscoveryCommitV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        let predecessor = if let Some(stored) = self
            .store
            .pre_spend_scope_discovery_by_idempotency(&parameters.idempotency_key)?
        {
            stored.predecessor
        } else {
            current.clone()
        };
        let (discovery, successor, replayed) = self.store.commit_pre_spend_scope_discovery(
            expected_state_digest,
            &current,
            parameters,
        )?;
        Ok(PreSpendScopeDiscoveryCommitV1 {
            discovery,
            predecessor,
            successor,
            replayed,
        })
    }

    /// Safely halts from a non-effecting boundary.
    pub fn halt(
        &mut self,
        expected_state_digest: &Digest,
        reason: HaltReasonRefV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        let successor = GovernedLoopKernelV1::halt(&current, reason)?;
        self.store.commit(
            expected_state_digest,
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
        expected_state_digest: &Digest,
        reason: HaltReasonRefV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        let successor = match GovernedLoopKernelV1::escalate(&current, reason) {
            Ok(successor) => successor,
            Err(KernelErrorV1::BudgetExhausted("escalation")) => {
                return self.halt_for_exhausted_budget(
                    expected_state_digest,
                    &current,
                    "escalation",
                    now_unix_ms,
                );
            }
            Err(error) => return Err(error.into()),
        };
        self.store.commit(
            expected_state_digest,
            &current,
            &successor,
            CampaignTransitionKindV1::Escalated,
            now_unix_ms,
        )?;
        Ok(successor)
    }

    /// Creates and durably records one exact non-authorizing governed-repair
    /// request under the current halted-state CAS.
    #[allow(clippy::too_many_arguments)]
    pub fn create_governed_repair_request(
        &mut self,
        expected_state_digest: &Digest,
        requirement: HumanDecisionRequirementV1,
        required_verifier_profile: Digest,
        required_verifier_root: Digest,
        required_verifier_executable: Digest,
        decision_consequences: Vec<Digest>,
        nonclaims: Vec<Digest>,
        idempotency_key: Digest,
        now_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<HumanDecisionRequestV1, CampaignEngineErrorV1> {
        let current = self.store.current()?;
        if current.state_digest() != expected_state_digest {
            return Err(CampaignStoreErrorV1::StalePredecessor {
                expected: expected_state_digest.clone(),
                authoritative: current.state_digest().clone(),
            }
            .into());
        }
        let request = GovernedLoopKernelV1::create_human_decision_request(
            &current,
            HumanDecisionRequestParametersV1 {
                requirement,
                required_verifier_profile,
                required_verifier_root,
                required_verifier_executable,
                decision_consequences,
                nonclaims,
                idempotency_key,
                created_at_unix_ms: now_unix_ms,
                expires_at_unix_ms,
            },
        )?;
        self.store
            .record_human_decision_request(expected_state_digest, &request)?;
        Ok(request)
    }

    /// Retrieves one exact durable governed-repair request.
    pub fn governed_repair_request(
        &self,
        request: &HumanDecisionRequestRefV1,
    ) -> Result<Option<HumanDecisionRequestV1>, CampaignEngineErrorV1> {
        Ok(self.store.human_decision_request(request)?)
    }

    /// Applies one exact freshly verified governed-repair disposition and
    /// atomically consumes its request/decision.  Approval never resumes the
    /// halted source; it opens the successor embedded in the artifact.
    pub fn apply_governed_repair_disposition(
        &mut self,
        expected_state_digest: &Digest,
        request: &HumanDecisionRequestRefV1,
        artifact: GovernedRepairDispositionV1,
        now_unix_ms: u64,
    ) -> Result<GovernedRepairDispositionEffectV1, CampaignEngineErrorV1> {
        let verified = self.store.verify_governed_repair_disposition(
            expected_state_digest,
            request,
            artifact,
            now_unix_ms,
        )?;
        let (effect, _) = self
            .store
            .commit_verified_governed_repair_disposition(verified)?;
        Ok(effect)
    }

    /// Completes from an authority-empty observation boundary only.
    #[allow(clippy::too_many_arguments)]
    pub fn complete<O: ObservationResolverV1>(
        &mut self,
        expected_state_digest: &Digest,
        observation_ref: ObservationRefV1,
        subject: &Digest,
        terminal_witness: TerminalWitnessRefV1,
        observation: &mut O,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        let successor = GovernedLoopKernelV1::complete_from_observation(
            &current,
            observation_ref,
            subject,
            terminal_witness,
            observation,
            now_unix_ms,
        )?;
        self.store.commit(
            expected_state_digest,
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
        expected_state_digest: &Digest,
        code: RefusalCodeV1,
        evidence: Option<Digest>,
        now_unix_ms: u64,
    ) -> Result<Digest, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        Ok(self.store.record_refusal(
            expected_state_digest,
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
        expected_state_digest: &Digest,
        docket: &mut D,
        now_unix_ms: u64,
    ) -> Result<CampaignRecoveryV1, CampaignEngineErrorV1> {
        let current = self.current_at(expected_state_digest)?;
        match current.program_counter() {
            ProgramCounterV1::AuthorizationConsumed => {
                let issuance = current
                    .issuance()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                match docket.reconcile_issuance(&issuance)? {
                    DocketIssuanceReconciliationV1::NotAccepted => {
                        if now_unix_ms >= issuance.expires_at_unix_ms {
                            let halted =
                                GovernedLoopKernelV1::halt_expired_issuance(&current, now_unix_ms)?;
                            self.store.commit(
                                expected_state_digest,
                                &current,
                                &halted,
                                CampaignTransitionKindV1::Halted,
                                now_unix_ms,
                            )?;
                            Ok(CampaignRecoveryV1::Advanced(halted))
                        } else {
                            Ok(CampaignRecoveryV1::IssuanceNotAccepted(issuance))
                        }
                    }
                    response => {
                        let advanced = self.apply_recovered_issuance(
                            expected_state_digest,
                            &current,
                            response,
                            now_unix_ms,
                        )?;
                        Ok(CampaignRecoveryV1::Advanced(advanced))
                    }
                }
            }
            ProgramCounterV1::Dispatched => {
                let reconciling = GovernedLoopKernelV1::recover_dispatched(&current)?;
                self.store.commit(
                    expected_state_digest,
                    &current,
                    &reconciling,
                    CampaignTransitionKindV1::RecoveryReconciliation,
                    now_unix_ms,
                )?;
                let custody = reconciling
                    .docket_custody()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let issuance = reconciling
                    .issuance()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let response = docket.reconcile_attempt(&issuance, &custody)?;
                Self::recovery_from_progress(
                    self.apply_docket_progress(
                        reconciling.state_digest(),
                        &reconciling,
                        response,
                        now_unix_ms,
                    )?,
                    &self.store,
                )
            }
            ProgramCounterV1::ReconciliationRequired => {
                let custody = current
                    .docket_custody()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let issuance = current
                    .issuance()
                    .cloned()
                    .ok_or(CampaignEngineErrorV1::DocketResponse)?;
                let response = docket.reconcile_attempt(&issuance, &custody)?;
                Self::recovery_from_progress(
                    self.apply_docket_progress(
                        expected_state_digest,
                        &current,
                        response,
                        now_unix_ms,
                    )?,
                    &self.store,
                )
            }
            _ => Ok(CampaignRecoveryV1::ExternalRevalidation(
                GovernedLoopKernelV1::recovery_requirement(&current),
            )),
        }
    }

    fn recovery_from_progress(
        progress: DocketProgressV1,
        store: &CampaignStoreV1,
    ) -> Result<CampaignRecoveryV1, CampaignEngineErrorV1> {
        match progress {
            DocketProgressV1::Pending | DocketProgressV1::ReconciliationRequired(_) => {
                Ok(CampaignRecoveryV1::Advanced(store.current()?))
            }
            DocketProgressV1::Settled(snapshot) => Ok(CampaignRecoveryV1::Advanced(snapshot)),
            DocketProgressV1::GovernedRepairRequired { halted, .. } => {
                Ok(CampaignRecoveryV1::Advanced(halted))
            }
        }
    }

    fn apply_recovered_issuance(
        &mut self,
        caller_expected: &Digest,
        current: &OccurrenceSnapshotV1,
        response: DocketIssuanceReconciliationV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        if let DocketIssuanceReconciliationV1::GovernedRepairRequired { custody, result } = response
        {
            let dispatched = GovernedLoopKernelV1::accept_docket_custody(current, custody)?;
            self.store.commit(
                caller_expected,
                current,
                &dispatched,
                CampaignTransitionKindV1::DocketCustodyAccepted,
                now_unix_ms,
            )?;
            let DocketProgressV1::GovernedRepairRequired { halted, .. } = self
                .apply_sealed_governed_repair(
                    dispatched.state_digest(),
                    &dispatched,
                    result,
                    now_unix_ms,
                )?
            else {
                return Err(CampaignEngineErrorV1::DocketResponse);
            };
            return Ok(halted);
        }
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
            DocketIssuanceReconciliationV1::Refused(refusal) => {
                return self.apply_docket_issuance_refusal(
                    caller_expected,
                    current,
                    refusal,
                    now_unix_ms,
                );
            }
            DocketIssuanceReconciliationV1::GovernedRepairRequired { .. } => unreachable!(
                "governed repair recovery response handled before ordinary reconciliation"
            ),
        };
        let dispatched = GovernedLoopKernelV1::accept_docket_custody(current, custody)?;
        self.store.commit(
            caller_expected,
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
                    dispatched.state_digest(),
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
                    dispatched.state_digest(),
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
                    dispatched.state_digest(),
                    &dispatched,
                    &reconciling,
                    CampaignTransitionKindV1::ReconciliationRequired,
                    now_unix_ms,
                )?;
                Ok(reconciling)
            }
        }
    }

    fn apply_docket_issuance_refusal(
        &mut self,
        caller_expected: &Digest,
        current: &OccurrenceSnapshotV1,
        refusal: ag_campaign::governed::DocketIssuanceRefusalV1,
        now_unix_ms: u64,
    ) -> Result<OccurrenceSnapshotV1, CampaignEngineErrorV1> {
        let halted = GovernedLoopKernelV1::halt_docket_issuance_refusal(current, refusal.clone())?;
        self.store.commit_docket_issuance_refusal(
            caller_expected,
            current,
            &halted,
            &refusal,
            now_unix_ms,
        )?;
        Ok(halted)
    }

    fn apply_docket_progress(
        &mut self,
        caller_expected: &Digest,
        current: &OccurrenceSnapshotV1,
        response: DocketIssuanceReconciliationV1,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1> {
        match response {
            // Attempt reconciliation is only legal after custody. A
            // pre-custody refusal on this boundary is a cross-phase
            // substitution, not a second terminal transition.
            DocketIssuanceReconciliationV1::NotAccepted
            | DocketIssuanceReconciliationV1::Refused(_) => {
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
                    caller_expected,
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
                    caller_expected,
                    current,
                    &successor,
                    CampaignTransitionKindV1::ReconciliationRequired,
                    now_unix_ms,
                )?;
                Ok(DocketProgressV1::ReconciliationRequired(successor))
            }
            DocketIssuanceReconciliationV1::GovernedRepairRequired { custody, result } => {
                if current.docket_custody() != Some(&custody) {
                    return Err(CampaignEngineErrorV1::DocketResponse);
                }
                self.apply_sealed_governed_repair(caller_expected, current, result, now_unix_ms)
            }
        }
    }

    fn apply_sealed_governed_repair(
        &mut self,
        caller_expected: &Digest,
        current: &OccurrenceSnapshotV1,
        result: DocketSealedGovernedRepairResultV1,
        now_unix_ms: u64,
    ) -> Result<DocketProgressV1, CampaignEngineErrorV1> {
        let exact_result = result.clone();
        let (outcome, requirement, domain) = match result {
            DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
                outcome,
                requirement,
            } => (
                outcome,
                HumanDecisionRequirementV1::ScopeExpansion(requirement),
                "ag.governed-loop.docket-scope-expansion-required/v1",
            ),
            DocketSealedGovernedRepairResultV1::ReadjudicationRequired {
                outcome,
                requirement,
            } => (
                outcome,
                HumanDecisionRequirementV1::Readjudication(requirement),
                "ag.governed-loop.docket-readjudication-required/v1",
            ),
        };
        let reason = HaltReasonRefV1::from_digest(Digest::hash_domain(
            domain,
            outcome.sealed_result.as_digest().as_str().as_bytes(),
        ));
        let halted = GovernedLoopKernelV1::halt_from_docket_governed_repair(
            current,
            &outcome,
            &requirement,
            reason,
        )?;
        self.store.commit_docket_governed_repair_halt(
            caller_expected,
            current,
            &halted,
            &exact_result,
            now_unix_ms,
        )?;
        Ok(DocketProgressV1::GovernedRepairRequired {
            halted,
            requirement,
        })
    }

    fn halt_for_exhausted_budget(
        &mut self,
        caller_expected: &Digest,
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
            caller_expected,
            current,
            &successor,
            CampaignTransitionKindV1::Halted,
            now_unix_ms,
        )?;
        Ok(successor)
    }
}
