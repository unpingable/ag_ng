//! Production-engine tests spanning live boundaries, `SQLite` state, Docket
//! custody, restart, reconciliation, continuation, and human disposition.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use crate::governed_loop::{
    CampaignEngineErrorV1, CampaignEngineV1, CampaignRecoveryV1, DocketProgressV1,
    EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
};
use crate::governed_store::CampaignStoreErrorV1;
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use tempfile::TempDir;
use uuid::Uuid;

const NOW: u64 = 30_000;

fn current_state_digest(engine: &CampaignEngineV1) -> Digest {
    engine.current().unwrap().state_digest().clone()
}

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-engine-test/v1", label.as_bytes())
}

fn campaign() -> CampaignId {
    CampaignId::from_digest(digest("campaign"))
}

fn occurrence(value: u128) -> OccurrenceId {
    OccurrenceId::from_uuid(Uuid::from_u128(value))
}

fn budget() -> LoopBudgetV1 {
    LoopBudgetV1 {
        retry_limit: 2,
        retries_used: 0,
        probe_limit: 1,
        probes_used: 0,
        escalation_limit: 1,
        escalations_used: 0,
    }
}

fn proposal(label: &str) -> ExactWorkProposalV1 {
    let scope = CanonicalEffectScopeV1::new(
        "test-effect".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "fixtures/exact-work".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    ExactWorkProposalV1::new(
        campaign(),
        digest("subject"),
        scope,
        "test.engine-work/v1".to_owned(),
        digest(label),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap()
}

fn catalog() -> ExactWorkCatalogV1 {
    ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        policy_basis: digest("policy"),
        entries: BTreeMap::from([(
            "test.engine-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.engine-work/v1".to_owned(),
                subject: digest("subject"),
                scope: proposal("catalog-scope").effect_scope().digest(),
            },
        )]),
    }
}

#[derive(Clone)]
struct ObservationBoundary {
    preconditions: PreconditionBasisRefV1,
    status: ObservationStatusV1,
    calls: usize,
}

impl ObservationBoundary {
    fn current(label: &str) -> Self {
        Self {
            preconditions: PreconditionBasisRefV1::from_digest(digest(label)),
            status: ObservationStatusV1::Current,
            calls: 0,
        }
    }
}

impl ObservationResolverV1 for ObservationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
        Ok(ObservationResolutionV1 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V1.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest(&format!(
                "observation-current-{}",
                self.calls
            ))),
            normalized_preconditions: self.preconditions.clone(),
            subject: request.subject.clone(),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

#[derive(Clone)]
struct StandingBoundary {
    status: StandingStatusV1,
    calls: usize,
}

impl StandingBoundary {
    fn current() -> Self {
        Self {
            status: StandingStatusV1::Current,
            calls: 0,
        }
    }
}

impl StandingResolverV1 for StandingBoundary {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
        Ok(CurrentStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest(&format!(
                "standing-resolution-{}",
                self.calls
            ))),
            currentness: StandingCurrentnessRefV1::from_digest(digest(&format!(
                "standing-currentness-{}",
                self.calls
            ))),
            mandate: MandateRefV1::from_digest(digest("mandate")),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

#[derive(Clone, Debug)]
enum FakeAttemptState {
    Accepted(DocketCustodyV1),
    Settled(DocketCustodyV1, DocketSettlementV1),
    Indeterminate(DocketCustodyV1, IndeterminateOutcomeV1),
    GovernedRepairRequired(DocketCustodyV1, Box<DocketSealedGovernedRepairResultV1>),
}

#[derive(Default)]
struct FakeDocketState {
    attempts: BTreeMap<AgIssuanceRefV1, FakeAttemptState>,
    accept_calls: usize,
    panic_after_accept: bool,
}

#[derive(Clone, Default)]
struct FakeDocket {
    shared: Arc<Mutex<FakeDocketState>>,
}

impl FakeDocket {
    fn custody(issuance: &AgIssuanceV2) -> DocketCustodyV1 {
        DocketCustodyV1 {
            schema: DOCKET_CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: DocketExecutionStandingRefV1::from_digest(digest(
                "docket-execution-standing",
            )),
            standing_currentness: StandingCurrentnessRefV1::from_digest(digest(
                "docket-standing-currentness",
            )),
            attempt: DocketAttemptRefV1::for_issuance(&issuance.issuance),
            executor_marker: ExecutorAttemptMarkerRefV1::from_digest(Digest::hash_domain(
                "ag-governed-engine-test/executor-marker/v1",
                issuance.issuance.as_str().as_bytes(),
            )),
            accepted_at_unix_ms: NOW + 10,
        }
    }

    fn settle(&self, issuance: &AgIssuanceRefV1, outcome: KnownOutcomeV1) {
        let mut state = self.shared.lock().unwrap();
        let Some(FakeAttemptState::Accepted(custody) | FakeAttemptState::Indeterminate(custody, _)) =
            state.attempts.get(issuance).cloned()
        else {
            panic!("issuance was not accepted or was already settled")
        };
        let mut settlement = DocketSettlementV1 {
            schema: DOCKET_SETTLEMENT_SCHEMA_V1.to_owned(),
            settlement: SettlementRefV1::from_digest(digest(match outcome {
                KnownOutcomeV1::Success => "known-success",
                KnownOutcomeV1::Failure => "known-failure",
            })),
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            executor_marker: custody.executor_marker.clone(),
            receipt: ReceiptRefV1::from_digest(digest("receipt")),
            outcome,
            cumulative_effect_journal_identity: Some(digest("cumulative-effect-journal")),
            settled_at_unix_ms: NOW + 20,
        };
        settlement.settlement = settlement.expected_reference().unwrap();
        state.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Settled(custody, settlement),
        );
    }

    fn make_indeterminate(&self, issuance: &AgIssuanceRefV1) {
        let mut state = self.shared.lock().unwrap();
        let Some(FakeAttemptState::Accepted(custody)) = state.attempts.get(issuance).cloned()
        else {
            panic!("issuance was not accepted")
        };
        let indeterminate = IndeterminateOutcomeV1 {
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            reconciliation: ReconciliationRefV1::from_digest(digest("reconciliation")),
            evidence: digest("unknown-outcome"),
        };
        state.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Indeterminate(custody, indeterminate),
        );
    }

    fn require_scope_expansion(
        &self,
        issuance: &AgIssuanceRefV1,
        original_scope: &CanonicalEffectScopeV1,
    ) {
        let mut state = self.shared.lock().unwrap();
        let Some(FakeAttemptState::Accepted(custody) | FakeAttemptState::Indeterminate(custody, _)) =
            state.attempts.get(issuance).cloned()
        else {
            panic!("issuance was not accepted or reconcilable")
        };
        let outcome = DocketGovernedRepairOutcomeRefV1 {
            checkpoint: DocketCheckpointRefV1::from_digest(digest("scope-checkpoint")),
            sealed_result: DocketSealedResultRefV1::from_digest(digest("scope-sealed-result")),
            outcome: digest("scope-outcome"),
            issuance: custody.issuance.clone(),
            custody: custody.reference(),
            attempt: custody.attempt.clone(),
            effect_journal: digest("scope-effect-journal"),
            executor_binding: digest("scope-executor-binding"),
            executor_result: digest("scope-executor-result"),
            executor_receipt: ReceiptRefV1::from_digest(digest("scope-executor-receipt")),
            immutable_work_checkpoint: None,
            reported_authorized_effects_occurred: false,
            created_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 1_000,
            idempotency: digest("scope-requirement-idempotency"),
        };
        let requested_delta = CanonicalEffectScopeV1::new(
            original_scope.effect_class().to_owned(),
            vec![CanonicalEffectResourceV1 {
                resource: "repository".to_owned(),
                path: "fixtures/required-adjacent".to_owned(),
                operations: vec![CanonicalEffectOperationV1::Modify],
            }],
        )
        .unwrap();
        let requirement = ScopeExpansionRequiredV1 {
            schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
            original_scope: original_scope.clone(),
            original_scope_digest: original_scope.digest(),
            requested_delta_digest: requested_delta.digest(),
            requested_delta,
            blocked_operation: BlockedEffectOperationV1 {
                resource: "repository".to_owned(),
                path: "fixtures/required-adjacent".to_owned(),
                operation: CanonicalEffectOperationV1::Modify,
            },
            reason: digest("scope-expansion-required"),
            dependency_evidence: sorted_digests(&["scope-dependency"]),
            limitations: sorted_digests(&["scope-limitation"]),
            docket_outcome: Some(outcome.clone()),
            no_unauthorized_effect_reported: true,
        };
        state.attempts.insert(
            issuance.clone(),
            FakeAttemptState::GovernedRepairRequired(
                custody,
                Box::new(DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
                    outcome,
                    requirement,
                }),
            ),
        );
    }

    fn set_panic_after_accept(&self) {
        self.shared.lock().unwrap().panic_after_accept = true;
    }

    fn accept_calls(&self) -> usize {
        self.shared.lock().unwrap().accept_calls
    }

    fn response_for(
        state: &FakeDocketState,
        issuance: &AgIssuanceRefV1,
    ) -> DocketIssuanceReconciliationV1 {
        match state.attempts.get(issuance) {
            None => DocketIssuanceReconciliationV1::NotAccepted,
            Some(FakeAttemptState::Accepted(custody)) => {
                DocketIssuanceReconciliationV1::Accepted(custody.clone())
            }
            Some(FakeAttemptState::Settled(custody, settlement)) => {
                DocketIssuanceReconciliationV1::Settled {
                    custody: custody.clone(),
                    settlement: settlement.clone(),
                }
            }
            Some(FakeAttemptState::Indeterminate(custody, indeterminate)) => {
                DocketIssuanceReconciliationV1::Indeterminate {
                    custody: custody.clone(),
                    indeterminate: indeterminate.clone(),
                }
            }
            Some(FakeAttemptState::GovernedRepairRequired(custody, result)) => {
                DocketIssuanceReconciliationV1::GovernedRepairRequired {
                    custody: custody.clone(),
                    result: result.as_ref().clone(),
                }
            }
        }
    }
}

impl DocketCustodyPortV1 for FakeDocket {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceAcceptanceV1, ExternalBoundaryErrorV1> {
        let mut state = self.shared.lock().unwrap();
        state.accept_calls += 1;
        let custody = match state.attempts.get(&issuance.issuance) {
            Some(
                FakeAttemptState::Accepted(custody)
                | FakeAttemptState::Settled(custody, _)
                | FakeAttemptState::Indeterminate(custody, _)
                | FakeAttemptState::GovernedRepairRequired(custody, _),
            ) => custody.clone(),
            None => {
                let custody = Self::custody(issuance);
                state.attempts.insert(
                    issuance.issuance.clone(),
                    FakeAttemptState::Accepted(custody.clone()),
                );
                custody
            }
        };
        let panic_after_accept = state.panic_after_accept;
        state.panic_after_accept = false;
        drop(state);
        assert!(!panic_after_accept, "injected crash after Docket custody");
        Ok(DocketIssuanceAcceptanceV1::Custody(custody))
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        let state = self.shared.lock().unwrap();
        Ok(Self::response_for(&state, &issuance.issuance))
    }

    fn reconcile_attempt(
        &mut self,
        issuance: &AgIssuanceV2,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        let state = self.shared.lock().unwrap();
        assert_eq!(&issuance.issuance, &custody.issuance);
        let response = Self::response_for(&state, &custody.issuance);
        match &response {
            DocketIssuanceReconciliationV1::Accepted(actual)
            | DocketIssuanceReconciliationV1::Settled {
                custody: actual, ..
            }
            | DocketIssuanceReconciliationV1::Indeterminate {
                custody: actual, ..
            } if actual == custody => Ok(response),
            DocketIssuanceReconciliationV1::GovernedRepairRequired {
                custody: actual, ..
            } if actual == custody => Ok(response),
            DocketIssuanceReconciliationV1::Refused(_) => Err(ExternalBoundaryErrorV1::Refused {
                code: "pre-custody-refusal-on-attempt-boundary".to_owned(),
                evidence: None,
            }),
            _ => Err(ExternalBoundaryErrorV1::Refused {
                code: "wrong-custody".to_owned(),
                evidence: None,
            }),
        }
    }
}

/// Development/qualification fixture only.  It is deliberately not a human
/// authority implementation and is never reachable from production wiring.
struct QualificationFixtureNotHumanAuthority;

impl GovernedRepairDispositionVerifierV1 for QualificationFixtureNotHumanAuthority {
    fn verify_governed_repair_disposition(
        &mut self,
        request: &GovernedRepairVerificationRequestV1<'_>,
    ) -> Result<GovernedRepairVerificationV1, ExternalBoundaryErrorV1> {
        Ok(GovernedRepairVerificationV1 {
            schema: GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1.to_owned(),
            disposition: request.artifact.reference(),
            request: request.request.reference(),
            halted_state_digest: request.request.halted_state_digest.clone(),
            verifier_profile: request.expected_profile.profile.clone(),
            verifier_root: request.expected_profile.root.clone(),
            verifier_executable: request.expected_profile.executable.clone(),
            verification: HumanVerificationRefV1::from_digest(Digest::hash_domain(
                "qualification-fixture-not-human-authority/v1",
                request.artifact.nonce.as_str().as_bytes(),
            )),
            verified_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 10,
        })
    }
}

fn sorted_digests(labels: &[&str]) -> Vec<Digest> {
    let mut values = labels.iter().map(|label| digest(label)).collect::<Vec<_>>();
    values.sort();
    values
}

fn repair_checkpoint(label: &str) -> GovernedRepairCheckpointV1 {
    GovernedRepairCheckpointV1 {
        repository: digest(&format!("repository-{label}")),
        commit: "1111111111111111111111111111111111111111".to_owned(),
        tree: "2222222222222222222222222222222222222222".to_owned(),
        diff_identity: None,
        content_manifest: digest(&format!("manifest-{label}")),
        docket_checkpoint: None,
    }
}

fn create_engine(directory: &TempDir, residuals: ResidualSetV1) -> CampaignEngineV1 {
    CampaignEngineV1::create(
        &directory.path().join("campaign.sqlite"),
        campaign(),
        occurrence(1),
        ProgramBasisRefV1::from_digest(digest("program")),
        residuals,
        budget(),
        NOW,
    )
    .unwrap()
}

fn advance_to_spent(
    engine: &mut CampaignEngineV1,
    observation: &mut ObservationBoundary,
    standing: &mut StandingBoundary,
) -> OccurrenceSnapshotV1 {
    engine
        .record_proposal(
            &current_state_digest(engine),
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            observation,
            NOW + 1,
        )
        .unwrap();
    engine
        .require_standing(&current_state_digest(engine), NOW + 2)
        .unwrap();
    engine
        .decide(
            &current_state_digest(engine),
            observation,
            standing,
            &catalog(),
            None,
            NOW + 3,
        )
        .unwrap();
    engine
        .authorize(
            &current_state_digest(engine),
            observation,
            standing,
            &catalog(),
            None,
            NOW + 4,
        )
        .unwrap()
}

#[test]
fn production_path_spends_once_settles_and_requires_a_new_occurrence() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let spent = advance_to_spent(&mut engine, &mut observation, &mut standing);
    assert_eq!(
        spent.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert!(observation.calls >= 3);
    assert_eq!(standing.calls, 2);

    let mut docket = FakeDocket::default();
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    assert_eq!(dispatched.program_counter(), ProgramCounterV1::Dispatched);
    assert_eq!(docket.accept_calls(), 1);
    assert!(
        engine
            .dispatch(&current_state_digest(&engine), &mut docket, NOW + 6)
            .is_err()
    );
    assert_eq!(docket.accept_calls(), 1);

    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 7)
        .unwrap()
    else {
        panic!("known outcome must settle")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert!(
        engine
            .authorize(
                &current_state_digest(&engine),
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                NOW + 8,
            )
            .is_err()
    );

    let next = engine
        .open_continuation(&current_state_digest(&engine), occurrence(2), NOW + 9)
        .unwrap();
    assert_eq!(
        next.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert_ne!(next.key().occurrence, spent.key().occurrence);
    assert!(next.ag_spend().is_none());
    assert_eq!(engine.replay().unwrap().docket_attempts, 1);
    assert_eq!(engine.replay().unwrap().settlements, 1);
}

#[test]
fn consequence_time_stale_observation_and_revoked_standing_do_not_spend() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 1,
        )
        .unwrap();
    engine
        .require_standing(&current_state_digest(&engine), NOW + 2)
        .unwrap();
    engine
        .decide(
            &current_state_digest(&engine),
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            NOW + 3,
        )
        .unwrap();
    let before = engine.current().unwrap();

    observation.status = ObservationStatusV1::Stale;
    assert!(
        engine
            .authorize(
                &current_state_digest(&engine),
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                NOW + 4,
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);

    observation.status = ObservationStatusV1::Current;
    standing.status = StandingStatusV1::Revoked;
    assert!(
        engine
            .authorize(
                &current_state_digest(&engine),
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                NOW + 5,
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[derive(Default)]
struct RefusingDocket {
    refusal: Option<DocketIssuanceRefusalV1>,
}

impl DocketCustodyPortV1 for RefusingDocket {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceAcceptanceV1, ExternalBoundaryErrorV1> {
        let mut refusal = DocketIssuanceRefusalV1 {
            schema: "docket.governed-loop.issuance-refusal/v1".to_owned(),
            refusal: digest("placeholder-refusal"),
            issuance: issuance.issuance.clone(),
            campaign: issuance.key.campaign.clone(),
            occurrence: issuance.key.occurrence,
            refusal_class: DocketIssuanceRefusalClassV1::StandingInvalid,
            reason_code: "standing_invalid".to_owned(),
            evidence: digest("standing-negative-evidence"),
            refused_at_unix_ms: NOW + 5,
        };
        refusal.refusal = refusal.derived_identity();
        self.refusal = Some(refusal.clone());
        Ok(DocketIssuanceAcceptanceV1::Refused(refusal))
    }

    fn reconcile_issuance(
        &mut self,
        _issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        Ok(self.refusal.clone().map_or(
            DocketIssuanceReconciliationV1::NotAccepted,
            DocketIssuanceReconciliationV1::Refused,
        ))
    }

    fn reconcile_attempt(
        &mut self,
        _issuance: &AgIssuanceV2,
        _custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        Err(ExternalBoundaryErrorV1::Refused {
            code: "no-custody-for-refusal".to_owned(),
            evidence: None,
        })
    }
}

#[test]
fn docket_pre_custody_refusal_terminalizes_spent_occurrence_and_replays() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let spent = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let spend_identity = spent.ag_spend().unwrap().spend.clone();
    let mut docket = RefusingDocket::default();

    let halted = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    assert_eq!(halted.program_counter(), ProgramCounterV1::Halted);
    let refusal = halted
        .halted()
        .unwrap()
        .docket_issuance_refusal()
        .unwrap()
        .clone();
    assert_eq!(
        halted.state().authority_history().ag_spend,
        Some(spend_identity)
    );
    assert!(halted.docket_custody().is_none());
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    drop(engine);

    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        reopened
            .current()
            .unwrap()
            .halted()
            .unwrap()
            .docket_issuance_refusal(),
        Some(&refusal)
    );
}

#[test]
fn custody_crash_recovers_to_reconciliation_without_respend_or_repeat() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let spent = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let issuance = spent.issuance().unwrap().issuance.clone();

    let mut docket = FakeDocket::default();
    docket.set_panic_after_accept();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let expected = current_state_digest(&engine);
            let _ = engine.dispatch(&expected, &mut docket, NOW + 5);
        }))
        .is_err()
    );
    drop(engine);

    let mut recovered = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        recovered.current().unwrap().program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    let CampaignRecoveryV1::Advanced(reconciling) = recovered
        .recover(&current_state_digest(&recovered), &mut docket, NOW + 6)
        .unwrap()
    else {
        panic!("known custody must advance recovery")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert_eq!(docket.accept_calls(), 1);
    assert_eq!(recovered.replay().unwrap().ag_spends, 1);
    assert_eq!(recovered.replay().unwrap().docket_attempts, 1);

    docket.settle(&issuance, KnownOutcomeV1::Failure);
    let DocketProgressV1::Settled(settled) = recovered
        .poll_docket(&current_state_digest(&recovered), &mut docket, NOW + 7)
        .unwrap()
    else {
        panic!("explicit exact reconciliation must settle")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(recovered.replay().unwrap().settlements, 1);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the restart specimen keeps every durable consequence cut visibly ordered"
)]
fn restart_at_each_consequence_boundary_preserves_pc_and_never_recreates_authority() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    let mut observation = ObservationBoundary::current("preconditions");
    engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 1,
        )
        .unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    engine
        .require_standing(&current_state_digest(&engine), NOW + 2)
        .unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::StandingRequired
    );
    let mut standing = StandingBoundary::current();
    engine
        .decide(
            &current_state_digest(&engine),
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            NOW + 3,
        )
        .unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    engine
        .authorize(
            &current_state_digest(&engine),
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            NOW + 4,
        )
        .unwrap();
    drop(engine);

    let mut docket = FakeDocket::default();
    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert!(matches!(
        engine
            .recover(&current_state_digest(&engine), &mut docket, NOW + 5)
            .unwrap(),
        CampaignRecoveryV1::IssuanceNotAccepted(_)
    ));
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 6)
        .unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::Dispatched
    );
    let CampaignRecoveryV1::Advanced(reconciling) = engine
        .recover(&current_state_digest(&engine), &mut docket, NOW + 7)
        .unwrap()
    else {
        panic!("accepted attempt must recover into explicit reconciliation")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert_eq!(docket.accept_calls(), 1);
    drop(engine);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    engine = CampaignEngineV1::open(&database).unwrap();
    let DocketProgressV1::Settled(settled) = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 8)
        .unwrap()
    else {
        panic!("explicit exact Docket settlement must close reconciliation")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert_eq!(engine.replay().unwrap().docket_attempts, 1);
    assert_eq!(engine.replay().unwrap().settlements, 1);
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    let next = engine
        .open_continuation(&current_state_digest(&engine), occurrence(2), NOW + 9)
        .unwrap();
    assert_eq!(
        next.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(next.ag_spend().is_none());
    assert!(next.docket_custody().is_none());
    assert_eq!(next.key().occurrence, occurrence(2));
}

#[test]
fn changed_preconditions_cannot_be_laundered_as_retry() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    docket.settle(
        &dispatched.issuance().unwrap().issuance,
        KnownOutcomeV1::Failure,
    );
    let _ = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 6)
        .unwrap();
    engine
        .open_continuation(&current_state_digest(&engine), occurrence(2), NOW + 7)
        .unwrap();

    observation.preconditions = PreconditionBasisRefV1::from_digest(digest("changed"));
    let error = engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-1"),
            ProposalClassV1::Retry,
            &mut observation,
            NOW + 8,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::RetryPreconditionsChanged)
    ));
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ObservationRequired
    );

    let successor = engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-2"),
            ProposalClassV1::Successor,
            &mut observation,
            NOW + 9,
        )
        .unwrap();
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    assert_eq!(successor.key().occurrence, occurrence(2));
}

#[test]
fn indeterminate_attempt_blocks_repeat_until_exact_settlement() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 6)
        .unwrap()
    else {
        panic!("unknown outcome must reconcile")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert!(
        engine
            .dispatch(&current_state_digest(&engine), &mut docket, NOW + 7)
            .is_err()
    );
    assert!(
        engine
            .open_continuation(&current_state_digest(&engine), occurrence(2), NOW + 8)
            .is_err()
    );
    assert_eq!(docket.accept_calls(), 1);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 9)
        .unwrap()
    else {
        panic!("reconciliation settlement must be consumed")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
}

#[test]
fn reconciled_governed_repair_halt_is_durable_and_replayable() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();

    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 6)
        .unwrap()
    else {
        panic!("unknown result must enter reconciliation")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );

    let original_scope = proposal("work-1").effect_scope().clone();
    docket.require_scope_expansion(&issuance, &original_scope);
    let DocketProgressV1::GovernedRepairRequired {
        halted,
        requirement,
    } = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 7)
        .unwrap()
    else {
        panic!("sealed reconciled requirement must durably halt")
    };
    let halted_state = halted.halted().unwrap();
    assert_eq!(
        halted_state.source(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert!(halted_state.unresolved_attempt().is_none());
    assert_eq!(
        halted_state.governed_repair_requirement(),
        Some(&requirement)
    );
    halted.validate_integrity().unwrap();

    let report = engine.replay().unwrap();
    assert_eq!(report.ag_spends, 1);
    assert_eq!(report.docket_attempts, 1);
    assert_eq!(report.current_state_digest, *halted.state_digest());
    drop(engine);

    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), halted);
    let replayed = reopened.replay().unwrap();
    assert_eq!(replayed.current_state_digest, *halted.state_digest());
    assert_eq!(replayed.ag_spends, 1);
    assert_eq!(replayed.docket_attempts, 1);
}

#[test]
fn logical_crash_after_docket_seal_before_ag_ingestion_reconciles_to_one_halt() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();

    // Docket's sealed result is durable in its own custody boundary while AG
    // still has only Dispatched. Dropping the engine is the logical crash cut;
    // physical power-loss durability remains an operational premise.
    docket.require_scope_expansion(&issuance, proposal("work-1").effect_scope());
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::Dispatched
    );
    drop(engine);

    let mut reopened = CampaignEngineV1::open(&database).unwrap();
    let CampaignRecoveryV1::Advanced(reconciling) = reopened
        .recover(&current_state_digest(&reopened), &mut docket, NOW + 6)
        .unwrap()
    else {
        panic!("dispatched restart must enter explicit reconciliation")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    let DocketProgressV1::GovernedRepairRequired { halted, .. } = reopened
        .poll_docket(&current_state_digest(&reopened), &mut docket, NOW + 7)
        .unwrap()
    else {
        panic!("explicit sealed Docket result must reconcile to one durable AG halt")
    };
    assert_eq!(halted.program_counter(), ProgramCounterV1::Halted);
    assert!(
        halted
            .halted()
            .unwrap()
            .governed_repair_requirement()
            .is_some()
    );
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
    assert_eq!(reopened.replay().unwrap().docket_attempts, 1);
    drop(reopened);

    let replayed = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(replayed.current().unwrap(), halted);
    assert_eq!(replayed.replay().unwrap().human_decision_requests, 0);
}

#[test]
fn durable_budget_fact_is_nonauthorizing_and_exhaustion_halts() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let observed = engine
        .note_probe(&current_state_digest(&engine), NOW + 1)
        .unwrap();
    assert_eq!(
        observed.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert_eq!(observed.state().meta().budget().probes_used, 1);
    assert!(observed.ag_spend().is_none());

    let halted = engine
        .note_probe(&current_state_digest(&engine), NOW + 2)
        .unwrap();
    assert_eq!(halted.program_counter(), ProgramCounterV1::Halted);
    assert_eq!(halted.state().meta().budget().probes_used, 1);
    assert!(halted.ag_spend().is_none());
    drop(engine);

    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), halted);
    assert_eq!(
        GovernedLoopKernelV1::recovery_requirement(&halted),
        RecoveryRequirementV1::ExternalDisposition
    );
}

#[test]
fn stale_engine_caller_cannot_redirect_proposal_after_intervening_commit() {
    struct InterleavingObservation {
        database: std::path::PathBuf,
        expected: Digest,
        calls: Arc<AtomicUsize>,
        inner: ObservationBoundary,
    }

    impl ObservationResolverV1 for InterleavingObservation {
        fn resolve_observation(
            &mut self,
            request: &ObservationResolutionRequestV1<'_>,
        ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut competing_engine = CampaignEngineV1::open(&self.database).unwrap();
            competing_engine
                .note_probe(&self.expected, NOW + 1)
                .unwrap();
            self.inner.resolve_observation(request)
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut stale_engine = create_engine(&directory, ResidualSetV1::default());
    let expected = current_state_digest(&stale_engine);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut observation = InterleavingObservation {
        database,
        expected: expected.clone(),
        calls: Arc::clone(&calls),
        inner: ObservationBoundary::current("resolved-before-store-cas"),
    };
    let error = stale_engine
        .record_proposal(
            &expected,
            ObservationRefV1::from_digest(digest("stale-observation")),
            proposal("stale-work"),
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 2,
        )
        .unwrap_err();
    let advanced = stale_engine.current().unwrap();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Store(CampaignStoreErrorV1::StalePredecessor {
            expected: stale_expected,
            authoritative,
        }) if stale_expected == expected && authoritative == *advanced.state_digest()
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(observation.inner.calls, 1);
    assert_eq!(
        advanced.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert_eq!(advanced.state().meta().budget().probes_used, 1);
    assert!(advanced.proposal().is_none());
    assert_eq!(stale_engine.replay().unwrap().transitions, 2);
}

#[test]
fn exact_reconciliation_and_settlement_replay_are_idempotent_but_substitution_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 6)
        .unwrap()
    else {
        panic!("indeterminate outcome must enter reconciliation")
    };
    let transition_count = engine.replay().unwrap().transitions;
    let replay = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 7)
        .unwrap();
    assert_eq!(
        replay,
        DocketProgressV1::ReconciliationRequired(reconciling.clone())
    );
    assert_eq!(engine.replay().unwrap().transitions, transition_count);

    {
        let mut shared = docket.shared.lock().unwrap();
        let FakeAttemptState::Indeterminate(custody, mut evidence) =
            shared.attempts.get(&issuance).cloned().unwrap()
        else {
            unreachable!()
        };
        evidence.evidence = digest("substituted-unknown");
        evidence.reconciliation =
            ReconciliationRefV1::from_digest(digest("substituted-reconciliation"));
        shared.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Indeterminate(custody, evidence),
        );
    }
    assert!(
        engine
            .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 8)
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), reconciling);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine
        .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 9)
        .unwrap()
    else {
        panic!("known reconciliation must settle")
    };
    let settled_transition_count = engine.replay().unwrap().transitions;
    assert_eq!(
        engine
            .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 10)
            .unwrap(),
        DocketProgressV1::Settled(settled.clone())
    );
    assert_eq!(
        engine.replay().unwrap().transitions,
        settled_transition_count
    );

    {
        let mut shared = docket.shared.lock().unwrap();
        let FakeAttemptState::Settled(custody, mut settlement) =
            shared.attempts.get(&issuance).cloned().unwrap()
        else {
            unreachable!()
        };
        settlement.receipt = ReceiptRefV1::from_digest(digest("substituted-receipt"));
        shared.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Settled(custody, settlement),
        );
    }
    assert!(
        engine
            .poll_docket(&current_state_digest(&engine), &mut docket, NOW + 11)
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), settled);
}

#[test]
fn concurrent_settlement_ingestion_has_one_legal_successor() {
    #[derive(Clone)]
    struct BarrierDocket {
        response: DocketIssuanceReconciliationV1,
        barrier: Arc<Barrier>,
    }

    impl DocketCustodyPortV1 for BarrierDocket {
        fn accept_issuance(
            &mut self,
            _issuance: &AgIssuanceV2,
        ) -> Result<DocketIssuanceAcceptanceV1, ExternalBoundaryErrorV1> {
            unreachable!()
        }

        fn reconcile_issuance(
            &mut self,
            _issuance: &AgIssuanceV2,
        ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
            unreachable!()
        }

        fn reconcile_attempt(
            &mut self,
            _issuance: &AgIssuanceV2,
            _custody: &DocketCustodyV1,
        ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
            self.barrier.wait();
            Ok(self.response.clone())
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine
        .dispatch(&current_state_digest(&engine), &mut docket, NOW + 5)
        .unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let response = {
        let shared = docket.shared.lock().unwrap();
        FakeDocket::response_for(&shared, &issuance)
    };
    drop(engine);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let barrier = Arc::clone(&barrier);
        let response = response.clone();
        handles.push(std::thread::spawn(move || {
            let mut engine = CampaignEngineV1::open(&database).unwrap();
            let expected = current_state_digest(&engine);
            engine
                .poll_docket(&expected, &mut BarrierDocket { response, barrier }, NOW + 6)
                .is_ok()
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| **result).count(), 1);
    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.replay().unwrap().settlements, 1);
    assert_eq!(
        reopened.current().unwrap().program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
}

#[test]
fn concurrent_authorization_consumes_exactly_one_ag_spend() {
    struct BarrierObservation {
        inner: ObservationBoundary,
        barrier: Arc<Barrier>,
    }

    impl ObservationResolverV1 for BarrierObservation {
        fn resolve_observation(
            &mut self,
            request: &ObservationResolutionRequestV1<'_>,
        ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1> {
            self.barrier.wait();
            self.inner.resolve_observation(request)
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("preconditions");
    let mut standing = StandingBoundary::current();
    engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 1,
        )
        .unwrap();
    engine
        .require_standing(&current_state_digest(&engine), NOW + 2)
        .unwrap();
    engine
        .decide(
            &current_state_digest(&engine),
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            NOW + 3,
        )
        .unwrap();
    drop(engine);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let mut engine = CampaignEngineV1::open(&database).unwrap();
            let expected = current_state_digest(&engine);
            engine
                .authorize(
                    &expected,
                    &mut BarrierObservation {
                        inner: ObservationBoundary::current("preconditions"),
                        barrier,
                    },
                    &mut StandingBoundary::current(),
                    &catalog(),
                    None,
                    NOW + 4,
                )
                .is_ok()
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| **result).count(), 1);
    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
    assert_eq!(
        reopened.current().unwrap().program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the end-to-end exact-scope successor specimen keeps all bindings visible"
)]
fn governed_scope_expansion_is_durable_exact_one_use_and_opens_only_new_occurrence() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("precondition-a");
    let proposed = proposal("work-1");
    let original_scope = proposed.effect_scope().clone();
    engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-repair")),
            proposed,
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 1,
        )
        .unwrap();
    let halted = engine
        .halt(
            &current_state_digest(&engine),
            HaltReasonRefV1::from_digest(digest("scope-insufficient")),
            NOW + 2,
        )
        .unwrap();
    let delta = CanonicalEffectScopeV1::new(
        original_scope.effect_class().to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "fixtures/required-adjacent".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let requirement = HumanDecisionRequirementV1::ScopeExpansion(ScopeExpansionRequiredV1 {
        schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
        original_scope: original_scope.clone(),
        original_scope_digest: original_scope.digest(),
        requested_delta: delta.clone(),
        requested_delta_digest: delta.digest(),
        blocked_operation: BlockedEffectOperationV1 {
            resource: "repository".to_owned(),
            path: "fixtures/required-adjacent".to_owned(),
            operation: CanonicalEffectOperationV1::Modify,
        },
        reason: digest("blocked-operation"),
        dependency_evidence: sorted_digests(&["dependency-a", "dependency-b"]),
        limitations: sorted_digests(&["limitation-a"]),
        docket_outcome: None,
        no_unauthorized_effect_reported: true,
    });
    let profile = GovernedRepairVerifierProfileV1 {
        profile: digest("qualification-fixture-not-human-authority-profile"),
        root: digest("qualification-fixture-not-human-authority-root"),
        executable: digest("qualification-fixture-not-human-authority-executable"),
        principal: HumanPrincipalRefV1::from_digest(digest("repair-principal")),
        mandate: MandateRefV1::from_digest(digest("repair-mandate")),
    };
    let request = engine
        .create_governed_repair_request(
            halted.state_digest(),
            requirement,
            profile.profile.clone(),
            profile.root.clone(),
            profile.executable.clone(),
            sorted_digests(&["approve-consequence", "reject-consequence"]),
            sorted_digests(&["not-standing", "not-qualification"]),
            digest("request-idempotency"),
            NOW + 3,
            NOW + 100,
        )
        .unwrap();
    assert_eq!(engine.replay().unwrap().human_decision_requests, 1);
    let checkpoint = repair_checkpoint("scope");
    let successor_scope = original_scope.exact_union(&delta).unwrap();
    let artifact = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::ApproveExactExpansion {
            request: request.reference(),
            successor_occurrence: occurrence(2),
            approved_delta: delta,
            successor_scope: successor_scope.clone(),
            checkpoint: checkpoint.clone(),
        },
        decision: HumanDecisionIdV1::from_digest(digest("repair-decision")),
        principal: profile.principal.clone(),
        mandate: profile.mandate.clone(),
        verifier_profile: profile.profile.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("repair-nonce")),
        expires_at_unix_ms: NOW + 90,
    };
    let mut verifier = QualificationFixtureNotHumanAuthority;
    let GovernedRepairDispositionEffectV1::OpenedSuccessor {
        halted: consumed_halt,
        successor,
        ..
    } = GovernedLoopKernelV1::apply_governed_repair_disposition(
        &halted,
        &request,
        artifact.clone(),
        &profile,
        &mut verifier,
        NOW + 4,
    )
    .unwrap()
    else {
        panic!("approval must open a distinct successor")
    };
    assert_eq!(successor.key().occurrence, occurrence(2));
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(successor.ag_spend().is_none());
    assert!(
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &consumed_halt,
            &request,
            artifact,
            &profile,
            &mut verifier,
            NOW + 5,
        )
        .is_err()
    );
    let hostile = ExactWorkProposalV1::new(
        campaign(),
        digest("subject"),
        original_scope,
        "test.engine-work/v1".to_owned(),
        digest("hostile-work"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap()
    .with_governed_repair_checkpoint(checkpoint.clone())
    .unwrap();
    assert!(
        GovernedLoopKernelV1::record_proposal(
            &successor,
            ObservationRefV1::from_digest(digest("observation-hostile")),
            hostile,
            ProposalClassV1::Successor,
            &mut ObservationBoundary::current("fresh"),
            NOW + 6,
        )
        .is_err()
    );
    let legal = ExactWorkProposalV1::new(
        campaign(),
        digest("subject"),
        successor_scope,
        "test.engine-work/v1".to_owned(),
        digest("successor-work"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap()
    .with_governed_repair_checkpoint(checkpoint)
    .unwrap();
    let recorded = GovernedLoopKernelV1::record_proposal(
        &successor,
        ObservationRefV1::from_digest(digest("observation-successor")),
        legal,
        ProposalClassV1::Successor,
        &mut ObservationBoundary::current("fresh"),
        NOW + 7,
    )
    .unwrap();
    assert_eq!(
        recorded.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    assert!(
        recorded.ag_spend().is_none(),
        "fresh standing/spend remain due"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the hostile readjudication specimen keeps collision and expiry checks together"
)]
fn governed_request_collision_expiry_profile_and_readjudication_mutation_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("precondition-b");
    let proposed = proposal("work-2");
    engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-readjudication")),
            proposed,
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 1,
        )
        .unwrap();
    let halted = engine
        .halt(
            &current_state_digest(&engine),
            HaltReasonRefV1::from_digest(digest("normative-gap")),
            NOW + 2,
        )
        .unwrap();
    let read_scope = CanonicalEffectScopeV1::new(
        "adjudication".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "evidence".to_owned(),
            path: "reviews/exact-record.json".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Read],
        }],
    )
    .unwrap();
    let requirement = HumanDecisionRequirementV1::Readjudication(ReadjudicationRequiredV1 {
        schema: READJUDICATION_REQUIRED_SCHEMA_V1.to_owned(),
        question: digest("question"),
        evidence_census: sorted_digests(&["evidence-a"]),
        diagnostic_census: sorted_digests(&["diagnostic-a"]),
        bounded_alternatives: sorted_digests(&["alternative-a"]),
        unresolved_facts: sorted_digests(&["fact-a"]),
        limitations: sorted_digests(&["limitation-a"]),
        adjudication_scope: read_scope.clone(),
        docket_outcome: None,
        no_unauthorized_effect_reported: true,
    });
    let profile = GovernedRepairVerifierProfileV1 {
        profile: digest("qualification-fixture-not-human-authority-profile-r"),
        root: digest("qualification-fixture-not-human-authority-root-r"),
        executable: digest("qualification-fixture-not-human-authority-executable-r"),
        principal: HumanPrincipalRefV1::from_digest(digest("principal-r")),
        mandate: MandateRefV1::from_digest(digest("mandate-r")),
    };
    let request = engine
        .create_governed_repair_request(
            halted.state_digest(),
            requirement,
            profile.profile.clone(),
            profile.root.clone(),
            profile.executable.clone(),
            sorted_digests(&["readjudicate-consequence", "reject-consequence-r"]),
            sorted_digests(&["not-repair-authority"]),
            digest("same-idempotency"),
            NOW + 3,
            NOW + 20,
        )
        .unwrap();
    assert!(
        engine
            .create_governed_repair_request(
                halted.state_digest(),
                request.requirement.clone(),
                profile.profile.clone(),
                profile.root.clone(),
                profile.executable.clone(),
                request.decision_consequences.clone(),
                request.nonclaims.clone(),
                digest("same-idempotency"),
                NOW + 3,
                NOW + 21,
            )
            .is_err(),
        "same idempotency key with changed bytes must collide"
    );

    let checkpoint = repair_checkpoint("readjudication");
    let artifact = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::RequestReadjudication {
            request: request.reference(),
            successor_occurrence: occurrence(3),
            successor_program: ProgramBasisRefV1::from_digest(digest("adjudicator-program")),
            checkpoint: checkpoint.clone(),
        },
        decision: HumanDecisionIdV1::from_digest(digest("decision-r")),
        principal: profile.principal.clone(),
        mandate: profile.mandate.clone(),
        verifier_profile: digest("wrong-profile"),
        nonce: HumanNonceRefV1::from_digest(digest("nonce-r")),
        expires_at_unix_ms: NOW + 19,
    };
    let mut verifier = QualificationFixtureNotHumanAuthority;
    assert!(
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &halted,
            &request,
            artifact.clone(),
            &profile,
            &mut verifier,
            NOW + 4,
        )
        .is_err()
    );
    let mut exact = artifact;
    exact.verifier_profile = profile.profile.clone();
    assert!(
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &halted,
            &request,
            exact.clone(),
            &profile,
            &mut verifier,
            NOW + 20,
        )
        .is_err(),
        "expiry must fail closed"
    );
    let GovernedRepairDispositionEffectV1::OpenedSuccessor { successor, .. } =
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &halted,
            &request,
            exact,
            &profile,
            &mut verifier,
            NOW + 5,
        )
        .unwrap()
    else {
        panic!("readjudication must open a distinct successor")
    };
    let mutation_scope = CanonicalEffectScopeV1::new(
        "adjudication".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "evidence".to_owned(),
            path: "reviews/exact-record.json".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let hostile = ExactWorkProposalV1::new(
        campaign(),
        digest("subject"),
        mutation_scope,
        "test.engine-work/v1".to_owned(),
        digest("readjudication-mutation"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap()
    .with_governed_repair_checkpoint(checkpoint)
    .unwrap();
    assert!(
        GovernedLoopKernelV1::record_proposal(
            &successor,
            ObservationRefV1::from_digest(digest("readjudication-observation")),
            hostile,
            ProposalClassV1::Successor,
            &mut ObservationBoundary::current("fresh-r"),
            NOW + 6,
        )
        .is_err()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the terminal rejection specimen retains the complete residual/request chain"
)]
fn governed_repair_rejection_is_terminal_halted_with_exact_residual() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current("precondition-reject");
    let proposed = proposal("work-reject");
    let original_scope = proposed.effect_scope().clone();
    engine
        .record_proposal(
            &current_state_digest(&engine),
            ObservationRefV1::from_digest(digest("observation-reject")),
            proposed,
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 1,
        )
        .unwrap();
    let halted = engine
        .halt(
            &current_state_digest(&engine),
            HaltReasonRefV1::from_digest(digest("reject-halt")),
            NOW + 2,
        )
        .unwrap();
    let delta = CanonicalEffectScopeV1::new(
        original_scope.effect_class().to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "fixtures/rejected".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let requirement = HumanDecisionRequirementV1::ScopeExpansion(ScopeExpansionRequiredV1 {
        schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
        original_scope: original_scope.clone(),
        original_scope_digest: original_scope.digest(),
        requested_delta: delta.clone(),
        requested_delta_digest: delta.digest(),
        blocked_operation: BlockedEffectOperationV1 {
            resource: "repository".to_owned(),
            path: "fixtures/rejected".to_owned(),
            operation: CanonicalEffectOperationV1::Modify,
        },
        reason: digest("reject-requirement"),
        dependency_evidence: sorted_digests(&["reject-dependency"]),
        limitations: sorted_digests(&["reject-limitation"]),
        docket_outcome: None,
        no_unauthorized_effect_reported: true,
    });
    let profile = GovernedRepairVerifierProfileV1 {
        profile: digest("qualification-fixture-not-human-authority-profile-reject"),
        root: digest("qualification-fixture-not-human-authority-root-reject"),
        executable: digest("qualification-fixture-not-human-authority-executable-reject"),
        principal: HumanPrincipalRefV1::from_digest(digest("principal-reject")),
        mandate: MandateRefV1::from_digest(digest("mandate-reject")),
    };
    let request = engine
        .create_governed_repair_request(
            halted.state_digest(),
            requirement,
            profile.profile.clone(),
            profile.root.clone(),
            profile.executable.clone(),
            sorted_digests(&["approve-reject", "reject-reject"]),
            sorted_digests(&["reject-nonclaim"]),
            digest("reject-idempotency"),
            NOW + 3,
            NOW + 50,
        )
        .unwrap();
    let artifact = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::Reject {
            request: request.reference(),
            reason: digest("human-rejection"),
        },
        decision: HumanDecisionIdV1::from_digest(digest("reject-decision")),
        principal: profile.principal.clone(),
        mandate: profile.mandate.clone(),
        verifier_profile: profile.profile.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("reject-nonce")),
        expires_at_unix_ms: NOW + 40,
    };
    let GovernedRepairDispositionEffectV1::Rejected { halted: closed, .. } =
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &halted,
            &request,
            artifact,
            &profile,
            &mut QualificationFixtureNotHumanAuthority,
            NOW + 4,
        )
        .unwrap()
    else {
        panic!("rejection must not open a successor")
    };
    assert!(closed.halted().unwrap().governed_repair_closed().is_some());
    assert_eq!(closed.state().meta().residuals().len(), 1);
    assert!(
        GovernedLoopKernelV1::create_human_decision_request(
            &closed,
            HumanDecisionRequestParametersV1 {
                requirement: request.requirement,
                required_verifier_profile: profile.profile,
                required_verifier_root: profile.root,
                required_verifier_executable: profile.executable,
                decision_consequences: request.decision_consequences,
                nonclaims: request.nonclaims,
                idempotency_key: digest("second-request"),
                created_at_unix_ms: NOW + 5,
                expires_at_unix_ms: NOW + 60,
            },
        )
        .is_err()
    );
}
