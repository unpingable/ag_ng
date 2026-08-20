//! Production-engine tests spanning live boundaries, `SQLite` state, Docket
//! custody, restart, reconciliation, continuation, and human disposition.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Barrier, Mutex};

use ag_app::governed_loop::{
    CampaignEngineErrorV1, CampaignEngineV1, CampaignRecoveryV1, DocketProgressV1,
    EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1, WorkPreconditionV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use tempfile::TempDir;
use uuid::Uuid;

const NOW: u64 = 30_000;
/// The resolver identity these tests configure the engine to expect.
const OBSERVATION_RESOLVER_ID: &str = "test.observation-resolver/v1";
/// The standing resolver identity these tests configure the engine to expect.
const STANDING_RESOLVER_ID: &str = "test.standing-resolver/v1";
/// Maximum accepted standing-answer lifetime in these tests.
const MAX_STANDING_TTL_MS: u64 = 60_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-engine-test/v1", label.as_bytes())
}

fn decision_basis(condition: &str, delivery: &str) -> DecisionBasisV1 {
    DecisionBasisV1 {
        schema: DECISION_BASIS_SCHEMA_V1.to_owned(),
        rule: DecisionBasisRuleV1 {
            id: DECISION_BASIS_RULE_ID_V1.to_owned(),
            version: DECISION_BASIS_RULE_VERSION_V1.to_owned(),
            digest: decision_basis_rule_digest_v1().as_str().to_owned(),
        },
        atoms: BTreeSet::from([condition.to_owned(), delivery.to_owned()]),
    }
}

fn clean_basis() -> DecisionBasisV1 {
    decision_basis("condition.clean", "delivery.not_required")
}

fn changed_basis() -> DecisionBasisV1 {
    decision_basis("condition.condition_present", "delivery.qualified")
}

fn failed_delivery_basis() -> DecisionBasisV1 {
    decision_basis("condition.clean", "delivery.failed")
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
    ExactWorkProposalV1::new(
        campaign(),
        digest("subject"),
        digest("scope"),
        "test.engine-work/v1".to_owned(),
        digest(label),
        None,
    )
    .unwrap()
}

fn catalog() -> ExactWorkCatalogV1 {
    catalog_with(WorkPreconditionV1::default())
}

/// A catalog whose single entry matches the test proposal and carries the
/// given finite workflow precondition. Its policy identity is derived from
/// its content; tests compare provenance against `catalog.policy_basis()`.
fn catalog_with(precondition: WorkPreconditionV1) -> ExactWorkCatalogV1 {
    ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            "test.engine-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.engine-work/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                precondition,
            },
        )]),
    }
}

/// A finite workflow precondition over frozen v1 basis atoms.
fn precondition(required: &[&str], forbidden: &[&str]) -> WorkPreconditionV1 {
    WorkPreconditionV1 {
        required: required.iter().map(|atom| (*atom).to_owned()).collect(),
        forbidden: forbidden.iter().map(|atom| (*atom).to_owned()).collect(),
    }
}

/// A valid catalog whose only entry matches a different work schema, so the
/// proposal used in these tests is outside its admitted set.
fn refusing_catalog() -> ExactWorkCatalogV1 {
    ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            "test.other-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.other-work/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                precondition: WorkPreconditionV1::default(),
            },
        )]),
    }
}

#[derive(Clone)]
struct ObservationBoundary {
    basis: DecisionBasisV1,
    status: ObservationStatusV1,
    calls: usize,
}

impl ObservationBoundary {
    fn current(basis: DecisionBasisV1) -> Self {
        Self {
            basis,
            status: ObservationStatusV1::Current,
            calls: 0,
        }
    }
}

impl ObservationResolverV1 for ObservationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV2, ExternalBoundaryErrorV1> {
        self.calls += 1;
        Ok(ObservationResolutionV2 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V2.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest(&format!(
                "observation-current-{}",
                self.calls
            ))),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                self.basis.decision_basis_digest().unwrap(),
            ),
            basis: self.basis.clone(),
            resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
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
    available: bool,
    calls: usize,
}

impl StandingBoundary {
    fn current() -> Self {
        Self {
            status: StandingStatusV1::Current,
            available: true,
            calls: 0,
        }
    }
}

impl StandingResolverV1 for StandingBoundary {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        self.calls += 1;
        if !self.available {
            return Err(ExternalBoundaryErrorV1::Unavailable {
                code: "standing-resolver-unavailable".to_owned(),
            });
        }
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
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
            resolver_id: STANDING_RESOLVER_ID.to_owned(),
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
    fn custody(issuance: &AgIssuanceV1) -> DocketCustodyV1 {
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
        let settlement = DocketSettlementV1 {
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
            settled_at_unix_ms: NOW + 20,
        };
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
        }
    }
}

impl DocketCustodyPortV1 for FakeDocket {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
        let mut state = self.shared.lock().unwrap();
        state.accept_calls += 1;
        let custody = match state.attempts.get(&issuance.issuance) {
            Some(
                FakeAttemptState::Accepted(custody)
                | FakeAttemptState::Settled(custody, _)
                | FakeAttemptState::Indeterminate(custody, _),
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
        Ok(custody)
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        let state = self.shared.lock().unwrap();
        Ok(Self::response_for(&state, &issuance.issuance))
    }

    fn reconcile_attempt(
        &mut self,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        let state = self.shared.lock().unwrap();
        let response = Self::response_for(&state, &custody.issuance);
        match &response {
            DocketIssuanceReconciliationV1::Accepted(actual)
            | DocketIssuanceReconciliationV1::Settled {
                custody: actual, ..
            }
            | DocketIssuanceReconciliationV1::Indeterminate {
                custody: actual, ..
            } if actual == custody => Ok(response),
            _ => Err(ExternalBoundaryErrorV1::Refused {
                code: "wrong-custody".to_owned(),
                evidence: None,
            }),
        }
    }
}

struct HumanVerifier;

impl HumanDispositionVerifierV1 for HumanVerifier {
    fn verify_human_disposition(
        &mut self,
        request: &HumanDispositionVerificationRequestV1<'_>,
    ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1> {
        Ok(HumanVerificationRefV1::from_digest(Digest::hash_domain(
            "ag-governed-engine-test/human-verification/v1",
            request.artifact.nonce.as_str().as_bytes(),
        )))
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
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine
        .decide(
            observation,
            standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    engine
        .authorize(
            observation,
            standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap()
}

#[test]
fn recording_a_proposal_is_informational_and_evaluates_no_catalog_policy() {
    // REGRESSION PIN (WO-1, pre-change semantics): proposal existence does
    // not imply admissibility. `record_proposal` takes no catalog/policy
    // input at all: evidence health is resolved, but no admissibility or
    // workflow-policy judgment is possible during recording, no authority
    // artifact is minted, and the occurrence does not advance past
    // ProposalRecorded. The first policy judgment happens at `decide`.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();

    let recorded = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(
        recorded.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    assert!(recorded.ag_spend().is_none());
    assert!(recorded.issuance().is_none());
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
    assert_eq!(observation.calls, 1);

    // A catalog that refuses this exact work is only consulted now, at
    // `decide`; its refusal cannot retroactively un-record the proposal and
    // preserves the current state.
    engine.require_standing(NOW + 2).unwrap();
    let before = engine.current().unwrap();
    assert!(
        engine
            .decide(
                &mut observation,
                &mut standing,
                &refusing_catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 3,
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);

    // The identical recorded proposal is admitted once the consulted policy
    // matches: recording was never the gate.
    let admitted = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    assert_eq!(
        admitted.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    assert!(admitted.ag_spend().is_none());
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn production_path_spends_once_settles_and_requires_a_new_occurrence() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
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
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    assert_eq!(dispatched.program_counter(), ProgramCounterV1::Dispatched);
    assert_eq!(docket.accept_calls(), 1);
    assert!(engine.dispatch(&mut docket, NOW + 6).is_err());
    assert_eq!(docket.accept_calls(), 1);

    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut docket, NOW + 7).unwrap()
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
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 8
            )
            .is_err()
    );

    let next = engine.open_continuation(occurrence(2), NOW + 9).unwrap();
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
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    let before = engine.current().unwrap();

    observation.status = ObservationStatusV1::Stale;
    assert!(
        engine
            .authorize(
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 4
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
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 5
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn custody_crash_recovers_to_reconciliation_without_respend_or_repeat() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let spent = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let issuance = spent.issuance().unwrap().issuance.clone();

    let mut docket = FakeDocket::default();
    docket.set_panic_after_accept();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = engine.dispatch(&mut docket, NOW + 5);
        }))
        .is_err()
    );
    drop(engine);

    let mut recovered = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        recovered.current().unwrap().program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    let CampaignRecoveryV1::Advanced(reconciling) =
        recovered.recover(&mut docket, NOW + 6).unwrap()
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
    let CampaignRecoveryV1::Advanced(settled) = recovered.recover(&mut docket, NOW + 7).unwrap()
    else {
        panic!("exact reconciliation must settle")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(recovered.replay().unwrap().settlements, 1);
}

#[test]
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
    let mut observation = ObservationBoundary::current(clean_basis());
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    engine.require_standing(NOW + 2).unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::StandingRequired
    );
    let mut standing = StandingBoundary::current();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
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
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    drop(engine);

    let mut docket = FakeDocket::default();
    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert!(matches!(
        engine.recover(&mut docket, NOW + 5).unwrap(),
        CampaignRecoveryV1::IssuanceNotAccepted(_)
    ));
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    let dispatched = engine.dispatch(&mut docket, NOW + 6).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::Dispatched
    );
    let CampaignRecoveryV1::Advanced(reconciling) = engine.recover(&mut docket, NOW + 7).unwrap()
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
    let CampaignRecoveryV1::Advanced(settled) = engine.recover(&mut docket, NOW + 8).unwrap()
    else {
        panic!("exact Docket settlement must close reconciliation")
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
    let next = engine.open_continuation(occurrence(2), NOW + 9).unwrap();
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
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    docket.settle(
        &dispatched.issuance().unwrap().issuance,
        KnownOutcomeV1::Failure,
    );
    let _ = engine.poll_docket(&mut docket, NOW + 6).unwrap();
    engine.open_continuation(occurrence(2), NOW + 7).unwrap();

    observation.basis = changed_basis();
    let error = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-1"),
            ProposalClassV1::Retry,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
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
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-2"),
            ProposalClassV1::Successor,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
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
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) =
        engine.poll_docket(&mut docket, NOW + 6).unwrap()
    else {
        panic!("unknown outcome must reconcile")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert!(engine.dispatch(&mut docket, NOW + 7).is_err());
    assert!(engine.open_continuation(occurrence(2), NOW + 8).is_err());
    assert_eq!(docket.accept_calls(), 1);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut docket, NOW + 9).unwrap()
    else {
        panic!("reconciliation settlement must be consumed")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
}

#[test]
fn human_return_is_one_use_and_opens_only_an_authority_empty_occurrence() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("operator-required")),
            NOW + 1,
        )
        .unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ReturnToObservation,
        decision: HumanDecisionIdV1::from_digest(digest("decision")),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("nonce")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let HumanDispositionEffectV1::OpenedOccurrence {
        halted: consumed_halt,
        successor,
        ..
    } = engine
        .apply_human_disposition(
            artifact,
            &scope,
            Some(occurrence(2)),
            &mut ObservationBoundary::current(clean_basis()),
            OBSERVATION_RESOLVER_ID,
            &mut HumanVerifier,
            NOW + 2,
        )
        .unwrap()
    else {
        panic!("return disposition must open an occurrence")
    };
    assert_eq!(consumed_halt.program_counter(), ProgramCounterV1::Halted);
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(successor.ag_spend().is_none());
    assert_eq!(successor.key().occurrence, occurrence(2));
    assert_eq!(engine.current().unwrap(), successor);
    assert_eq!(engine.replay().unwrap().transitions, 4);
    drop(engine);

    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), successor);
    assert_eq!(reopened.replay().unwrap().transitions, 4);
}

#[test]
fn residual_discharge_is_exact_durable_and_nonce_one_shot() {
    let directory = tempfile::tempdir().unwrap();
    let residual = ResidualObligationV1 {
        residual: ResidualIdV1::from_digest(digest("residual-1")),
        owner: digest("residual-owner"),
        subject: digest("residual-subject"),
        statement: digest("residual-statement"),
    };
    let mut engine = create_engine(
        &directory,
        ResidualSetV1::new(vec![residual.clone()]).unwrap(),
    );
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("residual-disposition-required")),
            NOW + 1,
        )
        .unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("residual-principal")),
        mandate: MandateRefV1::from_digest(digest("residual-mandate")),
    };
    let decision = HumanDecisionIdV1::from_digest(digest("residual-decision"));
    let nonce = HumanNonceRefV1::from_digest(digest("residual-nonce"));
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ExactResidualDisposition(ExactResidualDischargeV1 {
            campaign: campaign(),
            occurrence: occurrence(1),
            program: ProgramBasisRefV1::from_digest(digest("program")),
            authority: ResidualAuthorityRefV1::from_digest(digest("residual-authority")),
            disposition: decision.clone(),
            before: vec![residual.residual.clone()],
            authorized: vec![residual.residual.clone()],
            closed: vec![residual.residual.clone()],
            after: Vec::new(),
        }),
        decision,
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: nonce.clone(),
        expires_at_unix_ms: NOW + 1_000,
    };
    let HumanDispositionEffectV1::Updated {
        snapshot: cleared, ..
    } = engine
        .apply_human_disposition(
            artifact,
            &scope,
            None,
            &mut ObservationBoundary::current(clean_basis()),
            OBSERVATION_RESOLVER_ID,
            &mut HumanVerifier,
            NOW + 2,
        )
        .unwrap()
    else {
        panic!("exact residual discharge must remain halted")
    };
    assert!(cleared.state().meta().residuals().is_empty());
    assert_eq!(engine.replay().unwrap().human_dispositions, 1);

    let second_decision = HumanDecisionIdV1::from_digest(digest("second-decision"));
    let replayed_nonce = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: cleared.state_digest().clone(),
        disposition: HumanDispositionKindV1::ExactResidualDisposition(ExactResidualDischargeV1 {
            campaign: campaign(),
            occurrence: occurrence(1),
            program: ProgramBasisRefV1::from_digest(digest("program")),
            authority: ResidualAuthorityRefV1::from_digest(digest("residual-authority-2")),
            disposition: second_decision.clone(),
            before: Vec::new(),
            authorized: Vec::new(),
            closed: Vec::new(),
            after: Vec::new(),
        }),
        decision: second_decision,
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce,
        expires_at_unix_ms: NOW + 1_000,
    };
    assert!(
        engine
            .apply_human_disposition(
                replayed_nonce,
                &scope,
                None,
                &mut ObservationBoundary::current(clean_basis()),
                OBSERVATION_RESOLVER_ID,
                &mut HumanVerifier,
                NOW + 3,
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), cleared);
    assert_eq!(engine.replay().unwrap().human_dispositions, 1);
}

#[test]
fn durable_budget_fact_is_nonauthorizing_and_exhaustion_halts() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let observed = engine.note_probe(NOW + 1).unwrap();
    assert_eq!(
        observed.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert_eq!(observed.state().meta().budget().probes_used, 1);
    assert!(observed.ag_spend().is_none());

    let halted = engine.note_probe(NOW + 2).unwrap();
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
fn exact_reconciliation_and_settlement_replay_are_idempotent_but_substitution_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) =
        engine.poll_docket(&mut docket, NOW + 6).unwrap()
    else {
        panic!("indeterminate outcome must enter reconciliation")
    };
    let transition_count = engine.replay().unwrap().transitions;
    let replay = engine.poll_docket(&mut docket, NOW + 7).unwrap();
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
    assert!(engine.poll_docket(&mut docket, NOW + 8).is_err());
    assert_eq!(engine.current().unwrap(), reconciling);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut docket, NOW + 9).unwrap()
    else {
        panic!("known reconciliation must settle")
    };
    let settled_transition_count = engine.replay().unwrap().transitions;
    assert_eq!(
        engine.poll_docket(&mut docket, NOW + 10).unwrap(),
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
    assert!(engine.poll_docket(&mut docket, NOW + 11).is_err());
    assert_eq!(engine.current().unwrap(), settled);
}

#[test]
fn human_disposition_binding_attacks_and_direct_dispatch_refuse_without_transition() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("human-required")),
            NOW + 1,
        )
        .unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ReturnToObservation,
        decision: HumanDecisionIdV1::from_digest(digest("binding-decision")),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("binding-nonce")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let attacks = [
        HumanDispositionV1 {
            campaign: CampaignId::from_digest(digest("wrong-campaign")),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            occurrence: occurrence(9),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            halted_state_digest: digest("wrong-halted-state"),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            principal: HumanPrincipalRefV1::from_digest(digest("wrong-principal")),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            mandate: MandateRefV1::from_digest(digest("wrong-mandate")),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            expires_at_unix_ms: NOW + 1,
            ..artifact
        },
    ];
    for attack in attacks {
        assert!(
            engine
                .apply_human_disposition(
                    attack,
                    &scope,
                    Some(occurrence(2)),
                    &mut ObservationBoundary::current(clean_basis()),
                    OBSERVATION_RESOLVER_ID,
                    &mut HumanVerifier,
                    NOW + 2,
                )
                .is_err()
        );
        assert_eq!(engine.current().unwrap(), halted);
    }
    let mut docket = FakeDocket::default();
    assert!(engine.dispatch(&mut docket, NOW + 3).is_err());
    assert_eq!(docket.accept_calls(), 0);
    assert_eq!(engine.replay().unwrap().human_dispositions, 0);
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
            _issuance: &AgIssuanceV1,
        ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
            unreachable!()
        }

        fn reconcile_issuance(
            &mut self,
            _issuance: &AgIssuanceV1,
        ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
            unreachable!()
        }

        fn reconcile_attempt(
            &mut self,
            _custody: &DocketCustodyV1,
        ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
            self.barrier.wait();
            Ok(self.response.clone())
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
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
            engine
                .poll_docket(&mut BarrierDocket { response, barrier }, NOW + 6)
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
        ) -> Result<ObservationResolutionV2, ExternalBoundaryErrorV1> {
            self.barrier.wait();
            self.inner.resolve_observation(request)
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
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
            engine
                .authorize(
                    &mut BarrierObservation {
                        inner: ObservationBoundary::current(clean_basis()),
                        barrier,
                    },
                    &mut StandingBoundary::current(),
                    &catalog(),
                    None,
                    OBSERVATION_RESOLVER_ID,
                    STANDING_RESOLVER_ID,
                    MAX_STANDING_TTL_MS,
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
fn concurrent_human_resume_consumes_one_disposition_and_opens_one_occurrence() {
    struct BarrierVerifier(Arc<Barrier>);

    impl HumanDispositionVerifierV1 for BarrierVerifier {
        fn verify_human_disposition(
            &mut self,
            request: &HumanDispositionVerificationRequestV1<'_>,
        ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1> {
            self.0.wait();
            Ok(HumanVerificationRefV1::from_digest(Digest::hash_domain(
                "ag-governed-engine-test/concurrent-human/v1",
                request.artifact.decision.as_str().as_bytes(),
            )))
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("human-required")),
            NOW + 1,
        )
        .unwrap();
    drop(engine);
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ReturnToObservation,
        decision: HumanDecisionIdV1::from_digest(digest("concurrent-decision")),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("concurrent-nonce")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let barrier = Arc::clone(&barrier);
        let artifact = artifact.clone();
        let scope = scope.clone();
        handles.push(std::thread::spawn(move || {
            let mut engine = CampaignEngineV1::open(&database).unwrap();
            engine
                .apply_human_disposition(
                    artifact,
                    &scope,
                    Some(occurrence(2)),
                    &mut ObservationBoundary::current(clean_basis()),
                    OBSERVATION_RESOLVER_ID,
                    &mut BarrierVerifier(barrier),
                    NOW + 2,
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
    assert_eq!(reopened.replay().unwrap().human_dispositions, 1);
    assert_eq!(reopened.current().unwrap().key().occurrence, occurrence(2));
    assert!(reopened.current().unwrap().ag_spend().is_none());
}

/// Records a proposal and advances to the standing-required boundary with
/// the given observation basis.
fn advance_to_standing_required(
    engine: &mut CampaignEngineV1,
    observation: &mut ObservationBoundary,
) {
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
}

#[test]
fn rollout_precondition_refuses_a_condition_present_basis() {
    // T8: a rollout-style policy (`required = {condition.clean}`) refuses the
    // same condition-present basis a remediation policy admits in T9. The
    // refusal is policy refusal, the occurrence state is preserved, and no
    // authority artifact exists.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(changed_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let before = engine.current().unwrap();

    let error = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog_with(precondition(&["condition.clean"], &[])),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
    ));
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn remediation_precondition_admits_the_same_condition_present_basis() {
    // T9: there is no universal Clean rule. A remediation-style policy whose
    // required atom is `condition.condition_present` admits exactly the basis
    // T8's rollout policy refused.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(changed_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);

    let remediation = catalog_with(precondition(&["condition.condition_present"], &[]));
    let admitted = engine
        .decide(
            &mut observation,
            &mut standing,
            &remediation,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        admitted.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    // The recorded policy basis is the content-derived identity of the exact
    // catalog evaluated, not a caller-chosen label.
    assert_eq!(
        admitted.admission_decision().unwrap().policy_basis,
        remediation.policy_basis().unwrap()
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn forbidden_delivery_atom_refuses() {
    // T10: `forbidden ∩ basis ≠ ∅` refuses even when required atoms match.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(failed_delivery_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let before = engine.current().unwrap();

    let error = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog_with(precondition(&["condition.clean"], &["delivery.failed"])),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
    ));
    assert_eq!(engine.current().unwrap(), before);
}

#[test]
fn catalog_precondition_validation_rejects_overlap_and_unknown_atoms() {
    let overlap = catalog_with(precondition(&["condition.clean"], &["condition.clean"]));
    assert!(matches!(
        overlap.validate(),
        Err(CampaignEngineErrorV1::InvalidCatalog)
    ));
    let unknown = catalog_with(precondition(&["condition.perfectly_fine_honest"], &[]));
    assert!(matches!(
        unknown.validate(),
        Err(CampaignEngineErrorV1::InvalidCatalog)
    ));
    let unknown_forbidden = catalog_with(precondition(&[], &["delivery.mystery"]));
    assert!(matches!(
        unknown_forbidden.validate(),
        Err(CampaignEngineErrorV1::InvalidCatalog)
    ));
}

#[test]
fn omitted_precondition_is_unconditional_and_old_style_entries_parse() {
    // T11: an old-style three-field entry without `precondition` parses with
    // the defaulted unconditional precondition and admits any Current basis.
    let document = format!(
        "{{\"schema\":\"ag.governed-loop.exact-work-catalog/v1\",\"entries\":{{\"test.engine-work/v1\":{{\"work_schema\":\"test.engine-work/v1\",\"subject\":\"{}\",\"scope\":\"{}\"}}}}}}",
        digest("subject"),
        digest("scope"),
    );
    let catalog: ExactWorkCatalogV1 = serde_json::from_str(&document).unwrap();
    catalog.validate().unwrap();
    assert_eq!(
        catalog.entries["test.engine-work/v1"].precondition,
        WorkPreconditionV1::default()
    );

    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(changed_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
}

#[test]
fn a_catalog_document_cannot_assert_a_policy_identity() {
    // The wire has no `policy_basis` channel: a document carrying one —
    // the substitution-attack shape — is rejected at parse time, before any
    // judgment can run.
    let document = format!(
        "{{\"schema\":\"ag.governed-loop.exact-work-catalog/v1\",\"policy_basis\":\"{}\",\"entries\":{{\"test.engine-work/v1\":{{\"work_schema\":\"test.engine-work/v1\",\"subject\":\"{}\",\"scope\":\"{}\"}}}}}}",
        digest("forged-policy-identity"),
        digest("subject"),
        digest("scope"),
    );
    assert!(serde_json::from_str::<ExactWorkCatalogV1>(&document).is_err());
}

#[test]
fn equivalent_catalogs_have_one_policy_basis_and_semantic_changes_move_it() {
    let reference = catalog_with(precondition(&["condition.clean"], &["delivery.failed"]));
    let expected = reference.policy_basis().unwrap();

    // Entry/atom construction order is not semantic.
    let reordered = ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            "test.engine-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.engine-work/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                precondition: WorkPreconditionV1 {
                    required: BTreeSet::from(["condition.clean".to_owned()]),
                    forbidden: BTreeSet::from(["delivery.failed".to_owned()]),
                },
            },
        )]),
    };
    assert_eq!(reordered.policy_basis().unwrap(), expected);

    // Every admission-relevant field participates in the identity.
    let mut by_subject = reference.clone();
    by_subject
        .entries
        .values_mut()
        .for_each(|entry| entry.subject = digest("other-subject"));
    assert_ne!(by_subject.policy_basis().unwrap(), expected);
    let mut by_scope = reference.clone();
    by_scope
        .entries
        .values_mut()
        .for_each(|entry| entry.scope = digest("other-scope"));
    assert_ne!(by_scope.policy_basis().unwrap(), expected);
    let by_precondition = catalog_with(precondition(&["condition.clean"], &[]));
    assert_ne!(by_precondition.policy_basis().unwrap(), expected);
}

#[test]
fn tightened_catalog_before_spend_refuses_and_preserves_state() {
    // T13: catalog policy is present-tense at judgment. A proposal admitted
    // under unconditional V1 fails authorization once the current catalog
    // requires an atom its pinned basis does not contain. No spend occurs and
    // the occurrence remains admissible-pending.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    let before = engine.current().unwrap();

    let error = engine
        .authorize(
            &mut observation,
            &mut standing,
            &catalog_with(precondition(&["condition.condition_present"], &[])),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
    ));
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(
        before.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn loosened_catalog_before_spend_spends_under_the_current_policy_basis() {
    // T14: a looser current catalog governs the spend. The authorization
    // provenance names the content-derived V2 policy basis, not the V1 basis
    // that governed `decide`.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let v1 = catalog_with(precondition(&["condition.clean"], &[]));
    let admitted = engine
        .decide(
            &mut observation,
            &mut standing,
            &v1,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        admitted.admission_decision().unwrap().policy_basis,
        v1.policy_basis().unwrap()
    );

    let v2 = catalog_with(WorkPreconditionV1::default());
    assert_ne!(v1.policy_basis().unwrap(), v2.policy_basis().unwrap());
    let spent = engine
        .authorize(
            &mut observation,
            &mut standing,
            &v2,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    assert_eq!(
        spent.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert_eq!(
        spent.admission_decision().unwrap().policy_basis,
        v2.policy_basis().unwrap()
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn precondition_participates_in_the_derived_policy_basis() {
    // Provenance load-bearing: changing only an entry's precondition changes
    // the policy identity that judgment provenance records.
    let unconditional = catalog();
    let conditional = catalog_with(precondition(&["condition.clean"], &[]));
    assert_ne!(
        unconditional.policy_basis().unwrap(),
        conditional.policy_basis().unwrap()
    );
}

#[test]
fn standing_resolver_unavailable_at_decide_or_authorize_fails_closed() {
    // The standing boundary is a live external dependency at both judgment
    // points: unavailability refuses without state loss and without spend.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let before = engine.current().unwrap();

    standing.available = false;
    assert!(matches!(
        engine.decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        ),
        Err(CampaignEngineErrorV1::Kernel(KernelErrorV1::External(
            ExternalBoundaryErrorV1::Unavailable { .. }
        )))
    ));
    assert_eq!(engine.current().unwrap(), before);

    standing.available = true;
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    let admitted = engine.current().unwrap();

    standing.available = false;
    assert!(matches!(
        engine.authorize(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        ),
        Err(CampaignEngineErrorV1::Kernel(KernelErrorV1::External(
            ExternalBoundaryErrorV1::Unavailable { .. }
        )))
    ));
    assert_eq!(engine.current().unwrap(), admitted);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn revoked_standing_after_restart_still_blocks_spend() {
    // Fresh standing re-resolution at authorize is load-bearing across a
    // restart: the decide-time answer is never cached as sufficient.
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    drop(engine);

    let mut engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    standing.status = StandingStatusV1::Revoked;
    assert!(matches!(
        engine.authorize(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        ),
        Err(CampaignEngineErrorV1::Kernel(
            KernelErrorV1::StandingNotCurrent
        ))
    ));
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}
