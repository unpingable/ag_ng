//! Transactional, replay, concurrency, and restart tests for canonical campaign state.

use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};

use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use ag_store::campaign::{CampaignStoreErrorV1, CampaignStoreV1, CampaignTransitionKindV1};

const NOW: u64 = 20_000;
/// The resolver identity these tests configure the kernel to expect.
const OBSERVATION_RESOLVER_ID: &str = "test.observation-resolver/v1";
/// The standing resolver identity these tests configure the kernel to expect.
const STANDING_RESOLVER_ID: &str = "test.standing-resolver/v1";
/// Maximum accepted standing-answer lifetime in these tests.
const MAX_STANDING_TTL_MS: u64 = 60_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-store-test/v1", label.as_bytes())
}

fn clean_basis() -> DecisionBasisV1 {
    DecisionBasisV1 {
        schema: DECISION_BASIS_SCHEMA_V1.to_owned(),
        rule: DecisionBasisRuleV1 {
            id: DECISION_BASIS_RULE_ID_V1.to_owned(),
            version: DECISION_BASIS_RULE_VERSION_V1.to_owned(),
            digest: decision_basis_rule_digest_v1().as_str().to_owned(),
        },
        atoms: BTreeSet::from([
            "condition.clean".to_owned(),
            "delivery.not_required".to_owned(),
        ]),
    }
}

fn campaign() -> CampaignId {
    CampaignId::from_digest(digest("campaign"))
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

fn initial() -> OccurrenceSnapshotV1 {
    GovernedLoopKernelV1::create_initial(
        campaign(),
        OccurrenceId::allocate(),
        ProgramBasisRefV1::from_digest(digest("program")),
        ResidualSetV1::default(),
        budget(),
    )
    .unwrap()
}

fn proposal(work: &str) -> ExactWorkProposalV1 {
    ExactWorkProposalV1::new(
        campaign(),
        digest("subject"),
        digest("scope"),
        "test.store-work/v1".to_owned(),
        digest(work),
        None,
    )
    .unwrap()
}

#[derive(Clone)]
struct Observation {
    basis: DecisionBasisV1,
}

impl Observation {
    fn new() -> Self {
        Self {
            basis: clean_basis(),
        }
    }
}

impl ObservationResolverV1 for Observation {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV2, ExternalBoundaryErrorV1> {
        Ok(ObservationResolutionV2 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V2.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                self.basis.decision_basis_digest().unwrap(),
            ),
            basis: self.basis.clone(),
            resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
            subject: request.subject.clone(),
            status: ObservationStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

struct Standing;

impl StandingResolverV1 for Standing {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest("standing-resolution")),
            currentness: StandingCurrentnessRefV1::from_digest(digest("standing-currentness")),
            mandate: MandateRefV1::from_digest(digest("mandate")),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            resolver_id: STANDING_RESOLVER_ID.to_owned(),
            status: StandingStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

struct Decider;

impl AdmissibilityDeciderV1 for Decider {
    fn decide_admissibility(
        &mut self,
        request: &AdmissibilityRequestV1<'_>,
    ) -> Result<AdmissionDecisionV1, ExternalBoundaryErrorV1> {
        Ok(AdmissionDecisionV1 {
            decision: AdmissionDecisionRefV1::from_digest(digest("admission")),
            key: request.standing.key.clone(),
            observation: request.observation.observation.clone(),
            proposal: request.standing.proposal.clone(),
            standing_resolution: request.standing.resolution.clone(),
            disposition: AdmissionDispositionV1::Admitted,
            policy_basis: digest("policy"),
        })
    }
}

fn custody(spent: &OccurrenceSnapshotV1) -> DocketCustodyV1 {
    let issuance = spent.issuance().unwrap();
    DocketCustodyV1 {
        schema: DOCKET_CUSTODY_SCHEMA_V1.to_owned(),
        issuance: issuance.issuance.clone(),
        ag_spend: issuance.spend.clone(),
        execution_standing: DocketExecutionStandingRefV1::from_digest(digest("docket-standing")),
        standing_currentness: StandingCurrentnessRefV1::from_digest(digest("docket-currentness")),
        attempt: DocketAttemptRefV1::for_issuance(&issuance.issuance),
        executor_marker: ExecutorAttemptMarkerRefV1::from_digest(digest("executor-marker")),
        accepted_at_unix_ms: NOW + 1,
    }
}

fn settlement(dispatched: &OccurrenceSnapshotV1) -> DocketSettlementV1 {
    let custody = dispatched.docket_custody().unwrap();
    DocketSettlementV1 {
        schema: DOCKET_SETTLEMENT_SCHEMA_V1.to_owned(),
        settlement: SettlementRefV1::from_digest(digest("settlement")),
        issuance: custody.issuance.clone(),
        attempt: custody.attempt.clone(),
        executor_marker: custody.executor_marker.clone(),
        receipt: ReceiptRefV1::from_digest(digest("receipt")),
        outcome: KnownOutcomeV1::Success,
        settled_at_unix_ms: NOW + 2,
    }
}

fn commit_normal_path(
    store: &mut CampaignStoreV1,
    start: &OccurrenceSnapshotV1,
) -> OccurrenceSnapshotV1 {
    let mut observation = Observation::new();
    let proposed = GovernedLoopKernelV1::record_proposal(
        start,
        ObservationRefV1::from_digest(digest("observation")),
        proposal("work"),
        ProposalClassV1::Initial,
        &mut observation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();
    store
        .commit(
            start,
            &proposed,
            CampaignTransitionKindV1::ProposalRecorded,
            NOW,
        )
        .unwrap();
    let required = GovernedLoopKernelV1::require_standing(&proposed).unwrap();
    store
        .commit(
            &proposed,
            &required,
            CampaignTransitionKindV1::StandingRequired,
            NOW,
        )
        .unwrap();
    let admissible = GovernedLoopKernelV1::record_admissible(
        &required,
        &mut observation,
        &mut Standing,
        &mut Decider,
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();
    store
        .commit(
            &required,
            &admissible,
            CampaignTransitionKindV1::Admissible,
            NOW,
        )
        .unwrap();
    let spent = GovernedLoopKernelV1::consume_authorization(
        &admissible,
        &mut observation,
        &mut Standing,
        &mut Decider,
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();
    store
        .commit(
            &admissible,
            &spent,
            CampaignTransitionKindV1::AuthorizationConsumed,
            NOW,
        )
        .unwrap();
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    store
        .commit(
            &spent,
            &dispatched,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            NOW + 1,
        )
        .unwrap();
    let settled =
        GovernedLoopKernelV1::record_settlement(&dispatched, settlement(&dispatched)).unwrap();
    store
        .commit(
            &dispatched,
            &settled,
            CampaignTransitionKindV1::SettlementRecorded,
            NOW + 2,
        )
        .unwrap();
    settled
}

#[test]
fn one_transactional_path_replays_and_reconstructs_issuance() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let settled = commit_normal_path(&mut store, &start);
    assert_eq!(store.current().unwrap(), settled);
    assert_eq!(store.accounting_counts().unwrap(), (1, 1, 1));
    let issuance = settled.issuance().unwrap();
    assert_eq!(
        store.issuance(&issuance.issuance).unwrap().unwrap(),
        *issuance
    );
    let report = store.replay().unwrap();
    assert_eq!(report.transitions, 7);
    assert_eq!(report.ag_spends, 1);
    assert_eq!(report.docket_attempts, 1);
    assert_eq!(report.settlements, 1);

    drop(store);
    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), settled);
    assert_eq!(reopened.replay().unwrap(), report);
}

#[test]
fn stale_writer_and_duplicate_successor_refuse_without_partial_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    drop(store);

    let mut first_observation = Observation::new();
    let first = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-a")),
        proposal("work"),
        ProposalClassV1::Initial,
        &mut first_observation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();
    let mut second_observation = Observation::new();
    let second = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-b")),
        proposal("work"),
        ProposalClassV1::Initial,
        &mut second_observation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for successor in [first.clone(), second] {
        let barrier = Arc::clone(&barrier);
        let database = database.clone();
        let expected = start.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = CampaignStoreV1::open(&database).unwrap();
            barrier.wait();
            store.commit(
                &expected,
                &successor,
                CampaignTransitionKindV1::ProposalRecorded,
                NOW,
            )
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

    let mut store = CampaignStoreV1::open(&database).unwrap();
    let authoritative = store.current().unwrap();
    assert!(authoritative == first || authoritative.state_digest() != start.state_digest());
    assert!(matches!(
        store.commit(
            &start,
            &first,
            CampaignTransitionKindV1::ProposalRecorded,
            NOW,
        ),
        Err(CampaignStoreErrorV1::StalePredecessor { .. } | CampaignStoreErrorV1::BindingMismatch)
    ));
    assert_eq!(store.replay().unwrap().transitions, 2);
    assert_eq!(store.accounting_counts().unwrap(), (0, 0, 0));
}

#[test]
fn unrelated_sidecar_loss_cannot_revive_a_spent_occurrence() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let settled = commit_normal_path(&mut store, &start);
    let issuance_id = settled.issuance().unwrap().issuance.clone();
    std::fs::write(
        directory.path().join("non-authoritative-sidecar"),
        b"discardable",
    )
    .unwrap();
    std::fs::remove_file(directory.path().join("non-authoritative-sidecar")).unwrap();
    drop(store);

    let mut reopened = CampaignStoreV1::open(&database).unwrap();
    assert!(reopened.issuance(&issuance_id).unwrap().is_some());
    assert_eq!(reopened.accounting_counts().unwrap(), (1, 1, 1));
    assert!(
        reopened
            .commit(
                &start,
                &settled,
                CampaignTransitionKindV1::SettlementRecorded,
                NOW,
            )
            .is_err()
    );
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
}

#[test]
fn replay_detects_materialized_state_tampering() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute("UPDATE occurrences SET program_counter='completed'", [])
        .unwrap();
    drop(connection);
    assert!(CampaignStoreV1::open(&database).is_err());
}

#[test]
fn restart_refuses_tampered_spend_attempt_and_settlement_accounting() {
    for (label, statement) in [
        (
            "spend",
            "UPDATE ag_authorization_spends SET authorization_id='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        ),
        (
            "issuance",
            "UPDATE ag_authorization_spends SET issuance_jcs=x'7b7d'",
        ),
        ("attempt", "UPDATE docket_attempts SET custody_jcs=x'7b7d'"),
        (
            "settlement",
            "UPDATE docket_settlements SET receipt_id='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join(format!("{label}.sqlite"));
        let start = initial();
        let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
        commit_normal_path(&mut store, &start);
        drop(store);
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection.execute(statement, []).unwrap();
        drop(connection);
        assert!(
            CampaignStoreV1::open(&database).is_err(),
            "{label} accounting tamper must fail closed on restart"
        );
    }
}

#[cfg(unix)]
#[test]
fn restart_refuses_symlink_substitution_for_authoritative_store() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let alias = directory.path().join("campaign-alias.sqlite");
    let start = initial();
    drop(CampaignStoreV1::create(&database, &start, NOW).unwrap());
    symlink(&database, &alias).unwrap();
    assert!(CampaignStoreV1::open(&alias).is_err());
}
