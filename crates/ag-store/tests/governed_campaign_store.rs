//! Transactional, replay, concurrency, and restart tests for canonical campaign state.

use std::sync::{Arc, Barrier};

use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use ag_store::campaign::{CampaignStoreErrorV1, CampaignStoreV1, CampaignTransitionKindV1};

const NOW: u64 = 20_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-store-test/v1", label.as_bytes())
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
        "test.store-work/v1".to_owned(),
        digest(work),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap()
}

fn sorted(labels: &[&str]) -> Vec<Digest> {
    let mut values = labels.iter().map(|label| digest(label)).collect::<Vec<_>>();
    values.sort();
    values
}

fn canonical_bytes<T: serde::Serialize + ?Sized>(value: &T) -> Vec<u8> {
    JcsDocument::canonicalize(value)
        .unwrap()
        .as_bytes()
        .to_vec()
}

struct DirectRowSubstitution<'a> {
    table: &'a str,
    key_column: &'a str,
    key: &'a str,
    bytes_column: &'a str,
    artifact_identity: &'a Digest,
    field: &'a str,
    replacement: serde_json::Value,
}

fn assert_direct_row_substitution_refuses(
    store: &CampaignStoreV1,
    database: &std::path::Path,
    case: DirectRowSubstitution<'_>,
) {
    let DirectRowSubstitution {
        table,
        key_column,
        key,
        bytes_column,
        artifact_identity,
        field,
        replacement,
    } = case;
    let connection = rusqlite::Connection::open(database).unwrap();
    let select = format!("SELECT {bytes_column} FROM {table} WHERE {key_column}=?1");
    let original: Vec<u8> = connection
        .query_row(&select, rusqlite::params![key], |row| row.get(0))
        .unwrap();
    let mut substituted: serde_json::Value = serde_json::from_slice(&original).unwrap();
    substituted
        .as_object_mut()
        .expect("direct artifact is a canonical object")
        .insert(field.to_owned(), replacement);
    let changed = canonical_bytes(&substituted);
    assert_ne!(changed, original);
    let update = format!("UPDATE {table} SET {bytes_column}=?1 WHERE {key_column}=?2");
    connection
        .execute(&update, rusqlite::params![changed, key])
        .unwrap();
    assert!(
        store.artifact_bytes(artifact_identity).is_err(),
        "{table}.{bytes_column} substitution must fail closed"
    );
    connection
        .execute(&update, rusqlite::params![original.clone(), key])
        .unwrap();
    assert_eq!(
        store.artifact_bytes(artifact_identity).unwrap(),
        Some(original),
        "restored exact {table}.{bytes_column} must remain retrievable"
    );
}

#[cfg(unix)]
fn verifier_root(directory: &std::path::Path) -> (Digest, Vec<u8>) {
    use std::os::unix::fs::PermissionsExt as _;

    let executable = directory.join("qualification-fixture-not-human-authority.py");
    std::fs::write(
        &executable,
        r#"#!/usr/bin/env python3
import hashlib
import json
import sys

def domain_hash(domain, payload):
    prefix = b"ag-ng\x00digest\x00v1\x00"
    raw = (prefix + len(domain.encode()).to_bytes(16, "big") + domain.encode()
           + len(payload).to_bytes(16, "big") + payload)
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def value_hash(domain, value):
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return domain_hash(domain, payload)

request = json.load(sys.stdin)
artifact = request["artifact"]
decision_request = request["request"]
now = request["now_unix_ms"]
response = {
    "schema": "ag.governed-loop.governed-repair-verification/v1",
    "disposition": value_hash("ag.governed-loop.governed-repair-disposition/v1", artifact),
    "request": value_hash("ag.governed-loop.human-decision-request/v1", decision_request),
    "halted_state_digest": decision_request["halted_state_digest"],
    "verifier_profile": request["expected_profile"],
    "verifier_root": request["expected_root"],
    "verifier_executable": request["expected_executable"],
    "verification": domain_hash("qualification-fixture-not-human-authority/v1", artifact["nonce"].encode()),
    "verified_at_unix_ms": now,
    "expires_at_unix_ms": now + 5,
}
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
"#,
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let executable_identity = Digest::hash_bytes(&std::fs::read(&executable).unwrap());
    let root = serde_json::json!({
        "schema": "ag.governed-loop.governed-repair-verifier-root/v1",
        "verifier_label": "qualification-fixture-not-human-authority",
        "executable": executable,
        "executable_identity": executable_identity,
        "catalog": {
            "schema": "ag.governed-loop.governed-repair-verifier-catalog/v1",
            "profiles": [{
                "profile": digest("verifier-profile"),
                "principal": HumanPrincipalRefV1::from_digest(digest("verifier-principal")),
                "mandate": MandateRefV1::from_digest(digest("verifier-mandate")),
            }]
        }
    });
    let bytes = canonical_bytes(&root);
    let identity = Digest::hash_domain("ag.governed-loop.governed-repair-verifier-root/v1", &bytes);
    (identity, bytes)
}

#[derive(Clone)]
struct Observation {
    preconditions: PreconditionBasisRefV1,
}

impl Observation {
    fn new(label: &str) -> Self {
        Self {
            preconditions: PreconditionBasisRefV1::from_digest(digest(label)),
        }
    }
}

impl ObservationResolverV1 for Observation {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1> {
        Ok(ObservationResolutionV1 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V1.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: self.preconditions.clone(),
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
    ) -> Result<CurrentStandingResolutionV1, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest("standing-resolution")),
            currentness: StandingCurrentnessRefV1::from_digest(digest("standing-currentness")),
            mandate: MandateRefV1::from_digest(digest("mandate")),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
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

fn sealed_scope_result(dispatched: &OccurrenceSnapshotV1) -> DocketSealedGovernedRepairResultV1 {
    let custody = dispatched.docket_custody().unwrap();
    let original_scope = dispatched
        .proposal_contract()
        .unwrap()
        .effect_scope()
        .clone();
    let requested_delta = CanonicalEffectScopeV1::new(
        original_scope.effect_class().to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "fixtures/adjacent-required".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let outcome = DocketGovernedRepairOutcomeRefV1 {
        checkpoint: DocketCheckpointRefV1::from_digest(digest("docket-checkpoint")),
        sealed_result: DocketSealedResultRefV1::from_digest(digest("docket-sealed-result")),
        outcome: digest("docket-scope-outcome"),
        issuance: custody.issuance.clone(),
        custody: custody.reference(),
        attempt: custody.attempt.clone(),
        effect_journal: digest("effect-journal"),
        executor_binding: digest("executor-binding"),
        executor_result: digest("executor-result"),
        executor_receipt: ReceiptRefV1::from_digest(digest("executor-receipt")),
        immutable_work_checkpoint: None,
        authorized_effects_occurred: false,
        created_at_unix_ms: NOW + 2,
        expires_at_unix_ms: NOW + 100,
        idempotency: digest("docket-result-idempotency"),
    };
    DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
        outcome: outcome.clone(),
        requirement: ScopeExpansionRequiredV1 {
            schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
            original_scope: original_scope.clone(),
            original_scope_digest: original_scope.digest(),
            requested_delta: requested_delta.clone(),
            requested_delta_digest: requested_delta.digest(),
            blocked_operation: BlockedEffectOperationV1 {
                resource: "repository".to_owned(),
                path: "fixtures/adjacent-required".to_owned(),
                operation: CanonicalEffectOperationV1::Modify,
            },
            reason: digest("scope-insufficiency"),
            dependency_evidence: sorted(&["dependency"]),
            limitations: sorted(&["limitation"]),
            docket_outcome: Some(outcome),
            unauthorized_effect_not_performed: true,
        },
    }
}

fn halt_with_sealed_scope_result(
    store: &mut CampaignStoreV1,
    dispatched: &OccurrenceSnapshotV1,
    result: &DocketSealedGovernedRepairResultV1,
) -> OccurrenceSnapshotV1 {
    let (outcome, requirement) = match result {
        DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
            outcome,
            requirement,
        } => (
            outcome,
            HumanDecisionRequirementV1::ScopeExpansion(requirement.clone()),
        ),
        DocketSealedGovernedRepairResultV1::ReadjudicationRequired { .. } => {
            panic!("scope fixture changed kind")
        }
    };
    let halted = GovernedLoopKernelV1::halt_from_docket_governed_repair(
        dispatched,
        outcome,
        &requirement,
        HaltReasonRefV1::from_digest(digest("Docket governed repair required")),
    )
    .unwrap();
    store
        .commit_docket_governed_repair_halt(dispatched, &halted, result, NOW + 3)
        .unwrap();
    halted
}

fn issuance_refusal(spent: &OccurrenceSnapshotV1) -> DocketIssuanceRefusalV1 {
    let issuance = spent.issuance().unwrap();
    let mut refusal = DocketIssuanceRefusalV1 {
        schema: "docket.governed-loop.issuance-refusal/v1".to_owned(),
        refusal: digest("placeholder-refusal"),
        issuance: issuance.issuance.clone(),
        campaign: issuance.key.campaign.clone(),
        occurrence: issuance.key.occurrence,
        refusal_class: DocketIssuanceRefusalClassV1::StandingInvalid,
        reason_code: "standing_invalid".to_owned(),
        evidence: digest("negative-standing-evidence"),
        refused_at_unix_ms: NOW + 1,
    };
    refusal.refusal = refusal.derived_identity();
    refusal
}

fn commit_to_spent(
    store: &mut CampaignStoreV1,
    start: &OccurrenceSnapshotV1,
) -> OccurrenceSnapshotV1 {
    let mut observation = Observation::new("preconditions");
    let proposed = GovernedLoopKernelV1::record_proposal(
        start,
        ObservationRefV1::from_digest(digest("observation")),
        proposal("work"),
        ProposalClassV1::Initial,
        &mut observation,
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
    spent
}

fn commit_to_dispatched(
    store: &mut CampaignStoreV1,
    start: &OccurrenceSnapshotV1,
) -> OccurrenceSnapshotV1 {
    let spent = commit_to_spent(store, start);
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    store
        .commit(
            &spent,
            &dispatched,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            NOW + 1,
        )
        .unwrap();
    dispatched
}

fn commit_normal_path(
    store: &mut CampaignStoreV1,
    start: &OccurrenceSnapshotV1,
) -> OccurrenceSnapshotV1 {
    let dispatched = commit_to_dispatched(store, start);
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
    let spend = settled.ag_spend().unwrap();
    let custody = settled.docket_custody().unwrap();
    let settlement = settled.settlement().unwrap();
    assert_eq!(
        store.artifact_bytes(spend.spend.as_digest()).unwrap(),
        Some(canonical_bytes(spend))
    );
    assert_eq!(
        store
            .artifact_bytes(custody.reference().as_digest())
            .unwrap(),
        Some(canonical_bytes(custody))
    );
    assert_eq!(
        store
            .artifact_bytes(settlement.settlement.as_digest())
            .unwrap(),
        Some(canonical_bytes(settlement))
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

#[cfg(unix)]
#[test]
fn every_direct_table_artifact_refuses_canonical_row_byte_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let (root_identity, root_bytes) = verifier_root(directory.path());
    let product_key = digest("product-create-idempotency");
    let product_bytes = canonical_bytes(&serde_json::json!({
        "schema": "test.product-create/v1",
        "value": "exact-product-create"
    }));
    let product_identity =
        Digest::hash_domain("ag.governed-loop.product-create/v1", &product_bytes);
    let start = initial();
    let mut store = CampaignStoreV1::create_with_product_records(
        &database,
        &start,
        NOW,
        Some((&product_key, &product_identity, &product_bytes)),
        Some((&root_identity, &root_bytes)),
    )
    .unwrap();
    let settled = commit_normal_path(&mut store, &start);
    let spend = settled.ag_spend().unwrap();
    let issuance = settled.issuance().unwrap();
    let settlement = settled.settlement().unwrap();
    let refusal = RefusalOutcomeV1 {
        key: settled.key().clone(),
        at_state_digest: settled.state_digest().clone(),
        code: RefusalCodeV1::RecoveryRequired,
        evidence: Some(digest("refusal-evidence")),
    };
    let refusal_identity = store.record_refusal(&refusal, NOW + 3).unwrap();

    for case in [
        DirectRowSubstitution {
            table: "ag_authorization_spends",
            key_column: "spend_id",
            key: spend.spend.as_str(),
            bytes_column: "spend_jcs",
            artifact_identity: spend.spend.as_digest(),
            field: "consumed_at_unix_ms",
            replacement: serde_json::json!(NOW + 77),
        },
        DirectRowSubstitution {
            table: "ag_authorization_spends",
            key_column: "issuance_id",
            key: issuance.issuance.as_str(),
            bytes_column: "issuance_jcs",
            artifact_identity: issuance.issuance.as_digest(),
            field: "work",
            replacement: serde_json::to_value(digest("substituted-work")).unwrap(),
        },
        DirectRowSubstitution {
            table: "docket_settlements",
            key_column: "settlement_id",
            key: settlement.settlement.as_str(),
            bytes_column: "settlement_jcs",
            artifact_identity: settlement.settlement.as_digest(),
            field: "receipt",
            replacement: serde_json::to_value(ReceiptRefV1::from_digest(digest(
                "substituted-receipt",
            )))
            .unwrap(),
        },
        DirectRowSubstitution {
            table: "product_creation_request",
            key_column: "request_identity",
            key: product_identity.as_str(),
            bytes_column: "request_jcs",
            artifact_identity: &product_identity,
            field: "value",
            replacement: serde_json::json!("substituted-product-create"),
        },
        DirectRowSubstitution {
            table: "governed_repair_verifier_root",
            key_column: "config_identity",
            key: root_identity.as_str(),
            bytes_column: "config_jcs",
            artifact_identity: &root_identity,
            field: "verifier_label",
            replacement: serde_json::json!("substituted-verifier"),
        },
        DirectRowSubstitution {
            table: "refusals",
            key_column: "refusal_id",
            key: refusal_identity.as_str(),
            bytes_column: "refusal_jcs",
            artifact_identity: &refusal_identity,
            field: "evidence",
            replacement: serde_json::to_value(Some(digest("substituted-refusal-evidence")))
                .unwrap(),
        },
    ] {
        assert_direct_row_substitution_refuses(&store, &database, case);
    }
}

#[test]
fn complete_proposal_and_docket_result_artifacts_survive_exact_restart_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let dispatched = commit_to_dispatched(&mut store, &start);
    let exact_proposal = dispatched.proposal_contract().unwrap().clone();
    let proposal_identity = exact_proposal.reference();
    let result = sealed_scope_result(&dispatched);
    let result_identity = match &result {
        DocketSealedGovernedRepairResultV1::ScopeExpansionRequired { outcome, .. }
        | DocketSealedGovernedRepairResultV1::ReadjudicationRequired { outcome, .. } => {
            outcome.sealed_result.clone()
        }
    };
    let halted = halt_with_sealed_scope_result(&mut store, &dispatched, &result);

    assert_eq!(
        store.artifact_bytes(proposal_identity.as_digest()).unwrap(),
        Some(canonical_bytes(&exact_proposal))
    );
    assert_eq!(
        store.artifact_bytes(result_identity.as_digest()).unwrap(),
        Some(canonical_bytes(&result))
    );
    assert_eq!(store.last_recorded_at_unix_ms().unwrap(), NOW + 3);
    drop(store);

    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), halted);
    assert_eq!(
        reopened
            .artifact_bytes(proposal_identity.as_digest())
            .unwrap(),
        Some(canonical_bytes(&exact_proposal))
    );
    assert_eq!(
        reopened
            .artifact_bytes(result_identity.as_digest())
            .unwrap(),
        Some(canonical_bytes(&result))
    );
    assert!(
        reopened
            .artifact_bytes(&digest("wrong-artifact"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn docket_issuance_refusal_is_durable_exact_replayable_and_residual_bearing() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let spent = commit_to_spent(&mut store, &start);
    let spend_identity = spent.ag_spend().unwrap().spend.clone();
    let issuance = spent.issuance().unwrap().issuance.clone();
    let refusal = issuance_refusal(&spent);
    let halted =
        GovernedLoopKernelV1::halt_docket_issuance_refusal(&spent, refusal.clone()).unwrap();

    let mut pre_spend = refusal.clone();
    pre_spend.refused_at_unix_ms = spent.ag_spend().unwrap().consumed_at_unix_ms - 1;
    pre_spend.refusal = pre_spend.derived_identity();
    assert!(GovernedLoopKernelV1::halt_docket_issuance_refusal(&spent, pre_spend).is_err());

    assert!(
        store
            .commit_docket_issuance_refusal(
                &spent,
                &halted,
                &refusal,
                refusal.refused_at_unix_ms - 1,
            )
            .is_err()
    );
    assert_eq!(store.current().unwrap(), spent);

    let mut substituted = refusal.clone();
    substituted.evidence = digest("substituted-standing-evidence");
    assert!(
        store
            .commit_docket_issuance_refusal(&spent, &halted, &substituted, NOW + 1)
            .is_err()
    );
    assert_eq!(store.current().unwrap(), spent);
    assert_eq!(store.replay().unwrap().ag_spends, 1);

    store
        .commit_docket_issuance_refusal(&spent, &halted, &refusal, NOW + 1)
        .unwrap();
    assert_eq!(store.current().unwrap(), halted);
    assert_eq!(
        halted.state().authority_history().ag_spend,
        Some(spend_identity)
    );
    assert!(halted.docket_custody().is_none());
    let refusal_residual = halted
        .state()
        .meta()
        .residuals()
        .as_slice()
        .iter()
        .find(|residual| residual.statement == refusal.refusal)
        .expect("exact refusal residual is durable");
    assert_eq!(refusal_residual.owner, refusal.evidence);
    assert_eq!(refusal_residual.subject, *issuance.as_digest());
    assert_eq!(
        store.artifact_bytes(&refusal.refusal).unwrap(),
        Some(canonical_bytes(&refusal))
    );
    let report = store.replay().unwrap();
    assert_eq!(report.ag_spends, 1);
    assert_eq!(report.docket_attempts, 0);
    assert_eq!(report.settlements, 0);
    drop(store);

    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), halted);
    assert_eq!(
        reopened.artifact_bytes(&refusal.refusal).unwrap(),
        Some(canonical_bytes(&refusal))
    );
    assert_eq!(reopened.replay().unwrap(), report);
    drop(reopened);

    let connection = rusqlite::Connection::open(&database).unwrap();
    let mut bytes: Vec<u8> = connection
        .query_row(
            "SELECT evidence_jcs FROM transitions WHERE transition_kind='docket_issuance_refused'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    bytes.push(b' ');
    connection
        .execute(
            "UPDATE transitions SET evidence_jcs=?1 WHERE transition_kind='docket_issuance_refused'",
            rusqlite::params![bytes],
        )
        .unwrap();
    drop(connection);
    assert!(CampaignStoreV1::open(&database).is_err());
}

#[test]
fn decision_request_open_and_idempotency_queries_are_expiry_aware_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let dispatched = commit_to_dispatched(&mut store, &start);
    let result = sealed_scope_result(&dispatched);
    let halted = halt_with_sealed_scope_result(&mut store, &dispatched, &result);
    let requirement = halted
        .halted()
        .unwrap()
        .governed_repair_requirement()
        .unwrap()
        .clone();
    let idempotency = digest("decision-request-idempotency");
    let request = GovernedLoopKernelV1::create_human_decision_request(
        &halted,
        HumanDecisionRequestParametersV1 {
            requirement,
            required_verifier_profile: digest("verifier-profile"),
            required_verifier_root: digest("verifier-root"),
            required_verifier_executable: digest("verifier-executable"),
            decision_consequences: sorted(&["approve", "reject"]),
            nonclaims: sorted(&["not-authority", "not-standing"]),
            idempotency_key: idempotency.clone(),
            created_at_unix_ms: NOW + 4,
            expires_at_unix_ms: NOW + 20,
        },
    )
    .unwrap();
    let request_ref = store
        .record_human_decision_request(halted.state_digest(), &request)
        .unwrap();
    assert_eq!(
        store
            .record_human_decision_request(halted.state_digest(), &request)
            .unwrap(),
        request_ref
    );
    assert_eq!(
        store
            .open_human_decision_request_for_state(halted.state_digest(), NOW + 5)
            .unwrap(),
        Some(request_ref.clone())
    );
    assert_eq!(
        store
            .human_decision_request_by_idempotency(&idempotency)
            .unwrap(),
        Some(request.clone())
    );
    drop(store);

    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(
        reopened
            .open_human_decision_request_for_state(halted.state_digest(), NOW + 19)
            .unwrap(),
        Some(request_ref)
    );
    assert_eq!(
        reopened
            .open_human_decision_request_for_state(halted.state_digest(), NOW + 20)
            .unwrap(),
        None
    );
    assert_eq!(
        reopened
            .human_decision_request_by_idempotency(&idempotency)
            .unwrap(),
        Some(request)
    );
}

#[cfg(unix)]
#[test]
fn verified_disposition_receipt_is_exactly_addressable_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let (root_identity, root_bytes) = verifier_root(directory.path());
    let start = initial();
    let mut store = CampaignStoreV1::create_with_product_records(
        &database,
        &start,
        NOW,
        None,
        Some((&root_identity, &root_bytes)),
    )
    .unwrap();
    let dispatched = commit_to_dispatched(&mut store, &start);
    let result = sealed_scope_result(&dispatched);
    let halted = halt_with_sealed_scope_result(&mut store, &dispatched, &result);
    let request = GovernedLoopKernelV1::create_human_decision_request(
        &halted,
        HumanDecisionRequestParametersV1 {
            requirement: halted
                .halted()
                .unwrap()
                .governed_repair_requirement()
                .unwrap()
                .clone(),
            required_verifier_profile: digest("verifier-profile"),
            required_verifier_root: root_identity.clone(),
            required_verifier_executable: Digest::hash_bytes(
                &std::fs::read(
                    directory
                        .path()
                        .join("qualification-fixture-not-human-authority.py"),
                )
                .unwrap(),
            ),
            decision_consequences: sorted(&["approve", "reject"]),
            nonclaims: sorted(&["fixture-not-authority", "fixture-not-standing"]),
            idempotency_key: digest("verified-request-idempotency"),
            created_at_unix_ms: NOW + 4,
            expires_at_unix_ms: NOW + 20,
        },
    )
    .unwrap();
    let request_ref = store
        .record_human_decision_request(halted.state_digest(), &request)
        .unwrap();
    let artifact = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: halted.key().campaign.clone(),
        occurrence: halted.key().occurrence,
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::Reject {
            request: request_ref.clone(),
            reason: digest("fixture-rejection"),
        },
        decision: HumanDecisionIdV1::from_digest(digest("fixture-decision")),
        principal: HumanPrincipalRefV1::from_digest(digest("verifier-principal")),
        mandate: MandateRefV1::from_digest(digest("verifier-mandate")),
        verifier_profile: digest("verifier-profile"),
        nonce: HumanNonceRefV1::from_digest(digest("fixture-nonce")),
        expires_at_unix_ms: NOW + 15,
    };
    let disposition = artifact.reference();
    let verified = store
        .verify_governed_repair_disposition(halted.state_digest(), &request_ref, artifact, NOW + 5)
        .unwrap();
    store
        .commit_verified_governed_repair_disposition(verified)
        .unwrap();
    let verification = store
        .governed_repair_verification_for_disposition(&disposition)
        .unwrap()
        .unwrap();
    assert_eq!(verification.disposition, disposition);
    assert_eq!(
        store
            .artifact_bytes(verification.verification.as_digest())
            .unwrap(),
        Some(canonical_bytes(&verification))
    );
    drop(store);

    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(
        reopened
            .governed_repair_verification_for_disposition(&disposition)
            .unwrap(),
        Some(verification.clone())
    );
    assert_eq!(
        reopened
            .artifact_bytes(verification.verification.as_digest())
            .unwrap(),
        Some(canonical_bytes(&verification))
    );
}

#[cfg(unix)]
#[test]
fn request_and_disposition_direct_rows_refuse_canonical_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let (root_identity, root_bytes) = verifier_root(directory.path());
    let start = initial();
    let mut store = CampaignStoreV1::create_with_product_records(
        &database,
        &start,
        NOW,
        None,
        Some((&root_identity, &root_bytes)),
    )
    .unwrap();
    let dispatched = commit_to_dispatched(&mut store, &start);
    let result = sealed_scope_result(&dispatched);
    let halted = halt_with_sealed_scope_result(&mut store, &dispatched, &result);
    let request = GovernedLoopKernelV1::create_human_decision_request(
        &halted,
        HumanDecisionRequestParametersV1 {
            requirement: halted
                .halted()
                .unwrap()
                .governed_repair_requirement()
                .unwrap()
                .clone(),
            required_verifier_profile: digest("verifier-profile"),
            required_verifier_root: root_identity,
            required_verifier_executable: Digest::hash_bytes(
                &std::fs::read(
                    directory
                        .path()
                        .join("qualification-fixture-not-human-authority.py"),
                )
                .unwrap(),
            ),
            decision_consequences: sorted(&["approve", "reject"]),
            nonclaims: sorted(&["fixture-not-authority", "fixture-not-standing"]),
            idempotency_key: digest("hostile-request-idempotency"),
            created_at_unix_ms: NOW + 4,
            expires_at_unix_ms: NOW + 20,
        },
    )
    .unwrap();
    let request_ref = store
        .record_human_decision_request(halted.state_digest(), &request)
        .unwrap();
    let artifact = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: halted.key().campaign.clone(),
        occurrence: halted.key().occurrence,
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::Reject {
            request: request_ref.clone(),
            reason: digest("hostile-fixture-rejection"),
        },
        decision: HumanDecisionIdV1::from_digest(digest("hostile-fixture-decision")),
        principal: HumanPrincipalRefV1::from_digest(digest("verifier-principal")),
        mandate: MandateRefV1::from_digest(digest("verifier-mandate")),
        verifier_profile: digest("verifier-profile"),
        nonce: HumanNonceRefV1::from_digest(digest("hostile-fixture-nonce")),
        expires_at_unix_ms: NOW + 15,
    };
    let disposition = artifact.reference();
    let verified = store
        .verify_governed_repair_disposition(halted.state_digest(), &request_ref, artifact, NOW + 5)
        .unwrap();
    store
        .commit_verified_governed_repair_disposition(verified)
        .unwrap();

    for case in [
        DirectRowSubstitution {
            table: "human_decision_requests",
            key_column: "request_id",
            key: request_ref.as_str(),
            bytes_column: "request_jcs",
            artifact_identity: request_ref.as_digest(),
            field: "expires_at_unix_ms",
            replacement: serde_json::json!(NOW + 19),
        },
        DirectRowSubstitution {
            table: "governed_repair_dispositions",
            key_column: "disposition_id",
            key: disposition.as_str(),
            bytes_column: "artifact_jcs",
            artifact_identity: disposition.as_digest(),
            field: "expires_at_unix_ms",
            replacement: serde_json::json!(NOW + 14),
        },
    ] {
        assert_direct_row_substitution_refuses(&store, &database, case);
    }
}

#[test]
fn restart_refuses_changed_docket_artifact_bytes_under_prior_event_identity() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let dispatched = commit_to_dispatched(&mut store, &start);
    let result = sealed_scope_result(&dispatched);
    halt_with_sealed_scope_result(&mut store, &dispatched, &result);
    drop(store);

    let connection = rusqlite::Connection::open(&database).unwrap();
    let mut bytes: Vec<u8> = connection
        .query_row(
            "SELECT evidence_jcs FROM transitions WHERE transition_kind='docket_governed_repair_halted'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    bytes.push(b' ');
    connection
        .execute(
            "UPDATE transitions SET evidence_jcs=?1 WHERE transition_kind='docket_governed_repair_halted'",
            rusqlite::params![bytes],
        )
        .unwrap();
    drop(connection);
    assert!(CampaignStoreV1::open(&database).is_err());
}

#[test]
fn stale_writer_and_duplicate_successor_refuse_without_partial_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    drop(store);

    let mut first_observation = Observation::new("preconditions");
    let first = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-a")),
        proposal("work-a"),
        ProposalClassV1::Initial,
        &mut first_observation,
        NOW,
    )
    .unwrap();
    let mut second_observation = Observation::new("preconditions");
    let second = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-b")),
        proposal("work-b"),
        ProposalClassV1::Initial,
        &mut second_observation,
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
fn product_state_read_remains_coherent_during_concurrent_transitions() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    drop(store);

    let barrier = Arc::new(Barrier::new(2));
    let writer_database = database.clone();
    let writer_start = start.clone();
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        let mut store = CampaignStoreV1::open(&writer_database).unwrap();
        writer_barrier.wait();
        commit_to_dispatched(&mut store, &writer_start)
    });

    let reader = CampaignStoreV1::open(&database).unwrap();
    barrier.wait();
    for _ in 0..256 {
        let view = reader.campaign_state_read(NOW + 100).unwrap();
        assert_eq!(view.current.state_digest(), &view.head.state_digest);
        assert!(view.head.event_count >= 1);
        assert!(view.open_human_decision_request.is_none());
    }

    let dispatched = writer.join().unwrap();
    let final_view = reader.campaign_state_read(NOW + 100).unwrap();
    assert_eq!(final_view.current, dispatched);
    assert_eq!(
        final_view.current.state_digest(),
        &final_view.head.state_digest
    );
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
