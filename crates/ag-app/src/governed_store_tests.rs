//! Transactional, replay, concurrency, and restart tests for canonical campaign state.

use std::sync::{Arc, Barrier};

use crate::governed_store::{CampaignStoreErrorV1, CampaignStoreV1, CampaignTransitionKindV1};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};

const NOW: u64 = 20_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const FIRST_UNSAFE_INTEGER: u64 = 9_007_199_254_740_992;

fn demote_safe_integer_schema_to_v4(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER campaigns_safe_integer_insert_v1;
             DROP TRIGGER campaigns_safe_integer_update_v1;
             DROP TRIGGER occurrences_safe_integer_insert_v1;
             DROP TRIGGER occurrences_safe_integer_update_v1;
             DROP TRIGGER transitions_safe_integer_insert_v1;
             DROP TRIGGER transitions_safe_integer_update_v1;
             DROP TRIGGER human_dispositions_safe_integer_insert_v1;
             DROP TRIGGER human_dispositions_safe_integer_update_v1;
             DROP TRIGGER human_decision_requests_safe_integer_insert_v1;
             DROP TRIGGER human_decision_requests_safe_integer_update_v1;
             DROP TRIGGER governed_repair_dispositions_safe_integer_insert_v1;
             DROP TRIGGER governed_repair_dispositions_safe_integer_update_v1;
             DROP TRIGGER refusals_safe_integer_insert_v1;
             DROP TRIGGER refusals_safe_integer_update_v1;
             UPDATE store_identity
                SET schema_name='ag-governed-loop-campaign-store/v4',
                    schema_version=4,
                    schema_digest='sha256:2a4aea8855baf0caa6e3c9ccd8b8f57159ec84f45d9a7b3379057c534b49869e'
              WHERE singleton=1;
             PRAGMA user_version=4;",
        )
        .unwrap();
}

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

fn assert_direct_text_substitution_refuses(
    store: &CampaignStoreV1,
    database: &std::path::Path,
    key: &HumanDispositionRefV1,
    column: &str,
) {
    let connection = rusqlite::Connection::open(database).unwrap();
    let select =
        format!("SELECT {column} FROM governed_repair_dispositions WHERE disposition_id=?1");
    let original: String = connection
        .query_row(&select, rusqlite::params![key.as_str()], |row| row.get(0))
        .unwrap();
    let changed = digest(&format!("substituted-{column}"));
    assert_ne!(changed.as_str(), original);
    let update =
        format!("UPDATE governed_repair_dispositions SET {column}=?1 WHERE disposition_id=?2");
    connection
        .execute(&update, rusqlite::params![changed.as_str(), key.as_str()])
        .unwrap();
    assert!(
        store.replay().is_err(),
        "{column} substitution must fail closed"
    );
    connection
        .execute(&update, rusqlite::params![original, key.as_str()])
        .unwrap();
    assert!(store.replay().is_ok(), "restored {column} must replay");
}

fn assert_v2_to_v3_verification_migration(
    database: &std::path::Path,
    verification: &GovernedRepairVerificationV1,
) {
    // Recreate the exact V2 table shape and identity while preserving the
    // durable disposition row. Opening must transactionally derive both V3
    // verification indexes from the canonical complete record.
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute_batch(
            "ALTER TABLE governed_repair_dispositions
                 RENAME TO governed_repair_dispositions_v3;
             CREATE TABLE governed_repair_dispositions (
                 decision_id TEXT PRIMARY KEY,
                 nonce TEXT NOT NULL UNIQUE,
                 request_id TEXT NOT NULL UNIQUE,
                 campaign_id TEXT NOT NULL,
                 occurrence_id TEXT NOT NULL,
                 halted_state_digest TEXT NOT NULL,
                 disposition_id TEXT NOT NULL UNIQUE,
                 verification_jcs BLOB NOT NULL,
                 artifact_jcs BLOB NOT NULL,
                 consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms >= 0),
                 FOREIGN KEY (request_id) REFERENCES human_decision_requests(request_id),
                 FOREIGN KEY (campaign_id, occurrence_id)
                     REFERENCES occurrences(campaign_id, occurrence_id)
             ) STRICT;
             INSERT INTO governed_repair_dispositions
                    (decision_id,nonce,request_id,campaign_id,occurrence_id,
                     halted_state_digest,disposition_id,verification_jcs,
                     artifact_jcs,consumed_at_unix_ms)
             SELECT decision_id,nonce,request_id,campaign_id,occurrence_id,
                    halted_state_digest,disposition_id,verification_jcs,
                    artifact_jcs,consumed_at_unix_ms
               FROM governed_repair_dispositions_v3;
             DROP TABLE governed_repair_dispositions_v3;
             DROP TABLE governed_repair_verification_identities;
             DROP TABLE issuance_signing_reservations;
             UPDATE store_identity
                SET schema_name='ag-governed-loop-campaign-store/v2',
                    schema_version=2,
                    schema_digest='sha256:2f4d24faf67da2cae9ef7e63c3987172fbc47e067ae0c9d078a68abd04895f20'
              WHERE singleton=1;
             PRAGMA user_version=2;",
        )
        .unwrap();
    drop(connection);

    let migrated = CampaignStoreV1::open(database).unwrap();
    assert_eq!(
        migrated
            .governed_repair_verification(&verification.reference())
            .unwrap(),
        Some(verification.clone())
    );
    assert_eq!(
        migrated
            .governed_repair_verification_by_receipt(&verification.verification)
            .unwrap(),
        Some(verification.clone())
    );
}

fn assert_verification_addressable(
    store: &CampaignStoreV1,
    disposition: &HumanDispositionRefV1,
    verification: &GovernedRepairVerificationV1,
) {
    assert_eq!(
        store
            .governed_repair_verification_for_disposition(disposition)
            .unwrap(),
        Some(verification.clone())
    );
    assert_eq!(
        store
            .governed_repair_verification_by_receipt(&verification.verification)
            .unwrap(),
        Some(verification.clone())
    );
    assert_eq!(
        store
            .artifact_bytes(verification.verification.as_digest())
            .unwrap(),
        Some(canonical_bytes(verification))
    );
}

fn assert_request_disposition_verification_substitutions(
    store: &CampaignStoreV1,
    database: &std::path::Path,
    request: &HumanDecisionRequestRefV1,
    disposition: &HumanDispositionRefV1,
    verification: &GovernedRepairVerificationV1,
) {
    for case in [
        DirectRowSubstitution {
            table: "human_decision_requests",
            key_column: "request_id",
            key: request.as_str(),
            bytes_column: "request_jcs",
            artifact_identity: request.as_digest(),
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
        DirectRowSubstitution {
            table: "governed_repair_dispositions",
            key_column: "disposition_id",
            key: disposition.as_str(),
            bytes_column: "verification_jcs",
            artifact_identity: verification.verification.as_digest(),
            field: "verified_at_unix_ms",
            replacement: serde_json::json!(NOW + 6),
        },
    ] {
        assert_direct_row_substitution_refuses(store, database, case);
    }
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
    let mut settlement = DocketSettlementV1 {
        schema: DOCKET_SETTLEMENT_SCHEMA_V1.to_owned(),
        settlement: SettlementRefV1::from_digest(digest("settlement")),
        issuance: custody.issuance.clone(),
        attempt: custody.attempt.clone(),
        executor_marker: custody.executor_marker.clone(),
        receipt: ReceiptRefV1::from_digest(digest("receipt")),
        outcome: KnownOutcomeV1::Success,
        cumulative_effect_journal_identity: Some(digest("cumulative-effect-journal")),
        settled_at_unix_ms: NOW + 2,
    };
    settlement.settlement = settlement.expected_reference().unwrap();
    settlement
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
        reported_authorized_effects_occurred: false,
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
            no_unauthorized_effect_reported: true,
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
        .commit_docket_governed_repair_halt(
            dispatched.state_digest(),
            dispatched,
            &halted,
            result,
            NOW + 3,
        )
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
            start.state_digest(),
            start,
            &proposed,
            CampaignTransitionKindV1::ProposalRecorded,
            NOW,
        )
        .unwrap();
    let required = GovernedLoopKernelV1::require_standing(&proposed).unwrap();
    store
        .commit(
            proposed.state_digest(),
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
            required.state_digest(),
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
            admissible.state_digest(),
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
            spent.state_digest(),
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
            dispatched.state_digest(),
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

#[test]
fn rejected_r1_settlement_bytes_remain_historically_replayable() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let dispatched = commit_to_dispatched(&mut store, &start);
    let mut legacy = settlement(&dispatched);
    legacy.cumulative_effect_journal_identity = None;
    let outcome = "success";
    legacy.settlement = SettlementRefV1::from_digest(Digest::hash_domain(
        DOCKET_SETTLEMENT_IDENTITY_DOMAIN_V1,
        format!(
            "{}:{}:{}:{outcome}",
            legacy.issuance.as_str(),
            legacy.attempt.as_str(),
            legacy.receipt.as_str()
        )
        .as_bytes(),
    ));
    let settled = GovernedLoopKernelV1::record_settlement(&dispatched, legacy.clone()).unwrap();
    store
        .commit(
            dispatched.state_digest(),
            &dispatched,
            &settled,
            CampaignTransitionKindV1::SettlementRecorded,
            NOW + 2,
        )
        .unwrap();
    drop(store);
    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap().settlement(), Some(&legacy));
    assert_eq!(
        reopened
            .artifact_bytes(legacy.settlement.as_digest())
            .unwrap(),
        Some(canonical_bytes(&legacy))
    );
}

#[test]
fn signing_permit_is_store_minted_one_use_and_only_at_the_spent_cut() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    assert!(store.issuance_signing_permit(start.state_digest()).is_err());

    let spent = commit_to_spent(&mut store, &start);
    let expected = spent.issuance().unwrap().clone();
    let permit = store.issuance_signing_permit(spent.state_digest()).unwrap();
    assert_eq!(permit.into_issuance(), expected);
    assert!(matches!(
        store.issuance_signing_permit(spent.state_digest()),
        Err(CampaignStoreErrorV1::IssuanceSigningAlreadyReserved)
    ));
    drop(store);
    let mut store = CampaignStoreV1::open(&database).unwrap();
    assert!(matches!(
        store.issuance_signing_permit(spent.state_digest()),
        Err(CampaignStoreErrorV1::IssuanceSigningAlreadyReserved)
    ));

    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    store
        .commit(
            spent.state_digest(),
            &spent,
            &dispatched,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            NOW + 1,
        )
        .unwrap();
    assert!(
        store
            .issuance_signing_permit(dispatched.state_digest())
            .is_err()
    );
    drop(store);
    let mut reopened = CampaignStoreV1::open(&database).unwrap();
    assert!(
        reopened
            .issuance_signing_permit(dispatched.state_digest())
            .is_err()
    );
}

#[test]
fn transition_transaction_refuses_stale_caller_even_with_authoritative_predecessor() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let probed = GovernedLoopKernelV1::note_probe(&start).unwrap();
    store
        .commit(
            start.state_digest(),
            &start,
            &probed,
            CampaignTransitionKindV1::ProbeNoted,
            NOW + 1,
        )
        .unwrap();
    let proposed = GovernedLoopKernelV1::record_proposal(
        &probed,
        ObservationRefV1::from_digest(digest("caller-cas-observation")),
        proposal("caller-cas-work"),
        ProposalClassV1::Initial,
        &mut Observation::new("caller-cas-preconditions"),
        NOW + 2,
    )
    .unwrap();

    let error = store
        .commit(
            start.state_digest(),
            &probed,
            &proposed,
            CampaignTransitionKindV1::ProposalRecorded,
            NOW + 2,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignStoreErrorV1::StalePredecessor {
            expected,
            authoritative,
        } if expected == *start.state_digest() && authoritative == *probed.state_digest()
    ));
    assert_eq!(store.current().unwrap(), probed);
    assert_eq!(store.replay().unwrap().transitions, 2);
}

#[test]
fn signing_permit_transaction_refuses_stale_caller_without_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut stale_store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let spent = commit_to_spent(&mut stale_store, &start);
    let mut competing_store = CampaignStoreV1::open(&database).unwrap();
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    competing_store
        .commit(
            spent.state_digest(),
            &spent,
            &dispatched,
            CampaignTransitionKindV1::DocketCustodyAccepted,
            NOW + 1,
        )
        .unwrap();

    let Err(error) = stale_store.issuance_signing_permit(spent.state_digest()) else {
        panic!("stale caller must not mint a signing permit")
    };
    assert!(matches!(
        error,
        CampaignStoreErrorV1::StalePredecessor {
            expected,
            authoritative,
        } if expected == *spent.state_digest() && authoritative == *dispatched.state_digest()
    ));
    let connection = rusqlite::Connection::open(&database).unwrap();
    let reservations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM issuance_signing_reservations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reservations, 0);
    assert_eq!(stale_store.current().unwrap(), dispatched);
}

#[test]
fn refusal_transaction_refuses_stale_caller_without_sidecar_write() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut stale_store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let mut competing_store = CampaignStoreV1::open(&database).unwrap();
    let probed = GovernedLoopKernelV1::note_probe(&start).unwrap();
    competing_store
        .commit(
            start.state_digest(),
            &start,
            &probed,
            CampaignTransitionKindV1::ProbeNoted,
            NOW + 1,
        )
        .unwrap();
    let refusal = RefusalOutcomeV1 {
        key: probed.key().clone(),
        at_state_digest: probed.state_digest().clone(),
        code: RefusalCodeV1::RecoveryRequired,
        evidence: Some(digest("stale-refusal-evidence")),
    };

    let error = stale_store
        .record_refusal(start.state_digest(), &refusal, NOW + 2)
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignStoreErrorV1::StalePredecessor {
            expected,
            authoritative,
        } if expected == *start.state_digest() && authoritative == *probed.state_digest()
    ));
    let connection = rusqlite::Connection::open(&database).unwrap();
    let refusals: i64 = connection
        .query_row("SELECT COUNT(*) FROM refusals", [], |row| row.get(0))
        .unwrap();
    assert_eq!(refusals, 0);
    assert_eq!(stale_store.current().unwrap(), probed);
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
    let refusal_identity = store
        .record_refusal(settled.state_digest(), &refusal, NOW + 3)
        .unwrap();

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
    let mut altered_result = result.clone();
    let DocketSealedGovernedRepairResultV1::ScopeExpansionRequired { requirement, .. } =
        &mut altered_result
    else {
        panic!("scope fixture changed kind")
    };
    requirement.requested_delta_digest = digest("substituted-requested-delta");
    let (exact_outcome, exact_requirement) = match &result {
        DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
            outcome,
            requirement,
        } => (
            outcome,
            HumanDecisionRequirementV1::ScopeExpansion(requirement.clone()),
        ),
        DocketSealedGovernedRepairResultV1::ReadjudicationRequired { .. } => unreachable!(),
    };
    let exact_halt = GovernedLoopKernelV1::halt_from_docket_governed_repair(
        &dispatched,
        exact_outcome,
        &exact_requirement,
        HaltReasonRefV1::from_digest(digest("Docket governed repair required")),
    )
    .unwrap();
    assert!(
        store
            .commit_docket_governed_repair_halt(
                dispatched.state_digest(),
                &dispatched,
                &exact_halt,
                &altered_result,
                NOW + 3,
            )
            .is_err(),
        "a nested requested-delta substitution must fail before durable halt"
    );
    assert_eq!(store.current().unwrap(), dispatched);
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
                spent.state_digest(),
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
            .commit_docket_issuance_refusal(
                spent.state_digest(),
                &spent,
                &halted,
                &substituted,
                NOW + 1,
            )
            .is_err()
    );
    assert_eq!(store.current().unwrap(), spent);
    assert_eq!(store.replay().unwrap().ag_spends, 1);

    store
        .commit_docket_issuance_refusal(spent.state_digest(), &spent, &halted, &refusal, NOW + 1)
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
    assert_verification_addressable(&store, &disposition, &verification);
    drop(store);

    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_verification_addressable(&reopened, &disposition, &verification);
    drop(reopened);
    assert_v2_to_v3_verification_migration(&database, &verification);
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
    let verification = store
        .governed_repair_verification_for_disposition(&disposition)
        .unwrap()
        .unwrap();

    assert_request_disposition_verification_substitutions(
        &store,
        &database,
        &request_ref,
        &disposition,
        &verification,
    );
    for column in ["verification_receipt_ref", "verification_record_id"] {
        assert_direct_text_substitution_refuses(&store, &database, &disposition, column);
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
                expected.state_digest(),
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
            start.state_digest(),
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
    for _ in 0..64 {
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
fn replay_and_open_remain_coherent_during_concurrent_transitions() {
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

    // Opening a Store performs a full replay.  Exercise both that startup
    // boundary and repeated replay while the other connection advances the
    // same occurrence through several atomically committed cuts.  Every read
    // may lawfully resolve either side of a commit, but no read may combine a
    // transition journal from one cut with materialized rows from another.
    barrier.wait();
    for _ in 0..256 {
        let reader = CampaignStoreV1::open(&database).unwrap();
        let report = reader.replay().unwrap();
        assert!(report.transitions >= 1);
        reader.current().unwrap().validate_integrity().unwrap();
    }

    let dispatched = writer.join().unwrap();
    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), dispatched);
    assert_eq!(
        reopened.replay().unwrap().current_state_digest,
        *dispatched.state_digest()
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
                start.state_digest(),
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

#[test]
fn safe_integer_boundary_is_inclusive_and_unsafe_api_values_are_fallible() {
    for (label, unsafe_time) in [
        ("first-unsafe", FIRST_UNSAFE_INTEGER),
        ("u64-max", u64::MAX),
    ] {
        let unsafe_directory = tempfile::tempdir().unwrap();
        let unsafe_database = unsafe_directory
            .path()
            .join(format!("{label}-genesis.sqlite"));
        let unsafe_start = initial();
        let unsafe_create = std::panic::catch_unwind(|| {
            CampaignStoreV1::create(&unsafe_database, &unsafe_start, unsafe_time)
        });
        assert!(
            matches!(unsafe_create, Ok(Err(_))),
            "{label} event time must return an error rather than panic while hashing"
        );
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("safe-boundary.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, MAX_SAFE_INTEGER - 1).unwrap();
    let probed = GovernedLoopKernelV1::note_probe(&start).unwrap();
    store
        .commit(
            start.state_digest(),
            &start,
            &probed,
            CampaignTransitionKindV1::ProbeNoted,
            MAX_SAFE_INTEGER,
        )
        .unwrap();
    assert!(store.list_events(MAX_SAFE_INTEGER, 1).unwrap().is_empty());
    assert!(store.list_events(FIRST_UNSAFE_INTEGER, 1).is_err());

    let refusal = RefusalOutcomeV1 {
        key: probed.key().clone(),
        at_state_digest: probed.state_digest().clone(),
        code: RefusalCodeV1::RecoveryRequired,
        evidence: None,
    };
    assert!(
        store
            .record_refusal(probed.state_digest(), &refusal, FIRST_UNSAFE_INTEGER)
            .is_err()
    );
    store
        .record_refusal(probed.state_digest(), &refusal, MAX_SAFE_INTEGER)
        .unwrap();
    assert_eq!(store.last_recorded_at_unix_ms().unwrap(), MAX_SAFE_INTEGER);
    assert_eq!(
        store
            .campaign_state_read(MAX_SAFE_INTEGER)
            .unwrap()
            .last_recorded_at_unix_ms,
        MAX_SAFE_INTEGER
    );

    let transition_directory = tempfile::tempdir().unwrap();
    let transition_database = transition_directory.path().join("unsafe-transition.sqlite");
    let transition_start = initial();
    let mut transition_store =
        CampaignStoreV1::create(&transition_database, &transition_start, NOW).unwrap();
    let transition_successor = GovernedLoopKernelV1::note_probe(&transition_start).unwrap();
    let unsafe_commit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        transition_store.commit(
            transition_start.state_digest(),
            &transition_start,
            &transition_successor,
            CampaignTransitionKindV1::ProbeNoted,
            FIRST_UNSAFE_INTEGER,
        )
    }));
    assert!(matches!(unsafe_commit, Ok(Err(_))));
    assert_eq!(transition_store.current().unwrap(), transition_start);
}

#[test]
fn v4_safe_integer_migration_rolls_back_then_cleanly_retries_exact_sequence_counterexample() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    drop(CampaignStoreV1::create(&database, &start, NOW).unwrap());

    let connection = rusqlite::Connection::open(&database).unwrap();
    demote_safe_integer_schema_to_v4(&connection);
    connection
        .execute("UPDATE transitions SET sequence=9007199254740992", [])
        .unwrap();
    drop(connection);

    assert!(
        CampaignStoreV1::open(&database).is_err(),
        "the exact first unsafe SQL sequence must refuse V5 migration"
    );
    let connection = rusqlite::Connection::open(&database).unwrap();
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let identity: (String, u32) = connection
        .query_row(
            "SELECT schema_name,schema_version FROM store_identity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(version, 4, "failed migration must roll back user_version");
    assert_eq!(
        identity,
        ("ag-governed-loop-campaign-store/v4".to_owned(), 4),
        "failed migration must retain the exact V4 identity"
    );
    connection
        .execute("UPDATE transitions SET sequence=1", [])
        .unwrap();
    drop(connection);

    let reopened = CampaignStoreV1::open(&database).unwrap();
    assert_eq!(reopened.replay().unwrap().transitions, 1);
    drop(reopened);
    let connection = rusqlite::Connection::open(&database).unwrap();
    assert!(
        connection
            .execute("UPDATE transitions SET sequence=9007199254740992", [],)
            .is_err(),
        "the migrated additive trigger must reject the same counterexample"
    );
}

#[test]
fn replay_refuses_safe_but_discontinuous_transition_sequence() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    drop(CampaignStoreV1::create(&database, &start, NOW).unwrap());
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "UPDATE transitions SET sequence=2;
             UPDATE sqlite_sequence SET seq=2 WHERE name='transitions';",
        )
        .unwrap();
    drop(connection);
    assert!(CampaignStoreV1::open(&database).is_err());
}

#[test]
fn replay_strictly_refuses_unsafe_timestamp_inside_canonical_snapshot_blob() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    commit_to_spent(&mut store, &start);
    drop(store);

    let connection = rusqlite::Connection::open(&database).unwrap();
    let original: Vec<u8> = connection
        .query_row(
            "SELECT successor_snapshot_jcs FROM transitions
             WHERE transition_kind='proposal_recorded'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let original = String::from_utf8(original).unwrap();
    let changed = original.replacen(
        &format!("\"expires_at_unix_ms\":{}", NOW + 1_000),
        "\"expires_at_unix_ms\":9007199254740992",
        1,
    );
    assert_ne!(
        changed, original,
        "fixture must contain the proposal expiry"
    );
    connection
        .execute(
            "UPDATE transitions SET successor_snapshot_jcs=?1
             WHERE transition_kind='proposal_recorded'",
            rusqlite::params![changed.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert!(CampaignStoreV1::open(&database).is_err());
}

#[test]
fn v4_migration_and_replay_validate_refusal_timestamp_column() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    let mut store = CampaignStoreV1::create(&database, &start, NOW).unwrap();
    let refusal = RefusalOutcomeV1 {
        key: start.key().clone(),
        at_state_digest: start.state_digest().clone(),
        code: RefusalCodeV1::RecoveryRequired,
        evidence: None,
    };
    store
        .record_refusal(start.state_digest(), &refusal, NOW + 1)
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(&database).unwrap();
    demote_safe_integer_schema_to_v4(&connection);
    connection
        .execute(
            "UPDATE refusals SET recorded_at_unix_ms=9007199254740992",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(CampaignStoreV1::open(&database).is_err());

    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE refusals SET recorded_at_unix_ms=?1",
            rusqlite::params![i64::try_from(NOW + 1).unwrap()],
        )
        .unwrap();
    drop(connection);
    assert!(CampaignStoreV1::open(&database).is_ok());
}

#[test]
fn v4_migration_refuses_unsafe_transition_event_timestamp_and_rolls_back() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let start = initial();
    drop(CampaignStoreV1::create(&database, &start, NOW).unwrap());
    let connection = rusqlite::Connection::open(&database).unwrap();
    demote_safe_integer_schema_to_v4(&connection);
    connection
        .execute(
            "UPDATE transitions SET recorded_at_unix_ms=9007199254740992",
            [],
        )
        .unwrap();
    drop(connection);

    assert!(CampaignStoreV1::open(&database).is_err());
    let connection = rusqlite::Connection::open(&database).unwrap();
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 4, "unsafe event time rolls migration back");
}

#[test]
fn v4_migration_refuses_every_historical_sidecar_timestamp_column() {
    for table in [
        "human_dispositions",
        "human_decision_requests",
        "governed_repair_dispositions",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join(format!("{table}.sqlite"));
        let start = initial();
        drop(CampaignStoreV1::create(&database, &start, NOW).unwrap());
        let connection = rusqlite::Connection::open(&database).unwrap();
        demote_safe_integer_schema_to_v4(&connection);
        let campaign = start.key().campaign.as_str();
        let occurrence = start.key().occurrence.to_string();
        match table {
            "human_dispositions" => {
                connection
                    .execute(
                        "INSERT INTO human_dispositions
                         (decision_id,nonce,campaign_id,occurrence_id,
                          halted_state_digest,verification_ref,artifact_jcs,
                          consumed_at_unix_ms)
                         VALUES ('sha256:decision','sha256:nonce',?1,?2,?3,
                                 'sha256:verification',x'7b7d',9007199254740992)",
                        rusqlite::params![campaign, occurrence, start.state_digest().as_str()],
                    )
                    .unwrap();
            }
            "human_decision_requests" => {
                connection
                    .execute(
                        "INSERT INTO human_decision_requests
                         (request_id,idempotency_key,campaign_id,occurrence_id,
                          halted_state_digest,request_jcs,created_at_unix_ms)
                         VALUES ('sha256:request','sha256:idempotency',?1,?2,?3,
                                 x'7b7d',9007199254740992)",
                        rusqlite::params![campaign, occurrence, start.state_digest().as_str()],
                    )
                    .unwrap();
            }
            "governed_repair_dispositions" => {
                connection
                    .execute(
                        "INSERT INTO human_decision_requests
                         (request_id,idempotency_key,campaign_id,occurrence_id,
                          halted_state_digest,request_jcs,created_at_unix_ms)
                         VALUES ('sha256:request','sha256:idempotency',?1,?2,?3,x'7b7d',1)",
                        rusqlite::params![campaign, occurrence, start.state_digest().as_str()],
                    )
                    .unwrap();
                connection
                    .execute(
                        "INSERT INTO governed_repair_dispositions
                         (decision_id,nonce,request_id,campaign_id,occurrence_id,
                          halted_state_digest,disposition_id,verification_receipt_ref,
                          verification_record_id,verification_jcs,artifact_jcs,
                          consumed_at_unix_ms)
                         VALUES ('sha256:decision','sha256:nonce','sha256:request',?1,?2,?3,
                                 'sha256:disposition','sha256:receipt','sha256:record',
                                 x'7b7d',x'7b7d',9007199254740992)",
                        rusqlite::params![campaign, occurrence, start.state_digest().as_str()],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);

        assert!(
            CampaignStoreV1::open(&database).is_err(),
            "unsafe historical timestamp in {table} must refuse migration"
        );
        let connection = rusqlite::Connection::open(&database).unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 4, "{table} refusal must roll migration back");
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
