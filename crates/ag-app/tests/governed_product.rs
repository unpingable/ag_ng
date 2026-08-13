//! Stable product API tests. Fixture verifier records are explicitly not
//! human authority and never stand in for production verification.

use ag_app::governed_product::*;
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use ag_store::campaign::CampaignStoreV1;
use rusqlite::Connection;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use uuid::Uuid;

const NOW: u64 = 80_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain(
        "qualification-fixture-not-human-authority/v1",
        label.as_bytes(),
    )
}

fn sorted(labels: &[&str]) -> Vec<Digest> {
    let mut values = labels.iter().map(|label| digest(label)).collect::<Vec<_>>();
    values.sort();
    values
}

fn root() -> GovernedRepairVerifierRootV1 {
    root_with_executable(Path::new("/bin/true"))
}

fn root_with_executable(executable: &Path) -> GovernedRepairVerifierRootV1 {
    GovernedRepairVerifierRootV1 {
        schema: GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1.to_owned(),
        verifier_label: "qualification-fixture-not-human-authority".to_owned(),
        executable: executable.into(),
        executable_identity: Digest::hash_bytes(&std::fs::read(executable).unwrap()),
        catalog: GovernedRepairVerifierCatalogV1 {
            schema: GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1.to_owned(),
            profiles: vec![GovernedRepairVerifierProfileRecordV1 {
                profile: digest("profile"),
                principal: HumanPrincipalRefV1::from_digest(digest("principal")),
                mandate: MandateRefV1::from_digest(digest("mandate")),
            }],
        },
    }
}

fn verifier_fixture(directory: &Path) -> std::path::PathBuf {
    let path = directory.join("qualification-fixture-not-human-authority.py");
    std::fs::write(
        &path,
        r"#!/usr/bin/env python3
import hashlib,json,sys
def jcs(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def domain(name,payload):
    name=name.encode()
    value=(b'ag-ng\0digest\0v1\0'+len(name).to_bytes(16,'big')+name+
           len(payload).to_bytes(16,'big')+payload)
    return 'sha256:'+hashlib.sha256(value).hexdigest()
request=json.load(sys.stdin)
out={
  'schema':'ag.governed-loop.governed-repair-verification/v1',
  'disposition':domain('ag.governed-loop.governed-repair-disposition/v1',jcs(request['artifact'])),
  'request':domain('ag.governed-loop.human-decision-request/v1',jcs(request['request'])),
  'halted_state_digest':request['request']['halted_state_digest'],
  'verifier_profile':request['expected_profile'],
  'verifier_root':request['expected_root'],
  'verifier_executable':request['expected_executable'],
  'verification':domain('qualification-fixture-not-human-authority/v1',b'verification'),
  'verified_at_unix_ms':request['now_unix_ms'],
  'expires_at_unix_ms':request['now_unix_ms']+1,
}
sys.stdout.write(json.dumps(out,sort_keys=True,separators=(',',':')))
",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();
    path
}

fn pinned(path: &Path) -> PinnedDeploymentFileV1 {
    PinnedDeploymentFileV1 {
        path: path.to_owned(),
        identity: Digest::hash_bytes(&std::fs::read(path).unwrap()),
    }
}

fn policy_root(directory: &Path) -> GovernedAgPolicyRootV1 {
    let clock = directory.join("governed-clock");
    std::fs::write(&clock, format!("#!/bin/sh\nprintf '%s\\n' {NOW}\n")).unwrap();
    let observation = directory.join("governed-observation.py");
    std::fs::write(
        &observation,
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.observation-resolution/v1","key":r["key"],"observation":r["observation"],"currentness":d("currentness"),"normalized_preconditions":d("conditions"),"subject":r["subject"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"fresh_until_unix_ms":r["now_unix_ms"]+100}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .unwrap();
    let standing = directory.join("governed-standing.py");
    std::fs::write(
        &standing,
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.standing-resolution/v1","resolution":d("standing-resolution"),"currentness":d("standing-current"),"mandate":d("mandate"),"key":r["key"],"observation":r["observation"],"proposal":r["proposal"],"subject":r["subject"],"scope":r["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+100}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .unwrap();
    for path in [&clock, &observation, &standing] {
        let mut mode = std::fs::metadata(path).unwrap().permissions();
        mode.set_mode(0o700);
        std::fs::set_permissions(path, mode).unwrap();
    }
    let catalog_path = directory.join("exact-work-catalog.json");
    let catalog = ag_app::governed_loop::ExactWorkCatalogV1 {
        schema: ag_app::governed_loop::EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        policy_basis: digest("unused-catalog-policy"),
        entries: std::collections::BTreeMap::new(),
    };
    std::fs::write(
        &catalog_path,
        ag_primitives::JcsDocument::canonicalize(&catalog)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    GovernedAgPolicyRootV1 {
        schema: GOVERNED_AG_POLICY_ROOT_SCHEMA_V1.to_owned(),
        policy_label: "qualification-fixture-not-authority".to_owned(),
        consequence_clock: pinned(&clock),
        observation_resolver: pinned(&observation),
        standing_resolver: pinned(&standing),
        exact_work_catalog: pinned(&catalog_path),
        controlling_review: None,
    }
}

fn docket_root(directory: &Path, trust_config: &Path) -> GovernedDocketAdapterRootV1 {
    let state_directory = directory.join("docket-state");
    std::fs::create_dir_all(&state_directory).unwrap();
    let executable = Path::new("/bin/true");
    GovernedDocketAdapterRootV1 {
        schema: GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1.to_owned(),
        adapter_label: "qualification-fixture-not-human-authority".to_owned(),
        docket_program: pinned(executable),
        state_directory,
        trust_config: pinned(trust_config),
        standing_resolver: pinned(executable),
        executor_adapter: pinned(executable),
        executor_config: pinned(trust_config),
        checkpoint_verifier: None,
        issuer_principal: "qualification-fixture-not-human-authority".to_owned(),
        issuer_key_id: "qualification-fixture-not-human-authority".to_owned(),
        issuer_key: pinned(trust_config),
    }
}

fn assert_no_raw_state_key(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            assert!(
                !object.contains_key("state"),
                "product occurrence wire projection leaked nested raw state: {value}"
            );
            for nested in object.values() {
                assert_no_raw_state_key(nested);
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                assert_no_raw_state_key(nested);
            }
        }
        _ => {}
    }
}

fn creation(root: Option<GovernedRepairVerifierRootV1>, directory: &Path) -> CreateCampaignV1 {
    CreateCampaignV1 {
        campaign: CampaignId::from_digest(digest("campaign")),
        occurrence: OccurrenceId::from_uuid(Uuid::from_u128(1)),
        program: ProgramBasisRefV1::from_digest(digest("program")),
        residuals: ResidualSetV1::default(),
        budget: LoopBudgetV1 {
            retry_limit: 2,
            retries_used: 0,
            probe_limit: 1,
            probes_used: 0,
            escalation_limit: 1,
            escalations_used: 0,
        },
        idempotency_key: digest("create-idempotency"),
        governed_ag_policy_root: policy_root(directory),
        governed_repair_verifier_root: root,
        governed_docket_adapter_root: None,
    }
}

struct ScopeDecisionFixture {
    database: PathBuf,
    halted: OccurrenceViewV1,
    request: HumanDecisionRequestV1,
    original_scope: CanonicalEffectScopeV1,
    delta: CanonicalEffectScopeV1,
}

fn assert_proposal_contract(view: &OccurrenceViewV1, proposal: &ProposalRefV1) {
    let contract = view
        .proposal_contract
        .as_ref()
        .expect("recorded proposal contract is product-visible");
    assert_eq!(&contract.proposal, proposal);
    assert_eq!(contract.nonclaims, vec![digest("proposal-nonclaim")]);
    assert_eq!(contract.expires_at_unix_ms, NOW + 1_000);
}

fn scope_decision_fixture(directory: &Path) -> ScopeDecisionFixture {
    let database = directory.join("campaign.sqlite");
    let verifier = verifier_fixture(directory);
    let mut service = GovernedCampaignServiceV1::create(
        &database,
        creation(Some(root_with_executable(&verifier)), directory),
    )
    .unwrap();
    let initial = service.state().unwrap().current;
    let original_scope = CanonicalEffectScopeV1::new(
        "repair".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "bounded/original".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let proposal = ExactWorkProposalV1::new(
        initial.key().campaign.clone(),
        digest("subject"),
        original_scope.clone(),
        "test.product/v1".to_owned(),
        digest("work"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap();
    assert!(initial.proposal_contract.is_none());
    let proposal_ref = proposal.reference();
    let proposed = service
        .record_proposal(
            initial.state_digest(),
            ObservationRefV1::from_digest(digest("observation")),
            proposal,
            ProposalClassV1::Initial,
        )
        .unwrap();
    assert_proposal_contract(&proposed, &proposal_ref);
    let halted = service
        .halt(
            proposed.state_digest(),
            HaltReasonRefV1::from_digest(digest("scope-insufficient")),
        )
        .unwrap();
    assert_eq!(halted.proposal_contract, proposed.proposal_contract);
    let delta = CanonicalEffectScopeV1::new(
        "repair".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "bounded/adjacent".to_owned(),
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
            path: "bounded/adjacent".to_owned(),
            operation: CanonicalEffectOperationV1::Modify,
        },
        reason: digest("reason"),
        dependency_evidence: sorted(&["dependency"]),
        limitations: sorted(&["limitation"]),
        docket_outcome: None,
        unauthorized_effect_not_performed: true,
    });
    let request = service
        .create_decision_request(CreateDecisionRequestV1 {
            expected_state_digest: halted.state_digest().clone(),
            requirement,
            required_verifier_profile: digest("profile"),
            decision_consequences: sorted(&["approve", "reject"]),
            nonclaims: sorted(&["not-standing"]),
            idempotency_key: digest("request-idempotency"),
            expires_at_unix_ms: NOW + 50,
        })
        .unwrap();
    drop(service);
    ScopeDecisionFixture {
        database,
        halted,
        request,
        original_scope,
        delta,
    }
}

fn repair_checkpoint() -> GovernedRepairCheckpointV1 {
    GovernedRepairCheckpointV1 {
        repository: digest("repository"),
        commit: "1111111111111111111111111111111111111111".to_owned(),
        tree: "2222222222222222222222222222222222222222".to_owned(),
        diff_identity: None,
        content_manifest: digest("checkpoint-content"),
        docket_checkpoint: None,
    }
}

fn approval(fixture: &ScopeDecisionFixture) -> GovernedRepairDispositionV1 {
    GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: fixture.halted.key().campaign.clone(),
        occurrence: fixture.halted.key().occurrence,
        halted_state_digest: fixture.halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::ApproveExactExpansion {
            request: fixture.request.reference(),
            successor_occurrence: OccurrenceId::from_uuid(Uuid::from_u128(2)),
            approved_delta: fixture.delta.clone(),
            successor_scope: fixture.original_scope.exact_union(&fixture.delta).unwrap(),
            checkpoint: repair_checkpoint(),
        },
        decision: HumanDecisionIdV1::from_digest(digest("approve-decision")),
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("mandate")),
        verifier_profile: digest("profile"),
        nonce: HumanNonceRefV1::from_digest(digest("approve-nonce")),
        expires_at_unix_ms: NOW + 40,
    }
}

fn rejection(fixture: &ScopeDecisionFixture) -> GovernedRepairDispositionV1 {
    GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: fixture.halted.key().campaign.clone(),
        occurrence: fixture.halted.key().occurrence,
        halted_state_digest: fixture.halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::Reject {
            request: fixture.request.reference(),
            reason: digest("reject-reason"),
        },
        decision: HumanDecisionIdV1::from_digest(digest("reject-decision")),
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("mandate")),
        verifier_profile: digest("profile"),
        nonce: HumanNonceRefV1::from_digest(digest("reject-nonce")),
        expires_at_unix_ms: NOW + 40,
    }
}

#[test]
fn create_is_exact_idempotent_and_product_pages_are_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let request = creation(Some(root()), directory.path());
    let service = GovernedCampaignServiceV1::create(&database, request.clone()).unwrap();
    assert_eq!(service.state().unwrap().event_sequence, 1);
    assert_eq!(
        GovernedCampaignServiceV1::create(&database, request.clone())
            .unwrap()
            .state()
            .unwrap()
            .event_sequence,
        1
    );
    let mut collision = request;
    collision.idempotency_key = digest("changed-key");
    assert!(GovernedCampaignServiceV1::create(&database, collision).is_err());
    assert!(
        service
            .list_occurrences(&OccurrencePageRequestV1 {
                after: None,
                limit: 1001,
                program_counter: None,
                governed_repair_pending: None,
            })
            .is_err()
    );
    assert!(
        service
            .list_events(&PageRequestV1 {
                after: None,
                limit: 1001
            })
            .is_err()
    );
    let occurrence = service
        .list_occurrences(&OccurrencePageRequestV1 {
            after: None,
            limit: 1,
            program_counter: None,
            governed_repair_pending: None,
        })
        .unwrap();
    assert_eq!(occurrence.items.len(), 1);
    assert!(
        service
            .list_occurrences(&OccurrencePageRequestV1 {
                after: None,
                limit: 1,
                program_counter: Some(ProgramCounterV1::Halted),
                governed_repair_pending: None,
            })
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(
        service
            .list_occurrences(&OccurrencePageRequestV1 {
                after: None,
                limit: 1,
                program_counter: Some(ProgramCounterV1::ObservationRequired),
                governed_repair_pending: Some(false),
            })
            .unwrap()
            .items
            .len(),
        1
    );
    assert_eq!(occurrence.items[0], service.state().unwrap().current);
    assert_eq!(
        service
            .occurrence(occurrence.items[0].key())
            .unwrap()
            .unwrap(),
        occurrence.items[0]
    );
    let projected = serde_json::to_value(&occurrence.items[0]).unwrap();
    assert_no_raw_state_key(&projected);
    assert_eq!(
        projected.get("schema").and_then(serde_json::Value::as_str),
        Some(GOVERNED_OCCURRENCE_VIEW_SCHEMA_V1)
    );
    let events = service
        .list_events(&PageRequestV1 {
            after: None,
            limit: 1,
        })
        .unwrap();
    assert_eq!(events.items.len(), 1);
}

#[test]
fn docket_adapter_root_is_genesis_pinned_and_substitution_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let trust_a = directory.path().join("trust-a.json");
    let trust_b = directory.path().join("trust-b.json");
    std::fs::write(&trust_a, b"{\"trust\":\"a\"}\n").unwrap();
    std::fs::write(&trust_b, b"{\"trust\":\"b\"}\n").unwrap();

    let mut original = creation(None, directory.path());
    original.governed_docket_adapter_root = Some(docket_root(directory.path(), &trust_a));
    GovernedCampaignServiceV1::create(&database, original.clone()).unwrap();
    assert!(GovernedCampaignServiceV1::open(&database).is_ok());

    let mut substituted = original;
    substituted.governed_docket_adapter_root = Some(docket_root(directory.path(), &trust_b));
    assert!(GovernedCampaignServiceV1::create(&database, substituted).is_err());
    assert!(GovernedCampaignServiceV1::open(&database).is_ok());
}

#[test]
fn ag_policy_root_is_genesis_pinned_and_mutated_deployment_input_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let request = creation(None, directory.path());
    let clock_path = request
        .governed_ag_policy_root
        .consequence_clock
        .path
        .clone();
    GovernedCampaignServiceV1::create(&database, request).unwrap();
    assert!(GovernedCampaignServiceV1::open(&database).is_ok());

    std::fs::write(&clock_path, b"#!/bin/sh\nprintf '80001\\n'\n").unwrap();
    assert!(GovernedCampaignServiceV1::open(&database).is_err());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end product specimen keeps every exact request binding visible"
)]
fn verifier_root_and_request_are_pinned_and_open_request_view_is_current() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let verifier = verifier_fixture(directory.path());
    let mut service = GovernedCampaignServiceV1::create(
        &database,
        creation(Some(root_with_executable(&verifier)), directory.path()),
    )
    .unwrap();
    let initial = service.state().unwrap().current;
    let scope = CanonicalEffectScopeV1::new(
        "repair".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "bounded/original".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let proposal = ExactWorkProposalV1::new(
        initial.key().campaign.clone(),
        digest("subject"),
        scope.clone(),
        "test.product/v1".to_owned(),
        digest("work"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap();
    let proposed = service
        .record_proposal(
            initial.state_digest(),
            ObservationRefV1::from_digest(digest("observation")),
            proposal,
            ProposalClassV1::Initial,
        )
        .unwrap();
    let halted = service
        .halt(
            proposed.state_digest(),
            HaltReasonRefV1::from_digest(digest("scope-insufficient")),
        )
        .unwrap();
    let delta = CanonicalEffectScopeV1::new(
        "repair".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "bounded/adjacent".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let requirement = HumanDecisionRequirementV1::ScopeExpansion(ScopeExpansionRequiredV1 {
        schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
        original_scope: scope.clone(),
        original_scope_digest: scope.digest(),
        requested_delta: delta.clone(),
        requested_delta_digest: delta.digest(),
        blocked_operation: BlockedEffectOperationV1 {
            resource: "repository".to_owned(),
            path: "bounded/adjacent".to_owned(),
            operation: CanonicalEffectOperationV1::Modify,
        },
        reason: digest("reason"),
        dependency_evidence: sorted(&["dependency"]),
        limitations: sorted(&["limitation"]),
        docket_outcome: None,
        unauthorized_effect_not_performed: true,
    });
    let request = service
        .create_decision_request(CreateDecisionRequestV1 {
            expected_state_digest: halted.state_digest().clone(),
            requirement,
            required_verifier_profile: digest("profile"),
            decision_consequences: sorted(&["approve", "reject"]),
            nonclaims: sorted(&["not-standing"]),
            idempotency_key: digest("request-idempotency"),
            expires_at_unix_ms: NOW + 50,
        })
        .unwrap();
    assert!(
        service
            .state()
            .unwrap()
            .allowed_transitions
            .contains(&"submit_disposition".to_owned())
    );
    let artifact = service
        .artifact(request.reference().as_digest())
        .unwrap()
        .expect("request artifact");
    assert_eq!(artifact.bytes_identity, Digest::hash_bytes(&artifact.bytes));
    let request_ref = request.reference();
    assert_eq!(
        service.decision_request(&request_ref).unwrap(),
        Some(request.clone())
    );

    let disposition = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: halted.key().campaign.clone(),
        occurrence: halted.key().occurrence,
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::Reject {
            request: request_ref.clone(),
            reason: digest("review-rejected"),
        },
        decision: HumanDecisionIdV1::from_digest(digest("decision")),
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("mandate")),
        verifier_profile: digest("profile"),
        nonce: HumanNonceRefV1::from_digest(digest("nonce")),
        expires_at_unix_ms: NOW + 40,
    };
    let submitted = service
        .submit_governed_disposition(SubmitGovernedDispositionV1 {
            expected_state_digest: halted.state_digest().clone(),
            request: request_ref,
            artifact: disposition,
        })
        .unwrap();
    assert!(!submitted.replayed);
    assert!(
        submitted
            .current
            .halted()
            .unwrap()
            .governed_repair_closed()
            .is_some()
    );

    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE governed_repair_verifier_root SET config_jcs=?1 WHERE singleton=1",
            [b"{}".as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(GovernedCampaignServiceV1::open(&database).is_err());
}

#[test]
fn concurrent_identical_governed_dispositions_have_one_durable_winner() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = scope_decision_fixture(directory.path());
    let artifact = approval(&fixture);
    let artifact_ref = artifact.reference();
    let submission = SubmitGovernedDispositionV1 {
        expected_state_digest: fixture.halted.state_digest().clone(),
        request: fixture.request.reference(),
        artifact: artifact.clone(),
    };
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let database = fixture.database.clone();
            let submission = submission.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut service = GovernedCampaignServiceV1::open(&database).unwrap();
                barrier.wait();
                service.submit_governed_disposition(submission)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| !result.replayed).count(), 1);
    assert_eq!(results.iter().filter(|result| result.replayed).count(), 1);
    assert!(
        results
            .iter()
            .all(|result| result.disposition == artifact_ref)
    );

    let store = CampaignStoreV1::open(&fixture.database).unwrap();
    let replay = store.replay().unwrap();
    assert_eq!(replay.human_decision_requests, 1);
    assert_eq!(replay.governed_repair_dispositions, 1);
    assert_eq!(replay.transitions, 5);
    assert_eq!(
        store.governed_repair_disposition(&artifact_ref).unwrap(),
        Some(artifact)
    );
    let occurrences = store.list_occurrences(None, 10).unwrap();
    assert_eq!(
        occurrences.len(),
        2,
        "successor must be created exactly once"
    );
    assert_eq!(
        occurrences
            .iter()
            .filter(
                |snapshot| snapshot.key().occurrence == OccurrenceId::from_uuid(Uuid::from_u128(2))
            )
            .count(),
        1
    );
    let connection = Connection::open(&fixture.database).unwrap();
    let consumed: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM human_decision_requests
             WHERE consumed_by_decision_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(consumed, 1, "the request is consumed by one decision only");
}

#[test]
fn concurrent_conflicting_governed_dispositions_have_one_durable_winner() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = scope_decision_fixture(directory.path());
    let approved = approval(&fixture);
    let rejected = rejection(&fixture);
    let approved_ref = approved.reference();
    let rejected_ref = rejected.reference();
    let barrier = Arc::new(Barrier::new(3));
    let handles = [approved.clone(), rejected.clone()]
        .into_iter()
        .map(|artifact| {
            let database = fixture.database.clone();
            let expected_state_digest = fixture.halted.state_digest().clone();
            let request = fixture.request.reference();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let artifact_ref = artifact.reference();
                let mut service = GovernedCampaignServiceV1::open(&database).unwrap();
                barrier.wait();
                (
                    artifact_ref,
                    service.submit_governed_disposition(SubmitGovernedDispositionV1 {
                        expected_state_digest,
                        request,
                        artifact,
                    }),
                )
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_err()).count(),
        1
    );
    let winner = results
        .iter()
        .find_map(|(identity, result)| result.as_ref().ok().map(|_| identity.clone()))
        .unwrap();
    let loser = if winner == approved_ref {
        rejected_ref
    } else {
        approved_ref.clone()
    };

    let store = CampaignStoreV1::open(&fixture.database).unwrap();
    let replay = store.replay().unwrap();
    assert_eq!(replay.human_decision_requests, 1);
    assert_eq!(replay.governed_repair_dispositions, 1);
    assert!(
        store
            .governed_repair_disposition(&winner)
            .unwrap()
            .is_some()
    );
    assert_eq!(store.governed_repair_disposition(&loser).unwrap(), None);
    let occurrences = store.list_occurrences(None, 10).unwrap();
    let approval_won = winner == approved_ref;
    assert_eq!(occurrences.len(), if approval_won { 2 } else { 1 });
    assert_eq!(
        occurrences
            .iter()
            .filter(
                |snapshot| snapshot.key().occurrence == OccurrenceId::from_uuid(Uuid::from_u128(2))
            )
            .count(),
        usize::from(approval_won),
        "concurrent conflict cannot duplicate a successor"
    );
    assert_eq!(replay.transitions, if approval_won { 5 } else { 4 });
    let connection = Connection::open(&fixture.database).unwrap();
    let consumed: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM human_decision_requests
             WHERE consumed_by_decision_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        consumed, 1,
        "only the winning decision consumes the request"
    );
}

#[test]
fn logical_crash_after_halt_before_request_retrieval_preserves_exact_request() {
    let directory = tempfile::tempdir().unwrap();
    // This fixture commits Halted and the non-authorizing request, then drops
    // its service without ever retrieving the request through the product API.
    let fixture = scope_decision_fixture(directory.path());

    let reopened = GovernedCampaignServiceV1::open(&fixture.database).unwrap();
    assert_eq!(
        reopened.state().unwrap().current.program_counter(),
        ProgramCounterV1::Halted
    );
    let first = reopened
        .decision_request(&fixture.request.reference())
        .unwrap();
    let replay = reopened
        .decision_request(&fixture.request.reference())
        .unwrap();
    assert_eq!(first, Some(fixture.request.clone()));
    assert_eq!(replay, first, "request retrieval is read-only replay");
    let report = reopened.replay().unwrap();
    assert_eq!(report.human_decision_requests, 1);
    assert_eq!(report.governed_repair_dispositions, 0);
}

#[test]
fn logical_crash_after_verification_requires_fresh_verification_and_successor_has_no_issuance() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = scope_decision_fixture(directory.path());
    let artifact = approval(&fixture);

    // The Store-owned witness is process-local. Dropping it before the commit
    // models the exact verification/commit crash cut: no durable decision or
    // successor is allowed to appear.
    let store = CampaignStoreV1::open(&fixture.database).unwrap();
    let verified = store
        .verify_governed_repair_disposition(
            fixture.halted.state_digest(),
            &fixture.request.reference(),
            artifact.clone(),
            NOW + 4,
        )
        .unwrap();
    drop(verified);
    drop(store);

    let reopened_store = CampaignStoreV1::open(&fixture.database).unwrap();
    assert_eq!(
        reopened_store
            .replay()
            .unwrap()
            .governed_repair_dispositions,
        0
    );
    assert_eq!(reopened_store.list_occurrences(None, 10).unwrap().len(), 1);
    assert_eq!(
        reopened_store
            .human_decision_request(&fixture.request.reference())
            .unwrap(),
        Some(fixture.request.clone())
    );
    drop(reopened_store);

    // A fresh process must invoke the configured verifier again. Only that
    // newly verified occurrence may atomically consume the request and create
    // the distinct successor.
    let mut service = GovernedCampaignServiceV1::open(&fixture.database).unwrap();
    let result = service
        .submit_governed_disposition(SubmitGovernedDispositionV1 {
            expected_state_digest: fixture.halted.state_digest().clone(),
            request: fixture.request.reference(),
            artifact,
        })
        .unwrap();
    assert!(!result.replayed);
    assert_eq!(
        result.current.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    drop(service);

    // A second logical crash cut after successor creation but before any fresh
    // standing/spend/issuance preserves only an authority-empty successor.
    let successor_store = CampaignStoreV1::open(&fixture.database).unwrap();
    let successor = successor_store.current().unwrap();
    assert_eq!(
        successor.key().occurrence,
        OccurrenceId::from_uuid(Uuid::from_u128(2))
    );
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(successor.ag_spend().is_none());
    assert!(successor.issuance().is_none());
    assert_eq!(
        successor_store
            .replay()
            .unwrap()
            .governed_repair_dispositions,
        1
    );
    assert_eq!(successor_store.list_occurrences(None, 10).unwrap().len(), 2);
}

fn assert_source_census(source: &str, needle: &str, expected: usize) {
    assert_eq!(
        source.matches(needle).count(),
        expected,
        "load-bearing governed-repair source census changed for {needle:?}"
    );
}

#[test]
fn structural_census_keeps_store_owned_verification_halt_and_successor_path_exclusive() {
    let engine = include_str!("../src/governed_loop.rs");
    let product = include_str!("../src/governed_product.rs");
    let cli = include_str!("../src/bin/ag-loopctl.rs");
    let store = include_str!("../../ag-store/src/campaign.rs");

    // One engine bridge ingests a sealed Docket result and one bridge invokes
    // the Store-owned verifier/atomic disposition commit.
    assert_source_census(engine, "commit_docket_governed_repair_halt(", 1);
    assert_source_census(engine, "verify_governed_repair_disposition(", 1);
    assert_source_census(
        engine,
        "commit_verified_governed_repair_disposition(verified)",
        1,
    );

    // The opaque witness is bound back to its Store file, then the request is
    // consumed by a conditional update in the same Immediate transaction as
    // the halted/successor transition writes.
    assert_source_census(store, "store_file_identity(&self.path)? != store_file", 1);
    assert_source_census(
        store,
        "UPDATE human_decision_requests SET consumed_by_decision_id=?1",
        1,
    );
    assert_source_census(
        store,
        "WHERE request_id=?2 AND consumed_by_decision_id IS NULL",
        1,
    );

    // Product clients cannot inject a Docket port. The deployment-owned root
    // has one private constructor used by the three canonical operations:
    // dispatch, reconcile, and restart recovery.
    assert_source_census(product, "fn docket_port(&self)", 1);
    assert_source_census(product, ".docket_port()?", 3);
    assert_source_census(product, "CommandDocketCustodyPortV1::new(", 1);

    // The CLI is only a client of the canonical product surface. It cannot
    // inject a clock, observation/standing resolver, catalog, legacy human
    // verifier, or the retired parallel disposition path per operation.
    assert!(!cli.contains("GateArguments"));
    assert!(!cli.contains("ApplyDisposition"));
    assert!(!cli.contains("now_unix_ms"));
    assert!(!cli.contains("CommandObservationResolverV1"));
    assert!(!cli.contains("CommandStandingResolverV1"));
    assert!(!cli.contains("CommandHumanDispositionVerifierV1"));
}

#[test]
fn invalid_or_absent_root_fails_before_or_at_governed_request_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let invalid_database = directory.path().join("invalid.sqlite");
    let mut invalid = root();
    invalid.catalog.profiles.clear();
    assert!(
        GovernedCampaignServiceV1::create(
            &invalid_database,
            creation(Some(invalid), directory.path())
        )
        .is_err()
    );
    assert!(!invalid_database.exists());

    let database = directory.path().join("absent.sqlite");
    let service =
        GovernedCampaignServiceV1::create(&database, creation(None, directory.path())).unwrap();
    assert!(service.state().is_ok());
}

#[test]
fn verifier_root_is_genesis_bound_and_cannot_be_installed_or_removed_later() {
    let directory = tempfile::tempdir().unwrap();
    let rooted_database = directory.path().join("rooted.sqlite");
    GovernedCampaignServiceV1::create(&rooted_database, creation(Some(root()), directory.path()))
        .unwrap();
    let connection = Connection::open(&rooted_database).unwrap();
    connection
        .execute("DELETE FROM governed_repair_verifier_root", [])
        .unwrap();
    drop(connection);
    assert!(GovernedCampaignServiceV1::open(&rooted_database).is_err());

    let rootless_database = directory.path().join("rootless.sqlite");
    GovernedCampaignServiceV1::create(&rootless_database, creation(None, directory.path()))
        .unwrap();
    let configured = root();
    let bytes = ag_primitives::JcsDocument::canonicalize(&configured).unwrap();
    let identity = Digest::hash_domain(GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1, bytes.as_bytes());
    let connection = Connection::open(&rootless_database).unwrap();
    connection
        .execute(
            "INSERT INTO governed_repair_verifier_root
             (singleton,config_identity,config_jcs) VALUES (1,?1,?2)",
            rusqlite::params![identity.as_str(), bytes.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert!(GovernedCampaignServiceV1::open(&rootless_database).is_err());
}
