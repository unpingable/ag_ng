//! External-crate coverage for the R4 pre-spend discovery product boundary.
//!
//! These specimens use only [`GovernedCampaignServiceV1`] and `ag-loopctl`.
//! They never open the private Store or call the campaign mutation engine.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};

use ag_app::governed_product::*;
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use uuid::Uuid;

const NOW: u64 = 90_000;
const WORK_SCHEMA: &str = "qualification-fixture.pre-spend-repair/v1";

fn digest(label: &str) -> Digest {
    Digest::hash_domain(
        "qualification-fixture-not-human-authority.pre-spend/v1",
        label.as_bytes(),
    )
}

fn write_executable(path: &Path, source: &str) -> PinnedDeploymentFileV1 {
    std::fs::write(path, source).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).unwrap();
    PinnedDeploymentFileV1 {
        path: path.to_owned(),
        identity: Digest::hash_bytes(&std::fs::read(path).unwrap()),
    }
}

fn scope_with_paths(paths: impl IntoIterator<Item = String>) -> CanonicalEffectScopeV1 {
    CanonicalEffectScopeV1::new(
        "source_repair".to_owned(),
        paths
            .into_iter()
            .map(|path| CanonicalEffectResourceV1 {
                resource: "repository".to_owned(),
                path,
                operations: vec![CanonicalEffectOperationV1::Modify],
            })
            .collect(),
    )
    .unwrap()
}

fn original_scope() -> CanonicalEffectScopeV1 {
    scope_with_paths((0..28).map(|index| format!("crates/nq-store/src/fixture-{index:02}.rs")))
}

fn delta(path: &str) -> CanonicalEffectScopeV1 {
    scope_with_paths([path.to_owned()])
}

fn policy_root(
    directory: &Path,
    admitted_scope: &CanonicalEffectScopeV1,
) -> GovernedAgPolicyRootV1 {
    let clock = write_executable(
        &directory.join("clock"),
        &format!("#!/bin/sh\nprintf '{NOW}\\n'\n"),
    );
    let observation = write_executable(
        &directory.join("observation.py"),
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.observation-resolution/v1","key":r["key"],"observation":r["observation"],"currentness":d("observation-current"),"normalized_preconditions":d("preconditions"),"subject":r["subject"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"fresh_until_unix_ms":r["now_unix_ms"]+1000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    );
    let standing = write_executable(
        &directory.join("standing.py"),
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.standing-resolution/v1","resolution":d("standing-resolution"),"currentness":d("standing-current"),"mandate":d("mandate"),"key":r["key"],"observation":r["observation"],"proposal":r["proposal"],"subject":r["subject"],"scope":r["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+1000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    );
    let catalog_path = directory.join("catalog.json");
    let catalog = ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        policy_basis: digest("catalog-policy"),
        entries: BTreeMap::from([(
            WORK_SCHEMA.to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: WORK_SCHEMA.to_owned(),
                subject: digest("subject"),
                scope: admitted_scope.digest(),
            },
        )]),
    };
    std::fs::write(
        &catalog_path,
        JcsDocument::canonicalize(&catalog).unwrap().as_bytes(),
    )
    .unwrap();
    GovernedAgPolicyRootV1 {
        schema: GOVERNED_AG_POLICY_ROOT_SCHEMA_V1.to_owned(),
        policy_label: "qualification-fixture-not-human-authority".to_owned(),
        consequence_clock: clock,
        observation_resolver: observation,
        standing_resolver: standing,
        exact_work_catalog: PinnedDeploymentFileV1 {
            path: catalog_path.clone(),
            identity: Digest::hash_bytes(&std::fs::read(catalog_path).unwrap()),
        },
        controlling_review: None,
    }
}

struct ProposedFixture {
    directory: tempfile::TempDir,
    database: PathBuf,
    service: GovernedCampaignServiceV1,
    proposed: OccurrenceViewV1,
    original: ExactWorkProposalV1,
}

fn proposed_fixture(label: &str) -> ProposedFixture {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let original_scope = original_scope();
    let admitted_scope = original_scope
        .exact_additive_union(&delta(
            "crates/nq-store/src/governed_projection_capacity.rs",
        ))
        .unwrap();
    let campaign = CampaignId::from_digest(digest(&format!("campaign-{label}")));
    let occurrence = OccurrenceId::from_uuid(Uuid::new_v4());
    let mut service = GovernedCampaignServiceV1::create(
        &database,
        CreateCampaignV1 {
            campaign: campaign.clone(),
            occurrence,
            program: ProgramBasisRefV1::from_digest(digest("program")),
            residuals: ResidualSetV1::default(),
            budget: LoopBudgetV1 {
                retry_limit: 2,
                retries_used: 0,
                probe_limit: 2,
                probes_used: 0,
                escalation_limit: 2,
                escalations_used: 0,
            },
            idempotency_key: digest(&format!("create-{label}")),
            governed_ag_policy_root: policy_root(directory.path(), &admitted_scope),
            governed_repair_verifier_root: None,
            governed_docket_adapter_root: None,
        },
    )
    .unwrap();
    let initial = service.state().unwrap().current;
    let original = ExactWorkProposalV1::new(
        campaign,
        digest("subject"),
        original_scope,
        WORK_SCHEMA.to_owned(),
        digest("work"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("fixture-not-authority")],
            expires_at_unix_ms: NOW + 10_000,
        },
        None,
    )
    .unwrap();
    let proposed = service
        .record_proposal(
            initial.state_digest(),
            ObservationRefV1::from_digest(digest("observation")),
            original.clone(),
            ProposalClassV1::Initial,
        )
        .unwrap();
    ProposedFixture {
        directory,
        database,
        service,
        proposed,
        original,
    }
}

fn assert_reopen_and_fresh_governance(
    fixture: ProposedFixture,
    result: &PreSpendScopeDiscoveryResultV1,
    request: RecordPreSpendScopeDiscoveryV1,
) {
    let artifact = fixture
        .service
        .artifact(result.discovery.as_digest())
        .unwrap()
        .unwrap();
    assert_eq!(
        artifact.kind,
        GovernedArtifactKindV1::PreSpendScopeDiscovery
    );
    let discovery: PreSpendScopeDiscoveryV1 =
        ag_protocol::strict_json_from_slice(&artifact.bytes).unwrap();
    discovery.validate().unwrap();
    assert_eq!(discovery.reference(), &result.discovery);
    assert_eq!(discovery.original_proposal, fixture.original.reference());
    assert_eq!(discovery.revised_proposal, request.revised_proposal);

    drop(fixture.service);
    let mut reopened = GovernedCampaignServiceV1::open(&fixture.database).unwrap();
    assert_eq!(
        reopened
            .artifact(result.discovery.as_digest())
            .unwrap()
            .unwrap()
            .bytes,
        artifact.bytes
    );
    assert_eq!(
        reopened.state().unwrap().current.key,
        result.revised_occurrence
    );
    let before_fresh_proposal = reopened.state().unwrap().current;
    assert!(
        reopened
            .require_standing(before_fresh_proposal.state_digest())
            .is_err()
    );
    assert_eq!(
        reopened.state().unwrap().current.state_digest,
        before_fresh_proposal.state_digest
    );
    let freshly_proposed = reopened
        .record_proposal(
            before_fresh_proposal.state_digest(),
            ObservationRefV1::from_digest(digest("revised-observation")),
            request.exact_revised_proposal,
            ProposalClassV1::Successor,
        )
        .unwrap();
    assert_eq!(
        freshly_proposed.program_counter,
        ProgramCounterV1::ProposalRecorded
    );
}

fn typed_halt(fixture: &mut ProposedFixture, label: &str) -> OccurrenceViewV1 {
    fixture
        .service
        .halt_pre_spend_scope_insufficiency(HaltPreSpendScopeInsufficiencyV1 {
            expected_state_digest: fixture.proposed.state_digest.clone(),
            diagnostic_basis: digest(&format!("diagnostic-{label}")),
            idempotency_key: digest(&format!("halt-{label}")),
        })
        .unwrap()
        .halted
}

fn discovery_request(
    fixture: &ProposedFixture,
    halted: &OccurrenceViewV1,
    path: &str,
    revised_occurrence: OccurrenceId,
    idempotency_label: &str,
) -> RecordPreSpendScopeDiscoveryV1 {
    let diagnostic_basis = halted
        .halted
        .as_ref()
        .unwrap()
        .pre_spend_scope_insufficiency
        .as_ref()
        .unwrap()
        .diagnostic_basis
        .clone();
    discovery_request_with_diagnostic(
        fixture,
        halted,
        path,
        revised_occurrence,
        idempotency_label,
        diagnostic_basis,
    )
}

fn discovery_request_with_diagnostic(
    fixture: &ProposedFixture,
    halted: &OccurrenceViewV1,
    path: &str,
    revised_occurrence: OccurrenceId,
    idempotency_label: &str,
    diagnostic_basis: Digest,
) -> RecordPreSpendScopeDiscoveryV1 {
    let requested_delta = delta(path);
    let revised_scope = fixture
        .original
        .effect_scope()
        .exact_additive_union(&requested_delta)
        .unwrap();
    let exact_revised_proposal = fixture
        .original
        .derive_pre_spend_revision(revised_scope.clone())
        .unwrap();
    RecordPreSpendScopeDiscoveryV1 {
        expected_state_digest: halted.state_digest.clone(),
        predecessor: halted.key.clone(),
        original_proposal: fixture.original.reference(),
        original_scope_identity: fixture.original.scope().clone(),
        diagnostic_basis,
        requested_delta,
        revised_scope,
        revised_proposal: exact_revised_proposal.reference(),
        exact_revised_proposal,
        revised_occurrence,
        idempotency_key: digest(idempotency_label),
    }
}

#[test]
fn public_product_records_reopens_and_freshly_governs_exact_revision() {
    let mut fixture = proposed_fixture("public-happy");
    let original_proposal = fixture.original.clone();
    let proposed_state = fixture.proposed.state_digest.clone();
    let halted = typed_halt(&mut fixture, "public-happy");
    fixture.service = GovernedCampaignServiceV1::open(&fixture.database).unwrap();
    assert_eq!(
        fixture
            .service
            .occurrence(&halted.key)
            .unwrap()
            .unwrap()
            .state_digest,
        halted.state_digest
    );
    let request = discovery_request(
        &fixture,
        &halted,
        "crates/nq-store/src/governed_projection_capacity.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(29)),
        "discovery-public-happy",
    );
    let result = fixture
        .service
        .record_pre_spend_scope_discovery(request.clone())
        .unwrap();
    assert!(!result.replayed);
    assert_ne!(result.predecessor, result.revised_occurrence);

    let predecessor = fixture
        .service
        .occurrence(&result.predecessor)
        .unwrap()
        .unwrap();
    assert_eq!(predecessor.program_counter, ProgramCounterV1::Halted);
    assert_eq!(predecessor.prior_state_digest, proposed_state);
    assert_eq!(
        predecessor.proposal_contract.as_ref().unwrap().exact_record,
        original_proposal
    );
    let predecessor_halt = predecessor.halted.as_ref().unwrap();
    assert!(predecessor_halt.pre_spend_scope_insufficiency.is_some());
    assert!(predecessor_halt.governed_repair_requirement.is_none());
    assert!(predecessor_halt.open_human_decision_request.is_none());

    let revised = fixture
        .service
        .occurrence(&result.revised_occurrence)
        .unwrap()
        .unwrap();
    assert_eq!(
        revised.program_counter,
        ProgramCounterV1::ObservationRequired
    );
    assert!(revised.proposal_contract.is_none());
    assert!(revised.used_human_decisions.is_empty());
    assert_eq!(revised.authority_history, AuthorityHistoryV1::default());
    let constraint = revised.pre_spend_revision.as_ref().unwrap();
    assert_eq!(constraint.predecessor, result.predecessor);
    assert_eq!(constraint.discovery, result.discovery);
    assert_eq!(constraint.revised_proposal, request.revised_proposal);
    assert_eq!(
        constraint.exact_revised_proposal,
        request.exact_revised_proposal
    );
    assert_eq!(fixture.service.replay().unwrap().ag_spends, 0);
    assert_eq!(fixture.service.replay().unwrap().docket_attempts, 0);

    assert_reopen_and_fresh_governance(fixture, &result, request);
}

#[test]
fn nonauthorizing_refusal_does_not_strand_typed_pre_spend_discovery() {
    let mut fixture = proposed_fixture("refusal-preserved");
    let halted = typed_halt(&mut fixture, "refusal-preserved");
    let refusal = fixture
        .service
        .record_refusal(
            halted.state_digest(),
            RefusalCodeV1::RecoveryRequired,
            Some(digest("refusal-evidence")),
        )
        .unwrap();
    assert!(fixture.service.artifact(&refusal).unwrap().is_some());
    assert!(
        fixture
            .service
            .allowed_transitions()
            .unwrap()
            .allowed_transitions
            .contains(&GovernedOperationV1::RecordPreSpendScopeDiscovery)
    );
    let request = discovery_request(
        &fixture,
        &halted,
        "crates/nq-store/src/governed_projection_capacity.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(79)),
        "discovery-after-refusal",
    );
    let result = fixture
        .service
        .record_pre_spend_scope_discovery(request)
        .unwrap();
    assert!(!result.replayed);
    assert!(fixture.service.artifact(&refusal).unwrap().is_some());
}

fn assert_generic_halt_cannot_launder_discovery() {
    let mut generic = proposed_fixture("generic-halt");
    let generic_halted = generic
        .service
        .halt(
            generic.proposed.state_digest(),
            HaltReasonRefV1::from_digest(digest("generic-halt")),
        )
        .unwrap();
    let generic_request = discovery_request_with_diagnostic(
        &generic,
        &generic_halted,
        "crates/nq-store/src/governed_projection_capacity.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(229)),
        "generic-laundering",
        digest("generic-diagnostic"),
    );
    let generic_head = generic.service.state().unwrap();
    assert!(
        generic
            .service
            .record_pre_spend_scope_discovery(generic_request)
            .is_err()
    );
    assert_eq!(
        generic.service.state().unwrap().current,
        generic_head.current
    );
    assert_eq!(
        generic.service.state().unwrap().event_sequence,
        generic_head.event_sequence
    );
}

#[test]
fn public_product_replay_collision_stale_and_generic_halt_fail_closed() {
    let mut fixture = proposed_fixture("public-replay");
    let halted = typed_halt(&mut fixture, "public-replay");
    let halted_cut = fixture.service.state().unwrap();
    let exact_halt_replay = fixture
        .service
        .halt_pre_spend_scope_insufficiency(HaltPreSpendScopeInsufficiencyV1 {
            expected_state_digest: fixture.proposed.state_digest.clone(),
            diagnostic_basis: digest("diagnostic-public-replay"),
            idempotency_key: digest("halt-public-replay"),
        })
        .unwrap();
    assert!(exact_halt_replay.replayed);
    assert_eq!(exact_halt_replay.halted, halted);
    assert!(
        fixture
            .service
            .halt_pre_spend_scope_insufficiency(HaltPreSpendScopeInsufficiencyV1 {
                expected_state_digest: fixture.proposed.state_digest.clone(),
                diagnostic_basis: digest("changed-diagnostic-public-replay"),
                idempotency_key: digest("halt-public-replay"),
            })
            .is_err()
    );
    assert_eq!(fixture.service.state().unwrap().current, halted_cut.current);
    assert_eq!(
        fixture.service.state().unwrap().event_sequence,
        halted_cut.event_sequence
    );
    let request = discovery_request(
        &fixture,
        &halted,
        "crates/nq-store/src/governed_projection_capacity.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(129)),
        "discovery-public-replay",
    );
    let committed = fixture
        .service
        .record_pre_spend_scope_discovery(request.clone())
        .unwrap();
    let replay = fixture
        .service
        .record_pre_spend_scope_discovery(request.clone())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.discovery, committed.discovery);
    assert_eq!(replay.revised_occurrence, committed.revised_occurrence);

    let changed = discovery_request(
        &fixture,
        &halted,
        "crates/nq-store/src/unrelated-neighbor.rs",
        request.revised_occurrence,
        "discovery-public-replay",
    );
    let head = fixture.service.state().unwrap();
    assert!(
        fixture
            .service
            .record_pre_spend_scope_discovery(changed)
            .is_err()
    );
    assert_eq!(fixture.service.state().unwrap().current, head.current);
    assert_eq!(
        fixture.service.state().unwrap().event_sequence,
        head.event_sequence
    );

    let mut stale = request;
    stale.idempotency_key = digest("stale-request");
    stale.expected_state_digest = fixture.proposed.state_digest.clone();
    assert!(
        fixture
            .service
            .record_pre_spend_scope_discovery(stale)
            .is_err()
    );
    assert_eq!(fixture.service.state().unwrap().current, head.current);

    assert_generic_halt_cannot_launder_discovery();
}

fn concurrent_result(
    database: &Path,
    barrier: &Barrier,
    request: RecordPreSpendScopeDiscoveryV1,
) -> Result<PreSpendScopeDiscoveryResultV1, String> {
    let mut service =
        GovernedCampaignServiceV1::open(database).map_err(|error| error.to_string())?;
    barrier.wait();
    service
        .record_pre_spend_scope_discovery(request)
        .map_err(|error| error.to_string())
}

fn run_concurrently(
    database: &Path,
    requests: Vec<RecordPreSpendScopeDiscoveryV1>,
) -> Vec<Result<PreSpendScopeDiscoveryResultV1, String>> {
    let barrier = Arc::new(Barrier::new(requests.len() + 1));
    let handles = requests
        .into_iter()
        .map(|request| {
            let database = database.to_owned();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || concurrent_result(&database, barrier.as_ref(), request))
        })
        .collect::<Vec<_>>();
    barrier.wait();
    handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect()
}

fn assert_two_occurrences(database: &Path) -> Vec<OccurrenceViewV1> {
    GovernedCampaignServiceV1::open(database)
        .unwrap()
        .list_occurrences(&OccurrencePageRequestV1 {
            after: None,
            limit: 10,
            program_counter: None,
            governed_repair_pending: None,
        })
        .unwrap()
        .items
}

#[test]
fn public_product_concurrent_identical_and_conflicting_discoveries_have_one_successor() {
    let mut identical = proposed_fixture("concurrent-identical");
    let halted = typed_halt(&mut identical, "concurrent-identical");
    let request = discovery_request(
        &identical,
        &halted,
        "crates/nq-store/src/governed_projection_capacity.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(329)),
        "concurrent-identical",
    );
    drop(identical.service);
    let results = run_concurrently(&identical.database, vec![request.clone(), request]);
    let successes = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .collect::<Vec<_>>();
    assert!(
        !successes.is_empty(),
        "at least one exact caller must commit: {results:?}"
    );
    assert!(
        successes
            .iter()
            .all(|result| result.discovery == successes[0].discovery)
    );
    let occurrences = assert_two_occurrences(&identical.database);
    assert_eq!(occurrences.len(), 2);
    let discoveries = occurrences
        .iter()
        .flat_map(|occurrence| occurrence.artifacts.iter())
        .filter(|artifact| artifact.kind == GovernedArtifactKindV1::PreSpendScopeDiscovery)
        .map(|artifact| artifact.identity.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(discoveries.len(), 1);

    let mut conflicting = proposed_fixture("concurrent-conflicting");
    let halted = typed_halt(&mut conflicting, "concurrent-conflicting");
    let first = discovery_request(
        &conflicting,
        &halted,
        "crates/nq-store/src/governed_projection_capacity.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(429)),
        "concurrent-first",
    );
    let second = discovery_request(
        &conflicting,
        &halted,
        "crates/nq-store/src/unrelated-neighbor.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(430)),
        "concurrent-second",
    );
    drop(conflicting.service);
    let results = run_concurrently(&conflicting.database, vec![first, second]);
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(assert_two_occurrences(&conflicting.database).len(), 2);
}

#[test]
fn cli_strictly_refuses_malformed_discovery_records_before_consequence() {
    let mut fixture = proposed_fixture("strict-cli");
    let halted = typed_halt(&mut fixture, "strict-cli");
    let request = discovery_request(
        &fixture,
        &halted,
        "crates/nq-store/src/governed_projection_capacity.rs",
        OccurrenceId::from_uuid(Uuid::from_u128(529)),
        "strict-cli-discovery",
    );
    let before = fixture.service.state().unwrap();
    drop(fixture.service);
    let canonical = JcsDocument::canonicalize(&request).unwrap();
    let value: serde_json::Value = serde_json::from_slice(canonical.as_bytes()).unwrap();
    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), serde_json::Value::Bool(true));
    let mut missing = value.clone();
    missing.as_object_mut().unwrap().remove("requested_delta");
    let mut unsafe_integer = value.clone();
    unsafe_integer["exact_revised_proposal"]["expires_at_unix_ms"] =
        serde_json::json!(9_007_199_254_740_992_u64);
    let expected_field = serde_json::to_string(&request.expected_state_digest).unwrap();
    let duplicate = format!(
        "{{\"expected_state_digest\":{expected_field},{}",
        &canonical.as_str()[1..]
    )
    .into_bytes();
    let cases = [
        (
            "unknown",
            JcsDocument::canonicalize(&unknown)
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
        (
            "missing",
            JcsDocument::canonicalize(&missing)
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
        ("duplicate", duplicate),
        ("malformed", b"{".to_vec()),
        ("noncanonical", serde_json::to_vec_pretty(&value).unwrap()),
        (
            "unsafe-integer",
            serde_json::to_vec(&unsafe_integer).unwrap(),
        ),
    ];
    for (label, bytes) in cases {
        let input = fixture.directory.path().join(format!("{label}.json"));
        std::fs::write(&input, bytes).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_ag-loopctl"))
            .args([
                "record-pre-spend-scope-discovery",
                "--database",
                fixture.database.to_str().unwrap(),
                "--input",
                input.to_str().unwrap(),
                "--expected-state",
                request.expected_state_digest.as_str(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{label}: {output:?}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["code"].as_str().is_some_and(|code| !code.is_empty()));
        let reopened = GovernedCampaignServiceV1::open(&fixture.database).unwrap();
        let state = reopened.state().unwrap();
        assert_eq!(state.current, before.current, "{label}");
        assert_eq!(state.event_sequence, before.event_sequence, "{label}");
    }

    let input = fixture.directory.path().join("canonical.json");
    std::fs::write(&input, canonical.as_bytes()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ag-loopctl"))
        .args([
            "record-pre-spend-scope-discovery",
            "--database",
            fixture.database.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--expected-state",
            request.expected_state_digest.as_str(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: PreSpendScopeDiscoveryResultV1 = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result.revised_occurrence.occurrence,
        request.revised_occurrence
    );
}
