//! Subprocess and kernel-interoperability tests for the production standing
//! authority (`ag-standing-resolver`) and its local read-only mandate store.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use ag_app::governed_loop::{
    CampaignEngineV1, EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
    WorkPreconditionV1,
};
use ag_app::governed_ports::CommandStandingResolverV1;
use ag_app::standing_authority::{
    MandateStatusV1, STANDING_AUTHORITY_REQUEST_SCHEMA_V1, STANDING_MANDATE_STORE_SCHEMA_V1,
    StandingAuthorityRequestV1, StandingMandateStoreV1, StandingMandateV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use tempfile::TempDir;
use uuid::Uuid;

const NOW: u64 = 30_000;
/// The deployment identity the tests configure both sides to use.
const RESOLVER_ID: &str = "ag.standing-authority/test-v1";
/// The authority's configured answer lease.
const ANSWER_TTL_MS: u64 = 60_000;
/// AG's kernel maximum accepted standing-answer lifetime.
const MAX_STANDING_TTL_MS: u64 = 60_000;
/// The observation resolver identity the engine is configured to expect.
const OBSERVATION_RESOLVER_ID: &str = "test.observation-resolver/v1";

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-standing-resolver-test/v1", label.as_bytes())
}

fn subject() -> Digest {
    digest("subject")
}

fn scope() -> Digest {
    digest("scope")
}

fn campaign() -> CampaignId {
    CampaignId::from_digest(digest("campaign"))
}

fn occurrence(value: u128) -> OccurrenceId {
    OccurrenceId::from_uuid(Uuid::from_u128(value))
}

fn mandate(
    subject: &Digest,
    scope: &Digest,
    generation: u64,
    status: MandateStatusV1,
    valid_until_unix_ms: u64,
) -> StandingMandateV1 {
    StandingMandateV1 {
        subject: subject.clone(),
        scope: scope.clone(),
        generation,
        status,
        valid_until_unix_ms,
    }
}

fn store(mandates: Vec<StandingMandateV1>) -> StandingMandateStoreV1 {
    StandingMandateStoreV1 {
        schema: STANDING_MANDATE_STORE_SCHEMA_V1.to_owned(),
        mandates,
    }
}

fn request(subject: &Digest, scope: &Digest, now_unix_ms: u64) -> StandingAuthorityRequestV1 {
    StandingAuthorityRequestV1 {
        schema: STANDING_AUTHORITY_REQUEST_SCHEMA_V1.to_owned(),
        key: OccurrenceKeyV1 {
            campaign: campaign(),
            occurrence: occurrence(1),
        },
        observation: ObservationRefV1::from_digest(digest("observation-1")),
        proposal: ProposalRefV1::from_digest(digest("proposal-1")),
        subject: subject.clone(),
        scope: scope.clone(),
        now_unix_ms,
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn run_resolver(store_path: &Path, stdin: &[u8], resolver_id: &str, answer_ttl_ms: u64) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag-standing-resolver"))
        .arg("--mandate-store")
        .arg(store_path)
        .arg("--resolver-id")
        .arg(resolver_id)
        .arg("--answer-ttl-ms")
        .arg(answer_ttl_ms.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

/// Runs the resolver against the given store document and request, requiring
/// a successful semantic answer.
fn resolve(
    directory: &TempDir,
    store_document: &StandingMandateStoreV1,
    request: &StandingAuthorityRequestV1,
) -> CurrentStandingResolutionV2 {
    let store_path = directory.path().join("mandate-store.json");
    write_json(&store_path, store_document);
    let output = run_resolver(
        &store_path,
        &serde_json::to_vec(request).unwrap(),
        RESOLVER_ID,
        ANSWER_TTL_MS,
    );
    assert!(
        output.status.success(),
        "resolver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn current_mandate_answers_current_with_bounded_lease() {
    let directory = tempfile::tempdir().unwrap();
    let grant = mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    );
    let document = store(vec![grant.clone()]);
    let request = request(&subject(), &scope(), NOW);
    let resolution = resolve(&directory, &document, &request);
    assert_eq!(resolution.schema, STANDING_RESOLUTION_SCHEMA_V2);
    assert_eq!(resolution.status, StandingStatusV1::Current);
    assert_eq!(resolution.mandate, grant.mandate_ref());
    assert_eq!(resolution.resolver_id, RESOLVER_ID);
    assert_eq!(resolution.key, request.key);
    assert_eq!(resolution.observation, request.observation);
    assert_eq!(resolution.proposal, request.proposal);
    assert_eq!(resolution.subject, request.subject);
    assert_eq!(resolution.scope, request.scope);
    assert_eq!(resolution.resolved_at_unix_ms, NOW);
    // The mandate outlives the configured lease, so the lease bounds the
    // answer.
    assert_eq!(resolution.expires_at_unix_ms, NOW + ANSWER_TTL_MS);
}

#[test]
fn repeated_resolution_is_byte_deterministic() {
    let directory = tempfile::tempdir().unwrap();
    let document = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    )]);
    let store_path = directory.path().join("mandate-store.json");
    write_json(&store_path, &document);
    let stdin = serde_json::to_vec(&request(&subject(), &scope(), NOW)).unwrap();
    let first = run_resolver(&store_path, &stdin, RESOLVER_ID, ANSWER_TTL_MS);
    let second = run_resolver(&store_path, &stdin, RESOLVER_ID, ANSWER_TTL_MS);
    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(!first.stdout.is_empty());
}

#[test]
fn no_mandate_answers_absent() {
    let directory = tempfile::tempdir().unwrap();
    let document = store(vec![]);
    let resolution = resolve(&directory, &document, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Absent);
    assert_eq!(resolution.resolved_at_unix_ms, NOW);
}

#[test]
fn revoked_mandate_answers_revoked() {
    let directory = tempfile::tempdir().unwrap();
    let revoked = mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Revoked,
        NOW + 100_000,
    );
    let document = store(vec![revoked.clone()]);
    let resolution = resolve(&directory, &document, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Revoked);
    assert_eq!(resolution.mandate, revoked.mandate_ref());
}

#[test]
fn mandate_expiry_is_exact_at_equality() {
    let directory = tempfile::tempdir().unwrap();
    // `valid_until == now` is expired; the boundary is exclusive.
    let expired = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW,
    )]);
    let resolution = resolve(&directory, &expired, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Expired);
    // One millisecond later is still valid.
    let valid = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 1,
    )]);
    let resolution = resolve(&directory, &valid, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Current);
    assert_eq!(resolution.expires_at_unix_ms, NOW + 1);
}

#[test]
fn answer_lease_is_clipped_to_mandate_validity() {
    let directory = tempfile::tempdir().unwrap();
    // Mandate validity shorter than the configured lease: the mandate wins.
    let short = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 5_000,
    )]);
    let resolution = resolve(&directory, &short, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Current);
    assert_eq!(resolution.expires_at_unix_ms, NOW + 5_000);
    // Configured lease shorter than mandate validity: the lease wins.
    let store_path = directory.path().join("long.json");
    write_json(
        &store_path,
        &store(vec![mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Active,
            NOW + 100_000,
        )]),
    );
    let output = run_resolver(
        &store_path,
        &serde_json::to_vec(&request(&subject(), &scope(), NOW)).unwrap(),
        RESOLVER_ID,
        5_000,
    );
    assert!(output.status.success());
    let resolution: CurrentStandingResolutionV2 = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(resolution.expires_at_unix_ms, NOW + 5_000);
}

#[test]
fn highest_generation_governs_and_older_generations_do_not_rescue() {
    let directory = tempfile::tempdir().unwrap();
    // A newer revoked generation supersedes an older active one: standing is
    // revoked, and the older active mandate cannot rescue it.
    let older_active = mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    );
    let newer_revoked = mandate(
        &subject(),
        &scope(),
        2,
        MandateStatusV1::Revoked,
        NOW + 100_000,
    );
    let document = store(vec![older_active, newer_revoked.clone()]);
    let resolution = resolve(&directory, &document, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Revoked);
    assert_eq!(resolution.mandate, newer_revoked.mandate_ref());
    // A newer active generation supersedes an older revoked one and is the
    // mandate the Current answer names.
    let older_revoked = mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Revoked,
        NOW + 100_000,
    );
    let newer_active = mandate(
        &subject(),
        &scope(),
        2,
        MandateStatusV1::Active,
        NOW + 100_000,
    );
    let document = store(vec![older_revoked, newer_active.clone()]);
    let resolution = resolve(&directory, &document, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Current);
    assert_eq!(resolution.mandate, newer_active.mandate_ref());
}

#[test]
fn subject_and_scope_matching_is_exact() {
    let directory = tempfile::tempdir().unwrap();
    let document = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    )]);
    let wrong_scope = resolve(
        &directory,
        &document,
        &request(&subject(), &digest("other-scope"), NOW),
    );
    assert_eq!(wrong_scope.status, StandingStatusV1::Absent);
    let wrong_subject = resolve(
        &directory,
        &document,
        &request(&digest("other-subject"), &scope(), NOW),
    );
    assert_eq!(wrong_subject.status, StandingStatusV1::Absent);
}

#[test]
fn mandate_identity_is_content_derived() {
    let baseline = mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    );
    assert_eq!(baseline.mandate_ref(), baseline.mandate_ref());
    let variations = [
        mandate(
            &digest("other-subject"),
            &scope(),
            1,
            MandateStatusV1::Active,
            NOW + 100_000,
        ),
        mandate(
            &subject(),
            &digest("other-scope"),
            1,
            MandateStatusV1::Active,
            NOW + 100_000,
        ),
        mandate(
            &subject(),
            &scope(),
            2,
            MandateStatusV1::Active,
            NOW + 100_000,
        ),
        mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Revoked,
            NOW + 100_000,
        ),
        mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Active,
            NOW + 200_000,
        ),
    ];
    for variation in &variations {
        assert_ne!(baseline.mandate_ref(), variation.mandate_ref());
    }
}

#[test]
fn currentness_identity_tracks_the_exact_answer() {
    let directory = tempfile::tempdir().unwrap();
    let active = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    )]);
    let base_request = request(&subject(), &scope(), NOW);
    let baseline = resolve(&directory, &active, &base_request);
    assert_eq!(baseline.currentness, baseline.currentness);
    // A different mandate status is a different present-tense answer.
    let revoked = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Revoked,
        NOW + 100_000,
    )]);
    let changed_status = resolve(&directory, &revoked, &base_request);
    assert_ne!(baseline.currentness, changed_status.currentness);
    // A different answer window is a different answer.
    let later_request = request(&subject(), &scope(), NOW + 1);
    let changed_window = resolve(&directory, &active, &later_request);
    assert_ne!(baseline.currentness, changed_window.currentness);
    // A different mandate generation is a different answer.
    let generation_two = store(vec![mandate(
        &subject(),
        &scope(),
        2,
        MandateStatusV1::Active,
        NOW + 100_000,
    )]);
    let changed_mandate = resolve(&directory, &generation_two, &base_request);
    assert_ne!(baseline.currentness, changed_mandate.currentness);
}

#[test]
fn duplicate_or_unordered_store_records_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let request = request(&subject(), &scope(), NOW);
    let stdin = serde_json::to_vec(&request).unwrap();
    // Two records for the same (subject, scope, generation): ambiguous, must
    // never resolve by file order.
    let duplicate = store(vec![
        mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Active,
            NOW + 100_000,
        ),
        mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Revoked,
            NOW + 100_000,
        ),
    ]);
    let store_path = directory.path().join("duplicate.json");
    write_json(&store_path, &duplicate);
    let output = run_resolver(&store_path, &stdin, RESOLVER_ID, ANSWER_TTL_MS);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // Non-canonical record order is rejected rather than silently sorted.
    let unordered = store(vec![
        mandate(
            &subject(),
            &scope(),
            2,
            MandateStatusV1::Active,
            NOW + 100_000,
        ),
        mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Active,
            NOW + 100_000,
        ),
    ]);
    let store_path = directory.path().join("unordered.json");
    write_json(&store_path, &unordered);
    let output = run_resolver(&store_path, &stdin, RESOLVER_ID, ANSWER_TTL_MS);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn asserted_identity_fields_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let document = serde_json::to_value(store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    )]))
    .unwrap();
    // A mandate document trying to assert its own identity is malformed:
    // mandate identity is derived, never caller-supplied.
    let mut forged = document.clone();
    forged["mandates"][0]["mandate_ref"] =
        serde_json::Value::String("sha256:".to_owned() + &"0".repeat(64));
    let store_path = directory.path().join("forged.json");
    write_json(&store_path, &forged);
    let stdin = serde_json::to_vec(&request(&subject(), &scope(), NOW)).unwrap();
    let output = run_resolver(&store_path, &stdin, RESOLVER_ID, ANSWER_TTL_MS);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // Unknown store-level fields are equally malformed.
    let mut unknown = document;
    unknown["operator_note"] = serde_json::Value::String("trust me".to_owned());
    let store_path = directory.path().join("unknown.json");
    write_json(&store_path, &unknown);
    let output = run_resolver(&store_path, &stdin, RESOLVER_ID, ANSWER_TTL_MS);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_inputs_fail_the_process_not_the_status() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("mandate-store.json");
    write_json(
        &store_path,
        &store(vec![mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Active,
            NOW + 100_000,
        )]),
    );
    // Garbage request bytes.
    let output = run_resolver(&store_path, b"not json", RESOLVER_ID, ANSWER_TTL_MS);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // The wrong request schema.
    let mut wrong_schema = serde_json::to_value(request(&subject(), &scope(), NOW)).unwrap();
    wrong_schema["schema"] =
        serde_json::Value::String("ag.governed-loop.standing-request/v0".to_owned());
    let output = run_resolver(
        &store_path,
        &serde_json::to_vec(&wrong_schema).unwrap(),
        RESOLVER_ID,
        ANSWER_TTL_MS,
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // A malformed store document.
    let store_path = directory.path().join("garbage.json");
    std::fs::write(&store_path, b"not json").unwrap();
    let output = run_resolver(
        &store_path,
        &serde_json::to_vec(&request(&subject(), &scope(), NOW)).unwrap(),
        RESOLVER_ID,
        ANSWER_TTL_MS,
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn empty_resolver_identity_and_zero_lease_are_configuration_errors() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("mandate-store.json");
    write_json(&store_path, &store(vec![]));
    let stdin = serde_json::to_vec(&request(&subject(), &scope(), NOW)).unwrap();
    let output = run_resolver(&store_path, &stdin, "", ANSWER_TTL_MS);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let output = run_resolver(&store_path, &stdin, RESOLVER_ID, 0);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

// --- Kernel interoperability through the real governed-loop engine ---

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

fn proposal() -> ExactWorkProposalV1 {
    ExactWorkProposalV1::new(
        campaign(),
        subject(),
        scope(),
        "test.engine-work/v1".to_owned(),
        digest("work-1"),
        None,
    )
    .unwrap()
}

fn catalog() -> ExactWorkCatalogV1 {
    ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            "test.engine-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.engine-work/v1".to_owned(),
                subject: subject(),
                scope: scope(),
                precondition: WorkPreconditionV1::default(),
            },
        )]),
    }
}

struct ObservationBoundary;

impl ObservationResolverV1 for ObservationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV2, ExternalBoundaryErrorV1> {
        let basis = decision_basis("condition.clean", "delivery.not_required");
        Ok(ObservationResolutionV2 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V2.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                basis.decision_basis_digest().unwrap(),
            ),
            basis,
            resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
            subject: request.subject.clone(),
            status: ObservationStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

/// Writes the shell wrapper AG's command standing resolver invokes: the port
/// takes an executable with no argv, so the store path, identity, and lease
/// are bound here exactly as a deployment would bind them.
fn write_resolver_wrapper(directory: &TempDir, store_path: &Path) -> std::path::PathBuf {
    let wrapper = directory.path().join("standing-resolver-wrapper.sh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec \"{}\" --mandate-store \"{}\" --resolver-id \"{}\" --answer-ttl-ms {}\n",
            env!("CARGO_BIN_EXE_ag-standing-resolver"),
            store_path.display(),
            RESOLVER_ID,
            ANSWER_TTL_MS,
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    wrapper
}

fn create_engine(directory: &TempDir) -> CampaignEngineV1 {
    CampaignEngineV1::create(
        &directory.path().join("campaign.sqlite"),
        campaign(),
        occurrence(1),
        ProgramBasisRefV1::from_digest(digest("program")),
        digest("work-1"),
        ResidualSetV1::default(),
        budget(),
        NOW,
    )
    .unwrap()
}

#[test]
fn real_resolver_output_passes_kernel_validation_at_decide_and_authorize() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("mandate-store.json");
    write_json(
        &store_path,
        &store(vec![mandate(
            &subject(),
            &scope(),
            1,
            MandateStatusV1::Active,
            NOW + 100_000,
        )]),
    );
    let wrapper = write_resolver_wrapper(&directory, &store_path);
    let mut standing = CommandStandingResolverV1::new(&wrapper);
    let mut observation = ObservationBoundary;

    let mut engine = create_engine(&directory);
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal(),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    // The kernel validates the real binary's v2 answer: schema, resolver
    // identity, exact echoes, TTL window, freshness, and status.
    let decided = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        decided.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );

    // Governance revokes between decide and authorize by replacing the store
    // with a newer revoked generation; the read-only authority loads it
    // fresh, and the spend-time re-resolution refuses.
    write_json(
        &store_path,
        &store(vec![
            mandate(
                &subject(),
                &scope(),
                1,
                MandateStatusV1::Active,
                NOW + 100_000,
            ),
            mandate(
                &subject(),
                &scope(),
                2,
                MandateStatusV1::Revoked,
                NOW + 100_000,
            ),
        ]),
    );
    let before = engine.current().unwrap();
    assert!(
        engine
            .authorize(
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 4
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);

    // Governance restores standing with a still newer active generation; the
    // same proposal authorizes without any new evidence or occurrence.
    write_json(
        &store_path,
        &store(vec![
            mandate(
                &subject(),
                &scope(),
                1,
                MandateStatusV1::Active,
                NOW + 100_000,
            ),
            mandate(
                &subject(),
                &scope(),
                2,
                MandateStatusV1::Revoked,
                NOW + 100_000,
            ),
            mandate(
                &subject(),
                &scope(),
                3,
                MandateStatusV1::Active,
                NOW + 100_000,
            ),
        ]),
    );
    let authorized = engine
        .authorize(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 5,
        )
        .unwrap();
    assert_eq!(
        authorized.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn a_well_formed_lie_from_the_configured_authority_is_accepted() {
    // The mandate store below declares Active standing. Nothing in AG or in
    // the authority can tell whether that declaration is *true* in the world;
    // mandate-store truthfulness is an environmental/deployment assumption.
    // Content addressing binds provenance to the exact content evaluated, not
    // to its truth. This test deliberately pins that a well-formed answer
    // from the configured authority is accepted as-is.
    let directory = tempfile::tempdir().unwrap();
    let document = store(vec![mandate(
        &subject(),
        &scope(),
        1,
        MandateStatusV1::Active,
        NOW + 100_000,
    )]);
    let resolution = resolve(&directory, &document, &request(&subject(), &scope(), NOW));
    assert_eq!(resolution.status, StandingStatusV1::Current);
    assert_eq!(resolution.resolver_id, RESOLVER_ID);
}
