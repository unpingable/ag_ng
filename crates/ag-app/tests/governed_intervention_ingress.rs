//! Cross-process qualification of the authenticated governed-intervention loading dock.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};

use ag_app::governed_loop::CampaignEngineV1;
use ag_app::governed_ports::{CommandGovernedInterventionVerifierV1, GovernedRuntimeProfileV1};
use ag_app::intervention_ingress::{
    InterventionSubmissionLedgerV1, max_submission_bytes, read_exact_input, verify_submission_bytes,
};
use ag_campaign::governed::{GovernedInterventionRequestV1, HumanAuthorityScopeV1};
use ag_operator_ui::render;
use ag_operator_ui::source::{OperatorReaderV1, OperatorSourceConfigV1, hex_encode};
use ag_primitives::{Digest, JcsDocument};
use ag_store::campaign::RUNTIME_PROFILE_DIGEST_DOMAIN_V1;

const SUBMITTER_PKCS8_HEX: &str = "3051020101300506032b657004220420c226c22f628685cd349518c28eff015fd216a106bb49534286dceed3202b1c0e81210028d8b71d122a31cfd39f26313275119934a021918f5d37d100ad2f27acbaf776";

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn write_jcs(path: &Path, value: &Value) {
    fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
}

fn invoke(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ag-loopctl"))
        .args(arguments)
        .output()
        .unwrap()
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn value(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "ag-loopctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct Fixture {
    root: tempfile::TempDir,
    profile: PathBuf,
    database: PathBuf,
    submitter_key: PathBuf,
    verifier: PathBuf,
}

impl Fixture {
    fn create(label: &str) -> Self {
        Self::create_with_verifier_schema(label, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the full one-shot deployment fixture is intentionally visible in one place"
    )]
    fn create_with_verifier_schema(label: &str, supported_schema: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        let state = root.path().join("state");
        let secrets = root.path().join("secrets");
        for path in [&config, &state, &secrets] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let verifier = config.join("human-verifier");
        let verifier_schema = if supported_schema {
            "ag.governed-loop.intervention-verification-response/v1"
        } else {
            "ag.governed-loop.intervention-verification-response/unsupported"
        };
        fs::write(
            &verifier,
            format!(
                "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{{\"schema\":\"{verifier_schema}\",\"verification\":\"{}\"}}'\n",
                digest('e')
            ),
        )
        .unwrap();
        fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700)).unwrap();
        let inert = config.join("inert-boundary");
        fs::write(&inert, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&inert, fs::Permissions::from_mode(0o700)).unwrap();

        let catalog = config.join("catalog.json");
        write_jcs(
            &catalog,
            &json!({
                "schema": "ag.governed-loop.exact-work-catalog/v1",
                "entries": {
                    "fixture.work/v1": {
                        "work_schema": "fixture.work/v1",
                        "subject": digest('d'),
                        "scope": digest('c'),
                        "precondition": {"required": [], "forbidden": []}
                    }
                }
            }),
        );
        let trust = config.join("docket-trust.json");
        write_jcs(&trust, &json!({}));

        let key_bytes: Vec<u8> = (0..SUBMITTER_PKCS8_HEX.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&SUBMITTER_PKCS8_HEX[offset..offset + 2], 16).unwrap())
            .collect();
        let submitter_key = secrets.join("intervention-submitter.pk8");
        fs::write(&submitter_key, &key_bytes).unwrap();
        fs::set_permissions(&submitter_key, fs::Permissions::from_mode(0o600)).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes).unwrap();
        let public_key = config.join("intervention-submitter.pub");
        fs::write(&public_key, key_pair.public_key().as_ref()).unwrap();

        let issuer_key = secrets.join("issuer.pk8");
        fs::write(&issuer_key, &key_bytes).unwrap();
        fs::set_permissions(&issuer_key, fs::Permissions::from_mode(0o600)).unwrap();
        let enrollment = config.join("runtime-profile-enrollment.json");
        write_jcs(
            &enrollment,
            &json!({
                "schema": "ag.governed-loop.runtime-profile-enrollment/v1",
                "profile_label": label,
                "observation_resolver": inert,
                "observation_resolver_id": "fixture-observation/v1",
                "standing_resolver": inert,
                "standing_resolver_id": "fixture-standing/v1",
                "max_standing_ttl_ms": 60000,
                "exact_work_catalog": catalog,
                "controlling_review": null,
                "docket": {
                    "schema": "ag.governed-loop.docket-root-enrollment/v1",
                    "docket_program": inert,
                    "state_directory": state.join("docket"),
                    "trust_config": trust,
                    "standing_resolver": inert,
                    "executor_adapter": inert,
                    "issuer_principal": "fixture-ag",
                    "issuer_key_id": "fixture-issuer-key",
                    "issuer_key": issuer_key
                },
                "human_verifier": verifier,
                "intervention_ingress": {
                    "schema": "ag.governed-loop.intervention-ingress-enrollment/v1",
                    "submitter_principal": "maude-intervention-submitter",
                    "submitter_key_id": "maude-submit-key-1",
                    "submitter_public_key": public_key
                }
            }),
        );
        let profile = config.join("runtime-profile.json");
        let _ = value(&invoke(&args(&[
            "seal-runtime-profile",
            "--enrollment",
            &enrollment.display().to_string(),
            "--output",
            &profile.display().to_string(),
        ])));

        let genesis = config.join("genesis.json");
        write_jcs(
            &genesis,
            &json!({
                "campaign": digest('a'),
                "occurrence": "00000000-0000-4000-8000-000000000001",
                "program": digest('b'),
                "expected_ag_work": digest('f'),
                "residuals": [],
                "budget": {
                    "retry_limit": 1,
                    "retries_used": 0,
                    "probe_limit": 4,
                    "probes_used": 0,
                    "escalation_limit": 1,
                    "escalations_used": 0
                }
            }),
        );
        let database = state.join("campaign.sqlite");
        let _ = value(&invoke(&args(&[
            "init",
            "--database",
            &database.display().to_string(),
            "--genesis",
            &genesis.display().to_string(),
            "--runtime-profile",
            &profile.display().to_string(),
        ])));
        Self {
            root,
            profile,
            database,
            submitter_key,
            verifier,
        }
    }

    fn prepare_probe(&self, nonce: char, state_digest: &str, suffix: &str) -> (PathBuf, PathBuf) {
        let created = now_ms();
        let draft = self.root.path().join(format!("draft-{suffix}.json"));
        write_jcs(
            &draft,
            &json!({
                "principal": digest('1'),
                "mandate": digest('2'),
                "nonce": digest(nonce),
                "campaign": digest('a'),
                "occurrence": "00000000-0000-4000-8000-000000000001",
                "target_state_digest": state_digest,
                "intervention": {
                    "class": "request_probe",
                    "exact_probe_work": digest('3'),
                    "evidence": []
                },
                "created_at_unix_ms": created,
                "expires_at_unix_ms": created + 120_000
            }),
        );
        let request = self.root.path().join(format!("request-{suffix}.json"));
        let _ = value(&invoke(&args(&[
            "prepare-intervention-request",
            "--input",
            &draft.display().to_string(),
            "--output",
            &request.display().to_string(),
        ])));
        let submission = self.root.path().join(format!("submission-{suffix}.json"));
        let _ = value(&invoke(&args(&[
            "package-intervention-submission",
            "--runtime-profile",
            &self.profile.display().to_string(),
            "--request",
            &request.display().to_string(),
            "--submitter-principal",
            "maude-intervention-submitter",
            "--submitter-key-id",
            "maude-submit-key-1",
            "--submitter-key",
            &self.submitter_key.display().to_string(),
            "--created-at-unix-ms",
            &created.to_string(),
            "--expires-at-unix-ms",
            &(created + 120_000).to_string(),
            "--output",
            &submission.display().to_string(),
        ])));
        (request, submission)
    }
}

#[test]
fn authenticated_transport_does_not_satisfy_requester_authority() {
    let fixture = Fixture::create_with_verifier_schema("intervention-ingress-refusal", false);
    let initial = value(&invoke(&args(&[
        "status",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    let before = value(&invoke(&args(&[
        "replay",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    let (_, submission) = fixture.prepare_probe(
        '8',
        initial["state_digest"].as_str().unwrap(),
        "requester-refused",
    );
    let first = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &submission.display().to_string(),
    ])));
    assert_eq!(first["result"]["status"], "governed_refused");
    assert_eq!(
        first["result"]["code"],
        "requester_verification:foreign-intervention-verification-schema"
    );
    let second = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &submission.display().to_string(),
    ])));
    assert_eq!(second, first);
    let replay = value(&invoke(&args(&[
        "replay",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    assert_eq!(replay["transitions"], before["transitions"]);
    assert_eq!(replay["ag_spends"], before["ag_spends"]);
    assert_eq!(replay["docket_attempts"], before["docket_attempts"]);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one cross-process trace keeps custody/replay cuts adjacent"
)]
fn exact_submission_is_inspectable_restart_safe_and_idempotent() {
    let fixture = Fixture::create("intervention-ingress-fixture");
    let initial = value(&invoke(&args(&[
        "status",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    let state = initial["state_digest"].as_str().unwrap();
    let (request, submission) = fixture.prepare_probe('4', state, "accepted");
    let inspection = value(&invoke(&args(&[
        "inspect-intervention-request",
        "--request",
        &request.display().to_string(),
    ])));
    let request_bytes = fs::read(&request).unwrap();
    assert_eq!(inspection["exact_bytes_len"], request_bytes.len());

    let first = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &submission.display().to_string(),
    ])));
    assert_eq!(first["result"]["status"], "governed_accepted");
    let second_envelope = fixture.root.path().join("second-envelope.json");
    let repackaged = value(&invoke(&args(&[
        "package-intervention-submission",
        "--runtime-profile",
        &fixture.profile.display().to_string(),
        "--request",
        &request.display().to_string(),
        "--submitter-principal",
        "maude-intervention-submitter",
        "--submitter-key-id",
        "maude-submit-key-1",
        "--submitter-key",
        &fixture.submitter_key.display().to_string(),
        "--created-at-unix-ms",
        &(now_ms() + 1).to_string(),
        "--expires-at-unix-ms",
        &(now_ms() + 120_000).to_string(),
        "--output",
        &second_envelope.display().to_string(),
    ])));
    let submission_id = repackaged["body"]["submission"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(submission_id, first["submission"].as_str().unwrap());
    let repackaged_result = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &second_envelope.display().to_string(),
    ])));
    assert_eq!(repackaged_result["result"], first["result"]);

    // Exact timeout resend reopens both stores, finds the existing campaign
    // event, and returns the same immutable final receipt without a second probe.
    let duplicate = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &submission.display().to_string(),
    ])));
    assert_eq!(duplicate, first);
    let status = value(&invoke(&args(&[
        "status",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    assert_eq!(
        status["state"]["observation_required"]["meta"]["budget"]["probes_used"],
        1
    );
    let lookup = value(&invoke(&args(&[
        "intervention-receipt",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        first["submission"].as_str().unwrap(),
    ])));
    assert_eq!(lookup["receipts"].as_array().unwrap().len(), 2);
    assert_eq!(lookup["receipts"][0]["result"]["status"], "received");
    assert_eq!(
        lookup["receipts"][1]["result"]["status"],
        "governed_accepted"
    );
    let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
        campaign_root: fixture.database.parent().unwrap().to_owned(),
        ag_loopctl: Path::new(env!("CARGO_BIN_EXE_ag-loopctl")).to_owned(),
        nightshift: None,
        docket: None,
        maude_acquisition: None,
    })
    .unwrap();
    let detail = reader
        .campaign_detail(&hex_encode(b"campaign.sqlite"))
        .unwrap();
    let html = render::campaign_detail(&detail);
    assert!(html.contains("Intervention submission custody"));
    assert!(html.contains("governed_accepted"));
    assert!(html.contains("delivery is not authorization"));

    // A new request identity that targets the predecessor remains stale and is
    // retained as governed refusal rather than custody refusal.
    let (_, stale_submission) = fixture.prepare_probe('5', state, "stale");
    let stale_receipt = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &stale_submission.display().to_string(),
    ])));
    assert_eq!(stale_receipt["result"]["status"], "governed_refused");
    assert!(stale_receipt["result"]["refusal"].is_string());

    // Submission and verifier credentials never enter authority-bearing facts.
    let replay = value(&invoke(&args(&[
        "replay",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    assert_eq!(replay["ag_spends"], 0);
    assert_eq!(replay["docket_attempts"], 0);
    assert!(fixture.verifier.exists());
}

#[test]
fn runtime_signature_and_concurrent_resend_fail_closed_or_converge() {
    let fixture = Fixture::create("intervention-ingress-concurrency");
    let initial = value(&invoke(&args(&[
        "status",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    let (_, submission) =
        fixture.prepare_probe('6', initial["state_digest"].as_str().unwrap(), "race");
    let arguments = args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &submission.display().to_string(),
    ]);
    let a = arguments.clone();
    let b = arguments;
    let first = std::thread::spawn(move || invoke(&a));
    let second = std::thread::spawn(move || invoke(&b));
    let first = value(&first.join().unwrap());
    let second = value(&second.join().unwrap());
    assert_eq!(first, second);

    let mut attacked: Value = serde_json::from_slice(&fs::read(&submission).unwrap()).unwrap();
    let claimed_submission = attacked["body"]["submission"].as_str().unwrap().to_owned();
    attacked["body"]["target_runtime_profile"] = Value::String(digest('9'));
    // Even before signature verification, the content-derived outer self-ID
    // makes target substitution visible. The focused unit vector additionally
    // recomputes that ID and demonstrates the signature still refuses it.
    let attacked_path = fixture.root.path().join("attacked.json");
    write_jcs(&attacked_path, &attacked);
    let refusal = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &attacked_path.display().to_string(),
    ])));
    assert_eq!(refusal["result"]["status"], "custody_refused");
    assert_eq!(refusal["result"]["code"], "binding_mismatch");
    assert_eq!(refusal["submission"], claimed_submission);
    let recovered_refusal = value(&invoke(&args(&[
        "intervention-receipt",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &claimed_submission,
    ])));
    assert!(
        recovered_refusal["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|receipt| receipt["result"]["status"] == "custody_refused")
    );

    let all = value(&invoke(&args(&[
        "intervention-submissions",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    assert!(all["receipts"].as_array().unwrap().len() >= 3);
}

#[test]
fn restart_cuts_recover_received_and_post_transition_results_without_reapplication() {
    let fixture = Fixture::create("intervention-ingress-crash-cuts");
    let initial = value(&invoke(&args(&[
        "status",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    let (request_path, submission_path) =
        fixture.prepare_probe('7', initial["state_digest"].as_str().unwrap(), "crash-cut");
    let profile_bytes = fs::read(&fixture.profile).unwrap();
    let profile: GovernedRuntimeProfileV1 = serde_json::from_slice(&profile_bytes).unwrap();
    let profile_jcs = JcsDocument::canonicalize(&profile).unwrap();
    let profile_digest =
        Digest::hash_domain(RUNTIME_PROFILE_DIGEST_DOMAIN_V1, profile_jcs.as_bytes());
    let presentation = read_exact_input(&submission_path, max_submission_bytes()).unwrap();
    let verified = verify_submission_bytes(
        &presentation,
        profile.intervention_ingress.as_ref().unwrap(),
        &profile_digest,
        now_ms(),
    )
    .unwrap();
    let ledger_path = InterventionSubmissionLedgerV1::path_for_campaign(&fixture.database);
    {
        let mut ledger =
            InterventionSubmissionLedgerV1::open_writer(&ledger_path, profile_digest.clone())
                .unwrap();
        let _ = ledger.record_received(&verified, now_ms()).unwrap();
    }
    // Restart after custody receipt: lookup is honest pending receipt, not an
    // inferred transition or permission to create a different request.
    let pending = value(&invoke(&args(&[
        "intervention-receipt",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        verified.envelope.body.submission.as_str(),
    ])));
    assert_eq!(pending["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(pending["receipts"][0]["result"]["status"], "received");

    // Model a lost ingress response after the canonical transition commit by
    // calling the campaign engine directly from this test-only crash fixture.
    // No pre-custody production CLI adapter exists.
    let request: GovernedInterventionRequestV1 =
        serde_json::from_slice(&fs::read(request_path).unwrap()).unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: request.principal.clone(),
        mandate: request.mandate.clone(),
    };
    let mut engine = CampaignEngineV1::open(&fixture.database).unwrap();
    let mut authority_verifier =
        CommandGovernedInterventionVerifierV1::new(fixture.verifier.clone());
    let _ = engine
        .apply_governed_intervention(request, &scope, &mut authority_verifier, now_ms())
        .unwrap();
    drop(engine);

    // The restarted ingress reconciles the exact request against AG history
    // before application, appends the missing result receipt, and does not
    // consume a second probe.
    let recovered = value(&invoke(&args(&[
        "submit-intervention",
        "--database",
        &fixture.database.display().to_string(),
        "--submission",
        &submission_path.display().to_string(),
    ])));
    assert_eq!(recovered["result"]["status"], "governed_accepted");
    let status = value(&invoke(&args(&[
        "status",
        "--database",
        &fixture.database.display().to_string(),
    ])));
    assert_eq!(
        status["state"]["observation_required"]["meta"]["budget"]["probes_used"],
        1
    );
}
