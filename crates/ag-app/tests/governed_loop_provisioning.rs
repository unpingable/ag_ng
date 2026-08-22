//! Deployment-facing qualification for profile enrollment, one-shot process
//! reopen, structured inspection, and fail-closed missing custody.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::{Command, Output};

use ag_operator_ui::model::ProjectionCorrespondenceV1;
use ag_operator_ui::render;
use ag_operator_ui::source::{OperatorReaderV1, OperatorSourceConfigV1, hex_encode};
use serde_json::{Value, json};

const ISSUER_PKCS8_HEX: &str = "3051020101300506032b657004220420c226c22f628685cd349518c28eff015fd216a106bb49534286dceed3202b1c0e81210028d8b71d122a31cfd39f26313275119934a021918f5d37d100ad2f27acbaf776";

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn write_jcs(path: &Path, value: &Value) {
    fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
}

fn write_executable(path: &Path) {
    fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
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

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one production-CLI deployment trace keeps sealing, reopen, restore, and custody failures adjacent"
)]
fn profile_seal_reopen_inspect_and_missing_custody_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let config = root.join("config");
    let state = root.join("state");
    let secrets = root.join("secrets");
    for path in [&config, &state, &secrets] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let command = config.join("boundary-command");
    write_executable(&command);
    let catalog = config.join("catalog.json");
    write_jcs(
        &catalog,
        &json!({
            "schema": "ag.governed-loop.exact-work-catalog/v1",
            "entries": {
                "fixture.work/v1": {
                    "work_schema": "fixture.work/v1",
                    "subject": digest('d'),
                    "scope": digest('e'),
                    "precondition": {"required": [], "forbidden": []}
                }
            }
        }),
    );
    let trust = config.join("docket-trust.json");
    write_jcs(&trust, &json!({}));
    let executor_config = config.join("executor-plan.json");
    write_jcs(
        &executor_config,
        &json!({"fixture": "exact-occurrence-work"}),
    );
    let issuer_key = secrets.join("issuer.pk8");
    let key_bytes: Vec<u8> = (0..ISSUER_PKCS8_HEX.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&ISSUER_PKCS8_HEX[offset..offset + 2], 16).unwrap())
        .collect();
    fs::write(&issuer_key, key_bytes).unwrap();
    fs::set_permissions(&issuer_key, fs::Permissions::from_mode(0o600)).unwrap();

    let enrollment = config.join("runtime-profile-enrollment.json");
    write_jcs(
        &enrollment,
        &json!({
            "schema": "ag.governed-loop.runtime-profile-enrollment/v1",
            "profile_label": "local-process-deployment-qualification",
            "observation_resolver": command,
            "observation_resolver_id": "fixture-observation/v1",
            "standing_resolver": command,
            "standing_resolver_id": "fixture-standing/v1",
            "max_standing_ttl_ms": 60000,
            "exact_work_catalog": catalog,
            "controlling_review": null,
            "docket": {
                "schema": "ag.governed-loop.docket-root-enrollment/v1",
                "docket_program": command,
                "state_directory": state.join("docket"),
                "trust_config": trust,
                "standing_resolver": command,
                "executor_adapter": command,
                "issuer_principal": "fixture-ag",
                "issuer_key_id": "fixture-key-1",
                "issuer_key": issuer_key
            },
            "human_verifier": null
        }),
    );
    let profile = config.join("runtime-profile.json");
    let seal = value(&invoke(&args(&[
        "seal-runtime-profile",
        "--enrollment",
        &enrollment.display().to_string(),
        "--output",
        &profile.display().to_string(),
    ])));
    assert_eq!(
        seal["schema"],
        "ag.governed-loop.runtime-profile-seal-receipt/v1"
    );
    assert_eq!(fs::metadata(&profile).unwrap().mode() & 0o777, 0o600);
    assert!(
        !String::from_utf8_lossy(&serde_json::to_vec(&seal).unwrap()).contains(ISSUER_PKCS8_HEX),
        "the seal receipt must never expose private-key material"
    );
    let verified = value(&invoke(&args(&[
        "verify-runtime-profile",
        "--runtime-profile",
        &profile.display().to_string(),
    ])));
    assert_eq!(verified, seal);

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
                "probe_limit": 1,
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
    assert_eq!(fs::metadata(&database).unwrap().mode() & 0o777, 0o600);

    // Each read is a fresh process reopening and replaying the authoritative
    // store. Inspection is a projection and cannot transition the PC.
    let inspected = value(&invoke(&args(&[
        "inspect",
        "--database",
        &database.display().to_string(),
    ])));
    assert_eq!(
        inspected["schema"],
        "ag.governed-loop.operational-snapshot/v1"
    );
    assert!(inspected["current"]["state"]["observation_required"].is_object());
    assert_eq!(inspected["replay"]["ag_spends"], 0);
    assert_eq!(
        inspected["runtime_profile"]["digest"],
        seal["profile_digest"]
    );
    let _ = value(&invoke(&args(&[
        "status",
        "--database",
        &database.display().to_string(),
    ])));
    let replay = value(&invoke(&args(&[
        "replay",
        "--database",
        &database.display().to_string(),
    ])));
    assert_eq!(replay["ag_spends"], 0);
    let history = value(&invoke(&args(&[
        "history",
        "--database",
        &database.display().to_string(),
    ])));
    assert_eq!(history["schema"], "ag.governed-loop.transition-history/v1");
    assert_eq!(
        history["campaign"],
        inspected["current"]["state"]["observation_required"]["meta"]["key"]["campaign"]
    );
    assert_eq!(history["transitions"].as_array().unwrap().len(), 1);
    assert_eq!(history["transitions"][0]["kind"], "campaign_created");
    assert_eq!(
        history["current_state_digest"],
        inspected["current"]["state_digest"]
    );
    let refusals = value(&invoke(&args(&[
        "refusals",
        "--database",
        &database.display().to_string(),
    ])));
    assert_eq!(refusals["schema"], "ag.governed-loop.refusal-history/v1");
    assert_eq!(refusals["refusals"].as_array().unwrap().len(), 0);
    assert_eq!(
        refusals["verified_at_state_digest"],
        inspected["current"]["state_digest"]
    );

    // The UI backend invokes the real production CLI against the real
    // profile-bound store; it does not read SQLite or link the engine.
    let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
        campaign_root: state.clone(),
        ag_loopctl: Path::new(env!("CARGO_BIN_EXE_ag-loopctl")).to_owned(),
        nightshift: None,
        docket: None,
    })
    .unwrap();
    let index = reader.campaign_index().unwrap();
    assert_eq!(index.campaigns.len(), 1);
    let index_page = render::campaign_index(&index);
    assert!(
        index_page.contains(
            inspected["current"]["state"]["observation_required"]["meta"]["key"]["campaign"]
                .as_str()
                .unwrap()
        )
    );
    let token = hex_encode(b"campaign.sqlite");
    let detail = reader.campaign_detail(&token).unwrap();
    assert_eq!(
        detail.projection.correspondence,
        ProjectionCorrespondenceV1::Exact
    );
    let page = render::campaign_detail(&detail);
    assert!(page.contains("ObservationRequired"));
    assert!(page.contains(seal["profile_digest"].as_str().unwrap()));
    assert!(page.contains("No AG authorization spend exists"));
    assert!(page.contains("No observation lookup identity is available"));

    // A cleanly closed single-file copy reopens to the same authority-empty
    // facts. A truncated partial restore refuses rather than inventing state.
    let backup = state.join("campaign-backup.sqlite");
    fs::copy(&database, &backup).unwrap();
    let backup_snapshot = value(&invoke(&args(&[
        "inspect",
        "--database",
        &backup.display().to_string(),
    ])));
    assert_eq!(backup_snapshot["current"], inspected["current"]);
    let partial = state.join("campaign-partial.sqlite");
    fs::copy(&database, &partial).unwrap();
    let partial_file = fs::OpenOptions::new().write(true).open(&partial).unwrap();
    partial_file
        .set_len(fs::metadata(&partial).unwrap().len() / 2)
        .unwrap();
    drop(partial_file);
    assert!(
        !invoke(&args(&[
            "inspect",
            "--database",
            &partial.display().to_string(),
        ]))
        .status
        .success()
    );

    // Facts remain inspectable without the signing credential, but live
    // profile verification and dispatch custody fail. Missing custody cannot
    // mint a spend or Docket attempt.
    fs::remove_file(&issuer_key).unwrap();
    let after_secret_loss = value(&invoke(&args(&[
        "inspect",
        "--database",
        &database.display().to_string(),
    ])));
    assert_eq!(after_secret_loss["current"], inspected["current"]);
    assert!(
        !invoke(&args(&[
            "verify-runtime-profile",
            "--runtime-profile",
            &profile.display().to_string(),
        ]))
        .status
        .success()
    );
    assert!(
        !invoke(&args(&[
            "dispatch",
            "--database",
            &database.display().to_string(),
            "--docket",
            &command.display().to_string(),
            "--docket-state",
            &state.join("docket").display().to_string(),
            "--docket-trust",
            &trust.display().to_string(),
            "--docket-standing-resolver",
            &command.display().to_string(),
            "--executor",
            &command.display().to_string(),
            "--executor-config",
            &executor_config.display().to_string(),
            "--issuer-principal",
            "fixture-ag",
            "--issuer-key-id",
            "fixture-key-1",
            "--issuer-key",
            &issuer_key.display().to_string(),
        ]))
        .status
        .success()
    );
    let replay = value(&invoke(&args(&[
        "replay",
        "--database",
        &database.display().to_string(),
    ])));
    assert_eq!(replay["ag_spends"], 0);
    assert_eq!(replay["docket_attempts"], 0);

    // Missing deployment configuration is rejected before a campaign file is
    // created; sealing is create-once and cannot overwrite its prior output.
    let missing_database = state.join("missing-profile.sqlite");
    assert!(
        !invoke(&args(&[
            "init",
            "--database",
            &missing_database.display().to_string(),
            "--genesis",
            &genesis.display().to_string(),
            "--runtime-profile",
            &config.join("absent-profile.json").display().to_string(),
        ]))
        .status
        .success()
    );
    assert!(!missing_database.exists());
    assert!(
        !invoke(&args(&[
            "seal-runtime-profile",
            "--enrollment",
            &enrollment.display().to_string(),
            "--output",
            &profile.display().to_string(),
        ]))
        .status
        .success()
    );
}
