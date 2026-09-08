//! Process-bound qualification for the V2 systemd executor CLI.

#![cfg(feature = "systemd-dbus")]

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::process::{Command, Stdio};

use ag_app::effect_executor_adapter::{
    EffectExecutorDispatchV1, EffectExecutorSystemdPlanV2, EffectFilePolicyV1,
    EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2, EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2,
};
#[cfg(feature = "systemd-store-qualification-fixture")]
use ag_app::effect_executor_adapter::seed_terminal_systemd_store_for_qualification;
use ag_effect::{CanonicalEffectV1, SystemdUnitActionV1, TargetId};
use ag_primitives::{Digest, JcsDocument};
use rustix::fs::{flock, FlockOperation};

const EFFECTD: &str = env!("CARGO_BIN_EXE_ag-effectd");

#[test]
fn immutable_store_audit_is_an_explicit_query_only_cli_surface() {
    let output = Command::new(EFFECTD)
        .arg("audit-store")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Validate a copied terminal Systemd V2 store"));
    assert!(stdout.contains("--store-cut"));
    assert!(stdout.contains("--store-bytes"));
    assert!(stdout.contains("--store-sha256"));
}

#[test]
#[cfg(feature = "systemd-store-qualification-fixture")]
fn immutable_store_audit_cli_returns_owner_outcome_and_refuses_wrong_digest() {
    let directory = tempfile::tempdir().unwrap();
    let subject = Digest::hash_bytes(b"cli-audit-subject");
    let scope = Digest::hash_bytes(b"cli-audit-scope");
    let plan = EffectExecutorSystemdPlanV2 {
        schema: EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2.to_owned(),
        attempt_store: directory.path().join("attempts.sqlite"),
        subject: subject.clone(),
        scope: scope.clone(),
        effect_index: 0,
        effect: CanonicalEffectV1::SystemdUnit {
            target: TargetId::parse("constellation-beta-http-fixture").unwrap(),
            unit: "constellation-beta-http-fixture.service".to_owned(),
            action: SystemdUnitActionV1::Start,
            expected_active_state: "inactive".to_owned(),
            expected_unit_file_state: "disabled".to_owned(),
        },
        file_policy: EffectFilePolicyV1 {
            max_content_bytes: 1024,
            trusted_ancestor_uid: 0,
            trusted_parent_uid: 0,
            require_private_parent_writes: true,
        },
        systemd_machine_identity: "00000000000000000000000000000000".to_owned(),
        execution_lock_timeout_ms: 5_000,
        job_timeout_ms: 30_000,
    };
    let dispatch = EffectExecutorDispatchV1 {
        attempt: Digest::hash_bytes(b"cli-audit-attempt"),
        marker: Digest::hash_bytes(b"cli-audit-marker"),
        work_schema: EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
        work: plan.identity().unwrap(),
        subject,
        scope,
    };
    let expected = seed_terminal_systemd_store_for_qualification(&plan, &dispatch).unwrap();
    let plan_path = directory.path().join("plan.json");
    std::fs::write(
        &plan_path,
        JcsDocument::canonicalize(&plan).unwrap().as_bytes(),
    )
    .unwrap();
    let cut = directory.path().join("audit-store.sqlite");
    std::fs::copy(&plan.attempt_store, &cut).unwrap();
    let cut_bytes = std::fs::read(&cut).unwrap();
    let cut_digest = Digest::hash_bytes(&cut_bytes);

    let invoke = |digest: &Digest| {
        let mut child = Command::new(EFFECTD)
            .arg("audit-store")
            .arg(&plan_path)
            .arg("--store-cut")
            .arg(&cut)
            .arg("--store-bytes")
            .arg(cut_bytes.len().to_string())
            .arg("--store-sha256")
            .arg(digest.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(JcsDocument::canonicalize(&dispatch).unwrap().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let accepted = invoke(&cut_digest);
    assert!(accepted.status.success());
    assert!(accepted.stderr.is_empty());
    assert_eq!(
        accepted.stdout,
        [
            JcsDocument::canonicalize(&expected).unwrap().as_bytes(),
            b"\n"
        ]
        .concat()
    );
    let refused = invoke(&Digest::hash_bytes(b"different store bytes"));
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8(refused.stderr)
        .unwrap()
        .contains("systemd-audit-store-content-substitution"));
}

#[test]
fn lock_deadline_is_exact_exit_75_with_no_stdout_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let subject = Digest::hash_bytes(b"cli-systemd-subject");
    let scope = Digest::hash_bytes(b"cli-systemd-scope");
    let plan = EffectExecutorSystemdPlanV2 {
        schema: EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2.to_owned(),
        attempt_store: directory.path().join("attempts.sqlite"),
        subject: subject.clone(),
        scope: scope.clone(),
        effect_index: 0,
        effect: CanonicalEffectV1::SystemdUnit {
            target: TargetId::parse("constellation-beta-http-fixture").unwrap(),
            unit: "constellation-beta-http-fixture.service".to_owned(),
            action: SystemdUnitActionV1::Start,
            expected_active_state: "inactive".to_owned(),
            expected_unit_file_state: "disabled".to_owned(),
        },
        file_policy: EffectFilePolicyV1 {
            max_content_bytes: 1024,
            trusted_ancestor_uid: 0,
            trusted_parent_uid: 0,
            require_private_parent_writes: true,
        },
        systemd_machine_identity: "0123456789abcdef0123456789abcdef".to_owned(),
        execution_lock_timeout_ms: 1,
        job_timeout_ms: 30_000,
    };
    let dispatch = EffectExecutorDispatchV1 {
        attempt: Digest::hash_bytes(b"cli-systemd-attempt"),
        marker: Digest::hash_bytes(b"cli-systemd-marker"),
        work_schema: EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
        work: plan.identity().unwrap(),
        subject,
        scope,
    };
    let plan_path = directory.path().join("plan.json");
    std::fs::write(
        &plan_path,
        JcsDocument::canonicalize(&plan).unwrap().as_bytes(),
    )
    .unwrap();

    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&plan.attempt_store)
        .unwrap();
    flock(&lock_file, FlockOperation::NonBlockingLockExclusive).unwrap();

    let mut child = Command::new(EFFECTD)
        .arg("execute")
        .arg(&plan_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(JcsDocument::canonicalize(&dispatch).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(75));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"systemd_attempt_in_progress\n");
}
