//! Process-bound qualification for the V2 systemd executor CLI.

#![cfg(feature = "systemd-dbus")]

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::process::{Command, Stdio};

use ag_app::effect_executor_adapter::{
    EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2, EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2,
    EffectExecutorDispatchV1, EffectExecutorSystemdPlanV2, EffectFilePolicyV1,
};
use ag_effect::{CanonicalEffectV1, SystemdUnitActionV1, TargetId};
use ag_primitives::{Digest, JcsDocument};
use rustix::fs::{FlockOperation, flock};

const EFFECTD: &str = env!("CARGO_BIN_EXE_ag-effectd");

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
