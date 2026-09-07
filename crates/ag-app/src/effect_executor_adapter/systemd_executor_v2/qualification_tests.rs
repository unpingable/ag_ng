//! Deterministic qualification for V2 custody without contacting the system bus.

use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ag_effect::TargetId;
use rusqlite::{params, Connection};

use super::super::{
    load_effect_executor_plan_any, LoadedEffectExecutorPlan, EFFECT_EXECUTOR_WORK_SCHEMA_V1,
};
use super::*;

struct ScriptedDriver {
    calls: Arc<AtomicUsize>,
    observation: DriverObservationV2,
}

impl SystemdOperationDriverV2 for ScriptedDriver {
    fn run(&self, _plan: &EffectExecutorSystemdPlanV2) -> DriverObservationV2 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.observation.clone()
    }
}

fn fixture() -> (
    tempfile::TempDir,
    EffectExecutorSystemdPlanV2,
    EffectExecutorDispatchV1,
) {
    let directory = tempfile::tempdir().unwrap();
    let subject = Digest::hash_bytes(b"qualified-systemd-subject");
    let scope = Digest::hash_bytes(b"qualified-systemd-scope");
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
        execution_lock_timeout_ms: 5_000,
        job_timeout_ms: 30_000,
    };
    let dispatch = EffectExecutorDispatchV1 {
        attempt: Digest::hash_bytes(b"qualified-systemd-attempt"),
        marker: Digest::hash_bytes(b"qualified-systemd-marker"),
        work_schema: EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
        work: plan.identity().unwrap(),
        subject,
        scope,
    };
    (directory, plan, dispatch)
}

fn success_observation() -> DriverObservationV2 {
    DriverObservationV2 {
        started_at_unix_ms: 1_000,
        finished_at_unix_ms: 1_025,
        elapsed_ms: 25,
        live_machine_identity: Some("0123456789abcdef0123456789abcdef".to_owned()),
        unit_object_path: Some(
            "/org/freedesktop/systemd1/unit/constellation_2dbeta_2dhttp_2dfixture_2eservice"
                .to_owned(),
        ),
        previous_active_state: Some("inactive".to_owned()),
        previous_unit_file_state: Some("disabled".to_owned()),
        job_path: Some("/org/freedesktop/systemd1/job/42".to_owned()),
        job_result: Some("done".to_owned()),
        messages: [
            "get_machine_id_reply",
            "get_unit_reply",
            "pre_active_state_reply",
            "pre_unit_file_state_reply",
            "start_unit_reply",
            "job_removed_signal",
            "post_active_state_reply",
            "post_unit_file_state_reply",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| DriverMessageV2 {
            kind: kind.to_owned(),
            elapsed_ms: index as u64 + 1,
            bytes: format!("qualified-{kind}").into_bytes(),
        })
        .collect(),
        terminal: DriverTerminalV2::Success {
            resulting_active_state: "active".to_owned(),
            resulting_unit_file_state: "disabled".to_owned(),
        },
    }
}

fn empty_observation(terminal: DriverTerminalV2) -> DriverObservationV2 {
    DriverObservationV2 {
        started_at_unix_ms: 2_000,
        finished_at_unix_ms: 2_001,
        elapsed_ms: 1,
        live_machine_identity: None,
        unit_object_path: None,
        previous_active_state: None,
        previous_unit_file_state: None,
        job_path: None,
        job_result: None,
        messages: Vec::new(),
        terminal,
    }
}

fn run_script(
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
    observation: DriverObservationV2,
) -> (EffectExecutorOutcomeV1, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let driver = ScriptedDriver {
        calls: Arc::clone(&calls),
        observation,
    };
    let outcome = execute_with_driver(plan, dispatch, &driver, false).unwrap();
    (outcome, calls)
}

fn drop_evidence_triggers(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER systemd_dbus_evidence_no_update;
             DROP TRIGGER systemd_dbus_evidence_no_delete;",
        )
        .unwrap();
}

fn point_receipt_to(receipt: &mut DocketEffectExecutionReceiptV1, digest: Digest) {
    match &mut receipt.outcome {
        ExecutionOutcomeV1::Succeeded {
            success: EffectSuccessV1::SystemdUnit { evidence, .. },
        } => *evidence = digest,
        ExecutionOutcomeV1::Failed { failure } => failure.evidence = Some(digest),
        ExecutionOutcomeV1::Indeterminate { envelope } => envelope.evidence = Some(digest),
        ExecutionOutcomeV1::Succeeded { .. } => {
            panic!("fixture receipt has the wrong effect family")
        }
    }
}

fn coherently_reseal_evidence(
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
    mutate: impl FnOnce(&mut SystemdDbusEvidenceV1),
) {
    let connection = Connection::open(&plan.attempt_store).unwrap();
    let raw: Vec<u8> = connection
        .query_row(
            "SELECT raw FROM systemd_dbus_evidence WHERE attempt=?1",
            [dispatch.attempt.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let mut evidence: SystemdDbusEvidenceV1 = serde_json::from_slice(&raw).unwrap();
    mutate(&mut evidence);
    let raw = JcsDocument::canonicalize(&evidence).unwrap();
    let evidence_digest = Digest::hash_domain(SYSTEMD_DBUS_EVIDENCE_SCHEMA_V1, raw.as_bytes());
    let metadata = EvidenceMetadata::from_messages(&evidence.messages).unwrap();

    let receipt_raw: Vec<u8> = connection
        .query_row(
            "SELECT receipt_body FROM docket_effect_attempt WHERE attempt=?1",
            [dispatch.attempt.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let mut receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(&receipt_raw).unwrap();
    point_receipt_to(&mut receipt, evidence_digest.clone());
    let receipt_raw = JcsDocument::canonicalize(&receipt).unwrap();
    let receipt_digest = receipt.digest().unwrap();

    drop_evidence_triggers(&connection);
    connection
        .execute(
            "UPDATE systemd_dbus_evidence
             SET evidence=?1,raw_len=?2,message_count=?3,
                 maximum_message_bytes=?4,cumulative_message_bytes=?5,raw=?6
             WHERE attempt=?7",
            params![
                evidence_digest.as_str(),
                i64::try_from(raw.as_bytes().len()).unwrap(),
                i64::try_from(metadata.message_count).unwrap(),
                i64::try_from(metadata.maximum_message_bytes).unwrap(),
                i64::try_from(metadata.cumulative_message_bytes).unwrap(),
                raw.as_bytes(),
                dispatch.attempt.as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE docket_effect_attempt SET receipt=?1,receipt_body=?2 WHERE attempt=?3",
            params![
                receipt_digest.as_str(),
                receipt_raw.as_bytes(),
                dispatch.attempt.as_str()
            ],
        )
        .unwrap();
}

#[test]
fn query_only_raw_reopen_and_terminal_replay_use_exact_retained_evidence() {
    let (_directory, plan, dispatch) = fixture();
    let (first, calls) = run_script(&plan, &dispatch, success_observation());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let raw = reopen_systemd_dbus_evidence(&plan, &dispatch).unwrap();
    let evidence: SystemdDbusEvidenceV1 = serde_json::from_slice(&raw).unwrap();
    evidence.validate_bindings(&plan, &dispatch).unwrap();
    assert_eq!(evidence.outcome_class, SystemdEvidenceClassV1::Success);
    assert_eq!(
        reconcile_systemd_effect_attempt(&plan, &dispatch).unwrap(),
        first
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn no_effect_and_outcome_unknown_remain_distinct_terminal_classes() {
    for (terminal, expected, label) in [
        (
            DriverTerminalV2::Failure {
                code: "system_bus_unavailable".to_owned(),
                detail: "no StartUnit transmission".to_owned(),
            },
            EffectExecutorOutcomeClassV1::Failure,
            "failure",
        ),
        (
            DriverTerminalV2::Indeterminate {
                code: "systemd_start_reply_timeout".to_owned(),
                detail: "transmission began; reply absent".to_owned(),
            },
            EffectExecutorOutcomeClassV1::Indeterminate,
            "indeterminate",
        ),
    ] {
        let (_directory, plan, dispatch) = fixture();
        let (outcome, calls) = run_script(&plan, &dispatch, empty_observation(terminal));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{label}");
        assert_eq!(outcome.outcome, expected, "{label}");
        let raw = reopen_systemd_dbus_evidence(&plan, &dispatch).unwrap();
        let evidence: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(evidence["outcome_class"], label);
    }
}

#[test]
fn unqualified_action_refuses_before_driver_invocation() {
    let (_directory, mut plan, mut dispatch) = fixture();
    let CanonicalEffectV1::SystemdUnit { action, .. } = &mut plan.effect else {
        unreachable!()
    };
    *action = SystemdUnitActionV1::Stop;
    dispatch.work = plan.identity().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let driver = ScriptedDriver {
        calls: Arc::clone(&calls),
        observation: success_observation(),
    };
    let outcome = execute_with_driver(&plan, &dispatch, &driver, false).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(outcome.outcome, EffectExecutorOutcomeClassV1::Failure);
}

#[test]
fn execution_lock_contention_is_a_transport_refusal_and_never_calls_driver() {
    let (_directory, mut plan, mut dispatch) = fixture();
    plan.execution_lock_timeout_ms = 1;
    dispatch.work = plan.identity().unwrap();
    let held = ExecutionLockV2::acquire(&plan.attempt_store, 1)
        .unwrap()
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let driver = ScriptedDriver {
        calls: Arc::clone(&calls),
        observation: success_observation(),
    };
    assert_eq!(
        execute_with_driver(&plan, &dispatch, &driver, false).unwrap_err(),
        "systemd_attempt_in_progress"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(held);
    let first = execute_with_driver(&plan, &dispatch, &driver, false).unwrap();
    assert_eq!(first.outcome, EffectExecutorOutcomeClassV1::Success);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        execute_with_driver(&plan, &dispatch, &driver, false).unwrap(),
        first
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn oversized_driver_evidence_refuses_before_evidence_or_terminal_commit() {
    let (_directory, plan, dispatch) = fixture();
    let mut observation = success_observation();
    observation.messages[0].bytes = vec![0; MAX_MESSAGE_BYTES + 1];
    let calls = Arc::new(AtomicUsize::new(0));
    let driver = ScriptedDriver { calls, observation };
    assert_eq!(
        execute_with_driver(&plan, &dispatch, &driver, false).unwrap_err(),
        "systemd-evidence-message-shape"
    );
    let connection = Connection::open(&plan.attempt_store).unwrap();
    let (evidence_count, status): (i64, String) = (
        connection
            .query_row("SELECT count(*) FROM systemd_dbus_evidence", [], |row| {
                row.get(0)
            })
            .unwrap(),
        connection
            .query_row("SELECT status FROM docket_effect_attempt", [], |row| {
                row.get(0)
            })
            .unwrap(),
    );
    assert_eq!((evidence_count, status.as_str()), (0, "started"));
}
#[test]
fn cumulative_and_ordered_time_bounds_refuse_before_terminal_commit() {
    for case in ["cumulative", "time_inversion"] {
        let (_directory, plan, dispatch) = fixture();
        let mut observation = success_observation();
        let expected = match case {
            "cumulative" => {
                let per_message = MAX_CUMULATIVE_MESSAGE_BYTES / observation.messages.len() + 1;
                for message in &mut observation.messages {
                    message.bytes = vec![0; per_message];
                }
                "systemd-evidence-message-bound"
            }
            "time_inversion" => {
                observation.messages[1].elapsed_ms = 0;
                "systemd-evidence-message-shape"
            }
            _ => unreachable!(),
        };
        let driver = ScriptedDriver {
            calls: Arc::new(AtomicUsize::new(0)),
            observation,
        };
        assert_eq!(
            execute_with_driver(&plan, &dispatch, &driver, false).unwrap_err(),
            expected,
            "{case}"
        );
        let connection = Connection::open(&plan.attempt_store).unwrap();
        let evidence_count: i64 = connection
            .query_row("SELECT count(*) FROM systemd_dbus_evidence", [], |row| {
                row.get(0)
            })
            .unwrap();
        let status: String = connection
            .query_row("SELECT status FROM docket_effect_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((evidence_count, status.as_str()), (0, "started"), "{case}");
    }
}

#[test]
fn evidence_guard_deletion_content_and_metadata_substitutions_refuse_reopen() {
    for case in ["guards", "delete", "content", "metadata"] {
        let (_directory, plan, dispatch) = fixture();
        run_script(&plan, &dispatch, success_observation());
        let connection = Connection::open(&plan.attempt_store).unwrap();
        drop_evidence_triggers(&connection);
        match case {
            "guards" => {}
            "delete" => {
                connection
                    .execute(
                        "DELETE FROM systemd_dbus_evidence WHERE attempt=?1",
                        [dispatch.attempt.as_str()],
                    )
                    .unwrap();
            }
            "content" => {
                let raw_len: i64 = connection
                    .query_row(
                        "SELECT raw_len FROM systemd_dbus_evidence WHERE attempt=?1",
                        [dispatch.attempt.as_str()],
                        |row| row.get(0),
                    )
                    .unwrap();
                connection
                    .execute(
                        "UPDATE systemd_dbus_evidence SET raw=zeroblob(?1) WHERE attempt=?2",
                        params![raw_len, dispatch.attempt.as_str()],
                    )
                    .unwrap();
            }
            "metadata" => {
                connection
                    .execute_batch("PRAGMA ignore_check_constraints=ON;")
                    .unwrap();
                connection
                    .execute(
                        "UPDATE systemd_dbus_evidence SET raw_len=1048577 WHERE attempt=?1",
                        [dispatch.attempt.as_str()],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        assert!(
            reopen_systemd_dbus_evidence(&plan, &dispatch).is_err(),
            "{case}"
        );
        assert!(
            reconcile_systemd_effect_attempt(&plan, &dispatch).is_err(),
            "{case}"
        );
    }
}

#[test]
fn coherent_message_kind_and_order_substitutions_refuse_replay() {
    for case in ["kind", "order"] {
        let (_directory, plan, dispatch) = fixture();
        run_script(&plan, &dispatch, success_observation());
        coherently_reseal_evidence(&plan, &dispatch, |evidence| match case {
            "kind" => evidence.messages[0].kind = "get_unit_reply".to_owned(),
            "order" => evidence.messages.swap(0, 1),
            _ => unreachable!(),
        });
        assert!(
            reconcile_systemd_effect_attempt(&plan, &dispatch).is_err(),
            "{case}"
        );
    }
}
#[test]
fn evidence_owner_outcome_code_vocabulary_is_closed() {
    for (outcome_class, known_code) in [
        (SystemdEvidenceClassV1::Failure, "system_bus_unavailable"),
        (
            SystemdEvidenceClassV1::Indeterminate,
            "systemd_start_reply_timeout",
        ),
    ] {
        assert!(outcome_code_is_known(outcome_class, known_code));
        assert!(!outcome_code_is_known(
            outcome_class,
            "unrecognized_owner_outcome"
        ));
    }
}

#[test]
fn coherently_resealed_receipt_cannot_disagree_with_retained_evidence() {
    let (_directory, plan, dispatch) = fixture();
    run_script(&plan, &dispatch, success_observation());
    let connection = Connection::open(&plan.attempt_store).unwrap();
    let raw: Vec<u8> = connection
        .query_row(
            "SELECT receipt_body FROM docket_effect_attempt WHERE attempt=?1",
            [dispatch.attempt.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let mut receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(&raw).unwrap();
    let ExecutionOutcomeV1::Succeeded {
        success:
            EffectSuccessV1::SystemdUnit {
                resulting_active_state,
                ..
            },
    } = &mut receipt.outcome
    else {
        unreachable!()
    };
    *resulting_active_state = "inactive".to_owned();
    let raw = JcsDocument::canonicalize(&receipt).unwrap();
    let digest = receipt.digest().unwrap();
    connection
        .execute(
            "UPDATE docket_effect_attempt SET receipt=?1,receipt_body=?2 WHERE attempt=?3",
            params![digest.as_str(), raw.as_bytes(), dispatch.attempt.as_str()],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        reconcile_systemd_effect_attempt(&plan, &dispatch).unwrap_err(),
        "systemd-receipt-evidence-disagreement"
    );
}

#[test]
fn plan_and_dispatch_substitutions_refuse_before_store_creation() {
    let (_directory, plan, dispatch) = fixture();
    for case in ["work_schema", "work", "machine", "unit", "prestate"] {
        let mut candidate_plan = plan.clone();
        let mut candidate_dispatch = dispatch.clone();
        match case {
            "work_schema" => {
                candidate_dispatch.work_schema = EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned();
            }
            "work" => candidate_dispatch.work = Digest::hash_bytes(b"other-work"),
            "machine" => {
                candidate_plan.systemd_machine_identity =
                    "fedcba9876543210fedcba9876543210".to_owned();
            }
            "unit" => {
                let CanonicalEffectV1::SystemdUnit { unit, .. } = &mut candidate_plan.effect else {
                    unreachable!()
                };
                *unit = "other.service".to_owned();
            }
            "prestate" => {
                let CanonicalEffectV1::SystemdUnit {
                    expected_active_state,
                    ..
                } = &mut candidate_plan.effect
                else {
                    unreachable!()
                };
                *expected_active_state = "failed".to_owned();
            }
            _ => unreachable!(),
        }
        assert!(
            validate_dispatch(&candidate_plan, &candidate_dispatch).is_err(),
            "{case}"
        );
    }
    assert!(!plan.attempt_store.exists());
}
#[test]
fn discriminating_loader_is_bounded_no_follow_and_single_document() {
    let (directory, plan, _dispatch) = fixture();
    let canonical = JcsDocument::canonicalize(&plan).unwrap();
    let exact_path = directory.path().join("systemd-plan.json");
    std::fs::write(&exact_path, canonical.as_bytes()).unwrap();
    let loaded = load_effect_executor_plan_any(&exact_path).unwrap();
    let LoadedEffectExecutorPlan::SystemdV2(loaded) = loaded else {
        panic!("V2 schema must select the V2 plan exactly");
    };
    assert_eq!(loaded, plan);

    let link_path = directory.path().join("systemd-plan-link.json");
    symlink(&exact_path, &link_path).unwrap();
    assert!(
        load_effect_executor_plan_any(&link_path)
            .unwrap_err()
            .starts_with("effect-executor-plan-open:"),
        "final-component symlink must refuse before content acquisition"
    );

    let oversized_path = directory.path().join("oversized-plan.json");
    std::fs::write(
        &oversized_path,
        vec![b' '; usize::try_from(MAX_PLAN_BYTES).unwrap() + 1],
    )
    .unwrap();
    assert_eq!(
        load_effect_executor_plan_any(&oversized_path).unwrap_err(),
        "effect-executor-plan-not-bounded-regular-file"
    );
    assert!(!plan.attempt_store.exists());
}

#[test]
#[ignore = "schema fixture emitter; invoked by Python qualification"]
fn emit_systemd_schema_fixtures() {
    let (_directory, plan, dispatch) = fixture();
    run_script(&plan, &dispatch, success_observation());
    let plan_raw = JcsDocument::canonicalize(&plan).unwrap();
    let evidence_raw = reopen_systemd_dbus_evidence(&plan, &dispatch).unwrap();
    println!("AG_SYSTEMD_PLAN={}", plan_raw.as_str());
    println!(
        "AG_SYSTEMD_EVIDENCE={}",
        std::str::from_utf8(&evidence_raw).unwrap()
    );
}
