//! Contract, hostile-input, and restart witnesses for Governed Campaign Loop
//! V0. These tests use no caller-authored qualification verdict.

use ag_app::governed_campaign_v0::*;
use sha2::{Digest as _, Sha256};

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}
fn git(byte: char) -> GitObjectV0 {
    GitObjectV0 {
        object_format: "sha1".into(),
        digest: byte.to_string().repeat(40),
    }
}
fn profile_sha(value: &serde_json::Value) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(value).unwrap())
    )
}

fn profile(stage: usize, predecessor: char, result: char) -> serde_json::Value {
    serde_json::json!({
        "schema": NQ_QUALIFICATION_PROFILE_SCHEMA_V1,
        "profile_id": format!("gcl-v0-stage-{stage}"),
        "campaign_packet_sha256": "",
        "stage_id": format!("stage-{stage}"),
        "repository_id": digest('b'),
        "repository_ref": "refs/heads/gcl-v0-specimen",
        "predecessor_head": {"object_format":"sha1", "digest": predecessor.to_string().repeat(40)},
        "predecessor_tree": {"object_format":"sha1", "digest": predecessor.to_ascii_uppercase().to_string().repeat(40)},
        "result_head": {"object_format":"sha1", "digest": result.to_string().repeat(40)},
        "result_tree": {"object_format":"sha1", "digest": result.to_ascii_uppercase().to_string().repeat(40)},
        "expected_evidence_producer": {"producer_id":"ag.governed-campaign-factual-gate-producer/v0", "producer_version":"0", "executable_sha256":digest('c')},
        "ordered_gates": [{"ordinal":0, "gate_id":format!("stage-{stage}-artifact"), "context":{"executable_sha256":digest('d'), "argv_transcript_sha256":digest('e'), "repository_relative_cwd":".", "environment_transcript_sha256":digest('f')}, "required_exit_code":0}],
        "required_artifacts": [{"repository_relative_path":format!("synthetic/stage-{stage}.txt"), "sha256":digest(char::from_digit(u32::try_from(stage).unwrap(),10).unwrap())}],
        "required_workspace_predicates": ["REPOSITORY_IDENTITY_MATCHES", "PERSISTENT_WRITE_READ_ROUND_TRIP", "HEAD_AND_TREE_STABLE_DURING_QUALIFICATION", "WORKTREE_MATCHES_DECLARED_CLEANLINESS", "MUTATION_SCOPE_RESPECTED"],
        "expected_clean_worktree": true
    })
}

fn packet() -> CampaignPacketV0 {
    let mut value = CampaignPacketV0 {
        schema: CAMPAIGN_PACKET_SCHEMA_V0.into(),
        packet_id: digest('0'),
        campaign_id: digest('a'),
        repository_id: digest('b'),
        workspace: "/tmp/gcl-v0-specimen".into(),
        repository_ref: "refs/heads/gcl-v0-specimen".into(),
        worker: FixedWorkerV0 {
            worker_id: "gcl-v0-fixed-fixture-worker/v0".into(),
            executable_sha256: digest('c'),
            model: "NOT_APPLICABLE".into(),
            effort: "NOT_OBSERVABLE".into(),
            launch_configuration_sha256: digest('d'),
        },
        resources: ResourcePolicyV0 {
            minimum_available_memory_bytes: 268_435_456,
            minimum_available_disk_bytes: 268_435_456,
            maximum_concurrent_campaigns: 1,
            campaign_memory_ceiling_bytes: 536_870_912,
            campaign_process_ceiling: 32,
            campaign_cpu_quota_percent: 50,
        },
        stages: [('1', '2'), ('2', '3'), ('3', '4')]
            .into_iter()
            .enumerate()
            .map(|(index, (predecessor, result))| {
                let number = index + 1;
                CampaignStageV0 {
                    stage_id: format!("stage-{number}"),
                    attempt_id: format!("attempt-{number}"),
                    predecessor_head: git(predecessor),
                    predecessor_tree: git(predecessor.to_ascii_uppercase()),
                    predecessor_qualification_artifacts: vec![(
                        format!("qualification/stage-{}.json", number - 1),
                        digest('9'),
                    )],
                    result_head: git(result),
                    result_tree: git(result.to_ascii_uppercase()),
                    work_schema: format!("ag.governed-campaign.synthetic-stage-{number}/v0"),
                    work: digest(char::from_digit(u32::try_from(number).unwrap(), 10).unwrap()),
                    instruction_sha256: digest('8'),
                    allowed_mutation_paths: vec![format!("synthetic/stage-{number}.txt")],
                    qualification_gates: vec![DeclaredGateV0 {
                        ordinal: 0,
                        gate_id: format!("stage-{number}-artifact"),
                        executable: "/usr/bin/git".into(),
                        argv: vec!["git".into(), "diff-tree".into(), "--exit-code".into()],
                        repository_relative_cwd: ".".into(),
                        allowed_environment: Vec::new(),
                        required_exit_code: 0,
                    }],
                    nq_qualification_profile: profile(number, predecessor, result),
                    nq_qualification_profile_sha256: String::new(),
                    expected_successor_stage_id: (number < 3)
                        .then(|| format!("stage-{}", number + 1)),
                }
            })
            .collect(),
    };
    value.packet_id = value.computed_packet_id().unwrap();
    for stage in &mut value.stages {
        stage.nq_qualification_profile["campaign_packet_sha256"] =
            serde_json::json!(value.packet_id);
        stage.nq_qualification_profile_sha256 = profile_sha(&stage.nq_qualification_profile);
    }
    value.validate().unwrap();
    value
}

fn admission(packet: &CampaignPacketV0, index: usize) -> StageAdmissionV0 {
    let stage = &packet.stages[index];
    StageAdmissionV0 {
        packet_id: packet.packet_id.clone(),
        stage_id: stage.stage_id.clone(),
        predecessor_head: stage.predecessor_head.clone(),
        predecessor_tree: stage.predecessor_tree.clone(),
        workspace_custody_passed: true,
        persistence_probe_passed: true,
        worktree_state_passed: true,
        predecessor_artifacts_passed: true,
        worker_available: true,
        resources_admitted: true,
    }
}
fn settlement(packet: &CampaignPacketV0, index: usize) -> StageSettlementV0 {
    let stage = &packet.stages[index];
    StageSettlementV0 {
        stage_id: stage.stage_id.clone(),
        attempt_id: stage.attempt_id.clone(),
        settlement_id: digest('7'),
        mechanics_receipt: digest('6'),
        result_head: stage.result_head.clone(),
        result_tree: stage.result_tree.clone(),
    }
}
fn authorization(packet: &CampaignPacketV0, index: usize) -> AgQualifiedContinuationV0 {
    AgQualifiedContinuationV0 {
        source_stage_id: packet.stages[index].stage_id.clone(),
        successor_stage_id: packet.stages[index + 1].stage_id.clone(),
        nq_profile_sha256: packet.stages[index].nq_qualification_profile_sha256.clone(),
        basis_type: REPOSITORY_QUALIFICATION_BASIS_TYPE_V1.into(),
        basis_identity: digest('5'),
        resolver_id: REPOSITORY_QUALIFICATION_RESOLVER_V1.into(),
        observation_status: "current".into(),
        ag_authorization: digest('4'),
        authorized_work: packet.stages[index + 1].work.clone(),
    }
}
fn freeze(packet: &CampaignPacketV0, index: usize) -> StageFreezeV0 {
    StageFreezeV0 {
        stage_id: packet.stages[index].stage_id.clone(),
        head: packet.stages[index].result_head.clone(),
        tree: packet.stages[index].result_tree.clone(),
        evidence_set_sha256: digest('3'),
        clean_worktree: true,
    }
}
fn qualifying(packet: &CampaignPacketV0, index: usize) -> CampaignSnapshotV0 {
    CampaignSnapshotV0::prepare(packet)
        .unwrap()
        .admit(packet, &admission(packet, index))
        .unwrap()
        .dispatched(packet, &packet.stages[index].attempt_id)
        .unwrap()
        .settled(packet, settlement(packet, index))
        .unwrap()
}

#[test]
fn packet_freezes_three_exact_profiles_and_rejects_modification() {
    let packet = packet();
    assert_eq!(packet.stages.len(), 3);
    assert_eq!(packet.stages[2].expected_successor_stage_id, None);
    let mut changed = packet.clone();
    changed.stages[1].nq_qualification_profile["profile_id"] = serde_json::json!("modified");
    assert!(changed.validate().is_err());
    let mut successor = packet.clone();
    successor.stages[0].expected_successor_stage_id = Some("worker-choice".into());
    assert!(successor.validate().is_err());
}

#[test]
fn caller_verdicts_and_raw_success_have_no_positive_transition() {
    for status in ["qualified", "failed", "indeterminate"] {
        assert!(
            serde_json::from_value::<QualificationDispositionV0>(
                serde_json::json!({"disposition":status,"record":{}})
            )
            .is_err()
        );
    }
    let packet = packet();
    let mut raw = authorization(&packet, 0);
    raw.basis_type = "controller.raw-success/v0".into();
    let state = qualifying(&packet, 0)
        .qualified_and_frozen(
            &packet,
            QualificationDispositionV0::SuccessorAuthorized(raw),
            freeze(&packet, 0),
        )
        .unwrap();
    assert_eq!(state.phase, CampaignPhaseV0::Stopped);
}

#[test]
fn stale_failed_indeterminate_wrong_profile_and_worker_successor_stop() {
    let packet = packet();
    for case in 0..6 {
        let mut value = authorization(&packet, 0);
        match case {
            0 => value.observation_status = "stale".into(),
            1 => value.nq_profile_sha256 = digest('0'),
            2 => value.source_stage_id = "wrong-predecessor".into(),
            3 => value.successor_stage_id = "worker-selected".into(),
            4 => value.authorized_work = digest('0'),
            5 => value.resolver_id = "worker-resolver/v0".into(),
            _ => unreachable!(),
        }
        let state = qualifying(&packet, 0)
            .qualified_and_frozen(
                &packet,
                QualificationDispositionV0::SuccessorAuthorized(value),
                freeze(&packet, 0),
            )
            .unwrap();
        assert_eq!(state.phase, CampaignPhaseV0::Stopped);
    }
}

#[test]
fn every_admission_refusal_stops_before_dispatch() {
    let packet = packet();
    for case in 0..8 {
        let mut value = admission(&packet, 0);
        match case {
            0 => value.packet_id = digest('f'),
            1 => value.predecessor_head = git('f'),
            2 => value.workspace_custody_passed = false,
            3 => value.persistence_probe_passed = false,
            4 => value.worktree_state_passed = false,
            5 => value.predecessor_artifacts_passed = false,
            6 => value.worker_available = false,
            7 => value.resources_admitted = false,
            _ => unreachable!(),
        }
        let state = CampaignSnapshotV0::prepare(&packet)
            .unwrap()
            .admit(&packet, &value)
            .unwrap();
        assert_eq!(state.phase, CampaignPhaseV0::Stopped);
    }
}

#[test]
fn restart_reconciles_instead_of_repeating_effect() {
    let packet = packet();
    let prepared = CampaignSnapshotV0::prepare(&packet).unwrap();
    assert_eq!(
        prepared.restart_action(&packet).unwrap(),
        RestartActionV0::Readmit
    );
    let admitted = prepared.admit(&packet, &admission(&packet, 0)).unwrap();
    assert_eq!(
        admitted.restart_action(&packet).unwrap(),
        RestartActionV0::DispatchExact {
            attempt_id: "attempt-1".into()
        }
    );
    let executing = admitted.dispatched(&packet, "attempt-1").unwrap();
    assert_eq!(
        executing.restart_action(&packet).unwrap(),
        RestartActionV0::ReconcileExact {
            attempt_id: "attempt-1".into()
        }
    );
    let qualifying = executing.settled(&packet, settlement(&packet, 0)).unwrap();
    assert_eq!(
        qualifying.restart_action(&packet).unwrap(),
        RestartActionV0::ReplayQualificationEvidence
    );
}

#[test]
fn three_stages_run_unattended_then_ag_requires_human() {
    let packet = packet();
    let mut state = CampaignSnapshotV0::prepare(&packet).unwrap();
    for index in 0..3 {
        state = state
            .admit(&packet, &admission(&packet, index))
            .unwrap()
            .dispatched(&packet, &packet.stages[index].attempt_id)
            .unwrap()
            .settled(&packet, settlement(&packet, index))
            .unwrap();
        let disposition = if index < 2 {
            QualificationDispositionV0::SuccessorAuthorized(authorization(&packet, index))
        } else {
            QualificationDispositionV0::TerminalHumanRequired(AgTerminalHumanStopV0 {
                stage_id: "stage-3".into(),
                nq_profile_sha256: packet.stages[2].nq_qualification_profile_sha256.clone(),
                basis_identity: digest('2'),
                program_counter: "HUMAN_REQUIRED".into(),
            })
        };
        state = state
            .qualified_and_frozen(&packet, disposition, freeze(&packet, index))
            .unwrap();
        if index < 2 {
            state = state.observe_successor(&packet).unwrap();
        }
    }
    assert_eq!(state.phase, CampaignPhaseV0::HumanRequired);
    assert_eq!(
        state.restart_action(&packet).unwrap(),
        RestartActionV0::Stop
    );
}
