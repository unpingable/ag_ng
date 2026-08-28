#![allow(missing_docs)]

use ag_app::governed_campaign_v1::*;

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn git(byte: char) -> GitObjectV1 {
    GitObjectV1 {
        object_format: "sha1".into(),
        digest: byte.to_string().repeat(40),
    }
}

fn plan_template(stage: usize, predecessor: &PredecessorBindingV1) -> serde_json::Value {
    serde_json::json!({
        "schema": "ag.gcl-v1-worker-vm-plan-template/v1",
        "runtime_schema": "campaign-driver-ng.gcl-v1-worker-vm-plan/v2",
        "stage_id": format!("stage-{stage}"),
        "evidence_reservation": "",
        "predecessor": predecessor,
    })
}

fn nq_template(stage: usize, predecessor: &PredecessorBindingV1) -> serde_json::Value {
    serde_json::json!({
        "schema": "ag.nq-campaign-stage-realization-profile-template/v1",
        "runtime_schema": "nq.campaign-stage-realization-profile/v2",
        "stage_id": format!("stage-{stage}"),
        "evidence_reservation": "",
        "campaign_packet_sha256": "",
        "predecessor": predecessor,
    })
}

fn packet() -> CampaignPacketV1 {
    let campaign = digest('a');
    let mut stages: Vec<CampaignStageV1> = Vec::new();
    for index in 0..3 {
        let ordinal = u32::try_from(index + 1).unwrap();
        let predecessor = if index == 0 {
            PredecessorBindingV1::InitialGit {
                head: git('1'),
                tree: git('A'),
            }
        } else {
            PredecessorBindingV1::PriorStageRealization {
                stage_id: stages[index - 1].stage_id.clone(),
                reservation: stages[index - 1].reservation.reservation_id.clone(),
            }
        };
        let plan_template = plan_template(index + 1, &predecessor);
        let nq_template = nq_template(index + 1, &predecessor);
        let successor = if index < 2 {
            SuccessorLawV1::Stage {
                stage_id: format!("stage-{}", index + 2),
                work_schema: format!("gcl.specimen-stage-{}/v1", index + 2),
                work: digest(char::from_digit(u32::try_from(index + 2).unwrap(), 10).unwrap()),
            }
        } else {
            SuccessorLawV1::HumanRequired
        };
        let result_constraints = ExpectedResultConstraintsV1 {
            must_descend_from_predecessor: true,
            required_commit_count: 1,
            expected_clean_worktree: true,
            allowed_mutation_paths: vec![format!("src/stage{}.rs", index + 1)],
            factual_gate_profile_sha256: digest('f'),
        };
        let reservation = ExternalEvidenceReservationV1 {
            schema: String::new(),
            reservation_id: String::new(),
            campaign_id: campaign.clone(),
            stage_id: format!("stage-{}", index + 1),
            ordinal,
            logical_attempt_id: format!("attempt-{}", index + 1),
            predecessor,
            result_constraints,
            successor,
            worker_session_manifest_sha256: digest('b'),
            executor_plan_template_sha256: canonical_sha256(&plan_template).unwrap(),
            instruction_sha256: digest('c'),
            mutation_profile_sha256: digest('d'),
            resource_profile_sha256: digest('e'),
            nq_profile_template_sha256: canonical_sha256(&nq_template).unwrap(),
            does_not_establish: RESERVATION_NONCLAIMS_V1.map(str::to_owned).to_vec(),
        }
        .seal()
        .unwrap();
        stages.push(CampaignStageV1 {
            stage_id: reservation.stage_id.clone(),
            ordinal,
            logical_attempt_id: reservation.logical_attempt_id.clone(),
            work_schema: format!("gcl.specimen-stage-{}/v1", index + 1),
            work: digest(char::from_digit(u32::try_from(index + 1).unwrap(), 10).unwrap()),
            instruction_sha256: reservation.instruction_sha256.clone(),
            mutation_profile_sha256: reservation.mutation_profile_sha256.clone(),
            resource_profile_sha256: reservation.resource_profile_sha256.clone(),
            worker_session_manifest_sha256: reservation.worker_session_manifest_sha256.clone(),
            executor_plan_template: plan_template,
            executor_plan_template_sha256: reservation.executor_plan_template_sha256.clone(),
            nq_profile_template: nq_template,
            nq_profile_template_sha256: reservation.nq_profile_template_sha256.clone(),
            reservation,
        });
    }
    CampaignPacketV1 {
        schema: String::new(),
        packet_id: String::new(),
        campaign_id: campaign,
        repository_id: digest('9'),
        workspace: "/var/lib/gcl/velvet-pigeon".into(),
        repository_ref: "refs/heads/velvet-pigeon".into(),
        stages,
    }
    .seal()
    .unwrap()
}

#[test]
fn three_reservations_are_frozen_without_future_run_or_result_identities() {
    let packet = packet();
    assert_eq!(packet.stages.len(), 3);
    let text = serde_json::to_string(&packet).unwrap();
    assert!(!text.contains("porter_run"));
    assert!(!text.contains("settlement_id"));
    assert!(!text.contains("result_head"));
    assert_eq!(
        packet.stages[2].reservation.successor,
        SuccessorLawV1::HumanRequired
    );
}

#[test]
fn reservation_is_content_addressed_and_substitution_refuses() {
    let packet = packet();
    let mut changed = packet.clone();
    changed.stages[1].reservation.worker_session_manifest_sha256 = digest('0');
    assert!(changed.validate().is_err());
    let mut future = packet.clone();
    future.stages[0].executor_plan_template["porter_run_id"] = serde_json::json!("predicted");
    assert!(future.validate().is_err());
}

#[test]
fn predecessor_and_successor_chain_are_exact_and_stage_four_is_unrepresentable() {
    let packet = packet();
    let mut predecessor = packet.clone();
    if let PredecessorBindingV1::PriorStageRealization { reservation, .. } =
        &mut predecessor.stages[1].reservation.predecessor
    {
        *reservation = digest('0');
    }
    assert!(predecessor.validate().is_err());

    let mut successor = packet.clone();
    successor.stages[2].reservation.successor = SuccessorLawV1::Stage {
        stage_id: "stage-4".into(),
        work_schema: "gcl.specimen-stage-4/v1".into(),
        work: digest('4'),
    };
    assert!(successor.validate().is_err());
}

#[test]
fn exact_reservation_materialization_is_not_profile_wildcarding() {
    let packet = packet();
    let stage = &packet.stages[0];
    let mut wrong = stage.executor_plan_template.clone();
    wrong["evidence_reservation"] = serde_json::json!(digest('0'));
    assert!(materialize_template(&wrong, &stage.reservation.reservation_id).is_err());
    let exact = materialize_executor_plan_template(
        &stage.executor_plan_template,
        &stage.reservation,
        git('1'),
        git('A'),
    )
    .unwrap();
    assert_eq!(
        exact["evidence_reservation"],
        stage.reservation.reservation_id
    );
    let nq = materialize_nq_profile_template(
        &stage.nq_profile_template,
        &stage.reservation,
        &packet.packet_id,
        git('1'),
        git('A'),
    )
    .unwrap();
    assert_eq!(nq["evidence_reservation"], stage.reservation.reservation_id);
    assert_eq!(nq["campaign_packet_sha256"], packet.packet_id);
    assert_eq!(nq["predecessor"], stage.nq_profile_template["predecessor"]);
    let mut not_a_template = stage.nq_profile_template.clone();
    not_a_template["campaign_packet_sha256"] = serde_json::json!(packet.packet_id);
    assert!(materialize_nq_profile_template(
        &not_a_template,
        &stage.reservation,
        &packet.packet_id,
        git('1'),
        git('A'),
    )
    .is_err());
    assert!(!serde_json::to_string(&packet)
        .unwrap()
        .contains("executor_plan_sha256"));
}

#[test]
fn frozen_glass_heron_packet_closes_before_stage_one() {
    let Ok(path) = std::env::var("VELVET_PIGEON_PACKET_INPUT") else {
        eprintln!("VELVET-PIGEON packet fixture not requested");
        return;
    };
    let packet: CampaignPacketV1 = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    packet.validate().unwrap();
    let text = serde_json::to_string(&packet).unwrap();
    for stage in &packet.stages {
        assert!(!text.contains("\"porter_run_id\""));
        assert!(!stage
            .executor_plan_template
            .as_object()
            .unwrap()
            .contains_key("expected_result_head"));
        assert!(!stage
            .executor_plan_template
            .as_object()
            .unwrap()
            .contains_key("expected_result_tree"));
        assert!(!stage
            .executor_plan_template
            .as_object()
            .unwrap()
            .contains_key("predecessor_head"));
        assert!(!stage
            .executor_plan_template
            .as_object()
            .unwrap()
            .contains_key("predecessor_tree"));
        let (head, tree) = match &stage.reservation.predecessor {
            PredecessorBindingV1::InitialGit { head, tree } => (head.clone(), tree.clone()),
            PredecessorBindingV1::PriorStageRealization { .. } => (git('2'), git('B')),
        };
        materialize_executor_plan_template(
            &stage.executor_plan_template,
            &stage.reservation,
            head.clone(),
            tree.clone(),
        )
        .unwrap();
        materialize_nq_profile_template(
            &stage.nq_profile_template,
            &stage.reservation,
            &packet.packet_id,
            head,
            tree,
        )
        .unwrap();
    }
}
