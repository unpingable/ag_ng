//! Campaign office integration tests: the mock end-to-end loop is the
//! vertical slice consuming this crate.

use ag_campaign::{
    CampaignEventV1, CampaignIntentV1, CampaignLedgerV1, CampaignResidualV1, CandidateActionV1,
    DOCKET_STANDING_SCHEMA_V1, DocketStandingV1, EvidenceArtifactV1, EvidenceContractV1,
    EvidenceRequirementV1, FindingId, FindingV1, LedgerErrorV1, MutationScopeV1, PathGrantV1,
    PlanRefusalV1, PresentedReceiptV1, RUNTIME_RECEIPT_SCHEMA_V1, ReviewScopeV1, RuntimeEnvelopeV1,
    SidecarOutcomeV1, SidecarRuntimeReceiptV1, SidecarVerificationErrorV1, StageBasisV1, StageId,
    StageKindV1, StageProposalV1, StageReceiptV1, VerdictReceiptV1, VerdictV1, WorkerRoleV1,
    plan_from_ledger, present_from_ledger, recompose_campaign, stage_receipt_from_execution,
    verify_sidecar_receipt,
};
use ag_kernel::{NativeJudgment, NonEmpty, RecompositionFailure};
use ag_primitives::{Digest, LifecycleNonce};

const NOW: u64 = 1_000_000;
const EXPIRY: u64 = 2_000_000;
const EVIDENCE_SCHEMA: &str = "ag.test.report/v1";
const C1_PROCESS_STANDING_PATH: &str = "/audits/nq-host-role-runtime-seam-v1/c1-gen5-c2-guarded-store-generation/C1-GEN5-C2-DEVELOPMENT-PROCESS-STANDING-INVENTORY-V1.json";

fn digest(value: &str) -> Digest {
    Digest::hash_bytes(value.as_bytes())
}

fn intent() -> CampaignIntentV1 {
    CampaignIntentV1::new(
        "test-campaign".to_owned(),
        digest("human-authorization-instrument"),
        digest("operator-principal"),
        digest("reviewer-principal"),
    )
    .unwrap()
}

fn basis() -> StageBasisV1 {
    StageBasisV1 {
        repository: "repo:governed".to_owned(),
        base_commit: digest("commit-1"),
        base_tree: digest("tree-1"),
    }
}

fn grants() -> Vec<PathGrantV1> {
    vec![PathGrantV1 {
        repository: "repo:governed".to_owned(),
        path_prefix: "/src".to_owned(),
    }]
}

fn mutation_scope() -> MutationScopeV1 {
    MutationScopeV1 { grants: grants() }
}

fn evidence() -> EvidenceContractV1 {
    EvidenceContractV1 {
        required: vec![EvidenceRequirementV1 {
            schema: EVIDENCE_SCHEMA.to_owned(),
        }],
    }
}

fn artifacts() -> Vec<EvidenceArtifactV1> {
    vec![EvidenceArtifactV1 {
        schema: EVIDENCE_SCHEMA.to_owned(),
        digest: digest("artifact-1"),
    }]
}

fn standing(stage: &StageId, label: &str) -> DocketStandingV1 {
    DocketStandingV1 {
        schema: DOCKET_STANDING_SCHEMA_V1.to_owned(),
        stage: stage.clone(),
        standing_digest: digest(label),
        expiry_unix: EXPIRY,
    }
}

fn operator_proposal(campaign: &ag_campaign::CampaignId, seq: u64) -> StageProposalV1 {
    StageProposalV1::operator(campaign, seq, basis(), mutation_scope(), evidence()).unwrap()
}

/// Executes one operator stage through the full burn-before-effect loop and
/// returns its recorded stage receipt.
fn execute_operator_stage(
    ledger: &mut CampaignLedgerV1,
    proposal: &StageProposalV1,
    standing_label: &str,
) -> StageReceiptV1 {
    let stage = ledger.propose_stage(proposal.clone()).unwrap();
    ledger
        .admit_stage(&stage, standing(&stage, standing_label), NOW)
        .unwrap();
    let consumed = ledger.consume_standing(&stage, NOW).unwrap();
    let envelope = RuntimeEnvelopeV1::render(&consumed, proposal, LifecycleNonce::new([0x42; 16]));
    let envelope_digest = envelope.digest();
    ledger
        .record_dispatch(
            &consumed,
            &envelope_digest,
            envelope.allowed_paths().to_vec(),
        )
        .unwrap();
    let sidecar_receipt = SidecarRuntimeReceiptV1 {
        schema: RUNTIME_RECEIPT_SCHEMA_V1.to_owned(),
        envelope_digest,
        campaign: ledger.campaign().clone(),
        stage: stage.clone(),
        standing_digest: consumed.standing_digest().clone(),
        nonce: *envelope.nonce(),
        outcome: SidecarOutcomeV1::Completed,
        post_tree: Some(digest("post-tree-1")),
        artifacts: artifacts(),
    };
    let verified = verify_sidecar_receipt(&envelope, &sidecar_receipt).unwrap();
    let stage_receipt = stage_receipt_from_execution(&envelope, proposal, &verified).unwrap();
    ledger.record_stage_receipt(stage_receipt.clone()).unwrap();
    stage_receipt
}

/// Runs a review stage to its verdict and records it.
fn review_subject(
    ledger: &mut CampaignLedgerV1,
    seq: u64,
    subject: &StageId,
    subject_receipt: &StageReceiptV1,
    standing_label: &str,
    verdict: VerdictV1,
    findings: Vec<FindingV1>,
) -> VerdictReceiptV1 {
    let campaign = ledger.campaign().clone();
    let proposal = StageProposalV1::review(
        &campaign,
        seq,
        basis(),
        ReviewScopeV1 {
            subject_stage: subject.clone(),
            read_paths: grants(),
        },
        evidence(),
    )
    .unwrap();
    let review_stage = ledger.propose_stage(proposal).unwrap();
    ledger
        .admit_stage(&review_stage, standing(&review_stage, standing_label), NOW)
        .unwrap();
    ledger.consume_standing(&review_stage, NOW).unwrap();
    let verdict_receipt = VerdictReceiptV1::new(
        &campaign,
        review_stage,
        subject.clone(),
        subject_receipt.id(),
        digest("reviewer-principal"),
        verdict,
        findings,
        basis(),
    )
    .unwrap();
    ledger.record_verdict(verdict_receipt.clone()).unwrap();
    verdict_receipt
}

/// A complete one-stage accepted campaign.
fn completed_campaign() -> (CampaignLedgerV1, StageId) {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = proposal.id();
    let receipt = execute_operator_stage(&mut ledger, &proposal, "standing-1");
    review_subject(
        &mut ledger,
        2,
        &stage,
        &receipt,
        "standing-2",
        VerdictV1::Accept,
        vec![],
    );
    (ledger, stage)
}

#[test]
fn campaign_identity_is_exact_and_immutable() {
    let first = intent();
    let second = intent();
    assert_eq!(first.campaign_id(), second.campaign_id());

    let tampered = CampaignIntentV1::new(
        "test-campaign".to_owned(),
        digest("different-authorization"),
        digest("operator-principal"),
        digest("reviewer-principal"),
    )
    .unwrap();
    assert_ne!(first.campaign_id(), tampered.campaign_id());

    let deserialized: CampaignIntentV1 =
        serde_json::from_str(&serde_json::to_string(&first).unwrap()).unwrap();
    assert_eq!(deserialized.campaign_id(), first.campaign_id());
}

#[test]
fn stage_projection_binds_exactly_one_campaign_and_one_role() {
    let ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    assert_eq!(proposal.campaign(), &campaign);
    assert_eq!(proposal.role(), WorkerRoleV1::Operator);
    assert!(matches!(proposal.kind(), StageKindV1::Operator(_)));

    let mut foreign = CampaignLedgerV1::create(
        CampaignIntentV1::new(
            "other-campaign".to_owned(),
            digest("human-authorization-instrument"),
            digest("operator-principal"),
            digest("reviewer-principal"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        foreign.propose_stage(proposal).unwrap_err(),
        LedgerErrorV1::CampaignMismatch
    );

    // A reviewer stage has no mutation vocabulary: the variant carries only a
    // read scope, and its role is the reviewer role.
    let review = StageProposalV1::review(
        &campaign,
        2,
        basis(),
        ReviewScopeV1 {
            subject_stage: StageId::from_digest(digest("subject")),
            read_paths: grants(),
        },
        evidence(),
    )
    .unwrap();
    assert_eq!(review.role(), WorkerRoleV1::Reviewer);
    assert!(matches!(review.kind(), StageKindV1::Review(_)));
}

#[test]
fn exact_130_byte_c1_path_round_trips_without_rewriting_or_widening() {
    assert_eq!(C1_PROCESS_STANDING_PATH.len(), 130);
    let grant = PathGrantV1 {
        repository: "records".to_owned(),
        path_prefix: C1_PROCESS_STANDING_PATH.to_owned(),
    };
    grant
        .validate()
        .expect("the exact 130-byte canonical path must validate");

    let campaign = intent().campaign_id();
    let proposal = StageProposalV1::operator(
        &campaign,
        1,
        basis(),
        MutationScopeV1 {
            grants: vec![grant.clone()],
        },
        evidence(),
    )
    .unwrap();
    let encoded = serde_json::to_vec(&proposal).unwrap();
    let decoded: StageProposalV1 = serde_json::from_slice(&encoded).unwrap();
    let reencoded = serde_json::to_vec(&decoded).unwrap();

    assert_eq!(decoded, proposal);
    assert_eq!(decoded.id(), proposal.id());
    assert_eq!(reencoded, encoded);
    let StageKindV1::Operator(scope) = decoded.kind() else {
        panic!("the stage role must remain operator");
    };
    assert_eq!(scope.grants, vec![grant]);
    assert_eq!(
        scope.grants[0].path_prefix.as_bytes(),
        C1_PROCESS_STANDING_PATH.as_bytes()
    );
}

fn assert_dispatch_scope_change_refuses(altered_paths: Vec<PathGrantV1>) {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = StageProposalV1::operator(
        &campaign,
        1,
        basis(),
        MutationScopeV1 {
            grants: vec![PathGrantV1 {
                repository: "records".to_owned(),
                path_prefix: C1_PROCESS_STANDING_PATH.to_owned(),
            }],
        },
        evidence(),
    )
    .unwrap();
    let stage = ledger.propose_stage(proposal).unwrap();
    ledger
        .admit_stage(&stage, standing(&stage, "long-path-standing"), NOW)
        .unwrap();
    let consumed = ledger.consume_standing(&stage, NOW).unwrap();
    ledger
        .record_dispatch(&consumed, &digest("long-path-envelope"), altered_paths)
        .unwrap();
    assert!(matches!(
        plan_from_ledger(&ledger),
        Err(PlanRefusalV1::BroadenedPathScope { stage: refused }) if refused == stage
    ));
}

#[test]
fn increased_capacity_does_not_launder_scope_changes() {
    let parent = C1_PROCESS_STANDING_PATH
        .rsplit_once('/')
        .expect("the exact path has a parent")
        .0;
    let altered = [
        format!("{parent}/UNDECLARED-SIBLING.json"),
        format!("{C1_PROCESS_STANDING_PATH}/undeclared-child"),
        parent.to_owned(),
        C1_PROCESS_STANDING_PATH[..128].to_owned(),
        format!("{C1_PROCESS_STANDING_PATH}-prefix-collision"),
        C1_PROCESS_STANDING_PATH.replacen("/c1-gen5-c2", "//c1-gen5-c2", 1),
        format!("{parent}/*"),
    ];
    for path_prefix in altered {
        assert_dispatch_scope_change_refuses(vec![PathGrantV1 {
            repository: "records".to_owned(),
            path_prefix,
        }]);
    }

    assert_dispatch_scope_change_refuses(vec![
        PathGrantV1 {
            repository: "records".to_owned(),
            path_prefix: C1_PROCESS_STANDING_PATH.to_owned(),
        },
        PathGrantV1 {
            repository: "records".to_owned(),
            path_prefix: C1_PROCESS_STANDING_PATH.to_owned(),
        },
    ]);

    let traversal = PathGrantV1 {
        repository: "records".to_owned(),
        path_prefix: "/audits/../outside".to_owned(),
    };
    assert!(traversal.validate().is_err());
}

#[test]
fn operator_and_reviewer_must_be_distinct() {
    let collision = CampaignIntentV1::new(
        "test-campaign".to_owned(),
        digest("human-authorization-instrument"),
        digest("same-principal"),
        digest("same-principal"),
    );
    assert!(collision.is_err());

    // The operator principal cannot verdict its own work.
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = proposal.id();
    let receipt = execute_operator_stage(&mut ledger, &proposal, "standing-1");
    let review_proposal = StageProposalV1::review(
        &campaign,
        2,
        basis(),
        ReviewScopeV1 {
            subject_stage: stage.clone(),
            read_paths: grants(),
        },
        evidence(),
    )
    .unwrap();
    let review_stage = ledger.propose_stage(review_proposal).unwrap();
    ledger
        .admit_stage(&review_stage, standing(&review_stage, "standing-2"), NOW)
        .unwrap();
    ledger.consume_standing(&review_stage, NOW).unwrap();
    let self_review = VerdictReceiptV1::new(
        &campaign,
        review_stage,
        stage,
        receipt.id(),
        digest("operator-principal"),
        VerdictV1::Accept,
        vec![],
        basis(),
    )
    .unwrap();
    assert_eq!(
        ledger.record_verdict(self_review).unwrap_err(),
        LedgerErrorV1::ReviewerIdentity
    );
}

#[test]
fn proposed_repair_requires_exact_findings_and_rejected_review() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = proposal.id();
    let receipt = execute_operator_stage(&mut ledger, &proposal, "standing-1");
    let findings = vec![
        FindingV1 {
            finding_id: FindingId::new("finding-1").unwrap(),
            statement: "scope violation".to_owned(),
        },
        FindingV1 {
            finding_id: FindingId::new("finding-2").unwrap(),
            statement: "missing evidence".to_owned(),
        },
    ];
    let rejected = review_subject(
        &mut ledger,
        2,
        &stage,
        &receipt,
        "standing-2",
        VerdictV1::Reject,
        findings,
    );

    // Exact citation: known finding IDs plus the exact rejected review digest.
    let repair = StageProposalV1::repair(
        &campaign,
        3,
        basis(),
        mutation_scope(),
        evidence(),
        NonEmpty::new(FindingId::new("finding-1").unwrap()),
        rejected.id(),
    )
    .unwrap();
    ledger.propose_stage(repair).unwrap();

    // An altered finding identity refuses.
    let altered = StageProposalV1::repair(
        &campaign,
        4,
        basis(),
        mutation_scope(),
        evidence(),
        NonEmpty::new(FindingId::new("finding-9").unwrap()),
        rejected.id(),
    )
    .unwrap();
    assert_eq!(
        ledger.propose_stage(altered).unwrap_err(),
        LedgerErrorV1::AlteredFindingIdentity
    );

    // An unknown rejected-review digest refuses.
    let unknown = StageProposalV1::repair(
        &campaign,
        5,
        basis(),
        mutation_scope(),
        evidence(),
        NonEmpty::new(FindingId::new("finding-1").unwrap()),
        digest("not-a-review"),
    )
    .unwrap();
    assert_eq!(
        ledger.propose_stage(unknown).unwrap_err(),
        LedgerErrorV1::RejectedReviewUnknown
    );
}

#[test]
fn end_to_end_mock_loop_recomposes_with_independent_dispositions() {
    let (ledger, _stage) = completed_campaign();
    let plan = plan_from_ledger(&ledger).unwrap();
    let presented = present_from_ledger(&ledger);
    assert_eq!(presented.len(), plan.requirements.len());
    let NativeJudgment::Admit(receipt) = recompose_campaign(&plan, &presented, &ledger) else {
        panic!("a clean complete campaign must recompose");
    };
    let dispositions = receipt.dispositions();
    assert!(dispositions.operational_execution_completed);
    assert!(dispositions.review_accepted);
    assert!(dispositions.slice_accepted);
    assert!(dispositions.campaign_completed);
    assert!(dispositions.campaign_discharged);
    assert!(!dispositions.candidate_standing);
    assert!(!dispositions.qualification_standing);
    assert_eq!(receipt.open_residuals().len(), 0);
}

#[test]
fn recomposition_is_deterministic() {
    let (ledger, _stage) = completed_campaign();
    let first_plan = plan_from_ledger(&ledger).unwrap();
    let second_plan = plan_from_ledger(&ledger).unwrap();
    assert_eq!(first_plan, second_plan);
    let presented = present_from_ledger(&ledger);
    let first = recompose_campaign(&first_plan, &presented, &ledger);
    let second = recompose_campaign(&second_plan, &presented, &ledger);
    let (NativeJudgment::Admit(first), NativeJudgment::Admit(second)) = (first, second) else {
        panic!("clean campaigns must recompose");
    };
    assert_eq!(first.id(), second.id());

    // Replay of the exact event sequence lands on the same receipt.
    let replayed = CampaignLedgerV1::from_events(ledger.events().to_vec()).unwrap();
    let replayed_plan = plan_from_ledger(&replayed).unwrap();
    let replayed_presented = present_from_ledger(&replayed);
    let NativeJudgment::Admit(replayed_receipt) =
        recompose_campaign(&replayed_plan, &replayed_presented, &replayed)
    else {
        panic!("replayed campaign must recompose");
    };
    assert_eq!(first.id(), replayed_receipt.id());
}

#[test]
fn missing_receipt_refuses_recomposition() {
    let (ledger, _stage) = completed_campaign();
    let plan = plan_from_ledger(&ledger).unwrap();
    let presented = present_from_ledger(&ledger);
    let dropped = presented[3].boundary_id.clone();
    let incomplete: Vec<PresentedReceiptV1> = presented
        .into_iter()
        .enumerate()
        .filter(|(index, _)| *index != 3)
        .map(|(_, receipt)| receipt)
        .collect();
    let NativeJudgment::Refuse(refusal) = recompose_campaign(&plan, &incomplete, &ledger) else {
        panic!("a dropped receipt must refuse");
    };
    assert!(refusal.failures().iter().any(|failure| matches!(
        failure,
        RecompositionFailure::MissingBoundary { boundary_id } if *boundary_id == dropped
    )));
}

#[test]
fn duplicated_receipt_refuses_recomposition() {
    let (ledger, _stage) = completed_campaign();
    let plan = plan_from_ledger(&ledger).unwrap();
    let mut presented = present_from_ledger(&ledger);
    let duplicated = presented[2].clone();
    let duplicated_boundary = duplicated.boundary_id.clone();
    presented.push(duplicated);
    let NativeJudgment::Refuse(refusal) = recompose_campaign(&plan, &presented, &ledger) else {
        panic!("a duplicated receipt must refuse");
    };
    assert!(refusal.failures().iter().any(|failure| matches!(
        failure,
        RecompositionFailure::DuplicateBoundary { boundary_id } if *boundary_id == duplicated_boundary
    )));
}

#[test]
fn residual_erasure_refuses_and_residuals_block_discharge() {
    let (mut ledger, _stage) = completed_campaign();
    ledger
        .record_residual(CampaignResidualV1 {
            residual_id: "residual-1".to_owned(),
            stage: None,
            statement: "broker wiring for stage execution is pending".to_owned(),
        })
        .unwrap();
    let plan = plan_from_ledger(&ledger).unwrap();
    let residual_boundary = plan
        .requirements
        .iter()
        .find(|required| required.kind == ag_campaign::AccountingKindV1::Residual)
        .expect("the plan must account for the residual")
        .boundary_id
        .clone();

    // Erasing the residual from the presented receipts refuses.
    let presented: Vec<PresentedReceiptV1> = present_from_ledger(&ledger)
        .into_iter()
        .filter(|receipt| receipt.boundary_id != residual_boundary)
        .collect();
    let NativeJudgment::Refuse(refusal) = recompose_campaign(&plan, &presented, &ledger) else {
        panic!("residual erasure must refuse");
    };
    assert!(refusal.failures().iter().any(|failure| matches!(
        failure,
        RecompositionFailure::MissingBoundary { boundary_id } if *boundary_id == residual_boundary
    )));

    // Fully presented, the slice is accepted but the campaign is not
    // discharged: an accepted slice is not campaign discharge.
    let presented = present_from_ledger(&ledger);
    let NativeJudgment::Admit(receipt) = recompose_campaign(&plan, &presented, &ledger) else {
        panic!("a fully presented campaign with residuals must recompose");
    };
    assert!(receipt.dispositions().slice_accepted);
    assert!(receipt.dispositions().campaign_completed);
    assert!(!receipt.dispositions().campaign_discharged);
    assert_eq!(receipt.open_residuals().len(), 1);
}

#[test]
fn candidate_and_qualification_actions_always_refuse() {
    let (mut ledger, _stage) = completed_campaign();
    let candidate = ledger.refuse_prohibited_action(CandidateActionV1::CandidateStanding);
    let qualification = ledger.refuse_prohibited_action(CandidateActionV1::QualificationStanding);
    let freeze = ledger.refuse_prohibited_action(CandidateActionV1::CampaignFreeze);
    assert_ne!(candidate.refusal_digest, qualification.refusal_digest);
    assert_ne!(candidate.refusal_digest, freeze.refusal_digest);
    assert_eq!(ledger.candidate_refusals().len(), 3);

    // The refusal checks are accounted, and the receipt still pins both
    // standings to false.
    let plan = plan_from_ledger(&ledger).unwrap();
    assert_eq!(
        plan.requirements
            .iter()
            .filter(|required| required.kind == ag_campaign::AccountingKindV1::ExternalActionCheck)
            .count(),
        3
    );
    let presented = present_from_ledger(&ledger);
    let NativeJudgment::Admit(receipt) = recompose_campaign(&plan, &presented, &ledger) else {
        panic!("recorded prohibited-action refusals must not block recomposition");
    };
    assert!(!receipt.dispositions().candidate_standing);
    assert!(!receipt.dispositions().qualification_standing);
}

#[test]
fn envelope_requires_burned_standing_and_verifies_the_sidecar_receipt() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = ledger.propose_stage(proposal.clone()).unwrap();
    ledger
        .admit_stage(&stage, standing(&stage, "standing-1"), NOW)
        .unwrap();
    let consumed = ledger.consume_standing(&stage, NOW).unwrap();
    let envelope = RuntimeEnvelopeV1::render(&consumed, &proposal, LifecycleNonce::new([0x42; 16]));
    assert_eq!(envelope.standing_digest(), consumed.standing_digest());
    assert_eq!(envelope.consumption_digest(), consumed.consumption_digest());
    assert_eq!(envelope.allowed_paths(), grants().as_slice());

    let good = SidecarRuntimeReceiptV1 {
        schema: RUNTIME_RECEIPT_SCHEMA_V1.to_owned(),
        envelope_digest: envelope.digest(),
        campaign: campaign.clone(),
        stage: stage.clone(),
        standing_digest: consumed.standing_digest().clone(),
        nonce: *envelope.nonce(),
        outcome: SidecarOutcomeV1::Completed,
        post_tree: Some(digest("post-tree-1")),
        artifacts: artifacts(),
    };
    assert!(verify_sidecar_receipt(&envelope, &good).is_ok());

    let wrong_nonce = SidecarRuntimeReceiptV1 {
        nonce: LifecycleNonce::new([0x99; 16]),
        ..good.clone()
    };
    assert_eq!(
        verify_sidecar_receipt(&envelope, &wrong_nonce).unwrap_err(),
        SidecarVerificationErrorV1::NonceMismatch
    );

    let wrong_envelope = SidecarRuntimeReceiptV1 {
        envelope_digest: digest("other-envelope"),
        ..good.clone()
    };
    assert_eq!(
        verify_sidecar_receipt(&envelope, &wrong_envelope).unwrap_err(),
        SidecarVerificationErrorV1::EnvelopeMismatch
    );

    let missing_artifact = SidecarRuntimeReceiptV1 {
        artifacts: vec![],
        ..good.clone()
    };
    assert_eq!(
        verify_sidecar_receipt(&envelope, &missing_artifact).unwrap_err(),
        SidecarVerificationErrorV1::EvidenceContractViolation
    );

    let wrong_standing = SidecarRuntimeReceiptV1 {
        standing_digest: digest("other-standing"),
        ..good.clone()
    };
    assert_eq!(
        verify_sidecar_receipt(&envelope, &wrong_standing).unwrap_err(),
        SidecarVerificationErrorV1::StandingMismatch
    );

    // A failed outcome verifies but yields no stage receipt.
    let failed = SidecarRuntimeReceiptV1 {
        outcome: SidecarOutcomeV1::Failed,
        artifacts: vec![],
        post_tree: None,
        ..good.clone()
    };
    let verified = verify_sidecar_receipt(&envelope, &failed).unwrap();
    assert!(stage_receipt_from_execution(&envelope, &proposal, &verified).is_none());
}

#[test]
fn reviewer_envelope_refuses_mutation_claims() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = proposal.id();
    let _receipt = execute_operator_stage(&mut ledger, &proposal, "standing-1");
    let review_proposal = StageProposalV1::review(
        &campaign,
        2,
        basis(),
        ReviewScopeV1 {
            subject_stage: stage,
            read_paths: grants(),
        },
        evidence(),
    )
    .unwrap();
    let review_stage = ledger.propose_stage(review_proposal.clone()).unwrap();
    ledger
        .admit_stage(&review_stage, standing(&review_stage, "standing-2"), NOW)
        .unwrap();
    let consumed = ledger.consume_standing(&review_stage, NOW).unwrap();
    let envelope =
        RuntimeEnvelopeV1::render(&consumed, &review_proposal, LifecycleNonce::new([0x42; 16]));
    assert_eq!(envelope.role(), WorkerRoleV1::Reviewer);
    let mutation_claim = SidecarRuntimeReceiptV1 {
        schema: RUNTIME_RECEIPT_SCHEMA_V1.to_owned(),
        envelope_digest: envelope.digest(),
        campaign: campaign.clone(),
        stage: review_stage.clone(),
        standing_digest: consumed.standing_digest().clone(),
        nonce: *envelope.nonce(),
        outcome: SidecarOutcomeV1::Completed,
        post_tree: Some(digest("unauthorized-mutation")),
        artifacts: artifacts(),
    };
    assert_eq!(
        verify_sidecar_receipt(&envelope, &mutation_claim).unwrap_err(),
        SidecarVerificationErrorV1::ReviewerMutation
    );
}

#[test]
fn historical_standing_cannot_be_presented_as_current() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let first_proposal = operator_proposal(&campaign, 1);
    let _first_receipt = execute_operator_stage(&mut ledger, &first_proposal, "standing-1");

    let second_proposal = operator_proposal(&campaign, 2);
    let second_stage = ledger.propose_stage(second_proposal.clone()).unwrap();
    ledger
        .admit_stage(&second_stage, standing(&second_stage, "standing-2"), NOW)
        .unwrap();
    let consumed = ledger.consume_standing(&second_stage, NOW).unwrap();
    let envelope =
        RuntimeEnvelopeV1::render(&consumed, &second_proposal, LifecycleNonce::new([0x42; 16]));
    ledger
        .record_dispatch(
            &consumed,
            &envelope.digest(),
            envelope.allowed_paths().to_vec(),
        )
        .unwrap();

    // A receipt for stage two carrying stage one's (historical) standing.
    let laundered = StageReceiptV1 {
        schema: ag_campaign::STAGE_RECEIPT_SCHEMA_V1.to_owned(),
        campaign: campaign.clone(),
        stage: second_stage.clone(),
        stage_seq: 2,
        role: WorkerRoleV1::Operator,
        standing: digest("standing-1"),
        envelope: envelope.digest(),
        basis: basis(),
        post_tree: Some(digest("post-tree-1")),
        artifacts: artifacts(),
    };
    assert_eq!(
        ledger.record_stage_receipt(laundered).unwrap_err(),
        LedgerErrorV1::HistoricalStandingAsCurrent
    );

    // A receipt carrying a foreign standing is a plain mismatch.
    let foreign = StageReceiptV1 {
        standing: digest("never-issued"),
        ..StageReceiptV1 {
            schema: ag_campaign::STAGE_RECEIPT_SCHEMA_V1.to_owned(),
            campaign: campaign.clone(),
            stage: second_stage,
            stage_seq: 2,
            role: WorkerRoleV1::Operator,
            standing: digest("placeholder"),
            envelope: envelope.digest(),
            basis: basis(),
            post_tree: Some(digest("post-tree-1")),
            artifacts: artifacts(),
        }
    };
    assert_eq!(
        ledger.record_stage_receipt(foreign).unwrap_err(),
        LedgerErrorV1::StandingMismatch
    );
}

#[test]
fn worker_receipt_cannot_self_admit_the_next_stage() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let first = operator_proposal(&campaign, 1);
    execute_operator_stage(&mut ledger, &first, "standing-1");

    // Stage two is proposed but never admitted; the recorded worker receipt
    // for stage one admitted nothing.
    let second = operator_proposal(&campaign, 2);
    let second_stage = ledger.propose_stage(second).unwrap();
    assert_eq!(
        ledger.consume_standing(&second_stage, NOW).unwrap_err(),
        LedgerErrorV1::NotAdmitted
    );
}

#[test]
fn reviewer_output_after_repository_mutation_refuses() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let first = operator_proposal(&campaign, 1);
    let first_stage = first.id();
    let first_receipt = execute_operator_stage(&mut ledger, &first, "standing-1");

    // The review stage is admitted and consumed, but a second operator stage
    // mutates the same repository before the verdict is recorded.
    let review_proposal = StageProposalV1::review(
        &campaign,
        2,
        basis(),
        ReviewScopeV1 {
            subject_stage: first_stage.clone(),
            read_paths: grants(),
        },
        evidence(),
    )
    .unwrap();
    let review_stage = ledger.propose_stage(review_proposal).unwrap();
    ledger
        .admit_stage(&review_stage, standing(&review_stage, "standing-2"), NOW)
        .unwrap();
    ledger.consume_standing(&review_stage, NOW).unwrap();

    let second = operator_proposal(&campaign, 3);
    execute_operator_stage(&mut ledger, &second, "standing-3");

    let late_verdict = VerdictReceiptV1::new(
        &campaign,
        review_stage,
        first_stage,
        first_receipt.id(),
        digest("reviewer-principal"),
        VerdictV1::Accept,
        vec![],
        basis(),
    )
    .unwrap();
    assert_eq!(
        ledger.record_verdict(late_verdict).unwrap_err(),
        LedgerErrorV1::ReviewAfterMutation
    );
}

#[test]
fn rejected_verdict_obstructs_until_an_accepted_repair_closes_the_loop() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = proposal.id();
    let receipt = execute_operator_stage(&mut ledger, &proposal, "standing-1");
    let rejected = review_subject(
        &mut ledger,
        2,
        &stage,
        &receipt,
        "standing-2",
        VerdictV1::Reject,
        vec![FindingV1 {
            finding_id: FindingId::new("finding-1").unwrap(),
            statement: "scope violation".to_owned(),
        }],
    );

    // Without a repair the rejection is an obstruction.
    let plan = plan_from_ledger(&ledger).unwrap();
    let presented = present_from_ledger(&ledger);
    let NativeJudgment::Refuse(refusal) = recompose_campaign(&plan, &presented, &ledger) else {
        panic!("an unrepaired rejection must refuse recomposition");
    };
    assert!(
        refusal
            .failures()
            .iter()
            .any(|failure| matches!(failure, RecompositionFailure::ObstructedBoundary { .. }))
    );

    // The bounded repair loop executes and is accepted.
    let repair = StageProposalV1::repair(
        &campaign,
        3,
        basis(),
        mutation_scope(),
        evidence(),
        NonEmpty::new(FindingId::new("finding-1").unwrap()),
        rejected.id(),
    )
    .unwrap();
    let repair_stage = repair.id();
    let repair_receipt = execute_operator_stage(&mut ledger, &repair, "standing-3");
    review_subject(
        &mut ledger,
        4,
        &repair_stage,
        &repair_receipt,
        "standing-4",
        VerdictV1::Accept,
        vec![],
    );

    let plan = plan_from_ledger(&ledger).unwrap();
    assert!(
        plan.requirements
            .iter()
            .any(|required| required.kind == ag_campaign::AccountingKindV1::RepairLoop)
    );
    let presented = present_from_ledger(&ledger);
    let NativeJudgment::Admit(receipt) = recompose_campaign(&plan, &presented, &ledger) else {
        panic!("an accepted bounded repair closes the loop");
    };
    assert!(receipt.dispositions().slice_accepted);
    assert!(receipt.dispositions().campaign_completed);
}

#[test]
fn burn_before_effect_is_enforced() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = ledger.propose_stage(proposal.clone()).unwrap();
    ledger
        .admit_stage(&stage, standing(&stage, "standing-1"), NOW)
        .unwrap();

    // A receipt without a recorded consumption refuses.
    let premature = StageReceiptV1 {
        schema: ag_campaign::STAGE_RECEIPT_SCHEMA_V1.to_owned(),
        campaign: campaign.clone(),
        stage: stage.clone(),
        stage_seq: 1,
        role: WorkerRoleV1::Operator,
        standing: digest("standing-1"),
        envelope: digest("envelope"),
        basis: basis(),
        post_tree: None,
        artifacts: artifacts(),
    };
    assert_eq!(
        ledger.record_stage_receipt(premature.clone()).unwrap_err(),
        LedgerErrorV1::ConsumptionMissing
    );

    // Consumed but not dispatched: still refused.
    ledger.consume_standing(&stage, NOW).unwrap();
    assert_eq!(
        ledger.record_stage_receipt(premature).unwrap_err(),
        LedgerErrorV1::DispatchMissing
    );

    // One standing burns exactly once.
    assert_eq!(
        ledger.consume_standing(&stage, NOW).unwrap_err(),
        LedgerErrorV1::AlreadyConsumed
    );
}

#[test]
fn halt_and_resume_fence_in_flight_effects() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = ledger.propose_stage(proposal).unwrap();
    ledger.halt(digest("operator-halt")).unwrap();

    // Admission refuses while halted.
    assert_eq!(
        ledger
            .admit_stage(&stage, standing(&stage, "standing-1"), NOW)
            .unwrap_err(),
        LedgerErrorV1::Halted
    );
    ledger.resume().unwrap();

    // Consume, halt, and resume is blocked while the burn is in flight.
    ledger
        .admit_stage(&stage, standing(&stage, "standing-1"), NOW)
        .unwrap();
    ledger.consume_standing(&stage, NOW).unwrap();
    ledger.halt(digest("mid-flight-halt")).unwrap();
    let stage_id = stage.clone();
    assert_eq!(
        ledger.resume().unwrap_err(),
        LedgerErrorV1::ResumeBlocked { stage: stage_id }
    );
}

#[test]
fn standing_expiry_is_enforced_at_admission_and_consumption() {
    let mut ledger = CampaignLedgerV1::create(intent()).unwrap();
    let campaign = ledger.campaign().clone();
    let proposal = operator_proposal(&campaign, 1);
    let stage = ledger.propose_stage(proposal).unwrap();
    let expired = DocketStandingV1 {
        schema: DOCKET_STANDING_SCHEMA_V1.to_owned(),
        stage: stage.clone(),
        standing_digest: digest("standing-1"),
        expiry_unix: NOW, // expiry must be strictly later than now
    };
    assert_eq!(
        ledger.admit_stage(&stage, expired, NOW).unwrap_err(),
        LedgerErrorV1::StandingExpired
    );

    ledger
        .admit_stage(&stage, standing(&stage, "standing-1"), NOW)
        .unwrap();
    assert_eq!(
        ledger.consume_standing(&stage, EXPIRY).unwrap_err(),
        LedgerErrorV1::StandingExpired
    );

    let status = ledger.status(EXPIRY);
    assert_eq!(
        status.current_standing,
        ag_campaign::StandingStateV1::Expired
    );
    assert_eq!(
        status.candidate_freeze_qualification,
        ag_campaign::ProhibitionV1::ProhibitedPendingDistinctFutureAuthority
    );
    assert_eq!(
        status.human_authorization,
        digest("human-authorization-instrument")
    );
}

#[test]
fn tampered_event_log_refuses_replay() {
    let (ledger, _stage) = completed_campaign();
    let mut events = ledger.events().to_vec();
    // Rewrite history: drop the worker execution receipt. The verdict then
    // reviews an unexecuted stage and replay refuses.
    let receipt_index = events
        .iter()
        .position(|event| matches!(event, CampaignEventV1::StageReceiptRecorded { .. }))
        .unwrap();
    events.remove(receipt_index);
    assert!(CampaignLedgerV1::from_events(events).is_err());
}
