//! Hostile development tests for the frozen canonical governed-loop kernel.

#![allow(
    clippy::too_many_lines,
    reason = "hostile scenarios keep full setup and assertion chains visible"
)]

use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use uuid::Uuid;

const NOW: u64 = 10_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-loop-test/v1", label.as_bytes())
}

fn campaign() -> CampaignId {
    CampaignId::from_digest(digest("campaign"))
}

fn occurrence(value: u128) -> OccurrenceId {
    OccurrenceId::from_uuid(Uuid::from_u128(value))
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

#[test]
fn docket_issuance_refusal_identity_matches_frozen_cross_repository_vector() {
    let mut refusal = DocketIssuanceRefusalV1 {
        schema: "docket.governed-loop.issuance-refusal/v1".to_owned(),
        refusal: Digest::parse(&format!("sha256:{}", "00".repeat(32))).unwrap(),
        issuance: AgIssuanceRefV1::from_digest(
            Digest::parse(&format!("sha256:{}", "11".repeat(32))).unwrap(),
        ),
        campaign: CampaignId::from_digest(
            Digest::parse(&format!("sha256:{}", "22".repeat(32))).unwrap(),
        ),
        occurrence: occurrence(1),
        refusal_class: DocketIssuanceRefusalClassV1::StandingInvalid,
        reason_code: "standing_invalid".to_owned(),
        evidence: Digest::parse(&format!("sha256:{}", "33".repeat(32))).unwrap(),
        refused_at_unix_ms: 42,
    };
    refusal.refusal = refusal.derived_identity();
    assert_eq!(
        refusal.refusal.as_str(),
        "sha256:14e18c3d74be772ed6e72de25eb735fa26d5154c333a45aba0585f9a09306ce6"
    );
}

#[test]
fn shared_governed_wire_label_grammar_is_closed() {
    for accepted in [
        "repository-write/v1",
        "standing_invalid",
        "governed-checkpoint-invalid",
        "test.exact-work/v1",
        "a:b_c.d-e/f0",
    ] {
        assert!(governed_wire_label_is_canonical_v1(accepted), "{accepted}");
    }
    for refused in [
        "",
        "UPPER",
        "has space",
        "leading/slash/",
        "/absolute",
        "double//separator",
        "double--separator",
        "-leading-separator",
        "trailing-",
        "wild*card",
        "unicode-λ",
        "control\nlabel",
    ] {
        assert!(!governed_wire_label_is_canonical_v1(refused), "{refused}");
    }
    assert!(!governed_wire_label_is_canonical_v1(&"a".repeat(129)));
}

fn proposal(campaign: &CampaignId, work: &str) -> ExactWorkProposalV1 {
    let scope = CanonicalEffectScopeV1::new(
        "test-effect".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "fixtures/exact-work".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    ExactWorkProposalV1::new(
        campaign.clone(),
        digest("subject"),
        scope,
        "test.exact-work/v1".to_owned(),
        digest(work),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("proposal-nonclaim")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap()
}

#[derive(Clone)]
struct ObservationBoundary {
    preconditions: PreconditionBasisRefV1,
    status: ObservationStatusV1,
    substitute_occurrence: Option<OccurrenceId>,
    substitute_observation: Option<ObservationRefV1>,
    substitute_subject: Option<Digest>,
}

impl ObservationBoundary {
    fn current(preconditions: &str) -> Self {
        Self {
            preconditions: PreconditionBasisRefV1::from_digest(digest(preconditions)),
            status: ObservationStatusV1::Current,
            substitute_occurrence: None,
            substitute_observation: None,
            substitute_subject: None,
        }
    }
}

impl ObservationResolverV1 for ObservationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1> {
        let mut key = request.key.clone();
        if let Some(occurrence) = self.substitute_occurrence {
            key.occurrence = occurrence;
        }
        Ok(ObservationResolutionV1 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V1.to_owned(),
            key,
            observation: self
                .substitute_observation
                .clone()
                .unwrap_or_else(|| request.observation.clone()),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: self.preconditions.clone(),
            subject: self
                .substitute_subject
                .clone()
                .unwrap_or_else(|| request.subject.clone()),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

#[derive(Clone)]
struct StandingBoundary {
    status: StandingStatusV1,
    substitute_proposal: Option<ProposalRefV1>,
    substitute_occurrence: Option<OccurrenceId>,
}

impl StandingBoundary {
    fn current() -> Self {
        Self {
            status: StandingStatusV1::Current,
            substitute_proposal: None,
            substitute_occurrence: None,
        }
    }
}

impl StandingResolverV1 for StandingBoundary {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV1, ExternalBoundaryErrorV1> {
        let mut key = request.key.clone();
        if let Some(occurrence) = self.substitute_occurrence {
            key.occurrence = occurrence;
        }
        Ok(CurrentStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest("standing-resolution")),
            currentness: StandingCurrentnessRefV1::from_digest(digest("standing-current")),
            mandate: MandateRefV1::from_digest(digest("mandate")),
            key,
            observation: request.observation.clone(),
            proposal: self
                .substitute_proposal
                .clone()
                .unwrap_or_else(|| request.proposal.clone()),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

#[derive(Clone)]
struct Decider {
    disposition: AdmissionDispositionV1,
    substitute_proposal: Option<ProposalRefV1>,
}

impl Decider {
    fn admit() -> Self {
        Self {
            disposition: AdmissionDispositionV1::Admitted,
            substitute_proposal: None,
        }
    }
}

impl AdmissibilityDeciderV1 for Decider {
    fn decide_admissibility(
        &mut self,
        request: &AdmissibilityRequestV1<'_>,
    ) -> Result<AdmissionDecisionV1, ExternalBoundaryErrorV1> {
        Ok(AdmissionDecisionV1 {
            decision: AdmissionDecisionRefV1::from_digest(digest("decision")),
            key: request.standing.key.clone(),
            observation: request.observation.observation.clone(),
            proposal: self
                .substitute_proposal
                .clone()
                .unwrap_or_else(|| request.standing.proposal.clone()),
            standing_resolution: request.standing.resolution.clone(),
            disposition: self.disposition,
            policy_basis: digest("policy"),
        })
    }
}

fn initial_with(occurrence: OccurrenceId, residuals: ResidualSetV1) -> OccurrenceSnapshotV1 {
    GovernedLoopKernelV1::create_initial(
        campaign(),
        occurrence,
        ProgramBasisRefV1::from_digest(digest("program")),
        residuals,
        budget(),
    )
    .unwrap()
}

fn initial() -> OccurrenceSnapshotV1 {
    initial_with(occurrence(1), ResidualSetV1::default())
}

#[test]
fn proposal_nonclaims_and_expiry_are_identity_bound_and_fail_closed() {
    let base = proposal(&campaign(), "work");
    let changed_nonclaim = ExactWorkProposalV1::new(
        campaign(),
        base.subject().clone(),
        base.effect_scope().clone(),
        base.work_schema().to_owned(),
        base.work().clone(),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("different-nonclaim")],
            expires_at_unix_ms: base.expires_at_unix_ms(),
        },
        None,
    )
    .unwrap();
    let changed_expiry = ExactWorkProposalV1::new(
        campaign(),
        base.subject().clone(),
        base.effect_scope().clone(),
        base.work_schema().to_owned(),
        base.work().clone(),
        ProposalGovernanceTermsV1 {
            nonclaims: base.nonclaims().to_vec(),
            expires_at_unix_ms: base.expires_at_unix_ms() + 1,
        },
        None,
    )
    .unwrap();
    assert_ne!(base.reference(), changed_nonclaim.reference());
    assert_ne!(base.reference(), changed_expiry.reference());

    let spent = advance_to_spent(
        &initial(),
        base.clone(),
        ObservationRefV1::from_digest(digest("observation-proposal-contract")),
        &mut ObservationBoundary::current("preconditions"),
    );
    let issuance = spent.issuance().expect("authorization creates issuance");
    assert_eq!(issuance.nonclaims.as_slice(), base.nonclaims());
    assert_eq!(issuance.expires_at_unix_ms, base.expires_at_unix_ms());

    assert!(matches!(
        ExactWorkProposalV1::new(
            campaign(),
            base.subject().clone(),
            base.effect_scope().clone(),
            base.work_schema().to_owned(),
            base.work().clone(),
            ProposalGovernanceTermsV1 {
                nonclaims: Vec::new(),
                expires_at_unix_ms: NOW + 1,
            },
            None,
        ),
        Err(KernelErrorV1::Proposal(_))
    ));
    assert!(
        ExactWorkProposalV1::new(
            campaign(),
            base.subject().clone(),
            base.effect_scope().clone(),
            base.work_schema().to_owned(),
            base.work().clone(),
            ProposalGovernanceTermsV1 {
                nonclaims: base.nonclaims().to_vec(),
                expires_at_unix_ms: MAX_CANONICAL_JSON_INTEGER_V1,
            },
            None,
        )
        .is_ok()
    );
    assert!(matches!(
        ExactWorkProposalV1::new(
            campaign(),
            base.subject().clone(),
            base.effect_scope().clone(),
            base.work_schema().to_owned(),
            base.work().clone(),
            ProposalGovernanceTermsV1 {
                nonclaims: base.nonclaims().to_vec(),
                expires_at_unix_ms: MAX_CANONICAL_JSON_INTEGER_V1 + 1,
            },
            None,
        ),
        Err(KernelErrorV1::Proposal(_))
    ));
    assert!(matches!(
        ExactWorkProposalV1::new(
            campaign(),
            base.subject().clone(),
            base.effect_scope().clone(),
            base.work_schema().to_owned(),
            base.work().clone(),
            ProposalGovernanceTermsV1 {
                nonclaims: base.nonclaims().to_vec(),
                expires_at_unix_ms: u64::MAX,
            },
            None,
        ),
        Err(KernelErrorV1::Proposal(_))
    ));

    let expired = ExactWorkProposalV1::new(
        campaign(),
        base.subject().clone(),
        base.effect_scope().clone(),
        base.work_schema().to_owned(),
        base.work().clone(),
        ProposalGovernanceTermsV1 {
            nonclaims: base.nonclaims().to_vec(),
            expires_at_unix_ms: NOW,
        },
        None,
    )
    .unwrap();
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &initial(),
            ObservationRefV1::from_digest(digest("observation-expired")),
            expired,
            ProposalClassV1::Initial,
            &mut ObservationBoundary::current("preconditions"),
            NOW,
        ),
        Err(KernelErrorV1::Proposal("proposal expired"))
    ));
}

fn governed_checkpoint(diff_identity: Option<Digest>) -> GovernedRepairCheckpointV1 {
    GovernedRepairCheckpointV1 {
        repository: digest("checkpoint-repository"),
        commit: "1111111111111111111111111111111111111111".to_owned(),
        tree: "2222222222222222222222222222222222222222".to_owned(),
        diff_identity,
        content_manifest: digest("checkpoint-content-manifest"),
        docket_checkpoint: None,
    }
}

fn issuance_with_checkpoint(checkpoint: GovernedRepairCheckpointV1) -> AgIssuanceV2 {
    let exact_proposal = proposal(&campaign(), "checkpoint-wire")
        .with_governed_repair_checkpoint(checkpoint)
        .unwrap();
    advance_to_spent(
        &initial(),
        exact_proposal,
        ObservationRefV1::from_digest(digest("checkpoint-observation")),
        &mut ObservationBoundary::current("checkpoint-preconditions"),
    )
    .issuance()
    .unwrap()
    .clone()
}

#[test]
fn successor_issuance_checkpoint_has_one_exact_omission_and_required_manifest_law() {
    let absent = issuance_with_checkpoint(governed_checkpoint(None));
    let absent_document = JcsDocument::canonicalize(&absent).unwrap();
    let absent_json: serde_json::Value =
        serde_json::from_slice(absent_document.as_bytes()).unwrap();
    let checkpoint = absent_json["governed_repair_checkpoint"]
        .as_object()
        .unwrap();
    assert!(!checkpoint.contains_key("diff_identity"));
    assert!(checkpoint.contains_key("content_manifest"));
    assert_eq!(
        JcsDocument::from_canonical_bytes(absent_document.as_bytes())
            .unwrap()
            .decode::<AgIssuanceV2>()
            .unwrap(),
        absent
    );

    let mut explicit_null = absent_json.clone();
    explicit_null["governed_repair_checkpoint"]["diff_identity"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<AgIssuanceV2>(explicit_null).is_err());

    let mut missing_manifest = absent_json;
    missing_manifest["governed_repair_checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("content_manifest");
    assert!(serde_json::from_value::<AgIssuanceV2>(missing_manifest).is_err());

    let present = issuance_with_checkpoint(governed_checkpoint(Some(digest("checkpoint-diff"))));
    let present_json = serde_json::to_value(&present).unwrap();
    assert_eq!(
        present_json["governed_repair_checkpoint"]["diff_identity"],
        serde_json::Value::String(digest("checkpoint-diff").to_string())
    );
    assert_ne!(absent.issuance, present.issuance);
}

#[test]
fn scope_identity_is_the_domain_hash_of_the_exact_shared_jcs_record() {
    let scope = proposal(&campaign(), "scope-wire").effect_scope().clone();
    assert_eq!(
        scope.canonical_document().as_str(),
        r#"{"effect_class":"test-effect","resources":[{"operations":["modify"],"path":"fixtures/exact-work","resource":"repository"}],"schema":"ag.governed-loop.canonical-effect-scope/v1"}"#
    );
    assert_eq!(
        scope.digest(),
        Digest::hash_domain(
            CANONICAL_EFFECT_SCOPE_SCHEMA_V1,
            scope.canonical_document().as_bytes()
        )
    );
}

#[test]
fn scope_expansion_delta_is_strictly_additive_not_partially_redundant() {
    let original = proposal(&campaign(), "strict-delta").effect_scope().clone();
    let exact_new = CanonicalEffectScopeV1::new(
        original.effect_class().to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "fixtures/new-exact-work".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Create],
        }],
    )
    .unwrap();
    let requirement = |requested_delta: CanonicalEffectScopeV1| ScopeExpansionRequiredV1 {
        schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
        original_scope: original.clone(),
        original_scope_digest: original.digest(),
        requested_delta_digest: requested_delta.digest(),
        requested_delta,
        blocked_operation: BlockedEffectOperationV1 {
            resource: "repository".to_owned(),
            path: "fixtures/new-exact-work".to_owned(),
            operation: CanonicalEffectOperationV1::Create,
        },
        reason: digest("strict-delta-reason"),
        dependency_evidence: vec![digest("strict-delta-dependency")],
        limitations: vec![digest("strict-delta-limitation")],
        docket_outcome: None,
        no_unauthorized_effect_reported: true,
    };
    assert!(requirement(exact_new).validate().is_ok());

    let partially_redundant = CanonicalEffectScopeV1::new(
        original.effect_class().to_owned(),
        vec![
            CanonicalEffectResourceV1 {
                resource: "repository".to_owned(),
                path: "fixtures/exact-work".to_owned(),
                operations: vec![CanonicalEffectOperationV1::Modify],
            },
            CanonicalEffectResourceV1 {
                resource: "repository".to_owned(),
                path: "fixtures/new-exact-work".to_owned(),
                operations: vec![CanonicalEffectOperationV1::Create],
            },
        ],
    )
    .unwrap();
    assert!(matches!(
        requirement(partially_redundant).validate(),
        Err(KernelErrorV1::EffectScope(_))
    ));
}

fn advance_to_spent(
    start: &OccurrenceSnapshotV1,
    exact_proposal: ExactWorkProposalV1,
    observation_ref: ObservationRefV1,
    observation: &mut ObservationBoundary,
) -> OccurrenceSnapshotV1 {
    let proposed = GovernedLoopKernelV1::record_proposal(
        start,
        observation_ref,
        exact_proposal,
        if start.prior_occurrence().is_some() {
            ProposalClassV1::Retry
        } else {
            ProposalClassV1::Initial
        },
        observation,
        NOW,
    )
    .unwrap();
    let standing_required = GovernedLoopKernelV1::require_standing(&proposed).unwrap();
    let mut standing = StandingBoundary::current();
    let mut decider = Decider::admit();
    let admissible = GovernedLoopKernelV1::record_admissible(
        &standing_required,
        observation,
        &mut standing,
        &mut decider,
        None,
        NOW,
    )
    .unwrap();
    GovernedLoopKernelV1::consume_authorization(
        &admissible,
        observation,
        &mut standing,
        &mut decider,
        None,
        NOW,
    )
    .unwrap()
}

fn custody(spent: &OccurrenceSnapshotV1) -> DocketCustodyV1 {
    let issuance = spent.issuance().unwrap();
    DocketCustodyV1 {
        schema: DOCKET_CUSTODY_SCHEMA_V1.to_owned(),
        issuance: issuance.issuance.clone(),
        ag_spend: issuance.spend.clone(),
        execution_standing: DocketExecutionStandingRefV1::from_digest(digest("docket-standing")),
        standing_currentness: StandingCurrentnessRefV1::from_digest(digest("docket-currentness")),
        attempt: DocketAttemptRefV1::for_issuance(&issuance.issuance),
        executor_marker: ExecutorAttemptMarkerRefV1::from_digest(digest("executor-marker")),
        accepted_at_unix_ms: NOW + 1,
    }
}

fn settlement(dispatched: &OccurrenceSnapshotV1, outcome: KnownOutcomeV1) -> DocketSettlementV1 {
    let custody = dispatched.docket_custody().unwrap();
    let mut settlement = DocketSettlementV1 {
        schema: DOCKET_SETTLEMENT_SCHEMA_V1.to_owned(),
        settlement: SettlementRefV1::from_digest(digest(match outcome {
            KnownOutcomeV1::Success => "settlement-success",
            KnownOutcomeV1::Failure => "settlement-failure",
        })),
        issuance: custody.issuance.clone(),
        attempt: custody.attempt.clone(),
        executor_marker: custody.executor_marker.clone(),
        receipt: ReceiptRefV1::from_digest(digest("receipt")),
        outcome,
        cumulative_effect_journal_identity: Some(digest("cumulative-effect-journal")),
        settled_at_unix_ms: NOW + 2,
    };
    settlement.settlement = settlement.expected_reference().unwrap();
    settlement
}

fn settled() -> (OccurrenceSnapshotV1, ExactWorkProposalV1) {
    let initial = initial();
    let proposal = proposal(&campaign(), "work");
    let mut observation = ObservationBoundary::current("preconditions");
    let spent = advance_to_spent(
        &initial,
        proposal.clone(),
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    let exact_settlement = settlement(&dispatched, KnownOutcomeV1::Success);
    let mut changed_time = exact_settlement.clone();
    changed_time.settled_at_unix_ms += 1;
    assert!(GovernedLoopKernelV1::record_settlement(&dispatched, changed_time).is_err());
    let mut changed_journal = exact_settlement.clone();
    changed_journal.cumulative_effect_journal_identity = Some(digest("changed-journal"));
    assert!(GovernedLoopKernelV1::record_settlement(&dispatched, changed_journal).is_err());
    let settled = GovernedLoopKernelV1::record_settlement(&dispatched, exact_settlement).unwrap();
    (settled, proposal)
}

#[test]
fn normal_path_is_closed_and_one_shot() {
    let initial = initial();
    assert_eq!(
        initial.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    let exact_proposal = proposal(&campaign(), "work");
    let mut observation = ObservationBoundary::current("preconditions");
    let spent = advance_to_spent(
        &initial,
        exact_proposal,
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    assert_eq!(
        spent.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert!(spent.ag_spend().is_some());
    assert!(
        GovernedLoopKernelV1::consume_authorization(
            &spent,
            &mut observation,
            &mut StandingBoundary::current(),
            &mut Decider::admit(),
            None,
            NOW,
        )
        .is_err()
    );

    let mut docket_standing_substitution = custody(&spent);
    docket_standing_substitution.execution_standing = DocketExecutionStandingRefV1::from_digest(
        spent.ag_spend().unwrap().spend.as_digest().clone(),
    );
    assert!(
        GovernedLoopKernelV1::accept_docket_custody(&spent, docket_standing_substitution).is_err()
    );
    let mut executor_marker_substitution = custody(&spent);
    executor_marker_substitution.executor_marker = ExecutorAttemptMarkerRefV1::from_digest(
        executor_marker_substitution
            .execution_standing
            .as_digest()
            .clone(),
    );
    assert!(
        GovernedLoopKernelV1::accept_docket_custody(&spent, executor_marker_substitution).is_err()
    );

    let docket = custody(&spent);
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, docket.clone()).unwrap();
    assert_eq!(dispatched.program_counter(), ProgramCounterV1::Dispatched);
    assert_eq!(
        docket.attempt,
        DocketAttemptRefV1::for_issuance(&docket.issuance)
    );
    assert!(GovernedLoopKernelV1::accept_docket_custody(&dispatched, docket).is_err());

    let settled = GovernedLoopKernelV1::record_settlement(
        &dispatched,
        settlement(&dispatched, KnownOutcomeV1::Success),
    )
    .unwrap();
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert!(GovernedLoopKernelV1::accept_docket_custody(&settled, custody(&spent)).is_err());
    assert!(GovernedLoopKernelV1::require_standing(&settled).is_err());
}

#[test]
fn proposal_review_receipt_and_executor_output_have_no_transition_projection() {
    let initial = initial();
    let mut observation = ObservationBoundary::current("preconditions");
    let proposed = GovernedLoopKernelV1::record_proposal(
        &initial,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "work"),
        ProposalClassV1::Initial,
        &mut observation,
        NOW,
    )
    .unwrap();
    let fake_custody = DocketCustodyV1 {
        schema: DOCKET_CUSTODY_SCHEMA_V1.to_owned(),
        issuance: AgIssuanceRefV1::from_digest(digest("forged-issuance")),
        ag_spend: AgSpendRefV1::from_digest(digest("forged-spend")),
        execution_standing: DocketExecutionStandingRefV1::from_digest(digest("standing")),
        standing_currentness: StandingCurrentnessRefV1::from_digest(digest("currentness")),
        attempt: DocketAttemptRefV1::from_digest(digest("attempt")),
        executor_marker: ExecutorAttemptMarkerRefV1::from_digest(digest("marker")),
        accepted_at_unix_ms: NOW,
    };
    assert!(GovernedLoopKernelV1::accept_docket_custody(&proposed, fake_custody).is_err());
    let executor = ExecutorOutcomeV1 {
        attempt: DocketAttemptRefV1::from_digest(digest("attempt")),
        marker: ExecutorAttemptMarkerRefV1::from_digest(digest("marker")),
        receipt: ReceiptRefV1::from_digest(digest("receipt")),
        outcome: ExecutorOutcomeClassV1::Success,
    };
    // There is deliberately no kernel method accepting executor output.
    assert_eq!(executor.outcome, ExecutorOutcomeClassV1::Success);
    assert_eq!(
        proposed.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
}

#[test]
fn currentness_and_exact_binding_are_rechecked_before_spend() {
    let start = initial();
    let mut observation = ObservationBoundary::current("preconditions");
    let proposed = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "work"),
        ProposalClassV1::Initial,
        &mut observation,
        NOW,
    )
    .unwrap();
    let required = GovernedLoopKernelV1::require_standing(&proposed).unwrap();
    let mut standing = StandingBoundary::current();
    let mut decider = Decider::admit();
    let admissible = GovernedLoopKernelV1::record_admissible(
        &required,
        &mut observation,
        &mut standing,
        &mut decider,
        None,
        NOW,
    )
    .unwrap();

    standing.status = StandingStatusV1::Revoked;
    assert!(matches!(
        GovernedLoopKernelV1::consume_authorization(
            &admissible,
            &mut observation,
            &mut standing,
            &mut decider,
            None,
            NOW,
        ),
        Err(KernelErrorV1::StandingNotCurrent)
    ));
    standing = StandingBoundary::current();
    observation.status = ObservationStatusV1::Superseded;
    assert!(matches!(
        GovernedLoopKernelV1::consume_authorization(
            &admissible,
            &mut observation,
            &mut standing,
            &mut decider,
            None,
            NOW,
        ),
        Err(KernelErrorV1::ObservationNotCurrent)
    ));
}

#[test]
fn retry_is_a_distinct_occurrence_with_fresh_unchanged_preconditions() {
    let (settled, exact_proposal) = settled();
    let retry = GovernedLoopKernelV1::open_continuation(&settled, occurrence(2)).unwrap();
    assert_ne!(retry.key(), settled.key());
    assert_eq!(
        retry.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    let mut fresh = ObservationBoundary::current("preconditions");
    let proposed = GovernedLoopKernelV1::record_proposal(
        &retry,
        ObservationRefV1::from_digest(digest("observation-2")),
        exact_proposal.clone(),
        ProposalClassV1::Retry,
        &mut fresh,
        NOW,
    )
    .unwrap();
    assert_eq!(proposed.state().meta().budget().retries_used, 1);

    let retry_changed = GovernedLoopKernelV1::open_continuation(&settled, occurrence(3)).unwrap();
    let mut changed = ObservationBoundary::current("changed-preconditions");
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &retry_changed,
            ObservationRefV1::from_digest(digest("observation-3")),
            exact_proposal.clone(),
            ProposalClassV1::Retry,
            &mut changed,
            NOW,
        ),
        Err(KernelErrorV1::RetryPreconditionsChanged)
    ));
    let mut unchanged = ObservationBoundary::current("preconditions");
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &retry_changed,
            ObservationRefV1::from_digest(digest("observation-3b")),
            exact_proposal,
            ProposalClassV1::Successor,
            &mut unchanged,
            NOW,
        ),
        Err(KernelErrorV1::SuccessorProposalReused)
    ));
}

#[test]
fn exact_c1_repair_rejects_subset_extra_duplicate_and_substitution() {
    let findings = CanonicalFindingSetV1::new(vec![digest("f2"), digest("f1")]).unwrap();
    let controlling = C1RejectedReviewBasisV1 {
        review_receipt: digest("review"),
        review_session: digest("session"),
        reviewer: digest("reviewer"),
        history: digest("history"),
        findings: findings.clone(),
    };
    assert!(validate_exact_c1_repair(&controlling, &controlling).is_ok());

    let mut subset = controlling.clone();
    subset.findings = CanonicalFindingSetV1::new(vec![digest("f1")]).unwrap();
    assert_eq!(
        validate_exact_c1_repair(&subset, &controlling),
        Err(KernelErrorV1::AlteredFindingSet)
    );
    let mut extra = controlling.clone();
    extra.findings =
        CanonicalFindingSetV1::new(vec![digest("f1"), digest("f2"), digest("f3")]).unwrap();
    assert!(validate_exact_c1_repair(&extra, &controlling).is_err());
    assert!(CanonicalFindingSetV1::new(vec![digest("f1"), digest("f1")]).is_err());
    let mut wrong_session = controlling.clone();
    wrong_session.review_session = digest("other-session");
    assert!(validate_exact_c1_repair(&wrong_session, &controlling).is_err());
    let reordered = CanonicalFindingSetV1::new(vec![digest("f1"), digest("f2")]).unwrap();
    assert_eq!(reordered, findings);
}

#[test]
fn unknown_outcome_can_only_reconcile_or_halt_and_never_repeat() {
    let start = initial();
    let mut observation = ObservationBoundary::current("preconditions");
    let spent = advance_to_spent(
        &start,
        proposal(&campaign(), "work"),
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    let custody_record = dispatched.docket_custody().unwrap();
    let unknown = IndeterminateOutcomeV1 {
        issuance: custody_record.issuance.clone(),
        attempt: custody_record.attempt.clone(),
        reconciliation: ReconciliationRefV1::from_digest(digest("reconcile")),
        evidence: digest("unknown"),
    };
    let reconciling = GovernedLoopKernelV1::require_reconciliation(&dispatched, unknown).unwrap();
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert!(GovernedLoopKernelV1::accept_docket_custody(&reconciling, custody(&spent)).is_err());
    assert!(GovernedLoopKernelV1::open_continuation(&reconciling, occurrence(2)).is_err());
    let settled = GovernedLoopKernelV1::record_reconciled_settlement(
        &reconciling,
        settlement(&dispatched, KnownOutcomeV1::Failure),
    )
    .unwrap();
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
}

#[test]
fn restart_mapping_erases_authority_and_ambiguous_dispatch_reconciles() {
    let start = initial();
    assert_eq!(
        GovernedLoopKernelV1::recovery_requirement(&start),
        RecoveryRequirementV1::FreshObservation
    );
    let mut observation = ObservationBoundary::current("preconditions");
    let spent = advance_to_spent(
        &start,
        proposal(&campaign(), "work"),
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    assert_eq!(
        GovernedLoopKernelV1::recovery_requirement(&spent),
        RecoveryRequirementV1::ReconcileIssuance
    );
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    assert_eq!(
        GovernedLoopKernelV1::recovery_requirement(&dispatched),
        RecoveryRequirementV1::ReconcileAttempt
    );
    let recovered = GovernedLoopKernelV1::recover_dispatched(&dispatched).unwrap();
    assert_eq!(
        recovered.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert_eq!(recovered.ag_spend(), dispatched.ag_spend());
}

#[test]
fn typed_pre_spend_halt_reopens_only_for_nonauthorizing_scope_discovery() {
    let start = initial();
    let exact_proposal = proposal(&campaign(), "pre-spend-work");
    let mut observation = ObservationBoundary::current("pre-spend-preconditions");
    let proposed = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("pre-spend-observation")),
        exact_proposal,
        ProposalClassV1::Initial,
        &mut observation,
        NOW,
    )
    .unwrap();
    let halted = GovernedLoopKernelV1::halt_pre_spend_scope_insufficiency(
        &proposed,
        digest("pre-spend-diagnostic"),
        digest("pre-spend-idempotency"),
        NOW,
    )
    .unwrap();
    assert_eq!(
        GovernedLoopKernelV1::recovery_requirement(&halted),
        RecoveryRequirementV1::PreSpendScopeDiscovery
    );
    let bytes = JcsDocument::canonicalize(&halted).unwrap();
    let reopened: OccurrenceSnapshotV1 = JcsDocument::from_canonical_bytes(bytes.as_bytes())
        .unwrap()
        .decode()
        .unwrap();
    reopened.validate_integrity().unwrap();
    assert_eq!(reopened, halted);
    assert_eq!(
        GovernedLoopKernelV1::recovery_requirement(&reopened),
        RecoveryRequirementV1::PreSpendScopeDiscovery
    );
}

#[test]
fn completed_is_terminal_and_halted_is_effect_free() {
    let start = initial();
    let mut terminal = ObservationBoundary::current("terminal-preconditions");
    let completed = GovernedLoopKernelV1::complete_from_observation(
        &start,
        ObservationRefV1::from_digest(digest("terminal-observation")),
        &digest("terminal-subject"),
        TerminalWitnessRefV1::from_digest(digest("terminal-witness")),
        &mut terminal,
        NOW,
    )
    .unwrap();
    assert_eq!(completed.program_counter(), ProgramCounterV1::Completed);
    assert!(GovernedLoopKernelV1::open_continuation(&completed, occurrence(2)).is_err());
    assert!(
        GovernedLoopKernelV1::halt(
            &completed,
            HaltReasonRefV1::from_digest(digest("late-halt"))
        )
        .is_err()
    );

    let halted =
        GovernedLoopKernelV1::halt(&start, HaltReasonRefV1::from_digest(digest("halt"))).unwrap();
    assert!(GovernedLoopKernelV1::require_standing(&halted).is_err());
    assert!(
        GovernedLoopKernelV1::consume_authorization(
            &halted,
            &mut ObservationBoundary::current("preconditions"),
            &mut StandingBoundary::current(),
            &mut Decider::admit(),
            None,
            NOW,
        )
        .is_err()
    );
}

#[test]
fn occurrence_identity_is_independent_of_proposal_and_stage_content() {
    let same_proposal = proposal(&campaign(), "same-work");
    let first = initial_with(occurrence(1), ResidualSetV1::default());
    let second = initial_with(occurrence(2), ResidualSetV1::default());
    assert_ne!(first.key(), second.key());
    assert_eq!(same_proposal.reference(), same_proposal.reference());
    assert_ne!(first.state_digest(), second.state_digest());
    // Archaeological intent identity has no occurrence projection.
}
