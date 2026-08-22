//! Hostile development tests for the frozen canonical governed-loop kernel.

#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    reason = "hostile scenarios keep full setup and assertion chains visible"
)]

use std::collections::BTreeSet;

use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use uuid::Uuid;

const NOW: u64 = 10_000;
/// The resolver identity these tests configure the kernel to expect.
const OBSERVATION_RESOLVER_ID: &str = "test.observation-resolver/v1";
/// The standing resolver identity these tests configure the kernel to expect.
const STANDING_RESOLVER_ID: &str = "test.standing-resolver/v1";
/// Maximum accepted standing-answer lifetime in these tests.
const MAX_STANDING_TTL_MS: u64 = 60_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-loop-test/v1", label.as_bytes())
}

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

fn clean_basis() -> DecisionBasisV1 {
    decision_basis("condition.clean", "delivery.not_required")
}

fn changed_basis() -> DecisionBasisV1 {
    decision_basis("condition.condition_present", "delivery.qualified")
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

fn proposal(campaign: &CampaignId, work: &str) -> ExactWorkProposalV1 {
    ExactWorkProposalV1::new(
        campaign.clone(),
        digest("subject"),
        digest("scope"),
        "test.exact-work/v1".to_owned(),
        digest(work),
        None,
    )
    .unwrap()
}

/// Pinned byte-for-byte in Nightshift's authoring-context provenance module.
#[test]
fn proposal_reference_matches_nightshift_handoff_vector() {
    let exact = ExactWorkProposalV1::new(
        CampaignId::from_digest(Digest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap()),
        Digest::parse(&format!("sha256:{}", "b".repeat(64))).unwrap(),
        Digest::parse(&format!("sha256:{}", "c".repeat(64))).unwrap(),
        "test.exact-work/v1".to_owned(),
        Digest::parse(&format!("sha256:{}", "d".repeat(64))).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(
        exact.reference().as_str(),
        "sha256:101445d903d1c43207f5ab6bc44bd1b2b74c05d738d7afe464d22eff00704fe7"
    );
}

#[derive(Clone)]
struct ObservationBoundary {
    basis: DecisionBasisV1,
    status: ObservationStatusV1,
    substitute_occurrence: Option<OccurrenceId>,
    substitute_observation: Option<ObservationRefV1>,
    substitute_subject: Option<Digest>,
    substitute_schema: Option<String>,
    substitute_preconditions: Option<PreconditionBasisRefV1>,
    substitute_resolver_id: Option<String>,
}

impl ObservationBoundary {
    fn current(basis: DecisionBasisV1) -> Self {
        Self {
            basis,
            status: ObservationStatusV1::Current,
            substitute_occurrence: None,
            substitute_observation: None,
            substitute_subject: None,
            substitute_schema: None,
            substitute_preconditions: None,
            substitute_resolver_id: None,
        }
    }
}

impl ObservationResolverV1 for ObservationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV2, ExternalBoundaryErrorV1> {
        let mut key = request.key.clone();
        if let Some(occurrence) = self.substitute_occurrence {
            key.occurrence = occurrence;
        }
        Ok(ObservationResolutionV2 {
            schema: self
                .substitute_schema
                .clone()
                .unwrap_or_else(|| OBSERVATION_RESOLUTION_SCHEMA_V2.to_owned()),
            key,
            observation: self
                .substitute_observation
                .clone()
                .unwrap_or_else(|| request.observation.clone()),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: self.substitute_preconditions.clone().unwrap_or_else(|| {
                PreconditionBasisRefV1::from_digest(self.basis.decision_basis_digest().unwrap())
            }),
            basis: self.basis.clone(),
            resolver_id: self
                .substitute_resolver_id
                .clone()
                .unwrap_or_else(|| OBSERVATION_RESOLVER_ID.to_owned()),
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
    mandate: MandateRefV1,
    window_ms: u64,
    substitute_proposal: Option<ProposalRefV1>,
    substitute_occurrence: Option<OccurrenceId>,
    substitute_resolver_id: Option<String>,
    substitute_expires_unix_ms: Option<u64>,
}

impl StandingBoundary {
    fn current() -> Self {
        Self {
            status: StandingStatusV1::Current,
            mandate: MandateRefV1::from_digest(digest("mandate")),
            window_ms: 1_000,
            substitute_proposal: None,
            substitute_occurrence: None,
            substitute_resolver_id: None,
            substitute_expires_unix_ms: None,
        }
    }
}

impl StandingResolverV1 for StandingBoundary {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        let mut key = request.key.clone();
        if let Some(occurrence) = self.substitute_occurrence {
            key.occurrence = occurrence;
        }
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest(&format!(
                "standing-resolution-{}",
                self.mandate.as_str()
            ))),
            currentness: StandingCurrentnessRefV1::from_digest(digest("standing-current")),
            mandate: self.mandate.clone(),
            key,
            observation: request.observation.clone(),
            proposal: self
                .substitute_proposal
                .clone()
                .unwrap_or_else(|| request.proposal.clone()),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            resolver_id: self
                .substitute_resolver_id
                .clone()
                .unwrap_or_else(|| STANDING_RESOLVER_ID.to_owned()),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: self
                .substitute_expires_unix_ms
                .unwrap_or(request.now_unix_ms + self.window_ms),
        })
    }
}

#[derive(Clone)]
struct Decider {
    disposition: AdmissionDispositionV1,
    substitute_proposal: Option<ProposalRefV1>,
    calls: usize,
}

impl Decider {
    fn admit() -> Self {
        Self {
            disposition: AdmissionDispositionV1::Admitted,
            substitute_proposal: None,
            calls: 0,
        }
    }
}

impl AdmissibilityDeciderV1 for Decider {
    fn decide_admissibility(
        &mut self,
        request: &AdmissibilityRequestV1<'_>,
    ) -> Result<AdmissionDecisionV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
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

struct HumanVerifier;

impl HumanDispositionVerifierV1 for HumanVerifier {
    fn verify_human_disposition(
        &mut self,
        _request: &HumanDispositionVerificationRequestV1<'_>,
    ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1> {
        Ok(HumanVerificationRefV1::from_digest(digest(
            "human-verification",
        )))
    }
}

struct InterventionVerifier {
    calls: usize,
}

impl GovernedInterventionVerifierV1 for InterventionVerifier {
    fn verify_governed_intervention(
        &mut self,
        _request: &GovernedInterventionVerificationRequestV1<'_>,
    ) -> Result<GovernedInterventionVerificationRefV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
        Ok(GovernedInterventionVerificationRefV1::from_digest(digest(
            "intervention-verification",
        )))
    }
}

fn intervention_scope() -> GovernedInterventionAuthorityScopeV1 {
    HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("operator-principal")),
        mandate: MandateRefV1::from_digest(digest("operator-mandate")),
    }
}

fn intervention_request(
    current: &OccurrenceSnapshotV1,
    intervention: GovernedInterventionClassV1,
) -> GovernedInterventionRequestV1 {
    let scope = intervention_scope();
    GovernedInterventionRequestV1::new(
        scope.principal,
        scope.mandate,
        GovernedInterventionNonceRefV1::from_digest(digest("intervention-nonce")),
        current.key().campaign.clone(),
        current.key().occurrence,
        current.state_digest().clone(),
        intervention,
        NOW - 1,
        NOW + 1_000,
    )
    .unwrap()
}

fn initial_with(occurrence: OccurrenceId, residuals: ResidualSetV1) -> OccurrenceSnapshotV1 {
    GovernedLoopKernelV1::create_initial(
        campaign(),
        occurrence,
        ProgramBasisRefV1::from_digest(digest("program")),
        digest("work"),
        residuals,
        budget(),
    )
    .unwrap()
}

fn initial() -> OccurrenceSnapshotV1 {
    initial_with(occurrence(1), ResidualSetV1::default())
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
        OBSERVATION_RESOLVER_ID,
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
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();
    GovernedLoopKernelV1::consume_authorization(
        &admissible,
        observation,
        &mut standing,
        &mut decider,
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
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
    DocketSettlementV1 {
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
        settled_at_unix_ms: NOW + 2,
    }
}

fn settled() -> (OccurrenceSnapshotV1, ExactWorkProposalV1) {
    let initial = initial();
    let proposal = proposal(&campaign(), "work");
    let mut observation = ObservationBoundary::current(clean_basis());
    let spent = advance_to_spent(
        &initial,
        proposal.clone(),
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    let settled = GovernedLoopKernelV1::record_settlement(
        &dispatched,
        settlement(&dispatched, KnownOutcomeV1::Success),
    )
    .unwrap();
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
    let mut observation = ObservationBoundary::current(clean_basis());
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
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
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
    let mut observation = ObservationBoundary::current(clean_basis());
    let proposed = GovernedLoopKernelV1::record_proposal(
        &initial,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "work"),
        ProposalClassV1::Initial,
        &mut observation,
        OBSERVATION_RESOLVER_ID,
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
    let mut observation = ObservationBoundary::current(clean_basis());
    let proposed = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "work"),
        ProposalClassV1::Initial,
        &mut observation,
        OBSERVATION_RESOLVER_ID,
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
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
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
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
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
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::ObservationNotCurrent)
    ));
}

#[test]
fn retry_is_a_distinct_occurrence_with_fresh_unchanged_preconditions() {
    let (settled, exact_proposal) = settled();
    let retry =
        GovernedLoopKernelV1::open_continuation(&settled, occurrence(2), digest("work")).unwrap();
    assert_ne!(retry.key(), settled.key());
    assert_eq!(
        retry.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    let mut fresh = ObservationBoundary::current(clean_basis());
    let proposed = GovernedLoopKernelV1::record_proposal(
        &retry,
        ObservationRefV1::from_digest(digest("observation-2")),
        exact_proposal.clone(),
        ProposalClassV1::Retry,
        &mut fresh,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();
    assert_eq!(proposed.state().meta().budget().retries_used, 1);

    let retry_changed =
        GovernedLoopKernelV1::open_continuation(&settled, occurrence(3), digest("work")).unwrap();
    let mut changed = ObservationBoundary::current(changed_basis());
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &retry_changed,
            ObservationRefV1::from_digest(digest("observation-3")),
            exact_proposal.clone(),
            ProposalClassV1::Retry,
            &mut changed,
            OBSERVATION_RESOLVER_ID,
            NOW,
        ),
        Err(KernelErrorV1::RetryPreconditionsChanged)
    ));
    let mut unchanged = ObservationBoundary::current(clean_basis());
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &retry_changed,
            ObservationRefV1::from_digest(digest("observation-3b")),
            exact_proposal,
            ProposalClassV1::Successor,
            &mut unchanged,
            OBSERVATION_RESOLVER_ID,
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
    let mut observation = ObservationBoundary::current(clean_basis());
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
    assert!(
        GovernedLoopKernelV1::open_continuation(&reconciling, occurrence(2), digest("work"))
            .is_err()
    );
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
    let mut observation = ObservationBoundary::current(clean_basis());
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
fn residuals_are_exact_and_human_dispositions_never_dispatch() {
    let residual = ResidualObligationV1 {
        residual: ResidualIdV1::from_digest(digest("residual")),
        owner: digest("residual-owner"),
        subject: digest("residual-subject"),
        statement: digest("residual-statement"),
    };
    let start = initial_with(
        occurrence(1),
        ResidualSetV1::new(vec![residual.clone()]).unwrap(),
    );
    assert!(
        GovernedLoopKernelV1::complete_from_observation(
            &start,
            ObservationRefV1::from_digest(digest("terminal-observation")),
            &digest("subject"),
            TerminalWitnessRefV1::from_digest(digest("terminal")),
            &mut ObservationBoundary::current(clean_basis()),
            OBSERVATION_RESOLVER_ID,
            NOW,
        )
        .is_err()
    );
    let halted = GovernedLoopKernelV1::halt(
        &start,
        HaltReasonRefV1::from_digest(digest("human-required")),
    )
    .unwrap();
    let decision = HumanDecisionIdV1::from_digest(digest("discharge-decision"));
    let discharge = ExactResidualDischargeV1 {
        campaign: campaign(),
        occurrence: occurrence(1),
        program: ProgramBasisRefV1::from_digest(digest("program")),
        authority: ResidualAuthorityRefV1::from_digest(digest("residual-authority")),
        disposition: decision.clone(),
        before: vec![residual.residual.clone()],
        authorized: vec![residual.residual.clone()],
        closed: vec![residual.residual.clone()],
        after: Vec::new(),
    };
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ExactResidualDisposition(discharge),
        decision: decision.clone(),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("nonce-1")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let HumanDispositionEffectV1::Updated {
        snapshot: cleared, ..
    } = GovernedLoopKernelV1::apply_human_disposition(
        &halted,
        artifact.clone(),
        &scope,
        None,
        &mut ObservationBoundary::current(clean_basis()),
        OBSERVATION_RESOLVER_ID,
        &mut HumanVerifier,
        NOW,
    )
    .unwrap()
    else {
        panic!("residual disposition stays halted")
    };
    assert_eq!(cleared.program_counter(), ProgramCounterV1::Halted);
    assert!(cleared.state().meta().residuals().is_empty());
    assert!(
        GovernedLoopKernelV1::apply_human_disposition(
            &cleared,
            HumanDispositionV1 {
                halted_state_digest: cleared.state_digest().clone(),
                ..artifact
            },
            &scope,
            None,
            &mut ObservationBoundary::current(clean_basis()),
            OBSERVATION_RESOLVER_ID,
            &mut HumanVerifier,
            NOW,
        )
        .is_err()
    );

    let return_decision = HumanDecisionIdV1::from_digest(digest("return-decision"));
    let returned = GovernedLoopKernelV1::apply_human_disposition(
        &cleared,
        HumanDispositionV1 {
            schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
            campaign: campaign(),
            occurrence: occurrence(1),
            halted_state_digest: cleared.state_digest().clone(),
            disposition: HumanDispositionKindV1::ReturnToObservation,
            decision: return_decision,
            principal: scope.principal.clone(),
            mandate: scope.mandate.clone(),
            nonce: HumanNonceRefV1::from_digest(digest("nonce-2")),
            expires_at_unix_ms: NOW + 1_000,
        },
        &scope,
        Some(occurrence(2)),
        &mut ObservationBoundary::current(clean_basis()),
        OBSERVATION_RESOLVER_ID,
        &mut HumanVerifier,
        NOW,
    )
    .unwrap();
    let HumanDispositionEffectV1::OpenedOccurrence { successor, .. } = returned else {
        panic!("return opens a new occurrence")
    };
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(successor.ag_spend().is_none());
}

#[test]
fn completed_is_terminal_and_halted_is_effect_free() {
    let start = initial();
    let mut terminal = ObservationBoundary::current(clean_basis());
    let completed = GovernedLoopKernelV1::complete_from_observation(
        &start,
        ObservationRefV1::from_digest(digest("terminal-observation")),
        &digest("terminal-subject"),
        TerminalWitnessRefV1::from_digest(digest("terminal-witness")),
        &mut terminal,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();
    assert_eq!(completed.program_counter(), ProgramCounterV1::Completed);
    assert!(
        GovernedLoopKernelV1::open_continuation(&completed, occurrence(2), digest("work")).is_err()
    );
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
            &mut ObservationBoundary::current(clean_basis()),
            &mut StandingBoundary::current(),
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
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

#[test]
fn residual_disposition_refuses_wrong_basis_and_partial_accounting() {
    let residual = ResidualObligationV1 {
        residual: ResidualIdV1::from_digest(digest("residual-hostile")),
        owner: digest("residual-owner"),
        subject: digest("residual-subject"),
        statement: digest("residual-statement"),
    };
    let start = initial_with(
        occurrence(1),
        ResidualSetV1::new(vec![residual.clone()]).unwrap(),
    );
    let halted = GovernedLoopKernelV1::halt(
        &start,
        HaltReasonRefV1::from_digest(digest("residual-hostile-halt")),
    )
    .unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("residual-principal")),
        mandate: MandateRefV1::from_digest(digest("residual-mandate")),
    };
    let decision = HumanDecisionIdV1::from_digest(digest("residual-hostile-decision"));
    let exact = ExactResidualDischargeV1 {
        campaign: campaign(),
        occurrence: occurrence(1),
        program: ProgramBasisRefV1::from_digest(digest("program")),
        authority: ResidualAuthorityRefV1::from_digest(digest("residual-authority")),
        disposition: decision.clone(),
        before: vec![residual.residual.clone()],
        authorized: vec![residual.residual.clone()],
        closed: vec![residual.residual.clone()],
        after: Vec::new(),
    };
    let attacks = [
        ExactResidualDischargeV1 {
            campaign: CampaignId::from_digest(digest("wrong-campaign")),
            ..exact.clone()
        },
        ExactResidualDischargeV1 {
            occurrence: occurrence(9),
            ..exact.clone()
        },
        ExactResidualDischargeV1 {
            program: ProgramBasisRefV1::from_digest(digest("wrong-program")),
            ..exact.clone()
        },
        ExactResidualDischargeV1 {
            before: Vec::new(),
            ..exact.clone()
        },
        ExactResidualDischargeV1 {
            authorized: vec![ResidualIdV1::from_digest(digest("wrong-residual"))],
            ..exact
        },
    ];
    for (index, discharge) in attacks.into_iter().enumerate() {
        let artifact = HumanDispositionV1 {
            schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
            campaign: campaign(),
            occurrence: occurrence(1),
            halted_state_digest: halted.state_digest().clone(),
            disposition: HumanDispositionKindV1::ExactResidualDisposition(discharge),
            decision: decision.clone(),
            principal: scope.principal.clone(),
            mandate: scope.mandate.clone(),
            nonce: HumanNonceRefV1::from_digest(digest(&format!("residual-hostile-{index}"))),
            expires_at_unix_ms: NOW + 1_000,
        };
        assert!(matches!(
            GovernedLoopKernelV1::apply_human_disposition(
                &halted,
                artifact,
                &scope,
                None,
                &mut ObservationBoundary::current(clean_basis()),
                OBSERVATION_RESOLVER_ID,
                &mut HumanVerifier,
                NOW,
            ),
            Err(KernelErrorV1::ResidualAccounting)
        ));
        assert_eq!(
            halted.state().meta().residuals().as_slice(),
            std::slice::from_ref(&residual)
        );
    }
}

#[test]
fn program_replacement_is_authority_empty_and_unresolved_attempt_blocks_resume_or_termination() {
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let start = initial();
    let halted = GovernedLoopKernelV1::halt(
        &start,
        HaltReasonRefV1::from_digest(digest("replace-program")),
    )
    .unwrap();
    let replaced_program = ProgramBasisRefV1::from_digest(digest("replacement-program"));
    let replacement = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ReplaceProgram(replaced_program.clone()),
        decision: HumanDecisionIdV1::from_digest(digest("replace-decision")),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("replace-nonce")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let HumanDispositionEffectV1::OpenedOccurrence { successor, .. } =
        GovernedLoopKernelV1::apply_human_disposition(
            &halted,
            replacement,
            &scope,
            Some(occurrence(2)),
            &mut ObservationBoundary::current(clean_basis()),
            OBSERVATION_RESOLVER_ID,
            &mut HumanVerifier,
            NOW,
        )
        .unwrap()
    else {
        panic!("replacement must open a distinct observation boundary")
    };
    assert_eq!(successor.key().occurrence, occurrence(2));
    assert_eq!(successor.state().meta().program(), &replaced_program);
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(successor.ag_spend().is_none());
    assert!(successor.docket_custody().is_none());

    let mut observation = ObservationBoundary::current(clean_basis());
    let spent = advance_to_spent(
        &start,
        proposal(&campaign(), "work"),
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    let custody_record = dispatched.docket_custody().unwrap();
    let reconciling = GovernedLoopKernelV1::require_reconciliation(
        &dispatched,
        IndeterminateOutcomeV1 {
            issuance: custody_record.issuance.clone(),
            attempt: custody_record.attempt.clone(),
            reconciliation: ReconciliationRefV1::from_digest(digest("unresolved-reconcile")),
            evidence: digest("unresolved-evidence"),
        },
    )
    .unwrap();
    let unresolved = GovernedLoopKernelV1::halt(
        &reconciling,
        HaltReasonRefV1::from_digest(digest("unresolved-halt")),
    )
    .unwrap();
    for (index, disposition) in [
        HumanDispositionKindV1::ReturnToObservation,
        HumanDispositionKindV1::ReplaceProgram(ProgramBasisRefV1::from_digest(digest(
            "other-program",
        ))),
        HumanDispositionKindV1::Terminate {
            observation: ObservationRefV1::from_digest(digest("terminal-observation")),
            subject: digest("terminal-subject"),
            terminal_witness: TerminalWitnessRefV1::from_digest(digest("terminal-witness")),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let artifact = HumanDispositionV1 {
            schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
            campaign: campaign(),
            occurrence: occurrence(1),
            halted_state_digest: unresolved.state_digest().clone(),
            disposition,
            decision: HumanDecisionIdV1::from_digest(digest(&format!(
                "unresolved-decision-{index}"
            ))),
            principal: scope.principal.clone(),
            mandate: scope.mandate.clone(),
            nonce: HumanNonceRefV1::from_digest(digest(&format!("unresolved-nonce-{index}"))),
            expires_at_unix_ms: NOW + 1_000,
        };
        assert!(matches!(
            GovernedLoopKernelV1::apply_human_disposition(
                &unresolved,
                artifact,
                &scope,
                if index < 2 {
                    Some(occurrence(10 + index as u128))
                } else {
                    None
                },
                &mut ObservationBoundary::current(clean_basis()),
                OBSERVATION_RESOLVER_ID,
                &mut HumanVerifier,
                NOW,
            ),
            Err(KernelErrorV1::UnresolvedAttempt)
        ));
    }
}

#[test]
fn v2_resolution_requires_the_basis_digest_to_match_the_pinned_ref() {
    // The structured basis is the semantics; `normalized_preconditions` is its
    // canonical digest. A resolver that returns a valid basis whose digest
    // does not equal the pinned ref must fail closed before any status is
    // consumed.
    let start = initial();
    let mut mismatched = ObservationBoundary::current(clean_basis());
    mismatched.substitute_preconditions =
        Some(PreconditionBasisRefV1::from_digest(digest("foreign-basis")));
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &start,
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal(&campaign(), "work"),
            ProposalClassV1::Initial,
            &mut mismatched,
            OBSERVATION_RESOLVER_ID,
            NOW,
        ),
        Err(KernelErrorV1::BindingMismatch("precondition basis"))
    ));
    assert_eq!(
        start.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
}

#[test]
fn v2_resolution_rejects_a_malformed_or_foreign_rule_basis() {
    // In-process resolvers can construct a basis without going through the
    // validating wire parser, so the kernel re-validates the semantic content
    // itself.
    let start = initial();
    let mut unknown_atom = ObservationBoundary::current(DecisionBasisV1 {
        atoms: BTreeSet::from(["condition.clean".to_owned(), "delivery.unknown".to_owned()]),
        ..clean_basis()
    });
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &start,
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal(&campaign(), "work"),
            ProposalClassV1::Initial,
            &mut unknown_atom,
            OBSERVATION_RESOLVER_ID,
            NOW,
        ),
        Err(KernelErrorV1::ForeignSchema("decision basis"))
    ));

    let mut wrong_rule = ObservationBoundary::current(DecisionBasisV1 {
        rule: DecisionBasisRuleV1 {
            version: "2".to_owned(),
            ..clean_basis().rule
        },
        ..clean_basis()
    });
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &start,
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal(&campaign(), "work"),
            ProposalClassV1::Initial,
            &mut wrong_rule,
            OBSERVATION_RESOLVER_ID,
            NOW,
        ),
        Err(KernelErrorV1::ForeignSchema("decision basis"))
    ));
}

#[test]
fn v2_resolution_rejects_a_foreign_or_unconfigured_resolver_identity() {
    let start = initial();
    let mut foreign = ObservationBoundary::current(clean_basis());
    foreign.substitute_resolver_id = Some("test.other-resolver/v9".to_owned());
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &start,
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal(&campaign(), "work"),
            ProposalClassV1::Initial,
            &mut foreign,
            OBSERVATION_RESOLVER_ID,
            NOW,
        ),
        Err(KernelErrorV1::BindingMismatch(
            "observation resolver identity"
        ))
    ));

    // An empty configured expectation is a configuration failure, not an
    // identity match.
    let mut honest = ObservationBoundary::current(clean_basis());
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &start,
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal(&campaign(), "work"),
            ProposalClassV1::Initial,
            &mut honest,
            "",
            NOW,
        ),
        Err(KernelErrorV1::BindingMismatch(
            "observation resolver identity"
        ))
    ));
}

#[test]
fn legacy_v1_resolution_is_not_accepted_as_v2() {
    // A response naming the retired v1 schema is refused at the kernel.
    let start = initial();
    let mut legacy = ObservationBoundary::current(clean_basis());
    legacy.substitute_schema = Some("ag.governed-loop.observation-resolution/v1".to_owned());
    assert!(matches!(
        GovernedLoopKernelV1::record_proposal(
            &start,
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal(&campaign(), "work"),
            ProposalClassV1::Initial,
            &mut legacy,
            OBSERVATION_RESOLVER_ID,
            NOW,
        ),
        Err(KernelErrorV1::ForeignSchema("observation resolution"))
    ));

    // A v1-shaped wire document (no `basis`, no `resolver_id`) cannot even
    // parse as a v2 resolution.
    let mut resolver = ObservationBoundary::current(clean_basis());
    let request = ObservationResolutionRequestV1 {
        key: start.key(),
        observation: &ObservationRefV1::from_digest(digest("observation-1")),
        subject: &digest("subject"),
        now_unix_ms: NOW,
    };
    let resolution = resolver.resolve_observation(&request).unwrap();
    let mut wire = serde_json::to_value(&resolution).unwrap();
    let object = wire.as_object_mut().unwrap();
    object.remove("basis");
    object.remove("resolver_id");
    object.insert(
        "schema".to_owned(),
        serde_json::Value::String("ag.governed-loop.observation-resolution/v1".to_owned()),
    );
    assert!(serde_json::from_value::<ObservationResolutionV2>(wire).is_err());
}

#[test]
fn a_changed_basis_between_record_and_decide_keeps_the_proposal_unjudged() {
    // The proposal pins exactly one basis digest at record time. A later
    // resolution carrying different semantic content (and therefore a
    // different digest) cannot refresh it; the existing currentness refusal
    // applies and no state advances.
    let start = initial();
    let mut observation = ObservationBoundary::current(clean_basis());
    let proposed = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "work"),
        ProposalClassV1::Initial,
        &mut observation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();
    let required = GovernedLoopKernelV1::require_standing(&proposed).unwrap();

    observation.basis = changed_basis();
    assert!(matches!(
        GovernedLoopKernelV1::record_admissible(
            &required,
            &mut observation,
            &mut StandingBoundary::current(),
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::ObservationNotCurrent)
    ));
    assert_eq!(
        required.program_counter(),
        ProgramCounterV1::StandingRequired
    );
}

#[test]
fn a_negative_observation_status_never_reaches_the_admissibility_decider() {
    // The v2 wire requires every resolution to carry a syntactically valid
    // basis, so a negative resolver answer still contains atoms. Those atoms
    // are wire filler: evidence health must fail before the catalog decider
    // is consulted, and the decider must never see them.
    let start = initial();
    let mut observation = ObservationBoundary::current(clean_basis());
    let proposed = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "work"),
        ProposalClassV1::Initial,
        &mut observation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();
    let required = GovernedLoopKernelV1::require_standing(&proposed).unwrap();

    for status in [
        ObservationStatusV1::Stale,
        ObservationStatusV1::Superseded,
        ObservationStatusV1::Absent,
    ] {
        observation.status = status;
        let mut decider = Decider::admit();
        assert!(matches!(
            GovernedLoopKernelV1::record_admissible(
                &required,
                &mut observation,
                &mut StandingBoundary::current(),
                &mut decider,
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW,
            ),
            Err(KernelErrorV1::ObservationNotCurrent)
        ));
        assert_eq!(
            decider.calls, 0,
            "decider must not run for {status:?} observations"
        );
    }
    observation.status = ObservationStatusV1::Contradictory;
    let mut decider = Decider::admit();
    assert!(matches!(
        GovernedLoopKernelV1::record_admissible(
            &required,
            &mut observation,
            &mut StandingBoundary::current(),
            &mut decider,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::ObservationContradiction)
    ));
    assert_eq!(decider.calls, 0);
    assert_eq!(
        required.program_counter(),
        ProgramCounterV1::StandingRequired
    );
}

/// One occurrence holding a recorded proposal at the standing-required
/// boundary, plus its observation boundary fixture.
fn standing_required() -> (OccurrenceSnapshotV1, ObservationBoundary) {
    let start = initial();
    let mut observation = ObservationBoundary::current(clean_basis());
    let proposed = GovernedLoopKernelV1::record_proposal(
        &start,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "work"),
        ProposalClassV1::Initial,
        &mut observation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap();
    let required = GovernedLoopKernelV1::require_standing(&proposed).unwrap();
    (required, observation)
}

#[test]
fn standing_resolver_identity_is_checked_and_never_wildcard() {
    let (required, mut observation) = standing_required();
    let mut foreign = StandingBoundary::current();
    foreign.substitute_resolver_id = Some("test.other-standing-resolver/v9".to_owned());
    assert!(matches!(
        GovernedLoopKernelV1::record_admissible(
            &required,
            &mut observation,
            &mut foreign,
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::BindingMismatch("standing resolver identity"))
    ));

    // An empty configured expectation is a configuration failure, never a
    // wildcard match.
    let mut honest = StandingBoundary::current();
    assert!(matches!(
        GovernedLoopKernelV1::record_admissible(
            &required,
            &mut observation,
            &mut honest,
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            "",
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::BindingMismatch("standing resolver identity"))
    ));
    assert_eq!(
        required.program_counter(),
        ProgramCounterV1::StandingRequired
    );
}

#[test]
fn standing_answer_window_is_capped_by_the_configured_maximum() {
    // The fixture answers with a 1000 ms window. The cap is inclusive:
    // window == max is accepted, max - 1 refuses, and a reversed window
    // cannot wrap through checked subtraction.
    let (required, mut observation) = standing_required();
    let mut standing = StandingBoundary::current();
    GovernedLoopKernelV1::record_admissible(
        &required,
        &mut observation,
        &mut standing,
        &mut Decider::admit(),
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        1_000,
        NOW,
    )
    .unwrap();

    let mut standing = StandingBoundary::current();
    assert!(matches!(
        GovernedLoopKernelV1::record_admissible(
            &required,
            &mut observation,
            &mut standing,
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            999,
            NOW,
        ),
        Err(KernelErrorV1::StandingNotCurrent)
    ));

    let mut reversed = StandingBoundary::current();
    reversed.substitute_expires_unix_ms = Some(NOW - 1);
    assert!(matches!(
        GovernedLoopKernelV1::record_admissible(
            &required,
            &mut observation,
            &mut reversed,
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::StandingNotCurrent)
    ));
    assert_eq!(
        required.program_counter(),
        ProgramCounterV1::StandingRequired
    );
}

#[test]
fn standing_is_present_tense_and_may_recover_for_the_same_proposal() {
    // T25: standing is present-tense governance state, not proposal-pinned
    // evidence. Absent standing blocks admission; a later Current answer
    // admits the same unchanged proposal and the spend then succeeds.
    let (required, mut observation) = standing_required();
    let mut standing = StandingBoundary::current();
    standing.status = StandingStatusV1::Absent;
    assert!(matches!(
        GovernedLoopKernelV1::record_admissible(
            &required,
            &mut observation,
            &mut standing,
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::StandingAbsent)
    ));
    assert_eq!(
        required.program_counter(),
        ProgramCounterV1::StandingRequired
    );

    standing.status = StandingStatusV1::Current;
    let admissible = GovernedLoopKernelV1::record_admissible(
        &required,
        &mut observation,
        &mut standing,
        &mut Decider::admit(),
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();
    let spent = GovernedLoopKernelV1::consume_authorization(
        &admissible,
        &mut observation,
        &mut standing,
        &mut Decider::admit(),
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();
    assert!(spent.ag_spend().is_some());
}

#[test]
fn mandate_supersession_blocks_spend_and_a_new_mandate_spends_with_its_own_provenance() {
    // T26: a superseded mandate cannot spend; a fresh Current answer under a
    // new mandate spends with provenance naming the new standing resolution
    // and mandate.
    let (required, mut observation) = standing_required();
    let mut standing = StandingBoundary::current();
    let admissible = GovernedLoopKernelV1::record_admissible(
        &required,
        &mut observation,
        &mut standing,
        &mut Decider::admit(),
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();

    standing.status = StandingStatusV1::Superseded;
    assert!(matches!(
        GovernedLoopKernelV1::consume_authorization(
            &admissible,
            &mut observation,
            &mut standing,
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::StandingNotCurrent)
    ));
    assert_eq!(
        admissible.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );

    standing.status = StandingStatusV1::Current;
    standing.mandate = MandateRefV1::from_digest(digest("mandate-m2"));
    let spent = GovernedLoopKernelV1::consume_authorization(
        &admissible,
        &mut observation,
        &mut standing,
        &mut Decider::admit(),
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();
    let expected_resolution = StandingResolutionRefV1::from_digest(digest(&format!(
        "standing-resolution-{}",
        digest("mandate-m2").as_str()
    )));
    assert_eq!(
        spent.admission_decision().unwrap().standing_resolution,
        expected_resolution
    );
    assert_eq!(
        *spent.issuance().unwrap().mandate.as_digest(),
        digest("mandate-m2")
    );
}

#[test]
fn the_designated_standing_resolver_remains_a_trusted_authority_boundary() {
    // ENVIRONMENTAL TRUST BOUNDARY, pinned deliberately: a well-formed
    // answer from the configured resolver — correct identity, echoes, and
    // window, Current status, arbitrary opaque mandate/currentness content —
    // is accepted. Kernel binding proves the answer's shape and provenance;
    // it cannot prove the external governance claim true.
    let (required, mut observation) = standing_required();
    let mut standing = StandingBoundary::current();
    standing.mandate = MandateRefV1::from_digest(digest("arbitrary-opaque-mandate"));
    GovernedLoopKernelV1::record_admissible(
        &required,
        &mut observation,
        &mut standing,
        &mut Decider::admit(),
        None,
        OBSERVATION_RESOLVER_ID,
        STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS,
        NOW,
    )
    .unwrap();
}

#[test]
fn standing_alone_cannot_mint_authority() {
    // A Current standing answer is a revocable prerequisite, not authority:
    // with no proposal path there is nothing to spend, and no issuance can
    // exist.
    let start = initial();
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    assert!(matches!(
        GovernedLoopKernelV1::require_standing(&start),
        Err(KernelErrorV1::IllegalTransition { .. })
    ));
    assert!(matches!(
        GovernedLoopKernelV1::consume_authorization(
            &start,
            &mut observation,
            &mut standing,
            &mut Decider::admit(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW,
        ),
        Err(KernelErrorV1::IllegalTransition { .. })
    ));
    assert!(start.ag_spend().is_none());
    assert!(start.issuance().is_none());
}

#[test]
fn record_proposal_rejects_work_other_than_the_bound_expected_work() {
    // The occurrence was opened to govern digest("work"); an otherwise valid
    // proposal naming different executable work is an integrity failure, not
    // a policy refusal.
    let initial = initial();
    let mut observation = ObservationBoundary::current(clean_basis());
    let error = GovernedLoopKernelV1::record_proposal(
        &initial,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "substituted-work"),
        ProposalClassV1::Initial,
        &mut observation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        KernelErrorV1::BindingMismatch("prepared exact work")
    ));
    assert_eq!(
        initial.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
}

#[test]
fn work_binding_fails_before_any_observation_resolution() {
    // A resolver that can never answer proves the binding check precedes any
    // external consultation: the failure is the binding error, not the
    // resolver's unavailability.
    struct UnavailableObservation;
    impl ObservationResolverV1 for UnavailableObservation {
        fn resolve_observation(
            &mut self,
            _: &ObservationResolutionRequestV1<'_>,
        ) -> Result<ObservationResolutionV2, ExternalBoundaryErrorV1> {
            Err(ExternalBoundaryErrorV1::Unavailable {
                code: "observation-resolver-unavailable".to_owned(),
            })
        }
    }
    let initial = initial();
    let error = GovernedLoopKernelV1::record_proposal(
        &initial,
        ObservationRefV1::from_digest(digest("observation-1")),
        proposal(&campaign(), "substituted-work"),
        ProposalClassV1::Initial,
        &mut UnavailableObservation,
        OBSERVATION_RESOLVER_ID,
        NOW,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        KernelErrorV1::BindingMismatch("prepared exact work")
    ));
}

#[test]
fn intervention_request_is_content_bound_and_authentication_is_not_authority() {
    let current = initial();
    let request = intervention_request(
        &current,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("read-only-probe"),
            evidence: vec![digest("probe-evidence")],
        },
    );
    let mut substituted = request.clone();
    substituted.occurrence = occurrence(99);
    assert!(matches!(
        substituted.validate_integrity(),
        Err(KernelErrorV1::Intervention("request digest mismatch"))
    ));
    // Recomputing the outer request identity cannot hide the changed target:
    // the exact current occurrence/state applicability check still refuses.
    substituted.request = substituted.derived_request_id();
    let mut verifier = InterventionVerifier { calls: 0 };
    let verified = GovernedLoopKernelV1::verify_governed_intervention(
        substituted,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    assert_eq!(verifier.calls, 1);
    assert!(matches!(
        GovernedLoopKernelV1::apply_verified_governed_intervention(&current, verified),
        Err(KernelErrorV1::Intervention("wrong occurrence"))
    ));
    assert!(current.ag_spend().is_none());
    assert!(current.issuance().is_none());
    assert!(current.docket_custody().is_none());
}

#[test]
fn probe_halt_and_successor_requests_use_only_existing_authority_empty_laws() {
    let start = initial();
    let mut verifier = InterventionVerifier { calls: 0 };
    let probe = intervention_request(
        &start,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("probe-work"),
            evidence: vec![],
        },
    );
    let verified = GovernedLoopKernelV1::verify_governed_intervention(
        probe,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    let GovernedInterventionEffectV1::Transition { successor, .. } =
        GovernedLoopKernelV1::apply_verified_governed_intervention(&start, verified).unwrap()
    else {
        panic!("probe cannot become reconciliation");
    };
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert_eq!(successor.state().meta().budget().probes_used, 1);
    assert!(successor.ag_spend().is_none());

    // Exact replay targets the predecessor state and cannot consume budget twice.
    let replay = intervention_request(
        &start,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("probe-work-2"),
            evidence: vec![],
        },
    );
    let replay = GovernedLoopKernelV1::verify_governed_intervention(
        replay,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        GovernedLoopKernelV1::apply_verified_governed_intervention(&successor, replay),
        Err(KernelErrorV1::Intervention("stale target state"))
    ));

    let halt = intervention_request(
        &successor,
        GovernedInterventionClassV1::HaltContinuation {
            reason: HaltReasonRefV1::from_digest(digest("operator-halt")),
        },
    );
    let halt = GovernedLoopKernelV1::verify_governed_intervention(
        halt,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    let GovernedInterventionEffectV1::Transition {
        successor: halted, ..
    } = GovernedLoopKernelV1::apply_verified_governed_intervention(&successor, halt).unwrap()
    else {
        panic!("halt cannot become reconciliation");
    };
    assert_eq!(halted.program_counter(), ProgramCounterV1::Halted);
    assert!(halted.ag_spend().is_none());

    let (settled, _) = settled();
    let open = intervention_request(
        &settled,
        GovernedInterventionClassV1::OpenSuccessor {
            successor_occurrence: occurrence(20),
            exact_work: digest("successor-work"),
        },
    );
    let open = GovernedLoopKernelV1::verify_governed_intervention(
        open,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    let GovernedInterventionEffectV1::Transition { successor, .. } =
        GovernedLoopKernelV1::apply_verified_governed_intervention(&settled, open).unwrap()
    else {
        panic!("successor cannot become reconciliation");
    };
    assert_eq!(successor.key().occurrence, occurrence(20));
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(successor.proposal().is_none());
    assert!(successor.ag_spend().is_none());
}

#[test]
fn reconciliation_intervention_is_exact_read_only_and_never_dispatches() {
    let start = initial();
    let mut observation = ObservationBoundary::current(clean_basis());
    let spent = advance_to_spent(
        &start,
        proposal(&campaign(), "work"),
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    let dispatched = GovernedLoopKernelV1::accept_docket_custody(&spent, custody(&spent)).unwrap();
    let custody = dispatched.docket_custody().unwrap().clone();
    let reconciling = GovernedLoopKernelV1::require_reconciliation(
        &dispatched,
        IndeterminateOutcomeV1 {
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            reconciliation: ReconciliationRefV1::from_digest(digest("reconcile")),
            evidence: digest("unknown"),
        },
    )
    .unwrap();
    let request = intervention_request(
        &reconciling,
        GovernedInterventionClassV1::ReconcileAttempt {
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            evidence: vec![digest("manual-observation")],
        },
    );
    let mut verifier = InterventionVerifier { calls: 0 };
    let verified = GovernedLoopKernelV1::verify_governed_intervention(
        request,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        GovernedLoopKernelV1::apply_verified_governed_intervention(&reconciling, verified),
        Ok(GovernedInterventionEffectV1::Reconcile(_))
    ));
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );

    let wrong = intervention_request(
        &reconciling,
        GovernedInterventionClassV1::ReconcileAttempt {
            issuance: custody.issuance,
            attempt: DocketAttemptRefV1::from_digest(digest("substituted-attempt")),
            evidence: vec![],
        },
    );
    let wrong = GovernedLoopKernelV1::verify_governed_intervention(
        wrong,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        GovernedLoopKernelV1::apply_verified_governed_intervention(&reconciling, wrong),
        Err(KernelErrorV1::Intervention("wrong attempt"))
    ));
}

#[test]
fn authentication_alone_never_satisfies_standing_or_authorization() {
    let start = initial();
    let request = intervention_request(
        &start,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("probe"),
            evidence: vec![],
        },
    );
    let mut verifier = InterventionVerifier { calls: 0 };
    let verified = GovernedLoopKernelV1::verify_governed_intervention(
        request,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    let GovernedInterventionEffectV1::Transition { successor, .. } =
        GovernedLoopKernelV1::apply_verified_governed_intervention(&start, verified).unwrap()
    else {
        panic!("wrong effect");
    };
    assert!(successor.proposal().is_none());
    assert!(successor.standing_resolution().is_none());
    assert!(successor.ag_spend().is_none());
}

#[test]
fn malformed_expired_and_wrong_scope_interventions_fail_before_applicability() {
    let current = initial();
    let mut unsorted = intervention_request(
        &current,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("probe"),
            evidence: vec![],
        },
    );
    // The helper's constructor correctly rejects noncanonical evidence; build
    // the attack from a valid record and then rebind its outer identity.
    let mut noncanonical_evidence = vec![digest("z-evidence"), digest("a-evidence")];
    noncanonical_evidence.sort();
    noncanonical_evidence.reverse();
    unsorted.intervention = GovernedInterventionClassV1::RequestProbe {
        exact_probe_work: digest("probe"),
        evidence: noncanonical_evidence,
    };
    unsorted.request = unsorted.derived_request_id();
    assert!(matches!(
        unsorted.validate_integrity(),
        Err(KernelErrorV1::Intervention(
            "evidence must be bounded, sorted, and unique"
        ))
    ));

    let valid = intervention_request(
        &current,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("probe"),
            evidence: vec![],
        },
    );
    let wrong_scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("wrong-principal")),
        mandate: intervention_scope().mandate,
    };
    let mut verifier = InterventionVerifier { calls: 0 };
    assert!(matches!(
        GovernedLoopKernelV1::verify_governed_intervention(
            valid.clone(),
            &wrong_scope,
            &mut verifier,
            NOW,
        ),
        Err(KernelErrorV1::Intervention("wrong principal"))
    ));
    assert_eq!(verifier.calls, 0);
    assert!(matches!(
        GovernedLoopKernelV1::verify_governed_intervention(
            valid,
            &intervention_scope(),
            &mut verifier,
            NOW + 1_000,
        ),
        Err(KernelErrorV1::Intervention("expired"))
    ));
    assert_eq!(verifier.calls, 0);
}

#[test]
fn consumed_effectful_authority_cannot_be_recast_as_a_probe_intervention() {
    let start = initial();
    let mut observation = ObservationBoundary::current(clean_basis());
    let spent = advance_to_spent(
        &start,
        proposal(&campaign(), "work"),
        ObservationRefV1::from_digest(digest("observation-1")),
        &mut observation,
    );
    let request = intervention_request(
        &spent,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("read-only-probe"),
            evidence: vec![],
        },
    );
    let mut verifier = InterventionVerifier { calls: 0 };
    let verified = GovernedLoopKernelV1::verify_governed_intervention(
        request,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        GovernedLoopKernelV1::apply_verified_governed_intervention(&spent, verified),
        Err(KernelErrorV1::IllegalTransition { .. })
    ));
    assert_eq!(
        spent.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert!(spent.ag_spend().is_some());
    assert!(spent.docket_custody().is_none());
}

#[test]
fn intervention_presence_does_not_change_ag_authorization_or_issuance_material() {
    let plain = initial();
    let with_intent = initial();
    let request = intervention_request(
        &with_intent,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("read-only-probe"),
            evidence: vec![],
        },
    );
    let mut verifier = InterventionVerifier { calls: 0 };
    let authenticated = GovernedLoopKernelV1::verify_governed_intervention(
        request,
        &intervention_scope(),
        &mut verifier,
        NOW,
    )
    .unwrap();
    let GovernedInterventionEffectV1::Transition {
        successor: with_intent,
        ..
    } = GovernedLoopKernelV1::apply_verified_governed_intervention(&with_intent, authenticated)
        .unwrap()
    else {
        panic!("probe intent must use the probe law");
    };

    let exact = proposal(&campaign(), "work");
    let observation_ref = ObservationRefV1::from_digest(digest("observation-1"));
    let plain_spent = advance_to_spent(
        &plain,
        exact.clone(),
        observation_ref.clone(),
        &mut ObservationBoundary::current(clean_basis()),
    );
    let intent_spent = advance_to_spent(
        &with_intent,
        exact,
        observation_ref,
        &mut ObservationBoundary::current(clean_basis()),
    );
    assert_eq!(plain_spent.proposal(), intent_spent.proposal());
    assert_eq!(plain_spent.ag_spend(), intent_spent.ag_spend());
    assert_eq!(plain_spent.issuance(), intent_spent.issuance());
    assert_eq!(with_intent.state().meta().budget().probes_used, 1);
    assert_eq!(plain.state().meta().budget().probes_used, 0);
}
