//! AG lifecycle acceptance tests driven by immutable external NQ specimens.
//!
//! The checked-in records are historical evidence only.  These tests parse
//! them, then independently construct development-only AG/Docket/verifier
//! boundaries.  There is intentionally no fixture-to-authority conversion.

use std::collections::BTreeMap;

use ag_app::governed_loop::{
    CampaignEngineV1, EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
};
use ag_campaign::CampaignId;
use ag_campaign::external_repair_specimen::NqC1ImmutableSpecimenV1;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use tempfile::TempDir;
use uuid::Uuid;

const NOW: u64 = 40_000;
const PRE_SPEND: &[u8] =
    include_bytes!("../../ag-campaign/tests/fixtures/nq-c1/scope-discovery-pre-spend.v1.json");
const POST_SPEND: &[u8] =
    include_bytes!("../../ag-campaign/tests/fixtures/nq-c1/consumed-repair-hard-stop.v1.json");
const ARCHITECTURE: &[u8] =
    include_bytes!("../../ag-campaign/tests/fixtures/nq-c1/architectural-readjudication.v1.json");

fn digest(label: &str) -> Digest {
    Digest::hash_domain(
        "ag-app.nq-c1-governed-repair-lifecycle-test/v1",
        label.as_bytes(),
    )
}

fn campaign() -> CampaignId {
    CampaignId::from_digest(digest("campaign"))
}

fn occurrence(value: u128) -> OccurrenceId {
    OccurrenceId::from_uuid(Uuid::from_u128(value))
}

fn parse(bytes: &[u8]) -> NqC1ImmutableSpecimenV1 {
    NqC1ImmutableSpecimenV1::parse_fixture_file(bytes)
        .expect("checked-in external specimen must remain exact")
        .0
}

fn exact_repository_scope(
    paths: &[String],
    operation: CanonicalEffectOperationV1,
) -> CanonicalEffectScopeV1 {
    CanonicalEffectScopeV1::new(
        "repository-write/v1".to_owned(),
        paths
            .iter()
            .map(|path| CanonicalEffectResourceV1 {
                resource: "repository".to_owned(),
                path: path.clone(),
                operations: vec![operation],
            })
            .collect(),
    )
    .expect("fixture paths are exact normalized resources")
}

fn proposal(scope: CanonicalEffectScopeV1, label: &str) -> ExactWorkProposalV1 {
    ExactWorkProposalV1::new(
        campaign(),
        digest("nq-c1-rejected-candidate"),
        scope,
        "qualification-fixture-not-human-authority/nq-c1-repair/v1".to_owned(),
        digest(label),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("fixture-is-not-authority")],
            expires_at_unix_ms: NOW + 10_000,
        },
        None,
    )
    .unwrap()
}

fn catalog(proposal: &ExactWorkProposalV1) -> ExactWorkCatalogV1 {
    ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        policy_basis: digest("fixture-policy"),
        entries: BTreeMap::from([(
            proposal.work_schema().to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: proposal.work_schema().to_owned(),
                subject: proposal.subject().clone(),
                scope: proposal.effect_scope().digest(),
            },
        )]),
    }
}

fn create_engine(directory: &TempDir, occurrence: OccurrenceId) -> CampaignEngineV1 {
    CampaignEngineV1::create(
        &directory.path().join("campaign.sqlite"),
        campaign(),
        occurrence,
        ProgramBasisRefV1::from_digest(digest("program")),
        ResidualSetV1::default(),
        LoopBudgetV1 {
            retry_limit: 1,
            retries_used: 0,
            probe_limit: 1,
            probes_used: 0,
            escalation_limit: 1,
            escalations_used: 0,
        },
        NOW,
    )
    .unwrap()
}

struct CurrentObservation;

impl ObservationResolverV1 for CurrentObservation {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1> {
        Ok(ObservationResolutionV1 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V1.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(digest(
                "normalized-preconditions",
            )),
            subject: request.subject.clone(),
            status: ObservationStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

struct CurrentStanding;

impl StandingResolverV1 for CurrentStanding {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV1, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest("standing-resolution")),
            currentness: StandingCurrentnessRefV1::from_digest(digest("standing-current")),
            mandate: MandateRefV1::from_digest(digest("standing-mandate")),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            status: StandingStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

/// Development fixture only; it is not a human-authority implementation and
/// cannot be selected by production wiring.
struct QualificationFixtureNotHumanAuthority;

impl GovernedRepairDispositionVerifierV1 for QualificationFixtureNotHumanAuthority {
    fn verify_governed_repair_disposition(
        &mut self,
        request: &GovernedRepairVerificationRequestV1<'_>,
    ) -> Result<GovernedRepairVerificationV1, ExternalBoundaryErrorV1> {
        Ok(GovernedRepairVerificationV1 {
            schema: GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1.to_owned(),
            disposition: request.artifact.reference(),
            request: request.request.reference(),
            halted_state_digest: request.request.halted_state_digest.clone(),
            verifier_profile: request.expected_profile.profile.clone(),
            verifier_root: request.expected_profile.root.clone(),
            verifier_executable: request.expected_profile.executable.clone(),
            verification: HumanVerificationRefV1::from_digest(digest(
                "qualification-fixture-not-human-authority-verification",
            )),
            verified_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 10,
        })
    }
}

fn verifier_profile(label: &str) -> GovernedRepairVerifierProfileV1 {
    GovernedRepairVerifierProfileV1 {
        profile: digest(&format!(
            "qualification-fixture-not-human-authority-profile-{label}"
        )),
        root: digest(&format!(
            "qualification-fixture-not-human-authority-root-{label}"
        )),
        executable: digest(&format!(
            "qualification-fixture-not-human-authority-executable-{label}"
        )),
        principal: HumanPrincipalRefV1::from_digest(digest(&format!("principal-{label}"))),
        mandate: MandateRefV1::from_digest(digest(&format!("mandate-{label}"))),
    }
}

fn sorted_digests(labels: &[&str]) -> Vec<Digest> {
    let mut values = labels.iter().map(|label| digest(label)).collect::<Vec<_>>();
    values.sort();
    values
}

struct PostSpendFixtureDocket {
    missing_path: String,
}

impl DocketCustodyPortV1 for PostSpendFixtureDocket {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceAcceptanceV1, ExternalBoundaryErrorV1> {
        let custody = DocketCustodyV1 {
            schema: DOCKET_CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: DocketExecutionStandingRefV1::from_digest(digest(
                "fixture-docket-standing",
            )),
            standing_currentness: StandingCurrentnessRefV1::from_digest(digest(
                "fixture-docket-currentness",
            )),
            attempt: DocketAttemptRefV1::for_issuance(&issuance.issuance),
            executor_marker: ExecutorAttemptMarkerRefV1::from_digest(digest(
                "fixture-executor-marker",
            )),
            accepted_at_unix_ms: NOW + 6,
        };
        let outcome = DocketGovernedRepairOutcomeRefV1 {
            checkpoint: DocketCheckpointRefV1::from_digest(digest("fixture-docket-checkpoint")),
            sealed_result: DocketSealedResultRefV1::from_digest(digest(
                "fixture-docket-sealed-result",
            )),
            outcome: digest("fixture-docket-outcome"),
            issuance: issuance.issuance.clone(),
            custody: custody.reference(),
            attempt: custody.attempt.clone(),
            effect_journal: digest("fixture-empty-effect-journal"),
            executor_binding: digest("fixture-executor-binding"),
            executor_result: digest("fixture-executor-result"),
            executor_receipt: ReceiptRefV1::from_digest(digest("fixture-executor-receipt")),
            immutable_work_checkpoint: issuance.governed_repair_checkpoint.as_ref().map(
                |checkpoint| GovernedRepairCheckpointV1 {
                    docket_checkpoint: Some(DocketCheckpointRefV1::from_digest(digest(
                        "fixture-docket-checkpoint",
                    ))),
                    ..checkpoint.clone()
                },
            ),
            authorized_effects_occurred: false,
            created_at_unix_ms: NOW + 6,
            expires_at_unix_ms: NOW + 1_000,
            idempotency: digest("fixture-docket-requirement-idempotency"),
        };
        let requested_delta = exact_repository_scope(
            std::slice::from_ref(&self.missing_path),
            CanonicalEffectOperationV1::Modify,
        );
        let requirement = ScopeExpansionRequiredV1 {
            schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
            original_scope: issuance.effect_scope.clone(),
            original_scope_digest: issuance.effect_scope.digest(),
            requested_delta_digest: requested_delta.digest(),
            requested_delta,
            blocked_operation: BlockedEffectOperationV1 {
                resource: "repository".to_owned(),
                path: self.missing_path.clone(),
                operation: CanonicalEffectOperationV1::Modify,
            },
            reason: digest("fixture-scope-expansion-required"),
            dependency_evidence: sorted_digests(&["fixture-dependency"]),
            limitations: sorted_digests(&["historical-specimen-not-authority"]),
            docket_outcome: Some(outcome.clone()),
            unauthorized_effect_not_performed: true,
        };
        Ok(DocketIssuanceAcceptanceV1::GovernedRepairRequired {
            custody,
            result: DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
                outcome,
                requirement,
            },
        })
    }

    fn reconcile_issuance(
        &mut self,
        _issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        Err(ExternalBoundaryErrorV1::Unavailable {
            code: "qualification-fixture-does-not-reconcile".to_owned(),
        })
    }

    fn reconcile_attempt(
        &mut self,
        _issuance: &AgIssuanceV2,
        _custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        Err(ExternalBoundaryErrorV1::Unavailable {
            code: "qualification-fixture-does-not-reconcile".to_owned(),
        })
    }
}

#[test]
fn pre_spend_discovery_records_only_the_revised_exact_proposal() {
    let NqC1ImmutableSpecimenV1::ScopeDiscoveryPreSpend {
        authorization_consumed,
        authorized_paths,
        discovered_missing_path,
        source_mutation_attempted,
        ..
    } = parse(PRE_SPEND)
    else {
        unreachable!()
    };
    assert!(!authorization_consumed);
    assert!(!source_mutation_attempted);
    assert_eq!(authorized_paths.len(), 28);
    assert_eq!(
        discovered_missing_path,
        "crates/nq-store/src/governed_projection_capacity.rs"
    );

    let original_scope =
        exact_repository_scope(&authorized_paths, CanonicalEffectOperationV1::Modify);
    let delta = exact_repository_scope(
        std::slice::from_ref(&discovered_missing_path),
        CanonicalEffectOperationV1::Modify,
    );
    let revised_scope = original_scope.exact_union(&delta).unwrap();
    assert_eq!(original_scope.resources().len(), 28);
    assert_eq!(delta.resources().len(), 1);
    assert_eq!(revised_scope.resources().len(), 29);

    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, occurrence(1));
    let revised = proposal(revised_scope.clone(), "pre-spend-revised-proposal");
    let recorded = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("pre-spend-observation")),
            revised,
            ProposalClassV1::Initial,
            &mut CurrentObservation,
            NOW + 1,
        )
        .unwrap();

    assert_eq!(
        recorded.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    assert_eq!(recorded.proposal().unwrap().effect_scope(), &revised_scope);
    assert!(recorded.ag_spend().is_none());
    assert!(recorded.issuance().is_none());
    assert!(recorded.docket_custody().is_none());
    let replay = engine.replay().unwrap();
    assert_eq!(replay.transitions, 2);
    assert_eq!(replay.ag_spends, 0);
    assert_eq!(replay.docket_attempts, 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the approval/rejection branches keep the immutable post-spend bindings visible"
)]
fn post_spend_checkpoint_approval_opens_exact_successor_and_rejection_opens_none() {
    let NqC1ImmutableSpecimenV1::ConsumedRepairHardStop {
        authorized_paths,
        checkpoint_commit,
        checkpoint_tree,
        diff_identity,
        next_missing_path,
        ..
    } = parse(POST_SPEND)
    else {
        unreachable!()
    };
    assert_eq!(authorized_paths.len(), 29);
    assert_eq!(
        next_missing_path,
        concat!(
            "crates/nq-host-role-contract/assets/schemas/",
            "nq.v3_projection_capsule_bound_manifest.v2.schema.json"
        )
    );
    let original_scope =
        exact_repository_scope(&authorized_paths, CanonicalEffectOperationV1::Modify);
    let initial_checkpoint = GovernedRepairCheckpointV1 {
        repository: digest("nq-repository"),
        commit: checkpoint_commit.clone(),
        tree: checkpoint_tree.clone(),
        diff_identity: Some(diff_identity.clone()),
        content_manifest: digest("seven-path-checkpoint-content-manifest"),
        docket_checkpoint: None,
    };
    let proposed = proposal(original_scope.clone(), "post-spend-29-path-proposal")
        .with_governed_repair_checkpoint(initial_checkpoint.clone())
        .unwrap();
    let work_catalog = catalog(&proposed);
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, occurrence(1));
    let mut observation = CurrentObservation;
    let mut standing = CurrentStanding;
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("post-spend-observation")),
            proposed,
            ProposalClassV1::Initial,
            &mut observation,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &work_catalog,
            None,
            NOW + 3,
        )
        .unwrap();
    engine
        .authorize(
            &mut observation,
            &mut standing,
            &work_catalog,
            None,
            NOW + 4,
        )
        .unwrap();
    let halted = engine
        .dispatch(
            &mut PostSpendFixtureDocket {
                missing_path: next_missing_path.clone(),
            },
            NOW + 5,
        )
        .unwrap();
    assert_eq!(halted.program_counter(), ProgramCounterV1::Halted);
    let replay = engine.replay().unwrap();
    assert_eq!(replay.ag_spends, 1);
    assert_eq!(replay.docket_attempts, 1);
    let requirement = halted
        .halted()
        .and_then(HaltedV1::governed_repair_requirement)
        .cloned()
        .expect("Docket result must pin one exact requirement");
    let HumanDecisionRequirementV1::ScopeExpansion(expansion) = &requirement else {
        panic!("fixture requires exact scope expansion")
    };
    assert_eq!(expansion.original_scope, original_scope);
    assert_eq!(expansion.requested_delta.resources().len(), 1);
    assert_eq!(
        expansion.requested_delta.resources()[0].path,
        next_missing_path
    );
    assert!(expansion.unauthorized_effect_not_performed);
    let successor_scope = expansion.successor_scope().unwrap();
    assert_eq!(successor_scope.resources().len(), 30);

    let profile = verifier_profile("post-spend");
    let request = engine
        .create_governed_repair_request(
            halted.state_digest(),
            requirement.clone(),
            profile.profile.clone(),
            profile.root.clone(),
            profile.executable.clone(),
            sorted_digests(&["approve-exact-delta", "reject-exact-delta"]),
            sorted_digests(&["fixture-not-real-human-authority"]),
            digest("post-spend-request-idempotency"),
            NOW + 7,
            NOW + 100,
        )
        .unwrap();
    let docket_checkpoint = expansion
        .docket_outcome
        .as_ref()
        .map(|outcome| outcome.checkpoint.clone());
    let checkpoint = GovernedRepairCheckpointV1 {
        docket_checkpoint,
        ..initial_checkpoint
    };
    let approval = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::ApproveExactExpansion {
            request: request.reference(),
            successor_occurrence: occurrence(2),
            approved_delta: expansion.requested_delta.clone(),
            successor_scope: successor_scope.clone(),
            checkpoint: checkpoint.clone(),
        },
        decision: HumanDecisionIdV1::from_digest(digest("fixture-approval-decision")),
        principal: profile.principal.clone(),
        mandate: profile.mandate.clone(),
        verifier_profile: profile.profile.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("fixture-approval-nonce")),
        expires_at_unix_ms: NOW + 90,
    };
    let mut substituted_checkpoint = approval.clone();
    let GovernedRepairDispositionKindV1::ApproveExactExpansion {
        checkpoint: hostile_checkpoint,
        ..
    } = &mut substituted_checkpoint.disposition
    else {
        unreachable!()
    };
    hostile_checkpoint.commit = "f".repeat(40);
    assert!(
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &halted,
            &request,
            substituted_checkpoint,
            &profile,
            &mut QualificationFixtureNotHumanAuthority,
            NOW + 8,
        )
        .is_err(),
        "matching only the opaque Docket checkpoint cannot substitute the exact immutable work checkpoint"
    );
    let GovernedRepairDispositionEffectV1::OpenedSuccessor { successor, .. } =
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &halted,
            &request,
            approval,
            &profile,
            &mut QualificationFixtureNotHumanAuthority,
            NOW + 8,
        )
        .unwrap()
    else {
        panic!("approval must open a distinct successor")
    };
    assert_eq!(successor.key().occurrence, occurrence(2));
    assert!(successor.ag_spend().is_none());
    assert!(successor.issuance().is_none());
    let AuthorizedSuccessorBasisV1::ExactScopeExpansion {
        original_scope: retained_original,
        approved_delta,
        successor_scope: constrained_scope,
        checkpoint: retained_checkpoint,
        ..
    } = successor
        .prior_occurrence()
        .and_then(|prior| prior.authorized_successor.as_ref())
        .expect("successor must retain exact non-authorizing lineage")
    else {
        panic!("successor must be exact-scope constrained")
    };
    assert_eq!(retained_original, &original_scope);
    assert_eq!(approved_delta.resources().len(), 1);
    assert_eq!(approved_delta.resources()[0].path, next_missing_path);
    assert_eq!(constrained_scope, &successor_scope);
    assert_eq!(retained_checkpoint, &checkpoint);

    let neighboring_path = concat!(
        "crates/nq-host-role-contract/assets/schemas/",
        "nq.v3_projection_capsule_bound_manifest.v3.schema.json"
    )
    .to_owned();
    let neighboring_delta = exact_repository_scope(
        std::slice::from_ref(&neighboring_path),
        CanonicalEffectOperationV1::Modify,
    );
    let neighboring_scope = original_scope.exact_union(&neighboring_delta).unwrap();
    let neighboring_proposal = proposal(neighboring_scope, "unauthorized-neighboring-path")
        .with_governed_repair_checkpoint(checkpoint.clone())
        .unwrap();
    assert!(
        GovernedLoopKernelV1::record_proposal(
            &successor,
            ObservationRefV1::from_digest(digest("neighboring-path-observation")),
            neighboring_proposal,
            ProposalClassV1::Successor,
            &mut CurrentObservation,
            NOW + 9,
        )
        .is_err(),
        "approval of one exact path must not authorize an adjacent path"
    );

    let rejection = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::Reject {
            request: request.reference(),
            reason: digest("fixture-rejection"),
        },
        decision: HumanDecisionIdV1::from_digest(digest("fixture-rejection-decision")),
        principal: profile.principal.clone(),
        mandate: profile.mandate.clone(),
        verifier_profile: profile.profile.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("fixture-rejection-nonce")),
        expires_at_unix_ms: NOW + 90,
    };
    let GovernedRepairDispositionEffectV1::Rejected {
        halted: rejected, ..
    } = GovernedLoopKernelV1::apply_governed_repair_disposition(
        &halted,
        &request,
        rejection,
        &profile,
        &mut QualificationFixtureNotHumanAuthority,
        NOW + 8,
    )
    .unwrap()
    else {
        panic!("rejection must not open a successor")
    };
    assert!(
        rejected
            .halted()
            .unwrap()
            .governed_repair_closed()
            .is_some()
    );
    assert_eq!(rejected.state().meta().residuals().len(), 1);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the readjudication census and no-source-authority assertions are one specimen"
)]
fn architectural_census_yields_readjudication_without_repair_authority() {
    let NqC1ImmutableSpecimenV1::ArchitecturalReadjudication {
        additional_diagnostic_path_count,
        architecture_required,
        core_path_count,
        diagnostic_file_count,
        diagnostic_reference_count,
        existing_source_scope_admissible,
        overlap_path_count,
        ..
    } = parse(ARCHITECTURE)
    else {
        unreachable!()
    };
    assert!(architecture_required);
    assert!(!existing_source_scope_admissible);
    assert_eq!(
        (
            core_path_count,
            diagnostic_reference_count,
            diagnostic_file_count,
            overlap_path_count,
            additional_diagnostic_path_count,
        ),
        (32, 945, 33, 10, 23)
    );

    let adjudication_scope = CanonicalEffectScopeV1::new(
        "read-only-adjudication/v1".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "evidence".to_owned(),
            path: "audit/nq-c1-gen5/scope-closure-census.json".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Read],
        }],
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, occurrence(10));
    let read_only_proposal = proposal(adjudication_scope.clone(), "read-only-scope-audit");
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("readjudication-observation")),
            read_only_proposal,
            ProposalClassV1::Initial,
            &mut CurrentObservation,
            NOW + 1,
        )
        .unwrap();
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("architectural-classification-required")),
            NOW + 2,
        )
        .unwrap();
    let requirement = HumanDecisionRequirementV1::Readjudication(ReadjudicationRequiredV1 {
        schema: READJUDICATION_REQUIRED_SCHEMA_V1.to_owned(),
        question: digest("classify-clippy-diagnostics-before-exact-repair-scope"),
        evidence_census: sorted_digests(&[
            "observed-core-path-count-32",
            "observed-diagnostic-reference-count-945",
        ]),
        diagnostic_census: sorted_digests(&[
            "diagnostic-file-count-33",
            "overlap-path-count-10",
            "additional-path-count-23",
        ]),
        bounded_alternatives: sorted_digests(&[
            "intended-production-wiring",
            "compile-confined-specimen",
            "obsolete-or-mechanical-repair",
        ]),
        unresolved_facts: sorted_digests(&["diagnostic-semantic-classification"]),
        limitations: sorted_digests(&[
            "no-wildcard-scope",
            "historical-fixture-not-repair-authority",
        ]),
        adjudication_scope: adjudication_scope.clone(),
        docket_outcome: None,
        unauthorized_effect_not_performed: true,
    });
    let profile = verifier_profile("readjudication");
    let request = engine
        .create_governed_repair_request(
            halted.state_digest(),
            requirement,
            profile.profile.clone(),
            profile.root.clone(),
            profile.executable.clone(),
            sorted_digests(&["request-readjudication", "reject-readjudication"]),
            sorted_digests(&["no-source-repair-authority"]),
            digest("readjudication-idempotency"),
            NOW + 3,
            NOW + 100,
        )
        .unwrap();
    assert!(matches!(
        request.requirement,
        HumanDecisionRequirementV1::Readjudication(_)
    ));
    let replay = engine.replay().unwrap();
    assert_eq!(replay.ag_spends, 0);
    assert_eq!(replay.docket_attempts, 0);

    let checkpoint = GovernedRepairCheckpointV1 {
        repository: digest("nq-repository"),
        commit: "74975e6d0ede1ffb0f090a1b5e91e4624ce39783".to_owned(),
        tree: "9c4f067cc13861e43b32dba11651ce6904c606fd".to_owned(),
        diff_identity: None,
        content_manifest: digest("read-only-census-content-manifest"),
        docket_checkpoint: None,
    };
    let artifact = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(10),
        halted_state_digest: halted.state_digest().clone(),
        disposition: GovernedRepairDispositionKindV1::RequestReadjudication {
            request: request.reference(),
            successor_occurrence: occurrence(11),
            successor_program: ProgramBasisRefV1::from_digest(digest(
                "bounded-read-only-adjudicator",
            )),
            checkpoint: checkpoint.clone(),
        },
        decision: HumanDecisionIdV1::from_digest(digest("fixture-readjudication-decision")),
        principal: profile.principal.clone(),
        mandate: profile.mandate.clone(),
        verifier_profile: profile.profile.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("fixture-readjudication-nonce")),
        expires_at_unix_ms: NOW + 90,
    };
    let GovernedRepairDispositionEffectV1::OpenedSuccessor { successor, .. } =
        GovernedLoopKernelV1::apply_governed_repair_disposition(
            &halted,
            &request,
            artifact,
            &profile,
            &mut QualificationFixtureNotHumanAuthority,
            NOW + 4,
        )
        .unwrap()
    else {
        panic!("readjudication must open only a fresh bounded occurrence")
    };
    assert!(successor.ag_spend().is_none());
    assert!(successor.issuance().is_none());
    assert!(successor.docket_custody().is_none());
    let AuthorizedSuccessorBasisV1::Readjudication {
        adjudication_scope: retained_scope,
        checkpoint: retained_checkpoint,
        ..
    } = successor
        .prior_occurrence()
        .and_then(|prior| prior.authorized_successor.as_ref())
        .expect("readjudication lineage must remain exact")
    else {
        panic!("architectural ambiguity must not become scope-expansion authority")
    };
    assert_eq!(retained_scope, &adjudication_scope);
    assert_eq!(retained_checkpoint, &checkpoint);
    assert!(
        retained_scope
            .resources()
            .iter()
            .all(|resource| { resource.operations == [CanonicalEffectOperationV1::Read] })
    );

    let source_mutation = CanonicalEffectScopeV1::new(
        "read-only-adjudication/v1".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let hostile = proposal(source_mutation, "hostile-source-repair")
        .with_governed_repair_checkpoint(checkpoint)
        .unwrap();
    assert!(
        GovernedLoopKernelV1::record_proposal(
            &successor,
            ObservationRefV1::from_digest(digest("hostile-source-observation")),
            hostile,
            ProposalClassV1::Successor,
            &mut CurrentObservation,
            NOW + 5,
        )
        .is_err(),
        "readjudication evidence must not become source-repair authority"
    );
}
