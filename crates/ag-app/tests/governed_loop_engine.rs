//! Production-engine tests spanning live boundaries, `SQLite` state, Docket
//! custody, restart, reconciliation, continuation, and human disposition.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Barrier, Mutex};

use ag_app::governed_loop::{
    CampaignEngineErrorV1, CampaignEngineV1, CampaignRecoveryV1, DocketProgressV1,
    EXACT_WORK_CATALOG_SCHEMA_V1, EXACT_WORK_CATALOG_SCHEMA_V2, ExactObservationBasisRequirementV1,
    ExactWorkCatalogEntryV1, ExactWorkCatalogEntryV2, ExactWorkCatalogV1, ExactWorkCatalogV2,
    WorkPreconditionV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_operator_ui::links::GovernedRuntimeLinkV1;
use ag_operator_ui::model::{
    AgInspectV1, CAMPAIGN_DETAIL_SCHEMA_V1, CAMPAIGN_INDEX_SCHEMA_V1, CampaignDetailV1,
    CampaignIndexEntryV1, CampaignIndexV1, DEMO_CORPUS_SCHEMA_V1, DOCKET_INSPECTION_SCHEMA_V1,
    DemoCorpusV1, DemoSemanticLinkTargetV1, DocketAuthenticationV1, DocketInspectionV1,
    DocketRecordInspectionV1, DocketRecordStatusV1, NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1,
    NIGHTSHIFT_AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1, NIGHTSHIFT_OBSERVATION_EXPORT_SCHEMA_V1,
    NightshiftAuthoringContextExportV1, NightshiftAuthoringContextProvenanceV1,
    NightshiftAuthoringContextQueryV1, NightshiftFamilyV1, NightshiftObservationExportV1,
    NightshiftObservationMatchV1, NightshiftOrderKeyV1, ProjectionCheckV1,
    ProjectionCorrespondenceV1, ReadCommandNameV1, RelatedSourceV1, RuntimeProfileBindingV1,
    SourceErrorKindV1, SourceResultV1,
};
use ag_operator_ui::render;
use ag_operator_ui::source::{OperatorReaderV1, hex_encode, selected_snapshot};
use ag_primitives::Digest;
use ag_store::campaign::{
    CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1, CAMPAIGN_TRANSITION_HISTORY_SCHEMA_V1,
    CampaignRefusalHistoryV1, CampaignReplayReportV1, CampaignTransitionEvidenceV1,
    CampaignTransitionHistoryV1,
};
use serde::Serialize;
use tempfile::TempDir;
use uuid::Uuid;

const NOW: u64 = 30_000;
/// The resolver identity these tests configure the engine to expect.
const OBSERVATION_RESOLVER_ID: &str = "test.observation-resolver/v1";
const REPOSITORY_QUALIFICATION_RESOLVER_ID: &str =
    "nightshift.repository-qualification-resolver/v1";
const REPOSITORY_QUALIFICATION_BASIS_TYPE: &str =
    "nightshift.repository-qualification-applicability/v1";
/// The standing resolver identity these tests configure the engine to expect.
const STANDING_RESOLVER_ID: &str = "test.standing-resolver/v1";
/// Maximum accepted standing-answer lifetime in these tests.
const MAX_STANDING_TTL_MS: u64 = 60_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-engine-test/v1", label.as_bytes())
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

fn failed_delivery_basis() -> DecisionBasisV1 {
    decision_basis("condition.clean", "delivery.failed")
}

fn typed_basis(label: &str) -> TypedOpaqueObservationBasisV1 {
    TypedOpaqueObservationBasisV1::new(
        "civil.managed-file.ag-observation-basis/v1".to_owned(),
        digest(label),
    )
    .unwrap()
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

fn proposal(label: &str) -> ExactWorkProposalV1 {
    proposal_with_schema("test.engine-work/v1", label)
}

fn proposal_with_schema(work_schema: &str, label: &str) -> ExactWorkProposalV1 {
    ExactWorkProposalV1::new(
        campaign(),
        digest("subject"),
        digest("scope"),
        work_schema.to_owned(),
        digest(label),
        None,
    )
    .unwrap()
}

fn catalog() -> ExactWorkCatalogV1 {
    catalog_with(WorkPreconditionV1::default())
}

/// A catalog whose single entry matches the test proposal and carries the
/// given finite workflow precondition. Its policy identity is derived from
/// its content; tests compare provenance against `catalog.policy_basis()`.
fn catalog_with(precondition: WorkPreconditionV1) -> ExactWorkCatalogV1 {
    ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            "test.engine-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.engine-work/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                precondition,
            },
        )]),
    }
}

/// A finite workflow precondition over frozen v1 basis atoms.
fn precondition(required: &[&str], forbidden: &[&str]) -> WorkPreconditionV1 {
    WorkPreconditionV1 {
        required: required.iter().map(|atom| (*atom).to_owned()).collect(),
        forbidden: forbidden.iter().map(|atom| (*atom).to_owned()).collect(),
    }
}

/// A valid catalog whose only entry matches a different work schema, so the
/// proposal used in these tests is outside its admitted set.
fn refusing_catalog() -> ExactWorkCatalogV1 {
    ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            "test.other-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.other-work/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                precondition: WorkPreconditionV1::default(),
            },
        )]),
    }
}

fn typed_catalog(basis: TypedOpaqueObservationBasisV1) -> ExactWorkCatalogV2 {
    ExactWorkCatalogV2 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V2.to_owned(),
        entries: BTreeMap::from([(
            "test.engine-work/v1".to_owned(),
            ExactWorkCatalogEntryV2 {
                work_schema: "test.engine-work/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                observation_basis: ExactObservationBasisRequirementV1::TypedBasis(basis),
            },
        )]),
    }
}

#[derive(Clone)]
struct ObservationBoundary {
    basis: DecisionBasisV1,
    status: ObservationStatusV1,
    calls: usize,
}

impl ObservationBoundary {
    fn current(basis: DecisionBasisV1) -> Self {
        Self {
            basis,
            status: ObservationStatusV1::Current,
            calls: 0,
        }
    }
}

impl ObservationResolverV1 for ObservationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
        Ok(ObservationResolutionV2 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V2.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest(&format!(
                "observation-current-{}",
                self.calls
            ))),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                self.basis.decision_basis_digest().unwrap(),
            ),
            basis: self.basis.clone(),
            resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
            subject: request.subject.clone(),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        }
        .into())
    }
}

#[derive(Clone)]
struct TypedObservationBoundary {
    basis: TypedOpaqueObservationBasisV1,
    calls: usize,
    substitute_occurrence: Option<OccurrenceId>,
}

impl TypedObservationBoundary {
    fn current(basis: TypedOpaqueObservationBasisV1) -> Self {
        Self {
            basis,
            calls: 0,
            substitute_occurrence: None,
        }
    }
}

impl ObservationResolverV1 for TypedObservationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
        let mut key = request.key.clone();
        if let Some(occurrence) = self.substitute_occurrence {
            key.occurrence = occurrence;
        }
        Ok(ObservationResolutionV3 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V3.to_owned(),
            key,
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest(&format!(
                "typed-currentness-{}",
                self.calls
            ))),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                self.basis.binding_digest().unwrap(),
            ),
            basis: self.basis.clone(),
            resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
            subject: request.subject.clone(),
            status: TypedObservationStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        }
        .into())
    }
}

#[derive(Clone)]
struct RepositoryQualificationBoundary {
    basis: TypedOpaqueObservationBasisV1,
    status: TypedObservationStatusV1,
    resolver_id: String,
    substitute_occurrence: Option<OccurrenceId>,
    substitute_observation: Option<ObservationRefV1>,
    substitute_subject: Option<Digest>,
    calls: usize,
}

impl RepositoryQualificationBoundary {
    fn current(basis: TypedOpaqueObservationBasisV1) -> Self {
        Self {
            basis,
            status: TypedObservationStatusV1::Current,
            resolver_id: REPOSITORY_QUALIFICATION_RESOLVER_ID.to_owned(),
            substitute_occurrence: None,
            substitute_observation: None,
            substitute_subject: None,
            calls: 0,
        }
    }
}

impl ObservationResolverV1 for RepositoryQualificationBoundary {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
        let mut key = request.key.clone();
        if let Some(occurrence) = self.substitute_occurrence {
            key.occurrence = occurrence;
        }
        Ok(ObservationResolutionV3 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V3.to_owned(),
            key,
            observation: self
                .substitute_observation
                .clone()
                .unwrap_or_else(|| request.observation.clone()),
            currentness: ObservationCurrentnessRefV1::from_digest(digest(&format!(
                "repository-qualification-currentness-{}",
                self.calls
            ))),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                self.basis.binding_digest().unwrap(),
            ),
            basis: self.basis.clone(),
            resolver_id: self.resolver_id.clone(),
            subject: self
                .substitute_subject
                .clone()
                .unwrap_or_else(|| request.subject.clone()),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 1_000,
        }
        .into())
    }
}

struct FixedRepositoryQualificationResolution(ObservationResolutionV3);

impl ObservationResolverV1 for FixedRepositoryQualificationResolution {
    fn resolve_observation(
        &mut self,
        _: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        Ok(self.0.clone().into())
    }
}

#[derive(Clone)]
struct StandingBoundary {
    status: StandingStatusV1,
    available: bool,
    calls: usize,
}

impl StandingBoundary {
    fn current() -> Self {
        Self {
            status: StandingStatusV1::Current,
            available: true,
            calls: 0,
        }
    }
}

impl StandingResolverV1 for StandingBoundary {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        self.calls += 1;
        if !self.available {
            return Err(ExternalBoundaryErrorV1::Unavailable {
                code: "standing-resolver-unavailable".to_owned(),
            });
        }
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest(&format!(
                "standing-resolution-{}",
                self.calls
            ))),
            currentness: StandingCurrentnessRefV1::from_digest(digest(&format!(
                "standing-currentness-{}",
                self.calls
            ))),
            mandate: MandateRefV1::from_digest(digest("mandate")),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            resolver_id: STANDING_RESOLVER_ID.to_owned(),
            status: self.status,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 1_000,
        })
    }
}

#[derive(Clone, Debug)]
enum FakeAttemptState {
    Accepted(DocketCustodyV1),
    Settled(DocketCustodyV1, DocketSettlementV1),
    Indeterminate(DocketCustodyV1, IndeterminateOutcomeV1),
}

#[derive(Default)]
struct FakeDocketState {
    attempts: BTreeMap<AgIssuanceRefV1, FakeAttemptState>,
    accept_calls: usize,
    panic_after_accept: bool,
}

#[derive(Clone, Default)]
struct FakeDocket {
    shared: Arc<Mutex<FakeDocketState>>,
}

impl FakeDocket {
    fn custody(issuance: &AgIssuanceV1) -> DocketCustodyV1 {
        DocketCustodyV1 {
            schema: DOCKET_CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: DocketExecutionStandingRefV1::from_digest(digest(
                "docket-execution-standing",
            )),
            standing_currentness: StandingCurrentnessRefV1::from_digest(digest(
                "docket-standing-currentness",
            )),
            attempt: DocketAttemptRefV1::for_issuance(&issuance.issuance),
            executor_marker: ExecutorAttemptMarkerRefV1::from_digest(Digest::hash_domain(
                "ag-governed-engine-test/executor-marker/v1",
                issuance.issuance.as_str().as_bytes(),
            )),
            accepted_at_unix_ms: NOW + 10,
        }
    }

    fn settle(&self, issuance: &AgIssuanceRefV1, outcome: KnownOutcomeV1) {
        let mut state = self.shared.lock().unwrap();
        let Some(FakeAttemptState::Accepted(custody) | FakeAttemptState::Indeterminate(custody, _)) =
            state.attempts.get(issuance).cloned()
        else {
            panic!("issuance was not accepted or was already settled")
        };
        let settlement = DocketSettlementV1 {
            schema: DOCKET_SETTLEMENT_SCHEMA_V1.to_owned(),
            settlement: SettlementRefV1::from_digest(digest(match outcome {
                KnownOutcomeV1::Success => "known-success",
                KnownOutcomeV1::Failure => "known-failure",
            })),
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            executor_marker: custody.executor_marker.clone(),
            receipt: ReceiptRefV1::from_digest(digest("receipt")),
            outcome,
            settled_at_unix_ms: NOW + 20,
        };
        state.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Settled(custody, settlement),
        );
    }

    fn make_indeterminate(&self, issuance: &AgIssuanceRefV1) {
        let mut state = self.shared.lock().unwrap();
        let Some(FakeAttemptState::Accepted(custody)) = state.attempts.get(issuance).cloned()
        else {
            panic!("issuance was not accepted")
        };
        let indeterminate = IndeterminateOutcomeV1 {
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            reconciliation: ReconciliationRefV1::from_digest(digest("reconciliation")),
            evidence: digest("unknown-outcome"),
        };
        state.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Indeterminate(custody, indeterminate),
        );
    }

    fn set_panic_after_accept(&self) {
        self.shared.lock().unwrap().panic_after_accept = true;
    }

    fn accept_calls(&self) -> usize {
        self.shared.lock().unwrap().accept_calls
    }

    fn response_for(
        state: &FakeDocketState,
        issuance: &AgIssuanceRefV1,
    ) -> DocketIssuanceReconciliationV1 {
        match state.attempts.get(issuance) {
            None => DocketIssuanceReconciliationV1::NotAccepted,
            Some(FakeAttemptState::Accepted(custody)) => {
                DocketIssuanceReconciliationV1::Accepted(custody.clone())
            }
            Some(FakeAttemptState::Settled(custody, settlement)) => {
                DocketIssuanceReconciliationV1::Settled {
                    custody: custody.clone(),
                    settlement: settlement.clone(),
                }
            }
            Some(FakeAttemptState::Indeterminate(custody, indeterminate)) => {
                DocketIssuanceReconciliationV1::Indeterminate {
                    custody: custody.clone(),
                    indeterminate: indeterminate.clone(),
                }
            }
        }
    }
}

impl DocketCustodyPortV1 for FakeDocket {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
        let mut state = self.shared.lock().unwrap();
        state.accept_calls += 1;
        let custody = match state.attempts.get(&issuance.issuance) {
            Some(
                FakeAttemptState::Accepted(custody)
                | FakeAttemptState::Settled(custody, _)
                | FakeAttemptState::Indeterminate(custody, _),
            ) => custody.clone(),
            None => {
                let custody = Self::custody(issuance);
                state.attempts.insert(
                    issuance.issuance.clone(),
                    FakeAttemptState::Accepted(custody.clone()),
                );
                custody
            }
        };
        let panic_after_accept = state.panic_after_accept;
        state.panic_after_accept = false;
        drop(state);
        assert!(!panic_after_accept, "injected crash after Docket custody");
        Ok(custody)
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        let state = self.shared.lock().unwrap();
        Ok(Self::response_for(&state, &issuance.issuance))
    }

    fn reconcile_attempt(
        &mut self,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        let state = self.shared.lock().unwrap();
        let response = Self::response_for(&state, &custody.issuance);
        match &response {
            DocketIssuanceReconciliationV1::Accepted(actual)
            | DocketIssuanceReconciliationV1::Settled {
                custody: actual, ..
            }
            | DocketIssuanceReconciliationV1::Indeterminate {
                custody: actual, ..
            } if actual == custody => Ok(response),
            _ => Err(ExternalBoundaryErrorV1::Refused {
                code: "wrong-custody".to_owned(),
                evidence: None,
            }),
        }
    }
}

struct HumanVerifier;

impl HumanDispositionVerifierV1 for HumanVerifier {
    fn verify_human_disposition(
        &mut self,
        request: &HumanDispositionVerificationRequestV1<'_>,
    ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1> {
        Ok(HumanVerificationRefV1::from_digest(Digest::hash_domain(
            "ag-governed-engine-test/human-verification/v1",
            request.artifact.nonce.as_str().as_bytes(),
        )))
    }
}

#[derive(Default)]
struct InterventionVerifier {
    calls: usize,
}

impl GovernedInterventionVerifierV1 for InterventionVerifier {
    fn verify_governed_intervention(
        &mut self,
        request: &GovernedInterventionVerificationRequestV1<'_>,
    ) -> Result<GovernedInterventionVerificationRefV1, ExternalBoundaryErrorV1> {
        self.calls += 1;
        Ok(GovernedInterventionVerificationRefV1::from_digest(
            Digest::hash_domain(
                "ag-governed-engine-test/intervention-verification/v1",
                request.request.request.as_str().as_bytes(),
            ),
        ))
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
    class: GovernedInterventionClassV1,
    nonce: &str,
) -> GovernedInterventionRequestV1 {
    let scope = intervention_scope();
    GovernedInterventionRequestV1::new(
        scope.principal,
        scope.mandate,
        GovernedInterventionNonceRefV1::from_digest(digest(nonce)),
        current.key().campaign.clone(),
        current.key().occurrence,
        current.state_digest().clone(),
        class,
        NOW,
        NOW + 10_000,
    )
    .unwrap()
}

fn create_engine(directory: &TempDir, residuals: ResidualSetV1) -> CampaignEngineV1 {
    CampaignEngineV1::create(
        &directory.path().join("campaign.sqlite"),
        campaign(),
        occurrence(1),
        ProgramBasisRefV1::from_digest(digest("program")),
        digest("work-1"),
        residuals,
        budget(),
        NOW,
    )
    .unwrap()
}

#[test]
fn authenticated_probe_request_is_durable_authority_neutral_and_one_use_by_state() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let current = engine.current().unwrap();
    let request = intervention_request(
        &current,
        GovernedInterventionClassV1::RequestProbe {
            exact_probe_work: digest("read-only-probe"),
            evidence: vec![],
        },
        "probe-nonce",
    );
    let mut verifier = InterventionVerifier::default();
    let successor = engine
        .apply_governed_intervention(
            request.clone(),
            &intervention_scope(),
            &mut verifier,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(verifier.calls, 1);
    assert_eq!(successor.state().meta().budget().probes_used, 1);
    assert!(successor.proposal().is_none());
    assert!(successor.ag_spend().is_none());
    assert!(successor.issuance().is_none());

    drop(engine);
    let mut reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), successor);
    assert!(matches!(
        &reopened.history().unwrap().transitions[1].evidence,
        CampaignTransitionEvidenceV1::GovernedIntervention { verified }
            if verified.request == request
    ));
    let accepted_detail = operator_detail(
        successor.clone(),
        reopened.history().unwrap(),
        reopened.refusal_history().unwrap(),
    );
    let accepted_html = render::campaign_detail(&accepted_detail);
    assert!(accepted_html.contains("operator intent"));
    assert!(accepted_html.contains("authenticated request evidence, not authorization"));
    // Exact replay is stale because the request binds its predecessor digest.
    assert!(
        reopened
            .apply_governed_intervention(request, &intervention_scope(), &mut verifier, NOW + 2,)
            .is_err()
    );
    assert_eq!(reopened.current().unwrap(), successor);
    let refusals = reopened.refusal_history().unwrap();
    assert_eq!(refusals.refusals.len(), 1);
    assert_eq!(
        refusals.refusals[0].outcome.code,
        RefusalCodeV1::InterventionBindingMismatch
    );
    assert!(refusals.refusals[0].outcome.governed_intervention.is_some());
    let detail = operator_detail(successor, reopened.history().unwrap(), refusals);
    let html = render::campaign_detail(&detail);
    assert!(html.contains("intervention refused"));
    assert!(html.contains("authenticated intent created no transition or authority"));
}

fn available<T: Serialize>(command: ReadCommandNameV1, value: T) -> SourceResultV1<T> {
    let raw = serde_json::to_value(&value).unwrap();
    SourceResultV1::Available {
        source: "AG".to_owned(),
        command,
        captured_at_unix_ms: NOW,
        value,
        raw,
    }
}

fn operator_detail(
    current: OccurrenceSnapshotV1,
    history: CampaignTransitionHistoryV1,
    refusals: CampaignRefusalHistoryV1,
) -> CampaignDetailV1 {
    let ag_spends = u64::from(current.ag_spend().is_some());
    let docket_attempts = u64::from(current.docket_custody().is_some());
    let settlements = u64::from(current.settlement().is_some());
    let replay = CampaignReplayReportV1 {
        campaign: current.key().campaign.clone(),
        transitions: u64::try_from(history.transitions.len()).unwrap(),
        ag_spends,
        docket_attempts,
        settlements,
        human_dispositions: 0,
        current_state_digest: current.state_digest().clone(),
    };
    let inspect = AgInspectV1 {
        schema: "ag.governed-loop.operational-snapshot/v1".to_owned(),
        current: current.clone(),
        replay: replay.clone(),
        runtime_profile: RuntimeProfileBindingV1 {
            schema: "ag.governed-loop.runtime-profile/v1".to_owned(),
            digest: digest("operator-profile"),
        },
    };
    CampaignDetailV1 {
        schema: CAMPAIGN_DETAIL_SCHEMA_V1.to_owned(),
        locator_token: "63616d706169676e2e73716c697465".to_owned(),
        locator: "campaign.sqlite".to_owned(),
        inspect: available(ReadCommandNameV1::AgInspect, inspect),
        status: available(ReadCommandNameV1::AgStatus, current),
        replay: available(ReadCommandNameV1::AgReplay, replay),
        history: available(ReadCommandNameV1::AgHistory, history),
        refusals: available(ReadCommandNameV1::AgRefusals, refusals),
        intervention_submissions: None,
        projection: ProjectionCheckV1 {
            correspondence: ProjectionCorrespondenceV1::Exact,
            findings: vec!["fixture projections share exact canonical coordinates".to_owned()],
        },
        nightshift: Vec::new(),
        authoring_contexts: Vec::new(),
        authoring_custody: Vec::new(),
        external_observations: Vec::new(),
        observation_acquisitions: Vec::new(),
        docket: Vec::new(),
    }
}

fn available_from<T: Serialize>(
    source: &str,
    command: ReadCommandNameV1,
    value: T,
) -> SourceResultV1<T> {
    let raw = serde_json::to_value(&value).unwrap();
    SourceResultV1::Available {
        source: source.to_owned(),
        command,
        captured_at_unix_ms: NOW,
        value,
        raw,
    }
}

fn unavailable_fixture<T>(
    source: &str,
    command: ReadCommandNameV1,
    kind: SourceErrorKindV1,
    detail: &str,
) -> SourceResultV1<T> {
    SourceResultV1::Unavailable {
        source: source.to_owned(),
        command,
        captured_at_unix_ms: NOW,
        error_kind: kind,
        detail: detail.to_owned(),
        exit_status: None,
    }
}

fn demo_locator(detail: &mut CampaignDetailV1, name: &str) {
    detail.locator = format!("{name}.sqlite");
    detail.locator_token = hex_encode(detail.locator.as_bytes());
}

fn attach_demo_owner_sources(detail: &mut CampaignDetailV1) {
    let Some(current) = detail.inspect.value().map(|value| value.current.clone()) else {
        return;
    };
    let observation = current.observation().or_else(|| {
        current
            .completed()
            .map(ag_campaign::governed::CompletedV1::terminal_observation)
    });
    if let Some(observation) = observation {
        let order = NightshiftOrderKeyV1 {
            occurrence: u64::try_from(current.key().occurrence.as_uuid().as_u128())
                .expect("demo occurrence identity fits the Nightshift fixture order"),
            nominal_due_at: "2026-08-20T12:00:00Z".to_owned(),
            slot_id: format!("slot:{}", current.key().occurrence),
        };
        let export = NightshiftObservationExportV1 {
            schema: NIGHTSHIFT_OBSERVATION_EXPORT_SCHEMA_V1.to_owned(),
            observation_id: observation.observation().as_str().to_owned(),
            matches: vec![NightshiftObservationMatchV1 {
                cycle_id: digest("demo-nightshift-cycle").as_str().to_owned(),
                slot_id: order.slot_id.clone(),
                family: NightshiftFamilyV1 {
                    policy_id: "policy:operator-demo".to_owned(),
                    configuration_version: "configuration:operator-demo/v1".to_owned(),
                    subject_id: digest("subject").as_str().to_owned(),
                    scope_id: digest("scope").as_str().to_owned(),
                    scheduler_clock_id: "clock:operator-demo".to_owned(),
                },
                order_key: order.clone(),
                family_latest_cycle_id: Some(digest("demo-nightshift-cycle").as_str().to_owned()),
                family_latest_order_key: Some(order),
                observation: serde_json::json!({
                    "schema": "nightshift.observation_record.v2",
                    "observation_id": observation.observation().as_str(),
                    "source_admissions": [{
                        "schema": "nq.diagnostic_admission_provenance.v1",
                        "provenance_id": digest("demo-nq-provenance").as_str(),
                        "disposition": "admitted_report",
                        "nonclaims": [
                            "admission establishes evidence eligibility only",
                            "admission does not authorize work"
                        ]
                    }],
                    "support": {"standing": "current"},
                    "posture": {"current": true}
                }),
            }],
        };
        detail.nightshift.push(RelatedSourceV1 {
            identity: observation.observation().as_str().to_owned(),
            result: available_from(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportObservation,
                export,
            ),
        });
    }
    attach_demo_authoring_contexts(detail, &current);
    if let Some(issuance) = current.issuance() {
        let record = current.docket_custody().map(|custody| {
            let status = match current.program_counter() {
                ProgramCounterV1::ReconciliationRequired => DocketRecordStatusV1::Indeterminate,
                ProgramCounterV1::SettledObservationRequired => DocketRecordStatusV1::Settled,
                _ => DocketRecordStatusV1::Accepted,
            };
            DocketRecordInspectionV1 {
                issuance: issuance.clone(),
                authentication: DocketAuthenticationV1 {
                    issuer_principal: "principal:ag-ng-demo".to_owned(),
                    signer_key_id: "key:ag-ng-demo".to_owned(),
                    signer_public_key: "ed25519:demo-public-key".to_owned(),
                    signature: "ed25519:demo-signature".to_owned(),
                },
                custody: custody.clone(),
                status,
                settlement: current.settlement().cloned(),
                indeterminate: current.indeterminate().cloned(),
                executor_binding: digest("demo-executor-binding").as_str().to_owned(),
                executor_program_digest: digest("demo-executor-program").as_str().to_owned(),
                executor_plan: digest("demo-executor-plan").as_str().to_owned(),
            }
        });
        let inspection = DocketInspectionV1 {
            schema: DOCKET_INSPECTION_SCHEMA_V1.to_owned(),
            requested_issuance: issuance.issuance.as_str().to_owned(),
            record,
        };
        detail.docket.push(RelatedSourceV1 {
            identity: issuance.issuance.as_str().to_owned(),
            result: available_from(
                "Docket",
                ReadCommandNameV1::DocketGovernedLoopInspect,
                inspection,
            ),
        });
    }
}

fn attach_demo_authoring_contexts(detail: &mut CampaignDetailV1, current: &OccurrenceSnapshotV1) {
    // Fixture-only exact relations for presentation qualification. Historical
    // occurrences retain their own owner record. Occurrence 2 is deliberately
    // left unlinked to pin that a successor never inherits a predecessor's
    // Maude context by convenience.
    let mut governed_occurrences = BTreeMap::new();
    if let Some(history) = detail.history.value() {
        for transition in &history.transitions {
            let snapshot = &transition.successor;
            if snapshot.proposal().is_some() {
                governed_occurrences
                    .entry(snapshot.key().occurrence)
                    .or_insert_with(|| snapshot.clone());
            }
        }
    }
    if current.proposal().is_some() {
        governed_occurrences.insert(current.key().occurrence, current.clone());
    }
    for governed in governed_occurrences.values() {
        let proposal = governed
            .proposal()
            .expect("governed authoring fixture has an exact proposal");
        let matches = if governed.key().occurrence.as_uuid().as_u128() == 2 {
            Vec::new()
        } else {
            let mut provenance = NightshiftAuthoringContextProvenanceV1 {
                schema: NIGHTSHIFT_AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1.to_owned(),
                provenance_id: String::new(),
                producer_component: "nightshift.canonical_runtime".to_owned(),
                maude_plan_ref: Digest::hash_bytes(b"operator-demo exact Maude plan").to_string(),
                maude_session_id: "sess_0123456789ab".to_owned(),
                source_plan_bytes: 30,
                campaign_id: governed.key().campaign.to_string(),
                occurrence_id: governed.key().occurrence.to_string(),
                proposal_id: proposal.reference().to_string(),
                exact_work_id: governed.state().meta().expected_work().to_string(),
                source_intent_id: digest("demo-nightshift-intent").to_string(),
                recorded_at: "2026-08-21T12:00:00Z".to_owned(),
            };
            let mut preimage = serde_json::to_value(&provenance).unwrap();
            preimage.as_object_mut().unwrap().remove("provenance_id");
            provenance.provenance_id = Digest::from_serializable(&preimage).unwrap().to_string();
            vec![provenance]
        };
        let export = NightshiftAuthoringContextExportV1 {
            schema: NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1.to_owned(),
            query: NightshiftAuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: governed.key().campaign.to_string(),
                occurrence_id: governed.key().occurrence.to_string(),
            },
            matches,
        };
        detail.authoring_contexts.push(RelatedSourceV1 {
            identity: format!("{}/{}", governed.key().campaign, governed.key().occurrence),
            result: available_from(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportAuthoringContext,
                export,
            ),
        });
    }
}

fn detail_at_transition(
    complete_history: &CampaignTransitionHistoryV1,
    index: usize,
    name: &str,
) -> CampaignDetailV1 {
    let current = complete_history.transitions[index].successor.clone();
    let mut history = complete_history.clone();
    history.transitions.truncate(index + 1);
    history.current_state_digest = current.state_digest().clone();
    let refusals = CampaignRefusalHistoryV1 {
        schema: CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1.to_owned(),
        campaign: current.key().campaign.clone(),
        verified_at_state_digest: current.state_digest().clone(),
        refusals: Vec::new(),
    };
    let mut detail = operator_detail(current, history, refusals);
    demo_locator(&mut detail, name);
    attach_demo_owner_sources(&mut detail);
    detail
}

fn demo_index_entry(detail: &CampaignDetailV1) -> CampaignIndexEntryV1 {
    CampaignIndexEntryV1 {
        locator_token: detail.locator_token.clone(),
        locator: detail.locator.clone(),
        inspect: detail.inspect.clone(),
        history: detail.history.clone(),
        refusals: detail.refusals.clone(),
        projection: detail.projection.clone(),
    }
}

fn canonical_demo_details() -> Vec<CampaignDetailV1> {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let _ = engine.poll_docket(&mut docket, NOW + 6).unwrap();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let _ = engine.poll_docket(&mut docket, NOW + 7).unwrap();
    let _ = engine
        .open_continuation(occurrence(2), digest("work-2"), NOW + 8)
        .unwrap();
    let _ = engine
        .complete(
            ObservationRefV1::from_digest(digest("terminal-observation")),
            &digest("subject"),
            TerminalWitnessRefV1::from_digest(digest("terminal-witness")),
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 9,
        )
        .unwrap();
    let history = engine.history().unwrap();
    history
        .transitions
        .iter()
        .enumerate()
        .map(|(index, transition)| {
            detail_at_transition(
                &history,
                index,
                &format!(
                    "lifecycle-{index:02}-{:?}",
                    transition.successor.program_counter()
                )
                .to_ascii_lowercase(),
            )
        })
        .collect()
}

fn successor_proposal_demo_detail() -> CampaignDetailV1 {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let _ = engine.poll_docket(&mut docket, NOW + 6).unwrap();
    let _ = engine
        .open_continuation(occurrence(2), digest("work-2"), NOW + 7)
        .unwrap();
    let _ = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-2"),
            ProposalClassV1::Successor,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 8,
        )
        .unwrap();
    let mut detail = operator_detail(
        engine.current().unwrap(),
        engine.history().unwrap(),
        engine.refusal_history().unwrap(),
    );
    demo_locator(&mut detail, "successor-own-proposal");
    attach_demo_owner_sources(&mut detail);
    detail
}

fn human_required_demo_detail() -> CampaignDetailV1 {
    let human_directory = tempfile::tempdir().unwrap();
    let mut human = create_engine(&human_directory, ResidualSetV1::default());
    human
        .record_refusal(
            RefusalCodeV1::HumanDecisionRequired,
            Some(digest("operator-escalation-evidence")),
            NOW + 1,
        )
        .unwrap();
    human
        .record_refusal(
            RefusalCodeV1::AbsentStanding,
            Some(digest("standing-source-unavailable")),
            NOW + 2,
        )
        .unwrap();
    human
        .halt(
            HaltReasonRefV1::from_digest(digest("human-required")),
            NOW + 3,
        )
        .unwrap();
    let mut human_detail = operator_detail(
        human.current().unwrap(),
        human.history().unwrap(),
        human.refusal_history().unwrap(),
    );
    demo_locator(&mut human_detail, "human-required-multiple-refusals");
    human_detail
}

fn budget_exhaustion_demo_detail() -> CampaignDetailV1 {
    let budget_directory = tempfile::tempdir().unwrap();
    let mut budget_engine = create_engine(&budget_directory, ResidualSetV1::default());
    budget_engine.note_probe(NOW + 1).unwrap();
    budget_engine.note_probe(NOW + 2).unwrap();
    let mut budget_detail = operator_detail(
        budget_engine.current().unwrap(),
        budget_engine.history().unwrap(),
        budget_engine.refusal_history().unwrap(),
    );
    demo_locator(&mut budget_detail, "budget-probe-exhaustion");
    budget_detail
}

fn add_source_problem_demo_variants(campaigns: &mut Vec<CampaignDetailV1>) {
    let dispatched_index = campaigns
        .iter()
        .position(|detail| {
            detail.inspect.value().is_some_and(|value| {
                value.current.program_counter() == ProgramCounterV1::Dispatched
            })
        })
        .unwrap();
    let reconciliation_index = campaigns
        .iter()
        .position(|detail| {
            detail.inspect.value().is_some_and(|value| {
                value.current.program_counter() == ProgramCounterV1::ReconciliationRequired
            })
        })
        .unwrap();
    let settled_index = campaigns
        .iter()
        .position(|detail| {
            detail.inspect.value().is_some_and(|value| {
                value.current.program_counter() == ProgramCounterV1::SettledObservationRequired
            })
        })
        .unwrap();

    let mut partial = campaigns[dispatched_index].clone();
    demo_locator(&mut partial, "partial-ag-history-unavailable");
    partial.history = unavailable_fixture(
        "AG",
        ReadCommandNameV1::AgHistory,
        SourceErrorKindV1::Unavailable,
        "fixture: verified journal source temporarily unavailable",
    );
    partial.projection = ProjectionCheckV1 {
        correspondence: ProjectionCorrespondenceV1::Partial,
        findings: vec!["AG history unavailable; no timeline was inferred".to_owned()],
    };
    campaigns.push(partial);

    let mut disagreement = campaigns[1].clone();
    demo_locator(&mut disagreement, "projection-disagreement-refused");
    disagreement.status = campaigns[2].status.clone();
    disagreement.history = campaigns[2].history.clone();
    disagreement.projection = ProjectionCheckV1 {
        correspondence: ProjectionCorrespondenceV1::Disagreement,
        findings: vec![
            "inspect and status/history name different current-state digests".to_owned(),
            "canonical AG projections disagree; no value was reconciled".to_owned(),
        ],
    };
    campaigns.push(disagreement);

    let mut docket_unavailable = campaigns[dispatched_index].clone();
    demo_locator(&mut docket_unavailable, "dispatched-docket-unavailable");
    docket_unavailable.docket.iter_mut().for_each(|related| {
        related.result = unavailable_fixture(
            "Docket",
            ReadCommandNameV1::DocketGovernedLoopInspect,
            SourceErrorKindV1::Unavailable,
            "fixture: Docket owner command unavailable; AG custody fact remains visible",
        );
    });
    campaigns.push(docket_unavailable);

    let mut malformed = campaigns[reconciliation_index].clone();
    demo_locator(&mut malformed, "reconciliation-docket-malformed");
    malformed.docket.iter_mut().for_each(|related| {
        related.result = unavailable_fixture(
            "Docket",
            ReadCommandNameV1::DocketGovernedLoopInspect,
            SourceErrorKindV1::MalformedOutput,
            "fixture: owner output was not one supported structured value",
        );
    });
    campaigns.push(malformed);

    let mut nightshift_unavailable = campaigns[settled_index].clone();
    demo_locator(
        &mut nightshift_unavailable,
        "settled-nightshift-unavailable",
    );
    nightshift_unavailable
        .nightshift
        .iter_mut()
        .for_each(|related| {
            related.result = unavailable_fixture(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportObservation,
                SourceErrorKindV1::CommandRefused,
                "fixture: Nightshift refused the read projection",
            );
        });
    campaigns.push(nightshift_unavailable);
}

fn add_named_lifecycle_demo_variants(campaigns: &mut Vec<CampaignDetailV1>) {
    for (source_index, label) in [
        (0, "new-empty-campaign"),
        (4, "authority-consumed-before-dispatch"),
        (5, "outcome-unknown-no-settlement"),
        (6, "reconciliation-exact-attempt"),
        (7, "settled-fresh-observation-block"),
        (8, "successor-after-fresh-observation"),
        (9, "multi-occurrence-complete-history"),
    ] {
        let mut copy = campaigns[source_index].clone();
        demo_locator(&mut copy, label);
        campaigns.push(copy);
    }
}

fn demo_semantic_link_targets(campaigns: &[CampaignDetailV1]) -> Vec<DemoSemanticLinkTargetV1> {
    let target = campaigns
        .iter()
        .find(|detail| detail.locator == "multi-occurrence-complete-history.sqlite")
        .expect("complete-history demo capture exists");
    let history = target.history.value().expect("demo history is available");
    let mut latest_by_occurrence = BTreeMap::new();
    for transition in &history.transitions {
        latest_by_occurrence.insert(transition.successor.key().occurrence, &transition.successor);
    }
    let mut links = Vec::new();
    for (occurrence, snapshot) in latest_by_occurrence {
        links.push(DemoSemanticLinkTargetV1 {
            campaign: snapshot.key().campaign.clone(),
            occurrence,
            proposal: None,
            locator_token: target.locator_token.clone(),
        });
        if let Some(proposal) = snapshot.proposal() {
            links.push(DemoSemanticLinkTargetV1 {
                campaign: snapshot.key().campaign.clone(),
                occurrence,
                proposal: Some(proposal.reference()),
                locator_token: target.locator_token.clone(),
            });
        }
    }
    let successor = campaigns
        .iter()
        .find(|detail| detail.locator == "successor-own-proposal.sqlite")
        .expect("successor proposal demo capture exists");
    let successor_snapshot = &successor
        .inspect
        .value()
        .expect("successor proposal inspect is available")
        .current;
    links.push(DemoSemanticLinkTargetV1 {
        campaign: successor_snapshot.key().campaign.clone(),
        occurrence: successor_snapshot.key().occurrence,
        proposal: Some(
            successor_snapshot
                .proposal()
                .expect("successor proposal is recorded")
                .reference(),
        ),
        locator_token: successor.locator_token.clone(),
    });
    links
}

fn build_operator_demo_corpus() -> DemoCorpusV1 {
    let mut campaigns = canonical_demo_details();
    campaigns.push(successor_proposal_demo_detail());
    campaigns.push(human_required_demo_detail());
    campaigns.push(budget_exhaustion_demo_detail());
    add_source_problem_demo_variants(&mut campaigns);
    add_named_lifecycle_demo_variants(&mut campaigns);
    let semantic_link_targets = demo_semantic_link_targets(&campaigns);

    let index = CampaignIndexV1 {
        schema: CAMPAIGN_INDEX_SCHEMA_V1.to_owned(),
        campaigns: campaigns.iter().map(demo_index_entry).collect(),
    };
    DemoCorpusV1 {
        schema: DEMO_CORPUS_SCHEMA_V1.to_owned(),
        generated_by: "ag-app governed_loop_engine production-engine fixtures".to_owned(),
        canonical_schemas: vec![
            "ag.governed-loop.operational-snapshot/v1".to_owned(),
            CAMPAIGN_TRANSITION_HISTORY_SCHEMA_V1.to_owned(),
            CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1.to_owned(),
            NIGHTSHIFT_OBSERVATION_EXPORT_SCHEMA_V1.to_owned(),
            NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1.to_owned(),
            NIGHTSHIFT_AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1.to_owned(),
            DOCKET_INSPECTION_SCHEMA_V1.to_owned(),
        ],
        index,
        campaigns,
        semantic_link_targets,
    }
}

fn assert_successor_semantic_link(
    corpus: &DemoCorpusV1,
    reader: &OperatorReaderV1,
) -> GovernedRuntimeLinkV1 {
    let proposal_targets = corpus
        .semantic_link_targets
        .iter()
        .filter(|target| target.proposal.is_some())
        .collect::<Vec<_>>();
    assert_eq!(proposal_targets.len(), 2);
    assert_ne!(
        proposal_targets[0].occurrence,
        proposal_targets[1].occurrence
    );
    assert_ne!(proposal_targets[0].proposal, proposal_targets[1].proposal);
    let successor = proposal_targets
        .iter()
        .find(|target| target.occurrence == occurrence(2))
        .expect("successor occurrence has its own proposal link");
    let link = GovernedRuntimeLinkV1 {
        campaign: successor.campaign.as_digest().clone(),
        occurrence: successor.occurrence,
        proposal: successor
            .proposal
            .as_ref()
            .map(|proposal| proposal.as_digest().clone()),
    };
    let detail = reader.campaign_detail_for_link(&link).unwrap();
    let snapshot = selected_snapshot(&detail, &link).unwrap();
    assert_eq!(snapshot.key().occurrence, occurrence(2));
    assert_eq!(
        snapshot.proposal().unwrap().reference(),
        successor.proposal.clone().unwrap()
    );
    assert_eq!(snapshot.state().meta().expected_work(), &digest("work-2"));
    link
}

#[test]
#[ignore = "writes a deterministic operator presentation corpus to an explicit path"]
fn write_operator_demo_corpus_from_production_engine_fixtures() {
    let destination = std::env::var_os("AG_OPERATOR_DEMO_OUTPUT")
        .expect("AG_OPERATOR_DEMO_OUTPUT must name the output file");
    let corpus = build_operator_demo_corpus();
    assert!(corpus.campaigns.len() >= 20);
    let bytes = serde_json::to_vec_pretty(&corpus).unwrap();
    std::fs::write(destination, bytes).unwrap();
}

fn assert_demo_semantic_links(corpus: &DemoCorpusV1, reader: &OperatorReaderV1) {
    assert!(corpus.semantic_link_targets.len() >= 4);
    assert_eq!(
        corpus
            .semantic_link_targets
            .iter()
            .map(|target| target.occurrence)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    for target in &corpus.semantic_link_targets {
        let link = GovernedRuntimeLinkV1 {
            campaign: target.campaign.as_digest().clone(),
            occurrence: target.occurrence,
            proposal: target
                .proposal
                .as_ref()
                .map(|proposal| proposal.as_digest().clone()),
        };
        let detail = reader.campaign_detail_for_link(&link).unwrap();
        let selected = selected_snapshot(&detail, &link).unwrap();
        assert_eq!(selected.key().campaign, target.campaign);
        assert_eq!(selected.key().occurrence, target.occurrence);
        if let Some(proposal) = &target.proposal {
            assert_eq!(selected.proposal().unwrap().reference(), *proposal);
        }
        let html =
            render::campaign_detail_for_link_with_context(&detail, reader.mode_label(), &link);
        assert!(html.contains("semantic links carry identities, never authority"));
        if target.proposal.is_some() {
            if target.occurrence == occurrence(2) {
                assert!(html.contains("authoring context not recorded"));
                assert!(!html.contains("canonical Nightshift lineage"));
            } else {
                assert!(html.contains("canonical Nightshift lineage"));
                assert!(html.contains("Lineage, not permission"));
            }
        }
    }
    assert!(corpus.semantic_link_targets.iter().any(|target| {
        let link = GovernedRuntimeLinkV1 {
            campaign: target.campaign.as_digest().clone(),
            occurrence: target.occurrence,
            proposal: target
                .proposal
                .as_ref()
                .map(|proposal| proposal.as_digest().clone()),
        };
        let detail = reader.campaign_detail_for_link(&link).unwrap();
        render::campaign_detail_for_link_with_context(&detail, reader.mode_label(), &link)
            .contains("historical occurrence")
    }));
    let historical = corpus
        .semantic_link_targets
        .iter()
        .find(|target| target.proposal.is_some())
        .unwrap();
    let historical_link = GovernedRuntimeLinkV1 {
        campaign: historical.campaign.as_digest().clone(),
        occurrence: historical.occurrence,
        proposal: historical
            .proposal
            .as_ref()
            .map(|proposal| proposal.as_digest().clone()),
    };
    let detail = reader.campaign_detail_for_link(&historical_link).unwrap();
    assert_ne!(
        selected_snapshot(&detail, &historical_link)
            .unwrap()
            .key()
            .occurrence,
        detail.inspect.value().unwrap().current.key().occurrence
    );
    let _ = assert_successor_semantic_link(corpus, reader);
    let substituted = GovernedRuntimeLinkV1 {
        proposal: Some(digest("unrelated-authoring-proposal")),
        ..historical_link
    };
    assert!(reader.campaign_detail_for_link(&substituted).is_err());
}

#[test]
fn operator_demo_corpus_round_trips_through_the_bounded_typed_reader() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operator-demo.json");
    let corpus = build_operator_demo_corpus();
    std::fs::write(&path, serde_json::to_vec(&corpus).unwrap()).unwrap();
    let reader = OperatorReaderV1::from_demo_corpus(&path).unwrap();
    let index = reader.campaign_index().unwrap();
    assert_eq!(index.campaigns.len(), corpus.campaigns.len());
    assert!(index.campaigns.len() >= 20);

    let mut counters = Vec::new();
    for entry in &index.campaigns {
        let detail = reader.campaign_detail(&entry.locator_token).unwrap();
        let html = render::campaign_detail_with_context(&detail, reader.mode_label());
        assert!(html.contains("deterministic demo corpus"));
        assert!(html.contains("Raw canonical data and source diagnostics"));
        if let Some(inspect) = detail.inspect.value() {
            let counter = inspect.current.program_counter();
            if !counters.contains(&counter) {
                counters.push(counter);
            }
        }
    }
    assert_eq!(counters.len(), 10);
    assert!(index.campaigns.iter().any(|entry| {
        entry.projection.correspondence == ProjectionCorrespondenceV1::Disagreement
    }));
    assert!(
        index.campaigns.iter().any(|entry| {
            entry.projection.correspondence == ProjectionCorrespondenceV1::Partial
        })
    );

    assert_demo_semantic_links(&corpus, &reader);
}

fn assert_human_required_halt_view() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    engine
        .record_refusal(
            RefusalCodeV1::HumanDecisionRequired,
            Some(digest("operator-escalation-evidence")),
            NOW + 1,
        )
        .unwrap();
    engine
        .halt(
            HaltReasonRefV1::from_digest(digest("human-required")),
            NOW + 2,
        )
        .unwrap();
    let history = engine.history().unwrap();
    let refusals = engine.refusal_history().unwrap();
    assert_eq!(refusals.schema, CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1);
    let html = render::campaign_detail(&operator_detail(
        engine.current().unwrap(),
        history,
        refusals,
    ));
    assert!(html.contains("Halted"));
    assert!(html.contains("HumanDecisionRequired"));
    assert!(html.contains("non-authorizing facts"));
}

fn advance_to_spent(
    engine: &mut CampaignEngineV1,
    observation: &mut ObservationBoundary,
    standing: &mut StandingBoundary,
) -> OccurrenceSnapshotV1 {
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine
        .decide(
            observation,
            standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    engine
        .authorize(
            observation,
            standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap()
}

#[test]
fn recording_a_proposal_is_informational_and_evaluates_no_catalog_policy() {
    // REGRESSION PIN (WO-1, pre-change semantics): proposal existence does
    // not imply admissibility. `record_proposal` takes no catalog/policy
    // input at all: evidence health is resolved, but no admissibility or
    // workflow-policy judgment is possible during recording, no authority
    // artifact is minted, and the occurrence does not advance past
    // ProposalRecorded. The first policy judgment happens at `decide`.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();

    let recorded = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(
        recorded.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    assert!(recorded.ag_spend().is_none());
    assert!(recorded.issuance().is_none());
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
    assert_eq!(observation.calls, 1);

    // A catalog that refuses this exact work is only consulted now, at
    // `decide`; its refusal cannot retroactively un-record the proposal and
    // preserves the current state.
    engine.require_standing(NOW + 2).unwrap();
    let before = engine.current().unwrap();
    assert!(
        engine
            .decide(
                &mut observation,
                &mut standing,
                &refusing_catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 3,
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);

    // The identical recorded proposal is admitted once the consulted policy
    // matches: recording was never the gate.
    let admitted = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    assert_eq!(
        admitted.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    assert!(admitted.ag_spend().is_none());
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn production_path_spends_once_settles_and_requires_a_new_occurrence() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let spent = advance_to_spent(&mut engine, &mut observation, &mut standing);
    assert_eq!(
        spent.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert!(observation.calls >= 3);
    assert_eq!(standing.calls, 2);

    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    assert_eq!(dispatched.program_counter(), ProgramCounterV1::Dispatched);
    assert_eq!(docket.accept_calls(), 1);
    assert!(engine.dispatch(&mut docket, NOW + 6).is_err());
    assert_eq!(docket.accept_calls(), 1);

    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut docket, NOW + 7).unwrap()
    else {
        panic!("known outcome must settle")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert!(
        engine
            .authorize(
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 8
            )
            .is_err()
    );

    let next = engine
        .open_continuation(occurrence(2), digest("work-1"), NOW + 9)
        .unwrap();
    assert_eq!(
        next.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert_ne!(next.key().occurrence, spent.key().occurrence);
    assert!(next.ag_spend().is_none());
    assert_eq!(engine.replay().unwrap().docket_attempts, 1);
    assert_eq!(engine.replay().unwrap().settlements, 1);
}

#[test]
fn operator_views_render_every_canonical_counter_from_real_persisted_history() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let _ = engine.poll_docket(&mut docket, NOW + 6).unwrap();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let _ = engine.poll_docket(&mut docket, NOW + 7).unwrap();
    let successor = engine
        .open_continuation(occurrence(2), digest("work-2"), NOW + 8)
        .unwrap();
    assert_ne!(successor.key().occurrence, occurrence(1));
    let _ = engine
        .complete(
            ObservationRefV1::from_digest(digest("terminal-observation")),
            &digest("subject"),
            TerminalWitnessRefV1::from_digest(digest("terminal-witness")),
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 9,
        )
        .unwrap();

    let complete_history = engine.history().unwrap();
    assert_eq!(
        complete_history.schema,
        CAMPAIGN_TRANSITION_HISTORY_SCHEMA_V1
    );
    let counters = complete_history
        .transitions
        .iter()
        .map(|transition| transition.successor.program_counter())
        .collect::<Vec<_>>();
    for expected in [
        ProgramCounterV1::ObservationRequired,
        ProgramCounterV1::ProposalRecorded,
        ProgramCounterV1::StandingRequired,
        ProgramCounterV1::AdmissiblePendingAuthorization,
        ProgramCounterV1::AuthorizationConsumed,
        ProgramCounterV1::Dispatched,
        ProgramCounterV1::ReconciliationRequired,
        ProgramCounterV1::SettledObservationRequired,
        ProgramCounterV1::Completed,
    ] {
        assert!(counters.contains(&expected), "missing {expected:?}");
    }

    for (index, transition) in complete_history.transitions.iter().enumerate() {
        let current = transition.successor.clone();
        let mut history = complete_history.clone();
        history.transitions.truncate(index + 1);
        history.current_state_digest = current.state_digest().clone();
        let refusals = CampaignRefusalHistoryV1 {
            schema: CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1.to_owned(),
            campaign: current.key().campaign.clone(),
            verified_at_state_digest: current.state_digest().clone(),
            refusals: Vec::new(),
        };
        let html = render::campaign_detail(&operator_detail(current.clone(), history, refusals));
        assert!(html.contains(&format!("{:?}", current.program_counter())));
        match current.program_counter() {
            ProgramCounterV1::AuthorizationConsumed => {
                assert!(html.contains("spent and cannot be reused"));
            }
            ProgramCounterV1::Dispatched => {
                assert!(html.contains("outcome unknown"));
                assert!(html.contains("Absence of a receipt is not failure"));
            }
            ProgramCounterV1::ReconciliationRequired => {
                assert!(html.contains("Repeat dispatch is not authorized"));
            }
            ProgramCounterV1::SettledObservationRequired => {
                assert!(html.contains("fresh independent observation is required"));
            }
            ProgramCounterV1::Completed => {
                assert!(html.contains("completed:"));
                assert!(
                    html.contains(
                        current
                            .completed()
                            .unwrap()
                            .terminal_observation()
                            .observation()
                            .as_str()
                    )
                );
            }
            _ => {}
        }
    }

    assert_human_required_halt_view();
}

#[test]
fn consequence_time_stale_observation_and_revoked_standing_do_not_spend() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    let before = engine.current().unwrap();

    observation.status = ObservationStatusV1::Stale;
    assert!(
        engine
            .authorize(
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 4
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);

    observation.status = ObservationStatusV1::Current;
    standing.status = StandingStatusV1::Revoked;
    assert!(
        engine
            .authorize(
                &mut observation,
                &mut standing,
                &catalog(),
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 5
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn custody_crash_recovers_to_reconciliation_without_respend_or_repeat() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let spent = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let issuance = spent.issuance().unwrap().issuance.clone();

    let mut docket = FakeDocket::default();
    docket.set_panic_after_accept();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = engine.dispatch(&mut docket, NOW + 5);
        }))
        .is_err()
    );
    drop(engine);

    let mut recovered = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        recovered.current().unwrap().program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    let CampaignRecoveryV1::Advanced(reconciling) =
        recovered.recover(&mut docket, NOW + 6).unwrap()
    else {
        panic!("known custody must advance recovery")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert_eq!(docket.accept_calls(), 1);
    assert_eq!(recovered.replay().unwrap().ag_spends, 1);
    assert_eq!(recovered.replay().unwrap().docket_attempts, 1);

    docket.settle(&issuance, KnownOutcomeV1::Failure);
    let CampaignRecoveryV1::Advanced(settled) = recovered.recover(&mut docket, NOW + 7).unwrap()
    else {
        panic!("exact reconciliation must settle")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(recovered.replay().unwrap().settlements, 1);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one restart matrix keeps every consequence boundary visibly in one witness"
)]
fn restart_at_each_consequence_boundary_preserves_pc_and_never_recreates_authority() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    let mut observation = ObservationBoundary::current(clean_basis());
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    engine.require_standing(NOW + 2).unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::StandingRequired
    );
    let mut standing = StandingBoundary::current();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    engine
        .authorize(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    drop(engine);

    let mut docket = FakeDocket::default();
    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert!(matches!(
        engine.recover(&mut docket, NOW + 5).unwrap(),
        CampaignRecoveryV1::IssuanceNotAccepted(_)
    ));
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    let dispatched = engine.dispatch(&mut docket, NOW + 6).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::Dispatched
    );
    let CampaignRecoveryV1::Advanced(reconciling) = engine.recover(&mut docket, NOW + 7).unwrap()
    else {
        panic!("accepted attempt must recover into explicit reconciliation")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert_eq!(docket.accept_calls(), 1);
    drop(engine);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    let CampaignRecoveryV1::Advanced(settled) = engine.recover(&mut docket, NOW + 8).unwrap()
    else {
        panic!("exact Docket settlement must close reconciliation")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert_eq!(engine.replay().unwrap().docket_attempts, 1);
    assert_eq!(engine.replay().unwrap().settlements, 1);
    drop(engine);

    engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    let next = engine
        .open_continuation(occurrence(2), digest("work-1"), NOW + 9)
        .unwrap();
    assert_eq!(
        next.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(next.ag_spend().is_none());
    assert!(next.docket_custody().is_none());
    assert_eq!(next.key().occurrence, occurrence(2));
}

#[test]
fn changed_preconditions_cannot_be_laundered_as_retry() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    docket.settle(
        &dispatched.issuance().unwrap().issuance,
        KnownOutcomeV1::Failure,
    );
    let _ = engine.poll_docket(&mut docket, NOW + 6).unwrap();
    engine
        .open_continuation(occurrence(2), digest("work-1"), NOW + 7)
        .unwrap();

    observation.basis = changed_basis();
    let error = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-1"),
            ProposalClassV1::Retry,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 8,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::RetryPreconditionsChanged)
    ));
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ObservationRequired
    );

    let successor = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal_with_schema("test.successor-work/v1", "work-1"),
            ProposalClassV1::Successor,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 9,
        )
        .unwrap();
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    assert_eq!(successor.key().occurrence, occurrence(2));
}

#[test]
fn indeterminate_attempt_blocks_repeat_until_exact_settlement() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) =
        engine.poll_docket(&mut docket, NOW + 6).unwrap()
    else {
        panic!("unknown outcome must reconcile")
    };
    assert_eq!(
        reconciling.program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert!(engine.dispatch(&mut docket, NOW + 7).is_err());
    assert!(
        engine
            .open_continuation(occurrence(2), digest("work-1"), NOW + 8)
            .is_err()
    );
    assert_eq!(docket.accept_calls(), 1);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut docket, NOW + 9).unwrap()
    else {
        panic!("reconciliation settlement must be consumed")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
}

#[test]
fn intervention_reconciliation_queries_only_exact_attempt_and_persists_result() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) =
        engine.poll_docket(&mut docket, NOW + 6).unwrap()
    else {
        panic!("unknown outcome must reconcile")
    };
    let custody = reconciling.docket_custody().unwrap();
    let request = intervention_request(
        &reconciling,
        GovernedInterventionClassV1::ReconcileAttempt {
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            evidence: vec![digest("operator-reconciliation-evidence")],
        },
        "reconcile-nonce",
    );
    let mut verifier = InterventionVerifier::default();

    // Insufficient evidence remains visibly indeterminate and never repeats dispatch.
    assert!(matches!(
        engine
            .request_reconciliation(
                request.clone(),
                &intervention_scope(),
                &mut verifier,
                &mut docket,
                NOW + 7,
            )
            .unwrap(),
        DocketProgressV1::ReconciliationRequired(_)
    ));
    assert_eq!(docket.accept_calls(), 1);
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ReconciliationRequired
    );
    assert_eq!(engine.refusal_history().unwrap().refusals.len(), 1);
    // Exact transport replay is an idempotent read and retains one canonical
    // outcome-unknown refusal rather than minting another request or dispatch.
    assert!(matches!(
        engine
            .request_reconciliation(
                request.clone(),
                &intervention_scope(),
                &mut verifier,
                &mut docket,
                NOW + 7,
            )
            .unwrap(),
        DocketProgressV1::ReconciliationRequired(_)
    ));
    assert_eq!(engine.refusal_history().unwrap().refusals.len(), 1);
    assert_eq!(docket.accept_calls(), 1);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine
        .request_reconciliation(
            request.clone(),
            &intervention_scope(),
            &mut verifier,
            &mut docket,
            NOW + 8,
        )
        .unwrap()
    else {
        panic!("exact Docket settlement must settle")
    };
    assert_eq!(docket.accept_calls(), 1);
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    let history = engine.history().unwrap();
    assert!(matches!(
        &history.transitions.last().unwrap().evidence,
        CampaignTransitionEvidenceV1::GovernedIntervention { verified }
            if verified.request == request
    ));

    drop(engine);
    let mut reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), settled);
    // The exact historical request cannot silently retarget or resettle.
    assert!(
        reopened
            .request_reconciliation(
                request,
                &intervention_scope(),
                &mut verifier,
                &mut docket,
                NOW + 9,
            )
            .is_err()
    );
    assert_eq!(docket.accept_calls(), 1);
}

#[test]
fn human_return_is_one_use_and_opens_only_an_authority_empty_occurrence() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("operator-required")),
            NOW + 1,
        )
        .unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ReturnToObservation,
        decision: HumanDecisionIdV1::from_digest(digest("decision")),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("nonce")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let HumanDispositionEffectV1::OpenedOccurrence {
        halted: consumed_halt,
        successor,
        ..
    } = engine
        .apply_human_disposition(
            artifact,
            &scope,
            Some(occurrence(2)),
            &mut ObservationBoundary::current(clean_basis()),
            OBSERVATION_RESOLVER_ID,
            &mut HumanVerifier,
            NOW + 2,
        )
        .unwrap()
    else {
        panic!("return disposition must open an occurrence")
    };
    assert_eq!(consumed_halt.program_counter(), ProgramCounterV1::Halted);
    assert_eq!(
        successor.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert!(successor.ag_spend().is_none());
    assert_eq!(successor.key().occurrence, occurrence(2));
    assert_eq!(engine.current().unwrap(), successor);
    assert_eq!(engine.replay().unwrap().transitions, 4);
    drop(engine);

    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), successor);
    assert_eq!(reopened.replay().unwrap().transitions, 4);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one residual witness keeps persistence and nonce attacks visibly adjacent"
)]
fn residual_discharge_is_exact_durable_and_nonce_one_shot() {
    let directory = tempfile::tempdir().unwrap();
    let residual = ResidualObligationV1 {
        residual: ResidualIdV1::from_digest(digest("residual-1")),
        owner: digest("residual-owner"),
        subject: digest("residual-subject"),
        statement: digest("residual-statement"),
    };
    let mut engine = create_engine(
        &directory,
        ResidualSetV1::new(vec![residual.clone()]).unwrap(),
    );
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("residual-disposition-required")),
            NOW + 1,
        )
        .unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("residual-principal")),
        mandate: MandateRefV1::from_digest(digest("residual-mandate")),
    };
    let decision = HumanDecisionIdV1::from_digest(digest("residual-decision"));
    let nonce = HumanNonceRefV1::from_digest(digest("residual-nonce"));
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ExactResidualDisposition(ExactResidualDischargeV1 {
            campaign: campaign(),
            occurrence: occurrence(1),
            program: ProgramBasisRefV1::from_digest(digest("program")),
            authority: ResidualAuthorityRefV1::from_digest(digest("residual-authority")),
            disposition: decision.clone(),
            before: vec![residual.residual.clone()],
            authorized: vec![residual.residual.clone()],
            closed: vec![residual.residual.clone()],
            after: Vec::new(),
        }),
        decision,
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: nonce.clone(),
        expires_at_unix_ms: NOW + 1_000,
    };
    let HumanDispositionEffectV1::Updated {
        snapshot: cleared, ..
    } = engine
        .apply_human_disposition(
            artifact,
            &scope,
            None,
            &mut ObservationBoundary::current(clean_basis()),
            OBSERVATION_RESOLVER_ID,
            &mut HumanVerifier,
            NOW + 2,
        )
        .unwrap()
    else {
        panic!("exact residual discharge must remain halted")
    };
    assert!(cleared.state().meta().residuals().is_empty());
    assert_eq!(engine.replay().unwrap().human_dispositions, 1);

    let second_decision = HumanDecisionIdV1::from_digest(digest("second-decision"));
    let replayed_nonce = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: cleared.state_digest().clone(),
        disposition: HumanDispositionKindV1::ExactResidualDisposition(ExactResidualDischargeV1 {
            campaign: campaign(),
            occurrence: occurrence(1),
            program: ProgramBasisRefV1::from_digest(digest("program")),
            authority: ResidualAuthorityRefV1::from_digest(digest("residual-authority-2")),
            disposition: second_decision.clone(),
            before: Vec::new(),
            authorized: Vec::new(),
            closed: Vec::new(),
            after: Vec::new(),
        }),
        decision: second_decision,
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce,
        expires_at_unix_ms: NOW + 1_000,
    };
    assert!(
        engine
            .apply_human_disposition(
                replayed_nonce,
                &scope,
                None,
                &mut ObservationBoundary::current(clean_basis()),
                OBSERVATION_RESOLVER_ID,
                &mut HumanVerifier,
                NOW + 3,
            )
            .is_err()
    );
    assert_eq!(engine.current().unwrap(), cleared);
    assert_eq!(engine.replay().unwrap().human_dispositions, 1);
}

#[test]
fn durable_budget_fact_is_nonauthorizing_and_exhaustion_halts() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let observed = engine.note_probe(NOW + 1).unwrap();
    assert_eq!(
        observed.program_counter(),
        ProgramCounterV1::ObservationRequired
    );
    assert_eq!(observed.state().meta().budget().probes_used, 1);
    assert!(observed.ag_spend().is_none());

    let halted = engine.note_probe(NOW + 2).unwrap();
    assert_eq!(halted.program_counter(), ProgramCounterV1::Halted);
    assert_eq!(halted.state().meta().budget().probes_used, 1);
    assert!(halted.ag_spend().is_none());
    drop(engine);

    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.current().unwrap(), halted);
    assert_eq!(
        GovernedLoopKernelV1::recovery_requirement(&halted),
        RecoveryRequirementV1::ExternalDisposition
    );
}

#[test]
fn exact_reconciliation_and_settlement_replay_are_idempotent_but_substitution_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.make_indeterminate(&issuance);
    let DocketProgressV1::ReconciliationRequired(reconciling) =
        engine.poll_docket(&mut docket, NOW + 6).unwrap()
    else {
        panic!("indeterminate outcome must enter reconciliation")
    };
    let transition_count = engine.replay().unwrap().transitions;
    let replay = engine.poll_docket(&mut docket, NOW + 7).unwrap();
    assert_eq!(
        replay,
        DocketProgressV1::ReconciliationRequired(reconciling.clone())
    );
    assert_eq!(engine.replay().unwrap().transitions, transition_count);

    {
        let mut shared = docket.shared.lock().unwrap();
        let FakeAttemptState::Indeterminate(custody, mut evidence) =
            shared.attempts.get(&issuance).cloned().unwrap()
        else {
            unreachable!()
        };
        evidence.evidence = digest("substituted-unknown");
        evidence.reconciliation =
            ReconciliationRefV1::from_digest(digest("substituted-reconciliation"));
        shared.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Indeterminate(custody, evidence),
        );
    }
    assert!(engine.poll_docket(&mut docket, NOW + 8).is_err());
    assert_eq!(engine.current().unwrap(), reconciling);

    docket.settle(&issuance, KnownOutcomeV1::Success);
    let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut docket, NOW + 9).unwrap()
    else {
        panic!("known reconciliation must settle")
    };
    let settled_transition_count = engine.replay().unwrap().transitions;
    assert_eq!(
        engine.poll_docket(&mut docket, NOW + 10).unwrap(),
        DocketProgressV1::Settled(settled.clone())
    );
    assert_eq!(
        engine.replay().unwrap().transitions,
        settled_transition_count
    );

    {
        let mut shared = docket.shared.lock().unwrap();
        let FakeAttemptState::Settled(custody, mut settlement) =
            shared.attempts.get(&issuance).cloned().unwrap()
        else {
            unreachable!()
        };
        settlement.receipt = ReceiptRefV1::from_digest(digest("substituted-receipt"));
        shared.attempts.insert(
            issuance.clone(),
            FakeAttemptState::Settled(custody, settlement),
        );
    }
    assert!(engine.poll_docket(&mut docket, NOW + 11).is_err());
    assert_eq!(engine.current().unwrap(), settled);
}

#[test]
fn human_disposition_binding_attacks_and_direct_dispatch_refuse_without_transition() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("human-required")),
            NOW + 1,
        )
        .unwrap();
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ReturnToObservation,
        decision: HumanDecisionIdV1::from_digest(digest("binding-decision")),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("binding-nonce")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let attacks = [
        HumanDispositionV1 {
            campaign: CampaignId::from_digest(digest("wrong-campaign")),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            occurrence: occurrence(9),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            halted_state_digest: digest("wrong-halted-state"),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            principal: HumanPrincipalRefV1::from_digest(digest("wrong-principal")),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            mandate: MandateRefV1::from_digest(digest("wrong-mandate")),
            ..artifact.clone()
        },
        HumanDispositionV1 {
            expires_at_unix_ms: NOW + 1,
            ..artifact
        },
    ];
    for attack in attacks {
        assert!(
            engine
                .apply_human_disposition(
                    attack,
                    &scope,
                    Some(occurrence(2)),
                    &mut ObservationBoundary::current(clean_basis()),
                    OBSERVATION_RESOLVER_ID,
                    &mut HumanVerifier,
                    NOW + 2,
                )
                .is_err()
        );
        assert_eq!(engine.current().unwrap(), halted);
    }
    let mut docket = FakeDocket::default();
    assert!(engine.dispatch(&mut docket, NOW + 3).is_err());
    assert_eq!(docket.accept_calls(), 0);
    assert_eq!(engine.replay().unwrap().human_dispositions, 0);
}

#[test]
fn concurrent_settlement_ingestion_has_one_legal_successor() {
    #[derive(Clone)]
    struct BarrierDocket {
        response: DocketIssuanceReconciliationV1,
        barrier: Arc<Barrier>,
    }

    impl DocketCustodyPortV1 for BarrierDocket {
        fn accept_issuance(
            &mut self,
            _issuance: &AgIssuanceV1,
        ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
            unreachable!()
        }

        fn reconcile_issuance(
            &mut self,
            _issuance: &AgIssuanceV1,
        ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
            unreachable!()
        }

        fn reconcile_attempt(
            &mut self,
            _custody: &DocketCustodyV1,
        ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
            self.barrier.wait();
            Ok(self.response.clone())
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    let _ = advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    let issuance = dispatched.issuance().unwrap().issuance.clone();
    docket.settle(&issuance, KnownOutcomeV1::Success);
    let response = {
        let shared = docket.shared.lock().unwrap();
        FakeDocket::response_for(&shared, &issuance)
    };
    drop(engine);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let barrier = Arc::clone(&barrier);
        let response = response.clone();
        handles.push(std::thread::spawn(move || {
            let mut engine = CampaignEngineV1::open(&database).unwrap();
            engine
                .poll_docket(&mut BarrierDocket { response, barrier }, NOW + 6)
                .is_ok()
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| **result).count(), 1);
    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.replay().unwrap().settlements, 1);
    assert_eq!(
        reopened.current().unwrap().program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
}

#[test]
fn concurrent_authorization_consumes_exactly_one_ag_spend() {
    struct BarrierObservation {
        inner: ObservationBoundary,
        barrier: Arc<Barrier>,
    }

    impl ObservationResolverV1 for BarrierObservation {
        fn resolve_observation(
            &mut self,
            request: &ObservationResolutionRequestV1<'_>,
        ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
            self.barrier.wait();
            self.inner.resolve_observation(request)
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    drop(engine);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let mut engine = CampaignEngineV1::open(&database).unwrap();
            engine
                .authorize(
                    &mut BarrierObservation {
                        inner: ObservationBoundary::current(clean_basis()),
                        barrier,
                    },
                    &mut StandingBoundary::current(),
                    &catalog(),
                    None,
                    OBSERVATION_RESOLVER_ID,
                    STANDING_RESOLVER_ID,
                    MAX_STANDING_TTL_MS,
                    NOW + 4,
                )
                .is_ok()
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| **result).count(), 1);
    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
    assert_eq!(
        reopened.current().unwrap().program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
}

#[test]
fn concurrent_human_resume_consumes_one_disposition_and_opens_one_occurrence() {
    struct BarrierVerifier(Arc<Barrier>);

    impl HumanDispositionVerifierV1 for BarrierVerifier {
        fn verify_human_disposition(
            &mut self,
            request: &HumanDispositionVerificationRequestV1<'_>,
        ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1> {
            self.0.wait();
            Ok(HumanVerificationRefV1::from_digest(Digest::hash_domain(
                "ag-governed-engine-test/concurrent-human/v1",
                request.artifact.decision.as_str().as_bytes(),
            )))
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let halted = engine
        .halt(
            HaltReasonRefV1::from_digest(digest("human-required")),
            NOW + 1,
        )
        .unwrap();
    drop(engine);
    let scope = HumanAuthorityScopeV1 {
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("human-mandate")),
    };
    let artifact = HumanDispositionV1 {
        schema: HUMAN_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: campaign(),
        occurrence: occurrence(1),
        halted_state_digest: halted.state_digest().clone(),
        disposition: HumanDispositionKindV1::ReturnToObservation,
        decision: HumanDecisionIdV1::from_digest(digest("concurrent-decision")),
        principal: scope.principal.clone(),
        mandate: scope.mandate.clone(),
        nonce: HumanNonceRefV1::from_digest(digest("concurrent-nonce")),
        expires_at_unix_ms: NOW + 1_000,
    };
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let barrier = Arc::clone(&barrier);
        let artifact = artifact.clone();
        let scope = scope.clone();
        handles.push(std::thread::spawn(move || {
            let mut engine = CampaignEngineV1::open(&database).unwrap();
            engine
                .apply_human_disposition(
                    artifact,
                    &scope,
                    Some(occurrence(2)),
                    &mut ObservationBoundary::current(clean_basis()),
                    OBSERVATION_RESOLVER_ID,
                    &mut BarrierVerifier(barrier),
                    NOW + 2,
                )
                .is_ok()
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| **result).count(), 1);
    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(reopened.replay().unwrap().human_dispositions, 1);
    assert_eq!(reopened.current().unwrap().key().occurrence, occurrence(2));
    assert!(reopened.current().unwrap().ag_spend().is_none());
}

/// Records a proposal and advances to the standing-required boundary with
/// the given observation basis.
fn advance_to_standing_required<O: ObservationResolverV1>(
    engine: &mut CampaignEngineV1,
    observation: &mut O,
) {
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
}

#[test]
fn typed_basis_requires_the_explicit_exact_catalog_generation() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = TypedObservationBoundary::current(typed_basis("civil-basis-a"));
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let before = engine.current().unwrap();

    let error = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
    ));
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn typed_basis_cannot_bypass_the_occurrence_work_binding() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = TypedObservationBoundary::current(typed_basis("civil-basis-a"));
    let error = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("typed-observation")),
            proposal("substituted-work"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::BindingMismatch("prepared exact work"))
    ));
    assert_eq!(observation.calls, 0);
    assert_eq!(engine.replay().unwrap().transitions, 1);
}

#[test]
fn exact_typed_basis_catalog_admits_and_spends_once_without_atoms() {
    let expected = typed_basis("civil-basis-a");
    let catalog = typed_catalog(expected.clone());
    catalog.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = TypedObservationBoundary::current(expected);
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);

    let admitted = engine
        .decide_with_catalog_v2(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        admitted.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    assert_eq!(
        admitted.admission_decision().unwrap().policy_basis,
        catalog.policy_basis().unwrap()
    );
    observation.substitute_occurrence = Some(occurrence(99));
    let before = engine.current().unwrap();
    let error = engine
        .authorize_with_catalog_v2(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::OccurrenceMismatch)
    ));
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
    observation.substitute_occurrence = None;
    let spent = engine
        .authorize_with_catalog_v2(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    assert_eq!(
        spent.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert!(
        engine
            .authorize_with_catalog_v2(
                &mut observation,
                &mut standing,
                &catalog,
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 5,
            )
            .is_err()
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn exact_typed_catalog_rejects_consistent_type_or_identity_substitution() {
    let expected = typed_basis("civil-basis-a");
    let catalog = typed_catalog(expected);
    let substitutions = [
        typed_basis("civil-basis-b"),
        TypedOpaqueObservationBasisV1::new(
            "foreign.managed-file-basis/v1".to_owned(),
            digest("civil-basis-a"),
        )
        .unwrap(),
    ];

    for substituted in substitutions {
        let directory = tempfile::tempdir().unwrap();
        let mut engine = create_engine(&directory, ResidualSetV1::default());
        let mut observation = TypedObservationBoundary::current(substituted);
        let mut standing = StandingBoundary::current();
        advance_to_standing_required(&mut engine, &mut observation);
        let before = engine.current().unwrap();
        let error = engine
            .decide_with_catalog_v2(
                &mut observation,
                &mut standing,
                &catalog,
                None,
                OBSERVATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                NOW + 3,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
        ));
        assert_eq!(engine.current().unwrap(), before);
        assert_eq!(engine.replay().unwrap().ag_spends, 0);
    }
}

fn repository_basis() -> TypedOpaqueObservationBasisV1 {
    TypedOpaqueObservationBasisV1::new(
        REPOSITORY_QUALIFICATION_BASIS_TYPE.to_owned(),
        digest("exact-replayed-nq-receipt-and-nightshift-applicability"),
    )
    .unwrap()
}

fn advance_repository_specimen(
    engine: &mut CampaignEngineV1,
    observation: &mut RepositoryQualificationBoundary,
) {
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("repository-qualification-observation")),
            proposal("work-1"),
            ProposalClassV1::Initial,
            observation,
            REPOSITORY_QUALIFICATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
}

#[test]
fn repository_qualification_basis_authorizes_only_the_predeclared_exact_successor() {
    let expected = repository_basis();
    let catalog = typed_catalog(expected.clone());
    catalog.validate().unwrap();

    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = RepositoryQualificationBoundary::current(expected.clone());
    let mut standing = StandingBoundary::current();
    advance_repository_specimen(&mut engine, &mut observation);
    engine
        .decide_with_catalog_v2(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            REPOSITORY_QUALIFICATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    let authorized = engine
        .authorize_with_catalog_v2(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            REPOSITORY_QUALIFICATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    assert_eq!(authorized.program_counter(), ProgramCounterV1::AuthorizationConsumed);
    assert_eq!(engine.replay().unwrap().ag_spends, 1);

    for case in ["type", "profile", "occurrence", "observation", "subject", "resolver", "stale"] {
        let directory = tempfile::tempdir().unwrap();
        let mut engine = create_engine(&directory, ResidualSetV1::default());
        let mut boundary = RepositoryQualificationBoundary::current(expected.clone());
        let mut standing = StandingBoundary::current();
        advance_repository_specimen(&mut engine, &mut boundary);
        match case {
            "type" => boundary.basis = TypedOpaqueObservationBasisV1::new(
                "worker.asserted-qualified/v1".to_owned(), expected.basis_identity.clone()).unwrap(),
            "profile" => boundary.basis = TypedOpaqueObservationBasisV1::new(
                REPOSITORY_QUALIFICATION_BASIS_TYPE.to_owned(),
                digest("substituted-applicability-profile")).unwrap(),
            "occurrence" => boundary.substitute_occurrence = Some(occurrence(99)),
            "observation" => boundary.substitute_observation = Some(
                ObservationRefV1::from_digest(digest("worker-self-asserted-observation"))),
            "subject" => boundary.substitute_subject = Some(digest("other-subject")),
            "resolver" => boundary.resolver_id = "controller.self-qualification/v1".to_owned(),
            "stale" => boundary.status = TypedObservationStatusV1::Stale,
            _ => unreachable!(),
        }
        let before = engine.current().unwrap();
        assert!(engine.decide_with_catalog_v2(
            &mut boundary, &mut standing, &catalog, None,
            REPOSITORY_QUALIFICATION_RESOLVER_ID, STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS, NOW + 3).is_err(), "{case}");
        assert_eq!(engine.current().unwrap(), before, "{case}");
        assert_eq!(engine.replay().unwrap().ag_spends, 0, "{case}");
    }

    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut boundary = RepositoryQualificationBoundary::current(expected);
    assert!(engine.record_proposal(
        ObservationRefV1::from_digest(digest("repository-qualification-observation")),
        proposal("worker-substituted-work"), ProposalClassV1::Initial, &mut boundary,
        REPOSITORY_QUALIFICATION_RESOLVER_ID, NOW + 1).is_err());
    assert_eq!(boundary.calls, 0);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);

    for source in [include_str!("../src/governed_loop.rs"), include_str!("../../ag-campaign/src/governed.rs")] {
        for forbidden in ["nq.campaign-stage-qualification", "NqQualificationStatus", "ordered_gates"] {
            assert!(!source.contains(forbidden));
        }
    }
}

#[test]
fn external_nq_nightshift_resolution_authorizes_the_exact_catalog_entry() {
    let Ok(path) = std::env::var("Q4_RESOLUTION_INPUT") else {
        eprintln!("Q4 cross-office specimen not requested");
        return;
    };
    let resolution: ObservationResolutionV3 =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(resolution.schema, OBSERVATION_RESOLUTION_SCHEMA_V3);
    assert_eq!(resolution.resolver_id, REPOSITORY_QUALIFICATION_RESOLVER_ID);
    assert_eq!(resolution.basis.basis_type, REPOSITORY_QUALIFICATION_BASIS_TYPE);
    assert_eq!(resolution.key.campaign, campaign());
    assert_eq!(resolution.key.occurrence, occurrence(1));
    assert_eq!(resolution.subject, digest("subject"));
    assert_eq!(resolution.status, TypedObservationStatusV1::Current);

    let catalog = typed_catalog(resolution.basis.clone());
    let observation_ref = resolution.observation.clone();
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = FixedRepositoryQualificationResolution(resolution);
    let mut standing = StandingBoundary::current();
    engine.record_proposal(
        observation_ref, proposal("work-1"), ProposalClassV1::Initial,
        &mut observation, REPOSITORY_QUALIFICATION_RESOLVER_ID, NOW + 1).unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine.decide_with_catalog_v2(
        &mut observation, &mut standing, &catalog, None,
        REPOSITORY_QUALIFICATION_RESOLVER_ID, STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS, NOW + 3).unwrap();
    let authorized = engine.authorize_with_catalog_v2(
        &mut observation, &mut standing, &catalog, None,
        REPOSITORY_QUALIFICATION_RESOLVER_ID, STANDING_RESOLVER_ID,
        MAX_STANDING_TTL_MS, NOW + 4).unwrap();
    assert_eq!(authorized.program_counter(), ProgramCounterV1::AuthorizationConsumed);
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn v2_catalog_schema_is_closed_and_v1_serialization_is_unchanged() {
    let v1 = catalog();
    let versioned = ag_app::governed_loop::VersionedExactWorkCatalogV1::NightshiftV1(v1.clone());
    assert_eq!(
        serde_json::to_vec(&versioned).unwrap(),
        serde_json::to_vec(&v1).unwrap()
    );

    let mut v2 = typed_catalog(typed_basis("civil-basis-a"));
    v2.schema = EXACT_WORK_CATALOG_SCHEMA_V1.to_owned();
    assert!(matches!(
        v2.validate(),
        Err(CampaignEngineErrorV1::InvalidCatalog)
    ));
}

#[test]
fn external_reservation_realization_authorizes_exactly_once() {
    let Ok(path) = std::env::var("VELVET_PIGEON_RESOLUTION_INPUT") else {
        eprintln!("VELVET-PIGEON cross-office specimen not requested");
        return;
    };
    let resolution: ObservationResolutionV3 =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        resolution.basis.basis_type,
        "nightshift.repository-qualification-reservation-applicability/v1"
    );
    assert_eq!(resolution.status, TypedObservationStatusV1::Current);
    assert_eq!(resolution.key.campaign, campaign());
    assert_eq!(resolution.key.occurrence, occurrence(1));
    assert_eq!(resolution.subject, digest("subject"));

    let catalog = typed_catalog(resolution.basis.clone());
    let observation_ref = resolution.observation.clone();
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = FixedRepositoryQualificationResolution(resolution);
    let mut standing = StandingBoundary::current();
    engine
        .record_proposal(
            observation_ref,
            proposal("work-1"),
            ProposalClassV1::Initial,
            &mut observation,
            REPOSITORY_QUALIFICATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap();
    engine.require_standing(NOW + 2).unwrap();
    engine.decide_with_catalog_v2(&mut observation, &mut standing, &catalog, None, REPOSITORY_QUALIFICATION_RESOLVER_ID, STANDING_RESOLVER_ID, MAX_STANDING_TTL_MS, NOW + 3).unwrap();
    let authorized = engine.authorize_with_catalog_v2(&mut observation, &mut standing, &catalog, None, REPOSITORY_QUALIFICATION_RESOLVER_ID, STANDING_RESOLVER_ID, MAX_STANDING_TTL_MS, NOW + 4).unwrap();
    assert_eq!(authorized.program_counter(), ProgramCounterV1::AuthorizationConsumed);
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn rollout_precondition_refuses_a_condition_present_basis() {
    // T8: a rollout-style policy (`required = {condition.clean}`) refuses the
    // same condition-present basis a remediation policy admits in T9. The
    // refusal is policy refusal, the occurrence state is preserved, and no
    // authority artifact exists.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(changed_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let before = engine.current().unwrap();

    let error = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog_with(precondition(&["condition.clean"], &[])),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
    ));
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn remediation_precondition_admits_the_same_condition_present_basis() {
    // T9: there is no universal Clean rule. A remediation-style policy whose
    // required atom is `condition.condition_present` admits exactly the basis
    // T8's rollout policy refused.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(changed_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);

    let remediation = catalog_with(precondition(&["condition.condition_present"], &[]));
    let admitted = engine
        .decide(
            &mut observation,
            &mut standing,
            &remediation,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        admitted.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    // The recorded policy basis is the content-derived identity of the exact
    // catalog evaluated, not a caller-chosen label.
    assert_eq!(
        admitted.admission_decision().unwrap().policy_basis,
        remediation.policy_basis().unwrap()
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn forbidden_delivery_atom_refuses() {
    // T10: `forbidden ∩ basis ≠ ∅` refuses even when required atoms match.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(failed_delivery_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let before = engine.current().unwrap();

    let error = engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog_with(precondition(&["condition.clean"], &["delivery.failed"])),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
    ));
    assert_eq!(engine.current().unwrap(), before);
}

#[test]
fn catalog_precondition_validation_rejects_overlap_and_unknown_atoms() {
    let overlap = catalog_with(precondition(&["condition.clean"], &["condition.clean"]));
    assert!(matches!(
        overlap.validate(),
        Err(CampaignEngineErrorV1::InvalidCatalog)
    ));
    let unknown = catalog_with(precondition(&["condition.perfectly_fine_honest"], &[]));
    assert!(matches!(
        unknown.validate(),
        Err(CampaignEngineErrorV1::InvalidCatalog)
    ));
    let unknown_forbidden = catalog_with(precondition(&[], &["delivery.mystery"]));
    assert!(matches!(
        unknown_forbidden.validate(),
        Err(CampaignEngineErrorV1::InvalidCatalog)
    ));
}

#[test]
fn omitted_precondition_is_unconditional_and_old_style_entries_parse() {
    // T11: an old-style three-field entry without `precondition` parses with
    // the defaulted unconditional Nightshift predicate. Typed opaque evidence
    // still requires an explicit v2 catalog entry.
    let document = format!(
        "{{\"schema\":\"ag.governed-loop.exact-work-catalog/v1\",\"entries\":{{\"test.engine-work/v1\":{{\"work_schema\":\"test.engine-work/v1\",\"subject\":\"{}\",\"scope\":\"{}\"}}}}}}",
        digest("subject"),
        digest("scope"),
    );
    let catalog: ExactWorkCatalogV1 = serde_json::from_str(&document).unwrap();
    catalog.validate().unwrap();
    assert_eq!(
        catalog.entries["test.engine-work/v1"].precondition,
        WorkPreconditionV1::default()
    );

    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(changed_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
}

#[test]
fn a_catalog_document_cannot_assert_a_policy_identity() {
    // The wire has no `policy_basis` channel: a document carrying one —
    // the substitution-attack shape — is rejected at parse time, before any
    // judgment can run.
    let document = format!(
        "{{\"schema\":\"ag.governed-loop.exact-work-catalog/v1\",\"policy_basis\":\"{}\",\"entries\":{{\"test.engine-work/v1\":{{\"work_schema\":\"test.engine-work/v1\",\"subject\":\"{}\",\"scope\":\"{}\"}}}}}}",
        digest("forged-policy-identity"),
        digest("subject"),
        digest("scope"),
    );
    assert!(serde_json::from_str::<ExactWorkCatalogV1>(&document).is_err());
}

#[test]
fn equivalent_catalogs_have_one_policy_basis_and_semantic_changes_move_it() {
    let reference = catalog_with(precondition(&["condition.clean"], &["delivery.failed"]));
    let expected = reference.policy_basis().unwrap();

    // Entry/atom construction order is not semantic.
    let reordered = ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            "test.engine-work/v1".to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: "test.engine-work/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                precondition: WorkPreconditionV1 {
                    required: BTreeSet::from(["condition.clean".to_owned()]),
                    forbidden: BTreeSet::from(["delivery.failed".to_owned()]),
                },
            },
        )]),
    };
    assert_eq!(reordered.policy_basis().unwrap(), expected);

    // Every admission-relevant field participates in the identity.
    let mut by_subject = reference.clone();
    by_subject
        .entries
        .values_mut()
        .for_each(|entry| entry.subject = digest("other-subject"));
    assert_ne!(by_subject.policy_basis().unwrap(), expected);
    let mut by_scope = reference.clone();
    by_scope
        .entries
        .values_mut()
        .for_each(|entry| entry.scope = digest("other-scope"));
    assert_ne!(by_scope.policy_basis().unwrap(), expected);
    let by_precondition = catalog_with(precondition(&["condition.clean"], &[]));
    assert_ne!(by_precondition.policy_basis().unwrap(), expected);
}

#[test]
fn tightened_catalog_before_spend_refuses_and_preserves_state() {
    // T13: catalog policy is present-tense at judgment. A proposal admitted
    // under unconditional V1 fails authorization once the current catalog
    // requires an atom its pinned basis does not contain. No spend occurs and
    // the occurrence remains admissible-pending.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    let before = engine.current().unwrap();

    let error = engine
        .authorize(
            &mut observation,
            &mut standing,
            &catalog_with(precondition(&["condition.condition_present"], &[])),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::Inadmissible)
    ));
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(
        before.program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn loosened_catalog_before_spend_spends_under_the_current_policy_basis() {
    // T14: a looser current catalog governs the spend. The authorization
    // provenance names the content-derived V2 policy basis, not the V1 basis
    // that governed `decide`.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let v1 = catalog_with(precondition(&["condition.clean"], &[]));
    let admitted = engine
        .decide(
            &mut observation,
            &mut standing,
            &v1,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        admitted.admission_decision().unwrap().policy_basis,
        v1.policy_basis().unwrap()
    );

    let v2 = catalog_with(WorkPreconditionV1::default());
    assert_ne!(v1.policy_basis().unwrap(), v2.policy_basis().unwrap());
    let spent = engine
        .authorize(
            &mut observation,
            &mut standing,
            &v2,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        )
        .unwrap();
    assert_eq!(
        spent.program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert_eq!(
        spent.admission_decision().unwrap().policy_basis,
        v2.policy_basis().unwrap()
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn precondition_participates_in_the_derived_policy_basis() {
    // Provenance load-bearing: changing only an entry's precondition changes
    // the policy identity that judgment provenance records.
    let unconditional = catalog();
    let conditional = catalog_with(precondition(&["condition.clean"], &[]));
    assert_ne!(
        unconditional.policy_basis().unwrap(),
        conditional.policy_basis().unwrap()
    );
}

#[test]
fn standing_resolver_unavailable_at_decide_or_authorize_fails_closed() {
    // The standing boundary is a live external dependency at both judgment
    // points: unavailability refuses without state loss and without spend.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    let before = engine.current().unwrap();

    standing.available = false;
    assert!(matches!(
        engine.decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        ),
        Err(CampaignEngineErrorV1::Kernel(KernelErrorV1::External(
            ExternalBoundaryErrorV1::Unavailable { .. }
        )))
    ));
    assert_eq!(engine.current().unwrap(), before);

    standing.available = true;
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    let admitted = engine.current().unwrap();

    standing.available = false;
    assert!(matches!(
        engine.authorize(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        ),
        Err(CampaignEngineErrorV1::Kernel(KernelErrorV1::External(
            ExternalBoundaryErrorV1::Unavailable { .. }
        )))
    ));
    assert_eq!(engine.current().unwrap(), admitted);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn revoked_standing_after_restart_still_blocks_spend() {
    // Fresh standing re-resolution at authorize is load-bearing across a
    // restart: the decide-time answer is never cached as sufficient.
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("campaign.sqlite");
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_standing_required(&mut engine, &mut observation);
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 3,
        )
        .unwrap();
    drop(engine);

    let mut engine = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    standing.status = StandingStatusV1::Revoked;
    assert!(matches!(
        engine.authorize(
            &mut observation,
            &mut standing,
            &catalog(),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            NOW + 4,
        ),
        Err(CampaignEngineErrorV1::Kernel(
            KernelErrorV1::StandingNotCurrent
        ))
    ));
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AdmissiblePendingAuthorization
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn record_proposal_rejects_unbound_work_before_any_resolution() {
    // The occurrence was opened to govern digest("work-1"). An otherwise
    // valid proposal naming work-2 fails the exact-work binding before the
    // observation resolver is consulted, with no state change and no spend.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    // `record_proposal` has no standing or catalog parameter at all: neither
    // can be consulted at record time.
    let before = engine.current().unwrap();
    let error = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-1")),
            proposal("work-2"),
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 1,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::BindingMismatch("prepared exact work"))
    ));
    assert_eq!(observation.calls, 0, "no observation resolution consulted");
    assert_eq!(engine.current().unwrap(), before);
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn each_occurrence_binds_its_own_expected_work() {
    // A continuation opened with a new expected-work binding refuses the
    // predecessor's exact work and records the newly bound work.
    let directory = tempfile::tempdir().unwrap();
    let mut engine = create_engine(&directory, ResidualSetV1::default());
    let mut observation = ObservationBoundary::current(clean_basis());
    let mut standing = StandingBoundary::current();
    advance_to_spent(&mut engine, &mut observation, &mut standing);
    let mut docket = FakeDocket::default();
    let dispatched = engine.dispatch(&mut docket, NOW + 5).unwrap();
    docket.settle(
        &dispatched.issuance().unwrap().issuance,
        KnownOutcomeV1::Success,
    );
    let _ = engine.poll_docket(&mut docket, NOW + 6).unwrap();
    engine
        .open_continuation(occurrence(2), digest("work-2"), NOW + 7)
        .unwrap();

    // The predecessor's bound work is foreign to this occurrence.
    let error = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-1"),
            ProposalClassV1::Successor,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 8,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignEngineErrorV1::Kernel(KernelErrorV1::BindingMismatch("prepared exact work"))
    ));
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::ObservationRequired
    );

    // The newly bound work records (as a successor, since its identity
    // differs from the predecessor's proposal).
    let recorded = engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation-2")),
            proposal("work-2"),
            ProposalClassV1::Successor,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            NOW + 9,
        )
        .unwrap();
    assert_eq!(
        recorded.program_counter(),
        ProgramCounterV1::ProposalRecorded
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn three_external_nq_nightshift_observations_each_authorize_exact_work() {
    let Ok(path) = std::env::var("GCL_V0_RESOLUTIONS_INPUT") else {
        eprintln!("GCL V0 AG cross-office specimen not requested");
        return;
    };
    let resolutions: Vec<ObservationResolutionV3> =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(resolutions.len(), 3);

    let mut basis_identities = BTreeSet::new();
    for (index, resolution) in resolutions.into_iter().enumerate() {
        assert_eq!(resolution.schema, OBSERVATION_RESOLUTION_SCHEMA_V3);
        assert_eq!(
            resolution.resolver_id,
            REPOSITORY_QUALIFICATION_RESOLVER_ID
        );
        assert_eq!(
            resolution.basis.basis_type,
            REPOSITORY_QUALIFICATION_BASIS_TYPE
        );
        assert_eq!(resolution.key.campaign, campaign());
        assert_eq!(resolution.key.occurrence, occurrence(1));
        assert_eq!(resolution.subject, digest("subject"));
        assert_eq!(resolution.status, TypedObservationStatusV1::Current);
        assert!(basis_identities.insert(resolution.basis.basis_identity.clone()));
        let now = resolution.resolved_at_unix_ms;

        let catalog = typed_catalog(resolution.basis.clone());
        let observation_ref = resolution.observation.clone();
        let directory = tempfile::tempdir().unwrap();
        let mut engine = create_engine(&directory, ResidualSetV1::default());
        let mut observation = FixedRepositoryQualificationResolution(resolution);
        let mut standing = StandingBoundary::current();
        engine
            .record_proposal(
                observation_ref,
                proposal("work-1"),
                ProposalClassV1::Initial,
                &mut observation,
                REPOSITORY_QUALIFICATION_RESOLVER_ID,
                now + 1,
            )
            .unwrap();
        engine.require_standing(now + 2).unwrap();
        engine
            .decide_with_catalog_v2(
                &mut observation,
                &mut standing,
                &catalog,
                None,
                REPOSITORY_QUALIFICATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                now + 3,
            )
            .unwrap();
        let authorized = engine
            .authorize_with_catalog_v2(
                &mut observation,
                &mut standing,
                &catalog,
                None,
                REPOSITORY_QUALIFICATION_RESOLVER_ID,
                STANDING_RESOLVER_ID,
                MAX_STANDING_TTL_MS,
                now + 4,
            )
            .unwrap();
        assert_eq!(
            authorized.program_counter(),
            ProgramCounterV1::AuthorizationConsumed
        );
        assert_eq!(
            engine.replay().unwrap().ag_spends,
            1,
            "stage {}",
            index + 1
        );
    }
}
