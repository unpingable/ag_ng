//! Typed read model and exact supported canonical source schemas.

use ag_campaign::CampaignId;
use ag_campaign::governed::{
    AgIssuanceV1, DocketCustodyV1, DocketSettlementV1, IndeterminateOutcomeV1, OccurrenceId,
    OccurrenceSnapshotV1, ProposalRefV1,
};
use ag_primitives::Digest;
use ag_store::campaign::{
    CampaignRefusalHistoryV1, CampaignReplayReportV1, CampaignTransitionHistoryV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Exact operator API schema for a campaign index.
pub const CAMPAIGN_INDEX_SCHEMA_V1: &str = "ag.operator-ui.campaign-index/v1";
/// Exact operator API schema for a campaign detail.
pub const CAMPAIGN_DETAIL_SCHEMA_V1: &str = "ag.operator-ui.campaign-detail/v1";
/// Exact supported AG inspection schema.
pub const AG_INSPECT_SCHEMA_V1: &str = "ag.governed-loop.operational-snapshot/v1";
/// Exact supported AG intervention-submission history schema.
pub const AG_INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-submission-history/v1";
/// Exact supported Nightshift observation-export schema.
pub const NIGHTSHIFT_OBSERVATION_EXPORT_SCHEMA_V1: &str = "nightshift.observation_export.v1";
/// Exact supported Nightshift authoring-context export schema.
pub const NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1: &str =
    "nightshift.authoring_context_export.v1";
/// Exact owner-minted authoring-context provenance schema.
pub const NIGHTSHIFT_AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1: &str =
    "nightshift.authoring_context_provenance.v1";
/// Exact supported authenticated custody export schema.
pub const NIGHTSHIFT_AUTHORING_CUSTODY_EXPORT_SCHEMA_V1: &str =
    "nightshift.authoring_context_custody_export.v1";
/// Exact Nightshift-minted custody provenance schema.
pub const NIGHTSHIFT_AUTHORING_CUSTODY_PROVENANCE_SCHEMA_V1: &str =
    "nightshift.authoring_context_custody_provenance.v1";
/// Exact supported Nightshift application/world-evidence export schema.
pub const NIGHTSHIFT_EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1: &str =
    "nightshift.external_observation_export.v1";
/// Exact owner-validated workflow-specific observation-candidate schema.
pub const NIGHTSHIFT_EXTERNAL_OBSERVATION_SCHEMA_V1: &str =
    "maude.local-compose-world-observation/v1";
/// Exact owner-minted custody record for one authenticated candidate.
pub const NIGHTSHIFT_EXTERNAL_OBSERVATION_CUSTODY_SCHEMA_V1: &str =
    "nightshift.external_observation_custody_provenance.v1";
/// Exact workflow-specific `PlanNode` claim schema.
pub const NIGHTSHIFT_EXTERNAL_OBSERVATION_CLAIM_SCHEMA_V1: &str =
    "maude.local-compose-world-claim/v1";
/// Exact supported Docket inspection schema.
pub const DOCKET_INSPECTION_SCHEMA_V1: &str = "docket.governed-loop.inspection/v1";
/// Exact schema for a deterministic, read-only presentation corpus.
pub const DEMO_CORPUS_SCHEMA_V1: &str = "ag.operator-ui.demo-corpus/v1";

/// Runtime-profile identity carried by AG inspection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfileBindingV1 {
    /// Exact profile schema.
    pub schema: String,
    /// Domain-separated profile identity.
    pub digest: Digest,
}

/// Typed AG `inspect` response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgInspectV1 {
    /// Exact inspection schema.
    pub schema: String,
    /// Authoritative current occurrence.
    pub current: OccurrenceSnapshotV1,
    /// Deterministic replay/accounting result from the same command.
    pub replay: CampaignReplayReportV1,
    /// Genesis-bound runtime-profile identity.
    pub runtime_profile: RuntimeProfileBindingV1,
}

/// One read-only immutable intervention-ingress receipt. The typed identity
/// and custody coordinates are exposed directly while the closed owner result
/// remains retained verbatim so Phosphor-ng cannot reinterpret it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionSubmissionReceiptProjectionV1 {
    /// Exact receipt schema.
    pub schema: String,
    /// Content-derived receipt identity.
    pub receipt: Digest,
    /// Exact submission identity when structurally available.
    pub submission: Option<Digest>,
    /// Digest of exact presented bytes.
    pub presentation_digest: Digest,
    /// Canonical request identity when structurally available.
    pub request: Option<Digest>,
    /// Target runtime-profile identity.
    pub target_runtime_profile: Option<Digest>,
    /// Authenticated submitting service, never authority.
    pub submitting_principal: Option<String>,
    /// Closed canonical owner result retained without UI inference.
    pub result: Value,
    /// Previous exact receipt in this submission chain.
    pub previous_receipt: Option<Digest>,
    /// Durable receipt time; not freshness authority.
    pub recorded_at_unix_ms: u64,
}

/// Verified read-only projection of the AG intervention ingress ledger.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionSubmissionHistoryProjectionV1 {
    /// Exact history schema.
    pub schema: String,
    /// Genesis-bound runtime-profile target.
    pub target_runtime_profile: Digest,
    /// Optional exact lookup selector.
    pub submission: Option<Digest>,
    /// Immutable receipts in durable order.
    pub receipts: Vec<InterventionSubmissionReceiptProjectionV1>,
}

/// Nightshift observation-family identity. Fields remain independent even
/// when their textual values happen to match.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftFamilyV1 {
    /// Policy identity.
    pub policy_id: String,
    /// Configuration version.
    pub configuration_version: String,
    /// Subject identity.
    pub subject_id: String,
    /// Scope identity.
    pub scope_id: String,
    /// Scheduler clock identity.
    pub scheduler_clock_id: String,
}

/// Nightshift logical slot order.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftOrderKeyV1 {
    /// Logical occurrence number.
    pub occurrence: u64,
    /// Declared nominal due time, retained verbatim.
    pub nominal_due_at: String,
    /// Exact slot identity.
    pub slot_id: String,
}

/// One exact Nightshift observation-export match. The observation record is
/// retained as raw canonical JSON because AG-NG deliberately does not own or
/// reinterpret Nightshift/NQ's evolving provenance vocabulary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftObservationMatchV1 {
    /// Nightshift cycle identity.
    pub cycle_id: String,
    /// Slot identity.
    pub slot_id: String,
    /// Exact five-dimensional family.
    pub family: NightshiftFamilyV1,
    /// Exact logical order.
    pub order_key: NightshiftOrderKeyV1,
    /// Latest qualified cycle in this family, if present.
    pub family_latest_cycle_id: Option<String>,
    /// Latest qualified logical order, if present.
    pub family_latest_order_key: Option<NightshiftOrderKeyV1>,
    /// Complete canonical observation record, including propagated NQ
    /// admission provenance when present.
    pub observation: Value,
}

/// Typed Nightshift `cycle export-observation` response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftObservationExportV1 {
    /// Exact export schema.
    pub schema: String,
    /// Requested observation identity.
    pub observation_id: String,
    /// Zero, one, or multiple exact matches; ambiguity is never collapsed.
    pub matches: Vec<NightshiftObservationMatchV1>,
}

/// Exact immutable Maude-to-governed-work relation exported by Nightshift.
/// The record is lineage only; the UI never presents it as authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftAuthoringContextProvenanceV1 {
    /// Record schema.
    pub schema: String,
    /// Plain SHA-256 of the canonical record excluding this field.
    pub provenance_id: String,
    /// Software boundary that minted the relation.
    pub producer_component: String,
    /// Exact content-derived Maude plan identity.
    pub maude_plan_ref: String,
    /// Exact Maude supervised-session identity presented at handoff.
    pub maude_session_id: String,
    /// Byte length of the independently rehashed source plan.
    pub source_plan_bytes: u64,
    /// Exact AG campaign identity.
    pub campaign_id: String,
    /// Exact AG occurrence identity.
    pub occurrence_id: String,
    /// Exact AG proposal identity.
    pub proposal_id: String,
    /// Exact executable-work identity.
    pub exact_work_id: String,
    /// Exact Nightshift typed-intent identity.
    pub source_intent_id: String,
    /// Handoff time evidence; never an identity matcher.
    pub recorded_at: String,
}

/// Closed query echoed by Nightshift. Phosphor-ng currently uses only the
/// exact governed-occurrence lookup; the other variants remain available in
/// retained raw data for Maude and operator debugging.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "by", rename_all = "snake_case", deny_unknown_fields)]
pub enum NightshiftAuthoringContextQueryV1 {
    /// Exact campaign/occurrence lookup.
    GovernedOccurrence {
        /// AG campaign identity.
        campaign_id: String,
        /// AG occurrence identity.
        occurrence_id: String,
    },
    /// Exact proposal lookup.
    Proposal {
        /// AG proposal identity.
        proposal_id: String,
    },
    /// Exact Maude plan/session lookup.
    MaudeContext {
        /// Content-derived plan identity.
        plan_ref: String,
        /// Supervised-session identity.
        session_id: String,
    },
}

/// Typed owner-side authoring-context export.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftAuthoringContextExportV1 {
    /// Export schema.
    pub schema: String,
    /// Exact echoed query.
    pub query: NightshiftAuthoringContextQueryV1,
    /// Zero or more exact immutable matches.
    pub matches: Vec<NightshiftAuthoringContextProvenanceV1>,
}

/// Authenticated producer/session delivery evidence. This is custody only;
/// no field is accepted as currentness, standing, authorization, or spend.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftAuthoringCustodyProvenanceV1 {
    /// Record schema.
    pub schema: String,
    /// Self-digest of every other persisted field.
    pub custody_id: String,
    /// Authenticated handoff identity.
    pub handoff_id: String,
    /// Maude supervised-session custody receipt identity.
    pub session_record_id: String,
    /// Exact separate lineage record identity.
    pub authoring_context_provenance_id: String,
    /// Bound AG campaign.
    pub campaign_id: String,
    /// Bound AG occurrence.
    pub occurrence_id: String,
    /// Bound AG proposal.
    pub proposal_id: String,
    /// Bound exact work.
    pub exact_work_id: String,
    /// Authenticated delivering principal.
    pub producer_principal_id: String,
    /// Pinned custody credential identity.
    pub producer_key_id: String,
    /// Principal that minted the independently authenticated supervised-session receipt.
    pub session_issuer_principal_id: String,
    /// Pinned credential identity for the supervised-session receipt.
    pub session_issuer_key_id: String,
    /// Intended Nightshift deployment identity.
    pub target_runtime_id: String,
    /// Exact pre-authoring cycle request identity.
    pub target_request_id: String,
    /// Bound Maude supervised-session identity.
    pub maude_session_id: String,
    /// Bound exact Maude plan bytes identity.
    pub maude_plan_ref: String,
    /// Authentication mechanism used at ingress.
    pub authentication_method: String,
    /// Caller-sealed cycle evaluation-time evidence; not physical receiver time.
    pub recorded_at: String,
}

/// Typed Nightshift authenticated-custody export.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftAuthoringCustodyExportV1 {
    /// Export schema.
    pub schema: String,
    /// Exact owner-echoed query.
    pub query: NightshiftAuthoringContextQueryV1,
    /// Zero or more exact custody records.
    pub matches: Vec<NightshiftAuthoringCustodyProvenanceV1>,
}

/// Closed local-Compose action whose evidence was retained by Nightshift.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalObservationActionV1 {
    /// Observe the qualified cache-platform acceptance contract.
    Qualify,
    /// Observe campaign resource absence after teardown.
    Teardown,
}

/// Closed executor outcome. A settled success still does not establish
/// present-world truth or Nightshift currentness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalObservationOutcomeV1 {
    /// Executor produced the workflow's closed successful evidence shape.
    Success,
    /// Executor produced a known failure result.
    Failure,
    /// Executor outcome remained indeterminate.
    Indeterminate,
}

/// Closed workflow-specific claim kind. These are evidence projections, not
/// AG/Nightshift authority or currentness facts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalObservationClaimKindV1 {
    /// Front door returned the workflow's qualified response.
    FrontDoorReachable,
    /// Exact observed sequence was MISS/MISS/HIT/HIT.
    CacheMissThenHit,
    /// Requests remained served during one-cache failure.
    SingleCacheFailureSurvived,
    /// Both cache nodes were observed after restoration.
    CacheTopologyRestored,
    /// Recorded campaign resources were absent after teardown.
    CampaignResourcesAbsent,
}

/// Evidence claim status. Non-success outcomes may only project unknown.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalObservationClaimStatusV1 {
    /// Closed source evidence satisfied this workflow-specific claim.
    Satisfied,
    /// Source evidence did not establish this claim.
    Unknown,
}

/// Exact PlanNode-addressed claim from the workflow adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationClaimV1 {
    /// Claim schema.
    pub schema: String,
    /// Content-derived claim identity.
    pub claim_id: String,
    /// Closed workflow-specific meaning.
    pub kind: ExternalObservationClaimKindV1,
    /// Satisfied or honestly unknown.
    pub status: ExternalObservationClaimStatusV1,
    /// Stable originating `PlanNode` identity.
    pub plan_node_id: String,
    /// Exact compiler output bound to that `PlanNode`.
    pub compiled_output_identity: String,
    /// Exact JSON pointers into retained source evidence.
    pub evidence_paths: Vec<String>,
}

/// Workflow-specific application/world observation candidate retained by
/// Nightshift. It is deliberately distinct from canonical observation cycles.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationV1 {
    /// Observation-candidate schema.
    pub schema: String,
    /// Content-derived candidate identity.
    pub observation_id: String,
    /// Workflow adapter identity.
    pub adapter_id: String,
    /// Workflow adapter version.
    pub adapter_version: String,
    /// Closed workflow action.
    pub action: ExternalObservationActionV1,
    /// Exact locked `PlanDocument` digest.
    pub plan_document_digest: String,
    /// Exact workflow compilation receipt.
    pub compilation_id: String,
    /// Exact governed coordinates.
    pub campaign_id: String,
    /// Exact governed occurrence.
    pub occurrence_id: String,
    /// Exact AG proposal.
    pub proposal_id: String,
    /// Exact compiled work.
    pub exact_work_id: String,
    /// Exact AG issuance.
    pub issuance_id: String,
    /// Exact Docket attempt.
    pub attempt_id: String,
    /// Exact Docket settlement.
    pub settlement_id: String,
    /// Exact governed subject.
    pub subject_digest: String,
    /// Exact governed scope.
    pub scope_digest: String,
    /// Exact retained executor evidence receipt.
    pub executor_evidence_receipt: String,
    /// Exact canonical executor evidence byte length.
    pub executor_evidence_bytes: u64,
    /// Source observation time; evidence only.
    pub observed_at_unix_ms: i64,
    /// Closed executor outcome.
    pub outcome: ExternalObservationOutcomeV1,
    /// Complete owner-validated source record, not reinterpreted by AG/UI.
    pub source_evidence: Value,
    /// Stable PlanNode-addressed workflow claims.
    pub claims: Vec<ExternalObservationClaimV1>,
    /// Exact authority/currentness nonclaims retained with the candidate.
    pub nonclaims: Vec<String>,
}

/// Authenticated delivery evidence for one exact external observation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationCustodyV1 {
    /// Custody schema.
    pub schema: String,
    /// Content-derived custody identity.
    pub custody_id: String,
    /// Exact authenticated handoff.
    pub handoff_id: String,
    /// Exact candidate.
    pub observation_id: String,
    /// Authenticated producer identity.
    pub producer_principal_id: String,
    /// Pinned producer credential identity.
    pub producer_key_id: String,
    /// Intended Nightshift runtime.
    pub target_runtime_id: String,
    /// Exact governed and evidence coordinates.
    pub campaign_id: String,
    /// Exact governed occurrence.
    pub occurrence_id: String,
    /// Exact compiled work.
    pub exact_work_id: String,
    /// Exact Docket attempt.
    pub attempt_id: String,
    /// Exact Docket settlement.
    pub settlement_id: String,
    /// Exact executor evidence receipt.
    pub executor_evidence_receipt: String,
    /// First durable Nightshift receipt time.
    pub received_at: String,
}

/// Display-only arithmetic relation between source time and the exact
/// caller-supplied evaluation window. This is explicitly not currentness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalObservationEvidenceAgeV1 {
    /// Source time falls inside the caller's display window.
    FreshAtEvaluation,
    /// Source time predates the caller's display window.
    StaleAtEvaluation,
    /// Evaluation time precedes source time.
    NotYetObserved,
}

/// Exact occurrence-scoped owner query used by Phosphor-ng.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalObservationQueryV1 {
    /// Exact governed campaign/occurrence lookup.
    GovernedOccurrence {
        /// AG campaign identity.
        campaign_id: String,
        /// AG occurrence identity.
        occurrence_id: String,
    },
    /// Other owner queries are retained in raw output but not accepted by
    /// this occurrence-scoped UI projection.
    Observation {
        /// Exact observation-candidate identity.
        observation_id: String,
    },
    /// Exact Docket-attempt lookup.
    Attempt {
        /// Exact Docket attempt identity.
        attempt_id: String,
    },
}

/// One candidate plus custody and transparent evidence-age projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationExportMatchV1 {
    /// Exact workflow candidate.
    pub observation: ExternalObservationV1,
    /// Exact authenticated delivery receipt.
    pub custody: ExternalObservationCustodyV1,
    /// Caller-supplied evaluation time.
    pub evaluated_at_unix_ms: i64,
    /// Caller-supplied display age window.
    pub evidence_ttl_ms: u64,
    /// Arithmetic age class, never currentness.
    pub evidence_age: ExternalObservationEvidenceAgeV1,
}

/// Read-only Nightshift owner projection for external observation candidates.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationExportV1 {
    /// Export schema.
    pub schema: String,
    /// Exact owner-echoed lookup.
    pub query: ExternalObservationQueryV1,
    /// Zero or one candidate under current v1 persistence law.
    pub matches: Vec<ExternalObservationExportMatchV1>,
}

/// Authentication retained by Docket with the exact AG issuance.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocketAuthenticationV1 {
    /// AG issuer principal trusted by Docket at custody acceptance.
    pub issuer_principal: String,
    /// Exact signing-key identity.
    pub signer_key_id: String,
    /// Exact public key retained for verification.
    pub signer_public_key: String,
    /// Exact issuance signature.
    pub signature: String,
}

/// Exact Docket-owned record status; `accepted` does not imply an outcome.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocketRecordStatusV1 {
    /// Custody exists; outcome remains unknown.
    Accepted,
    /// A known settlement exists.
    Settled,
    /// Exact read-only reconciliation is required.
    Indeterminate,
}

/// One complete Docket persisted governed-loop record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocketRecordInspectionV1 {
    /// Exact AG issuance accepted by Docket.
    pub issuance: AgIssuanceV1,
    /// Retained issuer authentication.
    pub authentication: DocketAuthenticationV1,
    /// Docket custody fact.
    pub custody: DocketCustodyV1,
    /// Exact Docket record state.
    pub status: DocketRecordStatusV1,
    /// Known settlement, only for `settled`.
    pub settlement: Option<DocketSettlementV1>,
    /// Unknown-outcome evidence, only for `indeterminate`.
    pub indeterminate: Option<IndeterminateOutcomeV1>,
    /// Exact executor/configuration binding.
    pub executor_binding: String,
    /// Exact executable-program digest.
    pub executor_program_digest: String,
    /// Exact executor-plan digest.
    pub executor_plan: String,
}

/// Typed Docket read-only governed-loop inspection response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocketInspectionV1 {
    /// Exact inspection schema.
    pub schema: String,
    /// Exact issuance requested by AG-derived lookup.
    pub requested_issuance: String,
    /// Complete record, or `None` when custody was never accepted.
    pub record: Option<DocketRecordInspectionV1>,
}

/// Closed canonical command names reachable from the backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadCommandNameV1 {
    /// AG aggregate inspection.
    AgInspect,
    /// AG current occurrence.
    AgStatus,
    /// AG deterministic replay.
    AgReplay,
    /// AG verified transition journal.
    AgHistory,
    /// AG verified non-authorizing refusal journal.
    AgRefusals,
    /// AG authenticated intervention-ingress receipts.
    AgInterventionSubmissions,
    /// Nightshift exact observation export.
    NightshiftExportObservation,
    /// Nightshift exact authoring-context provenance export.
    NightshiftExportAuthoringContext,
    /// Nightshift authenticated authoring delivery evidence.
    NightshiftExportAuthoringCustody,
    /// Nightshift authenticated workflow-specific external observation.
    NightshiftExportExternalObservation,
    /// Docket exact persisted governed-loop record.
    DocketGovernedLoopInspect,
}

/// Transport/source error class. These values never classify governance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceErrorKindV1 {
    /// Optional source was not configured.
    NotConfigured,
    /// Configured source file or executable was absent.
    Missing,
    /// Process could not start or its source could not be read.
    Unavailable,
    /// Canonical command exceeded its bounded read time.
    Timeout,
    /// Canonical command returned a refusal/nonzero status.
    CommandRefused,
    /// Output exceeded the bounded transport size.
    OutputTooLarge,
    /// Output was not one complete JSON value of the expected typed shape.
    MalformedOutput,
    /// Output used an unsupported schema/version.
    IncompatibleSchema,
}

/// One canonical command result, retaining both typed and raw forms.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "availability", rename_all = "snake_case")]
pub enum SourceResultV1<T> {
    /// Canonical command succeeded and parsed under an exact supported schema.
    Available {
        /// Stable source/owner label.
        source: String,
        /// Closed command invoked.
        command: ReadCommandNameV1,
        /// Local capture time; never source freshness authority.
        captured_at_unix_ms: u64,
        /// Typed value used by presentation.
        value: T,
        /// Complete canonical structured output.
        raw: Value,
    },
    /// Source was unavailable/refused/incompatible; no value was synthesized.
    Unavailable {
        /// Stable source/owner label.
        source: String,
        /// Closed command attempted.
        command: ReadCommandNameV1,
        /// Local capture time; never source freshness authority.
        captured_at_unix_ms: u64,
        /// Transport/schema error class.
        error_kind: SourceErrorKindV1,
        /// Exact bounded diagnostic.
        detail: String,
        /// Process exit status when a process ran.
        exit_status: Option<i32>,
    },
}

impl<T> SourceResultV1<T> {
    /// Returns the typed value only when the source was available.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Available { value, .. } => Some(value),
            Self::Unavailable { .. } => None,
        }
    }

    /// Returns whether this exact source command was available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

/// Cross-command capture classification. This is transport correspondence,
/// never campaign health or authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCorrespondenceV1 {
    /// All AG projections were readable and shared exact coordinates.
    Exact,
    /// One or more AG projections were unavailable.
    Partial,
    /// Readable AG projections reported different canonical coordinates.
    Disagreement,
}

/// Explicit comparison of independently captured AG projections.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCheckV1 {
    /// Exact/partial/disagreement classification.
    pub correspondence: ProjectionCorrespondenceV1,
    /// Human-readable exact comparisons or unavailable sources.
    pub findings: Vec<String>,
}

/// One related source projection keyed by the exact identity AG retained.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedSourceV1<T> {
    /// Exact AG-retained identity used for the read-only lookup.
    pub identity: String,
    /// Independent source result.
    pub result: SourceResultV1<T>,
}

/// One campaign source in the index.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignIndexEntryV1 {
    /// Opaque URL token for a configured-root child, never campaign identity.
    pub locator_token: String,
    /// Operational filename locator.
    pub locator: String,
    /// Independent AG inspection result.
    pub inspect: SourceResultV1<AgInspectV1>,
    /// Independent AG history result used for the last durable transition.
    pub history: SourceResultV1<CampaignTransitionHistoryV1>,
    /// Independent AG refusal history used for human-required/refused state.
    pub refusals: SourceResultV1<CampaignRefusalHistoryV1>,
    /// Explicit source comparison.
    pub projection: ProjectionCheckV1,
}

/// Complete campaign index response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignIndexV1 {
    /// Exact API schema.
    pub schema: String,
    /// Every discovered regular campaign store or its visible read error.
    pub campaigns: Vec<CampaignIndexEntryV1>,
}

/// Complete campaign detail response, retaining every source independently.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDetailV1 {
    /// Exact API schema.
    pub schema: String,
    /// Opaque configured-root child token.
    pub locator_token: String,
    /// Operational filename locator.
    pub locator: String,
    /// AG aggregate inspection.
    pub inspect: SourceResultV1<AgInspectV1>,
    /// AG current occurrence.
    pub status: SourceResultV1<OccurrenceSnapshotV1>,
    /// AG deterministic replay.
    pub replay: SourceResultV1<CampaignReplayReportV1>,
    /// AG verified transition journal.
    pub history: SourceResultV1<CampaignTransitionHistoryV1>,
    /// AG verified durable non-authorizing refusals.
    pub refusals: SourceResultV1<CampaignRefusalHistoryV1>,
    /// AG authenticated transport/custody receipts. Historical demo captures
    /// may predate this projection and remain honestly absent.
    #[serde(default)]
    pub intervention_submissions: Option<SourceResultV1<InterventionSubmissionHistoryProjectionV1>>,
    /// Explicit comparison; disagreement is never reconciled.
    pub projection: ProjectionCheckV1,
    /// Nightshift exports keyed by exact AG observation identity.
    pub nightshift: Vec<RelatedSourceV1<NightshiftObservationExportV1>>,
    /// Nightshift authoring-context records keyed by exact AG
    /// campaign/occurrence identity.
    #[serde(default)]
    pub authoring_contexts: Vec<RelatedSourceV1<NightshiftAuthoringContextExportV1>>,
    /// Separately retained producer/session custody evidence. Historical
    /// lineage may legitimately have no custody match.
    #[serde(default)]
    pub authoring_custody: Vec<RelatedSourceV1<NightshiftAuthoringCustodyExportV1>>,
    /// Workflow-specific application/world evidence retained by Nightshift,
    /// keyed by exact governed occurrence. It is not cycle currentness.
    #[serde(default)]
    pub external_observations: Vec<RelatedSourceV1<ExternalObservationExportV1>>,
    /// Docket records keyed by exact AG issuance identity.
    pub docket: Vec<RelatedSourceV1<DocketInspectionV1>>,
}

/// One bounded deterministic corpus produced from the same typed read model
/// rendered in live mode. It is presentation evidence, never runtime state.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DemoCorpusV1 {
    /// Exact corpus schema.
    pub schema: String,
    /// Human-readable generator identity.
    pub generated_by: String,
    /// Canonical owner schemas represented by the capture.
    pub canonical_schemas: Vec<String>,
    /// Captured index projection.
    pub index: CampaignIndexV1,
    /// Exact detail projections addressed by their locator tokens.
    pub campaigns: Vec<CampaignDetailV1>,
    /// Fixture-only navigation selectors for semantic links when the corpus
    /// intentionally retains multiple captures of one campaign lifecycle.
    pub semantic_link_targets: Vec<DemoSemanticLinkTargetV1>,
}

/// A fixture-only choice of one captured projection for an exact semantic
/// path. This resolves demo-corpus time slices; it is not runtime provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DemoSemanticLinkTargetV1 {
    /// Exact campaign identity represented by the target capture.
    pub campaign: CampaignId,
    /// Exact occurrence identity represented by the target capture.
    pub occurrence: OccurrenceId,
    /// Optional exact proposal identity required by the path.
    pub proposal: Option<ProposalRefV1>,
    /// Existing corpus locator token selected for display.
    pub locator_token: String,
}

impl AgInspectV1 {
    /// Validates the exact supported outer schema and same-command bindings.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, corrupt snapshot, or a
    /// current/replay identity mismatch.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != AG_INSPECT_SCHEMA_V1 {
            return Err(format!("unsupported AG inspect schema {}", self.schema));
        }
        self.current
            .validate_integrity()
            .map_err(|error| format!("AG current snapshot integrity: {error}"))?;
        if self.current.key().campaign != self.replay.campaign
            || self.current.state_digest() != &self.replay.current_state_digest
        {
            return Err("AG inspect current/replay binding mismatch".to_owned());
        }
        Ok(())
    }
}

impl NightshiftObservationExportV1 {
    /// Validates the exact supported outer schema and requested identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or substituted observation.
    pub fn validate(&self, expected: &str) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_OBSERVATION_EXPORT_SCHEMA_V1 {
            return Err(format!(
                "unsupported Nightshift observation-export schema {}",
                self.schema
            ));
        }
        if self.observation_id != expected {
            return Err("Nightshift export substituted observation identity".to_owned());
        }
        Ok(())
    }
}

impl NightshiftAuthoringContextExportV1 {
    /// Verifies schema, echoed lookup coordinates, every self-digest, and all
    /// governed relationship fields used by navigation.
    ///
    /// # Errors
    ///
    /// Refuses unsupported schemas, substituted queries or matches, and
    /// malformed/self-inconsistent owner records.
    pub fn validate_for_occurrence(&self, campaign: &str, occurrence: &str) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1 {
            return Err(format!(
                "unsupported Nightshift authoring-context export schema {}",
                self.schema
            ));
        }
        let NightshiftAuthoringContextQueryV1::GovernedOccurrence {
            campaign_id,
            occurrence_id,
        } = &self.query
        else {
            return Err("Nightshift authoring-context response echoed the wrong query kind".into());
        };
        if campaign_id != campaign || occurrence_id != occurrence {
            return Err("Nightshift authoring-context response substituted lookup identity".into());
        }
        for record in &self.matches {
            record.validate()?;
            if record.campaign_id != campaign || record.occurrence_id != occurrence {
                return Err(
                    "Nightshift authoring-context response contains a substituted relation".into(),
                );
            }
        }
        Ok(())
    }
}

impl NightshiftAuthoringContextProvenanceV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1 {
            return Err(format!(
                "unsupported Nightshift authoring-context provenance schema {}",
                self.schema
            ));
        }
        if self.producer_component != "nightshift.canonical_runtime" {
            return Err("Nightshift authoring-context producer mismatch".into());
        }
        for (name, value) in [
            ("provenance_id", &self.provenance_id),
            ("maude_plan_ref", &self.maude_plan_ref),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("exact_work_id", &self.exact_work_id),
            ("source_intent_id", &self.source_intent_id),
        ] {
            Digest::parse(value).map_err(|error| format!("invalid {name}: {error}"))?;
        }
        if self.maude_session_id.trim().is_empty()
            || self.maude_session_id.chars().any(char::is_whitespace)
            || serde_json::from_value::<OccurrenceId>(Value::String(self.occurrence_id.clone()))
                .is_err()
            || self.source_plan_bytes == 0
        {
            return Err("Nightshift authoring-context identity or size is malformed".into());
        }
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("authoring context is an object")
            .remove("provenance_id");
        let expected = Digest::from_serializable(&value).map_err(|error| error.to_string())?;
        if expected.as_str() != self.provenance_id {
            return Err("Nightshift authoring-context self-digest mismatch".into());
        }
        Ok(())
    }

    /// Joins owner-minted lineage to the independently selected AG fact.
    /// Recomputing the lineage self-digest after substitution cannot satisfy
    /// this exact cross-owner relationship check.
    ///
    /// # Errors
    ///
    /// Refuses malformed lineage and any campaign, occurrence, proposal, or
    /// exact-work mismatch with the selected canonical AG occurrence.
    pub fn validate_for_governed_relationship(
        &self,
        campaign: &str,
        occurrence: &str,
        proposal: &str,
        exact_work: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if self.campaign_id != campaign
            || self.occurrence_id != occurrence
            || self.proposal_id != proposal
            || self.exact_work_id != exact_work
        {
            return Err(
                "Nightshift authoring context disagrees with canonical AG proposal/work".into(),
            );
        }
        Ok(())
    }
}

impl NightshiftAuthoringCustodyExportV1 {
    /// Validates exact occurrence-scoped lookup and every custody record.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema, echoed query, or any record does not
    /// bind the requested governed occurrence exactly.
    pub fn validate_for_occurrence(&self, campaign: &str, occurrence: &str) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_AUTHORING_CUSTODY_EXPORT_SCHEMA_V1 {
            return Err(format!(
                "unsupported Nightshift authoring custody export schema {}",
                self.schema
            ));
        }
        let NightshiftAuthoringContextQueryV1::GovernedOccurrence {
            campaign_id,
            occurrence_id,
        } = &self.query
        else {
            return Err("Nightshift authoring custody echoed the wrong query kind".into());
        };
        if campaign_id != campaign || occurrence_id != occurrence {
            return Err("Nightshift authoring custody substituted lookup identity".into());
        }
        for record in &self.matches {
            record.validate()?;
            if record.campaign_id != campaign || record.occurrence_id != occurrence {
                return Err("Nightshift authoring custody contains a substituted match".into());
            }
        }
        Ok(())
    }
}

impl NightshiftAuthoringCustodyProvenanceV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_AUTHORING_CUSTODY_PROVENANCE_SCHEMA_V1 {
            return Err(format!(
                "unsupported Nightshift authoring custody schema {}",
                self.schema
            ));
        }
        for (name, value) in [
            ("custody_id", &self.custody_id),
            ("handoff_id", &self.handoff_id),
            ("session_record_id", &self.session_record_id),
            (
                "authoring_context_provenance_id",
                &self.authoring_context_provenance_id,
            ),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("exact_work_id", &self.exact_work_id),
            ("target_request_id", &self.target_request_id),
            ("maude_plan_ref", &self.maude_plan_ref),
        ] {
            Digest::parse(value).map_err(|error| format!("invalid {name}: {error}"))?;
        }
        for value in [
            &self.producer_principal_id,
            &self.producer_key_id,
            &self.session_issuer_principal_id,
            &self.session_issuer_key_id,
            &self.target_runtime_id,
            &self.maude_session_id,
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                return Err("Nightshift authoring custody contains a malformed token".into());
            }
        }
        if self.authentication_method != "maude.hmac_sha256.v1"
            || serde_json::from_value::<OccurrenceId>(Value::String(self.occurrence_id.clone()))
                .is_err()
        {
            return Err("Nightshift authoring custody method or occurrence is malformed".into());
        }
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("authoring custody is an object")
            .remove("custody_id");
        let expected = Digest::from_serializable(&value).map_err(|error| error.to_string())?;
        if expected.as_str() != self.custody_id {
            return Err("Nightshift authoring custody self-digest mismatch".into());
        }
        Ok(())
    }

    /// Exact inert-lineage join to the separately exported authoring record
    /// and independently selected AG proposal/work.
    ///
    /// # Errors
    ///
    /// Returns an error when the custody record is malformed or disagrees
    /// with any exact lineage, campaign, occurrence, proposal, or work ID.
    pub fn validate_for_relationship(
        &self,
        authoring: &NightshiftAuthoringContextProvenanceV1,
        campaign: &str,
        occurrence: &str,
        proposal: &str,
        exact_work: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if self.authoring_context_provenance_id != authoring.provenance_id
            || self.maude_plan_ref != authoring.maude_plan_ref
            || self.maude_session_id != authoring.maude_session_id
            || self.campaign_id != campaign
            || self.occurrence_id != occurrence
            || self.proposal_id != proposal
            || self.exact_work_id != exact_work
        {
            return Err("Nightshift custody disagrees with exact lineage or AG work".into());
        }
        Ok(())
    }
}

impl ExternalObservationExportV1 {
    /// Validates the exact occurrence-scoped owner projection and every
    /// candidate/custody relationship without treating evidence age as
    /// Nightshift currentness.
    ///
    /// # Errors
    ///
    /// Refuses unsupported schemas, substituted lookup coordinates,
    /// malformed self-identities, and contradictory custody records.
    pub fn validate_for_occurrence(&self, campaign: &str, occurrence: &str) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1 {
            return Err(format!(
                "unsupported Nightshift external-observation export schema {}",
                self.schema
            ));
        }
        let ExternalObservationQueryV1::GovernedOccurrence {
            campaign_id,
            occurrence_id,
        } = &self.query
        else {
            return Err("Nightshift external observation echoed the wrong query kind".into());
        };
        if campaign_id != campaign || occurrence_id != occurrence {
            return Err("Nightshift external observation substituted lookup identity".into());
        }
        if self.matches.len() > 1 {
            return Err(
                "Nightshift returned ambiguous external observations for one occurrence".into(),
            );
        }
        for item in &self.matches {
            item.validate_for_occurrence(campaign, occurrence)?;
        }
        Ok(())
    }
}

impl ExternalObservationExportMatchV1 {
    fn validate_for_occurrence(&self, campaign: &str, occurrence: &str) -> Result<(), String> {
        self.observation.validate()?;
        self.custody.validate()?;
        if self.observation.campaign_id != campaign
            || self.observation.occurrence_id != occurrence
            || self.custody.campaign_id != campaign
            || self.custody.occurrence_id != occurrence
            || self.custody.observation_id != self.observation.observation_id
            || self.custody.exact_work_id != self.observation.exact_work_id
            || self.custody.attempt_id != self.observation.attempt_id
            || self.custody.settlement_id != self.observation.settlement_id
            || self.custody.executor_evidence_receipt != self.observation.executor_evidence_receipt
        {
            return Err("external observation custody disagrees with exact candidate".into());
        }
        if self.evaluated_at_unix_ms < 0
            || self.evidence_age
                != external_evidence_age(
                    self.observation.observed_at_unix_ms,
                    self.evaluated_at_unix_ms,
                    self.evidence_ttl_ms,
                )
        {
            return Err("external observation evidence-age projection mismatch".into());
        }
        Ok(())
    }
}

impl ExternalObservationV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_EXTERNAL_OBSERVATION_SCHEMA_V1
            || self.adapter_id != "maude.local-compose-observation-adapter"
            || self.adapter_version != "1"
            || self.executor_evidence_bytes == 0
            || self.observed_at_unix_ms < 0
        {
            return Err("external observation schema, adapter, size, or time is invalid".into());
        }
        for (name, value) in [
            ("observation_id", &self.observation_id),
            ("plan_document_digest", &self.plan_document_digest),
            ("compilation_id", &self.compilation_id),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("exact_work_id", &self.exact_work_id),
            ("issuance_id", &self.issuance_id),
            ("attempt_id", &self.attempt_id),
            ("settlement_id", &self.settlement_id),
            ("subject_digest", &self.subject_digest),
            ("scope_digest", &self.scope_digest),
            ("executor_evidence_receipt", &self.executor_evidence_receipt),
        ] {
            Digest::parse(value).map_err(|error| format!("invalid {name}: {error}"))?;
        }
        if serde_json::from_value::<OccurrenceId>(Value::String(self.occurrence_id.clone()))
            .is_err()
        {
            return Err("external observation occurrence is malformed".into());
        }
        let required_nonclaims = [
            "candidate is not Nightshift currentness",
            "Docket settlement is not world-state freshness",
            "producer authentication is not standing or authorization",
            "observation candidate cannot authorize or execute work",
        ];
        if self
            .nonclaims
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != required_nonclaims
        {
            return Err("external observation authority nonclaims drifted".into());
        }
        for claim in &self.claims {
            claim.validate()?;
            if self.outcome != ExternalObservationOutcomeV1::Success
                && claim.status != ExternalObservationClaimStatusV1::Unknown
            {
                return Err("non-success external observation projected a satisfied claim".into());
            }
        }
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("external observation is an object")
            .remove("observation_id");
        let expected = Digest::from_serializable(&value).map_err(|error| error.to_string())?;
        if expected.as_str() != self.observation_id {
            return Err("external observation self-digest mismatch".into());
        }
        Ok(())
    }
}

impl ExternalObservationClaimV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_EXTERNAL_OBSERVATION_CLAIM_SCHEMA_V1
            || self.plan_node_id.trim().is_empty()
            || self.plan_node_id.chars().any(char::is_whitespace)
            || self.evidence_paths.is_empty()
            || self
                .evidence_paths
                .iter()
                .any(|path| !path.starts_with('/'))
        {
            return Err("external observation claim shape is invalid".into());
        }
        Digest::parse(&self.claim_id).map_err(|error| format!("invalid claim_id: {error}"))?;
        Digest::parse(&self.compiled_output_identity)
            .map_err(|error| format!("invalid compiled output identity: {error}"))?;
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("external observation claim is an object")
            .remove("claim_id");
        let expected = Digest::from_serializable(&value).map_err(|error| error.to_string())?;
        if expected.as_str() != self.claim_id {
            return Err("external observation claim self-digest mismatch".into());
        }
        Ok(())
    }
}

impl ExternalObservationCustodyV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema != NIGHTSHIFT_EXTERNAL_OBSERVATION_CUSTODY_SCHEMA_V1 {
            return Err(format!(
                "unsupported external observation custody schema {}",
                self.schema
            ));
        }
        for (name, value) in [
            ("custody_id", &self.custody_id),
            ("handoff_id", &self.handoff_id),
            ("observation_id", &self.observation_id),
            ("campaign_id", &self.campaign_id),
            ("exact_work_id", &self.exact_work_id),
            ("attempt_id", &self.attempt_id),
            ("settlement_id", &self.settlement_id),
            ("executor_evidence_receipt", &self.executor_evidence_receipt),
        ] {
            Digest::parse(value).map_err(|error| format!("invalid {name}: {error}"))?;
        }
        for value in [
            &self.producer_principal_id,
            &self.producer_key_id,
            &self.target_runtime_id,
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                return Err("external observation custody contains a malformed token".into());
            }
        }
        if serde_json::from_value::<OccurrenceId>(Value::String(self.occurrence_id.clone()))
            .is_err()
            || self.received_at.trim().is_empty()
        {
            return Err("external observation custody occurrence or time is malformed".into());
        }
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("external observation custody is an object")
            .remove("custody_id");
        let expected = Digest::from_serializable(&value).map_err(|error| error.to_string())?;
        if expected.as_str() != self.custody_id {
            return Err("external observation custody self-digest mismatch".into());
        }
        Ok(())
    }
}

fn external_evidence_age(
    observed_at: i64,
    evaluated_at: i64,
    ttl_ms: u64,
) -> ExternalObservationEvidenceAgeV1 {
    if evaluated_at < observed_at {
        ExternalObservationEvidenceAgeV1::NotYetObserved
    } else if u64::try_from(evaluated_at - observed_at).is_ok_and(|age| age <= ttl_ms) {
        ExternalObservationEvidenceAgeV1::FreshAtEvaluation
    } else {
        ExternalObservationEvidenceAgeV1::StaleAtEvaluation
    }
}

/// Returns the campaign identity from an available AG inspection.
#[must_use]
pub fn inspected_campaign(source: &SourceResultV1<AgInspectV1>) -> Option<&CampaignId> {
    source.value().map(|value| &value.current.key().campaign)
}

#[cfg(test)]
mod authoring_context_tests {
    use super::*;

    fn digest(label: &str) -> String {
        Digest::hash_bytes(label.as_bytes()).to_string()
    }

    fn record() -> NightshiftAuthoringContextProvenanceV1 {
        let mut value = NightshiftAuthoringContextProvenanceV1 {
            schema: NIGHTSHIFT_AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1.to_owned(),
            provenance_id: String::new(),
            producer_component: "nightshift.canonical_runtime".to_owned(),
            maude_plan_ref: digest("plan"),
            maude_session_id: "sess_0123456789ab".to_owned(),
            source_plan_bytes: 4,
            campaign_id: digest("campaign"),
            occurrence_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            proposal_id: digest("proposal"),
            exact_work_id: digest("work"),
            source_intent_id: digest("intent"),
            recorded_at: "2026-08-21T12:00:00Z".to_owned(),
        };
        let mut preimage = serde_json::to_value(&value).unwrap();
        preimage.as_object_mut().unwrap().remove("provenance_id");
        value.provenance_id = Digest::from_serializable(&preimage).unwrap().to_string();
        value
    }

    fn custody(
        authoring: &NightshiftAuthoringContextProvenanceV1,
    ) -> NightshiftAuthoringCustodyProvenanceV1 {
        let mut value = NightshiftAuthoringCustodyProvenanceV1 {
            schema: NIGHTSHIFT_AUTHORING_CUSTODY_PROVENANCE_SCHEMA_V1.to_owned(),
            custody_id: String::new(),
            handoff_id: digest("handoff"),
            session_record_id: digest("session receipt"),
            authoring_context_provenance_id: authoring.provenance_id.clone(),
            campaign_id: authoring.campaign_id.clone(),
            occurrence_id: authoring.occurrence_id.clone(),
            proposal_id: authoring.proposal_id.clone(),
            exact_work_id: authoring.exact_work_id.clone(),
            producer_principal_id: "maude-handoff:local".to_owned(),
            producer_key_id: "maude-handoff-key:primary".to_owned(),
            session_issuer_principal_id: "maude:supervisor".to_owned(),
            session_issuer_key_id: "maude-session-key:primary".to_owned(),
            target_runtime_id: "nightshift:local-c1".to_owned(),
            target_request_id: digest("cycle request"),
            maude_session_id: authoring.maude_session_id.clone(),
            maude_plan_ref: authoring.maude_plan_ref.clone(),
            authentication_method: "maude.hmac_sha256.v1".to_owned(),
            recorded_at: "2026-08-21T12:00:00Z".to_owned(),
        };
        let mut preimage = serde_json::to_value(&value).unwrap();
        preimage.as_object_mut().unwrap().remove("custody_id");
        value.custody_id = Digest::from_serializable(&preimage).unwrap().to_string();
        value
    }

    fn external_observation_export() -> ExternalObservationExportV1 {
        let campaign = digest("campaign");
        let occurrence = "00000000-0000-0000-0000-000000000001".to_owned();
        let mut claim = ExternalObservationClaimV1 {
            schema: NIGHTSHIFT_EXTERNAL_OBSERVATION_CLAIM_SCHEMA_V1.to_owned(),
            claim_id: String::new(),
            kind: ExternalObservationClaimKindV1::FrontDoorReachable,
            status: ExternalObservationClaimStatusV1::Satisfied,
            plan_node_id: "pn_health".to_owned(),
            compiled_output_identity: digest("compiled node"),
            evidence_paths: vec!["/evidence/health".to_owned()],
        };
        let mut claim_preimage = serde_json::to_value(&claim).unwrap();
        claim_preimage.as_object_mut().unwrap().remove("claim_id");
        claim.claim_id = Digest::from_serializable(&claim_preimage)
            .unwrap()
            .to_string();
        let mut observation = ExternalObservationV1 {
            schema: NIGHTSHIFT_EXTERNAL_OBSERVATION_SCHEMA_V1.to_owned(),
            observation_id: String::new(),
            adapter_id: "maude.local-compose-observation-adapter".to_owned(),
            adapter_version: "1".to_owned(),
            action: ExternalObservationActionV1::Qualify,
            plan_document_digest: digest("plan"),
            compilation_id: digest("compilation"),
            campaign_id: campaign.clone(),
            occurrence_id: occurrence.clone(),
            proposal_id: digest("proposal"),
            exact_work_id: digest("work"),
            issuance_id: digest("issuance"),
            attempt_id: digest("attempt"),
            settlement_id: digest("settlement"),
            subject_digest: digest("subject"),
            scope_digest: digest("scope"),
            executor_evidence_receipt: digest("evidence"),
            executor_evidence_bytes: 2,
            observed_at_unix_ms: 1_000,
            outcome: ExternalObservationOutcomeV1::Success,
            source_evidence: serde_json::json!({}),
            claims: vec![claim],
            nonclaims: vec![
                "candidate is not Nightshift currentness".to_owned(),
                "Docket settlement is not world-state freshness".to_owned(),
                "producer authentication is not standing or authorization".to_owned(),
                "observation candidate cannot authorize or execute work".to_owned(),
            ],
        };
        let mut observation_preimage = serde_json::to_value(&observation).unwrap();
        observation_preimage
            .as_object_mut()
            .unwrap()
            .remove("observation_id");
        observation.observation_id = Digest::from_serializable(&observation_preimage)
            .unwrap()
            .to_string();
        let mut custody = ExternalObservationCustodyV1 {
            schema: NIGHTSHIFT_EXTERNAL_OBSERVATION_CUSTODY_SCHEMA_V1.to_owned(),
            custody_id: String::new(),
            handoff_id: digest("handoff"),
            observation_id: observation.observation_id.clone(),
            producer_principal_id: "maude-observer:local".to_owned(),
            producer_key_id: "maude-observer-key:one".to_owned(),
            target_runtime_id: "nightshift:local".to_owned(),
            campaign_id: campaign.clone(),
            occurrence_id: occurrence.clone(),
            exact_work_id: observation.exact_work_id.clone(),
            attempt_id: observation.attempt_id.clone(),
            settlement_id: observation.settlement_id.clone(),
            executor_evidence_receipt: observation.executor_evidence_receipt.clone(),
            received_at: "2026-08-22T18:00:00Z".to_owned(),
        };
        let mut custody_preimage = serde_json::to_value(&custody).unwrap();
        custody_preimage
            .as_object_mut()
            .unwrap()
            .remove("custody_id");
        custody.custody_id = Digest::from_serializable(&custody_preimage)
            .unwrap()
            .to_string();
        ExternalObservationExportV1 {
            schema: NIGHTSHIFT_EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1.to_owned(),
            query: ExternalObservationQueryV1::GovernedOccurrence {
                campaign_id: campaign,
                occurrence_id: occurrence,
            },
            matches: vec![ExternalObservationExportMatchV1 {
                observation,
                custody,
                evaluated_at_unix_ms: 1_000,
                evidence_ttl_ms: 0,
                evidence_age: ExternalObservationEvidenceAgeV1::FreshAtEvaluation,
            }],
        }
    }

    #[test]
    fn substituted_relationship_is_refused_even_with_typed_transport() {
        let mut record = record();
        assert!(record.validate().is_ok());
        record.proposal_id = digest("proposal-b");
        assert!(record.validate().is_err());

        let expected_proposal = digest("proposal");
        let expected_work = record.exact_work_id.clone();
        let mut preimage = serde_json::to_value(&record).unwrap();
        preimage.as_object_mut().unwrap().remove("provenance_id");
        record.provenance_id = Digest::from_serializable(&preimage).unwrap().to_string();
        assert!(record.validate().is_ok());
        assert!(
            record
                .validate_for_governed_relationship(
                    &record.campaign_id,
                    &record.occurrence_id,
                    &expected_proposal,
                    &expected_work,
                )
                .is_err()
        );
    }

    #[test]
    fn occurrence_query_echo_and_match_are_exact() {
        let record = record();
        let export = NightshiftAuthoringContextExportV1 {
            schema: NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1.to_owned(),
            query: NightshiftAuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: record.campaign_id.clone(),
                occurrence_id: record.occurrence_id.clone(),
            },
            matches: vec![record.clone()],
        };
        assert!(
            export
                .validate_for_occurrence(&record.campaign_id, &record.occurrence_id)
                .is_ok()
        );
        assert!(
            export
                .validate_for_occurrence(
                    &record.campaign_id,
                    "00000000-0000-0000-0000-000000000002"
                )
                .is_err()
        );
    }

    #[test]
    fn custody_requires_exact_lineage_and_independent_identity_roles() {
        let authoring = record();
        let custody = custody(&authoring);
        assert!(
            custody
                .validate_for_relationship(
                    &authoring,
                    &authoring.campaign_id,
                    &authoring.occurrence_id,
                    &authoring.proposal_id,
                    &authoring.exact_work_id,
                )
                .is_ok()
        );
        assert_ne!(
            custody.producer_key_id, custody.session_issuer_key_id,
            "presentation retains the two authenticated custody roles"
        );

        let mut substituted = custody;
        substituted.exact_work_id = digest("other work");
        let mut preimage = serde_json::to_value(&substituted).unwrap();
        preimage.as_object_mut().unwrap().remove("custody_id");
        substituted.custody_id = Digest::from_serializable(&preimage).unwrap().to_string();
        assert!(
            substituted
                .validate_for_relationship(
                    &authoring,
                    &authoring.campaign_id,
                    &authoring.occurrence_id,
                    &authoring.proposal_id,
                    &authoring.exact_work_id,
                )
                .is_err()
        );
    }

    #[test]
    fn external_observation_is_exact_custody_not_currentness() {
        let export = external_observation_export();
        let ExternalObservationQueryV1::GovernedOccurrence {
            campaign_id,
            occurrence_id,
        } = &export.query
        else {
            unreachable!()
        };
        assert!(
            export
                .validate_for_occurrence(campaign_id, occurrence_id)
                .is_ok()
        );
        let mut substituted = export.clone();
        substituted.matches[0].custody.attempt_id = digest("other attempt");
        let mut preimage = serde_json::to_value(&substituted.matches[0].custody).unwrap();
        preimage.as_object_mut().unwrap().remove("custody_id");
        substituted.matches[0].custody.custody_id =
            Digest::from_serializable(&preimage).unwrap().to_string();
        assert!(
            substituted
                .validate_for_occurrence(campaign_id, occurrence_id)
                .is_err()
        );
        let serialized = serde_json::to_string(&export).unwrap();
        assert!(!serialized.contains("\"currentness\":"));
        assert!(!serialized.contains("authorization\":"));
    }
}
