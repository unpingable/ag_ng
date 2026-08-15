//! Authority-neutral `ag-effectd` adapter for Docket-custodied attempts.
//!
//! This module owns only exact-effect mechanics and an executor-local
//! idempotency journal.  It consumes no AG authorization or standing, creates
//! no campaign transition, and has no continuation operation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ag_campaign::governed::{CanonicalEffectOperationV1, CanonicalEffectScopeV1};
use ag_effect::CanonicalEffectV1;
use ag_effect::executor::{
    ArtifactReadErrorV1, ArtifactSourceV1, CapabilityFailureV1, CapabilityOutcomeV1,
    DocketCustodiedExecutionPermitV1, DocketEffectExecutionReceiptV1, EffectExecutorV1,
    ExecutionOutcomeV1, ManagedFilePolicyV1, PinnedHelperIdentityV1, PinnedPointerHelperV1,
    PointerCasRequestV1, PointerCasSuccessV1, PointerPreparationRequestV1,
    PointerPreparationSuccessV1, SystemdDbusBackendV1, SystemdManagerReloadRequestV1,
    SystemdManagerReloadSuccessV1, SystemdUnitRequestV1, SystemdUnitSuccessV1,
};
use ag_primitives::{Digest, JcsDocument};
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Deserializer, Serialize};

fn deserialize_present_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Exact Docket work-schema accepted by this adapter.
pub const EFFECT_EXECUTOR_WORK_SCHEMA_V1: &str = "ag-effectd.docket-executor-work/v1";
/// Exact sealed executor-plan schema.
pub const EFFECT_EXECUTOR_PLAN_SCHEMA_V1: &str = "ag-effectd.docket-executor-plan/v1";

const STORE_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS docket_effect_attempt (
  attempt TEXT PRIMARY KEY NOT NULL,
  marker TEXT UNIQUE NOT NULL,
  work TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('started','success','failure','indeterminate')),
  receipt TEXT,
  receipt_body BLOB,
  CHECK (
    (status='started' AND receipt IS NULL AND receipt_body IS NULL)
    OR
    (status!='started' AND receipt IS NOT NULL AND receipt_body IS NOT NULL)
  )
) STRICT;
CREATE TABLE IF NOT EXISTS docket_reconciliation_context (
  round TEXT PRIMARY KEY NOT NULL,
  request TEXT UNIQUE NOT NULL,
  reservation TEXT UNIQUE NOT NULL,
  source_cut TEXT NOT NULL,
  attempt TEXT NOT NULL,
  dispatch_jcs BLOB NOT NULL
) STRICT;
";

/// Docket-to-executor message.  Its fields are exact references, not bearer
/// authority accepted independently by this adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorDispatchV1 {
    /// Docket-owned execution attempt.
    pub attempt: Digest,
    /// Executor-local idempotency marker.
    pub marker: Digest,
    /// Exact work schema.
    pub work_schema: String,
    /// Exact sealed executor-plan identity.
    pub work: Digest,
    /// Exact standing-bound subject.
    pub subject: Digest,
    /// Exact structured standing-bound effect scope.
    pub effect_scope: CanonicalEffectScopeV1,
    /// Mechanically derived identity of `effect_scope`.
    pub effect_scope_digest: Digest,
}

/// Exact Docket-owned envelope for one explicit reconciliation round.
///
/// This adapter treats the round coordinates opaquely but durably binds each
/// round to one exact canonical envelope before returning executor-local
/// evidence. It cannot mint or approve a reconciliation round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketExecutorReconciliationDispatchV1 {
    /// Exact Docket executor-envelope schema.
    pub schema: String,
    /// Exact authenticated AG request identity.
    pub request: Digest,
    /// Exact intentional reconciliation round.
    pub round: Digest,
    /// Exact Docket reservation claimed before this call.
    pub reservation: Digest,
    /// Exact Docket durable source cut.
    pub source_cut: Digest,
    /// Existing exact attempt mechanics binding.
    pub dispatch: EffectExecutorDispatchV1,
}

/// Exact Docket reconciliation-envelope schema accepted by `ag-effectd`.
pub const DOCKET_EXECUTOR_RECONCILIATION_DISPATCH_SCHEMA_V1: &str =
    "docket.governed-loop.executor-reconciliation-dispatch/v1";

/// Exact logical scope row that the sealed plan associates with its one
/// physical effect.  Docket independently verifies the emitted journal row
/// against the AG-issued canonical scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorJournalBindingV1 {
    /// Exact resource class from the canonical scope.
    pub resource: String,
    /// Exact normalized resource-relative path from the canonical scope.
    pub path: String,
    /// Exact closed operation from the canonical scope.
    pub operation: CanonicalEffectOperationV1,
}

/// One observed effect journal row returned to Docket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorJournalEntryV1 {
    /// Exact logical resource class.
    pub resource: String,
    /// Exact normalized resource-relative path.
    pub path: String,
    /// Exact closed operation.
    pub operation: CanonicalEffectOperationV1,
    /// Canonical identity of the physical effect consumed by the executor.
    pub effect_identity: Digest,
}

/// Uninhabited marker: this ordinary mechanics adapter cannot emit an
/// immutable governed-repair checkpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NoGovernedRepairCheckpointV1 {}

/// Uninhabited marker: this ordinary mechanics adapter cannot classify or
/// emit a governed-repair requirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NoGovernedRepairRequirementV1 {}

/// Closed mechanics outcome returned to Docket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectExecutorOutcomeClassV1 {
    /// Exact effect and durability boundary completed.
    Success,
    /// Exact mechanics proved no requested effect occurred.
    Failure,
    /// Mechanics cannot prove whether an effect occurred.
    Indeterminate,
}

/// Exact executor response consumed by Docket settlement logic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorOutcomeV1 {
    /// Exact Docket attempt.
    pub attempt: Digest,
    /// Exact executor marker.
    pub marker: Digest,
    /// Exact canonical mechanics receipt identity.
    pub receipt: Digest,
    /// Closed outcome class.
    pub outcome: EffectExecutorOutcomeClassV1,
    /// Exact successful effects. Known no-effect failures and indeterminate
    /// outcomes emit an empty journal.
    pub effect_journal: Vec<EffectExecutorJournalEntryV1>,
    /// Always `None`; governed checkpoints belong to a dedicated executor.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub immutable_work_checkpoint: Option<NoGovernedRepairCheckpointV1>,
    /// Always `None`; this adapter never interprets diagnostic meaning.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub governed_repair: Option<NoGovernedRepairRequirementV1>,
}

/// One exact artifact file bound into a sealed effect plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectArtifactFileV1 {
    /// Expected content identity.
    pub digest: Digest,
    /// Absolute non-symlink regular-file custody path.
    pub path: PathBuf,
}

/// Serializable managed-file trust policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFilePolicyV1 {
    /// Maximum admitted or existing managed-file size.
    pub max_content_bytes: u64,
    /// Required owner of stable ancestors.
    pub trusted_ancestor_uid: u32,
    /// Required owner of the final parent directory.
    pub trusted_parent_uid: u32,
    /// Whether group/world writable final parents are refused.
    pub require_private_parent_writes: bool,
}

impl From<EffectFilePolicyV1> for ManagedFilePolicyV1 {
    fn from(value: EffectFilePolicyV1) -> Self {
        Self {
            max_content_bytes: value.max_content_bytes,
            trusted_ancestor_uid: value.trusted_ancestor_uid,
            trusted_parent_uid: value.trusted_parent_uid,
            require_private_parent_writes: value.require_private_parent_writes,
        }
    }
}

/// Sealed exact mechanics plan referenced by an AG issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorPlanV1 {
    /// Plan schema.
    pub schema: String,
    /// Executor-local transactional idempotency journal.
    pub attempt_store: PathBuf,
    /// Exact Docket standing subject required by this plan.
    pub subject: Digest,
    /// Exact Docket standing scope required by this plan.
    pub scope: Digest,
    /// Exact logical effect row this plan may report after successful
    /// mechanics. The Store-issued structured scope must contain it.
    pub journal_binding: EffectExecutorJournalBindingV1,
    /// Effect position in the exact plan.
    pub effect_index: u32,
    /// One exact canonical effect.
    pub effect: CanonicalEffectV1,
    /// Exact artifact custody paths, normalized by digest.
    pub artifacts: Vec<EffectArtifactFileV1>,
    /// Closed direct-file mechanics policy.
    pub file_policy: EffectFilePolicyV1,
    /// Required durable reversible-preparation checkpoint for pointer commit.
    pub preparation_checkpoint: Option<Digest>,
}

impl EffectExecutorPlanV1 {
    /// Returns the exact immutable work identity bound into AG issuance.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is not closed and normalized.
    pub fn identity(&self) -> Result<Digest, String> {
        validate_plan(self)?;
        let bytes = JcsDocument::canonicalize(self)
            .map_err(|error| format!("effect-executor-plan-canonical:{error}"))?;
        Ok(Digest::hash_domain(
            EFFECT_EXECUTOR_PLAN_SCHEMA_V1,
            bytes.as_bytes(),
        ))
    }
}

/// Loads an exact canonical plan (optionally followed by one LF).
///
/// # Errors
///
/// Returns an error for noncanonical bytes, invalid shape, or unsafe paths.
pub fn load_effect_executor_plan(path: &Path) -> Result<EffectExecutorPlanV1, String> {
    if !path.is_absolute() {
        return Err("effect-executor-plan-path-not-absolute".to_owned());
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("effect-executor-plan-read:{}:{error}", path.display()))?;
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let canonical = JcsDocument::from_canonical_bytes(body)
        .map_err(|error| format!("effect-executor-plan-not-canonical:{error}"))?;
    let plan: EffectExecutorPlanV1 = serde_json::from_slice(canonical.as_bytes())
        .map_err(|error| format!("effect-executor-plan-decode:{error}"))?;
    validate_plan(&plan)?;
    Ok(plan)
}

/// Executes one exact Docket-custodied attempt or returns its prior outcome.
///
/// # Errors
///
/// Returns a refusal before mechanics for any binding or journal conflict.
pub fn execute_effect_attempt(
    plan: &EffectExecutorPlanV1,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<EffectExecutorOutcomeV1, String> {
    validate_dispatch(plan, dispatch)?;
    let mut store = EffectAttemptStoreV1::open(&plan.attempt_store)?;
    match store.reserve(plan, dispatch)? {
        ReservationV1::Prior(outcome) => return Ok(outcome),
        ReservationV1::Ambiguous => {
            return store.mark_indeterminate(
                plan,
                dispatch,
                "restart-after-reserved-attempt",
                None,
            );
        }
        ReservationV1::Reserved => {}
    }

    let artifacts = PlanArtifactSourceV1::new(plan)?;
    let pointer = UnavailablePointerHelperV1;
    let systemd = UnavailableSystemdBackendV1;
    let executor = EffectExecutorV1::new(
        &artifacts,
        &pointer,
        &systemd,
        ManagedFilePolicyV1::from(plan.file_policy),
    );
    let permit = match &plan.preparation_checkpoint {
        Some(checkpoint) => DocketCustodiedExecutionPermitV1::from_docket_preparation(
            dispatch.work.clone(),
            dispatch.marker.clone(),
            dispatch.attempt.clone(),
            plan.effect_index,
            checkpoint.clone(),
        ),
        None => DocketCustodiedExecutionPermitV1::from_docket_custody(
            dispatch.work.clone(),
            dispatch.marker.clone(),
            dispatch.attempt.clone(),
            plan.effect_index,
        ),
    };
    let receipt = executor.execute_docket_custodied_once(permit, &plan.effect);
    receipt
        .verify_bindings(
            &dispatch.work,
            &dispatch.marker,
            &dispatch.attempt,
            plan.effect_index,
            &plan.effect,
        )
        .map_err(|error| format!("effect-executor-receipt-binding:{error}"))?;
    let outcome = match &receipt.outcome {
        ExecutionOutcomeV1::Succeeded { .. } => EffectExecutorOutcomeClassV1::Success,
        ExecutionOutcomeV1::Failed { .. } => EffectExecutorOutcomeClassV1::Failure,
        ExecutionOutcomeV1::Indeterminate { .. } => EffectExecutorOutcomeClassV1::Indeterminate,
    };
    let receipt_body = JcsDocument::canonicalize(&receipt)
        .map_err(|error| format!("effect-executor-receipt-canonical:{error}"))?;
    let receipt_id = receipt
        .digest()
        .map_err(|error| format!("effect-executor-receipt-digest:{error}"))?;
    store.finish(plan, dispatch, receipt_id, outcome, receipt_body.as_bytes())
}

/// Reads only executor-local attempt evidence; never invokes mechanics.
///
/// # Errors
///
/// Returns a refusal for a missing or substituted attempt.
pub fn reconcile_effect_attempt(
    plan: &EffectExecutorPlanV1,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<EffectExecutorOutcomeV1, String> {
    validate_dispatch(plan, dispatch)?;
    let mut store = EffectAttemptStoreV1::open(&plan.attempt_store)?;
    match store.get(&dispatch.attempt)? {
        Some(record) if !record.matches(dispatch) => {
            Err("effect-executor-attempt-substitution".to_owned())
        }
        Some(record) => match record.outcome(plan)? {
            Some(outcome) => Ok(outcome),
            None => store.mark_indeterminate(
                plan,
                dispatch,
                "reconciliation-found-reserved-attempt",
                None,
            ),
        },
        None => Err("effect-executor-attempt-not-found".to_owned()),
    }
}

/// Reads executor-local evidence for one exact Docket reconciliation round.
///
/// The complete wrapper is transactionally registered before evidence is
/// returned, so changed bytes under a reused request, round, or reservation
/// fail closed. This registration is an idempotency/correspondence record,
/// not execution authority and never invokes mechanics.
///
/// # Errors
///
/// Returns a refusal for malformed wrapper bindings, changed round bytes, or
/// a missing/substituted attempt.
pub fn reconcile_effect_round(
    plan: &EffectExecutorPlanV1,
    envelope: &DocketExecutorReconciliationDispatchV1,
) -> Result<EffectExecutorOutcomeV1, String> {
    if envelope.schema != DOCKET_EXECUTOR_RECONCILIATION_DISPATCH_SCHEMA_V1 {
        return Err("effect-executor-reconciliation-envelope-schema".to_owned());
    }
    validate_dispatch(plan, &envelope.dispatch)?;
    let canonical = JcsDocument::canonicalize(envelope)
        .map_err(|error| format!("effect-executor-reconciliation-envelope-canonical:{error}"))?;
    let mut store = EffectAttemptStoreV1::open(&plan.attempt_store)?;
    store.register_reconciliation(envelope, canonical.as_bytes())?;
    match store.get(&envelope.dispatch.attempt)? {
        Some(record) if !record.matches(&envelope.dispatch) => {
            Err("effect-executor-attempt-substitution".to_owned())
        }
        Some(record) => match record.outcome(plan)? {
            Some(outcome) => Ok(outcome),
            None => store.mark_indeterminate(
                plan,
                &envelope.dispatch,
                "reconciliation-found-reserved-attempt",
                None,
            ),
        },
        None => Err("effect-executor-attempt-not-found".to_owned()),
    }
}

fn validate_plan(plan: &EffectExecutorPlanV1) -> Result<(), String> {
    if plan.schema != EFFECT_EXECUTOR_PLAN_SCHEMA_V1 {
        return Err("effect-executor-plan-schema".to_owned());
    }
    if !plan.attempt_store.is_absolute() || plan.file_policy.max_content_bytes == 0 {
        return Err("effect-executor-plan-store-or-limit".to_owned());
    }
    CanonicalEffectScopeV1::new(
        "executor-journal-binding/v1".to_owned(),
        vec![ag_campaign::governed::CanonicalEffectResourceV1 {
            resource: plan.journal_binding.resource.clone(),
            path: plan.journal_binding.path.clone(),
            operations: vec![plan.journal_binding.operation],
        }],
    )
    .map_err(|_| "effect-executor-plan-journal-binding".to_owned())?;
    let required_operation = match &plan.effect {
        CanonicalEffectV1::ManagedFilePut {
            expected_content, ..
        } => {
            if expected_content.is_some() {
                CanonicalEffectOperationV1::Modify
            } else {
                CanonicalEffectOperationV1::Create
            }
        }
        CanonicalEffectV1::ManagedFileDelete { .. } => CanonicalEffectOperationV1::Delete,
        CanonicalEffectV1::ManagedPointerPromotion { .. } => CanonicalEffectOperationV1::Modify,
        CanonicalEffectV1::SystemdUnit { .. } | CanonicalEffectV1::SystemdManagerReload { .. } => {
            CanonicalEffectOperationV1::Execute
        }
    };
    if plan.journal_binding.operation != required_operation {
        return Err("effect-executor-plan-journal-operation".to_owned());
    }
    let is_promotion = matches!(
        &plan.effect,
        CanonicalEffectV1::ManagedPointerPromotion { .. }
    );
    if is_promotion != plan.preparation_checkpoint.is_some() {
        return Err("effect-executor-plan-preparation-checkpoint".to_owned());
    }
    let mut previous: Option<&Digest> = None;
    for artifact in &plan.artifacts {
        if !artifact.path.is_absolute() {
            return Err("effect-executor-artifact-path-not-absolute".to_owned());
        }
        if previous.is_some_and(|prior| prior >= &artifact.digest) {
            return Err("effect-executor-artifacts-not-unique-sorted".to_owned());
        }
        previous = Some(&artifact.digest);
    }
    Ok(())
}

fn validate_dispatch(
    plan: &EffectExecutorPlanV1,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<(), String> {
    validate_plan(plan)?;
    let journal_admitted = dispatch.effect_scope.resources().iter().any(|row| {
        row.resource == plan.journal_binding.resource
            && row.path == plan.journal_binding.path
            && row.operations.contains(&plan.journal_binding.operation)
    });
    if dispatch.work_schema != EFFECT_EXECUTOR_WORK_SCHEMA_V1
        || dispatch.work != plan.identity()?
        || dispatch.subject != plan.subject
        || dispatch.effect_scope.validate().is_err()
        || dispatch.effect_scope.digest() != dispatch.effect_scope_digest
        || dispatch.effect_scope_digest != plan.scope
        || !journal_admitted
    {
        return Err("effect-executor-dispatch-plan-binding".to_owned());
    }
    Ok(())
}

fn effect_identity(effect: &CanonicalEffectV1) -> Result<Digest, String> {
    let canonical = JcsDocument::canonicalize(effect)
        .map_err(|error| format!("effect-executor-effect-canonical:{error}"))?;
    Ok(Digest::hash_domain(
        "ag-effectd.canonical-effect/v1",
        canonical.as_bytes(),
    ))
}

fn effect_journal(
    plan: &EffectExecutorPlanV1,
    outcome: EffectExecutorOutcomeClassV1,
) -> Result<Vec<EffectExecutorJournalEntryV1>, String> {
    if outcome != EffectExecutorOutcomeClassV1::Success {
        return Ok(Vec::new());
    }
    Ok(vec![EffectExecutorJournalEntryV1 {
        resource: plan.journal_binding.resource.clone(),
        path: plan.journal_binding.path.clone(),
        operation: plan.journal_binding.operation,
        effect_identity: effect_identity(&plan.effect)?,
    }])
}

struct PlanArtifactSourceV1 {
    paths: BTreeMap<Digest, PathBuf>,
    maximum: u64,
}

impl PlanArtifactSourceV1 {
    fn new(plan: &EffectExecutorPlanV1) -> Result<Self, String> {
        let paths = plan
            .artifacts
            .iter()
            .map(|artifact| (artifact.digest.clone(), artifact.path.clone()))
            .collect::<BTreeMap<_, _>>();
        if paths.len() != plan.artifacts.len() {
            return Err("effect-executor-artifact-duplicate".to_owned());
        }
        Ok(Self {
            paths,
            maximum: plan.file_policy.max_content_bytes,
        })
    }
}

impl ArtifactSourceV1 for PlanArtifactSourceV1 {
    fn load(&self, digest: &Digest) -> Result<Vec<u8>, ArtifactReadErrorV1> {
        let path = self.paths.get(digest).ok_or_else(|| {
            ArtifactReadErrorV1::new("artifact_not_bound", "effect plan does not bind artifact")
        })?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| ArtifactReadErrorV1::new("artifact_open", error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| ArtifactReadErrorV1::new("artifact_metadata", error.to_string()))?;
        if !metadata.is_file() || metadata.len() > self.maximum {
            return Err(ArtifactReadErrorV1::new(
                "artifact_shape",
                "artifact is not a bounded regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(self.maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ArtifactReadErrorV1::new("artifact_read", error.to_string()))?;
        if bytes.len() as u64 > self.maximum || Digest::hash_bytes(&bytes) != *digest {
            return Err(ArtifactReadErrorV1::new(
                "artifact_identity",
                "artifact bytes differ from exact plan identity",
            ));
        }
        Ok(bytes)
    }
}

struct UnavailablePointerHelperV1;

impl PinnedPointerHelperV1 for UnavailablePointerHelperV1 {
    fn identity(&self) -> CapabilityOutcomeV1<PinnedHelperIdentityV1> {
        CapabilityOutcomeV1::Failed(unavailable("pointer_helper_unavailable"))
    }

    fn prepare(
        &self,
        _request: &PointerPreparationRequestV1,
        _artifact: &[u8],
    ) -> CapabilityOutcomeV1<PointerPreparationSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("pointer_helper_unavailable"))
    }

    fn compare_and_swap(
        &self,
        _request: &PointerCasRequestV1,
    ) -> CapabilityOutcomeV1<PointerCasSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("pointer_helper_unavailable"))
    }
}

struct UnavailableSystemdBackendV1;

impl SystemdDbusBackendV1 for UnavailableSystemdBackendV1 {
    fn unit_action(
        &self,
        _request: &SystemdUnitRequestV1,
    ) -> CapabilityOutcomeV1<SystemdUnitSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("systemd_backend_unavailable"))
    }

    fn reload_manager(
        &self,
        _request: &SystemdManagerReloadRequestV1,
    ) -> CapabilityOutcomeV1<SystemdManagerReloadSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("systemd_backend_unavailable"))
    }
}

fn unavailable(code: &str) -> CapabilityFailureV1 {
    CapabilityFailureV1 {
        code: code.to_owned(),
        detail: "capability is not installed in this authority-neutral adapter".to_owned(),
        evidence: None,
    }
}

#[derive(Clone)]
struct AttemptRecordV1 {
    attempt: Digest,
    marker: Digest,
    work: Digest,
    subject: Digest,
    scope: Digest,
    status: String,
    receipt: Option<Digest>,
    receipt_body: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIndeterminateReceiptV1 {
    schema: String,
    attempt: Digest,
    marker: Digest,
    reason: String,
    evidence: Option<Vec<u8>>,
}

impl AttemptRecordV1 {
    fn matches(&self, dispatch: &EffectExecutorDispatchV1) -> bool {
        self.attempt == dispatch.attempt
            && self.marker == dispatch.marker
            && self.work == dispatch.work
            && self.subject == dispatch.subject
            && self.scope == dispatch.effect_scope_digest
    }

    fn outcome(
        &self,
        plan: &EffectExecutorPlanV1,
    ) -> Result<Option<EffectExecutorOutcomeV1>, String> {
        let Some(receipt) = &self.receipt else {
            return if self.status == "started" && self.receipt_body.is_none() {
                Ok(None)
            } else {
                Err("effect-executor-attempt-corrupt".to_owned())
            };
        };
        let body = self
            .receipt_body
            .as_deref()
            .ok_or_else(|| "effect-executor-receipt-body-missing".to_owned())?;
        let canonical = JcsDocument::from_canonical_bytes(body)
            .map_err(|error| format!("effect-executor-receipt-body-invalid:{error}"))?;
        if Digest::from_serializable(
            &serde_json::from_slice::<serde_json::Value>(canonical.as_bytes())
                .map_err(|error| format!("effect-executor-receipt-json:{error}"))?,
        )
        .map_err(|error| format!("effect-executor-receipt-redigest:{error}"))?
            != *receipt
        {
            return Err("effect-executor-receipt-identity-mismatch".to_owned());
        }
        let outcome = match self.status.as_str() {
            "success" => {
                self.verify_effect_receipt(canonical.as_bytes(), plan, false)?;
                EffectExecutorOutcomeClassV1::Success
            }
            "failure" => {
                self.verify_effect_receipt(canonical.as_bytes(), plan, false)?;
                EffectExecutorOutcomeClassV1::Failure
            }
            "indeterminate" => {
                if self
                    .verify_effect_receipt(canonical.as_bytes(), plan, true)
                    .is_err()
                {
                    let record: StoredIndeterminateReceiptV1 =
                        serde_json::from_slice(canonical.as_bytes()).map_err(|error| {
                            format!("effect-executor-indeterminate-body:{error}")
                        })?;
                    if record.schema != "ag-effectd.executor-indeterminate/v1"
                        || record.attempt != self.attempt
                        || record.marker != self.marker
                        || record.reason.is_empty()
                    {
                        return Err("effect-executor-indeterminate-binding".to_owned());
                    }
                    let _ = record.evidence;
                }
                EffectExecutorOutcomeClassV1::Indeterminate
            }
            _ => return Err("effect-executor-attempt-status".to_owned()),
        };
        Ok(Some(EffectExecutorOutcomeV1 {
            attempt: self.attempt.clone(),
            marker: self.marker.clone(),
            receipt: receipt.clone(),
            outcome,
            effect_journal: effect_journal(plan, outcome)?,
            immutable_work_checkpoint: None,
            governed_repair: None,
        }))
    }

    fn verify_effect_receipt(
        &self,
        body: &[u8],
        plan: &EffectExecutorPlanV1,
        expect_indeterminate: bool,
    ) -> Result<(), String> {
        let receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(body)
            .map_err(|error| format!("effect-executor-typed-receipt:{error}"))?;
        receipt
            .verify_bindings(
                &self.work,
                &self.marker,
                &self.attempt,
                plan.effect_index,
                &plan.effect,
            )
            .map_err(|_| "effect-executor-typed-receipt-binding".to_owned())?;
        let is_indeterminate = matches!(receipt.outcome, ExecutionOutcomeV1::Indeterminate { .. });
        let is_success = matches!(receipt.outcome, ExecutionOutcomeV1::Succeeded { .. });
        if is_indeterminate != expect_indeterminate
            || (self.status == "success" && !is_success)
            || (self.status == "failure" && (is_success || is_indeterminate))
        {
            return Err("effect-executor-typed-receipt-outcome".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ReservationV1 {
    Reserved,
    Prior(EffectExecutorOutcomeV1),
    Ambiguous,
}

struct EffectAttemptStoreV1 {
    connection: Connection,
}

impl EffectAttemptStoreV1 {
    fn open(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("effect-executor-store-path-not-absolute".to_owned());
        }
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("effect-executor-store-parent:{error}"))?;
            }
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
            {
                Ok(file) => drop(file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("effect-executor-store-create:{error}")),
            }
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("effect-executor-store-lstat:{error}"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err("effect-executor-store-not-regular".to_owned());
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| format!("effect-executor-store-open:{error}"))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| format!("effect-executor-store-busy:{error}"))?;
        // Two first deliveries can discover the newly created database at the
        // same time. `busy_timeout` covers SQLITE_BUSY, but SQLite can report
        // SQLITE_LOCKED while the other connection changes journal mode or
        // installs the schema.  Initialization is authority-neutral and
        // idempotent, so retry only these two lock classifications within the
        // same bounded five-second window used for write contention.
        execute_batch_with_lock_retry(
            &connection,
            "effect-executor-store-pragmas",
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
        )?;
        execute_batch_with_lock_retry(&connection, "effect-executor-store-schema", STORE_SCHEMA)?;
        verify_reconciliation_context_schema(&connection)?;
        Ok(Self { connection })
    }

    fn reserve(
        &mut self,
        plan: &EffectExecutorPlanV1,
        dispatch: &EffectExecutorDispatchV1,
    ) -> Result<ReservationV1, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("effect-executor-reserve-begin:{error}"))?;
        let existing = read_attempt(&transaction, &dispatch.attempt)?;
        let result = match existing {
            Some(record) if !record.matches(dispatch) => {
                return Err("effect-executor-attempt-substitution".to_owned());
            }
            Some(record) => match record.outcome(plan)? {
                Some(outcome) => ReservationV1::Prior(outcome),
                None => ReservationV1::Ambiguous,
            },
            None => {
                transaction
                    .execute(
                        "INSERT INTO docket_effect_attempt
                         (attempt,marker,work,subject,scope,status)
                         VALUES (?1,?2,?3,?4,?5,'started')",
                        params![
                            dispatch.attempt.as_str(),
                            dispatch.marker.as_str(),
                            dispatch.work.as_str(),
                            dispatch.subject.as_str(),
                            dispatch.effect_scope_digest.as_str()
                        ],
                    )
                    .map_err(|error| format!("effect-executor-reserve-insert:{error}"))?;
                ReservationV1::Reserved
            }
        };
        transaction
            .commit()
            .map_err(|error| format!("effect-executor-reserve-commit:{error}"))?;
        checkpoint(&self.connection)?;
        Ok(result)
    }

    fn register_reconciliation(
        &mut self,
        envelope: &DocketExecutorReconciliationDispatchV1,
        canonical: &[u8],
    ) -> Result<(), String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("effect-executor-reconciliation-begin:{error}"))?;
        let existing: Option<(String, String, String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT request,reservation,source_cut,attempt,dispatch_jcs
                 FROM docket_reconciliation_context WHERE round=?1",
                params![envelope.round.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("effect-executor-reconciliation-read:{error}"))?;
        if let Some((request, reservation, source_cut, attempt, bytes)) = existing {
            if request != envelope.request.as_str()
                || reservation != envelope.reservation.as_str()
                || source_cut != envelope.source_cut.as_str()
                || attempt != envelope.dispatch.attempt.as_str()
                || bytes != canonical
            {
                return Err("effect-executor-reconciliation-round-substitution".to_owned());
            }
        } else {
            transaction
                .execute(
                    "INSERT INTO docket_reconciliation_context
                     (round,request,reservation,source_cut,attempt,dispatch_jcs)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        envelope.round.as_str(),
                        envelope.request.as_str(),
                        envelope.reservation.as_str(),
                        envelope.source_cut.as_str(),
                        envelope.dispatch.attempt.as_str(),
                        canonical,
                    ],
                )
                .map_err(|error| format!("effect-executor-reconciliation-insert:{error}"))?;
        }
        transaction
            .commit()
            .map_err(|error| format!("effect-executor-reconciliation-commit:{error}"))?;
        checkpoint(&self.connection)
    }

    fn get(&mut self, attempt: &Digest) -> Result<Option<AttemptRecordV1>, String> {
        read_attempt(&self.connection, attempt)
    }

    fn finish(
        &mut self,
        plan: &EffectExecutorPlanV1,
        dispatch: &EffectExecutorDispatchV1,
        receipt: Digest,
        outcome: EffectExecutorOutcomeClassV1,
        body: &[u8],
    ) -> Result<EffectExecutorOutcomeV1, String> {
        let status = match outcome {
            EffectExecutorOutcomeClassV1::Success => "success",
            EffectExecutorOutcomeClassV1::Failure => "failure",
            EffectExecutorOutcomeClassV1::Indeterminate => "indeterminate",
        };
        let changed = self
            .connection
            .execute(
                "UPDATE docket_effect_attempt
                 SET status=?1,receipt=?2,receipt_body=?3
                 WHERE attempt=?4 AND marker=?5 AND status='started'",
                params![
                    status,
                    receipt.as_str(),
                    body,
                    dispatch.attempt.as_str(),
                    dispatch.marker.as_str()
                ],
            )
            .map_err(|error| format!("effect-executor-finish:{error}"))?;
        if changed != 1 {
            return self
                .get(&dispatch.attempt)?
                .ok_or_else(|| "effect-executor-finish-attempt-missing".to_owned())?
                .outcome(plan)?
                .ok_or_else(|| "effect-executor-finish-conflict".to_owned());
        }
        checkpoint(&self.connection)?;
        Ok(EffectExecutorOutcomeV1 {
            attempt: dispatch.attempt.clone(),
            marker: dispatch.marker.clone(),
            receipt,
            outcome,
            effect_journal: effect_journal(plan, outcome)?,
            immutable_work_checkpoint: None,
            governed_repair: None,
        })
    }

    fn mark_indeterminate(
        &mut self,
        plan: &EffectExecutorPlanV1,
        dispatch: &EffectExecutorDispatchV1,
        reason: &str,
        evidence: Option<&[u8]>,
    ) -> Result<EffectExecutorOutcomeV1, String> {
        #[derive(Serialize)]
        struct Indeterminate<'a> {
            schema: &'static str,
            attempt: &'a Digest,
            marker: &'a Digest,
            reason: &'a str,
            evidence: Option<&'a [u8]>,
        }
        let record = Indeterminate {
            schema: "ag-effectd.executor-indeterminate/v1",
            attempt: &dispatch.attempt,
            marker: &dispatch.marker,
            reason,
            evidence,
        };
        let body = JcsDocument::canonicalize(&record)
            .map_err(|error| format!("effect-executor-indeterminate-canonical:{error}"))?;
        let receipt = Digest::from_serializable(&record)
            .map_err(|error| format!("effect-executor-indeterminate-digest:{error}"))?;
        self.finish(
            plan,
            dispatch,
            receipt,
            EffectExecutorOutcomeClassV1::Indeterminate,
            body.as_bytes(),
        )
    }
}

fn verify_reconciliation_context_schema(connection: &Connection) -> Result<(), String> {
    let mut statement = connection
        .prepare("PRAGMA table_info(docket_reconciliation_context)")
        .map_err(|error| format!("effect-executor-reconciliation-schema-prepare:{error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| format!("effect-executor-reconciliation-schema-read:{error}"))?;
    let columns = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("effect-executor-reconciliation-schema-row:{error}"))?;
    let expected = vec![
        ("round".to_owned(), "TEXT".to_owned(), 1, 1),
        ("request".to_owned(), "TEXT".to_owned(), 1, 0),
        ("reservation".to_owned(), "TEXT".to_owned(), 1, 0),
        ("source_cut".to_owned(), "TEXT".to_owned(), 1, 0),
        ("attempt".to_owned(), "TEXT".to_owned(), 1, 0),
        ("dispatch_jcs".to_owned(), "BLOB".to_owned(), 1, 0),
    ];
    if columns != expected {
        return Err("effect-executor-reconciliation-schema-columns".to_owned());
    }
    let mut statement = connection
        .prepare("PRAGMA index_list(docket_reconciliation_context)")
        .map_err(|error| format!("effect-executor-reconciliation-index-prepare:{error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|error| format!("effect-executor-reconciliation-index-read:{error}"))?;
    let mut indexed = BTreeSet::new();
    for row in rows {
        let (name, unique, partial) =
            row.map_err(|error| format!("effect-executor-reconciliation-index-row:{error}"))?;
        if unique != 1 || partial != 0 {
            return Err("effect-executor-reconciliation-index-shape".to_owned());
        }
        let escaped = name.replace('"', "\"\"");
        let query = format!("PRAGMA index_info(\"{escaped}\")");
        let mut columns_statement = connection
            .prepare(&query)
            .map_err(|error| format!("effect-executor-reconciliation-index-info:{error}"))?;
        let names = columns_statement
            .query_map([], |row| row.get::<_, String>(2))
            .map_err(|error| format!("effect-executor-reconciliation-index-columns:{error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("effect-executor-reconciliation-index-column:{error}"))?;
        if names.len() != 1 || !indexed.insert(names[0].clone()) {
            return Err("effect-executor-reconciliation-index-shape".to_owned());
        }
    }
    if indexed.into_iter().collect::<Vec<_>>()
        != [
            "request".to_owned(),
            "reservation".to_owned(),
            "round".to_owned(),
        ]
    {
        return Err("effect-executor-reconciliation-index-set".to_owned());
    }
    Ok(())
}

fn execute_batch_with_lock_retry(
    connection: &Connection,
    context: &str,
    sql: &str,
) -> Result<(), String> {
    const RETRY_COUNT: usize = 1_000;
    const RETRY_DELAY: Duration = Duration::from_millis(5);

    for attempt in 0..=RETRY_COUNT {
        match connection.execute_batch(sql) {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt < RETRY_COUNT
                    && matches!(
                        error.sqlite_error_code(),
                        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
                    ) =>
            {
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(format!("{context}:{error}")),
        }
    }
    unreachable!("bounded SQLite initialization retry returns from every branch")
}

fn read_attempt(
    connection: &Connection,
    attempt: &Digest,
) -> Result<Option<AttemptRecordV1>, String> {
    connection
        .query_row(
            "SELECT attempt,marker,work,subject,scope,status,receipt,receipt_body
             FROM docket_effect_attempt WHERE attempt=?1",
            [attempt.as_str()],
            |row| {
                let attempt: String = row.get(0)?;
                let marker: String = row.get(1)?;
                let work: String = row.get(2)?;
                let subject: String = row.get(3)?;
                let scope: String = row.get(4)?;
                let receipt: Option<String> = row.get(6)?;
                Ok((
                    attempt,
                    marker,
                    work,
                    subject,
                    scope,
                    row.get(5)?,
                    receipt,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("effect-executor-attempt-read:{error}"))?
        .map(
            |(attempt, marker, work, subject, scope, status, receipt, receipt_body)| {
                Ok(AttemptRecordV1 {
                    attempt: Digest::parse(&attempt)
                        .map_err(|error| format!("effect-executor-attempt-digest:{error}"))?,
                    marker: Digest::parse(&marker)
                        .map_err(|error| format!("effect-executor-marker-digest:{error}"))?,
                    work: Digest::parse(&work)
                        .map_err(|error| format!("effect-executor-work-digest:{error}"))?,
                    subject: Digest::parse(&subject)
                        .map_err(|error| format!("effect-executor-subject-digest:{error}"))?,
                    scope: Digest::parse(&scope)
                        .map_err(|error| format!("effect-executor-scope-digest:{error}"))?,
                    status,
                    receipt: receipt
                        .map(|value| {
                            Digest::parse(&value)
                                .map_err(|error| format!("effect-executor-receipt-digest:{error}"))
                        })
                        .transpose()?,
                    receipt_body,
                })
            },
        )
        .transpose()
}

fn checkpoint(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
        .map_err(|error| format!("effect-executor-store-checkpoint:{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_campaign::governed::{CanonicalEffectOperationV1, CanonicalEffectResourceV1};
    use ag_effect::TargetId;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn fixture() -> (
        tempfile::TempDir,
        EffectExecutorPlanV1,
        EffectExecutorDispatchV1,
    ) {
        let directory = tempfile::tempdir().expect("temporary effect executor root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let artifact_path = directory.path().join("artifact");
        std::fs::write(&artifact_path, b"governed-loop-effect\n").unwrap();
        let content = Digest::hash_bytes(b"governed-loop-effect\n");
        let subject = Digest::hash_bytes(b"effect-subject");
        let effect_scope = CanonicalEffectScopeV1::new(
            "repository-write/v1".to_owned(),
            vec![CanonicalEffectResourceV1 {
                resource: "repository".to_owned(),
                path: "fixtures/exact-work".to_owned(),
                operations: vec![CanonicalEffectOperationV1::Create],
            }],
        )
        .unwrap();
        let scope = effect_scope.digest();
        let plan = EffectExecutorPlanV1 {
            schema: EFFECT_EXECUTOR_PLAN_SCHEMA_V1.to_owned(),
            attempt_store: directory.path().join("attempt.sqlite3"),
            subject: subject.clone(),
            scope: scope.clone(),
            journal_binding: EffectExecutorJournalBindingV1 {
                resource: "repository".to_owned(),
                path: "fixtures/exact-work".to_owned(),
                operation: CanonicalEffectOperationV1::Create,
            },
            effect_index: 0,
            effect: CanonicalEffectV1::ManagedFilePut {
                target: TargetId::parse("governed-loop-test").unwrap(),
                path: directory.path().join("target").display().to_string(),
                expected_content: None,
                content: content.clone(),
                mode: 0o600,
                uid: nix::unistd::Uid::current().as_raw(),
                gid: nix::unistd::Gid::current().as_raw(),
            },
            artifacts: vec![EffectArtifactFileV1 {
                digest: content,
                path: artifact_path,
            }],
            file_policy: EffectFilePolicyV1 {
                max_content_bytes: 1024,
                trusted_ancestor_uid: std::fs::metadata("/").unwrap().uid(),
                trusted_parent_uid: nix::unistd::Uid::current().as_raw(),
                require_private_parent_writes: true,
            },
            preparation_checkpoint: None,
        };
        let dispatch = EffectExecutorDispatchV1 {
            attempt: Digest::hash_bytes(b"effect-attempt"),
            marker: Digest::hash_bytes(b"effect-marker"),
            work_schema: EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
            work: plan.identity().unwrap(),
            subject,
            effect_scope,
            effect_scope_digest: scope,
        };
        (directory, plan, dispatch)
    }

    #[test]
    fn exact_docket_attempt_executes_once_and_replays_receipt() {
        let (_directory, plan, dispatch) = fixture();
        let first = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(
            first.outcome,
            EffectExecutorOutcomeClassV1::Success,
            "{first:?}"
        );
        let CanonicalEffectV1::ManagedFilePut { path, .. } = &plan.effect else {
            unreachable!()
        };
        std::fs::write(path, b"hostile-after-first\n").unwrap();
        let replay = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(replay, first);
        assert_eq!(std::fs::read(path).unwrap(), b"hostile-after-first\n");
        assert_eq!(reconcile_effect_attempt(&plan, &dispatch).unwrap(), first);
    }

    #[test]
    fn reconciliation_envelope_is_strict_and_round_bytes_are_one_use() {
        let (_directory, plan, dispatch) = fixture();
        let outcome = execute_effect_attempt(&plan, &dispatch).unwrap();
        let envelope = DocketExecutorReconciliationDispatchV1 {
            schema: DOCKET_EXECUTOR_RECONCILIATION_DISPATCH_SCHEMA_V1.to_owned(),
            request: Digest::hash_bytes(b"round-request"),
            round: Digest::hash_bytes(b"round"),
            reservation: Digest::hash_bytes(b"round-reservation"),
            source_cut: Digest::hash_bytes(b"round-source-cut"),
            dispatch,
        };
        assert_eq!(reconcile_effect_round(&plan, &envelope).unwrap(), outcome);
        assert_eq!(reconcile_effect_round(&plan, &envelope).unwrap(), outcome);

        let mut changed = envelope.clone();
        changed.source_cut = Digest::hash_bytes(b"changed-source-cut");
        assert_eq!(
            reconcile_effect_round(&plan, &changed).unwrap_err(),
            "effect-executor-reconciliation-round-substitution"
        );

        let mut wrong_schema = envelope;
        wrong_schema.schema = "docket.governed-loop.executor-reconciliation-dispatch/v2".to_owned();
        assert_eq!(
            reconcile_effect_round(&plan, &wrong_schema).unwrap_err(),
            "effect-executor-reconciliation-envelope-schema"
        );
    }

    #[test]
    fn reconciliation_context_reopen_refuses_incompatible_precreated_schema() {
        let (_directory, plan, dispatch) = fixture();
        let connection = Connection::open(&plan.attempt_store).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE docket_reconciliation_context (
                     round TEXT PRIMARY KEY NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        drop(connection);
        let envelope = DocketExecutorReconciliationDispatchV1 {
            schema: DOCKET_EXECUTOR_RECONCILIATION_DISPATCH_SCHEMA_V1.to_owned(),
            request: Digest::hash_bytes(b"round-request"),
            round: Digest::hash_bytes(b"round"),
            reservation: Digest::hash_bytes(b"round-reservation"),
            source_cut: Digest::hash_bytes(b"round-source-cut"),
            dispatch,
        };
        assert_eq!(
            reconcile_effect_round(&plan, &envelope).unwrap_err(),
            "effect-executor-reconciliation-schema-columns"
        );
    }

    #[test]
    fn ordinary_outcome_omits_absent_governed_fields_and_refuses_explicit_null() {
        let (_directory, plan, dispatch) = fixture();
        let outcome = execute_effect_attempt(&plan, &dispatch).unwrap();
        let canonical = JcsDocument::canonicalize(&outcome).unwrap();
        let value: serde_json::Value = serde_json::from_slice(canonical.as_bytes()).unwrap();
        assert!(value.get("immutable_work_checkpoint").is_none());
        assert!(value.get("governed_repair").is_none());

        let mut explicit_null = value;
        explicit_null
            .as_object_mut()
            .unwrap()
            .insert("governed_repair".to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<EffectExecutorOutcomeV1>(explicit_null).is_err());
    }

    #[test]
    fn marker_and_work_substitution_refuse_before_effect() {
        let (_directory, plan, dispatch) = fixture();
        let mut wrong_marker = dispatch.clone();
        wrong_marker.marker = Digest::hash_bytes(b"wrong-marker");
        execute_effect_attempt(&plan, &wrong_marker).unwrap();
        assert_eq!(
            execute_effect_attempt(&plan, &dispatch).unwrap_err(),
            "effect-executor-attempt-substitution"
        );

        let mut wrong_work = dispatch.clone();
        wrong_work.attempt = Digest::hash_bytes(b"another-attempt");
        wrong_work.work = Digest::hash_bytes(b"wrong-work");
        assert_eq!(
            execute_effect_attempt(&plan, &wrong_work).unwrap_err(),
            "effect-executor-dispatch-plan-binding"
        );
    }

    #[test]
    fn reserved_crash_cut_becomes_indeterminate_and_never_executes() {
        let (_directory, plan, dispatch) = fixture();
        let mut store = EffectAttemptStoreV1::open(&plan.attempt_store).unwrap();
        assert!(matches!(
            store.reserve(&plan, &dispatch).unwrap(),
            ReservationV1::Reserved
        ));
        drop(store);
        let outcome = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(outcome.outcome, EffectExecutorOutcomeClassV1::Indeterminate);
        let CanonicalEffectV1::ManagedFilePut { path, .. } = &plan.effect else {
            unreachable!()
        };
        assert!(!Path::new(path).exists());
    }

    #[test]
    fn concurrent_delivery_reserves_exactly_one_mechanics_attempt() {
        let (_directory, plan, dispatch) = fixture();
        let (left, right) = std::thread::scope(|scope| {
            let left_plan = plan.clone();
            let left_dispatch = dispatch.clone();
            let left = scope.spawn(move || {
                let mut store = EffectAttemptStoreV1::open(&left_plan.attempt_store).unwrap();
                store.reserve(&left_plan, &left_dispatch).unwrap()
            });
            let right_plan = plan.clone();
            let right_dispatch = dispatch.clone();
            let right = scope.spawn(move || {
                let mut store = EffectAttemptStoreV1::open(&right_plan.attempt_store).unwrap();
                store.reserve(&right_plan, &right_dispatch).unwrap()
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        let reserved = usize::from(matches!(left, ReservationV1::Reserved))
            + usize::from(matches!(right, ReservationV1::Reserved));
        let ambiguous = usize::from(matches!(left, ReservationV1::Ambiguous))
            + usize::from(matches!(right, ReservationV1::Ambiguous));
        assert_eq!((reserved, ambiguous), (1, 1));
    }

    #[test]
    fn restart_refuses_recomputed_receipt_for_substituted_effect() {
        let (_directory, plan, dispatch) = fixture();
        execute_effect_attempt(&plan, &dispatch).unwrap();

        let connection = Connection::open(&plan.attempt_store).unwrap();
        let body: Vec<u8> = connection
            .query_row(
                "SELECT receipt_body FROM docket_effect_attempt WHERE attempt=?1",
                [dispatch.attempt.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let mut receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(&body).unwrap();
        receipt.effect_index += 1;
        let hostile_body = JcsDocument::canonicalize(&receipt).unwrap();
        let hostile_digest = receipt.digest().unwrap();
        connection
            .execute(
                "UPDATE docket_effect_attempt SET receipt=?1,receipt_body=?2 WHERE attempt=?3",
                params![
                    hostile_digest.as_str(),
                    hostile_body.as_bytes(),
                    dispatch.attempt.as_str()
                ],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            reconcile_effect_attempt(&plan, &dispatch).unwrap_err(),
            "effect-executor-typed-receipt-binding"
        );
    }
}
