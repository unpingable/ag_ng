//! Machine-bound systemd execution for exact Docket-custodied V2 attempts.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ag_effect::executor::{
    DocketEffectExecutionReceiptV1, EffectSuccessV1, ExecutionFailureCodeV1, ExecutionFailureV1,
    ExecutionIndeterminateCodeV1, ExecutionIndeterminateV1, ExecutionOutcomeV1, ExecutionPhaseV1,
    DOCKET_EXECUTION_RECEIPT_SCHEMA_V1,
};
use ag_effect::CanonicalEffectV1;
use ag_effect::SystemdUnitActionV1;
use ag_primitives::{Digest, JcsDocument};
use rusqlite::{params, OptionalExtension as _, TransactionBehavior};
use rustix::fs::{flock, FlockOperation};
use serde::{Deserialize, Serialize};

use super::{
    checkpoint, read_attempt, validate_systemd_evidence_guards, AttemptRecordV1,
    EffectAttemptStoreV1, EffectExecutorDispatchV1, EffectExecutorOutcomeClassV1,
    EffectExecutorOutcomeV1, EffectFilePolicyV1,
};

#[cfg(feature = "systemd-dbus")]
mod zbus_driver;

/// Exact sealed machine-bound plan schema.
pub const EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2: &str =
    "ag-effectd.docket-executor-systemd-plan/v2";
/// Exact Docket work schema for a machine-bound systemd plan.
pub const EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2: &str =
    "ag-effectd.docket-executor-systemd-work/v2";
/// Content-addressed systemd D-Bus evidence schema.
pub const SYSTEMD_DBUS_EVIDENCE_SCHEMA_V1: &str = "ag-effectd.systemd-dbus-evidence/v1";
#[cfg(test)]
mod qualification_tests;

pub(super) const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_MESSAGES: usize = 16;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_CUMULATIVE_MESSAGE_BYTES: usize = 256 * 1024;

/// A distinct machine-bound systemd plan. V1 remains byte-for-byte unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorSystemdPlanV2 {
    /// Plan schema.
    pub schema: String,
    /// Executor-local attempt and evidence store.
    pub attempt_store: PathBuf,
    /// Exact Docket standing subject.
    pub subject: Digest,
    /// Exact Docket standing scope.
    pub scope: Digest,
    /// Effect position in the exact plan.
    pub effect_index: u32,
    /// One exact canonical `SystemdUnit` effect.
    pub effect: CanonicalEffectV1,
    /// Retained V1 file-policy field; it grants no systemd authority.
    pub file_policy: EffectFilePolicyV1,
    /// Exact lowercase system-bus machine identity.
    pub systemd_machine_identity: String,
    /// Maximum wait for the local exclusive execution lock.
    pub execution_lock_timeout_ms: u64,
    /// Maximum wait after `StartUnit` transmission begins.
    pub job_timeout_ms: u64,
}

impl EffectExecutorSystemdPlanV2 {
    /// Validate and derive the immutable work identity.
    ///
    /// # Errors
    ///
    /// Refuses a structurally invalid plan or failed canonicalization.
    pub fn identity(&self) -> Result<Digest, String> {
        validate_systemd_plan(self)?;
        let bytes = JcsDocument::canonicalize(self)
            .map_err(|error| format!("systemd-plan-canonical:{error}"))?;
        Ok(Digest::hash_domain(
            EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2,
            bytes.as_bytes(),
        ))
    }
}

/// Load one canonical, bounded, non-symlink V2 plan.
///
/// # Errors
///
/// Refuses unsafe path custody, unbounded input, or invalid canonical content.
pub fn load_effect_executor_systemd_plan(
    path: &Path,
) -> Result<EffectExecutorSystemdPlanV2, String> {
    if !path.is_absolute() {
        return Err("systemd-plan-path-not-absolute".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("systemd-plan-open:{}:{error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("systemd-plan-metadata:{error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PLAN_BYTES {
        return Err("systemd-plan-not-bounded-regular-file".to_owned());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("systemd-plan-read:{error}"))?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err("systemd-plan-too-large".to_owned());
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let canonical = JcsDocument::from_canonical_bytes(body)
        .map_err(|error| format!("systemd-plan-not-canonical:{error}"))?;
    decode_effect_executor_systemd_plan(&canonical)
}

pub(super) fn decode_effect_executor_systemd_plan(
    canonical: &JcsDocument,
) -> Result<EffectExecutorSystemdPlanV2, String> {
    let plan: EffectExecutorSystemdPlanV2 = serde_json::from_slice(canonical.as_bytes())
        .map_err(|error| format!("systemd-plan-decode:{error}"))?;
    validate_systemd_plan(&plan)?;
    Ok(plan)
}

fn validate_systemd_plan(plan: &EffectExecutorSystemdPlanV2) -> Result<(), String> {
    if plan.schema != EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2 {
        return Err("systemd-plan-schema".to_owned());
    }
    if !plan.attempt_store.is_absolute() || plan.file_policy.max_content_bytes == 0 {
        return Err("systemd-plan-store-or-limit".to_owned());
    }
    if plan.systemd_machine_identity.len() != 32
        || !plan
            .systemd_machine_identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("systemd-plan-machine-identity".to_owned());
    }
    if !(1..=5_000).contains(&plan.execution_lock_timeout_ms)
        || !(1..=30_000).contains(&plan.job_timeout_ms)
    {
        return Err("systemd-plan-timeout".to_owned());
    }
    let CanonicalEffectV1::SystemdUnit {
        unit,
        expected_active_state,
        expected_unit_file_state,
        ..
    } = &plan.effect
    else {
        return Err("systemd-plan-effect-family".to_owned());
    };
    if unit.is_empty()
        || unit.len() > 256
        || !unit.ends_with(".service")
        || !unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'@' | b'-')
        })
        || expected_active_state.is_empty()
        || expected_active_state.len() > 64
        || expected_unit_file_state.is_empty()
        || expected_unit_file_state.len() > 64
    {
        return Err("systemd-plan-effect-shape".to_owned());
    }
    Ok(())
}

fn validate_dispatch(
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<(), String> {
    validate_systemd_plan(plan)?;
    if dispatch.work_schema != EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2
        || dispatch.work != plan.identity()?
        || dispatch.subject != plan.subject
        || dispatch.scope != plan.scope
    {
        return Err("systemd-dispatch-plan-binding".to_owned());
    }
    Ok(())
}

/// One retained D-Bus reply or signal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemdDbusMessageEvidenceV1 {
    kind: String,
    elapsed_ms: u64,
    bytes: Vec<u8>,
}

/// Terminal evidence class. This is evidence vocabulary, not Docket authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SystemdEvidenceClassV1 {
    Success,
    Failure,
    Indeterminate,
}

impl SystemdEvidenceClassV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Canonical evidence retained before the receipt is made visible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemdDbusEvidenceV1 {
    schema: String,
    work: Digest,
    attempt: Digest,
    marker: Digest,
    effect_index: u32,
    systemd_machine_identity: String,
    unit: String,
    action: SystemdUnitActionV1,
    expected_active_state: String,
    expected_unit_file_state: String,
    execution_lock_timeout_ms: u64,
    job_timeout_ms: u64,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    elapsed_ms: u64,
    live_machine_identity: Option<String>,
    unit_object_path: Option<String>,
    previous_active_state: Option<String>,
    previous_unit_file_state: Option<String>,
    job_path: Option<String>,
    job_result: Option<String>,
    resulting_active_state: Option<String>,
    resulting_unit_file_state: Option<String>,
    outcome_class: SystemdEvidenceClassV1,
    outcome_code: String,
    messages: Vec<SystemdDbusMessageEvidenceV1>,
}

impl SystemdDbusEvidenceV1 {
    fn canonical(&self) -> Result<(JcsDocument, Digest, EvidenceMetadata), String> {
        self.validate_shape()?;
        let raw = JcsDocument::canonicalize(self)
            .map_err(|error| format!("systemd-evidence-canonical:{error}"))?;
        if raw.as_bytes().len() > MAX_EVIDENCE_BYTES {
            return Err("systemd-evidence-record-too-large".to_owned());
        }
        let metadata = EvidenceMetadata::from_messages(&self.messages)?;
        let digest = Digest::hash_domain(SYSTEMD_DBUS_EVIDENCE_SCHEMA_V1, raw.as_bytes());
        Ok((raw, digest, metadata))
    }

    fn validate_shape(&self) -> Result<(), String> {
        if self.schema != SYSTEMD_DBUS_EVIDENCE_SCHEMA_V1
            || self.started_at_unix_ms > self.finished_at_unix_ms
            || self.messages.len() > MAX_MESSAGES
            || self.outcome_code.is_empty()
            || self.outcome_code.len() > 128
            || !outcome_code_is_known(self.outcome_class, &self.outcome_code)
            || self.live_machine_identity.as_ref().is_some_and(|value| {
                value.len() != 32
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
            || !bounded_optional(self.unit_object_path.as_deref())
            || !bounded_optional(self.previous_active_state.as_deref())
            || !bounded_optional(self.previous_unit_file_state.as_deref())
            || !bounded_optional(self.job_path.as_deref())
            || !bounded_optional(self.job_result.as_deref())
            || !bounded_optional(self.resulting_active_state.as_deref())
            || !bounded_optional(self.resulting_unit_file_state.as_deref())
        {
            return Err("systemd-evidence-shape".to_owned());
        }
        let mut prior = 0;
        let mut prior_rank = None;
        let mut seen = [false; 8];
        for (index, message) in self.messages.iter().enumerate() {
            let Some(rank) = message_kind_rank(&message.kind) else {
                return Err("systemd-evidence-message-kind".to_owned());
            };
            if message.bytes.len() > MAX_MESSAGE_BYTES
                || (index > 0 && message.elapsed_ms < prior)
                || message.elapsed_ms > self.elapsed_ms
                || prior_rank.is_some_and(|prior| rank < prior)
                || (rank != 5 && seen[rank as usize])
            {
                return Err("systemd-evidence-message-shape".to_owned());
            }
            prior = message.elapsed_ms;
            prior_rank = Some(rank);
            seen[rank as usize] = true;
        }
        let _ = EvidenceMetadata::from_messages(&self.messages)?;
        match self.outcome_class {
            SystemdEvidenceClassV1::Success
                if self.action == SystemdUnitActionV1::Start
                    && self.outcome_code == "start_unit_completed"
                    && self.live_machine_identity.as_deref()
                        == Some(self.systemd_machine_identity.as_str())
                    && self.unit_object_path.is_some()
                    && self.previous_active_state.is_some()
                    && self.previous_unit_file_state.is_some()
                    && self.job_path.is_some()
                    && self.job_result.as_deref() == Some("done")
                    && self.resulting_active_state.is_some()
                    && self.resulting_unit_file_state.is_some()
                    && seen.iter().all(|present| *present) => {}
            SystemdEvidenceClassV1::Failure
                if self.resulting_active_state.is_none()
                    && self.resulting_unit_file_state.is_none()
                    && self.job_path.is_none()
                    && self.job_result.is_none()
                    && !seen[4..].iter().any(|present| *present) => {}
            SystemdEvidenceClassV1::Indeterminate
                if self.resulting_active_state.is_none()
                    && self.resulting_unit_file_state.is_none() => {}
            _ => return Err("systemd-evidence-outcome-shape".to_owned()),
        }
        Ok(())
    }

    fn validate_bindings(
        &self,
        plan: &EffectExecutorSystemdPlanV2,
        dispatch: &EffectExecutorDispatchV1,
    ) -> Result<(), String> {
        validate_dispatch(plan, dispatch)?;
        let CanonicalEffectV1::SystemdUnit {
            unit,
            action,
            expected_active_state,
            expected_unit_file_state,
            ..
        } = &plan.effect
        else {
            return Err("systemd-evidence-effect-family".to_owned());
        };
        if self.work != dispatch.work
            || self.attempt != dispatch.attempt
            || self.marker != dispatch.marker
            || self.effect_index != plan.effect_index
            || self.systemd_machine_identity != plan.systemd_machine_identity
            || &self.unit != unit
            || self.action != *action
            || &self.expected_active_state != expected_active_state
            || &self.expected_unit_file_state != expected_unit_file_state
            || self.execution_lock_timeout_ms != plan.execution_lock_timeout_ms
            || self.job_timeout_ms != plan.job_timeout_ms
        {
            return Err("systemd-evidence-binding".to_owned());
        }
        Ok(())
    }
}

fn bounded_optional(value: Option<&str>) -> bool {
    value.is_none_or(|value| !value.is_empty() && value.len() <= 1024)
}

fn outcome_code_is_known(class: SystemdEvidenceClassV1, code: &str) -> bool {
    match class {
        SystemdEvidenceClassV1::Success => code == "start_unit_completed",
        SystemdEvidenceClassV1::Failure => matches!(
            code,
            "systemd_action_not_qualified"
                | "system_bus_connection_timeout"
                | "system_bus_unavailable"
                | "systemd_peer_proxy_unavailable"
                | "systemd_machine_identity_timeout"
                | "systemd_machine_identity_unavailable"
                | "systemd_machine_identity_malformed"
                | "systemd_machine_identity_mismatch"
                | "systemd_manager_proxy_unavailable"
                | "systemd_unit_lookup_timeout"
                | "systemd_unit_lookup_failed"
                | "systemd_unit_lookup_malformed"
                | "systemd_property_timeout"
                | "systemd_property_failed"
                | "systemd_property_malformed"
                | "systemd_property_not_string"
                | "systemd_manager_call_timeout"
                | "systemd_manager_call_failed"
                | "systemd_manager_reply_malformed"
                | "systemd_prestate_mismatch"
                | "systemd_job_subscription_failed"
                | "dbus_evidence_size_overflow"
                | "dbus_evidence_message_count"
                | "dbus_evidence_message_too_large"
                | "dbus_evidence_cumulative_too_large"
                | "dbus_evidence_message_bound"
        ),
        SystemdEvidenceClassV1::Indeterminate => matches!(
            code,
            "reserved_attempt_without_terminal_receipt"
                | "systemd_start_reply_timeout"
                | "systemd_start_method_error"
                | "systemd_start_reply_malformed"
                | "systemd_job_timeout"
                | "systemd_job_stream_ended"
                | "systemd_job_signal_malformed"
                | "systemd_job_unit_mismatch"
                | "systemd_job_result_not_done"
                | "systemd_poststate_timeout"
                | "systemd_property_failed"
                | "systemd_property_malformed"
                | "systemd_property_not_string"
                | "systemd_manager_call_failed"
                | "systemd_manager_reply_malformed"
                | "dbus_evidence_size_overflow"
                | "dbus_evidence_message_count"
                | "dbus_evidence_message_too_large"
                | "dbus_evidence_cumulative_too_large"
                | "dbus_evidence_message_bound"
        ),
    }
}
fn message_kind_rank(kind: &str) -> Option<u8> {
    match kind {
        "get_machine_id_reply" => Some(0),
        "get_unit_reply" => Some(1),
        "pre_active_state_reply" => Some(2),
        "pre_unit_file_state_reply" => Some(3),
        "start_unit_reply" => Some(4),
        "job_removed_signal" => Some(5),
        "post_active_state_reply" => Some(6),
        "post_unit_file_state_reply" => Some(7),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct EvidenceMetadata {
    message_count: usize,
    maximum_message_bytes: usize,
    cumulative_message_bytes: usize,
}

impl EvidenceMetadata {
    fn from_messages(messages: &[SystemdDbusMessageEvidenceV1]) -> Result<Self, String> {
        let message_count = messages.len();
        let maximum_message_bytes = messages
            .iter()
            .map(|message| message.bytes.len())
            .max()
            .unwrap_or(0);
        let cumulative_message_bytes = messages.iter().try_fold(0usize, |total, message| {
            total
                .checked_add(message.bytes.len())
                .ok_or_else(|| "systemd-evidence-size-overflow".to_owned())
        })?;
        if message_count > MAX_MESSAGES
            || maximum_message_bytes > MAX_MESSAGE_BYTES
            || cumulative_message_bytes > MAX_CUMULATIVE_MESSAGE_BYTES
        {
            return Err("systemd-evidence-message-bound".to_owned());
        }
        Ok(Self {
            message_count,
            maximum_message_bytes,
            cumulative_message_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct DriverMessageV2 {
    pub(super) kind: String,
    pub(super) elapsed_ms: u64,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
#[cfg_attr(not(any(feature = "systemd-dbus", test)), allow(dead_code))]
pub(super) enum DriverTerminalV2 {
    Success {
        resulting_active_state: String,
        resulting_unit_file_state: String,
    },
    Failure {
        code: String,
        detail: String,
    },
    Indeterminate {
        code: String,
        detail: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct DriverObservationV2 {
    pub(super) started_at_unix_ms: u64,
    pub(super) finished_at_unix_ms: u64,
    pub(super) elapsed_ms: u64,
    pub(super) live_machine_identity: Option<String>,
    pub(super) unit_object_path: Option<String>,
    pub(super) previous_active_state: Option<String>,
    pub(super) previous_unit_file_state: Option<String>,
    pub(super) job_path: Option<String>,
    pub(super) job_result: Option<String>,
    pub(super) messages: Vec<DriverMessageV2>,
    pub(super) terminal: DriverTerminalV2,
}

#[cfg(any(feature = "systemd-dbus", test))]
pub(super) trait SystemdOperationDriverV2 {
    fn run(&self, plan: &EffectExecutorSystemdPlanV2) -> DriverObservationV2;
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn restart_observation(reason: &str) -> DriverObservationV2 {
    let now = wall_clock_ms();
    DriverObservationV2 {
        started_at_unix_ms: now,
        finished_at_unix_ms: now,
        elapsed_ms: 0,
        live_machine_identity: None,
        unit_object_path: None,
        previous_active_state: None,
        previous_unit_file_state: None,
        job_path: None,
        job_result: None,
        messages: Vec::new(),
        terminal: DriverTerminalV2::Indeterminate {
            code: "reserved_attempt_without_terminal_receipt".to_owned(),
            detail: reason.to_owned(),
        },
    }
}

struct ExecutionLockV2 {
    _file: File,
}

impl ExecutionLockV2 {
    fn acquire(path: &Path, timeout_ms: u64) -> Result<Option<Self>, String> {
        if !path.is_absolute() {
            return Err("systemd-store-path-not-absolute".to_owned());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("systemd-store-parent:{error}"))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| format!("systemd-store-lock-open:{error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("systemd-store-lock-metadata:{error}"))?;
        if !metadata.is_file() {
            return Err("systemd-store-lock-not-regular".to_owned());
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Some(Self { _file: file })),
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("systemd-store-lock:{error}")),
            }
        }
    }
}

/// Execute one machine-bound V2 systemd attempt.
///
/// # Errors
///
/// Refuses any plan, dispatch, custody, mechanics, or evidence disagreement.
pub fn execute_systemd_effect_attempt(
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<EffectExecutorOutcomeV1, String> {
    validate_dispatch(plan, dispatch)?;
    #[cfg(feature = "systemd-dbus")]
    {
        execute_with_driver(plan, dispatch, &zbus_driver::ZbusSystemdDriverV2, false)
    }
    #[cfg(not(feature = "systemd-dbus"))]
    {
        Err("systemd-dbus-feature-not-enabled".to_owned())
    }
}

/// Reopen only retained V2 evidence and terminal custody.
///
/// # Errors
///
/// Refuses missing, substituted, incomplete, or disagreeing retained custody.
#[allow(
    clippy::single_match_else,
    reason = "three retained custody states stay explicit"
)]
pub fn reconcile_systemd_effect_attempt(
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<EffectExecutorOutcomeV1, String> {
    validate_dispatch(plan, dispatch)?;
    let Some(_lock) =
        ExecutionLockV2::acquire(&plan.attempt_store, plan.execution_lock_timeout_ms)?
    else {
        return Err("systemd_attempt_in_progress".to_owned());
    };
    let mut store = EffectAttemptStoreV1::open(&plan.attempt_store)?;
    match store.get(&dispatch.attempt)? {
        Some(record) if !record.matches(dispatch) => {
            Err("effect-executor-attempt-substitution".to_owned())
        }
        Some(record) => match store.outcome_v2(&record, plan, dispatch)? {
            Some(outcome) => Ok(outcome),
            None => {
                if store.has_systemd_evidence(&dispatch.attempt)? {
                    return Err("systemd-evidence-without-terminal".to_owned());
                }
                finish_observation(
                    &mut store,
                    plan,
                    dispatch,
                    restart_observation("reconciliation found an unterminated reserved attempt"),
                    false,
                )
            }
        },
        None => Err("effect-executor-attempt-not-found".to_owned()),
    }
}

/// Reopen exact canonical D-Bus evidence without invoking mechanics.
///
/// # Errors
///
/// Refuses missing, substituted, oversized, or disagreeing retained evidence.
pub fn reopen_systemd_dbus_evidence(
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<Vec<u8>, String> {
    validate_dispatch(plan, dispatch)?;
    let connection = rusqlite::Connection::open_with_flags(
        &plan.attempt_store,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("systemd-evidence-store-open-read-only:{error}"))?;
    validate_systemd_evidence_guards(&connection)?;
    let record = read_attempt(&connection, &dispatch.attempt)?
        .ok_or_else(|| "effect-executor-attempt-not-found".to_owned())?;
    if !record.matches(dispatch) {
        return Err("effect-executor-attempt-substitution".to_owned());
    }
    let _ = outcome_v2_from_connection(&connection, &record, plan, dispatch)?
        .ok_or_else(|| "effect-executor-attempt-not-terminal".to_owned())?;
    let body = record
        .receipt_body
        .as_deref()
        .ok_or_else(|| "effect-executor-receipt-body-missing".to_owned())?;
    let receipt: DocketEffectExecutionReceiptV1 =
        serde_json::from_slice(body).map_err(|error| format!("systemd-receipt-decode:{error}"))?;
    let (_, evidence_digest) = evidence_reference(&receipt.outcome)?;
    let (_, raw) = load_evidence(&connection, &dispatch.attempt, &evidence_digest)?;
    Ok(raw)
}

#[cfg(any(feature = "systemd-dbus", test))]
fn execute_with_driver(
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
    driver: &dyn SystemdOperationDriverV2,
    fail_after_evidence_insert: bool,
) -> Result<EffectExecutorOutcomeV1, String> {
    validate_dispatch(plan, dispatch)?;
    let Some(_lock) =
        ExecutionLockV2::acquire(&plan.attempt_store, plan.execution_lock_timeout_ms)?
    else {
        return Err("systemd_attempt_in_progress".to_owned());
    };
    let mut store = EffectAttemptStoreV1::open(&plan.attempt_store)?;
    match store.reserve_v2(plan, dispatch)? {
        ReservationV2::Prior(outcome) => Ok(outcome),
        ReservationV2::Ambiguous => finish_observation(
            &mut store,
            plan,
            dispatch,
            restart_observation("execute found an unterminated reserved attempt"),
            fail_after_evidence_insert,
        ),
        ReservationV2::Reserved => {
            let CanonicalEffectV1::SystemdUnit { action, .. } = plan.effect else {
                return Err("systemd-plan-effect-family".to_owned());
            };
            if action != SystemdUnitActionV1::Start {
                return finish_observation(
                    &mut store,
                    plan,
                    dispatch,
                    DriverObservationV2 {
                        started_at_unix_ms: wall_clock_ms(),
                        finished_at_unix_ms: wall_clock_ms(),
                        elapsed_ms: 0,
                        live_machine_identity: None,
                        unit_object_path: None,
                        previous_active_state: None,
                        previous_unit_file_state: None,
                        job_path: None,
                        job_result: None,
                        messages: Vec::new(),
                        terminal: DriverTerminalV2::Failure {
                            code: "systemd_action_not_qualified".to_owned(),
                            detail: "the beta qualifies only StartUnit".to_owned(),
                        },
                    },
                    fail_after_evidence_insert,
                );
            }
            finish_observation(
                &mut store,
                plan,
                dispatch,
                driver.run(plan),
                fail_after_evidence_insert,
            )
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "atomic evidence and receipt construction stays visible"
)]
fn finish_observation(
    store: &mut EffectAttemptStoreV1,
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
    observation: DriverObservationV2,
    fail_after_evidence_insert: bool,
) -> Result<EffectExecutorOutcomeV1, String> {
    let CanonicalEffectV1::SystemdUnit {
        unit,
        action,
        expected_active_state,
        expected_unit_file_state,
        ..
    } = &plan.effect
    else {
        return Err("systemd-plan-effect-family".to_owned());
    };
    let (outcome_class, outcome_code, resulting_active_state, resulting_unit_file_state) =
        match &observation.terminal {
            DriverTerminalV2::Success {
                resulting_active_state,
                resulting_unit_file_state,
            } => (
                SystemdEvidenceClassV1::Success,
                "start_unit_completed".to_owned(),
                Some(resulting_active_state.clone()),
                Some(resulting_unit_file_state.clone()),
            ),
            DriverTerminalV2::Failure { code, .. } => {
                (SystemdEvidenceClassV1::Failure, code.clone(), None, None)
            }
            DriverTerminalV2::Indeterminate { code, .. } => (
                SystemdEvidenceClassV1::Indeterminate,
                code.clone(),
                None,
                None,
            ),
        };
    let evidence = SystemdDbusEvidenceV1 {
        schema: SYSTEMD_DBUS_EVIDENCE_SCHEMA_V1.to_owned(),
        work: dispatch.work.clone(),
        attempt: dispatch.attempt.clone(),
        marker: dispatch.marker.clone(),
        effect_index: plan.effect_index,
        systemd_machine_identity: plan.systemd_machine_identity.clone(),
        unit: unit.clone(),
        action: *action,
        expected_active_state: expected_active_state.clone(),
        expected_unit_file_state: expected_unit_file_state.clone(),
        execution_lock_timeout_ms: plan.execution_lock_timeout_ms,
        job_timeout_ms: plan.job_timeout_ms,
        started_at_unix_ms: observation.started_at_unix_ms,
        finished_at_unix_ms: observation.finished_at_unix_ms,
        elapsed_ms: observation.elapsed_ms,
        live_machine_identity: observation.live_machine_identity,
        unit_object_path: observation.unit_object_path,
        previous_active_state: observation.previous_active_state,
        previous_unit_file_state: observation.previous_unit_file_state,
        job_path: observation.job_path,
        job_result: observation.job_result,
        resulting_active_state,
        resulting_unit_file_state,
        outcome_class,
        outcome_code,
        messages: observation
            .messages
            .into_iter()
            .map(|message| SystemdDbusMessageEvidenceV1 {
                kind: message.kind,
                elapsed_ms: message.elapsed_ms,
                bytes: message.bytes,
            })
            .collect(),
    };
    evidence.validate_bindings(plan, dispatch)?;
    let (raw, evidence_digest, metadata) = evidence.canonical()?;
    let outcome = match observation.terminal {
        DriverTerminalV2::Success {
            resulting_active_state,
            resulting_unit_file_state,
        } => ExecutionOutcomeV1::Succeeded {
            success: EffectSuccessV1::SystemdUnit {
                resulting_active_state,
                resulting_unit_file_state,
                evidence: evidence_digest.clone(),
            },
        },
        DriverTerminalV2::Failure { code, detail } => ExecutionOutcomeV1::Failed {
            failure: ExecutionFailureV1 {
                code: ExecutionFailureCodeV1::BackendRejected,
                phase: ExecutionPhaseV1::SystemdDbus,
                detail,
                source_code: Some(code),
                evidence: Some(evidence_digest.clone()),
            },
        },
        DriverTerminalV2::Indeterminate { code, detail } => ExecutionOutcomeV1::Indeterminate {
            envelope: ExecutionIndeterminateV1 {
                code: ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                phase: ExecutionPhaseV1::SystemdDbus,
                detail,
                source_code: Some(code),
                evidence: Some(evidence_digest.clone()),
            },
        },
    };
    let receipt = DocketEffectExecutionReceiptV1 {
        schema: DOCKET_EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
        work: dispatch.work.clone(),
        executor_marker: dispatch.marker.clone(),
        attempt: dispatch.attempt.clone(),
        effect_index: plan.effect_index,
        effect: plan.effect.clone(),
        outcome,
    };
    let receipt_raw = JcsDocument::canonicalize(&receipt)
        .map_err(|error| format!("systemd-receipt-canonical:{error}"))?;
    let receipt_digest = receipt
        .digest()
        .map_err(|error| format!("systemd-receipt-digest:{error}"))?;
    store.finish_v2(
        plan,
        dispatch,
        &evidence,
        &raw,
        &evidence_digest,
        metadata,
        &receipt,
        &receipt_raw,
        &receipt_digest,
        fail_after_evidence_insert,
    )
}

#[cfg(any(feature = "systemd-dbus", test))]
enum ReservationV2 {
    Reserved,
    Prior(EffectExecutorOutcomeV1),
    Ambiguous,
}

impl EffectAttemptStoreV1 {
    #[cfg(any(feature = "systemd-dbus", test))]
    fn reserve_v2(
        &mut self,
        plan: &EffectExecutorSystemdPlanV2,
        dispatch: &EffectExecutorDispatchV1,
    ) -> Result<ReservationV2, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("systemd-reserve-begin:{error}"))?;
        let existing = read_attempt(&transaction, &dispatch.attempt)?;
        let result = match existing {
            Some(record) if !record.matches(dispatch) => {
                return Err("effect-executor-attempt-substitution".to_owned());
            }
            Some(record) => {
                match outcome_v2_from_connection(&transaction, &record, plan, dispatch)? {
                    Some(outcome) => ReservationV2::Prior(outcome),
                    None => ReservationV2::Ambiguous,
                }
            }
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
                            dispatch.scope.as_str()
                        ],
                    )
                    .map_err(|error| format!("systemd-reserve-insert:{error}"))?;
                ReservationV2::Reserved
            }
        };
        transaction
            .commit()
            .map_err(|error| format!("systemd-reserve-commit:{error}"))?;
        checkpoint(&self.connection)?;
        Ok(result)
    }

    fn has_systemd_evidence(&self, attempt: &Digest) -> Result<bool, String> {
        self.connection
            .query_row(
                "SELECT 1 FROM systemd_dbus_evidence WHERE attempt=?1",
                [attempt.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(|error| format!("systemd-evidence-exists:{error}"))
    }

    fn outcome_v2(
        &self,
        record: &AttemptRecordV1,
        plan: &EffectExecutorSystemdPlanV2,
        dispatch: &EffectExecutorDispatchV1,
    ) -> Result<Option<EffectExecutorOutcomeV1>, String> {
        outcome_v2_from_connection(&self.connection, record, plan, dispatch)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_v2(
        &mut self,
        plan: &EffectExecutorSystemdPlanV2,
        dispatch: &EffectExecutorDispatchV1,
        evidence: &SystemdDbusEvidenceV1,
        evidence_raw: &JcsDocument,
        evidence_digest: &Digest,
        metadata: EvidenceMetadata,
        receipt: &DocketEffectExecutionReceiptV1,
        receipt_raw: &JcsDocument,
        receipt_digest: &Digest,
        fail_after_evidence_insert: bool,
    ) -> Result<EffectExecutorOutcomeV1, String> {
        receipt
            .verify_bindings(
                &dispatch.work,
                &dispatch.marker,
                &dispatch.attempt,
                plan.effect_index,
                &plan.effect,
            )
            .map_err(|error| format!("systemd-receipt-binding:{error}"))?;
        evidence.validate_bindings(plan, dispatch)?;
        let status = evidence.outcome_class.as_str();
        let raw_len = i64::try_from(evidence_raw.as_bytes().len())
            .map_err(|_| "systemd-evidence-size-overflow".to_owned())?;
        let message_count = i64::try_from(metadata.message_count)
            .map_err(|_| "systemd-evidence-size-overflow".to_owned())?;
        let maximum_message_bytes = i64::try_from(metadata.maximum_message_bytes)
            .map_err(|_| "systemd-evidence-size-overflow".to_owned())?;
        let cumulative_message_bytes = i64::try_from(metadata.cumulative_message_bytes)
            .map_err(|_| "systemd-evidence-size-overflow".to_owned())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("systemd-finish-begin:{error}"))?;
        transaction
            .execute(
                "INSERT INTO systemd_dbus_evidence
                 (attempt,evidence,outcome_class,raw_len,message_count,
                  maximum_message_bytes,cumulative_message_bytes,raw)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    dispatch.attempt.as_str(),
                    evidence_digest.as_str(),
                    status,
                    raw_len,
                    message_count,
                    maximum_message_bytes,
                    cumulative_message_bytes,
                    evidence_raw.as_bytes()
                ],
            )
            .map_err(|error| format!("systemd-evidence-insert:{error}"))?;
        if fail_after_evidence_insert {
            return Err("systemd-test-fault-after-evidence-insert".to_owned());
        }
        let changed = transaction
            .execute(
                "UPDATE docket_effect_attempt
                 SET status=?1,receipt=?2,receipt_body=?3
                 WHERE attempt=?4 AND marker=?5 AND status='started'",
                params![
                    status,
                    receipt_digest.as_str(),
                    receipt_raw.as_bytes(),
                    dispatch.attempt.as_str(),
                    dispatch.marker.as_str()
                ],
            )
            .map_err(|error| format!("systemd-finish-update:{error}"))?;
        if changed != 1 {
            return Err("systemd-finish-conflict".to_owned());
        }
        transaction
            .commit()
            .map_err(|error| format!("systemd-finish-commit:{error}"))?;
        checkpoint(&self.connection)?;
        Ok(EffectExecutorOutcomeV1 {
            attempt: dispatch.attempt.clone(),
            marker: dispatch.marker.clone(),
            receipt: receipt_digest.clone(),
            outcome: match evidence.outcome_class {
                SystemdEvidenceClassV1::Success => EffectExecutorOutcomeClassV1::Success,
                SystemdEvidenceClassV1::Failure => EffectExecutorOutcomeClassV1::Failure,
                SystemdEvidenceClassV1::Indeterminate => {
                    EffectExecutorOutcomeClassV1::Indeterminate
                }
            },
        })
    }
}

fn outcome_v2_from_connection(
    connection: &rusqlite::Connection,
    record: &AttemptRecordV1,
    plan: &EffectExecutorSystemdPlanV2,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<Option<EffectExecutorOutcomeV1>, String> {
    let Some(receipt_digest) = &record.receipt else {
        if record.status == "started" && record.receipt_body.is_none() {
            let evidence_present = connection
                .query_row(
                    "SELECT 1 FROM systemd_dbus_evidence WHERE attempt=?1",
                    [record.attempt.as_str()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| format!("systemd-evidence-exists:{error}"))?
                .is_some();
            return if evidence_present {
                Err("systemd-evidence-without-terminal".to_owned())
            } else {
                Ok(None)
            };
        }
        return Err("effect-executor-attempt-corrupt".to_owned());
    };
    let receipt_body = record
        .receipt_body
        .as_deref()
        .ok_or_else(|| "effect-executor-receipt-body-missing".to_owned())?;
    let canonical = JcsDocument::from_canonical_bytes(receipt_body)
        .map_err(|error| format!("systemd-receipt-body-invalid:{error}"))?;
    let receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(canonical.as_bytes())
        .map_err(|error| format!("systemd-receipt-decode:{error}"))?;
    receipt
        .verify_bindings(
            &dispatch.work,
            &dispatch.marker,
            &dispatch.attempt,
            plan.effect_index,
            &plan.effect,
        )
        .map_err(|error| format!("systemd-receipt-binding:{error}"))?;
    if receipt.digest().map_err(|error| error.to_string())? != *receipt_digest {
        return Err("systemd-receipt-identity".to_owned());
    }
    let (class, evidence_digest) = evidence_reference(&receipt.outcome)?;
    if record.status != class.as_str() {
        return Err("systemd-receipt-status-disagreement".to_owned());
    }
    let (evidence, _) = load_evidence(connection, &dispatch.attempt, &evidence_digest)?;
    evidence.validate_bindings(plan, dispatch)?;
    if evidence.outcome_class != class {
        return Err("systemd-evidence-outcome-disagreement".to_owned());
    }
    validate_receipt_evidence_agreement(&receipt.outcome, &evidence)?;
    Ok(Some(EffectExecutorOutcomeV1 {
        attempt: dispatch.attempt.clone(),
        marker: dispatch.marker.clone(),
        receipt: receipt_digest.clone(),
        outcome: match class {
            SystemdEvidenceClassV1::Success => EffectExecutorOutcomeClassV1::Success,
            SystemdEvidenceClassV1::Failure => EffectExecutorOutcomeClassV1::Failure,
            SystemdEvidenceClassV1::Indeterminate => EffectExecutorOutcomeClassV1::Indeterminate,
        },
    }))
}

fn validate_receipt_evidence_agreement(
    outcome: &ExecutionOutcomeV1,
    evidence: &SystemdDbusEvidenceV1,
) -> Result<(), String> {
    let agrees = match outcome {
        ExecutionOutcomeV1::Succeeded {
            success:
                EffectSuccessV1::SystemdUnit {
                    resulting_active_state,
                    resulting_unit_file_state,
                    ..
                },
        } => {
            evidence.outcome_class == SystemdEvidenceClassV1::Success
                && evidence.resulting_active_state.as_ref() == Some(resulting_active_state)
                && evidence.resulting_unit_file_state.as_ref() == Some(resulting_unit_file_state)
        }
        ExecutionOutcomeV1::Failed { failure } => {
            evidence.outcome_class == SystemdEvidenceClassV1::Failure
                && failure.code == ExecutionFailureCodeV1::BackendRejected
                && failure.phase == ExecutionPhaseV1::SystemdDbus
                && failure.source_code.as_deref() == Some(evidence.outcome_code.as_str())
        }
        ExecutionOutcomeV1::Indeterminate { envelope } => {
            evidence.outcome_class == SystemdEvidenceClassV1::Indeterminate
                && envelope.code == ExecutionIndeterminateCodeV1::BackendOutcomeUnknown
                && envelope.phase == ExecutionPhaseV1::SystemdDbus
                && envelope.source_code.as_deref() == Some(evidence.outcome_code.as_str())
        }
        ExecutionOutcomeV1::Succeeded { .. } => false,
    };
    if agrees {
        Ok(())
    } else {
        Err("systemd-receipt-evidence-disagreement".to_owned())
    }
}

fn evidence_reference(
    outcome: &ExecutionOutcomeV1,
) -> Result<(SystemdEvidenceClassV1, Digest), String> {
    match outcome {
        ExecutionOutcomeV1::Succeeded {
            success: EffectSuccessV1::SystemdUnit { evidence, .. },
        } => Ok((SystemdEvidenceClassV1::Success, evidence.clone())),
        ExecutionOutcomeV1::Failed {
            failure:
                ExecutionFailureV1 {
                    evidence: Some(evidence),
                    ..
                },
        } => Ok((SystemdEvidenceClassV1::Failure, evidence.clone())),
        ExecutionOutcomeV1::Indeterminate {
            envelope:
                ExecutionIndeterminateV1 {
                    evidence: Some(evidence),
                    ..
                },
        } => Ok((SystemdEvidenceClassV1::Indeterminate, evidence.clone())),
        _ => Err("systemd-receipt-evidence-reference".to_owned()),
    }
}

fn load_evidence(
    connection: &rusqlite::Connection,
    attempt: &Digest,
    expected_digest: &Digest,
) -> Result<(SystemdDbusEvidenceV1, Vec<u8>), String> {
    let metadata = connection
        .query_row(
            "SELECT evidence,outcome_class,raw_len,message_count,
                    maximum_message_bytes,cumulative_message_bytes,length(raw)
             FROM systemd_dbus_evidence WHERE attempt=?1",
            [attempt.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("systemd-evidence-metadata:{error}"))?
        .ok_or_else(|| "systemd-evidence-missing".to_owned())?;
    let (digest, class, raw_len, count, maximum, cumulative, actual_len) = metadata;
    let raw_len =
        usize::try_from(raw_len).map_err(|_| "systemd-evidence-metadata-bound".to_owned())?;
    let count = usize::try_from(count).map_err(|_| "systemd-evidence-metadata-bound".to_owned())?;
    let maximum =
        usize::try_from(maximum).map_err(|_| "systemd-evidence-metadata-bound".to_owned())?;
    let cumulative =
        usize::try_from(cumulative).map_err(|_| "systemd-evidence-metadata-bound".to_owned())?;
    let actual_len =
        usize::try_from(actual_len).map_err(|_| "systemd-evidence-metadata-bound".to_owned())?;
    if Digest::parse(&digest).map_err(|error| error.to_string())? != *expected_digest
        || !matches!(class.as_str(), "success" | "failure" | "indeterminate")
        || raw_len == 0
        || raw_len > MAX_EVIDENCE_BYTES
        || actual_len != raw_len
        || count > MAX_MESSAGES
        || maximum > MAX_MESSAGE_BYTES
        || cumulative > MAX_CUMULATIVE_MESSAGE_BYTES
    {
        return Err("systemd-evidence-metadata-bound".to_owned());
    }
    let raw: Vec<u8> = connection
        .query_row(
            "SELECT raw FROM systemd_dbus_evidence WHERE attempt=?1",
            [attempt.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| format!("systemd-evidence-read:{error}"))?;
    let canonical = JcsDocument::from_canonical_bytes(&raw)
        .map_err(|error| format!("systemd-evidence-canonical-read:{error}"))?;
    if raw.len() != raw_len
        || Digest::hash_domain(SYSTEMD_DBUS_EVIDENCE_SCHEMA_V1, canonical.as_bytes())
            != *expected_digest
    {
        return Err("systemd-evidence-identity".to_owned());
    }
    let evidence: SystemdDbusEvidenceV1 = serde_json::from_slice(canonical.as_bytes())
        .map_err(|error| format!("systemd-evidence-decode:{error}"))?;
    evidence.validate_shape()?;
    let computed = EvidenceMetadata::from_messages(&evidence.messages)?;
    if computed.message_count != count
        || computed.maximum_message_bytes != maximum
        || computed.cumulative_message_bytes != cumulative
        || evidence.outcome_class.as_str() != class
    {
        return Err("systemd-evidence-metadata-disagreement".to_owned());
    }
    Ok((evidence, raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_effect::TargetId;

    struct ScriptedDriver {
        observation: DriverObservationV2,
    }

    impl SystemdOperationDriverV2 for ScriptedDriver {
        fn run(&self, _plan: &EffectExecutorSystemdPlanV2) -> DriverObservationV2 {
            self.observation.clone()
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        EffectExecutorSystemdPlanV2,
        EffectExecutorDispatchV1,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let subject = Digest::hash_bytes(b"systemd-subject");
        let scope = Digest::hash_bytes(b"systemd-scope");
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
            attempt: Digest::hash_bytes(b"systemd-attempt"),
            marker: Digest::hash_bytes(b"systemd-marker"),
            work_schema: EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
            work: plan.identity().unwrap(),
            subject,
            scope,
        };
        (directory, plan, dispatch)
    }

    fn success() -> DriverObservationV2 {
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
                bytes: format!("exact-{kind}").into_bytes(),
            })
            .collect(),
            terminal: DriverTerminalV2::Success {
                resulting_active_state: "active".to_owned(),
                resulting_unit_file_state: "disabled".to_owned(),
            },
        }
    }

    #[test]
    fn exact_v2_attempt_commits_evidence_and_replays_without_driver() {
        let (_directory, plan, dispatch) = fixture();
        let driver = ScriptedDriver {
            observation: success(),
        };
        let first = execute_with_driver(&plan, &dispatch, &driver, false).unwrap();
        assert_eq!(first.outcome, EffectExecutorOutcomeClassV1::Success);
        let replay_driver = ScriptedDriver {
            observation: DriverObservationV2 {
                terminal: DriverTerminalV2::Failure {
                    code: "must_not_run".to_owned(),
                    detail: "must not run".to_owned(),
                },
                ..success()
            },
        };
        assert_eq!(
            execute_with_driver(&plan, &dispatch, &replay_driver, false).unwrap(),
            first
        );
        assert_eq!(
            reconcile_systemd_effect_attempt(&plan, &dispatch).unwrap(),
            first
        );
    }

    #[test]
    fn evidence_and_terminal_update_roll_back_together() {
        let (_directory, plan, dispatch) = fixture();
        let driver = ScriptedDriver {
            observation: success(),
        };
        assert_eq!(
            execute_with_driver(&plan, &dispatch, &driver, true).unwrap_err(),
            "systemd-test-fault-after-evidence-insert"
        );
        let connection = rusqlite::Connection::open(&plan.attempt_store).unwrap();
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
        assert_eq!((evidence_count, status.as_str()), (0, "started"));
        drop(connection);
        let reconciled = reconcile_systemd_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(
            reconciled.outcome,
            EffectExecutorOutcomeClassV1::Indeterminate
        );
    }

    #[test]
    fn coherent_machine_and_timeout_substitutions_refuse() {
        let (_directory, plan, dispatch) = fixture();
        for mutate in [
            |candidate: &mut EffectExecutorSystemdPlanV2| {
                candidate.systemd_machine_identity = "fedcba9876543210fedcba9876543210".to_owned();
            },
            |candidate: &mut EffectExecutorSystemdPlanV2| {
                candidate.execution_lock_timeout_ms = 4_999;
            },
            |candidate: &mut EffectExecutorSystemdPlanV2| {
                candidate.job_timeout_ms = 29_999;
            },
        ] {
            let mut candidate = plan.clone();
            mutate(&mut candidate);
            assert_eq!(
                validate_dispatch(&candidate, &dispatch).unwrap_err(),
                "systemd-dispatch-plan-binding"
            );
        }
    }
}
