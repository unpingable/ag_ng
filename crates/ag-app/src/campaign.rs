//! Local, authority-neutral campaign store and `agctl campaign` operations.
//!
//! The store is an append-only canonical-JSON event log with a digest chain;
//! every mutation replays the log through [`CampaignLedgerV1`] before
//! appending, so a tampered log refuses rather than reinterprets. Read
//! operations (`status`, `tail`, `report`, `doctor`, intent validation) never
//! open a file for writing. This is a local-only surface: no network, no
//! daemon wiring, and no authority — a campaign grants none.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_campaign::{
    CampaignEventV1, CampaignId, CampaignIntentV1, CampaignLedgerV1,
    CampaignRecompositionReceiptV1, CampaignRecompositionRefusalV1, CampaignResidualV1,
    CampaignStatusV1, DocketStandingV1, RecordedRefusalV1, RuntimeEnvelopeV1, SidecarOutcomeV1,
    SidecarRuntimeReceiptV1, StageId, StageKindV1, StageProposalV1, StageReceiptV1,
    VerdictReceiptV1, plan_from_ledger, present_from_ledger, recompose_campaign,
    stage_receipt_from_execution, verify_sidecar_receipt_against,
};
use ag_kernel::NativeJudgment;
use ag_primitives::{Digest, LifecycleNonce};
use ag_protocol::{canonical_json, strict_json_from_slice};
use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

/// Digest domain for the stored-event hash chain.
pub const CAMPAIGN_EVENT_DOMAIN_V1: &str = "ag.campaign.event/v1";

/// The campaign recomposition judgment returned by `report`.
pub type CampaignReportV1 =
    NativeJudgment<CampaignRecompositionReceiptV1, CampaignRecompositionRefusalV1>;

const EVENTS_FILE: &str = "events.jsonl";
const ENVELOPES_DIR: &str = "envelopes";
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// One stored event with its chain linkage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEventV1 {
    /// One-based position in the log.
    pub sequence: u64,
    /// Digest of the previous stored event; the campaign identity at genesis.
    pub previous: Digest,
    /// The campaign transition.
    pub event: CampaignEventV1,
}

impl StoredEventV1 {
    /// Returns the exact stored-event digest.
    ///
    /// # Panics
    ///
    /// Panics only if a stored event cannot canonicalize; every field is a
    /// strict JCS-compatible value by construction.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let bytes = canonical_json(self)
            .expect("stored campaign events contain only strict JCS-compatible values");
        Digest::hash_domain(CAMPAIGN_EVENT_DOMAIN_V1, &bytes)
    }
}

/// The outcome of one `campaign run` invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcomeV1 {
    /// The exact envelope was rendered and durably dispatched; the sidecar
    /// receipt is awaited.
    EnvelopeDispatched {
        /// Dispatched stage.
        stage: StageId,
        /// Exact envelope digest (typed transcript identity).
        envelope: Digest,
        /// SHA-256 over the exact envelope file bytes; the cross-repository
        /// artifact identity the sidecar's receipt must bind.
        envelope_file_digest: Digest,
        /// Envelope file path.
        envelope_path: PathBuf,
    },
    /// The sidecar receipt verified and the stage receipt was recorded.
    StageReceiptRecorded {
        /// Executed stage.
        stage: StageId,
        /// Exact stage receipt digest.
        receipt: Digest,
    },
    /// The sidecar reported failure or refusal; a refusal was recorded.
    ExecutionNotCompleted {
        /// Attempted stage.
        stage: StageId,
        /// Verified non-completed outcome.
        outcome: SidecarOutcomeV1,
        /// Recorded refusal digest.
        refusal: Digest,
    },
}

/// One doctor check line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDoctorCheckV1 {
    /// Check name.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Bounded check detail.
    pub detail: String,
}

/// The campaign doctor report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDoctorReportV1 {
    /// Campaign identity, when the log replayed.
    pub campaign: Option<CampaignId>,
    /// Every check.
    pub checks: Vec<CampaignDoctorCheckV1>,
    /// Whether every check passed.
    pub healthy: bool,
}

/// The result of validating a campaign intent. Validation is read-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentValidationV1 {
    /// Whether the intent is valid.
    pub valid: bool,
    /// The exact campaign identity derived from the intent.
    pub campaign: CampaignId,
    /// The human authorization instrument identity the intent binds.
    pub human_authorization: Digest,
}

/// Returns the current Unix time in seconds for ledger comparisons.
///
/// # Errors
///
/// Returns an error if the system clock is before the Unix epoch.
pub fn now_unix() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

/// Reads one bounded strict-JSON record file.
///
/// # Errors
///
/// Returns an error for an unreadable, oversized, or noncanonical record.
pub fn read_record_file<T>(path: &Path) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot inspect record file {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
        bail!(
            "record file {} is not a regular file within the byte bound",
            path.display()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    strict_json_from_slice(bytes).with_context(|| {
        format!(
            "record file {} is not a strict canonical record",
            path.display()
        )
    })
}

/// Validates a campaign intent and returns its exact identity. Read-only.
///
/// # Errors
///
/// Returns an error for an invalid intent.
pub fn validate_intent(intent: &CampaignIntentV1) -> anyhow::Result<CampaignId> {
    intent.validate().context("campaign intent is invalid")?;
    Ok(intent.campaign_id())
}

fn events_path(dir: &Path) -> PathBuf {
    dir.join(EVENTS_FILE)
}

fn envelope_path(dir: &Path, stage: &StageId) -> PathBuf {
    dir.join(ENVELOPES_DIR)
        .join(format!("{}.json", &stage.as_str()["sha256:".len()..]))
}

fn load_stored_events(dir: &Path) -> anyhow::Result<Vec<StoredEventV1>> {
    let path = events_path(dir);
    let bytes = fs::read(&path)
        .with_context(|| format!("cannot read campaign event log {}", path.display()))?;
    let mut stored = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let event: StoredEventV1 = strict_json_from_slice(line).with_context(|| {
            format!(
                "campaign event log line {} is not a strict stored event",
                index + 1
            )
        })?;
        stored.push(event);
    }
    Ok(stored)
}

fn verify_chain(stored: &[StoredEventV1], genesis: &CampaignId) -> anyhow::Result<()> {
    let mut previous = genesis.as_digest().clone();
    for (index, event) in stored.iter().enumerate() {
        let expected_sequence = u64::try_from(index)? + 1;
        if event.sequence != expected_sequence {
            bail!("campaign event log sequence break at entry {expected_sequence}");
        }
        if event.previous != previous {
            bail!("campaign event log digest-chain break at entry {expected_sequence}");
        }
        previous = event.digest();
    }
    Ok(())
}

/// Loads and replays the campaign ledger. Read-only.
///
/// # Errors
///
/// Returns an error for a missing, malformed, broken-chain, or
/// semantically-invalid log.
pub fn load(dir: &Path) -> anyhow::Result<CampaignLedgerV1> {
    let stored = load_stored_events(dir)?;
    let Some(first) = stored.first() else {
        bail!("campaign event log is empty");
    };
    let CampaignEventV1::CampaignCreated { intent, campaign } = &first.event else {
        bail!("campaign event log does not begin with the creation event");
    };
    if intent.campaign_id() != *campaign {
        bail!("campaign creation event identity does not match its intent");
    }
    verify_chain(&stored, campaign)?;
    let ledger =
        CampaignLedgerV1::from_events(stored.iter().map(|event| event.event.clone()).collect())
            .context("campaign event log replay refused")?;
    Ok(ledger)
}

fn append_events(
    dir: &Path,
    stored: &[StoredEventV1],
    new_events: &[CampaignEventV1],
) -> anyhow::Result<()> {
    let mut previous = stored
        .last()
        .context("campaign event log is empty; cannot append")?
        .digest();
    let mut sequence = u64::try_from(stored.len())?;
    let mut encoded = Vec::new();
    for event in new_events {
        sequence += 1;
        let stored_event = StoredEventV1 {
            sequence,
            previous,
            event: event.clone(),
        };
        previous = stored_event.digest();
        encoded.extend_from_slice(&canonical_json(&stored_event)?);
        encoded.push(b'\n');
    }
    let path = events_path(dir);
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot append to campaign event log {}", path.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    Ok(())
}

/// Loads the ledger, applies one mutation, and durably appends its events.
fn mutate<T>(
    dir: &Path,
    mutation: impl FnOnce(&mut CampaignLedgerV1) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let stored = load_stored_events(dir)?;
    let mut ledger = load(dir)?;
    let recorded = ledger.events().len();
    let result = mutation(&mut ledger)?;
    let new_events = &ledger.events()[recorded..];
    if new_events.is_empty() {
        bail!("campaign mutation produced no event");
    }
    append_events(dir, &stored, new_events)?;
    Ok(result)
}

/// Initializes a campaign store from a human-authorized intent.
///
/// # Errors
///
/// Returns an error for an invalid intent, an existing store, or an I/O
/// failure.
pub fn init(dir: &Path, intent: &CampaignIntentV1) -> anyhow::Result<CampaignId> {
    let campaign = validate_intent(intent)?;
    if dir.exists() {
        bail!("campaign store {} already exists", dir.display());
    }
    fs::create_dir_all(dir.join(ENVELOPES_DIR))
        .with_context(|| format!("cannot create campaign store {}", dir.display()))?;
    let ledger = CampaignLedgerV1::create(intent.clone()).context("campaign creation refused")?;
    let genesis = StoredEventV1 {
        sequence: 1,
        previous: campaign.as_digest().clone(),
        event: ledger.events()[0].clone(),
    };
    let mut encoded = canonical_json(&genesis)?;
    encoded.push(b'\n');
    let path = events_path(dir);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("cannot create campaign event log {}", path.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    let intent_bytes = canonical_json(intent)?;
    fs::write(dir.join("intent.json"), {
        let mut bytes = intent_bytes;
        bytes.push(b'\n');
        bytes
    })?;
    Ok(campaign)
}

/// Proposes a stage: a request for Docket admission, never an admission.
///
/// # Errors
///
/// Returns an error when the ledger refuses the proposal.
pub fn propose_stage(dir: &Path, proposal: StageProposalV1) -> anyhow::Result<StageId> {
    mutate(dir, |ledger| {
        ledger
            .propose_stage(proposal)
            .context("stage proposal refused")
    })
}

/// Records Docket admission for a proposed stage from a standing fixture.
///
/// # Errors
///
/// Returns an error when the ledger refuses the admission.
pub fn admit_stage(
    dir: &Path,
    standing: DocketStandingV1,
    now_unix: u64,
) -> anyhow::Result<StageId> {
    let stage = standing.stage.clone();
    mutate(dir, |ledger| {
        ledger
            .admit_stage(&stage, standing, now_unix)
            .context("stage admission refused")
    })?;
    Ok(stage)
}

/// Runs the current runnable stage: consumes its standing, renders and
/// durably records the exact runtime envelope, and — when a sidecar receipt
/// is supplied — verifies it against that envelope and records the stage
/// receipt or a refusal.
///
/// The runnable stage is the first proposed stage that still needs the
/// executor: a stage never dispatched, or a dispatched operator stage
/// awaiting its sidecar receipt. A receipted operator stage is complete for
/// dispatch purposes (its verdict arrives through a later review stage), and
/// a dispatched review stage completes by verdict, never by a receipt, so
/// neither is selected again.
///
/// # Errors
///
/// Returns an error when no admitted undispatched stage is runnable, the
/// receipt fails verification, or the ledger refuses a transition.
pub fn run(
    dir: &Path,
    receipt: Option<SidecarRuntimeReceiptV1>,
    now_unix: u64,
) -> anyhow::Result<RunOutcomeV1> {
    let ledger = load(dir)?;
    let stage = ledger
        .stage_order()
        .iter()
        .filter_map(|stage| ledger.stage(stage).map(|entry| (stage, entry)))
        .find(|(_, entry)| {
            if entry.dispatch().is_none() {
                return true;
            }
            entry.receipt().is_none() && matches!(entry.proposal().kind(), StageKindV1::Operator(_))
        })
        .map(|(stage, _)| stage.clone())
        .context("campaign has no non-terminal stage to run")?;
    let stage = &stage;
    let current = ledger
        .stage(stage)
        .context("current stage is missing from the ledger")?;
    let already_dispatched = current.dispatch().is_some();

    if already_dispatched && receipt.is_none() {
        bail!("stage is already dispatched; supply the sidecar receipt with --receipt");
    }

    if !already_dispatched {
        if current.admission().is_none() {
            bail!("stage has no admitted Docket standing; admit it first");
        }
        if current.consumption().is_some() {
            bail!("stage standing is consumed but not dispatched; the log is inconsistent");
        }
        let proposal = current.proposal().clone();
        let outcome = mutate(dir, |ledger| {
            let consumed = ledger
                .consume_standing(stage, now_unix)
                .context("standing consumption refused")?;
            let envelope =
                RuntimeEnvelopeV1::render(&consumed, &proposal, LifecycleNonce::random());
            let digest = envelope.digest();
            ledger
                .record_dispatch(&consumed, &digest, envelope.allowed_paths().to_vec())
                .context("dispatch recording refused")?;
            Ok((envelope, digest))
        });
        let (envelope, digest) = outcome?;
        let path = envelope_path(dir, stage);
        let mut bytes = canonical_json(&envelope)?;
        bytes.push(b'\n');
        fs::write(&path, &bytes)
            .with_context(|| format!("cannot write runtime envelope {}", path.display()))?;
        let file_digest = Digest::of_bytes(&bytes);
        if receipt.is_none() {
            return Ok(RunOutcomeV1::EnvelopeDispatched {
                stage: stage.clone(),
                envelope: digest,
                envelope_file_digest: file_digest,
                envelope_path: path,
            });
        }
    }

    let receipt =
        receipt.context("a sidecar receipt is required to complete a dispatched stage")?;
    let envelope_bytes = fs::read(envelope_path(dir, stage))
        .context("cannot read the dispatched runtime envelope")?;
    let envelope: RuntimeEnvelopeV1 = strict_json_from_slice(
        envelope_bytes
            .strip_suffix(b"\n")
            .unwrap_or(&envelope_bytes),
    )
    .context("dispatched runtime envelope is not a strict canonical record")?;
    // Cross-repository artifact rule: the receipt binds the exact envelope
    // file bytes (SHA-256), not a re-canonicalization across implementations.
    let envelope_file_digest = Digest::of_bytes(&envelope_bytes);
    let verified = verify_sidecar_receipt_against(&envelope, &envelope_file_digest, &receipt)
        .context("sidecar receipt refused")?;
    let proposal = ledger
        .stage(stage)
        .context("current stage is missing from the ledger")?
        .proposal()
        .clone();
    if let Some(stage_receipt) = stage_receipt_from_execution(&envelope, &proposal, &verified) {
        let receipt_digest = stage_receipt.id();
        record_stage_receipt_value(dir, stage_receipt)?;
        return Ok(RunOutcomeV1::StageReceiptRecorded {
            stage: stage.clone(),
            receipt: receipt_digest,
        });
    }
    let refusal_digest = record_execution_refusal(dir, &envelope, verified.outcome())?;
    Ok(RunOutcomeV1::ExecutionNotCompleted {
        stage: stage.clone(),
        outcome: verified.outcome(),
        refusal: refusal_digest,
    })
}

fn record_stage_receipt_value(dir: &Path, receipt: StageReceiptV1) -> anyhow::Result<()> {
    mutate(dir, |ledger| {
        ledger
            .record_stage_receipt(receipt)
            .context("stage receipt recording refused")
    })
}

fn record_execution_refusal(
    dir: &Path,
    envelope: &RuntimeEnvelopeV1,
    outcome: SidecarOutcomeV1,
) -> anyhow::Result<Digest> {
    let refusal = RecordedRefusalV1 {
        refusal_id: format!("sidecar-{}", &envelope.digest().as_str()[..16]),
        statement: format!("sidecar execution did not complete: {outcome:?}"),
        context: envelope.digest(),
    };
    let digest = refusal.id();
    mutate(dir, |ledger| {
        ledger
            .record_refusal(refusal)
            .context("execution refusal recording failed")
    })?;
    Ok(digest)
}

/// Records a reviewer verdict receipt.
///
/// # Errors
///
/// Returns an error when the ledger refuses the verdict.
pub fn record_verdict(dir: &Path, verdict: VerdictReceiptV1) -> anyhow::Result<Digest> {
    let digest = verdict.id();
    mutate(dir, |ledger| {
        ledger
            .record_verdict(verdict)
            .context("verdict recording refused")
    })?;
    Ok(digest)
}

/// Records a bounded residual.
///
/// # Errors
///
/// Returns an error when the ledger refuses the residual.
pub fn record_residual(dir: &Path, residual: CampaignResidualV1) -> anyhow::Result<Digest> {
    let digest = residual.id();
    mutate(dir, |ledger| {
        ledger
            .record_residual(residual)
            .context("residual recording refused")
    })?;
    Ok(digest)
}

/// Halts the campaign with an exact reason digest.
///
/// # Errors
///
/// Returns an error when the campaign is already halted.
pub fn abort(dir: &Path, reason: Digest) -> anyhow::Result<()> {
    mutate(dir, |ledger| {
        ledger.halt(reason).context("campaign halt refused")
    })
}

/// Resumes a halted campaign once no consumed stage is in flight.
///
/// # Errors
///
/// Returns an error when the campaign is not halted or resume is blocked.
pub fn resume(dir: &Path) -> anyhow::Result<()> {
    mutate(dir, |ledger| {
        ledger.resume().context("campaign resume refused")
    })
}

/// Projects the campaign status. Read-only.
///
/// # Errors
///
/// Returns an error when the log cannot be replayed.
pub fn status(dir: &Path, now_unix: u64) -> anyhow::Result<CampaignStatusV1> {
    Ok(load(dir)?.status(now_unix))
}

/// Returns the last `limit` stored events. Read-only.
///
/// # Errors
///
/// Returns an error when the log cannot be read.
pub fn tail(dir: &Path, limit: u32) -> anyhow::Result<Vec<StoredEventV1>> {
    let stored = load_stored_events(dir)?;
    let limit = usize::try_from(limit)?;
    Ok(stored.into_iter().rev().take(limit).collect())
}

/// Computes the campaign recomposition judgment. Read-only: the receipt is
/// returned, never persisted.
///
/// # Errors
///
/// Returns an error when the log cannot be replayed or the accounting plan
/// refuses (campaign-law inconsistency).
pub fn report(dir: &Path) -> anyhow::Result<CampaignReportV1> {
    let ledger = load(dir)?;
    let plan = plan_from_ledger(&ledger).context("campaign accounting plan refused")?;
    let presented = present_from_ledger(&ledger);
    Ok(recompose_campaign(&plan, &presented, &ledger))
}

/// Audits the campaign store. Read-only.
///
/// # Errors
///
/// Returns an error only for unreadable store files; check failures are
/// reported in the report itself.
pub fn doctor(dir: &Path) -> anyhow::Result<CampaignDoctorReportV1> {
    let mut checks = Vec::new();
    let mut campaign = None;

    let stored = load_stored_events(dir);
    let (stored_ok, stored_detail) = match &stored {
        Ok(events) => (true, format!("{} stored events parsed", events.len())),
        Err(error) => (false, format!("{error:#}")),
    };
    checks.push(CampaignDoctorCheckV1 {
        name: "event_log_parse".to_owned(),
        passed: stored_ok,
        detail: stored_detail,
    });

    if let Ok(events) = &stored {
        let genesis = events.first().and_then(|event| match &event.event {
            CampaignEventV1::CampaignCreated { campaign, .. } => Some(campaign.clone()),
            _ => None,
        });
        match &genesis {
            Some(identity) => {
                campaign = Some(identity.clone());
                let chain = verify_chain(events, identity);
                checks.push(CampaignDoctorCheckV1 {
                    name: "digest_chain".to_owned(),
                    passed: chain.is_ok(),
                    detail: chain
                        .map_or_else(|error| format!("{error:#}"), |()| "chain intact".to_owned()),
                });
            }
            None => checks.push(CampaignDoctorCheckV1 {
                name: "digest_chain".to_owned(),
                passed: false,
                detail: "log does not begin with the creation event".to_owned(),
            }),
        }
        let replay =
            CampaignLedgerV1::from_events(events.iter().map(|event| event.event.clone()).collect());
        match &replay {
            Ok(ledger) => {
                checks.push(CampaignDoctorCheckV1 {
                    name: "semantic_replay".to_owned(),
                    passed: true,
                    detail: format!("{} events replayed", ledger.events().len()),
                });
                let mut envelopes_ok = true;
                let mut detail = String::from("all dispatched envelopes verified");
                for stage in ledger.stage_order() {
                    let Some(state) = ledger.stage(stage) else {
                        continue;
                    };
                    let Some(dispatch) = state.dispatch() else {
                        continue;
                    };
                    let path = envelope_path(dir, stage);
                    let verified = fs::read(&path)
                        .ok()
                        .and_then(|bytes| {
                            strict_json_from_slice::<RuntimeEnvelopeV1>(
                                bytes.strip_suffix(b"\n").unwrap_or(&bytes),
                            )
                            .ok()
                        })
                        .is_some_and(|envelope| envelope.digest() == dispatch.envelope);
                    if !verified {
                        envelopes_ok = false;
                        detail = format!("envelope for stage {stage} is missing or altered");
                        break;
                    }
                }
                checks.push(CampaignDoctorCheckV1 {
                    name: "dispatched_envelopes".to_owned(),
                    passed: envelopes_ok,
                    detail,
                });
            }
            Err(error) => checks.push(CampaignDoctorCheckV1 {
                name: "semantic_replay".to_owned(),
                passed: false,
                detail: format!("{error:#}"),
            }),
        }
    }

    let healthy = checks.iter().all(|check| check.passed);
    Ok(CampaignDoctorReportV1 {
        campaign,
        checks,
        healthy,
    })
}
