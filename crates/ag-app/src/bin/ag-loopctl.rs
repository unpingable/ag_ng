#![allow(
    clippy::wildcard_imports,
    reason = "the record-driven CLI exposes the governed kernel's complete typed input vocabulary"
)]
#![allow(
    clippy::too_many_lines,
    reason = "the closed command dispatch remains one explicit auditable match"
)]

//! Exact, record-driven production CLI for the canonical AG governed loop.
//!
//! This CLI is deliberately not a planner.  It accepts only typed exact
//! records and invokes external currentness/authority owners at each live
//! boundary.  The `SQLite` campaign store is the sole program-counter owner.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::governed_loop::{CampaignEngineErrorV1, CampaignEngineV1, ExactWorkCatalogV1};
use ag_app::governed_ports::{
    AgIssuanceSignerV1, CommandDocketCustodyPortV1, CommandDocketReconciliationPortV1,
    CommandGovernedInterventionVerifierV1, CommandHumanDispositionVerifierV1,
    CommandObservationResolverV1, CommandStandingResolverV1, GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
    GovernedRuntimeProfileEnrollmentV1, GovernedRuntimeProfileV1,
};
use ag_app::intervention_ingress::*;
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use ag_protocol::strict_json_from_slice;
use ag_store::campaign::{CampaignReplayReportV1, CampaignTransitionEvidenceV1};
use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Parser)]
#[command(
    name = "ag-loopctl",
    version,
    about = "Canonical AG exact-occurrence governed-loop controller"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Measure deployment inputs and create one immutable runtime profile.
    SealRuntimeProfile {
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Remeasure and validate one sealed runtime profile without creating authority.
    VerifyRuntimeProfile {
        #[arg(long)]
        runtime_profile: PathBuf,
    },
    /// Construct canonical intervention-request bytes from one exact typed draft.
    PrepareInterventionRequest {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect the exact canonical intervention-request bytes without mutation.
    InspectInterventionRequest {
        #[arg(long)]
        request: PathBuf,
    },
    /// Sign/package exact request bytes for one genesis-bound AG runtime.
    PackageInterventionSubmission {
        #[arg(long)]
        runtime_profile: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        submitter_principal: String,
        #[arg(long)]
        submitter_key_id: String,
        #[arg(long)]
        submitter_key: PathBuf,
        #[arg(long)]
        created_at_unix_ms: u64,
        #[arg(long)]
        expires_at_unix_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create one authority-empty campaign occurrence.
    Init {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
        /// Deployment-owned policy and Docket boundary, pinned at genesis.
        #[arg(long)]
        runtime_profile: PathBuf,
    },
    /// Print the exact authoritative current occurrence.
    Status {
        #[arg(long)]
        database: PathBuf,
    },
    /// Deterministically replay and verify the authoritative store.
    Replay {
        #[arg(long)]
        database: PathBuf,
    },
    /// Emit the verified canonical transition journal in durable order.
    History {
        #[arg(long)]
        database: PathBuf,
    },
    /// Emit verified durable non-authorizing refusal facts.
    Refusals {
        #[arg(long)]
        database: PathBuf,
    },
    /// Emit one machine-readable state/replay/profile projection for operators.
    Inspect {
        #[arg(long)]
        database: PathBuf,
    },
    /// Resolve a fresh observation and record one exact proposal.
    RecordProposal {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        observation_resolver: PathBuf,
        #[arg(long)]
        expected_observation_resolver_id: String,
    },
    /// Enter the explicit current-standing-required state.
    RequireStanding {
        #[arg(long)]
        database: PathBuf,
    },
    /// Resolve current premises and record a positive AG decision only.
    Decide {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        gate: GateArguments,
    },
    /// Re-resolve current premises and durably spend the one AG authorization.
    Authorize {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        gate: GateArguments,
    },
    /// Submit the already-durable exact issuance to Docket custody.
    Dispatch {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        docket: DocketArguments,
    },
    /// Read-only reconcile/poll the exact Docket attempt.
    Poll {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        docket: DocketArguments,
    },
    /// Apply the PC-specific restart law without reconstructing authority.
    Recover {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        docket: DocketArguments,
    },
    /// Open a distinct authority-empty occurrence after settlement.
    Continue {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Persist one read-only probe-count fact.
    NoteProbe {
        #[arg(long)]
        database: PathBuf,
    },
    /// Halt from an authority-safe boundary.
    Halt {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Consume one escalation budget fact and halt.
    Escalate {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Apply one exact externally verified human disposition.
    ApplyDisposition {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        observation_resolver: PathBuf,
        #[arg(long)]
        expected_observation_resolver_id: String,
        #[arg(long)]
        human_verifier: PathBuf,
    },
    /// Authenticate and submit one already-typed exact intervention envelope.
    SubmitIntervention {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        submission: PathBuf,
        /// Exact Docket executor plan; required only for `reconcile_attempt`.
        #[arg(long)]
        executor_config: Option<PathBuf>,
    },
    /// Read-only lookup of one exact immutable submission receipt chain.
    InterventionReceipt {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        submission: String,
    },
    /// Read-only projection of every immutable submission receipt.
    InterventionSubmissions {
        #[arg(long)]
        database: PathBuf,
    },
    /// Complete only from a fresh observation boundary with no residuals.
    Complete {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        observation_resolver: PathBuf,
        #[arg(long)]
        expected_observation_resolver_id: String,
    },
    /// Record a typed non-authorizing refusal without advancing the PC.
    Refuse {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Args)]
struct GateArguments {
    #[arg(long)]
    catalog: PathBuf,
    #[arg(long)]
    observation_resolver: PathBuf,
    #[arg(long)]
    expected_observation_resolver_id: String,
    #[arg(long)]
    standing_resolver: PathBuf,
    #[arg(long)]
    expected_standing_resolver_id: String,
    /// Maximum accepted standing-answer lifetime in milliseconds.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    max_standing_ttl_ms: u64,
    #[arg(long)]
    controlling_review: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DocketArguments {
    #[arg(long)]
    docket: PathBuf,
    #[arg(long)]
    docket_state: PathBuf,
    #[arg(long)]
    docket_trust: PathBuf,
    #[arg(long)]
    docket_standing_resolver: PathBuf,
    #[arg(long)]
    executor: PathBuf,
    #[arg(long)]
    executor_config: PathBuf,
    #[arg(long)]
    issuer_principal: String,
    #[arg(long)]
    issuer_key_id: String,
    #[arg(long)]
    issuer_key: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisInputV1 {
    campaign: CampaignId,
    occurrence: OccurrenceId,
    program: ProgramBasisRefV1,
    /// The exact executable-work identity this occurrence is opened to
    /// govern, taken from the Nightshift-prepared binding.
    expected_ag_work: Digest,
    residuals: ResidualSetV1,
    budget: LoopBudgetV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProposalInputV1 {
    observation: ObservationRefV1,
    proposal: ExactWorkProposalV1,
    class: ProposalClassV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContinuationInputV1 {
    occurrence: OccurrenceId,
    /// The exact executable-work identity the continuation occurrence is
    /// opened to govern.
    expected_ag_work: Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HaltInputV1 {
    reason: HaltReasonRefV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HumanDispositionInputV1 {
    artifact: HumanDispositionV1,
    expected_principal: HumanPrincipalRefV1,
    expected_mandate: MandateRefV1,
    new_occurrence: Option<OccurrenceId>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionInputV1 {
    observation: ObservationRefV1,
    subject: Digest,
    terminal_witness: TerminalWitnessRefV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RefusalInputV1 {
    code: RefusalCodeV1,
    evidence: Option<Digest>,
}

const RUNTIME_PROFILE_SEAL_RECEIPT_SCHEMA_V1: &str =
    "ag.governed-loop.runtime-profile-seal-receipt/v1";
const OPERATIONAL_SNAPSHOT_SCHEMA_V1: &str = "ag.governed-loop.operational-snapshot/v1";

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProfileSealReceiptV1 {
    schema: &'static str,
    profile_schema: &'static str,
    profile_digest: Digest,
    observation_resolver_id: String,
    standing_resolver_id: String,
    issuer_principal: String,
    issuer_key_id: String,
    intervention_submitter_principal: Option<String>,
    intervention_submitter_key_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProfileBindingV1 {
    schema: String,
    digest: Digest,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationalSnapshotV1 {
    schema: &'static str,
    current: OccurrenceSnapshotV1,
    replay: CampaignReplayReportV1,
    runtime_profile: RuntimeProfileBindingV1,
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let now = now_unix_ms;
    match arguments.command {
        Command::SealRuntimeProfile { enrollment, output } => {
            let enrollment: GovernedRuntimeProfileEnrollmentV1 = read_exact_record(&enrollment)?;
            let profile = enrollment.seal()?;
            let canonical = JcsDocument::canonicalize(&profile)?;
            write_exact_file(&output, canonical.as_bytes())?;
            write_exact(&runtime_profile_receipt(&profile, canonical.as_bytes()))
        }
        Command::VerifyRuntimeProfile { runtime_profile } => {
            let profile: GovernedRuntimeProfileV1 = read_exact_record(&runtime_profile)?;
            profile.verify_genesis()?;
            let canonical = JcsDocument::canonicalize(&profile)?;
            write_exact(&runtime_profile_receipt(&profile, canonical.as_bytes()))
        }
        Command::PrepareInterventionRequest { input, output } => {
            let draft: GovernedInterventionRequestDraftV1 = read_exact_record(&input)?;
            let request = draft.construct()?;
            let canonical = JcsDocument::canonicalize(&request)?;
            write_exact_file(&output, canonical.as_bytes())?;
            write_exact(&inspect_request_bytes(canonical.as_bytes())?)
        }
        Command::InspectInterventionRequest { request } => {
            let bytes = read_exact_input(&request, max_request_bytes())?;
            write_exact(&inspect_request_bytes(&bytes)?)
        }
        Command::PackageInterventionSubmission {
            runtime_profile,
            request,
            submitter_principal,
            submitter_key_id,
            submitter_key,
            created_at_unix_ms,
            expires_at_unix_ms,
            output,
        } => {
            let profile: GovernedRuntimeProfileV1 = read_exact_record(&runtime_profile)?;
            let ingress = profile
                .intervention_ingress
                .as_ref()
                .context("runtime profile has no intervention ingress")?;
            if ingress.submitter_principal != submitter_principal
                || ingress.submitter_key_id != submitter_key_id
            {
                bail!("packager identity differs from the runtime-profile ingress");
            }
            let signer = GovernedInterventionSubmissionSignerV1::from_protected_file(
                submitter_principal,
                submitter_key_id,
                &submitter_key,
            )?;
            if signer.public_key_b64() != ingress.submitter_public_key {
                bail!("packager key differs from the runtime-profile ingress key");
            }
            let request_bytes = read_exact_input(&request, max_request_bytes())?;
            let profile_jcs = JcsDocument::canonicalize(&profile)?;
            let submission = signer.package(
                &request_bytes,
                runtime_profile_digest(profile_jcs.as_bytes()),
                created_at_unix_ms,
                expires_at_unix_ms,
            )?;
            let canonical = JcsDocument::canonicalize(&submission)?;
            write_exact_file(&output, canonical.as_bytes())?;
            write_exact(&submission)
        }
        Command::Init {
            database,
            genesis,
            runtime_profile,
        } => {
            let input: GenesisInputV1 = read_exact_record(&genesis)?;
            let profile: GovernedRuntimeProfileV1 = read_exact_record(&runtime_profile)?;
            profile.verify_genesis()?;
            let profile_jcs = JcsDocument::canonicalize(&profile)?;
            let engine = CampaignEngineV1::create_with_runtime_profile(
                &database,
                input.campaign,
                input.occurrence,
                input.program,
                input.expected_ag_work,
                input.residuals,
                input.budget,
                GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
                profile_jcs.as_bytes(),
                now()?,
            )?;
            write_exact(&engine.current()?)
        }
        Command::Status { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.current()?)
        }
        Command::Replay { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.replay()?)
        }
        Command::History { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.history()?)
        }
        Command::Refusals { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.refusal_history()?)
        }
        Command::Inspect { database } => {
            let (engine, _) = open_bound(&database)?;
            let stored = engine
                .runtime_profile()?
                .context("campaign has no genesis-bound runtime profile")?;
            let current = engine.current()?;
            let replay = engine.replay()?;
            if replay.current_state_digest != *current.state_digest() {
                bail!("operational snapshot state differs from deterministic replay");
            }
            write_exact(&OperationalSnapshotV1 {
                schema: OPERATIONAL_SNAPSHOT_SCHEMA_V1,
                current,
                replay,
                runtime_profile: RuntimeProfileBindingV1 {
                    schema: stored.schema,
                    digest: stored.digest,
                },
            })
        }
        Command::RecordProposal {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
        } => {
            let input: ProposalInputV1 = read_exact_record(&input)?;
            let (mut engine, profile) = open_bound(&database)?;
            let _ = profile
                .observation_resolver
                .verify_presented(&observation_resolver, true)?;
            if expected_observation_resolver_id != profile.observation_resolver_id {
                bail!("caller substituted the genesis-pinned observation resolver identity");
            }
            let mut observation =
                CommandObservationResolverV1::new(profile.observation_resolver.path.clone());
            let state = engine.record_proposal(
                input.observation,
                input.proposal,
                input.class,
                &mut observation,
                &profile.observation_resolver_id,
                now()?,
            )?;
            write_exact(&state)
        }
        Command::RequireStanding { database } => {
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.require_standing(now()?)?)
        }
        Command::Decide { database, gate } => {
            let (mut engine, profile) = open_bound(&database)?;
            let (mut observation, mut standing, catalog, review) =
                gate_components(&profile, &gate)?;
            write_exact(&engine.decide(
                &mut observation,
                &mut standing,
                &catalog,
                review.as_ref(),
                &profile.observation_resolver_id,
                &profile.standing_resolver_id,
                profile.max_standing_ttl_ms,
                now()?,
            )?)
        }
        Command::Authorize { database, gate } => {
            let (mut engine, profile) = open_bound(&database)?;
            let (mut observation, mut standing, catalog, review) =
                gate_components(&profile, &gate)?;
            write_exact(&engine.authorize(
                &mut observation,
                &mut standing,
                &catalog,
                review.as_ref(),
                &profile.observation_resolver_id,
                &profile.standing_resolver_id,
                profile.max_standing_ttl_ms,
                now()?,
            )?)
        }
        Command::Dispatch { database, docket } => {
            let (mut engine, profile) = open_bound(&database)?;
            let mut docket = docket_port(&profile, &docket)?;
            write_exact(&engine.dispatch(&mut docket, now()?)?)
        }
        Command::Poll { database, docket } => {
            let (mut engine, profile) = open_bound(&database)?;
            let mut docket = docket_port(&profile, &docket)?;
            let _ = engine.poll_docket(&mut docket, now()?)?;
            write_exact(&engine.current()?)
        }
        Command::Recover { database, docket } => {
            let (mut engine, profile) = open_bound(&database)?;
            let mut docket = docket_port(&profile, &docket)?;
            write_exact(&engine.recover(&mut docket, now()?)?)
        }
        Command::Continue { database, input } => {
            let input: ContinuationInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.open_continuation(
                input.occurrence,
                input.expected_ag_work,
                now()?,
            )?)
        }
        Command::NoteProbe { database } => {
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.note_probe(now()?)?)
        }
        Command::Halt { database, input } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.halt(input.reason, now()?)?)
        }
        Command::Escalate { database, input } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.escalate(input.reason, now()?)?)
        }
        Command::ApplyDisposition {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
            human_verifier,
        } => {
            let input: HumanDispositionInputV1 = read_exact_record(&input)?;
            let (mut engine, profile) = open_bound(&database)?;
            let _ = profile
                .observation_resolver
                .verify_presented(&observation_resolver, true)?;
            if expected_observation_resolver_id != profile.observation_resolver_id {
                bail!("caller substituted the genesis-pinned observation resolver identity");
            }
            let pinned_verifier = profile
                .human_verifier
                .as_ref()
                .context("campaign has no genesis-pinned human verifier")?;
            let _ = pinned_verifier.verify_presented(&human_verifier, true)?;
            let mut observation =
                CommandObservationResolverV1::new(profile.observation_resolver.path.clone());
            let mut verifier = CommandHumanDispositionVerifierV1::new(pinned_verifier.path.clone());
            let scope = HumanAuthorityScopeV1 {
                principal: input.expected_principal,
                mandate: input.expected_mandate,
            };
            let _ = engine.apply_human_disposition(
                input.artifact,
                &scope,
                input.new_occurrence,
                &mut observation,
                &profile.observation_resolver_id,
                &mut verifier,
                now()?,
            )?;
            write_exact(&engine.current()?)
        }
        Command::SubmitIntervention {
            database,
            submission,
            executor_config,
        } => submit_intervention(&database, &submission, executor_config.as_deref(), now()?),
        Command::InterventionReceipt {
            database,
            submission,
        } => {
            let (_, profile, profile_digest) = open_bound_with_digest(&database)?;
            profile
                .intervention_ingress
                .as_ref()
                .context("runtime profile has no intervention ingress")?;
            let submission = Digest::parse(&submission)?;
            let ledger_path = InterventionSubmissionLedgerV1::path_for_campaign(&database);
            if !ledger_path.exists() {
                return write_exact(&InterventionSubmissionHistoryV1 {
                    schema: INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1.to_owned(),
                    target_runtime_profile: profile_digest,
                    submission: Some(submission),
                    receipts: Vec::new(),
                });
            }
            let ledger = InterventionSubmissionLedgerV1::open_reader(&ledger_path, profile_digest)?;
            write_exact(&ledger.history(Some(&submission))?)
        }
        Command::InterventionSubmissions { database } => {
            let (_, profile, profile_digest) = open_bound_with_digest(&database)?;
            profile
                .intervention_ingress
                .as_ref()
                .context("runtime profile has no intervention ingress")?;
            let ledger_path = InterventionSubmissionLedgerV1::path_for_campaign(&database);
            if !ledger_path.exists() {
                return write_exact(&InterventionSubmissionHistoryV1 {
                    schema: INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1.to_owned(),
                    target_runtime_profile: profile_digest,
                    submission: None,
                    receipts: Vec::new(),
                });
            }
            let ledger = InterventionSubmissionLedgerV1::open_reader(&ledger_path, profile_digest)?;
            write_exact(&ledger.history(None)?)
        }
        Command::Complete {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
        } => {
            let input: CompletionInputV1 = read_exact_record(&input)?;
            let (mut engine, profile) = open_bound(&database)?;
            let _ = profile
                .observation_resolver
                .verify_presented(&observation_resolver, true)?;
            if expected_observation_resolver_id != profile.observation_resolver_id {
                bail!("caller substituted the genesis-pinned observation resolver identity");
            }
            let mut observation =
                CommandObservationResolverV1::new(profile.observation_resolver.path.clone());
            write_exact(&engine.complete(
                input.observation,
                &input.subject,
                input.terminal_witness,
                &mut observation,
                &profile.observation_resolver_id,
                now()?,
            )?)
        }
        Command::Refuse { database, input } => {
            let input: RefusalInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            let refusal = engine.record_refusal(input.code, input.evidence, now()?)?;
            write_exact(&refusal)
        }
    }
}

fn open_bound(database: &Path) -> anyhow::Result<(CampaignEngineV1, GovernedRuntimeProfileV1)> {
    let (engine, profile, _) = open_bound_with_digest(database)?;
    Ok((engine, profile))
}

fn open_bound_with_digest(
    database: &Path,
) -> anyhow::Result<(CampaignEngineV1, GovernedRuntimeProfileV1, Digest)> {
    let engine = CampaignEngineV1::open(database)?;
    let stored = engine
        .runtime_profile()?
        .context("campaign was not created through the genesis-bound production surface")?;
    if stored.schema != GOVERNED_RUNTIME_PROFILE_SCHEMA_V1 {
        bail!("campaign runtime profile schema is not supported");
    }
    let profile: GovernedRuntimeProfileV1 = strict_json_from_slice(&stored.canonical_bytes)
        .context("decode genesis-bound runtime profile")?;
    if profile.schema != stored.schema {
        bail!("campaign runtime profile schema binding is inconsistent");
    }
    Ok((engine, profile, stored.digest))
}

fn submit_intervention(
    database: &Path,
    submission_path: &Path,
    executor_config: Option<&Path>,
    now_unix_ms: u64,
) -> anyhow::Result<()> {
    let presentation = read_exact_input(submission_path, max_submission_bytes())?;
    let (mut engine, profile, profile_digest) = open_bound_with_digest(database)?;
    let ingress = profile
        .intervention_ingress
        .as_ref()
        .context("campaign has no genesis-bound intervention ingress")?;
    let ledger_path = InterventionSubmissionLedgerV1::path_for_campaign(database);
    let mut ledger =
        InterventionSubmissionLedgerV1::open_writer(&ledger_path, profile_digest.clone())?;

    let verified =
        match verify_submission_bytes(&presentation, ingress, &profile_digest, now_unix_ms) {
            Ok(verified) => verified,
            Err(InterventionIngressErrorV1::Custody(code)) => {
                let (claimed_submission, claimed_request) =
                    claimed_submission_references(&presentation);
                let receipt = ledger.record_custody_refusal(
                    &presentation,
                    claimed_submission,
                    claimed_request,
                    code,
                    now_unix_ms,
                )?;
                return write_exact(&receipt);
            }
            Err(error) => return Err(error.into()),
        };
    let _ = ledger.record_received(&verified, now_unix_ms)?;

    if let Some(result) = canonical_submission_result(&engine, &verified.request)? {
        let receipt = ledger.record_result(&verified, result, now_unix_ms)?;
        return write_exact(&receipt);
    }

    let request = verified.request.clone();
    let scope = HumanAuthorityScopeV1 {
        principal: request.principal.clone(),
        mandate: request.mandate.clone(),
    };
    let evaluation = (|| -> anyhow::Result<()> {
        let pinned_verifier = profile
            .human_verifier
            .as_ref()
            .context("campaign has no genesis-pinned human/intervention verifier")?;
        let _ = pinned_verifier.verify(true)?;
        let mut authority_verifier =
            CommandGovernedInterventionVerifierV1::new(pinned_verifier.path.clone());

        if matches!(
            request.intervention,
            GovernedInterventionClassV1::ReconcileAttempt { .. }
        ) {
            let executor_config = executor_config.context(
                "reconcile_attempt submission requires the exact Docket executor configuration",
            )?;
            let mut docket = docket_port_from_profile(&profile, executor_config)?;
            let _ = engine.request_reconciliation(
                request,
                &scope,
                &mut authority_verifier,
                &mut docket,
                now_unix_ms,
            )?;
        } else {
            if executor_config.is_some() {
                bail!("executor configuration is accepted only for reconcile_attempt");
            }
            let _ = engine.apply_governed_intervention(
                request,
                &scope,
                &mut authority_verifier,
                now_unix_ms,
            )?;
        }
        Ok(())
    })();

    let result = if let Some(result) = canonical_submission_result(&engine, &verified.request)? {
        result
    } else {
        match evaluation {
            Ok(()) => InterventionSubmissionStatusV1::OutcomeUnknown {
                code: "governed_result_missing".to_owned(),
            },
            Err(error) => {
                if let Some(
                    CampaignEngineErrorV1::Kernel(KernelErrorV1::External(
                        ExternalBoundaryErrorV1::Refused { code, .. },
                    ))
                    | CampaignEngineErrorV1::External(ExternalBoundaryErrorV1::Refused {
                        code, ..
                    }),
                ) = error.downcast_ref::<CampaignEngineErrorV1>()
                {
                    InterventionSubmissionStatusV1::GovernedRefused {
                        refusal: None,
                        code: format!("requester_verification:{code}"),
                    }
                } else if let Some(CampaignEngineErrorV1::Kernel(_)) =
                    error.downcast_ref::<CampaignEngineErrorV1>()
                {
                    InterventionSubmissionStatusV1::GovernedRefused {
                        refusal: None,
                        code: "governed_kernel_refusal".to_owned(),
                    }
                } else {
                    InterventionSubmissionStatusV1::OutcomeUnknown {
                        code: "governed_evaluation_unavailable".to_owned(),
                    }
                }
            }
        }
    };
    let receipt = ledger.record_result(&verified, result, now_unix_ms)?;
    write_exact(&receipt)
}

fn canonical_submission_result(
    engine: &CampaignEngineV1,
    request: &GovernedInterventionRequestV1,
) -> anyhow::Result<Option<InterventionSubmissionStatusV1>> {
    let history = engine.history()?;
    for transition in history.transitions.iter().rev() {
        if let CampaignTransitionEvidenceV1::GovernedIntervention { verified } =
            &transition.evidence
            && verified.request.request == request.request
        {
            return Ok(Some(InterventionSubmissionStatusV1::GovernedAccepted {
                event: transition.event_digest.clone(),
                successor_state: transition.successor_state_digest.clone(),
                transition: serde_enum_name(&transition.kind)?,
            }));
        }
    }
    let refusals = engine.refusal_history()?;
    for refusal in refusals.refusals.iter().rev() {
        if let Some(verified) = &refusal.outcome.governed_intervention
            && verified.request.request == request.request
        {
            if refusal.outcome.code == RefusalCodeV1::InterventionOutcomeUnknown {
                return Ok(Some(InterventionSubmissionStatusV1::OutcomeUnknown {
                    code: "reconciliation_outcome_unknown".to_owned(),
                }));
            }
            return Ok(Some(InterventionSubmissionStatusV1::GovernedRefused {
                refusal: Some(refusal.refusal.clone()),
                code: serde_enum_name(&refusal.outcome.code)?,
            }));
        }
    }
    Ok(None)
}

fn serde_enum_name<T: Serialize>(value: &T) -> anyhow::Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(ToOwned::to_owned)
        .context("canonical enum is not represented by one string")
}

fn docket_port_from_profile(
    profile: &GovernedRuntimeProfileV1,
    executor_config: &Path,
) -> anyhow::Result<CommandDocketReconciliationPortV1> {
    let pinned = &profile.docket;
    let _ = pinned.docket_program.verify(true)?;
    let _ = pinned.trust_config.verify(false)?;
    let _ = pinned.standing_resolver.verify(true)?;
    let _ = pinned.executor_adapter.verify(true)?;
    Ok(CommandDocketReconciliationPortV1::new(
        pinned.docket_program.path.clone(),
        pinned.state_directory.clone(),
        pinned.trust_config.path.clone(),
        pinned.standing_resolver.path.clone(),
        pinned.executor_adapter.path.clone(),
        executor_config.to_owned(),
    ))
}

fn gate_components(
    profile: &GovernedRuntimeProfileV1,
    arguments: &GateArguments,
) -> anyhow::Result<(
    CommandObservationResolverV1,
    CommandStandingResolverV1,
    ExactWorkCatalogV1,
    Option<C1RejectedReviewBasisV1>,
)> {
    let _ = profile
        .observation_resolver
        .verify_presented(&arguments.observation_resolver, true)?;
    let _ = profile
        .standing_resolver
        .verify_presented(&arguments.standing_resolver, true)?;
    let _ = profile
        .exact_work_catalog
        .verify_presented(&arguments.catalog, false)?;
    if arguments.expected_observation_resolver_id != profile.observation_resolver_id
        || arguments.expected_standing_resolver_id != profile.standing_resolver_id
        || arguments.max_standing_ttl_ms != profile.max_standing_ttl_ms
    {
        bail!("caller substituted a genesis-pinned governance parameter");
    }
    match (&profile.controlling_review, &arguments.controlling_review) {
        (None, None) => {}
        (Some(pinned), Some(presented)) => {
            let _ = pinned.verify_presented(presented, false)?;
        }
        _ => bail!("caller substituted the genesis-pinned controlling review"),
    }
    let catalog: ExactWorkCatalogV1 = read_exact_record(&profile.exact_work_catalog.path)?;
    let review = profile
        .controlling_review
        .as_ref()
        .map(|pinned| read_exact_record(&pinned.path))
        .transpose()?;
    Ok((
        CommandObservationResolverV1::new(profile.observation_resolver.path.clone()),
        CommandStandingResolverV1::new(profile.standing_resolver.path.clone()),
        catalog,
        review,
    ))
}

fn docket_port(
    profile: &GovernedRuntimeProfileV1,
    arguments: &DocketArguments,
) -> anyhow::Result<CommandDocketCustodyPortV1> {
    let pinned = &profile.docket;
    if arguments.docket != pinned.docket_program.path
        || arguments.docket_state != pinned.state_directory
        || arguments.docket_trust != pinned.trust_config.path
        || arguments.docket_standing_resolver != pinned.standing_resolver.path
        || arguments.executor != pinned.executor_adapter.path
        || arguments.issuer_principal != pinned.issuer_principal
        || arguments.issuer_key_id != pinned.issuer_key_id
        || arguments.issuer_key != pinned.issuer_key.path
    {
        bail!("caller substituted the genesis-pinned Docket boundary");
    }
    pinned.verify_all()?;
    let key = pinned.issuer_key.verify(false)?;
    let signer = AgIssuanceSignerV1::from_pkcs8(
        pinned.issuer_principal.clone(),
        pinned.issuer_key_id.clone(),
        &key,
    )?;
    // The executor plan is not a deployment selector: it is the exact work
    // for this occurrence, and Docket refuses it unless its identity equals
    // the work identity in AG's signed issuance.
    Ok(CommandDocketCustodyPortV1::new(
        pinned.docket_program.path.clone(),
        pinned.state_directory.clone(),
        pinned.trust_config.path.clone(),
        pinned.standing_resolver.path.clone(),
        pinned.executor_adapter.path.clone(),
        arguments.executor_config.clone(),
        signer,
    ))
}

fn runtime_profile_receipt(
    profile: &GovernedRuntimeProfileV1,
    canonical_bytes: &[u8],
) -> RuntimeProfileSealReceiptV1 {
    RuntimeProfileSealReceiptV1 {
        schema: RUNTIME_PROFILE_SEAL_RECEIPT_SCHEMA_V1,
        profile_schema: GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
        profile_digest: Digest::hash_domain(GOVERNED_RUNTIME_PROFILE_SCHEMA_V1, canonical_bytes),
        observation_resolver_id: profile.observation_resolver_id.clone(),
        standing_resolver_id: profile.standing_resolver_id.clone(),
        issuer_principal: profile.docket.issuer_principal.clone(),
        issuer_key_id: profile.docket.issuer_key_id.clone(),
        intervention_submitter_principal: profile
            .intervention_ingress
            .as_ref()
            .map(|ingress| ingress.submitter_principal.clone()),
        intervention_submitter_key_id: profile
            .intervention_ingress
            .as_ref()
            .map(|ingress| ingress.submitter_key_id.clone()),
    }
}

fn runtime_profile_digest(canonical_bytes: &[u8]) -> Digest {
    Digest::hash_domain(GOVERNED_RUNTIME_PROFILE_SCHEMA_V1, canonical_bytes)
}

fn write_exact_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if !path.is_absolute() {
        bail!("sealed runtime-profile output path must be absolute");
    }
    let parent = path
        .parent()
        .context("sealed runtime-profile output has no parent")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("sealed runtime-profile output has no normal filename")?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .with_context(|| format!("create sealed profile {}", temporary.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path).with_context(|| {
            format!(
                "publish sealed profile without replacement: {}",
                path.display()
            )
        })?;
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_exact_record<T>(path: &Path) -> anyhow::Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = fs::read(path).with_context(|| format!("read exact record {}", path.display()))?;
    let value: T = strict_json_from_slice(&bytes)
        .with_context(|| format!("parse exact record {}", path.display()))?;
    let canonical = JcsDocument::canonicalize(&value)?;
    if bytes != canonical.as_bytes()
        && !(bytes.ends_with(b"\n") && &bytes[..bytes.len() - 1] == canonical.as_bytes())
    {
        bail!(
            "record is not canonical JSON (with at most one final LF): {}",
            path.display()
        );
    }
    Ok(value)
}

fn write_exact<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<()> {
    let canonical = JcsDocument::canonicalize(value)?;
    println!("{}", canonical.as_str());
    Ok(())
}

fn now_unix_ms() -> anyhow::Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    u64::try_from(duration.as_millis()).context("system clock exceeds u64 milliseconds")
}
