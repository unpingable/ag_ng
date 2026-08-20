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

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::governed_loop::{CampaignEngineV1, ExactWorkCatalogV1};
use ag_app::governed_ports::{
    AgIssuanceSignerV1, CommandDocketCustodyPortV1, CommandHumanDispositionVerifierV1,
    CommandObservationResolverV1, CommandStandingResolverV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use ag_protocol::strict_json_from_slice;
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
    /// Create one authority-empty campaign occurrence.
    Init {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
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

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let now = now_unix_ms()?;
    match arguments.command {
        Command::Init { database, genesis } => {
            let input: GenesisInputV1 = read_exact_record(&genesis)?;
            let engine = CampaignEngineV1::create(
                &database,
                input.campaign,
                input.occurrence,
                input.program,
                input.expected_ag_work,
                input.residuals,
                input.budget,
                now,
            )?;
            write_exact(&engine.current()?)
        }
        Command::Status { database } => write_exact(&CampaignEngineV1::open(&database)?.current()?),
        Command::Replay { database } => write_exact(&CampaignEngineV1::open(&database)?.replay()?),
        Command::RecordProposal {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
        } => {
            let input: ProposalInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut observation = CommandObservationResolverV1::new(observation_resolver);
            let state = engine.record_proposal(
                input.observation,
                input.proposal,
                input.class,
                &mut observation,
                &expected_observation_resolver_id,
                now,
            )?;
            write_exact(&state)
        }
        Command::RequireStanding { database } => {
            let mut engine = CampaignEngineV1::open(&database)?;
            write_exact(&engine.require_standing(now)?)
        }
        Command::Decide { database, gate } => {
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut observation = CommandObservationResolverV1::new(gate.observation_resolver);
            let mut standing = CommandStandingResolverV1::new(gate.standing_resolver);
            let catalog: ExactWorkCatalogV1 = read_exact_record(&gate.catalog)?;
            let review = gate
                .controlling_review
                .as_deref()
                .map(read_exact_record)
                .transpose()?;
            write_exact(&engine.decide(
                &mut observation,
                &mut standing,
                &catalog,
                review.as_ref(),
                &gate.expected_observation_resolver_id,
                &gate.expected_standing_resolver_id,
                gate.max_standing_ttl_ms,
                now,
            )?)
        }
        Command::Authorize { database, gate } => {
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut observation = CommandObservationResolverV1::new(gate.observation_resolver);
            let mut standing = CommandStandingResolverV1::new(gate.standing_resolver);
            let catalog: ExactWorkCatalogV1 = read_exact_record(&gate.catalog)?;
            let review = gate
                .controlling_review
                .as_deref()
                .map(read_exact_record)
                .transpose()?;
            write_exact(&engine.authorize(
                &mut observation,
                &mut standing,
                &catalog,
                review.as_ref(),
                &gate.expected_observation_resolver_id,
                &gate.expected_standing_resolver_id,
                gate.max_standing_ttl_ms,
                now,
            )?)
        }
        Command::Dispatch { database, docket } => {
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut docket = docket_port(docket)?;
            write_exact(&engine.dispatch(&mut docket, now)?)
        }
        Command::Poll { database, docket } => {
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut docket = docket_port(docket)?;
            let _ = engine.poll_docket(&mut docket, now)?;
            write_exact(&engine.current()?)
        }
        Command::Recover { database, docket } => {
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut docket = docket_port(docket)?;
            write_exact(&engine.recover(&mut docket, now)?)
        }
        Command::Continue { database, input } => {
            let input: ContinuationInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            write_exact(&engine.open_continuation(input.occurrence, input.expected_ag_work, now)?)
        }
        Command::NoteProbe { database } => {
            let mut engine = CampaignEngineV1::open(&database)?;
            write_exact(&engine.note_probe(now)?)
        }
        Command::Halt { database, input } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            write_exact(&engine.halt(input.reason, now)?)
        }
        Command::Escalate { database, input } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            write_exact(&engine.escalate(input.reason, now)?)
        }
        Command::ApplyDisposition {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
            human_verifier,
        } => {
            let input: HumanDispositionInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut observation = CommandObservationResolverV1::new(observation_resolver);
            let mut verifier = CommandHumanDispositionVerifierV1::new(human_verifier);
            let scope = HumanAuthorityScopeV1 {
                principal: input.expected_principal,
                mandate: input.expected_mandate,
            };
            let _ = engine.apply_human_disposition(
                input.artifact,
                &scope,
                input.new_occurrence,
                &mut observation,
                &expected_observation_resolver_id,
                &mut verifier,
                now,
            )?;
            write_exact(&engine.current()?)
        }
        Command::Complete {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
        } => {
            let input: CompletionInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            let mut observation = CommandObservationResolverV1::new(observation_resolver);
            write_exact(&engine.complete(
                input.observation,
                &input.subject,
                input.terminal_witness,
                &mut observation,
                &expected_observation_resolver_id,
                now,
            )?)
        }
        Command::Refuse { database, input } => {
            let input: RefusalInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            let refusal = engine.record_refusal(input.code, input.evidence, now)?;
            write_exact(&refusal)
        }
    }
}

fn docket_port(arguments: DocketArguments) -> anyhow::Result<CommandDocketCustodyPortV1> {
    let signer = AgIssuanceSignerV1::from_pkcs8_file(
        arguments.issuer_principal,
        arguments.issuer_key_id,
        &arguments.issuer_key,
    )?;
    Ok(CommandDocketCustodyPortV1::new(
        arguments.docket,
        arguments.docket_state,
        arguments.docket_trust,
        arguments.docket_standing_resolver,
        arguments.executor,
        arguments.executor_config,
        signer,
    ))
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
