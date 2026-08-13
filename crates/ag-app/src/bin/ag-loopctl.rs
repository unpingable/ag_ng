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

use ag_app::governed_product::{
    CreateCampaignV1, CreateDecisionRequestV1, GovernedAgPolicyRootV1, GovernedCampaignServiceV1,
    GovernedDocketAdapterRootV1, GovernedRepairVerifierRootV1, OccurrencePageRequestV1,
    PageRequestV1, SubmitGovernedDispositionV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use ag_protocol::strict_json_from_slice;
use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
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
    /// Print the stable product state plus allowed transitions/event cursor.
    ProductState {
        #[arg(long)]
        database: PathBuf,
    },
    /// List occurrences through the stable product cursor contract.
    ListOccurrences {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long, value_enum)]
        program_counter: Option<ProgramCounterArgumentV1>,
        #[arg(long)]
        governed_repair_pending: Option<bool>,
    },
    /// List ordered events through the stable product cursor contract.
    ListEvents {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Create one durable non-authorizing governed-repair request.
    CreateDecisionRequest {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Submit one exact governed-repair disposition through root-owned profile.
    SubmitGovernedDisposition {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Resolve a fresh observation and record one exact proposal.
    RecordProposal {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Enter the explicit current-standing-required state.
    RequireStanding {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Resolve current premises and record a positive AG decision only.
    Decide {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Re-resolve current premises and durably spend the one AG authorization.
    Authorize {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Submit the already-durable exact issuance to Docket custody.
    Dispatch {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Read-only reconcile/poll the exact Docket attempt.
    Poll {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Apply the PC-specific restart law without reconstructing authority.
    Recover {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Open a distinct authority-empty occurrence after settlement.
    Continue {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Persist one read-only probe-count fact.
    NoteProbe {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Halt from an authority-safe boundary.
    Halt {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Consume one escalation budget fact and halt.
    Escalate {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Complete only from a fresh observation boundary with no residuals.
    Complete {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
    /// Record a typed non-authorizing refusal without advancing the PC.
    Refuse {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[command(flatten)]
        cas: CasArguments,
    },
}

#[derive(Debug, Args)]
struct CasArguments {
    /// Exact state observed by the caller; stale values fail closed.
    #[arg(long)]
    expected_state: String,
}

#[derive(Clone, Debug, ValueEnum)]
enum ProgramCounterArgumentV1 {
    ObservationRequired,
    ProposalRecorded,
    StandingRequired,
    AdmissiblePendingAuthorization,
    AuthorizationConsumed,
    Dispatched,
    ReconciliationRequired,
    SettledObservationRequired,
    Halted,
    Completed,
}

impl From<ProgramCounterArgumentV1> for ProgramCounterV1 {
    fn from(value: ProgramCounterArgumentV1) -> Self {
        match value {
            ProgramCounterArgumentV1::ObservationRequired => Self::ObservationRequired,
            ProgramCounterArgumentV1::ProposalRecorded => Self::ProposalRecorded,
            ProgramCounterArgumentV1::StandingRequired => Self::StandingRequired,
            ProgramCounterArgumentV1::AdmissiblePendingAuthorization => {
                Self::AdmissiblePendingAuthorization
            }
            ProgramCounterArgumentV1::AuthorizationConsumed => Self::AuthorizationConsumed,
            ProgramCounterArgumentV1::Dispatched => Self::Dispatched,
            ProgramCounterArgumentV1::ReconciliationRequired => Self::ReconciliationRequired,
            ProgramCounterArgumentV1::SettledObservationRequired => {
                Self::SettledObservationRequired
            }
            ProgramCounterArgumentV1::Halted => Self::Halted,
            ProgramCounterArgumentV1::Completed => Self::Completed,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisInputV1 {
    campaign: CampaignId,
    occurrence: OccurrenceId,
    program: ProgramBasisRefV1,
    residuals: ResidualSetV1,
    budget: LoopBudgetV1,
    idempotency_key: Digest,
    governed_ag_policy_root: GovernedAgPolicyRootV1,
    governed_repair_verifier_root: Option<GovernedRepairVerifierRootV1>,
    governed_docket_adapter_root: Option<GovernedDocketAdapterRootV1>,
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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HaltInputV1 {
    reason: HaltReasonRefV1,
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
    match arguments.command {
        Command::Init { database, genesis } => {
            let input: GenesisInputV1 = read_exact_record(&genesis)?;
            let service = GovernedCampaignServiceV1::create(
                &database,
                CreateCampaignV1 {
                    campaign: input.campaign,
                    occurrence: input.occurrence,
                    program: input.program,
                    residuals: input.residuals,
                    budget: input.budget,
                    idempotency_key: input.idempotency_key,
                    governed_ag_policy_root: input.governed_ag_policy_root,
                    governed_repair_verifier_root: input.governed_repair_verifier_root,
                    governed_docket_adapter_root: input.governed_docket_adapter_root,
                },
            )?;
            write_exact(&service.state()?.current)
        }
        Command::Status { database } => {
            write_exact(&GovernedCampaignServiceV1::open(&database)?.state()?.current)
        }
        Command::Replay { database } => {
            write_exact(&GovernedCampaignServiceV1::open(&database)?.replay()?)
        }
        Command::ProductState { database } => {
            write_exact(&GovernedCampaignServiceV1::open(&database)?.state()?)
        }
        Command::ListOccurrences {
            database,
            after,
            limit,
            program_counter,
            governed_repair_pending,
        } => write_exact(
            &GovernedCampaignServiceV1::open(&database)?.list_occurrences(
                &OccurrencePageRequestV1 {
                    after,
                    limit,
                    program_counter: program_counter.map(Into::into),
                    governed_repair_pending,
                },
            )?,
        ),
        Command::ListEvents {
            database,
            after,
            limit,
        } => write_exact(
            &GovernedCampaignServiceV1::open(&database)?
                .list_events(&PageRequestV1 { after, limit })?,
        ),
        Command::CreateDecisionRequest {
            database,
            input,
            cas,
        } => {
            let request: CreateDecisionRequestV1 = read_exact_record(&input)?;
            let expected = parse_expected_state(&cas)?;
            if request.expected_state_digest != expected {
                bail!("input and --expected-state differ");
            }
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            write_exact(&service.create_decision_request(request)?)
        }
        Command::SubmitGovernedDisposition {
            database,
            input,
            cas,
        } => {
            let request: SubmitGovernedDispositionV1 = read_exact_record(&input)?;
            let expected = parse_expected_state(&cas)?;
            if request.expected_state_digest != expected {
                bail!("input and --expected-state differ");
            }
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            write_exact(&service.submit_governed_disposition(request)?)
        }
        Command::RecordProposal {
            database,
            input,
            cas,
        } => {
            let input: ProposalInputV1 = read_exact_record(&input)?;
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            let state = service.record_proposal(
                &expected,
                input.observation,
                input.proposal,
                input.class,
            )?;
            write_exact(&state)
        }
        Command::RequireStanding { database, cas } => {
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.require_standing(&expected)?)
        }
        Command::Decide { database, cas } => {
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.decide(&expected)?)
        }
        Command::Authorize { database, cas } => {
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.authorize(&expected)?)
        }
        Command::Dispatch { database, cas } => {
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.dispatch(&expected)?)
        }
        Command::Poll { database, cas } => {
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.reconcile_docket(&expected)?)
        }
        Command::Recover { database, cas } => {
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.recover(&expected)?)
        }
        Command::Continue {
            database,
            input,
            cas,
        } => {
            let input: ContinuationInputV1 = read_exact_record(&input)?;
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.open_continuation(&expected, input.occurrence)?)
        }
        Command::NoteProbe { database, cas } => {
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.note_probe(&expected)?)
        }
        Command::Halt {
            database,
            input,
            cas,
        } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.halt(&expected, input.reason)?)
        }
        Command::Escalate {
            database,
            input,
            cas,
        } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.escalate(&expected, input.reason)?)
        }
        Command::Complete {
            database,
            input,
            cas,
        } => {
            let input: CompletionInputV1 = read_exact_record(&input)?;
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            write_exact(&service.complete(
                &expected,
                input.observation,
                &input.subject,
                input.terminal_witness,
            )?)
        }
        Command::Refuse {
            database,
            input,
            cas,
        } => {
            let input: RefusalInputV1 = read_exact_record(&input)?;
            let mut service = GovernedCampaignServiceV1::open(&database)?;
            let expected = parse_expected_state(&cas)?;
            let refusal = service.record_refusal(&expected, input.code, input.evidence)?;
            write_exact(&refusal)
        }
    }
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

fn parse_expected_state(arguments: &CasArguments) -> anyhow::Result<Digest> {
    Digest::parse(&arguments.expected_state).context("parse --expected-state")
}
