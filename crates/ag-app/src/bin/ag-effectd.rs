//! Authority-neutral exact-effect adapter for Docket-custodied attempts.

use std::io::Read as _;
use std::path::PathBuf;

use ag_app::effect_executor_adapter::{
    audit_systemd_effect_store_cut, execute_effect_attempt, execute_systemd_effect_attempt,
    load_effect_executor_plan_any, reconcile_effect_attempt, reconcile_systemd_effect_attempt,
    EffectExecutorDispatchV1, LoadedEffectExecutorPlan, DOCKET_EXECUTOR_MAX_DOCUMENT_BYTES_V1,
};
use ag_primitives::JcsDocument;
use anyhow::Context as _;
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;

#[derive(Debug, Parser)]
#[command(
    name = "ag-effectd",
    version,
    about = "Authority-neutral Docket exact-effect adapter"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the exact immutable work identity of a sealed executor plan.
    PlanId {
        /// Canonical executor-plan JSON.
        plan: PathBuf,
    },
    /// Execute one exact Docket-custodied attempt from stdin.
    Execute {
        /// Canonical executor-plan JSON.
        plan: PathBuf,
    },
    /// Read executor-local evidence without invoking mechanics.
    Reconcile {
        /// Canonical executor-plan JSON.
        plan: PathBuf,
    },
    /// Validate a copied terminal Systemd V2 store without invoking mechanics.
    AuditStore {
        /// Canonical executor-plan JSON whose live store identity remains unchanged.
        plan: PathBuf,
        /// Immutable copied `SQLite` store to validate as evidence.
        #[arg(long)]
        store_cut: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::PlanId { plan } => {
            let plan = load_effect_executor_plan_any(&plan).map_err(anyhow::Error::msg)?;
            println!("{}", plan.identity().map_err(anyhow::Error::msg)?);
        }
        Command::Execute { plan } => {
            let plan = load_effect_executor_plan_any(&plan).map_err(anyhow::Error::msg)?;
            let dispatch: EffectExecutorDispatchV1 = read_stdin_strict()?;
            let outcome = match &plan {
                LoadedEffectExecutorPlan::V1(plan) => execute_effect_attempt(plan, &dispatch),
                LoadedEffectExecutorPlan::SystemdV2(plan) => {
                    execute_systemd_effect_attempt(plan, &dispatch)
                }
            }
            .map_or_else(handle_adapter_error, Ok)?;
            write_canonical(&outcome)?;
        }
        Command::Reconcile { plan } => {
            let plan = load_effect_executor_plan_any(&plan).map_err(anyhow::Error::msg)?;
            let dispatch: EffectExecutorDispatchV1 = read_stdin_strict()?;
            let outcome = match &plan {
                LoadedEffectExecutorPlan::V1(plan) => reconcile_effect_attempt(plan, &dispatch),
                LoadedEffectExecutorPlan::SystemdV2(plan) => {
                    reconcile_systemd_effect_attempt(plan, &dispatch)
                }
            }
            .map_or_else(handle_adapter_error, Ok)?;
            write_canonical(&outcome)?;
        }
        Command::AuditStore { plan, store_cut } => {
            let plan = load_effect_executor_plan_any(&plan).map_err(anyhow::Error::msg)?;
            let dispatch: EffectExecutorDispatchV1 = read_stdin_strict()?;
            let LoadedEffectExecutorPlan::SystemdV2(plan) = &plan else {
                anyhow::bail!("audit-store-requires-systemd-v2");
            };
            let outcome = audit_systemd_effect_store_cut(plan, &dispatch, &store_cut)
                .map_err(anyhow::Error::msg)?;
            write_canonical(&outcome)?;
        }
    }
    Ok(())
}

fn handle_adapter_error(
    error: String,
) -> anyhow::Result<ag_app::effect_executor_adapter::EffectExecutorOutcomeV1> {
    if error == "systemd_attempt_in_progress" {
        eprintln!("systemd_attempt_in_progress");
        std::process::exit(75);
    }
    Err(anyhow::Error::msg(error))
}

fn read_stdin_strict<T: DeserializeOwned>() -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(DOCKET_EXECUTOR_MAX_DOCUMENT_BYTES_V1 + 1)
        .read_to_end(&mut bytes)
        .context("read exact Docket dispatch")?;
    if bytes.is_empty() || bytes.len() as u64 > DOCKET_EXECUTOR_MAX_DOCUMENT_BYTES_V1 {
        anyhow::bail!("Docket dispatch is empty or exceeds the exact bound");
    }
    let document = JcsDocument::parse(&bytes).context("strict Docket dispatch JSON")?;
    serde_json::from_slice(document.as_bytes()).context("decode exact Docket dispatch")
}

fn write_canonical<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let document = JcsDocument::canonicalize(value).context("canonical executor outcome")?;
    println!("{}", document.as_str());
    Ok(())
}
