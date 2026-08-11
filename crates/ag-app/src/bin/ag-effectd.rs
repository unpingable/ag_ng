//! Authority-neutral exact-effect adapter for Docket-custodied attempts.

use std::io::Read as _;
use std::path::PathBuf;

use ag_app::effect_executor_adapter::{
    EffectExecutorDispatchV1, execute_effect_attempt, load_effect_executor_plan,
    reconcile_effect_attempt,
};
use ag_primitives::JcsDocument;
use anyhow::Context as _;
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;

const MAX_DISPATCH_BYTES: u64 = 1024 * 1024;

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
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::PlanId { plan } => {
            let plan = load_effect_executor_plan(&plan).map_err(anyhow::Error::msg)?;
            println!("{}", plan.identity().map_err(anyhow::Error::msg)?);
        }
        Command::Execute { plan } => {
            let plan = load_effect_executor_plan(&plan).map_err(anyhow::Error::msg)?;
            let dispatch: EffectExecutorDispatchV1 = read_stdin_strict()?;
            let outcome = execute_effect_attempt(&plan, &dispatch).map_err(anyhow::Error::msg)?;
            write_canonical(&outcome)?;
        }
        Command::Reconcile { plan } => {
            let plan = load_effect_executor_plan(&plan).map_err(anyhow::Error::msg)?;
            let dispatch: EffectExecutorDispatchV1 = read_stdin_strict()?;
            let outcome = reconcile_effect_attempt(&plan, &dispatch).map_err(anyhow::Error::msg)?;
            write_canonical(&outcome)?;
        }
    }
    Ok(())
}

fn read_stdin_strict<T: DeserializeOwned>() -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_DISPATCH_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read exact Docket dispatch")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_DISPATCH_BYTES {
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
