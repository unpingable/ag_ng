//! Local read-only operator interface for persisted governed campaigns.

use std::net::SocketAddr;
use std::path::PathBuf;

use ag_operator_ui::server::{serve, validate_bind_ip};
use ag_operator_ui::source::{
    DocketReadSourceV1, MaudeAcquisitionReadSourceV1, NightshiftReadSourceV1, OperatorReaderV1,
    OperatorSourceConfigV1,
};
use anyhow::{Context as _, Result, bail};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "ag-operator-ui",
    about = "Phosphor-ng: loopback-only, read-only governed-runtime inspector"
)]
struct Args {
    /// Directory containing immediate canonical AG campaign `.sqlite` stores.
    #[arg(long, conflicts_with = "demo_corpus")]
    campaign_root: Option<PathBuf>,

    /// Absolute path to the canonical `ag-loopctl` executable.
    #[arg(long, conflicts_with = "demo_corpus")]
    ag_loopctl: Option<PathBuf>,

    /// Deterministic captured corpus for presentation qualification only.
    #[arg(long, conflicts_with_all = ["campaign_root", "ag_loopctl", "nightshift_bin", "nightshift_store", "docket_bin", "docket_state", "maude_acquisition_bin", "maude_acquisition_ledger"])]
    demo_corpus: Option<PathBuf>,

    /// Absolute path to the canonical `nightshift` executable.
    #[arg(long, requires = "nightshift_store")]
    nightshift_bin: Option<PathBuf>,

    /// Existing Nightshift canonical store.
    #[arg(long, requires = "nightshift_bin")]
    nightshift_store: Option<PathBuf>,

    /// Absolute path to the canonical `docket` executable.
    #[arg(long, requires = "docket_state")]
    docket_bin: Option<PathBuf>,

    /// Existing Docket state directory.
    #[arg(long, requires = "docket_bin")]
    docket_state: Option<PathBuf>,

    /// Absolute path to the closed Maude acquisition CLI.
    #[arg(long, requires = "maude_acquisition_ledger")]
    maude_acquisition_bin: Option<PathBuf>,

    /// Existing Maude acquisition trigger/request/event ledger.
    #[arg(long, requires = "maude_acquisition_bin")]
    maude_acquisition_ledger: Option<PathBuf>,

    /// Loopback address for the local HTTP listener.
    #[arg(long, default_value = "127.0.0.1:8417")]
    bind: SocketAddr,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_bind_ip(args.bind.ip()).map_err(anyhow::Error::msg)?;
    let reader = if let Some(corpus) = args.demo_corpus {
        OperatorReaderV1::from_demo_corpus(&corpus)
            .map_err(anyhow::Error::msg)
            .context("validate deterministic operator demo corpus")?
    } else {
        let nightshift = match (args.nightshift_bin, args.nightshift_store) {
            (Some(program), Some(store)) => Some(NightshiftReadSourceV1 { program, store }),
            (None, None) => None,
            _ => bail!("Nightshift binary and store must be configured together"),
        };
        let docket = match (args.docket_bin, args.docket_state) {
            (Some(program), Some(state)) => Some(DocketReadSourceV1 { program, state }),
            (None, None) => None,
            _ => bail!("Docket binary and state must be configured together"),
        };
        let maude_acquisition = match (args.maude_acquisition_bin, args.maude_acquisition_ledger) {
            (Some(program), Some(ledger)) => Some(MaudeAcquisitionReadSourceV1 { program, ledger }),
            (None, None) => None,
            _ => bail!("Maude acquisition binary and ledger must be configured together"),
        };
        OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: args
                .campaign_root
                .context("--campaign-root is required outside demo mode")?,
            ag_loopctl: args
                .ag_loopctl
                .context("--ag-loopctl is required outside demo mode")?,
            nightshift,
            docket,
            maude_acquisition,
        })
        .map_err(anyhow::Error::msg)
        .context("validate read-only operator sources")?
    };
    serve(args.bind, reader).map_err(anyhow::Error::msg)
}
