//! Offline immutable backup publication verifier and evidence restorer.

use std::path::PathBuf;

use ag_store::{publish_backup_staging, restore_backup_evidence, verify_backup_publication};
use anyhow::Context as _;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ag-backup",
    version,
    about = "Offline AG-ng coherent backup publication and evidence verification"
)]
struct Arguments {
    /// Offline operation. This tool never contacts a running daemon.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify the manifest, all three databases/chains, and every immutable object.
    Verify {
        /// Published immutable bundle root.
        #[arg(long, value_name = "PATH")]
        publication: PathBuf,
    },
    /// Atomically rename a fully verified sibling staging tree into place.
    Publish {
        /// Fully materialized and immutable staging root.
        #[arg(long, value_name = "PATH")]
        staging: PathBuf,
        /// Previously absent immutable publication name in the same directory.
        #[arg(long, value_name = "PATH")]
        destination: PathBuf,
    },
    /// Copy and atomically install a verified immutable evidence tree.
    ///
    /// This does not activate daemon stores or advance the authority epoch.
    RestoreEvidence {
        /// Verified source publication.
        #[arg(long, value_name = "PATH")]
        publication: PathBuf,
        /// Previously absent evidence destination.
        #[arg(long, value_name = "PATH")]
        destination: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let publication = match arguments.command {
        Command::Verify { publication } => verify_backup_publication(&publication)
            .with_context(|| format!("backup verification failed: {}", publication.display()))?,
        Command::Publish {
            staging,
            destination,
        } => publish_backup_staging(&staging, &destination).with_context(|| {
            format!(
                "atomic backup publication failed: {} -> {}",
                staging.display(),
                destination.display()
            )
        })?,
        Command::RestoreEvidence {
            publication,
            destination,
        } => restore_backup_evidence(&publication, &destination).with_context(|| {
            format!(
                "offline evidence restore failed: {} -> {}",
                publication.display(),
                destination.display()
            )
        })?,
    };
    println!("{}", publication.digest());
    Ok(())
}
