//! `ag-migrate`: offline verification for migration ledgers and classic archives.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use ag_migrate::{read_control_document, verify_archive, verify_ledger};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ag-migrate",
    version,
    about = "Verify AG-ng migration evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify a canonical replacement/retirement ledger and bound AG-ng evidence.
    Ledger {
        /// Canonical migration-ledger JSON file.
        #[arg(long)]
        ledger: PathBuf,
        /// Root containing the ledger's source manifest and AG-ng evidence.
        #[arg(long)]
        evidence_root: PathBuf,
    },
    /// Verify a frozen classic archive as opaque, non-authoritative bytes.
    Archive {
        /// Canonical archive-manifest JSON file.
        #[arg(long)]
        manifest: PathBuf,
        /// Root of the frozen classic archive.
        #[arg(long)]
        archive_root: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Ledger {
            ledger,
            evidence_root,
        } => {
            let bytes = read_control_document(&ledger)?;
            let result = verify_ledger(&bytes, &evidence_root)?;
            println!(
                "verified ledger={} inventory={} replaced={} retired={} blocked={} completeness=partial_authority_critical classic_runtime_authority=false",
                result.ledger_digest,
                result.inventory,
                result.replaced,
                result.retired,
                result.blocked
            );
        }
        Command::Archive {
            manifest,
            archive_root,
        } => {
            let bytes = read_control_document(&manifest)?;
            let result = verify_archive(&bytes, &archive_root)?;
            println!(
                "verified manifest={} files={} bytes={} authority_use=archive_evidence_only",
                result.manifest_digest, result.files, result.total_bytes
            );
        }
    }
    Ok(())
}
