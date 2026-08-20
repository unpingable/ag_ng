//! The production standing authority: a one-shot, read-only resolver that
//! answers AG's exact standing request from a local mandate store.
//!
//! The process reads one `ag.governed-loop.standing-request/v1` document from
//! stdin, loads the mandate store fresh, answers with one canonical
//! `ag.governed-loop.standing-resolution/v2` document on stdout, and exits.
//! Negative standing answers (`Absent`/`Revoked`/`Expired`) are successful
//! semantic answers and exit 0; only malformed input, an ambiguous store, or
//! invalid configuration fails the process.
//!
//! This binary has no write API, no networking, and no signing surface.
//! Mandates change out of band by replacing the store document.

use std::io::Read as _;
use std::path::PathBuf;

use ag_app::standing_authority::{
    StandingAuthorityRequestV1, StandingMandateStoreV1, StandingResolverConfigV1, resolve_standing,
};
use ag_primitives::JcsDocument;
use ag_protocol::strict_json_from_slice;
use anyhow::Context as _;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "ag-standing-resolver",
    version,
    about = "Canonical AG standing authority over a local read-only mandate store"
)]
struct Arguments {
    /// Path to the canonical standing-mandate-store document.
    #[arg(long)]
    mandate_store: PathBuf,
    /// The exact resolver identity AG is configured to expect.
    #[arg(long)]
    resolver_id: String,
    /// The authority's maximum answer lease, in milliseconds.
    #[arg(long)]
    answer_ttl_ms: u64,
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let config = StandingResolverConfigV1 {
        resolver_id: arguments.resolver_id,
        answer_ttl_ms: arguments.answer_ttl_ms,
    };
    let mut request_bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut request_bytes)
        .context("failed to read standing request from stdin")?;
    let request: StandingAuthorityRequestV1 = strict_json_from_slice(&request_bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("malformed standing request")?;
    let store_bytes = std::fs::read(&arguments.mandate_store).with_context(|| {
        format!(
            "failed to read mandate store {}",
            arguments.mandate_store.display()
        )
    })?;
    let store: StandingMandateStoreV1 = strict_json_from_slice(&store_bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("malformed standing mandate store")?;
    let resolution = resolve_standing(&store, &request, &config)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let document =
        JcsDocument::canonicalize(&resolution).context("standing resolution failed to encode")?;
    println!("{}", document.as_str());
    Ok(())
}
