//! The `ag-external-authorizer` daemon binary.
//!
//! Same-UID local custody only: no cryptographic authentication. The daemon
//! fails closed at startup on any custody violation and never maps a
//! daemon-internal failure to a refusal.

use std::path::PathBuf;
use std::process::ExitCode;

use ag_external_authz::adjudicate::DaemonConfigV1;
use ag_external_authz::daemon::{bind_socket, serve, validate_startup};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "ag-external-authorizer",
    version,
    about = "Authorize one exact external action occurrence through AG's governed loop"
)]
struct Arguments {
    /// Filesystem Unix-socket path to bind (created mode 0600).
    #[arg(long)]
    socket: PathBuf,
    /// Existing daemon state directory (mode 0700, owned by euid).
    #[arg(long)]
    state_dir: PathBuf,
    /// Root-owned standing mandate store file (regular file, owned by euid).
    #[arg(long)]
    standing_store: PathBuf,
    /// Exact observation resolver identity.
    #[arg(long)]
    observation_resolver_id: String,
    /// Exact standing resolver identity.
    #[arg(long)]
    standing_resolver_id: String,
    /// Maximum standing-answer lifetime the kernel accepts, in milliseconds.
    #[arg(long)]
    max_standing_ttl_ms: u64,
    /// The standing authority's answer lease, in milliseconds.
    #[arg(long)]
    answer_ttl_ms: u64,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let arguments = Arguments::parse();
    let config = DaemonConfigV1 {
        state_dir: arguments.state_dir.clone(),
        standing_store: arguments.standing_store.clone(),
        observation_resolver_id: arguments.observation_resolver_id,
        standing_resolver_id: arguments.standing_resolver_id,
        max_standing_ttl_ms: arguments.max_standing_ttl_ms,
        answer_ttl_ms: arguments.answer_ttl_ms,
    };
    if let Err(error) = validate_startup(
        &arguments.socket,
        &arguments.state_dir,
        &arguments.standing_store,
        &config,
    ) {
        tracing::error!(%error, "refusing to start");
        return ExitCode::FAILURE;
    }
    let listener = match bind_socket(&arguments.socket) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, "refusing to start");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(socket = %arguments.socket.display(), "ag-external-authorizer serving");
    if let Err(error) = serve(&listener, &config) {
        tracing::error!(%error, "serving failed");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
