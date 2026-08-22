//! Shared daemon and CLI implementation for Agent Governor NG.

pub mod agd;
pub mod api;
pub mod config;
mod custody;
pub mod derived;
pub mod descriptor_path;
pub mod docket_issuance;
pub mod doctor;
pub mod effect_executor_adapter;
pub mod effectd;
pub mod effectd_activation;
mod exact_exec;
pub mod governed_loop;
pub mod governed_ports;
pub mod intervention_ingress;
pub mod managed_pointer;
pub mod peer;
pub mod rpc_auth;
pub mod runtime;
pub mod signed_transport;
pub mod standing_authority;
pub mod transport;
pub mod worker;
pub mod worker_protocol;
pub mod worker_session;

use tracing_subscriber::EnvFilter;

/// Installs structured logging with a conservative default filter.
pub fn init_logging(service: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
    tracing::info!(service, "service starting");
}
