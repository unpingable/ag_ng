//! Shared daemon and CLI implementation for Agent Governor NG.

pub mod agd;
pub mod api;
pub mod config;
mod custody;
pub mod derived;
pub mod descriptor_path;
pub mod doctor;
pub mod effect_executor_adapter;
pub mod effectd;
pub mod effectd_activation;
mod exact_exec;
mod governed_loop;
#[cfg(test)]
mod governed_loop_tests;
mod governed_ports;
pub mod governed_product;
#[cfg(test)]
mod governed_product_fixture_support;
#[cfg(test)]
mod governed_product_tests;
#[cfg(test)]
mod governed_repair_docket_process_tests;
mod governed_store;
#[cfg(test)]
mod governed_store_tests;
pub mod managed_pointer;
#[cfg(test)]
mod nq_c1_governed_repair_lifecycle_tests;
pub mod peer;
pub mod rpc_auth;
pub mod runtime;
pub mod signed_transport;
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
