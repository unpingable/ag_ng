//! Phosphor-ng read-only operator projection for the canonical AG governed loop.
//!
//! The crate consumes only versioned canonical command output. It does not
//! link the campaign engine, construct transitions, or expose a mutation API.

#![forbid(unsafe_code)]

pub mod investigation;
pub mod links;
pub mod model;
pub mod render;
pub mod server;
pub mod source;
