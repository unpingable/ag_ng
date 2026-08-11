//! Canonical governed-loop semantics for Agent Governor NG.
//!
//! This crate owns the one production campaign transition law: exact
//! occurrence identity, the closed program counter, AG authorization spend,
//! continuation legality, reconciliation, residual preservation, halt, and
//! completion. Execution, standing, observation, scheduling, and human
//! authority remain external boundaries.

#![forbid(unsafe_code)]

pub mod governed;
mod identity;
mod transcript;

pub use governed::*;
pub use identity::{CampaignId, CampaignLabelError};
