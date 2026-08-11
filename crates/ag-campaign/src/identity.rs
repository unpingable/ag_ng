//! Exact campaign identity and bounded semantic labels.

use core::fmt;

use ag_primitives::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The exact, immutable identity of one campaign.
///
/// The source of this digest is an external exact program/campaign basis. It
/// has no mutator and no constructor from ambient text.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CampaignId(Digest);

impl CampaignId {
    /// Wraps an already-derived campaign identity digest.
    #[must_use]
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    #[must_use]
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }

    /// Returns the canonical digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for CampaignId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A rejected bounded semantic label.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CampaignLabelError {
    /// The label is empty.
    #[error("{kind} must not be empty")]
    Empty {
        /// Label family.
        kind: &'static str,
    },
    /// The label exceeds the 128-byte bound.
    #[error("{kind} exceeds 128 bytes (got {actual})")]
    TooLong {
        /// Label family.
        kind: &'static str,
        /// Actual byte length.
        actual: usize,
    },
    /// The label contains an ASCII control character.
    #[error("{kind} contains an ASCII control character")]
    ControlCharacter {
        /// Label family.
        kind: &'static str,
    },
}
