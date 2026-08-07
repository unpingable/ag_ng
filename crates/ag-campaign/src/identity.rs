//! Campaign identity, human-authorized intent, and worker-role separation.

use core::fmt;

use ag_primitives::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::transcript::{transcript_digest, validate_label};

/// Wire schema of the human-authorized campaign intent.
pub const CAMPAIGN_INTENT_SCHEMA_V1: &str = "ag.campaign.intent/v1";
/// Digest domain binding a campaign identity to its exact intent transcript.
pub const CAMPAIGN_IDENTITY_DOMAIN_V1: &str = "ag.campaign.identity/v1";

/// The exact, immutable identity of one campaign.
///
/// A campaign identity is the domain-separated digest of the exact canonical
/// intent transcript. It has no mutator and no constructor from ambient text.
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

/// The exactly-one-role vocabulary for campaign stages and workers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRoleV1 {
    /// Executes the stage's bounded mutation scope.
    Operator,
    /// Reviews executed work; carries no mutation effects.
    Reviewer,
}

impl WorkerRoleV1 {
    /// Returns the stable role name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Reviewer => "reviewer",
        }
    }
}

/// A rejected bounded label or path.
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
    /// A path prefix exceeds the independently bounded canonical-path capacity.
    #[error("path prefix exceeds 256 bytes (got {actual})")]
    PathTooLong {
        /// Actual UTF-8 byte length of the canonical leading-slash form.
        actual: usize,
    },
    /// The label contains an ASCII control character.
    #[error("{kind} contains an ASCII control character")]
    ControlCharacter {
        /// Label family.
        kind: &'static str,
    },
    /// A path prefix is not absolute and normalized.
    #[error("path prefix must be absolute, normalized, and free of `..` components")]
    NonCanonicalPath,
    /// The record carries a foreign schema.
    #[error("{kind} carries a foreign schema")]
    ForeignSchema {
        /// Record family.
        kind: &'static str,
    },
    /// A set contains a duplicate member.
    #[error("{kind} contains a duplicate member")]
    Duplicate {
        /// Set family.
        kind: &'static str,
    },
    /// A value is outside its admitted domain here.
    #[error("{kind} is not admitted here")]
    NotAdmitted {
        /// Value family.
        kind: &'static str,
    },
}

/// A rejected campaign intent.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CampaignIntentError {
    /// The schema is not exactly [`CAMPAIGN_INTENT_SCHEMA_V1`].
    #[error("campaign intent schema must be exactly `{CAMPAIGN_INTENT_SCHEMA_V1}`")]
    Schema,
    /// The operator and reviewer principal identities are equal.
    #[error("operator and reviewer principals must be distinct")]
    RoleSeparation,
    /// The campaign label is not canonical.
    #[error("invalid campaign label: {0}")]
    Label(#[from] CampaignLabelError),
}

/// The human-authorized campaign intent.
///
/// The intent binds the human authorization instrument identity and the two
/// separated worker principal identities. It is a request context, not
/// authority: nothing in it can admit a stage or construct an `Authority`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignIntentV1 {
    schema: String,
    label: String,
    human_authorization: Digest,
    operator_principal: Digest,
    reviewer_principal: Digest,
}

impl CampaignIntentV1 {
    /// Creates an intent, refusing when operator and reviewer are not distinct.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignIntentError::RoleSeparation`] when the two principal
    /// identities are equal and [`CampaignIntentError::Label`] for a
    /// noncanonical label.
    pub fn new(
        label: String,
        human_authorization: Digest,
        operator_principal: Digest,
        reviewer_principal: Digest,
    ) -> Result<Self, CampaignIntentError> {
        if operator_principal == reviewer_principal {
            return Err(CampaignIntentError::RoleSeparation);
        }
        validate_label("campaign label", &label)?;
        Ok(Self {
            schema: CAMPAIGN_INTENT_SCHEMA_V1.to_owned(),
            label,
            human_authorization,
            operator_principal,
            reviewer_principal,
        })
    }

    /// Revalidates a deserialized intent.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::new`], plus
    /// [`CampaignIntentError::Schema`] for a foreign schema.
    pub fn validate(&self) -> Result<(), CampaignIntentError> {
        if self.schema != CAMPAIGN_INTENT_SCHEMA_V1 {
            return Err(CampaignIntentError::Schema);
        }
        Self::new(
            self.label.clone(),
            self.human_authorization.clone(),
            self.operator_principal.clone(),
            self.reviewer_principal.clone(),
        )?;
        Ok(())
    }

    /// Returns the exact campaign identity derived from this intent.
    #[must_use]
    pub fn campaign_id(&self) -> CampaignId {
        CampaignId(transcript_digest(CAMPAIGN_IDENTITY_DOMAIN_V1, self))
    }

    /// Returns the exact wire schema.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the campaign label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the human authorization instrument identity.
    #[must_use]
    pub const fn human_authorization(&self) -> &Digest {
        &self.human_authorization
    }

    /// Returns the operator principal identity.
    #[must_use]
    pub const fn operator_principal(&self) -> &Digest {
        &self.operator_principal
    }

    /// Returns the reviewer principal identity.
    #[must_use]
    pub const fn reviewer_principal(&self) -> &Digest {
        &self.reviewer_principal
    }
}
