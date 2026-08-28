//! In-process [`StandingResolverV1`] over the daemon's root-owned mandate
//! store file.
//!
//! The fixture mirrors the production standing authority exactly
//! ([`ag_app::standing_authority`]): the store is re-read, strictly decoded,
//! and re-validated on every resolution call, so an out-of-band mandate
//! replacement is visible to the next answer with no cache machinery. The
//! resolver has no write API and never interprets mandate content beyond the
//! authority's own selection law (highest generation for the exact
//! `(subject, scope)`; `valid_until <= now` is expired, equality included).
//!
//! A store that cannot be read or validated is an unavailability of the
//! external boundary, surfaced as [`ExternalBoundaryErrorV1::Unavailable`] —
//! it is never a standing status and never a refusal.

use std::path::{Path, PathBuf};

use ag_app::standing_authority::{
    STANDING_AUTHORITY_REQUEST_SCHEMA_V1, StandingAuthorityRequestV1, StandingMandateStoreV1,
    StandingResolverConfigV1, resolve_standing,
};
use ag_campaign::governed::{
    CurrentStandingResolutionV2, ExternalBoundaryErrorV1, StandingResolutionRequestV1,
    StandingResolverV1,
};
use ag_protocol::strict_json_from_slice;

use crate::protocol::bounded_reason;

/// Loads and validates the root-owned standing mandate store.
///
/// Used both by the resolver fixture (per resolution call) and by
/// [`crate::adjudicate`] as a fail-closed pre-check: an unreadable or
/// malformed store is a daemon-internal failure surfaced before any
/// adjudication state exists, never a decision.
///
/// # Errors
///
/// Returns a bounded human-readable reason for any I/O, strict-decoding, or
/// store-validity failure.
pub fn load_standing_store(path: &Path) -> Result<StandingMandateStoreV1, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| bounded_reason(format!("cannot read standing mandate store: {error}")))?;
    let store: StandingMandateStoreV1 = strict_json_from_slice(&bytes).map_err(|error| {
        bounded_reason(format!(
            "standing mandate store is not strict canonical JSON: {error}"
        ))
    })?;
    store
        .validate()
        .map_err(|error| bounded_reason(format!("standing mandate store is invalid: {error}")))?;
    Ok(store)
}

/// The daemon's in-process standing boundary over the mandate store file.
pub struct StandingStoreResolverV1 {
    store_path: PathBuf,
    config: StandingResolverConfigV1,
}

impl StandingStoreResolverV1 {
    /// Binds the resolver to one mandate store path and one exact resolver
    /// identity/answer-lease configuration.
    #[must_use]
    pub fn new(store_path: PathBuf, config: StandingResolverConfigV1) -> Self {
        Self { store_path, config }
    }
}

impl StandingResolverV1 for StandingStoreResolverV1 {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        let store = load_standing_store(&self.store_path).map_err(|reason| {
            ExternalBoundaryErrorV1::Unavailable {
                code: format!("standing-store:{reason}"),
            }
        })?;
        let authority_request = StandingAuthorityRequestV1 {
            schema: STANDING_AUTHORITY_REQUEST_SCHEMA_V1.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            now_unix_ms: request.now_unix_ms,
        };
        resolve_standing(&store, &authority_request, &self.config).map_err(|error| {
            ExternalBoundaryErrorV1::Unavailable {
                code: bounded_reason(format!("standing-authority:{error}")),
            }
        })
    }
}
