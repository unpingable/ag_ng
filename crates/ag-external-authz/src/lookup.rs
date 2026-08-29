//! Read-only reconciliation of one exact external authorization request.
//!
//! Lookup never drives the campaign engine, spends authority, creates state,
//! or repairs an incomplete record. It reports only `not_found`,
//! `outcome_unknown`, or the exact durable decision already under custody.

use ag_primitives::Digest;
use uuid::Uuid;

use crate::adjudicate::DaemonConfigV1;
use crate::custody::{load_outcome, load_request, request_digest};
use crate::protocol::{
    ERROR_SCHEMA_V1, ErrorKindV1, ExternalAuthorizationErrorV1,
    ExternalAuthorizationLookupRequestV1, ExternalAuthorizationLookupResponseV1,
    ExternalAuthorizationRequestV1, ExternalAuthorizationResponseV1, LOOKUP_REQUEST_SCHEMA_V1,
    LOOKUP_RESPONSE_SCHEMA_V1, LookupStatusV1, RESPONSE_SCHEMA_V1, bounded_reason,
};

/// Outcome of one lookup frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LookupOutcomeV1 {
    /// A read-only lookup result.
    Lookup(ExternalAuthorizationLookupResponseV1),
    /// Invalid query or custody/infrastructure failure; not an adjudication.
    Rejected(ExternalAuthorizationErrorV1),
}

fn reject(
    kind: ErrorKindV1,
    request_id: Option<String>,
    reason: impl Into<String>,
) -> LookupOutcomeV1 {
    LookupOutcomeV1::Rejected(ExternalAuthorizationErrorV1 {
        schema: ERROR_SCHEMA_V1.to_owned(),
        request_id,
        kind,
        reason: bounded_reason(reason),
    })
}

fn response(
    request: &ExternalAuthorizationLookupRequestV1,
    status: LookupStatusV1,
    outcome: Option<ExternalAuthorizationResponseV1>,
) -> LookupOutcomeV1 {
    LookupOutcomeV1::Lookup(ExternalAuthorizationLookupResponseV1 {
        schema: LOOKUP_RESPONSE_SCHEMA_V1.to_owned(),
        lookup_request_id: request.lookup_request_id.clone(),
        authorization_request_id: request.authorization_request_id.clone(),
        authorization_occurrence_id: request.authorization_occurrence_id.clone(),
        request_digest: request.request_digest.clone(),
        status,
        outcome,
    })
}

fn validate_lookup(request: &ExternalAuthorizationLookupRequestV1) -> Result<Uuid, String> {
    if request.schema != LOOKUP_REQUEST_SCHEMA_V1 {
        return Err(format!("unsupported lookup schema {}", request.schema));
    }
    if Uuid::parse_str(&request.lookup_request_id).is_err() {
        return Err("lookup_request_id must be a UUID".to_owned());
    }
    if Uuid::parse_str(&request.authorization_request_id).is_err() {
        return Err("authorization_request_id must be a UUID".to_owned());
    }
    Uuid::parse_str(&request.authorization_occurrence_id)
        .map_err(|_| "authorization_occurrence_id must be a UUID".to_owned())
}

fn request_matches(
    stored: &ExternalAuthorizationRequestV1,
    query: &ExternalAuthorizationLookupRequestV1,
) -> Result<bool, String> {
    Ok(stored.request_id == query.authorization_request_id
        && stored.occurrence.authorization_occurrence_id == query.authorization_occurrence_id
        && request_digest(stored)? == query.request_digest)
}

fn outcome_matches(
    request: &ExternalAuthorizationRequestV1,
    outcome: &ExternalAuthorizationResponseV1,
) -> bool {
    if outcome.schema != RESPONSE_SCHEMA_V1
        || outcome.request_id != request.request_id
        || outcome.occurrence_id != request.occurrence.authorization_occurrence_id
        || outcome.action_digest != request.action.action_digest.as_str()
        || outcome.admissibility_receipt_digest != request.admissibility.receipt_digest.as_str()
    {
        return false;
    }
    match outcome.decision {
        crate::protocol::ExternalDecisionV1::Authorized => {
            outcome.authorization.is_some()
                && outcome.refusal.is_none()
                && outcome.failure.is_none()
        }
        crate::protocol::ExternalDecisionV1::Refused => {
            outcome.authorization.is_none()
                && outcome.refusal.is_some()
                && outcome.failure.is_none()
        }
        crate::protocol::ExternalDecisionV1::Indeterminate => {
            outcome.authorization.is_none()
                && outcome.refusal.is_none()
                && outcome.failure.is_some()
        }
    }
}

/// Resolves one exact prior request from durable daemon custody.
///
/// This function is strictly read-only. In particular, incomplete state is
/// returned as `OutcomeUnknown`, never repaired and never interpreted as a
/// refusal or permission to submit another occurrence.
#[must_use]
pub fn lookup(
    config: &DaemonConfigV1,
    request: &ExternalAuthorizationLookupRequestV1,
) -> LookupOutcomeV1 {
    let occurrence = match validate_lookup(request) {
        Ok(occurrence) => occurrence,
        Err(reason) => {
            return reject(
                ErrorKindV1::InvalidRequest,
                Some(request.lookup_request_id.clone()),
                reason,
            );
        }
    };
    let occurrence_dir = config.state_dir.join(occurrence.hyphenated().to_string());
    match std::fs::symlink_metadata(&occurrence_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return response(request, LookupStatusV1::NotFound, None);
        }
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return reject(
                ErrorKindV1::Infrastructure,
                Some(request.lookup_request_id.clone()),
                "authorization occurrence custody path is not a real directory",
            );
        }
        Err(error) => {
            return reject(
                ErrorKindV1::Infrastructure,
                Some(request.lookup_request_id.clone()),
                format!("cannot inspect authorization occurrence custody: {error}"),
            );
        }
    }
    let stored_request = match load_request(&occurrence_dir) {
        Ok(Some(stored)) => stored,
        Ok(None) => return response(request, LookupStatusV1::OutcomeUnknown, None),
        Err(reason) => {
            return reject(
                ErrorKindV1::Infrastructure,
                Some(request.lookup_request_id.clone()),
                reason,
            );
        }
    };
    match request_matches(&stored_request, request) {
        Ok(true) => {}
        Ok(false) => {
            return reject(
                ErrorKindV1::InvalidRequest,
                Some(request.lookup_request_id.clone()),
                "lookup does not match the exact custodied authorization request",
            );
        }
        Err(reason) => {
            return reject(
                ErrorKindV1::Infrastructure,
                Some(request.lookup_request_id.clone()),
                reason,
            );
        }
    }
    let outcome = match load_outcome(&occurrence_dir) {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return response(request, LookupStatusV1::OutcomeUnknown, None),
        Err(reason) => {
            return reject(
                ErrorKindV1::Infrastructure,
                Some(request.lookup_request_id.clone()),
                reason,
            );
        }
    };
    if !outcome_matches(&stored_request, &outcome) {
        return reject(
            ErrorKindV1::Infrastructure,
            Some(request.lookup_request_id.clone()),
            "durable authorization outcome does not match its custodied request",
        );
    }
    response(request, LookupStatusV1::Resolved, Some(outcome))
}

/// Builds the exact complete-request digest used by clients and tests.
///
/// # Errors
///
/// Returns an error only if the closed request cannot be serialized.
pub fn exact_request_digest(request: &ExternalAuthorizationRequestV1) -> Result<Digest, String> {
    request_digest(request)
}
