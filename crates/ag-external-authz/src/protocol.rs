//! Wire contract types for the external-authorization socket protocol.
//!
//! The request schema `ag.external-authorization-request:v1` and the response
//! schemas `ag.external-authorization:v1` /
//! `ag.external-authorization-error:v1` are a fixed contract mirrored exactly
//! by the Codex-side client. All types use `deny_unknown_fields` and are
//! decoded through [`ag_protocol::strict_json_from_slice`], so duplicate keys,
//! unknown fields, floats, and non-canonical digests are rejected before any
//! adjudication state exists.

use ag_primitives::Digest;
use serde::{Deserialize, Serialize};

/// Exact request schema.
pub const REQUEST_SCHEMA_V1: &str = "ag.external-authorization-request:v1";
/// Exact decision-response schema.
pub const RESPONSE_SCHEMA_V1: &str = "ag.external-authorization:v1";
/// Exact non-decision error-response schema.
pub const ERROR_SCHEMA_V1: &str = "ag.external-authorization-error:v1";
/// Exact read-only adjudication lookup request schema.
pub const LOOKUP_REQUEST_SCHEMA_V1: &str = "ag.external-authorization-lookup-request:v1";
/// Exact read-only adjudication lookup response schema.
pub const LOOKUP_RESPONSE_SCHEMA_V1: &str = "ag.external-authorization-lookup:v1";

/// Maximum length of any human-readable reason string on the wire.
pub const MAX_REASON_CHARS: usize = 4000;

/// The admissibility decision AG will consider; anything else is invalid
/// input because AG never rescues a non-Continue admissibility result.
pub const ADMISSIBILITY_DECISION_CONTINUE: &str = "continue";

/// The closed external-occurrence stage vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceStageV1 {
    /// A generic tool proposal.
    GenericToolProposal,
    /// A prepared `apply_patch` invocation.
    PreparedApplyPatch,
    /// A prepared MCP tool call.
    PreparedMcpCall,
}

impl OccurrenceStageV1 {
    /// The exact work schema this stage must carry.
    #[must_use]
    pub const fn work_schema(self) -> &'static str {
        match self {
            Self::GenericToolProposal => "codex.generic-tool-proposal/v1",
            Self::PreparedApplyPatch => "codex.prepared-apply-patch/v1",
            Self::PreparedMcpCall => "codex.prepared-mcp-call/v1",
        }
    }
}

/// Occurrence identity and stage of the external action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceDescriptorV1 {
    /// Unique external authorization-occurrence identity (a UUID); the
    /// daemon adjudicates each value at most once.
    pub authorization_occurrence_id: String,
    /// Originating session identity (provenance only).
    pub session_id: String,
    /// Originating thread identity (provenance only).
    pub thread_id: String,
    /// Originating turn identity (provenance only).
    pub turn_id: String,
    /// Originating call identity (provenance only).
    pub call_id: String,
    /// Exact occurrence stage; must agree with `action.work_schema`.
    pub stage: OccurrenceStageV1,
}

/// Digest-bound exact action under adjudication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDescriptorV1 {
    /// Exact typed work schema; must agree with `occurrence.stage`.
    pub work_schema: String,
    /// Canonical JSON of the exact action. The daemon hashes these bytes
    /// verbatim; it never re-canonicalizes.
    pub canonical_json: String,
    /// Client-computed SHA-256 of `canonical_json`; recomputed and compared
    /// by the daemon, mismatch is invalid input, not a refusal.
    pub action_digest: Digest,
}

/// One declarative-admissibility evidence citation (opaque to AG).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceUsedV1 {
    /// Exact requirement identity.
    pub requirement_id: String,
    /// Exact fact identity.
    pub fact_id: String,
    /// Exact evidence receipt digest.
    pub receipt_id: Digest,
    /// Exact qualifier identity.
    pub qualifier_id: String,
    /// Exact qualifier revision.
    pub qualifier_revision: String,
}

/// The declarative-admissibility result the observation basis binds to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissibilityDescriptorV1 {
    /// Exact admissibility profile identity.
    pub profile_id: String,
    /// Exact admissibility profile revision.
    pub profile_revision: String,
    /// Must be exactly `continue`; any other value is invalid input.
    pub decision: String,
    /// Client-side evaluation time (provenance only).
    pub evaluation_time_unix_ms: u64,
    /// Evidence citations backing the admissibility result (opaque to AG).
    pub evidence_used: Vec<EvidenceUsedV1>,
    /// Digest of the complete admissibility receipt; becomes the opaque
    /// observation-basis identity AG pins.
    pub receipt_digest: Digest,
}

/// The exact external-authorization request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthorizationRequestV1 {
    /// Exact schema.
    pub schema: String,
    /// Client request identity (a UUID), echoed on every response.
    pub request_id: String,
    /// Occurrence identity and stage.
    pub occurrence: OccurrenceDescriptorV1,
    /// Digest-bound exact action.
    pub action: ActionDescriptorV1,
    /// Exact governed subject digest.
    pub subject_digest: Digest,
    /// Exact governed scope digest.
    pub scope_digest: Digest,
    /// Declarative admissibility result.
    pub admissibility: AdmissibilityDescriptorV1,
}

/// Exact read-only lookup for one previously submitted authorization request.
/// `request_digest` is SHA-256 over the serialized request bytes under daemon
/// custody; it prevents a caller from reconciling a substituted request that
/// reuses only selected correlation fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthorizationLookupRequestV1 {
    /// Exact schema.
    pub schema: String,
    /// Fresh lookup correlation identity (a UUID).
    pub lookup_request_id: String,
    /// Original authorization request identity.
    pub authorization_request_id: String,
    /// Exact authorization occurrence identity.
    pub authorization_occurrence_id: String,
    /// SHA-256 of the complete serialized original request.
    pub request_digest: Digest,
}

/// The closed wire decision vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDecisionV1 {
    /// AG durably spent the one-use authorization.
    Authorized,
    /// AG refused; no authority exists.
    Refused,
    /// A genuinely unresolved operational state; no decision exists.
    Indeterminate,
}

/// Authorization refs present only when the decision is `authorized`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationOutcomeV1 {
    /// Exact AG campaign identity.
    pub campaign_id: String,
    /// Exact AG occurrence identity.
    pub ag_occurrence_id: String,
    /// Exact AG authorization identity.
    pub authorization_ref: String,
    /// Exact AG spend identity.
    pub spend_ref: String,
    /// Exact AG issuance identity.
    pub issuance_ref: String,
    /// Exact standing resolution consumed at spend.
    pub standing_resolution_ref: String,
    /// Content-derived mandate identity.
    pub mandate_ref: String,
    /// Exclusive standing-answer deadline consumed at spend.
    pub standing_expires_at_unix_ms: u64,
}

/// Refusal detail present only when the decision is `refused`. The code is
/// the AG refusal/error code name, preserving AG's real vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalDetailV1 {
    /// Stable refusal code.
    pub code: String,
    /// Bounded human-readable reason.
    pub reason: String,
}

/// Indeterminate detail present only when the decision is `indeterminate`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndeterminateDetailV1 {
    /// Typed unresolved-condition kinds.
    pub kinds: Vec<String>,
    /// Bounded human-readable reason.
    pub reason: String,
}

/// The exact external-authorization decision response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthorizationResponseV1 {
    /// Exact schema.
    pub schema: String,
    /// Echoed request identity.
    pub request_id: String,
    /// Echoed `authorization_occurrence_id`.
    pub occurrence_id: String,
    /// Echoed action digest.
    pub action_digest: String,
    /// Echoed admissibility receipt digest.
    pub admissibility_receipt_digest: String,
    /// The AG decision.
    pub decision: ExternalDecisionV1,
    /// Daemon-side evaluation time.
    pub evaluated_at_unix_ms: u64,
    /// Authorization refs; present only for `authorized`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<AuthorizationOutcomeV1>,
    /// Refusal detail; present only for `refused`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<RefusalDetailV1>,
    /// Indeterminate detail; present only for `indeterminate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<IndeterminateDetailV1>,
}

/// Closed read-only adjudication lookup status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupStatusV1 {
    /// No daemon-custodied request exists for the exact occurrence.
    NotFound,
    /// Request custody exists but no durable decision is available.
    OutcomeUnknown,
    /// A durable decision exists and is returned exactly.
    Resolved,
}

/// Exact read-only adjudication lookup response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthorizationLookupResponseV1 {
    /// Exact schema.
    pub schema: String,
    /// Echoed lookup correlation identity.
    pub lookup_request_id: String,
    /// Echoed original authorization request identity.
    pub authorization_request_id: String,
    /// Echoed occurrence identity.
    pub authorization_occurrence_id: String,
    /// Echoed complete-request digest.
    pub request_digest: Digest,
    /// Read-only resolution state.
    pub status: LookupStatusV1,
    /// Original durable decision, present exactly when `status` is `resolved`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ExternalAuthorizationResponseV1>,
}

/// The closed non-decision error kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKindV1 {
    /// The request violated the wire contract (malformed frame, unknown
    /// schema/fields, action-digest mismatch, non-`continue` admissibility,
    /// stage/work-schema inconsistency). No decision was recorded.
    InvalidRequest,
    /// A daemon-internal failure (state-dir I/O, unreadable/malformed
    /// standing store, unexpected engine error). No decision was recorded.
    Infrastructure,
}

/// A non-decision error response: invalid input or daemon-internal failure.
/// This is never a refusal and never an adjudication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthorizationErrorV1 {
    /// Exact schema.
    pub schema: String,
    /// Echoed request identity when the request decoded far enough to have
    /// one; otherwise absent.
    pub request_id: Option<String>,
    /// Closed error kind.
    pub kind: ErrorKindV1,
    /// Bounded human-readable reason.
    pub reason: String,
}

/// Bounds one reason string to [`MAX_REASON_CHARS`] on a char boundary.
#[must_use]
pub fn bounded_reason(reason: impl Into<String>) -> String {
    let reason = reason.into();
    if reason.chars().count() <= MAX_REASON_CHARS {
        return reason;
    }
    reason.chars().take(MAX_REASON_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_and_work_schema_agree_on_the_closed_vocabulary() {
        assert_eq!(
            OccurrenceStageV1::GenericToolProposal.work_schema(),
            "codex.generic-tool-proposal/v1"
        );
        assert_eq!(
            OccurrenceStageV1::PreparedApplyPatch.work_schema(),
            "codex.prepared-apply-patch/v1"
        );
        assert_eq!(
            OccurrenceStageV1::PreparedMcpCall.work_schema(),
            "codex.prepared-mcp-call/v1"
        );
        assert_eq!(
            serde_json::to_value(OccurrenceStageV1::PreparedApplyPatch).unwrap(),
            serde_json::json!("prepared_apply_patch")
        );
    }

    #[test]
    fn bounded_reason_truncates_on_a_char_boundary() {
        let short = "short reason";
        assert_eq!(bounded_reason(short), short);
        let long = "é".repeat(MAX_REASON_CHARS + 10);
        let bounded = bounded_reason(long);
        assert_eq!(bounded.chars().count(), MAX_REASON_CHARS);
    }

    #[test]
    fn decision_and_error_wire_names_are_stable() {
        assert_eq!(
            serde_json::to_value(ExternalDecisionV1::Indeterminate).unwrap(),
            serde_json::json!("indeterminate")
        );
        assert_eq!(
            serde_json::to_value(ErrorKindV1::InvalidRequest).unwrap(),
            serde_json::json!("invalid_request")
        );
        assert_eq!(
            serde_json::to_value(LookupStatusV1::OutcomeUnknown).unwrap(),
            serde_json::json!("outcome_unknown")
        );
    }
}
