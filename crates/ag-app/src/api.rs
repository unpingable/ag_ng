//! Strict local API message families.

use std::fmt;

use ag_effect::{
    CanonicalEffectProposalV1, ProposalIntentV1, ProposalStateV1, RatificationV1,
    ReconciliationEvidenceV1, ReconciliationRecordV1,
};
use ag_primitives::{Digest, InferenceCapabilityId, PrincipalId};
use ag_session::{ProviderCapabilityV1, ProviderRequestCustodyV1, SessionId};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::rpc_auth::{SignedRequestEnvelopeV1, SignedServerChallengeV1};

/// Exact direct effect-plane record projection schema.
pub const EFFECT_RECORD_SCHEMA_V1: &str = "ag.effect-record/v1";

/// Exact opaque bytes encoded as canonical padded RFC 4648 base64 on JSON wires.
///
/// This type deliberately does not accept JSON integer arrays, unpadded input,
/// whitespace, or alternate alphabets. Re-encoding after decoding must produce
/// the byte-for-byte input string.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OpaqueBytesV1(Vec<u8>);

impl OpaqueBytesV1 {
    /// Wrap exact bytes for canonical wire encoding.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the exact decoded bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Return the exact decoded byte count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the exact byte string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper and return its exact decoded bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for OpaqueBytesV1 {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for OpaqueBytesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueBytesV1")
            .field("byte_length", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaqueBytesV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for OpaqueBytesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        if STANDARD.encode(&decoded) != encoded {
            return Err(serde::de::Error::custom("non-canonical base64"));
        }
        Ok(Self(decoded))
    }
}

/// Liveness/readiness response shared by all daemons.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthV1 {
    /// Wire schema.
    pub schema: String,
    /// Exact daemon role.
    pub service: String,
    /// Build/version identity.
    pub build: String,
    /// True only after store fencing and socket setup succeeded.
    pub ready: bool,
    /// Current quiescence state.
    pub quiesced: bool,
}

/// Requests accepted by `agd`'s unprivileged control socket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgdRequestV1 {
    /// Read-only health.
    Health,
    /// Submit an admitted proposal intent for forwarding to the broker.
    SubmitProposal {
        /// Untrusted intent. `agd` cannot canonicalize this into authority.
        intent: Box<ProposalIntentV1>,
    },
}

/// Responses from the governor control plane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgdResponseV1 {
    /// Health response.
    Health {
        /// Exact governor health record.
        health: HealthV1,
    },
    /// Broker correlation for a forwarded intent.
    ProposalSubmitted {
        /// Broker-generated correlation identifier.
        proposal_id: String,
    },
    /// Broker returned an operationally indeterminate envelope.
    Indeterminate {
        /// Exact operational envelope.
        envelope: Digest,
    },
    /// Broker returned semantic refusal evidence.
    Refused {
        /// Exact refusal record.
        refusal: Digest,
    },
}

/// Requests accepted only on `ag-effectd`'s governor-facing proposal socket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectProposalRequestV1 {
    /// Read-only health.
    Health,
    /// Submit the original end-to-end authenticated intent plus governed
    /// artifact references. Target observations are absent.
    SubmitAuthenticatedIntent {
        /// Exact original proposer-to-governor exchange. Effectd independently
        /// verifies both signatures and reconstructs the proposer chain.
        ingress: Box<ProposalIngressProofV1>,
        /// Exact admitted artifact bytes transferred into effectd custody.
        /// The initial vertical slice bounds these to one local protocol frame.
        artifacts: Vec<ArtifactTransferV1>,
    },
}

/// Original proposer authentication forwarded intact across the governor.
///
/// The outer effectd RPC separately authenticates `agd`; this object proves
/// who signed the exact inner proposal request addressed to that governor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalIngressProofV1 {
    /// Governor challenge signed for the enrolled proposer.
    pub server_challenge: SignedServerChallengeV1,
    /// Exact proposer-signed request, including its strict intent body.
    pub signed_request: Box<SignedRequestEnvelopeV1<AgdRequestV1>>,
}

/// One bounded content-addressed artifact transfer into effectd custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTransferV1 {
    /// Exact content identity.
    pub digest: Digest,
    /// Exact decoded byte length.
    pub byte_length: u64,
    /// Canonical RFC 4648 base64 with padding.
    pub content_base64: String,
}

/// Proposal-socket responses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectProposalResponseV1 {
    /// Health response.
    Health {
        /// Exact effect-broker health record.
        health: HealthV1,
    },
    /// Broker compiled and persisted its own canonical bytes.
    Canonicalized {
        /// Broker proposal ID.
        proposal_id: String,
        /// Digest of broker-owned canonical bytes.
        proposal_digest: Digest,
    },
    /// Evaluation failed operationally; this is not a semantic refusal.
    Indeterminate {
        /// Operational evidence that is neither refusal nor admission.
        envelope: Digest,
    },
    /// Native judgment refused the proposal.
    Refused {
        /// Exact semantic refusal identity.
        refusal: Digest,
    },
}

/// Requests accepted on the broker admin/inspection socket.
///
/// Read-only inspection and ratification both terminate here. `agd` has no
/// projection method capable of answering these requests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectAdminRequestV1 {
    /// Read-only health.
    Health,
    /// Display broker-owned canonical bytes by exact digest.
    InspectProposal {
        /// Exact broker-owned proposal digest.
        proposal: Digest,
    },
    /// Read the full broker-owned authority and lifecycle custody projection.
    InspectRecord {
        /// Exact broker-owned proposal digest.
        proposal: Digest,
    },
    /// List bounded broker-owned proposal summaries.
    ListProposals {
        /// Explicit result bound, further clamped by the broker.
        limit: u32,
    },
    /// Ratify exactly the bytes returned by `InspectProposal`.
    Ratify {
        /// Exact canonical digest.
        proposal: Digest,
        /// Broker-issued display challenge.
        challenge: String,
    },
    /// Derive complete reconciliation evidence from broker custody and a
    /// fresh canonical-target observation. This is read-only and does not
    /// ratify or submit the returned evidence.
    DraftReconciliation {
        /// Exact canonical proposal in `reconciliation_required` state.
        proposal: Digest,
    },
    /// Record operator-authenticated reconciliation.
    Reconcile {
        /// Full canonical evidence. Effectd verifies every broker-custodied
        /// binding and independently reproduces the target observation.
        evidence: Box<ReconciliationEvidenceV1>,
    },
}

/// One broker-owned proposal summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalSummaryV1 {
    /// Broker proposal ID.
    pub proposal_id: String,
    /// Canonical digest.
    pub proposal_digest: Digest,
    /// Durable state name.
    pub state: String,
}

/// Strict read-only projection of one complete broker-owned proposal record.
///
/// This mirrors the bounded durable custody needed for operational inspection
/// without exposing store events, internal revisions, or a generic query
/// surface. Effectd validates the underlying record before constructing it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecordV1 {
    /// Exact projection schema.
    pub schema: String,
    /// Exact broker-owned canonical proposal.
    pub canonical: CanonicalEffectProposalV1,
    /// Durable burn-before-effect lifecycle.
    pub state: ProposalStateV1,
    /// Exact accepted authority record, when burned.
    pub authorization: Option<RatificationV1>,
    /// Composite terminal execution or reconciliation receipt.
    pub terminal_receipt: Option<Digest>,
    /// Exact bounded step receipts in execution order.
    pub step_receipts: Vec<Digest>,
    /// Exact one-shot execution attempt, once begun.
    pub execution_attempt: Option<Digest>,
    /// Full broker-owned reconciliation record, once committed.
    pub reconciliation: Option<ReconciliationRecordV1>,
}

/// Responses on the direct effect-plane admin/inspection socket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectAdminResponseV1 {
    /// Health response.
    Health {
        /// Exact effect-broker health record.
        health: HealthV1,
    },
    /// Exact broker-owned object plus one-time display challenge.
    Proposal {
        /// Canonical object.
        proposal: Box<CanonicalEffectProposalV1>,
        /// One-time challenge bound to authenticated peer and digest.
        challenge: String,
    },
    /// Complete validated broker-owned authority/lifecycle projection.
    Record {
        /// Strict typed record projection.
        record: Box<EffectRecordV1>,
    },
    /// Bounded summaries.
    Proposals {
        /// Bounded deterministic broker-owned summaries.
        proposals: Vec<ProposalSummaryV1>,
    },
    /// Authority was durably burned and execution reached a terminal result.
    ExecutionReceipt {
        /// Exact terminal receipt.
        receipt: Digest,
        /// Stable terminal state.
        terminal_state: String,
    },
    /// Read-only broker-derived reconciliation evidence draft.
    ReconciliationDraft {
        /// Full evidence assembled from durable custody and fresh observation.
        evidence: Box<ReconciliationEvidenceV1>,
    },
    /// Reconciliation record was committed.
    Reconciled {
        /// Digest of the full broker-owned, operator-authenticated record.
        receipt: Digest,
    },
}

/// Requests accepted by the credential-isolated provider daemon.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderRequestV1 {
    /// Read-only health.
    Health {},
    /// Register one capability and its stable worker-principal binding. This
    /// method is accepted only through the signed `agd` proxy.
    RegisterCapability {
        /// Capability definition.
        capability: Box<ProviderCapabilityV1>,
        /// Stable worker principal resolved by the governor launcher.
        worker_principal: PrincipalId,
    },
    /// Spend a peer-bound capability on exact credential-free request bytes.
    Infer {
        /// Session-scoped capability.
        capability: Box<ProviderCapabilityV1>,
        /// Exact request custody record already committed by `agd`.
        request: Box<ProviderRequestCustodyV1>,
        /// Exact credential-free request bytes whose digest is in custody.
        request_bytes: OpaqueBytesV1,
    },
    /// Fetch exact completed provider custody. Fetch does not acknowledge
    /// governor durability and is therefore safely repeatable.
    FetchInference {
        /// Provider-owned deterministic dispatch identity.
        dispatch: Digest,
    },
    /// Confirm that `agd` durably committed the exact fetched bytes.
    AcknowledgeInferenceCustody {
        /// Provider-owned deterministic dispatch identity.
        dispatch: Digest,
        /// Digest of the exact complete event-stream bytes committed by `agd`.
        exact_event_stream: Digest,
        /// Governor custody receipt binding its durable local commit.
        governor_custody_record: Digest,
    },
    /// Burn all capability state for a terminal session.
    TerminateSession {
        /// Exact terminal session whose grants must be burned.
        session: SessionId,
    },
}

/// Provider daemon responses for crash-safe two-phase governor custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderResponseV1 {
    /// Health response.
    Health {
        /// Exact provider-broker health record.
        health: HealthV1,
    },
    /// Capability and dynamic peer binding were durably registered.
    CapabilityRegistered {
        /// Exact capability identity.
        capability: InferenceCapabilityId,
    },
    /// Dispatch completed and exact bytes are durably fetchable.
    InferenceAvailable {
        /// Provider-owned deterministic dispatch identity.
        dispatch: Digest,
        /// Digest of the exact complete event-stream bytes.
        exact_event_stream: Digest,
        /// Exact complete event-stream byte count before base64 wire encoding.
        byte_length: u64,
        /// True only for a protocol terminal event.
        protocol_terminal: bool,
    },
    /// Complete raw provider event stream retained pending explicit custody ack.
    Inference {
        /// Provider-owned deterministic dispatch identity.
        dispatch: Digest,
        /// Digest of the exact complete event-stream bytes.
        exact_event_stream: Digest,
        /// Exact complete event-stream bytes, canonically base64 encoded by
        /// [`OpaqueBytesV1`] on the JSON wire.
        event_stream: OpaqueBytesV1,
        /// Sanitized response headers.
        sanitized_headers: Vec<(String, String)>,
        /// True only for a protocol terminal event.
        protocol_terminal: bool,
    },
    /// Exact governor custody acknowledgment became durable.
    InferenceCustodyAcknowledged {
        /// Provider-owned deterministic dispatch identity.
        dispatch: Digest,
        /// Provider receipt binding the exact governor custody record.
        receipt: Digest,
    },
    /// Session grants were burned.
    SessionTerminated {
        /// Exact durable capability-burn receipt.
        receipt: Digest,
    },
}

/// Error codes are stable and messages carry no authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCodeV1 {
    /// Peer failed configured identity checks.
    Unauthenticated,
    /// Peer identity is valid but lacks this socket/method role.
    Unauthorized,
    /// Request bytes/schema are invalid.
    InvalidRequest,
    /// Referenced object does not exist.
    NotFound,
    /// Preconditions or lifecycle state conflict.
    Conflict,
    /// Daemon is quiesced for a coherent backup cut.
    Quiesced,
    /// Evaluation reached no semantic answer.
    Indeterminate,
    /// Requested authority family is deliberately unsupported.
    UnsupportedAuthorityFamily,
    /// Internal error with a correlation identifier.
    Internal,
}

/// Every API response is explicitly success or error.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApiResultV1<T> {
    /// Successful method response.
    Ok {
        /// Method-specific successful response.
        response: T,
    },
    /// Failure. The message is diagnostic and never evidence.
    Error {
        /// Stable machine code.
        code: ApiErrorCodeV1,
        /// Safe diagnostic.
        message: String,
        /// Correlation identity for local audit lookup.
        correlation: String,
    },
}

impl<T> ApiResultV1<T> {
    /// Creates a diagnostic error response.
    #[must_use]
    pub fn error(code: ApiErrorCodeV1, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
            correlation: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_bytes_use_only_canonical_padded_base64() {
        let bytes = OpaqueBytesV1::new(vec![0, 255]);
        assert_eq!(serde_json::to_string(&bytes).unwrap(), r#""AP8=""#);
        assert_eq!(
            serde_json::from_str::<OpaqueBytesV1>(r#""AP8=""#)
                .unwrap()
                .as_slice(),
            &[0, 255]
        );

        assert!(serde_json::from_str::<OpaqueBytesV1>(r#""AP8""#).is_err());
        assert!(serde_json::from_str::<OpaqueBytesV1>(r#""AP8==""#).is_err());
        assert!(serde_json::from_str::<OpaqueBytesV1>("[0,255]").is_err());
    }

    #[test]
    fn provider_unit_requests_reject_extra_fields() {
        assert!(
            serde_json::from_str::<ProviderRequestV1>(
                r#"{"method":"health","reserved_cost_microunits":0}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn effect_inspection_requests_are_closed_and_digest_only() {
        let proposal = Digest::hash_bytes(b"proposal");
        let record = format!(r#"{{"method":"inspect_record","proposal":"{proposal}"}}"#);
        assert!(matches!(
            serde_json::from_str::<EffectAdminRequestV1>(&record).unwrap(),
            EffectAdminRequestV1::InspectRecord { proposal: parsed } if parsed == proposal
        ));
        assert!(
            serde_json::from_str::<EffectAdminRequestV1>(&format!(
                r#"{{"method":"inspect_record","proposal":"{proposal}","query":"events"}}"#
            ))
            .is_err()
        );
        assert!(
            serde_json::from_str::<EffectAdminRequestV1>(&format!(
                r#"{{"method":"draft_reconciliation","proposal":"{proposal}","classification":"applied"}}"#
            ))
            .is_err()
        );
    }
}
