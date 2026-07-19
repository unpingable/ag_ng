//! Strict local API message families.

use std::{collections::BTreeMap, fmt};

use ag_effect::{
    CanonicalEffectProposalV1, ManagedPointerCandidateRatificationV1,
    ManagedPointerPromotionRefusalV1, PreparedManagedPointerCandidateV1, ProposalIntentV1,
    ProposalStateV1, RatificationV1, ReconciliationEvidenceV1, ReconciliationRecordV1, TargetId,
};
use ag_primitives::{
    Digest, InferenceCapabilityId, JcsDocument, JcsError, LifecycleNonce, PrincipalChainV1,
    PrincipalId, WorkerSessionPrincipalV1,
};
use ag_session::{
    ProviderCapabilityV1, ProviderRequestCustodyV1, SessionId, WorkerSessionRecordV1,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::managed_pointer::ManagedPointerActivationReceiptV1;
use crate::rpc_auth::{RpcPeerKeyPolicyV1, SignedRequestEnvelopeV1, SignedServerChallengeV1};

/// Exact direct effect-plane record projection schema.
pub const EFFECT_RECORD_SCHEMA_V3: &str = "ag.effect-record/v3";

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
    /// Launch one exact reviewed fixed-argv worker profile.
    LaunchWorker {
        /// Root-reviewed profile identifier; never an executable or argv.
        profile_id: String,
    },
    /// Inspect one durable worker-session record.
    InspectWorker {
        /// Non-reusable session identity.
        session_id: SessionId,
    },
    /// Permanently fence and terminate one worker principal.
    CancelWorker {
        /// Non-reusable session identity.
        session_id: SessionId,
        /// Exact operator/service cancellation reason evidence.
        reason: Digest,
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
        /// Exact broker-owned canonical proposal identity.
        proposal_digest: Digest,
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
    /// A reviewed worker profile was durably launched.
    WorkerLaunched {
        /// Non-reusable session identity.
        session_id: SessionId,
        /// Exact minted worker-session principal.
        principal: PrincipalId,
    },
    /// Direct durable worker-session status.
    WorkerStatus {
        /// Exact governor-owned worker record.
        record: Box<WorkerSessionRecordV1>,
    },
    /// Worker ingress is durably fenced and cleanup has begun.
    WorkerCancelled {
        /// Exact cancelled session.
        session_id: SessionId,
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
        /// Exact governed source accepted by the governor. Effectd verifies
        /// the source variant and reconstructs the proposer chain itself.
        ingress: Box<GovernedProposalIngressV1>,
        /// Exact admitted artifact bytes transferred into effectd custody.
        /// The initial vertical slice bounds these to one local protocol frame.
        /// Worker ingress sends this vector empty: its one candidate artifact
        /// is derived from the independently authenticated proof so candidate
        /// bytes occur only once on the governor-to-broker wire.
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

/// Candidate-only request emitted by one live worker session.
///
/// Authority context, session identity, workspace identity, effects,
/// judgments, receipts, and principal chains are deliberately absent. The
/// governor resolves those exclusively from reviewed durable launch state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerCandidateRequestV1 {
    /// Submit one bounded candidate byte string.
    Submit {
        /// Non-transferable nonce bound to this worker lifecycle.
        candidate_nonce: LifecycleNonce,
        /// Closed semantic type interpreted by reviewed governor policy.
        semantic_type: String,
        /// Exact candidate bytes; these are not canonical effect bytes.
        content: OpaqueBytesV1,
    },
}

/// Public, credential-free bootstrap delivered through one admitted worker
/// descriptor. The PKCS#8 candidate-ingress key is carried on a separate
/// read-only descriptor and is never serialized into this object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCandidateBootstrapV1 {
    /// Exact bootstrap schema.
    pub schema: String,
    /// Principal represented by the ephemeral candidate-ingress key.
    pub principal: Digest,
    /// Exact ephemeral key identifier.
    pub key_id: crate::rpc_auth::RpcKeyIdV1,
    /// Lifecycle nonce required in the candidate-only request.
    pub candidate_nonce: LifecycleNonce,
    /// Reviewed candidate semantic type for this fixed launch profile.
    pub semantic_type: String,
    /// Exact request identifier fixed by the launcher.
    pub request_id: ag_protocol::RequestId,
    /// Maximum complete signed candidate frame.
    pub maximum_frame_bytes: u32,
    /// Maximum decoded candidate bytes bound into the principal/session.
    pub maximum_candidate_bytes: u64,
    /// Governor-signed challenge addressed to the ephemeral worker key.
    pub server_challenge: SignedServerChallengeV1,
}

/// Exact compact worker-to-governor proof held as canonical bytes in durable
/// candidate custody and forwarded to the effect broker.
///
/// This is authenticated evidence, never bearer authority. The outer signed
/// effectd request independently authenticates `agd`, and effectd re-verifies
/// the embedded dynamic worker proof before compiling any canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCandidateIngressProofV1 {
    /// Exact governor enrollment policy under which candidate ingress checked
    /// challenge freshness. Effectd requires equality with its configured agd
    /// enrollment before replaying this durable proof.
    pub governor_enrollment: RpcPeerKeyPolicyV1,
    /// Ephemeral public enrollment committed before worker launch.
    pub worker_enrollment: RpcPeerKeyPolicyV1,
    /// Governor challenge addressed to this dynamic worker enrollment.
    pub server_challenge: SignedServerChallengeV1,
    /// Exact worker-signed candidate-only request.
    pub signed_request: Box<SignedRequestEnvelopeV1<WorkerCandidateRequestV1>>,
}

impl WorkerCandidateIngressProofV1 {
    /// Returns the exact JCS bytes which enter immutable candidate custody.
    ///
    /// # Errors
    ///
    /// Returns an error if the strict proof cannot be canonicalized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JcsError> {
        Ok(JcsDocument::canonicalize(self)?.as_bytes().to_vec())
    }

    /// Returns the digest of the exact JCS custody bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the strict proof cannot be canonicalized.
    pub fn digest(&self) -> Result<Digest, JcsError> {
        Digest::from_serializable(self)
    }
}

/// Exact worker source bindings forwarded to the effect broker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCandidateSourceProofV1 {
    /// Full, immutable worker principal minted from reviewed launch state.
    pub worker: WorkerSessionPrincipalV1,
    /// Exact authenticated governor-to-worker lineage.
    pub worker_chain: PrincipalChainV1,
    /// Exact opaque proof whose canonical bytes are held in candidate custody.
    pub ingress_proof: WorkerCandidateIngressProofV1,
    /// Immutable session-spec binding; never a digest of mutable lifecycle state.
    pub session_binding: Digest,
    /// Descriptor-bound proposal-workspace construction identity.
    pub workspace_identity: Digest,
    /// Exact descriptor-bound launch receipt.
    pub launch_receipt: Digest,
    /// Exact governor candidate-custody record.
    pub candidate_custody: Digest,
    /// Trusted time at which complete candidate ingress committed.
    pub accepted_at_unix_ms: u64,
}

/// Computes the exact opaque worker-ingress proof identity held in candidate
/// custody.
///
/// The digest covers only the dynamic enrollment and the complete
/// challenge/request exchange. Lifecycle records bind this value before the
/// candidate can be forwarded; later cleanup does not change it.
///
/// # Errors
///
/// Returns an error if the strict proof values cannot be canonicalized.
pub fn worker_candidate_ingress_proof_digest(
    proof: &WorkerCandidateIngressProofV1,
) -> Result<Digest, JcsError> {
    proof.digest()
}

/// Closed authenticated sources from which effectd may receive an untrusted
/// proposal intent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "ingress_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernedProposalIngressV1 {
    /// Existing statically enrolled proposer-to-governor exchange.
    ExternalSigned {
        /// Exact end-to-end proof containing the untrusted intent.
        proof: Box<ProposalIngressProofV1>,
    },
    /// Candidate from a dynamically minted, bounded worker principal.
    WorkerCandidate {
        /// Intent constructed by `agd` from reviewed policy and durable
        /// candidate custody; it was not supplied by the worker.
        intent: Box<ProposalIntentV1>,
        /// Exact worker proof and governor custody binding.
        source: Box<WorkerCandidateSourceProofV1>,
    },
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
    /// Exact pre-ratification preparation history by promotion target.
    pub prepared_candidates: BTreeMap<TargetId, PreparedManagedPointerCandidateV1>,
    /// Exact candidate-and-basis ratification, once promotion authority burns.
    pub candidate_ratification: Option<ManagedPointerCandidateRatificationV1>,
    /// Typed failed attempts to mint current promotion standing.
    pub promotion_refusals: Vec<ManagedPointerPromotionRefusalV1>,
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
    /// Full durable managed-pointer activation explanation, present only for
    /// a verified successful promotion.
    pub managed_pointer_activation: Option<ManagedPointerActivationReceiptV1>,
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
    fn worker_candidate_wire_cannot_smuggle_authority_context() {
        let valid = r#"{"method":"submit","candidate_nonce":"07070707070707070707070707070707","semantic_type":"managed_file_content","content":"YQ=="}"#;
        assert!(matches!(
            serde_json::from_str::<WorkerCandidateRequestV1>(valid).unwrap(),
            WorkerCandidateRequestV1::Submit { content, .. } if content.as_slice() == b"a"
        ));
        let smuggled = r#"{"method":"submit","candidate_nonce":"07070707070707070707070707070707","semantic_type":"managed_file_content","content":"YQ==","judgment":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert!(serde_json::from_str::<WorkerCandidateRequestV1>(smuggled).is_err());
    }

    #[test]
    fn worker_control_requests_select_profiles_not_executables() {
        assert!(matches!(
            serde_json::from_str::<AgdRequestV1>(
                r#"{"method":"launch_worker","profile_id":"fixture"}"#
            )
            .unwrap(),
            AgdRequestV1::LaunchWorker { profile_id } if profile_id == "fixture"
        ));
        assert!(
            serde_json::from_str::<AgdRequestV1>(
                r#"{"method":"launch_worker","profile_id":"fixture","executable":"/bin/sh"}"#
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
