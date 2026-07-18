//! Candidate-only protocol helpers for contained generic workers.
//!
//! A worker receives a public governor challenge and one ephemeral Ed25519
//! private key through separate admitted descriptors. It can emit bounded
//! candidate requests, but replay accounting and the atomic principal
//! tombstone let the governor accept at most one. This protocol cannot express
//! an effect target, judgment, canonical proposal, ratification, or receipt.

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_protocol::{FrameCodec, RequestEnvelopeV1, canonical_json, strict_json_from_slice};
use thiserror::Error;

use crate::api::{OpaqueBytesV1, WorkerCandidateBootstrapV1, WorkerCandidateRequestV1};
use crate::rpc_auth::{RpcSignerV1, SignedRequestEnvelopeV1};

/// Evidence-bound role of the pipe carrying a worker's ephemeral ingress key.
pub const CANDIDATE_INGRESS_CREDENTIAL_PURPOSE: &str = "candidate-ingress-credential";

/// Evidence-bound role of the pipe carrying a worker's public bootstrap.
pub const CANDIDATE_BOOTSTRAP_PURPOSE: &str = "candidate-bootstrap";

/// Fixed upper bound for the public worker-bootstrap payload.
pub const MAX_WORKER_BOOTSTRAP_FRAME_BYTES: u32 = 128 * 1024;

/// Reads one exact public bootstrap frame from an admitted descriptor.
///
/// # Errors
///
/// Returns an error for truncated/oversized/non-strict JSON or inconsistent
/// challenge/audience bounds.
pub fn read_worker_bootstrap(
    reader: &mut impl Read,
) -> Result<WorkerCandidateBootstrapV1, WorkerProtocolError> {
    let codec = FrameCodec::new(MAX_WORKER_BOOTSTRAP_FRAME_BYTES)?;
    let maximum_wire_bytes = u64::from(MAX_WORKER_BOOTSTRAP_FRAME_BYTES) + 5;
    let mut frame = Vec::new();
    reader
        .take(maximum_wire_bytes)
        .read_to_end(&mut frame)
        .map_err(ag_protocol::ProtocolError::from)?;
    let payload = codec.decode_frame(&frame)?;
    let bootstrap: WorkerCandidateBootstrapV1 = strict_json_from_slice(payload)?;
    if bootstrap.schema != "ag.worker-candidate-bootstrap/v1"
        || bootstrap.maximum_frame_bytes == 0
        || bootstrap.maximum_candidate_bytes == 0
        || bootstrap.server_challenge.authentication.audience_principal != bootstrap.principal
        || bootstrap.server_challenge.authentication.audience_key_id != bootstrap.key_id
        || bootstrap.semantic_type.is_empty()
        || bootstrap.semantic_type.len() > 128
    {
        return Err(WorkerProtocolError::BootstrapBinding);
    }
    Ok(bootstrap)
}

/// Decodes exactly one complete signed candidate frame.
///
/// This is the governor-side complement to [`write_signed_worker_candidate`].
/// It refuses truncated output, a second frame, and any trailing byte before
/// parsing strict JSON or allowing authentication and durable custody. It does
/// not authenticate the request; the caller must revalidate it against the
/// durably enrolled worker principal and server challenge.
///
/// # Errors
///
/// Returns an error for an invalid frame bound, truncated/oversized/trailing
/// wire bytes, non-strict JSON, an invalid outer schema, or an invalid request
/// body digest.
pub fn decode_exact_signed_worker_candidate(
    frame: &[u8],
    maximum_frame_bytes: u32,
) -> Result<SignedRequestEnvelopeV1<WorkerCandidateRequestV1>, WorkerProtocolError> {
    let payload = FrameCodec::new(maximum_frame_bytes)?.decode_frame(frame)?;
    let signed: SignedRequestEnvelopeV1<WorkerCandidateRequestV1> =
        strict_json_from_slice(payload)?;
    if signed.schema != "ag.local-rpc.signed-request.v1" {
        return Err(WorkerProtocolError::CandidateEnvelopeBinding);
    }
    signed.request.validate()?;
    Ok(signed)
}

/// Signs and writes one candidate-only frame using descriptor-delivered
/// ephemeral authentication material.
///
/// # Errors
///
/// Returns an error for invalid bootstrap/key material, oversized candidate or
/// signed frame, clock failure, canonicalization, or descriptor I/O.
pub fn write_signed_worker_candidate(
    private_key_reader: &mut impl Read,
    bootstrap: &WorkerCandidateBootstrapV1,
    candidate: Vec<u8>,
    output: &mut impl Write,
) -> Result<SignedRequestEnvelopeV1<WorkerCandidateRequestV1>, WorkerProtocolError> {
    if u64::try_from(candidate.len()).map_err(|_| WorkerProtocolError::CandidateTooLarge)?
        > bootstrap.maximum_candidate_bytes
    {
        return Err(WorkerProtocolError::CandidateTooLarge);
    }
    let candidate_signer = RpcSignerV1::from_ephemeral_candidate_ingress_reader(
        bootstrap.principal.clone(),
        bootstrap.key_id.clone(),
        private_key_reader,
    )?;
    let request = RequestEnvelopeV1::new(
        bootstrap.request_id.clone(),
        WorkerCandidateRequestV1::Submit {
            candidate_nonce: bootstrap.candidate_nonce,
            semantic_type: bootstrap.semantic_type.clone(),
            content: OpaqueBytesV1::new(candidate),
        },
    )?;
    let issued_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| WorkerProtocolError::Clock(error.to_string()))?
            .as_millis(),
    )
    .map_err(|_| WorkerProtocolError::Clock("clock overflow".to_owned()))?;
    let signed_request =
        candidate_signer.sign_request(request, &bootstrap.server_challenge, issued_at_unix_ms)?;
    let payload = canonical_json(&signed_request)?;
    FrameCodec::new(bootstrap.maximum_frame_bytes)?.write_frame(output, &payload)?;
    Ok(signed_request)
}

/// Candidate protocol failures. No variant includes private key or candidate
/// contents in diagnostics.
#[derive(Debug, Error)]
pub enum WorkerProtocolError {
    /// Strict framing or JSON protocol failed.
    #[error(transparent)]
    Protocol(#[from] ag_protocol::ProtocolError),
    /// Ephemeral signature construction failed.
    #[error(transparent)]
    Authentication(#[from] crate::rpc_auth::RpcAuthError),
    /// Bootstrap fields disagree with the signed challenge or protocol bounds.
    #[error("worker bootstrap binding mismatch")]
    BootstrapBinding,
    /// Candidate envelope has an invalid outer schema.
    #[error("worker candidate envelope binding mismatch")]
    CandidateEnvelopeBinding,
    /// Candidate exceeds its principal/session budget.
    #[error("worker candidate exceeds its output budget")]
    CandidateTooLarge,
    /// Trusted clock failed.
    #[error("worker candidate clock failed: {0}")]
    Clock(String),
}

#[cfg(test)]
mod tests {
    use ag_primitives::{Digest, LifecycleNonce};
    use ag_protocol::{ProtocolError, RequestId};
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::rpc_auth::{RpcKeyIdV1, RpcSignerV1};

    #[test]
    fn descriptor_protocol_carries_candidate_only_and_enforces_budget() {
        let governor_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key");
        let governor = RpcSignerV1::from_pkcs8_for_test(
            Digest::hash_bytes(b"governor"),
            RpcKeyIdV1::new("governor").expect("key id"),
            governor_key.as_ref(),
        )
        .expect("signer");
        let principal = Digest::hash_bytes(b"worker");
        let (worker, private) = RpcSignerV1::generate_ephemeral_candidate_ingress(
            principal.clone(),
            RpcKeyIdV1::new("worker-session").expect("key id"),
        )
        .expect("ephemeral worker");
        let enrollment = worker.enrollment(30_000).expect("enrollment");
        let challenge = governor.issue_challenge(&enrollment, 1).expect("challenge");
        let bootstrap = WorkerCandidateBootstrapV1 {
            schema: "ag.worker-candidate-bootstrap/v1".to_owned(),
            principal,
            key_id: worker.key_id().clone(),
            candidate_nonce: LifecycleNonce::new([7; 16]),
            semantic_type: "managed_file_content_v1".to_owned(),
            request_id: RequestId::new("candidate-1").expect("request id"),
            maximum_frame_bytes: 64 * 1024,
            maximum_candidate_bytes: 16,
            server_challenge: challenge,
        };
        let mut key_bytes = Vec::new();
        private.write_to(&mut key_bytes).expect("private pipe");
        let mut output = Vec::new();
        let signed = write_signed_worker_candidate(
            &mut key_bytes.as_slice(),
            &bootstrap,
            b"candidate".to_vec(),
            &mut output,
        )
        .expect("candidate frame");
        assert_eq!(
            decode_exact_signed_worker_candidate(&output, bootstrap.maximum_frame_bytes)
                .expect("decode exact candidate"),
            signed
        );
        assert!(matches!(
            signed.request.body,
            WorkerCandidateRequestV1::Submit { ref content, .. }
                if content.as_slice() == b"candidate"
        ));
        assert!(
            write_signed_worker_candidate(
                &mut key_bytes.as_slice(),
                &bootstrap,
                vec![0; 17],
                &mut Vec::new(),
            )
            .is_err()
        );

        let mut truncated = output.clone();
        truncated.pop();
        assert!(matches!(
            decode_exact_signed_worker_candidate(&truncated, bootstrap.maximum_frame_bytes),
            Err(WorkerProtocolError::Protocol(
                ProtocolError::TruncatedFrame { .. }
            ))
        ));

        let mut two_frames = output.clone();
        two_frames.extend_from_slice(&output);
        assert!(matches!(
            decode_exact_signed_worker_candidate(&two_frames, bootstrap.maximum_frame_bytes),
            Err(WorkerProtocolError::Protocol(
                ProtocolError::TrailingFrameBytes(_)
            ))
        ));

        let mut trailing = output;
        trailing.push(0);
        assert!(matches!(
            decode_exact_signed_worker_candidate(&trailing, bootstrap.maximum_frame_bytes),
            Err(WorkerProtocolError::Protocol(
                ProtocolError::TrailingFrameBytes(1)
            ))
        ));
    }
}
