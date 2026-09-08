//! Mutually authenticated, replay-resistant local RPC over Unix sockets.
//!
//! The exchange is exactly three bounded frames on one connection:
//!
//! 1. the server signs a fresh audience-bound challenge;
//! 2. the client signs the strict request and the exact challenge;
//! 3. the server signs the exact request echo and response body.
//!
//! The client half-closes after its request. Consequently the server rejects
//! appended request frames before dispatch, while a captured request cannot be
//! replayed on a new connection because it binds a new server challenge.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use ag_protocol::{
    FrameCodec, ProtocolError, RequestEnvelopeV1, RequestId, canonical_json, strict_json_from_slice,
};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::rpc_auth::{
    RpcAuthError, RpcClockV1, RpcPeerEnrollmentV1, RpcReplayGuardV1, RpcSignerV1,
    SignedRequestEnvelopeV1, SignedResponseEnvelopeV1, SignedServerChallengeV1,
    VerifiedRpcPrincipalV1, verify_server_challenge, verify_signed_request, verify_signed_response,
};

/// Local client response deadline for the fixed signed-RPC exchange.
///
/// Long-running server methods must finish their external work and durable
/// commit with margin inside this bound.
pub const SIGNED_RPC_RESPONSE_TIMEOUT_MS: u64 = 30_000;

/// Kernel credentials observed on the connected socket.
///
/// These values are diagnostic lifecycle facts. They are never substituted
/// for the cryptographically enrolled principal returned alongside them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketPeerObservationV1 {
    /// Kernel-reported UID.
    pub uid: u32,
    /// Kernel-reported primary GID.
    pub gid: u32,
    /// Kernel-reported PID at connection time.
    pub pid: i32,
}

/// Explicit policy for the non-authoritative kernel observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketPeerCheckV1 {
    /// Record `SO_PEERCRED` without using it as an identity predicate.
    ObserveOnly,
    /// Additionally require configured UID/GID, useful as defense in depth or
    /// in development. Stable identity still comes only from the signature.
    RequireUidGid {
        /// Expected kernel UID.
        uid: u32,
        /// Expected kernel primary GID.
        gid: u32,
    },
}

/// A verified request and its stable signer identity.
///
/// This is authenticated evidence, not runtime effect authority.
pub struct AcceptedSignedRequestV1<T> {
    /// Exact server challenge to which the caller proof was bound. Keeping
    /// this permits a downstream authority membrane to verify the original
    /// proposer proof instead of trusting an intermediary's projection.
    pub server_challenge: SignedServerChallengeV1,
    /// Exact signed request retained for response binding.
    pub signed_request: SignedRequestEnvelopeV1<T>,
    /// Stable principal and key proven by the signed request.
    pub authenticated_peer: VerifiedRpcPrincipalV1,
    /// Non-authoritative socket observation, when the platform exposes it.
    pub socket_peer: Option<SocketPeerObservationV1>,
}

impl<T> AcceptedSignedRequestV1<T> {
    /// Returns the existing strict request envelope.
    #[must_use]
    pub fn request(&self) -> &RequestEnvelopeV1<T> {
        &self.signed_request.request
    }

    /// Returns the method-specific request body.
    #[must_use]
    pub fn body(&self) -> &T {
        &self.signed_request.request.body
    }
}

/// Signed local transport failures. Errors never include secret key bytes.
#[derive(Debug, Error)]
pub enum SignedTransportError {
    /// I/O failed.
    #[error("signed local transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Strict framing or JSON failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Cryptographic proof or replay validation failed.
    #[error(transparent)]
    Authentication(#[from] RpcAuthError),
    /// A peer appended bytes/frames or failed to half-close its request.
    #[error("signed RPC connection did not contain exactly the expected frames")]
    ExtraFrame,
    /// `SO_PEERCRED` could not be observed.
    #[error("cannot observe signed RPC Unix peer credentials: {0}")]
    PeerCredentials(#[from] nix::Error),
    /// Optional UID/GID defense-in-depth policy failed.
    #[error("signed RPC peer failed the optional kernel credential check")]
    KernelPeerMismatch,
    /// Response signer differs from the identity which issued the challenge.
    #[error("response signer differs from this connection's challenge signer")]
    LocalSignerMismatch,
}

/// Server side: issue a challenge, read one half-closed request, and verify it.
///
/// No application method should be dispatched until this function succeeds.
///
/// # Errors
///
/// Returns an error for socket/framing failure, strict schema failure, invalid
/// identity proof, timestamp, replay, or optional kernel-peer mismatch.
pub fn accept_signed_request<T>(
    stream: &mut UnixStream,
    codec: FrameCodec,
    local_signer: &RpcSignerV1,
    caller: &RpcPeerEnrollmentV1,
    replay_guard: &RpcReplayGuardV1,
    clock: &dyn RpcClockV1,
    socket_check: SocketPeerCheckV1,
) -> Result<AcceptedSignedRequestV1<T>, SignedTransportError>
where
    T: DeserializeOwned + Serialize,
{
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let socket_peer = observe_and_check(stream, socket_check)?;
    let challenge = local_signer.issue_challenge(caller, clock.now_unix_ms()?)?;
    codec.write_frame(&mut *stream, &canonical_json(&challenge)?)?;

    let payload = read_payload_and_require_eof(stream, codec)?;
    let signed_request: SignedRequestEnvelopeV1<T> = strict_json_from_slice(&payload)?;
    verify_signed_request(
        &signed_request,
        &challenge,
        caller,
        local_signer,
        replay_guard,
        clock.now_unix_ms()?,
    )?;
    Ok(AcceptedSignedRequestV1 {
        server_challenge: challenge,
        signed_request,
        authenticated_peer: VerifiedRpcPrincipalV1 {
            principal: caller.principal.clone(),
            key_id: caller.key.key_id.clone(),
        },
        socket_peer,
    })
}

/// Server side: sign and write a response bound to an accepted request.
///
/// # Errors
///
/// Returns an error for signing, framing, I/O, or a local signer different
/// from the one to which the accepted request was addressed.
pub fn write_signed_response<T, U>(
    stream: &mut UnixStream,
    codec: FrameCodec,
    local_signer: &RpcSignerV1,
    accepted: &AcceptedSignedRequestV1<U>,
    body: T,
    clock: &dyn RpcClockV1,
) -> Result<(), SignedTransportError>
where
    T: Serialize,
    U: Serialize,
{
    if accepted.signed_request.authentication.audience_principal != *local_signer.principal()
        || accepted.signed_request.authentication.audience_key_id != *local_signer.key_id()
    {
        return Err(SignedTransportError::LocalSignerMismatch);
    }
    stream.set_write_timeout(Some(Duration::from_millis(SIGNED_RPC_RESPONSE_TIMEOUT_MS)))?;
    let response =
        local_signer.sign_response(&accepted.signed_request, body, clock.now_unix_ms()?)?;
    codec.write_frame(&mut *stream, &canonical_json(&response)?)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

/// Client side: connect and perform one mutually authenticated RPC exchange.
///
/// # Errors
///
/// Returns an error if connection/framing fails or any server challenge,
/// response proof, request echo, timestamp, or nonce is invalid.
#[allow(clippy::too_many_arguments)]
pub fn call_signed<Req, Resp>(
    path: &Path,
    request_id: RequestId,
    body: Req,
    maximum: u32,
    local_signer: &RpcSignerV1,
    server: &RpcPeerEnrollmentV1,
    replay_guard: &RpcReplayGuardV1,
    clock: &dyn RpcClockV1,
    socket_check: SocketPeerCheckV1,
) -> Result<Resp, SignedTransportError>
where
    Req: Serialize,
    Resp: DeserializeOwned + Serialize,
{
    call_signed_with_timeout(
        path,
        request_id,
        body,
        maximum,
        local_signer,
        server,
        replay_guard,
        clock,
        socket_check,
        Duration::from_millis(SIGNED_RPC_RESPONSE_TIMEOUT_MS),
    )
}

/// Client side signed exchange with an explicit response wait.
///
/// This is reserved for a service whose root-owned policy admits a longer
/// operation than the ordinary control-plane bound, such as inference. The
/// caller remains responsible for supplying a finite deployment bound.
///
/// # Errors
///
/// Returns an error when the socket, frame, signature, peer, replay, clock, or
/// explicit response-deadline contract is not satisfied.
#[allow(clippy::too_many_arguments)]
pub fn call_signed_with_timeout<Req, Resp>(
    path: &Path,
    request_id: RequestId,
    body: Req,
    maximum: u32,
    local_signer: &RpcSignerV1,
    server: &RpcPeerEnrollmentV1,
    replay_guard: &RpcReplayGuardV1,
    clock: &dyn RpcClockV1,
    socket_check: SocketPeerCheckV1,
    response_timeout: Duration,
) -> Result<Resp, SignedTransportError>
where
    Req: Serialize,
    Resp: DeserializeOwned + Serialize,
{
    let mut stream = UnixStream::connect(path)?;
    let codec = FrameCodec::new(maximum)?;
    call_signed_on_stream_with_timeout(
        &mut stream,
        codec,
        request_id,
        body,
        local_signer,
        server,
        replay_guard,
        clock,
        socket_check,
        response_timeout,
    )
}

/// Client side exchange on an already connected Unix stream.
///
/// This entry point supports socket activation, integration tests, and callers
/// that connect through a separately constrained Unix namespace.
///
/// # Errors
///
/// Returns an error if framing, signing, peer observation, challenge proof,
/// response proof, echo binding, timestamp, or replay validation fails.
#[allow(clippy::too_many_arguments)]
pub fn call_signed_on_stream<Req, Resp>(
    stream: &mut UnixStream,
    codec: FrameCodec,
    request_id: RequestId,
    body: Req,
    local_signer: &RpcSignerV1,
    server: &RpcPeerEnrollmentV1,
    replay_guard: &RpcReplayGuardV1,
    clock: &dyn RpcClockV1,
    socket_check: SocketPeerCheckV1,
) -> Result<Resp, SignedTransportError>
where
    Req: Serialize,
    Resp: DeserializeOwned + Serialize,
{
    call_signed_on_stream_with_timeout(
        stream,
        codec,
        request_id,
        body,
        local_signer,
        server,
        replay_guard,
        clock,
        socket_check,
        Duration::from_millis(SIGNED_RPC_RESPONSE_TIMEOUT_MS),
    )
}

#[allow(clippy::too_many_arguments)]
fn call_signed_on_stream_with_timeout<Req, Resp>(
    stream: &mut UnixStream,
    codec: FrameCodec,
    request_id: RequestId,
    body: Req,
    local_signer: &RpcSignerV1,
    server: &RpcPeerEnrollmentV1,
    replay_guard: &RpcReplayGuardV1,
    clock: &dyn RpcClockV1,
    socket_check: SocketPeerCheckV1,
    response_timeout: Duration,
) -> Result<Resp, SignedTransportError>
where
    Req: Serialize,
    Resp: DeserializeOwned + Serialize,
{
    if response_timeout.is_zero() {
        return Err(SignedTransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "signed RPC response timeout must be nonzero",
        )));
    }
    stream.set_read_timeout(Some(response_timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let _socket_peer = observe_and_check(stream, socket_check)?;

    let payload = codec.read_frame(&mut *stream)?;
    let challenge: SignedServerChallengeV1 = strict_json_from_slice(&payload)?;
    verify_server_challenge(
        &challenge,
        server,
        local_signer,
        replay_guard,
        clock.now_unix_ms()?,
    )?;

    let request = RequestEnvelopeV1::new(request_id, body)?;
    let signed_request = local_signer.sign_request(request, &challenge, clock.now_unix_ms()?)?;
    codec.write_frame(&mut *stream, &canonical_json(&signed_request)?)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let payload = codec.read_frame(&mut *stream)?;
    let response: SignedResponseEnvelopeV1<Resp> = strict_json_from_slice(&payload)?;
    verify_signed_response(
        &response,
        &signed_request,
        server,
        local_signer,
        replay_guard,
        clock.now_unix_ms()?,
    )?;
    require_eof(stream)?;
    Ok(response.response.body)
}

fn observe_and_check(
    stream: &UnixStream,
    check: SocketPeerCheckV1,
) -> Result<Option<SocketPeerObservationV1>, SignedTransportError> {
    let credentials = match getsockopt(stream, PeerCredentials) {
        Ok(credentials) => credentials,
        Err(_) if check == SocketPeerCheckV1::ObserveOnly => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let observation = SocketPeerObservationV1 {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid: credentials.pid(),
    };
    check_observation(observation, check)?;
    Ok(Some(observation))
}

fn check_observation(
    observation: SocketPeerObservationV1,
    check: SocketPeerCheckV1,
) -> Result<(), SignedTransportError> {
    if let SocketPeerCheckV1::RequireUidGid { uid, gid } = check
        && (observation.uid != uid || observation.gid != gid)
    {
        return Err(SignedTransportError::KernelPeerMismatch);
    }
    Ok(())
}

fn read_payload_and_require_eof(
    stream: &mut UnixStream,
    codec: FrameCodec,
) -> Result<Vec<u8>, SignedTransportError> {
    let payload = codec.read_frame(&mut *stream)?;
    require_eof(stream)?;
    Ok(payload)
}

fn require_eof(stream: &mut UnixStream) -> Result<(), SignedTransportError> {
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(SignedTransportError::ExtraFrame),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Err(SignedTransportError::ExtraFrame)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

    use ag_primitives::Digest;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::rpc_auth::{RpcKeyIdV1, RpcSignerV1};

    #[test]
    fn kernel_peer_check_is_additional_and_fail_closed() {
        let expected = SocketPeerObservationV1 {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
            pid: i32::try_from(std::process::id()).expect("PID fits i32"),
        };
        check_observation(
            expected,
            SocketPeerCheckV1::RequireUidGid {
                uid: expected.uid,
                gid: expected.gid,
            },
        )
        .expect("matching observation");
        assert!(matches!(
            check_observation(
                expected,
                SocketPeerCheckV1::RequireUidGid {
                    uid: expected.uid.wrapping_add(1),
                    gid: expected.gid,
                },
            ),
            Err(SignedTransportError::KernelPeerMismatch)
        ));

        // Some test sandboxes deny SO_PEERCRED. RequireUidGid must never
        // degrade to ObserveOnly in that environment.
        let (left, _right) = UnixStream::pair().expect("socket pair");
        let observed = observe_and_check(
            &left,
            SocketPeerCheckV1::RequireUidGid {
                uid: expected.uid,
                gid: expected.gid,
            },
        );
        assert!(
            matches!(
                observed,
                Ok(Some(observation)) if observation.uid == expected.uid
                    && observation.gid == expected.gid
            ) || matches!(observed, Err(SignedTransportError::PeerCredentials(_)))
        );
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ping {
        value: u64,
    }

    struct FixedClock(u64);

    impl RpcClockV1 for FixedClock {
        fn now_unix_ms(&self) -> Result<u64, RpcAuthError> {
            Ok(self.0)
        }
    }

    fn signer(label: &str) -> RpcSignerV1 {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        RpcSignerV1::from_pkcs8_for_test(
            Digest::hash_domain("transport-test-principal-v1", label.as_bytes()),
            RpcKeyIdV1::new(format!("{label}-key")).expect("key id"),
            pkcs8.as_ref(),
        )
        .expect("signer")
    }

    #[test]
    fn complete_mutually_authenticated_exchange() {
        // Some CI sandboxes deny the `shutdown(2)` syscall. The production
        // protocol deliberately requires a half-close to reject appended
        // frames before dispatch, so do not weaken that invariant for the
        // sandbox: the proof-level hostile tests still run there.
        let (probe, _peer) = UnixStream::pair().expect("probe pair");
        if probe
            .shutdown(std::net::Shutdown::Write)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
        {
            return;
        }
        let (mut client_stream, mut server_stream) = UnixStream::pair().expect("pair");
        let server_signer = signer("server");
        let client_signer = signer("client");
        let server_enrollment = server_signer.enrollment(30_000).expect("enrollment");
        let client_enrollment = client_signer.enrollment(30_000).expect("enrollment");
        let codec = FrameCodec::new(16 * 1024).expect("codec");
        let clock = Arc::new(FixedClock(1_900_000_000_000));
        let server_clock = Arc::clone(&clock);

        let server = std::thread::spawn(move || {
            let replay = RpcReplayGuardV1::new(16).expect("guard");
            let accepted: AcceptedSignedRequestV1<Ping> = accept_signed_request(
                &mut server_stream,
                codec,
                &server_signer,
                &client_enrollment,
                &replay,
                server_clock.as_ref(),
                SocketPeerCheckV1::ObserveOnly,
            )
            .expect("accept");
            assert_eq!(accepted.body(), &Ping { value: 41 });
            write_signed_response(
                &mut server_stream,
                codec,
                &server_signer,
                &accepted,
                Ping { value: 42 },
                server_clock.as_ref(),
            )
            .expect("response");
        });

        let response: Ping = call_signed_on_stream(
            &mut client_stream,
            codec,
            RequestId::new("transport-test").expect("id"),
            Ping { value: 41 },
            &client_signer,
            &server_enrollment,
            &RpcReplayGuardV1::new(16).expect("guard"),
            clock.as_ref(),
            SocketPeerCheckV1::ObserveOnly,
        )
        .expect("call");
        assert_eq!(response, Ping { value: 42 });
        server.join().expect("server thread");
    }
}
