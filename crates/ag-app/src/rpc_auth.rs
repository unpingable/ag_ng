//! Cryptographic identity and proof objects for local RPC.
//!
//! Linux socket credentials are useful lifecycle observations, but are not a
//! stable principal identity. This module authenticates an enrolled principal
//! with an Ed25519 key whose public half is held in root-owned policy. Private
//! keys are loaded only from explicit systemd credential paths.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ag_primitives::Digest;
use ag_protocol::{
    ProtocolError, ProtocolVersionV1, RequestEnvelopeV1, ResponseEnvelopeV1, canonical_json,
    canonical_json_digest,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const RPC_NONCE_LEN: usize = 32;
const MAX_CREDENTIAL_BYTES: u64 = 4096;
const SIGNATURE_PREFIX: &[u8] = b"ag-ng\0local-rpc-signature\0v1\0";

/// Identifier of one enrolled Ed25519 key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RpcKeyIdV1(String);

impl RpcKeyIdV1 {
    /// Parses a bounded ASCII key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`RpcAuthError::InvalidKeyId`] for empty, oversized, or
    /// non-canonical identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, RpcAuthError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(RpcAuthError::InvalidKeyId);
        }
        Ok(Self(value))
    }

    /// Returns the canonical key identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RpcKeyIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

macro_rules! fixed_base64_type {
    ($name:ident, $length:expr, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $length]);

        impl $name {
            fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            #[allow(dead_code)]
            fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            fn parse(value: &str) -> Result<Self, RpcAuthError> {
                let bytes = URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|_| RpcAuthError::InvalidBase64)?;
                let bytes: [u8; $length] = bytes
                    .try_into()
                    .map_err(|_| RpcAuthError::InvalidEncodedLength)?;
                if URL_SAFE_NO_PAD.encode(bytes) != value {
                    return Err(RpcAuthError::NonCanonicalBase64);
                }
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

fixed_base64_type!(
    RpcPublicKeyV1,
    ED25519_PUBLIC_KEY_LEN,
    "A canonical base64url-no-pad Ed25519 public key."
);
fixed_base64_type!(
    RpcSignatureV1,
    ED25519_SIGNATURE_LEN,
    "A canonical base64url-no-pad Ed25519 signature."
);
fixed_base64_type!(
    RpcNonceV1,
    RPC_NONCE_LEN,
    "A canonical 256-bit local-RPC nonce."
);

impl RpcPublicKeyV1 {
    /// Parses an exact canonical Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns an error unless `value` is canonical unpadded base64url of
    /// exactly 32 bytes.
    pub fn from_base64url(value: &str) -> Result<Self, RpcAuthError> {
        Self::parse(value)
    }

    /// Returns the canonical public-key encoding used in enrollment policy.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl RpcNonceV1 {
    fn random() -> Result<Self, RpcAuthError> {
        let mut bytes = [0_u8; RPC_NONCE_LEN];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| RpcAuthError::Randomness)?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Root-owned enrollment data for one RPC peer key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcPeerKeyPolicyV1 {
    /// Exact stable or lifecycle principal represented by this key.
    pub principal: Digest,
    /// Exact key ID accepted for the principal.
    pub key_id: RpcKeyIdV1,
    /// Exact Ed25519 public key.
    pub public_key: RpcPublicKeyV1,
    /// Maximum permitted absolute timestamp skew.
    pub maximum_clock_skew_ms: u64,
}

impl RpcPeerKeyPolicyV1 {
    /// Validates fail-closed policy bounds.
    ///
    /// # Errors
    ///
    /// Returns [`RpcAuthError::InvalidClockSkewPolicy`] for a zero or greater
    /// than five minute acceptance window.
    pub fn validate(&self) -> Result<(), RpcAuthError> {
        if self.maximum_clock_skew_ms == 0 || self.maximum_clock_skew_ms > 300_000 {
            return Err(RpcAuthError::InvalidClockSkewPolicy);
        }
        Ok(())
    }
}

/// Computes the reviewed identity of one ephemeral worker candidate-ingress
/// key policy without including its lifecycle principal.
///
/// Excluding `policy.principal` is intentional: the worker principal itself
/// commits this identity, so including it would create a construction cycle.
/// The explicit role tag prevents the same key material from being silently
/// reinterpreted as another credential role.
///
/// # Errors
///
/// Returns an error if the policy bounds or canonical encoding are invalid.
pub fn candidate_ingress_key_identity(policy: &RpcPeerKeyPolicyV1) -> Result<Digest, RpcAuthError> {
    policy.validate()?;
    canonical_json_digest(
        "ag-local-rpc-candidate-ingress-key-identity-v1",
        &(
            "worker_candidate_ingress",
            &policy.key_id,
            &policy.public_key,
            policy.maximum_clock_skew_ms,
        ),
    )
    .map_err(RpcAuthError::from)
}

/// Local signing identity whose secret half is an explicit credential file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSigningIdentityConfigV1 {
    /// Stable enrolled principal root represented by this key.
    pub principal: Digest,
    /// Exact key identifier.
    pub key_id: RpcKeyIdV1,
    /// Expected public key, detecting an accidentally substituted credential.
    pub public_key: RpcPublicKeyV1,
    /// Absolute systemd credential path containing Ed25519 PKCS#8 v2 bytes.
    pub private_key_credential: PathBuf,
}

impl RpcSigningIdentityConfigV1 {
    /// Validates path shape without reading secret material.
    ///
    /// # Errors
    ///
    /// Returns [`RpcAuthError::UnsafeCredentialPath`] unless the credential
    /// path is absolute and normalized.
    pub fn validate(&self) -> Result<(), RpcAuthError> {
        let mut normalized = PathBuf::from("/");
        let mut components = self.private_key_credential.components();
        if !matches!(components.next(), Some(std::path::Component::RootDir)) {
            return Err(RpcAuthError::UnsafeCredentialPath);
        }
        for component in components {
            let std::path::Component::Normal(component) = component else {
                return Err(RpcAuthError::UnsafeCredentialPath);
            };
            normalized.push(component);
        }
        if normalized.as_os_str().as_bytes() != self.private_key_credential.as_os_str().as_bytes()
            || normalized == Path::new("/")
        {
            return Err(RpcAuthError::UnsafeCredentialPath);
        }
        Ok(())
    }
}

/// A fully enrolled peer identity used by proof verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcPeerEnrollmentV1 {
    /// Stable principal identity, never a PID or UID.
    pub principal: Digest,
    /// Enrolled verification key and timestamp policy.
    pub key: RpcPeerKeyPolicyV1,
}

/// Principal proven by a successfully verified signed message.
///
/// This object is authentication evidence and carries no effect authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRpcPrincipalV1 {
    /// Stable enrolled principal, never a kernel process identifier.
    pub principal: Digest,
    /// Exact enrolled key which proved the message.
    pub key_id: RpcKeyIdV1,
}

impl VerifiedRpcPrincipalV1 {
    /// Returns a canonical binding used for connection-scoped challenges.
    ///
    /// # Errors
    ///
    /// Returns an error if the strict principal evidence cannot be
    /// canonicalized.
    pub fn binding_digest(&self) -> Result<Digest, RpcAuthError> {
        Ok(canonical_json_digest(
            "ag-local-rpc-verified-principal-v1",
            self,
        )?)
    }
}

impl RpcPeerEnrollmentV1 {
    /// Constructs a checked enrollment.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timestamp policy or when the separately
    /// supplied principal differs from the key's enrolled principal.
    pub fn new(principal: Digest, key: RpcPeerKeyPolicyV1) -> Result<Self, RpcAuthError> {
        key.validate()?;
        if principal != key.principal {
            return Err(RpcAuthError::SignerMismatch);
        }
        Ok(Self { principal, key })
    }
}

/// Direction is a signed field, preventing reflection between message kinds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcDirectionV1 {
    /// Server-to-client challenge before a request is accepted.
    ServerChallenge,
    /// Client-to-server request.
    Request,
    /// Server-to-client response.
    Response,
}

/// Authentication proof on a server challenge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeProofV1 {
    /// Stable server principal.
    pub signer_principal: Digest,
    /// Enrolled server key ID.
    pub signer_key_id: RpcKeyIdV1,
    /// Stable intended client principal.
    pub audience_principal: Digest,
    /// Intended client key ID.
    pub audience_key_id: RpcKeyIdV1,
    /// Must be `server_challenge`.
    pub direction: RpcDirectionV1,
    /// Fresh random challenge.
    pub nonce: RpcNonceV1,
    /// Wall-clock issue time.
    pub issued_at_unix_ms: u64,
    /// Ed25519 proof over the canonical challenge statement.
    pub signature: RpcSignatureV1,
}

/// First frame in the mutually authenticated local RPC exchange.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServerChallengeV1 {
    /// Exact challenge schema.
    pub schema: String,
    /// Exact protocol version accepted on this connection.
    pub protocol_version: ProtocolVersionV1,
    /// Signed challenge proof.
    pub authentication: ChallengeProofV1,
}

/// Authentication proof on a strict request envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestProofV1 {
    /// Stable caller principal.
    pub signer_principal: Digest,
    /// Enrolled caller key ID.
    pub signer_key_id: RpcKeyIdV1,
    /// Stable target daemon principal.
    pub audience_principal: Digest,
    /// Exact target key ID.
    pub audience_key_id: RpcKeyIdV1,
    /// Must be `request`.
    pub direction: RpcDirectionV1,
    /// Fresh caller nonce.
    pub nonce: RpcNonceV1,
    /// Caller wall-clock issue time.
    pub issued_at_unix_ms: u64,
    /// Digest of the exact signed server challenge.
    pub challenge_digest: Digest,
    /// Ed25519 proof over the canonical request statement.
    pub signature: RpcSignatureV1,
}

/// Strict request plus cryptographic principal proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequestEnvelopeV1<T> {
    /// Exact signed-request schema.
    pub schema: String,
    /// Existing strict request envelope.
    pub request: RequestEnvelopeV1<T>,
    /// Caller authentication proof.
    pub authentication: RequestProofV1,
}

/// Authentication proof on a strict response envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseProofV1 {
    /// Stable responding daemon principal.
    pub signer_principal: Digest,
    /// Enrolled responder key ID.
    pub signer_key_id: RpcKeyIdV1,
    /// Stable caller principal.
    pub audience_principal: Digest,
    /// Exact caller key ID.
    pub audience_key_id: RpcKeyIdV1,
    /// Must be `response`.
    pub direction: RpcDirectionV1,
    /// Fresh responder nonce.
    pub nonce: RpcNonceV1,
    /// Responder wall-clock issue time.
    pub issued_at_unix_ms: u64,
    /// Digest of the exact signed request wrapper being answered.
    pub signed_request_digest: Digest,
    /// Exact caller request nonce.
    pub request_nonce: RpcNonceV1,
    /// Digest of the canonical response body.
    pub response_body_digest: Digest,
    /// Ed25519 proof over the canonical response statement.
    pub signature: RpcSignatureV1,
}

/// Strict response plus cryptographic daemon proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedResponseEnvelopeV1<T> {
    /// Exact signed-response schema.
    pub schema: String,
    /// Existing request-bound strict response.
    pub response: ResponseEnvelopeV1<T>,
    /// Responder authentication proof.
    pub authentication: ResponseProofV1,
}

#[derive(Serialize)]
struct ChallengeStatementV1<'a> {
    context: &'static str,
    protocol_version: &'a ProtocolVersionV1,
    signer_principal: &'a Digest,
    signer_key_id: &'a RpcKeyIdV1,
    audience_principal: &'a Digest,
    audience_key_id: &'a RpcKeyIdV1,
    direction: RpcDirectionV1,
    nonce: &'a RpcNonceV1,
    issued_at_unix_ms: u64,
}

#[derive(Serialize)]
struct RequestStatementV1<'a> {
    context: &'static str,
    protocol_version: &'a ProtocolVersionV1,
    request_id: &'a ag_protocol::RequestId,
    request_body_digest: &'a Digest,
    signer_principal: &'a Digest,
    signer_key_id: &'a RpcKeyIdV1,
    audience_principal: &'a Digest,
    audience_key_id: &'a RpcKeyIdV1,
    direction: RpcDirectionV1,
    nonce: &'a RpcNonceV1,
    issued_at_unix_ms: u64,
    challenge_digest: &'a Digest,
}

#[derive(Serialize)]
struct ResponseStatementV1<'a> {
    context: &'static str,
    protocol_version: &'a ProtocolVersionV1,
    request_id: &'a ag_protocol::RequestId,
    request_body_digest: &'a Digest,
    response_body_digest: &'a Digest,
    signer_principal: &'a Digest,
    signer_key_id: &'a RpcKeyIdV1,
    audience_principal: &'a Digest,
    audience_key_id: &'a RpcKeyIdV1,
    direction: RpcDirectionV1,
    nonce: &'a RpcNonceV1,
    issued_at_unix_ms: u64,
    signed_request_digest: &'a Digest,
    request_nonce: &'a RpcNonceV1,
}

/// Ed25519 local identity. Debug output is intentionally unavailable.
pub struct RpcSignerV1 {
    principal: Digest,
    key_id: RpcKeyIdV1,
    public_key: RpcPublicKeyV1,
    key_pair: Ed25519KeyPair,
}

/// Owned PKCS#8 bytes for one ephemeral worker candidate-ingress key.
///
/// This key can authenticate exactly the protocol role into which its public
/// enrollment is installed. It carries no effect, ratification, provider, or
/// other bearer authority. The wrapper deliberately has no `Debug`, clone, or
/// byte-returning accessor; launchers transfer it only through an explicitly
/// admitted descriptor and then drop it.
pub struct EphemeralRpcPrivateKeyV1 {
    bytes: Vec<u8>,
}

impl EphemeralRpcPrivateKeyV1 {
    /// Writes the exact PKCS#8 bytes to one launcher-admitted descriptor.
    ///
    /// # Errors
    ///
    /// Returns an I/O error without exposing private bytes in diagnostics.
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), std::io::Error> {
        writer.write_all(&self.bytes)
    }

    /// Returns the bounded byte count for descriptor accounting.
    #[must_use]
    pub fn byte_length(&self) -> usize {
        self.bytes.len()
    }
}

impl Drop for EphemeralRpcPrivateKeyV1 {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

impl RpcSignerV1 {
    /// Loads an Ed25519 PKCS#8 v2 key from one explicit, protected credential.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe credential path or file, invalid key
    /// bytes, or a public key which differs from root-owned configuration.
    pub fn from_systemd_credential(
        config: &RpcSigningIdentityConfigV1,
    ) -> Result<Self, RpcAuthError> {
        config.validate()?;
        let bytes = read_protected_credential(&config.private_key_credential)?;
        let signer = Self::from_pkcs8(config.principal.clone(), config.key_id.clone(), &bytes)?;
        if signer.public_key != config.public_key {
            return Err(RpcAuthError::CredentialPublicKeyMismatch);
        }
        Ok(signer)
    }

    /// Generates a fresh Ed25519 identity for one worker's candidate-ingress
    /// channel.
    ///
    /// The launcher may supply a provisional construction principal, compute
    /// the public key-policy identity (which deliberately excludes that field),
    /// and then rebind the public enrollment to the complete reviewed
    /// `WorkerSessionPrincipalV1`. It must durably commit that final enrollment
    /// before release, write the private material only to an admitted worker
    /// descriptor, and then drop both private copies. This is authentication
    /// material, not serialized effect authority.
    ///
    /// # Errors
    ///
    /// Returns an error if secure key generation or PKCS#8 parsing fails.
    pub fn generate_ephemeral_candidate_ingress(
        principal: Digest,
        key_id: RpcKeyIdV1,
    ) -> Result<(Self, EphemeralRpcPrivateKeyV1), RpcAuthError> {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| RpcAuthError::Randomness)?;
        let material = EphemeralRpcPrivateKeyV1 {
            bytes: document.as_ref().to_vec(),
        };
        let signer = Self::from_pkcs8(principal, key_id, &material.bytes)?;
        Ok((signer, material))
    }

    /// Loads one worker candidate-ingress signer from an admitted descriptor.
    ///
    /// Callers supply the principal and key ID from the immutable session
    /// record. The reader is bounded and must contain exactly one nonempty
    /// Ed25519 PKCS#8 v2 document. This method does not accept a pathname or
    /// perform implicit credential discovery.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, unreadable, or invalid key.
    pub fn from_ephemeral_candidate_ingress_reader(
        principal: Digest,
        key_id: RpcKeyIdV1,
        reader: &mut impl Read,
    ) -> Result<Self, RpcAuthError> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| RpcAuthError::CredentialIo { source })?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
            bytes.fill(0);
            return Err(RpcAuthError::InvalidCredentialFile);
        }
        let result = Self::from_pkcs8(principal, key_id, &bytes);
        bytes.fill(0);
        result
    }

    fn from_pkcs8(
        principal: Digest,
        key_id: RpcKeyIdV1,
        bytes: &[u8],
    ) -> Result<Self, RpcAuthError> {
        let key_pair =
            Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| RpcAuthError::InvalidPrivateKey)?;
        let public_key: [u8; ED25519_PUBLIC_KEY_LEN] = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| RpcAuthError::InvalidPrivateKey)?;
        Ok(Self {
            principal,
            key_id,
            public_key: RpcPublicKeyV1::from_bytes(public_key),
            key_pair,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_pkcs8_for_test(
        principal: Digest,
        key_id: RpcKeyIdV1,
        bytes: &[u8],
    ) -> Result<Self, RpcAuthError> {
        Self::from_pkcs8(principal, key_id, bytes)
    }

    /// Returns public enrollment data for this signer.
    ///
    /// # Errors
    ///
    /// Returns an error if `maximum_clock_skew_ms` is outside policy bounds.
    pub fn enrollment(
        &self,
        maximum_clock_skew_ms: u64,
    ) -> Result<RpcPeerEnrollmentV1, RpcAuthError> {
        RpcPeerEnrollmentV1::new(
            self.principal.clone(),
            RpcPeerKeyPolicyV1 {
                principal: self.principal.clone(),
                key_id: self.key_id.clone(),
                public_key: self.public_key.clone(),
                maximum_clock_skew_ms,
            },
        )
    }

    /// Returns the stable principal represented by the private key.
    #[must_use]
    pub fn principal(&self) -> &Digest {
        &self.principal
    }

    /// Returns the non-secret key identifier.
    #[must_use]
    pub fn key_id(&self) -> &RpcKeyIdV1 {
        &self.key_id
    }

    /// Creates a fresh, audience-bound server challenge.
    ///
    /// This low-level primitive is public so a launcher-owned, per-session
    /// candidate ingress can use the same three-frame proof protocol without
    /// inventing another signature format. Enrollment at the receiving socket
    /// determines the only accepted role; a challenge is not effect authority.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid enrollment policy, randomness, or strict
    /// canonicalization failure.
    pub fn issue_challenge(
        &self,
        audience: &RpcPeerEnrollmentV1,
        issued_at_unix_ms: u64,
    ) -> Result<SignedServerChallengeV1, RpcAuthError> {
        audience.key.validate()?;
        let mut challenge = SignedServerChallengeV1 {
            schema: "ag.local-rpc.server-challenge.v1".to_owned(),
            protocol_version: ProtocolVersionV1::current(),
            authentication: ChallengeProofV1 {
                signer_principal: self.principal.clone(),
                signer_key_id: self.key_id.clone(),
                audience_principal: audience.principal.clone(),
                audience_key_id: audience.key.key_id.clone(),
                direction: RpcDirectionV1::ServerChallenge,
                nonce: RpcNonceV1::random()?,
                issued_at_unix_ms,
                signature: RpcSignatureV1::from_bytes([0_u8; ED25519_SIGNATURE_LEN]),
            },
        };
        let message = challenge_message(&challenge)?;
        challenge.authentication.signature = self.sign(&message);
        Ok(challenge)
    }

    /// Signs a strict request for one exact server challenge.
    ///
    /// Generic fixed workers use this only with `WorkerCandidateRequestV1` and
    /// their per-session ephemeral signer. The proof authenticates candidate
    /// bytes to that enrolled ingress; it cannot create a proposal judgment,
    /// canonical effect, ratification, or provider capability.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid request, wrong challenge audience,
    /// randomness, or strict canonicalization failure.
    pub fn sign_request<T: Serialize>(
        &self,
        request: RequestEnvelopeV1<T>,
        challenge: &SignedServerChallengeV1,
        issued_at_unix_ms: u64,
    ) -> Result<SignedRequestEnvelopeV1<T>, RpcAuthError> {
        request.validate()?;
        if challenge.authentication.audience_principal != self.principal
            || challenge.authentication.audience_key_id != self.key_id
        {
            return Err(RpcAuthError::AudienceMismatch);
        }
        let mut signed = SignedRequestEnvelopeV1 {
            schema: "ag.local-rpc.signed-request.v1".to_owned(),
            request,
            authentication: RequestProofV1 {
                signer_principal: self.principal.clone(),
                signer_key_id: self.key_id.clone(),
                audience_principal: challenge.authentication.signer_principal.clone(),
                audience_key_id: challenge.authentication.signer_key_id.clone(),
                direction: RpcDirectionV1::Request,
                nonce: RpcNonceV1::random()?,
                issued_at_unix_ms,
                challenge_digest: canonical_json_digest(
                    "ag-local-rpc-server-challenge-v1",
                    challenge,
                )?,
                signature: RpcSignatureV1::from_bytes([0_u8; ED25519_SIGNATURE_LEN]),
            },
        };
        let message = request_message(&signed)?;
        signed.authentication.signature = self.sign(&message);
        Ok(signed)
    }

    /// Signs a response bound to the exact signed request and response body.
    pub(crate) fn sign_response<T: Serialize, U: Serialize>(
        &self,
        request: &SignedRequestEnvelopeV1<U>,
        body: T,
        issued_at_unix_ms: u64,
    ) -> Result<SignedResponseEnvelopeV1<T>, RpcAuthError> {
        request.request.validate()?;
        let response = ResponseEnvelopeV1::for_request(&request.request, body);
        let response_body_digest =
            canonical_json_digest("ag-local-rpc-response-body-v1", &response.body)?;
        let mut signed = SignedResponseEnvelopeV1 {
            schema: "ag.local-rpc.signed-response.v1".to_owned(),
            response,
            authentication: ResponseProofV1 {
                signer_principal: self.principal.clone(),
                signer_key_id: self.key_id.clone(),
                audience_principal: request.authentication.signer_principal.clone(),
                audience_key_id: request.authentication.signer_key_id.clone(),
                direction: RpcDirectionV1::Response,
                nonce: RpcNonceV1::random()?,
                issued_at_unix_ms,
                signed_request_digest: canonical_json_digest(
                    "ag-local-rpc-signed-request-v1",
                    request,
                )?,
                request_nonce: request.authentication.nonce.clone(),
                response_body_digest,
                signature: RpcSignatureV1::from_bytes([0_u8; ED25519_SIGNATURE_LEN]),
            },
        };
        let message = response_message(&signed)?;
        signed.authentication.signature = self.sign(&message);
        Ok(signed)
    }

    fn sign(&self, message: &[u8]) -> RpcSignatureV1 {
        let signature = self.key_pair.sign(message);
        let bytes: [u8; ED25519_SIGNATURE_LEN] = signature
            .as_ref()
            .try_into()
            .expect("ring Ed25519 signatures have a fixed 64-byte representation");
        RpcSignatureV1::from_bytes(bytes)
    }
}

fn read_protected_credential(path: &Path) -> Result<Vec<u8>, RpcAuthError> {
    use rustix::fs::{Mode, OFlags};

    let root = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno_to_io)
    .map_err(|source| RpcAuthError::CredentialIo { source })?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| RpcAuthError::UnsafeCredentialPath)?;
    let descriptor = crate::descriptor_path::open_beneath(
        &root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(errno_to_io)
    .map_err(|source| RpcAuthError::CredentialIo { source })?;
    let mut file = File::from(descriptor);
    let before = validate_credential_metadata(&file)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| RpcAuthError::CredentialIo { source })?;
    let after = validate_credential_metadata(&file)?;
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_CREDENTIAL_BYTES
        || u64::try_from(bytes.len()).ok() != Some(before.size())
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.size() != after.size()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(RpcAuthError::InvalidCredentialFile);
    }
    Ok(bytes)
}

fn validate_credential_metadata(file: &File) -> Result<std::fs::Metadata, RpcAuthError> {
    let metadata = file
        .metadata()
        .map_err(|source| RpcAuthError::CredentialIo { source })?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
    {
        return Err(RpcAuthError::InvalidCredentialFile);
    }
    Ok(metadata)
}

fn errno_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

/// Clock abstraction; production uses [`SystemRpcClockV1`] and tests inject a fixed clock.
pub trait RpcClockV1: Send + Sync {
    /// Returns current Unix epoch milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`RpcAuthError::Clock`] when the clock cannot be represented.
    fn now_unix_ms(&self) -> Result<u64, RpcAuthError>;
}

/// System wall clock for signed RPC timestamps.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRpcClockV1;

impl RpcClockV1 for SystemRpcClockV1 {
    fn now_unix_ms(&self) -> Result<u64, RpcAuthError> {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| RpcAuthError::Clock)?
                .as_millis(),
        )
        .map_err(|_| RpcAuthError::Clock)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayKeyV1 {
    signer: Digest,
    key_id: RpcKeyIdV1,
    direction: RpcDirectionV1,
    nonce: RpcNonceV1,
}

struct ReplayObservationV1<'a> {
    signer: &'a Digest,
    key_id: &'a RpcKeyIdV1,
    direction: RpcDirectionV1,
    nonce: &'a RpcNonceV1,
    issued_at_unix_ms: u64,
    maximum_clock_skew_ms: u64,
}

/// Bounded fail-closed replay cache.
///
/// Unexpired entries are never evicted to make room for attacker input. A
/// full cache therefore rejects new traffic until entries expire.
pub struct RpcReplayGuardV1 {
    capacity: usize,
    entries: Mutex<HashMap<ReplayKeyV1, u64>>,
}

impl RpcReplayGuardV1 {
    /// Creates a replay guard with an explicit non-zero capacity.
    ///
    /// # Errors
    ///
    /// Returns [`RpcAuthError::InvalidReplayCapacity`] for zero.
    pub fn new(capacity: usize) -> Result<Self, RpcAuthError> {
        if capacity == 0 {
            return Err(RpcAuthError::InvalidReplayCapacity);
        }
        Ok(Self {
            capacity,
            entries: Mutex::new(HashMap::new()),
        })
    }

    fn check_and_record(
        &self,
        observation: ReplayObservationV1<'_>,
        now_unix_ms: u64,
    ) -> Result<(), RpcAuthError> {
        self.check_and_record_all(&[observation], now_unix_ms)
    }

    fn check_and_record_all(
        &self,
        observations: &[ReplayObservationV1<'_>],
        now_unix_ms: u64,
    ) -> Result<(), RpcAuthError> {
        for observation in observations {
            validate_time(
                observation.issued_at_unix_ms,
                now_unix_ms,
                observation.maximum_clock_skew_ms,
            )?;
        }
        let mut entries = self.entries.lock().map_err(|_| RpcAuthError::ReplayState)?;
        entries.retain(|_, expires_at| *expires_at >= now_unix_ms);
        let candidates = observations
            .iter()
            .map(|observation| {
                (
                    ReplayKeyV1 {
                        signer: observation.signer.clone(),
                        key_id: observation.key_id.clone(),
                        direction: observation.direction,
                        nonce: observation.nonce.clone(),
                    },
                    observation
                        .issued_at_unix_ms
                        .saturating_add(observation.maximum_clock_skew_ms),
                )
            })
            .collect::<Vec<_>>();
        if candidates.iter().any(|(key, _)| entries.contains_key(key))
            || candidates
                .iter()
                .enumerate()
                .any(|(index, (key, _))| candidates[..index].iter().any(|(seen, _)| seen == key))
        {
            return Err(RpcAuthError::Replay);
        }
        if entries.len().saturating_add(candidates.len()) > self.capacity {
            return Err(RpcAuthError::ReplayCapacityExhausted);
        }
        entries.extend(candidates);
        Ok(())
    }
}

fn validate_time(issued: u64, now: u64, skew: u64) -> Result<(), RpcAuthError> {
    if skew == 0 || issued > now.saturating_add(skew) || issued.saturating_add(skew) < now {
        return Err(RpcAuthError::TimestampOutsideWindow);
    }
    Ok(())
}

/// Verifies and records one server challenge.
pub(crate) fn verify_server_challenge(
    challenge: &SignedServerChallengeV1,
    server: &RpcPeerEnrollmentV1,
    local_signer: &RpcSignerV1,
    replay_guard: &RpcReplayGuardV1,
    now_unix_ms: u64,
) -> Result<(), RpcAuthError> {
    server.key.validate()?;
    if challenge.schema != "ag.local-rpc.server-challenge.v1" {
        return Err(RpcAuthError::Schema);
    }
    if challenge.protocol_version != ProtocolVersionV1::current() {
        return Err(RpcAuthError::ProtocolVersion);
    }
    let proof = &challenge.authentication;
    require_direction(proof.direction, RpcDirectionV1::ServerChallenge)?;
    require_signer(&proof.signer_principal, &proof.signer_key_id, server)?;
    if proof.audience_principal != *local_signer.principal()
        || proof.audience_key_id != *local_signer.key_id()
    {
        return Err(RpcAuthError::AudienceMismatch);
    }
    verify_signature(
        &server.key.public_key,
        &challenge_message(challenge)?,
        &proof.signature,
    )?;
    replay_guard.check_and_record(
        ReplayObservationV1 {
            signer: &proof.signer_principal,
            key_id: &proof.signer_key_id,
            direction: proof.direction,
            nonce: &proof.nonce,
            issued_at_unix_ms: proof.issued_at_unix_ms,
            maximum_clock_skew_ms: server.key.maximum_clock_skew_ms,
        },
        now_unix_ms,
    )
}

/// Verifies a request against the exact challenge issued on this connection.
pub(crate) fn verify_signed_request<T: Serialize>(
    signed: &SignedRequestEnvelopeV1<T>,
    challenge: &SignedServerChallengeV1,
    caller: &RpcPeerEnrollmentV1,
    local_signer: &RpcSignerV1,
    replay_guard: &RpcReplayGuardV1,
    now_unix_ms: u64,
) -> Result<(), RpcAuthError> {
    caller.key.validate()?;
    if signed.schema != "ag.local-rpc.signed-request.v1" {
        return Err(RpcAuthError::Schema);
    }
    signed.request.validate()?;
    let proof = &signed.authentication;
    require_direction(proof.direction, RpcDirectionV1::Request)?;
    require_signer(&proof.signer_principal, &proof.signer_key_id, caller)?;
    if proof.audience_principal != *local_signer.principal()
        || proof.audience_key_id != *local_signer.key_id()
    {
        return Err(RpcAuthError::AudienceMismatch);
    }
    let challenge_digest = canonical_json_digest("ag-local-rpc-server-challenge-v1", challenge)?;
    if proof.challenge_digest != challenge_digest {
        return Err(RpcAuthError::ChallengeMismatch);
    }
    verify_signature(
        &caller.key.public_key,
        &request_message(signed)?,
        &proof.signature,
    )?;
    replay_guard.check_and_record(
        ReplayObservationV1 {
            signer: &proof.signer_principal,
            key_id: &proof.signer_key_id,
            direction: proof.direction,
            nonce: &proof.nonce,
            issued_at_unix_ms: proof.issued_at_unix_ms,
            maximum_clock_skew_ms: caller.key.maximum_clock_skew_ms,
        },
        now_unix_ms,
    )
}

/// Verifies an original caller-to-governor exchange forwarded through an
/// independently authenticated governor connection.
///
/// This is the end-to-end proposer proof used by the effect membrane. The
/// downstream verifier enrolls both the governor which issued the challenge
/// and the original proposer which signed the request. It therefore need not
/// trust the governor to restate proposer identity.
///
/// # Errors
///
/// Returns an error for any schema, version, direction, signer, audience,
/// challenge, signature, freshness, or replay mismatch.
pub fn verify_forwarded_signed_request<T: Serialize>(
    challenge: &SignedServerChallengeV1,
    signed: &SignedRequestEnvelopeV1<T>,
    governor: &RpcPeerEnrollmentV1,
    proposer: &RpcPeerEnrollmentV1,
    replay_guard: &RpcReplayGuardV1,
    now_unix_ms: u64,
) -> Result<VerifiedRpcPrincipalV1, RpcAuthError> {
    let verified = verify_forwarded_signed_request_bindings(challenge, signed, governor, proposer)?;
    record_forwarded_signed_request_freshness(
        challenge,
        signed,
        governor,
        proposer,
        replay_guard,
        now_unix_ms,
    )?;
    Ok(verified)
}

/// Verifies the immutable cryptographic and protocol bindings of a forwarded
/// caller-to-governor exchange without treating it as a new use.
///
/// This deliberately does not check freshness or mutate replay state. The
/// effect broker uses it only to locate an already committed submission whose
/// durable record contains the exact same proof. A proof which does not match
/// such a record must pass [`record_forwarded_signed_request_freshness`]
/// before it can create any state.
///
/// # Errors
///
/// Returns an error for any schema, version, direction, signer, audience,
/// challenge, or signature mismatch.
pub(crate) fn verify_forwarded_signed_request_bindings<T: Serialize>(
    challenge: &SignedServerChallengeV1,
    signed: &SignedRequestEnvelopeV1<T>,
    governor: &RpcPeerEnrollmentV1,
    proposer: &RpcPeerEnrollmentV1,
) -> Result<VerifiedRpcPrincipalV1, RpcAuthError> {
    governor.key.validate()?;
    proposer.key.validate()?;
    if challenge.schema != "ag.local-rpc.server-challenge.v1"
        || signed.schema != "ag.local-rpc.signed-request.v1"
    {
        return Err(RpcAuthError::Schema);
    }
    if challenge.protocol_version != ProtocolVersionV1::current() {
        return Err(RpcAuthError::ProtocolVersion);
    }
    signed.request.validate()?;

    let challenge_proof = &challenge.authentication;
    require_direction(challenge_proof.direction, RpcDirectionV1::ServerChallenge)?;
    require_signer(
        &challenge_proof.signer_principal,
        &challenge_proof.signer_key_id,
        governor,
    )?;
    if challenge_proof.audience_principal != proposer.principal
        || challenge_proof.audience_key_id != proposer.key.key_id
    {
        return Err(RpcAuthError::AudienceMismatch);
    }
    verify_signature(
        &governor.key.public_key,
        &challenge_message(challenge)?,
        &challenge_proof.signature,
    )?;

    let request_proof = &signed.authentication;
    require_direction(request_proof.direction, RpcDirectionV1::Request)?;
    require_signer(
        &request_proof.signer_principal,
        &request_proof.signer_key_id,
        proposer,
    )?;
    if request_proof.audience_principal != governor.principal
        || request_proof.audience_key_id != governor.key.key_id
    {
        return Err(RpcAuthError::AudienceMismatch);
    }
    let challenge_digest = canonical_json_digest("ag-local-rpc-server-challenge-v1", challenge)?;
    if request_proof.challenge_digest != challenge_digest {
        return Err(RpcAuthError::ChallengeMismatch);
    }
    verify_signature(
        &proposer.key.public_key,
        &request_message(signed)?,
        &request_proof.signature,
    )?;

    Ok(VerifiedRpcPrincipalV1 {
        principal: proposer.principal.clone(),
        key_id: proposer.key.key_id.clone(),
    })
}

/// Applies freshness and one-use replay accounting to a cryptographically
/// verified forwarded exchange.
///
/// Callers must first invoke [`verify_forwarded_signed_request_bindings`].
/// Keeping this stateful step separate lets effectd return an exact durable
/// result for the exact proof which originally created it, while every new
/// proof still consumes replay entries before any mutation.
///
/// # Errors
///
/// Returns an error when either proof is stale, replayed, or cannot be
/// recorded atomically.
pub(crate) fn record_forwarded_signed_request_freshness<T>(
    challenge: &SignedServerChallengeV1,
    signed: &SignedRequestEnvelopeV1<T>,
    governor: &RpcPeerEnrollmentV1,
    proposer: &RpcPeerEnrollmentV1,
    replay_guard: &RpcReplayGuardV1,
    now_unix_ms: u64,
) -> Result<(), RpcAuthError> {
    let challenge_proof = &challenge.authentication;
    let request_proof = &signed.authentication;

    replay_guard.check_and_record_all(
        &[
            ReplayObservationV1 {
                signer: &challenge_proof.signer_principal,
                key_id: &challenge_proof.signer_key_id,
                direction: challenge_proof.direction,
                nonce: &challenge_proof.nonce,
                issued_at_unix_ms: challenge_proof.issued_at_unix_ms,
                maximum_clock_skew_ms: governor.key.maximum_clock_skew_ms,
            },
            ReplayObservationV1 {
                signer: &request_proof.signer_principal,
                key_id: &request_proof.signer_key_id,
                direction: request_proof.direction,
                nonce: &request_proof.nonce,
                issued_at_unix_ms: request_proof.issued_at_unix_ms,
                maximum_clock_skew_ms: proposer.key.maximum_clock_skew_ms,
            },
        ],
        now_unix_ms,
    )
}

/// Verifies a response against the exact request sent on this connection.
pub(crate) fn verify_signed_response<T: Serialize, U: Serialize>(
    signed: &SignedResponseEnvelopeV1<T>,
    request: &SignedRequestEnvelopeV1<U>,
    server: &RpcPeerEnrollmentV1,
    local_signer: &RpcSignerV1,
    replay_guard: &RpcReplayGuardV1,
    now_unix_ms: u64,
) -> Result<(), RpcAuthError> {
    server.key.validate()?;
    if signed.schema != "ag.local-rpc.signed-response.v1" {
        return Err(RpcAuthError::Schema);
    }
    signed.response.validate_echo(&request.request)?;
    let proof = &signed.authentication;
    require_direction(proof.direction, RpcDirectionV1::Response)?;
    require_signer(&proof.signer_principal, &proof.signer_key_id, server)?;
    if proof.audience_principal != *local_signer.principal()
        || proof.audience_key_id != *local_signer.key_id()
    {
        return Err(RpcAuthError::AudienceMismatch);
    }
    let expected_request_digest = canonical_json_digest("ag-local-rpc-signed-request-v1", request)?;
    if proof.signed_request_digest != expected_request_digest
        || proof.request_nonce != request.authentication.nonce
    {
        return Err(RpcAuthError::RequestBindingMismatch);
    }
    let response_body_digest =
        canonical_json_digest("ag-local-rpc-response-body-v1", &signed.response.body)?;
    if proof.response_body_digest != response_body_digest {
        return Err(RpcAuthError::ResponseBodyDigestMismatch);
    }
    verify_signature(
        &server.key.public_key,
        &response_message(signed)?,
        &proof.signature,
    )?;
    replay_guard.check_and_record(
        ReplayObservationV1 {
            signer: &proof.signer_principal,
            key_id: &proof.signer_key_id,
            direction: proof.direction,
            nonce: &proof.nonce,
            issued_at_unix_ms: proof.issued_at_unix_ms,
            maximum_clock_skew_ms: server.key.maximum_clock_skew_ms,
        },
        now_unix_ms,
    )
}

fn require_direction(actual: RpcDirectionV1, expected: RpcDirectionV1) -> Result<(), RpcAuthError> {
    if actual != expected {
        return Err(RpcAuthError::WrongDirection);
    }
    Ok(())
}

fn require_signer(
    principal: &Digest,
    key_id: &RpcKeyIdV1,
    expected: &RpcPeerEnrollmentV1,
) -> Result<(), RpcAuthError> {
    if principal != &expected.principal || key_id != &expected.key.key_id {
        return Err(RpcAuthError::SignerMismatch);
    }
    Ok(())
}

fn challenge_message(challenge: &SignedServerChallengeV1) -> Result<Vec<u8>, RpcAuthError> {
    let proof = &challenge.authentication;
    signature_message(&ChallengeStatementV1 {
        context: "ag.local-rpc.challenge-signature.v1",
        protocol_version: &challenge.protocol_version,
        signer_principal: &proof.signer_principal,
        signer_key_id: &proof.signer_key_id,
        audience_principal: &proof.audience_principal,
        audience_key_id: &proof.audience_key_id,
        direction: proof.direction,
        nonce: &proof.nonce,
        issued_at_unix_ms: proof.issued_at_unix_ms,
    })
}

fn request_message<T: Serialize>(
    signed: &SignedRequestEnvelopeV1<T>,
) -> Result<Vec<u8>, RpcAuthError> {
    let proof = &signed.authentication;
    signature_message(&RequestStatementV1 {
        context: "ag.local-rpc.request-signature.v1",
        protocol_version: &signed.request.echo.protocol_version,
        request_id: &signed.request.echo.request_id,
        request_body_digest: &signed.request.echo.request_digest,
        signer_principal: &proof.signer_principal,
        signer_key_id: &proof.signer_key_id,
        audience_principal: &proof.audience_principal,
        audience_key_id: &proof.audience_key_id,
        direction: proof.direction,
        nonce: &proof.nonce,
        issued_at_unix_ms: proof.issued_at_unix_ms,
        challenge_digest: &proof.challenge_digest,
    })
}

fn response_message<T: Serialize>(
    signed: &SignedResponseEnvelopeV1<T>,
) -> Result<Vec<u8>, RpcAuthError> {
    let proof = &signed.authentication;
    signature_message(&ResponseStatementV1 {
        context: "ag.local-rpc.response-signature.v1",
        protocol_version: &signed.response.echo.protocol_version,
        request_id: &signed.response.echo.request_id,
        request_body_digest: &signed.response.echo.request_digest,
        response_body_digest: &proof.response_body_digest,
        signer_principal: &proof.signer_principal,
        signer_key_id: &proof.signer_key_id,
        audience_principal: &proof.audience_principal,
        audience_key_id: &proof.audience_key_id,
        direction: proof.direction,
        nonce: &proof.nonce,
        issued_at_unix_ms: proof.issued_at_unix_ms,
        signed_request_digest: &proof.signed_request_digest,
        request_nonce: &proof.request_nonce,
    })
}

fn signature_message<T: Serialize>(statement: &T) -> Result<Vec<u8>, RpcAuthError> {
    let statement = canonical_json(statement)?;
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + statement.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&statement);
    Ok(message)
}

fn verify_signature(
    key: &RpcPublicKeyV1,
    message: &[u8],
    signature: &RpcSignatureV1,
) -> Result<(), RpcAuthError> {
    UnparsedPublicKey::new(&ED25519, key.as_bytes())
        .verify(message, signature.as_bytes())
        .map_err(|_| RpcAuthError::SignatureInvalid)
}

/// Cryptographic local-RPC failures. Variants never contain private key bytes.
#[derive(Debug, Error)]
pub enum RpcAuthError {
    /// Key identifier is malformed.
    #[error("invalid RPC key identifier")]
    InvalidKeyId,
    /// Base64url data is malformed.
    #[error("invalid RPC base64url value")]
    InvalidBase64,
    /// Encoded key, nonce, or signature has the wrong length.
    #[error("invalid RPC encoded value length")]
    InvalidEncodedLength,
    /// Base64url representation is not canonical and unpadded.
    #[error("non-canonical RPC base64url value")]
    NonCanonicalBase64,
    /// Credential path is not an absolute normalized path.
    #[error("unsafe RPC signing credential path")]
    UnsafeCredentialPath,
    /// Credential file cannot be opened or read.
    #[error("cannot read RPC signing credential: {source}")]
    CredentialIo {
        /// Underlying I/O error; no credential bytes are included.
        source: std::io::Error,
    },
    /// Credential metadata or length is unsafe.
    #[error("RPC signing credential is not a protected regular file")]
    InvalidCredentialFile,
    /// Credential is not a valid Ed25519 PKCS#8 v2 private key.
    #[error("RPC signing credential is not a valid Ed25519 PKCS#8 v2 key")]
    InvalidPrivateKey,
    /// Credential public half differs from root-owned local policy.
    #[error("RPC signing credential does not match its enrolled public key")]
    CredentialPublicKeyMismatch,
    /// Secure random generation failed.
    #[error("secure RPC nonce generation failed")]
    Randomness,
    /// Clock cannot supply Unix epoch milliseconds.
    #[error("RPC authentication clock failed")]
    Clock,
    /// Clock-skew policy is zero or unreasonably large.
    #[error("invalid RPC clock-skew policy")]
    InvalidClockSkewPolicy,
    /// Message timestamp is expired or too far in the future.
    #[error("RPC authentication timestamp is outside the accepted window")]
    TimestampOutsideWindow,
    /// Replay guard capacity must be non-zero.
    #[error("RPC replay capacity must be non-zero")]
    InvalidReplayCapacity,
    /// Replay state lock is unavailable.
    #[error("RPC replay state is unavailable")]
    ReplayState,
    /// An already accepted nonce was presented again.
    #[error("replayed RPC authentication nonce")]
    Replay,
    /// Replay guard is full of unexpired entries and fails closed.
    #[error("RPC replay capacity is exhausted")]
    ReplayCapacityExhausted,
    /// Wrapper schema is not the exact expected family.
    #[error("unexpected signed RPC schema")]
    Schema,
    /// Protocol version is not the current exact version.
    #[error("unexpected signed RPC protocol version")]
    ProtocolVersion,
    /// Signed direction is invalid for the wrapper.
    #[error("signed RPC direction does not match the message kind")]
    WrongDirection,
    /// Signer principal or key ID differs from enrollment policy.
    #[error("signed RPC signer is not the enrolled peer")]
    SignerMismatch,
    /// Proof names a different target principal or key.
    #[error("signed RPC audience does not match the local identity")]
    AudienceMismatch,
    /// Request was not signed for the exact challenge on this connection.
    #[error("signed RPC request does not bind the connection challenge")]
    ChallengeMismatch,
    /// Response does not bind the exact signed request.
    #[error("signed RPC response does not bind the exact request")]
    RequestBindingMismatch,
    /// Response body differs from its authenticated digest.
    #[error("signed RPC response body digest mismatch")]
    ResponseBodyDigestMismatch,
    /// Ed25519 verification failed.
    #[error("signed RPC Ed25519 verification failed")]
    SignatureInvalid,
    /// Existing strict protocol validation failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde::{Deserialize, Serialize};

    use super::*;

    const NOW: u64 = 1_900_000_000_000;

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ping {
        value: u64,
    }

    fn signer(label: &str) -> RpcSignerV1 {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        RpcSignerV1::from_pkcs8_for_test(
            Digest::hash_domain("test-principal-v1", label.as_bytes()),
            RpcKeyIdV1::new(format!("{label}-key")).expect("key id"),
            pkcs8.as_ref(),
        )
        .expect("signer")
    }

    #[test]
    fn ephemeral_candidate_key_round_trips_only_through_admitted_bytes() {
        let principal = Digest::hash_bytes(b"ephemeral-worker-principal");
        let key_id = RpcKeyIdV1::new("worker-candidate.v1").expect("key ID");
        let (generated, material) =
            RpcSignerV1::generate_ephemeral_candidate_ingress(principal.clone(), key_id.clone())
                .expect("generate candidate key");
        let credential_limit =
            usize::try_from(MAX_CREDENTIAL_BYTES).expect("credential limit fits usize");
        assert!(material.byte_length() > 0);
        assert!(material.byte_length() <= credential_limit);

        let mut admitted = Vec::new();
        material.write_to(&mut admitted).expect("write admitted FD");
        let mut reader = std::io::Cursor::new(admitted);
        let loaded =
            RpcSignerV1::from_ephemeral_candidate_ingress_reader(principal, key_id, &mut reader)
                .expect("load candidate key");
        assert_eq!(
            generated.enrollment(30_000).expect("generated enrollment"),
            loaded.enrollment(30_000).expect("loaded enrollment")
        );

        let mut oversized = std::io::Cursor::new(vec![0_u8; credential_limit + 1]);
        assert!(matches!(
            RpcSignerV1::from_ephemeral_candidate_ingress_reader(
                Digest::hash_bytes(b"other-worker"),
                RpcKeyIdV1::new("other-worker.v1").expect("key ID"),
                &mut oversized,
            ),
            Err(RpcAuthError::InvalidCredentialFile)
        ));
    }

    #[test]
    fn candidate_ingress_key_identity_excludes_principal_but_binds_key_policy() {
        let original = signer("candidate-key")
            .enrollment(30_000)
            .expect("candidate enrollment")
            .key;
        let identity = candidate_ingress_key_identity(&original).expect("candidate key identity");

        let mut another_principal = original.clone();
        another_principal.principal = Digest::hash_bytes(b"principal-computed-after-key-binding");
        assert_eq!(
            identity,
            candidate_ingress_key_identity(&another_principal).expect("acyclic identity")
        );

        let mut another_key_id = original.clone();
        another_key_id.key_id = RpcKeyIdV1::new("candidate-key-rotated").expect("key ID");
        assert_ne!(
            identity,
            candidate_ingress_key_identity(&another_key_id).expect("key-id identity")
        );

        let mut another_public_key = original.clone();
        another_public_key.public_key = signer("substituted-candidate-key")
            .enrollment(30_000)
            .expect("substitute enrollment")
            .key
            .public_key;
        assert_ne!(
            identity,
            candidate_ingress_key_identity(&another_public_key).expect("public-key identity")
        );

        let mut another_skew = original;
        another_skew.maximum_clock_skew_ms = 30_001;
        assert_ne!(
            identity,
            candidate_ingress_key_identity(&another_skew).expect("skew identity")
        );
    }

    #[test]
    fn credential_loader_rejects_weak_mode_and_symlink() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let credential = directory.path().join("rpc-key.pk8");
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        fs::write(&credential, pkcs8.as_ref()).expect("write credential");
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))
            .expect("protect credential");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let public_key: [u8; ED25519_PUBLIC_KEY_LEN] =
            pair.public_key().as_ref().try_into().expect("public key");
        let config = RpcSigningIdentityConfigV1 {
            principal: Digest::hash_bytes(b"credential-test-principal"),
            key_id: RpcKeyIdV1::new("credential-test-key").expect("key id"),
            public_key: RpcPublicKeyV1::from_bytes(public_key),
            private_key_credential: credential.clone(),
        };
        let repeated_separator = RpcSigningIdentityConfigV1 {
            private_key_credential: PathBuf::from(format!(
                "//{}",
                credential
                    .strip_prefix("/")
                    .expect("absolute test path")
                    .display()
            )),
            ..config.clone()
        };
        assert!(matches!(
            repeated_separator.validate(),
            Err(RpcAuthError::UnsafeCredentialPath)
        ));
        RpcSignerV1::from_systemd_credential(&config).expect("protected credential loads");

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o644))
            .expect("weaken credential");
        assert!(matches!(
            RpcSignerV1::from_systemd_credential(&config),
            Err(RpcAuthError::InvalidCredentialFile)
        ));

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).expect("restore mode");
        let hard_link = directory.path().join("rpc-key-hard-link.pk8");
        fs::hard_link(&credential, &hard_link).expect("hard link");
        let linked_inode = RpcSigningIdentityConfigV1 {
            private_key_credential: hard_link.clone(),
            ..config.clone()
        };
        assert!(matches!(
            RpcSignerV1::from_systemd_credential(&linked_inode),
            Err(RpcAuthError::InvalidCredentialFile)
        ));
        fs::remove_file(&hard_link).expect("remove hard link");

        let link = directory.path().join("rpc-key-link.pk8");
        symlink(&credential, &link).expect("symlink");
        let linked = RpcSigningIdentityConfigV1 {
            private_key_credential: link,
            ..config
        };
        assert!(matches!(
            RpcSignerV1::from_systemd_credential(&linked),
            Err(RpcAuthError::CredentialIo { .. })
        ));
    }

    fn exchange() -> (
        RpcSignerV1,
        RpcSignerV1,
        RpcPeerEnrollmentV1,
        RpcPeerEnrollmentV1,
        SignedServerChallengeV1,
        SignedRequestEnvelopeV1<Ping>,
        SignedResponseEnvelopeV1<Ping>,
    ) {
        let server = signer("server");
        let client = signer("client");
        let server_enrollment = server.enrollment(30_000).expect("server enrollment");
        let client_enrollment = client.enrollment(30_000).expect("client enrollment");
        let challenge = server
            .issue_challenge(&client_enrollment, NOW)
            .expect("challenge");
        let request = RequestEnvelopeV1::new(
            ag_protocol::RequestId::new("request-1").expect("id"),
            Ping { value: 7 },
        )
        .expect("request");
        let signed_request = client
            .sign_request(request, &challenge, NOW)
            .expect("signed request");
        let signed_response = server
            .sign_response(&signed_request, Ping { value: 8 }, NOW)
            .expect("signed response");
        (
            server,
            client,
            server_enrollment,
            client_enrollment,
            challenge,
            signed_request,
            signed_response,
        )
    }

    #[test]
    fn valid_proofs_bind_all_three_frames() {
        let (server, client, server_policy, client_policy, challenge, request, response) =
            exchange();
        let client_replay = RpcReplayGuardV1::new(8).expect("guard");
        verify_server_challenge(&challenge, &server_policy, &client, &client_replay, NOW)
            .expect("challenge verifies");
        let server_replay = RpcReplayGuardV1::new(8).expect("guard");
        verify_signed_request(
            &request,
            &challenge,
            &client_policy,
            &server,
            &server_replay,
            NOW,
        )
        .expect("request verifies");
        verify_signed_response(
            &response,
            &request,
            &server_policy,
            &client,
            &client_replay,
            NOW,
        )
        .expect("response verifies");
    }

    #[test]
    fn tampered_request_body_is_rejected() {
        let (server, _, _, client_policy, challenge, mut request, _) = exchange();
        request.request.body.value = 99;
        let result = verify_signed_request(
            &request,
            &challenge,
            &client_policy,
            &server,
            &RpcReplayGuardV1::new(8).expect("guard"),
            NOW,
        );
        assert!(matches!(result, Err(RpcAuthError::Protocol(_))));
    }

    #[test]
    fn replay_is_rejected_after_one_valid_verification() {
        let (server, _, _, client_policy, challenge, request, _) = exchange();
        let guard = RpcReplayGuardV1::new(8).expect("guard");
        verify_signed_request(&request, &challenge, &client_policy, &server, &guard, NOW)
            .expect("first request");
        assert!(matches!(
            verify_signed_request(&request, &challenge, &client_policy, &server, &guard, NOW),
            Err(RpcAuthError::Replay)
        ));
    }

    #[test]
    fn forwarded_request_retains_end_to_end_proposer_identity() {
        let (_, _, governor, proposer, challenge, request, _) = exchange();
        let guard = RpcReplayGuardV1::new(8).expect("guard");
        let verified = verify_forwarded_signed_request(
            &challenge, &request, &governor, &proposer, &guard, NOW,
        )
        .expect("forwarded exchange verifies");
        assert_eq!(verified.principal, proposer.principal);
        assert_eq!(verified.key_id, proposer.key.key_id);
        assert!(matches!(
            verify_forwarded_signed_request(
                &challenge, &request, &governor, &proposer, &guard, NOW,
            ),
            Err(RpcAuthError::Replay)
        ));

        let impostor = signer("forwarded-impostor")
            .enrollment(30_000)
            .expect("impostor enrollment");
        assert!(
            verify_forwarded_signed_request(
                &challenge,
                &request,
                &governor,
                &impostor,
                &RpcReplayGuardV1::new(8).expect("guard"),
                NOW,
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_direction_and_wrong_key_are_rejected() {
        let (server, _, _, client_policy, challenge, mut request, _) = exchange();
        request.authentication.direction = RpcDirectionV1::Response;
        assert!(matches!(
            verify_signed_request(
                &request,
                &challenge,
                &client_policy,
                &server,
                &RpcReplayGuardV1::new(8).expect("guard"),
                NOW,
            ),
            Err(RpcAuthError::WrongDirection)
        ));

        let (_, impostor, _, _, _, _, _) = exchange();
        let impostor_policy = impostor.enrollment(30_000).expect("enrollment");
        request.authentication.direction = RpcDirectionV1::Request;
        assert!(matches!(
            verify_signed_request(
                &request,
                &challenge,
                &impostor_policy,
                &server,
                &RpcReplayGuardV1::new(8).expect("guard"),
                NOW,
            ),
            Err(RpcAuthError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_response_echo_and_body_are_rejected() {
        let (_, client, server_policy, _, _, request, mut response) = exchange();
        response.response.echo.request_id = ag_protocol::RequestId::new("different").expect("id");
        assert!(matches!(
            verify_signed_response(
                &response,
                &request,
                &server_policy,
                &client,
                &RpcReplayGuardV1::new(8).expect("guard"),
                NOW,
            ),
            Err(RpcAuthError::Protocol(ProtocolError::ResponseEchoMismatch))
        ));

        let (_, client, server_policy, _, _, request, mut response) = exchange();
        response.response.body.value = 123;
        assert!(matches!(
            verify_signed_response(
                &response,
                &request,
                &server_policy,
                &client,
                &RpcReplayGuardV1::new(8).expect("guard"),
                NOW,
            ),
            Err(RpcAuthError::ResponseBodyDigestMismatch)
        ));
    }

    #[test]
    fn expired_and_future_proofs_are_rejected() {
        let (server, _, _, client_policy, challenge, request, _) = exchange();
        let guard = RpcReplayGuardV1::new(8).expect("guard");
        assert!(matches!(
            verify_signed_request(
                &request,
                &challenge,
                &client_policy,
                &server,
                &guard,
                NOW + 30_001,
            ),
            Err(RpcAuthError::TimestampOutsideWindow)
        ));
        assert!(matches!(
            verify_signed_request(
                &request,
                &challenge,
                &client_policy,
                &server,
                &guard,
                NOW - 30_001,
            ),
            Err(RpcAuthError::TimestampOutsideWindow)
        ));
    }
}
