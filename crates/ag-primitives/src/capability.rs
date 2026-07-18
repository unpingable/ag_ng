//! Session-bound inference capabilities.
//!
//! An [`InferenceCapabilityV1`] authorizes no governed effect. It permits one
//! exact active worker principal to ask `ag-providerd` for inference within a
//! closed provider envelope and cumulative budget. Validation always requires
//! live epoch, peer, session, revocation, lifecycle, clock, and usage context;
//! possession of serialized capability bytes is insufficient.

use core::fmt;
use core::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    AuthorityDomainId, Digest, EpochId, JcsDocument, LifecycleNonce, PrincipalId, ProjectId,
    SessionId,
};

const MAX_ENVELOPE_NAME_LENGTH: usize = 192;

macro_rules! envelope_name_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validates and constructs a ", $description, ".")]
            ///
            /// # Errors
            ///
            /// Returns an error for an empty, overlong, or noncanonical name.
            pub fn new(value: impl Into<String>) -> Result<Self, CapabilityDefinitionError> {
                let value = value.into();
                validate_envelope_name(stringify!($name), &value)?;
                Ok(Self(value))
            }

            #[doc = concat!("Parses a ", $description, ".")]
            ///
            /// # Errors
            ///
            /// Returns an error unless `value` is a canonical name.
            pub fn parse(value: &str) -> Result<Self, CapabilityDefinitionError> {
                Self::new(value)
            }

            /// Returns the canonical configured identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = CapabilityDefinitionError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct NameVisitor;

                impl Visitor<'_> for NameVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a canonical inference-envelope identifier")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::parse(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(NameVisitor)
            }
        }
    };
}

envelope_name_type!(
    ProviderEndpointId,
    "configured provider endpoint identifier"
);
envelope_name_type!(ModelId, "configured provider model identifier");
envelope_name_type!(InferenceMethodId, "configured inference method identifier");

/// The exact provider/model/protocol envelope admitted for a capability.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceEnvelopeV1 {
    /// Root-configured endpoint identity, not an arbitrary URL.
    pub endpoint: ProviderEndpointId,
    /// Root-configured model identity.
    pub model: ModelId,
    /// Closed provider operation/method identity.
    pub method: InferenceMethodId,
    /// Exact adapter wire/protocol revision.
    pub protocol_digest: Digest,
}

/// Maximum cumulative inference use admitted by one capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceBudgetV1 {
    /// Maximum number of provider requests.
    pub requests: u64,
    /// Maximum credential-free request bytes.
    pub input_bytes: u64,
    /// Maximum complete provider response/event bytes.
    pub output_bytes: u64,
    /// Maximum provider cost in deployment-defined integer microunits.
    pub cost_microunits: u64,
}

impl InferenceBudgetV1 {
    /// Validates that the capability can authorize at least one request.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDefinitionError::ZeroRequestBudget`] when no request
    /// could be admitted.
    pub const fn validate(self) -> Result<(), CapabilityDefinitionError> {
        if self.requests == 0 {
            Err(CapabilityDefinitionError::ZeroRequestBudget)
        } else {
            Ok(())
        }
    }
}

/// Counted usage committed against an inference capability.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceUsageV1 {
    /// Counted provider requests.
    pub requests: u64,
    /// Counted credential-free request bytes.
    pub input_bytes: u64,
    /// Counted complete response/event bytes.
    pub output_bytes: u64,
    /// Counted cost in deployment-defined integer microunits.
    pub cost_microunits: u64,
}

impl InferenceUsageV1 {
    /// Adds usage with overflow checking.
    #[must_use]
    pub const fn checked_add(self, requested: Self) -> Option<Self> {
        let Some(requests) = self.requests.checked_add(requested.requests) else {
            return None;
        };
        let Some(input_bytes) = self.input_bytes.checked_add(requested.input_bytes) else {
            return None;
        };
        let Some(output_bytes) = self.output_bytes.checked_add(requested.output_bytes) else {
            return None;
        };
        let Some(cost_microunits) = self.cost_microunits.checked_add(requested.cost_microunits)
        else {
            return None;
        };
        Some(Self {
            requests,
            input_bytes,
            output_bytes,
            cost_microunits,
        })
    }

    const fn first_exceeded(self, budget: InferenceBudgetV1) -> Option<BudgetDimensionV1> {
        if self.requests > budget.requests {
            Some(BudgetDimensionV1::Requests)
        } else if self.input_bytes > budget.input_bytes {
            Some(BudgetDimensionV1::InputBytes)
        } else if self.output_bytes > budget.output_bytes {
            Some(BudgetDimensionV1::OutputBytes)
        } else if self.cost_microunits > budget.cost_microunits {
            Some(BudgetDimensionV1::CostMicrounits)
        } else {
            None
        }
    }
}

/// One exact, session-bound inference capability definition.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceCapabilityV1 {
    /// Installation authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Authority epoch; epoch changes invalidate the capability.
    pub epoch: EpochId,
    /// Governed project.
    pub project: ProjectId,
    /// Exact active session record.
    pub session_id: SessionId,
    /// Exact admitted session lifecycle.
    pub session_nonce: LifecycleNonce,
    /// Exact active worker peer principal.
    pub worker_principal: PrincipalId,
    /// Exact provider policy revision.
    pub provider_policy_digest: Digest,
    /// Closed provider/model/method/protocol envelope.
    pub envelope: InferenceEnvelopeV1,
    /// Maximum cumulative use.
    pub budget: InferenceBudgetV1,
    /// Inclusive beginning of the capability lifetime, Unix milliseconds.
    pub not_before_unix_ms: u64,
    /// Exclusive end of the capability lifetime, Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Issuance nonce preventing otherwise-identical capability aliasing.
    pub capability_nonce: LifecycleNonce,
}

impl InferenceCapabilityV1 {
    /// Constructs and intrinsically validates a capability.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDefinitionError`] for an empty lifetime or request
    /// budget.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_domain: AuthorityDomainId,
        epoch: EpochId,
        project: ProjectId,
        session_id: SessionId,
        session_nonce: LifecycleNonce,
        worker_principal: PrincipalId,
        provider_policy_digest: Digest,
        envelope: InferenceEnvelopeV1,
        budget: InferenceBudgetV1,
        not_before_unix_ms: u64,
        expires_at_unix_ms: u64,
        capability_nonce: LifecycleNonce,
    ) -> Result<Self, CapabilityDefinitionError> {
        let capability = Self {
            authority_domain,
            epoch,
            project,
            session_id,
            session_nonce,
            worker_principal,
            provider_policy_digest,
            envelope,
            budget,
            not_before_unix_ms,
            expires_at_unix_ms,
            capability_nonce,
        };
        capability.validate_definition()?;
        Ok(capability)
    }

    /// Validates intrinsic bounds independent from live session state.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDefinitionError`] for an empty lifetime or request
    /// budget.
    pub const fn validate_definition(&self) -> Result<(), CapabilityDefinitionError> {
        if self.not_before_unix_ms >= self.expires_at_unix_ms {
            return Err(CapabilityDefinitionError::InvalidLifetime);
        }
        self.budget.validate()
    }

    /// Returns the domain-separated digest of the exact capability definition.
    ///
    /// # Panics
    ///
    /// This cannot panic for a capability constructed through the public API:
    /// every field has a strict integer-only JCS representation.
    #[must_use]
    pub fn id(&self) -> InferenceCapabilityId {
        let document = JcsDocument::canonicalize(self)
            .expect("inference-capability schemas contain only strict JCS-compatible values");
        InferenceCapabilityId::new(Digest::hash_domain(
            "ag-ng/inference-capability/v1",
            document.as_bytes(),
        ))
    }

    /// Validates one proposed use against live, authenticated state.
    ///
    /// Successful validation returns a non-authoritative checked-use record.
    /// The provider store must commit `resulting_usage` with the request before
    /// dispatch so concurrent clients cannot spend the same remainder.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityUseError`] unless every definition, revocation,
    /// session, peer, epoch, clock, envelope, and cumulative budget check passes.
    pub fn validate_use(
        &self,
        context: &CapabilityUseContextV1,
    ) -> Result<ValidatedInferenceUseV1, CapabilityUseError> {
        self.validate_definition()?;

        if context.revocation_state != RevocationStateV1::NotRevoked {
            return Err(CapabilityUseError::Revoked);
        }
        if context.session_state != SessionLifecycleStateV1::Active {
            return Err(CapabilityUseError::SessionNotActive {
                state: context.session_state,
            });
        }
        if self.authority_domain != context.authority_domain {
            return Err(CapabilityUseError::AuthorityDomainMismatch);
        }
        if self.epoch != context.epoch {
            return Err(CapabilityUseError::EpochMismatch);
        }
        if self.project != context.project {
            return Err(CapabilityUseError::ProjectMismatch);
        }
        if self.session_id != context.session_id {
            return Err(CapabilityUseError::SessionMismatch);
        }
        if self.session_nonce != context.session_nonce {
            return Err(CapabilityUseError::SessionLifecycleMismatch);
        }
        if self.worker_principal != context.peer_principal {
            return Err(CapabilityUseError::PeerPrincipalMismatch);
        }
        if self.provider_policy_digest != context.provider_policy_digest {
            return Err(CapabilityUseError::ProviderPolicyMismatch);
        }
        if self.envelope != context.requested_envelope {
            return Err(CapabilityUseError::EnvelopeMismatch);
        }
        if context.now_unix_ms < self.not_before_unix_ms {
            return Err(CapabilityUseError::NotYetValid);
        }
        if context.now_unix_ms >= self.expires_at_unix_ms {
            return Err(CapabilityUseError::Expired);
        }
        if context.requested_usage.requests != 1 {
            return Err(CapabilityUseError::UseMustCountExactlyOneRequest);
        }

        let resulting_usage = context
            .committed_usage
            .checked_add(context.requested_usage)
            .ok_or(CapabilityUseError::UsageOverflow)?;
        if let Some(dimension) = resulting_usage.first_exceeded(self.budget) {
            return Err(CapabilityUseError::BudgetExceeded { dimension });
        }

        Ok(ValidatedInferenceUseV1 {
            capability_id: self.id(),
            worker_principal: self.worker_principal.clone(),
            session_id: self.session_id.clone(),
            session_nonce: self.session_nonce,
            envelope: self.envelope.clone(),
            resulting_usage,
            checked_at_unix_ms: context.now_unix_ms,
        })
    }
}

impl<'de> Deserialize<'de> for InferenceCapabilityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = InferenceCapabilityWire::deserialize(deserializer)?;
        Self::new(
            wire.authority_domain,
            wire.epoch,
            wire.project,
            wire.session_id,
            wire.session_nonce,
            wire.worker_principal,
            wire.provider_policy_digest,
            wire.envelope,
            wire.budget,
            wire.not_before_unix_ms,
            wire.expires_at_unix_ms,
            wire.capability_nonce,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceCapabilityWire {
    authority_domain: AuthorityDomainId,
    epoch: EpochId,
    project: ProjectId,
    session_id: SessionId,
    session_nonce: LifecycleNonce,
    worker_principal: PrincipalId,
    provider_policy_digest: Digest,
    envelope: InferenceEnvelopeV1,
    budget: InferenceBudgetV1,
    not_before_unix_ms: u64,
    expires_at_unix_ms: u64,
    capability_nonce: LifecycleNonce,
}

/// Digest identity of an exact inference capability definition.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InferenceCapabilityId(Digest);

impl InferenceCapabilityId {
    /// Wraps a domain-separated capability digest.
    #[must_use]
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    /// Returns the exact capability digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Display for InferenceCapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Live facts required to validate one capability use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityUseContextV1 {
    /// Currently active authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Currently active epoch.
    pub epoch: EpochId,
    /// Project authenticated for this connection.
    pub project: ProjectId,
    /// Current session record.
    pub session_id: SessionId,
    /// Current session lifecycle nonce.
    pub session_nonce: LifecycleNonce,
    /// Principal resolved from the live peer connection.
    pub peer_principal: PrincipalId,
    /// Currently configured provider-policy revision.
    pub provider_policy_digest: Digest,
    /// Exact requested endpoint/model/method/protocol envelope.
    pub requested_envelope: InferenceEnvelopeV1,
    /// Usage already committed by the provider store.
    pub committed_usage: InferenceUsageV1,
    /// Usage reserved for this one request.
    pub requested_usage: InferenceUsageV1,
    /// Trusted daemon clock observation, Unix milliseconds.
    pub now_unix_ms: u64,
    /// Current durable session state.
    pub session_state: SessionLifecycleStateV1,
    /// Current durable revocation state.
    pub revocation_state: RevocationStateV1,
}

/// Durable session state relevant to capability spending.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycleStateV1 {
    /// The session is active and may spend a capability.
    Active,
    /// Cancellation has begun; no new inference is permitted.
    Cancelling,
    /// The session reached a terminal outcome.
    Terminal,
}

/// Durable capability revocation state.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RevocationStateV1 {
    /// No revocation has been committed.
    NotRevoked,
    /// Revocation is durable and terminal for this capability.
    Revoked {
        /// Time at which revocation committed, Unix milliseconds.
        revoked_at_unix_ms: u64,
        /// Digest of the structured revocation reason/evidence.
        reason_digest: Digest,
    },
}

/// A successful live capability check.
///
/// This value is a check result, not bearer authority. `ag-providerd` must
/// atomically reserve the resulting usage and independently retain the live
/// peer/session binding before dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedInferenceUseV1 {
    /// Exact capability definition used.
    pub capability_id: InferenceCapabilityId,
    /// Authenticated worker peer.
    pub worker_principal: PrincipalId,
    /// Exact session record.
    pub session_id: SessionId,
    /// Exact session lifecycle.
    pub session_nonce: LifecycleNonce,
    /// Exact provider request envelope.
    pub envelope: InferenceEnvelopeV1,
    /// Usage that must be committed before dispatch.
    pub resulting_usage: InferenceUsageV1,
    /// Trusted check time.
    pub checked_at_unix_ms: u64,
}

/// Inference budget dimension used in refusal evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimensionV1 {
    /// Request count.
    Requests,
    /// Request/input bytes.
    InputBytes,
    /// Response/event bytes.
    OutputBytes,
    /// Provider cost microunits.
    CostMicrounits,
}

/// An intrinsically invalid capability definition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CapabilityDefinitionError {
    /// Capability lifetime must be a nonempty half-open interval.
    #[error("capability lifetime must satisfy not_before < expires_at")]
    InvalidLifetime,
    /// A capability that admits no request is not issued.
    #[error("capability request budget must be nonzero")]
    ZeroRequestBudget,
    /// A provider envelope identifier is empty.
    #[error("{kind} must not be empty")]
    EmptyName {
        /// Identifier family.
        kind: &'static str,
    },
    /// A provider envelope identifier exceeds the protocol bound.
    #[error("{kind} exceeds {maximum} bytes (got {actual})")]
    NameTooLong {
        /// Identifier family.
        kind: &'static str,
        /// Maximum admitted length.
        maximum: usize,
        /// Actual length.
        actual: usize,
    },
    /// A provider identifier is not canonical.
    #[error("{kind} is not a canonical lowercase inference identifier")]
    NonCanonicalName {
        /// Identifier family.
        kind: &'static str,
    },
}

/// A failed live inference-capability check.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CapabilityUseError {
    /// Capability definition itself is malformed.
    #[error(transparent)]
    InvalidDefinition(#[from] CapabilityDefinitionError),
    /// Durable revocation has occurred.
    #[error("inference capability is revoked")]
    Revoked,
    /// Cancellation or terminal session state burns usability immediately.
    #[error("session is not active ({state:?})")]
    SessionNotActive {
        /// Observed state.
        state: SessionLifecycleStateV1,
    },
    /// Active installation domain differs.
    #[error("inference capability authority domain does not match")]
    AuthorityDomainMismatch,
    /// Active epoch differs.
    #[error("inference capability epoch does not match")]
    EpochMismatch,
    /// Authenticated project differs.
    #[error("inference capability project does not match")]
    ProjectMismatch,
    /// Session record differs.
    #[error("inference capability session does not match")]
    SessionMismatch,
    /// A recycled session ID has a different lifecycle nonce.
    #[error("inference capability session lifecycle does not match")]
    SessionLifecycleMismatch,
    /// The live peer is not the worker to which the capability was issued.
    #[error("inference capability peer principal does not match")]
    PeerPrincipalMismatch,
    /// Provider policy has drifted.
    #[error("inference capability provider policy does not match")]
    ProviderPolicyMismatch,
    /// Endpoint, model, method, or protocol differs.
    #[error("requested inference envelope does not match")]
    EnvelopeMismatch,
    /// Trusted clock is before the inclusive lower bound.
    #[error("inference capability is not yet valid")]
    NotYetValid,
    /// Trusted clock is at or after the exclusive upper bound.
    #[error("inference capability is expired")]
    Expired,
    /// Each dispatch must reserve exactly one request.
    #[error("one inference use must count exactly one request")]
    UseMustCountExactlyOneRequest,
    /// Usage arithmetic overflowed and cannot be safely evaluated.
    #[error("inference usage arithmetic overflowed")]
    UsageOverflow,
    /// Cumulative use would exceed a bound.
    #[error("inference capability budget exceeded for {dimension:?}")]
    BudgetExceeded {
        /// First exceeded dimension in stable check order.
        dimension: BudgetDimensionV1,
    },
}

fn validate_envelope_name(
    kind: &'static str,
    value: &str,
) -> Result<(), CapabilityDefinitionError> {
    if value.is_empty() {
        return Err(CapabilityDefinitionError::EmptyName { kind });
    }
    if value.len() > MAX_ENVELOPE_NAME_LENGTH {
        return Err(CapabilityDefinitionError::NameTooLong {
            kind,
            maximum: MAX_ENVELOPE_NAME_LENGTH,
            actual: value.len(),
        });
    }
    let bytes = value.as_bytes();
    let endpoint = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let admitted = |byte: u8| endpoint(byte) || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/');
    if !endpoint(bytes[0])
        || !endpoint(bytes[bytes.len() - 1])
        || !bytes.iter().copied().all(admitted)
    {
        return Err(CapabilityDefinitionError::NonCanonicalName { kind });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::hash_bytes(label.as_bytes())
    }

    fn envelope() -> InferenceEnvelopeV1 {
        InferenceEnvelopeV1 {
            endpoint: ProviderEndpointId::new("anthropic:primary").unwrap(),
            model: ModelId::new("claude-sonnet-4-5").unwrap(),
            method: InferenceMethodId::new("messages-v1").unwrap(),
            protocol_digest: digest("protocol"),
        }
    }

    fn capability() -> InferenceCapabilityV1 {
        InferenceCapabilityV1::new(
            AuthorityDomainId::new("site:prod").unwrap(),
            EpochId::new(9).unwrap(),
            ProjectId::new("ag-ng").unwrap(),
            SessionId::new("session-1").unwrap(),
            LifecycleNonce::new([1; 16]),
            PrincipalId::new(digest("worker")),
            digest("provider-policy"),
            envelope(),
            InferenceBudgetV1 {
                requests: 2,
                input_bytes: 1_000,
                output_bytes: 2_000,
                cost_microunits: 300,
            },
            1_000,
            2_000,
            LifecycleNonce::new([2; 16]),
        )
        .unwrap()
    }

    fn context(capability: &InferenceCapabilityV1) -> CapabilityUseContextV1 {
        CapabilityUseContextV1 {
            authority_domain: capability.authority_domain.clone(),
            epoch: capability.epoch,
            project: capability.project.clone(),
            session_id: capability.session_id.clone(),
            session_nonce: capability.session_nonce,
            peer_principal: capability.worker_principal.clone(),
            provider_policy_digest: capability.provider_policy_digest.clone(),
            requested_envelope: capability.envelope.clone(),
            committed_usage: InferenceUsageV1::default(),
            requested_usage: InferenceUsageV1 {
                requests: 1,
                input_bytes: 100,
                output_bytes: 200,
                cost_microunits: 20,
            },
            now_unix_ms: 1_000,
            session_state: SessionLifecycleStateV1::Active,
            revocation_state: RevocationStateV1::NotRevoked,
        }
    }

    #[test]
    fn valid_use_binds_and_returns_resulting_usage() {
        let capability = capability();
        let checked = capability.validate_use(&context(&capability)).unwrap();
        assert_eq!(checked.capability_id, capability.id());
        assert_eq!(checked.resulting_usage.requests, 1);
        assert_eq!(checked.checked_at_unix_ms, 1_000);
    }

    #[test]
    fn half_open_lifetime_is_exact() {
        let capability = capability();
        let mut before = context(&capability);
        before.now_unix_ms = 999;
        assert_eq!(
            capability.validate_use(&before).unwrap_err(),
            CapabilityUseError::NotYetValid
        );

        let mut final_instant = context(&capability);
        final_instant.now_unix_ms = 1_999;
        assert!(capability.validate_use(&final_instant).is_ok());

        let mut expired = context(&capability);
        expired.now_unix_ms = 2_000;
        assert_eq!(
            capability.validate_use(&expired).unwrap_err(),
            CapabilityUseError::Expired
        );
    }

    #[test]
    fn another_peer_or_recycled_session_cannot_replay() {
        let capability = capability();
        let mut wrong_peer = context(&capability);
        wrong_peer.peer_principal = PrincipalId::new(digest("other-worker"));
        assert_eq!(
            capability.validate_use(&wrong_peer).unwrap_err(),
            CapabilityUseError::PeerPrincipalMismatch
        );

        let mut recycled = context(&capability);
        recycled.session_nonce = LifecycleNonce::new([9; 16]);
        assert_eq!(
            capability.validate_use(&recycled).unwrap_err(),
            CapabilityUseError::SessionLifecycleMismatch
        );
    }

    #[test]
    fn epoch_policy_and_envelope_drift_fail_closed() {
        let capability = capability();
        let mut drift = context(&capability);
        drift.epoch = EpochId::new(10).unwrap();
        assert_eq!(
            capability.validate_use(&drift).unwrap_err(),
            CapabilityUseError::EpochMismatch
        );

        let mut drift = context(&capability);
        drift.provider_policy_digest = digest("new-policy");
        assert_eq!(
            capability.validate_use(&drift).unwrap_err(),
            CapabilityUseError::ProviderPolicyMismatch
        );

        let mut drift = context(&capability);
        drift.requested_envelope.model = ModelId::new("different-model").unwrap();
        assert_eq!(
            capability.validate_use(&drift).unwrap_err(),
            CapabilityUseError::EnvelopeMismatch
        );
    }

    #[test]
    fn revocation_cancellation_and_termination_burn_usability() {
        let capability = capability();
        let mut revoked = context(&capability);
        revoked.revocation_state = RevocationStateV1::Revoked {
            revoked_at_unix_ms: 1_100,
            reason_digest: digest("reason"),
        };
        assert_eq!(
            capability.validate_use(&revoked).unwrap_err(),
            CapabilityUseError::Revoked
        );

        for state in [
            SessionLifecycleStateV1::Cancelling,
            SessionLifecycleStateV1::Terminal,
        ] {
            let mut inactive = context(&capability);
            inactive.session_state = state;
            assert_eq!(
                capability.validate_use(&inactive).unwrap_err(),
                CapabilityUseError::SessionNotActive { state }
            );
        }
    }

    #[test]
    fn cumulative_budget_is_checked_with_overflow_protection() {
        let capability = capability();
        let mut context = context(&capability);
        context.committed_usage.requests = 2;
        assert_eq!(
            capability.validate_use(&context).unwrap_err(),
            CapabilityUseError::BudgetExceeded {
                dimension: BudgetDimensionV1::Requests
            }
        );

        context.committed_usage.requests = 0;
        context.committed_usage.input_bytes = u64::MAX;
        assert_eq!(
            capability.validate_use(&context).unwrap_err(),
            CapabilityUseError::UsageOverflow
        );
    }

    #[test]
    fn deserialization_rejects_invalid_lifetime_and_zero_request_budget() {
        let capability = capability();
        let mut value = serde_json::to_value(&capability).unwrap();
        value["expires_at_unix_ms"] = value["not_before_unix_ms"].clone();
        assert!(serde_json::from_value::<InferenceCapabilityV1>(value).is_err());

        let mut value = serde_json::to_value(&capability).unwrap();
        value["budget"]["requests"] = serde_json::json!(0);
        assert!(serde_json::from_value::<InferenceCapabilityV1>(value).is_err());
    }

    #[test]
    fn issuance_nonce_changes_capability_identity() {
        let first = capability();
        let mut second = first.clone();
        second.capability_nonce = LifecycleNonce::new([3; 16]);
        assert_ne!(first.id(), second.id());
    }
}
