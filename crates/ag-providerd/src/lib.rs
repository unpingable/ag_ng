//! Credential-isolated inference proxy with durable pre-dispatch accounting.
//!
//! This package is deliberately outside the `ag-app` dependency graph so the
//! effect broker cannot acquire HTTP/TLS client code through shared linkage.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ag_primitives::{
    AuthorityDomain, CapabilityUseContextV1, Digest, Epoch, InferenceCapabilityId,
    InferenceCapabilityV1, InferenceUsageV1, PrincipalId, RevocationStateV1,
    SessionLifecycleStateV1,
};
use ag_session::ProviderRequestCustodyV1;
use ag_store::{NewEventV1, Store};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rustix::fs::{FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use ag_app::api::{
    ApiErrorCodeV1, ApiResultV1, HealthV1, OpaqueBytesV1, ProviderRequestV1, ProviderResponseV1,
};
use ag_app::config::{
    ProviderCommandConfigV1, ProviderCommandModelArgumentV1, ProviderEndpointConfigV1,
    ProviderModelPolicyConfigV1, ProviderTransportConfigV1, ProviderdConfigV1,
};
use ag_app::descriptor_path::open_beneath;
use ag_app::rpc_auth::VerifiedRpcPrincipalV1;

const TERMINATION_PAGE_SIZE: u32 = 64;
const MAX_PROVIDER_CREDENTIAL_BYTES: u64 = 64 * 1024;
const MAX_PROVIDER_CREDENTIAL_NAME_BYTES: usize = 128;

/// Durable provider-side capability accounting state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilityStateV1 {
    /// Exact registered capability definition.
    pub capability: InferenceCapabilityV1,
    /// Stable worker principal bound by the committed capability.
    pub worker_principal: ag_primitives::PrincipalId,
    /// Cumulative usage committed before dispatch.
    pub usage: InferenceUsageV1,
    /// Durable session lifecycle.
    pub session_state: SessionLifecycleStateV1,
    /// Durable revocation state.
    pub revocation_state: RevocationStateV1,
}

/// Durable crash-safe state for one deterministic provider dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDispatchStateV1 {
    /// Authority domain in which the dispatch was reserved.
    pub authority_domain: AuthorityDomain,
    /// Revocation epoch in which the dispatch was reserved.
    pub epoch: Epoch,
    /// Exact provider policy used to price and bound the dispatch.
    pub provider_policy_digest: Digest,
    /// Deterministic dispatch identity.
    pub dispatch: Digest,
    /// Exact committed capability identity.
    pub capability: InferenceCapabilityId,
    /// Governor custody identity for the exact request.
    pub request_custody_record: Digest,
    /// Digest of exact credential-free request bytes.
    pub exact_request: Digest,
    /// Root-policy-owned reservation committed before network dispatch.
    pub reserved_usage: InferenceUsageV1,
    /// Durable dispatch/custody lifecycle.
    pub phase: ProviderDispatchPhaseV1,
}

/// Durable dispatch/custody lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderDispatchPhaseV1 {
    /// Budget is burned; no safe claim about the external outcome exists yet.
    Reserved,
    /// A complete bounded event stream is durable and repeatedly fetchable.
    Available {
        /// Digest of the exact canonical event-stream bytes.
        exact_event_stream: Digest,
        /// Exact complete canonical event-stream bytes.
        event_stream: OpaqueBytesV1,
        /// Sanitized response headers projected for convenience.
        sanitized_headers: Vec<(String, String)>,
        /// True only when the configured adapter observed a terminal event.
        protocol_terminal: bool,
    },
    /// `agd` explicitly acknowledged a durable exact-byte custody commit.
    Acknowledged {
        /// Digest of the exact event-stream bytes acknowledged by `agd`.
        exact_event_stream: Digest,
        /// Exact byte count acknowledged by `agd`.
        byte_length: u64,
        /// Governor's durable custody record.
        governor_custody_record: Digest,
        /// Provider receipt binding the acknowledgment.
        acknowledgment_receipt: Digest,
        /// Trusted local acknowledgment time.
        acknowledged_at_unix_ms: u64,
    },
}

/// Durable completion of a session-wide provider capability burn.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSessionTerminationCompletionV1 {
    /// Time at which every capability visible behind the tombstone was burned.
    pub completed_at_unix_ms: u64,
    /// Number of capability identities bound into the aggregate.
    pub capability_count: u64,
    /// Ordered hash-chain root covering every capability identity.
    pub capability_set_digest: Digest,
    /// Stable aggregate session termination receipt.
    pub receipt: Digest,
}

/// Durable terminal tombstone for one provider session.
///
/// Entity existence is the terminal fact. `completion` remains absent only
/// while a crash-recoverable capability scan is still in progress.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSessionTerminationStateV1 {
    /// Authority domain in which the terminal fact was committed.
    pub authority_domain: AuthorityDomain,
    /// Revocation epoch in which the terminal fact was committed.
    pub epoch: Epoch,
    /// Provider policy active when the terminal fence was established.
    pub provider_policy_digest: Digest,
    /// Exact session burned by this tombstone.
    pub session: ag_primitives::SessionId,
    /// Time at which the terminal fence became durable.
    pub terminal_since_unix_ms: u64,
    /// Aggregate completion, once the paginated burn has reached the end.
    pub completion: Option<ProviderSessionTerminationCompletionV1>,
}

/// Credential-free complete event stream durably retained for governor custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderEventStreamV1 {
    /// Complete bounded HTTP response.
    HttpResponse {
        /// Numeric HTTP status.
        status: u16,
        /// Sanitized response headers.
        headers: BTreeMap<String, String>,
        /// Exact response body bytes.
        body: OpaqueBytesV1,
        /// True only when the configured adapter found its semantic terminal event.
        protocol_terminal: bool,
    },
    /// Transport failed before a complete HTTP response existed.
    TransportFailure {
        /// Closed failure class without secret-bearing diagnostics.
        class: ProviderTransportFailureV1,
    },
    /// Provider exceeded the hard custody bound; no partial plaintext is retained here.
    ResponseLimitExceeded {
        /// Numeric HTTP status.
        status: u16,
        /// Sanitized response headers.
        headers: BTreeMap<String, String>,
        /// Bound that was exceeded.
        maximum_bytes: u64,
    },
}

/// Sanitized provider transport failure classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTransportFailureV1 {
    /// TLS/connect/DNS failed.
    Connect,
    /// Request or response exceeded a deadline.
    Timeout,
    /// Response stream failed after headers.
    Body,
    /// Other error deliberately stripped of provider content.
    Other,
}

/// Single-writer provider accounting and dispatch core.
pub struct ProviderCoreV1 {
    store: Store,
    config: ProviderdConfigV1,
    endpoints: BTreeMap<String, ProviderEndpointConfigV1>,
    provider_policy: Digest,
    authority_domain: AuthorityDomain,
    epoch: Epoch,
    client: Client,
}

impl ProviderCoreV1 {
    /// Constructs the provider core and verifies store/catalog identity.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt storage, duplicate endpoints, invalid
    /// authority context, canonicalization failure, or an unsafe HTTP client.
    pub fn new(store: Store, config: ProviderdConfigV1) -> Result<Self, ProviderError> {
        store.verify_chain()?;
        let mut endpoints = BTreeMap::new();
        for endpoint in &config.endpoints {
            if endpoints
                .insert(endpoint.id.clone(), endpoint.clone())
                .is_some()
            {
                return Err(ProviderError::DuplicateEndpoint(endpoint.id.clone()));
            }
        }
        let provider_policy = Digest::from_serializable(&endpoints)?;
        let authority_domain = AuthorityDomain::parse(&config.authority_domain)?;
        let epoch = Epoch::parse(&config.epoch)?;
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_millis(config.limits.provider_deadline_ms))
            .build()?;
        Ok(Self {
            store,
            config,
            endpoints,
            provider_policy,
            authority_domain,
            epoch,
            client,
        })
    }

    /// Handles one request from the single signed, enrolled caller.
    ///
    /// The caller may be `agd` or one independently enrolled fixed service.
    /// Dynamic-worker presentation remains absent. Every capability is bound
    /// to the authenticated caller principal, so serialized capability data
    /// cannot be replayed by another local peer.
    pub fn handle(
        &mut self,
        request: ProviderRequestV1,
        peer: &VerifiedRpcPrincipalV1,
    ) -> ApiResultV1<ProviderResponseV1> {
        match self.try_handle(request, peer) {
            Ok(response) => ApiResultV1::Ok { response },
            Err(error) => provider_api_error(&error),
        }
    }

    fn try_handle(
        &mut self,
        request: ProviderRequestV1,
        peer: &VerifiedRpcPrincipalV1,
    ) -> Result<ProviderResponseV1, ProviderError> {
        if peer.principal != self.config.caller_peer.rpc_key.principal
            || peer.key_id != self.config.caller_peer.rpc_key.key_id
        {
            return Err(ProviderError::ServiceAuthenticationRequired);
        }
        match request {
            ProviderRequestV1::Health {} => Ok(ProviderResponseV1::Health {
                health: HealthV1 {
                    schema: "ag.health/v1".to_owned(),
                    service: "ag-providerd".to_owned(),
                    build: env!("CARGO_PKG_VERSION").to_owned(),
                    // A fixed service ingress is complete at this boundary.
                    // The daemon-proxy profile remains non-ready until agd
                    // proves its dynamic WorkerSessionPrincipal relation.
                    ready: self.config.caller_peer.principal_kind
                        == ag_primitives::PrincipalKindV1::Service,
                    quiesced: self.store.active_backup_cut()?.is_some(),
                },
            }),
            ProviderRequestV1::RegisterCapability {
                capability,
                worker_principal,
            } => {
                if capability.worker_principal != worker_principal
                    || (self.config.caller_peer.principal_kind
                        == ag_primitives::PrincipalKindV1::Service
                        && worker_principal != PrincipalId::new(peer.principal.clone()))
                    || capability.provider_policy_digest != self.provider_policy
                    || capability.authority_domain != self.authority_domain
                    || capability.epoch != self.epoch
                {
                    return Err(ProviderError::CapabilityBindingMismatch);
                }
                capability.validate_definition()?;
                self.ensure_endpoint(&capability)?;
                self.ensure_session_active(&capability.session_id)?;
                let capability_id = capability.id();
                let entity = capability_entity(&capability_id);
                if let Some(existing) = self
                    .store
                    .materialized_state::<ProviderCapabilityStateV1>(&entity)?
                {
                    if existing.state.capability == *capability
                        && existing.state.worker_principal == worker_principal
                    {
                        return Ok(ProviderResponseV1::CapabilityRegistered {
                            capability: capability_id,
                        });
                    }
                    return Err(ProviderError::CapabilityRegistrationConflict);
                }
                if self.store.active_backup_cut()?.is_some() {
                    return Err(ProviderError::Quiesced);
                }
                let state = ProviderCapabilityStateV1 {
                    capability: capability.as_ref().clone(),
                    worker_principal,
                    usage: InferenceUsageV1::default(),
                    session_state: SessionLifecycleStateV1::Active,
                    revocation_state: RevocationStateV1::NotRevoked,
                };
                self.store.append_event(
                    NewEventV1 {
                        event_id: uuid::Uuid::new_v4().to_string(),
                        entity_id: entity,
                        event_kind: "provider-capability.registered.v1".to_owned(),
                        occurred_at_unix_ms: now_i64()?,
                        payload: (&capability, &state.worker_principal),
                    },
                    &state,
                    0,
                )?;
                Ok(ProviderResponseV1::CapabilityRegistered {
                    capability: capability_id,
                })
            }
            ProviderRequestV1::Infer {
                capability,
                request,
                request_bytes,
            } => self.infer(peer, &capability, &request, request_bytes.into_vec()),
            ProviderRequestV1::FetchInference { dispatch } => self.fetch_inference(&dispatch),
            ProviderRequestV1::AcknowledgeInferenceCustody {
                dispatch,
                exact_event_stream,
                governor_custody_record,
            } => self.acknowledge_inference_custody(
                &dispatch,
                &exact_event_stream,
                &governor_custody_record,
            ),
            ProviderRequestV1::TerminateSession { session } => self.terminate_session(&session),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn infer(
        &mut self,
        peer: &VerifiedRpcPrincipalV1,
        capability: &InferenceCapabilityV1,
        request: &ProviderRequestCustodyV1,
        request_bytes: Vec<u8>,
    ) -> Result<ProviderResponseV1, ProviderError> {
        if self.config.caller_peer.principal_kind == ag_primitives::PrincipalKindV1::Service
            && capability.worker_principal != PrincipalId::new(peer.principal.clone())
        {
            return Err(ProviderError::CapabilityBindingMismatch);
        }
        if self.store.active_backup_cut()?.is_some() {
            return Err(ProviderError::Quiesced);
        }
        self.ensure_session_active(&capability.session_id)?;
        if request_bytes.len() as u64 > self.config.limits.max_request_bytes {
            return Err(ProviderError::RequestLimit);
        }
        request.verify()?;
        if request.exact_request != Digest::hash_bytes(&request_bytes)
            || request.capability_id != capability.id()
            || request.envelope != capability.envelope
        {
            return Err(ProviderError::CustodyBindingMismatch);
        }
        validate_request_headers(&request.sanitized_headers)?;
        validate_adapter_request(capability, &request_bytes)?;

        let capability_id = capability.id();
        let entity = capability_entity(&capability_id);
        let loaded = self
            .store
            .materialized_state::<ProviderCapabilityStateV1>(&entity)?
            .ok_or(ProviderError::CapabilityNotRegistered)?;
        if loaded.state.capability != *capability
            || loaded.state.worker_principal != capability.worker_principal
        {
            return Err(ProviderError::CapabilityBindingMismatch);
        }
        // From this point onward only the committed definition is consulted;
        // the serialized capability was lookup/equality evidence, not bearer
        // authority.
        let capability = loaded.state.capability.clone();
        let (endpoint, model_policy) = self.ensure_endpoint(&capability)?;
        let endpoint = endpoint.clone();
        let model_policy = model_policy.clone();
        let dispatch = dispatch_identity(
            &self.authority_domain,
            self.epoch,
            &capability_id,
            &request.custody_record,
        )?;
        let dispatch_entity = dispatch_entity(&dispatch);
        if let Some(existing) = self
            .store
            .materialized_state::<ProviderDispatchStateV1>(&dispatch_entity)?
        {
            self.validate_dispatch_binding(&existing.state, &dispatch, &capability_id, request)?;
            return response_for_existing_dispatch(&existing.state);
        }

        // Neither reserve is supplied by the caller. Both are selected from
        // the exact root-owned endpoint/model policy which is itself bound
        // into the capability's provider-policy digest.
        let requested_usage = InferenceUsageV1 {
            requests: 1,
            input_bytes: request_bytes.len() as u64,
            output_bytes: model_policy.max_event_stream_bytes,
            cost_microunits: model_policy.worst_case_cost_microunits,
        };
        let validated = capability.validate_use(&CapabilityUseContextV1 {
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            project: capability.project.clone(),
            session_id: capability.session_id.clone(),
            session_nonce: capability.session_nonce,
            peer_principal: capability.worker_principal.clone(),
            provider_policy_digest: self.provider_policy.clone(),
            requested_envelope: request.envelope.clone(),
            committed_usage: loaded.state.usage,
            requested_usage,
            now_unix_ms: now_u64()?,
            session_state: loaded.state.session_state,
            revocation_state: loaded.state.revocation_state.clone(),
        })?;

        // Reservation is committed before any credential is loaded or network
        // dispatch begins. A crash cannot restore/reuse this budget.
        let state = ProviderCapabilityStateV1 {
            usage: validated.resulting_usage,
            ..loaded.state
        };
        let dispatch_state = ProviderDispatchStateV1 {
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            provider_policy_digest: self.provider_policy.clone(),
            dispatch: dispatch.clone(),
            capability: capability_id.clone(),
            request_custody_record: request.custody_record.clone(),
            exact_request: request.exact_request.clone(),
            reserved_usage: requested_usage,
            phase: ProviderDispatchPhaseV1::Reserved,
        };
        let (_reservation_receipt, dispatch_reservation) = self.store.append_distinct_event_pair(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: entity.clone(),
                event_kind: "provider-dispatch.reserved.v1".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: (&dispatch, &request.custody_record, requested_usage),
            },
            &state,
            loaded.revision,
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: dispatch_entity.clone(),
                event_kind: "provider-dispatch.custody-reserved.v1".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: (&capability_id, &request.custody_record, requested_usage),
            },
            &dispatch_state,
            0,
        )?;

        let event_stream = self.dispatch(
            &endpoint,
            request,
            request_bytes,
            model_policy.max_event_stream_bytes,
        )?;
        let (event_stream, event_bytes) =
            bounded_event_stream_bytes(event_stream, model_policy.max_event_stream_bytes)?;
        let exact_event_stream = Digest::hash_bytes(&event_bytes);
        let completion_receipt = Digest::from_serializable(&(
            "ag.provider.dispatch-receipt/v1",
            &dispatch,
            &capability_id,
            &request.custody_record,
            &exact_event_stream,
            dispatch_reservation.event_digest,
        ))?;
        let (headers, protocol_terminal) = event_stream_projection(&event_stream);
        let available = ProviderDispatchStateV1 {
            phase: ProviderDispatchPhaseV1::Available {
                exact_event_stream: exact_event_stream.clone(),
                event_stream: OpaqueBytesV1::new(event_bytes.clone()),
                sanitized_headers: headers,
                protocol_terminal,
            },
            ..dispatch_state
        };
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: dispatch_entity,
                event_kind: "provider-dispatch.completed.v1".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: (
                    &completion_receipt,
                    &exact_event_stream,
                    event_bytes.len() as u64,
                ),
            },
            &available,
            dispatch_reservation.entity_revision,
        )?;
        Ok(ProviderResponseV1::InferenceAvailable {
            dispatch,
            exact_event_stream,
            byte_length: event_bytes.len() as u64,
            protocol_terminal,
        })
    }

    fn fetch_inference(&self, dispatch: &Digest) -> Result<ProviderResponseV1, ProviderError> {
        let loaded = self
            .store
            .materialized_state::<ProviderDispatchStateV1>(&dispatch_entity(dispatch))?
            .ok_or(ProviderError::DispatchNotFound)?;
        self.validate_dispatch_identity(&loaded.state, dispatch)?;
        match loaded.state.phase {
            ProviderDispatchPhaseV1::Reserved => Err(ProviderError::DispatchOutcomeIndeterminate),
            ProviderDispatchPhaseV1::Available {
                exact_event_stream,
                event_stream,
                sanitized_headers,
                protocol_terminal,
            } => {
                if event_stream.len() as u64 > self.config.limits.max_response_bytes
                    || Digest::hash_bytes(event_stream.as_slice()) != exact_event_stream
                {
                    return Err(ProviderError::DispatchCustodyCorrupt);
                }
                Ok(ProviderResponseV1::Inference {
                    dispatch: dispatch.clone(),
                    exact_event_stream,
                    event_stream,
                    sanitized_headers,
                    protocol_terminal,
                })
            }
            ProviderDispatchPhaseV1::Acknowledged {
                acknowledgment_receipt,
                ..
            } => Ok(ProviderResponseV1::InferenceCustodyAcknowledged {
                dispatch: dispatch.clone(),
                receipt: acknowledgment_receipt,
            }),
        }
    }

    fn acknowledge_inference_custody(
        &mut self,
        dispatch: &Digest,
        exact_event_stream: &Digest,
        governor_custody_record: &Digest,
    ) -> Result<ProviderResponseV1, ProviderError> {
        if self.store.active_backup_cut()?.is_some() {
            return Err(ProviderError::Quiesced);
        }
        let entity = dispatch_entity(dispatch);
        let loaded = self
            .store
            .materialized_state::<ProviderDispatchStateV1>(&entity)?
            .ok_or(ProviderError::DispatchNotFound)?;
        self.validate_dispatch_identity(&loaded.state, dispatch)?;
        let (byte_length, protocol_terminal) = match &loaded.state.phase {
            ProviderDispatchPhaseV1::Reserved => {
                return Err(ProviderError::DispatchOutcomeIndeterminate);
            }
            ProviderDispatchPhaseV1::Available {
                exact_event_stream: stored_digest,
                event_stream,
                protocol_terminal,
                ..
            } => {
                if stored_digest != exact_event_stream
                    || Digest::hash_bytes(event_stream.as_slice()) != *stored_digest
                {
                    return Err(ProviderError::CustodyAcknowledgmentMismatch);
                }
                (event_stream.len() as u64, *protocol_terminal)
            }
            ProviderDispatchPhaseV1::Acknowledged {
                exact_event_stream: stored_digest,
                governor_custody_record: stored_custody,
                acknowledgment_receipt,
                ..
            } => {
                if stored_digest != exact_event_stream || stored_custody != governor_custody_record
                {
                    return Err(ProviderError::CustodyAcknowledgmentMismatch);
                }
                return Ok(ProviderResponseV1::InferenceCustodyAcknowledged {
                    dispatch: dispatch.clone(),
                    receipt: acknowledgment_receipt.clone(),
                });
            }
        };
        let acknowledged_at_unix_ms = now_u64()?;
        let acknowledgment_receipt = Digest::from_serializable(&(
            "ag.provider.governor-custody-acknowledgment/v1",
            dispatch,
            exact_event_stream,
            byte_length,
            governor_custody_record,
            acknowledged_at_unix_ms,
        ))?;
        let state = ProviderDispatchStateV1 {
            phase: ProviderDispatchPhaseV1::Acknowledged {
                exact_event_stream: exact_event_stream.clone(),
                byte_length,
                governor_custody_record: governor_custody_record.clone(),
                acknowledgment_receipt: acknowledgment_receipt.clone(),
                acknowledged_at_unix_ms,
            },
            ..loaded.state
        };
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: entity,
                event_kind: "provider-dispatch.governor-custody-acknowledged.v1".to_owned(),
                occurred_at_unix_ms: i64::try_from(acknowledged_at_unix_ms)
                    .map_err(|_| ProviderError::Clock)?,
                payload: (
                    exact_event_stream,
                    byte_length,
                    governor_custody_record,
                    &acknowledgment_receipt,
                    protocol_terminal,
                ),
            },
            &state,
            loaded.revision,
        )?;
        Ok(ProviderResponseV1::InferenceCustodyAcknowledged {
            dispatch: dispatch.clone(),
            receipt: acknowledgment_receipt,
        })
    }

    fn validate_dispatch_identity(
        &self,
        state: &ProviderDispatchStateV1,
        dispatch: &Digest,
    ) -> Result<(), ProviderError> {
        if state.dispatch != *dispatch
            || state.authority_domain != self.authority_domain
            || state.epoch != self.epoch
            || state.provider_policy_digest != self.provider_policy
        {
            return Err(ProviderError::DispatchBindingMismatch);
        }
        Ok(())
    }

    fn validate_dispatch_binding(
        &self,
        state: &ProviderDispatchStateV1,
        dispatch: &Digest,
        capability: &InferenceCapabilityId,
        request: &ProviderRequestCustodyV1,
    ) -> Result<(), ProviderError> {
        self.validate_dispatch_identity(state, dispatch)?;
        if state.capability != *capability
            || state.request_custody_record != request.custody_record
            || state.exact_request != request.exact_request
        {
            return Err(ProviderError::DispatchBindingMismatch);
        }
        Ok(())
    }

    fn dispatch(
        &self,
        endpoint: &ProviderEndpointConfigV1,
        request: &ProviderRequestCustodyV1,
        request_bytes: Vec<u8>,
        maximum_event_stream_bytes: u64,
    ) -> Result<ProviderEventStreamV1, ProviderError> {
        let mut headers = HeaderMap::new();
        for (name, value) in &endpoint.headers {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
        for (name, value) in &request.sanitized_headers {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
        let url = match &endpoint.transport {
            ProviderTransportConfigV1::Command { command } => {
                return self.dispatch_command(command, request_bytes, maximum_event_stream_bytes);
            }
            ProviderTransportConfigV1::LocalHttp { url, .. } => url,
            ProviderTransportConfigV1::CredentialedHttpsApi {
                url,
                credential_name,
                credential_header,
                credential_prefix,
            } => {
                let credential_directory = std::env::var_os("CREDENTIALS_DIRECTORY")
                    .ok_or(ProviderError::CredentialUnavailable)?;
                let mut credential =
                    read_provider_credential(Path::new(&credential_directory), credential_name)?;
                while credential.ends_with(['\n', '\r']) {
                    credential.pop();
                }
                if credential.is_empty() || credential.contains(['\n', '\r', '\0']) {
                    return Err(ProviderError::CredentialUnavailable);
                }
                let header = HeaderName::from_bytes(credential_header.as_bytes())?;
                let value = HeaderValue::from_str(&format!("{credential_prefix}{credential}"))?;
                headers.insert(header, value);
                url
            }
        };

        let response = match self
            .client
            .post(url)
            .headers(headers)
            .body(request_bytes)
            .send()
        {
            Ok(response) => response,
            Err(error) if error.is_timeout() => {
                // Once a request may have reached a provider, a timeout cannot
                // prove non-execution or non-billing. Leave the durable
                // reservation unresolved for reconciliation; never redispatch.
                return Err(ProviderError::DispatchOutcomeIndeterminate);
            }
            Err(error) => {
                return Ok(ProviderEventStreamV1::TransportFailure {
                    class: classify_transport(&error),
                });
            }
        };
        let status = response.status().as_u16();
        let sanitized = sanitize_response_headers(response.headers());
        // A raw body larger than the entire canonical custody envelope can
        // never fit the admitted event-stream byte domain. Read one extra byte
        // to distinguish an exact-bound response from an overflow.
        let maximum = self
            .config
            .limits
            .max_response_bytes
            .min(maximum_event_stream_bytes);
        let mut body = Vec::new();
        if let Err(_error) = response
            .take(maximum.saturating_add(1))
            .read_to_end(&mut body)
        {
            return Ok(ProviderEventStreamV1::TransportFailure {
                class: ProviderTransportFailureV1::Body,
            });
        }
        if body.len() as u64 > maximum {
            return Ok(ProviderEventStreamV1::ResponseLimitExceeded {
                status,
                headers: sanitized,
                maximum_bytes: maximum,
            });
        }
        let terminal = protocol_terminal(&endpoint.protocol, status, &body);
        Ok(ProviderEventStreamV1::HttpResponse {
            status,
            headers: sanitized,
            body: OpaqueBytesV1::new(body),
            protocol_terminal: terminal,
        })
    }

    fn dispatch_command(
        &self,
        command: &ProviderCommandConfigV1,
        request_bytes: Vec<u8>,
        maximum_event_stream_bytes: u64,
    ) -> Result<ProviderEventStreamV1, ProviderError> {
        let request: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|_| ProviderError::AdapterRequestMismatch)?;
        let model = request
            .get("model")
            .and_then(serde_json::Value::as_str)
            .ok_or(ProviderError::AdapterRequestMismatch)?;
        let messages = request
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .ok_or(ProviderError::AdapterRequestMismatch)?;
        let mut prompt = String::new();
        for message in messages {
            let role = message
                .get("role")
                .and_then(serde_json::Value::as_str)
                .ok_or(ProviderError::AdapterRequestMismatch)?;
            let content = message
                .get("content")
                .and_then(serde_json::Value::as_str)
                .ok_or(ProviderError::AdapterRequestMismatch)?;
            if !matches!(role, "system" | "user" | "assistant") {
                return Err(ProviderError::AdapterRequestMismatch);
            }
            prompt.push('<');
            prompt.push_str(role);
            prompt.push_str(">\n");
            prompt.push_str(content);
            prompt.push_str("\n</");
            prompt.push_str(role);
            prompt.push_str(">\n");
        }

        let mut process = Command::new(&command.executable);
        process
            .env_clear()
            .envs(&command.environment)
            .current_dir(&command.working_directory)
            .process_group(0);
        match command.adapter.as_str() {
            "codex" => {
                process.args(["exec", "--json"]);
                if command.model_argument == ProviderCommandModelArgumentV1::Required {
                    process.args(["-m", model]);
                }
                process.arg("-");
            }
            "claude-code" => {
                process.args([
                    "--print",
                    "--output-format",
                    "json",
                    "--verbose",
                    "--model",
                    model,
                    "--tools",
                    "",
                    "--no-session-persistence",
                    "--disable-slash-commands",
                    "--safe-mode",
                ]);
            }
            "kimi-code" => {
                process.args([
                    "--model",
                    model,
                    "--prompt",
                    &prompt,
                    "--output-format",
                    "stream-json",
                ]);
            }
            _ => return Err(ProviderError::EndpointNotAllowed),
        }
        let uses_stdin = command.adapter != "kimi-code";
        process
            .stdin(if uses_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match process.spawn() {
            Ok(child) => child,
            Err(_) => {
                return Ok(ProviderEventStreamV1::TransportFailure {
                    class: ProviderTransportFailureV1::Connect,
                });
            }
        };
        if uses_stdin {
            let mut stdin = child.stdin.take().ok_or(ProviderError::CommandPipe)?;
            if std::io::Write::write_all(&mut stdin, prompt.as_bytes()).is_err() {
                terminate_process_group(&mut child);
                let _ = child.wait();
                return Err(ProviderError::DispatchOutcomeIndeterminate);
            }
        }
        let stdout = child.stdout.take().ok_or(ProviderError::CommandPipe)?;
        let stderr = child.stderr.take().ok_or(ProviderError::CommandPipe)?;
        let stdout_reader =
            thread::spawn(move || drain_bounded(stdout, maximum_event_stream_bytes));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr, 8192));
        let started = std::time::Instant::now();
        let deadline = Duration::from_millis(self.config.limits.provider_deadline_ms);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < deadline => {
                    thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    terminate_process_group(&mut child);
                    let grace = std::time::Instant::now();
                    while grace.elapsed() < Duration::from_secs(5) {
                        if child.try_wait().ok().flatten().is_some() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(25));
                    }
                    if child.try_wait().ok().flatten().is_none() {
                        kill_process_group(&mut child);
                    }
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(ProviderError::DispatchOutcomeIndeterminate);
                }
                Err(_) => {
                    terminate_process_group(&mut child);
                    kill_process_group(&mut child);
                    let _ = child.wait();
                    return Err(ProviderError::DispatchOutcomeIndeterminate);
                }
            }
        };
        let (stdout, stdout_exceeded) = stdout_reader
            .join()
            .map_err(|_| ProviderError::CommandPipe)??;
        let _stderr = stderr_reader
            .join()
            .map_err(|_| ProviderError::CommandPipe)??;
        if stdout_exceeded {
            return Ok(ProviderEventStreamV1::ResponseLimitExceeded {
                status: 200,
                headers: BTreeMap::new(),
                maximum_bytes: maximum_event_stream_bytes,
            });
        }
        let (status, body) = if status.success() {
            (200, stdout)
        } else {
            let body = serde_jcs::to_vec(&serde_json::json!({
                "error": "command_refused",
                "exit_code": status.code(),
            }))
            .map_err(|error| ProviderError::Canonical(error.to_string()))?;
            (502, body)
        };
        Ok(ProviderEventStreamV1::HttpResponse {
            status,
            headers: BTreeMap::new(),
            body: OpaqueBytesV1::new(body),
            protocol_terminal: true,
        })
    }

    fn ensure_endpoint(
        &self,
        capability: &InferenceCapabilityV1,
    ) -> Result<(&ProviderEndpointConfigV1, &ProviderModelPolicyConfigV1), ProviderError> {
        let endpoint = self
            .endpoints
            .get(capability.envelope.endpoint.as_str())
            .ok_or(ProviderError::EndpointNotAllowed)?;
        let model = endpoint
            .models
            .iter()
            .find(|model| model.id == capability.envelope.model.as_str())
            .ok_or(ProviderError::EndpointNotAllowed)?;
        if !endpoint
            .methods
            .iter()
            .any(|method| method == capability.envelope.method.as_str())
            || Digest::hash_bytes(endpoint.protocol.as_bytes())
                != capability.envelope.protocol_digest
        {
            return Err(ProviderError::EndpointNotAllowed);
        }
        Ok((endpoint, model))
    }

    fn ensure_session_active(
        &self,
        session: &ag_primitives::SessionId,
    ) -> Result<(), ProviderError> {
        let entity = session_termination_entity(session);
        let Some(tombstone) = self
            .store
            .materialized_state::<ProviderSessionTerminationStateV1>(&entity)?
        else {
            return Ok(());
        };
        self.validate_session_tombstone(session, &tombstone.state)?;
        Err(ProviderError::SessionTerminated)
    }

    fn validate_session_tombstone(
        &self,
        session: &ag_primitives::SessionId,
        tombstone: &ProviderSessionTerminationStateV1,
    ) -> Result<(), ProviderError> {
        if tombstone.session != *session
            || tombstone.authority_domain != self.authority_domain
            || tombstone.epoch != self.epoch
            || tombstone.provider_policy_digest != self.provider_policy
        {
            return Err(ProviderError::SessionTombstoneMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn terminate_session(
        &mut self,
        session: &ag_primitives::SessionId,
    ) -> Result<ProviderResponseV1, ProviderError> {
        let session_entity = session_termination_entity(session);
        let existing = self
            .store
            .materialized_state::<ProviderSessionTerminationStateV1>(&session_entity)?;
        if let Some(loaded) = &existing {
            self.validate_session_tombstone(session, &loaded.state)?;
            if let Some(completion) = &loaded.state.completion {
                return Ok(ProviderResponseV1::SessionTerminated {
                    receipt: completion.receipt.clone(),
                });
            }
        }
        if self.store.active_backup_cut()?.is_some() {
            return Err(ProviderError::Quiesced);
        }
        let (terminal_since_unix_ms, session_revision) = if let Some(loaded) = existing {
            (loaded.state.terminal_since_unix_ms, loaded.revision)
        } else {
            // The tombstone is committed before the first capability scan.
            // Registration and inference consult it, so a crash cannot reopen
            // the session or race a late capability into the completed set.
            let terminal_since_unix_ms = now_u64()?;
            let tombstone = ProviderSessionTerminationStateV1 {
                authority_domain: self.authority_domain.clone(),
                epoch: self.epoch,
                provider_policy_digest: self.provider_policy.clone(),
                session: session.clone(),
                terminal_since_unix_ms,
                completion: None,
            };
            let receipt = self.store.append_event(
                NewEventV1 {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    entity_id: session_entity.clone(),
                    event_kind: "provider-session.termination-started.v1".to_owned(),
                    occurred_at_unix_ms: i64::try_from(terminal_since_unix_ms)
                        .map_err(|_| ProviderError::Clock)?,
                    payload: session,
                },
                &tombstone,
                0,
            )?;
            (terminal_since_unix_ms, receipt.entity_revision)
        };

        let mut capability_count = 0_u64;
        let mut capability_set_digest = Digest::from_serializable(&(
            "ag.provider.session-capability-set.genesis/v1",
            &self.authority_domain,
            self.epoch,
            &self.provider_policy,
            session,
        ))?;
        let mut cursor = None;
        loop {
            let entities = self.store.entity_ids_after(
                "provider-capability-",
                cursor.as_deref(),
                TERMINATION_PAGE_SIZE,
            )?;
            if entities.is_empty() {
                break;
            }
            cursor = entities.last().cloned();
            for entity in entities {
                let Some(loaded) = self
                    .store
                    .materialized_state::<ProviderCapabilityStateV1>(&entity)?
                else {
                    continue;
                };
                if &loaded.state.capability.session_id != session {
                    continue;
                }
                let capability_id = loaded.state.capability.id();
                let needs_burn = loaded.state.session_state != SessionLifecycleStateV1::Terminal
                    || loaded.state.revocation_state == RevocationStateV1::NotRevoked;
                if needs_burn {
                    let reason = Digest::from_serializable(&(
                        "ag.provider.session-terminated/v1",
                        session,
                        &capability_id,
                    ))?;
                    let revocation_state = match &loaded.state.revocation_state {
                        RevocationStateV1::NotRevoked => RevocationStateV1::Revoked {
                            revoked_at_unix_ms: now_u64()?,
                            reason_digest: reason.clone(),
                        },
                        existing @ RevocationStateV1::Revoked { .. } => existing.clone(),
                    };
                    let state = ProviderCapabilityStateV1 {
                        session_state: SessionLifecycleStateV1::Terminal,
                        revocation_state,
                        ..loaded.state
                    };
                    self.store.append_event(
                        NewEventV1 {
                            event_id: uuid::Uuid::new_v4().to_string(),
                            entity_id: entity,
                            event_kind: "provider-capability.revoked.v1".to_owned(),
                            occurred_at_unix_ms: now_i64()?,
                            payload: (&reason, session, &capability_id),
                        },
                        &state,
                        loaded.revision,
                    )?;
                }
                capability_count = capability_count
                    .checked_add(1)
                    .ok_or(ProviderError::CapabilityCountOverflow)?;
                capability_set_digest = Digest::from_serializable(&(
                    "ag.provider.session-capability-set.step/v1",
                    capability_set_digest,
                    &capability_id,
                ))?;
            }
        }

        let completed_at_unix_ms = now_u64()?;
        let receipt = Digest::from_serializable(&(
            "ag.provider.session-revocation-receipt/v1",
            &self.authority_domain,
            self.epoch,
            &self.provider_policy,
            session,
            capability_count,
            &capability_set_digest,
        ))?;
        let completion = ProviderSessionTerminationCompletionV1 {
            completed_at_unix_ms,
            capability_count,
            capability_set_digest,
            receipt: receipt.clone(),
        };
        let state = ProviderSessionTerminationStateV1 {
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            provider_policy_digest: self.provider_policy.clone(),
            session: session.clone(),
            terminal_since_unix_ms,
            completion: Some(completion.clone()),
        };
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: session_entity,
                event_kind: "provider-session.termination-completed.v1".to_owned(),
                occurred_at_unix_ms: i64::try_from(completed_at_unix_ms)
                    .map_err(|_| ProviderError::Clock)?,
                payload: &completion,
            },
            &state,
            session_revision,
        )?;
        Ok(ProviderResponseV1::SessionTerminated { receipt })
    }
}

fn terminate_process_group(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        );
    }
}

fn kill_process_group(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

fn drain_bounded(
    mut reader: impl Read,
    maximum_retained_bytes: u64,
) -> std::io::Result<(Vec<u8>, bool)> {
    let retained_limit = maximum_retained_bytes.saturating_add(1);
    let mut retained = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let available = retained_limit.saturating_sub(retained.len() as u64);
        let keep = usize::try_from(available.min(count as u64)).unwrap_or(0);
        retained.extend_from_slice(&buffer[..keep]);
        exceeded |= count > keep;
    }
    let exceeded = exceeded || retained.len() as u64 > maximum_retained_bytes;
    Ok((retained, exceeded))
}

fn read_provider_credential(
    directory: &Path,
    credential_name: &str,
) -> Result<String, ProviderError> {
    if credential_name.is_empty()
        || credential_name.len() > MAX_PROVIDER_CREDENTIAL_NAME_BYTES
        || matches!(credential_name, "." | "..")
        || !credential_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProviderError::CredentialUnavailable);
    }
    let normalized: std::path::PathBuf = directory.components().collect();
    if !directory.is_absolute()
        || normalized != directory
        || directory.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(ProviderError::CredentialUnavailable);
    }
    let relative = directory
        .strip_prefix("/")
        .map_err(|_| ProviderError::CredentialUnavailable)?;
    let root = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ProviderError::CredentialUnavailable)?;
    let directory_fd = open_beneath(
        &root,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ProviderError::CredentialUnavailable)?;
    validate_credential_directory(&directory_fd)?;
    let credential_fd = open_beneath(
        &directory_fd,
        Path::new(credential_name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ProviderError::CredentialUnavailable)?;
    read_credential_fd(credential_fd)
}

fn validate_credential_directory(directory: &OwnedFd) -> Result<(), ProviderError> {
    let stat = rustix::fs::fstat(directory).map_err(|_| ProviderError::CredentialUnavailable)?;
    let effective_uid = nix::unistd::geteuid().as_raw();
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || (stat.st_uid != 0 && stat.st_uid != effective_uid)
        || stat.st_mode & 0o022 != 0
    {
        return Err(ProviderError::CredentialUnavailable);
    }
    Ok(())
}

fn read_credential_fd(fd: OwnedFd) -> Result<String, ProviderError> {
    let before = rustix::fs::fstat(&fd).map_err(|_| ProviderError::CredentialUnavailable)?;
    let effective_uid = nix::unistd::geteuid().as_raw();
    let length = u64::try_from(before.st_size).map_err(|_| ProviderError::CredentialUnavailable)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_nlink != 1
        || (before.st_uid != 0 && before.st_uid != effective_uid)
        || before.st_mode & 0o077 != 0
        || before.st_mode & 0o7111 != 0
        || before.st_mode & 0o400 == 0
        || length == 0
        || length > MAX_PROVIDER_CREDENTIAL_BYTES
    {
        return Err(ProviderError::CredentialUnavailable);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(length).map_err(|_| ProviderError::CredentialUnavailable)?,
    );
    let mut file = File::from(fd);
    file.by_ref()
        .take(MAX_PROVIDER_CREDENTIAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::CredentialUnavailable)?;
    let after = rustix::fs::fstat(&file).map_err(|_| ProviderError::CredentialUnavailable)?;
    if bytes.len() as u64 != length
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(ProviderError::CredentialUnavailable);
    }
    String::from_utf8(bytes).map_err(|_| ProviderError::CredentialUnavailable)
}

fn response_for_existing_dispatch(
    state: &ProviderDispatchStateV1,
) -> Result<ProviderResponseV1, ProviderError> {
    match &state.phase {
        ProviderDispatchPhaseV1::Reserved => Err(ProviderError::DispatchOutcomeIndeterminate),
        ProviderDispatchPhaseV1::Available {
            exact_event_stream,
            event_stream,
            protocol_terminal,
            ..
        } => {
            if Digest::hash_bytes(event_stream.as_slice()) != *exact_event_stream {
                return Err(ProviderError::DispatchCustodyCorrupt);
            }
            Ok(ProviderResponseV1::InferenceAvailable {
                dispatch: state.dispatch.clone(),
                exact_event_stream: exact_event_stream.clone(),
                byte_length: event_stream.len() as u64,
                protocol_terminal: *protocol_terminal,
            })
        }
        ProviderDispatchPhaseV1::Acknowledged {
            acknowledgment_receipt,
            ..
        } => Ok(ProviderResponseV1::InferenceCustodyAcknowledged {
            dispatch: state.dispatch.clone(),
            receipt: acknowledgment_receipt.clone(),
        }),
    }
}

fn bounded_event_stream_bytes(
    event_stream: ProviderEventStreamV1,
    maximum_bytes: u64,
) -> Result<(ProviderEventStreamV1, Vec<u8>), ProviderError> {
    let bytes = serde_jcs::to_vec(&event_stream)
        .map_err(|error| ProviderError::Canonical(error.to_string()))?;
    if bytes.len() as u64 <= maximum_bytes {
        return Ok((event_stream, bytes));
    }
    let ProviderEventStreamV1::HttpResponse {
        status, headers, ..
    } = event_stream
    else {
        return Err(ProviderError::ConfiguredEventLimitTooSmall);
    };
    let limited = ProviderEventStreamV1::ResponseLimitExceeded {
        status,
        headers,
        maximum_bytes,
    };
    let bytes =
        serde_jcs::to_vec(&limited).map_err(|error| ProviderError::Canonical(error.to_string()))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(ProviderError::ConfiguredEventLimitTooSmall);
    }
    Ok((limited, bytes))
}

fn event_stream_projection(event_stream: &ProviderEventStreamV1) -> (Vec<(String, String)>, bool) {
    match event_stream {
        ProviderEventStreamV1::HttpResponse {
            headers,
            protocol_terminal,
            ..
        } => (
            headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            *protocol_terminal,
        ),
        ProviderEventStreamV1::ResponseLimitExceeded { headers, .. } => (
            headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            false,
        ),
        ProviderEventStreamV1::TransportFailure { .. } => (Vec::new(), false),
    }
}

fn dispatch_identity(
    authority_domain: &AuthorityDomain,
    epoch: Epoch,
    capability: &InferenceCapabilityId,
    request_custody_record: &Digest,
) -> Result<Digest, ProviderError> {
    Ok(Digest::from_serializable(&(
        "ag.provider.dispatch-id/v1",
        authority_domain,
        epoch,
        capability,
        request_custody_record,
    ))?)
}

fn dispatch_entity(dispatch: &Digest) -> String {
    format!(
        "provider-dispatch-{}",
        dispatch
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(dispatch.as_str())
    )
}

fn validate_request_headers(headers: &BTreeMap<String, String>) -> Result<(), ProviderError> {
    for (name, value) in headers {
        if !matches!(name.as_str(), "accept" | "content-type")
            || value.contains(['\r', '\n', '\0'])
            || value.len() > 512
        {
            return Err(ProviderError::UnsafeHeader);
        }
    }
    Ok(())
}

fn validate_adapter_request(
    capability: &InferenceCapabilityV1,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProviderError::AdapterRequestMismatch)?;
    if value.get("model").and_then(serde_json::Value::as_str)
        != Some(capability.envelope.model.as_str())
    {
        return Err(ProviderError::AdapterRequestMismatch);
    }
    Ok(())
}

fn sanitize_response_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut sanitized = BTreeMap::new();
    for name in [
        "content-type",
        "date",
        "openai-request-id",
        "request-id",
        "x-request-id",
    ] {
        if let Some(value) = headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= 512)
        {
            sanitized.insert(name.to_owned(), value.to_owned());
        }
    }
    sanitized
}

fn protocol_terminal(protocol: &str, status: u16, body: &[u8]) -> bool {
    if !(200..300).contains(&status) {
        return true;
    }
    match protocol {
        "openai_responses_sse_v1" => String::from_utf8_lossy(body).lines().any(|line| {
            matches!(
                line.trim(),
                "event: response.completed"
                    | "event: response.failed"
                    | "event: response.incomplete"
            )
        }),
        "opaque_json_v1" => serde_json::from_slice::<serde_json::Value>(body).is_ok(),
        _ => false,
    }
}

fn classify_transport(error: &reqwest::Error) -> ProviderTransportFailureV1 {
    if error.is_timeout() {
        ProviderTransportFailureV1::Timeout
    } else if error.is_connect() {
        ProviderTransportFailureV1::Connect
    } else if error.is_body() {
        ProviderTransportFailureV1::Body
    } else {
        ProviderTransportFailureV1::Other
    }
}

fn capability_entity(id: &InferenceCapabilityId) -> String {
    format!(
        "provider-capability-{}",
        id.digest()
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(id.digest().as_str())
    )
}

fn session_termination_entity(session: &ag_primitives::SessionId) -> String {
    format!("provider-session-termination-{}", session.as_str())
}

fn now_u64() -> Result<u64, ProviderError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| ProviderError::Clock)
}

fn now_i64() -> Result<i64, ProviderError> {
    i64::try_from(now_u64()?).map_err(|_| ProviderError::Clock)
}

fn provider_api_error<T>(error: &ProviderError) -> ApiResultV1<T> {
    let code = match error {
        ProviderError::Quiesced => ApiErrorCodeV1::Quiesced,
        ProviderError::ServiceAuthenticationRequired | ProviderError::CapabilityBindingMismatch => {
            ApiErrorCodeV1::Unauthenticated
        }
        ProviderError::CapabilityNotRegistered | ProviderError::DispatchNotFound => {
            ApiErrorCodeV1::NotFound
        }
        ProviderError::CapabilityRegistrationConflict
        | ProviderError::DispatchBindingMismatch
        | ProviderError::CustodyAcknowledgmentMismatch => ApiErrorCodeV1::Conflict,
        ProviderError::CapabilityUse(_) | ProviderError::SessionTerminated => {
            ApiErrorCodeV1::Unauthorized
        }
        ProviderError::CustodyBindingMismatch
        | ProviderError::RequestLimit
        | ProviderError::UnsafeHeader
        | ProviderError::AdapterRequestMismatch
        | ProviderError::EndpointNotAllowed => ApiErrorCodeV1::InvalidRequest,
        ProviderError::CredentialUnavailable
        | ProviderError::CommandPipe
        | ProviderError::CommandWait
        | ProviderError::DispatchOutcomeIndeterminate => ApiErrorCodeV1::Indeterminate,
        _ => ApiErrorCodeV1::Internal,
    };
    ApiResultV1::error(code, error.to_string())
}

/// Provider daemon implementation failures.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// Authority domain or epoch configuration is invalid.
    #[error(transparent)]
    Identifier(#[from] ag_primitives::IdentifierError),
    /// Store operation failed.
    #[error(transparent)]
    Store(#[from] ag_store::StoreError),
    /// Canonical identity failed.
    #[error(transparent)]
    Jcs(#[from] ag_primitives::JcsError),
    /// Capability definition failed.
    #[error(transparent)]
    CapabilityDefinition(#[from] ag_primitives::CapabilityDefinitionError),
    /// Live capability use failed.
    #[error(transparent)]
    CapabilityUse(#[from] ag_primitives::CapabilityUseError),
    /// Session custody binding failed.
    #[error(transparent)]
    Session(#[from] ag_session::SessionError),
    /// HTTP client construction failed.
    #[error("provider HTTP client failed")]
    Http(#[from] reqwest::Error),
    /// Header name is malformed.
    #[error("provider header name is invalid")]
    HeaderName(#[from] reqwest::header::InvalidHeaderName),
    /// Header value is malformed.
    #[error("provider header value is invalid")]
    HeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    /// Credential file read failed.
    #[error("provider credential cannot be read")]
    Io(#[from] std::io::Error),
    /// A fixed command transport pipe could not be established or drained.
    #[error("provider command pipe failed")]
    CommandPipe,
    /// A fixed command transport could not be observed to completion.
    #[error("provider command wait failed")]
    CommandWait,
    /// Endpoint IDs are duplicated.
    #[error("duplicate provider endpoint: {0}")]
    DuplicateEndpoint(String),
    /// Service-only method lacked daemon authentication.
    #[error("authenticated governor service is required")]
    ServiceAuthenticationRequired,
    /// Capability was not registered.
    #[error("provider capability is not registered")]
    CapabilityNotRegistered,
    /// Registration conflicts with an existing capability identity.
    #[error("provider capability registration conflicts with existing state")]
    CapabilityRegistrationConflict,
    /// Deterministic dispatch identity does not exist.
    #[error("provider dispatch does not exist")]
    DispatchNotFound,
    /// A retry found a burned reservation without durable completion bytes;
    /// redispatch would risk duplicating an externally accepted request.
    #[error("provider dispatch outcome is operationally indeterminate")]
    DispatchOutcomeIndeterminate,
    /// Dispatch entity, authority context, request, or capability disagrees.
    #[error("provider dispatch binding is inconsistent")]
    DispatchBindingMismatch,
    /// Durable available bytes fail their committed digest or size check.
    #[error("provider dispatch custody is corrupt")]
    DispatchCustodyCorrupt,
    /// Governor acknowledgment differs from exact retained custody.
    #[error("provider custody acknowledgment does not match retained bytes")]
    CustodyAcknowledgmentMismatch,
    /// Session has a durable terminal provider tombstone.
    #[error("provider session is terminal")]
    SessionTerminated,
    /// Session tombstone entity and body disagree.
    #[error("provider session tombstone identity is inconsistent")]
    SessionTombstoneMismatch,
    /// Capability aggregation exceeded its exact integer representation.
    #[error("provider session capability count overflowed")]
    CapabilityCountOverflow,
    /// Capability/session/live-peer binding differs.
    #[error("provider capability does not match live worker binding")]
    CapabilityBindingMismatch,
    /// Request bytes differ from exact governor custody.
    #[error("provider request does not match custody binding")]
    CustodyBindingMismatch,
    /// Request/reservation exceeds configured bounds.
    #[error("provider request exceeds configured bound")]
    RequestLimit,
    /// Worker attempted a credential/transport header.
    #[error("provider request contains a non-admitted header")]
    UnsafeHeader,
    /// Adapter request bytes disagree with capability envelope.
    #[error("provider request body does not match model envelope")]
    AdapterRequestMismatch,
    /// Endpoint/model/method/protocol is not root-configured.
    #[error("provider endpoint envelope is not allowed")]
    EndpointNotAllowed,
    /// systemd credential is absent or malformed.
    #[error("provider credential is unavailable")]
    CredentialUnavailable,
    /// Event stream could not be canonicalized.
    #[error("provider event stream canonicalization failed: {0}")]
    Canonical(String),
    /// Root policy is too small to encode even its bounded failure record.
    #[error("provider event-stream policy cannot encode a bounded failure record")]
    ConfiguredEventLimitTooSmall,
    /// Backup barrier fences dispatch/registration/revocation.
    #[error("provider daemon is quiesced for a coherent backup cut")]
    Quiesced,
    /// Trusted clock failed.
    #[error("trusted clock failed")]
    Clock,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use ag_primitives::{
        InferenceBudgetV1, InferenceEnvelopeV1, InferenceMethodId, LifecycleNonce, ModelId,
        PrincipalId, ProjectId, ProviderEndpointId, SessionId,
    };
    use ag_store::{StoreIdentityV1, WriterIdentityV1};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn provider_credential_reader_is_bounded_and_descriptor_safe() {
        let directory = tempfile::tempdir().expect("credential directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("credential directory mode");
        let credential = directory.path().join("provider-key");
        fs::write(&credential, b"secret-value\n").expect("credential bytes");
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))
            .expect("credential mode");
        assert_eq!(
            read_provider_credential(directory.path(), "provider-key")
                .expect("protected credential"),
            "secret-value\n"
        );

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o640)).expect("weak mode");
        assert!(
            read_provider_credential(directory.path(), "provider-key").is_err(),
            "group-readable credentials must fail closed"
        );

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o700))
            .expect("executable mode");
        assert!(
            read_provider_credential(directory.path(), "provider-key").is_err(),
            "executable credential files must fail closed"
        );

        fs::remove_file(&credential).expect("remove credential");
        let outside = directory.path().join("outside");
        fs::write(&outside, b"outside").expect("outside bytes");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).expect("outside mode");
        symlink(&outside, &credential).expect("credential symlink");
        assert!(read_provider_credential(directory.path(), "provider-key").is_err());
        assert!(read_provider_credential(directory.path(), "../outside").is_err());

        let malformed = directory.path().join("malformed");
        fs::write(&malformed, []).expect("empty credential");
        fs::set_permissions(&malformed, fs::Permissions::from_mode(0o600)).expect("malformed mode");
        assert!(read_provider_credential(directory.path(), "malformed").is_err());
        fs::write(&malformed, [0xff]).expect("non-UTF-8 credential");
        assert!(read_provider_credential(directory.path(), "malformed").is_err());
        fs::write(
            &malformed,
            vec![b'x'; usize::try_from(MAX_PROVIDER_CREDENTIAL_BYTES + 1).expect("test bound")],
        )
        .expect("oversized credential");
        assert!(read_provider_credential(directory.path(), "malformed").is_err());
    }

    #[test]
    fn every_explicit_transport_variant_is_root_routable() {
        let directory = tempfile::tempdir().unwrap();
        let mut config: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../config/providerd.example.toml")).unwrap();
        config.store.database = directory.path().join("provider.db");
        config.store.object_store = directory.path().join("objects");
        let mut local = config.endpoints[0].clone();
        local.id = "local".to_owned();
        local.models[0].id = "local-model".to_owned();
        local.protocol = "opaque_json_v1".to_owned();
        local.methods = vec!["chat.completions.create".to_owned()];
        local.transport = ProviderTransportConfigV1::LocalHttp {
            url: "http://orion:11434/v1/chat/completions".to_owned(),
            allowed_origins: vec!["http://orion:11434".to_owned()],
            redirect_policy: ag_app::config::ProviderLocalRedirectPolicyV1::Deny,
        };
        let mut command = config.endpoints[0].clone();
        command.id = "command".to_owned();
        command.models[0].id = "command-model".to_owned();
        command.protocol = "opaque_json_v1".to_owned();
        command.methods = vec!["command.complete".to_owned()];
        command.transport = ProviderTransportConfigV1::Command {
            command: ProviderCommandConfigV1 {
                adapter: "codex".to_owned(),
                model_argument: ProviderCommandModelArgumentV1::Required,
                executable: Path::new("/opt/codex/codex").to_path_buf(),
                working_directory: Path::new("/work").to_path_buf(),
                environment: BTreeMap::new(),
            },
        };
        config.endpoints.extend([local, command]);
        config.validate().unwrap();
        let identity = StoreIdentityV1::current(0x4147_5052, "provider-variant-test").unwrap();
        let writer = WriterIdentityV1 {
            writer_id: "provider-variant-test-writer".to_owned(),
            principal_digest: Digest::hash_bytes(b"provider-variant-test-writer"),
            process_nonce: uuid::Uuid::new_v4().to_string(),
            claimed_at_unix_ms: 1,
        };
        let store = Store::open(
            &config.store.database,
            &config.store.object_store,
            identity,
            &writer,
        )
        .unwrap();
        let core = ProviderCoreV1::new(store, config).unwrap();
        let session = SessionId::new("variant-session").unwrap();
        for (sequence, endpoint_id) in ["primary", "local", "command"].into_iter().enumerate() {
            let endpoint = core.endpoints.get(endpoint_id).unwrap();
            let mut nonce = [0_u8; 16];
            nonce[8..].copy_from_slice(&(sequence as u64).to_be_bytes());
            let capability = InferenceCapabilityV1::new(
                core.authority_domain.clone(),
                core.epoch,
                ProjectId::new("provider-tests").unwrap(),
                session.clone(),
                LifecycleNonce::new([0x5a; 16]),
                PrincipalId::new(Digest::hash_bytes(b"provider-test-worker")),
                core.provider_policy.clone(),
                InferenceEnvelopeV1 {
                    endpoint: ProviderEndpointId::new(endpoint.id.clone()).unwrap(),
                    model: ModelId::new(endpoint.models[0].id.clone()).unwrap(),
                    method: InferenceMethodId::new(endpoint.methods[0].clone()).unwrap(),
                    protocol_digest: Digest::hash_bytes(endpoint.protocol.as_bytes()),
                },
                InferenceBudgetV1 {
                    requests: 1,
                    input_bytes: 4096,
                    output_bytes: endpoint.models[0].max_event_stream_bytes,
                    cost_microunits: endpoint.models[0].worst_case_cost_microunits,
                },
                1,
                9_000_000_000_000,
                LifecycleNonce::new(nonce),
            )
            .unwrap();
            let (resolved, _) = core.ensure_endpoint(&capability).unwrap();
            assert_eq!(resolved.id, endpoint_id);
        }
    }

    struct ProviderFixture {
        _directory: TempDir,
        core: ProviderCoreV1,
        peer: VerifiedRpcPrincipalV1,
    }

    impl ProviderFixture {
        fn new() -> Self {
            Self::with_caller_kind(ag_primitives::PrincipalKindV1::Daemon)
        }

        fn with_caller_kind(kind: ag_primitives::PrincipalKindV1) -> Self {
            Self::with_config(|config| config.caller_peer.principal_kind = kind)
        }

        fn with_config(configure: impl FnOnce(&mut ProviderdConfigV1)) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let mut config: ProviderdConfigV1 =
                toml::from_str(include_str!("../../../config/providerd.example.toml")).unwrap();
            configure(&mut config);
            config.store.database = directory.path().join("provider.db");
            config.store.object_store = directory.path().join("objects");
            let peer = VerifiedRpcPrincipalV1 {
                principal: config.caller_peer.rpc_key.principal.clone(),
                key_id: config.caller_peer.rpc_key.key_id.clone(),
            };
            let identity =
                StoreIdentityV1::current(0x4147_5052, "provider-lifecycle-test").unwrap();
            let writer = WriterIdentityV1 {
                writer_id: "provider-lifecycle-test-writer".to_owned(),
                principal_digest: Digest::hash_bytes(b"provider-lifecycle-test-writer"),
                process_nonce: uuid::Uuid::new_v4().to_string(),
                claimed_at_unix_ms: 1,
            };
            let store = Store::open(
                &config.store.database,
                &config.store.object_store,
                identity,
                &writer,
            )
            .unwrap();
            let core = ProviderCoreV1::new(store, config).unwrap();
            Self {
                _directory: directory,
                core,
                peer,
            }
        }

        fn capability(&self, session: &SessionId, sequence: u64) -> InferenceCapabilityV1 {
            let endpoint = self.core.endpoints.get("primary").unwrap();
            let model_policy = &endpoint.models[0];
            let mut nonce = [0_u8; 16];
            nonce[8..].copy_from_slice(&sequence.to_be_bytes());
            InferenceCapabilityV1::new(
                self.core.authority_domain.clone(),
                self.core.epoch,
                ProjectId::new("provider-tests").unwrap(),
                session.clone(),
                LifecycleNonce::new([0x5a; 16]),
                PrincipalId::new(Digest::hash_bytes(b"provider-test-worker")),
                self.core.provider_policy.clone(),
                InferenceEnvelopeV1 {
                    endpoint: ProviderEndpointId::new(endpoint.id.clone()).unwrap(),
                    model: ModelId::new(model_policy.id.clone()).unwrap(),
                    method: InferenceMethodId::new(endpoint.methods[0].clone()).unwrap(),
                    protocol_digest: Digest::hash_bytes(endpoint.protocol.as_bytes()),
                },
                InferenceBudgetV1 {
                    requests: 4,
                    input_bytes: 4096,
                    output_bytes: model_policy.max_event_stream_bytes * 4,
                    cost_microunits: model_policy.worst_case_cost_microunits * 4,
                },
                1,
                9_000_000_000_000,
                LifecycleNonce::new(nonce),
            )
            .unwrap()
        }

        fn register(&mut self, capability: &InferenceCapabilityV1) -> ProviderResponseV1 {
            let result = self.core.handle(
                ProviderRequestV1::RegisterCapability {
                    capability: Box::new(capability.clone()),
                    worker_principal: capability.worker_principal.clone(),
                },
                &self.peer,
            );
            match result {
                ApiResultV1::Ok { response } => response,
                ApiResultV1::Error { code, message, .. } => {
                    panic!("registration failed with {code:?}: {message}")
                }
            }
        }

        fn install_available_dispatch(
            &mut self,
            capability: &InferenceCapabilityV1,
            request_bytes: &[u8],
        ) -> (Digest, Digest, Vec<u8>) {
            let request = request_custody(capability, request_bytes);
            let dispatch = dispatch_identity(
                &self.core.authority_domain,
                self.core.epoch,
                &capability.id(),
                &request.custody_record,
            )
            .unwrap();
            let event_stream = serde_jcs::to_vec(&ProviderEventStreamV1::HttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: OpaqueBytesV1::new(b"exact-provider-body".to_vec()),
                protocol_terminal: true,
            })
            .unwrap();
            let exact_event_stream = Digest::hash_bytes(&event_stream);
            let state = ProviderDispatchStateV1 {
                authority_domain: self.core.authority_domain.clone(),
                epoch: self.core.epoch,
                provider_policy_digest: self.core.provider_policy.clone(),
                dispatch: dispatch.clone(),
                capability: capability.id(),
                request_custody_record: request.custody_record,
                exact_request: request.exact_request,
                reserved_usage: InferenceUsageV1 {
                    requests: 1,
                    input_bytes: request_bytes.len() as u64,
                    output_bytes: event_stream.len() as u64,
                    cost_microunits: 1,
                },
                phase: ProviderDispatchPhaseV1::Available {
                    exact_event_stream: exact_event_stream.clone(),
                    event_stream: OpaqueBytesV1::new(event_stream.clone()),
                    sanitized_headers: Vec::new(),
                    protocol_terminal: true,
                },
            };
            self.core
                .store
                .append_event(
                    NewEventV1 {
                        event_id: uuid::Uuid::new_v4().to_string(),
                        entity_id: dispatch_entity(&dispatch),
                        event_kind: "provider-dispatch.completed-test.v1".to_owned(),
                        occurred_at_unix_ms: now_i64().unwrap(),
                        payload: &exact_event_stream,
                    },
                    &state,
                    0,
                )
                .unwrap();
            (dispatch, exact_event_stream, event_stream)
        }
    }

    fn assert_unauthorized(result: &ApiResultV1<ProviderResponseV1>) {
        assert!(matches!(
            result,
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Unauthorized,
                ..
            }
        ));
    }

    fn request_custody(
        capability: &InferenceCapabilityV1,
        request_bytes: &[u8],
    ) -> ProviderRequestCustodyV1 {
        #[derive(Serialize)]
        struct CustodyBinding<'a> {
            capability_id: &'a InferenceCapabilityId,
            exact_request: &'a Digest,
            sanitized_headers: &'a BTreeMap<String, String>,
            envelope: &'a ag_primitives::InferenceEnvelopeV1,
        }

        let capability_id = capability.id();
        let exact_request = Digest::hash_bytes(request_bytes);
        let sanitized_headers = BTreeMap::new();
        let custody_record = Digest::from_serializable(&CustodyBinding {
            capability_id: &capability_id,
            exact_request: &exact_request,
            sanitized_headers: &sanitized_headers,
            envelope: &capability.envelope,
        })
        .unwrap();
        ProviderRequestCustodyV1 {
            capability_id,
            exact_request,
            sanitized_headers,
            envelope: capability.envelope.clone(),
            custody_record,
        }
    }

    #[test]
    fn credential_headers_cannot_enter_governed_request() {
        let mut headers = BTreeMap::new();
        headers.insert("authorization".to_owned(), "secret".to_owned());
        assert!(matches!(
            validate_request_headers(&headers),
            Err(ProviderError::UnsafeHeader)
        ));
    }

    #[test]
    fn adapter_terminal_is_explicit() {
        assert!(protocol_terminal("opaque_json_v1", 200, br#"{"ok":true}"#));
        assert!(!protocol_terminal("opaque_json_v1", 200, b"partial"));
        assert!(protocol_terminal(
            "openai_responses_sse_v1",
            200,
            b"event: response.completed\ndata: {}\n\n"
        ));
    }

    #[test]
    fn fixed_command_transport_captures_success_and_sanitizes_failure() {
        let fixture = ProviderFixture::new();
        let executable = fixture._directory.path().join("fake-claude");
        fs::write(
            &executable,
            "#!/bin/sh\ninput=$(cat)\nprintf '{\"result\":\"ok\",\"input\":\"%s\"}' \"$input\"\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let command = ProviderCommandConfigV1 {
            adapter: "claude-code".to_owned(),
            model_argument: ProviderCommandModelArgumentV1::Required,
            executable: executable.clone(),
            working_directory: fixture._directory.path().to_path_buf(),
            environment: BTreeMap::new(),
        };
        let request =
            br#"{"messages":[{"content":"hello","role":"user"}],"model":"production-model"}"#;
        let event = fixture
            .core
            .dispatch_command(&command, request.to_vec(), 16 * 1024)
            .unwrap();
        assert!(matches!(
            event,
            ProviderEventStreamV1::HttpResponse {
                status: 200,
                protocol_terminal: true,
                ..
            }
        ));

        fs::write(
            &executable,
            "#!/bin/sh\ncat >/dev/null\necho super-secret >&2\nexit 7\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let event = fixture
            .core
            .dispatch_command(&command, request.to_vec(), 16 * 1024)
            .unwrap();
        let ProviderEventStreamV1::HttpResponse { status, body, .. } = event else {
            panic!("expected terminal sanitized command refusal")
        };
        assert_eq!(status, 502);
        let text = String::from_utf8(body.into_vec()).unwrap();
        assert!(text.contains("command_refused"));
        assert!(!text.contains("super-secret"));
    }

    #[test]
    fn codex_provider_default_omits_the_model_flag() {
        let fixture = ProviderFixture::new();
        let executable = fixture._directory.path().join("fake-codex");
        fs::write(
            &executable,
            "#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = -m ] && exit 9; done\ncat >/dev/null\nprintf '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"READY\"}}\\n'\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let command = ProviderCommandConfigV1 {
            adapter: "codex".to_owned(),
            model_argument: ProviderCommandModelArgumentV1::Omit,
            executable,
            working_directory: fixture._directory.path().to_path_buf(),
            environment: BTreeMap::new(),
        };
        let request =
            br#"{"messages":[{"content":"hello","role":"user"}],"model":"provider-default"}"#;
        assert!(matches!(
            fixture
                .core
                .dispatch_command(&command, request.to_vec(), 16 * 1024),
            Ok(ProviderEventStreamV1::HttpResponse { status: 200, .. })
        ));
    }

    #[test]
    fn local_http_redirect_is_captured_and_never_followed() {
        let escaped = TcpListener::bind("127.0.0.1:0").unwrap();
        escaped.set_nonblocking(true).unwrap();
        let escaped_origin = format!("http://{}", escaped.local_addr().unwrap());
        let escaped_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&escaped_hits);
        let escaped_thread = thread::spawn(move || {
            let started = std::time::Instant::now();
            while started.elapsed() < Duration::from_millis(500) {
                match escaped.accept() {
                    Ok((_stream, _)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });

        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_origin = format!("http://{}", redirect.local_addr().unwrap());
        let redirect_url = format!("{redirect_origin}/v1/chat/completions");
        let location = format!("{escaped_origin}/credential-escape");
        let redirect_thread = thread::spawn(move || {
            let (mut stream, _) = redirect.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let mut fixture = ProviderFixture::with_config(|config| {
            config.endpoints[0].transport = ProviderTransportConfigV1::LocalHttp {
                url: redirect_url,
                allowed_origins: vec![redirect_origin],
                redirect_policy: ag_app::config::ProviderLocalRedirectPolicyV1::Deny,
            };
        });
        let capability = fixture.capability(&SessionId::new("redirect-session").unwrap(), 1);
        let endpoint = fixture.core.endpoints.remove("primary").unwrap();
        let event = fixture
            .core
            .dispatch(
                &endpoint,
                &request_custody(
                    &capability,
                    br#"{"messages":[{"content":"hello","role":"user"}],"model":"production-model"}"#,
                ),
                br#"{"messages":[{"content":"hello","role":"user"}],"model":"production-model"}"#.to_vec(),
                16 * 1024,
            )
            .unwrap();
        assert!(matches!(
            event,
            ProviderEventStreamV1::HttpResponse { status: 302, .. }
        ));
        redirect_thread.join().unwrap();
        escaped_thread.join().unwrap();
        assert_eq!(escaped_hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn http_timeout_stays_reserved_and_replay_never_redispatches() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let url = format!("{origin}/v1/chat/completions");
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&hits);
        let server = thread::spawn(move || {
            let started = std::time::Instant::now();
            while started.elapsed() < Duration::from_millis(750) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        observed.fetch_add(1, Ordering::SeqCst);
                        let mut request = [0_u8; 4096];
                        let _ = stream.read(&mut request);
                        thread::sleep(Duration::from_millis(250));
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        let mut fixture = ProviderFixture::with_config(|config| {
            config.limits.provider_deadline_ms = 50;
            config.endpoints[0].transport = ProviderTransportConfigV1::LocalHttp {
                url,
                allowed_origins: vec![origin],
                redirect_policy: ag_app::config::ProviderLocalRedirectPolicyV1::Deny,
            };
        });
        let session = SessionId::new("timeout-session").unwrap();
        let capability = fixture.capability(&session, 1);
        fixture.register(&capability);
        let bytes =
            br#"{"messages":[{"content":"hello","role":"user"}],"model":"production-model"}"#;
        let request = request_custody(&capability, bytes);
        let infer = || ProviderRequestV1::Infer {
            capability: Box::new(capability.clone()),
            request: Box::new(request.clone()),
            request_bytes: OpaqueBytesV1::new(bytes.to_vec()),
        };
        for _ in 0..2 {
            assert!(matches!(
                fixture.core.handle(infer(), &fixture.peer),
                ApiResultV1::Error {
                    code: ApiErrorCodeV1::Indeterminate,
                    ..
                }
            ));
        }
        server.join().unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timed_out_command_kills_the_process_group_and_is_indeterminate() {
        let mut fixture = ProviderFixture::new();
        fixture.core.config.limits.provider_deadline_ms = 50;
        let executable = fixture._directory.path().join("slow-command");
        let marker = fixture._directory.path().join("survived");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\n(sleep 1; printf survived > '{}') &\nwait\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let command = ProviderCommandConfigV1 {
            adapter: "claude-code".to_owned(),
            model_argument: ProviderCommandModelArgumentV1::Required,
            executable,
            working_directory: fixture._directory.path().to_path_buf(),
            environment: BTreeMap::new(),
        };
        let request =
            br#"{"messages":[{"content":"hello","role":"user"}],"model":"production-model"}"#;
        assert!(matches!(
            fixture
                .core
                .dispatch_command(&command, request.to_vec(), 16 * 1024),
            Err(ProviderError::DispatchOutcomeIndeterminate)
        ));
        thread::sleep(Duration::from_millis(1100));
        assert!(
            !marker.exists(),
            "the timed-out command process tree survived"
        );
    }

    #[test]
    fn complete_event_stream_uses_base64_and_is_bounded_in_its_exact_domain() {
        let event = ProviderEventStreamV1::HttpResponse {
            status: 200,
            headers: BTreeMap::from([("request-id".to_owned(), "abc".to_owned())]),
            body: OpaqueBytesV1::new(vec![0, 255]),
            protocol_terminal: true,
        };
        let encoded = serde_jcs::to_vec(&event).unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains(r#""body":"AP8=""#));
        assert!(!text.contains(r#""body":["#));

        let oversized = ProviderEventStreamV1::HttpResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: OpaqueBytesV1::new(vec![0x5a; 4096]),
            protocol_terminal: true,
        };
        let (limited, exact_bytes) = bounded_event_stream_bytes(oversized, 4096).unwrap();
        assert!(matches!(
            limited,
            ProviderEventStreamV1::ResponseLimitExceeded { .. }
        ));
        assert!(exact_bytes.len() <= 4096);
    }

    #[test]
    fn root_model_policy_reserves_nonzero_worst_case_cost_before_dispatch() {
        let mut fixture = ProviderFixture::new();
        let session = SessionId::new("priced-session").unwrap();
        let mut capability = fixture.capability(&session, 1);
        let endpoint = fixture.core.endpoints.get("primary").unwrap();
        capability.budget.cost_microunits = endpoint.models[0]
            .worst_case_cost_microunits
            .saturating_sub(1);
        fixture.register(&capability);
        let request_bytes = br#"{"model":"production-model"}"#.to_vec();
        let custody = request_custody(&capability, &request_bytes);

        let result = fixture.core.handle(
            ProviderRequestV1::Infer {
                capability: Box::new(capability.clone()),
                request: Box::new(custody),
                request_bytes: OpaqueBytesV1::new(request_bytes),
            },
            &fixture.peer,
        );
        assert_unauthorized(&result);
        let stored = fixture
            .core
            .store
            .materialized_state::<ProviderCapabilityStateV1>(&capability_entity(&capability.id()))
            .unwrap()
            .unwrap();
        assert_eq!(stored.state.usage, InferenceUsageV1::default());
    }

    #[test]
    fn infer_wire_rejects_caller_selected_cost_or_output_reservations() {
        let fixture = ProviderFixture::new();
        let capability = fixture.capability(&SessionId::new("strict-wire-session").unwrap(), 4);
        let request_bytes = br#"{"model":"production-model"}"#.to_vec();
        let request = ProviderRequestV1::Infer {
            capability: Box::new(capability.clone()),
            request: Box::new(request_custody(&capability, &request_bytes)),
            request_bytes: OpaqueBytesV1::new(request_bytes),
        };
        let mut wire = serde_json::to_value(request).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("reserved_cost_microunits".to_owned(), serde_json::json!(0));
        wire.as_object_mut()
            .unwrap()
            .insert("reserved_output_bytes".to_owned(), serde_json::json!(1));
        assert!(serde_json::from_value::<ProviderRequestV1>(wire).is_err());
    }

    #[test]
    fn retry_of_reserved_dispatch_is_indeterminate_and_never_charged_twice() {
        let mut fixture = ProviderFixture::new();
        let session = SessionId::new("reserved-retry-session").unwrap();
        let capability = fixture.capability(&session, 7);
        fixture.register(&capability);
        let request_bytes = br#"{"model":"production-model"}"#.to_vec();
        let request = request_custody(&capability, &request_bytes);
        let capability_id = capability.id();
        let capability_entity = capability_entity(&capability_id);
        let loaded = fixture
            .core
            .store
            .materialized_state::<ProviderCapabilityStateV1>(&capability_entity)
            .unwrap()
            .unwrap();
        let model = &fixture.core.endpoints.get("primary").unwrap().models[0];
        let reserved_usage = InferenceUsageV1 {
            requests: 1,
            input_bytes: request_bytes.len() as u64,
            output_bytes: model.max_event_stream_bytes,
            cost_microunits: model.worst_case_cost_microunits,
        };
        let dispatch = dispatch_identity(
            &fixture.core.authority_domain,
            fixture.core.epoch,
            &capability_id,
            &request.custody_record,
        )
        .unwrap();
        let capability_state = ProviderCapabilityStateV1 {
            usage: reserved_usage,
            ..loaded.state
        };
        let dispatch_state = ProviderDispatchStateV1 {
            authority_domain: fixture.core.authority_domain.clone(),
            epoch: fixture.core.epoch,
            provider_policy_digest: fixture.core.provider_policy.clone(),
            dispatch: dispatch.clone(),
            capability: capability_id,
            request_custody_record: request.custody_record.clone(),
            exact_request: request.exact_request.clone(),
            reserved_usage,
            phase: ProviderDispatchPhaseV1::Reserved,
        };
        fixture
            .core
            .store
            .append_distinct_event_pair(
                NewEventV1 {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    entity_id: capability_entity.clone(),
                    event_kind: "provider-dispatch.reserved-test.v1".to_owned(),
                    occurred_at_unix_ms: now_i64().unwrap(),
                    payload: &dispatch,
                },
                &capability_state,
                loaded.revision,
                NewEventV1 {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    entity_id: dispatch_entity(&dispatch),
                    event_kind: "provider-dispatch.custody-reserved-test.v1".to_owned(),
                    occurred_at_unix_ms: now_i64().unwrap(),
                    payload: &dispatch,
                },
                &dispatch_state,
                0,
            )
            .unwrap();

        let retried = fixture.core.handle(
            ProviderRequestV1::Infer {
                capability: Box::new(capability),
                request: Box::new(request),
                request_bytes: OpaqueBytesV1::new(request_bytes),
            },
            &fixture.peer,
        );
        assert!(matches!(
            retried,
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Indeterminate,
                ..
            }
        ));
        let stored = fixture
            .core
            .store
            .materialized_state::<ProviderCapabilityStateV1>(&capability_entity)
            .unwrap()
            .unwrap();
        assert_eq!(stored.state.usage, reserved_usage);
    }

    #[test]
    fn exact_response_survives_fetch_until_durable_ack_then_plaintext_is_cleared() {
        let mut fixture = ProviderFixture::new();
        let session = SessionId::new("custody-session").unwrap();
        let capability = fixture.capability(&session, 2);
        let request_bytes = br#"{"model":"production-model"}"#;
        let (dispatch, exact_event_stream, event_stream) =
            fixture.install_available_dispatch(&capability, request_bytes);

        for _ in 0..2 {
            let fetched = fixture.core.handle(
                ProviderRequestV1::FetchInference {
                    dispatch: dispatch.clone(),
                },
                &fixture.peer,
            );
            let ApiResultV1::Ok {
                response:
                    ProviderResponseV1::Inference {
                        event_stream: fetched,
                        exact_event_stream: fetched_digest,
                        ..
                    },
            } = fetched
            else {
                panic!("exact available custody was not fetchable");
            };
            assert_eq!(fetched.as_slice(), event_stream);
            assert_eq!(fetched_digest, exact_event_stream);
        }

        let governor_custody_record = Digest::hash_bytes(b"durable-agd-custody");
        let mismatch = fixture.core.handle(
            ProviderRequestV1::AcknowledgeInferenceCustody {
                dispatch: dispatch.clone(),
                exact_event_stream: Digest::hash_bytes(b"forged-event-stream"),
                governor_custody_record: governor_custody_record.clone(),
            },
            &fixture.peer,
        );
        assert!(matches!(
            mismatch,
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Conflict,
                ..
            }
        ));
        let acknowledged = fixture.core.handle(
            ProviderRequestV1::AcknowledgeInferenceCustody {
                dispatch: dispatch.clone(),
                exact_event_stream: exact_event_stream.clone(),
                governor_custody_record: governor_custody_record.clone(),
            },
            &fixture.peer,
        );
        assert!(matches!(
            acknowledged,
            ApiResultV1::Ok {
                response: ProviderResponseV1::InferenceCustodyAcknowledged { .. }
            }
        ));
        let stored = fixture
            .core
            .store
            .materialized_state::<ProviderDispatchStateV1>(&dispatch_entity(&dispatch))
            .unwrap()
            .unwrap();
        assert!(matches!(
            stored.state.phase,
            ProviderDispatchPhaseV1::Acknowledged {
                exact_event_stream: stored,
                governor_custody_record: custody,
                ..
            } if stored == exact_event_stream && custody == governor_custody_record
        ));
    }

    #[test]
    fn provider_health_does_not_claim_missing_worker_session_ingress() {
        let mut fixture = ProviderFixture::new();
        let response = fixture
            .core
            .handle(ProviderRequestV1::Health {}, &fixture.peer);
        assert!(matches!(
            response,
            ApiResultV1::Ok {
                response: ProviderResponseV1::Health {
                    health: HealthV1 { ready: false, .. }
                }
            }
        ));
    }

    #[test]
    fn fixed_service_health_is_ready_and_capabilities_are_bound_to_its_signed_identity() {
        let mut fixture =
            ProviderFixture::with_caller_kind(ag_primitives::PrincipalKindV1::Service);
        let response = fixture
            .core
            .handle(ProviderRequestV1::Health {}, &fixture.peer);
        assert!(matches!(
            response,
            ApiResultV1::Ok {
                response: ProviderResponseV1::Health {
                    health: HealthV1 { ready: true, .. }
                }
            }
        ));

        let session = SessionId::new("fixed-service-session").unwrap();
        let mut rejected = fixture.capability(&session, 1);
        assert!(matches!(
            fixture.core.handle(
                ProviderRequestV1::RegisterCapability {
                    capability: Box::new(rejected.clone()),
                    worker_principal: rejected.worker_principal.clone(),
                },
                &fixture.peer,
            ),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Unauthenticated,
                ..
            }
        ));

        rejected.worker_principal = PrincipalId::new(fixture.peer.principal.clone());
        assert!(matches!(
            fixture.core.handle(
                ProviderRequestV1::RegisterCapability {
                    capability: Box::new(rejected.clone()),
                    worker_principal: rejected.worker_principal.clone(),
                },
                &fixture.peer,
            ),
            ApiResultV1::Ok {
                response: ProviderResponseV1::CapabilityRegistered { .. }
            }
        ));
    }

    #[test]
    fn in_progress_tombstone_rejects_late_registration_and_use() {
        let mut fixture = ProviderFixture::new();
        let session = SessionId::new("terminal-session").unwrap();
        let terminal_since_unix_ms = now_u64().unwrap();
        let tombstone = ProviderSessionTerminationStateV1 {
            authority_domain: fixture.core.authority_domain.clone(),
            epoch: fixture.core.epoch,
            provider_policy_digest: fixture.core.provider_policy.clone(),
            session: session.clone(),
            terminal_since_unix_ms,
            completion: None,
        };
        fixture
            .core
            .store
            .append_event(
                NewEventV1 {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    entity_id: session_termination_entity(&session),
                    event_kind: "provider-session.termination-started.v1".to_owned(),
                    occurred_at_unix_ms: i64::try_from(terminal_since_unix_ms).unwrap(),
                    payload: &session,
                },
                &tombstone,
                0,
            )
            .unwrap();

        let capability = fixture.capability(&session, 1);
        assert_unauthorized(&fixture.core.handle(
            ProviderRequestV1::RegisterCapability {
                capability: Box::new(capability.clone()),
                worker_principal: capability.worker_principal.clone(),
            },
            &fixture.peer,
        ));
        let request_bytes = br#"{"model":"production-model"}"#.to_vec();
        let custody = ProviderRequestCustodyV1 {
            capability_id: capability.id(),
            exact_request: Digest::hash_bytes(&request_bytes),
            sanitized_headers: BTreeMap::new(),
            envelope: capability.envelope.clone(),
            custody_record: Digest::hash_bytes(b"unreached-invalid-custody"),
        };
        assert_unauthorized(&fixture.core.handle(
            ProviderRequestV1::Infer {
                capability: Box::new(capability),
                request: Box::new(custody),
                request_bytes: OpaqueBytesV1::new(request_bytes),
            },
            &fixture.peer,
        ));

        let result = fixture.core.handle(
            ProviderRequestV1::TerminateSession {
                session: session.clone(),
            },
            &fixture.peer,
        );
        let ApiResultV1::Ok {
            response: ProviderResponseV1::SessionTerminated { receipt },
        } = result
        else {
            panic!("incomplete tombstone did not resume");
        };
        let stored = fixture
            .core
            .store
            .materialized_state::<ProviderSessionTerminationStateV1>(&session_termination_entity(
                &session,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(stored.state.completion.unwrap().receipt, receipt);
    }

    #[test]
    fn paginated_termination_is_complete_durable_and_idempotent() {
        let mut fixture = ProviderFixture::new();
        let session = SessionId::new("many-capabilities").unwrap();
        let capability_total = u64::from(TERMINATION_PAGE_SIZE) + 5;
        let mut capability_ids = Vec::new();
        for sequence in 0..capability_total {
            let capability = fixture.capability(&session, sequence);
            capability_ids.push(capability.id());
            assert!(matches!(
                fixture.register(&capability),
                ProviderResponseV1::CapabilityRegistered { .. }
            ));
        }

        let terminated = fixture.core.handle(
            ProviderRequestV1::TerminateSession {
                session: session.clone(),
            },
            &fixture.peer,
        );
        let ApiResultV1::Ok {
            response: ProviderResponseV1::SessionTerminated { receipt },
        } = terminated
        else {
            panic!("paginated termination failed");
        };
        let stored = fixture
            .core
            .store
            .materialized_state::<ProviderSessionTerminationStateV1>(&session_termination_entity(
                &session,
            ))
            .unwrap()
            .unwrap();
        let completion = stored.state.completion.unwrap();
        assert_eq!(completion.capability_count, capability_total);
        assert_eq!(completion.receipt, receipt);
        for capability_id in capability_ids {
            let capability = fixture
                .core
                .store
                .materialized_state::<ProviderCapabilityStateV1>(&capability_entity(&capability_id))
                .unwrap()
                .unwrap();
            assert_eq!(
                capability.state.session_state,
                SessionLifecycleStateV1::Terminal
            );
            assert!(matches!(
                capability.state.revocation_state,
                RevocationStateV1::Revoked { .. }
            ));
        }

        let head_before_retry = fixture.core.store.chain_head().unwrap();
        let retried = fixture.core.handle(
            ProviderRequestV1::TerminateSession { session },
            &fixture.peer,
        );
        assert!(matches!(
            retried,
            ApiResultV1::Ok {
                response: ProviderResponseV1::SessionTerminated {
                    receipt: retried_receipt
                }
            } if retried_receipt == receipt
        ));
        assert_eq!(fixture.core.store.chain_head().unwrap(), head_before_retry);
    }
}
