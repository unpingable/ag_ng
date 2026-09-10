//! Governor-side calculus replay and broker forwarding.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ag_effect::{EFFECT_SCHEMA_V1, EffectIntentV1, ProposalIntentV1, TargetId};
use ag_kernel::{
    AdmissionCommit, CapacityBook, CapacityBookEntry, CapacityClaim, CapacityRef, CustodyBook,
    CustodyBookEntry, CustodyClaim, CustodyRef, EffectCrossingClaim, EffectCrossingRefusal,
    EffectCrossingWitness, FailureEvidence, NativeJudgment, NonEmpty, ObligationBook,
    ObligationBookEntry, ObligationClaim, ObligationRef, StandingBook, StandingBookEntry,
    StandingClaim, StandingRef, evaluate_effect_crossing, reconstruct_effect_authority,
};
use ag_primitives::{
    AuthorityDomain, BookLocalId, CgroupIdentity, Digest, Epoch, HostCredentialObservationV1,
    InferenceCapabilityV1, LaunchProfileIdentityV1, LifecycleNonce, LifecycleOrigin,
    PrincipalChainNodeV1, PrincipalChainV1, PrincipalId, PrincipalKindV1, PrincipalNameError,
    ProjectId, SessionId, WorkerProviderRouteV1, WorkerSessionPrincipalV1,
};
use ag_protocol::{FrameCodec, RequestId};
use ag_session::{
    AdmittedDescriptorV1, BatchSessionSpecV1, DescriptorAccessV1, DescriptorPurposeV1,
    IsolationEvidenceV1, ProviderRequestCustodyV1, ProviderResponseCustodyV1, SecurityProfileV1,
    SessionError, SourceSnapshotV1, WorkerBindingV1, WorkerCandidateBrokerOutcomeV1,
    WorkerCandidateCustodyStateV1, WorkerCandidateRefusalCodeV1, WorkerIngressContextV1,
    WorkerSessionRecordV1, WorkerTerminationReasonV1, WorkspaceModeV1,
};
use ag_store::{BlobDescriptorV1, NewEventV1, Store};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::{
    AgdRequestV1, AgdResponseV1, ApiErrorCodeV1, ApiResultV1, ArtifactTransferV1,
    EffectProposalRequestV1, EffectProposalResponseV1, GovernedProposalIngressV1, HealthV1,
    ProposalIngressProofV1, WorkerCandidateBootstrapV1, WorkerCandidateIngressProofV1,
    WorkerCandidateRequestV1, WorkerCandidateSourceProofV1, worker_candidate_ingress_proof_digest,
};
use crate::config::{AgdConfigV1, WorkerCandidateEffectV1, WorkerProfileConfigV1};
use crate::peer::signed_principal_chain;
use crate::rpc_auth::{
    EphemeralRpcPrivateKeyV1, RpcKeyIdV1, RpcPeerEnrollmentV1, RpcPeerKeyPolicyV1,
    RpcReplayGuardV1, RpcSignerV1, SignedServerChallengeV1, SystemRpcClockV1,
    VerifiedRpcPrincipalV1, candidate_ingress_key_identity, verify_forwarded_signed_request,
    verify_forwarded_signed_request_bindings,
};
use crate::signed_transport::{AcceptedSignedRequestV1, SocketPeerCheckV1, call_signed};
use crate::worker::{
    AdmittedWorkerInputV1, PreparedWorkerLaunchV1, WorkerLaunchError, WorkerLaunchReleaseV1,
    WorkerProcessV1, prepare_worker_launch,
};
use crate::worker_protocol::{
    CANDIDATE_BOOTSTRAP_PURPOSE, CANDIDATE_INGRESS_CREDENTIAL_PURPOSE, WorkerProtocolError,
    decode_exact_signed_worker_candidate,
};
use crate::worker_session::{
    WorkerSessionStoreError, WorkerSessionStoreV1, WorkerStartupRecoveryReportV1,
};

/// Exact replay inputs from the four separately committed family books.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectBookSnapshotV1 {
    /// One lifecycle origin shared by every entry/claim.
    pub origin: LifecycleOrigin,
    /// Standing entries in durable replay order.
    pub standing: Vec<StandingBookEntry>,
    /// Custody entries in durable replay order.
    pub custody: Vec<CustodyBookEntry>,
    /// Obligation entries in durable replay order.
    pub obligation: Vec<ObligationBookEntry>,
    /// Capacity entries in durable replay order.
    pub capacity: Vec<CapacityBookEntry>,
}

/// Internal input produced from governed session custody, never a public
/// authority token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectEvaluationInputV1 {
    /// Semantic proposal subject.
    pub subject: Digest,
    /// Exact committed book replay.
    pub books: EffectBookSnapshotV1,
    /// Named four-family crossing claim.
    pub claim: EffectCrossingClaim,
}

/// Durable, lossless outcome of one governed effect evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredEffectJudgmentV1 {
    /// Semantic admission plus reconstructable committed evidence.
    Admit {
        /// Evidence record; not bearer authority.
        commit: Box<AdmissionCommit<EffectCrossingWitness>>,
    },
    /// Semantic refusal preserving all family-native failures.
    Refuse {
        /// Exact composite refusal.
        refusal: EffectCrossingRefusal,
    },
    /// Evaluation did not reach a semantic answer.
    Indeterminate {
        /// Non-empty operational envelope.
        failures: NonEmpty<FailureEvidence>,
    },
}

/// Materialized judgment record in the governor store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectJudgmentRecordV1 {
    /// Exact record schema.
    pub schema: String,
    /// Semantic proposal subject.
    pub subject: Digest,
    /// Reconstructable book snapshot, absent only for pre-replay indeterminate outcomes.
    pub books: Option<EffectBookSnapshotV1>,
    /// Lossless semantic/operational outcome.
    pub judgment: StoredEffectJudgmentV1,
}

/// Result of rebuilding sealed authority immediately before broker forwarding.
/// This record is evidence of a local check, not the authority object itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedEffectAdmissionV1 {
    /// Judgment record identity.
    pub judgment: Digest,
    /// Exact committed evidence identity returned by sealed authority.
    pub commit: Digest,
}

/// Durable governor outbox state committed before crossing into effectd.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ForwardOutboxStateV1 {
    /// Admission was reconstructed and dispatch may be resumed.
    Pending,
    /// Effectd returned this exact terminal submission outcome.
    Completed {
        /// Exact governor response returned on every semantic retry.
        response: AgdResponseV1,
    },
}

/// One semantic proposal forwarding operation, uniquely keyed independently
/// from transport nonces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardOutboxRecordV1 {
    /// Record schema.
    pub schema: String,
    /// Exact stable source identity.
    pub source: Digest,
    /// Exact intent bytes identity.
    pub intent: Digest,
    /// Reconstructed admission evidence.
    pub admission: VerifiedEffectAdmissionV1,
    /// Exact authenticated proposer exchange to resume after a crash.
    ///
    /// This is evidence already accepted by agd, not bearer authority.
    /// Effectd independently verifies it and permits a stale/replayed proof
    /// only when it exactly matches the proof in an existing durable result.
    pub ingress: GovernedProposalIngressV1,
    /// Durable dispatch lifecycle.
    pub state: ForwardOutboxStateV1,
}

/// Durable governor custody for one worker-selected inference attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProviderAttemptRecordV1 {
    /// Exact schema.
    pub schema: String,
    /// Active session from retained descriptor custody.
    pub session: SessionId,
    /// Exact live worker principal resolved by the governor.
    pub worker_principal: PrincipalId,
    /// Worker-local stable attempt identity.
    pub attempt: RequestId,
    /// Exact credential-free request custody.
    pub request: ProviderRequestCustodyV1,
    /// Dispatch and response custody lifecycle.
    pub state: WorkerProviderAttemptStateV1,
}

/// Crash-reconcilable lifecycle for one provider attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerProviderAttemptStateV1 {
    /// Exact request bytes are durable; no provider outcome is asserted.
    RequestInCustody,
    /// Provider daemon reports a durable dispatch available for fetch.
    DispatchAvailable {
        /// Provider-owned deterministic dispatch identity.
        dispatch: Digest,
        /// Exact complete stream digest reported by provider custody.
        exact_event_stream: Digest,
        /// True only when the provider adapter observed its terminal marker.
        protocol_terminal: bool,
    },
    /// Complete response bytes are durable in the governor store.
    ResponseInCustody {
        /// Provider-owned dispatch identity.
        dispatch: Digest,
        /// Exact governor response custody.
        response: ProviderResponseCustodyV1,
    },
    /// Provider daemon durably acknowledged governor custody.
    Acknowledged {
        /// Provider-owned dispatch identity.
        dispatch: Digest,
        /// Exact governor response custody.
        response: ProviderResponseCustodyV1,
        /// Provider-owned acknowledgment receipt.
        provider_receipt: Digest,
    },
}

/// Result of one bounded startup pass over the durable forwarding outbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ForwardRecoveryReportV1 {
    /// Pending records whose exact durable effectd response was recovered.
    pub completed: u64,
    /// Records which still require effectd availability or a fresh proposer proof.
    pub deferred: u64,
}

enum ForwardOutboxPreparationV1 {
    Completed(AgdResponseV1),
    Pending {
        entity: String,
        record: Box<ForwardOutboxRecordV1>,
        revision: u64,
    },
}

struct ActiveWorkerRuntimeV1 {
    process: WorkerProcessV1,
    governor_enrollment: RpcPeerKeyPolicyV1,
    worker_enrollment: RpcPeerKeyPolicyV1,
    server_challenge: SignedServerChallengeV1,
    ingress: WorkerRuntimeIngressBindingsV1,
}

/// Launcher-retained facts used to revalidate live candidate ingress.
///
/// These values are captured from the descriptor-bound prepared launch before
/// the durable session record is written.  Ingress compares them with the
/// independently reloaded session; it never manufactures "live" evidence by
/// copying the values it is supposed to check from that record.
struct WorkerRuntimeIngressBindingsV1 {
    authority_domain: AuthorityDomain,
    epoch: Epoch,
    principal_id: PrincipalId,
    session_id: SessionId,
    proposal_workspace_identity: Digest,
    security_profile_identity: Digest,
    executable: ag_primitives::ExecutableIdentityV1,
    observed_uid: u32,
    observed_gid: u32,
    session_binding: Digest,
}

impl WorkerRuntimeIngressBindingsV1 {
    fn context(&self, now_unix_ms: u64) -> WorkerIngressContextV1 {
        WorkerIngressContextV1 {
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            principal_id: self.principal_id.clone(),
            session_id: self.session_id.clone(),
            proposal_workspace_identity: self.proposal_workspace_identity.clone(),
            security_profile_identity: self.security_profile_identity.clone(),
            executable: self.executable.clone(),
            observed_uid: self.observed_uid,
            observed_gid: self.observed_gid,
            now_unix_ms,
        }
    }
}

/// Result of one nonblocking pass over the live worker set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerPollReportV1 {
    /// Processes which remain live after this pass.
    pub pending: u64,
    /// Complete authenticated candidates committed to durable custody.
    pub accepted: u64,
    /// Workers durably fenced after a known terminal failure.
    pub failed: u64,
    /// Accepted candidates whose broker forward remains recoverable.
    pub deferred: u64,
}

/// Result of one bounded startup pass over accepted candidate custody.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerCandidateRecoveryReportV1 {
    /// Sessions linked to broker-owned canonical proposal bytes.
    pub canonicalized: u64,
    /// Sessions durably linked to broker-owned semantic refusals.
    pub refused: u64,
    /// Sessions durably linked to broker-owned reconciliation envelopes.
    pub indeterminate: u64,
    /// Safe, tombstoned custody which still awaits broker availability/outcome.
    pub deferred: u64,
}

/// Single-writer governor core.
pub struct AgdCoreV1 {
    store: Store,
    config: AgdConfigV1,
    authority_domain: AuthorityDomain,
    epoch: Epoch,
    rpc_signer: Arc<RpcSignerV1>,
    rpc_replay: Arc<RpcReplayGuardV1>,
    active_workers: BTreeMap<SessionId, ActiveWorkerRuntimeV1>,
    worker_recovery_required: bool,
}

impl AgdCoreV1 {
    /// Constructs a governor after verifying its event chain.
    ///
    /// # Errors
    ///
    /// Returns an error if the store chain is corrupt or the configured
    /// authority domain or epoch is invalid.
    pub fn new(
        store: Store,
        config: AgdConfigV1,
        rpc_signer: Arc<RpcSignerV1>,
        rpc_replay: Arc<RpcReplayGuardV1>,
    ) -> Result<Self, AgdError> {
        store.verify_chain()?;
        let authority_domain = AuthorityDomain::parse(&config.authority_domain)?;
        let epoch = Epoch::parse(&config.epoch)?;
        Ok(Self {
            store,
            config,
            authority_domain,
            epoch,
            rpc_signer,
            rpc_replay,
            active_workers: BTreeMap::new(),
            worker_recovery_required: false,
        })
    }

    /// Permanently retires every prepared or active worker principal found
    /// after daemon startup. Historical records remain inspectable; no
    /// principal is recreated or worker relaunched.
    ///
    /// # Errors
    ///
    /// Returns an error if a durable session/index binding is corrupt, the
    /// trusted clock cannot be represented, or the store cannot commit the
    /// restart tombstones.
    pub fn recover_worker_sessions(&mut self) -> Result<WorkerStartupRecoveryReportV1, AgdError> {
        Ok(WorkerSessionStoreV1::new(&mut self.store).recover_startup(now_u64()?)?)
    }

    /// Loads one historical or live worker record directly from governor
    /// custody.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent session or any durable binding failure.
    pub fn inspect_worker_session(
        &mut self,
        session: &ag_session::SessionId,
    ) -> Result<WorkerSessionRecordV1, AgdError> {
        Ok(WorkerSessionStoreV1::new(&mut self.store)
            .load_session(session)?
            .record)
    }

    /// Reloads the exact durable provider capability for a presently retained
    /// worker runtime and revalidates every launcher-owned live binding.
    ///
    /// This is the mandatory entry to each future infer/fetch/ack transition;
    /// callers must not cache the returned capability across transitions.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when process custody is absent, the durable
    /// session changed, any live binding differs, or the capability is not
    /// currently effective.
    pub fn reload_active_worker_provider_capability(
        &mut self,
        session: &SessionId,
        now_unix_ms: u64,
    ) -> Result<InferenceCapabilityV1, AgdError> {
        let runtime = self
            .active_workers
            .get(session)
            .ok_or(AgdError::WorkerRuntimeMissing)?;
        let loaded = WorkerSessionStoreV1::new(&mut self.store).load_session(session)?;
        if loaded.record.spec.session != *session
            || runtime.ingress.session_id != *session
            || runtime.ingress.session_binding != Digest::from_serializable(&loaded.record.spec)?
        {
            return Err(AgdError::WorkerProofMismatch);
        }
        loaded
            .record
            .active_provider_capability(&runtime.ingress.context(now_unix_ms))
            .cloned()
            .map_err(AgdError::from)
    }

    /// Commits one exact credential-free worker inference request before any
    /// provider-daemon dispatch. Repeating the same session/attempt returns
    /// the existing record; changing its bytes or headers refuses.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal for stale worker custody, an offline session,
    /// a request outside the enrolled bound, a duplicate binding mismatch, or
    /// a failed durable blob/event commit.
    pub fn prepare_worker_provider_attempt(
        &mut self,
        session: &SessionId,
        attempt: RequestId,
        sanitized_headers: BTreeMap<String, String>,
        request_bytes: &[u8],
        now_unix_ms: u64,
    ) -> Result<WorkerProviderAttemptRecordV1, AgdError> {
        let capability = self.reload_active_worker_provider_capability(session, now_unix_ms)?;
        let byte_length =
            u64::try_from(request_bytes.len()).map_err(|_| AgdError::ArtifactTransferTooLarge)?;
        if byte_length == 0 || byte_length > capability.budget.input_bytes {
            return Err(AgdError::WorkerProviderRequestTooLarge);
        }
        let exact_request = Digest::hash_bytes(request_bytes);
        let request = ProviderRequestCustodyV1::new(
            capability.id(),
            exact_request.clone(),
            sanitized_headers,
            capability.envelope.clone(),
        )?;
        let entity = worker_provider_attempt_entity(session, &attempt)?;
        if let Some(existing) = self
            .store
            .materialized_state::<WorkerProviderAttemptRecordV1>(&entity)?
        {
            validate_worker_provider_attempt_record(&entity, &existing.state)?;
            if existing.state.request != request
                || existing.state.worker_principal != capability.worker_principal
            {
                return Err(AgdError::WorkerProviderAttemptMismatch);
            }
            return Ok(existing.state);
        }
        self.store.install_blob(
            &BlobDescriptorV1 {
                digest: exact_request,
                byte_length,
            },
            &mut Cursor::new(request_bytes),
            i64::try_from(now_unix_ms).map_err(|_| AgdError::Clock("time overflow".to_owned()))?,
        )?;
        let record = WorkerProviderAttemptRecordV1 {
            schema: "ag.worker-provider-attempt/v1".to_owned(),
            session: session.clone(),
            worker_principal: capability.worker_principal,
            attempt,
            request,
            state: WorkerProviderAttemptStateV1::RequestInCustody,
        };
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: entity,
                event_kind: "worker-provider.request-custodied.v1".to_owned(),
                occurred_at_unix_ms: i64::try_from(now_unix_ms)
                    .map_err(|_| AgdError::Clock("time overflow".to_owned()))?,
                payload: (&record.session, &record.attempt, &record.request),
            },
            &record,
            0,
        )?;
        Ok(record)
    }

    /// Launches one configured offline worker behind a durable principal fence.
    ///
    /// The child is prepared behind a descriptor gate. Its exact executable,
    /// workspace, ephemeral ingress key, fixed argv, host observations, and
    /// deadline are committed before the gate is released. No caller-supplied
    /// executable, argv, target, identity, or workspace enters this path.
    ///
    /// # Errors
    ///
    /// Returns a typed error for quiescence, catalog/profile mismatch,
    /// containment refusal, session-capacity exhaustion, key/protocol failure,
    /// durable binding failure, or release failure.
    // Keeping the gate/key/principal/store/release sequence linear makes its
    // fail-closed order directly auditable; splitting it would obscure which
    // fallible operations occur before durable activation.
    #[allow(clippy::too_many_lines)]
    pub fn launch_worker(
        &mut self,
        profile_id: &str,
    ) -> Result<(SessionId, PrincipalId), AgdError> {
        if self.worker_recovery_required {
            return Err(AgdError::WorkerRecoveryRequired);
        }
        if self.store.active_backup_cut()?.is_some() {
            return Err(AgdError::Quiesced);
        }
        if !self.active_workers.is_empty() {
            return Err(AgdError::WorkerCapacityExhausted);
        }
        let launcher = self
            .config
            .worker_launcher
            .clone()
            .ok_or(AgdError::WorkerRuntimeUnavailable)?;
        let profile = launcher
            .profiles
            .iter()
            .find(|profile| profile.profile_id == profile_id)
            .cloned()
            .ok_or_else(|| WorkerLaunchError::UnknownProfile(profile_id.to_owned()))?;
        if profile.provider_access.is_some() {
            // The policy and session capability can be constructed, but the
            // live worker request/response proxy is a separate custody
            // boundary. Refuse before process preparation until that proxy
            // can reload and prove the exact active session on every call.
            return Err(AgdError::WorkerProviderRuntimeUnavailable);
        }
        let security_profile = configured_worker_security_profile(&self.config.security_profile)?;
        let governor_enrollment = self
            .rpc_signer
            .enrollment(launcher.governor_challenge_maximum_clock_skew_ms)?
            .key;
        let session_nonce = LifecycleNonce::random();
        let session = SessionId::new(format!("worker-{}", hex::encode(session_nonce.as_bytes())))?;
        if self.active_workers.contains_key(&session) {
            return Err(AgdError::WorkerRuntimeCollision);
        }
        let key_id = RpcKeyIdV1::new(format!("worker-{}", hex::encode(session_nonce.as_bytes())))?;
        let provisional_principal = Digest::hash_domain(
            "ag-ng/worker-candidate-key-provisional/v1",
            session_nonce.as_bytes(),
        );
        let (candidate_signer, private_key) =
            RpcSignerV1::generate_ephemeral_candidate_ingress(provisional_principal, key_id)?;
        let provisional_enrollment = candidate_signer.enrollment(profile.timeout_ms)?;
        let candidate_key_identity = candidate_ingress_key_identity(&provisional_enrollment.key)?;
        let admitted_inputs = worker_admitted_inputs();
        let maximum_wire_bytes = u64::from(self.config.limits.max_control_frame_bytes)
            .checked_add(4)
            .ok_or(AgdError::ArtifactTransferTooLarge)?;
        let mut prepared = prepare_worker_launch(
            security_profile,
            &launcher,
            profile_id,
            session.as_str(),
            maximum_wire_bytes,
            &admitted_inputs,
        )?;
        // The launcher arms its monotonic process deadline immediately before
        // returning this gated process. Observing the durable wall deadline
        // afterward guarantees process custody expires no later than the
        // principal, even when executable hashing is slow.
        let prepared_at = now_u64()?;
        let expires_at = prepared_at
            .checked_add(profile.timeout_ms)
            .ok_or_else(|| AgdError::Clock("worker deadline overflow".to_owned()))?;
        let launch_receipt = Digest::from_serializable(&prepared.evidence)?;
        let worker = worker_principal_from_launch(
            &self.authority_domain,
            self.epoch,
            self.rpc_signer.principal(),
            &profile,
            &session,
            session_nonce,
            expires_at,
            candidate_key_identity.clone(),
            &prepared,
        )?;
        let worker_id = worker.id();
        let worker_chain = worker_principal_chain(
            &self.authority_domain,
            self.epoch,
            &launcher.governor_principal_root,
            self.rpc_signer.principal(),
            &worker,
        )?;
        let worker_enrollment = RpcPeerKeyPolicyV1 {
            principal: worker_id.digest().clone(),
            ..provisional_enrollment.key
        };
        debug_assert_eq!(
            candidate_ingress_key_identity(&worker_enrollment)?,
            candidate_key_identity
        );
        let enrolled_worker =
            RpcPeerEnrollmentV1::new(worker_id.digest().clone(), worker_enrollment.clone())?;
        let server_challenge = self
            .rpc_signer
            .issue_challenge(&enrolled_worker, prepared_at)?;
        let bootstrap = WorkerCandidateBootstrapV1 {
            schema: "ag.worker-candidate-bootstrap/v1".to_owned(),
            principal: worker_id.digest().clone(),
            key_id: worker_enrollment.key_id.clone(),
            candidate_nonce: session_nonce,
            semantic_type: profile.candidate_semantic_type.clone(),
            request_id: RequestId::new(format!("candidate-{}", session.as_str()))?,
            maximum_frame_bytes: self.config.limits.max_control_frame_bytes,
            maximum_candidate_bytes: profile.output_budget_bytes,
            server_challenge: server_challenge.clone(),
        };
        populate_worker_inputs(&mut prepared, &private_key, &bootstrap)?;
        let spec = worker_session_spec(
            &self.authority_domain,
            self.epoch,
            security_profile,
            &profile,
            &session,
            candidate_key_identity,
            worker,
            worker_chain,
            &prepared,
            prepared_at,
            expires_at,
        )?;
        let ingress = WorkerRuntimeIngressBindingsV1 {
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            principal_id: worker_id.clone(),
            session_id: session.clone(),
            proposal_workspace_identity: prepared.workspace.identity.clone(),
            security_profile_identity: security_profile.identity(),
            executable: prepared.evidence.worker_executable.clone(),
            observed_uid: prepared.evidence.observed_uid,
            observed_gid: prepared.evidence.observed_gid,
            session_binding: Digest::from_serializable(&spec)?,
        };
        let record = WorkerSessionRecordV1::new(spec)?;
        if WorkerSessionStoreV1::new(&mut self.store)
            .prepare(&record, prepared_at)
            .is_err()
        {
            // A store error may be commit-ambiguous.  The worker remains
            // gated and is synchronously reaped, while this governor refuses
            // every further mutating request until startup recovery inspects
            // the durable session namespace.
            self.worker_recovery_required = true;
            prepared.release.abort();
            let _ = prepared.process.terminate();
            return Err(AgdError::WorkerRecoveryRequired);
        }
        if let Err(error) = WorkerSessionStoreV1::new(&mut self.store).activate(
            &session,
            launch_receipt,
            prepared_at,
        ) {
            let failure = Digest::hash_domain(
                "ag-ng/worker-activation-failure/v1",
                b"worker-session-activation-store-boundary",
            );
            let reason = WorkerTerminationReasonV1::LaunchFailed { failure };
            let tombstone = WorkerSessionStoreV1::new(&mut self.store).tombstone(
                &session,
                reason.clone(),
                prepared_at,
            );
            prepared.release.abort();
            let terminated = prepared.process.terminate();
            if tombstone.is_err() || terminated.is_err() {
                self.worker_recovery_required = true;
                return Err(AgdError::WorkerRecoveryRequired);
            }
            let cleanup = Digest::from_serializable(&(
                "ag.worker-activation-failure-cleanup/v1",
                &session,
                &reason,
                prepared_at,
            ))?;
            let Ok(cleanup_at) = now_u64() else {
                self.worker_recovery_required = true;
                return Err(AgdError::WorkerRecoveryRequired);
            };
            if WorkerSessionStoreV1::new(&mut self.store)
                .complete_cleanup(&session, cleanup, cleanup_at)
                .is_err()
            {
                self.worker_recovery_required = true;
                return Err(AgdError::WorkerRecoveryRequired);
            }
            return Err(error.into());
        }
        if prepared.process.deadline_expired() {
            self.fence_and_cleanup_runtime(
                &session,
                &mut prepared.process,
                WorkerTerminationReasonV1::DeadlineExpired,
                Some(prepared.release),
            )?;
            return Err(WorkerLaunchError::TimedOut.into());
        }
        if let Err(error) = prepared.release.release() {
            let failure = Digest::hash_domain(
                "ag-ng/worker-release-failure/v1",
                b"worker-release-gate-boundary",
            );
            self.fence_and_cleanup_runtime(
                &session,
                &mut prepared.process,
                WorkerTerminationReasonV1::LaunchFailed { failure },
                None,
            )?;
            return Err(error.into());
        }
        let replaced = self.active_workers.insert(
            session.clone(),
            ActiveWorkerRuntimeV1 {
                process: prepared.process,
                governor_enrollment,
                worker_enrollment,
                server_challenge,
                ingress,
            },
        );
        debug_assert!(replaced.is_none());
        Ok((session, worker_id))
    }

    fn fence_and_cleanup_runtime(
        &mut self,
        session: &SessionId,
        process: &mut WorkerProcessV1,
        reason: WorkerTerminationReasonV1,
        gated_release: Option<WorkerLaunchReleaseV1>,
    ) -> Result<(), AgdError> {
        let Ok(terminal_at) = now_u64() else {
            self.worker_recovery_required = true;
            return Err(AgdError::WorkerRecoveryRequired);
        };
        let Ok(cleanup_receipt) = Digest::from_serializable(&(
            "ag.worker-process-cleanup/v1",
            session,
            &reason,
            terminal_at,
        )) else {
            self.worker_recovery_required = true;
            return Err(AgdError::WorkerRecoveryRequired);
        };
        if WorkerSessionStoreV1::new(&mut self.store)
            .tombstone(session, reason, terminal_at)
            .is_err()
        {
            // The session CAS may be commit-ambiguous. The retained release
            // guard/process still fail closed on return, but the in-memory
            // runtime is no longer a sufficient capacity fence. Refuse all
            // further mutation until startup recovery resolves durable state.
            self.worker_recovery_required = true;
            return Err(AgdError::WorkerRecoveryRequired);
        }
        if let Some(release) = gated_release {
            release.abort();
        }
        process.terminate()?;
        WorkerSessionStoreV1::new(&mut self.store).complete_cleanup(
            session,
            cleanup_receipt,
            now_u64()?,
        )?;
        Ok(())
    }

    /// Polls every retained worker without blocking for process completion.
    ///
    /// A timeout, output overflow, or process failure is durably tombstoned
    /// before the supervisor sends a termination signal. A successful process
    /// must produce exactly one complete signed candidate frame before its
    /// principal is atomically exchanged for candidate custody.
    ///
    /// # Errors
    ///
    /// Returns an error only when the durable authority boundary cannot be
    /// updated or its state is corrupt. Individual worker failures are fenced
    /// and counted rather than terminating the daemon.
    pub fn poll_workers(&mut self) -> Result<WorkerPollReportV1, AgdError> {
        let mut report = WorkerPollReportV1::default();
        let sessions = self.active_workers.keys().cloned().collect::<Vec<_>>();
        for session in sessions {
            let poll = self
                .active_workers
                .get_mut(&session)
                .ok_or(AgdError::WorkerRuntimeCollision)?
                .process
                .try_wait();
            match poll {
                Ok(None) => {
                    report.pending = report.pending.saturating_add(1);
                }
                Err(error) => {
                    let mut runtime = self
                        .active_workers
                        .remove(&session)
                        .ok_or(AgdError::WorkerRuntimeCollision)?;
                    let reason = worker_process_failure_reason(&error);
                    self.fence_and_cleanup_runtime(&session, &mut runtime.process, reason, None)?;
                    report.failed = report.failed.saturating_add(1);
                }
                Ok(Some(exit)) => {
                    let mut runtime = self
                        .active_workers
                        .remove(&session)
                        .ok_or(AgdError::WorkerRuntimeCollision)?;
                    if !exit.status.success() {
                        let reason = WorkerTerminationReasonV1::WorkerFailed {
                            failure: Digest::from_serializable(&(
                                "ag.worker-abnormal-exit/v1",
                                &session,
                                exit.status.code(),
                            ))?,
                        };
                        self.fence_and_cleanup_runtime(
                            &session,
                            &mut runtime.process,
                            reason,
                            None,
                        )?;
                        report.failed = report.failed.saturating_add(1);
                        continue;
                    }
                    if let Err(error) =
                        self.accept_worker_candidate(&session, &runtime, &exit.candidate)
                    {
                        if let Some(reason) = worker_candidate_refusal_reason(&error) {
                            self.fence_and_cleanup_runtime(
                                &session,
                                &mut runtime.process,
                                reason,
                                None,
                            )?;
                            report.failed = report.failed.saturating_add(1);
                            continue;
                        }
                        // A nonsemantic ingress error may be a commit-ambiguous
                        // store boundary.  Do not overwrite it with a refusal
                        // tombstone or cleanup receipt.  Confirm process exit,
                        // poison this core, and make the daemon restart into
                        // durable recovery.
                        self.worker_recovery_required = true;
                        runtime.process.terminate()?;
                        return Err(AgdError::WorkerRecoveryRequired);
                    }
                    self.complete_accepted_worker_cleanup(&session, &mut runtime.process)?;
                    report.accepted = report.accepted.saturating_add(1);
                    match self.forward_custodied_worker_candidate(&session) {
                        Ok(_) => {}
                        Err(error) if is_deferred_forward_error(&error) => {
                            report.deferred = report.deferred.saturating_add(1);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(report)
    }

    /// Permanently fences an active worker, then terminates and reaps its
    /// retained process handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable tombstone cannot commit, the session
    /// is not represented by a live retained process, or cleanup cannot be
    /// recorded.
    pub fn cancel_worker(
        &mut self,
        session: &SessionId,
        reason_digest: Digest,
    ) -> Result<(), AgdError> {
        let terminal_at = now_u64()?;
        let reason = WorkerTerminationReasonV1::Cancelled { reason_digest };
        WorkerSessionStoreV1::new(&mut self.store).tombstone(
            session,
            reason.clone(),
            terminal_at,
        )?;
        let mut runtime = self
            .active_workers
            .remove(session)
            .ok_or(AgdError::WorkerRuntimeMissing)?;
        runtime.process.terminate()?;
        let cleanup = Digest::from_serializable(&(
            "ag.worker-cancel-cleanup/v1",
            session,
            &reason,
            terminal_at,
        ))?;
        WorkerSessionStoreV1::new(&mut self.store).complete_cleanup(
            session,
            cleanup,
            now_u64()?,
        )?;
        Ok(())
    }

    /// Replays every accepted, non-canonicalized candidate from exact durable
    /// proof and blob custody. No historical principal is recreated.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt session/proof bindings or an unrecoverable
    /// broker/store response. Broker unavailability remains a deferred count.
    pub fn recover_worker_candidates(
        &mut self,
    ) -> Result<WorkerCandidateRecoveryReportV1, AgdError> {
        if self.worker_recovery_required {
            return Err(AgdError::WorkerRecoveryRequired);
        }
        if !self.active_workers.is_empty() {
            return Err(AgdError::WorkerSupervisorBusy);
        }
        let mut report = WorkerCandidateRecoveryReportV1::default();
        let mut cursor = None;
        loop {
            let entities =
                self.store
                    .entity_ids_after("worker-session:", cursor.as_deref(), 128)?;
            if entities.is_empty() {
                return Ok(report);
            }
            cursor = entities.last().cloned();
            for entity in entities {
                let Some(materialized) = self
                    .store
                    .materialized_state::<WorkerSessionRecordV1>(&entity)?
                else {
                    return Err(AgdError::WorkerProofMismatch);
                };
                let loaded = WorkerSessionStoreV1::new(&mut self.store)
                    .load_session(&materialized.state.spec.session)?;
                if loaded.entity_id != entity || loaded.record != materialized.state {
                    return Err(AgdError::WorkerProofMismatch);
                }
                if !matches!(
                    loaded.record.candidate,
                    WorkerCandidateCustodyStateV1::InCustody { .. }
                ) {
                    continue;
                }
                match self.forward_custodied_worker_candidate(&loaded.record.spec.session) {
                    Ok(WorkerCandidateBrokerOutcomeV1::Canonicalized { .. }) => {
                        report.canonicalized = report.canonicalized.saturating_add(1);
                    }
                    Ok(WorkerCandidateBrokerOutcomeV1::Refused { .. }) => {
                        report.refused = report.refused.saturating_add(1);
                    }
                    Ok(WorkerCandidateBrokerOutcomeV1::Indeterminate { .. }) => {
                        report.indeterminate = report.indeterminate.saturating_add(1);
                    }
                    Err(error) if is_deferred_forward_error(&error) => {
                        report.deferred = report.deferred.saturating_add(1);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    fn accept_worker_candidate(
        &mut self,
        session: &SessionId,
        runtime: &ActiveWorkerRuntimeV1,
        frame: &[u8],
    ) -> Result<(), AgdError> {
        let accepted_at = now_u64()?;
        let loaded = WorkerSessionStoreV1::new(&mut self.store).load_session(session)?;
        let principal = &loaded.record.spec.worker.principal;
        if accepted_at >= principal.expires_at_unix_ms {
            return Err(AgdError::WorkerCandidateExpired);
        }
        if runtime.ingress.session_id != *session
            || runtime.ingress.session_binding != Digest::from_serializable(&loaded.record.spec)?
            || runtime.worker_enrollment.principal != *principal.id().digest()
            || principal.candidate_ingress_key_identity
                != candidate_ingress_key_identity(&runtime.worker_enrollment)?
        {
            return Err(AgdError::WorkerProofMismatch);
        }
        let context = runtime.ingress.context(accepted_at);
        match loaded.record.validate_active_ingress(&context) {
            Ok(()) => {}
            Err(SessionError::PrincipalExpired) => {
                return Err(AgdError::WorkerCandidateExpired);
            }
            Err(_) => return Err(AgdError::WorkerProofMismatch),
        }
        let signed = decode_exact_signed_worker_candidate(
            frame,
            self.config.limits.max_control_frame_bytes,
        )?;
        let worker_enrollment = RpcPeerEnrollmentV1::new(
            principal.id().digest().clone(),
            runtime.worker_enrollment.clone(),
        )?;
        let governor_enrollment = RpcPeerEnrollmentV1::new(
            self.rpc_signer.principal().clone(),
            runtime.governor_enrollment.clone(),
        )?;
        let verified = verify_forwarded_signed_request(
            &runtime.server_challenge,
            &signed,
            &governor_enrollment,
            &worker_enrollment,
            &self.rpc_replay,
            accepted_at,
        )?;
        if verified.principal != *principal.id().digest()
            || signed.request.echo.request_id
                != RequestId::new(format!("candidate-{}", session.as_str()))?
        {
            return Err(AgdError::WorkerProofMismatch);
        }
        let proof = WorkerCandidateIngressProofV1 {
            governor_enrollment: runtime.governor_enrollment.clone(),
            worker_enrollment: runtime.worker_enrollment.clone(),
            server_challenge: runtime.server_challenge.clone(),
            signed_request: Box::new(signed),
        };
        let WorkerCandidateRequestV1::Submit {
            candidate_nonce,
            semantic_type,
            content,
        } = &proof.signed_request.request.body;
        let reviewed_profile =
            self.config
                .worker_launcher
                .as_ref()
                .and_then(|launcher| {
                    launcher.profiles.iter().find(|profile| {
                        profile.profile_id == loaded.record.spec.reviewed_profile_id
                    })
                })
                .ok_or(AgdError::WorkerProfileBindingMismatch)?;
        if loaded.record.spec.output_budget_bytes != reviewed_profile.output_budget_bytes {
            return Err(AgdError::WorkerProfileBindingMismatch);
        }
        if *candidate_nonce != principal.session_nonce {
            return Err(AgdError::WorkerProofMismatch);
        }
        if *semantic_type != reviewed_profile.candidate_semantic_type {
            return Err(AgdError::WorkerCandidateSemanticMismatch);
        }
        if u64::try_from(content.len())
            .ok()
            .is_none_or(|length| length > loaded.record.spec.output_budget_bytes)
        {
            return Err(AgdError::WorkerCandidateBudgetExceeded {
                observed_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
            });
        }
        let proof_bytes = proof.canonical_bytes()?;
        WorkerSessionStoreV1::new(&mut self.store).accept_candidate(
            &context,
            content.as_slice(),
            &proof_bytes,
            semantic_type.clone(),
            None,
        )?;
        Ok(())
    }

    fn complete_accepted_worker_cleanup(
        &mut self,
        session: &SessionId,
        process: &mut WorkerProcessV1,
    ) -> Result<(), AgdError> {
        let record = WorkerSessionStoreV1::new(&mut self.store)
            .load_session(session)?
            .record;
        let receipt = Digest::from_serializable(&(
            "ag.worker-accepted-cleanup/v1",
            session,
            &record.authority,
        ))?;
        process.terminate()?;
        WorkerSessionStoreV1::new(&mut self.store).complete_cleanup(
            session,
            receipt,
            now_u64()?,
        )?;
        Ok(())
    }

    fn worker_candidate_source(
        &mut self,
        session: &SessionId,
    ) -> Result<WorkerCandidateSourceProofV1, AgdError> {
        let proof_bytes = WorkerSessionStoreV1::new(&mut self.store).read_ingress_proof(session)?;
        let ingress_proof: WorkerCandidateIngressProofV1 =
            ag_protocol::strict_json_from_slice(&proof_bytes)?;
        if ingress_proof.canonical_bytes()? != proof_bytes {
            return Err(AgdError::WorkerProofMismatch);
        }
        let record = WorkerSessionStoreV1::new(&mut self.store)
            .load_session(session)?
            .record;
        let candidate = match &record.candidate {
            WorkerCandidateCustodyStateV1::InCustody { candidate }
            | WorkerCandidateCustodyStateV1::BrokerCompleted { candidate, .. } => candidate,
            WorkerCandidateCustodyStateV1::Awaiting => {
                return Err(AgdError::WorkerCandidateNotInCustody);
            }
        };
        let (launch_receipt, tombstone) = match &record.authority {
            ag_session::WorkerAuthorityStateV1::Tombstoned {
                launch_receipt: Some(launch_receipt),
                tombstone,
                ..
            } if tombstone.reason == WorkerTerminationReasonV1::CandidateAccepted => {
                (launch_receipt, tombstone)
            }
            _ => return Err(AgdError::WorkerProofMismatch),
        };
        if candidate.ingress_proof != ingress_proof.digest()? {
            return Err(AgdError::WorkerProofMismatch);
        }
        let launcher = self
            .config
            .worker_launcher
            .as_ref()
            .ok_or(AgdError::WorkerRuntimeUnavailable)?;
        let expected_chain = worker_principal_chain(
            &self.authority_domain,
            self.epoch,
            &launcher.governor_principal_root,
            self.rpc_signer.principal(),
            &record.spec.worker.principal,
        )?;
        if expected_chain != record.spec.worker.principal_chain {
            return Err(AgdError::WorkerProofMismatch);
        }
        let session_binding = Digest::from_serializable(&record.spec)?;
        Ok(WorkerCandidateSourceProofV1 {
            worker: record.spec.worker.principal,
            worker_chain: expected_chain,
            ingress_proof,
            session_binding,
            workspace_identity: record.spec.proposal_workspace_identity,
            launch_receipt: launch_receipt.clone(),
            candidate_custody: candidate.custody_record.clone(),
            accepted_at_unix_ms: tombstone.terminal_since_unix_ms,
        })
    }

    fn forward_custodied_worker_candidate(
        &mut self,
        session: &SessionId,
    ) -> Result<WorkerCandidateBrokerOutcomeV1, AgdError> {
        let record = WorkerSessionStoreV1::new(&mut self.store)
            .load_session(session)?
            .record;
        if let WorkerCandidateCustodyStateV1::BrokerCompleted { outcome, .. } = record.candidate {
            return Ok(outcome);
        }
        let source = self.worker_candidate_source(session)?;
        let intent = self.admit_worker_candidate(session)?;
        let response = self.forward_worker_candidate(&intent, source)?;
        let outcome = match response {
            AgdResponseV1::ProposalSubmitted {
                proposal_digest, ..
            } => WorkerCandidateBrokerOutcomeV1::Canonicalized {
                canonical_proposal: proposal_digest,
            },
            AgdResponseV1::Refused { refusal } => {
                WorkerCandidateBrokerOutcomeV1::Refused { refusal }
            }
            AgdResponseV1::Indeterminate { envelope } => {
                WorkerCandidateBrokerOutcomeV1::Indeterminate { envelope }
            }
            _ => return Err(AgdError::OutboxBindingMismatch),
        };
        WorkerSessionStoreV1::new(&mut self.store).record_broker_outcome(
            session,
            outcome.clone(),
            now_u64()?,
        )?;
        Ok(outcome)
    }

    /// Attempts to finish every durable pending effect forward.
    ///
    /// An exact stored ingress can recover a response which effectd committed
    /// before agd lost the connection. If effectd has no such durable record,
    /// an expired proof remains pending until the proposer supplies a fresh
    /// authenticated request; recovery never turns stale evidence into new
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt outbox/store state, lost admission or
    /// artifact custody, or a failed durable completion commit. Transport and
    /// broker availability failures leave the record pending and are counted
    /// as deferred.
    pub fn recover_forward_outbox(&mut self) -> Result<ForwardRecoveryReportV1, AgdError> {
        if self.worker_recovery_required {
            return Err(AgdError::WorkerRecoveryRequired);
        }
        if !self.active_workers.is_empty() {
            return Err(AgdError::WorkerSupervisorBusy);
        }
        let mut report = ForwardRecoveryReportV1::default();
        let mut cursor = None;
        loop {
            let entities = self
                .store
                .entity_ids_after("forward-", cursor.as_deref(), 128)?;
            if entities.is_empty() {
                return Ok(report);
            }
            cursor = entities.last().cloned();
            for entity in entities {
                let Some(loaded) = self
                    .store
                    .materialized_state::<ForwardOutboxRecordV1>(&entity)?
                else {
                    return Err(AgdError::OutboxBindingMismatch);
                };
                self.validate_forward_record(&entity, &loaded.state)?;
                if matches!(loaded.state.state, ForwardOutboxStateV1::Completed { .. }) {
                    continue;
                }
                if self.store.active_backup_cut()?.is_some() {
                    report.deferred = report.deferred.saturating_add(1);
                    continue;
                }
                let intent = ingress_intent(&loaded.state.ingress)?.clone();
                let subject = intent.judgment_subject_digest()?;
                let admission = self.verify_admission(&intent.judgment, &subject)?;
                if admission != loaded.state.admission {
                    return Err(AgdError::OutboxBindingMismatch);
                }
                let artifacts = if matches!(
                    &loaded.state.ingress,
                    GovernedProposalIngressV1::WorkerCandidate { .. }
                ) {
                    Vec::new()
                } else {
                    self.load_artifact_transfers(&intent)?
                };
                match self.submit_to_effectd(loaded.state.ingress.clone(), artifacts) {
                    Ok(response) => {
                        self.complete_forward_outbox(
                            entity,
                            loaded.state,
                            loaded.revision,
                            &response,
                        )?;
                        report.completed = report.completed.saturating_add(1);
                    }
                    Err(error) if is_deferred_forward_error(&error) => {
                        report.deferred = report.deferred.saturating_add(1);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    /// Evaluates a named effect crossing and commits its lossless result.
    /// Only the contained-session subsystem should call this method.
    ///
    /// # Errors
    ///
    /// Returns an error when backup quiescence is active, book replay or
    /// crossing bindings fail, canonicalization fails, or the atomic store
    /// transition cannot commit.
    pub fn evaluate_and_commit(
        &mut self,
        input: EffectEvaluationInputV1,
    ) -> Result<(Digest, StoredEffectJudgmentV1), AgdError> {
        if self.store.active_backup_cut()?.is_some() {
            return Err(AgdError::Quiesced);
        }
        ensure_claim_subject(&input.claim, &input.subject)?;
        let (standing, custody, obligation, capacity) = replay_books(&input.books)?;
        let judgment = match evaluate_effect_crossing(
            &standing,
            &custody,
            &obligation,
            &capacity,
            &input.claim,
        ) {
            NativeJudgment::Admit(witness) => StoredEffectJudgmentV1::Admit {
                commit: Box::new(AdmissionCommit::effect(witness)?),
            },
            NativeJudgment::Refuse(refusal) => StoredEffectJudgmentV1::Refuse { refusal },
        };
        let record = EffectJudgmentRecordV1 {
            schema: "ag.effect-judgment/v1".to_owned(),
            subject: input.subject,
            books: Some(input.books),
            judgment: judgment.clone(),
        };
        let digest = Digest::from_serializable(&record)?;
        let entity = judgment_entity(&digest);
        if let Some(existing) = self
            .store
            .materialized_state::<EffectJudgmentRecordV1>(&entity)?
        {
            if existing.state != record || Digest::from_serializable(&existing.state)? != digest {
                return Err(AgdError::JudgmentBindingMismatch);
            }
            return Ok((digest, existing.state.judgment));
        }
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: entity,
                event_kind: judgment_kind(&judgment).to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: &record,
            },
            &record,
            0,
        )?;
        Ok((digest, judgment))
    }

    /// Commits an operationally indeterminate result without reclassifying it
    /// as either refusal or admission.
    ///
    /// # Errors
    ///
    /// Returns an error during backup quiescence or if canonicalization,
    /// clock observation, or the durable store transition fails.
    pub fn commit_indeterminate(
        &mut self,
        subject: Digest,
        failures: NonEmpty<FailureEvidence>,
    ) -> Result<Digest, AgdError> {
        if self.store.active_backup_cut()?.is_some() {
            return Err(AgdError::Quiesced);
        }
        let judgment = StoredEffectJudgmentV1::Indeterminate { failures };
        let record = EffectJudgmentRecordV1 {
            schema: "ag.effect-judgment/v1".to_owned(),
            subject,
            books: None,
            judgment,
        };
        let digest = Digest::from_serializable(&record)?;
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: judgment_entity(&digest),
                event_kind: "effect-judgment.indeterminate.v1".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: &record,
            },
            &record,
            0,
        )?;
        Ok(digest)
    }

    /// Reconstructs non-serializable authority from committed state and exact
    /// book replay. Refusals and indeterminate records cannot enter this path.
    ///
    /// # Errors
    ///
    /// Returns an error when the judgment is absent, refused, indeterminate,
    /// digest-mismatched, subject-mismatched, or cannot be reconstructed from
    /// the exact committed family books.
    pub fn verify_admission(
        &self,
        judgment: &Digest,
        expected_subject: &Digest,
    ) -> Result<VerifiedEffectAdmissionV1, AgdError> {
        let state = self
            .store
            .materialized_state::<EffectJudgmentRecordV1>(&judgment_entity(judgment))?
            .ok_or(AgdError::JudgmentNotFound)?;
        if Digest::from_serializable(&state.state)? != *judgment
            || state.state.subject != *expected_subject
        {
            return Err(AgdError::JudgmentBindingMismatch);
        }
        let StoredEffectJudgmentV1::Admit { commit } = state.state.judgment else {
            return Err(AgdError::JudgmentDidNotAdmit);
        };
        let books = state.state.books.ok_or(AgdError::JudgmentBindingMismatch)?;
        let (standing, custody, obligation, capacity) = replay_books(&books)?;
        let authority =
            reconstruct_effect_authority(&standing, &custody, &obligation, &capacity, *commit)?;
        Ok(VerifiedEffectAdmissionV1 {
            judgment: judgment.clone(),
            commit: authority.commit_digest().clone(),
        })
    }

    /// Maps one durably accepted candidate through a single reviewed closed
    /// effect and commits the native four-family judgment used by the normal
    /// proposal path. Effect family and target selection are policy inputs;
    /// worker bytes cannot name or alter either value.
    ///
    /// # Errors
    ///
    /// Returns an error unless candidate custody and its tombstone are valid,
    /// the worker chain is exact, the target is canonical, or the native
    /// judgment/store transition fails.
    pub fn admit_worker_candidate(
        &mut self,
        session: &ag_session::SessionId,
    ) -> Result<ProposalIntentV1, AgdError> {
        let record = WorkerSessionStoreV1::new(&mut self.store)
            .load_session(session)?
            .record;
        record.validate()?;
        let candidate = match &record.candidate {
            WorkerCandidateCustodyStateV1::InCustody { candidate }
            | WorkerCandidateCustodyStateV1::BrokerCompleted { candidate, .. } => candidate,
            WorkerCandidateCustodyStateV1::Awaiting => {
                return Err(AgdError::WorkerCandidateNotInCustody);
            }
        };
        let launcher = self
            .config
            .worker_launcher
            .as_ref()
            .ok_or(AgdError::WorkerRuntimeUnavailable)?;
        let profile = launcher
            .profiles
            .iter()
            .find(|profile| profile.profile_id == record.spec.reviewed_profile_id)
            .ok_or(AgdError::WorkerProfileBindingMismatch)?;
        if candidate.semantic_type != profile.candidate_semantic_type {
            return Err(AgdError::WorkerProfileBindingMismatch);
        }
        let principal = &record.spec.worker.principal;
        let worker_chain = worker_principal_chain(
            &self.authority_domain,
            self.epoch,
            &launcher.governor_principal_root,
            self.rpc_signer.principal(),
            principal,
        )?;
        let target = TargetId::parse(profile.candidate_target.clone())?;
        let effect = match profile.candidate_effect {
            WorkerCandidateEffectV1::ManagedFilePut => EffectIntentV1::ManagedFilePut {
                target,
                content: candidate.content.clone(),
            },
            WorkerCandidateEffectV1::ManagedPointerPromotion => {
                EffectIntentV1::ManagedPointerPromotion {
                    target,
                    artifact: candidate.content.clone(),
                }
            }
        };
        let mut intent = ProposalIntentV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            intent_id: worker_intent_id(&record.spec.session, &candidate.custody_record),
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            proposer: worker_chain,
            // Excluded from the semantic subject and replaced immediately
            // after the exact native judgment commits.
            judgment: Digest::hash_domain(
                "ag-ng/worker-judgment-placeholder/v1",
                candidate.custody_record.as_str().as_bytes(),
            ),
            admitted_artifacts: BTreeSet::from([candidate.content.clone()]),
            effects: vec![effect],
        };
        let subject = intent.judgment_subject_digest()?;
        let evaluation = worker_effect_evaluation(
            self.authority_domain.clone(),
            self.epoch,
            principal.session_nonce,
            subject,
        )?;
        let (judgment, result) = self.evaluate_and_commit(evaluation)?;
        if !matches!(result, StoredEffectJudgmentV1::Admit { .. }) {
            return Err(AgdError::WorkerJudgmentDidNotAdmit);
        }
        intent.judgment = judgment;
        intent.validate_shape()?;
        Ok(intent)
    }

    /// Handles one authenticated governor control request.
    pub fn handle_control(
        &mut self,
        accepted: &AcceptedSignedRequestV1<AgdRequestV1>,
    ) -> ApiResultV1<AgdResponseV1> {
        match self.try_handle_control(accepted) {
            Ok(response) => ApiResultV1::Ok { response },
            Err(error) => agd_api_error(&error),
        }
    }

    fn try_handle_control(
        &mut self,
        accepted: &AcceptedSignedRequestV1<AgdRequestV1>,
    ) -> Result<AgdResponseV1, AgdError> {
        if self.worker_recovery_required
            && !matches!(
                accepted.body(),
                AgdRequestV1::Health | AgdRequestV1::InspectWorker { .. }
            )
        {
            return Err(AgdError::WorkerRecoveryRequired);
        }
        if !self.active_workers.is_empty()
            && matches!(
                accepted.body(),
                AgdRequestV1::SubmitProposal { .. } | AgdRequestV1::LaunchWorker { .. }
            )
        {
            return Err(AgdError::WorkerSupervisorBusy);
        }
        match accepted.body() {
            AgdRequestV1::Health => Ok(AgdResponseV1::Health {
                health: HealthV1 {
                    schema: "ag.health/v1".to_owned(),
                    service: "agd".to_owned(),
                    build: env!("CARGO_PKG_VERSION").to_owned(),
                    // Session-launch/provider ingress and activation-level
                    // readiness are not yet installed; liveness must not be
                    // presented as production readiness.
                    ready: false,
                    quiesced: self.store.active_backup_cut()?.is_some(),
                },
            }),
            AgdRequestV1::SubmitProposal { intent } => self.forward_intent(
                intent,
                &accepted.authenticated_peer,
                GovernedProposalIngressV1::ExternalSigned {
                    proof: Box::new(ProposalIngressProofV1 {
                        server_challenge: accepted.server_challenge.clone(),
                        signed_request: Box::new(accepted.signed_request.clone()),
                    }),
                },
            ),
            AgdRequestV1::LaunchWorker { profile_id } => {
                let (session_id, principal) = self.launch_worker(profile_id)?;
                Ok(AgdResponseV1::WorkerLaunched {
                    session_id,
                    principal,
                })
            }
            AgdRequestV1::InspectWorker { session_id } => Ok(AgdResponseV1::WorkerStatus {
                record: Box::new(self.inspect_worker_session(session_id)?),
            }),
            AgdRequestV1::CancelWorker { session_id, reason } => {
                self.cancel_worker(session_id, reason.clone())?;
                Ok(AgdResponseV1::WorkerCancelled {
                    session_id: session_id.clone(),
                })
            }
        }
    }

    fn forward_intent(
        &mut self,
        intent: &ProposalIntentV1,
        peer: &VerifiedRpcPrincipalV1,
        ingress: GovernedProposalIngressV1,
    ) -> Result<AgdResponseV1, AgdError> {
        if self.store.active_backup_cut()?.is_some() {
            return Err(AgdError::Quiesced);
        }
        intent.validate_shape()?;
        let authenticated_proposer = signed_principal_chain(
            peer,
            &self.config.proposer_peer,
            self.authority_domain.clone(),
            self.epoch,
        )?;
        if !proposer_binding_matches(
            &intent.authority_domain,
            intent.epoch,
            &intent.proposer,
            &self.authority_domain,
            self.epoch,
            &authenticated_proposer,
        ) {
            return Err(AgdError::ProposerBindingMismatch);
        }
        self.forward_governed_intent(intent, ingress)
    }

    /// Verifies one dynamic worker proof and forwards only the governor-built
    /// intent already backed by durable candidate custody and a native
    /// admission judgment.
    ///
    /// # Errors
    ///
    /// Returns an error for any signature, freshness, lifecycle, chain,
    /// candidate-custody, admission, artifact, or broker binding failure.
    pub fn forward_worker_candidate(
        &mut self,
        intent: &ProposalIntentV1,
        source: WorkerCandidateSourceProofV1,
    ) -> Result<AgdResponseV1, AgdError> {
        let durable_source = self.worker_candidate_source(&source.worker.session_id)?;
        if durable_source != source {
            return Err(AgdError::WorkerProofMismatch);
        }
        let proof = &source.ingress_proof;
        let worker_id = source.worker.id();
        if proof.worker_enrollment.principal != *worker_id.digest()
            || source.worker.candidate_ingress_key_identity
                != candidate_ingress_key_identity(&proof.worker_enrollment)?
            || intent.proposer != source.worker_chain
            || source.worker_chain.authority_domain() != &self.authority_domain
            || source.worker_chain.epoch() != self.epoch
            || source.worker.authority_domain != self.authority_domain
            || source.worker.epoch != self.epoch
            || source.worker.proposal_workspace_identity != source.workspace_identity
            || source.accepted_at_unix_ms >= source.worker.expires_at_unix_ms
        {
            return Err(AgdError::WorkerProofMismatch);
        }
        let worker_enrollment =
            RpcPeerEnrollmentV1::new(worker_id.digest().clone(), proof.worker_enrollment.clone())?;
        let launcher = self
            .config
            .worker_launcher
            .as_ref()
            .ok_or(AgdError::WorkerRuntimeUnavailable)?;
        let expected_governor_policy = self
            .rpc_signer
            .enrollment(launcher.governor_challenge_maximum_clock_skew_ms)?
            .key;
        if proof.governor_enrollment != expected_governor_policy {
            return Err(AgdError::WorkerProofMismatch);
        }
        let governor_enrollment = RpcPeerEnrollmentV1::new(
            self.rpc_signer.principal().clone(),
            proof.governor_enrollment.clone(),
        )?;
        let verified = verify_forwarded_signed_request_bindings(
            &proof.server_challenge,
            &proof.signed_request,
            &governor_enrollment,
            &worker_enrollment,
        )?;
        if verified.principal != *worker_id.digest() {
            return Err(AgdError::WorkerProofMismatch);
        }
        let WorkerCandidateRequestV1::Submit {
            candidate_nonce,
            semantic_type,
            content,
        } = &proof.signed_request.request.body;
        let ingress_proof = worker_candidate_ingress_proof_digest(proof)?;
        let candidate = ag_session::WorkerCandidateCustodyV1::new(
            Digest::hash_bytes(content.as_slice()),
            u64::try_from(content.len()).map_err(|_| AgdError::ArtifactTransferTooLarge)?,
            semantic_type.clone(),
            None,
            ingress_proof,
        )?;
        if *candidate_nonce != source.worker.session_nonce
            || candidate.custody_record != source.candidate_custody
        {
            return Err(AgdError::WorkerProofMismatch);
        }
        let ingress = GovernedProposalIngressV1::WorkerCandidate {
            intent: Box::new(intent.clone()),
            source: Box::new(source),
        };
        self.forward_governed_intent(intent, ingress)
    }

    fn forward_governed_intent(
        &mut self,
        intent: &ProposalIntentV1,
        ingress: GovernedProposalIngressV1,
    ) -> Result<AgdResponseV1, AgdError> {
        if self.worker_recovery_required {
            return Err(AgdError::WorkerRecoveryRequired);
        }
        if !self.active_workers.is_empty() {
            return Err(AgdError::WorkerSupervisorBusy);
        }
        if self.store.active_backup_cut()?.is_some() {
            return Err(AgdError::Quiesced);
        }
        intent.validate_shape()?;
        if intent.authority_domain != self.authority_domain
            || intent.epoch != self.epoch
            || intent.proposer.authority_domain() != &self.authority_domain
            || intent.proposer.epoch() != self.epoch
        {
            return Err(AgdError::ProposerBindingMismatch);
        }
        let expected_subject = intent.judgment_subject_digest()?;
        let verified = self.verify_admission(&intent.judgment, &expected_subject)?;
        let intent_digest = Digest::from_serializable(intent)?;
        let source =
            governor_forward_source(&self.authority_domain, self.epoch, &ingress, &intent_digest)?;
        let (entity, record, revision) =
            match self.prepare_forward_outbox(&source, intent_digest, &verified, &ingress)? {
                ForwardOutboxPreparationV1::Completed(response) => return Ok(response),
                ForwardOutboxPreparationV1::Pending {
                    entity,
                    record,
                    revision,
                } => (entity, *record, revision),
            };
        // Worker candidate bytes already occur exactly once in the signed
        // ingress proof.  Re-encoding them as an artifact transfer would
        // double the frame cost and could strand accepted custody behind a
        // second, hidden wire limit.  Effectd derives and installs that one
        // artifact from the independently verified proof.
        let artifacts = if matches!(&ingress, GovernedProposalIngressV1::WorkerCandidate { .. }) {
            Vec::new()
        } else {
            self.load_artifact_transfers(intent)?
        };
        let result = self.submit_to_effectd(ingress, artifacts)?;
        self.complete_forward_outbox(entity, record, revision, &result)?;
        Ok(result)
    }

    fn prepare_forward_outbox(
        &mut self,
        source: &Digest,
        intent: Digest,
        admission: &VerifiedEffectAdmissionV1,
        ingress: &GovernedProposalIngressV1,
    ) -> Result<ForwardOutboxPreparationV1, AgdError> {
        let entity = forward_entity(source);
        if let Some(loaded) = self
            .store
            .materialized_state::<ForwardOutboxRecordV1>(&entity)?
        {
            self.validate_forward_record(&entity, &loaded.state)?;
            if loaded.state.source != *source
                || loaded.state.intent != intent
                || loaded.state.admission != *admission
            {
                return Err(AgdError::OutboxBindingMismatch);
            }
            if let ForwardOutboxStateV1::Completed { response } = &loaded.state.state {
                return Ok(ForwardOutboxPreparationV1::Completed(response.clone()));
            }
            if loaded.state.ingress != *ingress {
                let updated = ForwardOutboxRecordV1 {
                    ingress: ingress.clone(),
                    ..loaded.state
                };
                let receipt = self.store.append_event(
                    NewEventV1 {
                        event_id: uuid::Uuid::new_v4().to_string(),
                        entity_id: entity.clone(),
                        event_kind: "effect-forward.reproofed.v3".to_owned(),
                        occurred_at_unix_ms: now_i64()?,
                        payload: ingress,
                    },
                    &updated,
                    loaded.revision,
                )?;
                return Ok(ForwardOutboxPreparationV1::Pending {
                    entity,
                    record: Box::new(updated),
                    revision: receipt.entity_revision,
                });
            }
            return Ok(ForwardOutboxPreparationV1::Pending {
                entity,
                record: Box::new(loaded.state),
                revision: loaded.revision,
            });
        }
        let record = ForwardOutboxRecordV1 {
            schema: "ag.effect-forward-outbox/v3".to_owned(),
            source: source.clone(),
            intent,
            admission: admission.clone(),
            ingress: ingress.clone(),
            state: ForwardOutboxStateV1::Pending,
        };
        let receipt = self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: entity.clone(),
                event_kind: "effect-forward.pending.v3".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: (source, admission),
            },
            &record,
            0,
        )?;
        Ok(ForwardOutboxPreparationV1::Pending {
            entity,
            record: Box::new(record),
            revision: receipt.entity_revision,
        })
    }

    fn validate_forward_record(
        &self,
        entity: &str,
        record: &ForwardOutboxRecordV1,
    ) -> Result<(), AgdError> {
        let intent = ingress_intent(&record.ingress)?;
        let intent_digest = Digest::from_serializable(intent)?;
        let source = governor_forward_source(
            &self.authority_domain,
            self.epoch,
            &record.ingress,
            &intent_digest,
        )?;
        if record.schema != "ag.effect-forward-outbox/v3"
            || record.intent != intent_digest
            || record.source != source
            || entity != forward_entity(&source)
        {
            return Err(AgdError::OutboxBindingMismatch);
        }
        Ok(())
    }

    fn load_artifact_transfers(
        &self,
        intent: &ProposalIntentV1,
    ) -> Result<Vec<ArtifactTransferV1>, AgdError> {
        let mut artifacts = Vec::with_capacity(intent.admitted_artifacts.len());
        let mut remaining = u64::from(self.config.limits.max_control_frame_bytes) / 2;
        for digest in &intent.admitted_artifacts {
            let maximum = self.config.limits.max_artifact_bytes.min(remaining);
            let bytes = self.store.read_blob(digest, maximum)?;
            let byte_length =
                u64::try_from(bytes.len()).map_err(|_| AgdError::ArtifactTransferTooLarge)?;
            remaining = remaining
                .checked_sub(byte_length)
                .ok_or(AgdError::ArtifactTransferTooLarge)?;
            artifacts.push(ArtifactTransferV1 {
                digest: digest.clone(),
                byte_length,
                content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            });
        }
        Ok(artifacts)
    }

    fn submit_to_effectd(
        &self,
        ingress: GovernedProposalIngressV1,
        artifacts: Vec<ArtifactTransferV1>,
    ) -> Result<AgdResponseV1, AgdError> {
        let request_id = RequestId::new(format!("agd-{}", uuid::Uuid::new_v4()))?;
        let effectd = self.config.effectd_peer.rpc_enrollment()?;
        let response: ApiResultV1<EffectProposalResponseV1> = call_signed(
            &self.config.effectd_proposal_socket,
            request_id,
            EffectProposalRequestV1::SubmitAuthenticatedIntent {
                ingress: Box::new(ingress),
                artifacts,
            },
            self.config.limits.max_control_frame_bytes,
            &self.rpc_signer,
            &effectd,
            &self.rpc_replay,
            &SystemRpcClockV1,
            SocketPeerCheckV1::RequireUidGid {
                uid: self.config.effectd_peer.uid,
                gid: self.config.effectd_peer.gid,
            },
        )?;
        let broker_response = match response {
            ApiResultV1::Ok { response } => response,
            ApiResultV1::Error {
                code: _,
                message,
                correlation: _,
            } => {
                return Err(AgdError::Broker(message));
            }
        };
        match broker_response {
            EffectProposalResponseV1::Canonicalized {
                proposal_id,
                proposal_digest,
            } => Ok(AgdResponseV1::ProposalSubmitted {
                proposal_id,
                proposal_digest,
            }),
            EffectProposalResponseV1::Indeterminate { envelope } => {
                Ok(AgdResponseV1::Indeterminate { envelope })
            }
            EffectProposalResponseV1::Refused { refusal } => Ok(AgdResponseV1::Refused { refusal }),
            EffectProposalResponseV1::Health { .. } => {
                Err(AgdError::Broker("unexpected health response".to_owned()))
            }
        }
    }

    fn complete_forward_outbox(
        &mut self,
        entity: String,
        record: ForwardOutboxRecordV1,
        revision: u64,
        result: &AgdResponseV1,
    ) -> Result<(), AgdError> {
        let completed = ForwardOutboxRecordV1 {
            state: ForwardOutboxStateV1::Completed {
                response: result.clone(),
            },
            ..record
        };
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: entity,
                event_kind: "effect-forward.completed.v1".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: result,
            },
            &completed,
            revision,
        )?;
        Ok(())
    }
}

fn proposer_binding_matches(
    intent_domain: &AuthorityDomain,
    intent_epoch: Epoch,
    intent_proposer: &PrincipalChainV1,
    authenticated_domain: &AuthorityDomain,
    authenticated_epoch: Epoch,
    authenticated_proposer: &PrincipalChainV1,
) -> bool {
    intent_domain == authenticated_domain
        && intent_epoch == authenticated_epoch
        && intent_proposer.authority_domain() == authenticated_domain
        && intent_proposer.epoch() == authenticated_epoch
        && intent_proposer == authenticated_proposer
        && intent_proposer.root().principal_id == authenticated_proposer.root().principal_id
        && intent_proposer.leaf().principal_id == authenticated_proposer.leaf().principal_id
}

fn configured_worker_security_profile(profile: &str) -> Result<SecurityProfileV1, AgdError> {
    match profile {
        "development" => Ok(SecurityProfileV1::Development),
        "production" => Ok(SecurityProfileV1::Production),
        "high_assurance" => Ok(SecurityProfileV1::HighAssurance),
        _ => Err(AgdError::WorkerRuntimeUnavailable),
    }
}

fn worker_process_failure_reason(error: &WorkerLaunchError) -> WorkerTerminationReasonV1 {
    match error {
        WorkerLaunchError::TimedOut => WorkerTerminationReasonV1::DeadlineExpired,
        WorkerLaunchError::CandidateLimitExceeded { observed_bytes } => {
            WorkerTerminationReasonV1::OutputBudgetExceeded {
                observed_bytes: *observed_bytes,
            }
        }
        WorkerLaunchError::CandidateStreamIndeterminate | WorkerLaunchError::Io { .. } => {
            WorkerTerminationReasonV1::BoundaryIndeterminate {
                envelope: Digest::hash_domain(
                    "ag-ng/worker-boundary-failure/v1",
                    error.to_string().as_bytes(),
                ),
            }
        }
        _ => WorkerTerminationReasonV1::WorkerFailed {
            failure: Digest::hash_domain(
                "ag-ng/worker-process-failure/v1",
                error.to_string().as_bytes(),
            ),
        },
    }
}

fn worker_candidate_refusal_reason(error: &AgdError) -> Option<WorkerTerminationReasonV1> {
    let code = match error {
        AgdError::WorkerProtocol(_) => WorkerCandidateRefusalCodeV1::MalformedFrame,
        AgdError::RpcAuthentication(_) => WorkerCandidateRefusalCodeV1::AuthenticationFailed,
        AgdError::WorkerProofMismatch => WorkerCandidateRefusalCodeV1::PrincipalBindingMismatch,
        AgdError::WorkerProfileBindingMismatch | AgdError::WorkerCandidateSemanticMismatch => {
            WorkerCandidateRefusalCodeV1::ReviewedProfileMismatch
        }
        AgdError::WorkerCandidateExpired => WorkerCandidateRefusalCodeV1::Expired,
        AgdError::WorkerCandidateBudgetExceeded { observed_bytes } => {
            return Some(WorkerTerminationReasonV1::OutputBudgetExceeded {
                observed_bytes: *observed_bytes,
            });
        }
        _ => return None,
    };
    Some(WorkerTerminationReasonV1::CandidateRefused { code })
}

fn worker_admitted_inputs() -> Vec<AdmittedWorkerInputV1> {
    vec![
        AdmittedWorkerInputV1 {
            descriptor: 3,
            purpose: CANDIDATE_INGRESS_CREDENTIAL_PURPOSE.to_owned(),
            maximum_bytes: 4096,
        },
        AdmittedWorkerInputV1 {
            descriptor: 4,
            purpose: CANDIDATE_BOOTSTRAP_PURPOSE.to_owned(),
            maximum_bytes: 4096,
        },
    ]
}

fn populate_worker_inputs(
    prepared: &mut PreparedWorkerLaunchV1,
    private_key: &EphemeralRpcPrivateKeyV1,
    bootstrap: &WorkerCandidateBootstrapV1,
) -> Result<(), AgdError> {
    let mut private_bytes = Vec::with_capacity(private_key.byte_length());
    if let Err(source) = private_key.write_to(&mut private_bytes) {
        private_bytes.fill(0);
        return Err(WorkerLaunchError::Io {
            operation: "materialize admitted worker credential",
            source,
        }
        .into());
    }
    let bootstrap_frame = FrameCodec::new(bootstrap.maximum_frame_bytes)?.encode_json(bootstrap)?;
    let result = (|| {
        let mut wrote_credential = false;
        let mut wrote_challenge = false;
        for mut pipe in std::mem::take(&mut prepared.admitted_inputs) {
            match pipe.purpose() {
                CANDIDATE_INGRESS_CREDENTIAL_PURPOSE if !wrote_credential => {
                    pipe.write_all(&private_bytes)?;
                    wrote_credential = true;
                }
                CANDIDATE_BOOTSTRAP_PURPOSE if !wrote_challenge => {
                    pipe.write_all(&bootstrap_frame)?;
                    wrote_challenge = true;
                }
                _ => return Err(WorkerLaunchError::DescriptorHandoff.into()),
            }
            pipe.close();
        }
        if !wrote_credential || !wrote_challenge {
            return Err(WorkerLaunchError::DescriptorHandoff.into());
        }
        Ok(())
    })();
    private_bytes.fill(0);
    result
}

fn worker_session_inputs(
    session: &SessionId,
    candidate_key_identity: &Digest,
    workspace: &Digest,
    profile: &WorkerProfileConfigV1,
) -> Result<(SourceSnapshotV1, Vec<AdmittedDescriptorV1>, Digest), AgdError> {
    let source = SourceSnapshotV1 {
        content: Digest::hash_domain("ag-ng/worker-empty-source/v1", session.as_str().as_bytes()),
        format: "empty_snapshot_v1".to_owned(),
        source_object: None,
    };
    let mut descriptors = vec![
        AdmittedDescriptorV1 {
            descriptor: 1,
            purpose: DescriptorPurposeV1::CandidateSink,
            access: DescriptorAccessV1::WriteOnly,
            object_identity: Digest::from_serializable(&(
                "ag.worker-candidate-sink/v1",
                session,
                workspace,
            ))?,
        },
        AdmittedDescriptorV1 {
            descriptor: 3,
            purpose: DescriptorPurposeV1::CandidateIngressCredential,
            access: DescriptorAccessV1::ReadOnly,
            object_identity: candidate_key_identity.clone(),
        },
        AdmittedDescriptorV1 {
            descriptor: 4,
            purpose: DescriptorPurposeV1::CandidateChallenge,
            access: DescriptorAccessV1::ReadOnly,
            object_identity: Digest::from_serializable(&(
                "ag.worker-candidate-challenge-channel/v1",
                session,
                candidate_key_identity,
            ))?,
        },
    ];
    if let Some(provider) = &profile.provider_access {
        descriptors.extend([
            AdmittedDescriptorV1 {
                descriptor: 5,
                purpose: DescriptorPurposeV1::ProviderRequest,
                access: DescriptorAccessV1::WriteOnly,
                object_identity: Digest::from_serializable(&(
                    "ag.worker-provider-request-channel/v1",
                    session,
                    &provider.provider_policy_digest,
                    &provider.envelope,
                ))?,
            },
            AdmittedDescriptorV1 {
                descriptor: 6,
                purpose: DescriptorPurposeV1::ProviderResponse,
                access: DescriptorAccessV1::ReadOnly,
                object_identity: Digest::from_serializable(&(
                    "ag.worker-provider-response-channel/v1",
                    session,
                    &provider.provider_policy_digest,
                    &provider.envelope,
                ))?,
            },
        ]);
    }
    let input_set =
        Digest::from_serializable(&("ag.worker-admitted-input-set/v1", &source, &descriptors))?;
    Ok((source, descriptors, input_set))
}

#[allow(clippy::too_many_arguments)]
fn worker_principal_from_launch(
    authority_domain: &AuthorityDomain,
    epoch: Epoch,
    governor_principal: &Digest,
    profile: &crate::config::WorkerProfileConfigV1,
    session: &SessionId,
    session_nonce: LifecycleNonce,
    expires_at_unix_ms: u64,
    candidate_key_identity: Digest,
    prepared: &PreparedWorkerLaunchV1,
) -> Result<WorkerSessionPrincipalV1, AgdError> {
    let (_, _, input_set_digest) = worker_session_inputs(
        session,
        &candidate_key_identity,
        &prepared.workspace.identity,
        profile,
    )?;
    let provider_route = worker_provider_route(profile);
    Ok(WorkerSessionPrincipalV1 {
        authority_domain: authority_domain.clone(),
        epoch,
        project: ProjectId::parse(&profile.project)?,
        session_id: session.clone(),
        session_nonce,
        launcher: PrincipalId::new(governor_principal.clone()),
        executable: prepared.evidence.worker_executable.clone(),
        launch_profile: LaunchProfileIdentityV1::new(
            prepared.evidence.launch_profile.clone(),
            Digest::hash_domain(
                "ag-ng/worker-candidate-protocol-schema/v1",
                b"candidate-only-signed-frame-v1",
            ),
        ),
        proposal_workspace_identity: prepared.workspace.identity.clone(),
        security_profile_identity: SecurityProfileV1::Development.identity(),
        candidate_ingress_key_identity: candidate_key_identity,
        expires_at_unix_ms,
        output_budget_bytes: profile.output_budget_bytes,
        provider_route,
        input_set_digest,
        observed_credentials: HostCredentialObservationV1 {
            uid: prepared.evidence.observed_uid,
            gid: prepared.evidence.observed_gid,
            pid: prepared.evidence.sandbox_pid,
            cgroup: CgroupIdentity::parse("development-unattested")?,
        },
    })
}

fn worker_provider_route(profile: &WorkerProfileConfigV1) -> WorkerProviderRouteV1 {
    profile
        .provider_access
        .as_ref()
        .map_or(WorkerProviderRouteV1::Offline, |provider| {
            WorkerProviderRouteV1::Constrained {
                provider_policy_digest: provider.provider_policy_digest.clone(),
                envelope: provider.envelope.clone(),
                budget: provider.budget,
            }
        })
}

fn worker_provider_attempt_entity(
    session: &SessionId,
    attempt: &RequestId,
) -> Result<String, AgdError> {
    Ok(format!(
        "worker-provider-attempt:{}",
        Digest::from_serializable(&("ag.worker-provider-attempt-identity/v1", session, attempt))?
            .as_str()
    ))
}

fn validate_worker_provider_attempt_record(
    entity: &str,
    record: &WorkerProviderAttemptRecordV1,
) -> Result<(), AgdError> {
    record.request.verify()?;
    if record.schema != "ag.worker-provider-attempt/v1"
        || entity != worker_provider_attempt_entity(&record.session, &record.attempt)?
    {
        return Err(AgdError::WorkerProviderAttemptMismatch);
    }
    if let WorkerProviderAttemptStateV1::ResponseInCustody { response, .. }
    | WorkerProviderAttemptStateV1::Acknowledged { response, .. } = &record.state
    {
        response.verify()?;
        if response.request_custody != record.request.custody_record {
            return Err(AgdError::WorkerProviderAttemptMismatch);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn worker_provider_capability(
    profile: &WorkerProfileConfigV1,
    authority_domain: &AuthorityDomain,
    epoch: Epoch,
    project: &ProjectId,
    session: &SessionId,
    session_nonce: LifecycleNonce,
    worker_principal: PrincipalId,
    not_before_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<Option<InferenceCapabilityV1>, AgdError> {
    let Some(provider) = &profile.provider_access else {
        return Ok(None);
    };
    Ok(Some(
        InferenceCapabilityV1::new(
            authority_domain.clone(),
            epoch,
            project.clone(),
            session.clone(),
            session_nonce,
            worker_principal,
            provider.provider_policy_digest.clone(),
            provider.envelope.clone(),
            provider.budget,
            not_before_unix_ms,
            expires_at_unix_ms,
            session_nonce,
        )
        .map_err(ag_session::SessionError::ProviderCapabilityDefinition)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn worker_session_spec(
    authority_domain: &AuthorityDomain,
    epoch: Epoch,
    security_profile: SecurityProfileV1,
    profile: &crate::config::WorkerProfileConfigV1,
    session: &SessionId,
    candidate_key_identity: Digest,
    worker: WorkerSessionPrincipalV1,
    worker_chain: PrincipalChainV1,
    prepared: &PreparedWorkerLaunchV1,
    not_before_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<BatchSessionSpecV1, AgdError> {
    let (source, admitted_descriptors, input_set_digest) = worker_session_inputs(
        session,
        &candidate_key_identity,
        &prepared.workspace.identity,
        profile,
    )?;
    if worker.input_set_digest != input_set_digest {
        return Err(AgdError::WorkerProfileBindingMismatch);
    }
    let launch_receipt = Digest::from_serializable(&prepared.evidence)?;
    let isolation = IsolationEvidenceV1 {
        user_namespace: Digest::hash_domain(
            "ag-ng/development-user-namespace-evidence/v1",
            launch_receipt.as_str().as_bytes(),
        ),
        mount_namespace: Digest::hash_domain(
            "ag-ng/development-mount-namespace-evidence/v1",
            launch_receipt.as_str().as_bytes(),
        ),
        pid_namespace: Digest::hash_domain(
            "ag-ng/development-pid-namespace-evidence/v1",
            launch_receipt.as_str().as_bytes(),
        ),
        cgroup: Digest::hash_domain(
            "ag-ng/development-unattested-cgroup/v1",
            launch_receipt.as_str().as_bytes(),
        ),
        seccomp_profile: Digest::hash_domain(
            "ag-ng/development-unattested-seccomp/v1",
            launch_receipt.as_str().as_bytes(),
        ),
        landlock_ruleset: Digest::hash_domain(
            "ag-ng/development-unattested-landlock/v1",
            launch_receipt.as_str().as_bytes(),
        ),
        network_namespace: Digest::hash_domain(
            "ag-ng/development-network-namespace/v1",
            launch_receipt.as_str().as_bytes(),
        ),
        observed_uid: prepared.evidence.observed_uid,
        observed_gid: prepared.evidence.observed_gid,
        observed_pid: prepared.evidence.sandbox_pid,
        observed_executable: prepared.evidence.worker_executable.clone(),
    };
    let provider_capability = worker_provider_capability(
        profile,
        authority_domain,
        epoch,
        &worker.project,
        session,
        worker.session_nonce,
        worker.id(),
        not_before_unix_ms,
        expires_at_unix_ms,
    )?;
    Ok(BatchSessionSpecV1 {
        schema: ag_session::SESSION_SCHEMA_V1.to_owned(),
        session: session.clone(),
        authority_domain: authority_domain.clone(),
        epoch,
        security_profile,
        reviewed_profile_id: profile.profile_id.clone(),
        candidate_ingress_key_identity: candidate_key_identity,
        worker: WorkerBindingV1 {
            principal: worker,
            principal_chain: worker_chain,
            isolation,
        },
        workspace_mode: WorkspaceModeV1::IndependentSnapshot,
        proposal_workspace_identity: prepared.workspace.identity.clone(),
        source,
        admitted_descriptors,
        provider_capability,
        deadline_unix_ms: expires_at_unix_ms,
        output_budget_bytes: profile.output_budget_bytes,
    })
}

fn worker_effect_evaluation(
    authority_domain: AuthorityDomain,
    epoch: Epoch,
    lifecycle_nonce: ag_primitives::LifecycleNonce,
    subject: Digest,
) -> Result<EffectEvaluationInputV1, AgdError> {
    let origin = LifecycleOrigin::new(authority_domain, epoch, lifecycle_nonce);
    let standing_ref = StandingRef::new(origin.clone(), BookLocalId::new("worker-standing-v1")?);
    let custody_ref = CustodyRef::new(
        origin.clone(),
        BookLocalId::new("worker-candidate-custody-v1")?,
    );
    let obligation_ref = ObligationRef::new(
        origin.clone(),
        BookLocalId::new("worker-reviewed-mapping-v1")?,
    );
    let capacity_ref = CapacityRef::new(
        origin.clone(),
        BookLocalId::new("worker-output-capacity-v1")?,
    );
    Ok(EffectEvaluationInputV1 {
        subject: subject.clone(),
        books: EffectBookSnapshotV1 {
            origin: origin.clone(),
            standing: vec![StandingBookEntry::new(
                standing_ref.clone(),
                subject.clone(),
            )],
            custody: vec![CustodyBookEntry::new(custody_ref.clone(), subject.clone())],
            obligation: vec![ObligationBookEntry::new(
                obligation_ref.clone(),
                subject.clone(),
            )],
            capacity: vec![CapacityBookEntry::new(
                capacity_ref.clone(),
                subject.clone(),
            )],
        },
        claim: EffectCrossingClaim::new(
            StandingClaim::new(origin.clone(), subject.clone(), standing_ref),
            CustodyClaim::new(origin.clone(), subject.clone(), custody_ref),
            ObligationClaim::new(origin.clone(), subject.clone(), obligation_ref),
            CapacityClaim::new(origin, subject, capacity_ref),
        ),
    })
}

fn worker_principal_chain(
    authority_domain: &AuthorityDomain,
    epoch: Epoch,
    configured_root: &Digest,
    governor_signing_principal: &Digest,
    worker: &ag_primitives::WorkerSessionPrincipalV1,
) -> Result<PrincipalChainV1, AgdError> {
    let root = PrincipalId::new(configured_root.clone());
    let governor = PrincipalId::new(governor_signing_principal.clone());
    if worker.launcher != governor {
        return Err(AgdError::WorkerProfileBindingMismatch);
    }
    let mut nodes = vec![PrincipalChainNodeV1::root(
        root.clone(),
        PrincipalKindV1::Daemon,
    )];
    if governor != root {
        nodes.push(PrincipalChainNodeV1::child(
            governor.clone(),
            PrincipalKindV1::Daemon,
            root,
        ));
    }
    nodes.push(PrincipalChainNodeV1::child(
        worker.id(),
        PrincipalKindV1::WorkerSession,
        governor,
    ));
    Ok(PrincipalChainV1::new(
        authority_domain.clone(),
        epoch,
        nodes,
    )?)
}

fn worker_intent_id(session: &ag_session::SessionId, custody: &Digest) -> String {
    let suffix = custody
        .as_str()
        .strip_prefix("sha256:")
        .unwrap_or(custody.as_str());
    format!("worker-{}-{}", session.as_str(), &suffix[..16])
}

fn replay_books(
    snapshot: &EffectBookSnapshotV1,
) -> Result<(StandingBook, CustodyBook, ObligationBook, CapacityBook), AgdError> {
    let mut standing = StandingBook::new(snapshot.origin.clone());
    for entry in &snapshot.standing {
        standing.replay_committed(entry.clone())?;
    }
    let mut custody = CustodyBook::new(snapshot.origin.clone());
    for entry in &snapshot.custody {
        custody.replay_committed(entry.clone())?;
    }
    let mut obligation = ObligationBook::new(snapshot.origin.clone());
    for entry in &snapshot.obligation {
        obligation.replay_committed(entry.clone())?;
    }
    let mut capacity = CapacityBook::new(snapshot.origin.clone());
    for entry in &snapshot.capacity {
        capacity.replay_committed(entry.clone())?;
    }
    Ok((standing, custody, obligation, capacity))
}

fn ensure_claim_subject(claim: &EffectCrossingClaim, subject: &Digest) -> Result<(), AgdError> {
    if claim.standing().subject_digest() != subject
        || claim.custody().subject_digest() != subject
        || claim.obligation().subject_digest() != subject
        || claim.capacity().subject_digest() != subject
    {
        return Err(AgdError::JudgmentBindingMismatch);
    }
    Ok(())
}

fn judgment_entity(digest: &Digest) -> String {
    format!(
        "judgment-{}",
        digest
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(digest.as_str())
    )
}

fn forward_entity(source: &Digest) -> String {
    format!(
        "forward-{}",
        source
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(source.as_str())
    )
}

fn ingress_intent(ingress: &GovernedProposalIngressV1) -> Result<&ProposalIntentV1, AgdError> {
    match ingress {
        GovernedProposalIngressV1::ExternalSigned { proof } => {
            match &proof.signed_request.request.body {
                AgdRequestV1::SubmitProposal { intent } => Ok(intent),
                AgdRequestV1::Health
                | AgdRequestV1::LaunchWorker { .. }
                | AgdRequestV1::InspectWorker { .. }
                | AgdRequestV1::CancelWorker { .. } => Err(AgdError::OutboxBindingMismatch),
            }
        }
        GovernedProposalIngressV1::WorkerCandidate { intent, .. } => Ok(intent),
    }
}

fn governor_forward_source(
    authority_domain: &AuthorityDomain,
    epoch: Epoch,
    ingress: &GovernedProposalIngressV1,
    intent_digest: &Digest,
) -> Result<Digest, AgdError> {
    let intent = ingress_intent(ingress)?;
    match ingress {
        GovernedProposalIngressV1::ExternalSigned { .. } => Ok(Digest::from_serializable(&(
            "ag.effect.governor-forward-source/v1",
            authority_domain,
            epoch,
            &intent.proposer,
            intent_digest,
        ))?),
        GovernedProposalIngressV1::WorkerCandidate { source, .. } => {
            Ok(Digest::from_serializable(&(
                "ag.effect.governor-worker-forward-source/v1",
                authority_domain,
                epoch,
                &intent.proposer,
                intent_digest,
                source,
            ))?)
        }
    }
}

fn is_deferred_forward_error(error: &AgdError) -> bool {
    matches!(
        error,
        AgdError::Transport(_) | AgdError::SignedTransport(_) | AgdError::Broker(_)
    )
}

fn judgment_kind(judgment: &StoredEffectJudgmentV1) -> &'static str {
    match judgment {
        StoredEffectJudgmentV1::Admit { .. } => "effect-judgment.admitted.v1",
        StoredEffectJudgmentV1::Refuse { .. } => "effect-judgment.refused.v1",
        StoredEffectJudgmentV1::Indeterminate { .. } => "effect-judgment.indeterminate.v1",
    }
}

fn now_i64() -> Result<i64, AgdError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AgdError::Clock(error.to_string()))?;
    i64::try_from(duration.as_millis()).map_err(|_| AgdError::Clock("clock overflow".to_owned()))
}

fn now_u64() -> Result<u64, AgdError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AgdError::Clock(error.to_string()))?;
    u64::try_from(duration.as_millis()).map_err(|_| AgdError::Clock("clock overflow".to_owned()))
}

fn agd_api_error<T>(error: &AgdError) -> ApiResultV1<T> {
    let code = match error {
        AgdError::Quiesced => ApiErrorCodeV1::Quiesced,
        AgdError::JudgmentNotFound => ApiErrorCodeV1::NotFound,
        AgdError::JudgmentBindingMismatch | AgdError::JudgmentDidNotAdmit => {
            ApiErrorCodeV1::Unauthorized
        }
        AgdError::ProposerBindingMismatch => ApiErrorCodeV1::Unauthenticated,
        AgdError::Effect(_) | AgdError::Protocol(_) => ApiErrorCodeV1::InvalidRequest,
        AgdError::Broker(_) | AgdError::WorkerRecoveryRequired => ApiErrorCodeV1::Indeterminate,
        AgdError::WorkerSupervisorBusy | AgdError::WorkerCapacityExhausted => {
            ApiErrorCodeV1::Conflict
        }
        AgdError::WorkerProviderRuntimeUnavailable => ApiErrorCodeV1::Conflict,
        AgdError::WorkerProviderRequestTooLarge => ApiErrorCodeV1::InvalidRequest,
        AgdError::WorkerProviderAttemptMismatch => ApiErrorCodeV1::Conflict,
        _ => ApiErrorCodeV1::Internal,
    };
    ApiResultV1::error(code, error.to_string())
}

/// Governor-core failures.
#[derive(Debug, Error)]
pub enum AgdError {
    /// Authority identifier failed strict parsing.
    #[error(transparent)]
    Identifier(#[from] ag_primitives::IdentifierError),
    /// Canonical principal/session name failed strict parsing.
    #[error(transparent)]
    PrincipalName(#[from] PrincipalNameError),
    /// Principal lineage failed structural validation.
    #[error(transparent)]
    PrincipalChain(#[from] ag_primitives::PrincipalChainError),
    /// Event store failed.
    #[error(transparent)]
    Store(#[from] ag_store::StoreError),
    /// Durable worker-session custody failed.
    #[error(transparent)]
    WorkerSessionStore(#[from] WorkerSessionStoreError),
    /// Fixed-profile worker launch or process custody failed.
    #[error(transparent)]
    WorkerLaunch(#[from] WorkerLaunchError),
    /// Candidate-only worker framing/signing protocol failed.
    #[error(transparent)]
    WorkerProtocol(#[from] WorkerProtocolError),
    /// Worker principal/candidate model failed closed validation.
    #[error(transparent)]
    Session(#[from] ag_session::SessionError),
    /// Family-book replay failed.
    #[error(transparent)]
    Book(#[from] ag_kernel::FamilyBookError),
    /// Authority evidence reconstruction failed.
    #[error(transparent)]
    Authority(#[from] ag_kernel::AuthorityError),
    /// Effect intent failed.
    #[error(transparent)]
    Effect(#[from] ag_effect::EffectError),
    /// Canonical record identity failed.
    #[error(transparent)]
    Jcs(#[from] ag_primitives::JcsError),
    /// Strict RPC protocol failed.
    #[error(transparent)]
    Protocol(#[from] ag_protocol::ProtocolError),
    /// Local RPC transport failed.
    #[error(transparent)]
    Transport(#[from] crate::transport::TransportError),
    /// Signed local RPC failed.
    #[error(transparent)]
    SignedTransport(#[from] crate::signed_transport::SignedTransportError),
    /// Signed principal-chain reconstruction failed.
    #[error(transparent)]
    Peer(#[from] crate::peer::PeerError),
    /// Signed RPC peer enrollment was invalid.
    #[error(transparent)]
    RpcAuthentication(#[from] crate::rpc_auth::RpcAuthError),
    /// Effect broker returned a diagnostic failure.
    #[error("effect broker did not accept intent: {0}")]
    Broker(String),
    /// Coherent backup cut fences mutation.
    #[error("governor is quiesced for a coherent backup cut")]
    Quiesced,
    /// Judgment reference is absent.
    #[error("effect judgment record not found")]
    JudgmentNotFound,
    /// Subject/digest/book correspondence failed.
    #[error("effect judgment does not bind the exact proposal subject")]
    JudgmentBindingMismatch,
    /// Refusal/indeterminate cannot become admission.
    #[error("effect judgment is not an admission")]
    JudgmentDidNotAdmit,
    /// Caller-supplied proposer chain differs from the signed caller lineage.
    #[error("proposal intent proposer is not the authenticated signed caller chain")]
    ProposerBindingMismatch,
    /// Durable outbox bytes do not bind the exact authenticated intent and
    /// reconstructed admission.
    #[error("governor forward outbox binding mismatch")]
    OutboxBindingMismatch,
    /// Trusted clock cannot be represented.
    #[error("trusted clock failed: {0}")]
    Clock(String),
    /// Initial framed artifact-transfer slice exceeded its explicit bound.
    #[error("admitted artifacts exceed the bounded proposal transfer frame")]
    ArtifactTransferTooLarge,
    /// The reviewed worker catalog exists but the live launch supervisor has
    /// not been attached to this governor core.
    #[error("worker launch runtime is unavailable")]
    WorkerRuntimeUnavailable,
    /// A profile enrolled provider access, but the live worker/session proxy
    /// and request/response descriptor handoff are not yet implemented.
    #[error("worker provider runtime is unavailable")]
    WorkerProviderRuntimeUnavailable,
    /// Credential-free request bytes exceeded the enrolled session budget.
    #[error("worker provider request exceeds the enrolled bound")]
    WorkerProviderRequestTooLarge,
    /// A repeated attempt identity disagreed with its durable request/state.
    #[error("worker provider attempt does not match durable custody")]
    WorkerProviderAttemptMismatch,
    /// Configured maximum live-worker count has been reached.
    #[error("worker launch capacity is exhausted")]
    WorkerCapacityExhausted,
    /// A non-reusable session unexpectedly collided in live process custody.
    #[error("worker runtime session collision")]
    WorkerRuntimeCollision,
    /// A durable active worker had no retained process custody.
    #[error("worker runtime process custody is missing")]
    WorkerRuntimeMissing,
    /// Deadline-critical supervision excludes blocking authority work while
    /// the one admitted worker is live.
    #[error("worker supervisor is busy with the one admitted live worker")]
    WorkerSupervisorBusy,
    /// A commit-ambiguous launch-store transition requires daemon restart and
    /// startup recovery before any further mutation.
    #[error("worker launch state requires restart recovery")]
    WorkerRecoveryRequired,
    /// Dynamic candidate proof does not bind the active worker/session.
    #[error("worker candidate proof does not match durable session custody")]
    WorkerProofMismatch,
    /// Candidate semantic type differs from the exact reviewed profile.
    #[error("worker candidate semantic type does not match the reviewed profile")]
    WorkerCandidateSemanticMismatch,
    /// Candidate bytes exceed the exact reviewed output budget.
    #[error("worker candidate exceeds the reviewed output budget")]
    WorkerCandidateBudgetExceeded {
        /// Exact decoded candidate length observed at ingress.
        observed_bytes: u64,
    },
    /// Candidate arrived at or after the principal's exclusive deadline.
    #[error("worker candidate principal is expired")]
    WorkerCandidateExpired,
    /// Worker candidate custody has not reached the atomic accepted state.
    #[error("worker candidate is not in durable governor custody")]
    WorkerCandidateNotInCustody,
    /// A contained-session native judgment unexpectedly did not admit the
    /// exact reviewed candidate mapping.
    #[error("worker candidate native judgment did not admit")]
    WorkerJudgmentDidNotAdmit,
    /// Durable session/profile/launcher mapping differs from reviewed config.
    #[error("worker session does not match its reviewed launch profile")]
    WorkerProfileBindingMismatch,
}

#[cfg(test)]
mod tests {
    use ag_primitives::{PrincipalChainNodeV1, PrincipalId, PrincipalKindV1};

    use super::*;

    fn chain(domain: &AuthorityDomain, epoch: Epoch, label: &[u8]) -> PrincipalChainV1 {
        PrincipalChainV1::new(
            domain.clone(),
            epoch,
            vec![PrincipalChainNodeV1::root(
                PrincipalId::new(Digest::hash_bytes(label)),
                PrincipalKindV1::Operator,
            )],
        )
        .expect("chain")
    }

    #[test]
    fn proposer_must_equal_the_signed_caller_lineage_and_context() {
        let domain = AuthorityDomain::parse("test-host").expect("domain");
        let epoch = Epoch::parse("1").expect("epoch");
        let authenticated = chain(&domain, epoch, b"authenticated");
        assert!(proposer_binding_matches(
            &domain,
            epoch,
            &authenticated,
            &domain,
            epoch,
            &authenticated,
        ));
        let attacker = chain(&domain, epoch, b"attacker");
        assert!(!proposer_binding_matches(
            &domain,
            epoch,
            &attacker,
            &domain,
            epoch,
            &authenticated,
        ));
        let other_domain = AuthorityDomain::parse("other-host").expect("domain");
        assert!(!proposer_binding_matches(
            &other_domain,
            epoch,
            &authenticated,
            &domain,
            epoch,
            &authenticated,
        ));
    }

    #[test]
    fn candidate_refusals_remain_closed_and_budget_is_not_authentication() {
        assert_eq!(
            worker_candidate_refusal_reason(&AgdError::WorkerProofMismatch),
            Some(WorkerTerminationReasonV1::CandidateRefused {
                code: WorkerCandidateRefusalCodeV1::PrincipalBindingMismatch,
            })
        );
        assert_eq!(
            worker_candidate_refusal_reason(&AgdError::WorkerCandidateSemanticMismatch),
            Some(WorkerTerminationReasonV1::CandidateRefused {
                code: WorkerCandidateRefusalCodeV1::ReviewedProfileMismatch,
            })
        );
        assert_eq!(
            worker_candidate_refusal_reason(&AgdError::WorkerCandidateExpired),
            Some(WorkerTerminationReasonV1::CandidateRefused {
                code: WorkerCandidateRefusalCodeV1::Expired,
            })
        );
        assert_eq!(
            worker_candidate_refusal_reason(&AgdError::WorkerCandidateBudgetExceeded {
                observed_bytes: 4097,
            }),
            Some(WorkerTerminationReasonV1::OutputBudgetExceeded {
                observed_bytes: 4097,
            })
        );
        assert_eq!(
            worker_candidate_refusal_reason(&AgdError::WorkerRecoveryRequired),
            None
        );
    }

    #[test]
    fn provider_profile_builds_exact_route_capability_and_descriptor_contract() {
        let profile: WorkerProfileConfigV1 = serde_json::from_value(serde_json::json!({
            "profile_id": "fixture",
            "project": "fixture",
            "executable": "/usr/bin/fixture-worker",
            "executable_identity": {
                "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 1,
                "build_identity": null
            },
            "fixed_arguments": [],
            "candidate_effect": "managed_file_put",
            "candidate_target": "fixture.target",
            "candidate_semantic_type": "managed_file_content_v1",
            "timeout_ms": 1000,
            "output_budget_bytes": 1024,
            "provider_access": {
                "provider_policy_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "envelope": {
                    "endpoint": "primary", "model": "production-model",
                    "method": "responses.create",
                    "protocol_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                },
                "budget": {"requests": 1, "input_bytes": 4096,
                    "output_bytes": 4096, "cost_microunits": 1000}
            }
        }))
        .expect("closed provider profile");
        let provider = profile.provider_access.as_ref().expect("provider policy");
        assert_eq!(
            worker_provider_route(&profile),
            WorkerProviderRouteV1::Constrained {
                provider_policy_digest: provider.provider_policy_digest.clone(),
                envelope: provider.envelope.clone(),
                budget: provider.budget,
            }
        );

        let domain = AuthorityDomain::parse("test-host").expect("domain");
        let epoch = Epoch::parse("1").expect("epoch");
        let session = SessionId::new("provider-session").expect("session");
        let session_nonce = LifecycleNonce::new([7; 16]);
        let principal = PrincipalId::new(Digest::hash_bytes(b"worker"));
        let capability = worker_provider_capability(
            &profile,
            &domain,
            epoch,
            &ProjectId::parse("fixture").expect("project"),
            &session,
            session_nonce,
            principal.clone(),
            100,
            200,
        )
        .expect("capability construction")
        .expect("provider capability");
        assert_eq!(capability.worker_principal, principal);
        assert_eq!(capability.envelope, provider.envelope);
        assert_eq!(capability.budget, provider.budget);
        assert_eq!(capability.not_before_unix_ms, 100);
        assert_eq!(capability.expires_at_unix_ms, 200);

        let (_, descriptors, _) = worker_session_inputs(
            &session,
            &Digest::hash_bytes(b"candidate-key"),
            &Digest::hash_bytes(b"workspace"),
            &profile,
        )
        .expect("provider descriptor contract");
        assert!(descriptors.iter().any(|descriptor| {
            descriptor.descriptor == 5
                && descriptor.purpose == DescriptorPurposeV1::ProviderRequest
                && descriptor.access == DescriptorAccessV1::WriteOnly
        }));
        assert!(descriptors.iter().any(|descriptor| {
            descriptor.descriptor == 6
                && descriptor.purpose == DescriptorPurposeV1::ProviderResponse
                && descriptor.access == DescriptorAccessV1::ReadOnly
        }));
        assert!(matches!(
            agd_api_error::<()>(&AgdError::WorkerProviderRuntimeUnavailable),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Conflict,
                ..
            }
        ));

        let request = ProviderRequestCustodyV1::new(
            capability.id(),
            Digest::hash_bytes(b"request"),
            BTreeMap::new(),
            capability.envelope,
        )
        .expect("request custody");
        let attempt = RequestId::new("attempt-1").expect("attempt identity");
        let entity = worker_provider_attempt_entity(&session, &attempt).expect("entity");
        let record = WorkerProviderAttemptRecordV1 {
            schema: "ag.worker-provider-attempt/v1".to_owned(),
            session,
            worker_principal: principal,
            attempt,
            request,
            state: WorkerProviderAttemptStateV1::RequestInCustody,
        };
        validate_worker_provider_attempt_record(&entity, &record).expect("valid attempt");
        let mut mismatched = record;
        mismatched.request.exact_request = Digest::hash_bytes(b"changed");
        assert!(validate_worker_provider_attempt_record(&entity, &mismatched).is_err());
    }
}
