//! Governor-side calculus replay and broker forwarding.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ag_effect::ProposalIntentV1;
use ag_kernel::{
    AdmissionCommit, CapacityBook, CapacityBookEntry, CustodyBook, CustodyBookEntry,
    EffectCrossingClaim, EffectCrossingRefusal, EffectCrossingWitness, FailureEvidence,
    NativeJudgment, NonEmpty, ObligationBook, ObligationBookEntry, StandingBook, StandingBookEntry,
    evaluate_effect_crossing, reconstruct_effect_authority,
};
use ag_primitives::{AuthorityDomain, Digest, Epoch, LifecycleOrigin, PrincipalChainV1};
use ag_protocol::RequestId;
use ag_store::{NewEventV1, Store};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::{
    AgdRequestV1, AgdResponseV1, ApiErrorCodeV1, ApiResultV1, ArtifactTransferV1,
    EffectProposalRequestV1, EffectProposalResponseV1, HealthV1, ProposalIngressProofV1,
};
use crate::config::AgdConfigV1;
use crate::peer::signed_principal_chain;
use crate::rpc_auth::{RpcReplayGuardV1, RpcSignerV1, SystemRpcClockV1, VerifiedRpcPrincipalV1};
use crate::signed_transport::{AcceptedSignedRequestV1, SocketPeerCheckV1, call_signed};

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
    pub ingress: ProposalIngressProofV1,
    /// Durable dispatch lifecycle.
    pub state: ForwardOutboxStateV1,
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

/// Single-writer governor core.
pub struct AgdCoreV1 {
    store: Store,
    config: AgdConfigV1,
    authority_domain: AuthorityDomain,
    epoch: Epoch,
    rpc_signer: Arc<RpcSignerV1>,
    rpc_replay: Arc<RpcReplayGuardV1>,
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
        })
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
                let artifacts = self.load_artifact_transfers(&intent)?;
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
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: judgment_entity(&digest),
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
                ProposalIngressProofV1 {
                    server_challenge: accepted.server_challenge.clone(),
                    signed_request: Box::new(accepted.signed_request.clone()),
                },
            ),
        }
    }

    fn forward_intent(
        &mut self,
        intent: &ProposalIntentV1,
        peer: &VerifiedRpcPrincipalV1,
        ingress: ProposalIngressProofV1,
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
        let expected_subject = intent.judgment_subject_digest()?;
        let verified = self.verify_admission(&intent.judgment, &expected_subject)?;
        let intent_digest = Digest::from_serializable(intent)?;
        let source = Digest::from_serializable(&(
            "ag.effect.governor-forward-source/v1",
            &self.authority_domain,
            self.epoch,
            &authenticated_proposer,
            &intent_digest,
        ))?;
        let (entity, record, revision) =
            match self.prepare_forward_outbox(&source, intent_digest, &verified, &ingress)? {
                ForwardOutboxPreparationV1::Completed(response) => return Ok(response),
                ForwardOutboxPreparationV1::Pending {
                    entity,
                    record,
                    revision,
                } => (entity, *record, revision),
            };
        let artifacts = self.load_artifact_transfers(intent)?;
        let result = self.submit_to_effectd(ingress, artifacts)?;
        self.complete_forward_outbox(entity, record, revision, &result)?;
        Ok(result)
    }

    fn prepare_forward_outbox(
        &mut self,
        source: &Digest,
        intent: Digest,
        admission: &VerifiedEffectAdmissionV1,
        ingress: &ProposalIngressProofV1,
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
                        event_kind: "effect-forward.reproofed.v2".to_owned(),
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
            schema: "ag.effect-forward-outbox/v2".to_owned(),
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
                event_kind: "effect-forward.pending.v2".to_owned(),
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
        let source = Digest::from_serializable(&(
            "ag.effect.governor-forward-source/v1",
            &self.authority_domain,
            self.epoch,
            &intent.proposer,
            &intent_digest,
        ))?;
        if record.schema != "ag.effect-forward-outbox/v2"
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
        ingress: ProposalIngressProofV1,
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
            EffectProposalResponseV1::Canonicalized { proposal_id, .. } => {
                Ok(AgdResponseV1::ProposalSubmitted { proposal_id })
            }
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

fn ingress_intent(ingress: &ProposalIngressProofV1) -> Result<&ProposalIntentV1, AgdError> {
    match &ingress.signed_request.request.body {
        AgdRequestV1::SubmitProposal { intent } => Ok(intent),
        AgdRequestV1::Health => Err(AgdError::OutboxBindingMismatch),
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

fn agd_api_error<T>(error: &AgdError) -> ApiResultV1<T> {
    let code = match error {
        AgdError::Quiesced => ApiErrorCodeV1::Quiesced,
        AgdError::JudgmentNotFound => ApiErrorCodeV1::NotFound,
        AgdError::JudgmentBindingMismatch | AgdError::JudgmentDidNotAdmit => {
            ApiErrorCodeV1::Unauthorized
        }
        AgdError::ProposerBindingMismatch => ApiErrorCodeV1::Unauthenticated,
        AgdError::Effect(_) | AgdError::Protocol(_) => ApiErrorCodeV1::InvalidRequest,
        AgdError::Broker(_) => ApiErrorCodeV1::Indeterminate,
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
    /// Event store failed.
    #[error(transparent)]
    Store(#[from] ag_store::StoreError),
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
}
