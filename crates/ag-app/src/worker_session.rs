//! Durable governor custody for one-shot worker sessions.
//!
//! This module owns no launcher or transport. It commits the already-reviewed
//! session model, resolves launcher-authenticated principals to those records,
//! and serializes every authority transition through one fenced [`Store`].

use std::io::Cursor;

use ag_primitives::{Digest, JcsError, LifecycleNonce, PrincipalId, SessionId};
use ag_session::{
    WorkerAuthorityStateV1, WorkerCandidateBrokerOutcomeV1, WorkerCandidateCustodyStateV1,
    WorkerCandidateCustodyV1, WorkerCleanupStateV1, WorkerIngressContextV1,
    WorkerPrincipalTombstoneV1, WorkerSessionEventV1, WorkerSessionRecordV1,
    WorkerTerminationReasonV1, WorkspaceDeltaV1,
};
use ag_store::{
    BlobDescriptorV1, MaterializedStateV1, NewEventV1, Store, StoreDigestV1, StoreError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SESSION_ENTITY_PREFIX: &str = "worker-session:";
const PRINCIPAL_ENTITY_PREFIX: &str = "worker-principal:";
const PRINCIPAL_INDEX_SCHEMA_V1: &str = "ag.worker-principal-index/v1";
const RECOVERY_PAGE_SIZE: u32 = 128;
const INGRESS_PROOF_STRUCTURAL_RESERVE_BYTES: u64 = 128 * 1024;

/// Immutable principal-to-session lookup record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPrincipalIndexV1 {
    /// Exact index schema.
    pub schema: String,
    /// Principal named by the materialized entity ID.
    pub principal_id: PrincipalId,
    /// Non-reusable session named by the target record.
    pub session_id: SessionId,
    /// Exact session lifecycle bound into the principal.
    pub session_nonce: LifecycleNonce,
    /// Digest of the immutable reviewed session specification.
    pub session_spec_digest: Digest,
}

/// Fully validated durable session state plus optimistic revision evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedWorkerSessionV1 {
    /// Canonical materialized entity ID.
    pub entity_id: String,
    /// Entity-local revision used for the next compare-and-swap.
    pub revision: u64,
    /// Canonical materialized-state digest.
    pub state_digest: StoreDigestV1,
    /// Exact validated worker-session state.
    pub record: WorkerSessionRecordV1,
}

/// Result of one bounded startup recovery scan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerStartupRecoveryReportV1 {
    /// Prepared or active principals durably tombstoned by this pass.
    pub tombstoned: u64,
    /// Records already tombstoned before this pass.
    pub already_terminal: u64,
}

/// Store-backed worker-session coordinator.
pub struct WorkerSessionStoreV1<'a> {
    store: &'a mut Store,
}

impl<'a> WorkerSessionStoreV1<'a> {
    /// Borrows the governor's single-authoritative-writer store.
    #[must_use]
    pub const fn new(store: &'a mut Store) -> Self {
        Self { store }
    }

    /// Atomically prepares a validated session and immutable principal index.
    ///
    /// Exact retries return the existing session, including if its lifecycle
    /// has advanced. A changed specification, one-sided pair, or reused
    /// principal/session binding refuses.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid/non-prepared record, binding conflict,
    /// canonicalization failure, clock overflow, backup barrier, or store
    /// failure.
    pub fn prepare(
        &mut self,
        record: &WorkerSessionRecordV1,
        occurred_at_unix_ms: u64,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        record.validate()?;
        if !matches!(record.authority, WorkerAuthorityStateV1::Prepared)
            || !matches!(record.candidate, WorkerCandidateCustodyStateV1::Awaiting)
        {
            return Err(WorkerSessionStoreError::PrepareRequiresPristineRecord);
        }
        let principal = &record.spec.worker.principal;
        let session_entity = session_entity(&record.spec.session);
        let principal_entity = principal_entity(&principal.id());
        let index = principal_index(record)?;
        let existing_session = self.load_session_optional(&record.spec.session)?;
        let existing_index = self.load_index_optional(&principal.id())?;
        match (existing_session, existing_index) {
            (Some(existing), Some(stored_index)) => {
                Self::validate_index(&principal.id(), &stored_index.state, &existing.record)?;
                if existing.record.spec != record.spec || stored_index.state != index {
                    return Err(WorkerSessionStoreError::PrepareConflict);
                }
                return Ok(existing);
            }
            (None, None) => {}
            _ => return Err(WorkerSessionStoreError::IncompletePreparePair),
        }

        let occurred_at_unix_ms = clock_i64(occurred_at_unix_ms)?;
        self.store.append_distinct_event_pair(
            NewEventV1 {
                event_id: event_id("worker-session-prepared", &record)?,
                entity_id: session_entity,
                event_kind: "worker-session.prepared.v1".to_owned(),
                occurred_at_unix_ms,
                payload: &record,
            },
            &record,
            0,
            NewEventV1 {
                event_id: event_id("worker-principal-indexed", &index)?,
                entity_id: principal_entity,
                event_kind: "worker-principal.indexed.v1".to_owned(),
                occurred_at_unix_ms,
                payload: &index,
            },
            &index,
            0,
        )?;
        self.load_session(&record.spec.session)
    }

    /// Loads and fully validates one canonical session entity.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or any entity/body/model
    /// binding is inconsistent.
    pub fn load_session(
        &self,
        session: &SessionId,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let loaded = self
            .load_session_optional(session)?
            .ok_or_else(|| WorkerSessionStoreError::SessionNotFound(session.clone()))?;
        let principal = loaded.record.spec.worker.principal.id();
        let index = self
            .load_index_optional(&principal)?
            .ok_or(WorkerSessionStoreError::IncompletePreparePair)?;
        Self::validate_index(&principal, &index.state, &loaded.record)?;
        Ok(loaded)
    }

    /// Resolves an immutable principal index and fully validates its session.
    ///
    /// # Errors
    ///
    /// Returns an error if the principal/index/session is absent or any digest,
    /// entity, lifecycle, or principal binding differs.
    pub fn load_by_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let loaded_index = self
            .load_index_optional(principal)?
            .ok_or_else(|| WorkerSessionStoreError::PrincipalNotFound(principal.clone()))?;
        let session = self.load_session(&loaded_index.state.session_id)?;
        Self::validate_index(principal, &loaded_index.state, &session.record)?;
        Ok(session)
    }

    /// Compare-and-swap activates one prepared principal.
    ///
    /// An exact retry of the same launch receipt is idempotent. Changed launch
    /// material or a terminal record refuses.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent session, forbidden lifecycle edge,
    /// changed retry, clock overflow, or store failure.
    pub fn activate(
        &mut self,
        session: &SessionId,
        launch_receipt: Digest,
        occurred_at_unix_ms: u64,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let loaded = self.load_session(session)?;
        match &loaded.record.authority {
            WorkerAuthorityStateV1::Active {
                launch_receipt: existing,
            } if *existing == launch_receipt => return Ok(loaded),
            WorkerAuthorityStateV1::Active { .. } => {
                return Err(WorkerSessionStoreError::ChangedRetry);
            }
            WorkerAuthorityStateV1::Tombstoned { .. } => {
                return Err(WorkerSessionStoreError::PrincipalTombstoned);
            }
            WorkerAuthorityStateV1::Prepared => {}
        }
        self.apply_event(
            loaded,
            &WorkerSessionEventV1::Activate { launch_receipt },
            "worker-session.activated.v1",
            occurred_at_unix_ms,
        )
    }

    /// Validates authenticated ingress, installs exact immutable ingress proof
    /// and candidate bytes, then atomically commits custody plus its tombstone.
    ///
    /// Proof and candidate blob installation intentionally precede the session
    /// event. A crash or event failure may leave unreferenced immutable blobs;
    /// it cannot leave partial candidate/canonical-proposal state.
    ///
    /// # Errors
    ///
    /// Returns a typed session refusal before blob installation unless the
    /// principal is active and every live binding matches. Also returns an
    /// error for output-budget overflow, blob/store failure, or transition CAS.
    pub fn accept_candidate(
        &mut self,
        context: &WorkerIngressContextV1,
        candidate_bytes: &[u8],
        ingress_proof_bytes: &[u8],
        semantic_type: impl Into<String>,
        workspace_delta: Option<WorkspaceDeltaV1>,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let loaded = self.load_by_principal(&context.principal_id)?;
        loaded.record.validate_active_ingress(context)?;
        if ingress_proof_bytes.is_empty() {
            return Err(WorkerSessionStoreError::IngressProofEmpty);
        }
        let proof_byte_length = u64::try_from(ingress_proof_bytes.len())
            .map_err(|_| WorkerSessionStoreError::IngressProofLengthOverflow)?;
        let maximum_proof_bytes =
            maximum_ingress_proof_bytes(loaded.record.spec.output_budget_bytes)?;
        if proof_byte_length > maximum_proof_bytes {
            return Err(WorkerSessionStoreError::IngressProofBudgetExceeded);
        }
        let byte_length = u64::try_from(candidate_bytes.len())
            .map_err(|_| WorkerSessionStoreError::CandidateLengthOverflow)?;
        if byte_length > loaded.record.spec.output_budget_bytes {
            return Err(WorkerSessionStoreError::Session(
                ag_session::SessionError::CandidateBudgetExceeded,
            ));
        }
        let ingress_proof_digest = Digest::hash_bytes(ingress_proof_bytes);
        let candidate_digest = Digest::hash_bytes(candidate_bytes);
        let candidate = WorkerCandidateCustodyV1::new(
            candidate_digest.clone(),
            byte_length,
            semantic_type,
            workspace_delta,
            ingress_proof_digest.clone(),
        )?;
        let proof_descriptor = BlobDescriptorV1 {
            digest: ingress_proof_digest,
            byte_length: proof_byte_length,
        };
        self.store.install_blob(
            &proof_descriptor,
            &mut Cursor::new(ingress_proof_bytes),
            clock_i64(context.now_unix_ms)?,
        )?;
        let candidate_descriptor = BlobDescriptorV1 {
            digest: candidate_digest,
            byte_length,
        };
        self.store.install_blob(
            &candidate_descriptor,
            &mut Cursor::new(candidate_bytes),
            clock_i64(context.now_unix_ms)?,
        )?;
        let principal = &loaded.record.spec.worker.principal;
        let tombstone = WorkerPrincipalTombstoneV1 {
            principal_id: principal.id(),
            session_id: loaded.record.spec.session.clone(),
            session_nonce: principal.session_nonce,
            reason: WorkerTerminationReasonV1::CandidateAccepted,
            terminal_since_unix_ms: context.now_unix_ms,
        };
        self.apply_event(
            loaded,
            &WorkerSessionEventV1::AcceptCandidate {
                candidate,
                tombstone,
            },
            "worker-session.candidate-accepted.v1",
            context.now_unix_ms,
        )
    }

    /// Reads the exact opaque ingress proof bound into candidate custody.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent session, missing custody, an invalid
    /// proof bound, or missing/corrupt/oversized immutable proof bytes.
    pub fn read_ingress_proof(
        &self,
        session: &SessionId,
    ) -> Result<Vec<u8>, WorkerSessionStoreError> {
        let loaded = self.load_session(session)?;
        let candidate = match &loaded.record.candidate {
            WorkerCandidateCustodyStateV1::InCustody { candidate }
            | WorkerCandidateCustodyStateV1::BrokerCompleted { candidate, .. } => candidate,
            WorkerCandidateCustodyStateV1::Awaiting => {
                return Err(WorkerSessionStoreError::CandidateNotInCustody);
            }
        };
        let maximum_bytes = maximum_ingress_proof_bytes(loaded.record.spec.output_budget_bytes)?;
        self.store
            .read_blob(&candidate.ingress_proof, maximum_bytes)
            .map_err(WorkerSessionStoreError::from)
    }

    /// Permanently fences a prepared or active principal without candidate
    /// custody.
    ///
    /// An exact terminal retry is idempotent; changed terminal material refuses.
    ///
    /// # Errors
    ///
    /// Returns an error for absence, changed terminal material, clock overflow,
    /// invalid transition, or store failure.
    pub fn tombstone(
        &mut self,
        session: &SessionId,
        reason: WorkerTerminationReasonV1,
        terminal_since_unix_ms: u64,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let loaded = self.load_session(session)?;
        let principal = &loaded.record.spec.worker.principal;
        let tombstone = WorkerPrincipalTombstoneV1 {
            principal_id: principal.id(),
            session_id: session.clone(),
            session_nonce: principal.session_nonce,
            reason,
            terminal_since_unix_ms,
        };
        if let WorkerAuthorityStateV1::Tombstoned {
            tombstone: existing,
            ..
        } = &loaded.record.authority
        {
            return if *existing == tombstone {
                Ok(loaded)
            } else {
                Err(WorkerSessionStoreError::ChangedRetry)
            };
        }
        self.apply_event(
            loaded,
            &WorkerSessionEventV1::Tombstone { tombstone },
            "worker-session.tombstoned.v1",
            terminal_since_unix_ms,
        )
    }

    /// Completes process/provider cleanup behind an existing tombstone.
    ///
    /// # Errors
    ///
    /// Returns an error for absence, nonterminal state, changed retry, clock
    /// overflow, or store failure.
    pub fn complete_cleanup(
        &mut self,
        session: &SessionId,
        receipt: Digest,
        completed_at_unix_ms: u64,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let loaded = self.load_session(session)?;
        match &loaded.record.authority {
            WorkerAuthorityStateV1::Tombstoned {
                cleanup:
                    WorkerCleanupStateV1::Complete {
                        receipt: existing,
                        completed_at_unix_ms: existing_time,
                    },
                ..
            } if *existing == receipt && *existing_time == completed_at_unix_ms => {
                return Ok(loaded);
            }
            WorkerAuthorityStateV1::Tombstoned {
                cleanup: WorkerCleanupStateV1::Complete { .. },
                ..
            } => return Err(WorkerSessionStoreError::ChangedRetry),
            WorkerAuthorityStateV1::Tombstoned {
                cleanup: WorkerCleanupStateV1::Pending,
                ..
            } => {}
            _ => return Err(WorkerSessionStoreError::PrincipalNotTombstoned),
        }
        self.apply_event(
            loaded,
            &WorkerSessionEventV1::CompleteCleanup {
                receipt,
                completed_at_unix_ms,
            },
            "worker-session.cleanup-completed.v1",
            completed_at_unix_ms,
        )
    }

    /// Records one closed terminal broker outcome after candidate custody.
    ///
    /// An exact retry is idempotent. Once any terminal outcome is committed,
    /// a retry presenting different material refuses rather than rewriting
    /// history.
    ///
    /// # Errors
    ///
    /// Returns an error for absence, missing candidate custody, changed retry,
    /// clock overflow, or store failure.
    pub fn record_broker_outcome(
        &mut self,
        session: &SessionId,
        outcome: WorkerCandidateBrokerOutcomeV1,
        occurred_at_unix_ms: u64,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let loaded = self.load_session(session)?;
        match &loaded.record.candidate {
            WorkerCandidateCustodyStateV1::BrokerCompleted {
                outcome: existing, ..
            } if *existing == outcome => return Ok(loaded),
            WorkerCandidateCustodyStateV1::BrokerCompleted { .. } => {
                return Err(WorkerSessionStoreError::ChangedRetry);
            }
            WorkerCandidateCustodyStateV1::InCustody { .. } => {}
            WorkerCandidateCustodyStateV1::Awaiting => {
                return Err(WorkerSessionStoreError::CandidateNotInCustody);
            }
        }
        self.apply_event(
            loaded,
            &WorkerSessionEventV1::RecordBrokerOutcome { outcome },
            "worker-session.broker-outcome-recorded.v1",
            occurred_at_unix_ms,
        )
    }

    /// Tombstones every prepared/active session found during bounded startup
    /// recovery. Existing terminal records are inspected but never recreated.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt records, changed bindings, clock overflow,
    /// backup barrier, or store failure. Already-committed tombstones remain
    /// durable if a later page fails.
    pub fn recover_startup(
        &mut self,
        terminal_since_unix_ms: u64,
    ) -> Result<WorkerStartupRecoveryReportV1, WorkerSessionStoreError> {
        let mut report = WorkerStartupRecoveryReportV1::default();
        let mut cursor = None;
        loop {
            let entities = self.store.entity_ids_after(
                SESSION_ENTITY_PREFIX,
                cursor.as_deref(),
                RECOVERY_PAGE_SIZE,
            )?;
            if entities.is_empty() {
                return Ok(report);
            }
            cursor = entities.last().cloned();
            for entity in entities {
                let loaded = self.load_session_entity(&entity)?;
                match loaded.record.authority {
                    WorkerAuthorityStateV1::Prepared | WorkerAuthorityStateV1::Active { .. } => {
                        self.tombstone(
                            &loaded.record.spec.session,
                            WorkerTerminationReasonV1::RestartRecovery,
                            terminal_since_unix_ms,
                        )?;
                        report.tombstoned = report
                            .tombstoned
                            .checked_add(1)
                            .ok_or(WorkerSessionStoreError::RecoveryCountOverflow)?;
                    }
                    WorkerAuthorityStateV1::Tombstoned { .. } => {
                        report.already_terminal = report
                            .already_terminal
                            .checked_add(1)
                            .ok_or(WorkerSessionStoreError::RecoveryCountOverflow)?;
                    }
                }
            }
        }
    }

    fn apply_event(
        &mut self,
        loaded: LoadedWorkerSessionV1,
        event: &WorkerSessionEventV1,
        event_kind: &'static str,
        occurred_at_unix_ms: u64,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        let next = loaded.record.clone().apply(event.clone())?;
        self.store.append_event(
            NewEventV1 {
                event_id: event_id(event_kind, &(&loaded.record.spec.session, event))?,
                entity_id: loaded.entity_id,
                event_kind: event_kind.to_owned(),
                occurred_at_unix_ms: clock_i64(occurred_at_unix_ms)?,
                payload: event,
            },
            &next,
            loaded.revision,
        )?;
        self.load_session(&next.spec.session)
    }

    fn load_session_optional(
        &self,
        session: &SessionId,
    ) -> Result<Option<LoadedWorkerSessionV1>, WorkerSessionStoreError> {
        let entity = session_entity(session);
        let Some(loaded) = self
            .store
            .materialized_state::<WorkerSessionRecordV1>(&entity)?
        else {
            return Ok(None);
        };
        Self::validate_loaded_session(&entity, session, loaded).map(Some)
    }

    fn load_session_entity(
        &self,
        entity: &str,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        if !entity.starts_with(SESSION_ENTITY_PREFIX) {
            return Err(WorkerSessionStoreError::SessionEntityBindingMismatch);
        }
        let loaded = self
            .store
            .materialized_state::<WorkerSessionRecordV1>(entity)?
            .ok_or(WorkerSessionStoreError::SessionEntityBindingMismatch)?;
        let session = loaded.state.spec.session.clone();
        let loaded = Self::validate_loaded_session(entity, &session, loaded)?;
        let principal = loaded.record.spec.worker.principal.id();
        let index = self
            .load_index_optional(&principal)?
            .ok_or(WorkerSessionStoreError::IncompletePreparePair)?;
        Self::validate_index(&principal, &index.state, &loaded.record)?;
        Ok(loaded)
    }

    fn validate_loaded_session(
        entity: &str,
        expected_session: &SessionId,
        loaded: MaterializedStateV1<WorkerSessionRecordV1>,
    ) -> Result<LoadedWorkerSessionV1, WorkerSessionStoreError> {
        loaded.state.validate()?;
        if loaded.entity_id != entity
            || loaded.state.spec.session != *expected_session
            || entity != session_entity(expected_session)
        {
            return Err(WorkerSessionStoreError::SessionEntityBindingMismatch);
        }
        Ok(LoadedWorkerSessionV1 {
            entity_id: loaded.entity_id,
            revision: loaded.revision,
            state_digest: loaded.state_digest,
            record: loaded.state,
        })
    }

    fn load_index_optional(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<MaterializedStateV1<WorkerPrincipalIndexV1>>, WorkerSessionStoreError> {
        let entity = principal_entity(principal);
        let loaded = self
            .store
            .materialized_state::<WorkerPrincipalIndexV1>(&entity)?;
        if let Some(loaded) = &loaded
            && (loaded.entity_id != entity
                || loaded.state.schema != PRINCIPAL_INDEX_SCHEMA_V1
                || loaded.state.principal_id != *principal)
        {
            return Err(WorkerSessionStoreError::PrincipalIndexBindingMismatch);
        }
        Ok(loaded)
    }

    fn validate_index(
        expected_principal: &PrincipalId,
        index: &WorkerPrincipalIndexV1,
        record: &WorkerSessionRecordV1,
    ) -> Result<(), WorkerSessionStoreError> {
        let principal = &record.spec.worker.principal;
        if index.schema != PRINCIPAL_INDEX_SCHEMA_V1
            || index.principal_id != *expected_principal
            || principal.id() != *expected_principal
            || index.session_id != record.spec.session
            || index.session_nonce != principal.session_nonce
            || index.session_spec_digest != session_spec_digest(record)?
        {
            return Err(WorkerSessionStoreError::PrincipalIndexBindingMismatch);
        }
        Ok(())
    }
}

fn principal_index(
    record: &WorkerSessionRecordV1,
) -> Result<WorkerPrincipalIndexV1, WorkerSessionStoreError> {
    let principal = &record.spec.worker.principal;
    Ok(WorkerPrincipalIndexV1 {
        schema: PRINCIPAL_INDEX_SCHEMA_V1.to_owned(),
        principal_id: principal.id(),
        session_id: record.spec.session.clone(),
        session_nonce: principal.session_nonce,
        session_spec_digest: session_spec_digest(record)?,
    })
}

fn session_spec_digest(record: &WorkerSessionRecordV1) -> Result<Digest, WorkerSessionStoreError> {
    Digest::from_serializable(&record.spec).map_err(WorkerSessionStoreError::from)
}

fn session_entity(session: &SessionId) -> String {
    format!("{SESSION_ENTITY_PREFIX}{session}")
}

fn principal_entity(principal: &PrincipalId) -> String {
    format!("{PRINCIPAL_ENTITY_PREFIX}{principal}")
}

fn event_id<T: Serialize>(kind: &str, material: &T) -> Result<String, WorkerSessionStoreError> {
    let material = Digest::from_serializable(&(kind, material))?;
    Ok(format!("{kind}:{material}"))
}

fn clock_i64(value: u64) -> Result<i64, WorkerSessionStoreError> {
    i64::try_from(value).map_err(|_| WorkerSessionStoreError::ClockOutOfRange(value))
}

fn maximum_ingress_proof_bytes(output_budget_bytes: u64) -> Result<u64, WorkerSessionStoreError> {
    output_budget_bytes
        .div_ceil(3)
        .checked_mul(4)
        .and_then(|encoded| encoded.checked_add(INGRESS_PROOF_STRUCTURAL_RESERVE_BYTES))
        .ok_or(WorkerSessionStoreError::IngressProofBudgetOverflow)
}

/// Durable worker-session coordination failures.
#[derive(Debug, Error)]
pub enum WorkerSessionStoreError {
    /// Generic fenced-store failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Session model or ingress refusal.
    #[error(transparent)]
    Session(#[from] ag_session::SessionError),
    /// Canonical serialization failed.
    #[error(transparent)]
    Canonicalization(#[from] JcsError),
    /// Caller-provided clock evidence does not fit the durable signed range.
    #[error("worker-session time {0} exceeds durable signed milliseconds")]
    ClockOutOfRange(u64),
    /// Named session does not exist.
    #[error("worker session {0} does not exist")]
    SessionNotFound(SessionId),
    /// Authenticated principal has no immutable session index.
    #[error("worker principal {0} is unknown")]
    PrincipalNotFound(PrincipalId),
    /// Session entity name and durable body disagree.
    #[error("worker session entity binding is inconsistent")]
    SessionEntityBindingMismatch,
    /// Principal index name/body/spec binding disagrees.
    #[error("worker principal index binding is inconsistent")]
    PrincipalIndexBindingMismatch,
    /// Prepare found exactly one side of the required atomic pair.
    #[error("worker session prepare pair is incomplete")]
    IncompletePreparePair,
    /// Session/principal identity was reused with changed reviewed material.
    #[error("worker session prepare conflicts with durable reviewed material")]
    PrepareConflict,
    /// Prepare accepts only a pristine Prepared/Awaiting record.
    #[error("worker session prepare requires a pristine record")]
    PrepareRequiresPristineRecord,
    /// A semantic retry changed immutable event material.
    #[error("worker session retry changed previously committed material")]
    ChangedRetry,
    /// Terminal principal refuses activation or late ingress.
    #[error("worker principal is tombstoned")]
    PrincipalTombstoned,
    /// Cleanup completion requires a durable tombstone.
    #[error("worker principal is not tombstoned")]
    PrincipalNotTombstoned,
    /// Canonical proposal recording requires candidate custody.
    #[error("worker candidate is not in governor custody")]
    CandidateNotInCustody,
    /// Candidate length could not be represented durably.
    #[error("worker candidate length cannot be represented")]
    CandidateLengthOverflow,
    /// Authenticated ingress proof bytes are required for durable custody.
    #[error("worker candidate ingress proof is empty")]
    IngressProofEmpty,
    /// Ingress proof length could not be represented durably.
    #[error("worker candidate ingress proof length cannot be represented")]
    IngressProofLengthOverflow,
    /// Ingress proof bytes exceed the reviewed signed-frame bound.
    #[error("worker candidate ingress proof exceeds its signed-frame bound")]
    IngressProofBudgetExceeded,
    /// The reviewed signed-frame bound cannot be represented durably.
    #[error("worker candidate ingress proof bound cannot be represented")]
    IngressProofBudgetOverflow,
    /// Startup recovery counter overflowed.
    #[error("worker startup recovery count overflowed")]
    RecoveryCountOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_primitives::{
        AuthorityDomain, CgroupIdentity, Epoch, ExecutableIdentityV1, HostCredentialObservationV1,
        LaunchProfileIdentityV1, PrincipalChainNodeV1, PrincipalChainV1, PrincipalKindV1,
        ProjectId, WorkerProviderRouteV1, WorkerSessionPrincipalV1,
    };
    use ag_session::{
        AdmittedDescriptorV1, BatchSessionSpecV1, DescriptorAccessV1, DescriptorPurposeV1,
        IsolationEvidenceV1, SESSION_SCHEMA_V1, SecurityProfileV1, SourceSnapshotV1,
        WorkerBindingV1, WorkspaceModeV1,
    };
    use ag_store::{StoreActivationIdentityV1, StoreIdentityV1, WriterIdentityV1};
    use tempfile::TempDir;

    fn digest(label: &str) -> Digest {
        Digest::hash_bytes(label.as_bytes())
    }

    fn open_store(root: &TempDir, writer_label: &str) -> Store {
        Store::open_activated(
            root.path().join("agd.sqlite"),
            root.path().join("objects"),
            StoreIdentityV1::current(0x4147_1050, "agd-worker-test").unwrap(),
            &StoreActivationIdentityV1 {
                schema: StoreActivationIdentityV1::SCHEMA.to_owned(),
                authority_domain: AuthorityDomain::new("site:prod").unwrap(),
                epoch: Epoch::new(5).unwrap(),
                config_identity: digest("config"),
                security_profile_identity: digest("security-profile"),
                build_identity: digest("build"),
                authority_catalog_identity: None,
            },
            &WriterIdentityV1 {
                writer_id: format!("writer-{writer_label}"),
                principal_digest: digest("agd-writer"),
                process_nonce: format!("nonce-{writer_label}"),
                claimed_at_unix_ms: 1,
            },
        )
        .unwrap()
    }

    fn worker_record(session_name: &str) -> WorkerSessionRecordV1 {
        let authority_domain = AuthorityDomain::new("site:prod").unwrap();
        let epoch = Epoch::new(5).unwrap();
        let session = SessionId::new(session_name).unwrap();
        let launcher = PrincipalId::new(digest("agd-launcher"));
        let executable = ExecutableIdentityV1::new(digest("fixture-worker"), 4096, None);
        let workspace = digest(&format!("workspace-{session_name}"));
        let principal = WorkerSessionPrincipalV1 {
            authority_domain: authority_domain.clone(),
            epoch,
            project: ProjectId::new("project-alpha").unwrap(),
            session_id: session.clone(),
            session_nonce: LifecycleNonce::new(session_nonce_bytes(session_name)),
            launcher: launcher.clone(),
            executable: executable.clone(),
            launch_profile: LaunchProfileIdentityV1::new(
                digest("launch-profile"),
                digest("worker-protocol"),
            ),
            proposal_workspace_identity: workspace.clone(),
            security_profile_identity: SecurityProfileV1::Development.identity(),
            candidate_ingress_key_identity: digest("candidate-ingress-key-identity"),
            expires_at_unix_ms: 10_000,
            output_budget_bytes: 1024,
            provider_route: WorkerProviderRouteV1::Offline,
            input_set_digest: digest(&format!("input-{session_name}")),
            observed_credentials: HostCredentialObservationV1 {
                uid: 901,
                gid: 902,
                pid: 903,
                cgroup: CgroupIdentity::new(format!("{session_name}.scope")).unwrap(),
            },
        };
        let principal_chain = PrincipalChainV1::new(
            authority_domain.clone(),
            epoch,
            vec![
                PrincipalChainNodeV1::root(launcher.clone(), PrincipalKindV1::Daemon),
                PrincipalChainNodeV1::child(
                    principal.id(),
                    PrincipalKindV1::WorkerSession,
                    launcher,
                ),
            ],
        )
        .unwrap();
        WorkerSessionRecordV1::new(BatchSessionSpecV1 {
            schema: SESSION_SCHEMA_V1.to_owned(),
            session,
            authority_domain,
            epoch,
            security_profile: SecurityProfileV1::Development,
            reviewed_profile_id: "fixture-worker".to_owned(),
            candidate_ingress_key_identity: digest("candidate-ingress-key-identity"),
            worker: WorkerBindingV1 {
                principal,
                principal_chain,
                isolation: IsolationEvidenceV1 {
                    user_namespace: digest("user-ns"),
                    mount_namespace: digest("mount-ns"),
                    pid_namespace: digest("pid-ns"),
                    cgroup: digest("cgroup"),
                    seccomp_profile: digest("seccomp"),
                    landlock_ruleset: digest("landlock"),
                    network_namespace: digest("network-ns"),
                    observed_uid: 901,
                    observed_gid: 902,
                    observed_pid: 903,
                    observed_executable: executable,
                },
            },
            workspace_mode: WorkspaceModeV1::IndependentSnapshot,
            proposal_workspace_identity: workspace,
            source: SourceSnapshotV1 {
                content: digest("source"),
                format: "archive_v1".to_owned(),
                source_object: None,
            },
            admitted_descriptors: vec![
                AdmittedDescriptorV1 {
                    descriptor: 3,
                    purpose: DescriptorPurposeV1::SourceSnapshot,
                    access: DescriptorAccessV1::ReadOnly,
                    object_identity: digest("source-fd"),
                },
                AdmittedDescriptorV1 {
                    descriptor: 4,
                    purpose: DescriptorPurposeV1::ArtifactSink,
                    access: DescriptorAccessV1::WriteOnly,
                    object_identity: digest("artifact-fd"),
                },
            ],
            provider_capability: None,
            deadline_unix_ms: 10_000,
            output_budget_bytes: 1024,
        })
        .unwrap()
    }

    fn session_nonce_bytes(session_name: &str) -> [u8; 16] {
        let digest = Digest::hash_bytes(session_name.as_bytes());
        let hex = digest.as_str().strip_prefix("sha256:").unwrap();
        let bytes = hex.as_bytes();
        let mut nonce = [0_u8; 16];
        for (index, chunk) in bytes[..32].chunks_exact(2).enumerate() {
            nonce[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        nonce
    }

    fn ingress(record: &WorkerSessionRecordV1, now_unix_ms: u64) -> WorkerIngressContextV1 {
        let spec = &record.spec;
        let principal = &spec.worker.principal;
        WorkerIngressContextV1 {
            authority_domain: spec.authority_domain.clone(),
            epoch: spec.epoch,
            principal_id: principal.id(),
            session_id: spec.session.clone(),
            proposal_workspace_identity: principal.proposal_workspace_identity.clone(),
            security_profile_identity: principal.security_profile_identity.clone(),
            executable: principal.executable.clone(),
            observed_uid: principal.observed_credentials.uid,
            observed_gid: principal.observed_credentials.gid,
            now_unix_ms,
        }
    }

    #[test]
    fn prepare_commits_session_and_immutable_principal_index_atomically() {
        let root = TempDir::new().unwrap();
        let mut store = open_store(&root, "prepare");
        let record = worker_record("session-prepare");
        let principal = record.spec.worker.principal.id();
        let session = record.spec.session.clone();
        let mut sessions = WorkerSessionStoreV1::new(&mut store);

        let prepared = sessions.prepare(&record, 100).unwrap();
        assert_eq!(prepared.revision, 1);
        assert_eq!(sessions.load_session(&session).unwrap(), prepared);
        assert_eq!(sessions.load_by_principal(&principal).unwrap(), prepared);
        assert_eq!(sessions.prepare(&record, 100).unwrap(), prepared);

        let mut changed = record;
        changed.spec.source.content = digest("changed-source");
        assert!(matches!(
            sessions.prepare(&changed, 100),
            Err(WorkerSessionStoreError::PrepareConflict)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn candidate_and_tombstone_winner_schedules_leave_one_terminal_fact() {
        let root = TempDir::new().unwrap();
        let mut store = open_store(&root, "winner");
        let candidate_record = worker_record("session-candidate-wins");
        let candidate_session = candidate_record.spec.session.clone();
        let candidate_context = ingress(&candidate_record, 200);
        let tombstone_record = worker_record("session-tombstone-wins");
        let tombstone_session = tombstone_record.spec.session.clone();
        let tombstone_context = ingress(&tombstone_record, 200);
        let mut sessions = WorkerSessionStoreV1::new(&mut store);

        sessions.prepare(&candidate_record, 100).unwrap();
        sessions
            .activate(&candidate_session, digest("launch-a"), 110)
            .unwrap();
        let accepted = sessions
            .accept_candidate(
                &candidate_context,
                b"candidate bytes",
                b"signed candidate ingress proof",
                "artifact_v1",
                None,
            )
            .unwrap();
        assert!(matches!(
            accepted.record.candidate,
            WorkerCandidateCustodyStateV1::InCustody { .. }
        ));
        assert!(matches!(
            &accepted.record.authority,
            WorkerAuthorityStateV1::Tombstoned {
                launch_receipt: Some(receipt),
                ..
            } if *receipt == digest("launch-a")
        ));
        assert_eq!(
            sessions.read_ingress_proof(&candidate_session).unwrap(),
            b"signed candidate ingress proof"
        );
        assert!(matches!(
            sessions.accept_candidate(
                &candidate_context,
                b"late bytes",
                b"late ingress proof",
                "artifact_v1",
                None
            ),
            Err(WorkerSessionStoreError::Session(
                ag_session::SessionError::PrincipalTombstoned
            ))
        ));
        assert!(matches!(
            sessions.tombstone(
                &candidate_session,
                WorkerTerminationReasonV1::Cancelled {
                    reason_digest: digest("cancel")
                },
                201
            ),
            Err(WorkerSessionStoreError::ChangedRetry)
        ));
        let cleaned = sessions
            .complete_cleanup(&candidate_session, digest("cleanup"), 202)
            .unwrap();
        assert!(matches!(
            cleaned.record.authority,
            WorkerAuthorityStateV1::Tombstoned {
                cleanup: WorkerCleanupStateV1::Complete { .. },
                ..
            }
        ));
        let canonical_outcome = WorkerCandidateBrokerOutcomeV1::Canonicalized {
            canonical_proposal: digest("proposal"),
        };
        let canonical = sessions
            .record_broker_outcome(&candidate_session, canonical_outcome.clone(), 203)
            .unwrap();
        assert!(matches!(
            canonical.record.candidate,
            WorkerCandidateCustodyStateV1::BrokerCompleted {
                outcome: WorkerCandidateBrokerOutcomeV1::Canonicalized { .. },
                ..
            }
        ));
        assert_eq!(
            sessions
                .record_broker_outcome(&candidate_session, canonical_outcome, 204)
                .unwrap(),
            canonical
        );
        assert!(matches!(
            sessions.record_broker_outcome(
                &candidate_session,
                WorkerCandidateBrokerOutcomeV1::Canonicalized {
                    canonical_proposal: digest("changed-proposal"),
                },
                205,
            ),
            Err(WorkerSessionStoreError::ChangedRetry)
        ));

        sessions.prepare(&tombstone_record, 100).unwrap();
        sessions
            .activate(&tombstone_session, digest("launch-b"), 110)
            .unwrap();
        sessions
            .tombstone(
                &tombstone_session,
                WorkerTerminationReasonV1::Cancelled {
                    reason_digest: digest("cancel"),
                },
                190,
            )
            .unwrap();
        assert!(matches!(
            sessions.accept_candidate(
                &tombstone_context,
                b"late candidate",
                b"late ingress proof",
                "artifact_v1",
                None
            ),
            Err(WorkerSessionStoreError::Session(
                ag_session::SessionError::PrincipalTombstoned
            ))
        ));
        let terminal = sessions.load_session(&tombstone_session).unwrap();
        assert!(matches!(
            terminal.record.candidate,
            WorkerCandidateCustodyStateV1::Awaiting
        ));
        assert!(matches!(
            terminal.record.authority,
            WorkerAuthorityStateV1::Tombstoned {
                launch_receipt: Some(receipt),
                ..
            } if receipt == digest("launch-b")
        ));
    }

    #[test]
    fn terminal_broker_outcomes_are_durable_idempotent_and_conflict_closed() {
        let cases = [
            (
                "canonicalized",
                WorkerCandidateBrokerOutcomeV1::Canonicalized {
                    canonical_proposal: digest("canonical-proposal"),
                },
            ),
            (
                "refused",
                WorkerCandidateBrokerOutcomeV1::Refused {
                    refusal: digest("broker-refusal"),
                },
            ),
            (
                "indeterminate",
                WorkerCandidateBrokerOutcomeV1::Indeterminate {
                    envelope: digest("broker-indeterminate-envelope"),
                },
            ),
        ];

        for (label, outcome) in cases {
            let root = TempDir::new().unwrap();
            let session_name = format!("session-broker-{label}");
            let record = worker_record(&session_name);
            let session = record.spec.session.clone();
            let context = ingress(&record, 200);
            let committed;
            {
                let mut store = open_store(&root, &format!("{label}-first"));
                let mut sessions = WorkerSessionStoreV1::new(&mut store);
                sessions.prepare(&record, 100).unwrap();
                sessions.activate(&session, digest("launch"), 110).unwrap();
                sessions
                    .accept_candidate(
                        &context,
                        b"candidate bytes",
                        b"signed candidate ingress proof",
                        "artifact_v1",
                        None,
                    )
                    .unwrap();
                committed = sessions
                    .record_broker_outcome(&session, outcome.clone(), 210)
                    .unwrap();
                assert_eq!(
                    sessions
                        .record_broker_outcome(&session, outcome.clone(), 211)
                        .unwrap(),
                    committed
                );
                assert!(matches!(
                    sessions.record_broker_outcome(
                        &session,
                        WorkerCandidateBrokerOutcomeV1::Refused {
                            refusal: digest(&format!("changed-{label}")),
                        },
                        212,
                    ),
                    Err(WorkerSessionStoreError::ChangedRetry)
                ));
            }

            let mut reopened = open_store(&root, &format!("{label}-replay"));
            let mut sessions = WorkerSessionStoreV1::new(&mut reopened);
            let replayed = sessions.load_session(&session).unwrap();
            assert_eq!(replayed, committed);
            assert!(matches!(
                &replayed.record.candidate,
                WorkerCandidateCustodyStateV1::BrokerCompleted {
                    outcome: observed,
                    ..
                } if *observed == outcome
            ));
            assert_eq!(
                sessions
                    .record_broker_outcome(&session, outcome.clone(), 220)
                    .unwrap(),
                replayed
            );
            assert_eq!(
                sessions.read_ingress_proof(&session).unwrap(),
                b"signed candidate ingress proof"
            );
        }
    }

    #[test]
    fn ingress_proof_is_required_and_bounded_before_custody() {
        let root = TempDir::new().unwrap();
        let mut store = open_store(&root, "proof-bound");
        let record = worker_record("session-proof-bound");
        let session = record.spec.session.clone();
        let context = ingress(&record, 200);
        let maximum = maximum_ingress_proof_bytes(record.spec.output_budget_bytes).unwrap();
        let oversized = vec![0; usize::try_from(maximum + 1).unwrap()];
        let mut sessions = WorkerSessionStoreV1::new(&mut store);
        sessions.prepare(&record, 100).unwrap();
        sessions
            .activate(&session, digest("launch-proof-bound"), 110)
            .unwrap();

        assert!(matches!(
            sessions.accept_candidate(&context, b"candidate", b"", "artifact_v1", None),
            Err(WorkerSessionStoreError::IngressProofEmpty)
        ));
        assert!(matches!(
            sessions.accept_candidate(&context, b"candidate", &oversized, "artifact_v1", None,),
            Err(WorkerSessionStoreError::IngressProofBudgetExceeded)
        ));
        let unchanged = sessions.load_session(&session).unwrap();
        assert!(matches!(
            unchanged.record.authority,
            WorkerAuthorityStateV1::Active { .. }
        ));
        assert!(matches!(
            unchanged.record.candidate,
            WorkerCandidateCustodyStateV1::Awaiting
        ));
        assert!(matches!(
            maximum_ingress_proof_bytes(u64::MAX),
            Err(WorkerSessionStoreError::IngressProofBudgetOverflow)
        ));
    }

    #[test]
    fn startup_recovery_tombstones_prepared_and_active_without_recreation() {
        let root = TempDir::new().unwrap();
        let mut store = open_store(&root, "recovery");
        let prepared = worker_record("session-prepared");
        let prepared_session = prepared.spec.session.clone();
        let active = worker_record("session-active");
        let active_session = active.spec.session.clone();
        let already_terminal = worker_record("session-terminal");
        let terminal_session = already_terminal.spec.session.clone();
        let mut sessions = WorkerSessionStoreV1::new(&mut store);
        sessions.prepare(&prepared, 100).unwrap();
        sessions.prepare(&active, 100).unwrap();
        sessions
            .activate(&active_session, digest("launch"), 110)
            .unwrap();
        sessions.prepare(&already_terminal, 100).unwrap();
        sessions
            .tombstone(
                &terminal_session,
                WorkerTerminationReasonV1::WorkerFailed {
                    failure: digest("failure"),
                },
                120,
            )
            .unwrap();

        assert_eq!(
            sessions.recover_startup(200).unwrap(),
            WorkerStartupRecoveryReportV1 {
                tombstoned: 2,
                already_terminal: 1,
            }
        );
        let recovered_prepared = sessions.load_session(&prepared_session).unwrap();
        assert!(matches!(
            recovered_prepared.record.authority,
            WorkerAuthorityStateV1::Tombstoned {
                launch_receipt: None,
                tombstone: WorkerPrincipalTombstoneV1 {
                    reason: WorkerTerminationReasonV1::RestartRecovery,
                    ..
                },
                cleanup: WorkerCleanupStateV1::Pending,
            }
        ));
        let recovered_active = sessions.load_session(&active_session).unwrap();
        assert!(matches!(
            recovered_active.record.authority,
            WorkerAuthorityStateV1::Tombstoned {
                launch_receipt: Some(receipt),
                tombstone: WorkerPrincipalTombstoneV1 {
                    reason: WorkerTerminationReasonV1::RestartRecovery,
                    ..
                },
                cleanup: WorkerCleanupStateV1::Pending,
            } if receipt == digest("launch")
        ));
        assert_eq!(
            sessions.recover_startup(200).unwrap(),
            WorkerStartupRecoveryReportV1 {
                tombstoned: 0,
                already_terminal: 3,
            }
        );
    }

    #[test]
    fn orphan_blobs_after_simulated_crash_never_create_candidate_state() {
        let root = TempDir::new().unwrap();
        let session;
        let candidate_descriptor;
        let proof_descriptor;
        {
            let mut store = open_store(&root, "orphan-first");
            let record = worker_record("session-orphan");
            session = record.spec.session.clone();
            {
                let mut sessions = WorkerSessionStoreV1::new(&mut store);
                sessions.prepare(&record, 100).unwrap();
                sessions.activate(&session, digest("launch"), 110).unwrap();
            }

            let proof_bytes = b"fully installed but unreferenced proof";
            proof_descriptor = BlobDescriptorV1 {
                digest: Digest::hash_bytes(proof_bytes),
                byte_length: proof_bytes.len() as u64,
            };
            store
                .install_blob(&proof_descriptor, &mut Cursor::new(proof_bytes), 119)
                .unwrap();
            let candidate_bytes = b"fully installed but unreferenced candidate";
            candidate_descriptor = BlobDescriptorV1 {
                digest: Digest::hash_bytes(candidate_bytes),
                byte_length: candidate_bytes.len() as u64,
            };
            store
                .install_blob(
                    &candidate_descriptor,
                    &mut Cursor::new(candidate_bytes),
                    120,
                )
                .unwrap();
        }

        let mut reopened = open_store(&root, "orphan-second");
        let sessions = WorkerSessionStoreV1::new(&mut reopened);
        let loaded = sessions.load_session(&session).unwrap();
        assert!(matches!(
            loaded.record.candidate,
            WorkerCandidateCustodyStateV1::Awaiting
        ));
        assert!(matches!(
            sessions.read_ingress_proof(&session),
            Err(WorkerSessionStoreError::CandidateNotInCustody)
        ));
        assert_eq!(
            reopened.read_blob(&proof_descriptor.digest, 1024).unwrap(),
            b"fully installed but unreferenced proof"
        );
        assert_eq!(
            reopened
                .read_blob(&candidate_descriptor.digest, 1024)
                .unwrap(),
            b"fully installed but unreferenced candidate"
        );
    }

    #[test]
    fn load_rejects_corrupt_principal_index_binding() {
        let root = TempDir::new().unwrap();
        let mut store = open_store(&root, "corrupt-index");
        let record = worker_record("session-corrupt-index");
        let principal = record.spec.worker.principal.id();
        let mut index = principal_index(&record).unwrap();
        index.session_id = SessionId::new("wrong-session").unwrap();
        store
            .append_distinct_event_pair(
                NewEventV1 {
                    event_id: "corrupt-session-event".to_owned(),
                    entity_id: session_entity(&record.spec.session),
                    event_kind: "worker-session.prepared.v1".to_owned(),
                    occurred_at_unix_ms: 100,
                    payload: &record,
                },
                &record,
                0,
                NewEventV1 {
                    event_id: "corrupt-index-event".to_owned(),
                    entity_id: principal_entity(&principal),
                    event_kind: "worker-principal.indexed.v1".to_owned(),
                    occurred_at_unix_ms: 100,
                    payload: &index,
                },
                &index,
                0,
            )
            .unwrap();
        let sessions = WorkerSessionStoreV1::new(&mut store);
        assert!(matches!(
            sessions.load_session(&record.spec.session),
            Err(WorkerSessionStoreError::PrincipalIndexBindingMismatch)
        ));
        assert!(matches!(
            sessions.load_by_principal(&principal),
            Err(WorkerSessionStoreError::SessionNotFound(_)
                | WorkerSessionStoreError::PrincipalIndexBindingMismatch)
        ));
    }
}
