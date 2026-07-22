//! Single-writer effect-broker actor and durable proposal repository.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ag_effect::{
    CanonicalEffectV1, EFFECT_CATALOG_SCHEMA_V1, EFFECT_SCHEMA_V1, EffectCatalogV1,
    EffectCompilationCutV1, EffectCompilerV1, EffectError, EffectFamilyV1,
    MANAGED_POINTER_CANDIDATE_RATIFICATION_SCHEMA_V1, MANAGED_POINTER_PROMOTION_REFUSAL_SCHEMA_V1,
    ManagedPointerCandidateRatificationV1, ManagedPointerPromotionRefusalCodeV1,
    ManagedPointerPromotionRefusalV1, PreparedManagedPointerCandidateV1, ProposalEventV1,
    ProposalIntentV1, ProposalStateV1, RECONCILIATION_EVIDENCE_SCHEMA_V1,
    RECONCILIATION_RECORD_SCHEMA_V1, RatificationV1, ReconciliationClassificationV1,
    ReconciliationEvidenceV1, ReconciliationRecordV1, TargetDefinitionV1, TargetId,
    TargetObservationV1,
};
use ag_primitives::{
    AuthorityDomain, Digest, Epoch, PrincipalChainNodeV1, PrincipalChainV1, PrincipalKindV1,
};
use ag_session::WorkerCandidateCustodyV1;
use ag_store::{BlobDescriptorV1, NewEventV1, Store};
use base64::Engine as _;
use rustix::fs::{FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::{
    AgdRequestV1, ApiErrorCodeV1, ApiResultV1, ArtifactTransferV1, EFFECT_RECORD_SCHEMA_V3,
    EffectAdminRequestV1, EffectAdminResponseV1, EffectProposalRequestV1, EffectProposalResponseV1,
    EffectRecordV1, GovernedProposalIngressV1, HealthV1, ProposalSummaryV1,
    WorkerCandidateRequestV1, WorkerCandidateSourceProofV1, worker_candidate_ingress_proof_digest,
};
#[cfg(test)]
use crate::api::{ProposalIngressProofV1, WorkerCandidateIngressProofV1};
use crate::config::{EffectTargetConfigV1, EffectdConfigV1, PeerPolicyV1};
use crate::descriptor_path::open_beneath;
use crate::effectd_activation::{
    EFFECTD_ACTIVATION_STATUS_SCHEMA_V1, EffectdActivationReceiptV1, EffectdActivationStatusV1,
    EffectdLiveActivationV1,
};
use crate::managed_pointer::{
    ManagedPointerActivationHeadV1, ManagedPointerActivationReceiptV1,
    ManagedPointerCommitEvidenceV1, ManagedPointerCommitResultV1, ManagedPointerError,
    ManagedPointerPoststateEvidenceV1, ManagedPointerPreparationStandingContextV1,
    ManagedPointerRuntimeV1,
};
use crate::peer::signed_principal_chain;
use crate::rpc_auth::{
    RpcReplayGuardV1, VerifiedRpcPrincipalV1, candidate_ingress_key_identity,
    record_forwarded_signed_request_freshness, verify_forwarded_signed_request_bindings,
};

#[cfg(target_os = "linux")]
use ag_effect::executor::{
    ArtifactReadErrorV1, ArtifactSourceV1, BurnedExecutionPermitV1, CapabilityFailureV1,
    CapabilityOutcomeV1, EXECUTION_RECEIPT_SCHEMA_V1, EffectExecutorV1,
    ExecutionIndeterminateCodeV1, ExecutionIndeterminateV1, ExecutionOutcomeV1, ExecutionPhaseV1,
    ExecutionReceiptV1, ManagedFilePolicyV1, PinnedHelperIdentityV1, PinnedPointerHelperV1,
    PointerCasRequestV1, PointerCasSuccessV1, PointerPreparationRequestV1,
    PointerPreparationSuccessV1, SystemdDbusBackendV1, SystemdManagerReloadRequestV1,
    SystemdManagerReloadSuccessV1, SystemdUnitRequestV1, SystemdUnitSuccessV1,
};

/// The broker's durable materialized proposal state.
pub const BROKER_PROPOSAL_RECORD_SCHEMA_V3: &str = "ag.effect-broker-proposal/v3";

/// The broker's durable materialized proposal state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerProposalRecordV1 {
    /// Explicit record schema. Legacy records without v3 activation custody
    /// deserialize only to fail closed during broker validation.
    #[serde(default)]
    pub schema: String,
    /// Exact broker-owned proposal.
    pub canonical: ag_effect::CanonicalEffectProposalV1,
    /// Exact pre-ratification preparation history by managed-pointer target.
    #[serde(default)]
    pub prepared_candidates: BTreeMap<TargetId, PreparedManagedPointerCandidateV1>,
    /// Exact candidate-and-basis ratification persisted at authority burn.
    #[serde(default)]
    pub candidate_ratification: Option<ManagedPointerCandidateRatificationV1>,
    /// Typed pre-burn eligibility refusals. History cannot become standing.
    #[serde(default)]
    pub promotion_refusals: Vec<ManagedPointerPromotionRefusalV1>,
    /// Durable burn-before-effect lifecycle.
    pub state: ProposalStateV1,
    /// Exact accepted authority record, when burned.
    pub authorization: Option<RatificationV1>,
    /// Composite terminal execution receipt.
    pub terminal_receipt: Option<Digest>,
    /// Exact step receipts persisted before the next effect may begin.
    pub step_receipts: Vec<Digest>,
    /// Exact execution attempt retained through terminal/reconciliation states.
    pub execution_attempt: Option<Digest>,
    /// Full broker-owned reconciliation record, when completed.
    pub reconciliation: Option<ReconciliationRecordV1>,
    /// Full durable managed-pointer activation explanation, present only for
    /// a verified successful promotion. Persisted evidence is never standing.
    pub managed_pointer_activation: Option<ManagedPointerActivationReceiptV1>,
}

/// Durable unique submission record binding one authenticated intent to its
/// only broker outcome. The original proof is evidence, never bearer authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSubmissionRecordV1 {
    /// Stable unique source key, independent of connection nonces.
    pub source: Digest,
    /// Authenticated outer governor key.
    pub governor: VerifiedRpcPrincipalV1,
    /// Proposer chain reconstructed by effectd from the forwarded proof.
    pub proposer: PrincipalChainV1,
    /// Exact originally verified governed proposal source.
    pub ingress_proof: GovernedProposalIngressV1,
    /// Full broker-owned evaluation evidence. A digest-only response is never
    /// the sole custody for a refusal or operational failure.
    pub evaluation: BrokerEvaluationEvidenceV1,
    /// Durable outcome returned for every retry of this exact source.
    pub response: EffectProposalResponseV1,
}

struct BrokerPreparedIntentV1 {
    observations: BTreeMap<TargetId, TargetObservationV1>,
    prepared_candidates: BTreeMap<TargetId, PreparedManagedPointerCandidateV1>,
}

/// Exact broker-owned evidence behind one submission result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerEvaluationEvidenceV1 {
    /// Canonical bytes were compiled and persisted by effectd.
    Canonicalized {
        /// Broker proposal identifier.
        proposal_id: String,
        /// Exact broker-owned canonical proposal.
        proposal: Digest,
    },
    /// A typed semantic compiler refusal.
    Refused {
        /// Broker proposal identifier.
        proposal_id: String,
        /// Lossless closed refusal returned by the compiler.
        refusal: EffectError,
    },
    /// Evaluation failed operationally without making a semantic judgment.
    Indeterminate {
        /// Broker proposal identifier.
        proposal_id: String,
        /// Exact evaluation phase which could not complete.
        phase: BrokerEvaluationPhaseV1,
        /// Closed failure family.
        failure_code: BrokerEvaluationFailureCodeV1,
        /// Sanitized lossless diagnostic retained in broker custody.
        detail: String,
        /// Typed compiler failure when canonical compilation itself failed.
        compiler_error: Option<EffectError>,
    },
}

impl BrokerEvaluationEvidenceV1 {
    fn digest(&self) -> Result<Digest, BrokerError> {
        Ok(Digest::from_serializable(self)?)
    }

    fn matches_response(&self, response: &EffectProposalResponseV1) -> bool {
        match (self, response) {
            (
                Self::Canonicalized {
                    proposal_id,
                    proposal,
                },
                EffectProposalResponseV1::Canonicalized {
                    proposal_id: response_id,
                    proposal_digest,
                },
            ) => proposal_id == response_id && proposal == proposal_digest,
            (Self::Refused { .. }, EffectProposalResponseV1::Refused { refusal }) => {
                self.digest().is_ok_and(|digest| digest == *refusal)
            }
            (Self::Indeterminate { .. }, EffectProposalResponseV1::Indeterminate { envelope }) => {
                self.digest().is_ok_and(|digest| digest == *envelope)
            }
            _ => false,
        }
    }
}

/// Closed broker evaluation phase retained for operational routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerEvaluationPhaseV1 {
    /// Broker-owned target observation.
    TargetObservation,
    /// Canonical proposal compilation.
    CanonicalCompilation,
}

/// Closed operational evaluation failure family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerEvaluationFailureCodeV1 {
    /// A target observer returned a bounded semantic uncertainty.
    ObservationUnavailable,
    /// Local descriptor or filesystem observation failed.
    ObservationIo,
    /// Canonical compilation failed for a non-semantic reason.
    CompilationUnavailable,
}

/// Closed step result returned by an injected exact-effect implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerStepOutcomeV1 {
    /// Exact effect completed and was durably observed.
    Succeeded {
        /// Exact successful step receipt.
        receipt: Digest,
    },
    /// Exact effect failed with a known no-retry outcome.
    Failed {
        /// Exact known-failure step receipt.
        receipt: Digest,
    },
    /// Boundary outcome cannot safely be determined.
    Indeterminate {
        /// Exact reconciliation evidence envelope.
        envelope: Digest,
    },
}

/// Narrow adapter used by the actor; implementations cannot alter the plan.
pub trait BrokerEffectRunnerV1 {
    /// Executes exactly one canonical effect once under a durable attempt ID.
    fn execute_once(
        &mut self,
        store: &Store,
        proposal: &Digest,
        authorization: &Digest,
        attempt: &Digest,
        effect_index: u32,
        effect: &CanonicalEffectV1,
    ) -> ExecutionReceiptV1;
}

/// Fail-closed runner useful while a deployment has no installed backend.
#[derive(Default)]
pub struct RefusingEffectRunnerV1;

impl BrokerEffectRunnerV1 for RefusingEffectRunnerV1 {
    fn execute_once(
        &mut self,
        _store: &Store,
        proposal: &Digest,
        authorization: &Digest,
        attempt: &Digest,
        effect_index: u32,
        effect: &CanonicalEffectV1,
    ) -> ExecutionReceiptV1 {
        ExecutionReceiptV1 {
            schema: EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
            proposal: proposal.clone(),
            authorization: authorization.clone(),
            attempt: attempt.clone(),
            effect_index,
            effect: effect.clone(),
            outcome: ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                    phase: ExecutionPhaseV1::PrestateCheck,
                    detail: "exact effect backend is not installed".to_owned(),
                    source_code: Some("backend_unavailable".to_owned()),
                    evidence: None,
                },
            },
        }
    }
}

/// Linux runner providing the direct managed-file implementation. Pointer and
/// systemd families remain typed fail-closed capabilities until deployments
/// inject their pinned helper and D-Bus adapters.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxManagedEffectRunnerV1 {
    /// Direct file-executor policy.
    pub file_policy: ManagedFilePolicyV1,
}

#[cfg(target_os = "linux")]
impl BrokerEffectRunnerV1 for LinuxManagedEffectRunnerV1 {
    fn execute_once(
        &mut self,
        store: &Store,
        proposal: &Digest,
        authorization: &Digest,
        attempt: &Digest,
        effect_index: u32,
        effect: &CanonicalEffectV1,
    ) -> ExecutionReceiptV1 {
        let artifacts =
            StoreArtifactSourceV1::preload(store, effect, self.file_policy.max_content_bytes);
        let pointer = UnavailablePointerHelperV1;
        let systemd = UnavailableSystemdBackendV1;
        EffectExecutorV1::new(&artifacts, &pointer, &systemd, self.file_policy).execute_once(
            BurnedExecutionPermitV1::from_durable_burn(
                proposal.clone(),
                authorization.clone(),
                attempt.clone(),
                effect_index,
            ),
            effect,
        )
    }
}

#[cfg(target_os = "linux")]
struct StoreArtifactSourceV1 {
    loaded: Option<(Digest, Result<Vec<u8>, ArtifactReadErrorV1>)>,
}

#[cfg(target_os = "linux")]
impl StoreArtifactSourceV1 {
    fn preload(store: &Store, effect: &CanonicalEffectV1, maximum: u64) -> Self {
        let CanonicalEffectV1::ManagedFilePut { content, .. } = effect else {
            return Self { loaded: None };
        };
        let loaded = store
            .read_blob(content, maximum)
            .map_err(|error| ArtifactReadErrorV1::new("effectd_store_custody", error.to_string()));
        Self {
            loaded: Some((content.clone(), loaded)),
        }
    }
}

#[cfg(target_os = "linux")]
impl ArtifactSourceV1 for StoreArtifactSourceV1 {
    fn load(&self, digest: &Digest) -> Result<Vec<u8>, ArtifactReadErrorV1> {
        match &self.loaded {
            Some((expected, result)) if expected == digest => result.clone(),
            _ => Err(ArtifactReadErrorV1::new(
                "effectd_store_custody",
                "artifact was not preloaded for this exact effect",
            )),
        }
    }
}

#[cfg(target_os = "linux")]
struct UnavailablePointerHelperV1;

#[cfg(target_os = "linux")]
impl PinnedPointerHelperV1 for UnavailablePointerHelperV1 {
    fn identity(&self) -> CapabilityOutcomeV1<PinnedHelperIdentityV1> {
        CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
            code: "pinned_helper_unavailable".to_owned(),
            detail: "no deployment pointer helper adapter is installed".to_owned(),
            evidence: None,
        })
    }

    fn prepare(
        &self,
        _request: &PointerPreparationRequestV1,
        _artifact: &[u8],
    ) -> CapabilityOutcomeV1<PointerPreparationSuccessV1> {
        CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
            code: "pinned_helper_unavailable".to_owned(),
            detail: "no deployment pointer helper adapter is installed".to_owned(),
            evidence: None,
        })
    }

    fn compare_and_swap(
        &self,
        _request: &PointerCasRequestV1,
    ) -> CapabilityOutcomeV1<PointerCasSuccessV1> {
        CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
            code: "pinned_helper_unavailable".to_owned(),
            detail: "no deployment pointer helper adapter is installed".to_owned(),
            evidence: None,
        })
    }
}

#[cfg(target_os = "linux")]
struct UnavailableSystemdBackendV1;

#[cfg(target_os = "linux")]
impl SystemdDbusBackendV1 for UnavailableSystemdBackendV1 {
    fn unit_action(
        &self,
        _request: &SystemdUnitRequestV1,
    ) -> CapabilityOutcomeV1<SystemdUnitSuccessV1> {
        CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
            code: "systemd_dbus_backend_unavailable".to_owned(),
            detail: "no typed systemd D-Bus adapter is installed".to_owned(),
            evidence: None,
        })
    }

    fn reload_manager(
        &self,
        _request: &SystemdManagerReloadRequestV1,
    ) -> CapabilityOutcomeV1<SystemdManagerReloadSuccessV1> {
        CapabilityOutcomeV1::Failed(CapabilityFailureV1 {
            code: "systemd_dbus_backend_unavailable".to_owned(),
            detail: "no typed systemd D-Bus adapter is installed".to_owned(),
            evidence: None,
        })
    }
}

#[derive(Clone, Debug)]
struct ChallengeV1 {
    value: String,
    peer: Digest,
    expires_unix_ms: u64,
}

/// The one authoritative effect-store writer and state machine.
pub struct EffectBrokerV1<R> {
    store: Store,
    compiler: EffectCompilerV1,
    catalog_identity: Digest,
    security_profile_identity: Digest,
    targets: BTreeMap<TargetId, EffectTargetConfigV1>,
    authority_domain: AuthorityDomain,
    epoch: Epoch,
    agd_policy: PeerPolicyV1,
    proposer_policy: PeerPolicyV1,
    admin_policy: PeerPolicyV1,
    rpc_replay: Arc<RpcReplayGuardV1>,
    max_plan_steps: u32,
    max_ready_proposals: u32,
    max_artifact_bytes: u64,
    development_authority_bypass: bool,
    activation_ready: bool,
    activation_receipt: Option<EffectdActivationReceiptV1>,
    activation_status: EffectdActivationStatusV1,
    challenges: BTreeMap<String, ChallengeV1>,
    pointer_runtime: ManagedPointerRuntimeV1,
    runner: R,
}

impl<R: BrokerEffectRunnerV1> EffectBrokerV1<R> {
    /// Builds the actor after config/store validation and catalog pin checks.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid authority identifiers, catalog/helper
    /// drift, corrupt storage, or incomplete-attempt recovery failure.
    pub fn new(
        config: &EffectdConfigV1,
        activated_catalog_identity: &Digest,
        store: Store,
        runner: R,
        rpc_replay: Arc<RpcReplayGuardV1>,
    ) -> Result<Self, BrokerError> {
        let authority_domain = AuthorityDomain::parse(&config.authority_domain)?;
        let epoch = Epoch::parse(&config.epoch)?;
        let (catalog, targets) = build_catalog(&config.targets)?;
        let catalog_identity = catalog.identity.clone();
        if &catalog_identity != activated_catalog_identity {
            return Err(BrokerError::CatalogIdentityMismatch);
        }
        let pointer_runtime = ManagedPointerRuntimeV1::from_config(config)?;
        let profile_identity = security_profile_identity(&config.security_profile);
        if pointer_runtime.security_profile_identity() != &profile_identity {
            return Err(BrokerError::SecurityProfileIdentityMismatch);
        }
        let mut broker = Self {
            store,
            compiler: EffectCompilerV1::new(catalog, profile_identity.clone()),
            catalog_identity,
            security_profile_identity: profile_identity,
            targets,
            authority_domain,
            epoch,
            agd_policy: config.agd_peer.clone(),
            proposer_policy: config.proposer_peer.clone(),
            admin_policy: config.admin_peer.clone(),
            rpc_replay,
            max_plan_steps: config.limits.max_plan_steps,
            max_ready_proposals: config.limits.max_ready_proposals,
            max_artifact_bytes: config.limits.max_artifact_bytes,
            development_authority_bypass: config.security_profile == "development",
            // The effective service-unit sandbox and activation journal are
            // not yet attested by this build. Production authority must stay
            // disabled until that proof is installed.
            activation_ready: false,
            activation_receipt: None,
            activation_status: EffectdActivationStatusV1::NotReady {
                schema: EFFECTD_ACTIVATION_STATUS_SCHEMA_V1.to_owned(),
                phase: "startup".to_owned(),
                code: if config.security_profile == "development" {
                    "development_profile"
                } else {
                    "live_attestation_not_applied"
                }
                .to_owned(),
                detail: if config.security_profile == "development" {
                    "development authority bypass does not create production readiness"
                } else {
                    "fresh live activation evidence has not been applied"
                }
                .to_owned(),
            },
            challenges: BTreeMap::new(),
            pointer_runtime,
            runner,
        };
        broker.store.verify_chain()?;
        broker.validate_all_proposal_records()?;
        broker.recover_incomplete_attempts()?;
        Ok(broker)
    }

    /// Consume fresh, non-serializable startup evidence and enable the
    /// production authority gate for this process lifetime only.
    ///
    /// The serializable receipt remains process-memory diagnostic evidence.
    /// Restart reconstructs a new live value and never reloads this field as
    /// standing.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence differs from the exact store,
    /// config, catalog, profile, helper, repository, or staging context.
    pub fn apply_live_activation(
        &mut self,
        config: &EffectdConfigV1,
        activation: EffectdLiveActivationV1,
    ) -> Result<(), BrokerError> {
        activation
            .verify_for(config, &self.catalog_identity, &self.store)
            .map_err(|error| BrokerError::ActivationEvidence(error.to_string()))?;
        let target_readiness = self
            .pointer_runtime
            .production_readiness()
            .map_err(|error| BrokerError::ActivationEvidence(error.to_string()))?;
        if activation.receipt().target_readiness != target_readiness {
            return Err(BrokerError::ActivationEvidence(
                "managed-pointer target state changed during activation".to_owned(),
            ));
        }
        self.validate_current_managed_pointer_activations()?;
        let receipt = activation.into_receipt();
        self.activation_status = EffectdActivationStatusV1::Ready {
            schema: EFFECTD_ACTIVATION_STATUS_SCHEMA_V1.to_owned(),
            receipt: Box::new(receipt.clone()),
        };
        self.activation_receipt = Some(receipt);
        self.activation_ready = true;
        Ok(())
    }

    /// Retain a bounded, non-authorizing explanation when startup activation
    /// cannot be established. This never changes authority state to ready.
    pub fn record_activation_failure(&mut self, phase: &str, code: &str, detail: &str) {
        self.activation_ready = false;
        self.activation_receipt = None;
        self.activation_status = EffectdActivationStatusV1::NotReady {
            schema: EFFECTD_ACTIVATION_STATUS_SCHEMA_V1.to_owned(),
            phase: bounded_activation_text(phase),
            code: bounded_activation_text(code),
            detail: bounded_activation_text(detail),
        };
    }

    #[allow(clippy::too_many_lines)]
    fn reconstruct_managed_pointer_activation_heads(
        &self,
    ) -> Result<BTreeMap<TargetId, ManagedPointerActivationHeadV1>, BrokerError> {
        let mut history = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .store
                .entity_ids_after("proposal-", cursor.as_deref(), 512)?;
            if page.is_empty() {
                break;
            }
            cursor = page.last().cloned();
            for entity in page {
                let loaded = self.load_proposal_entity_with_revision(&entity)?;
                if matches!(
                    &loaded.state.canonical.body().effects[0],
                    CanonicalEffectV1::ManagedPointerPromotion { .. }
                ) {
                    history.push((loaded.last_event_sequence, loaded.state));
                }
            }
        }
        history.sort_by_key(|(sequence, _)| *sequence);
        let mut expected_current = self.pointer_runtime.activation_geneses();
        for (_, record) in history {
            let effect = &record.canonical.body().effects[0];
            let CanonicalEffectV1::ManagedPointerPromotion {
                target,
                expected_object,
                expected_tree,
                prestate_identity,
                new_object,
                expected_post_tree,
                ..
            } = effect
            else {
                return Err(BrokerError::Corrupt(
                    "managed-pointer history contains another effect family".to_owned(),
                ));
            };
            let current = expected_current.get_mut(target).ok_or_else(|| {
                BrokerError::Corrupt(
                    "managed-pointer history names a target without activation genesis".to_owned(),
                )
            })?;
            let requires_current_prestate = matches!(
                &record.state,
                ProposalStateV1::Succeeded { .. }
                    | ProposalStateV1::Reconciled { .. }
                    | ProposalStateV1::AuthorizationBurned { .. }
                    | ProposalStateV1::Preparing { .. }
                    | ProposalStateV1::Executing { .. }
                    | ProposalStateV1::ReconciliationRequired { .. }
            );
            if requires_current_prestate
                && (current.object != *expected_object
                    || current.tree != *expected_tree
                    || current.state_identity != *prestate_identity)
            {
                return Err(BrokerError::ActivationEvidence(
                    "managed-pointer activation history is not an exact predecessor chain"
                        .to_owned(),
                ));
            }
            match &record.state {
                ProposalStateV1::Succeeded { .. } => {
                    let activation =
                        record.managed_pointer_activation.as_ref().ok_or_else(|| {
                            BrokerError::Corrupt(
                                "successful managed-pointer history lacks activation custody"
                                    .to_owned(),
                            )
                        })?;
                    activation.verify(effect)?;
                    *current = ManagedPointerActivationHeadV1 {
                        object: new_object.clone(),
                        tree: expected_post_tree.clone(),
                        state_identity: activation.poststate.state.identity()?,
                    };
                }
                ProposalStateV1::ReconciliationRequired { .. }
                | ProposalStateV1::AuthorizationBurned { .. }
                | ProposalStateV1::Preparing { .. }
                | ProposalStateV1::Executing { .. } => {
                    return Err(BrokerError::ActivationEvidence(
                        "managed-pointer activation history contains an unresolved attempt"
                            .to_owned(),
                    ));
                }
                ProposalStateV1::Reconciled { .. } => {
                    let reconciliation = record.reconciliation.as_ref().ok_or_else(|| {
                        BrokerError::Corrupt("reconciled promotion lacks exact custody".to_owned())
                    })?;
                    let classification = reconciliation.evidence.classification;
                    match classification {
                        ReconciliationClassificationV1::Applied => {
                            return Err(BrokerError::ActivationEvidence(
                                "applied managed-pointer reconciliation lacks an exact durability-confirmation receipt"
                                    .to_owned(),
                            ));
                        }
                        ReconciliationClassificationV1::NotApplied => {
                            let observation = reconciliation
                                .evidence
                                .observed_poststate
                                .get(target)
                                .ok_or_else(|| {
                                    BrokerError::Corrupt(
                                        "managed-pointer reconciliation lacks its target observation"
                                            .to_owned(),
                                    )
                                })?;
                            let TargetObservationV1::ManagedPointer {
                                current_object,
                                current_tree,
                                prestate_identity,
                                ..
                            } = observation
                            else {
                                return Err(BrokerError::Corrupt(
                                    "managed-pointer reconciliation has foreign observation family"
                                        .to_owned(),
                                ));
                            };
                            if current_object != &current.object
                                || current_tree != &current.tree
                                || prestate_identity != &current.state_identity
                            {
                                return Err(BrokerError::ActivationEvidence(
                                    "not-applied reconciliation does not preserve the exact governed head"
                                        .to_owned(),
                                ));
                            }
                        }
                        ReconciliationClassificationV1::Foreign => {
                            return Err(BrokerError::ActivationEvidence(
                                "managed-pointer activation history ends in foreign state"
                                    .to_owned(),
                            ));
                        }
                    }
                }
                ProposalStateV1::Ready { .. }
                | ProposalStateV1::Failed { .. }
                | ProposalStateV1::Received
                | ProposalStateV1::Refused { .. }
                | ProposalStateV1::Indeterminate { .. } => {}
            }
        }
        Ok(expected_current)
    }

    fn validate_live_managed_pointer_heads(
        &self,
        expected: &BTreeMap<TargetId, ManagedPointerActivationHeadV1>,
    ) -> Result<(), BrokerError> {
        for (target, head) in expected {
            self.pointer_runtime
                .require_activation_state(target, head)
                .map_err(|error| BrokerError::ActivationEvidence(error.to_string()))?;
        }
        Ok(())
    }

    fn validate_current_managed_pointer_activations(
        &self,
    ) -> Result<BTreeMap<TargetId, ManagedPointerActivationHeadV1>, BrokerError> {
        let heads = self.reconstruct_managed_pointer_activation_heads()?;
        self.validate_live_managed_pointer_heads(&heads)?;
        Ok(heads)
    }

    /// Borrow the current-process activation receipt for startup logging and
    /// diagnostics. It is never accepted as authority input.
    #[must_use]
    pub fn activation_receipt(&self) -> Option<&EffectdActivationReceiptV1> {
        self.activation_receipt.as_ref()
    }

    /// Handles one authenticated governor-facing method.
    pub fn handle_proposal(
        &mut self,
        request: EffectProposalRequestV1,
        peer: &VerifiedRpcPrincipalV1,
    ) -> ApiResultV1<EffectProposalResponseV1> {
        match self.try_handle_proposal(request, peer) {
            Ok(response) => ApiResultV1::Ok { response },
            Err(error) => broker_api_error(&error),
        }
    }

    fn try_handle_proposal(
        &mut self,
        request: EffectProposalRequestV1,
        peer: &VerifiedRpcPrincipalV1,
    ) -> Result<EffectProposalResponseV1, BrokerError> {
        let governor_chain = signed_principal_chain(
            peer,
            &self.agd_policy,
            self.authority_domain.clone(),
            self.epoch,
        )?;
        match request {
            EffectProposalRequestV1::Health => Ok(EffectProposalResponseV1::Health {
                health: self.health()?,
            }),
            EffectProposalRequestV1::SubmitAuthenticatedIntent { ingress, artifacts } => {
                self.submit_authenticated_intent(&ingress, artifacts, peer, &governor_chain)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn submit_authenticated_intent(
        &mut self,
        ingress: &GovernedProposalIngressV1,
        artifacts: Vec<ArtifactTransferV1>,
        governor: &VerifiedRpcPrincipalV1,
        governor_chain: &PrincipalChainV1,
    ) -> Result<EffectProposalResponseV1, BrokerError> {
        if self.store.active_backup_cut()?.is_some() {
            return Err(BrokerError::Quiesced);
        }
        if matches!(ingress, GovernedProposalIngressV1::WorkerCandidate { .. })
            && !artifacts.is_empty()
        {
            return Err(BrokerError::ArtifactTransferMismatch);
        }
        let (intent, authenticated_proposer, source) =
            self.verify_governed_ingress_bindings(ingress, governor, governor_chain)?;
        if let Some(existing) = self
            .store
            .materialized_state::<BrokerSubmissionRecordV1>(&submission_entity(&source))?
        {
            if existing.state.source != source
                || existing.state.governor != *governor
                || existing.state.proposer != authenticated_proposer
                || !existing
                    .state
                    .evaluation
                    .matches_response(&existing.state.response)
            {
                return Err(BrokerError::Corrupt(
                    "submission index does not bind its authenticated source".to_owned(),
                ));
            }
            if let EffectProposalResponseV1::Canonicalized {
                proposal_id,
                proposal_digest,
            } = &existing.state.response
            {
                let proposal = self.load_proposal(proposal_digest)?;
                if proposal.canonical.body().proposal_id != *proposal_id {
                    return Err(BrokerError::Corrupt(
                        "submission index references another canonical proposal".to_owned(),
                    ));
                }
            }
            // Re-presenting the exact proof which created this durable record
            // is a result lookup, not a new authority use. This path is what
            // lets agd recover after effectd committed but its signed response
            // was lost. A worker session is one-shot, so any changed proof or
            // candidate under that principal refuses. The static external
            // path preserves its existing fresh-proof behavior.
            if existing.state.ingress_proof != *ingress {
                if matches!(ingress, GovernedProposalIngressV1::WorkerCandidate { .. }) {
                    return Err(BrokerError::WorkerSourceProofMismatch);
                }
                self.record_governed_ingress_freshness(ingress)?;
            }
            return Ok(existing.state.response);
        }
        self.record_governed_ingress_freshness(ingress)?;
        if intent.authority_domain != self.authority_domain
            || intent.epoch != self.epoch
            || intent.proposer.authority_domain() != &self.authority_domain
            || intent.proposer.epoch() != self.epoch
        {
            return Err(BrokerError::AuthorityContextMismatch);
        }
        if intent.effects.len() != 1 || self.max_plan_steps != 1 {
            return Err(BrokerError::PlanTooLarge);
        }
        if self.ready_proposal_count()? >= self.max_ready_proposals as usize {
            return Err(BrokerError::ReadyLimit);
        }
        self.install_governed_artifacts(&intent, ingress, artifacts)?;

        let proposal_id = stable_proposal_id(&source);
        let governor_authentication = source.clone();
        let preparation = match self.prepare_intent(&intent) {
            Ok(preparation) => preparation,
            Err(error) => {
                let failure_code = match &error {
                    BrokerError::Io(_) => BrokerEvaluationFailureCodeV1::ObservationIo,
                    _ => BrokerEvaluationFailureCodeV1::ObservationUnavailable,
                };
                let evaluation = BrokerEvaluationEvidenceV1::Indeterminate {
                    proposal_id: proposal_id.clone(),
                    phase: BrokerEvaluationPhaseV1::TargetObservation,
                    failure_code,
                    detail: error.to_string(),
                    compiler_error: None,
                };
                let envelope = evaluation.digest()?;
                let response = EffectProposalResponseV1::Indeterminate { envelope };
                self.persist_submission(
                    &BrokerSubmissionRecordV1 {
                        source,
                        governor: governor.clone(),
                        proposer: authenticated_proposer,
                        ingress_proof: ingress.clone(),
                        evaluation,
                        response: response.clone(),
                    },
                    "effect-evaluation.indeterminate.v1",
                )?;
                return Ok(response);
            }
        };
        let canonical = match self.compiler.compile(
            proposal_id.clone(),
            &intent,
            &authenticated_proposer,
            governor_authentication,
            EffectCompilationCutV1 {
                compiled_at_unix_ms: now_u64()?,
                observations: &preparation.observations,
                prepared_candidates: &preparation.prepared_candidates,
            },
        ) {
            Ok(canonical) => canonical,
            Err(error) => {
                let semantic_refusal = error.is_semantic_compilation_refusal();
                let evaluation = if semantic_refusal {
                    BrokerEvaluationEvidenceV1::Refused {
                        proposal_id: proposal_id.clone(),
                        refusal: error,
                    }
                } else {
                    BrokerEvaluationEvidenceV1::Indeterminate {
                        proposal_id: proposal_id.clone(),
                        phase: BrokerEvaluationPhaseV1::CanonicalCompilation,
                        failure_code: BrokerEvaluationFailureCodeV1::CompilationUnavailable,
                        detail: error.to_string(),
                        compiler_error: Some(error),
                    }
                };
                let evidence = evaluation.digest()?;
                let response = if semantic_refusal {
                    EffectProposalResponseV1::Refused { refusal: evidence }
                } else {
                    EffectProposalResponseV1::Indeterminate { envelope: evidence }
                };
                self.persist_submission(
                    &BrokerSubmissionRecordV1 {
                        source,
                        governor: governor.clone(),
                        proposer: authenticated_proposer,
                        ingress_proof: ingress.clone(),
                        evaluation,
                        response: response.clone(),
                    },
                    compiler_evaluation_event_kind(semantic_refusal),
                )?;
                return Ok(response);
            }
        };
        self.persist_canonical_submission(
            &source,
            governor.clone(),
            authenticated_proposer,
            ingress.clone(),
            &canonical,
            preparation.prepared_candidates,
        )
    }

    fn verify_governed_ingress_bindings(
        &self,
        ingress: &GovernedProposalIngressV1,
        governor: &VerifiedRpcPrincipalV1,
        governor_chain: &PrincipalChainV1,
    ) -> Result<(ProposalIntentV1, PrincipalChainV1, Digest), BrokerError> {
        match ingress {
            GovernedProposalIngressV1::ExternalSigned { proof } => {
                let governor_enrollment = self.agd_policy.rpc_enrollment()?;
                let proposer_enrollment = self.proposer_policy.rpc_enrollment()?;
                let verified_proposer = verify_forwarded_signed_request_bindings(
                    &proof.server_challenge,
                    &proof.signed_request,
                    &governor_enrollment,
                    &proposer_enrollment,
                )?;
                let authenticated_proposer = signed_principal_chain(
                    &verified_proposer,
                    &self.proposer_policy,
                    self.authority_domain.clone(),
                    self.epoch,
                )?;
                let AgdRequestV1::SubmitProposal { intent } = &proof.signed_request.request.body
                else {
                    return Err(BrokerError::ProposerProofMismatch);
                };
                if intent.proposer != authenticated_proposer {
                    return Err(BrokerError::ProposerProofMismatch);
                }
                let intent_digest = Digest::from_serializable(intent.as_ref())?;
                let source = Digest::from_serializable(&(
                    "ag.effect.authenticated-submission-key/v1",
                    &self.authority_domain,
                    self.epoch,
                    governor,
                    governor_chain,
                    &verified_proposer,
                    &authenticated_proposer,
                    &intent_digest,
                ))?;
                Ok((intent.as_ref().clone(), authenticated_proposer, source))
            }
            GovernedProposalIngressV1::WorkerCandidate { intent, source } => self
                .verify_worker_candidate_bindings(
                    intent.as_ref(),
                    source,
                    governor,
                    governor_chain,
                ),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn verify_worker_candidate_bindings(
        &self,
        intent: &ProposalIntentV1,
        source: &WorkerCandidateSourceProofV1,
        governor: &VerifiedRpcPrincipalV1,
        governor_chain: &PrincipalChainV1,
    ) -> Result<(ProposalIntentV1, PrincipalChainV1, Digest), BrokerError> {
        let proof = &source.ingress_proof;
        let worker_id = source.worker.id();
        if proof.governor_enrollment != self.agd_policy.rpc_key
            || proof.worker_enrollment.principal != *worker_id.digest()
            || source.worker.candidate_ingress_key_identity
                != candidate_ingress_key_identity(&proof.worker_enrollment)?
        {
            return Err(BrokerError::WorkerSourceProofMismatch);
        }
        let worker_enrollment = crate::rpc_auth::RpcPeerEnrollmentV1::new(
            worker_id.digest().clone(),
            proof.worker_enrollment.clone(),
        )?;
        let governor_enrollment = crate::rpc_auth::RpcPeerEnrollmentV1::new(
            proof.governor_enrollment.principal.clone(),
            proof.governor_enrollment.clone(),
        )?;
        let verified_worker = verify_forwarded_signed_request_bindings(
            &proof.server_challenge,
            &proof.signed_request,
            &governor_enrollment,
            &worker_enrollment,
        )?;
        if verified_worker.principal != *worker_id.digest() {
            return Err(BrokerError::WorkerSourceProofMismatch);
        }

        let governor_nodes = governor_chain.nodes();
        let worker_nodes = source.worker_chain.nodes();
        let Some(worker_leaf) = worker_nodes.last() else {
            return Err(BrokerError::WorkerSourceProofMismatch);
        };
        if source.worker_chain.authority_domain() != &self.authority_domain
            || source.worker_chain.epoch() != self.epoch
            || worker_nodes.len() != governor_nodes.len().saturating_add(1)
            || worker_nodes.get(..governor_nodes.len()) != Some(governor_nodes)
            || worker_leaf
                != &PrincipalChainNodeV1::child(
                    worker_id.clone(),
                    PrincipalKindV1::WorkerSession,
                    governor_chain.leaf().principal_id.clone(),
                )
            || source.worker.launcher != governor_chain.leaf().principal_id
        {
            return Err(BrokerError::WorkerSourceProofMismatch);
        }

        if source.worker.authority_domain != self.authority_domain
            || source.worker.epoch != self.epoch
            || source.worker.proposal_workspace_identity != source.workspace_identity
            || source.worker.output_budget_bytes == 0
            || source.accepted_at_unix_ms >= source.worker.expires_at_unix_ms
            || intent.proposer != source.worker_chain
        {
            return Err(BrokerError::WorkerSourceBindingMismatch);
        }

        let WorkerCandidateRequestV1::Submit {
            candidate_nonce,
            semantic_type,
            content,
        } = &proof.signed_request.request.body;
        let byte_length =
            u64::try_from(content.len()).map_err(|_| BrokerError::WorkerCandidateMismatch)?;
        let content_digest = Digest::hash_bytes(content.as_slice());
        let ingress_proof = worker_candidate_ingress_proof_digest(proof)?;
        let custody = WorkerCandidateCustodyV1::new(
            content_digest.clone(),
            byte_length,
            semantic_type.clone(),
            None,
            ingress_proof,
        )?;
        if *candidate_nonce != source.worker.session_nonce
            || byte_length > source.worker.output_budget_bytes
            || custody.custody_record != source.candidate_custody
            || intent.admitted_artifacts != BTreeSet::from([content_digest])
        {
            return Err(BrokerError::WorkerCandidateMismatch);
        }

        let source_digest = Digest::from_serializable(&(
            "ag.effect.worker-session-one-shot-submission-key/v1",
            &self.authority_domain,
            self.epoch,
            governor,
            governor_chain,
            &verified_worker,
            &source.worker,
            &source.worker_chain,
        ))?;
        Ok((intent.clone(), source.worker_chain.clone(), source_digest))
    }

    fn record_governed_ingress_freshness(
        &self,
        ingress: &GovernedProposalIngressV1,
    ) -> Result<(), BrokerError> {
        let governor_enrollment = self.agd_policy.rpc_enrollment()?;
        match ingress {
            GovernedProposalIngressV1::ExternalSigned { proof } => {
                let proposer_enrollment = self.proposer_policy.rpc_enrollment()?;
                record_forwarded_signed_request_freshness(
                    &proof.server_challenge,
                    &proof.signed_request,
                    &governor_enrollment,
                    &proposer_enrollment,
                    &self.rpc_replay,
                    now_u64()?,
                )?;
            }
            GovernedProposalIngressV1::WorkerCandidate { source, .. } => {
                let proof = &source.ingress_proof;
                if proof.governor_enrollment != self.agd_policy.rpc_key {
                    return Err(BrokerError::WorkerSourceProofMismatch);
                }
                let governor_enrollment = crate::rpc_auth::RpcPeerEnrollmentV1::new(
                    proof.governor_enrollment.principal.clone(),
                    proof.governor_enrollment.clone(),
                )?;
                let worker_enrollment = crate::rpc_auth::RpcPeerEnrollmentV1::new(
                    source.worker.id().digest().clone(),
                    proof.worker_enrollment.clone(),
                )?;
                record_forwarded_signed_request_freshness(
                    &proof.server_challenge,
                    &proof.signed_request,
                    &governor_enrollment,
                    &worker_enrollment,
                    &self.rpc_replay,
                    source.accepted_at_unix_ms,
                )?;
            }
        }
        Ok(())
    }

    /// Handles one direct authenticated inspection/admin method.
    pub fn handle_admin(
        &mut self,
        request: EffectAdminRequestV1,
        peer: &VerifiedRpcPrincipalV1,
        signed_request: &Digest,
    ) -> ApiResultV1<EffectAdminResponseV1> {
        match self.try_handle_admin(request, peer, signed_request) {
            Ok(response) => ApiResultV1::Ok { response },
            Err(error) => broker_api_error(&error),
        }
    }

    fn try_handle_admin(
        &mut self,
        request: EffectAdminRequestV1,
        peer: &VerifiedRpcPrincipalV1,
        signed_request: &Digest,
    ) -> Result<EffectAdminResponseV1, BrokerError> {
        match request {
            EffectAdminRequestV1::Health => {
                let activation = self.current_activation_status();
                Ok(EffectAdminResponseV1::Health {
                    health: self.health_for_activation(&activation)?,
                    activation,
                })
            }
            EffectAdminRequestV1::InspectProposal { proposal } => {
                let record = self.load_proposal(&proposal)?;
                record.canonical.verify_digest()?;
                let peer_digest = peer.binding_digest()?;
                let challenge = uuid::Uuid::new_v4().to_string();
                self.challenges.insert(
                    proposal.as_str().to_owned(),
                    ChallengeV1 {
                        value: challenge.clone(),
                        peer: peer_digest,
                        expires_unix_ms: now_u64()?.saturating_add(5 * 60 * 1000),
                    },
                );
                Ok(EffectAdminResponseV1::Proposal {
                    proposal: Box::new(record.canonical),
                    challenge,
                })
            }
            EffectAdminRequestV1::InspectRecord { proposal } => {
                let record = self.load_proposal(&proposal)?;
                Ok(EffectAdminResponseV1::Record {
                    record: Box::new(effect_record_projection(record)),
                })
            }
            EffectAdminRequestV1::ListProposals { limit } => {
                let limit = limit.clamp(1, 1_000);
                let mut proposals = Vec::new();
                for entity in self.store.entity_ids("proposal-", limit)? {
                    let record = self.load_proposal_entity_with_revision(&entity)?.state;
                    proposals.push(ProposalSummaryV1 {
                        proposal_id: record.canonical.body().proposal_id.clone(),
                        proposal_digest: record.canonical.digest().clone(),
                        state: proposal_state_name(&record.state).to_owned(),
                    });
                }
                Ok(EffectAdminResponseV1::Proposals { proposals })
            }
            EffectAdminRequestV1::Ratify {
                proposal,
                challenge,
            } => self.ratify_human(&proposal, challenge, peer, signed_request),
            EffectAdminRequestV1::DraftReconciliation { proposal } => {
                self.draft_reconciliation(&proposal)
            }
            EffectAdminRequestV1::Reconcile { evidence } => {
                self.reconcile(*evidence, peer, signed_request)
            }
        }
    }

    fn draft_reconciliation(
        &self,
        proposal: &Digest,
    ) -> Result<EffectAdminResponseV1, BrokerError> {
        let record = self.load_proposal(proposal)?;
        let ProposalStateV1::ReconciliationRequired { envelope } = &record.state else {
            return Err(BrokerError::ReconciliationNotRequired);
        };
        let attempt = record.execution_attempt.clone().ok_or_else(|| {
            BrokerError::Corrupt(
                "reconciliation-required record is missing its execution attempt".to_owned(),
            )
        })?;
        let observed_poststate = self.observe_canonical(&record.canonical)?;
        let effect = record
            .canonical
            .body()
            .effects
            .first()
            .ok_or_else(|| BrokerError::Corrupt("canonical effect is missing".to_owned()))?;
        let observation = observed_poststate.get(effect.target()).ok_or_else(|| {
            BrokerError::Corrupt("canonical target observation is missing".to_owned())
        })?;
        let classification = classify_reconciliation(effect, observation)?;
        Ok(EffectAdminResponseV1::ReconciliationDraft {
            evidence: Box::new(ReconciliationEvidenceV1 {
                schema: RECONCILIATION_EVIDENCE_SCHEMA_V1.to_owned(),
                proposal: proposal.clone(),
                attempt,
                uncertainty_envelope: envelope.clone(),
                step_receipts: record.step_receipts,
                observed_poststate,
                classification,
            }),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn ratify_human(
        &mut self,
        proposal: &Digest,
        challenge: String,
        peer: &VerifiedRpcPrincipalV1,
        signed_request: &Digest,
    ) -> Result<EffectAdminResponseV1, BrokerError> {
        if self.store.active_backup_cut()?.is_some() {
            return Err(BrokerError::Quiesced);
        }
        let governed_heads = self.require_authority_activation()?;
        let expected = self
            .challenges
            .remove(proposal.as_str())
            .ok_or(BrokerError::ChallengeInvalid)?;
        if expected.value != challenge
            || expected.peer != peer.binding_digest()?
            || now_u64()? > expected.expires_unix_ms
        {
            return Err(BrokerError::ChallengeInvalid);
        }
        let loaded = self.load_proposal_with_revision(proposal)?;
        loaded.state.canonical.verify_digest()?;
        let effect = loaded.state.canonical.body().effects[0].clone();
        if let CanonicalEffectV1::ManagedPointerPromotion {
            expires_unix_ms, ..
        } = &effect
            && now_u64()? >= *expires_unix_ms
        {
            return Err(BrokerError::PromotionExpired);
        }
        let ratifier = signed_principal_chain(
            peer,
            &self.admin_policy,
            self.authority_domain.clone(),
            self.epoch,
        )?;
        if !loaded
            .state
            .canonical
            .body()
            .proposer
            .independent_from(&ratifier)
        {
            return Err(BrokerError::PrincipalChainsNotIndependent);
        }
        let authorization = RatificationV1::HumanExact {
            proposal: proposal.to_owned(),
            ratifier,
            challenge,
            signed_request: signed_request.clone(),
        };
        let authorization_digest = Digest::from_serializable(&authorization)?;
        let state = loaded
            .state
            .state
            .clone()
            .apply(ProposalEventV1::BurnAuthorization {
                proposal: proposal.to_owned(),
                authorization: authorization_digest.clone(),
                family: effect.family(),
            })?;
        let attempt = Digest::from_serializable(&(
            "ag.effect.execution-attempt/v1",
            &proposal,
            uuid::Uuid::new_v4().to_string(),
        ))?;
        let context = crate::managed_pointer::ManagedPointerExecutionContextV1 {
            proposal: proposal.clone(),
            authorization: authorization_digest.clone(),
            attempt: attempt.clone(),
            effect_index: 0,
        };
        let (candidate_ratification, promotion_standing) =
            if let CanonicalEffectV1::ManagedPointerPromotion { target, .. } = &effect {
                let candidate = loaded
                    .state
                    .prepared_candidates
                    .get(target)
                    .ok_or_else(|| {
                        BrokerError::Corrupt(
                            "managed-pointer proposal is missing prepared-candidate custody"
                                .to_owned(),
                        )
                    })?;
                let binding = ManagedPointerCandidateRatificationV1 {
                    schema: MANAGED_POINTER_CANDIDATE_RATIFICATION_SCHEMA_V1.to_owned(),
                    proposal: proposal.clone(),
                    candidate: candidate.identity()?,
                    exact_basis: candidate.exact_basis.identity()?,
                    complete_inputs: candidate
                        .complete_inputs
                        .identity(candidate.exact_basis.object_format)?,
                    preparation_receipt: candidate.preparation_receipt.identity()?,
                    authorization: authorization_digest.clone(),
                };
                binding.verify_bindings(proposal, candidate, &authorization_digest)?;
                let standing_observed_at = now_u64()?;
                let governed_head = governed_heads.get(target).ok_or_else(|| {
                    BrokerError::Corrupt(
                        "managed-pointer proposal target lacks a governed activation head"
                            .to_owned(),
                    )
                })?;
                if candidate.exact_basis.current_object != governed_head.object
                    || candidate.exact_basis.current_tree != governed_head.tree
                    || candidate.exact_basis.prestate_identity != governed_head.state_identity
                {
                    return self.record_promotion_refusal(
                        loaded,
                        authorization,
                        binding,
                        standing_observed_at,
                        &ManagedPointerError::PrestateDrift(
                            "candidate basis is not the exact governed activation head".to_owned(),
                        ),
                    );
                }
                let standing = match self.pointer_runtime.promotion_standing(
                    &context,
                    &effect,
                    candidate,
                    &binding,
                    standing_observed_at,
                ) {
                    Ok(standing) => standing,
                    Err(error) => {
                        return self.record_promotion_refusal(
                            loaded,
                            authorization,
                            binding,
                            standing_observed_at,
                            &error,
                        );
                    }
                };
                (Some(binding), Some(standing))
            } else {
                (None, None)
            };
        let mut record = BrokerProposalRecordV1 {
            state,
            authorization: Some(authorization),
            candidate_ratification,
            ..loaded.state
        };
        let mut revision = self.persist_record(
            &record,
            loaded.revision,
            "effect-authorization.burned.v1",
            &authorization_digest,
        )?;
        record.execution_attempt = Some(attempt.clone());
        if effect.family() == EffectFamilyV1::CodePromotion {
            let promotion_standing = promotion_standing.ok_or_else(|| {
                BrokerError::Corrupt(
                    "promotion authority burn lacks live single-use standing".to_owned(),
                )
            })?;
            record.state = record.state.apply(ProposalEventV1::BeginPreparation {
                attempt: attempt.clone(),
            })?;
            revision = self.persist_record(
                &record,
                revision,
                "effect-promotion.preparation-began.v1",
                &attempt,
            )?;
            let prepared = match self.pointer_runtime.prepare_from_store(
                promotion_standing,
                &self.store,
                &context,
                &effect,
                self.max_artifact_bytes,
                now_u64()?,
            ) {
                Ok(prepared) => prepared,
                Err(receipt) => {
                    let receipt = enforce_receipt_bindings(
                        receipt,
                        proposal,
                        &authorization_digest,
                        &attempt,
                        0,
                        &effect,
                    );
                    return self.finish_preparation_failure(record, revision, receipt);
                }
            };
            let checkpoint = prepared.checkpoint.clone();
            record.state = record.state.apply(ProposalEventV1::CommitMayProceed {
                checkpoint: checkpoint.clone(),
            })?;
            revision = self.persist_record(
                &record,
                revision,
                "effect-promotion.commit-armed.v1",
                &prepared.evidence,
            )?;
            let ManagedPointerCommitResultV1 {
                receipt,
                commit_evidence,
                poststate_evidence,
                activation_receipt,
            } = self.pointer_runtime.commit(prepared, now_u64()?);
            let mut receipt = enforce_receipt_bindings(
                receipt,
                proposal,
                &authorization_digest,
                &attempt,
                0,
                &effect,
            );
            enforce_managed_pointer_evidence_bindings(
                &mut receipt,
                commit_evidence.as_ref(),
                poststate_evidence.as_ref(),
                activation_receipt.as_ref(),
            );
            return self.finish_execution(
                record,
                revision,
                &receipt,
                commit_evidence.as_ref(),
                poststate_evidence.as_ref(),
                activation_receipt.as_ref(),
            );
        }

        record.state = record.state.apply(ProposalEventV1::BeginExecution {
            attempt: attempt.clone(),
        })?;
        revision = self.persist_record(&record, revision, "effect-execution.began.v1", &attempt)?;
        let receipt = self.runner.execute_once(
            &self.store,
            proposal,
            &authorization_digest,
            &attempt,
            0,
            &effect,
        );
        let receipt = enforce_receipt_bindings(
            receipt,
            proposal,
            &authorization_digest,
            &attempt,
            0,
            &effect,
        );
        self.finish_execution(record, revision, &receipt, None, None, None)
    }

    fn record_promotion_refusal(
        &mut self,
        loaded: ag_store::MaterializedStateV1<BrokerProposalRecordV1>,
        attempted_authorization: RatificationV1,
        candidate_ratification: ManagedPointerCandidateRatificationV1,
        observed_at_unix_ms: u64,
        error: &ManagedPointerError,
    ) -> Result<EffectAdminResponseV1, BrokerError> {
        let code = match error {
            ManagedPointerError::PrestateDrift(_)
            | ManagedPointerError::ProtectedProjectionChanged => {
                ManagedPointerPromotionRefusalCodeV1::CurrentBasisMismatch
            }
            ManagedPointerError::BindingMismatch
            | ManagedPointerError::PromotionStandingMismatch
            | ManagedPointerError::TargetUnavailable
            | ManagedPointerError::GitIdentityMismatch
            | ManagedPointerError::LaunchProfileMismatch => {
                ManagedPointerPromotionRefusalCodeV1::CandidateBindingMismatch
            }
            _ => ManagedPointerPromotionRefusalCodeV1::StandingUnavailable,
        };
        let detail: String = error
            .to_string()
            .chars()
            .map(|character| {
                if character.is_ascii() && !character.is_ascii_control() {
                    character
                } else {
                    '?'
                }
            })
            .take(512)
            .collect();
        let refusal = ManagedPointerPromotionRefusalV1 {
            schema: MANAGED_POINTER_PROMOTION_REFUSAL_SCHEMA_V1.to_owned(),
            proposal: candidate_ratification.proposal.clone(),
            candidate: candidate_ratification.candidate.clone(),
            exact_basis: candidate_ratification.exact_basis.clone(),
            candidate_ratification,
            attempted_authorization,
            observed_at_unix_ms,
            code,
            detail,
        };
        let receipt = refusal.identity()?;
        let mut record = loaded.state;
        if record.promotion_refusals.len() < 32 {
            record.promotion_refusals.push(refusal.clone());
        }
        self.persist_record(
            &record,
            loaded.revision,
            "effect-promotion.eligibility-refused.v1",
            &refusal,
        )?;
        Err(BrokerError::PromotionEligibilityRefused(receipt))
    }

    fn finish_preparation_failure(
        &mut self,
        mut record: BrokerProposalRecordV1,
        revision: u64,
        mut execution_receipt: ExecutionReceiptV1,
    ) -> Result<EffectAdminResponseV1, BrokerError> {
        if matches!(
            execution_receipt.outcome,
            ExecutionOutcomeV1::Succeeded { .. }
        ) {
            execution_receipt.outcome = ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::BackendContractViolation,
                    phase: ExecutionPhaseV1::ReceiptValidation,
                    detail: "promotion preparation returned success as a terminal failure"
                        .to_owned(),
                    source_code: Some("preparation_contract_violation".to_owned()),
                    evidence: None,
                },
            };
        }
        let step_digest = execution_receipt
            .digest()
            .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
        record.step_receipts.push(step_digest);
        let attempt = record.execution_attempt.as_ref().ok_or_else(|| {
            BrokerError::Corrupt("preparation failure is missing its attempt".to_owned())
        })?;
        let (terminal, event) = match &execution_receipt.outcome {
            ExecutionOutcomeV1::Failed { .. } => {
                let terminal = composite_execution_receipt(
                    record.canonical.digest(),
                    attempt,
                    &record.step_receipts,
                    CompositeTerminalV1::Failed,
                )?;
                (
                    terminal.clone(),
                    ProposalEventV1::PreparationFailed { receipt: terminal },
                )
            }
            ExecutionOutcomeV1::Indeterminate { .. } => {
                let terminal = composite_execution_receipt(
                    record.canonical.digest(),
                    attempt,
                    &record.step_receipts,
                    CompositeTerminalV1::Indeterminate,
                )?;
                (
                    terminal.clone(),
                    ProposalEventV1::PreparationIndeterminate { envelope: terminal },
                )
            }
            ExecutionOutcomeV1::Succeeded { .. } => unreachable!("normalized above"),
        };
        record.state = record.state.apply(event)?;
        record.terminal_receipt = Some(terminal.clone());
        self.persist_record(
            &record,
            revision,
            "effect-promotion.preparation-terminal.v1",
            &execution_receipt,
        )?;
        Ok(EffectAdminResponseV1::ExecutionReceipt {
            receipt: terminal,
            terminal_state: proposal_state_name(&record.state).to_owned(),
        })
    }

    fn finish_execution(
        &mut self,
        mut record: BrokerProposalRecordV1,
        mut revision: u64,
        execution_receipt: &ExecutionReceiptV1,
        pointer_commit_evidence: Option<&ManagedPointerCommitEvidenceV1>,
        pointer_poststate_evidence: Option<&ManagedPointerPoststateEvidenceV1>,
        pointer_activation: Option<&ManagedPointerActivationReceiptV1>,
    ) -> Result<EffectAdminResponseV1, BrokerError> {
        let step_digest = execution_receipt
            .digest()
            .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
        let terminal_kind = match &execution_receipt.outcome {
            ExecutionOutcomeV1::Succeeded { .. } => CompositeTerminalV1::Succeeded,
            ExecutionOutcomeV1::Failed { .. } => CompositeTerminalV1::Failed,
            ExecutionOutcomeV1::Indeterminate { .. } => CompositeTerminalV1::Indeterminate,
        };
        record.step_receipts.push(step_digest);
        revision = if pointer_commit_evidence.is_some()
            || pointer_poststate_evidence.is_some()
            || pointer_activation.is_some()
        {
            #[derive(Serialize)]
            struct PointerStepEventV1<'a> {
                schema: &'static str,
                receipt: &'a ExecutionReceiptV1,
                commit_evidence: Option<&'a ManagedPointerCommitEvidenceV1>,
                poststate_evidence: Option<&'a ManagedPointerPoststateEvidenceV1>,
                activation: Option<&'a ManagedPointerActivationReceiptV1>,
            }
            self.persist_record(
                &record,
                revision,
                "effect-promotion.step-terminal.v1",
                &PointerStepEventV1 {
                    schema: "ag.effect.managed-pointer-step-event/v1",
                    receipt: execution_receipt,
                    commit_evidence: pointer_commit_evidence,
                    poststate_evidence: pointer_poststate_evidence,
                    activation: pointer_activation,
                },
            )?
        } else {
            self.persist_record(
                &record,
                revision,
                "effect-execution.step-terminal.v1",
                execution_receipt,
            )?
        };
        let attempt = record.execution_attempt.as_ref().ok_or_else(|| {
            BrokerError::Corrupt("terminal execution is missing its attempt".to_owned())
        })?;
        let terminal = composite_execution_receipt(
            record.canonical.digest(),
            attempt,
            &record.step_receipts,
            terminal_kind,
        )?;
        let event = match terminal_kind {
            CompositeTerminalV1::Succeeded => ProposalEventV1::ExecutionSucceeded {
                receipt: terminal.clone(),
            },
            CompositeTerminalV1::Failed => ProposalEventV1::ExecutionFailed {
                receipt: terminal.clone(),
            },
            CompositeTerminalV1::Indeterminate => ProposalEventV1::ExecutionIndeterminate {
                envelope: terminal.clone(),
            },
        };
        record.state = record.state.apply(event)?;
        record.terminal_receipt = Some(terminal.clone());
        record.managed_pointer_activation = pointer_activation.cloned();
        self.persist_record(
            &record,
            revision,
            "effect-execution.terminal.v1",
            execution_receipt,
        )?;
        Ok(EffectAdminResponseV1::ExecutionReceipt {
            receipt: terminal,
            terminal_state: proposal_state_name(&record.state).to_owned(),
        })
    }

    fn reconcile(
        &mut self,
        evidence: ReconciliationEvidenceV1,
        peer: &VerifiedRpcPrincipalV1,
        signed_request: &Digest,
    ) -> Result<EffectAdminResponseV1, BrokerError> {
        if self.store.active_backup_cut()?.is_some() {
            return Err(BrokerError::Quiesced);
        }
        let loaded = self.load_proposal_with_revision(&evidence.proposal)?;
        loaded.state.canonical.verify_digest()?;
        let ProposalStateV1::ReconciliationRequired { envelope } = &loaded.state.state else {
            return Err(BrokerError::ReconciliationEvidenceMismatch);
        };
        if evidence.schema != RECONCILIATION_EVIDENCE_SCHEMA_V1
            || evidence.uncertainty_envelope != *envelope
            || loaded.state.execution_attempt.as_ref() != Some(&evidence.attempt)
            || loaded.state.step_receipts != evidence.step_receipts
        {
            return Err(BrokerError::ReconciliationEvidenceMismatch);
        }
        let observed = self.observe_canonical(&loaded.state.canonical)?;
        if evidence.observed_poststate != observed {
            return Err(BrokerError::ReconciliationEvidenceMismatch);
        }
        let effect = loaded
            .state
            .canonical
            .body()
            .effects
            .first()
            .ok_or(BrokerError::ReconciliationEvidenceMismatch)?;
        let observation = observed
            .get(effect.target())
            .ok_or(BrokerError::ReconciliationEvidenceMismatch)?;
        if classify_reconciliation(effect, observation)? != evidence.classification {
            return Err(BrokerError::ReconciliationEvidenceMismatch);
        }
        let ratifier = signed_principal_chain(
            peer,
            &self.admin_policy,
            self.authority_domain.clone(),
            self.epoch,
        )?;
        if !loaded
            .state
            .canonical
            .body()
            .proposer
            .independent_from(&ratifier)
        {
            return Err(BrokerError::PrincipalChainsNotIndependent);
        }
        let reconciliation = ReconciliationRecordV1 {
            schema: RECONCILIATION_RECORD_SCHEMA_V1.to_owned(),
            evidence,
            ratifier,
            signed_request: signed_request.clone(),
        };
        let receipt = reconciliation.digest()?;
        let state = loaded
            .state
            .state
            .clone()
            .apply(ProposalEventV1::Reconciled {
                receipt: receipt.clone(),
            })?;
        let record = BrokerProposalRecordV1 {
            state,
            terminal_receipt: Some(receipt.clone()),
            reconciliation: Some(reconciliation.clone()),
            ..loaded.state
        };
        self.persist_record(
            &record,
            loaded.revision,
            "effect-proposal.reconciled.v1",
            &reconciliation,
        )?;
        Ok(EffectAdminResponseV1::Reconciled { receipt })
    }

    fn prepare_intent(
        &self,
        intent: &ag_effect::ProposalIntentV1,
    ) -> Result<BrokerPreparedIntentV1, BrokerError> {
        let mut observations = BTreeMap::new();
        let mut prepared_candidates = BTreeMap::new();
        for effect in &intent.effects {
            let target = effect.target();
            if observations.contains_key(target) {
                continue;
            }
            let configured = self
                .targets
                .get(target)
                .ok_or_else(|| BrokerError::Observation("target not catalogued".to_owned()))?;
            let observation = match configured {
                EffectTargetConfigV1::ManagedFile { path, .. } => {
                    observe_file(path, self.max_artifact_bytes)?
                }
                EffectTargetConfigV1::ManagedPointer { .. } => {
                    let ag_effect::EffectIntentV1::ManagedPointerPromotion { artifact, .. } =
                        effect
                    else {
                        return Err(BrokerError::Observation(
                            "managed-pointer catalog entry received another effect family"
                                .to_owned(),
                        ));
                    };
                    let now_unix_ms = now_u64()?;
                    let standing = self.pointer_runtime.preparation_standing(
                        target,
                        ManagedPointerPreparationStandingContextV1 {
                            authority_domain: self.authority_domain.clone(),
                            epoch: self.epoch,
                            catalog_identity: self.catalog_identity.clone(),
                            security_profile_identity: self.security_profile_identity.clone(),
                            max_artifact_bytes: self.max_artifact_bytes,
                            now_unix_ms,
                        },
                    )?;
                    let prepared = self.pointer_runtime.prepare_candidate_from_store(
                        Some(standing),
                        &self.store,
                        artifact,
                        now_unix_ms,
                    )?;
                    if prepared_candidates
                        .insert(target.clone(), prepared.candidate)
                        .is_some()
                    {
                        return Err(BrokerError::Observation(
                            "managed-pointer preparation repeated a target".to_owned(),
                        ));
                    }
                    prepared.observation
                }
                EffectTargetConfigV1::SystemdUnit { .. }
                | EffectTargetConfigV1::SystemdManager { .. } => {
                    return Err(BrokerError::Observation(
                        "typed systemd D-Bus observer is not installed".to_owned(),
                    ));
                }
            };
            observations.insert(target.clone(), observation);
        }
        Ok(BrokerPreparedIntentV1 {
            observations,
            prepared_candidates,
        })
    }

    fn observe_canonical(
        &self,
        proposal: &ag_effect::CanonicalEffectProposalV1,
    ) -> Result<BTreeMap<TargetId, TargetObservationV1>, BrokerError> {
        proposal
            .verify_digest()
            .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
        self.validate_catalog_admission(proposal)?;
        let mut observations = BTreeMap::new();
        for effect in &proposal.body().effects {
            let target = effect.target();
            let observation = self.observe_canonical_effect(effect)?;
            if observations.insert(target.clone(), observation).is_some() {
                return Err(BrokerError::Corrupt(
                    "canonical proposal contains a repeated reconciliation target".to_owned(),
                ));
            }
        }
        Ok(observations)
    }

    fn observe_canonical_effect(
        &self,
        effect: &CanonicalEffectV1,
    ) -> Result<TargetObservationV1, BrokerError> {
        match effect {
            CanonicalEffectV1::ManagedFilePut { path, .. }
            | CanonicalEffectV1::ManagedFileDelete { path, .. } => {
                // The effect-plane truth is the exact path ratified in the
                // canonical bytes. The live catalog is only an admission
                // check and can never redirect this observation.
                observe_file(Path::new(path), self.max_artifact_bytes)
            }
            CanonicalEffectV1::ManagedPointerPromotion { .. } => {
                Ok(self.pointer_runtime.observe_canonical(effect)?)
            }
            CanonicalEffectV1::SystemdUnit { .. }
            | CanonicalEffectV1::SystemdManagerReload { .. } => Err(BrokerError::Observation(
                "reconciliation observer is unavailable for this target family".to_owned(),
            )),
        }
    }

    // Admission deliberately compares the complete typed effect against the
    // active catalog in one place so no binding can be skipped by dispatch.
    #[allow(clippy::too_many_lines)]
    fn validate_catalog_admission(
        &self,
        proposal: &ag_effect::CanonicalEffectProposalV1,
    ) -> Result<(), BrokerError> {
        if proposal.body().catalog_schema != EFFECT_CATALOG_SCHEMA_V1
            || proposal.body().catalog_identity != self.catalog_identity
            || proposal.body().security_profile_identity != self.security_profile_identity
        {
            return Err(BrokerError::Observation(
                "canonical proposal catalog or security-profile identity is not active".to_owned(),
            ));
        }
        for effect in &proposal.body().effects {
            let configured = self.targets.get(effect.target()).ok_or_else(|| {
                BrokerError::Observation("canonical target is not catalogued".to_owned())
            })?;
            let admitted = match (effect, configured) {
                (
                    CanonicalEffectV1::ManagedPointerPromotion {
                        allowed_root,
                        repository,
                        reference,
                        repository_identity,
                        uid,
                        gid,
                        staging_root,
                        expires_unix_ms,
                        helper_executable,
                        helper_launch_profile,
                        ..
                    },
                    EffectTargetConfigV1::ManagedPointer {
                        allowed_root: configured_allowed_root,
                        repository: configured_repository,
                        reference: configured_reference,
                        repository_identity: configured_repository_identity,
                        uid: target_user_id,
                        gid: target_group_id,
                        staging_root: configured_staging_root,
                        promotion_ttl_ms,
                        helper_executable: configured_helper_executable,
                        helper_launch_profile: configured_helper_launch_profile,
                        ..
                    },
                ) => {
                    let configured_expiry = proposal
                        .body()
                        .compiled_at_unix_ms
                        .checked_add(*promotion_ttl_ms);
                    allowed_root == &utf8_path(configured_allowed_root)?
                        && repository
                            == &repository_relative_path(
                                configured_allowed_root,
                                configured_repository,
                            )?
                        && reference == configured_reference
                        && repository_identity == configured_repository_identity
                        && uid == target_user_id
                        && gid == target_group_id
                        && staging_root == &utf8_path(configured_staging_root)?
                        && configured_expiry.as_ref() == Some(expires_unix_ms)
                        && helper_executable == configured_helper_executable
                        && helper_launch_profile == configured_helper_launch_profile
                }
                (
                    CanonicalEffectV1::ManagedFilePut {
                        path,
                        mode,
                        uid,
                        gid,
                        ..
                    },
                    EffectTargetConfigV1::ManagedFile {
                        path: configured_path,
                        mode: configured_mode,
                        uid: configured_owner,
                        gid: configured_group,
                        ..
                    },
                ) => {
                    path == &utf8_path(configured_path)?
                        && mode == configured_mode
                        && uid == configured_owner
                        && gid == configured_group
                }
                (
                    CanonicalEffectV1::ManagedFileDelete { path, .. },
                    EffectTargetConfigV1::ManagedFile {
                        path: configured_path,
                        ..
                    },
                ) => path == &utf8_path(configured_path)?,
                (
                    CanonicalEffectV1::SystemdUnit { unit, action, .. },
                    EffectTargetConfigV1::SystemdUnit {
                        unit: configured_unit,
                        allowed_actions,
                        ..
                    },
                ) => unit == configured_unit && allowed_actions.contains(action),
                (
                    CanonicalEffectV1::SystemdManagerReload { .. },
                    EffectTargetConfigV1::SystemdManager { .. },
                ) => true,
                _ => false,
            };
            if !admitted {
                return Err(BrokerError::Observation(
                    "canonical effect is not admitted by the active catalog".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn install_governed_artifacts(
        &mut self,
        intent: &ag_effect::ProposalIntentV1,
        ingress: &GovernedProposalIngressV1,
        artifacts: Vec<ArtifactTransferV1>,
    ) -> Result<(), BrokerError> {
        if let GovernedProposalIngressV1::WorkerCandidate { source, .. } = ingress {
            if !artifacts.is_empty() {
                return Err(BrokerError::ArtifactTransferMismatch);
            }
            let WorkerCandidateRequestV1::Submit { content, .. } =
                &source.ingress_proof.signed_request.request.body;
            let byte_length =
                u64::try_from(content.len()).map_err(|_| BrokerError::ArtifactTransferMismatch)?;
            let digest = Digest::hash_bytes(content.as_slice());
            if byte_length > self.max_artifact_bytes
                || intent.admitted_artifacts != BTreeSet::from([digest.clone()])
            {
                return Err(BrokerError::ArtifactTransferMismatch);
            }
            self.store.install_blob(
                &BlobDescriptorV1 {
                    digest,
                    byte_length,
                },
                &mut content.as_slice(),
                now_i64()?,
            )?;
            return Ok(());
        }

        let mut observed = BTreeSet::new();
        for transfer in artifacts {
            if !observed.insert(transfer.digest.clone())
                || transfer.byte_length > self.max_artifact_bytes
            {
                return Err(BrokerError::ArtifactTransferMismatch);
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&transfer.content_base64)
                .map_err(|_| BrokerError::ArtifactTransferMismatch)?;
            if base64::engine::general_purpose::STANDARD.encode(&bytes) != transfer.content_base64
                || bytes.len() as u64 != transfer.byte_length
                || Digest::hash_bytes(&bytes) != transfer.digest
            {
                return Err(BrokerError::ArtifactTransferMismatch);
            }
            self.store.install_blob(
                &BlobDescriptorV1 {
                    digest: transfer.digest,
                    byte_length: transfer.byte_length,
                },
                &mut bytes.as_slice(),
                now_i64()?,
            )?;
        }
        if observed != intent.admitted_artifacts {
            return Err(BrokerError::ArtifactTransferMismatch);
        }
        Ok(())
    }

    fn health(&self) -> Result<HealthV1, BrokerError> {
        let activation = self.current_activation_status();
        self.health_for_activation(&activation)
    }

    fn health_for_activation(
        &self,
        activation: &EffectdActivationStatusV1,
    ) -> Result<HealthV1, BrokerError> {
        Ok(HealthV1 {
            schema: "ag.health/v1".to_owned(),
            service: "ag-effectd".to_owned(),
            build: env!("CARGO_PKG_VERSION").to_owned(),
            // Production readiness exists only after this process consumed
            // fresh, non-serializable activation evidence. Development keeps
            // its explicit authority bypass but does not manufacture a
            // production-readiness claim.
            ready: matches!(activation, EffectdActivationStatusV1::Ready { .. }),
            quiesced: self.store.active_backup_cut()?.is_some(),
        })
    }

    fn current_activation_status(&self) -> EffectdActivationStatusV1 {
        if !self.activation_ready {
            return self.activation_status.clone();
        }
        match self.require_authority_activation() {
            Ok(_) => self.activation_status.clone(),
            Err(error) => EffectdActivationStatusV1::NotReady {
                schema: EFFECTD_ACTIVATION_STATUS_SCHEMA_V1.to_owned(),
                phase: "runtime_revalidation".to_owned(),
                code: "activation_evidence_mismatch".to_owned(),
                detail: bounded_activation_text(&error.to_string()),
            },
        }
    }

    fn require_authority_activation(
        &self,
    ) -> Result<BTreeMap<TargetId, ManagedPointerActivationHeadV1>, BrokerError> {
        if self.activation_ready || self.development_authority_bypass {
            if self.activation_ready {
                let receipt = self.activation_receipt.as_ref().ok_or_else(|| {
                    BrokerError::ActivationEvidence(
                        "live activation flag lacks its process receipt".to_owned(),
                    )
                })?;
                let static_readiness = self
                    .pointer_runtime
                    .production_readiness()
                    .map_err(|error| BrokerError::ActivationEvidence(error.to_string()))?;
                if static_readiness != receipt.target_readiness {
                    return Err(BrokerError::ActivationEvidence(
                        "static helper, staging, or repository custody changed after activation"
                            .to_owned(),
                    ));
                }
            }
            // A process-lifetime host token cannot launder a later unresolved
            // or externally divergent target transition. Rebuild the exact
            // genesis-to-terminal chain and compare every live managed pointer
            // with it immediately before any authority family can spend
            // standing. The selected target's proposal-specific typed checks
            // remain an additional boundary rather than a substitute for this
            // shared activation gate.
            self.validate_current_managed_pointer_activations()
        } else {
            Err(BrokerError::ActivationNotReady)
        }
    }

    fn ready_proposal_count(&self) -> Result<usize, BrokerError> {
        let mut count = 0_usize;
        let observed_at = now_u64()?;
        let mut cursor = None;
        loop {
            let page = self
                .store
                .entity_ids_after("proposal-", cursor.as_deref(), 512)?;
            if page.is_empty() {
                return Ok(count);
            }
            cursor = page.last().cloned();
            for entity in page {
                let record = self.load_proposal_entity_with_revision(&entity)?;
                let expired_promotion =
                    record
                        .state
                        .canonical
                        .body()
                        .effects
                        .first()
                        .is_some_and(|effect| {
                            matches!(
                                effect,
                                CanonicalEffectV1::ManagedPointerPromotion {
                                    expires_unix_ms,
                                    ..
                                } if observed_at >= *expires_unix_ms
                            )
                        });
                if matches!(record.state.state, ProposalStateV1::Ready { .. }) && !expired_promotion
                {
                    count += 1;
                    if count >= self.max_ready_proposals as usize {
                        return Ok(count);
                    }
                }
            }
        }
    }

    // Recovery keeps the state-machine cases adjacent to make every restart
    // transition auditable as a single exhaustive ceremony.
    #[allow(clippy::too_many_lines)]
    fn recover_incomplete_attempts(&mut self) -> Result<(), BrokerError> {
        if self.store.active_backup_cut()?.is_some() {
            return Ok(());
        }
        let mut cursor = None;
        loop {
            let page = self
                .store
                .entity_ids_after("proposal-", cursor.as_deref(), 512)?;
            if page.is_empty() {
                return Ok(());
            }
            cursor = page.last().cloned();
            for entity in page {
                let loaded = self.load_proposal_entity_with_revision(&entity)?;
                if let ProposalStateV1::Preparing { proposal, attempt } = &loaded.state.state {
                    let proposal = proposal.clone();
                    let attempt = attempt.clone();
                    let effect = &loaded.state.canonical.body().effects[0];
                    let authorization = loaded
                        .state
                        .authorization
                        .as_ref()
                        .map(Digest::from_serializable)
                        .transpose()?
                        .ok_or_else(|| {
                            BrokerError::Corrupt(
                                "preparing promotion is missing authorization custody".to_owned(),
                            )
                        })?;
                    let observation = self.pointer_runtime.observe_canonical(effect);
                    let known_prestate = observation.as_ref().is_ok_and(|observed| {
                        classify_reconciliation(effect, observed).is_ok_and(|classification| {
                            classification == ReconciliationClassificationV1::NotApplied
                        })
                    });
                    let observation_evidence = observation
                        .as_ref()
                        .ok()
                        .map(Digest::from_serializable)
                        .transpose()?;
                    let outcome = if known_prestate {
                        ExecutionOutcomeV1::Failed {
                            failure: ag_effect::executor::ExecutionFailureV1 {
                                code: ag_effect::executor::ExecutionFailureCodeV1::BackendRejected,
                                phase: ExecutionPhaseV1::PromotionPreparation,
                                detail: "restart proved the managed ref remained at the exact ratified prestate"
                                    .to_owned(),
                                source_code: Some("preparation_abandoned_on_restart".to_owned()),
                                evidence: observation_evidence,
                            },
                        }
                    } else {
                        ExecutionOutcomeV1::Indeterminate {
                            envelope: ExecutionIndeterminateV1 {
                                code: ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                                phase: ExecutionPhaseV1::PromotionPreparation,
                                detail: "restart could not prove an unchanged promotion prestate"
                                    .to_owned(),
                                source_code: Some("preparation_restart_unresolved".to_owned()),
                                evidence: observation_evidence,
                            },
                        }
                    };
                    let execution_receipt = ExecutionReceiptV1 {
                        schema: EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
                        proposal: proposal.clone(),
                        authorization,
                        attempt: attempt.clone(),
                        effect_index: 0,
                        effect: effect.clone(),
                        outcome,
                    };
                    let step = execution_receipt
                        .digest()
                        .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
                    let terminal_kind = if known_prestate {
                        CompositeTerminalV1::Failed
                    } else {
                        CompositeTerminalV1::Indeterminate
                    };
                    let mut record = loaded.state;
                    record.step_receipts.push(step);
                    let terminal = composite_execution_receipt(
                        &proposal,
                        &attempt,
                        &record.step_receipts,
                        terminal_kind,
                    )?;
                    let event = if known_prestate {
                        ProposalEventV1::PreparationAbandoned {
                            receipt: terminal.clone(),
                        }
                    } else {
                        ProposalEventV1::PreparationIndeterminate {
                            envelope: terminal.clone(),
                        }
                    };
                    record.state = record.state.apply(event)?;
                    record.terminal_receipt = Some(terminal);
                    self.persist_record(
                        &record,
                        loaded.revision,
                        if known_prestate {
                            "effect-promotion.restart-proven-unchanged.v1"
                        } else {
                            "effect-promotion.restart-indeterminate.v1"
                        },
                        &execution_receipt,
                    )?;
                    continue;
                }
                let event = match &loaded.state.state {
                    ProposalStateV1::AuthorizationBurned { proposal, .. } => {
                        let receipt = Digest::from_serializable(&(
                            "ag.effect.abandoned-before-execution/v1",
                            proposal,
                            loaded.last_event_digest.to_string(),
                        ))?;
                        Some((
                            ProposalEventV1::ExecutionAbandoned {
                                receipt: receipt.clone(),
                            },
                            receipt,
                            "effect-execution.abandoned-before-begin.v1",
                        ))
                    }
                    ProposalStateV1::Executing {
                        proposal, attempt, ..
                    } => {
                        let envelope = restart_reconciliation_envelope(
                            proposal,
                            attempt,
                            &loaded.state.step_receipts,
                        )?;
                        Some((
                            ProposalEventV1::ExecutionIndeterminate {
                                envelope: envelope.clone(),
                            },
                            envelope,
                            "effect-execution.restart-indeterminate.v1",
                        ))
                    }
                    _ => None,
                };
                if let Some((event, evidence, kind)) = event {
                    let mut record = loaded.state;
                    record.state = record.state.apply(event)?;
                    record.terminal_receipt = Some(evidence.clone());
                    self.persist_record(&record, loaded.revision, kind, &evidence)?;
                }
            }
        }
    }

    fn load_proposal(&self, proposal: &Digest) -> Result<BrokerProposalRecordV1, BrokerError> {
        Ok(self.load_proposal_with_revision(proposal)?.state)
    }

    fn load_proposal_with_revision(
        &self,
        proposal: &Digest,
    ) -> Result<ag_store::MaterializedStateV1<BrokerProposalRecordV1>, BrokerError> {
        let loaded = self
            .store
            .materialized_state(&proposal_entity(proposal))?
            .ok_or(BrokerError::NotFound)?;
        self.validate_proposal_record(proposal, &loaded.state)?;
        Ok(loaded)
    }

    fn load_proposal_entity_with_revision(
        &self,
        entity: &str,
    ) -> Result<ag_store::MaterializedStateV1<BrokerProposalRecordV1>, BrokerError> {
        let expected = proposal_digest_from_entity(entity)?;
        let loaded = self
            .store
            .materialized_state(entity)?
            .ok_or_else(|| BrokerError::Corrupt("listed proposal is missing".to_owned()))?;
        if loaded.entity_id != entity {
            return Err(BrokerError::Corrupt(
                "proposal materialization returned another entity".to_owned(),
            ));
        }
        self.validate_proposal_record(&expected, &loaded.state)?;
        Ok(loaded)
    }

    fn validate_all_proposal_records(&self) -> Result<(), BrokerError> {
        let mut cursor = None;
        loop {
            let page = self
                .store
                .entity_ids_after("proposal-", cursor.as_deref(), 512)?;
            if page.is_empty() {
                return Ok(());
            }
            cursor = page.last().cloned();
            for entity in page {
                self.load_proposal_entity_with_revision(&entity)?;
            }
        }
    }

    #[allow(clippy::too_many_lines, clippy::single_match_else)]
    fn validate_proposal_record(
        &self,
        requested: &Digest,
        record: &BrokerProposalRecordV1,
    ) -> Result<(), BrokerError> {
        record
            .canonical
            .verify_digest()
            .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
        require_record_invariant(
            record.schema == BROKER_PROPOSAL_RECORD_SCHEMA_V3,
            "proposal record lacks the v3 activation-explanation schema",
        )?;
        require_record_invariant(
            requested == record.canonical.digest(),
            "proposal entity does not bind the canonical digest",
        )?;
        require_record_invariant(
            record.canonical.body().schema == EFFECT_SCHEMA_V1,
            "canonical proposal has an unexpected schema",
        )?;
        require_record_invariant(
            record.canonical.body().authority_domain == self.authority_domain
                && record.canonical.body().epoch == self.epoch,
            "canonical proposal is outside the broker authority context",
        )?;
        require_record_invariant(
            record.canonical.body().catalog_schema == EFFECT_CATALOG_SCHEMA_V1
                && record.canonical.body().catalog_identity == self.catalog_identity
                && record.canonical.body().security_profile_identity
                    == self.security_profile_identity,
            "canonical proposal is outside the active catalog or security profile",
        )?;
        require_record_invariant(
            record.canonical.body().effects.len() == 1,
            "canonical proposal does not contain exactly one effect",
        )?;
        require_record_invariant(
            record.step_receipts.len() <= record.canonical.body().effects.len(),
            "proposal has more step receipts than canonical effects",
        )?;

        let promotion_candidate = match &record.canonical.body().effects[0] {
            CanonicalEffectV1::ManagedPointerPromotion {
                target,
                prepared_candidate,
                exact_basis,
                complete_inputs,
                candidate_preparation_receipt,
                repository_identity,
                prestate_identity,
                repository_device,
                repository_inode,
                git_directory_device,
                git_directory_inode,
                uid,
                gid,
                reference,
                artifact,
                candidate_pack_digest,
                expected_object,
                expected_tree,
                new_object,
                expected_post_tree,
                helper_executable,
                helper_launch_profile,
                staging_root,
                ..
            } => {
                let candidate = record.prepared_candidates.get(target).ok_or_else(|| {
                    BrokerError::Corrupt(
                        "managed-pointer record lacks exact prepared-candidate history".to_owned(),
                    )
                })?;
                require_record_invariant(
                    record.prepared_candidates.len() == 1
                        && candidate.identity()? == *prepared_candidate
                        && candidate.exact_basis.identity()? == *exact_basis
                        && candidate
                            .complete_inputs
                            .identity(candidate.exact_basis.object_format)?
                            == *complete_inputs
                        && candidate.preparation_receipt.identity()?
                            == *candidate_preparation_receipt
                        && candidate.exact_basis.authority_domain
                            == record.canonical.body().authority_domain
                        && candidate.exact_basis.epoch == record.canonical.body().epoch
                        && candidate.exact_basis.catalog_identity
                            == record.canonical.body().catalog_identity
                        && candidate.exact_basis.security_profile_identity
                            == record.canonical.body().security_profile_identity
                        && candidate.preparation_standing.max_artifact_bytes
                            == self.max_artifact_bytes
                        && self.max_artifact_bytes.checked_mul(2)
                            == Some(candidate.preparation_standing.quarantine_budget_bytes)
                        && candidate.exact_basis.target == *target
                        && candidate.exact_basis.repository_identity == *repository_identity
                        && candidate.exact_basis.prestate_identity == *prestate_identity
                        && candidate.exact_basis.repository_device == *repository_device
                        && candidate.exact_basis.repository_inode == *repository_inode
                        && candidate.exact_basis.git_directory_device == *git_directory_device
                        && candidate.exact_basis.git_directory_inode == *git_directory_inode
                        && candidate.exact_basis.uid == *uid
                        && candidate.exact_basis.gid == *gid
                        && candidate.exact_basis.reference == *reference
                        && candidate.exact_basis.current_object == *expected_object
                        && candidate.exact_basis.current_tree == *expected_tree
                        && candidate.complete_inputs.artifact == *artifact
                        && candidate.complete_inputs.candidate_pack_digest
                            == *candidate_pack_digest
                        && candidate.complete_inputs.candidate_object == *new_object
                        && candidate.complete_inputs.candidate_tree == *expected_post_tree
                        && candidate.complete_inputs.helper_executable == *helper_executable
                        && candidate.complete_inputs.helper_launch_profile
                            == *helper_launch_profile
                        && candidate.complete_inputs.staging_root == *staging_root,
                    "managed-pointer prepared candidate differs from canonical effect bindings",
                )?;
                Some(candidate)
            }
            _ => {
                require_record_invariant(
                    record.prepared_candidates.is_empty()
                        && record.candidate_ratification.is_none()
                        && record.promotion_refusals.is_empty(),
                    "non-promotion record contains managed-pointer preparation authority residue",
                )?;
                None
            }
        };
        require_record_invariant(
            record.promotion_refusals.len() <= 32,
            "proposal contains too many promotion-eligibility refusals",
        )?;
        for refusal in &record.promotion_refusals {
            let candidate = promotion_candidate.ok_or_else(|| {
                BrokerError::Corrupt(
                    "promotion refusal is attached to a non-promotion proposal".to_owned(),
                )
            })?;
            refusal
                .identity()
                .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
            let attempted_authorization =
                Digest::from_serializable(&refusal.attempted_authorization)?;
            refusal
                .candidate_ratification
                .verify_bindings(
                    record.canonical.digest(),
                    candidate,
                    &attempted_authorization,
                )
                .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
            let RatificationV1::HumanExact { ratifier, .. } = &refusal.attempted_authorization
            else {
                return Err(BrokerError::Corrupt(
                    "pre-burn promotion refusal contains a non-human authority path".to_owned(),
                ));
            };
            require_record_invariant(
                ratifier.authority_domain() == &record.canonical.body().authority_domain
                    && ratifier.epoch() == record.canonical.body().epoch
                    && record.canonical.body().proposer.independent_from(ratifier),
                "promotion refusal ratifier is outside or dependent on proposal context",
            )?;
        }

        let authorization_digest = record
            .authorization
            .as_ref()
            .map(Digest::from_serializable)
            .transpose()
            .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
        if let Some(authorization) = &record.authorization {
            require_record_invariant(
                authorization.proposal() == record.canonical.digest(),
                "authorization references another canonical proposal",
            )?;
            match authorization {
                RatificationV1::HumanExact { ratifier, .. } => {
                    require_record_invariant(
                        ratifier.authority_domain() == &record.canonical.body().authority_domain
                            && ratifier.epoch() == record.canonical.body().epoch
                            && record.canonical.body().proposer.independent_from(ratifier),
                        "exact ratifier is outside or dependent on the proposal authority context",
                    )?;
                }
                RatificationV1::BoundedMandate { actor, .. } => {
                    require_record_invariant(
                        actor.authority_domain() == &record.canonical.body().authority_domain
                            && actor.epoch() == record.canonical.body().epoch,
                        "mandate actor is outside the proposal authority context",
                    )?;
                }
                RatificationV1::DerivedCodePromotion { adapter, .. } => {
                    require_record_invariant(
                        adapter.authority_domain() == &record.canonical.body().authority_domain
                            && adapter.epoch() == record.canonical.body().epoch
                            && record.canonical.body().proposer.independent_from(adapter),
                        "derived adapter is outside or dependent on the proposal authority context",
                    )?;
                }
            }
        }
        match (
            promotion_candidate,
            record.authorization.as_ref(),
            record.candidate_ratification.as_ref(),
            authorization_digest.as_ref(),
        ) {
            (Some(candidate), Some(_), Some(binding), Some(authorization)) => binding
                .verify_bindings(record.canonical.digest(), candidate, authorization)
                .map_err(|error| BrokerError::Corrupt(error.to_string()))?,
            (Some(_), None, None, None) | (None, _, None, _) => {}
            _ => {
                return Err(BrokerError::Corrupt(
                    "candidate ratification does not match promotion authority custody".to_owned(),
                ));
            }
        }

        let activation_required = promotion_candidate.is_some()
            && matches!(&record.state, ProposalStateV1::Succeeded { .. });
        require_record_invariant(
            record.managed_pointer_activation.is_some() == activation_required,
            "managed-pointer activation explanation does not match terminal lifecycle",
        )?;
        if let Some(activation) = &record.managed_pointer_activation {
            let effect = &record.canonical.body().effects[0];
            let candidate = promotion_candidate.ok_or_else(|| {
                BrokerError::Corrupt(
                    "activation explanation is attached to a non-promotion proposal".to_owned(),
                )
            })?;
            let candidate_ratification =
                record.candidate_ratification.as_ref().ok_or_else(|| {
                    BrokerError::Corrupt(
                        "activation explanation lacks candidate ratification custody".to_owned(),
                    )
                })?;
            let authorization = authorization_digest.as_ref().ok_or_else(|| {
                BrokerError::Corrupt(
                    "activation explanation lacks accepted authorization custody".to_owned(),
                )
            })?;
            let attempt = record.execution_attempt.as_ref().ok_or_else(|| {
                BrokerError::Corrupt(
                    "activation explanation lacks one-shot attempt custody".to_owned(),
                )
            })?;
            activation
                .verify(effect)
                .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
            require_record_invariant(
                activation.execution.proposal == *record.canonical.digest()
                    && activation.execution.authorization == *authorization
                    && activation.execution.attempt == *attempt
                    && activation.execution.effect_index == 0
                    && activation.prepared_candidate == candidate.identity()?
                    && activation.candidate_ratification == candidate_ratification.identity()?,
                "activation explanation differs from proposal authority or candidate custody",
            )?;
        }

        match &record.state {
            ProposalStateV1::Ready { proposal } => {
                require_record_invariant(
                    proposal == record.canonical.digest(),
                    "ready lifecycle references another canonical proposal",
                )?;
                require_record_invariant(
                    record.authorization.is_none()
                        && record.terminal_receipt.is_none()
                        && record.step_receipts.is_empty()
                        && record.execution_attempt.is_none()
                        && record.reconciliation.is_none(),
                    "ready lifecycle contains execution or authority residue",
                )?;
            }
            ProposalStateV1::AuthorizationBurned {
                proposal,
                authorization,
                family,
            } => {
                require_record_invariant(
                    proposal == record.canonical.digest()
                        && authorization_digest.as_ref() == Some(authorization),
                    "burned lifecycle does not bind exact proposal authority",
                )?;
                require_record_invariant(
                    record.terminal_receipt.is_none()
                        && record.step_receipts.is_empty()
                        && record.execution_attempt.is_none()
                        && record.reconciliation.is_none(),
                    "burned lifecycle contains execution residue",
                )?;
                require_record_invariant(
                    record.canonical.body().effects[0].family() == *family,
                    "burned lifecycle names another effect family",
                )?;
            }
            ProposalStateV1::Preparing { proposal, attempt } => {
                require_record_invariant(
                    proposal == record.canonical.digest()
                        && record.authorization.is_some()
                        && record.execution_attempt.as_ref() == Some(attempt)
                        && record.canonical.body().effects[0].family()
                            == EffectFamilyV1::CodePromotion,
                    "preparing lifecycle does not bind one code-promotion attempt",
                )?;
                require_record_invariant(
                    record.terminal_receipt.is_none()
                        && record.step_receipts.is_empty()
                        && record.reconciliation.is_none(),
                    "preparing lifecycle contains terminal execution residue",
                )?;
            }
            ProposalStateV1::Executing {
                proposal,
                attempt,
                preparation_checkpoint,
            } => {
                let is_promotion =
                    record.canonical.body().effects[0].family() == EffectFamilyV1::CodePromotion;
                require_record_invariant(
                    proposal == record.canonical.digest()
                        && record.authorization.is_some()
                        && record.execution_attempt.as_ref() == Some(attempt)
                        && preparation_checkpoint.is_some() == is_promotion,
                    "executing lifecycle does not bind proposal, authority, and attempt",
                )?;
                require_record_invariant(
                    record.terminal_receipt.is_none() && record.reconciliation.is_none(),
                    "executing lifecycle contains terminal residue",
                )?;
            }
            ProposalStateV1::Succeeded { receipt } => {
                require_record_invariant(
                    record.authorization.is_some()
                        && record.execution_attempt.is_some()
                        && record.terminal_receipt.as_ref() == Some(receipt)
                        && record.step_receipts.len() == record.canonical.body().effects.len()
                        && record.reconciliation.is_none(),
                    "successful lifecycle does not bind its complete execution receipts",
                )?;
                let attempt = record.execution_attempt.as_ref().ok_or_else(|| {
                    BrokerError::Corrupt("successful lifecycle is missing its attempt".to_owned())
                })?;
                require_record_invariant(
                    composite_execution_receipt(
                        record.canonical.digest(),
                        attempt,
                        &record.step_receipts,
                        CompositeTerminalV1::Succeeded,
                    )? == *receipt,
                    "successful terminal receipt does not bind proposal, attempt, and steps",
                )?;
            }
            ProposalStateV1::Failed { receipt } => {
                require_record_invariant(
                    record.authorization.is_some()
                        && record.terminal_receipt.as_ref() == Some(receipt)
                        && record.reconciliation.is_none(),
                    "failed lifecycle does not bind authority and terminal receipt",
                )?;
                require_record_invariant(
                    record.execution_attempt.is_some() || record.step_receipts.is_empty(),
                    "abandoned pre-execution lifecycle contains step receipts",
                )?;
                if let Some(attempt) = &record.execution_attempt {
                    require_record_invariant(
                        !record.step_receipts.is_empty(),
                        "attempted failure is missing its step receipt",
                    )?;
                    require_record_invariant(
                        composite_execution_receipt(
                            record.canonical.digest(),
                            attempt,
                            &record.step_receipts,
                            CompositeTerminalV1::Failed,
                        )? == *receipt,
                        "failed terminal receipt does not bind proposal, attempt, and steps",
                    )?;
                }
            }
            ProposalStateV1::ReconciliationRequired { envelope } => {
                require_record_invariant(
                    record.authorization.is_some()
                        && record.execution_attempt.is_some()
                        && record.terminal_receipt.as_ref() == Some(envelope)
                        && record.reconciliation.is_none(),
                    "indeterminate lifecycle does not bind authority, attempt, and envelope",
                )?;
                let attempt = record.execution_attempt.as_ref().ok_or_else(|| {
                    BrokerError::Corrupt(
                        "indeterminate lifecycle is missing its attempt".to_owned(),
                    )
                })?;
                let execution_envelope = if record.step_receipts.is_empty() {
                    None
                } else {
                    Some(composite_execution_receipt(
                        record.canonical.digest(),
                        attempt,
                        &record.step_receipts,
                        CompositeTerminalV1::Indeterminate,
                    )?)
                };
                let restart_envelope = restart_reconciliation_envelope(
                    record.canonical.digest(),
                    attempt,
                    &record.step_receipts,
                )?;
                require_record_invariant(
                    execution_envelope.as_ref() == Some(envelope) || restart_envelope == *envelope,
                    "indeterminate envelope does not bind proposal, attempt, and steps",
                )?;
            }
            ProposalStateV1::Reconciled { receipt } => {
                let reconciliation = record.reconciliation.as_ref().ok_or_else(|| {
                    BrokerError::Corrupt(
                        "reconciled lifecycle is missing reconciliation custody".to_owned(),
                    )
                })?;
                let reconciliation_digest = reconciliation
                    .digest()
                    .map_err(|error| BrokerError::Corrupt(error.to_string()))?;
                require_record_invariant(
                    record.authorization.is_some()
                        && record.execution_attempt.is_some()
                        && record.terminal_receipt.as_ref() == Some(receipt)
                        && reconciliation_digest == *receipt
                        && reconciliation.schema == RECONCILIATION_RECORD_SCHEMA_V1
                        && reconciliation.evidence.schema == RECONCILIATION_EVIDENCE_SCHEMA_V1
                        && reconciliation.evidence.proposal == *record.canonical.digest()
                        && record.execution_attempt.as_ref()
                            == Some(&reconciliation.evidence.attempt)
                        && record.step_receipts == reconciliation.evidence.step_receipts,
                    "reconciled lifecycle does not bind exact evidence and receipts",
                )?;
                require_record_invariant(
                    reconciliation.ratifier.authority_domain()
                        == &record.canonical.body().authority_domain
                        && reconciliation.ratifier.epoch() == record.canonical.body().epoch
                        && record
                            .canonical
                            .body()
                            .proposer
                            .independent_from(&reconciliation.ratifier),
                    "reconciliation ratifier is outside or dependent on the proposal context",
                )?;
                let effect = &record.canonical.body().effects[0];
                require_record_invariant(
                    reconciliation.evidence.observed_poststate.len() == 1
                        && reconciliation
                            .evidence
                            .observed_poststate
                            .contains_key(effect.target()),
                    "reconciliation observation set does not match canonical targets",
                )?;
                let observation = &reconciliation.evidence.observed_poststate[effect.target()];
                let classification =
                    classify_reconciliation(effect, observation).map_err(|_| {
                        BrokerError::Corrupt(
                            "reconciliation observation cannot prove its classification".to_owned(),
                        )
                    })?;
                require_record_invariant(
                    classification == reconciliation.evidence.classification,
                    "reconciliation classification does not match observed state",
                )?;
                let execution_envelope = if record.step_receipts.is_empty() {
                    None
                } else {
                    Some(composite_execution_receipt(
                        record.canonical.digest(),
                        &reconciliation.evidence.attempt,
                        &record.step_receipts,
                        CompositeTerminalV1::Indeterminate,
                    )?)
                };
                let restart_envelope = restart_reconciliation_envelope(
                    record.canonical.digest(),
                    &reconciliation.evidence.attempt,
                    &record.step_receipts,
                )?;
                require_record_invariant(
                    execution_envelope.as_ref()
                        == Some(&reconciliation.evidence.uncertainty_envelope)
                        || restart_envelope == reconciliation.evidence.uncertainty_envelope,
                    "reconciliation uncertainty does not bind proposal, attempt, and steps",
                )?;
            }
            ProposalStateV1::Received
            | ProposalStateV1::Refused { .. }
            | ProposalStateV1::Indeterminate { .. } => {
                return Err(BrokerError::Corrupt(
                    "canonical proposal has an impossible pre-compilation lifecycle".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn persist_record<T: Serialize>(
        &mut self,
        record: &BrokerProposalRecordV1,
        expected_revision: u64,
        event_kind: &str,
        payload: &T,
    ) -> Result<u64, BrokerError> {
        self.validate_proposal_record(record.canonical.digest(), record)?;
        let receipt = self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: proposal_entity(record.canonical.digest()),
                event_kind: event_kind.to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload,
            },
            record,
            expected_revision,
        )?;
        Ok(receipt.entity_revision)
    }

    fn persist_submission(
        &mut self,
        record: &BrokerSubmissionRecordV1,
        event_kind: &str,
    ) -> Result<(), BrokerError> {
        self.store.append_event(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: submission_entity(&record.source),
                event_kind: event_kind.to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: &record.source,
            },
            record,
            0,
        )?;
        Ok(())
    }

    fn persist_canonical_submission(
        &mut self,
        source: &Digest,
        governor: VerifiedRpcPrincipalV1,
        proposer: PrincipalChainV1,
        ingress_proof: GovernedProposalIngressV1,
        canonical: &ag_effect::CanonicalEffectProposalV1,
        prepared_candidates: BTreeMap<TargetId, PreparedManagedPointerCandidateV1>,
    ) -> Result<EffectProposalResponseV1, BrokerError> {
        canonical.verify_digest()?;
        let state = ProposalStateV1::Received.apply(ProposalEventV1::Compiled {
            proposal: canonical.digest().clone(),
        })?;
        let proposal_record = BrokerProposalRecordV1 {
            schema: BROKER_PROPOSAL_RECORD_SCHEMA_V3.to_owned(),
            canonical: canonical.clone(),
            prepared_candidates,
            candidate_ratification: None,
            promotion_refusals: Vec::new(),
            state,
            authorization: None,
            terminal_receipt: None,
            step_receipts: Vec::new(),
            execution_attempt: None,
            reconciliation: None,
            managed_pointer_activation: None,
        };
        self.validate_proposal_record(canonical.digest(), &proposal_record)?;
        let response = EffectProposalResponseV1::Canonicalized {
            proposal_id: canonical.body().proposal_id.clone(),
            proposal_digest: canonical.digest().clone(),
        };
        let evaluation = BrokerEvaluationEvidenceV1::Canonicalized {
            proposal_id: canonical.body().proposal_id.clone(),
            proposal: canonical.digest().clone(),
        };
        let submission_record = BrokerSubmissionRecordV1 {
            source: source.clone(),
            governor,
            proposer,
            ingress_proof,
            evaluation,
            response: response.clone(),
        };
        self.store.append_distinct_event_pair(
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: proposal_entity(canonical.digest()),
                event_kind: "effect-proposal.canonicalized.v1".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: &canonical,
            },
            &proposal_record,
            0,
            NewEventV1 {
                event_id: uuid::Uuid::new_v4().to_string(),
                entity_id: submission_entity(source),
                event_kind: "effect-submission.canonicalized.v1".to_owned(),
                occurred_at_unix_ms: now_i64()?,
                payload: source,
            },
            &submission_record,
            0,
        )?;
        Ok(response)
    }
}

fn build_catalog(
    configured: &[EffectTargetConfigV1],
) -> Result<(EffectCatalogV1, BTreeMap<TargetId, EffectTargetConfigV1>), BrokerError> {
    let mut targets = BTreeMap::new();
    let mut source = BTreeMap::new();
    for target in configured {
        let (id_text, definition) = match target {
            EffectTargetConfigV1::ManagedPointer {
                id,
                allowed_root,
                repository,
                reference,
                repository_identity,
                uid,
                gid,
                staging_root,
                promotion_ttl_ms,
                helper,
                helper_executable,
                helper_launch_profile,
                ..
            } => {
                if Digest::hash_bytes(&fs::read(helper)?) != *helper_executable {
                    return Err(BrokerError::HelperIdentityMismatch(
                        helper.display().to_string(),
                    ));
                }
                (
                    id,
                    TargetDefinitionV1::ManagedPointer {
                        allowed_root: utf8_path(allowed_root)?,
                        repository: repository_relative_path(allowed_root, repository)?,
                        reference: reference.clone(),
                        repository_identity: repository_identity.clone(),
                        uid: *uid,
                        gid: *gid,
                        staging_root: utf8_path(staging_root)?,
                        promotion_ttl_ms: *promotion_ttl_ms,
                        helper_executable: helper_executable.clone(),
                        helper_launch_profile: helper_launch_profile.clone(),
                    },
                )
            }
            EffectTargetConfigV1::ManagedFile {
                id,
                path,
                mode,
                uid,
                gid,
            } => (
                id,
                TargetDefinitionV1::ManagedFile {
                    path: utf8_path(path)?,
                    mode: *mode,
                    uid: *uid,
                    gid: *gid,
                },
            ),
            EffectTargetConfigV1::SystemdUnit {
                id,
                unit,
                allowed_actions,
            } => (
                id,
                TargetDefinitionV1::SystemdUnit {
                    unit: unit.clone(),
                    allowed_actions: allowed_actions.iter().copied().collect::<BTreeSet<_>>(),
                },
            ),
            EffectTargetConfigV1::SystemdManager { id } => (id, TargetDefinitionV1::SystemdManager),
        };
        let id = TargetId::parse(id_text.clone())?;
        if targets.insert(id.clone(), definition).is_some()
            || source.insert(id, target.clone()).is_some()
        {
            return Err(BrokerError::DuplicateTarget(id_text.clone()));
        }
    }
    let identity = Digest::from_serializable(&(EFFECT_CATALOG_SCHEMA_V1, &targets))?;
    Ok((
        EffectCatalogV1 {
            schema: EFFECT_CATALOG_SCHEMA_V1.to_owned(),
            identity,
            targets,
        },
        source,
    ))
}

/// Computes the exact compiler catalog identity after applying the same target
/// normalization and pinned-helper byte verification used by broker startup.
///
/// This is intentionally the only pre-store activation path for effectd's
/// authority catalog identity; callers cannot supply a config-file digest or
/// independently reconstructed approximation.
///
/// # Errors
///
/// Returns an error for invalid/duplicate targets, non-UTF-8 canonical paths,
/// unreadable helper bytes, or a pinned helper identity mismatch.
pub fn configured_catalog_identity(
    configured: &[EffectTargetConfigV1],
) -> Result<Digest, BrokerError> {
    Ok(build_catalog(configured)?.0.identity)
}

fn observe_file(path: &Path, configured_maximum: u64) -> Result<TargetObservationV1, BrokerError> {
    const HARD_OBSERVATION_MAXIMUM: u64 = 64 * 1024 * 1024;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| BrokerError::Observation("managed path is not absolute".to_owned()))?;
    let root = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io_error)?;
    let fd = match open_beneath(
        &root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            return Ok(TargetObservationV1::ManagedFile {
                current_content: None,
                regular_file: true,
            });
        }
        Err(error) => return Err(std::io::Error::from_raw_os_error(error.raw_os_error()).into()),
    };
    let before = rustix::fs::fstat(&fd).map_err(rustix_io_error)?;
    if !FileType::from_raw_mode(before.st_mode).is_file() || before.st_nlink != 1 {
        return Ok(TargetObservationV1::ManagedFile {
            current_content: None,
            regular_file: false,
        });
    }
    let length = u64::try_from(before.st_size)
        .map_err(|_| BrokerError::Observation("managed file has a negative size".to_owned()))?;
    let maximum = configured_maximum.min(HARD_OBSERVATION_MAXIMUM);
    if length > maximum {
        return Err(BrokerError::Observation(
            "managed file exceeds the bounded observation size".to_owned(),
        ));
    }
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(
        usize::try_from(length)
            .map_err(|_| BrokerError::Observation("managed file size overflow".to_owned()))?,
    );
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = rustix::fs::fstat(&file).map_err(rustix_io_error)?;
    if bytes.len() as u64 != length
        || bytes.len() as u64 > maximum
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(BrokerError::Observation(
            "managed file changed during exact descriptor observation".to_owned(),
        ));
    }
    Ok(TargetObservationV1::ManagedFile {
        current_content: Some(Digest::hash_bytes(&bytes)),
        regular_file: true,
    })
}

fn rustix_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

// This exhaustive match is the authority boundary between observed state and
// operator reconciliation; keeping all effect families together prevents a
// permissive default from creeping in.
#[allow(clippy::too_many_lines)]
fn classify_reconciliation(
    effect: &CanonicalEffectV1,
    observation: &TargetObservationV1,
) -> Result<ReconciliationClassificationV1, BrokerError> {
    match (effect, observation) {
        (
            CanonicalEffectV1::ManagedPointerPromotion {
                repository_identity,
                prestate_identity,
                repository_device,
                repository_inode,
                git_directory_device,
                git_directory_inode,
                uid,
                gid,
                candidate_pack_digest,
                object_format,
                expected_object,
                expected_tree,
                new_object,
                expected_post_tree,
                ..
            },
            TargetObservationV1::ManagedPointer {
                current_object,
                current_tree,
                candidate_object,
                candidate_tree,
                candidate_parent,
                candidate_pack_digest: observed_pack,
                object_format: observed_format,
                repository_identity: observed_identity,
                prestate_identity: observed_prestate_identity,
                repository_device: observed_repository_device,
                repository_inode: observed_repository_inode,
                git_directory_device: observed_git_device,
                git_directory_inode: observed_git_inode,
                repository_uid,
                repository_gid,
                clean,
                reference_checked_out,
            },
        ) => {
            let exact_identity = repository_identity == observed_identity
                && repository_device == observed_repository_device
                && repository_inode == observed_repository_inode
                && git_directory_device == observed_git_device
                && git_directory_inode == observed_git_inode
                && uid == repository_uid
                && gid == repository_gid
                && candidate_pack_digest == observed_pack
                && object_format == observed_format
                && candidate_object == new_object
                && candidate_tree == expected_post_tree
                && candidate_parent == expected_object
                && *clean
                && !*reference_checked_out;
            if !exact_identity {
                return Ok(ReconciliationClassificationV1::Foreign);
            }
            if current_object == new_object && current_tree == expected_post_tree {
                Ok(ReconciliationClassificationV1::Applied)
            } else if current_object == expected_object
                && current_tree == expected_tree
                && prestate_identity == observed_prestate_identity
            {
                Ok(ReconciliationClassificationV1::NotApplied)
            } else {
                Ok(ReconciliationClassificationV1::Foreign)
            }
        }
        (
            CanonicalEffectV1::ManagedFilePut {
                expected_content: _,
                content,
                ..
            },
            TargetObservationV1::ManagedFile {
                current_content,
                regular_file: true,
            },
        ) if current_content.as_ref() == Some(content) => {
            Ok(ReconciliationClassificationV1::Applied)
        }
        (
            CanonicalEffectV1::ManagedFilePut {
                expected_content, ..
            },
            TargetObservationV1::ManagedFile {
                current_content,
                regular_file: true,
            },
        ) if current_content == expected_content => Ok(ReconciliationClassificationV1::NotApplied),
        (
            CanonicalEffectV1::ManagedFileDelete {
                expected_content: _,
                ..
            },
            TargetObservationV1::ManagedFile {
                current_content: None,
                regular_file: true,
            },
        ) => Ok(ReconciliationClassificationV1::Applied),
        (
            CanonicalEffectV1::ManagedFileDelete {
                expected_content, ..
            },
            TargetObservationV1::ManagedFile {
                current_content: Some(current),
                regular_file: true,
            },
        ) if current == expected_content => Ok(ReconciliationClassificationV1::NotApplied),
        _ => Err(BrokerError::ReconciliationStateUnresolved),
    }
}

fn effect_record_projection(record: BrokerProposalRecordV1) -> EffectRecordV1 {
    EffectRecordV1 {
        schema: EFFECT_RECORD_SCHEMA_V3.to_owned(),
        canonical: record.canonical,
        prepared_candidates: record.prepared_candidates,
        candidate_ratification: record.candidate_ratification,
        promotion_refusals: record.promotion_refusals,
        state: record.state,
        authorization: record.authorization,
        terminal_receipt: record.terminal_receipt,
        step_receipts: record.step_receipts,
        execution_attempt: record.execution_attempt,
        reconciliation: record.reconciliation,
        managed_pointer_activation: record.managed_pointer_activation,
    }
}

fn enforce_receipt_bindings(
    receipt: ExecutionReceiptV1,
    proposal: &Digest,
    authorization: &Digest,
    attempt: &Digest,
    effect_index: u32,
    effect: &CanonicalEffectV1,
) -> ExecutionReceiptV1 {
    if receipt
        .verify_bindings(proposal, authorization, attempt, effect_index, effect)
        .is_ok()
    {
        return receipt;
    }
    ExecutionReceiptV1 {
        schema: EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
        proposal: proposal.clone(),
        authorization: authorization.clone(),
        attempt: attempt.clone(),
        effect_index,
        effect: effect.clone(),
        outcome: ExecutionOutcomeV1::Indeterminate {
            envelope: ExecutionIndeterminateV1 {
                code: ExecutionIndeterminateCodeV1::BackendContractViolation,
                phase: ExecutionPhaseV1::ReceiptValidation,
                detail: "effect runner returned a receipt for another authority context".to_owned(),
                source_code: Some("runner_contract_violation".to_owned()),
                evidence: None,
            },
        },
    }
}

fn enforce_managed_pointer_evidence_bindings(
    receipt: &mut ExecutionReceiptV1,
    commit: Option<&ManagedPointerCommitEvidenceV1>,
    poststate: Option<&ManagedPointerPoststateEvidenceV1>,
    activation: Option<&ManagedPointerActivationReceiptV1>,
) {
    if !matches!(receipt.outcome, ExecutionOutcomeV1::Succeeded { .. }) {
        return;
    }
    let activation_matches = activation.is_some_and(|activation| {
        activation.verify(&receipt.effect).is_ok()
            && commit == Some(&activation.commit)
            && poststate == Some(&activation.poststate)
    });
    if commit.is_none() || poststate.is_none() || !activation_matches {
        receipt.outcome = ExecutionOutcomeV1::Indeterminate {
            envelope: ExecutionIndeterminateV1 {
                code: ExecutionIndeterminateCodeV1::BackendContractViolation,
                phase: ExecutionPhaseV1::ReceiptValidation,
                detail: "managed-pointer success lacks complete activation evidence".to_owned(),
                source_code: Some("missing_promotion_evidence".to_owned()),
                evidence: None,
            },
        };
    }
}

fn utf8_path(path: &Path) -> Result<String, BrokerError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| BrokerError::Observation("configured path is not UTF-8".to_owned()))
}

fn repository_relative_path(allowed_root: &Path, repository: &Path) -> Result<String, BrokerError> {
    let relative = repository.strip_prefix(allowed_root).map_err(|_| {
        BrokerError::Observation("managed repository is outside its allowed root".to_owned())
    })?;
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(BrokerError::Observation(
            "managed repository is not strictly beneath its allowed root".to_owned(),
        ));
    }
    utf8_path(relative)
}

fn proposal_entity(proposal: &Digest) -> String {
    format!(
        "proposal-{}",
        proposal
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(proposal.as_str())
    )
}

fn proposal_digest_from_entity(entity: &str) -> Result<Digest, BrokerError> {
    let suffix = entity.strip_prefix("proposal-").ok_or_else(|| {
        BrokerError::Corrupt("proposal materialization has an invalid entity prefix".to_owned())
    })?;
    let digest = Digest::parse(&format!("sha256:{suffix}")).map_err(|_| {
        BrokerError::Corrupt("proposal materialization has an invalid digest entity".to_owned())
    })?;
    if proposal_entity(&digest) != entity {
        return Err(BrokerError::Corrupt(
            "proposal materialization has a noncanonical entity".to_owned(),
        ));
    }
    Ok(digest)
}

fn require_record_invariant(condition: bool, detail: &str) -> Result<(), BrokerError> {
    if condition {
        Ok(())
    } else {
        Err(BrokerError::Corrupt(detail.to_owned()))
    }
}

#[derive(Clone, Copy)]
enum CompositeTerminalV1 {
    Succeeded,
    Failed,
    Indeterminate,
}

fn composite_execution_receipt(
    proposal: &Digest,
    attempt: &Digest,
    step_receipts: &[Digest],
    terminal: CompositeTerminalV1,
) -> Result<Digest, BrokerError> {
    let last = step_receipts.len().saturating_sub(1);
    let steps = step_receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            if index != last || matches!(terminal, CompositeTerminalV1::Succeeded) {
                BrokerStepOutcomeV1::Succeeded {
                    receipt: receipt.clone(),
                }
            } else if matches!(terminal, CompositeTerminalV1::Failed) {
                BrokerStepOutcomeV1::Failed {
                    receipt: receipt.clone(),
                }
            } else {
                BrokerStepOutcomeV1::Indeterminate {
                    envelope: receipt.clone(),
                }
            }
        })
        .collect::<Vec<_>>();
    Digest::from_serializable(&(
        "ag.effect.composite-execution-receipt/v1",
        proposal,
        attempt,
        steps,
    ))
    .map_err(|error| BrokerError::Corrupt(error.to_string()))
}

fn restart_reconciliation_envelope(
    proposal: &Digest,
    attempt: &Digest,
    step_receipts: &[Digest],
) -> Result<Digest, BrokerError> {
    Digest::from_serializable(&(
        "ag.effect.restart-reconciliation/v1",
        proposal,
        attempt,
        step_receipts,
    ))
    .map_err(|error| BrokerError::Corrupt(error.to_string()))
}

fn submission_entity(source: &Digest) -> String {
    format!(
        "submission-{}",
        source
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(source.as_str())
    )
}

fn stable_proposal_id(source: &Digest) -> String {
    format!(
        "p-{}",
        source
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(source.as_str())
    )
}

const fn compiler_evaluation_event_kind(semantic_refusal: bool) -> &'static str {
    if semantic_refusal {
        "effect-evaluation.refused.v1"
    } else {
        "effect-evaluation.indeterminate.v1"
    }
}

fn proposal_state_name(state: &ProposalStateV1) -> &'static str {
    match state {
        ProposalStateV1::Received => "received",
        ProposalStateV1::Ready { .. } => "ready",
        ProposalStateV1::Refused { .. } => "refused",
        ProposalStateV1::Indeterminate { .. } => "indeterminate",
        ProposalStateV1::AuthorizationBurned { .. } => "authorization_burned",
        ProposalStateV1::Preparing { .. } => "preparing",
        ProposalStateV1::Executing { .. } => "executing",
        ProposalStateV1::Succeeded { .. } => "succeeded",
        ProposalStateV1::Failed { .. } => "failed",
        ProposalStateV1::ReconciliationRequired { .. } => "reconciliation_required",
        ProposalStateV1::Reconciled { .. } => "reconciled",
    }
}

fn security_profile_identity(profile: &str) -> Digest {
    Digest::hash_domain("ag-security-profile-identity-v1", profile.as_bytes())
}

fn bounded_activation_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii() && !character.is_ascii_control() {
                character
            } else {
                '?'
            }
        })
        .take(512)
        .collect()
}

fn now_u64() -> Result<u64, BrokerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| BrokerError::Clock(error.to_string()))?;
    u64::try_from(duration.as_millis()).map_err(|_| BrokerError::Clock("clock overflow".to_owned()))
}

fn now_i64() -> Result<i64, BrokerError> {
    i64::try_from(now_u64()?).map_err(|_| BrokerError::Clock("clock overflow".to_owned()))
}

fn broker_api_error<T>(error: &BrokerError) -> ApiResultV1<T> {
    let code = match error {
        BrokerError::NotFound => ApiErrorCodeV1::NotFound,
        BrokerError::Quiesced => ApiErrorCodeV1::Quiesced,
        BrokerError::ChallengeInvalid
        | BrokerError::PrincipalChainsNotIndependent
        | BrokerError::AuthorityContextMismatch
        | BrokerError::ProposerProofMismatch
        | BrokerError::WorkerSourceProofMismatch
        | BrokerError::WorkerSourceBindingMismatch
        | BrokerError::RpcAuthentication(_) => ApiErrorCodeV1::Unauthorized,
        BrokerError::UnsupportedAuthorityFamily => ApiErrorCodeV1::UnsupportedAuthorityFamily,
        BrokerError::Observation(_)
        | BrokerError::ManagedPointer(_)
        | BrokerError::ActivationEvidence(_)
        | BrokerError::ActivationNotReady => ApiErrorCodeV1::Indeterminate,
        BrokerError::Effect(EffectError::InvalidTransition { .. })
        | BrokerError::PromotionExpired
        | BrokerError::PromotionEligibilityRefused(_)
        | BrokerError::ReconciliationStateUnresolved
        | BrokerError::ReconciliationNotRequired => ApiErrorCodeV1::Conflict,
        BrokerError::Effect(_)
        | BrokerError::Session(_)
        | BrokerError::WorkerCandidateMismatch
        | BrokerError::PlanTooLarge
        | BrokerError::ReadyLimit
        | BrokerError::ReconciliationEvidenceMismatch => ApiErrorCodeV1::InvalidRequest,
        _ => ApiErrorCodeV1::Internal,
    };
    ApiResultV1::error(code, error.to_string())
}

/// Broker implementation failures.
#[derive(Debug, Error)]
pub enum BrokerError {
    /// Primitive identifier failed.
    #[error("invalid authority identifier: {0}")]
    Identifier(#[from] ag_primitives::IdentifierError),
    /// JCS identity failed.
    #[error("canonical identity failed: {0}")]
    Jcs(#[from] ag_primitives::JcsError),
    /// Effect vocabulary/state failed.
    #[error(transparent)]
    Effect(#[from] EffectError),
    /// Store operation failed.
    #[error(transparent)]
    Store(#[from] ag_store::StoreError),
    /// Peer identity failed.
    #[error(transparent)]
    Peer(#[from] crate::peer::PeerError),
    /// Signed-RPC principal binding failed.
    #[error(transparent)]
    RpcAuthentication(#[from] crate::rpc_auth::RpcAuthError),
    /// Worker-session custody contract failed strict validation.
    #[error(transparent)]
    Session(#[from] ag_session::SessionError),
    /// Local observation failed.
    #[error("effect observation failed: {0}")]
    Io(#[from] std::io::Error),
    /// Closed managed-pointer runtime failed without widening its operation.
    #[error(transparent)]
    ManagedPointer(#[from] ManagedPointerError),
    /// Named target is duplicated.
    #[error("duplicate target ID: {0}")]
    DuplicateTarget(String),
    /// Helper bytes changed relative to root config.
    #[error("pinned helper executable identity mismatch: {0}")]
    HelperIdentityMismatch(String),
    /// Catalog bound into the store activation differs from the compiler's
    /// exact rebuilt catalog.
    #[error("activated effect catalog identity does not match the rebuilt compiler catalog")]
    CatalogIdentityMismatch,
    /// Runtime and compiler disagree about the exact service sandbox/profile.
    #[error("managed-pointer runtime security-profile identity mismatch")]
    SecurityProfileIdentityMismatch,
    /// Exact promotion authority expired before the independent ratification burn.
    #[error("managed-pointer proposal expired before ratification")]
    PromotionExpired,
    /// Fresh exact basis/candidate checks refused standing before authority burn.
    #[error("managed-pointer promotion eligibility refused: {0}")]
    PromotionEligibilityRefused(Digest),
    /// Broker cannot safely observe a target.
    #[error("target observation indeterminate: {0}")]
    Observation(String),
    /// Intent comes from another authority context.
    #[error("intent authority domain or epoch mismatch")]
    AuthorityContextMismatch,
    /// Forwarded original request did not contain the exact authenticated
    /// proposer and proposal intent.
    #[error("forwarded proposal does not match the end-to-end proposer proof")]
    ProposerProofMismatch,
    /// Dynamic worker signature/enrollment or launcher-chain proof differs.
    #[error("worker candidate does not match its authenticated principal proof")]
    WorkerSourceProofMismatch,
    /// Worker authority context, workspace, expiry, budget, or proposer differs.
    #[error("worker candidate source does not match its durable session bindings")]
    WorkerSourceBindingMismatch,
    /// Candidate nonce, bytes, length, custody digest, or admitted artifact differs.
    #[error("worker candidate bytes do not match governor custody and intent")]
    WorkerCandidateMismatch,
    /// Submitted reconciliation bytes disagree with broker custody, the
    /// uncertainty boundary, or the independently observed target state.
    #[error("reconciliation evidence does not match broker-owned state")]
    ReconciliationEvidenceMismatch,
    /// Current target state proves neither exact application nor exact
    /// preservation of the ratified prestate.
    #[error("target state remains unresolved and cannot be reconciled")]
    ReconciliationStateUnresolved,
    /// A read-only draft is meaningful only at the exact indeterminate
    /// lifecycle boundary.
    #[error("proposal does not require reconciliation")]
    ReconciliationNotRequired,
    /// Plan exceeds the closed configured bound.
    #[error("proposal exceeds configured effect-step bound")]
    PlanTooLarge,
    /// Ready proposal bound is full.
    #[error("ready proposal bound reached")]
    ReadyLimit,
    /// Artifact list/bytes/digest/canonical base64 differ from admitted refs.
    #[error("transferred artifacts do not exactly match admitted custody references")]
    ArtifactTransferMismatch,
    /// Coherent backup cut fences mutation.
    #[error("effect broker is quiesced for a coherent backup cut")]
    Quiesced,
    /// Canonical proposal is absent.
    #[error("canonical proposal not found")]
    NotFound,
    /// Display challenge is absent, consumed, expired, or peer-mismatched.
    #[error("ratification display challenge is invalid")]
    ChallengeInvalid,
    /// Proposer and ratifier chains are not independent.
    #[error("proposer and ratifier principal chains are not independent")]
    PrincipalChainsNotIndependent,
    /// Authority path is not yet honestly implemented.
    #[error("authority family is not supported by this build")]
    UnsupportedAuthorityFamily,
    /// Production authority remains disabled until activation-level
    /// readiness, including the effective sandbox, has been attested.
    #[error("effect authority is disabled because broker activation is not ready")]
    ActivationNotReady,
    /// Fresh live startup evidence differs from the exact broker context.
    #[error("effect broker activation evidence refused: {0}")]
    ActivationEvidence(String),
    /// Clock cannot be represented.
    #[error("trusted clock observation failed: {0}")]
    Clock(String),
    /// Durable state cannot be trusted.
    #[error("broker store is corrupt: {0}")]
    Corrupt(String),
}

#[cfg(test)]
mod tests {
    use ag_effect::{EFFECT_SCHEMA_V1, EffectIntentV1, ProposalIntentV1};
    use ag_primitives::{
        CgroupIdentity, ExecutableIdentityV1, HostCredentialObservationV1, LaunchProfileIdentityV1,
        LifecycleNonce, ProjectId, SessionId, WorkerProviderRouteV1, WorkerSessionPrincipalV1,
    };
    use ag_protocol::{RequestEnvelopeV1, RequestId};
    use ag_session::WorkerCandidateCustodyV1;
    use ag_store::{StoreIdentityV1, WriterIdentityV1};
    use nix::unistd::{getegid, geteuid};
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::rpc_auth::{RpcKeyIdV1, RpcSignerV1};

    fn signer(label: &str) -> RpcSignerV1 {
        let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        RpcSignerV1::from_pkcs8_for_test(
            Digest::hash_domain("effectd-test-principal", label.as_bytes()),
            RpcKeyIdV1::new(format!("{label}.v1")).expect("key ID"),
            bytes.as_ref(),
        )
        .expect("signer")
    }

    fn ingress(
        governor: &RpcSignerV1,
        proposer: &RpcSignerV1,
        intent: ProposalIntentV1,
        request_id: &str,
    ) -> ProposalIngressProofV1 {
        let now = now_u64().expect("clock");
        let proposer_enrollment = proposer.enrollment(30_000).expect("proposer enrollment");
        let challenge = governor
            .issue_challenge(&proposer_enrollment, now)
            .expect("challenge");
        let request = RequestEnvelopeV1::new(
            RequestId::new(request_id).expect("request ID"),
            AgdRequestV1::SubmitProposal {
                intent: Box::new(intent),
            },
        )
        .expect("request");
        ProposalIngressProofV1 {
            server_challenge: challenge.clone(),
            signed_request: Box::new(
                proposer
                    .sign_request(request, &challenge, now)
                    .expect("signed request"),
            ),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn worker_candidate_source_is_verified_end_to_end_and_hostile_drift_refuses() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../config/effectd.example.toml"))
                .expect("effectd config");
        config.store.database = directory.path().join("effectd.db");
        config.store.object_store = directory.path().join("objects");
        config.targets = vec![EffectTargetConfigV1::ManagedFile {
            id: "managed-config".to_owned(),
            path: directory.path().join("managed.conf"),
            mode: 0o600,
            uid: geteuid().as_raw(),
            gid: getegid().as_raw(),
        }];

        let governor_signer = signer("worker-governor");
        config.agd_peer.rpc_key = governor_signer
            .enrollment(30_000)
            .expect("governor enrollment")
            .key;
        let governor_peer = VerifiedRpcPrincipalV1 {
            principal: config.agd_peer.rpc_key.principal.clone(),
            key_id: config.agd_peer.rpc_key.key_id.clone(),
        };
        let domain = AuthorityDomain::parse(&config.authority_domain).expect("domain");
        let epoch = Epoch::parse(&config.epoch).expect("epoch");
        let governor_chain =
            signed_principal_chain(&governor_peer, &config.agd_peer, domain.clone(), epoch)
                .expect("governor chain");

        let content = b"worker candidate content".to_vec();
        let content_digest = Digest::hash_bytes(&content);
        let workspace_identity = Digest::hash_bytes(b"workspace-inode-and-construction");
        let session_nonce = LifecycleNonce::new([7; 16]);
        // The broker is intentionally created well after this one-shot proof
        // was accepted and the worker expired. A new replay guard models an
        // effectd restart recovering a durably custodied candidate.
        let broker_started_at = now_u64().expect("clock");
        let accepted_at = broker_started_at.saturating_sub(600_000);
        let worker_key_material =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("worker key");
        let worker_key_id = RpcKeyIdV1::new("worker-session.v1").expect("worker key ID");
        let provisional_worker_signer = RpcSignerV1::from_pkcs8_for_test(
            Digest::hash_bytes(b"principal-not-yet-constructed"),
            worker_key_id.clone(),
            worker_key_material.as_ref(),
        )
        .expect("provisional worker signer");
        let provisional_worker_policy = provisional_worker_signer
            .enrollment(30_000)
            .expect("provisional worker enrollment")
            .key;
        let candidate_key_identity =
            candidate_ingress_key_identity(&provisional_worker_policy).expect("candidate key ID");
        let worker = WorkerSessionPrincipalV1 {
            authority_domain: domain.clone(),
            epoch,
            project: ProjectId::parse("fixture-project").expect("project"),
            session_id: SessionId::parse("fixture-session").expect("session"),
            session_nonce,
            launcher: governor_chain.leaf().principal_id.clone(),
            executable: ExecutableIdentityV1::new(
                Digest::hash_bytes(b"fixture-worker-executable"),
                4096,
                None,
            ),
            launch_profile: LaunchProfileIdentityV1::new(
                Digest::hash_bytes(b"fixed-argv-launch-profile"),
                Digest::hash_bytes(b"candidate-protocol-schema"),
            ),
            proposal_workspace_identity: workspace_identity.clone(),
            security_profile_identity: Digest::hash_bytes(b"development-profile"),
            candidate_ingress_key_identity: candidate_key_identity,
            expires_at_unix_ms: accepted_at.saturating_add(60_000),
            output_budget_bytes: content.len() as u64,
            provider_route: WorkerProviderRouteV1::Offline,
            input_set_digest: Digest::hash_bytes(b"reviewed-input-set"),
            observed_credentials: HostCredentialObservationV1 {
                uid: 65_534,
                gid: 65_534,
                pid: 4242,
                cgroup: CgroupIdentity::parse("ag-worker/fixture-session").expect("cgroup"),
            },
        };
        assert!(worker.expires_at_unix_ms < broker_started_at);
        let worker_signer = RpcSignerV1::from_pkcs8_for_test(
            worker.id().digest().clone(),
            worker_key_id,
            worker_key_material.as_ref(),
        )
        .expect("worker signer");
        let worker_enrollment = worker_signer
            .enrollment(30_000)
            .expect("worker enrollment")
            .key;
        assert_eq!(
            candidate_ingress_key_identity(&worker_enrollment).expect("final candidate key ID"),
            worker.candidate_ingress_key_identity
        );
        let mut worker_nodes = governor_chain.nodes().to_vec();
        worker_nodes.push(PrincipalChainNodeV1::child(
            worker.id(),
            PrincipalKindV1::WorkerSession,
            governor_chain.leaf().principal_id.clone(),
        ));
        let worker_chain =
            PrincipalChainV1::new(domain.clone(), epoch, worker_nodes).expect("worker chain");
        let challenge = governor_signer
            .issue_challenge(
                &worker_signer.enrollment(30_000).expect("worker enrollment"),
                accepted_at,
            )
            .expect("worker challenge");
        let candidate_request = RequestEnvelopeV1::new(
            RequestId::new("worker-candidate-1").expect("request ID"),
            WorkerCandidateRequestV1::Submit {
                candidate_nonce: session_nonce,
                semantic_type: "managed_file_content".to_owned(),
                content: crate::api::OpaqueBytesV1::new(content.clone()),
            },
        )
        .expect("candidate request");
        let signed_request = worker_signer
            .sign_request(candidate_request, &challenge, accepted_at)
            .expect("signed worker request");
        let ingress_proof = WorkerCandidateIngressProofV1 {
            governor_enrollment: config.agd_peer.rpc_key.clone(),
            worker_enrollment,
            server_challenge: challenge,
            signed_request: Box::new(signed_request),
        };
        let ingress_proof_digest =
            worker_candidate_ingress_proof_digest(&ingress_proof).expect("ingress proof");
        assert_eq!(
            Digest::hash_bytes(
                &ingress_proof
                    .canonical_bytes()
                    .expect("canonical proof bytes")
            ),
            ingress_proof_digest
        );
        let candidate_custody = WorkerCandidateCustodyV1::new(
            content_digest.clone(),
            content.len() as u64,
            "managed_file_content",
            None,
            ingress_proof_digest,
        )
        .expect("candidate custody")
        .custody_record;
        let intent = ProposalIntentV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            intent_id: "worker-intent-1".to_owned(),
            authority_domain: domain,
            epoch,
            proposer: worker_chain.clone(),
            judgment: Digest::hash_bytes(b"agd-constructed-admission"),
            admitted_artifacts: BTreeSet::from([content_digest.clone()]),
            effects: vec![EffectIntentV1::ManagedFilePut {
                target: TargetId::parse("managed-config").expect("target"),
                content: content_digest.clone(),
            }],
        };
        let worker_source = WorkerCandidateSourceProofV1 {
            worker,
            worker_chain: worker_chain.clone(),
            ingress_proof,
            session_binding: Digest::hash_bytes(b"immutable-session-spec"),
            workspace_identity,
            launch_receipt: Digest::hash_bytes(b"descriptor-bound-launch"),
            candidate_custody,
            accepted_at_unix_ms: accepted_at,
        };
        let ingress = GovernedProposalIngressV1::WorkerCandidate {
            intent: Box::new(intent),
            source: Box::new(worker_source),
        };

        let store = Store::open(
            &config.store.database,
            &config.store.object_store,
            StoreIdentityV1::current(0x4147_4554, "effectd-worker-source-test")
                .expect("store identity"),
            &WriterIdentityV1 {
                writer_id: "effectd-worker-source-writer".to_owned(),
                principal_digest: Digest::hash_bytes(b"effectd-worker-source-writer"),
                process_nonce: "effectd-worker-source-nonce".to_owned(),
                claimed_at_unix_ms: 1,
            },
        )
        .expect("store");
        let replay = Arc::new(RpcReplayGuardV1::new(64).expect("replay"));
        let catalog_identity =
            configured_catalog_identity(&config.targets).expect("catalog identity");
        let mut broker = EffectBrokerV1::new(
            &config,
            &catalog_identity,
            store,
            RefusingEffectRunnerV1,
            replay,
        )
        .expect("broker");

        let verified = broker
            .verify_governed_ingress_bindings(&ingress, &governor_peer, &governor_chain)
            .expect("valid worker proof");
        assert_eq!(verified.1, worker_chain);

        let mut forged_key = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } = &mut forged_key else {
            unreachable!();
        };
        let attacker = signer("worker-attacker");
        source.ingress_proof.worker_enrollment.public_key = attacker
            .enrollment(30_000)
            .expect("attacker enrollment")
            .key
            .public_key;
        assert!(matches!(
            broker.verify_governed_ingress_bindings(&forged_key, &governor_peer, &governor_chain),
            Err(BrokerError::WorkerSourceProofMismatch)
        ));

        let mut wrong_governor_challenge_policy = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } =
            &mut wrong_governor_challenge_policy
        else {
            unreachable!();
        };
        source
            .ingress_proof
            .governor_enrollment
            .maximum_clock_skew_ms += 1;
        assert!(matches!(
            broker.verify_governed_ingress_bindings(
                &wrong_governor_challenge_policy,
                &governor_peer,
                &governor_chain
            ),
            Err(BrokerError::WorkerSourceProofMismatch)
        ));

        let mut wrong_enrollment_identity = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } =
            &mut wrong_enrollment_identity
        else {
            unreachable!();
        };
        source.worker.candidate_ingress_key_identity =
            Digest::hash_bytes(b"unrelated-candidate-key-policy");
        assert!(matches!(
            broker.verify_governed_ingress_bindings(
                &wrong_enrollment_identity,
                &governor_peer,
                &governor_chain
            ),
            Err(BrokerError::WorkerSourceProofMismatch)
        ));

        let mut wrong_chain = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } = &mut wrong_chain else {
            unreachable!();
        };
        source.worker_chain = governor_chain.clone();
        assert!(matches!(
            broker.verify_governed_ingress_bindings(&wrong_chain, &governor_peer, &governor_chain),
            Err(BrokerError::WorkerSourceProofMismatch)
        ));

        let mut wrong_workspace = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } = &mut wrong_workspace else {
            unreachable!();
        };
        source.workspace_identity = Digest::hash_bytes(b"other-workspace");
        assert!(matches!(
            broker.verify_governed_ingress_bindings(
                &wrong_workspace,
                &governor_peer,
                &governor_chain
            ),
            Err(BrokerError::WorkerSourceBindingMismatch)
        ));

        let mut expired = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } = &mut expired else {
            unreachable!();
        };
        source.accepted_at_unix_ms = source.worker.expires_at_unix_ms;
        assert!(matches!(
            broker.verify_governed_ingress_bindings(&expired, &governor_peer, &governor_chain),
            Err(BrokerError::WorkerSourceBindingMismatch)
        ));

        let mut wrong_candidate = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } = &mut wrong_candidate else {
            unreachable!();
        };
        source.candidate_custody = WorkerCandidateCustodyV1::new(
            content_digest.clone(),
            content.len() as u64,
            "managed_file_content",
            None,
            Digest::hash_bytes(b"different-authenticated-ingress-proof"),
        )
        .expect("wrong proof custody")
        .custody_record;
        assert!(matches!(
            broker.verify_governed_ingress_bindings(
                &wrong_candidate,
                &governor_peer,
                &governor_chain
            ),
            Err(BrokerError::WorkerCandidateMismatch)
        ));

        let mut changed_valid_proof = ingress.clone();
        let GovernedProposalIngressV1::WorkerCandidate { source, .. } = &mut changed_valid_proof
        else {
            unreachable!();
        };
        let changed_challenge = governor_signer
            .issue_challenge(
                &worker_signer
                    .enrollment(30_000)
                    .expect("changed worker enrollment"),
                accepted_at,
            )
            .expect("changed challenge");
        let changed_request = RequestEnvelopeV1::new(
            RequestId::new("worker-candidate-2").expect("changed request ID"),
            WorkerCandidateRequestV1::Submit {
                candidate_nonce: session_nonce,
                semantic_type: "managed_file_content".to_owned(),
                content: crate::api::OpaqueBytesV1::new(content.clone()),
            },
        )
        .expect("changed request");
        let changed_signed_request = worker_signer
            .sign_request(changed_request, &changed_challenge, accepted_at)
            .expect("changed signed request");
        source.ingress_proof = WorkerCandidateIngressProofV1 {
            governor_enrollment: config.agd_peer.rpc_key.clone(),
            worker_enrollment: worker_signer
                .enrollment(30_000)
                .expect("changed worker enrollment")
                .key,
            server_challenge: changed_challenge,
            signed_request: Box::new(changed_signed_request),
        };
        source.candidate_custody = WorkerCandidateCustodyV1::new(
            content_digest.clone(),
            content.len() as u64,
            "managed_file_content",
            None,
            worker_candidate_ingress_proof_digest(&source.ingress_proof)
                .expect("changed proof digest"),
        )
        .expect("changed proof custody")
        .custody_record;

        let artifact = ArtifactTransferV1 {
            digest: content_digest.clone(),
            byte_length: content.len() as u64,
            content_base64: base64::engine::general_purpose::STANDARD.encode(&content),
        };
        let GovernedProposalIngressV1::WorkerCandidate { intent, .. } = &ingress else {
            unreachable!();
        };
        assert!(matches!(
            broker.install_governed_artifacts(intent, &ingress, vec![artifact.clone()]),
            Err(BrokerError::ArtifactTransferMismatch)
        ));
        let exact_retry_ingress = ingress.clone();
        let response = broker.handle_proposal(
            EffectProposalRequestV1::SubmitAuthenticatedIntent {
                ingress: Box::new(ingress),
                artifacts: Vec::new(),
            },
            &governor_peer,
        );
        assert!(matches!(
            response,
            ApiResultV1::Ok {
                response: EffectProposalResponseV1::Canonicalized { .. }
            }
        ));
        assert!(matches!(
            broker.submit_authenticated_intent(
                &changed_valid_proof,
                Vec::new(),
                &governor_peer,
                &governor_chain
            ),
            Err(BrokerError::WorkerSourceProofMismatch)
        ));
        assert!(matches!(
            broker.submit_authenticated_intent(
                &exact_retry_ingress,
                vec![artifact],
                &governor_peer,
                &governor_chain
            ),
            Err(BrokerError::ArtifactTransferMismatch)
        ));
        let exact_retry = broker.handle_proposal(
            EffectProposalRequestV1::SubmitAuthenticatedIntent {
                ingress: Box::new(exact_retry_ingress),
                artifacts: Vec::new(),
            },
            &governor_peer,
        );
        assert_eq!(response, exact_retry);
        assert_eq!(broker.store.entity_ids("proposal-", 10).unwrap().len(), 1);
        assert_eq!(broker.store.entity_ids("submission-", 10).unwrap().len(), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authenticated_submission_is_idempotent_and_ratifiable_only_by_independent_admin() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../config/effectd.example.toml"))
                .expect("effectd config");
        config.store.database = directory.path().join("effectd.db");
        config.store.object_store = directory.path().join("objects");
        let target_path = directory.path().join("managed.conf");
        config.targets = vec![EffectTargetConfigV1::ManagedFile {
            id: "managed-config".to_owned(),
            path: target_path.clone(),
            mode: 0o600,
            uid: geteuid().as_raw(),
            gid: getegid().as_raw(),
        }];

        let governor_signer = signer("governor");
        let proposer_signer = signer("proposer");
        config.agd_peer.rpc_key = governor_signer
            .enrollment(30_000)
            .expect("governor enrollment")
            .key;
        config.proposer_peer.rpc_key = proposer_signer
            .enrollment(30_000)
            .expect("proposer enrollment")
            .key;
        let governor_peer = VerifiedRpcPrincipalV1 {
            principal: config.agd_peer.rpc_key.principal.clone(),
            key_id: config.agd_peer.rpc_key.key_id.clone(),
        };
        let proposer_peer = VerifiedRpcPrincipalV1 {
            principal: config.proposer_peer.rpc_key.principal.clone(),
            key_id: config.proposer_peer.rpc_key.key_id.clone(),
        };
        let proposer_chain = signed_principal_chain(
            &proposer_peer,
            &config.proposer_peer,
            AuthorityDomain::parse(&config.authority_domain).expect("domain"),
            Epoch::parse(&config.epoch).expect("epoch"),
        )
        .expect("proposer chain");
        let content = b"governed content".to_vec();
        let content_digest = Digest::hash_bytes(&content);
        let intent = ProposalIntentV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            intent_id: "stable-intent-1".to_owned(),
            authority_domain: AuthorityDomain::parse(&config.authority_domain).expect("domain"),
            epoch: Epoch::parse(&config.epoch).expect("epoch"),
            proposer: proposer_chain.clone(),
            judgment: Digest::hash_bytes(b"admitted-judgment"),
            admitted_artifacts: BTreeSet::from([content_digest.clone()]),
            effects: vec![EffectIntentV1::ManagedFilePut {
                target: TargetId::parse("managed-config").expect("target"),
                content: content_digest.clone(),
            }],
        };
        let artifact = ArtifactTransferV1 {
            digest: content_digest,
            byte_length: content.len() as u64,
            content_base64: base64::engine::general_purpose::STANDARD.encode(&content),
        };
        let store = Store::open(
            &config.store.database,
            &config.store.object_store,
            StoreIdentityV1::current(0x4147_4554, "effectd-idempotence-test")
                .expect("store identity"),
            &WriterIdentityV1 {
                writer_id: "effectd-idempotence-writer".to_owned(),
                principal_digest: Digest::hash_bytes(b"effectd-test-writer"),
                process_nonce: "effectd-idempotence-nonce".to_owned(),
                claimed_at_unix_ms: 1,
            },
        )
        .expect("store");
        let replay = Arc::new(RpcReplayGuardV1::new(32).expect("replay"));
        let catalog_identity =
            configured_catalog_identity(&config.targets).expect("configured catalog identity");
        let mut broker = EffectBrokerV1::new(
            &config,
            &catalog_identity,
            store,
            RefusingEffectRunnerV1,
            replay,
        )
        .expect("broker");

        let original_ingress = ingress(
            &governor_signer,
            &proposer_signer,
            intent.clone(),
            "submission-1",
        );
        let first = broker.handle_proposal(
            EffectProposalRequestV1::SubmitAuthenticatedIntent {
                ingress: Box::new(GovernedProposalIngressV1::ExternalSigned {
                    proof: Box::new(original_ingress.clone()),
                }),
                artifacts: vec![artifact.clone()],
            },
            &governor_peer,
        );
        let exact_retry = broker.handle_proposal(
            EffectProposalRequestV1::SubmitAuthenticatedIntent {
                ingress: Box::new(GovernedProposalIngressV1::ExternalSigned {
                    proof: Box::new(original_ingress),
                }),
                artifacts: vec![artifact.clone()],
            },
            &governor_peer,
        );
        let second = broker.handle_proposal(
            EffectProposalRequestV1::SubmitAuthenticatedIntent {
                ingress: Box::new(GovernedProposalIngressV1::ExternalSigned {
                    proof: Box::new(ingress(
                        &governor_signer,
                        &proposer_signer,
                        intent,
                        "submission-2",
                    )),
                }),
                artifacts: vec![artifact],
            },
            &governor_peer,
        );
        assert_eq!(first, exact_retry);
        assert_eq!(first, second);
        assert_eq!(broker.store.entity_ids("proposal-", 10).unwrap().len(), 1);
        let submissions = broker.store.entity_ids("submission-", 10).unwrap();
        assert_eq!(submissions.len(), 1);
        let submission = broker
            .store
            .materialized_state::<BrokerSubmissionRecordV1>(&submissions[0])
            .expect("submission lookup")
            .expect("submission custody")
            .state;
        assert!(submission.evaluation.matches_response(&submission.response));
        assert!(matches!(
            submission.evaluation,
            BrokerEvaluationEvidenceV1::Canonicalized { .. }
        ));

        let ApiResultV1::Ok {
            response:
                EffectProposalResponseV1::Canonicalized {
                    proposal_digest, ..
                },
        } = first
        else {
            panic!("proposal must canonicalize");
        };
        let admin_peer = VerifiedRpcPrincipalV1 {
            principal: config.admin_peer.rpc_key.principal.clone(),
            key_id: config.admin_peer.rpc_key.key_id.clone(),
        };
        let admin_request = Digest::from_serializable(&("effectd-test-admin-request", &admin_peer))
            .expect("admin request digest");
        let inspected = broker.handle_admin(
            EffectAdminRequestV1::InspectProposal {
                proposal: proposal_digest.clone(),
            },
            &admin_peer,
            &admin_request,
        );
        let ApiResultV1::Ok {
            response:
                EffectAdminResponseV1::Proposal {
                    challenge,
                    proposal,
                },
        } = inspected
        else {
            panic!("independent admin must inspect");
        };
        assert_eq!(proposal.body().proposer, proposer_chain);
        let ApiResultV1::Ok {
            response:
                EffectAdminResponseV1::Record {
                    record: ready_record,
                },
        } = broker.handle_admin(
            EffectAdminRequestV1::InspectRecord {
                proposal: proposal_digest.clone(),
            },
            &admin_peer,
            &admin_request,
        )
        else {
            panic!("direct record inspection must succeed");
        };
        assert_eq!(ready_record.schema, EFFECT_RECORD_SCHEMA_V3);
        assert_eq!(ready_record.canonical, *proposal);
        assert!(matches!(ready_record.state, ProposalStateV1::Ready { .. }));
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::DraftReconciliation {
                    proposal: proposal_digest.clone(),
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Conflict,
                ..
            }
        ));
        let unrelated_path = directory.path().join("unrelated.conf");
        fs::write(&unrelated_path, &content).expect("write unrelated desired state");
        assert_eq!(
            broker
                .observe_canonical_effect(&proposal.body().effects[0])
                .expect("observe exact canonical path"),
            TargetObservationV1::ManagedFile {
                current_content: None,
                regular_file: true,
            },
            "an unrelated configured path must not substitute for canonical bytes"
        );
        let target = TargetId::parse("managed-config").expect("target");
        let admitted_target = broker.targets.get(&target).expect("catalog target").clone();
        broker.targets.insert(
            target.clone(),
            EffectTargetConfigV1::ManagedFile {
                id: "managed-config".to_owned(),
                path: unrelated_path,
                mode: 0o600,
                uid: geteuid().as_raw(),
                gid: getegid().as_raw(),
            },
        );
        assert!(matches!(
            broker.observe_canonical(&proposal),
            Err(BrokerError::Observation(_))
        ));
        broker.targets.insert(target, admitted_target);
        let admitted_catalog = broker.catalog_identity.clone();
        broker.catalog_identity = Digest::hash_bytes(b"hostile-catalog-drift");
        assert!(matches!(
            broker.observe_canonical(&proposal),
            Err(BrokerError::Observation(_))
        ));
        broker.catalog_identity = admitted_catalog;

        assert!(
            !broker.development_authority_bypass,
            "the production example must not silently bypass activation readiness"
        );
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::Ratify {
                    proposal: proposal_digest.clone(),
                    challenge: challenge.clone(),
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Indeterminate,
                ..
            }
        ));
        // This private test-only switch explicitly emulates a development
        // profile so the rest of the lifecycle can be exercised. Production
        // construction never sets it.
        broker.development_authority_bypass = true;
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::Ratify {
                    proposal: proposal_digest.clone(),
                    challenge,
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Ok {
                response: EffectAdminResponseV1::ExecutionReceipt { .. }
            }
        ));

        let uncertain = broker
            .load_proposal(&proposal_digest)
            .expect("uncertain proposal");
        let ProposalStateV1::ReconciliationRequired { envelope } = &uncertain.state else {
            panic!("refusing runner must require reconciliation");
        };
        let hostile_digest = Digest::hash_bytes(b"hostile-proposal-binding");
        assert!(matches!(
            broker.validate_proposal_record(&hostile_digest, &uncertain),
            Err(BrokerError::Corrupt(_))
        ));
        let mut legacy_unbound_record = uncertain.clone();
        legacy_unbound_record.schema.clear();
        assert!(matches!(
            broker.validate_proposal_record(&proposal_digest, &legacy_unbound_record),
            Err(BrokerError::Corrupt(_))
        ));
        let mut hostile_attempt = uncertain.clone();
        hostile_attempt.state = ProposalStateV1::Executing {
            proposal: proposal_digest.clone(),
            attempt: uncertain.execution_attempt.clone().expect("attempt"),
            preparation_checkpoint: None,
        };
        hostile_attempt.execution_attempt = Some(hostile_digest.clone());
        hostile_attempt.terminal_receipt = None;
        assert!(matches!(
            broker.validate_proposal_record(&proposal_digest, &hostile_attempt),
            Err(BrokerError::Corrupt(_))
        ));
        let mut hostile_authorization = uncertain.clone();
        hostile_authorization.authorization = None;
        assert!(matches!(
            broker.validate_proposal_record(&proposal_digest, &hostile_authorization),
            Err(BrokerError::Corrupt(_))
        ));
        let mut hostile_terminal = uncertain.clone();
        hostile_terminal.terminal_receipt = Some(hostile_digest.clone());
        assert!(matches!(
            broker.validate_proposal_record(&proposal_digest, &hostile_terminal),
            Err(BrokerError::Corrupt(_))
        ));
        let target = TargetId::parse("managed-config").expect("target");
        let admitted_target = broker.targets.get(&target).expect("target").clone();
        broker.targets.insert(
            target.clone(),
            EffectTargetConfigV1::ManagedFile {
                id: "managed-config".to_owned(),
                path: directory.path().join("hostile-draft-substitution.conf"),
                mode: 0o600,
                uid: geteuid().as_raw(),
                gid: getegid().as_raw(),
            },
        );
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::DraftReconciliation {
                    proposal: proposal_digest.clone(),
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Indeterminate,
                ..
            }
        ));
        broker.targets.insert(target, admitted_target);
        let ApiResultV1::Ok {
            response: EffectAdminResponseV1::ReconciliationDraft { evidence },
        } = broker.handle_admin(
            EffectAdminRequestV1::DraftReconciliation {
                proposal: proposal_digest.clone(),
            },
            &admin_peer,
            &admin_request,
        )
        else {
            panic!("effectd must derive a complete reconciliation draft");
        };
        let evidence = *evidence;
        assert_eq!(evidence.schema, RECONCILIATION_EVIDENCE_SCHEMA_V1);
        assert_eq!(evidence.proposal, proposal_digest);
        assert_eq!(
            evidence.attempt,
            uncertain.execution_attempt.expect("attempt")
        );
        assert_eq!(evidence.uncertainty_envelope, *envelope);
        assert_eq!(evidence.step_receipts, uncertain.step_receipts);
        assert_eq!(
            evidence.classification,
            ReconciliationClassificationV1::NotApplied
        );
        let mut hostile = evidence.clone();
        hostile.uncertainty_envelope = Digest::hash_bytes(b"invented-envelope");
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::Reconcile {
                    evidence: Box::new(hostile),
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::InvalidRequest,
                ..
            }
        ));
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::Reconcile {
                    evidence: Box::new(evidence),
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Ok {
                response: EffectAdminResponseV1::Reconciled { .. }
            }
        ));
        let reconciled = broker
            .load_proposal(&proposal_digest)
            .expect("reconciled proposal");
        assert_eq!(
            reconciled
                .reconciliation
                .as_ref()
                .expect("full reconciliation custody")
                .signed_request,
            admin_request
        );
        let ApiResultV1::Ok {
            response: EffectAdminResponseV1::Record { record },
        } = broker.handle_admin(
            EffectAdminRequestV1::InspectRecord {
                proposal: proposal_digest.clone(),
            },
            &admin_peer,
            &admin_request,
        )
        else {
            panic!("reconciled custody record must remain inspectable");
        };
        assert_eq!(record.schema, EFFECT_RECORD_SCHEMA_V3);
        assert_eq!(record.canonical, reconciled.canonical);
        assert_eq!(record.state, reconciled.state);
        assert_eq!(record.authorization, reconciled.authorization);
        assert_eq!(record.terminal_receipt, reconciled.terminal_receipt);
        assert_eq!(record.step_receipts, reconciled.step_receipts);
        assert_eq!(record.execution_attempt, reconciled.execution_attempt);
        assert_eq!(record.reconciliation, reconciled.reconciliation);
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::DraftReconciliation {
                    proposal: proposal_digest.clone(),
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Conflict,
                ..
            }
        ));
        let mut hostile_reconciliation = reconciled.clone();
        hostile_reconciliation
            .reconciliation
            .as_mut()
            .expect("reconciliation")
            .evidence
            .proposal = hostile_digest.clone();
        assert!(matches!(
            broker.validate_proposal_record(&proposal_digest, &hostile_reconciliation),
            Err(BrokerError::Corrupt(_))
        ));

        let hostile_entity = proposal_entity(&hostile_digest);
        broker
            .store
            .append_event(
                NewEventV1 {
                    event_id: "hostile-proposal-entity-substitution".to_owned(),
                    entity_id: hostile_entity,
                    event_kind: "test.hostile-proposal-substitution.v1".to_owned(),
                    occurred_at_unix_ms: now_i64().expect("clock"),
                    payload: &hostile_digest,
                },
                &reconciled,
                0,
            )
            .expect("inject structurally valid hostile materialization");
        assert!(matches!(
            broker.load_proposal(&hostile_digest),
            Err(BrokerError::Corrupt(_))
        ));
        assert!(matches!(
            broker.handle_admin(
                EffectAdminRequestV1::InspectRecord {
                    proposal: hostile_digest.clone(),
                },
                &admin_peer,
                &admin_request,
            ),
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Internal,
                ..
            }
        ));
        assert!(matches!(
            broker.validate_all_proposal_records(),
            Err(BrokerError::Corrupt(_))
        ));
    }

    #[test]
    fn compiler_operational_failure_uses_indeterminate_event_kind() {
        assert_eq!(
            compiler_evaluation_event_kind(false),
            "effect-evaluation.indeterminate.v1"
        );
        assert_eq!(
            compiler_evaluation_event_kind(true),
            "effect-evaluation.refused.v1"
        );
    }

    #[test]
    fn promotion_reconciliation_distinguishes_pre_post_and_foreign_state() {
        let identity = Digest::hash_bytes(b"repository-identity");
        let prestate_identity = Digest::hash_bytes(b"repository-layout-and-prestate");
        let pack = Digest::hash_bytes(b"candidate-pack");
        let old_object = "1".repeat(40);
        let old_tree = "2".repeat(40);
        let new_object = "3".repeat(40);
        let new_tree = "4".repeat(40);
        let effect = CanonicalEffectV1::ManagedPointerPromotion {
            schema: ag_effect::MANAGED_POINTER_PROMOTION_SCHEMA_V2.to_owned(),
            operation_id: Digest::hash_bytes(b"operation"),
            prepared_candidate: Digest::hash_bytes(b"prepared-candidate"),
            exact_basis: Digest::hash_bytes(b"exact-basis"),
            complete_inputs: Digest::hash_bytes(b"complete-inputs"),
            candidate_preparation_receipt: Digest::hash_bytes(b"candidate-preparation"),
            target: TargetId::parse("repository.main").expect("target"),
            allowed_root: "/srv/git".to_owned(),
            repository: "repository.git".to_owned(),
            reference: "refs/heads/main".to_owned(),
            repository_identity: identity.clone(),
            prestate_identity: prestate_identity.clone(),
            repository_device: 11,
            repository_inode: 12,
            git_directory_device: 13,
            git_directory_inode: 14,
            uid: 1000,
            gid: 1000,
            staging_root: "/var/lib/ag-effectd/promotion".to_owned(),
            artifact: Digest::hash_bytes(b"bundle"),
            candidate_pack_digest: pack.clone(),
            object_format: ag_effect::GitObjectFormatV1::Sha1,
            expected_object: old_object.clone(),
            expected_tree: old_tree.clone(),
            new_object: new_object.clone(),
            expected_post_tree: new_tree.clone(),
            expires_unix_ms: u64::MAX,
            helper_executable: Digest::hash_bytes(b"git"),
            helper_launch_profile: Digest::hash_bytes(b"profile"),
        };
        let observation =
            |current_object: String, current_tree: String| TargetObservationV1::ManagedPointer {
                current_object,
                current_tree,
                candidate_object: new_object.clone(),
                candidate_tree: new_tree.clone(),
                candidate_parent: old_object.clone(),
                candidate_pack_digest: pack.clone(),
                object_format: ag_effect::GitObjectFormatV1::Sha1,
                repository_identity: identity.clone(),
                prestate_identity: prestate_identity.clone(),
                repository_device: 11,
                repository_inode: 12,
                git_directory_device: 13,
                git_directory_inode: 14,
                repository_uid: 1000,
                repository_gid: 1000,
                clean: true,
                reference_checked_out: false,
            };
        assert_eq!(
            classify_reconciliation(&effect, &observation(old_object.clone(), old_tree.clone()))
                .expect("exact prestate"),
            ReconciliationClassificationV1::NotApplied
        );
        assert_eq!(
            classify_reconciliation(&effect, &observation(new_object.clone(), new_tree.clone()))
                .expect("exact poststate"),
            ReconciliationClassificationV1::Applied
        );
        assert_eq!(
            classify_reconciliation(&effect, &observation("5".repeat(40), "6".repeat(40)))
                .expect("foreign state"),
            ReconciliationClassificationV1::Foreign
        );
        let mut substituted = observation(old_object.clone(), old_tree.clone());
        let TargetObservationV1::ManagedPointer {
            repository_inode, ..
        } = &mut substituted
        else {
            unreachable!()
        };
        *repository_inode += 1;
        assert_eq!(
            classify_reconciliation(&effect, &substituted).expect("substituted target"),
            ReconciliationClassificationV1::Foreign
        );
        let mut substituted_prestate = observation(old_object.clone(), old_tree.clone());
        let TargetObservationV1::ManagedPointer {
            prestate_identity, ..
        } = &mut substituted_prestate
        else {
            unreachable!()
        };
        *prestate_identity = Digest::hash_bytes(b"same-value-replaced-ref-inode");
        assert_eq!(
            classify_reconciliation(&effect, &substituted_prestate)
                .expect("substituted prestate layout"),
            ReconciliationClassificationV1::Foreign
        );
    }

    #[test]
    fn configured_catalog_identity_changes_with_exact_target_admission() {
        let mut targets = vec![EffectTargetConfigV1::ManagedFile {
            id: "managed-config".to_owned(),
            path: Path::new("/etc/agent-governor/managed.conf").to_path_buf(),
            mode: 0o600,
            uid: 0,
            gid: 0,
        }];
        let enrolled = configured_catalog_identity(&targets).expect("catalog identity");
        let EffectTargetConfigV1::ManagedFile { mode, .. } = &mut targets[0] else {
            panic!("managed-file target");
        };
        *mode = 0o640;
        let drifted = configured_catalog_identity(&targets).expect("drifted catalog identity");
        assert_ne!(enrolled, drifted);
    }
}
