//! Contained batch-session contracts.
//!
//! The types here deliberately cannot express a PTY, interactive input, a
//! linked worktree, or a host target mount.  Workers receive an independent
//! repository/snapshot and a small, explicit descriptor manifest. Provider
//! calls are useful evidence only when the exact credential-free request and
//! complete response event stream have entered governor custody.

use std::collections::{BTreeMap, BTreeSet};

use ag_primitives::{
    AuthorityDomain, CapabilityDefinitionError, Digest, Epoch, ExecutableIdentityV1,
    InferenceCapabilityId, PrincipalChainV1, PrincipalId, PrincipalKindV1, WorkerProviderRouteV1,
    WorkerSessionPrincipalV1,
};
pub use ag_primitives::{
    InferenceCapabilityV1 as ProviderCapabilityV1, InferenceEnvelopeV1 as ProviderEnvelopeV1,
    SessionId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current session schema.
pub const SESSION_SCHEMA_V1: &str = "ag.session/v1";

/// Current durable worker-session record schema.
pub const WORKER_SESSION_RECORD_SCHEMA_V1: &str = "ag.worker-session-record/v1";

/// Deployment security profile. Production profiles fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProfileV1 {
    /// Local development; never a production identity.
    Development,
    /// Namespaces, cgroups, seccomp, Landlock, and dynamic identity required.
    Production,
    /// Production plus locally configured stronger isolation requirements.
    HighAssurance,
}

impl SecurityProfileV1 {
    /// Returns the domain-separated identity committed by a worker principal.
    #[must_use]
    pub fn identity(self) -> Digest {
        let name = match self {
            Self::Development => b"development".as_slice(),
            Self::Production => b"production".as_slice(),
            Self::HighAssurance => b"high_assurance".as_slice(),
        };
        Digest::hash_domain("ag-ng/worker-security-profile/v1", name)
    }
}

/// The security mechanisms proven present by the launcher.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationEvidenceV1 {
    /// New user namespace identity.
    pub user_namespace: Digest,
    /// New mount namespace identity.
    pub mount_namespace: Digest,
    /// New PID namespace identity.
    pub pid_namespace: Digest,
    /// Cgroup v2 leaf identity and limits.
    pub cgroup: Digest,
    /// Exact seccomp program.
    pub seccomp_profile: Digest,
    /// Exact Landlock ruleset.
    pub landlock_ruleset: Digest,
    /// Network namespace identity, normally loopback-only or absent.
    pub network_namespace: Digest,
    /// Dynamic host credential observed at launch.
    pub observed_uid: u32,
    /// Dynamic host group credential observed at launch.
    pub observed_gid: u32,
    /// Initial host PID observation.
    pub observed_pid: u32,
    /// Exact executable bytes observed through the retained launch object.
    pub observed_executable: ExecutableIdentityV1,
}

/// A stable worker binding. UID/PID are observations, never its identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerBindingV1 {
    /// Stable authenticated worker principal.
    pub principal: WorkerSessionPrincipalV1,
    /// Launcher-to-session principal chain.
    pub principal_chain: PrincipalChainV1,
    /// Kernel observations proving the live process matches this binding.
    pub isolation: IsolationEvidenceV1,
}

/// Purpose of one intentionally inherited descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorPurposeV1 {
    /// Read-only source snapshot.
    SourceSnapshot,
    /// Write-only result artifact sink.
    ArtifactSink,
    /// Read-only ephemeral worker signing credential supplied by the launcher.
    CandidateIngressCredential,
    /// Read-only broker challenge bound to this candidate submission.
    CandidateChallenge,
    /// Write-only authenticated candidate submission channel.
    CandidateSink,
    /// Request side of the session-scoped provider channel.
    ProviderRequest,
    /// Response side of the session-scoped provider channel.
    ProviderResponse,
    /// Structured status/receipt sink.
    StatusSink,
}

/// Direction allowed on an inherited descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorAccessV1 {
    /// Worker may read only.
    ReadOnly,
    /// Worker may write only.
    WriteOnly,
}

/// One explicitly admitted descriptor; all other inherited FDs are forbidden.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedDescriptorV1 {
    /// Fixed descriptor number in the launched child.
    pub descriptor: u32,
    /// Closed purpose.
    pub purpose: DescriptorPurposeV1,
    /// Direction.
    pub access: DescriptorAccessV1,
    /// Identity of the kernel object/helper endpoint.
    pub object_identity: Digest,
}

/// Immutable, path-free source delivered to a worker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotV1 {
    /// Exact source archive or repository bundle bytes.
    pub content: Digest,
    /// Source semantic kind (for example `git_bundle_v1`).
    pub format: String,
    /// Optional immutable upstream object identity.
    pub source_object: Option<String>,
}

/// Workspace construction mode. Linked worktrees are intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceModeV1 {
    /// Independent repository materialized from an admitted bundle.
    IndependentRepository,
    /// Independent directory materialized from an immutable snapshot.
    IndependentSnapshot,
}

/// Worker output artifact declared before governed ingestion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedArtifactV1 {
    /// Content identity.
    pub content: Digest,
    /// Exact length.
    pub byte_length: u64,
    /// Bounded semantic type.
    pub semantic_type: String,
}

/// A path-free description of changes made in the isolated workspace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceDeltaV1 {
    /// Base source identity.
    pub base: Digest,
    /// Canonical manifest of added/changed/deleted relative names.
    pub manifest: Digest,
    /// Immutable archive/bundle carrying the exact delta.
    pub content: Digest,
}

/// Exact credential-free provider request held by `agd`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequestCustodyV1 {
    /// Capability spent for the call.
    pub capability_id: InferenceCapabilityId,
    /// Exact credential-free request body blob.
    pub exact_request: Digest,
    /// Complete sanitized header map. Credential fields are structurally absent.
    pub sanitized_headers: BTreeMap<String, String>,
    /// Exact endpoint/model/method/protocol envelope.
    pub envelope: ProviderEnvelopeV1,
    /// Canonical record binding headers, envelope, and body.
    pub custody_record: Digest,
}

impl ProviderRequestCustodyV1 {
    /// Recomputes the exact credential-free custody binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be canonically encoded or its
    /// committed digest does not bind every request field.
    pub fn verify(&self) -> Result<(), SessionError> {
        #[derive(Serialize)]
        struct CustodyBinding<'a> {
            capability_id: &'a InferenceCapabilityId,
            exact_request: &'a Digest,
            sanitized_headers: &'a BTreeMap<String, String>,
            envelope: &'a ProviderEnvelopeV1,
        }
        let observed = Digest::from_serializable(&CustodyBinding {
            capability_id: &self.capability_id,
            exact_request: &self.exact_request,
            sanitized_headers: &self.sanitized_headers,
            envelope: &self.envelope,
        })
        .map_err(|error| SessionError::CustodyBinding(error.to_string()))?;
        if observed != self.custody_record {
            return Err(SessionError::CustodyMismatch);
        }
        Ok(())
    }
}

/// Exact complete provider event stream held by `agd`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResponseCustodyV1 {
    /// Exact request custody record.
    pub request_custody: Digest,
    /// Complete byte/event stream, including terminal marker or transport failure.
    pub complete_event_stream: Digest,
    /// Canonical parsing/transcript record.
    pub custody_record: Digest,
    /// True only when the stream includes a protocol terminal event.
    pub protocol_terminal: bool,
}

/// Strength of evidence available for a provider interaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "custody", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderCustodyV1 {
    /// Replayable request plus complete response stream.
    ExactReplayable {
        /// Request evidence.
        request: Box<ProviderRequestCustodyV1>,
        /// Response evidence.
        response: Box<ProviderResponseCustodyV1>,
    },
    /// Digest-only evidence imported from a weaker source.
    DigestOnlyWeak {
        /// Request digest.
        request_digest: Digest,
        /// Response digest.
        response_digest: Digest,
    },
}

impl ProviderCustodyV1 {
    /// Whether exact request and response bytes are available for replay.
    ///
    /// This reports custody only. Replayability does not establish semantic
    /// truth, testimonial sufficiency, admission, authority, or effect success.
    #[must_use]
    pub fn is_replayable(&self) -> bool {
        matches!(self, Self::ExactReplayable { .. })
    }
}

/// Immutable specification for one bounded batch session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchSessionSpecV1 {
    /// Schema identity.
    pub schema: String,
    /// Non-reusable session identity.
    pub session: SessionId,
    /// Authority domain.
    pub authority_domain: AuthorityDomain,
    /// Epoch at launch.
    pub epoch: Epoch,
    /// Profile that must be satisfied.
    pub security_profile: SecurityProfileV1,
    /// Root-reviewed fixed-argv worker profile identifier.
    pub reviewed_profile_id: String,
    /// Exact reviewed candidate signing-key binding, excluding the principal ID.
    pub candidate_ingress_key_identity: Digest,
    /// Stable worker binding.
    pub worker: WorkerBindingV1,
    /// Isolated workspace mode.
    pub workspace_mode: WorkspaceModeV1,
    /// Exact reviewed proposal-workspace construction identity.
    pub proposal_workspace_identity: Digest,
    /// Immutable input.
    pub source: SourceSnapshotV1,
    /// Intentionally inherited descriptor set.
    pub admitted_descriptors: Vec<AdmittedDescriptorV1>,
    /// Optional provider grant.
    pub provider_capability: Option<ProviderCapabilityV1>,
    /// Wall-clock deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Maximum output bytes across sinks.
    pub output_budget_bytes: u64,
}

impl BatchSessionSpecV1 {
    /// Checks invariants available before launch.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema, descriptor manifest, provider
    /// capability binding, or required production isolation evidence is
    /// inconsistent.
    pub fn validate(&self) -> Result<(), SessionError> {
        if self.schema != SESSION_SCHEMA_V1 {
            return Err(SessionError::UnknownSchema(self.schema.clone()));
        }
        if !valid_reviewed_profile_id(&self.reviewed_profile_id) {
            return Err(SessionError::InvalidReviewedProfileId);
        }
        let mut descriptor_numbers = BTreeSet::new();
        let mut purposes = BTreeSet::new();
        for descriptor in &self.admitted_descriptors {
            let is_dedicated_stdout_candidate_sink = descriptor.descriptor == 1
                && descriptor.purpose == DescriptorPurposeV1::CandidateSink
                && descriptor.access == DescriptorAccessV1::WriteOnly;
            if (descriptor.descriptor <= 2 && !is_dedicated_stdout_candidate_sink)
                || !descriptor_numbers.insert(descriptor.descriptor)
                || !purposes.insert(descriptor.purpose)
            {
                return Err(SessionError::InvalidDescriptorManifest);
            }
            let expected_access = match descriptor.purpose {
                DescriptorPurposeV1::SourceSnapshot
                | DescriptorPurposeV1::CandidateIngressCredential
                | DescriptorPurposeV1::CandidateChallenge
                | DescriptorPurposeV1::ProviderResponse => DescriptorAccessV1::ReadOnly,
                DescriptorPurposeV1::ArtifactSink
                | DescriptorPurposeV1::CandidateSink
                | DescriptorPurposeV1::ProviderRequest
                | DescriptorPurposeV1::StatusSink => DescriptorAccessV1::WriteOnly,
            };
            if descriptor.access != expected_access {
                return Err(SessionError::InvalidDescriptorManifest);
            }
        }

        self.validate_principal_binding()?;
        self.validate_provider_route(&purposes)?;
        if matches!(
            self.security_profile,
            SecurityProfileV1::Production | SecurityProfileV1::HighAssurance
        ) && (self.worker.isolation.observed_uid == 0
            || self.worker.isolation.observed_gid == 0
            || self.deadline_unix_ms == 0)
        {
            return Err(SessionError::ProductionIsolationIncomplete);
        }
        Ok(())
    }

    fn validate_principal_binding(&self) -> Result<(), SessionError> {
        let principal = &self.worker.principal;
        if principal.authority_domain != self.authority_domain {
            return Err(SessionError::PrincipalAuthorityDomainMismatch);
        }
        if principal.epoch != self.epoch {
            return Err(SessionError::PrincipalEpochMismatch);
        }
        if principal.session_id != self.session {
            return Err(SessionError::PrincipalSessionMismatch);
        }
        if principal.proposal_workspace_identity != self.proposal_workspace_identity {
            return Err(SessionError::PrincipalWorkspaceMismatch);
        }
        if principal.security_profile_identity != self.security_profile.identity() {
            return Err(SessionError::PrincipalSecurityProfileMismatch);
        }
        if principal.candidate_ingress_key_identity != self.candidate_ingress_key_identity {
            return Err(SessionError::PrincipalCandidateIngressKeyIdentityMismatch);
        }
        if principal.executable != self.worker.isolation.observed_executable {
            return Err(SessionError::PrincipalExecutableMismatch);
        }
        if principal.observed_credentials.uid != self.worker.isolation.observed_uid {
            return Err(SessionError::PrincipalUidMismatch);
        }
        if principal.observed_credentials.gid != self.worker.isolation.observed_gid {
            return Err(SessionError::PrincipalGidMismatch);
        }
        if principal.observed_credentials.pid != self.worker.isolation.observed_pid {
            return Err(SessionError::PrincipalPidMismatch);
        }
        if principal.expires_at_unix_ms != self.deadline_unix_ms {
            return Err(SessionError::PrincipalExpiryMismatch);
        }
        if principal.output_budget_bytes != self.output_budget_bytes
            || self.output_budget_bytes == 0
        {
            return Err(SessionError::PrincipalOutputBudgetMismatch);
        }

        let chain = &self.worker.principal_chain;
        let nodes = chain.nodes();
        let leaf = chain.leaf();
        let parent = nodes.get(nodes.len().saturating_sub(2));
        if chain.authority_domain() != &self.authority_domain
            || chain.epoch() != self.epoch
            || leaf.kind != PrincipalKindV1::WorkerSession
            || leaf.principal_id != principal.id()
            || leaf.parent.as_ref() != Some(&principal.launcher)
            || parent.map(|node| &node.principal_id) != Some(&principal.launcher)
        {
            return Err(SessionError::PrincipalChainMismatch);
        }
        Ok(())
    }

    fn validate_provider_route(
        &self,
        purposes: &BTreeSet<DescriptorPurposeV1>,
    ) -> Result<(), SessionError> {
        let principal = &self.worker.principal;
        let has_provider_request = purposes.contains(&DescriptorPurposeV1::ProviderRequest);
        let has_provider_response = purposes.contains(&DescriptorPurposeV1::ProviderResponse);
        match (&principal.provider_route, &self.provider_capability) {
            (WorkerProviderRouteV1::Offline, None)
                if !has_provider_request && !has_provider_response => {}
            (
                WorkerProviderRouteV1::Constrained {
                    provider_policy_digest,
                    envelope,
                    budget,
                },
                Some(capability),
            ) if has_provider_request && has_provider_response => {
                capability.validate_definition()?;
                if capability.session_id != self.session
                    || capability.authority_domain != self.authority_domain
                    || capability.epoch != self.epoch
                    || capability.project != principal.project
                    || capability.worker_principal != principal.id()
                    || capability.session_nonce != principal.session_nonce
                    || capability.provider_policy_digest != *provider_policy_digest
                    || capability.envelope != *envelope
                    || capability.budget != *budget
                    || capability.expires_at_unix_ms > principal.expires_at_unix_ms
                {
                    return Err(SessionError::CapabilityContextMismatch);
                }
            }
            _ => return Err(SessionError::ProviderRouteMismatch),
        }
        Ok(())
    }
}

/// Candidate bytes held by the governor before canonical proposal construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCandidateCustodyV1 {
    /// Broker-computed content identity.
    pub content: Digest,
    /// Exact broker-observed byte length.
    pub byte_length: u64,
    /// Closed candidate semantic type.
    pub semantic_type: String,
    /// Optional path-free workspace delta description.
    pub workspace_delta: Option<WorkspaceDeltaV1>,
    /// Digest of the exact opaque authenticated ingress proof blob.
    pub ingress_proof: Digest,
    /// Canonical binding of every candidate field above.
    pub custody_record: Digest,
}

impl WorkerCandidateCustodyV1 {
    /// Constructs broker-owned candidate custody.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty semantic type or failed canonicalization.
    pub fn new(
        content: Digest,
        byte_length: u64,
        semantic_type: impl Into<String>,
        workspace_delta: Option<WorkspaceDeltaV1>,
        ingress_proof: Digest,
    ) -> Result<Self, SessionError> {
        let semantic_type = semantic_type.into();
        validate_candidate_semantic_type(&semantic_type)?;
        let custody_record = candidate_custody_digest(
            &content,
            byte_length,
            &semantic_type,
            workspace_delta.as_ref(),
            &ingress_proof,
        )?;
        Ok(Self {
            content,
            byte_length,
            semantic_type,
            workspace_delta,
            ingress_proof,
            custody_record,
        })
    }

    /// Revalidates broker-owned candidate custody.
    ///
    /// # Errors
    ///
    /// Returns an error if the semantic type or canonical binding differs.
    pub fn verify(&self) -> Result<(), SessionError> {
        validate_candidate_semantic_type(&self.semantic_type)?;
        let observed = candidate_custody_digest(
            &self.content,
            self.byte_length,
            &self.semantic_type,
            self.workspace_delta.as_ref(),
            &self.ingress_proof,
        )?;
        if observed != self.custody_record {
            return Err(SessionError::CandidateCustodyMismatch);
        }
        Ok(())
    }
}

/// Durable candidate custody and broker-forwarding state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerCandidateCustodyStateV1 {
    /// No complete candidate has entered governor custody.
    Awaiting,
    /// Complete candidate bytes are in immutable governor custody.
    InCustody {
        /// Exact candidate custody record.
        candidate: WorkerCandidateCustodyV1,
    },
    /// The broker durably returned one terminal outcome through its normal path.
    BrokerCompleted {
        /// Exact candidate presented to the broker.
        candidate: WorkerCandidateCustodyV1,
        /// Exact closed terminal result returned by the broker.
        outcome: WorkerCandidateBrokerOutcomeV1,
    },
}

/// Closed terminal result of forwarding a worker candidate to the effect broker.
///
/// The session store commits identities of the broker-owned records rather
/// than importing their schemas or treating their serialized bytes as
/// authority. The referenced records remain in their owning durable stores.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerCandidateBrokerOutcomeV1 {
    /// The broker created one canonical proposal through its normal path.
    Canonicalized {
        /// Broker-owned canonical proposal identity.
        canonical_proposal: Digest,
    },
    /// The broker semantically refused the governed intent.
    Refused {
        /// Identity of the exact broker-owned refusal record.
        refusal: Digest,
    },
    /// The broker boundary could not establish a semantic outcome.
    Indeterminate {
        /// Identity of the exact broker-owned reconciliation envelope.
        envelope: Digest,
    },
}

/// Closed refusal emitted while authenticating candidate ingress.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerCandidateRefusalCodeV1 {
    /// Candidate framing or canonical encoding was malformed.
    MalformedFrame,
    /// Candidate authentication failed.
    AuthenticationFailed,
    /// The live peer or durable principal binding differed.
    PrincipalBindingMismatch,
    /// Candidate semantics differed from the reviewed launch profile.
    ReviewedProfileMismatch,
    /// The worker principal reached its exclusive deadline.
    Expired,
}

/// Typed reason that permanently retires a worker principal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerTerminationReasonV1 {
    /// A complete candidate entered governor custody.
    CandidateAccepted,
    /// Candidate ingress was refused before custody.
    CandidateRefused {
        /// Closed refusal code suitable for durable policy and audit handling.
        code: WorkerCandidateRefusalCodeV1,
    },
    /// The fixed launch failed before useful worker execution.
    LaunchFailed {
        /// Exact failure evidence.
        failure: Digest,
    },
    /// The launched worker exited abnormally.
    WorkerFailed {
        /// Exact failure evidence.
        failure: Digest,
    },
    /// The principal reached its exclusive deadline.
    DeadlineExpired,
    /// Candidate output exceeded its bound.
    OutputBudgetExceeded {
        /// Bytes observed when the bound was crossed.
        observed_bytes: u64,
    },
    /// A governor-authorized cancellation occurred.
    Cancelled {
        /// Exact cancellation reason/evidence.
        reason_digest: Digest,
    },
    /// Startup found a principal that was active before daemon restart.
    RestartRecovery,
    /// The worker boundary outcome requires explicit reconciliation.
    BoundaryIndeterminate {
        /// Exact operational evidence envelope.
        envelope: Digest,
    },
}

/// Durable fact that immediately fences all further worker ingress.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPrincipalTombstoneV1 {
    /// Exact retired principal.
    pub principal_id: PrincipalId,
    /// Exact non-reusable session record.
    pub session_id: SessionId,
    /// Exact retired session lifecycle.
    pub session_nonce: ag_primitives::LifecycleNonce,
    /// Closed terminal reason.
    pub reason: WorkerTerminationReasonV1,
    /// Time at which the ingress fence became durable, Unix milliseconds.
    pub terminal_since_unix_ms: u64,
}

/// Crash-resumable process/provider cleanup behind a durable tombstone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerCleanupStateV1 {
    /// Ingress is fenced; process exit/provider revocation still needs proof.
    Pending,
    /// Every configured cleanup obligation completed.
    Complete {
        /// Exact process-exit and provider-revocation aggregate receipt.
        receipt: Digest,
        /// Trusted completion time, Unix milliseconds.
        completed_at_unix_ms: u64,
    },
}

/// Durable authority state for a non-reusable worker principal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerAuthorityStateV1 {
    /// Reviewed specification is durable but no worker may submit yet.
    Prepared,
    /// The exact launched worker may submit one bounded candidate.
    Active {
        /// Descriptor-bound launch evidence.
        launch_receipt: Digest,
    },
    /// Ingress is permanently fenced; cleanup may still be resumed.
    Tombstoned {
        /// Launch evidence retained from the active state, or `None` if the
        /// principal was fenced before launch.
        launch_receipt: Option<Digest>,
        /// Durable terminal principal fact.
        tombstone: WorkerPrincipalTombstoneV1,
        /// Crash-resumable cleanup progress.
        cleanup: WorkerCleanupStateV1,
    },
}

/// Closed worker-record lifecycle events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerSessionEventV1 {
    /// Admit the exact launched worker after durable binding.
    Activate {
        /// Descriptor-bound launch evidence.
        launch_receipt: Digest,
    },
    /// Permanently fence a principal without accepting candidate bytes.
    Tombstone {
        /// Exact terminal fact.
        tombstone: WorkerPrincipalTombstoneV1,
    },
    /// Atomically accept candidate custody and fence its producer.
    AcceptCandidate {
        /// Exact broker-owned candidate custody.
        candidate: WorkerCandidateCustodyV1,
        /// Candidate-accepted tombstone committed in the same transition.
        tombstone: WorkerPrincipalTombstoneV1,
    },
    /// Complete cleanup behind an existing tombstone.
    CompleteCleanup {
        /// Exact aggregate cleanup receipt.
        receipt: Digest,
        /// Trusted completion time, Unix milliseconds.
        completed_at_unix_ms: u64,
    },
    /// Record the terminal result returned by the normal broker path.
    RecordBrokerOutcome {
        /// Exact closed broker result.
        outcome: WorkerCandidateBrokerOutcomeV1,
    },
}

/// Trusted live facts supplied by the launcher-owned ingress boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerIngressContextV1 {
    /// Active installation domain.
    pub authority_domain: AuthorityDomain,
    /// Active installation epoch.
    pub epoch: Epoch,
    /// Principal resolved from the launcher-owned live channel.
    pub principal_id: PrincipalId,
    /// Session resolved from durable principal indexing.
    pub session_id: SessionId,
    /// Workspace resolved from the launcher-held workspace descriptor.
    pub proposal_workspace_identity: Digest,
    /// Security profile resolved from reviewed launch state.
    pub security_profile_identity: Digest,
    /// Executable identity resolved from the retained launch object.
    pub executable: ExecutableIdentityV1,
    /// Launcher-retained host UID observation captured before release.
    pub observed_uid: u32,
    /// Launcher-retained host GID observation captured before release.
    pub observed_gid: u32,
    /// Trusted ingress time, Unix milliseconds.
    pub now_unix_ms: u64,
}

/// Durable aggregate for one worker session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSessionRecordV1 {
    /// Exact record schema.
    pub schema: String,
    /// Immutable reviewed session specification.
    pub spec: BatchSessionSpecV1,
    /// Principal authority lifecycle.
    pub authority: WorkerAuthorityStateV1,
    /// Candidate custody lifecycle.
    pub candidate: WorkerCandidateCustodyStateV1,
}

impl WorkerSessionRecordV1 {
    /// Constructs a prepared durable worker record.
    ///
    /// # Errors
    ///
    /// Returns an error unless the immutable session specification is valid.
    pub fn new(spec: BatchSessionSpecV1) -> Result<Self, SessionError> {
        let record = Self {
            schema: WORKER_SESSION_RECORD_SCHEMA_V1.to_owned(),
            spec,
            authority: WorkerAuthorityStateV1::Prepared,
            candidate: WorkerCandidateCustodyStateV1::Awaiting,
        };
        record.validate()?;
        Ok(record)
    }

    /// Revalidates every durable record binding.
    ///
    /// # Errors
    ///
    /// Returns a typed error for schema, spec, tombstone, custody, or lifecycle
    /// disagreement.
    pub fn validate(&self) -> Result<(), SessionError> {
        if self.schema != WORKER_SESSION_RECORD_SCHEMA_V1 {
            return Err(SessionError::UnknownWorkerRecordSchema(self.schema.clone()));
        }
        self.spec.validate()?;
        if let WorkerAuthorityStateV1::Tombstoned { tombstone, .. } = &self.authority {
            self.validate_tombstone(tombstone)?;
        }
        let custody = match &self.candidate {
            WorkerCandidateCustodyStateV1::Awaiting => None,
            WorkerCandidateCustodyStateV1::InCustody { candidate }
            | WorkerCandidateCustodyStateV1::BrokerCompleted { candidate, .. } => Some(candidate),
        };
        if let Some(candidate) = custody {
            candidate.verify()?;
            if candidate.byte_length > self.spec.output_budget_bytes {
                return Err(SessionError::CandidateBudgetExceeded);
            }
            let WorkerAuthorityStateV1::Tombstoned {
                launch_receipt: Some(_),
                tombstone,
                ..
            } = &self.authority
            else {
                return Err(SessionError::CandidateRequiresTombstone);
            };
            if tombstone.reason != WorkerTerminationReasonV1::CandidateAccepted {
                return Err(SessionError::CandidateRequiresTombstone);
            }
        }
        Ok(())
    }

    /// Validates a launcher-authenticated live ingress connection.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal unless the principal is active, unexpired, and
    /// exactly matches every trusted live binding.
    pub fn validate_active_ingress(
        &self,
        context: &WorkerIngressContextV1,
    ) -> Result<(), SessionError> {
        self.validate()?;
        match self.authority {
            WorkerAuthorityStateV1::Prepared => return Err(SessionError::PrincipalNotActive),
            WorkerAuthorityStateV1::Tombstoned { .. } => {
                return Err(SessionError::PrincipalTombstoned);
            }
            WorkerAuthorityStateV1::Active { .. } => {}
        }
        let principal = &self.spec.worker.principal;
        if context.authority_domain != self.spec.authority_domain {
            return Err(SessionError::IngressAuthorityDomainMismatch);
        }
        if context.epoch != self.spec.epoch {
            return Err(SessionError::IngressEpochMismatch);
        }
        if context.principal_id != principal.id() {
            return Err(SessionError::IngressPrincipalMismatch);
        }
        if context.session_id != self.spec.session {
            return Err(SessionError::IngressSessionMismatch);
        }
        if context.proposal_workspace_identity != principal.proposal_workspace_identity {
            return Err(SessionError::IngressWorkspaceMismatch);
        }
        if context.security_profile_identity != principal.security_profile_identity {
            return Err(SessionError::IngressSecurityProfileMismatch);
        }
        if context.executable != principal.executable {
            return Err(SessionError::IngressExecutableMismatch);
        }
        if context.observed_uid != principal.observed_credentials.uid {
            return Err(SessionError::IngressUidMismatch);
        }
        if context.observed_gid != principal.observed_credentials.gid {
            return Err(SessionError::IngressGidMismatch);
        }
        if context.now_unix_ms >= principal.expires_at_unix_ms {
            return Err(SessionError::PrincipalExpired);
        }
        Ok(())
    }

    /// Applies one legal durable worker lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns a typed error for post-tombstone activation/candidate ingress,
    /// duplicate cleanup, invalid custody, or a mismatched tombstone.
    pub fn apply(mut self, event: WorkerSessionEventV1) -> Result<Self, SessionError> {
        match event {
            WorkerSessionEventV1::Activate { launch_receipt }
                if matches!(self.authority, WorkerAuthorityStateV1::Prepared) =>
            {
                self.authority = WorkerAuthorityStateV1::Active { launch_receipt };
            }
            WorkerSessionEventV1::Tombstone { tombstone } => {
                let launch_receipt = match &self.authority {
                    WorkerAuthorityStateV1::Prepared => None,
                    WorkerAuthorityStateV1::Active { launch_receipt } => {
                        Some(launch_receipt.clone())
                    }
                    WorkerAuthorityStateV1::Tombstoned { .. } => {
                        return Err(SessionError::InvalidWorkerTransition);
                    }
                };
                self.validate_tombstone(&tombstone)?;
                self.authority = WorkerAuthorityStateV1::Tombstoned {
                    launch_receipt,
                    tombstone,
                    cleanup: WorkerCleanupStateV1::Pending,
                };
            }
            WorkerSessionEventV1::AcceptCandidate {
                candidate,
                tombstone,
            } => {
                let WorkerAuthorityStateV1::Active { launch_receipt } = &self.authority else {
                    return Err(SessionError::InvalidWorkerTransition);
                };
                if !matches!(self.candidate, WorkerCandidateCustodyStateV1::Awaiting) {
                    return Err(SessionError::InvalidWorkerTransition);
                }
                let launch_receipt = launch_receipt.clone();
                candidate.verify()?;
                if candidate.byte_length > self.spec.output_budget_bytes {
                    return Err(SessionError::CandidateBudgetExceeded);
                }
                self.validate_tombstone(&tombstone)?;
                if tombstone.reason != WorkerTerminationReasonV1::CandidateAccepted {
                    return Err(SessionError::CandidateRequiresTombstone);
                }
                self.authority = WorkerAuthorityStateV1::Tombstoned {
                    launch_receipt: Some(launch_receipt),
                    tombstone,
                    cleanup: WorkerCleanupStateV1::Pending,
                };
                self.candidate = WorkerCandidateCustodyStateV1::InCustody { candidate };
            }
            WorkerSessionEventV1::CompleteCleanup {
                receipt,
                completed_at_unix_ms,
            } => {
                let WorkerAuthorityStateV1::Tombstoned { cleanup, .. } = &mut self.authority else {
                    return Err(SessionError::InvalidWorkerTransition);
                };
                if !matches!(cleanup, WorkerCleanupStateV1::Pending) {
                    return Err(SessionError::InvalidWorkerTransition);
                }
                *cleanup = WorkerCleanupStateV1::Complete {
                    receipt,
                    completed_at_unix_ms,
                };
            }
            WorkerSessionEventV1::RecordBrokerOutcome { outcome } => match &self.candidate {
                WorkerCandidateCustodyStateV1::InCustody { candidate } => {
                    self.candidate = WorkerCandidateCustodyStateV1::BrokerCompleted {
                        candidate: candidate.clone(),
                        outcome,
                    };
                }
                WorkerCandidateCustodyStateV1::BrokerCompleted {
                    outcome: existing, ..
                } if *existing == outcome => {}
                WorkerCandidateCustodyStateV1::BrokerCompleted { .. } => {
                    return Err(SessionError::CandidateBrokerOutcomeConflict);
                }
                WorkerCandidateCustodyStateV1::Awaiting => {
                    return Err(SessionError::InvalidWorkerTransition);
                }
            },
            WorkerSessionEventV1::Activate { .. } => {
                return Err(SessionError::InvalidWorkerTransition);
            }
        }
        self.validate()?;
        Ok(self)
    }

    fn validate_tombstone(
        &self,
        tombstone: &WorkerPrincipalTombstoneV1,
    ) -> Result<(), SessionError> {
        let principal = &self.spec.worker.principal;
        if tombstone.principal_id != principal.id()
            || tombstone.session_id != self.spec.session
            || tombstone.session_nonce != principal.session_nonce
        {
            return Err(SessionError::TombstoneBindingMismatch);
        }
        Ok(())
    }
}

fn candidate_custody_digest(
    content: &Digest,
    byte_length: u64,
    semantic_type: &str,
    workspace_delta: Option<&WorkspaceDeltaV1>,
    ingress_proof: &Digest,
) -> Result<Digest, SessionError> {
    #[derive(Serialize)]
    struct CandidateBinding<'a> {
        content: &'a Digest,
        byte_length: u64,
        semantic_type: &'a str,
        workspace_delta: Option<&'a WorkspaceDeltaV1>,
        ingress_proof: &'a Digest,
    }
    Digest::from_serializable(&CandidateBinding {
        content,
        byte_length,
        semantic_type,
        workspace_delta,
        ingress_proof,
    })
    .map_err(|error| SessionError::CandidateCustodyBinding(error.to_string()))
}

fn validate_candidate_semantic_type(value: &str) -> Result<(), SessionError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_' | b'/')
        })
    {
        return Err(SessionError::InvalidCandidateSemanticType);
    }
    Ok(())
}

fn valid_reviewed_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Durable batch lifecycle. Interactive/pause/resume edges do not exist.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionStateV1 {
    /// Specification accepted but worker not launched.
    Created,
    /// Launcher proved isolation and bound the live worker.
    Running {
        /// Launch evidence.
        launch_receipt: Digest,
    },
    /// Worker completed and outputs are in governor custody.
    Completed {
        /// Exact worker result record.
        result: Digest,
    },
    /// Worker failed with known terminal status.
    Failed {
        /// Exact failure record.
        failure: Digest,
    },
    /// Governor terminated the worker and burned its provider capability.
    Terminated {
        /// Exact termination/revocation record.
        receipt: Digest,
    },
    /// Boundary outcome is unknowable and needs reconciliation.
    Indeterminate {
        /// Operational evidence envelope.
        envelope: Digest,
    },
}

/// Durable session lifecycle events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEventV1 {
    /// Bind launched worker.
    Launched {
        /// Exact admitted-helper launch receipt.
        launch_receipt: Digest,
    },
    /// Commit complete results.
    WorkerCompleted {
        /// Exact terminal worker result in session custody.
        result: Digest,
    },
    /// Commit known failure.
    WorkerFailed {
        /// Exact terminal worker failure evidence.
        failure: Digest,
    },
    /// Kill worker and revoke capability.
    Terminate {
        /// Exact session-termination and capability-burn receipt.
        receipt: Digest,
    },
    /// Record unknown boundary outcome.
    BoundaryIndeterminate {
        /// Operational envelope requiring explicit reconciliation.
        envelope: Digest,
    },
}

impl SessionStateV1 {
    /// Applies a legal batch lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns an error for any interactive, retry, post-terminal, or
    /// otherwise unsupported state transition.
    pub fn apply(self, event: SessionEventV1) -> Result<Self, SessionError> {
        match (self, event) {
            (Self::Created, SessionEventV1::Launched { launch_receipt }) => {
                Ok(Self::Running { launch_receipt })
            }
            (Self::Running { .. }, SessionEventV1::WorkerCompleted { result }) => {
                Ok(Self::Completed { result })
            }
            (Self::Running { .. }, SessionEventV1::WorkerFailed { failure }) => {
                Ok(Self::Failed { failure })
            }
            (Self::Created | Self::Running { .. }, SessionEventV1::Terminate { receipt }) => {
                Ok(Self::Terminated { receipt })
            }
            (Self::Running { .. }, SessionEventV1::BoundaryIndeterminate { envelope }) => {
                Ok(Self::Indeterminate { envelope })
            }
            (state, event) => Err(SessionError::InvalidTransition {
                state: format!("{state:?}"),
                event: format!("{event:?}"),
            }),
        }
    }
}

/// Session-model errors.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SessionError {
    /// Schema is not understood.
    #[error("unknown session schema: {0}")]
    UnknownSchema(String),
    /// Reviewed launch-profile identifier is empty, unbounded, or unsafe.
    #[error("reviewed worker profile identifier is invalid")]
    InvalidReviewedProfileId,
    /// Durable worker-record schema is not understood.
    #[error("unknown worker-session record schema: {0}")]
    UnknownWorkerRecordSchema(String),
    /// Descriptor numbers, directions, or purposes are unsafe.
    #[error("invalid admitted descriptor manifest")]
    InvalidDescriptorManifest,
    /// Provider capability was used by the wrong live peer/context.
    #[error("provider capability context mismatch")]
    CapabilityContextMismatch,
    /// Provider capability definition is intrinsically invalid.
    #[error(transparent)]
    ProviderCapabilityDefinition(#[from] CapabilityDefinitionError),
    /// Offline/constrained provider policy disagrees with capability or FDs.
    #[error("worker provider route does not match capability and descriptor policy")]
    ProviderRouteMismatch,
    /// Worker principal belongs to a different authority domain.
    #[error("worker principal authority domain does not match session")]
    PrincipalAuthorityDomainMismatch,
    /// Worker principal belongs to a different authority epoch.
    #[error("worker principal epoch does not match session")]
    PrincipalEpochMismatch,
    /// Worker principal belongs to another session record.
    #[error("worker principal session does not match")]
    PrincipalSessionMismatch,
    /// Worker principal is bound to another proposal workspace.
    #[error("worker principal proposal workspace does not match")]
    PrincipalWorkspaceMismatch,
    /// Worker principal is bound to another security profile.
    #[error("worker principal security profile does not match")]
    PrincipalSecurityProfileMismatch,
    /// Worker principal is bound to another candidate signing-key identity.
    #[error("worker principal candidate ingress key identity does not match")]
    PrincipalCandidateIngressKeyIdentityMismatch,
    /// Descriptor-bound executable observation differs from the principal.
    #[error("worker executable observation does not match principal")]
    PrincipalExecutableMismatch,
    /// Kernel-observed UID differs from the principal.
    #[error("worker UID observation does not match principal")]
    PrincipalUidMismatch,
    /// Kernel-observed GID differs from the principal.
    #[error("worker GID observation does not match principal")]
    PrincipalGidMismatch,
    /// Kernel-observed PID differs from the principal.
    #[error("worker PID observation does not match principal")]
    PrincipalPidMismatch,
    /// Principal and session deadline differ.
    #[error("worker principal expiry does not match session deadline")]
    PrincipalExpiryMismatch,
    /// Principal and session output budget differ or are empty.
    #[error("worker principal output budget does not match session")]
    PrincipalOutputBudgetMismatch,
    /// Principal chain does not terminate in the exact worker/launcher pair.
    #[error("worker principal chain binding does not match")]
    PrincipalChainMismatch,
    /// Exact custody fields cannot be canonicalized.
    #[error("provider custody binding cannot be canonicalized: {0}")]
    CustodyBinding(String),
    /// Custody record does not match its exact request fields.
    #[error("provider request custody record mismatch")]
    CustodyMismatch,
    /// Production isolation evidence is incomplete.
    #[error("production isolation evidence is incomplete")]
    ProductionIsolationIncomplete,
    /// Candidate semantic type is empty, unbounded, or noncanonical.
    #[error("worker candidate semantic type is invalid")]
    InvalidCandidateSemanticType,
    /// Candidate custody fields cannot be canonicalized.
    #[error("worker candidate custody cannot be canonicalized: {0}")]
    CandidateCustodyBinding(String),
    /// Candidate custody record does not bind its exact fields.
    #[error("worker candidate custody record mismatch")]
    CandidateCustodyMismatch,
    /// Candidate bytes exceed the principal/session output bound.
    #[error("worker candidate exceeds the output budget")]
    CandidateBudgetExceeded,
    /// Candidate custody exists without a candidate-accepted tombstone.
    #[error("worker candidate custody requires a candidate-accepted tombstone")]
    CandidateRequiresTombstone,
    /// A broker retry disagrees with the already committed terminal outcome.
    #[error("worker candidate broker outcome conflicts with durable terminal outcome")]
    CandidateBrokerOutcomeConflict,
    /// Tombstone does not bind the exact principal/session lifecycle.
    #[error("worker principal tombstone binding mismatch")]
    TombstoneBindingMismatch,
    /// Reviewed principal has not reached its active launch state.
    #[error("worker principal is not active")]
    PrincipalNotActive,
    /// Durable terminal state permanently refuses late ingress.
    #[error("worker principal is tombstoned")]
    PrincipalTombstoned,
    /// Principal has reached its exclusive expiry.
    #[error("worker principal is expired")]
    PrincipalExpired,
    /// Trusted live ingress domain differs.
    #[error("worker ingress authority domain does not match")]
    IngressAuthorityDomainMismatch,
    /// Trusted live ingress epoch differs.
    #[error("worker ingress epoch does not match")]
    IngressEpochMismatch,
    /// Authenticated live principal differs.
    #[error("worker ingress principal does not match")]
    IngressPrincipalMismatch,
    /// Durable principal index resolved another session.
    #[error("worker ingress session does not match")]
    IngressSessionMismatch,
    /// Launcher-held workspace descriptor differs.
    #[error("worker ingress proposal workspace does not match")]
    IngressWorkspaceMismatch,
    /// Reviewed live security profile differs.
    #[error("worker ingress security profile does not match")]
    IngressSecurityProfileMismatch,
    /// Retained executable object differs.
    #[error("worker ingress executable does not match")]
    IngressExecutableMismatch,
    /// Kernel peer UID differs.
    #[error("worker ingress UID does not match")]
    IngressUidMismatch,
    /// Kernel peer GID differs.
    #[error("worker ingress GID does not match")]
    IngressGidMismatch,
    /// Durable worker-record lifecycle edge is forbidden.
    #[error("invalid durable worker-session transition")]
    InvalidWorkerTransition,
    /// Lifecycle edge is forbidden.
    #[error("invalid session transition from {state} using {event}")]
    InvalidTransition {
        /// Prior state.
        state: String,
        /// Attempted event.
        event: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_primitives::{
        CgroupIdentity, InferenceBudgetV1, InferenceCapabilityV1, InferenceEnvelopeV1,
        InferenceMethodId, LaunchProfileIdentityV1, LifecycleNonce, ModelId, PrincipalChainNodeV1,
        ProjectId, ProviderEndpointId,
    };

    fn digest(label: &str) -> Digest {
        Digest::hash_bytes(label.as_bytes())
    }

    fn fixture_spec() -> BatchSessionSpecV1 {
        let authority_domain = AuthorityDomain::new("site:prod").unwrap();
        let epoch = Epoch::new(7).unwrap();
        let session = SessionId::new("session-42").unwrap();
        let launcher = PrincipalId::new(digest("agd-instance"));
        let executable = ExecutableIdentityV1::new(digest("fixture-worker"), 4096, None);
        let proposal_workspace_identity = digest("proposal-workspace");
        let principal = WorkerSessionPrincipalV1 {
            authority_domain: authority_domain.clone(),
            epoch,
            project: ProjectId::new("project-alpha").unwrap(),
            session_id: session.clone(),
            session_nonce: LifecycleNonce::new([4; 16]),
            launcher: launcher.clone(),
            executable: executable.clone(),
            launch_profile: LaunchProfileIdentityV1::new(
                digest("launch-profile"),
                digest("worker-protocol"),
            ),
            proposal_workspace_identity: proposal_workspace_identity.clone(),
            security_profile_identity: SecurityProfileV1::Development.identity(),
            candidate_ingress_key_identity: digest("candidate-ingress-key-identity"),
            expires_at_unix_ms: 200,
            output_budget_bytes: 1024,
            provider_route: WorkerProviderRouteV1::Offline,
            input_set_digest: digest("input-set"),
            observed_credentials: ag_primitives::HostCredentialObservationV1 {
                uid: 901,
                gid: 902,
                pid: 903,
                cgroup: CgroupIdentity::new("worker-session-42.scope").unwrap(),
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
        BatchSessionSpecV1 {
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
            proposal_workspace_identity,
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
            deadline_unix_ms: 200,
            output_budget_bytes: 1024,
        }
    }

    fn rebind_chain(spec: &mut BatchSessionSpecV1) {
        let launcher = spec.worker.principal.launcher.clone();
        spec.worker.principal_chain = PrincipalChainV1::new(
            spec.authority_domain.clone(),
            spec.epoch,
            vec![
                PrincipalChainNodeV1::root(launcher.clone(), PrincipalKindV1::Daemon),
                PrincipalChainNodeV1::child(
                    spec.worker.principal.id(),
                    PrincipalKindV1::WorkerSession,
                    launcher,
                ),
            ],
        )
        .unwrap();
    }

    fn ingress_context(spec: &BatchSessionSpecV1, now_unix_ms: u64) -> WorkerIngressContextV1 {
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

    fn tombstone(
        spec: &BatchSessionSpecV1,
        reason: WorkerTerminationReasonV1,
    ) -> WorkerPrincipalTombstoneV1 {
        WorkerPrincipalTombstoneV1 {
            principal_id: spec.worker.principal.id(),
            session_id: spec.session.clone(),
            session_nonce: spec.worker.principal.session_nonce,
            reason,
            terminal_since_unix_ms: 150,
        }
    }

    fn fixture_candidate_in_custody() -> WorkerSessionRecordV1 {
        let spec = fixture_spec();
        WorkerSessionRecordV1::new(spec.clone())
            .unwrap()
            .apply(WorkerSessionEventV1::Activate {
                launch_receipt: digest("launch-receipt"),
            })
            .unwrap()
            .apply(WorkerSessionEventV1::AcceptCandidate {
                candidate: WorkerCandidateCustodyV1::new(
                    digest("candidate"),
                    512,
                    "workspace_delta_v1",
                    None,
                    digest("ingress-proof"),
                )
                .unwrap(),
                tombstone: tombstone(&spec, WorkerTerminationReasonV1::CandidateAccepted),
            })
            .unwrap()
    }

    #[test]
    fn identifiers_cannot_smuggle_paths() {
        assert!(SessionId::parse("session-42").is_ok());
        assert!(SessionId::parse("../../root").is_err());
    }

    #[test]
    fn digest_only_provider_records_are_explicitly_weak() {
        let record = ProviderCustodyV1::DigestOnlyWeak {
            request_digest: Digest::hash_bytes(b"request"),
            response_digest: Digest::hash_bytes(b"response"),
        };
        assert!(!record.is_replayable());
    }

    #[test]
    fn completed_sessions_cannot_resume() {
        let state = SessionStateV1::Completed {
            result: Digest::hash_bytes(b"done"),
        };
        assert!(
            state
                .apply(SessionEventV1::Launched {
                    launch_receipt: Digest::hash_bytes(b"again"),
                })
                .is_err()
        );
    }

    #[test]
    fn offline_spec_cross_binds_principal_chain_workspace_executable_and_credentials() {
        let spec = fixture_spec();
        spec.validate().unwrap();

        let mut wrong = spec.clone();
        wrong.worker.isolation.observed_gid += 1;
        assert_eq!(wrong.validate(), Err(SessionError::PrincipalGidMismatch));

        let mut wrong = spec.clone();
        wrong.worker.isolation.observed_executable.size += 1;
        assert_eq!(
            wrong.validate(),
            Err(SessionError::PrincipalExecutableMismatch)
        );

        let mut wrong = spec.clone();
        wrong.proposal_workspace_identity = digest("other-workspace");
        assert_eq!(
            wrong.validate(),
            Err(SessionError::PrincipalWorkspaceMismatch)
        );

        let mut wrong = spec.clone();
        wrong.candidate_ingress_key_identity = digest("other-ingress-key");
        assert_eq!(
            wrong.validate(),
            Err(SessionError::PrincipalCandidateIngressKeyIdentityMismatch)
        );

        let mut wrong = spec.clone();
        wrong.reviewed_profile_id = "../worker".to_owned();
        assert_eq!(
            wrong.validate(),
            Err(SessionError::InvalidReviewedProfileId)
        );

        let mut wrong = spec;
        let launcher = wrong.worker.principal.launcher.clone();
        wrong.worker.principal_chain = PrincipalChainV1::new(
            wrong.authority_domain.clone(),
            wrong.epoch,
            vec![
                PrincipalChainNodeV1::root(launcher.clone(), PrincipalKindV1::Daemon),
                PrincipalChainNodeV1::child(
                    PrincipalId::new(digest("forged-worker")),
                    PrincipalKindV1::WorkerSession,
                    launcher,
                ),
            ],
        )
        .unwrap();
        assert_eq!(wrong.validate(), Err(SessionError::PrincipalChainMismatch));
    }

    #[test]
    fn provider_route_is_explicit_and_exactly_bound_without_hash_cycle() {
        let mut spec = fixture_spec();
        let envelope = InferenceEnvelopeV1 {
            endpoint: ProviderEndpointId::new("fixture:proxy").unwrap(),
            model: ModelId::new("fixture-model").unwrap(),
            method: InferenceMethodId::new("complete").unwrap(),
            protocol_digest: digest("fixture-protocol"),
        };
        let budget = InferenceBudgetV1 {
            requests: 2,
            input_bytes: 4096,
            output_bytes: 8192,
            cost_microunits: 10,
        };
        let policy = digest("provider-policy");
        spec.worker.principal.provider_route = WorkerProviderRouteV1::Constrained {
            provider_policy_digest: policy.clone(),
            envelope: envelope.clone(),
            budget,
        };
        rebind_chain(&mut spec);
        let principal_id = spec.worker.principal.id();
        spec.provider_capability = Some(
            InferenceCapabilityV1::new(
                spec.authority_domain.clone(),
                spec.epoch,
                spec.worker.principal.project.clone(),
                spec.session.clone(),
                spec.worker.principal.session_nonce,
                principal_id,
                policy,
                envelope,
                budget,
                100,
                spec.deadline_unix_ms,
                LifecycleNonce::new([8; 16]),
            )
            .unwrap(),
        );
        spec.admitted_descriptors.extend([
            AdmittedDescriptorV1 {
                descriptor: 5,
                purpose: DescriptorPurposeV1::ProviderRequest,
                access: DescriptorAccessV1::WriteOnly,
                object_identity: digest("provider-request-fd"),
            },
            AdmittedDescriptorV1 {
                descriptor: 6,
                purpose: DescriptorPurposeV1::ProviderResponse,
                access: DescriptorAccessV1::ReadOnly,
                object_identity: digest("provider-response-fd"),
            },
        ]);
        spec.validate().unwrap();

        spec.provider_capability.as_mut().unwrap().project =
            ProjectId::new("other-project").unwrap();
        assert_eq!(
            spec.validate(),
            Err(SessionError::CapabilityContextMismatch)
        );
    }

    #[test]
    fn offline_mode_rejects_provider_capability_or_channel_descriptors() {
        let mut spec = fixture_spec();
        spec.admitted_descriptors.push(AdmittedDescriptorV1 {
            descriptor: 5,
            purpose: DescriptorPurposeV1::ProviderRequest,
            access: DescriptorAccessV1::WriteOnly,
            object_identity: digest("provider-request-fd"),
        });
        assert_eq!(spec.validate(), Err(SessionError::ProviderRouteMismatch));
    }

    #[test]
    fn candidate_ingress_descriptor_roles_have_exact_closed_directions() {
        let mut spec = fixture_spec();
        spec.admitted_descriptors.extend([
            AdmittedDescriptorV1 {
                descriptor: 5,
                purpose: DescriptorPurposeV1::CandidateIngressCredential,
                access: DescriptorAccessV1::ReadOnly,
                object_identity: digest("candidate-credential-fd"),
            },
            AdmittedDescriptorV1 {
                descriptor: 6,
                purpose: DescriptorPurposeV1::CandidateChallenge,
                access: DescriptorAccessV1::ReadOnly,
                object_identity: digest("candidate-challenge-fd"),
            },
            AdmittedDescriptorV1 {
                descriptor: 1,
                purpose: DescriptorPurposeV1::CandidateSink,
                access: DescriptorAccessV1::WriteOnly,
                object_identity: digest("candidate-sink-fd"),
            },
        ]);
        spec.validate().unwrap();

        for purpose in [
            DescriptorPurposeV1::CandidateIngressCredential,
            DescriptorPurposeV1::CandidateChallenge,
        ] {
            let mut wrong = spec.clone();
            wrong
                .admitted_descriptors
                .iter_mut()
                .find(|descriptor| descriptor.purpose == purpose)
                .unwrap()
                .access = DescriptorAccessV1::WriteOnly;
            assert_eq!(
                wrong.validate(),
                Err(SessionError::InvalidDescriptorManifest)
            );
        }

        let mut wrong_sink = spec;
        wrong_sink
            .admitted_descriptors
            .iter_mut()
            .find(|descriptor| descriptor.purpose == DescriptorPurposeV1::CandidateSink)
            .unwrap()
            .access = DescriptorAccessV1::ReadOnly;
        assert_eq!(
            wrong_sink.validate(),
            Err(SessionError::InvalidDescriptorManifest)
        );

        for descriptor in [0, 2] {
            let mut wrong = fixture_spec();
            wrong.admitted_descriptors.push(AdmittedDescriptorV1 {
                descriptor,
                purpose: DescriptorPurposeV1::CandidateSink,
                access: DescriptorAccessV1::WriteOnly,
                object_identity: digest("candidate-sink-standard-fd"),
            });
            assert_eq!(
                wrong.validate(),
                Err(SessionError::InvalidDescriptorManifest)
            );
        }

        let mut wrong_stdout_purpose = fixture_spec();
        wrong_stdout_purpose
            .admitted_descriptors
            .push(AdmittedDescriptorV1 {
                descriptor: 1,
                purpose: DescriptorPurposeV1::StatusSink,
                access: DescriptorAccessV1::WriteOnly,
                object_identity: digest("status-stdout"),
            });
        assert_eq!(
            wrong_stdout_purpose.validate(),
            Err(SessionError::InvalidDescriptorManifest)
        );
    }

    #[test]
    fn active_ingress_revalidates_live_bindings_expiry_and_tombstone() {
        let spec = fixture_spec();
        let context = ingress_context(&spec, 150);
        let record = WorkerSessionRecordV1::new(spec)
            .unwrap()
            .apply(WorkerSessionEventV1::Activate {
                launch_receipt: digest("launch-receipt"),
            })
            .unwrap();
        record.validate_active_ingress(&context).unwrap();

        let mut wrong_uid = context.clone();
        wrong_uid.observed_uid += 1;
        assert_eq!(
            record.validate_active_ingress(&wrong_uid),
            Err(SessionError::IngressUidMismatch)
        );
        let mut mismatched_group = context.clone();
        mismatched_group.observed_gid += 1;
        assert_eq!(
            record.validate_active_ingress(&mismatched_group),
            Err(SessionError::IngressGidMismatch)
        );
        let mut forged_principal = context.clone();
        forged_principal.principal_id = PrincipalId::new(digest("forged-principal"));
        assert_eq!(
            record.validate_active_ingress(&forged_principal),
            Err(SessionError::IngressPrincipalMismatch)
        );
        let mut replayed_session = context.clone();
        replayed_session.session_id = SessionId::new("session-replay").unwrap();
        assert_eq!(
            record.validate_active_ingress(&replayed_session),
            Err(SessionError::IngressSessionMismatch)
        );
        let mut wrong_workspace = context.clone();
        wrong_workspace.proposal_workspace_identity = digest("replayed-workspace");
        assert_eq!(
            record.validate_active_ingress(&wrong_workspace),
            Err(SessionError::IngressWorkspaceMismatch)
        );
        let mut expired = context.clone();
        expired.now_unix_ms = 200;
        assert_eq!(
            record.validate_active_ingress(&expired),
            Err(SessionError::PrincipalExpired)
        );

        let terminal = record
            .apply(WorkerSessionEventV1::Tombstone {
                tombstone: tombstone(&fixture_spec(), WorkerTerminationReasonV1::RestartRecovery),
            })
            .unwrap();
        assert_eq!(
            terminal.validate_active_ingress(&context),
            Err(SessionError::PrincipalTombstoned)
        );
        assert_eq!(
            terminal.apply(WorkerSessionEventV1::Activate {
                launch_receipt: digest("replayed-launch"),
            }),
            Err(SessionError::InvalidWorkerTransition)
        );
    }

    #[test]
    fn candidate_acceptance_atomically_tombstones_and_custody_is_strict() {
        let spec = fixture_spec();
        let candidate = WorkerCandidateCustodyV1::new(
            digest("candidate"),
            512,
            "workspace_delta_v1",
            Some(WorkspaceDeltaV1 {
                base: digest("base"),
                manifest: digest("manifest"),
                content: digest("delta"),
            }),
            digest("ingress-proof"),
        )
        .unwrap();
        let record = WorkerSessionRecordV1::new(spec.clone())
            .unwrap()
            .apply(WorkerSessionEventV1::Activate {
                launch_receipt: digest("launch-receipt"),
            })
            .unwrap()
            .apply(WorkerSessionEventV1::AcceptCandidate {
                candidate: candidate.clone(),
                tombstone: tombstone(&spec, WorkerTerminationReasonV1::CandidateAccepted),
            })
            .unwrap();
        assert!(matches!(
            &record.authority,
            WorkerAuthorityStateV1::Tombstoned {
                launch_receipt: Some(receipt),
                cleanup: WorkerCleanupStateV1::Pending,
                ..
            } if *receipt == digest("launch-receipt")
        ));
        assert!(matches!(
            record.candidate,
            WorkerCandidateCustodyStateV1::InCustody { .. }
        ));

        let completed_cleanup = record
            .apply(WorkerSessionEventV1::CompleteCleanup {
                receipt: digest("cleanup"),
                completed_at_unix_ms: 160,
            })
            .unwrap();
        let completed = completed_cleanup
            .apply(WorkerSessionEventV1::RecordBrokerOutcome {
                outcome: WorkerCandidateBrokerOutcomeV1::Canonicalized {
                    canonical_proposal: digest("canonical-proposal"),
                },
            })
            .unwrap();
        assert!(Digest::from_serializable(&completed).is_ok());

        let mut tampered = candidate;
        tampered.byte_length += 1;
        assert_eq!(
            tampered.verify(),
            Err(SessionError::CandidateCustodyMismatch)
        );

        let mut tampered_proof = WorkerCandidateCustodyV1::new(
            digest("candidate"),
            512,
            "workspace_delta_v1",
            None,
            digest("ingress-proof"),
        )
        .unwrap();
        tampered_proof.ingress_proof = digest("other-ingress-proof");
        assert_eq!(
            tampered_proof.verify(),
            Err(SessionError::CandidateCustodyMismatch)
        );

        let mut missing_launch_evidence = completed;
        let WorkerAuthorityStateV1::Tombstoned { launch_receipt, .. } =
            &mut missing_launch_evidence.authority
        else {
            panic!("accepted candidate must tombstone its principal");
        };
        *launch_receipt = None;
        assert_eq!(
            missing_launch_evidence.validate(),
            Err(SessionError::CandidateRequiresTombstone)
        );
    }

    #[test]
    fn broker_outcomes_are_closed_idempotent_and_conflict_on_changed_replay() {
        let in_custody = fixture_candidate_in_custody();
        let outcomes = [
            WorkerCandidateBrokerOutcomeV1::Canonicalized {
                canonical_proposal: digest("canonical-proposal"),
            },
            WorkerCandidateBrokerOutcomeV1::Refused {
                refusal: digest("refusal"),
            },
            WorkerCandidateBrokerOutcomeV1::Indeterminate {
                envelope: digest("indeterminate"),
            },
        ];
        for outcome in outcomes {
            let event = WorkerSessionEventV1::RecordBrokerOutcome {
                outcome: outcome.clone(),
            };
            let completed = in_custody.clone().apply(event.clone()).unwrap();
            assert!(matches!(
                &completed.candidate,
                WorkerCandidateCustodyStateV1::BrokerCompleted {
                    outcome: recorded,
                    ..
                } if *recorded == outcome
            ));
            assert_eq!(completed.clone().apply(event).unwrap(), completed);
            assert_eq!(
                completed
                    .clone()
                    .apply(WorkerSessionEventV1::RecordBrokerOutcome {
                        outcome: WorkerCandidateBrokerOutcomeV1::Refused {
                            refusal: digest("changed-refusal"),
                        },
                    }),
                Err(SessionError::CandidateBrokerOutcomeConflict)
            );
            let document = ag_primitives::JcsDocument::canonicalize(&completed).unwrap();
            assert_eq!(
                document.decode::<WorkerSessionRecordV1>().unwrap(),
                completed
            );
        }
    }

    #[test]
    fn candidate_refusal_codes_are_closed_serializable_terminal_facts() {
        let codes = [
            WorkerCandidateRefusalCodeV1::MalformedFrame,
            WorkerCandidateRefusalCodeV1::AuthenticationFailed,
            WorkerCandidateRefusalCodeV1::PrincipalBindingMismatch,
            WorkerCandidateRefusalCodeV1::ReviewedProfileMismatch,
            WorkerCandidateRefusalCodeV1::Expired,
        ];
        for code in codes {
            let spec = fixture_spec();
            let record = WorkerSessionRecordV1::new(spec.clone())
                .unwrap()
                .apply(WorkerSessionEventV1::Activate {
                    launch_receipt: digest("launch"),
                })
                .unwrap()
                .apply(WorkerSessionEventV1::Tombstone {
                    tombstone: tombstone(
                        &spec,
                        WorkerTerminationReasonV1::CandidateRefused { code },
                    ),
                })
                .unwrap();
            assert!(matches!(
                &record.authority,
                WorkerAuthorityStateV1::Tombstoned {
                    tombstone: WorkerPrincipalTombstoneV1 {
                        reason: WorkerTerminationReasonV1::CandidateRefused { code: observed },
                        ..
                    },
                    ..
                } if *observed == code
            ));
            assert!(matches!(
                record.candidate,
                WorkerCandidateCustodyStateV1::Awaiting
            ));
            let document = ag_primitives::JcsDocument::canonicalize(&record).unwrap();
            assert_eq!(document.decode::<WorkerSessionRecordV1>().unwrap(), record);
        }
    }

    #[test]
    fn oversized_candidate_cannot_create_custody_or_tombstone_transition() {
        let spec = fixture_spec();
        let candidate = WorkerCandidateCustodyV1::new(
            digest("oversized"),
            spec.output_budget_bytes + 1,
            "artifact_v1",
            None,
            digest("ingress-proof"),
        )
        .unwrap();
        let record = WorkerSessionRecordV1::new(spec.clone())
            .unwrap()
            .apply(WorkerSessionEventV1::Activate {
                launch_receipt: digest("launch"),
            })
            .unwrap();
        assert_eq!(
            record.apply(WorkerSessionEventV1::AcceptCandidate {
                candidate,
                tombstone: tombstone(&spec, WorkerTerminationReasonV1::CandidateAccepted),
            }),
            Err(SessionError::CandidateBudgetExceeded)
        );
    }
}
