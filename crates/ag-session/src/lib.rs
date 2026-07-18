//! Contained batch-session contracts.
//!
//! The types here deliberately cannot express a PTY, interactive input, a
//! linked worktree, or a host target mount.  Workers receive an independent
//! repository/snapshot and a small, explicit descriptor manifest. Provider
//! calls are useful evidence only when the exact credential-free request and
//! complete response event stream have entered governor custody.

use std::collections::{BTreeMap, BTreeSet};

use ag_primitives::{
    AuthorityDomain, Digest, Epoch, InferenceCapabilityId, PrincipalChainV1,
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
    /// Initial host PID observation.
    pub observed_pid: u32,
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
    /// Whether this is replayable governed custody suitable for native admission.
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
    /// Stable worker binding.
    pub worker: WorkerBindingV1,
    /// Isolated workspace mode.
    pub workspace_mode: WorkspaceModeV1,
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
        let mut descriptor_numbers = BTreeSet::new();
        let mut purposes = BTreeSet::new();
        for descriptor in &self.admitted_descriptors {
            if descriptor.descriptor <= 2
                || !descriptor_numbers.insert(descriptor.descriptor)
                || !purposes.insert(descriptor.purpose)
            {
                return Err(SessionError::InvalidDescriptorManifest);
            }
            let expected_access = match descriptor.purpose {
                DescriptorPurposeV1::SourceSnapshot | DescriptorPurposeV1::ProviderResponse => {
                    DescriptorAccessV1::ReadOnly
                }
                DescriptorPurposeV1::ArtifactSink
                | DescriptorPurposeV1::ProviderRequest
                | DescriptorPurposeV1::StatusSink => DescriptorAccessV1::WriteOnly,
            };
            if descriptor.access != expected_access {
                return Err(SessionError::InvalidDescriptorManifest);
            }
        }
        if let Some(capability) = &self.provider_capability
            && (capability.session_id != self.session
                || capability.authority_domain != self.authority_domain
                || capability.epoch != self.epoch
                || capability.worker_principal != self.worker.principal.id()
                || capability.session_nonce != self.worker.principal.session_nonce)
        {
            return Err(SessionError::CapabilityContextMismatch);
        }
        if matches!(
            self.security_profile,
            SecurityProfileV1::Production | SecurityProfileV1::HighAssurance
        ) && (self.worker.isolation.observed_uid == 0
            || self.output_budget_bytes == 0
            || self.deadline_unix_ms == 0)
        {
            return Err(SessionError::ProductionIsolationIncomplete);
        }
        Ok(())
    }
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
    /// Descriptor numbers, directions, or purposes are unsafe.
    #[error("invalid admitted descriptor manifest")]
    InvalidDescriptorManifest,
    /// Provider capability was used by the wrong live peer/context.
    #[error("provider capability context mismatch")]
    CapabilityContextMismatch,
    /// Exact custody fields cannot be canonicalized.
    #[error("provider custody binding cannot be canonicalized: {0}")]
    CustodyBinding(String),
    /// Custody record does not match its exact request fields.
    #[error("provider request custody record mismatch")]
    CustodyMismatch,
    /// Production isolation evidence is incomplete.
    #[error("production isolation evidence is incomplete")]
    ProductionIsolationIncomplete,
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
}
