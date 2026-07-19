//! Authenticated, role-separated CLI for proposal ingress or exact effects.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use ag_app::api::{
    AgdRequestV1, AgdResponseV1, ApiResultV1, EFFECT_RECORD_SCHEMA_V3, EffectAdminRequestV1,
    EffectAdminResponseV1, HealthV1,
};
use ag_app::config::{
    AgctlCommandProfileV1, AgctlConfigV1, AgctlDaemonPeerV1, AgctlSocketPeerCheckV1, load_config,
};
use ag_app::doctor::{DoctorConfigPathsV1, diagnose_host};
use ag_app::rpc_auth::{RpcPeerEnrollmentV1, RpcReplayGuardV1, RpcSignerV1, SystemRpcClockV1};
use ag_app::signed_transport::{SocketPeerCheckV1, call_signed};
use ag_effect::{ProposalIntentV1, ReconciliationEvidenceV1};
use ag_primitives::{Digest, SessionId};
use ag_protocol::{RequestId, canonical_json, strict_json_from_slice};
use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug, Parser)]
#[command(
    name = "agctl",
    version,
    about = "Authenticated AG-ng proposal ingress or direct effect administration"
)]
struct Arguments {
    /// Root-owned single-role configuration and one daemon enrollment.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Validate configuration without loading the signing credential or connecting.
    #[arg(long)]
    check_config: bool,
    /// Closed operator operation.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit all three daemon configurations and their effective host deployment.
    Doctor {
        /// Root-owned governor configuration.
        #[arg(long, value_name = "PATH")]
        agd_config: PathBuf,
        /// Root-owned effect-broker configuration.
        #[arg(long, value_name = "PATH")]
        effectd_config: PathBuf,
        /// Root-owned provider-broker configuration.
        #[arg(long, value_name = "PATH")]
        providerd_config: PathBuf,
    },
    /// Read authenticated daemon readiness.
    Health {
        /// Exact component to inspect.
        #[arg(value_enum)]
        component: HealthComponent,
    },
    /// Inspect or administer broker-owned exact effects directly at ag-effectd.
    Effect {
        /// Direct effect-plane operation.
        #[command(subcommand)]
        command: EffectCommand,
    },
    /// Submit untrusted intent to the governor; this never bypasses admission.
    Intent {
        /// Governor intent operation.
        #[command(subcommand)]
        command: IntentCommand,
    },
    /// Launch, inspect, or cancel a reviewed contained worker session.
    Worker {
        /// Governor worker operation.
        #[command(subcommand)]
        command: WorkerCommand,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HealthComponent {
    /// Unprivileged judgment/session governor.
    #[value(name = "agd")]
    Agd,
    /// Privileged exact-effect broker, reached on its admin socket.
    #[value(name = "ag-effectd", alias = "effectd")]
    Effectd,
}

#[derive(Debug, Subcommand)]
enum EffectCommand {
    /// Display exact broker-owned canonical proposal bytes and a one-time challenge.
    Show {
        /// Exact canonical proposal digest.
        proposal: Digest,
    },
    /// Display full broker-owned authority and lifecycle custody.
    Record {
        /// Exact canonical proposal digest.
        proposal: Digest,
    },
    /// List bounded broker-owned proposal summaries.
    List {
        /// Number of summaries, from 1 through 1000.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
    },
    /// Ratify the exact proposal displayed directly by ag-effectd.
    Ratify {
        /// Exact canonical proposal digest previously inspected.
        proposal: Digest,
        /// One-time challenge printed by `effect show` for this principal and digest.
        #[arg(long)]
        challenge: String,
    },
    /// Derive a complete read-only reconciliation evidence draft.
    ReconcileDraft {
        /// Exact proposal in reconciliation-required state.
        proposal: Digest,
    },
    /// Submit exact operator reconciliation evidence for broker verification.
    Reconcile {
        /// Regular, non-symlink `ReconciliationEvidenceV1` JSON file.
        #[arg(long, value_name = "PATH")]
        evidence: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum IntentCommand {
    /// Submit one strict `ProposalIntentV1` JSON document to agd.
    Submit {
        /// Regular, non-symlink intent file. Standard input is deliberately unsupported.
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum WorkerCommand {
    /// Launch one root-reviewed fixed executable/argv profile.
    Launch {
        /// Closed profile ID from the agd worker catalog.
        profile_id: String,
    },
    /// Inspect durable worker authority, custody, and terminal state.
    Show {
        /// Non-reusable worker session ID.
        session_id: SessionId,
    },
    /// Durably fence a live worker principal and begin bounded cleanup.
    Cancel {
        /// Non-reusable worker session ID.
        session_id: SessionId,
        /// Digest of the caller's reviewed cancellation reason/evidence.
        #[arg(long)]
        reason: Digest,
    },
}

struct ClientV1 {
    signer: RpcSignerV1,
    endpoint: ClientEndpointV1,
    replay: RpcReplayGuardV1,
    max_control_frame_bytes: u32,
}

enum ClientEndpointV1 {
    Proposer {
        socket: PathBuf,
        peer: RpcPeerEnrollmentV1,
        socket_check: SocketPeerCheckV1,
        max_intent_file_bytes: u64,
    },
    EffectAdmin {
        socket: PathBuf,
        peer: RpcPeerEnrollmentV1,
        socket_check: SocketPeerCheckV1,
    },
}

impl ClientV1 {
    fn new(config: AgctlConfigV1) -> anyhow::Result<Self> {
        let signer = RpcSignerV1::from_systemd_credential(&config.rpc_signing_identity)
            .context("cannot load the enrolled agctl signing credential")?;
        let replay_capacity = usize::try_from(config.limits.rpc_replay_capacity)
            .context("agctl replay bound does not fit this platform")?;
        let replay =
            RpcReplayGuardV1::new(replay_capacity).context("invalid agctl replay bound")?;
        let endpoint = match config.command_profile {
            AgctlCommandProfileV1::Proposer {
                agd_socket,
                agd_peer,
                max_intent_file_bytes,
            } => ClientEndpointV1::Proposer {
                socket: agd_socket,
                peer: enrollment(&agd_peer).context("invalid agd enrollment")?,
                socket_check: socket_check(&agd_peer),
                max_intent_file_bytes,
            },
            AgctlCommandProfileV1::EffectAdmin {
                effectd_admin_socket,
                effectd_peer,
            } => ClientEndpointV1::EffectAdmin {
                socket: effectd_admin_socket,
                peer: enrollment(&effectd_peer).context("invalid ag-effectd enrollment")?,
                socket_check: socket_check(&effectd_peer),
            },
        };
        Ok(Self {
            signer,
            endpoint,
            replay,
            max_control_frame_bytes: config.limits.max_control_frame_bytes,
        })
    }

    fn call_agd(&self, request: AgdRequestV1) -> anyhow::Result<AgdResponseV1> {
        let ClientEndpointV1::Proposer {
            socket,
            peer,
            socket_check,
            ..
        } = &self.endpoint
        else {
            bail!("the effect-admin profile cannot call the governor plane");
        };
        let result: ApiResultV1<AgdResponseV1> = call_signed(
            socket,
            request_id()?,
            request,
            self.max_control_frame_bytes,
            &self.signer,
            peer,
            &self.replay,
            &SystemRpcClockV1,
            *socket_check,
        )
        .context("authenticated agd RPC failed")?;
        require_api_ok(result)
    }

    fn call_effectd(&self, request: EffectAdminRequestV1) -> anyhow::Result<EffectAdminResponseV1> {
        let ClientEndpointV1::EffectAdmin {
            socket,
            peer,
            socket_check,
        } = &self.endpoint
        else {
            bail!("the proposer profile cannot call the effect-admin plane");
        };
        // Inspection, challenge creation, ratification, and reconciliation
        // terminate on this socket. There is intentionally no agd projection.
        let result: ApiResultV1<EffectAdminResponseV1> = call_signed(
            socket,
            request_id()?,
            request,
            self.max_control_frame_bytes,
            &self.signer,
            peer,
            &self.replay,
            &SystemRpcClockV1,
            *socket_check,
        )
        .context("authenticated direct ag-effectd RPC failed")?;
        require_api_ok(result)
    }

    fn max_intent_file_bytes(&self) -> anyhow::Result<u64> {
        match self.endpoint {
            ClientEndpointV1::Proposer {
                max_intent_file_bytes,
                ..
            } => Ok(max_intent_file_bytes),
            ClientEndpointV1::EffectAdmin { .. } => {
                bail!("the effect-admin profile cannot read or submit intent")
            }
        }
    }

    fn max_reconciliation_evidence_file_bytes(&self) -> anyhow::Result<u64> {
        match self.endpoint {
            ClientEndpointV1::EffectAdmin { .. } => Ok(u64::from(self.max_control_frame_bytes)),
            ClientEndpointV1::Proposer { .. } => {
                bail!("the proposer profile cannot read or submit reconciliation evidence")
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let Arguments {
        config,
        check_config,
        command,
    } = Arguments::parse();
    if let Some(Command::Doctor {
        agd_config,
        effectd_config,
        providerd_config,
    }) = command
    {
        if config.is_some() || check_config {
            bail!("doctor cannot be combined with --config or --check-config");
        }
        let report = diagnose_host(&DoctorConfigPathsV1 {
            agd: agd_config,
            effectd: effectd_config,
            providerd: providerd_config,
        });
        write_canonical(&report)?;
        if !report.ready {
            bail!("doctor found failed or unavailable required checks");
        }
        return Ok(());
    }
    let config_path = config.context("--config is required for this operation")?;
    // Custody cannot be selected by a field read from an untrusted file: an
    // attacker could otherwise relabel their own config as `development`.
    let config: AgctlConfigV1 = load_config(&config_path, true)?;
    config.validate()?;
    if check_config {
        if command.is_some() {
            bail!("--check-config cannot be combined with an operation");
        }
        return Ok(());
    }
    let command = command.context("an operation is required unless --check-config is used")?;
    authorize_command(&config.command_profile, &command)?;
    let client = ClientV1::new(config)?;
    dispatch(&client, command)
}

fn authorize_command(profile: &AgctlCommandProfileV1, command: &Command) -> anyhow::Result<()> {
    let authorized = match profile {
        AgctlCommandProfileV1::Proposer { .. } => matches!(
            command,
            Command::Health {
                component: HealthComponent::Agd
            } | Command::Intent { .. }
                | Command::Worker { .. }
        ),
        AgctlCommandProfileV1::EffectAdmin { .. } => matches!(
            command,
            Command::Health {
                component: HealthComponent::Effectd
            } | Command::Effect { .. }
        ),
    };
    if authorized {
        Ok(())
    } else {
        bail!("the configured agctl role does not authorize this command plane")
    }
}

fn dispatch(client: &ClientV1, command: Command) -> anyhow::Result<()> {
    match command {
        Command::Doctor { .. } => bail!("doctor is not a signed command-plane operation"),
        Command::Health { component } => health(client, component),
        Command::Effect { command } => effect(client, command),
        Command::Intent { command } => match command {
            IntentCommand::Submit { file } => {
                let intent = read_intent(&file, client.max_intent_file_bytes()?)?;
                let response = client.call_agd(AgdRequestV1::SubmitProposal {
                    intent: Box::new(intent),
                })?;
                match &response {
                    AgdResponseV1::ProposalSubmitted { .. } => write_canonical(&response),
                    AgdResponseV1::Refused { .. } => {
                        write_canonical(&response)?;
                        bail!("agd semantically refused the intent")
                    }
                    AgdResponseV1::Indeterminate { .. } => {
                        write_canonical(&response)?;
                        bail!("agd reached an operationally indeterminate result")
                    }
                    AgdResponseV1::Health { .. } => bail!("agd returned an unexpected response"),
                    AgdResponseV1::WorkerLaunched { .. }
                    | AgdResponseV1::WorkerStatus { .. }
                    | AgdResponseV1::WorkerCancelled { .. } => {
                        bail!("agd returned a worker response to an intent request")
                    }
                }
            }
        },
        Command::Worker { command } => worker(client, command),
    }
}

fn worker(client: &ClientV1, command: WorkerCommand) -> anyhow::Result<()> {
    let response = match command {
        WorkerCommand::Launch { profile_id } => {
            client.call_agd(AgdRequestV1::LaunchWorker { profile_id })?
        }
        WorkerCommand::Show { session_id } => {
            client.call_agd(AgdRequestV1::InspectWorker { session_id })?
        }
        WorkerCommand::Cancel { session_id, reason } => {
            client.call_agd(AgdRequestV1::CancelWorker { session_id, reason })?
        }
    };
    match &response {
        AgdResponseV1::WorkerLaunched { .. }
        | AgdResponseV1::WorkerStatus { .. }
        | AgdResponseV1::WorkerCancelled { .. } => write_canonical(&response),
        AgdResponseV1::Health { .. }
        | AgdResponseV1::ProposalSubmitted { .. }
        | AgdResponseV1::Indeterminate { .. }
        | AgdResponseV1::Refused { .. } => bail!("agd returned an unexpected response"),
    }
}

fn health(client: &ClientV1, component: HealthComponent) -> anyhow::Result<()> {
    let health = match component {
        HealthComponent::Agd => match client.call_agd(AgdRequestV1::Health)? {
            AgdResponseV1::Health { health } => require_health_service(health, "agd")?,
            _ => bail!("agd returned an unexpected response"),
        },
        HealthComponent::Effectd => match client.call_effectd(EffectAdminRequestV1::Health)? {
            EffectAdminResponseV1::Health { health } => {
                require_health_service(health, "ag-effectd")?
            }
            _ => bail!("ag-effectd returned an unexpected response"),
        },
    };
    write_canonical(&health)?;
    if health.quiesced {
        bail!("{} is quiesced", health.service);
    }
    if !health.ready {
        bail!("{} is not ready", health.service);
    }
    Ok(())
}

fn effect(client: &ClientV1, command: EffectCommand) -> anyhow::Result<()> {
    match command {
        EffectCommand::Show { proposal } => {
            let response = client.call_effectd(EffectAdminRequestV1::InspectProposal {
                proposal: proposal.clone(),
            })?;
            let EffectAdminResponseV1::Proposal {
                proposal: canonical,
                challenge,
            } = response
            else {
                bail!("ag-effectd returned an unexpected response");
            };
            canonical
                .verify_digest()
                .context("ag-effectd returned a proposal with an invalid canonical digest")?;
            if canonical.digest() != &proposal {
                bail!("ag-effectd returned a different proposal than requested");
            }
            validate_challenge(&challenge)?;
            // stdout is exactly the broker-owned canonical object plus LF, so
            // redirecting stdout exports precisely the bytes an operator saw.
            write_canonical(&canonical)?;
            eprintln!("ratification_challenge={challenge}");
            Ok(())
        }
        EffectCommand::Record { proposal } => inspect_effect_record(client, &proposal),
        EffectCommand::List { limit } => {
            let response = client.call_effectd(EffectAdminRequestV1::ListProposals { limit })?;
            match response {
                EffectAdminResponseV1::Proposals { .. } => write_canonical(&response),
                _ => bail!("ag-effectd returned an unexpected response"),
            }
        }
        EffectCommand::Ratify {
            proposal,
            challenge,
        } => {
            validate_challenge(&challenge)?;
            let response = client.call_effectd(EffectAdminRequestV1::Ratify {
                proposal,
                challenge,
            })?;
            match &response {
                EffectAdminResponseV1::ExecutionReceipt { terminal_state, .. } => {
                    write_canonical(&response)?;
                    match terminal_state.as_str() {
                        "succeeded" => Ok(()),
                        "failed" => bail!("effect execution failed; inspect the exact receipt"),
                        "reconciliation_required" => {
                            bail!("effect outcome is indeterminate and requires reconciliation")
                        }
                        _ => bail!("ag-effectd returned an invalid terminal state"),
                    }
                }
                _ => bail!("ag-effectd returned an unexpected response"),
            }
        }
        EffectCommand::ReconcileDraft { proposal } => draft_reconciliation(client, &proposal),
        EffectCommand::Reconcile { evidence } => {
            let evidence: ReconciliationEvidenceV1 = read_strict_json_file(
                &evidence,
                client.max_reconciliation_evidence_file_bytes()?,
                "reconciliation evidence",
            )?;
            let response = client.call_effectd(EffectAdminRequestV1::Reconcile {
                evidence: Box::new(evidence),
            })?;
            match response {
                EffectAdminResponseV1::Reconciled { .. } => write_canonical(&response),
                _ => bail!("ag-effectd returned an unexpected response"),
            }
        }
    }
}

fn inspect_effect_record(client: &ClientV1, proposal: &Digest) -> anyhow::Result<()> {
    let response = client.call_effectd(EffectAdminRequestV1::InspectRecord {
        proposal: proposal.clone(),
    })?;
    let EffectAdminResponseV1::Record { record } = response else {
        bail!("ag-effectd returned an unexpected response");
    };
    if record.schema != EFFECT_RECORD_SCHEMA_V3 {
        bail!("ag-effectd returned an unsupported effect record schema");
    }
    record
        .canonical
        .verify_digest()
        .context("ag-effectd returned a record with an invalid canonical digest")?;
    if record.canonical.digest() != proposal {
        bail!("ag-effectd returned a different effect record than requested");
    }
    write_canonical(&record)
}

fn draft_reconciliation(client: &ClientV1, proposal: &Digest) -> anyhow::Result<()> {
    let response = client.call_effectd(EffectAdminRequestV1::DraftReconciliation {
        proposal: proposal.clone(),
    })?;
    let EffectAdminResponseV1::ReconciliationDraft { evidence } = response else {
        bail!("ag-effectd returned an unexpected response");
    };
    if evidence.schema != ag_effect::RECONCILIATION_EVIDENCE_SCHEMA_V1
        || &evidence.proposal != proposal
    {
        bail!("ag-effectd returned a mismatched reconciliation draft");
    }
    // stdout is directly reusable as the strict evidence input after
    // independent operator review; requesting a draft does not submit it.
    write_canonical(&evidence)
}

fn require_api_ok<T>(result: ApiResultV1<T>) -> anyhow::Result<T> {
    match result {
        ApiResultV1::Ok { response } => Ok(response),
        ApiResultV1::Error {
            code,
            message,
            correlation,
        } => bail!("daemon rejected request ({code:?}, correlation {correlation}): {message}"),
    }
}

fn require_health_service(health: HealthV1, expected: &str) -> anyhow::Result<HealthV1> {
    if health.schema != "ag.health/v1" || health.service != expected {
        bail!("authenticated peer returned the wrong health identity");
    }
    Ok(health)
}

fn enrollment(peer: &AgctlDaemonPeerV1) -> anyhow::Result<RpcPeerEnrollmentV1> {
    RpcPeerEnrollmentV1::new(peer.rpc_key.principal.clone(), peer.rpc_key.clone())
        .map_err(Into::into)
}

fn socket_check(peer: &AgctlDaemonPeerV1) -> SocketPeerCheckV1 {
    match peer.socket_peer {
        AgctlSocketPeerCheckV1::ObserveOnly => SocketPeerCheckV1::ObserveOnly,
        AgctlSocketPeerCheckV1::RequireUidGid { uid, gid } => {
            SocketPeerCheckV1::RequireUidGid { uid, gid }
        }
    }
}

fn request_id() -> anyhow::Result<RequestId> {
    RequestId::new(format!("agctl-{}", uuid::Uuid::new_v4())).map_err(Into::into)
}

fn validate_challenge(challenge: &str) -> anyhow::Result<()> {
    let parsed = uuid::Uuid::parse_str(challenge).context("invalid broker display challenge")?;
    if parsed.hyphenated().to_string() != challenge {
        bail!("noncanonical broker display challenge");
    }
    Ok(())
}

fn read_intent(path: &Path, maximum: u64) -> anyhow::Result<ProposalIntentV1> {
    let intent: ProposalIntentV1 = read_strict_json_file(path, maximum, "proposal intent")?;
    intent
        .validate_shape()
        .context("intent failed closed shape validation")?;
    Ok(intent)
}

fn read_strict_json_file<T>(path: &Path, maximum: u64, input_name: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("cannot open {input_name} file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect {input_name} file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{input_name} input must be a regular file");
    }
    if metadata.len() > maximum {
        bail!("{input_name} input exceeds configured byte bound");
    }
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {input_name} file {}", path.display()))?;
    let byte_length = u64::try_from(bytes.len())
        .with_context(|| format!("{input_name} length does not fit the protocol bound"))?;
    if byte_length > maximum {
        bail!("{input_name} input exceeds configured byte bound");
    }
    strict_json_from_slice(&bytes)
        .with_context(|| format!("{input_name} is not strict JSON of the required schema"))
}

fn write_canonical<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let bytes = canonical_json(value).context("cannot encode canonical output")?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(&bytes)?;
    lock.write_all(b"\n")?;
    lock.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{UnixListener, UnixStream};

    use ag_app::rpc_auth::{
        RpcKeyIdV1, RpcPeerKeyPolicyV1, RpcPublicKeyV1, RpcSigningIdentityConfigV1,
    };
    use ag_app::signed_transport::{
        AcceptedSignedRequestV1, accept_signed_request, write_signed_response,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    fn reconciliation_evidence() -> ReconciliationEvidenceV1 {
        ReconciliationEvidenceV1 {
            schema: ag_effect::RECONCILIATION_EVIDENCE_SCHEMA_V1.to_owned(),
            proposal: Digest::hash_bytes(b"proposal"),
            attempt: Digest::hash_bytes(b"attempt"),
            uncertainty_envelope: Digest::hash_bytes(b"uncertainty"),
            step_receipts: vec![Digest::hash_bytes(b"step")],
            observed_poststate: BTreeMap::new(),
            classification: ag_effect::ReconciliationClassificationV1::NotApplied,
        }
    }

    #[test]
    fn effect_commands_are_a_closed_surface() {
        let parsed = Arguments::try_parse_from([
            "agctl",
            "--config",
            "/etc/agent-governor/agctl.toml",
            "effect",
            "list",
            "--limit",
            "10",
        ])
        .expect("closed command");
        assert!(matches!(
            parsed.command,
            Some(Command::Effect {
                command: EffectCommand::List { limit: 10 }
            })
        ));
        let proposal = Digest::hash_bytes(b"proposal").to_string();
        let record = Arguments::try_parse_from([
            "agctl",
            "--config",
            "/etc/agent-governor/agctl.toml",
            "effect",
            "record",
            &proposal,
        ])
        .expect("typed record inspection command");
        assert!(matches!(
            record.command,
            Some(Command::Effect {
                command: EffectCommand::Record { .. }
            })
        ));
        let draft = Arguments::try_parse_from([
            "agctl",
            "--config",
            "/etc/agent-governor/agctl.toml",
            "effect",
            "reconcile-draft",
            &proposal,
        ])
        .expect("typed reconciliation draft command");
        assert!(matches!(
            draft.command,
            Some(Command::Effect {
                command: EffectCommand::ReconcileDraft { .. }
            })
        ));
        assert!(
            Arguments::try_parse_from([
                "agctl",
                "--config",
                "/etc/agent-governor/agctl.toml",
                "effect",
                "reconcile-draft",
                &proposal,
                "--classification",
                "applied",
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from([
                "agctl",
                "--config",
                "/etc/agent-governor/agctl.toml",
                "effect",
                "run",
                "id",
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from([
                "agctl",
                "--config",
                "/etc/agent-governor/agctl.toml",
                "break-glass",
            ])
            .is_err()
        );
    }

    #[test]
    fn doctor_has_explicit_three_config_grammar_and_no_signing_profile() {
        let parsed = Arguments::try_parse_from([
            "agctl",
            "doctor",
            "--agd-config",
            "/etc/agent-governor/agd.toml",
            "--effectd-config",
            "/etc/agent-governor/effectd.toml",
            "--providerd-config",
            "/etc/agent-governor/providerd.toml",
        ])
        .expect("closed doctor command");
        assert!(parsed.config.is_none());
        assert!(matches!(parsed.command, Some(Command::Doctor { .. })));

        assert!(
            Arguments::try_parse_from([
                "agctl",
                "doctor",
                "--agd-config",
                "/agd.toml",
                "--effectd-config",
                "/effectd.toml",
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from([
                "agctl",
                "doctor",
                "--agd-config",
                "/agd.toml",
                "--effectd-config",
                "/effectd.toml",
                "--providerd-config",
                "/providerd.toml",
                "--unit",
                "ssh.service",
            ])
            .is_err()
        );
    }

    #[test]
    fn ratification_requires_an_explicit_challenge() {
        let digest = Digest::hash_bytes(b"proposal").to_string();
        assert!(
            Arguments::try_parse_from([
                "agctl",
                "--config",
                "/etc/agent-governor/agctl.toml",
                "effect",
                "ratify",
                &digest,
            ])
            .is_err()
        );
    }

    #[test]
    fn reconciliation_accepts_one_evidence_file_and_rejects_digest_only_ux() {
        let parsed = Arguments::try_parse_from([
            "agctl",
            "--config",
            "/etc/agent-governor/agctl.toml",
            "effect",
            "reconcile",
            "--evidence",
            "/run/agent-governor/reconciliation.json",
        ])
        .expect("evidence-file reconciliation command");
        assert!(matches!(
            parsed.command,
            Some(Command::Effect {
                command: EffectCommand::Reconcile { evidence }
            }) if evidence == Path::new("/run/agent-governor/reconciliation.json")
        ));

        let proposal = Digest::hash_bytes(b"proposal").to_string();
        let receipt = Digest::hash_bytes(b"receipt").to_string();
        assert!(
            Arguments::try_parse_from([
                "agctl",
                "--config",
                "/etc/agent-governor/agctl.toml",
                "effect",
                "reconcile",
                &proposal,
                "--receipt",
                &receipt,
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from([
                "agctl",
                "--config",
                "/etc/agent-governor/agctl.toml",
                "effect",
                "reconcile",
                "--evidence",
                "/first.json",
                "--evidence",
                "/second.json",
            ])
            .is_err()
        );
    }

    #[test]
    fn command_profiles_reject_every_opposite_plane_operation() {
        let effect_admin: AgctlConfigV1 =
            toml::from_str(include_str!("../../../../config/agctl.example.toml"))
                .expect("effect-admin example");
        let proposer: AgctlConfigV1 = toml::from_str(include_str!(
            "../../../../config/agctl-proposer.example.toml"
        ))
        .expect("proposer example");
        let proposal = Digest::hash_bytes(b"proposal");

        assert!(
            authorize_command(
                &effect_admin.command_profile,
                &Command::Health {
                    component: HealthComponent::Effectd,
                },
            )
            .is_ok()
        );
        assert!(
            authorize_command(
                &effect_admin.command_profile,
                &Command::Effect {
                    command: EffectCommand::Show {
                        proposal: proposal.clone(),
                    },
                },
            )
            .is_ok()
        );
        assert!(
            authorize_command(
                &effect_admin.command_profile,
                &Command::Health {
                    component: HealthComponent::Agd,
                },
            )
            .is_err()
        );
        assert!(
            authorize_command(
                &effect_admin.command_profile,
                &Command::Intent {
                    command: IntentCommand::Submit {
                        file: PathBuf::from("/must/not/be/read"),
                    },
                },
            )
            .is_err()
        );

        assert!(
            authorize_command(
                &proposer.command_profile,
                &Command::Health {
                    component: HealthComponent::Agd,
                },
            )
            .is_ok()
        );
        assert!(
            authorize_command(
                &proposer.command_profile,
                &Command::Intent {
                    command: IntentCommand::Submit {
                        file: PathBuf::from("/admitted/by-profile"),
                    },
                },
            )
            .is_ok()
        );
        assert!(
            authorize_command(
                &proposer.command_profile,
                &Command::Health {
                    component: HealthComponent::Effectd,
                },
            )
            .is_err()
        );
        assert!(
            authorize_command(
                &proposer.command_profile,
                &Command::Effect {
                    command: EffectCommand::Reconcile {
                        evidence: PathBuf::from("/must/not/be/read"),
                    },
                },
            )
            .is_err()
        );
    }

    #[test]
    fn display_challenges_are_canonical_and_terminal_safe() {
        assert!(validate_challenge("990c37f1-2711-44e9-94d0-6635d31c43cb").is_ok());
        assert!(validate_challenge("990C37F1-2711-44E9-94D0-6635D31C43CB").is_err());
        assert!(validate_challenge("challenge\nforged-output").is_err());
    }

    #[test]
    fn intent_reader_rejects_symlinks_and_growth_past_the_bound() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("intent.json");
        std::fs::write(&target, b"12345").expect("write target");
        let link = directory.path().join("intent-link.json");
        symlink(&target, &link).expect("create symlink");

        assert!(read_intent(&link, 1024).is_err());
        assert!(read_intent(&target, 4).is_err());
    }

    #[test]
    fn intent_reader_uses_the_duplicate_rejecting_decoder() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("intent.json");
        std::fs::write(
            &path,
            br#"{"schema":"ag.effect/v1","schema":"ag.effect/v1"}"#,
        )
        .expect("write duplicate-key specimen");
        assert!(read_intent(&path, 1024).is_err());
    }

    #[test]
    fn reconciliation_reader_returns_the_exact_typed_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("reconciliation.json");
        let expected = reconciliation_evidence();
        std::fs::write(
            &path,
            canonical_json(&expected).expect("canonical evidence"),
        )
        .expect("write evidence");

        let observed: ReconciliationEvidenceV1 =
            read_strict_json_file(&path, 64 * 1024, "reconciliation evidence")
                .expect("strict evidence");
        assert_eq!(observed, expected);
    }

    #[test]
    fn reconciliation_reader_rejects_non_regular_and_oversized_inputs() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("reconciliation.json");
        std::fs::write(&target, b"12345").expect("write target");
        let link = directory.path().join("reconciliation-link.json");
        symlink(&target, &link).expect("create symlink");

        assert!(
            read_strict_json_file::<ReconciliationEvidenceV1>(
                &link,
                1024,
                "reconciliation evidence",
            )
            .is_err()
        );
        assert!(
            read_strict_json_file::<ReconciliationEvidenceV1>(
                directory.path(),
                1024,
                "reconciliation evidence",
            )
            .is_err()
        );
        assert!(
            read_strict_json_file::<ReconciliationEvidenceV1>(
                &target,
                4,
                "reconciliation evidence",
            )
            .is_err()
        );
    }

    #[test]
    fn reconciliation_reader_rejects_hostile_json_shapes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("reconciliation.json");
        let valid = String::from_utf8(
            canonical_json(&reconciliation_evidence()).expect("canonical evidence"),
        )
        .expect("JSON is UTF-8");
        let fields = valid.strip_prefix('{').expect("object");
        let without_end = valid.strip_suffix('}').expect("object");
        let specimens = [
            (
                format!("{{\"schema\":\"ag.reconciliation-evidence/v1\",{fields}"),
                "duplicate JSON key",
            ),
            (
                format!("{without_end},\"unexpected\":true}}"),
                "unknown field `unexpected`",
            ),
            (
                format!("{without_end},\"unexpected_float\":1.5}}"),
                "floating-point JSON numbers are forbidden",
            ),
            (format!("{valid}{{}}"), "invalid JSON"),
        ];

        for (specimen, expected_error) in specimens {
            std::fs::write(&path, specimen).expect("write hostile evidence");
            let error = read_strict_json_file::<ReconciliationEvidenceV1>(
                &path,
                64 * 1024,
                "reconciliation evidence",
            )
            .expect_err("hostile evidence must fail");
            assert!(
                format!("{error:#}").contains(expected_error),
                "unexpected strict-decoder error: {error:#}",
            );
        }
    }

    #[test]
    fn effect_health_uses_only_the_signed_direct_effect_socket() {
        // Keep the production half-close invariant even in sandboxes which
        // happen to deny shutdown(2): the proof-level transport tests cover
        // the exchange in that environment.
        let (probe, _peer) = UnixStream::pair().expect("probe pair");
        if probe
            .shutdown(std::net::Shutdown::Write)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
        {
            return;
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let (operator_signing, operator_policy) = test_identity(directory.path(), "operator");
        let (effectd_signing, effectd_policy) = test_identity(directory.path(), "effectd");
        let effectd_socket = directory.path().join("effectd-admin.sock");
        let listener = UnixListener::bind(&effectd_socket).expect("bind effect socket");
        let server_signer =
            RpcSignerV1::from_systemd_credential(&effectd_signing).expect("server signer");
        let operator_enrollment =
            RpcPeerEnrollmentV1::new(operator_policy.principal.clone(), operator_policy.clone())
                .expect("operator enrollment");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept effect call");
            let codec = ag_protocol::FrameCodec::new(16 * 1024).expect("codec");
            let replay = RpcReplayGuardV1::new(8).expect("replay guard");
            let accepted: AcceptedSignedRequestV1<EffectAdminRequestV1> = accept_signed_request(
                &mut stream,
                codec,
                &server_signer,
                &operator_enrollment,
                &replay,
                &SystemRpcClockV1,
                SocketPeerCheckV1::ObserveOnly,
            )
            .expect("authenticate request");
            assert!(matches!(accepted.body(), EffectAdminRequestV1::Health));
            write_signed_response(
                &mut stream,
                codec,
                &server_signer,
                &accepted,
                ApiResultV1::Ok {
                    response: EffectAdminResponseV1::Health {
                        health: HealthV1 {
                            schema: "ag.health/v1".to_owned(),
                            service: "ag-effectd".to_owned(),
                            build: "test".to_owned(),
                            ready: true,
                            quiesced: false,
                        },
                    },
                },
                &SystemRpcClockV1,
            )
            .expect("signed response");
        });

        let config = AgctlConfigV1 {
            schema: "ag.config.agctl.v1".to_owned(),
            security_profile: "development".to_owned(),
            rpc_signing_identity: operator_signing,
            command_profile: AgctlCommandProfileV1::EffectAdmin {
                effectd_admin_socket: effectd_socket,
                effectd_peer: AgctlDaemonPeerV1 {
                    rpc_key: effectd_policy,
                    socket_peer: AgctlSocketPeerCheckV1::ObserveOnly,
                },
            },
            limits: ag_app::config::AgctlLimitsV1 {
                max_control_frame_bytes: 16 * 1024,
                rpc_replay_capacity: 8,
            },
        };
        config.validate().expect("client config");
        let client = ClientV1::new(config).expect("client");
        let response = client
            .call_effectd(EffectAdminRequestV1::Health)
            .expect("direct health");
        assert!(matches!(response, EffectAdminResponseV1::Health { .. }));
        server.join().expect("server thread");
    }

    fn test_identity(
        directory: &Path,
        label: &str,
    ) -> (RpcSigningIdentityConfigV1, RpcPeerKeyPolicyV1) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let public_key =
            RpcPublicKeyV1::from_base64url(&URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref()))
                .expect("public key");
        let principal = Digest::hash_domain("agctl-test-principal-v1", label.as_bytes());
        let key_id = RpcKeyIdV1::new(format!("{label}.v1")).expect("key ID");
        let credential = directory.join(format!("{label}.pk8"));
        std::fs::write(&credential, pkcs8.as_ref()).expect("write credential");
        let mut permissions = std::fs::metadata(&credential)
            .expect("credential metadata")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&credential, permissions).expect("protect credential");
        (
            RpcSigningIdentityConfigV1 {
                principal: principal.clone(),
                key_id: key_id.clone(),
                public_key: public_key.clone(),
                private_key_credential: credential,
            },
            RpcPeerKeyPolicyV1 {
                principal,
                key_id,
                public_key,
                maximum_clock_skew_ms: 30_000,
            },
        )
    }
}
