//! Authenticated, role-separated CLI for proposal ingress or exact effects.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use ag_app::api::{
    AgdRequestV1, AgdResponseV1, ApiResultV1, EFFECT_RECORD_SCHEMA_V3, EffectAdminRequestV1,
    EffectAdminResponseV1, HealthV1,
};
use ag_app::campaign::{self, IntentValidationV1};
use ag_app::config::{
    AgctlCommandProfileV1, AgctlConfigV1, AgctlDaemonPeerV1, AgctlSocketPeerCheckV1,
    EffectTargetConfigV1, EffectdConfigV1, LoadedConfigV1, MAX_CONFIG_BYTES, load_config,
    load_config_with_identity,
};
use ag_app::doctor::{
    DoctorConfigPathsV1, diagnose_host, required_effectd_capabilities, required_effectd_write_paths,
};
use ag_app::effectd::configured_catalog_identity;
use ag_app::managed_pointer::{
    MANAGED_POINTER_GENESIS_ENROLLMENT_RECEIPT_SCHEMA_V1, ManagedPointerGenesisContextV1,
    ManagedPointerGenesisEnrollmentReceiptV1, ManagedPointerGenesisMeasurementV1,
    ManagedPointerGenesisRequestV1, ManagedPointerRuntimeV1, enroll_managed_pointer_genesis,
    measure_managed_pointer_genesis,
};
use ag_app::rpc_auth::{RpcPeerEnrollmentV1, RpcReplayGuardV1, RpcSignerV1, SystemRpcClockV1};
use ag_app::runtime::require_uninitialized_component_store;
use ag_app::signed_transport::{SocketPeerCheckV1, call_signed};
use ag_campaign::{
    CampaignIntentV1, CampaignResidualV1, DocketStandingV1, SidecarRuntimeReceiptV1,
    StageProposalV1, VerdictReceiptV1,
};
use ag_effect::{ProposalIntentV1, ReconciliationEvidenceV1};
use ag_primitives::{Digest, SessionId};
use ag_protocol::{RequestId, canonical_json, strict_json_from_slice};
use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand, ValueEnum};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde::Serialize;
use serde::de::DeserializeOwned;

const MAX_EFFECTD_UNIT_DROP_IN_BYTES: u64 = 64 * 1024;

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
    /// Measure and enroll one initial managed Git head before effectd startup.
    ManagedPointer {
        /// Closed offline managed-pointer enrollment operation.
        #[command(subcommand)]
        command: ManagedPointerCommand,
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
    /// Operate a local campaign orchestration store. Local-only; no daemon
    /// contact and no authority movement.
    Campaign {
        /// Campaign operation.
        #[command(subcommand)]
        command: CampaignCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CampaignCommand {
    /// Create a local campaign store from a human-authorized intent.
    Init {
        /// Strict `CampaignIntentV1` JSON file.
        #[arg(long, value_name = "PATH")]
        intent: PathBuf,
        /// New campaign store directory; must not exist.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
    },
    /// Validate a campaign intent and print its exact identity. Read-only.
    Validate {
        /// Strict `CampaignIntentV1` JSON file.
        #[arg(long, value_name = "PATH")]
        intent: PathBuf,
    },
    /// Audit campaign store integrity and replay. Read-only.
    Doctor {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
    },
    /// Propose a stage; a proposal is a request for Docket admission.
    ProposeStage {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
        /// Strict `StageProposalV1` JSON file.
        #[arg(long, value_name = "PATH")]
        stage: PathBuf,
    },
    /// Record Docket admission for a proposed stage from a standing fixture.
    AdmitStage {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
        /// Strict `DocketStandingV1` JSON fixture.
        #[arg(long, value_name = "PATH")]
        standing: PathBuf,
    },
    /// Consume the current stage's standing, render the exact runtime
    /// envelope, and optionally verify a sidecar receipt against it.
    Run {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
        /// Dispatch the envelope and exit without a receipt.
        #[arg(long)]
        detach: bool,
        /// Strict `SidecarRuntimeReceiptV1` JSON file answering the envelope.
        #[arg(long, value_name = "PATH")]
        receipt: Option<PathBuf>,
    },
    /// Record a reviewer verdict receipt.
    RecordVerdict {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
        /// Strict `VerdictReceiptV1` JSON file.
        #[arg(long, value_name = "PATH")]
        verdict: PathBuf,
    },
    /// Record a bounded residual.
    RecordResidual {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
        /// Strict `CampaignResidualV1` JSON file.
        #[arg(long, value_name = "PATH")]
        residual: PathBuf,
    },
    /// Show campaign status. Read-only.
    Status {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
    },
    /// Show the most recent stored campaign events. Read-only.
    Tail {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
        /// Number of events, from 1 through 1000.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000), default_value_t = 20)]
        limit: u32,
    },
    /// Compute the campaign recomposition judgment. Read-only.
    Report {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
    },
    /// Halt the campaign with an exact reason digest.
    Abort {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
        /// Digest of the halt reason/evidence.
        #[arg(long)]
        reason: Digest,
    },
    /// Resume a halted campaign once no consumed stage is in flight.
    Resume {
        /// Campaign store directory.
        #[arg(long, value_name = "PATH")]
        campaign_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ManagedPointerCommand {
    /// Emit exact repository-read-only genesis evidence for independent review.
    MeasureGenesis {
        /// Root-owned strict enrollment request in TOML.
        #[arg(long, value_name = "PATH")]
        request: PathBuf,
        /// Root-owned complete effectd config before adding this target.
        #[arg(long, value_name = "PATH")]
        effectd_config_template: PathBuf,
    },
    /// Remeasure reviewed genesis and create complete deployment artifacts.
    EnrollGenesis {
        /// Root-owned strict enrollment request in TOML.
        #[arg(long, value_name = "PATH")]
        request: PathBuf,
        /// Root-owned effectd template used by the reviewed measurement.
        #[arg(long, value_name = "PATH")]
        effectd_config_template: PathBuf,
        /// Root-owned canonical measurement previously emitted for review.
        #[arg(long, value_name = "PATH")]
        measurement: PathBuf,
        /// New root-owned final effectd TOML configuration.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// New root-owned systemd drop-in derived from the final catalog.
        #[arg(long, value_name = "PATH")]
        unit_drop_in_output: PathBuf,
        /// New root-owned canonical enrollment receipt, published first.
        #[arg(long, value_name = "PATH")]
        receipt_output: PathBuf,
    },
    /// Verify published genesis artifacts and repeat the exact live measurement.
    VerifyGenesisEnrollment {
        /// Root-owned canonical measurement reviewed before enrollment.
        #[arg(long, value_name = "PATH")]
        measurement: PathBuf,
        /// Root-owned managed-pointer-free template bound by the measurement.
        #[arg(long, value_name = "PATH")]
        effectd_config_template: PathBuf,
        /// Root-owned canonical enrollment receipt.
        #[arg(long, value_name = "PATH")]
        receipt: PathBuf,
        /// Published complete effectd configuration.
        #[arg(long, value_name = "PATH")]
        effectd_config: PathBuf,
        /// Published target-derived systemd drop-in.
        #[arg(long, value_name = "PATH")]
        unit_drop_in: PathBuf,
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
    let command = match command {
        Some(Command::Doctor {
            agd_config,
            effectd_config,
            providerd_config,
        }) => {
            require_offline_invocation(config.as_deref(), check_config, "doctor")?;
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
        Some(Command::ManagedPointer { command }) => {
            require_offline_invocation(
                config.as_deref(),
                check_config,
                "offline managed-pointer enrollment",
            )?;
            return managed_pointer(command);
        }
        Some(Command::Campaign { command }) => {
            require_offline_invocation(config.as_deref(), check_config, "campaign")?;
            return campaign(command);
        }
        command => command,
    };
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

fn require_offline_invocation(
    config: Option<&Path>,
    check_config: bool,
    operation: &str,
) -> anyhow::Result<()> {
    if config.is_some() || check_config {
        bail!("{operation} cannot be combined with --config or --check-config");
    }
    Ok(())
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
        Command::ManagedPointer { .. } => {
            bail!("managed-pointer enrollment is not a signed command-plane operation")
        }
        Command::Campaign { .. } => bail!("campaign is not a signed command-plane operation"),
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

// Keep the complete offline publication order in one auditable function: the
// receipt and unit drop-in must precede the final config commit point.
#[allow(clippy::too_many_lines)]
fn managed_pointer(command: ManagedPointerCommand) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
        bail!("managed-pointer genesis measurement and enrollment require effective UID and GID 0");
    }
    nix::unistd::setgroups(&[]).context("cannot clear supplementary groups for enrollment")?;
    if !nix::unistd::getgroups()?.is_empty() {
        bail!("supplementary groups remain after the enrollment privilege-floor transition");
    }
    match command {
        ManagedPointerCommand::MeasureGenesis {
            request,
            effectd_config_template,
        } => {
            let request: ManagedPointerGenesisRequestV1 = load_config(&request, true)
                .context("cannot load the root-owned genesis request")?;
            let (template, context) = load_genesis_template(&effectd_config_template, &request)?;
            require_uninitialized_component_store(&template.store)?;
            let measurement = measure_managed_pointer_genesis(&request, &context)
                .context("managed-pointer genesis measurement refused")?;
            write_canonical(&measurement)
        }
        ManagedPointerCommand::EnrollGenesis {
            request,
            effectd_config_template,
            measurement,
            output,
            unit_drop_in_output,
            receipt_output,
        } => {
            let request: ManagedPointerGenesisRequestV1 = load_config(&request, true)
                .context("cannot load the root-owned genesis request")?;
            let (template, context) = load_genesis_template(&effectd_config_template, &request)?;
            require_genesis_artifact_isolation(
                &template,
                &request,
                &[&receipt_output, &unit_drop_in_output, &output],
            )?;
            require_uninitialized_component_store(&template.store)?;
            let reviewed: ManagedPointerGenesisMeasurementV1 =
                read_root_custodied_strict_json_file(
                    &measurement,
                    1024 * 1024,
                    "managed-pointer genesis measurement",
                )?;
            let (target, measurement_identity) =
                enroll_managed_pointer_genesis(&request, &context, &reviewed)
                    .context("fresh managed-pointer genesis enrollment refused")?;
            let template = derive_final_effectd_config(template, target)?;
            let effectd_config = render_final_effectd_config(&template)?;
            let unit_drop_in = render_effectd_unit_drop_in(&template)?;
            let receipt = ManagedPointerGenesisEnrollmentReceiptV1 {
                schema: MANAGED_POINTER_GENESIS_ENROLLMENT_RECEIPT_SCHEMA_V1.to_owned(),
                authority_domain: context.authority_domain,
                epoch: context.epoch,
                target: request.target,
                measurement: measurement_identity,
                activation_genesis_object: reviewed.activation_genesis_object.clone(),
                activation_genesis_tree: reviewed.activation_genesis_tree.clone(),
                activation_genesis_state: reviewed.activation_genesis_state.clone(),
                repository_identity: reviewed.repository_identity.clone(),
                effectd_config: Digest::hash_bytes(&effectd_config),
                effectd_config_path: normalized_output_path_text(&output)?,
                effectd_unit_drop_in: Digest::hash_bytes(&unit_drop_in),
                effectd_unit_drop_in_path: normalized_output_path_text(&unit_drop_in_output)?,
                receipt_path: normalized_output_path_text(&receipt_output)?,
            };
            receipt
                .verify(&reviewed)
                .context("derived genesis enrollment receipt is invalid")?;
            require_distinct_absent_outputs(&[&receipt_output, &unit_drop_in_output, &output])?;
            let mut receipt_bytes = canonical_json(&receipt)?;
            receipt_bytes.push(b'\n');
            // The receipt is deliberately safe to orphan. The unit envelope is
            // next, and the final effectd config is the publication commit point.
            atomic_write_new_root_file(&receipt_output, &receipt_bytes)?;
            atomic_write_new_root_file(&unit_drop_in_output, &unit_drop_in)?;
            require_uninitialized_component_store(&template.store)?;
            atomic_write_new_root_file(&output, &effectd_config)?;
            write_canonical(&receipt)
        }
        ManagedPointerCommand::VerifyGenesisEnrollment {
            measurement,
            effectd_config_template,
            receipt,
            effectd_config,
            unit_drop_in,
        } => {
            let reviewed: ManagedPointerGenesisMeasurementV1 =
                read_root_custodied_strict_json_file(
                    &measurement,
                    1024 * 1024,
                    "managed-pointer genesis measurement",
                )?;
            let receipt_record: ManagedPointerGenesisEnrollmentReceiptV1 =
                read_root_custodied_strict_json_file(
                    &receipt,
                    1024 * 1024,
                    "managed-pointer genesis enrollment receipt",
                )?;
            receipt_record
                .verify(&reviewed)
                .context("genesis enrollment receipt is invalid")?;
            let (template, context) =
                load_genesis_template(&effectd_config_template, &reviewed.request)?;
            if context != reviewed.context {
                bail!("effectd template does not match the reviewed enrollment context");
            }
            require_genesis_artifact_isolation(
                &template,
                &reviewed.request,
                &[&receipt, &unit_drop_in, &effectd_config],
            )?;
            require_uninitialized_component_store(&template.store)?;
            let (expected_target, _) =
                enroll_managed_pointer_genesis(&reviewed.request, &context, &reviewed)?;
            let expected_config = derive_final_effectd_config(template, expected_target)?;
            let expected_config_bytes = render_final_effectd_config(&expected_config)?;
            let expected_config_digest = Digest::hash_bytes(&expected_config_bytes);
            if receipt_record.receipt_path != normalized_output_path_text(&receipt)?
                || receipt_record.effectd_config_path
                    != normalized_output_path_text(&effectd_config)?
                || receipt_record.effectd_unit_drop_in_path
                    != normalized_output_path_text(&unit_drop_in)?
            {
                bail!("genesis enrollment receipt names different artifact paths");
            }
            let LoadedConfigV1 {
                config,
                exact_bytes_digest,
            }: LoadedConfigV1<EffectdConfigV1> = load_config_with_identity(&effectd_config, true)
                .context("cannot load published effectd config")?;
            config
                .validate()
                .context("published effectd config is invalid")?;
            if exact_bytes_digest != expected_config_digest
                || receipt_record.effectd_config != expected_config_digest
            {
                bail!(
                    "published effectd config is not the exact reviewed template plus measured target"
                );
            }
            require_uninitialized_component_store(&config.store)?;
            configured_catalog_identity(&config.targets)?;
            ManagedPointerRuntimeV1::from_config(&config)?.require_configured_genesis()?;
            let drop_in_bytes = read_root_custodied_file_bytes(
                &unit_drop_in,
                MAX_EFFECTD_UNIT_DROP_IN_BYTES,
                "effectd unit drop-in",
            )?;
            if Digest::hash_bytes(&drop_in_bytes) != receipt_record.effectd_unit_drop_in
                || drop_in_bytes != render_effectd_unit_drop_in(&expected_config)?
            {
                bail!("published effectd unit drop-in does not match final config");
            }
            write_canonical(&receipt_record)
        }
    }
}

fn derive_final_effectd_config(
    mut template: EffectdConfigV1,
    target: EffectTargetConfigV1,
) -> anyhow::Result<EffectdConfigV1> {
    template.targets.push(target);
    template
        .validate()
        .context("derived final effectd config is invalid")?;
    configured_catalog_identity(&template.targets)
        .context("derived final effectd catalog is invalid")?;
    ManagedPointerRuntimeV1::from_config(&template)
        .context("derived final managed-pointer runtime is invalid")?;
    Ok(template)
}

fn require_genesis_artifact_isolation(
    template: &EffectdConfigV1,
    request: &ManagedPointerGenesisRequestV1,
    artifacts: &[&Path],
) -> anyhow::Result<()> {
    let database_parent = template
        .store
        .database
        .parent()
        .context("effectd database path has no parent")?;
    let mut authority_roots = vec![
        database_parent,
        template.store.object_store.as_path(),
        request.staging_root.as_path(),
        request.allowed_root.as_path(),
        request.repository.as_path(),
        template
            .proposal_socket
            .parent()
            .context("effectd proposal socket has no parent")?,
        template
            .admin_socket
            .parent()
            .context("effectd admin socket has no parent")?,
    ];
    for target in &template.targets {
        if let EffectTargetConfigV1::ManagedFile { path, .. } = target {
            authority_roots.push(path.parent().context("managed-file target has no parent")?);
        }
    }
    for artifact in artifacts {
        normalized_output_path_text(artifact)?;
        if authority_roots
            .iter()
            .any(|root| *artifact == *root || artifact.starts_with(root))
        {
            bail!(
                "genesis publication artifact overlaps a protected store, socket, target, staging, or repository root"
            );
        }
    }
    Ok(())
}

fn load_genesis_template(
    path: &Path,
    request: &ManagedPointerGenesisRequestV1,
) -> anyhow::Result<(EffectdConfigV1, ManagedPointerGenesisContextV1)> {
    let LoadedConfigV1 {
        config,
        exact_bytes_digest,
    }: LoadedConfigV1<EffectdConfigV1> = load_config_with_identity(path, true)
        .context("cannot load the root-owned effectd enrollment template")?;
    config
        .validate()
        .context("effectd enrollment template is invalid")?;
    configured_catalog_identity(&config.targets)
        .context("effectd enrollment template catalog is invalid")?;
    request
        .validate()
        .context("managed-pointer genesis request is invalid")?;
    if config.security_profile != request.security_profile {
        bail!("genesis request and effectd template security profiles differ");
    }
    for target in &config.targets {
        let id = match target {
            EffectTargetConfigV1::ManagedPointer { .. } => {
                bail!("effectd genesis template already contains a managed-pointer target")
            }
            EffectTargetConfigV1::ManagedFile { id, .. }
            | EffectTargetConfigV1::SystemdUnit { id, .. }
            | EffectTargetConfigV1::SystemdManager { id } => id,
        };
        if id == &request.target {
            bail!("effectd genesis template already contains the requested target ID");
        }
    }
    let context = ManagedPointerGenesisContextV1 {
        authority_domain: config.authority_domain.clone(),
        epoch: config.epoch.clone(),
        effectd_config_template: exact_bytes_digest,
        effectd_database: config.store.database.clone(),
        effectd_object_store: config.store.object_store.clone(),
    };
    Ok((config, context))
}

fn render_final_effectd_config(config: &EffectdConfigV1) -> anyhow::Result<Vec<u8>> {
    let text = toml::to_string(config).context("cannot encode final effectd configuration")?;
    if u64::try_from(text.len())? > MAX_CONFIG_BYTES {
        bail!("derived final effectd configuration exceeds the loader byte limit");
    }
    let round_trip: EffectdConfigV1 =
        toml::from_str(&text).context("cannot decode derived final effectd configuration")?;
    round_trip
        .validate()
        .context("derived effectd configuration failed round-trip validation")?;
    Ok(text.into_bytes())
}

fn render_effectd_unit_drop_in(config: &EffectdConfigV1) -> anyhow::Result<Vec<u8>> {
    let capabilities = required_effectd_capabilities(config)
        .into_iter()
        .map(str::to_ascii_uppercase)
        .collect::<Vec<_>>()
        .join(" ");
    let paths = required_effectd_write_paths(config).map_err(|error| anyhow::anyhow!(error))?;
    let mut text = format!(
        "[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet={capabilities}\nReadWritePaths=\n"
    );
    for path in paths {
        let path = path.to_str().context("effectd write path is not UTF-8")?;
        if !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':')
        }) {
            bail!("effectd write path requires unsupported systemd escaping");
        }
        text.push_str("ReadWritePaths=");
        text.push_str(path);
        text.push('\n');
    }
    if u64::try_from(text.len())? > MAX_EFFECTD_UNIT_DROP_IN_BYTES {
        bail!("derived effectd unit drop-in exceeds the verifier byte limit");
    }
    Ok(text.into_bytes())
}

fn normalized_output_path_text(path: &Path) -> anyhow::Result<String> {
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute()
        || normalized != *path
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        bail!("genesis enrollment output must be a normalized absolute path");
    }
    path.to_str()
        .map(str::to_owned)
        .context("genesis enrollment output path is not UTF-8")
}

fn require_distinct_absent_outputs(paths: &[&Path]) -> anyhow::Result<()> {
    let mut normalized = std::collections::BTreeSet::new();
    for path in paths {
        let path_text = normalized_output_path_text(path)?;
        if !normalized.insert(path_text) {
            bail!("genesis enrollment output paths must be distinct");
        }
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!(
                "genesis enrollment output already exists: {}",
                path.display()
            ),
            Err(error) => return Err(error).context("cannot inspect enrollment output"),
        }
        validate_root_owned_output_ancestry(path)?;
    }
    Ok(())
}

fn validate_root_owned_output_ancestry(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("genesis enrollment output has no parent")?;
    let mut current = PathBuf::from("/");
    for component in parent.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(name) => current.push(name),
            _ => bail!("genesis enrollment output ancestry is not normalized"),
        }
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("cannot inspect output ancestor {}", current.display()))?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "genesis enrollment output ancestry must be root-owned, nonsymlink, and not group/other writable"
            );
        }
    }
    Ok(())
}

fn atomic_write_new_root_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    validate_root_owned_output_ancestry(path)?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path.parent().context("enrollment output has no parent")?)?;
    let file_name = path
        .file_name()
        .context("enrollment output has no filename")?
        .to_string_lossy();
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .context("cannot create enrollment staging file")?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() != u64::try_from(bytes.len())?
        {
            bail!("enrollment staging file has unexpected custody");
        }
        renameat_with(CWD, &temporary, CWD, path, RenameFlags::NOREPLACE)
            .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        parent.sync_all()?;
        let final_bytes = std::fs::read(path)?;
        if final_bytes != bytes {
            bail!("published enrollment output failed exact readback");
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn campaign(command: CampaignCommand) -> anyhow::Result<()> {
    match command {
        CampaignCommand::Init {
            intent,
            campaign_dir,
        } => {
            let intent: CampaignIntentV1 = campaign::read_record_file(&intent)?;
            campaign::init(&campaign_dir, &intent)?;
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
        CampaignCommand::Validate { intent } => {
            let intent: CampaignIntentV1 = campaign::read_record_file(&intent)?;
            let campaign_id = campaign::validate_intent(&intent)?;
            write_canonical(&IntentValidationV1 {
                valid: true,
                campaign: campaign_id,
                human_authorization: intent.human_authorization().clone(),
            })
        }
        CampaignCommand::Doctor { campaign_dir } => {
            let report = campaign::doctor(&campaign_dir)?;
            write_canonical(&report)?;
            if !report.healthy {
                bail!("campaign doctor found failed checks");
            }
            Ok(())
        }
        CampaignCommand::ProposeStage {
            campaign_dir,
            stage,
        } => {
            let proposal: StageProposalV1 = campaign::read_record_file(&stage)?;
            campaign::propose_stage(&campaign_dir, proposal)?;
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
        CampaignCommand::AdmitStage {
            campaign_dir,
            standing,
        } => {
            let standing: DocketStandingV1 = campaign::read_record_file(&standing)?;
            campaign::admit_stage(&campaign_dir, standing, campaign::now_unix()?)?;
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
        CampaignCommand::Run {
            campaign_dir,
            detach,
            receipt,
        } => {
            let receipt = receipt
                .map(|path| campaign::read_record_file::<SidecarRuntimeReceiptV1>(&path))
                .transpose()?;
            if receipt.is_none() && !detach {
                bail!(
                    "campaign run requires --detach or --receipt; dispatch burns standing exactly once"
                );
            }
            let outcome = campaign::run(&campaign_dir, receipt, campaign::now_unix()?)?;
            write_canonical(&outcome)
        }
        CampaignCommand::RecordVerdict {
            campaign_dir,
            verdict,
        } => {
            let verdict: VerdictReceiptV1 = campaign::read_record_file(&verdict)?;
            campaign::record_verdict(&campaign_dir, verdict)?;
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
        CampaignCommand::RecordResidual {
            campaign_dir,
            residual,
        } => {
            let residual: CampaignResidualV1 = campaign::read_record_file(&residual)?;
            campaign::record_residual(&campaign_dir, residual)?;
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
        CampaignCommand::Status { campaign_dir } => {
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
        CampaignCommand::Tail {
            campaign_dir,
            limit,
        } => write_canonical(&campaign::tail(&campaign_dir, limit)?),
        CampaignCommand::Report { campaign_dir } => {
            let judgment = campaign::report(&campaign_dir)?;
            let refused = matches!(&judgment, ag_kernel::NativeJudgment::Refuse(_));
            write_canonical(&judgment)?;
            if refused {
                bail!("campaign recomposition refused; inspect the exact failures");
            }
            Ok(())
        }
        CampaignCommand::Abort {
            campaign_dir,
            reason,
        } => {
            campaign::abort(&campaign_dir, reason)?;
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
        CampaignCommand::Resume { campaign_dir } => {
            campaign::resume(&campaign_dir)?;
            write_canonical(&campaign::status(&campaign_dir, campaign::now_unix()?)?)
        }
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
            EffectAdminResponseV1::Health { health, .. } => {
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
    read_strict_json_file_with_custody(path, maximum, input_name, false, false)
}

fn read_root_custodied_strict_json_file<T>(
    path: &Path,
    maximum: u64,
    input_name: &str,
) -> anyhow::Result<T>
where
    T: DeserializeOwned + Serialize,
{
    read_strict_json_file_with_custody(path, maximum, input_name, true, true)
}

fn read_strict_json_file_with_custody<T>(
    path: &Path,
    maximum: u64,
    input_name: &str,
    require_root_custody: bool,
    require_canonical_line: bool,
) -> anyhow::Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot open {input_name} file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect {input_name} file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{input_name} input must be a regular file");
    }
    if metadata.nlink() != 1
        || (require_root_custody && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0))
    {
        bail!("{input_name} input has unsafe custody");
    }
    if metadata.len() > maximum {
        bail!("{input_name} input exceeds configured byte bound");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {input_name} file {}", path.display()))?;
    let byte_length = u64::try_from(bytes.len())
        .with_context(|| format!("{input_name} length does not fit the protocol bound"))?;
    if byte_length > maximum {
        bail!("{input_name} input exceeds configured byte bound");
    }
    let after = file
        .metadata()
        .with_context(|| format!("cannot re-inspect {input_name} file {}", path.display()))?;
    if metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.len() != after.len()
        || metadata.mtime() != after.mtime()
        || metadata.mtime_nsec() != after.mtime_nsec()
        || metadata.ctime() != after.ctime()
        || metadata.ctime_nsec() != after.ctime_nsec()
    {
        bail!("{input_name} changed during exact read");
    }
    let decoded: T = strict_json_from_slice(&bytes)
        .with_context(|| format!("{input_name} is not strict JSON of the required schema"))?;
    if require_canonical_line {
        let mut expected = canonical_json(&decoded)?;
        expected.push(b'\n');
        if bytes != expected {
            bail!("{input_name} must be canonical JSON followed by exactly one LF");
        }
    }
    Ok(decoded)
}

fn read_root_custodied_file_bytes(
    path: &Path,
    maximum: u64,
    input_name: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open {input_name} {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file()
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || before.nlink() != 1
        || before.len() > maximum
    {
        bail!("{input_name} has unsafe custody or exceeds its byte bound");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 > maximum
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("{input_name} changed during exact read");
    }
    Ok(bytes)
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
                        activation:
                            ag_app::effectd_activation::EffectdActivationStatusV1::NotReady {
                                schema:
                                    ag_app::effectd_activation::EFFECTD_ACTIVATION_STATUS_SCHEMA_V1
                                        .to_owned(),
                                phase: "test".to_owned(),
                                code: "test".to_owned(),
                                detail: "test fixture".to_owned(),
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

    #[test]
    fn managed_pointer_genesis_commands_have_a_closed_offline_grammar() {
        let measured = Arguments::try_parse_from([
            "agctl",
            "managed-pointer",
            "measure-genesis",
            "--request",
            "/etc/agent-governor/genesis-request.toml",
            "--effectd-config-template",
            "/etc/agent-governor/effectd.template.toml",
        ])
        .expect("measure grammar");
        assert!(matches!(
            measured.command,
            Some(Command::ManagedPointer {
                command: ManagedPointerCommand::MeasureGenesis { .. }
            })
        ));
        let enrolled = Arguments::try_parse_from([
            "agctl",
            "managed-pointer",
            "enroll-genesis",
            "--request",
            "/etc/agent-governor/genesis-request.toml",
            "--effectd-config-template",
            "/etc/agent-governor/effectd.template.toml",
            "--measurement",
            "/etc/agent-governor/genesis.json",
            "--receipt-output",
            "/etc/agent-governor/genesis-receipt.json",
            "--unit-drop-in-output",
            "/etc/systemd/system/ag-effectd.service.d/50-managed-pointer.conf",
            "--output",
            "/etc/agent-governor/effectd.toml",
        ])
        .expect("enroll grammar");
        assert!(matches!(
            enrolled.command,
            Some(Command::ManagedPointer {
                command: ManagedPointerCommand::EnrollGenesis { .. }
            })
        ));
        let verified = Arguments::try_parse_from([
            "agctl",
            "managed-pointer",
            "verify-genesis-enrollment",
            "--measurement",
            "/etc/agent-governor/genesis.json",
            "--effectd-config-template",
            "/etc/agent-governor/effectd.template.toml",
            "--receipt",
            "/etc/agent-governor/genesis-receipt.json",
            "--effectd-config",
            "/etc/agent-governor/effectd.toml",
            "--unit-drop-in",
            "/etc/systemd/system/ag-effectd.service.d/50-managed-pointer.conf",
        ])
        .expect("verify grammar");
        assert!(matches!(
            verified.command,
            Some(Command::ManagedPointer {
                command: ManagedPointerCommand::VerifyGenesisEnrollment { .. }
            })
        ));
        for flag in ["--config", "--check-config"] {
            let mut arguments = vec!["agctl", flag];
            if flag == "--config" {
                arguments.push("/etc/agent-governor/agctl.toml");
            }
            arguments.extend([
                "managed-pointer",
                "measure-genesis",
                "--request",
                "/request",
                "--effectd-config-template",
                "/effectd.template.toml",
            ]);
            let parsed = Arguments::try_parse_from(arguments).expect("complete conflict grammar");
            assert!(
                require_offline_invocation(
                    parsed.config.as_deref(),
                    parsed.check_config,
                    "offline managed-pointer enrollment"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn generated_effectd_config_and_unit_drop_in_are_complete_and_exact() {
        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../../config/effectd.example.toml"))
                .expect("effectd example");
        config.targets.push(EffectTargetConfigV1::ManagedPointer {
            id: "service-repository".to_owned(),
            allowed_root: PathBuf::from("/srv/agent-governor/repositories"),
            repository: PathBuf::from("/srv/agent-governor/repositories/service.git"),
            reference: "refs/heads/main".to_owned(),
            activation_genesis_object: "1111111111111111111111111111111111111111".to_owned(),
            activation_genesis_tree: "2222222222222222222222222222222222222222".to_owned(),
            activation_genesis_state: Digest::hash_bytes(b"genesis state"),
            repository_identity: Digest::hash_bytes(b"repository identity"),
            uid: 1001,
            gid: 1001,
            staging_root: PathBuf::from("/var/lib/agent-governor/effectd/promotion-stage"),
            promotion_ttl_ms: 900_000,
            helper: PathBuf::from("/usr/bin/git"),
            helper_executable: Digest::hash_bytes(b"git"),
            helper_launch_profile: Digest::hash_bytes(b"launch profile"),
        });
        config.validate().expect("structurally valid final config");
        let encoded = render_final_effectd_config(&config).expect("complete config");
        let decoded: EffectdConfigV1 =
            toml::from_str(std::str::from_utf8(&encoded).expect("UTF-8 config"))
                .expect("round-trip config");
        assert_eq!(decoded.targets.len(), 2);

        let mut altered = config.clone();
        altered.limits.max_ready_proposals += 1;
        let altered = render_final_effectd_config(&altered).expect("altered complete config");
        assert_ne!(Digest::hash_bytes(&encoded), Digest::hash_bytes(&altered));

        let drop_in =
            String::from_utf8(render_effectd_unit_drop_in(&config).expect("derived exact drop-in"))
                .expect("UTF-8 drop-in");
        assert_eq!(
            drop_in,
            concat!(
                "[Service]\n",
                "CapabilityBoundingSet=\n",
                "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_SETGID CAP_SETUID\n",
                "ReadWritePaths=\n",
                "ReadWritePaths=/etc/example-service\n",
                "ReadWritePaths=/run/agent-governor/effectd/admin\n",
                "ReadWritePaths=/run/agent-governor/effectd/proposal\n",
                "ReadWritePaths=/srv/agent-governor/repositories/service.git\n",
                "ReadWritePaths=/var/lib/agent-governor/effectd\n",
                "ReadWritePaths=/var/lib/agent-governor/effectd/objects\n",
                "ReadWritePaths=/var/lib/agent-governor/effectd/promotion-stage\n",
            )
        );
    }

    #[test]
    fn packaged_genesis_example_has_complete_static_host_scaffolding() {
        let request: ManagedPointerGenesisRequestV1 = toml::from_str(include_str!(
            "../../../../config/managed-pointer-genesis-request.example.toml"
        ))
        .expect("strict packaged genesis request");
        request.validate().expect("valid packaged genesis request");
        let effectd: EffectdConfigV1 =
            toml::from_str(include_str!("../../../../config/effectd.example.toml"))
                .expect("strict packaged effectd template");

        let tmpfiles =
            include_str!("../../../../packaging/systemd/tmpfiles.d/agent-governor-ng.conf");
        let entry_for = |path: &Path| {
            let expected = path.to_str().expect("example path is UTF-8");
            tmpfiles
                .lines()
                .map(str::split_whitespace)
                .map(Iterator::collect::<Vec<_>>)
                .find(|fields| fields.get(1).is_some_and(|field| *field == expected))
                .expect("example-required path has a tmpfiles entry")
        };
        for path in [
            effectd.store.database.parent().expect("database parent"),
            effectd.store.object_store.as_path(),
            request.staging_root.as_path(),
        ] {
            let fields = entry_for(path);
            assert_eq!(
                fields,
                ["d", path.to_str().unwrap(), "0700", "root", "root", "-"]
            );
        }

        assert!(
            include_str!("../../../../debian/agent-governor-ng.dirs")
                .lines()
                .any(|line| line == "etc/systemd/system/ag-effectd.service.d")
        );
        assert!(
            include_str!("../../../../docs/clean-host-activation-qualification.md")
                .contains("systemctl daemon-reload")
        );
    }

    #[test]
    fn genesis_artifacts_cannot_overlap_store_staging_or_repository_roots() {
        let template: EffectdConfigV1 =
            toml::from_str(include_str!("../../../../config/effectd.example.toml"))
                .expect("effectd template");
        let request: ManagedPointerGenesisRequestV1 = toml::from_str(include_str!(
            "../../../../config/managed-pointer-genesis-request.example.toml"
        ))
        .expect("genesis request");
        require_genesis_artifact_isolation(
            &template,
            &request,
            &[
                Path::new("/etc/agent-governor/genesis-receipt.json"),
                Path::new("/etc/systemd/system/ag-effectd.service.d/50-managed-pointer.conf"),
                Path::new("/etc/agent-governor/effectd.toml"),
            ],
        )
        .expect("isolated deployment outputs");

        for hostile in [
            template.store.database.clone(),
            template.store.database.with_file_name("effectd.db-wal"),
            template.store.object_store.join("receipt.json"),
            request.staging_root.join("receipt.json"),
            request.repository.join("effectd.toml"),
            template.proposal_socket.clone(),
            template.admin_socket.clone(),
            PathBuf::from("/etc/example-service/genesis-receipt.json"),
        ] {
            assert!(require_genesis_artifact_isolation(&template, &request, &[&hostile]).is_err());
        }
    }

    #[test]
    fn genesis_store_preflight_refuses_sidecars_and_nonempty_object_custody() {
        let directory = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("root mode");
        let object_store = directory.path().join("objects");
        std::fs::create_dir(&object_store).expect("object store");
        std::fs::set_permissions(&object_store, std::fs::Permissions::from_mode(0o700))
            .expect("object mode");
        let metadata = std::fs::metadata(directory.path()).expect("root metadata");
        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../../config/effectd.example.toml"))
                .expect("effectd example");
        config.store.database = directory.path().join("effectd.db");
        config.store.object_store = object_store.clone();
        config.store.store_custody.database_parent.uid = metadata.uid();
        config.store.store_custody.database_parent.gid = metadata.gid();
        config.store.store_custody.object_store.uid = metadata.uid();
        config.store.store_custody.object_store.gid = metadata.gid();
        require_uninitialized_component_store(&config.store).expect("empty uninitialized store");

        std::fs::write(directory.path().join("effectd.db-journal"), b"stale")
            .expect("stale journal");
        assert!(require_uninitialized_component_store(&config.store).is_err());
        std::fs::remove_file(directory.path().join("effectd.db-journal"))
            .expect("remove test journal");
        std::fs::write(object_store.join("foreign"), b"foreign").expect("foreign object");
        assert!(require_uninitialized_component_store(&config.store).is_err());
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
