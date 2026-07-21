//! Qualification-only key enrollment and signed local-RPC fixture.
//!
//! This binary is deliberately outside the production Cargo workspace and
//! Debian install manifest. It reuses production protocol types and transport
//! code so clean-host qualification does not invent a second wire protocol.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use ag_app::api::{
    AgdRequestV1, AgdResponseV1, ApiResultV1, ArtifactTransferV1, EffectAdminRequestV1,
    EffectAdminResponseV1, EffectProposalRequestV1, EffectProposalResponseV1,
    GovernedProposalIngressV1, HealthV1, ProposalIngressProofV1,
};
use ag_app::config::{
    AgctlCommandProfileV1, AgctlConfigV1, AgctlDaemonPeerV1, AgctlSocketPeerCheckV1,
    EffectTargetConfigV1, EffectdConfigV1, PeerPolicyV1, load_config,
};
use ag_app::peer::signed_principal_chain;
use ag_app::rpc_auth::{
    RpcClockV1, RpcKeyIdV1, RpcPeerEnrollmentV1, RpcPeerKeyPolicyV1, RpcPublicKeyV1,
    RpcReplayGuardV1, RpcSignerV1, RpcSigningIdentityConfigV1, SystemRpcClockV1,
    VerifiedRpcPrincipalV1,
};
use ag_app::signed_transport::{SocketPeerCheckV1, call_signed};
use ag_effect::{EFFECT_SCHEMA_V1, EffectIntentV1, ProposalIntentV1, TargetId};
use ag_primitives::{AuthorityDomain, Digest, Epoch};
use ag_protocol::{RequestEnvelopeV1, RequestId, canonical_json, strict_json_from_slice};
use anyhow::{Context as _, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::{Deserialize, Serialize};

const KEY_ENROLLMENT_SCHEMA: &str = "ag.qualification.rpc-key-enrollment.v1";

#[derive(Debug, Parser)]
#[command(
    name = "ag-clean-host-rpc",
    version,
    about = "Qualification-only AG-ng key enrollment and signed-RPC fixture"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate one ring-compatible Ed25519 PKCS#8-v2 key and public enrollment.
    GenerateKey {
        /// Exact stable principal represented by the key.
        #[arg(long)]
        principal: Digest,
        /// Exact enrolled key identifier.
        #[arg(long)]
        key_id: String,
        /// New plaintext PKCS#8-v2 output; it must not already exist.
        #[arg(long, value_name = "PATH")]
        private_key_output: PathBuf,
        /// Runtime systemd credential path to place in configuration.
        #[arg(long, value_name = "PATH")]
        credential_path: PathBuf,
        /// Maximum absolute clock skew accepted for this peer enrollment.
        #[arg(long, default_value_t = 30_000)]
        maximum_clock_skew_ms: u64,
    },
    /// Perform one mutually authenticated health exchange.
    Health {
        /// Root-custodied single-role agctl configuration.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// Exact signed command plane to inspect.
        #[arg(value_enum)]
        component: HealthComponent,
    },
    /// Forward one strict proposal intent through agd's signed ingress.
    SubmitProposal {
        /// Root-custodied proposer-role agctl configuration.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// Bounded strict `ProposalIntentV1` JSON input.
        #[arg(long, value_name = "PATH")]
        intent: PathBuf,
    },
    /// Submit one synthetic governed managed-pointer request directly to effectd.
    ForwardManagedPointer {
        /// Root-custodied complete effectd configuration.
        #[arg(long, value_name = "PATH")]
        effectd_config: PathBuf,
        /// Protected plaintext PKCS#8-v2 key matching effectd's agd peer.
        #[arg(long, value_name = "PATH")]
        governor_credential: PathBuf,
        /// Protected plaintext PKCS#8-v2 key matching effectd's proposer peer.
        #[arg(long, value_name = "PATH")]
        proposer_credential: PathBuf,
        /// Stable bounded Git bundle transferred as the sole artifact.
        #[arg(long, value_name = "PATH")]
        artifact: PathBuf,
        /// Exact configured managed-pointer target ID.
        #[arg(long)]
        target: String,
        /// Exact nonempty intent correlation ID.
        #[arg(long)]
        intent_id: String,
        /// Exact governor judgment record digest to bind into the intent.
        #[arg(long)]
        judgment: Digest,
        /// Maximum skew used when authenticating effectd's response.
        #[arg(long)]
        effectd_skew_ms: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HealthComponent {
    /// Governor control plane.
    #[value(name = "agd")]
    Agd,
    /// Direct effect-broker admin plane, including activation status.
    #[value(name = "ag-effectd", alias = "effectd")]
    Effectd,
}

/// Public, canonical evidence emitted after the protected key file is durable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationKeyEnrollmentV1 {
    schema: String,
    private_key_output: PathBuf,
    private_key_byte_length: u64,
    signing_identity: RpcSigningIdentityConfigV1,
    peer_key_policy: RpcPeerKeyPolicyV1,
}

struct ClientV1 {
    signer: RpcSignerV1,
    endpoint: ClientEndpointV1,
    replay: RpcReplayGuardV1,
    maximum_frame_bytes: u32,
}

enum ClientEndpointV1 {
    Proposer {
        socket: PathBuf,
        peer: RpcPeerEnrollmentV1,
        socket_check: SocketPeerCheckV1,
        maximum_intent_bytes: u64,
    },
    EffectAdmin {
        socket: PathBuf,
        peer: RpcPeerEnrollmentV1,
        socket_check: SocketPeerCheckV1,
    },
}

impl ClientV1 {
    fn from_root_config(path: &Path) -> anyhow::Result<Self> {
        let config: AgctlConfigV1 =
            load_config(path, true).context("cannot load root-custodied agctl config")?;
        config.validate().context("invalid agctl config")?;
        let signer = RpcSignerV1::from_systemd_credential(&config.rpc_signing_identity)
            .context("cannot load enrolled client signing credential")?;
        let replay_capacity = usize::try_from(config.limits.rpc_replay_capacity)
            .context("RPC replay capacity does not fit this platform")?;
        let replay = RpcReplayGuardV1::new(replay_capacity)?;
        let endpoint = match config.command_profile {
            AgctlCommandProfileV1::Proposer {
                agd_socket,
                agd_peer,
                max_intent_file_bytes,
            } => ClientEndpointV1::Proposer {
                socket: agd_socket,
                peer: enrollment(&agd_peer)?,
                socket_check: socket_check(&agd_peer),
                maximum_intent_bytes: max_intent_file_bytes,
            },
            AgctlCommandProfileV1::EffectAdmin {
                effectd_admin_socket,
                effectd_peer,
            } => ClientEndpointV1::EffectAdmin {
                socket: effectd_admin_socket,
                peer: enrollment(&effectd_peer)?,
                socket_check: socket_check(&effectd_peer),
            },
        };
        Ok(Self {
            signer,
            endpoint,
            replay,
            maximum_frame_bytes: config.limits.max_control_frame_bytes,
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
            bail!("effect-admin configuration cannot call agd");
        };
        let result: ApiResultV1<AgdResponseV1> = call_signed(
            socket,
            request_id()?,
            request,
            self.maximum_frame_bytes,
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
            bail!("proposer configuration cannot call ag-effectd admin");
        };
        let result: ApiResultV1<EffectAdminResponseV1> = call_signed(
            socket,
            request_id()?,
            request,
            self.maximum_frame_bytes,
            &self.signer,
            peer,
            &self.replay,
            &SystemRpcClockV1,
            *socket_check,
        )
        .context("authenticated ag-effectd RPC failed")?;
        require_api_ok(result)
    }
}

fn main() -> anyhow::Result<()> {
    match Arguments::parse().command {
        Command::GenerateKey {
            principal,
            key_id,
            private_key_output,
            credential_path,
            maximum_clock_skew_ms,
        } => {
            let record = generate_key(
                principal,
                RpcKeyIdV1::new(key_id)?,
                &private_key_output,
                credential_path,
                maximum_clock_skew_ms,
            )?;
            write_canonical(&record)
        }
        Command::Health { config, component } => health(&config, component),
        Command::SubmitProposal { config, intent } => submit_proposal(&config, &intent),
        Command::ForwardManagedPointer {
            effectd_config,
            governor_credential,
            proposer_credential,
            artifact,
            target,
            intent_id,
            judgment,
            effectd_skew_ms,
        } => forward_managed_pointer(ForwardManagedPointerArgsV1 {
            effectd_config,
            governor_credential,
            proposer_credential,
            artifact,
            target,
            intent_id,
            judgment,
            effectd_skew_ms,
        }),
    }
}

fn generate_key(
    principal: Digest,
    key_id: RpcKeyIdV1,
    private_key_output: &Path,
    credential_path: PathBuf,
    maximum_clock_skew_ms: u64,
) -> anyhow::Result<QualificationKeyEnrollmentV1> {
    require_normalized_absolute(private_key_output, "private-key output")?;
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("secure Ed25519 key generation failed"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(document.as_ref())
        .map_err(|_| anyhow::anyhow!("generated Ed25519 PKCS#8-v2 key did not reopen"))?;
    let public_key =
        RpcPublicKeyV1::from_base64url(&URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref()))?;
    let signing_identity = RpcSigningIdentityConfigV1 {
        principal: principal.clone(),
        key_id: key_id.clone(),
        public_key: public_key.clone(),
        private_key_credential: credential_path,
    };
    signing_identity.validate()?;
    let peer_key_policy = RpcPeerKeyPolicyV1 {
        principal,
        key_id,
        public_key,
        maximum_clock_skew_ms,
    };
    peer_key_policy.validate()?;
    write_new_private_key(private_key_output, document.as_ref())?;
    Ok(QualificationKeyEnrollmentV1 {
        schema: KEY_ENROLLMENT_SCHEMA.to_owned(),
        private_key_output: private_key_output.to_owned(),
        private_key_byte_length: u64::try_from(document.as_ref().len())?,
        signing_identity,
        peer_key_policy,
    })
}

fn write_new_private_key(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    // Keep the exclusive create outside the cleanup scope: an `AlreadyExists`
    // refusal must never unlink the pre-existing file it protected.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot create new private-key output {}", path.display()))?;
    let result = (|| -> anyhow::Result<()> {
        file.write_all(bytes)
            .context("cannot write private-key output")?;
        file.sync_all().context("cannot sync private-key output")?;
        let metadata = file
            .metadata()
            .context("cannot inspect private-key output descriptor")?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.gid() != nix::unistd::getegid().as_raw()
            || metadata.len() != u64::try_from(bytes.len())?
        {
            bail!("private-key output has unexpected custody or length");
        }
        let parent = path
            .parent()
            .context("private-key output has no parent directory")?;
        File::open(parent)
            .context("cannot open private-key parent directory")?
            .sync_all()
            .context("cannot sync private-key parent directory")?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

fn require_normalized_absolute(path: &Path, description: &str) -> anyhow::Result<()> {
    let mut normalized = PathBuf::from("/");
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        bail!("{description} must be absolute");
    }
    for component in components {
        let Component::Normal(component) = component else {
            bail!("{description} must be normalized");
        };
        normalized.push(component);
    }
    if normalized != path || normalized == Path::new("/") {
        bail!("{description} must be a non-root normalized absolute path");
    }
    Ok(())
}

fn health(config: &Path, component: HealthComponent) -> anyhow::Result<()> {
    let client = ClientV1::from_root_config(config)?;
    match component {
        HealthComponent::Agd => {
            let response = client.call_agd(AgdRequestV1::Health)?;
            let AgdResponseV1::Health { health } = &response else {
                bail!("agd returned an unexpected response");
            };
            require_health_identity(health, "agd")?;
            write_canonical(&response)?;
            require_ready(health)
        }
        HealthComponent::Effectd => {
            let response = client.call_effectd(EffectAdminRequestV1::Health)?;
            let EffectAdminResponseV1::Health { health, .. } = &response else {
                bail!("ag-effectd returned an unexpected response");
            };
            require_health_identity(health, "ag-effectd")?;
            // Unlike installed agctl, retain the complete activation status.
            write_canonical(&response)?;
            require_ready(health)
        }
    }
}

fn submit_proposal(config: &Path, intent: &Path) -> anyhow::Result<()> {
    let client = ClientV1::from_root_config(config)?;
    let ClientEndpointV1::Proposer {
        maximum_intent_bytes,
        ..
    } = &client.endpoint
    else {
        bail!("effect-admin configuration cannot submit a proposal");
    };
    let intent: ProposalIntentV1 = read_strict_file(intent, *maximum_intent_bytes)?;
    intent
        .validate_shape()
        .context("proposal intent failed closed shape validation")?;
    let response = client.call_agd(AgdRequestV1::SubmitProposal {
        intent: Box::new(intent),
    })?;
    write_canonical(&response)?;
    match response {
        AgdResponseV1::ProposalSubmitted { .. } => Ok(()),
        AgdResponseV1::Refused { .. } => bail!("agd semantically refused the proposal"),
        AgdResponseV1::Indeterminate { .. } => {
            bail!("agd returned an operationally indeterminate proposal result")
        }
        _ => bail!("agd returned an unexpected proposal response"),
    }
}

struct ForwardManagedPointerArgsV1 {
    effectd_config: PathBuf,
    governor_credential: PathBuf,
    proposer_credential: PathBuf,
    artifact: PathBuf,
    target: String,
    intent_id: String,
    judgment: Digest,
    effectd_skew_ms: Option<u64>,
}

#[allow(clippy::similar_names)]
fn forward_managed_pointer(arguments: ForwardManagedPointerArgsV1) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
        bail!("direct managed-pointer forwarding must start with effective UID and GID 0");
    }
    let config: EffectdConfigV1 = load_config(&arguments.effectd_config, true)
        .context("cannot load root-custodied effectd config")?;
    config.validate().context("invalid effectd config")?;

    let artifact_bound = managed_pointer_artifact_bound(
        config.limits.max_artifact_bytes,
        config.limits.max_control_frame_bytes,
    );
    let artifact = read_stable_bytes(
        &arguments.artifact,
        artifact_bound,
        "managed-pointer artifact",
    )?;
    let governor_identity =
        signing_identity_for_peer(&config.agd_peer, arguments.governor_credential)?;
    let proposer_identity =
        signing_identity_for_peer(&config.proposer_peer, arguments.proposer_credential)?;
    // Both protected credentials and the root-owned config are opened before
    // leaving root. The real effectd connection occurs only after the exact
    // configured ag-governor identity transition below.
    let governor = RpcSignerV1::from_systemd_credential(&governor_identity)
        .context("cannot load the enrolled governor signing credential")?;
    let proposer = RpcSignerV1::from_systemd_credential(&proposer_identity)
        .context("cannot load the enrolled proposer signing credential")?;
    let now_unix_ms = SystemRpcClockV1.now_unix_ms()?;
    let request = build_managed_pointer_submission(
        &config,
        &governor,
        &proposer,
        &artifact,
        &arguments.target,
        &arguments.intent_id,
        arguments.judgment,
        now_unix_ms,
    )?;
    drop(artifact);
    drop(proposer);

    let effectd = effectd_enrollment(&config, arguments.effectd_skew_ms.unwrap_or(30_000))?;
    let replay_capacity = usize::try_from(config.limits.max_rpc_replay_entries)
        .context("effectd RPC replay capacity does not fit this platform")?;
    let replay = RpcReplayGuardV1::new(replay_capacity)?;
    let proposal_socket = config.proposal_socket.clone();
    let maximum_frame_bytes = config.limits.max_control_frame_bytes;
    let governor_uid = config.agd_peer.uid;
    let governor_gid = config.agd_peer.gid;
    drop(config);

    drop_to_governor_identity(governor_uid, governor_gid)?;
    let response: ApiResultV1<EffectProposalResponseV1> = call_signed(
        &proposal_socket,
        request_id()?,
        request,
        maximum_frame_bytes,
        &governor,
        &effectd,
        &replay,
        &SystemRpcClockV1,
        SocketPeerCheckV1::RequireUidGid { uid: 0, gid: 0 },
    )
    .context("authenticated direct effectd proposal RPC failed")?;
    write_canonical(&response)?;
    match response {
        ApiResultV1::Ok {
            response: EffectProposalResponseV1::Canonicalized { .. },
        } => Ok(()),
        ApiResultV1::Ok { .. } => {
            bail!("effectd returned a non-canonicalized managed-pointer result")
        }
        ApiResultV1::Error { .. } => bail!("effectd rejected managed-pointer forwarding"),
    }
}

fn managed_pointer_artifact_bound(maximum_artifact_bytes: u64, maximum_frame_bytes: u32) -> u64 {
    // Match production agd's transfer budget: the balance of the signed frame
    // remains available for base64 expansion and the authenticated envelope.
    maximum_artifact_bytes.min(u64::from(maximum_frame_bytes) / 2)
}

#[allow(clippy::too_many_arguments)]
fn build_managed_pointer_submission(
    config: &EffectdConfigV1,
    governor: &RpcSignerV1,
    proposer: &RpcSignerV1,
    artifact_bytes: &[u8],
    target: &str,
    intent_id: &str,
    judgment: Digest,
    now_unix_ms: u64,
) -> anyhow::Result<EffectProposalRequestV1> {
    let _governor_enrollment = signer_matches_peer(governor, &config.agd_peer)
        .context("governor signer does not match effectd enrollment")?;
    let proposer_enrollment = signer_matches_peer(proposer, &config.proposer_peer)
        .context("proposer signer does not match effectd enrollment")?;
    let target = TargetId::parse(target.to_owned()).context("invalid target ID")?;
    let configured_target = config.targets.iter().find(|configured| {
        let id = match configured {
            EffectTargetConfigV1::ManagedPointer { id, .. }
            | EffectTargetConfigV1::ManagedFile { id, .. }
            | EffectTargetConfigV1::SystemdUnit { id, .. }
            | EffectTargetConfigV1::SystemdManager { id } => id,
        };
        id == target.as_str()
    });
    match configured_target {
        Some(EffectTargetConfigV1::ManagedPointer { .. }) => {}
        Some(_) => bail!("requested target is not a configured managed pointer"),
        None => bail!("requested managed-pointer target is absent from effectd config"),
    }

    let authority_domain = AuthorityDomain::parse(&config.authority_domain)
        .context("invalid effectd authority domain")?;
    let epoch = Epoch::parse(&config.epoch).context("invalid effectd authority epoch")?;
    let verified_proposer = VerifiedRpcPrincipalV1 {
        principal: proposer_enrollment.principal.clone(),
        key_id: proposer_enrollment.key.key_id.clone(),
    };
    let proposer_chain = signed_principal_chain(
        &verified_proposer,
        &config.proposer_peer,
        authority_domain.clone(),
        epoch,
    )?;
    let artifact = Digest::hash_bytes(artifact_bytes);
    let intent = ProposalIntentV1 {
        schema: EFFECT_SCHEMA_V1.to_owned(),
        intent_id: intent_id.to_owned(),
        authority_domain,
        epoch,
        proposer: proposer_chain,
        judgment,
        admitted_artifacts: BTreeSet::from([artifact.clone()]),
        effects: vec![EffectIntentV1::ManagedPointerPromotion {
            target,
            artifact: artifact.clone(),
        }],
    };
    intent
        .validate_shape()
        .context("synthetic managed-pointer intent is invalid")?;

    let challenge = governor.issue_challenge(&proposer_enrollment, now_unix_ms)?;
    let inner_request = RequestEnvelopeV1::new(
        RequestId::new(format!("ag-clean-host-inner-{}", uuid::Uuid::new_v4()))?,
        AgdRequestV1::SubmitProposal {
            intent: Box::new(intent),
        },
    )?;
    let signed_request = proposer.sign_request(inner_request, &challenge, now_unix_ms)?;
    Ok(EffectProposalRequestV1::SubmitAuthenticatedIntent {
        ingress: Box::new(GovernedProposalIngressV1::ExternalSigned {
            proof: Box::new(ProposalIngressProofV1 {
                server_challenge: challenge,
                signed_request: Box::new(signed_request),
            }),
        }),
        artifacts: vec![ArtifactTransferV1 {
            digest: artifact,
            byte_length: u64::try_from(artifact_bytes.len())?,
            content_base64: STANDARD.encode(artifact_bytes),
        }],
    })
}

fn signing_identity_for_peer(
    peer: &PeerPolicyV1,
    private_key_credential: PathBuf,
) -> anyhow::Result<RpcSigningIdentityConfigV1> {
    let identity = RpcSigningIdentityConfigV1 {
        principal: peer.rpc_key.principal.clone(),
        key_id: peer.rpc_key.key_id.clone(),
        public_key: peer.rpc_key.public_key.clone(),
        private_key_credential,
    };
    identity.validate()?;
    Ok(identity)
}

fn signer_matches_peer(
    signer: &RpcSignerV1,
    peer: &PeerPolicyV1,
) -> anyhow::Result<RpcPeerEnrollmentV1> {
    let enrollment = signer.enrollment(peer.rpc_key.maximum_clock_skew_ms)?;
    if enrollment.principal != peer.rpc_key.principal || enrollment.key != peer.rpc_key {
        bail!("signing credential differs from configured peer key policy");
    }
    Ok(enrollment)
}

fn effectd_enrollment(
    config: &EffectdConfigV1,
    maximum_clock_skew_ms: u64,
) -> anyhow::Result<RpcPeerEnrollmentV1> {
    let key = RpcPeerKeyPolicyV1 {
        principal: config.rpc_signing_identity.principal.clone(),
        key_id: config.rpc_signing_identity.key_id.clone(),
        public_key: config.rpc_signing_identity.public_key.clone(),
        maximum_clock_skew_ms,
    };
    RpcPeerEnrollmentV1::new(key.principal.clone(), key).map_err(Into::into)
}

#[allow(clippy::similar_names)]
fn drop_to_governor_identity(uid: u32, gid: u32) -> anyhow::Result<()> {
    if uid == 0 || gid == 0 || uid == u32::MAX || gid == u32::MAX {
        bail!("configured ag-governor UID/GID is not an ordinary service identity");
    }
    nix::unistd::setgroups(&[]).context("cannot clear supplementary groups")?;
    let governor_gid = nix::unistd::Gid::from_raw(gid);
    nix::unistd::setresgid(governor_gid, governor_gid, governor_gid)
        .context("cannot enter configured real/effective/saved ag-governor GID")?;
    let governor_uid = nix::unistd::Uid::from_raw(uid);
    nix::unistd::setresuid(governor_uid, governor_uid, governor_uid)
        .context("cannot enter configured real/effective/saved ag-governor UID")?;
    let observed_uid = nix::unistd::getresuid().context("cannot verify ag-governor UIDs")?;
    let observed_gid = nix::unistd::getresgid().context("cannot verify ag-governor GIDs")?;
    if observed_uid.real != governor_uid
        || observed_uid.effective != governor_uid
        || observed_uid.saved != governor_uid
        || observed_gid.real != governor_gid
        || observed_gid.effective != governor_gid
        || observed_gid.saved != governor_gid
        || !nix::unistd::getgroups()?.is_empty()
    {
        bail!("ag-governor privilege-floor transition did not hold exactly");
    }
    Ok(())
}

fn read_strict_file<T>(path: &Path, maximum: u64) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let bytes = read_stable_bytes(path, maximum, "strict input")?;
    strict_json_from_slice(&bytes).context("strict input is invalid JSON")
}

fn read_stable_bytes(path: &Path, maximum: u64, name: &str) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open {name} {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("cannot inspect {name}"))?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > maximum {
        bail!("{name} is not a bounded single-link regular file");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {name}"))?;
    let after = file
        .metadata()
        .with_context(|| format!("cannot re-inspect {name}"))?;
    if u64::try_from(bytes.len())? > maximum
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.len() != u64::try_from(bytes.len())?
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("{name} changed while it was read");
    }
    Ok(bytes)
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
    RequestId::new(format!("ag-clean-host-{}", uuid::Uuid::new_v4())).map_err(Into::into)
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

fn require_health_identity(health: &HealthV1, expected: &str) -> anyhow::Result<()> {
    if health.schema != "ag.health/v1" || health.service != expected {
        bail!("authenticated peer returned the wrong health identity");
    }
    Ok(())
}

fn require_ready(health: &HealthV1) -> anyhow::Result<()> {
    if health.quiesced {
        bail!("{} is quiesced", health.service);
    }
    if !health.ready {
        bail!("{} is not ready", health.service);
    }
    Ok(())
}

fn write_canonical(value: &impl Serialize) -> anyhow::Result<()> {
    let mut bytes = canonical_json(value)?;
    bytes.push(b'\n');
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .context("cannot write canonical output")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const PRINCIPAL: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const POINTER_TARGET: &str = "qualification-pointer";

    fn ephemeral_signer(label: &str) -> RpcSignerV1 {
        RpcSignerV1::generate_ephemeral_candidate_ingress(
            Digest::hash_domain(
                "ag-ng/qualification-rpc-test-principal/v1",
                label.as_bytes(),
            ),
            RpcKeyIdV1::new(format!("qualification-{label}.v1")).expect("key ID"),
        )
        .expect("ephemeral signer")
        .0
    }

    fn enroll_test_peer(peer: &mut PeerPolicyV1, signer: &RpcSignerV1) {
        let enrollment = signer.enrollment(30_000).expect("peer enrollment");
        peer.stable_principal_root = enrollment.principal;
        peer.rpc_key = enrollment.key;
    }

    fn forwarding_config(
        governor: &RpcSignerV1,
        proposer: &RpcSignerV1,
        effectd: &RpcSignerV1,
    ) -> EffectdConfigV1 {
        let mut config: EffectdConfigV1 =
            toml::from_str(include_str!("../../../../config/effectd.example.toml"))
                .expect("effectd example");
        enroll_test_peer(&mut config.agd_peer, governor);
        enroll_test_peer(&mut config.proposer_peer, proposer);
        let enrollment = effectd.enrollment(30_000).expect("effectd enrollment");
        config.rpc_signing_identity = RpcSigningIdentityConfigV1 {
            principal: enrollment.principal,
            key_id: enrollment.key.key_id,
            public_key: enrollment.key.public_key,
            private_key_credential: PathBuf::from(
                "/run/credentials/ag-effectd.service/rpc-ed25519-pkcs8",
            ),
        };
        config.targets.push(EffectTargetConfigV1::ManagedPointer {
            id: POINTER_TARGET.to_owned(),
            allowed_root: PathBuf::from("/srv/agent-governor/repositories"),
            repository: PathBuf::from("/srv/agent-governor/repositories/service.git"),
            reference: "refs/heads/main".to_owned(),
            activation_genesis_object: "1".repeat(40),
            activation_genesis_tree: "2".repeat(40),
            activation_genesis_state: Digest::hash_bytes(b"genesis state"),
            repository_identity: Digest::hash_bytes(b"repository identity"),
            uid: 1001,
            gid: 1001,
            staging_root: PathBuf::from("/var/lib/agent-governor/effectd/promotion-stage"),
            promotion_ttl_ms: 60_000,
            helper: PathBuf::from("/usr/bin/git"),
            helper_executable: Digest::hash_bytes(b"git executable"),
            helper_launch_profile: Digest::hash_bytes(b"git launch profile"),
        });
        config.validate().expect("forwarding config");
        config
    }

    #[test]
    fn managed_pointer_forwarding_has_exact_nested_proofs_and_artifact() {
        let governor = ephemeral_signer("governor");
        let proposer = ephemeral_signer("proposer");
        let effectd = ephemeral_signer("effectd");
        let config = forwarding_config(&governor, &proposer, &effectd);
        let artifact_bytes = b"qualification managed-pointer bundle bytes";
        let judgment = Digest::hash_bytes(b"qualification judgment");
        let now_unix_ms = 1_900_000_000_000;
        let request = build_managed_pointer_submission(
            &config,
            &governor,
            &proposer,
            artifact_bytes,
            POINTER_TARGET,
            "qualification-intent-1",
            judgment.clone(),
            now_unix_ms,
        )
        .expect("managed-pointer forwarding request");

        let EffectProposalRequestV1::SubmitAuthenticatedIntent { ingress, artifacts } = request
        else {
            panic!("unexpected effectd request");
        };
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].digest, Digest::hash_bytes(artifact_bytes));
        assert_eq!(artifacts[0].byte_length, artifact_bytes.len() as u64);
        assert_eq!(
            STANDARD
                .decode(&artifacts[0].content_base64)
                .expect("base64"),
            artifact_bytes
        );
        let GovernedProposalIngressV1::ExternalSigned { proof } = *ingress else {
            panic!("unexpected ingress kind");
        };
        let governor_enrollment = governor.enrollment(30_000).expect("governor enrollment");
        let proposer_enrollment = proposer.enrollment(30_000).expect("proposer enrollment");
        let verified = ag_app::rpc_auth::verify_forwarded_signed_request(
            &proof.server_challenge,
            &proof.signed_request,
            &governor_enrollment,
            &proposer_enrollment,
            &RpcReplayGuardV1::new(4).expect("replay guard"),
            now_unix_ms,
        )
        .expect("nested proof verifies");
        assert_eq!(verified.principal, *proposer.principal());
        let AgdRequestV1::SubmitProposal { intent } = &proof.signed_request.request.body else {
            panic!("unexpected inner request");
        };
        assert_eq!(intent.schema, EFFECT_SCHEMA_V1);
        assert_eq!(intent.intent_id, "qualification-intent-1");
        assert_eq!(intent.authority_domain.as_str(), config.authority_domain);
        assert_eq!(intent.epoch, Epoch::parse(&config.epoch).expect("epoch"));
        assert_eq!(intent.judgment, judgment);
        assert_eq!(
            intent.admitted_artifacts,
            BTreeSet::from([Digest::hash_bytes(artifact_bytes)])
        );
        assert!(matches!(
            intent.effects.as_slice(),
            [EffectIntentV1::ManagedPointerPromotion { target, artifact }]
                if target.as_str() == POINTER_TARGET
                    && artifact == &Digest::hash_bytes(artifact_bytes)
        ));
    }

    #[test]
    fn managed_pointer_forwarding_rejects_non_pointer_target() {
        let governor = ephemeral_signer("governor-wrong-target");
        let proposer = ephemeral_signer("proposer-wrong-target");
        let effectd = ephemeral_signer("effectd-wrong-target");
        let config = forwarding_config(&governor, &proposer, &effectd);
        let error = build_managed_pointer_submission(
            &config,
            &governor,
            &proposer,
            b"artifact",
            "service-config",
            "qualification-intent-2",
            Digest::hash_bytes(b"judgment"),
            1_900_000_000_000,
        )
        .expect_err("managed-file target must refuse");
        assert!(
            error
                .to_string()
                .contains("not a configured managed pointer")
        );
    }

    #[test]
    fn stable_artifact_reader_rejects_symlink() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact = temporary.path().join("artifact.bundle");
        let link = temporary.path().join("artifact-link.bundle");
        std::fs::write(&artifact, b"bundle").expect("artifact");
        std::os::unix::fs::symlink(&artifact, &link).expect("symlink");
        read_stable_bytes(&link, 1024, "managed-pointer artifact")
            .expect_err("symlink must refuse");
    }

    #[test]
    fn managed_pointer_artifact_bound_matches_production_forwarder() {
        assert_eq!(managed_pointer_artifact_bound(20_000, 30_000), 15_000);
        assert_eq!(managed_pointer_artifact_bound(10_000, 30_000), 10_000);
    }

    #[test]
    fn generated_key_reopens_and_matches_public_enrollment() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let output = temporary.path().join("rpc.pkcs8");
        let record = generate_key(
            Digest::parse(PRINCIPAL).expect("principal"),
            RpcKeyIdV1::new("qualification.v1").expect("key ID"),
            &output,
            PathBuf::from("/run/credentials/fixture.service/rpc-ed25519-pkcs8"),
            30_000,
        )
        .expect("generate key");

        let bytes = std::fs::read(&output).expect("private key");
        let key_pair = Ed25519KeyPair::from_pkcs8(&bytes).expect("ring PKCS#8 v2");
        assert_eq!(record.schema, KEY_ENROLLMENT_SCHEMA);
        assert_eq!(record.private_key_byte_length, bytes.len() as u64);
        assert_eq!(
            record.peer_key_policy.public_key.to_base64url(),
            URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref())
        );
        assert_eq!(
            record.signing_identity.public_key,
            record.peer_key_policy.public_key
        );
        let metadata = std::fs::metadata(&output).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);

        let canonical = canonical_json(&record).expect("canonical record");
        let reopened: QualificationKeyEnrollmentV1 =
            strict_json_from_slice(&canonical).expect("strict record");
        assert_eq!(reopened, record);
    }

    #[test]
    fn existing_private_key_output_is_never_replaced() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let output = temporary.path().join("rpc.pkcs8");
        std::fs::write(&output, b"sentinel").expect("sentinel");
        let error = generate_key(
            Digest::parse(PRINCIPAL).expect("principal"),
            RpcKeyIdV1::new("qualification.v1").expect("key ID"),
            &output,
            PathBuf::from("/run/credentials/fixture.service/rpc-ed25519-pkcs8"),
            30_000,
        )
        .expect_err("existing output must refuse");
        assert!(
            error
                .to_string()
                .contains("cannot create new private-key output")
        );
        assert_eq!(std::fs::read(&output).expect("sentinel"), b"sentinel");
    }

    #[test]
    fn invalid_credential_path_does_not_publish_a_key() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let output = temporary.path().join("rpc.pkcs8");
        generate_key(
            Digest::parse(PRINCIPAL).expect("principal"),
            RpcKeyIdV1::new("qualification.v1").expect("key ID"),
            &output,
            PathBuf::from("relative/credential"),
            30_000,
        )
        .expect_err("relative credential path must refuse");
        assert!(!output.exists());
    }

    #[test]
    fn fixture_is_absent_from_production_build_and_install_manifests() {
        let root_manifest = include_str!("../../../../Cargo.toml");
        let install_manifest = include_str!("../../../../debian/agent-governor-ng.install");
        assert!(!root_manifest.contains("qualification/clean-host/rpc-tool"));
        assert!(!install_manifest.contains("ag-clean-host-rpc"));
        assert!(!install_manifest.contains("qualification/clean-host/rpc-tool"));
    }
}
