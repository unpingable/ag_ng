//! Qualification-only key enrollment and signed local-RPC fixture.
//!
//! This binary is deliberately outside the production Cargo workspace and
//! Debian install manifest. It reuses production protocol types and transport
//! code so clean-host qualification does not invent a second wire protocol.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use ag_app::api::{
    AgdRequestV1, AgdResponseV1, ApiResultV1, EffectAdminRequestV1, EffectAdminResponseV1, HealthV1,
};
use ag_app::config::{
    AgctlCommandProfileV1, AgctlConfigV1, AgctlDaemonPeerV1, AgctlSocketPeerCheckV1, load_config,
};
use ag_app::rpc_auth::{
    RpcKeyIdV1, RpcPeerEnrollmentV1, RpcPeerKeyPolicyV1, RpcPublicKeyV1, RpcReplayGuardV1,
    RpcSignerV1, RpcSigningIdentityConfigV1, SystemRpcClockV1,
};
use ag_app::signed_transport::{SocketPeerCheckV1, call_signed};
use ag_effect::ProposalIntentV1;
use ag_primitives::Digest;
use ag_protocol::{RequestId, canonical_json, strict_json_from_slice};
use anyhow::{Context as _, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

fn read_strict_file<T>(path: &Path, maximum: u64) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open strict input {}", path.display()))?;
    let before = file.metadata().context("cannot inspect strict input")?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > maximum {
        bail!("strict input is not a bounded single-link regular file");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("cannot read strict input")?;
    let after = file.metadata().context("cannot re-inspect strict input")?;
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
        bail!("strict input changed while it was read");
    }
    strict_json_from_slice(&bytes).context("strict input is invalid JSON")
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
