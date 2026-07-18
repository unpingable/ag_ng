//! Unprivileged governor daemon entry point.

use std::path::PathBuf;
use std::sync::Arc;

use ag_app::agd::AgdCoreV1;
use ag_app::api::{AgdRequestV1, AgdResponseV1, ApiResultV1};
use ag_app::config::{AgdConfigV1, LoadedConfigV1, load_config_with_identity};
use ag_app::rpc_auth::{RpcReplayGuardV1, RpcSignerV1, SystemRpcClockV1};
use ag_app::runtime::{ComponentActivationContextV1, open_component_store};
use ag_app::signed_transport::{
    AcceptedSignedRequestV1, SocketPeerCheckV1, accept_signed_request, write_signed_response,
};
use ag_app::transport::bind_socket;
use ag_protocol::FrameCodec;
use clap::Parser;
use tracing::{info, warn};

const AGD_APPLICATION_ID: u32 = 0x4147_4401;

#[derive(Debug, Parser)]
#[command(
    name = "agd",
    version,
    about = "AG-ng judgment and batch-session daemon"
)]
struct Arguments {
    /// Daemon configuration.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    /// Validate configuration without opening the store or socket.
    #[arg(long)]
    check_config: bool,
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    ag_app::init_logging("agd");
    let LoadedConfigV1 {
        config,
        exact_bytes_digest: config_identity,
    }: LoadedConfigV1<AgdConfigV1> = load_config_with_identity(&arguments.config, true)?;
    config.validate()?;
    if arguments.check_config {
        info!(path = %arguments.config.display(), "configuration is valid");
        return Ok(());
    }

    let signer = Arc::new(RpcSignerV1::from_systemd_credential(
        &config.rpc_signing_identity,
    )?);
    let proposer = config.proposer_peer.rpc_enrollment()?;
    let proposer_socket_check = SocketPeerCheckV1::RequireUidGid {
        uid: config.proposer_peer.uid,
        gid: config.proposer_peer.gid,
    };
    let replay = Arc::new(RpcReplayGuardV1::new(
        config.limits.max_rpc_replay_entries as usize,
    )?);

    let store = open_component_store(
        AGD_APPLICATION_ID,
        "agd",
        &config_identity,
        ComponentActivationContextV1 {
            authority_domain: &config.authority_domain,
            epoch: &config.epoch,
            security_profile: &config.security_profile,
            authority_catalog_identity: None,
        },
        &config.store,
    )?;
    let listener = bind_socket(&config.control_socket, &config.control_socket_custody)?;
    let codec = FrameCodec::new(config.limits.max_control_frame_bytes)?;
    let socket_display = config.control_socket.display().to_string();
    let mut governor = AgdCoreV1::new(store, config, Arc::clone(&signer), Arc::clone(&replay))?;
    let recovery = governor.recover_forward_outbox()?;
    if recovery.completed > 0 {
        info!(
            completed = recovery.completed,
            "recovered durable effect-forward responses"
        );
    }
    if recovery.deferred > 0 {
        warn!(
            deferred = recovery.deferred,
            "effect forwards remain pending; effectd availability or fresh proposer proof is required"
        );
    }
    info!(socket = %socket_display, "governor listening");

    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                warn!(%error, "control socket accept failed");
                continue;
            }
        };
        let request: AcceptedSignedRequestV1<AgdRequestV1> = match accept_signed_request(
            &mut stream,
            codec,
            &signer,
            &proposer,
            &replay,
            &SystemRpcClockV1,
            proposer_socket_check,
        ) {
            Ok(request) => request,
            Err(error) => {
                warn!(%error, "rejected signed governor request");
                continue;
            }
        };
        let response: ApiResultV1<AgdResponseV1> = governor.handle_control(&request);
        if let Err(error) = write_signed_response(
            &mut stream,
            codec,
            &signer,
            &request,
            response,
            &SystemRpcClockV1,
        ) {
            warn!(%error, "governor response write failed");
        }
    }
    Ok(())
}
