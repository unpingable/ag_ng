//! Credential-isolated provider proxy entry point.

use std::path::PathBuf;
use std::sync::Arc;

use ag_app::api::{ApiResultV1, ProviderRequestV1, ProviderResponseV1};
use ag_app::config::{LoadedConfigV1, ProviderdConfigV1, load_config_with_identity};
use ag_app::rpc_auth::{RpcReplayGuardV1, RpcSignerV1, SystemRpcClockV1};
use ag_app::runtime::{ComponentActivationContextV1, open_component_store};
use ag_app::signed_transport::{
    AcceptedSignedRequestV1, SocketPeerCheckV1, accept_signed_request, write_signed_response,
};
use ag_app::transport::bind_socket;
use ag_protocol::FrameCodec;
use ag_providerd::ProviderCoreV1;
use clap::Parser;
use tracing::{info, warn};

const PROVIDERD_APPLICATION_ID: u32 = 0x4147_5001;

#[derive(Debug, Parser)]
#[command(
    name = "ag-providerd",
    version,
    about = "Session-bound AG-ng inference credential proxy"
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
    ag_app::init_logging("ag-providerd");
    let LoadedConfigV1 {
        config,
        exact_bytes_digest: config_identity,
    }: LoadedConfigV1<ProviderdConfigV1> = load_config_with_identity(&arguments.config, true)?;
    config.validate()?;
    if arguments.check_config {
        info!(path = %arguments.config.display(), "configuration is valid");
        return Ok(());
    }

    let signer = Arc::new(RpcSignerV1::from_systemd_credential(
        &config.rpc_signing_identity,
    )?);
    let replay = Arc::new(RpcReplayGuardV1::new(
        config.limits.max_rpc_replay_entries as usize,
    )?);
    let caller = config.caller_peer.rpc_enrollment()?;
    let caller_socket_check = SocketPeerCheckV1::RequireUidGid {
        uid: config.caller_peer.uid,
        gid: config.caller_peer.gid,
    };

    let store = open_component_store(
        PROVIDERD_APPLICATION_ID,
        "ag-providerd",
        &config_identity,
        ComponentActivationContextV1 {
            authority_domain: &config.authority_domain,
            epoch: &config.epoch,
            security_profile: &config.security_profile,
            authority_catalog_identity: None,
        },
        &config.store,
    )?;
    let listener = bind_socket(&config.socket, &config.socket_custody)?;
    let codec = FrameCodec::new(config.limits.max_control_frame_bytes)?;
    let socket_display = config.socket.display().to_string();
    let mut provider = ProviderCoreV1::new(store, config)?;
    info!(socket = %socket_display, "provider proxy listening");

    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                warn!(%error, "provider socket accept failed");
                continue;
            }
        };
        let request: AcceptedSignedRequestV1<ProviderRequestV1> = match accept_signed_request(
            &mut stream,
            codec,
            &signer,
            &caller,
            &replay,
            &SystemRpcClockV1,
            caller_socket_check,
        ) {
            Ok(request) => request,
            Err(error) => {
                warn!(%error, "rejected signed provider request");
                continue;
            }
        };
        let response: ApiResultV1<ProviderResponseV1> =
            provider.handle(request.body().clone(), &request.authenticated_peer);
        if let Err(error) = write_signed_response(
            &mut stream,
            codec,
            &signer,
            &request,
            response,
            &SystemRpcClockV1,
        ) {
            warn!(%error, "provider response write failed");
        }
    }
    Ok(())
}
