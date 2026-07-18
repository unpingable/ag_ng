//! Privileged exact-effect broker entry point.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;

use ag_app::api::{
    ApiResultV1, EffectAdminRequestV1, EffectAdminResponseV1, EffectProposalRequestV1,
    EffectProposalResponseV1,
};
use ag_app::config::{EffectdConfigV1, LoadedConfigV1, load_config_with_identity};
use ag_app::effectd::{EffectBrokerV1, LinuxManagedEffectRunnerV1, configured_catalog_identity};
use ag_app::rpc_auth::{
    RpcPeerEnrollmentV1, RpcReplayGuardV1, RpcSignerV1, SystemRpcClockV1, VerifiedRpcPrincipalV1,
};
use ag_app::runtime::{ComponentActivationContextV1, open_component_store};
use ag_app::signed_transport::{
    AcceptedSignedRequestV1, SocketPeerCheckV1, accept_signed_request, write_signed_response,
};
use ag_app::transport::bind_socket;
use ag_primitives::Digest;
use ag_protocol::FrameCodec;
use clap::Parser;
use tracing::{error, info, warn};

const EFFECTD_APPLICATION_ID: u32 = 0x4147_4501;

#[derive(Debug, Parser)]
#[command(
    name = "ag-effectd",
    version,
    about = "Exact, networkless AG-ng effect broker"
)]
struct Arguments {
    /// Root-owned daemon configuration.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    /// Validate configuration and exit without opening sockets or the store.
    #[arg(long)]
    check_config: bool,
}

enum BrokerCommand {
    Proposal {
        request: EffectProposalRequestV1,
        peer: VerifiedRpcPrincipalV1,
        reply: mpsc::SyncSender<ApiResultV1<EffectProposalResponseV1>>,
    },
    Admin {
        request: EffectAdminRequestV1,
        peer: VerifiedRpcPrincipalV1,
        signed_request: Digest,
        reply: mpsc::SyncSender<ApiResultV1<EffectAdminResponseV1>>,
    },
}

// Startup deliberately keeps the authority-bearing resources and listener handoff
// visible in one place so their ownership is auditable.
#[allow(clippy::too_many_lines)]
fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    ag_app::init_logging("ag-effectd");
    let LoadedConfigV1 {
        config,
        exact_bytes_digest: config_identity,
    }: LoadedConfigV1<EffectdConfigV1> = load_config_with_identity(&arguments.config, true)?;
    config.validate()?;
    let catalog_identity = configured_catalog_identity(&config.targets)?;
    if arguments.check_config {
        info!(path = %arguments.config.display(), "configuration is valid");
        return Ok(());
    }

    let signer = Arc::new(RpcSignerV1::from_systemd_credential(
        &config.rpc_signing_identity,
    )?);
    let replay_guard = Arc::new(RpcReplayGuardV1::new(
        config.limits.max_rpc_replay_entries as usize,
    )?);
    let proposal_peer = config.agd_peer.rpc_enrollment()?;
    let admin_peer = config.admin_peer.rpc_enrollment()?;
    let proposal_socket_check = SocketPeerCheckV1::RequireUidGid {
        uid: config.agd_peer.uid,
        gid: config.agd_peer.gid,
    };
    let admin_socket_check = SocketPeerCheckV1::RequireUidGid {
        uid: config.admin_peer.uid,
        gid: config.admin_peer.gid,
    };

    let store = open_component_store(
        EFFECTD_APPLICATION_ID,
        "ag-effectd",
        &config_identity,
        ComponentActivationContextV1 {
            authority_domain: &config.authority_domain,
            epoch: &config.epoch,
            security_profile: &config.security_profile,
            authority_catalog_identity: Some(&catalog_identity),
        },
        &config.store,
    )?;
    let mut broker = EffectBrokerV1::new(
        &config,
        &catalog_identity,
        store,
        LinuxManagedEffectRunnerV1::default(),
        Arc::clone(&replay_guard),
    )?;
    let proposal_listener = bind_socket(&config.proposal_socket, &config.proposal_socket_custody)?;
    let admin_listener = bind_socket(&config.admin_socket, &config.admin_socket_custody)?;
    let codec = FrameCodec::new(config.limits.max_control_frame_bytes)?;
    let (commands_tx, commands_rx) = mpsc::sync_channel::<BrokerCommand>(128);

    let proposal_tx = commands_tx.clone();
    let proposal_signer = Arc::clone(&signer);
    let proposal_replay = Arc::clone(&replay_guard);
    std::thread::Builder::new()
        .name("effectd-proposal-listener".to_owned())
        .spawn(move || {
            for connection in proposal_listener.incoming() {
                let mut stream = match connection {
                    Ok(stream) => stream,
                    Err(error) => {
                        error!(%error, "proposal socket accept failed");
                        continue;
                    }
                };
                let request: AcceptedSignedRequestV1<EffectProposalRequestV1> =
                    match accept_signed_request(
                        &mut stream,
                        codec,
                        &proposal_signer,
                        &proposal_peer,
                        &proposal_replay,
                        &SystemRpcClockV1,
                        proposal_socket_check,
                    ) {
                        Ok(request) => request,
                        Err(error) => {
                            warn!(%error, "rejected signed proposal request");
                            continue;
                        }
                    };
                let (reply_tx, reply_rx) = mpsc::sync_channel(1);
                if proposal_tx
                    .send(BrokerCommand::Proposal {
                        request: request.body().clone(),
                        peer: request.authenticated_peer.clone(),
                        reply: reply_tx,
                    })
                    .is_err()
                {
                    break;
                }
                match reply_rx.recv() {
                    Ok(broker_response) => {
                        if let Err(error) = write_signed_response(
                            &mut stream,
                            codec,
                            &proposal_signer,
                            &request,
                            broker_response,
                            &SystemRpcClockV1,
                        ) {
                            warn!(%error, "proposal response write failed");
                        }
                    }
                    Err(_) => break,
                }
            }
        })?;

    let admin_tx = commands_tx;
    let admin_signer = Arc::clone(&signer);
    let admin_replay = Arc::clone(&replay_guard);
    std::thread::Builder::new()
        .name("effectd-admin-listener".to_owned())
        .spawn(move || {
            run_admin_listener(
                &admin_listener,
                codec,
                &admin_peer,
                &admin_signer,
                &admin_replay,
                &admin_tx,
                admin_socket_check,
            );
        })?;

    info!(
        proposal_socket = %config.proposal_socket.display(),
        admin_socket = %config.admin_socket.display(),
        "effect broker listening"
    );
    for command in commands_rx {
        match command {
            BrokerCommand::Proposal {
                request,
                peer,
                reply,
            } => {
                let _ = reply.send(broker.handle_proposal(request, &peer));
            }
            BrokerCommand::Admin {
                request,
                peer,
                signed_request,
                reply,
            } => {
                let _ = reply.send(broker.handle_admin(request, &peer, &signed_request));
            }
        }
    }
    Ok(())
}

fn run_admin_listener(
    listener: &std::os::unix::net::UnixListener,
    codec: FrameCodec,
    peer: &RpcPeerEnrollmentV1,
    signer: &RpcSignerV1,
    replay_guard: &RpcReplayGuardV1,
    commands: &mpsc::SyncSender<BrokerCommand>,
    socket_check: SocketPeerCheckV1,
) {
    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                error!(%error, "admin socket accept failed");
                continue;
            }
        };
        let request: AcceptedSignedRequestV1<EffectAdminRequestV1> = match accept_signed_request(
            &mut stream,
            codec,
            signer,
            peer,
            replay_guard,
            &SystemRpcClockV1,
            socket_check,
        ) {
            Ok(request) => request,
            Err(error) => {
                warn!(%error, "rejected signed admin request");
                continue;
            }
        };
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let signed_request = match Digest::from_serializable(&request.signed_request) {
            Ok(digest) => digest,
            Err(error) => {
                warn!(%error, "cannot bind accepted admin request to canonical evidence");
                continue;
            }
        };
        if commands
            .send(BrokerCommand::Admin {
                request: request.body().clone(),
                peer: request.authenticated_peer.clone(),
                signed_request,
                reply: reply_tx,
            })
            .is_err()
        {
            return;
        }
        match reply_rx.recv() {
            Ok(broker_response) => {
                if let Err(error) = write_signed_response(
                    &mut stream,
                    codec,
                    signer,
                    &request,
                    broker_response,
                    &SystemRpcClockV1,
                ) {
                    warn!(%error, "admin response write failed");
                }
            }
            Err(_) => return,
        }
    }
}
