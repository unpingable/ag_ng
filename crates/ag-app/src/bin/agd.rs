//! Unprivileged governor daemon entry point.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ag_app::agd::{AgdCoreV1, ProviderIoWorkerV1, spawn_provider_io_worker};
use ag_app::api::{
    AgdRequestV1, AgdResponseV1, ApiErrorCodeV1, ApiResultV1, ProviderRequestV1,
    ProviderResponseV1, WorkerProviderRequestV1, WorkerProviderResponseV1,
};
use ag_app::config::{AgdConfigV1, LoadedConfigV1, load_config_with_identity};
use ag_app::rpc_auth::{RpcPeerEnrollmentV1, RpcReplayGuardV1, RpcSignerV1, SystemRpcClockV1};
use ag_app::runtime::{ComponentActivationContextV1, open_component_store};
use ag_app::signed_transport::{
    AcceptedSignedRequestV1, SocketPeerCheckV1, accept_signed_request, call_signed_with_timeout,
    write_signed_response,
};
use ag_app::transport::bind_socket;
use ag_protocol::FrameCodec;
use clap::Parser;
use tracing::{info, warn};

const AGD_APPLICATION_ID: u32 = 0x4147_4401;
const CONTROL_IO_WORKERS: usize = 4;
const CONTROL_ACCEPT_QUEUE: usize = 32;
const CONTROL_DISPATCH_QUEUE: usize = 32;
const CONTROL_ACCEPT_BURST: usize = 16;
const CONTROL_DISPATCH_BURST: usize = 16;
const CONTROL_REPLY_TIMEOUT: Duration = Duration::from_secs(35);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAIN_IDLE_SLICE: Duration = Duration::from_millis(2);

type ControlResponseV1 = ApiResultV1<AgdResponseV1>;

struct AuthenticatedControlV1 {
    accepted: AcceptedSignedRequestV1<AgdRequestV1>,
    reply: SyncSender<CompletedControlV1>,
}

struct CompletedControlV1 {
    accepted: AcceptedSignedRequestV1<AgdRequestV1>,
    response: ControlResponseV1,
}

#[derive(Clone)]
struct ControlIoContextV1 {
    codec: FrameCodec,
    signer: Arc<RpcSignerV1>,
    proposer: RpcPeerEnrollmentV1,
    replay: Arc<RpcReplayGuardV1>,
    socket_check: SocketPeerCheckV1,
    dispatch: SyncSender<AuthenticatedControlV1>,
}

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
    let mut provider_io = if let Some(provider_peer) = config.providerd_peer.clone() {
        let provider_socket = config.providerd_socket.clone();
        let maximum = config.limits.max_control_frame_bytes;
        let timeout = Duration::from_millis(
            config
                .limits
                .max_session_seconds
                .saturating_mul(1000)
                .min(30_000),
        );
        let provider = provider_peer.rpc_enrollment()?;
        let socket_check = SocketPeerCheckV1::RequireUidGid {
            uid: provider_peer.uid,
            gid: provider_peer.gid,
        };
        let provider_signer = Arc::clone(&signer);
        let provider_replay = Arc::clone(&replay);
        Some(spawn_provider_io_worker(
            1,
            move |request: ProviderRequestV1| {
                call_signed_with_timeout::<_, ApiResultV1<ProviderResponseV1>>(
                    &provider_socket,
                    ag_protocol::RequestId::new(format!("agd-provider-{}", uuid::Uuid::new_v4()))
                        .expect("generated provider request identity is valid"),
                    request,
                    maximum,
                    &provider_signer,
                    &provider,
                    &provider_replay,
                    &SystemRpcClockV1,
                    socket_check,
                    timeout,
                )
                .unwrap_or_else(|_| {
                    ApiResultV1::error(
                        ApiErrorCodeV1::Indeterminate,
                        "signed provider transport outcome is indeterminate",
                    )
                })
            },
        )?)
    } else {
        None
    };
    let socket_display = config.control_socket.display().to_string();
    let mut governor = AgdCoreV1::new(store, config, Arc::clone(&signer), Arc::clone(&replay))?;
    recover_startup(&mut governor)?;

    let (accepted_sender, accepted_receiver) = sync_channel(CONTROL_ACCEPT_QUEUE);
    let (dispatch_sender, dispatch_receiver) = sync_channel(CONTROL_DISPATCH_QUEUE);
    let io_workers = spawn_control_io_workers(
        accepted_receiver,
        &ControlIoContextV1 {
            codec,
            signer: Arc::clone(&signer),
            proposer,
            replay: Arc::clone(&replay),
            socket_check: proposer_socket_check,
            dispatch: dispatch_sender,
        },
    )?;
    listener.set_nonblocking(true)?;
    info!(socket = %socket_display, "governor listening");

    let mut next_worker_poll = Instant::now();
    loop {
        if io_workers.iter().any(thread::JoinHandle::is_finished) {
            anyhow::bail!("a bounded governor control I/O worker terminated");
        }
        if provider_io
            .as_ref()
            .is_some_and(|provider| provider.thread.is_finished())
        {
            anyhow::bail!("the bounded provider I/O worker terminated");
        }

        poll_workers_if_due(&mut governor, &mut next_worker_poll)?;
        pump_provider_io(&mut governor, provider_io.as_mut())?;
        accept_control_burst(&listener, &accepted_sender)?;
        for _ in 0..CONTROL_DISPATCH_BURST {
            match dispatch_receiver.try_recv() {
                Ok(control) => {
                    dispatch_control(&mut governor, control);
                    poll_workers_if_due(&mut governor, &mut next_worker_poll)?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    anyhow::bail!("all bounded governor control I/O workers disconnected");
                }
            }
        }
        poll_workers_if_due(&mut governor, &mut next_worker_poll)?;
        pump_provider_io(&mut governor, provider_io.as_mut())?;

        let until_poll = next_worker_poll.saturating_duration_since(Instant::now());
        if !until_poll.is_zero() {
            thread::sleep(until_poll.min(MAIN_IDLE_SLICE));
        }
    }
}

fn pump_provider_io(
    governor: &mut AgdCoreV1,
    provider: Option<&mut ProviderIoWorkerV1>,
) -> anyhow::Result<()> {
    let Some(provider) = provider else {
        return Ok(());
    };
    while let Ok(completion) = provider.completions.try_recv() {
        let session = completion.job.session.clone();
        let attempt = completion.job.attempt.clone();
        let failure = match &completion.result {
            ApiResultV1::Error {
                code,
                message,
                correlation,
            } => Some((code.clone(), message.clone(), correlation.clone())),
            ApiResultV1::Ok { .. } => None,
        };
        if let Some(ack) =
            governor.reconcile_provider_io_completion(completion, current_unix_ms()?)?
        {
            provider.jobs.try_send(ack)?;
        } else if let Some((code, message, correlation)) = failure {
            governor.queue_worker_provider_response(
                &session,
                &ApiResultV1::Error {
                    code,
                    message,
                    correlation,
                },
            )?;
        } else {
            let response = governor.worker_provider_response(&session, &attempt)?;
            governor.queue_worker_provider_response(&session, &ApiResultV1::Ok { response })?;
        }
    }
    for (session, request) in governor.poll_worker_provider_frames()? {
        match request {
            WorkerProviderRequestV1::Infer {
                attempt,
                sanitized_headers,
                request_bytes,
            } => {
                governor.prepare_worker_provider_attempt(
                    &session,
                    attempt.clone(),
                    sanitized_headers,
                    request_bytes.as_slice(),
                    current_unix_ms()?,
                )?;
                let job =
                    governor.worker_provider_begin_job(&session, &attempt, current_unix_ms()?)?;
                provider.jobs.try_send(job)?;
                governor.queue_worker_provider_response(
                    &session,
                    &ApiResultV1::Ok {
                        response: WorkerProviderResponseV1::Pending { attempt },
                    },
                )?;
            }
            WorkerProviderRequestV1::Reconcile { attempt } => {
                let response = governor.worker_provider_response(&session, &attempt)?;
                governor.queue_worker_provider_response(&session, &ApiResultV1::Ok { response })?;
            }
        }
    }
    governor.flush_worker_provider_responses()?;
    Ok(())
}

fn current_unix_ms() -> anyhow::Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn recover_startup(governor: &mut AgdCoreV1) -> anyhow::Result<()> {
    let worker_recovery = governor.recover_worker_sessions()?;
    if worker_recovery.tombstoned > 0 {
        warn!(
            tombstoned = worker_recovery.tombstoned,
            "retired worker principals recovered from an interrupted daemon activation"
        );
    }
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
    let candidate_recovery = governor.recover_worker_candidates()?;
    if candidate_recovery.canonicalized > 0 {
        info!(
            canonicalized = candidate_recovery.canonicalized,
            "recovered broker-owned proposals from durable worker candidate custody"
        );
    }
    if candidate_recovery.refused > 0 {
        info!(
            refused = candidate_recovery.refused,
            "recovered durable broker refusal outcomes for worker candidates"
        );
    }
    if candidate_recovery.indeterminate > 0 {
        warn!(
            indeterminate = candidate_recovery.indeterminate,
            "recovered durable indeterminate broker outcomes for worker candidates"
        );
    }
    if candidate_recovery.deferred > 0 {
        warn!(
            deferred = candidate_recovery.deferred,
            "worker candidates remain in safe tombstoned custody pending broker outcome"
        );
    }
    Ok(())
}

fn spawn_control_io_workers(
    accepted: Receiver<UnixStream>,
    context: &ControlIoContextV1,
) -> anyhow::Result<Vec<thread::JoinHandle<()>>> {
    let accepted = Arc::new(Mutex::new(accepted));
    let mut workers = Vec::with_capacity(CONTROL_IO_WORKERS);
    for index in 0..CONTROL_IO_WORKERS {
        let accepted = Arc::clone(&accepted);
        let context = context.clone();
        workers.push(
            thread::Builder::new()
                .name(format!("agd-control-io-{index}"))
                .spawn(move || control_io_worker(&accepted, &context))?,
        );
    }
    Ok(workers)
}

fn control_io_worker(accepted: &Mutex<Receiver<UnixStream>>, context: &ControlIoContextV1) {
    loop {
        let stream = {
            let Ok(receiver) = accepted.lock() else {
                warn!("bounded governor control accept queue was poisoned");
                return;
            };
            match receiver.recv() {
                Ok(stream) => stream,
                Err(_) => return,
            }
        };
        serve_control_stream(stream, context);
    }
}

fn serve_control_stream(mut stream: UnixStream, context: &ControlIoContextV1) {
    if let Err(error) = stream.set_nonblocking(false) {
        warn!(%error, "could not restore blocking mode on accepted control stream");
        return;
    }
    let accepted = match accept_signed_request::<AgdRequestV1>(
        &mut stream,
        context.codec,
        &context.signer,
        &context.proposer,
        &context.replay,
        &SystemRpcClockV1,
        context.socket_check,
    ) {
        Ok(accepted) => accepted,
        Err(error) => {
            warn!(%error, "rejected signed governor request");
            return;
        }
    };
    let (reply, completed) = sync_channel(1);
    match context
        .dispatch
        .try_send(AuthenticatedControlV1 { accepted, reply })
    {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            warn!("bounded governor control dispatch queue is full; refusing request");
            return;
        }
        Err(TrySendError::Disconnected(_)) => {
            warn!("governor control dispatcher disconnected");
            return;
        }
    }
    let completed = match completed.recv_timeout(CONTROL_REPLY_TIMEOUT) {
        Ok(completed) => completed,
        Err(RecvTimeoutError::Timeout) => {
            warn!("governor control mutation exceeded its bounded reply deadline");
            return;
        }
        Err(RecvTimeoutError::Disconnected) => {
            warn!("governor control mutation dispatcher terminated");
            return;
        }
    };
    if let Err(error) = write_signed_response(
        &mut stream,
        context.codec,
        &context.signer,
        &completed.accepted,
        completed.response,
        &SystemRpcClockV1,
    ) {
        warn!(%error, "governor response write failed");
    }
}

fn accept_control_burst(
    listener: &UnixListener,
    accepted: &SyncSender<UnixStream>,
) -> anyhow::Result<()> {
    for _ in 0..CONTROL_ACCEPT_BURST {
        match listener.accept() {
            Ok((stream, _)) => match accepted.try_send(stream) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    warn!("bounded governor control accept queue is full; dropping connection");
                }
                Err(TrySendError::Disconnected(_)) => {
                    anyhow::bail!("bounded governor control I/O pool disconnected");
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => {
                warn!(%error, "control socket accept failed");
                break;
            }
        }
    }
    Ok(())
}

fn dispatch_control(governor: &mut AgdCoreV1, control: AuthenticatedControlV1) {
    let response = governor.handle_control(&control.accepted);
    let completed = CompletedControlV1 {
        accepted: control.accepted,
        response,
    };
    match control.reply.try_send(completed) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            warn!("governor control I/O worker did not consume its unique response");
        }
        Err(TrySendError::Disconnected(_)) => {
            warn!("governor control client disconnected before mutation response");
        }
    }
}

fn poll_workers_if_due(
    governor: &mut AgdCoreV1,
    next_worker_poll: &mut Instant,
) -> anyhow::Result<()> {
    if Instant::now() < *next_worker_poll {
        return Ok(());
    }
    let worker_poll = governor.poll_workers()?;
    if worker_poll.accepted > 0 || worker_poll.failed > 0 || worker_poll.deferred > 0 {
        info!(
            accepted = worker_poll.accepted,
            failed = worker_poll.failed,
            deferred = worker_poll.deferred,
            "completed worker supervisor pass"
        );
    }
    *next_worker_poll = Instant::now() + WORKER_POLL_INTERVAL;
    Ok(())
}
