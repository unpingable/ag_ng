//! Fixed-profile worker launch with descriptor-bound Bubblewrap custody.
//!
//! This module is deliberately a launcher, not a command runner.  It accepts
//! only a worker selected from the reviewed daemon configuration, launches the
//! bytes held by an already-verified descriptor, gives the worker a fresh
//! proposal workspace, and returns bounded stdout as candidate material.

use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ag_primitives::{Digest, ExecutableIdentityV1};
use ag_session::SecurityProfileV1;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
use nix::unistd::{Pid, pipe2};
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, Stat};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::config::{
    FilesystemNodeCustodyV1, WorkerCandidateEffectV1, WorkerLauncherConfigV1, WorkerProfileConfigV1,
};

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ADMITTED_INPUTS: usize = 8;
const MAX_ADMITTED_INPUT_BYTES: u64 = 4096;
const MAX_INPUT_PURPOSE_BYTES: usize = 128;
const MAX_WORKSPACE_NAME_BYTES: usize = 128;
const MAX_CANDIDATE_WIRE_BYTES: u64 = 64 * 1024 * 1024;
const WORKER_PATH: &str = "/run/ag/worker";
const WORKSPACE_PATH: &str = "/work";
const ACTIVATION_PROTOCOL_MAGIC: &[u8; 8] = b"AGNGFD1\0";
const PROVIDER_REQUEST_DESCRIPTOR: u32 = 5;
const PROVIDER_RESPONSE_DESCRIPTOR: u32 = 6;
const PROVIDER_REQUEST_PURPOSE: &str = "provider-request-v1";
const PROVIDER_RESPONSE_PURPOSE: &str = "provider-response-v1";

/// First descriptor number installed by the worker activation protocol.
///
/// Bubblewrap intentionally closes arbitrary inherited descriptors.  The
/// launcher therefore passes a one-shot `SOCK_SEQPACKET` endpoint as stdin and
/// sends admitted pipe read ends with `SCM_RIGHTS` while the command is still
/// held behind `--block-fd`.  A conforming worker performs `recvmsg(0, ...)` as
/// its first descriptor operation.  With only stdin/stdout/stderr initially
/// open, Linux installs the received descriptors consecutively beginning here.
pub const FIRST_WORKER_INPUT_DESCRIPTOR: u32 = 3;

/// One read-only pipe intentionally delivered to a worker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedWorkerInputV1 {
    /// Exact descriptor installed in the worker by its initial `recvmsg`.
    pub descriptor: u32,
    /// Bounded reviewed role name committed by launch evidence.
    pub purpose: String,
    /// Maximum bytes the parent may write to this pipe.
    pub maximum_bytes: u64,
}

/// One activation input received by a conforming worker.
///
/// The raw descriptor is closed on drop.  Workers can either use
/// [`Self::read_to_end`] or pass [`Self::descriptor`] to a descriptor-aware
/// protocol implementation.
#[derive(Debug)]
pub struct ReceivedWorkerInputV1 {
    /// Exact descriptor installed by the kernel.
    pub descriptor: u32,
    /// Evidence-bound purpose received from the launcher.
    pub purpose: String,
    /// Maximum admitted byte length.
    pub maximum_bytes: u64,
    open: bool,
}

impl ReceivedWorkerInputV1 {
    /// Reads the complete bounded input and closes its descriptor.
    ///
    /// # Errors
    ///
    /// Returns a typed activation error on I/O failure or if the launcher
    /// violates the advertised byte bound.
    pub fn read_to_end(mut self) -> Result<Vec<u8>, WorkerActivationError> {
        let capacity = usize::try_from(self.maximum_bytes)
            .map_err(|_| WorkerActivationError::InvalidEnvelope)?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut buffer = [0_u8; 1024];
        let descriptor = raw_worker_descriptor(self.descriptor)?;
        loop {
            let length = nix::unistd::read(descriptor, &mut buffer)
                .map_err(|error| WorkerActivationError::Io(nix_errno_to_io(error)))?;
            if length == 0 {
                self.close_descriptor();
                return Ok(bytes);
            }
            let next = bytes
                .len()
                .checked_add(length)
                .filter(|length| *length <= capacity)
                .ok_or(WorkerActivationError::InputLimitExceeded(self.descriptor))?;
            bytes.extend_from_slice(&buffer[..length]);
            debug_assert_eq!(bytes.len(), next);
        }
    }

    /// Explicitly closes this input without reading it.
    pub fn close(mut self) {
        self.close_descriptor();
    }

    fn close_descriptor(&mut self) {
        if self.open {
            if let Ok(descriptor) = RawFd::try_from(self.descriptor) {
                let _ = nix::unistd::close(descriptor);
            }
            self.open = false;
        }
    }
}

impl Drop for ReceivedWorkerInputV1 {
    fn drop(&mut self) {
        self.close_descriptor();
    }
}

/// Refusal while a worker receives its one-shot activation descriptors.
#[derive(Debug, Error)]
pub enum WorkerActivationError {
    /// The activation socket could not be read.
    #[error("worker activation transport failed: {0}")]
    Io(#[source] std::io::Error),
    /// The activation payload was malformed or outside fixed bounds.
    #[error("worker activation envelope is invalid")]
    InvalidEnvelope,
    /// The worker already had a descriptor needed by the closed manifest.
    #[error("worker activation descriptor {0} was already occupied")]
    DescriptorOccupied(u32),
    /// The kernel-installed descriptors did not match the manifest.
    #[error("worker activation descriptors did not match the manifest")]
    DescriptorMismatch,
    /// More bytes arrived than the manifest admitted.
    #[error("worker activation input {0} exceeded its bound")]
    InputLimitExceeded(u32),
}

/// Receives the launcher's one-shot activation manifest and pipe descriptors.
///
/// A conforming generic worker calls this exactly once, before opening any
/// other descriptor.  Stdin must still be the launcher's `SOCK_SEQPACKET`
/// endpoint.  The helper requires descriptors 3 through N to be free, receives
/// the pipes with close-on-exec, verifies their exact assigned numbers and
/// roles, and closes stdin before returning.
///
/// # Errors
///
/// Returns a typed refusal for an occupied descriptor, malformed/truncated
/// envelope, descriptor mismatch, or socket error.  Every received descriptor
/// is closed on refusal.
pub fn receive_worker_activation() -> Result<Vec<ReceivedWorkerInputV1>, WorkerActivationError> {
    for index in 0..MAX_ADMITTED_INPUTS {
        let descriptor = FIRST_WORKER_INPUT_DESCRIPTOR
            + u32::try_from(index).map_err(|_| WorkerActivationError::InvalidEnvelope)?;
        match fcntl(raw_worker_descriptor(descriptor)?, FcntlArg::F_GETFD) {
            Err(nix::errno::Errno::EBADF) => {}
            Ok(_) => return Err(WorkerActivationError::DescriptorOccupied(descriptor)),
            Err(error) => return Err(WorkerActivationError::Io(nix_errno_to_io(error))),
        }
    }

    let mut payload = [0_u8; 2048];
    let mut iov = [IoSliceMut::new(&mut payload)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; MAX_ADMITTED_INPUTS]);
    let message = recvmsg::<()>(
        0,
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(|error| WorkerActivationError::Io(nix_errno_to_io(error)))?;
    let length = message.bytes;
    let truncated = message
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    let mut descriptors = Vec::new();
    let messages = message
        .cmsgs()
        .map_err(|error| WorkerActivationError::Io(nix_errno_to_io(error)))?;
    for control in messages {
        if let ControlMessageOwned::ScmRights(received) = control {
            descriptors.extend(received);
        }
    }
    let _ = nix::unistd::close(0);
    if truncated {
        close_raw_descriptors(&descriptors);
        return Err(WorkerActivationError::InvalidEnvelope);
    }
    let admitted = match parse_activation_payload(&payload[..length]) {
        Ok(admitted) => admitted,
        Err(error) => {
            close_raw_descriptors(&descriptors);
            return Err(error);
        }
    };
    if descriptors.len() != admitted.len()
        || descriptors
            .iter()
            .zip(&admitted)
            .any(|(observed, expected)| RawFd::try_from(expected.descriptor) != Ok(*observed))
    {
        close_raw_descriptors(&descriptors);
        return Err(WorkerActivationError::DescriptorMismatch);
    }
    Ok(admitted
        .into_iter()
        .map(|input| ReceivedWorkerInputV1 {
            descriptor: input.descriptor,
            purpose: input.purpose,
            maximum_bytes: input.maximum_bytes,
            open: true,
        })
        .collect())
}

fn raw_worker_descriptor(descriptor: u32) -> Result<RawFd, WorkerActivationError> {
    RawFd::try_from(descriptor).map_err(|_| WorkerActivationError::InvalidEnvelope)
}

/// Descriptor-bound identity of a proposal workspace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalWorkspaceV1 {
    /// Diagnostic path.  Security decisions use the retained descriptor and
    /// the identity below, never this pathname.
    pub path: PathBuf,
    /// Device containing the opened directory.
    pub device: u64,
    /// Inode of the opened directory.
    pub inode: u64,
    /// Observed owner.
    pub uid: u32,
    /// Observed group.
    pub gid: u32,
    /// Exact permission and special bits.
    pub mode: u32,
    /// Canonical binding of all workspace identity fields.
    pub identity: Digest,
}

/// Evidence for one prepared, still-gated worker launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLaunchEvidenceV1 {
    /// Digest of the complete fixed launch profile.
    pub launch_profile: Digest,
    /// Exact sandbox executable identity.
    pub sandbox_executable: ExecutableIdentityV1,
    /// Exact worker executable identity.
    pub worker_executable: ExecutableIdentityV1,
    /// Exact logical argv, including the fixed synthetic worker path as argv zero.
    pub argv: Vec<String>,
    /// Exact workspace identity.
    pub workspace: Digest,
    /// Explicitly admitted descriptor roles and bounds.
    pub admitted_inputs: Vec<AdmittedWorkerInputV1>,
    /// Bound on the exact ingress wire bytes collected from stdout.
    pub maximum_candidate_wire_bytes: u64,
    /// Host PID of the gated Bubblewrap supervisor.
    pub sandbox_pid: u32,
    /// Host effective UID that prepared the process.
    pub observed_uid: u32,
    /// Host effective GID that prepared the process.
    pub observed_gid: u32,
    /// This slice has no provider channel or network route.
    pub offline: bool,
}

/// Parent write end for one admitted read-only worker pipe.
#[derive(Debug)]
pub struct AdmittedWorkerInputPipeV1 {
    descriptor: u32,
    purpose: String,
    maximum_bytes: u64,
    bytes_written: u64,
    writer: Option<File>,
}

impl AdmittedWorkerInputPipeV1 {
    /// Returns the exact descriptor installed in the worker.
    #[must_use]
    pub const fn descriptor(&self) -> u32 {
        self.descriptor
    }

    /// Returns the evidence-bound descriptor purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Writes bytes without exceeding the reviewed bound.
    ///
    /// # Errors
    ///
    /// Returns an error if this input is closed, the bound would be exceeded,
    /// or the pipe cannot be written completely.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), WorkerLaunchError> {
        let additional = u64::try_from(bytes.len())
            .map_err(|_| WorkerLaunchError::InputBudgetExceeded(self.descriptor))?;
        let next = self
            .bytes_written
            .checked_add(additional)
            .filter(|total| *total <= self.maximum_bytes)
            .ok_or(WorkerLaunchError::InputBudgetExceeded(self.descriptor))?;
        self.writer
            .as_mut()
            .ok_or(WorkerLaunchError::InputClosed(self.descriptor))?
            .write_all(bytes)
            .map_err(|source| WorkerLaunchError::Io {
                operation: "write admitted worker input",
                source,
            })?;
        self.bytes_written = next;
        Ok(())
    }

    /// Closes the parent write end so the worker observes EOF.
    pub fn close(mut self) {
        self.writer.take();
    }
}

/// One-shot release for a prepared worker.
///
/// Dropping this value before release kills the gated supervisor before
/// closing the gate.  Merely losing a launch handle can therefore never turn
/// into implicit authority to run.
#[derive(Debug)]
pub struct WorkerLaunchReleaseV1 {
    gate: Option<OwnedFd>,
    sandbox_pid: u32,
    released: bool,
}

impl WorkerLaunchReleaseV1 {
    /// Releases the worker only after the caller has durably bound its live
    /// principal and populated/closed all admitted input pipes.
    ///
    /// # Errors
    ///
    /// Returns an error when the gate cannot be signalled.  Failure also kills
    /// the still-gated sandbox.
    pub fn release(mut self) -> Result<(), WorkerLaunchError> {
        let gate = self.gate.as_ref().ok_or(WorkerLaunchError::GateClosed)?;
        nix::unistd::write(gate, &[1]).map_err(|error| WorkerLaunchError::Io {
            operation: "release worker gate",
            source: nix_errno_to_io(error),
        })?;
        self.released = true;
        self.gate.take();
        Ok(())
    }

    /// Kills the still-retained sandbox before process reaping and disarms the
    /// raw-PID drop fallback. The retained [`WorkerProcessV1`] remains the
    /// authority for proving that the process was actually reaped.
    pub(crate) fn abort(mut self) {
        let _ = kill(
            Pid::from_raw(i32::try_from(self.sandbox_pid).unwrap_or(i32::MAX)),
            Signal::SIGKILL,
        );
        self.released = true;
        self.gate.take();
    }
}

impl Drop for WorkerLaunchReleaseV1 {
    fn drop(&mut self) {
        if !self.released {
            let _ = kill(
                Pid::from_raw(i32::try_from(self.sandbox_pid).unwrap_or(i32::MAX)),
                Signal::SIGKILL,
            );
        }
        self.gate.take();
    }
}

/// A successfully prepared launch.  The process remains blocked until
/// [`WorkerLaunchReleaseV1::release`] is called.
///
/// Field order is safety-relevant: Rust drops fields in declaration order, so
/// an implicitly abandoned preparation kills through the live gate guard
/// before `process` reaps the child. The raw PID can therefore never be used
/// after that child becomes recyclable.
#[derive(Debug)]
pub struct PreparedWorkerLaunchV1 {
    /// Explicit release/abort gate; deliberately dropped before `process`.
    pub release: WorkerLaunchReleaseV1,
    /// Process custody and bounded candidate collection.
    pub process: WorkerProcessV1,
    /// Durable evidence material available before release.
    pub evidence: WorkerLaunchEvidenceV1,
    /// Fresh descriptor-bound proposal workspace.
    pub workspace: ProposalWorkspaceV1,
    /// Parent write ends for the read-only bootstrap entries in
    /// `evidence.admitted_inputs`; provider endpoints have separate custody.
    pub admitted_inputs: Vec<AdmittedWorkerInputPipeV1>,
    /// Parent endpoints for the optional session-scoped provider channel.
    /// The worker receives only fd 5 (write) and fd 6 (read).
    pub provider_channel: Option<WorkerProviderChannelV1>,
}

/// Governor custody of one worker's descriptor-only provider channel.
#[derive(Debug)]
pub struct WorkerProviderChannelV1 {
    request: OwnedFd,
    response: OwnedFd,
}

impl WorkerProviderChannelV1 {
    /// Receives one bounded credential-free worker request chunk.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the worker endpoint closed. The caller owns
    /// complete framing, size enforcement, and durability.
    pub fn receive_request(&self, buffer: &mut [u8]) -> Result<usize, WorkerLaunchError> {
        let received = nix::unistd::read(self.request.as_raw_fd(), buffer).map_err(|error| {
            WorkerLaunchError::Io {
                operation: "receive worker provider request",
                source: nix_errno_to_io(error),
            }
        })?;
        if received == 0 || received > buffer.len() {
            return Err(WorkerLaunchError::ProviderChannelFrame);
        }
        Ok(received)
    }

    /// Sends one bounded governor response chunk to the worker.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or a short-write refusal. Provider content and
    /// credentials are not interpreted by this transport primitive.
    pub fn send_response(&self, bytes: &[u8]) -> Result<(), WorkerLaunchError> {
        let sent =
            nix::unistd::write(&self.response, bytes).map_err(|error| WorkerLaunchError::Io {
                operation: "send worker provider response",
                source: nix_errno_to_io(error),
            })?;
        if sent != bytes.len() {
            return Err(WorkerLaunchError::ProviderChannelFrame);
        }
        Ok(())
    }
}

/// Completed worker status and its bounded candidate bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerExitV1 {
    /// Raw process exit status.
    pub status: ExitStatus,
    /// Candidate bytes collected from stdout.  They are not a canonical
    /// proposal and acquire no authority from this type.
    pub candidate: Vec<u8>,
}

/// Custody of a launched worker and its bounded candidate stream.
#[derive(Debug)]
pub struct WorkerProcessV1 {
    child: Option<Child>,
    stdout: Option<ChildStdout>,
    gate_sentinel: Option<OwnedFd>,
    candidate: Vec<u8>,
    candidate_limit: u64,
    deadline: Instant,
}

impl WorkerProcessV1 {
    /// Returns the host PID of the Bubblewrap supervisor while live.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Polls for completion while continuing bounded candidate collection.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal on output overflow, timeout, or process I/O
    /// failure.  The caller retains process custody on error so it can durably
    /// tombstone the principal before calling [`Self::terminate`].
    pub fn try_wait(&mut self) -> Result<Option<WorkerExitV1>, WorkerLaunchError> {
        self.drain_candidate()?;
        if Instant::now() >= self.deadline {
            return Err(WorkerLaunchError::TimedOut);
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let status = child.try_wait().map_err(|source| WorkerLaunchError::Io {
            operation: "poll worker",
            source,
        })?;
        let Some(status) = status else {
            return Ok(None);
        };
        self.child.take();
        self.gate_sentinel.take();
        self.drain_candidate_to_eof()?;
        Ok(Some(WorkerExitV1 {
            status,
            candidate: std::mem::take(&mut self.candidate),
        }))
    }

    /// Waits until completion or the reviewed deadline.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal on output overflow, timeout, or process I/O
    /// failure.  Because this consuming convenience method drops itself on
    /// error, it fail-safe terminates any live child; authority-aware callers
    /// should poll with [`Self::try_wait`] and tombstone before termination.
    pub fn wait(mut self) -> Result<WorkerExitV1, WorkerLaunchError> {
        loop {
            if let Some(completed) = self.try_wait()? {
                return Ok(completed);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Reports whether the launcher's retained monotonic deadline has passed.
    ///
    /// Authority-aware callers use this immediately before releasing a gated
    /// worker, so durable activation work cannot consume the entire execution
    /// window and then start an already-expired process.
    #[must_use]
    pub fn deadline_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Synchronously terminates the sandbox and confirms that it was reaped.
    ///
    /// A successful return is the lifecycle boundary on which callers may
    /// durably report that process cleanup completed.  A failed kill or reap
    /// retains child custody so an authority-aware caller can retry without
    /// laundering an uncertain cleanup into success.
    ///
    /// # Errors
    ///
    /// Returns a typed process-operation error unless the child is confirmed
    /// reaped.  A child already reaped by [`Self::try_wait`] is successful and
    /// repeated termination is idempotent.
    pub fn terminate(&mut self) -> Result<(), WorkerLaunchError> {
        self.stop_checked()
    }

    fn drain_candidate(&mut self) -> Result<(), WorkerLaunchError> {
        let Some(stdout) = self.stdout.as_mut() else {
            return Ok(());
        };
        let mut buffer = [0_u8; 8192];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    self.stdout.take();
                    return Ok(());
                }
                Ok(length) => {
                    let next = u64::try_from(self.candidate.len())
                        .ok()
                        .and_then(|current| current.checked_add(length as u64));
                    if next.is_none_or(|total| total > self.candidate_limit) {
                        return Err(WorkerLaunchError::CandidateLimitExceeded {
                            observed_bytes: next.unwrap_or(u64::MAX),
                        });
                    }
                    self.candidate.extend_from_slice(&buffer[..length]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(source) => {
                    return Err(WorkerLaunchError::Io {
                        operation: "read worker candidate",
                        source,
                    });
                }
            }
        }
    }

    fn drain_candidate_to_eof(&mut self) -> Result<(), WorkerLaunchError> {
        loop {
            self.drain_candidate()?;
            if self.stdout.is_none() {
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err(WorkerLaunchError::CandidateStreamIndeterminate);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn stop_checked(&mut self) -> Result<(), WorkerLaunchError> {
        let Some(mut child) = self.child.take() else {
            self.gate_sentinel.take();
            self.stdout.take();
            return Ok(());
        };

        if let Err(source) = child.kill()
            && source.kind() != std::io::ErrorKind::InvalidInput
            && source.raw_os_error() != Some(libc::ESRCH)
        {
            self.child = Some(child);
            return Err(WorkerLaunchError::Io {
                operation: "terminate worker",
                source,
            });
        }

        loop {
            match child.wait() {
                Ok(_) => break,
                Err(source) => {
                    if source.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    self.child = Some(child);
                    return Err(WorkerLaunchError::Io {
                        operation: "reap terminated worker",
                        source,
                    });
                }
            }
        }
        self.gate_sentinel.take();
        self.stdout.take();
        Ok(())
    }
}

impl Drop for WorkerProcessV1 {
    fn drop(&mut self) {
        // Destruction is the final fail-safe, not an authority-bearing cleanup
        // receipt.  Explicit callers use `terminate` and handle its result;
        // Drop remains best-effort and must never panic.
        let _ = self.stop_checked();
    }
}

/// Which retained executable failed custody validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerExecutableRoleV1 {
    /// Bubblewrap itself.
    Sandbox,
    /// The fixed worker.
    Worker,
}

/// Typed launch refusal or bounded-execution failure.
#[derive(Debug, Error)]
pub enum WorkerLaunchError {
    /// This slice cannot honestly satisfy a production isolation profile.
    #[error("worker isolation is unproven for security profile {0:?}")]
    IsolationUnproven(SecurityProfileV1),
    /// The requested profile was not present in reviewed configuration.
    #[error("unknown reviewed worker profile: {0}")]
    UnknownProfile(String),
    /// A reviewed launch field was invalid.
    #[error("invalid reviewed worker launch field: {0}")]
    InvalidReview(&'static str),
    /// An executable did not match its exact reviewed bytes.
    #[error("{role:?} executable identity mismatch at {path}")]
    ExecutableIdentityMismatch {
        /// Executable role.
        role: WorkerExecutableRoleV1,
        /// Reviewed diagnostic path.
        path: PathBuf,
    },
    /// The path no longer selected the retained executable immediately before
    /// launch.  The retained bytes are not launched in this case.
    #[error("{role:?} executable was substituted at {path}")]
    ExecutableSubstituted {
        /// Executable role.
        role: WorkerExecutableRoleV1,
        /// Reviewed diagnostic path.
        path: PathBuf,
    },
    /// An executable descriptor had unsafe type, links, permissions, or size.
    #[error("unsafe {role:?} executable at {path}: {reason}")]
    UnsafeExecutable {
        /// Executable role.
        role: WorkerExecutableRoleV1,
        /// Reviewed diagnostic path.
        path: PathBuf,
        /// Stable refusal detail.
        reason: &'static str,
    },
    /// A required directory failed descriptor-bound custody validation.
    #[error("unsafe worker directory {path}: {reason}")]
    UnsafeDirectory {
        /// Diagnostic path.
        path: PathBuf,
        /// Stable refusal detail.
        reason: &'static str,
    },
    /// The unique workspace already exists and is never reused.
    #[error("worker workspace already exists: {0}")]
    WorkspaceExists(PathBuf),
    /// The worker activation descriptor protocol could not be established.
    #[error("worker activation descriptor handoff failed")]
    DescriptorHandoff,
    /// One provider-channel transfer was empty or only partly sent.
    #[error("worker provider channel transfer is incomplete")]
    ProviderChannelFrame,
    /// A parent attempted to exceed an admitted input bound.
    #[error("worker input descriptor {0} exceeded its reviewed bound")]
    InputBudgetExceeded(u32),
    /// A parent attempted to reuse a closed input.
    #[error("worker input descriptor {0} is closed")]
    InputClosed(u32),
    /// The release gate was already closed.
    #[error("worker release gate is closed")]
    GateClosed,
    /// Candidate stdout exceeded the reviewed limit.
    #[error("worker candidate output exceeded its reviewed bound at {observed_bytes} bytes")]
    CandidateLimitExceeded {
        /// Exact bytes read when the bound was crossed, or `u64::MAX` on
        /// arithmetic overflow.
        observed_bytes: u64,
    },
    /// The supervisor exited but candidate stdout never reached a proven EOF.
    #[error("worker candidate stream did not reach EOF before its deadline")]
    CandidateStreamIndeterminate,
    /// The retained exclusive monotonic deadline expired.
    #[error("worker exceeded its reviewed timeout")]
    TimedOut,
    /// Canonical launch evidence could not be constructed.
    #[error("worker launch evidence could not be canonicalized")]
    Evidence,
    /// A local kernel or process operation failed.
    #[error("{operation}: {source}")]
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying operating-system error.
        #[source]
        source: std::io::Error,
    },
}

/// Prepares one reviewed worker behind a fail-closed release gate.
///
/// `profile_id` is resolved inside `launcher.profiles`; callers cannot supply
/// an ad-hoc executable or argv.  Production profiles refuse because this
/// development substrate does not yet prove cgroup, seccomp, Landlock, and
/// dynamic host-identity requirements.
///
/// # Errors
///
/// Returns a typed refusal for an unknown/unsafe review, executable
/// substitution, workspace collision, unsupported isolation profile, or
/// kernel launch failure.
pub fn prepare_worker_launch(
    security_profile: SecurityProfileV1,
    launcher: &WorkerLauncherConfigV1,
    profile_id: &str,
    workspace_name: &str,
    maximum_candidate_wire_bytes: u64,
    admitted_inputs: &[AdmittedWorkerInputV1],
) -> Result<PreparedWorkerLaunchV1, WorkerLaunchError> {
    prepare_worker_launch_inner(
        security_profile,
        launcher,
        profile_id,
        workspace_name,
        maximum_candidate_wire_bytes,
        admitted_inputs,
        false,
        || {},
    )
}

/// Prepares a reviewed worker with the session-scoped provider channel on
/// exact descriptors 5 and 6.
///
/// # Errors
///
/// Returns the same bounded launch refusals as [`prepare_worker_launch`], plus
/// provider-channel construction or descriptor-handoff failures.
pub fn prepare_worker_launch_with_provider(
    security_profile: SecurityProfileV1,
    launcher: &WorkerLauncherConfigV1,
    profile_id: &str,
    workspace_name: &str,
    maximum_candidate_wire_bytes: u64,
    admitted_inputs: &[AdmittedWorkerInputV1],
) -> Result<PreparedWorkerLaunchV1, WorkerLaunchError> {
    prepare_worker_launch_inner(
        security_profile,
        launcher,
        profile_id,
        workspace_name,
        maximum_candidate_wire_bytes,
        admitted_inputs,
        true,
        || {},
    )
}

#[allow(clippy::too_many_lines)]
fn prepare_worker_launch_inner<F>(
    security_profile: SecurityProfileV1,
    launcher: &WorkerLauncherConfigV1,
    profile_id: &str,
    workspace_name: &str,
    maximum_candidate_wire_bytes: u64,
    admitted_inputs: &[AdmittedWorkerInputV1],
    provider_channel: bool,
    before_revalidation: F,
) -> Result<PreparedWorkerLaunchV1, WorkerLaunchError>
where
    F: FnOnce(),
{
    if security_profile != SecurityProfileV1::Development {
        return Err(WorkerLaunchError::IsolationUnproven(security_profile));
    }
    let worker_profile = reviewed_profile(launcher, profile_id)?;
    validate_review(
        launcher,
        worker_profile,
        workspace_name,
        maximum_candidate_wire_bytes,
        admitted_inputs,
    )?;
    if provider_channel
        && (admitted_inputs.len() != 2
            || admitted_inputs[0].descriptor != FIRST_WORKER_INPUT_DESCRIPTOR
            || admitted_inputs[1].descriptor != FIRST_WORKER_INPUT_DESCRIPTOR + 1)
    {
        return Err(WorkerLaunchError::InvalidReview(
            "provider channel requires exact fd 3/4 bootstrap inputs",
        ));
    }

    let root = open_root()?;
    let mut sandbox = pin_executable(
        &root,
        &launcher.sandbox_executable,
        &launcher.sandbox_identity,
        WorkerExecutableRoleV1::Sandbox,
    )?;
    let mut worker = pin_executable(
        &root,
        &worker_profile.executable,
        &worker_profile.executable_identity,
        WorkerExecutableRoleV1::Worker,
    )?;
    let runtime = open_runtime_roots(&root, &launcher.runtime_roots)?;
    let workspace_root = open_reviewed_directory(
        &root,
        &launcher.workspace_root,
        &launcher.workspace_root_custody,
    )?;
    let (workspace_fd, workspace) =
        create_workspace(&workspace_root, &launcher.workspace_root, workspace_name)?;

    let argv = std::iter::once(WORKER_PATH.to_owned())
        .chain(worker_profile.fixed_arguments.iter().cloned())
        .collect::<Vec<_>>();
    let mut activation_manifest = admitted_inputs.to_vec();
    if provider_channel {
        activation_manifest.extend([
            AdmittedWorkerInputV1 {
                descriptor: PROVIDER_REQUEST_DESCRIPTOR,
                purpose: PROVIDER_REQUEST_PURPOSE.to_owned(),
                maximum_bytes: maximum_candidate_wire_bytes,
            },
            AdmittedWorkerInputV1 {
                descriptor: PROVIDER_RESPONSE_DESCRIPTOR,
                purpose: PROVIDER_RESPONSE_PURPOSE.to_owned(),
                maximum_bytes: maximum_candidate_wire_bytes,
            },
        ]);
    }
    let launch_profile = launch_profile_digest(
        security_profile,
        launcher,
        worker_profile,
        &argv,
        maximum_candidate_wire_bytes,
        &activation_manifest,
        &workspace,
        &runtime,
    )?;

    let (gate_read, gate_write) =
        pipe2(OFlag::O_CLOEXEC).map_err(|error| WorkerLaunchError::Io {
            operation: "create worker release gate",
            source: nix_errno_to_io(error),
        })?;
    let gate_child = rustix::io::dup(&gate_read).map_err(|error| WorkerLaunchError::Io {
        operation: "duplicate worker release gate",
        source: errno_to_io(error),
    })?;
    let gate_sentinel =
        rustix::io::fcntl_dupfd_cloexec(&gate_write, 0).map_err(|error| WorkerLaunchError::Io {
            operation: "retain fail-closed worker gate sentinel",
            source: errno_to_io(error),
        })?;
    drop(gate_read);

    let (input_transport, input_child, input_readers, input_writers, provider_channel) =
        prepare_input_transport(admitted_inputs, provider_channel)?;
    let worker_mount = rustix::io::dup(&worker.file).map_err(|error| WorkerLaunchError::Io {
        operation: "duplicate retained worker descriptor",
        source: errno_to_io(error),
    })?;
    let workspace_mount =
        rustix::io::dup(&workspace_fd).map_err(|error| WorkerLaunchError::Io {
            operation: "duplicate retained workspace descriptor",
            source: errno_to_io(error),
        })?;
    let runtime_mounts = runtime
        .iter()
        .map(|entry| {
            rustix::io::dup(&entry.file).map_err(|error| WorkerLaunchError::Io {
                operation: "duplicate retained runtime descriptor",
                source: errno_to_io(error),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut command = Command::new(format!("/proc/self/fd/{}", sandbox.file.as_raw_fd()));
    command
        .env_clear()
        .current_dir("/")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .arg("--unshare-all")
        .arg("--unshare-user")
        .arg("--die-with-parent")
        .arg("--new-session")
        .arg("--disable-userns")
        .arg("--clearenv")
        .arg("--cap-drop")
        .arg("ALL")
        .arg("--block-fd")
        .arg(gate_child.as_raw_fd().to_string());

    if let Some(input_child) = input_child {
        command.stdin(Stdio::from(input_child));
    } else {
        command.stdin(Stdio::null());
    }
    for (entry, descriptor) in runtime.iter().zip(&runtime_mounts) {
        command
            .arg("--dir")
            .arg(&entry.mount_path)
            .arg("--ro-bind-fd")
            .arg(descriptor.as_raw_fd().to_string())
            .arg(&entry.mount_path);
    }
    command
        .arg("--symlink")
        .arg("usr/lib")
        .arg("/lib")
        .arg("--symlink")
        .arg("usr/lib64")
        .arg("/lib64")
        .arg("--dir")
        .arg("/run")
        .arg("--dir")
        .arg("/run/ag")
        .arg("--ro-bind-fd")
        .arg(worker_mount.as_raw_fd().to_string())
        .arg(WORKER_PATH)
        .arg("--dir")
        .arg(WORKSPACE_PATH)
        .arg("--symlink")
        .arg("work/tmp")
        .arg("/tmp")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--remount-ro")
        .arg("/")
        .arg("--bind-fd")
        .arg(workspace_mount.as_raw_fd().to_string())
        .arg(WORKSPACE_PATH)
        .arg("--chdir")
        .arg(WORKSPACE_PATH)
        .arg("--")
        .arg(WORKER_PATH)
        .args(&worker_profile.fixed_arguments);

    before_revalidation();
    revalidate_executable(&root, &mut sandbox)?;
    revalidate_executable(&root, &mut worker)?;

    let mut child = command.spawn().map_err(|source| WorkerLaunchError::Io {
        operation: "spawn retained sandbox executable",
        source,
    })?;
    drop(gate_child);
    drop(worker_mount);
    drop(workspace_mount);
    drop(runtime_mounts);

    if let Some(transport) = input_transport.as_ref()
        && let Err(error) = send_input_descriptors(transport, &activation_manifest, &input_readers)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    drop(input_transport);
    drop(input_readers);

    let sandbox_pid = child.id();
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(WorkerLaunchError::DescriptorHandoff);
    };
    if let Err(error) = set_nonblocking(&stdout) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let timeout = Duration::from_millis(worker_profile.timeout_ms);
    let process = WorkerProcessV1 {
        child: Some(child),
        stdout: Some(stdout),
        gate_sentinel: Some(gate_sentinel),
        candidate: Vec::new(),
        candidate_limit: maximum_candidate_wire_bytes,
        deadline: Instant::now() + timeout,
    };
    let evidence = WorkerLaunchEvidenceV1 {
        launch_profile,
        sandbox_executable: sandbox.identity.clone(),
        worker_executable: worker.identity.clone(),
        argv,
        workspace: workspace.identity.clone(),
        admitted_inputs: activation_manifest,
        maximum_candidate_wire_bytes,
        sandbox_pid,
        observed_uid: nix::unistd::geteuid().as_raw(),
        observed_gid: nix::unistd::getegid().as_raw(),
        offline: provider_channel.is_none(),
    };
    Ok(PreparedWorkerLaunchV1 {
        process,
        evidence,
        workspace,
        release: WorkerLaunchReleaseV1 {
            gate: Some(gate_write),
            sandbox_pid,
            released: false,
        },
        admitted_inputs: input_writers,
        provider_channel,
    })
}

fn reviewed_profile<'a>(
    launcher: &'a WorkerLauncherConfigV1,
    profile_id: &str,
) -> Result<&'a WorkerProfileConfigV1, WorkerLaunchError> {
    launcher
        .profiles
        .iter()
        .find(|profile| profile.profile_id == profile_id)
        .ok_or_else(|| WorkerLaunchError::UnknownProfile(profile_id.to_owned()))
}

fn validate_review(
    launcher: &WorkerLauncherConfigV1,
    profile: &WorkerProfileConfigV1,
    workspace_name: &str,
    maximum_candidate_wire_bytes: u64,
    admitted_inputs: &[AdmittedWorkerInputV1],
) -> Result<(), WorkerLaunchError> {
    if !valid_token(workspace_name, MAX_WORKSPACE_NAME_BYTES) {
        return Err(WorkerLaunchError::InvalidReview("workspace name"));
    }
    if launcher.runtime_roots.is_empty()
        || !launcher
            .runtime_roots
            .iter()
            .any(|path| path == Path::new("/usr"))
        || launcher
            .runtime_roots
            .iter()
            .any(|path| path != Path::new("/usr"))
    {
        return Err(WorkerLaunchError::InvalidReview(
            "runtime roots must be exactly /usr",
        ));
    }
    if profile.profile_id.is_empty()
        || profile.profile_id.as_bytes().contains(&0)
        || profile.candidate_semantic_type != profile.candidate_effect.semantic_type()
        || launcher.sandbox_identity.build_identity.is_some()
        || profile.executable_identity.build_identity.is_some()
        || profile.fixed_arguments.len() > 64
        || profile.fixed_arguments.iter().any(|argument| {
            argument.is_empty() || argument.len() > 4096 || argument.as_bytes().contains(&0)
        })
        || profile.timeout_ms == 0
        || profile.output_budget_bytes == 0
        || maximum_candidate_wire_bytes == 0
        || maximum_candidate_wire_bytes > MAX_CANDIDATE_WIRE_BYTES
    {
        return Err(WorkerLaunchError::InvalidReview("worker profile"));
    }
    if admitted_inputs.len() > MAX_ADMITTED_INPUTS {
        return Err(WorkerLaunchError::InvalidReview("admitted input count"));
    }
    for (index, input) in admitted_inputs.iter().enumerate() {
        let expected = FIRST_WORKER_INPUT_DESCRIPTOR
            .checked_add(u32::try_from(index).map_err(|_| {
                WorkerLaunchError::InvalidReview("admitted input descriptor overflow")
            })?)
            .ok_or(WorkerLaunchError::InvalidReview(
                "admitted input descriptor overflow",
            ))?;
        if input.descriptor != expected
            || !valid_token(&input.purpose, MAX_INPUT_PURPOSE_BYTES)
            || input.maximum_bytes == 0
            || input.maximum_bytes > MAX_ADMITTED_INPUT_BYTES
        {
            return Err(WorkerLaunchError::InvalidReview("admitted input"));
        }
    }
    Ok(())
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug)]
struct PinnedExecutable {
    file: File,
    path: PathBuf,
    identity: ExecutableIdentityV1,
    role: WorkerExecutableRoleV1,
    stat: StableStat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableStat {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl From<&Stat> for StableStat {
    fn from(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            links: stat.st_nlink,
            uid: stat.st_uid,
            gid: stat.st_gid,
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

fn open_root() -> Result<OwnedFd, WorkerLaunchError> {
    rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| WorkerLaunchError::Io {
        operation: "open filesystem root",
        source: errno_to_io(error),
    })
}

fn open_absolute(root: &OwnedFd, path: &Path, flags: OFlags) -> Result<OwnedFd, WorkerLaunchError> {
    let relative = path
        .strip_prefix("/")
        .map_err(|_| WorkerLaunchError::InvalidReview("absolute path"))?;
    if relative.as_os_str().is_empty() {
        return Err(WorkerLaunchError::InvalidReview("filesystem root path"));
    }
    rustix::fs::openat2(
        root,
        relative,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| WorkerLaunchError::Io {
        operation: "open reviewed path without symlinks",
        source: errno_to_io(error),
    })
}

fn pin_executable(
    root: &OwnedFd,
    path: &Path,
    expected: &ExecutableIdentityV1,
    role: WorkerExecutableRoleV1,
) -> Result<PinnedExecutable, WorkerLaunchError> {
    let descriptor = open_absolute(root, path, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let before = rustix::fs::fstat(&descriptor).map_err(|error| WorkerLaunchError::Io {
        operation: "stat reviewed executable",
        source: errno_to_io(error),
    })?;
    validate_executable_stat(&before, path, role)?;
    let mut file = File::from(descriptor);
    require_native_elf(&mut file, path, role)?;
    let identity = hash_executable(&mut file, expected.build_identity.clone())?;
    let after = rustix::fs::fstat(&file).map_err(|error| WorkerLaunchError::Io {
        operation: "restat reviewed executable",
        source: errno_to_io(error),
    })?;
    if StableStat::from(&before) != StableStat::from(&after) {
        return Err(WorkerLaunchError::ExecutableSubstituted {
            role,
            path: path.to_owned(),
        });
    }
    if &identity != expected {
        return Err(WorkerLaunchError::ExecutableIdentityMismatch {
            role,
            path: path.to_owned(),
        });
    }
    Ok(PinnedExecutable {
        file,
        path: path.to_owned(),
        identity,
        role,
        stat: StableStat::from(&after),
    })
}

fn require_native_elf(
    file: &mut File,
    path: &Path,
    role: WorkerExecutableRoleV1,
) -> Result<(), WorkerLaunchError> {
    let mut magic = [0_u8; 4];
    let length = file
        .read(&mut magic)
        .map_err(|source| WorkerLaunchError::Io {
            operation: "read retained executable format",
            source,
        })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| WorkerLaunchError::Io {
            operation: "rewind retained executable format",
            source,
        })?;
    if length != magic.len() || magic != *b"\x7fELF" {
        return Err(WorkerLaunchError::UnsafeExecutable {
            role,
            path: path.to_owned(),
            reason: "startup scripts and non-ELF executables are forbidden",
        });
    }
    Ok(())
}

fn validate_executable_stat(
    stat: &Stat,
    path: &Path,
    role: WorkerExecutableRoleV1,
) -> Result<(), WorkerLaunchError> {
    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    let reason = if !FileType::from_raw_mode(stat.st_mode).is_file() {
        Some("not a regular file")
    } else if stat.st_nlink != 1 {
        Some("link count is not one")
    } else if stat.st_mode & 0o111 == 0 {
        Some("not executable")
    } else if stat.st_mode & 0o022 != 0 {
        Some("executable is writable by group or other")
    } else if stat.st_mode & 0o200 != 0 && (stat.st_uid != 0 || nix::unistd::geteuid().is_root()) {
        Some("executable is writable by the activating identity")
    } else if stat.st_uid != 0 && stat.st_uid != nix::unistd::geteuid().as_raw() {
        Some("executable owner is not protected for this activation")
    } else if size == 0 || size > MAX_EXECUTABLE_BYTES {
        Some("invalid executable size")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(WorkerLaunchError::UnsafeExecutable {
            role,
            path: path.to_owned(),
            reason,
        });
    }
    Ok(())
}

fn hash_executable(
    file: &mut File,
    build_identity: Option<Digest>,
) -> Result<ExecutableIdentityV1, WorkerLaunchError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| WorkerLaunchError::Io {
            operation: "rewind retained executable",
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 32 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| WorkerLaunchError::Io {
                operation: "hash retained executable",
                source,
            })?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| WorkerLaunchError::InvalidReview("executable size"))?,
            )
            .filter(|value| *value <= MAX_EXECUTABLE_BYTES)
            .ok_or(WorkerLaunchError::InvalidReview("executable size"))?;
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| WorkerLaunchError::Io {
            operation: "rewind retained executable after hash",
            source,
        })?;
    let digest = Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|_| WorkerLaunchError::Evidence)?;
    Ok(ExecutableIdentityV1::new(digest, length, build_identity))
}

fn revalidate_executable(
    root: &OwnedFd,
    executable: &mut PinnedExecutable,
) -> Result<(), WorkerLaunchError> {
    let reopened = open_absolute(root, &executable.path, OFlags::RDONLY | OFlags::NONBLOCK)
        .map_err(|_| WorkerLaunchError::ExecutableSubstituted {
            role: executable.role,
            path: executable.path.clone(),
        })?;
    let stat =
        rustix::fs::fstat(&reopened).map_err(|_| WorkerLaunchError::ExecutableSubstituted {
            role: executable.role,
            path: executable.path.clone(),
        })?;
    if StableStat::from(&stat) != executable.stat {
        return Err(WorkerLaunchError::ExecutableSubstituted {
            role: executable.role,
            path: executable.path.clone(),
        });
    }
    let identity = hash_executable(
        &mut executable.file,
        executable.identity.build_identity.clone(),
    )
    .map_err(|_| WorkerLaunchError::ExecutableSubstituted {
        role: executable.role,
        path: executable.path.clone(),
    })?;
    let retained_after = rustix::fs::fstat(&executable.file).map_err(|_| {
        WorkerLaunchError::ExecutableSubstituted {
            role: executable.role,
            path: executable.path.clone(),
        }
    })?;
    if identity != executable.identity || StableStat::from(&retained_after) != executable.stat {
        return Err(WorkerLaunchError::ExecutableSubstituted {
            role: executable.role,
            path: executable.path.clone(),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct RuntimeRoot {
    file: OwnedFd,
    mount_path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

fn open_runtime_roots(
    root: &OwnedFd,
    roots: &[PathBuf],
) -> Result<Vec<RuntimeRoot>, WorkerLaunchError> {
    roots
        .iter()
        .map(|path| {
            let file = open_absolute(root, path, OFlags::RDONLY | OFlags::DIRECTORY)?;
            let stat = rustix::fs::fstat(&file).map_err(|error| WorkerLaunchError::Io {
                operation: "stat runtime root",
                source: errno_to_io(error),
            })?;
            if !FileType::from_raw_mode(stat.st_mode).is_dir() || stat.st_mode & 0o022 != 0 {
                return Err(WorkerLaunchError::UnsafeDirectory {
                    path: path.clone(),
                    reason: "runtime root is not a protected directory",
                });
            }
            Ok(RuntimeRoot {
                file,
                mount_path: path.clone(),
                device: stat.st_dev,
                inode: stat.st_ino,
                uid: stat.st_uid,
                gid: stat.st_gid,
                mode: stat.st_mode & 0o7777,
            })
        })
        .collect()
}

fn open_reviewed_directory(
    root: &OwnedFd,
    path: &Path,
    custody: &FilesystemNodeCustodyV1,
) -> Result<OwnedFd, WorkerLaunchError> {
    let directory = open_absolute(root, path, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let stat = rustix::fs::fstat(&directory).map_err(|error| WorkerLaunchError::Io {
        operation: "stat reviewed directory",
        source: errno_to_io(error),
    })?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != custody.uid
        || stat.st_gid != custody.gid
        || stat.st_mode & 0o7777 != custody.mode
        || stat.st_mode & 0o022 != 0
    {
        return Err(WorkerLaunchError::UnsafeDirectory {
            path: path.to_owned(),
            reason: "descriptor does not match exact reviewed custody",
        });
    }
    Ok(directory)
}

#[derive(Serialize)]
struct WorkspaceBinding<'a> {
    name: &'a str,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

fn create_workspace(
    root: &OwnedFd,
    root_path: &Path,
    name: &str,
) -> Result<(OwnedFd, ProposalWorkspaceV1), WorkerLaunchError> {
    match rustix::fs::mkdirat(root, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            return Err(WorkerLaunchError::WorkspaceExists(root_path.join(name)));
        }
        Err(error) => {
            return Err(WorkerLaunchError::Io {
                operation: "create proposal workspace",
                source: errno_to_io(error),
            });
        }
    }
    let workspace = rustix::fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| WorkerLaunchError::Io {
        operation: "reopen proposal workspace",
        source: errno_to_io(error),
    })?;
    rustix::fs::fchmod(&workspace, Mode::from_raw_mode(0o700)).map_err(|error| {
        WorkerLaunchError::Io {
            operation: "set proposal workspace mode",
            source: errno_to_io(error),
        }
    })?;
    rustix::fs::mkdirat(&workspace, "tmp", Mode::from_raw_mode(0o700)).map_err(|error| {
        WorkerLaunchError::Io {
            operation: "create private worker tmp",
            source: errno_to_io(error),
        }
    })?;
    let stat = rustix::fs::fstat(&workspace).map_err(|error| WorkerLaunchError::Io {
        operation: "stat proposal workspace",
        source: errno_to_io(error),
    })?;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(WorkerLaunchError::UnsafeDirectory {
            path: root_path.join(name),
            reason: "fresh workspace has unexpected custody",
        });
    }
    let mode = stat.st_mode & 0o7777;
    let identity = Digest::from_serializable(&WorkspaceBinding {
        name,
        device: stat.st_dev,
        inode: stat.st_ino,
        uid,
        gid,
        mode,
    })
    .map_err(|_| WorkerLaunchError::Evidence)?;
    Ok((
        workspace,
        ProposalWorkspaceV1 {
            path: root_path.join(name),
            device: stat.st_dev,
            inode: stat.st_ino,
            uid,
            gid,
            mode,
            identity,
        },
    ))
}

type InputTransport = (
    Option<OwnedFd>,
    Option<OwnedFd>,
    Vec<OwnedFd>,
    Vec<AdmittedWorkerInputPipeV1>,
    Option<WorkerProviderChannelV1>,
);

fn prepare_input_transport(
    admitted: &[AdmittedWorkerInputV1],
    provider_channel: bool,
) -> Result<InputTransport, WorkerLaunchError> {
    if admitted.is_empty() && !provider_channel {
        return Ok((None, None, Vec::new(), Vec::new(), None));
    }
    let (parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|error| WorkerLaunchError::Io {
        operation: "create worker descriptor transport",
        source: nix_errno_to_io(error),
    })?;
    let mut readers = Vec::with_capacity(admitted.len());
    let mut writers = Vec::with_capacity(admitted.len());
    for input in admitted {
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC).map_err(|error| WorkerLaunchError::Io {
            operation: "create admitted worker input",
            source: nix_errno_to_io(error),
        })?;
        readers.push(reader);
        writers.push(AdmittedWorkerInputPipeV1 {
            descriptor: input.descriptor,
            purpose: input.purpose.clone(),
            maximum_bytes: input.maximum_bytes,
            bytes_written: 0,
            writer: Some(File::from(writer)),
        });
    }
    let provider = if provider_channel {
        let (request_parent, request_child) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| WorkerLaunchError::Io {
                operation: "create worker provider request channel",
                source: nix_errno_to_io(error),
            })?;
        let (response_child, response_parent) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| WorkerLaunchError::Io {
                operation: "create worker provider response channel",
                source: nix_errno_to_io(error),
            })?;
        readers.push(request_child);
        readers.push(response_child);
        Some(WorkerProviderChannelV1 {
            request: request_parent,
            response: response_parent,
        })
    } else {
        None
    };
    Ok((Some(parent), Some(child), readers, writers, provider))
}

fn send_input_descriptors(
    transport: &OwnedFd,
    admitted: &[AdmittedWorkerInputV1],
    readers: &[OwnedFd],
) -> Result<(), WorkerLaunchError> {
    let payload = activation_payload(admitted)?;
    let descriptors = readers.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
    let iov = [IoSlice::new(&payload)];
    let rights = [ControlMessage::ScmRights(&descriptors)];
    let written = sendmsg::<()>(
        transport.as_raw_fd(),
        &iov,
        &rights,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(|_| WorkerLaunchError::DescriptorHandoff)?;
    if written != payload.len() {
        return Err(WorkerLaunchError::DescriptorHandoff);
    }
    Ok(())
}

fn activation_payload(admitted: &[AdmittedWorkerInputV1]) -> Result<Vec<u8>, WorkerLaunchError> {
    let mut payload = Vec::with_capacity(256);
    payload.extend_from_slice(ACTIVATION_PROTOCOL_MAGIC);
    payload.extend_from_slice(
        &u32::try_from(admitted.len())
            .map_err(|_| WorkerLaunchError::DescriptorHandoff)?
            .to_be_bytes(),
    );
    for input in admitted {
        payload.extend_from_slice(&input.descriptor.to_be_bytes());
        payload.extend_from_slice(&input.maximum_bytes.to_be_bytes());
        let length =
            u16::try_from(input.purpose.len()).map_err(|_| WorkerLaunchError::DescriptorHandoff)?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(input.purpose.as_bytes());
    }
    Ok(payload)
}

fn parse_activation_payload(
    payload: &[u8],
) -> Result<Vec<AdmittedWorkerInputV1>, WorkerActivationError> {
    if payload.len() < ACTIVATION_PROTOCOL_MAGIC.len() + 4
        || &payload[..ACTIVATION_PROTOCOL_MAGIC.len()] != ACTIVATION_PROTOCOL_MAGIC
    {
        return Err(WorkerActivationError::InvalidEnvelope);
    }
    let mut cursor = ACTIVATION_PROTOCOL_MAGIC.len();
    let count = usize::try_from(read_u32(payload, &mut cursor)?)
        .map_err(|_| WorkerActivationError::InvalidEnvelope)?;
    if count == 0 || count > MAX_ADMITTED_INPUTS {
        return Err(WorkerActivationError::InvalidEnvelope);
    }
    let mut admitted = Vec::with_capacity(count);
    for index in 0..count {
        let descriptor = read_u32(payload, &mut cursor)?;
        let maximum_bytes = read_u64(payload, &mut cursor)?;
        let purpose_length = usize::from(read_u16(payload, &mut cursor)?);
        let purpose_end = cursor
            .checked_add(purpose_length)
            .filter(|end| *end <= payload.len())
            .ok_or(WorkerActivationError::InvalidEnvelope)?;
        let purpose = std::str::from_utf8(&payload[cursor..purpose_end])
            .map_err(|_| WorkerActivationError::InvalidEnvelope)?
            .to_owned();
        cursor = purpose_end;
        let expected = FIRST_WORKER_INPUT_DESCRIPTOR
            + u32::try_from(index).map_err(|_| WorkerActivationError::InvalidEnvelope)?;
        let maximum_for_purpose =
            if purpose == PROVIDER_REQUEST_PURPOSE || purpose == PROVIDER_RESPONSE_PURPOSE {
                MAX_CANDIDATE_WIRE_BYTES
            } else {
                MAX_ADMITTED_INPUT_BYTES
            };
        if descriptor != expected
            || maximum_bytes == 0
            || maximum_bytes > maximum_for_purpose
            || !valid_token(&purpose, MAX_INPUT_PURPOSE_BYTES)
        {
            return Err(WorkerActivationError::InvalidEnvelope);
        }
        admitted.push(AdmittedWorkerInputV1 {
            descriptor,
            purpose,
            maximum_bytes,
        });
    }
    if cursor != payload.len() {
        return Err(WorkerActivationError::InvalidEnvelope);
    }
    Ok(admitted)
}

fn read_u16(payload: &[u8], cursor: &mut usize) -> Result<u16, WorkerActivationError> {
    let end = cursor
        .checked_add(2)
        .filter(|end| *end <= payload.len())
        .ok_or(WorkerActivationError::InvalidEnvelope)?;
    let bytes: [u8; 2] = payload[*cursor..end]
        .try_into()
        .map_err(|_| WorkerActivationError::InvalidEnvelope)?;
    *cursor = end;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(payload: &[u8], cursor: &mut usize) -> Result<u32, WorkerActivationError> {
    let end = cursor
        .checked_add(4)
        .filter(|end| *end <= payload.len())
        .ok_or(WorkerActivationError::InvalidEnvelope)?;
    let bytes: [u8; 4] = payload[*cursor..end]
        .try_into()
        .map_err(|_| WorkerActivationError::InvalidEnvelope)?;
    *cursor = end;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(payload: &[u8], cursor: &mut usize) -> Result<u64, WorkerActivationError> {
    let end = cursor
        .checked_add(8)
        .filter(|end| *end <= payload.len())
        .ok_or(WorkerActivationError::InvalidEnvelope)?;
    let bytes: [u8; 8] = payload[*cursor..end]
        .try_into()
        .map_err(|_| WorkerActivationError::InvalidEnvelope)?;
    *cursor = end;
    Ok(u64::from_be_bytes(bytes))
}

fn close_raw_descriptors(descriptors: &[RawFd]) {
    for descriptor in descriptors {
        let _ = nix::unistd::close(*descriptor);
    }
}

fn set_nonblocking(stdout: &ChildStdout) -> Result<(), WorkerLaunchError> {
    let current =
        fcntl(stdout.as_raw_fd(), FcntlArg::F_GETFL).map_err(|error| WorkerLaunchError::Io {
            operation: "inspect worker stdout flags",
            source: nix_errno_to_io(error),
        })?;
    let flags = OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK;
    fcntl(stdout.as_raw_fd(), FcntlArg::F_SETFL(flags)).map_err(|error| WorkerLaunchError::Io {
        operation: "bound worker stdout",
        source: nix_errno_to_io(error),
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn launch_profile_digest(
    security_profile: SecurityProfileV1,
    launcher: &WorkerLauncherConfigV1,
    profile: &WorkerProfileConfigV1,
    argv: &[String],
    maximum_candidate_wire_bytes: u64,
    admitted_inputs: &[AdmittedWorkerInputV1],
    workspace: &ProposalWorkspaceV1,
    runtime_roots: &[RuntimeRoot],
) -> Result<Digest, WorkerLaunchError> {
    #[derive(Serialize)]
    struct RuntimeRootBinding<'a> {
        path: &'a Path,
        device: u64,
        inode: u64,
        uid: u32,
        gid: u32,
        mode: u32,
    }
    #[derive(Serialize)]
    struct RuntimeObservation<'a> {
        roots: Vec<RuntimeRootBinding<'a>>,
        synthetic_lib: &'static str,
        synthetic_lib64: &'static str,
    }
    #[derive(Serialize)]
    struct LaunchBinding<'a> {
        schema: &'static str,
        security_profile: SecurityProfileV1,
        project: &'a str,
        sandbox: &'a ExecutableIdentityV1,
        worker: &'a ExecutableIdentityV1,
        argv: &'a [String],
        candidate_effect: WorkerCandidateEffectV1,
        candidate_target: &'a str,
        candidate_semantic_type: &'a str,
        runtime: RuntimeObservation<'a>,
        workspace_root: &'a FilesystemNodeCustodyV1,
        workspace: &'a Digest,
        admitted_inputs: &'a [AdmittedWorkerInputV1],
        timeout_ms: u64,
        decoded_output_limit: u64,
        candidate_wire_limit: u64,
        network: &'static str,
        environment: &'static str,
        worker_path: &'static str,
        workspace_path: &'static str,
    }
    let observed_runtime = runtime_roots
        .iter()
        .map(|root| RuntimeRootBinding {
            path: &root.mount_path,
            device: root.device,
            inode: root.inode,
            uid: root.uid,
            gid: root.gid,
            mode: root.mode,
        })
        .collect();
    Digest::from_serializable(&LaunchBinding {
        schema: "ag.worker-launch-profile/v1",
        security_profile,
        project: &profile.project,
        sandbox: &launcher.sandbox_identity,
        worker: &profile.executable_identity,
        argv,
        candidate_effect: profile.candidate_effect,
        candidate_target: &profile.candidate_target,
        candidate_semantic_type: &profile.candidate_semantic_type,
        runtime: RuntimeObservation {
            roots: observed_runtime,
            synthetic_lib: "usr/lib",
            synthetic_lib64: "usr/lib64",
        },
        workspace_root: &launcher.workspace_root_custody,
        workspace: &workspace.identity,
        admitted_inputs,
        timeout_ms: profile.timeout_ms,
        decoded_output_limit: profile.output_budget_bytes,
        candidate_wire_limit: maximum_candidate_wire_bytes,
        network: "new_unshared_namespace_no_interfaces",
        environment: "clearenv_with_fixed_pwd_work_only",
        worker_path: WORKER_PATH,
        workspace_path: WORKSPACE_PATH,
    })
    .map_err(|_| WorkerLaunchError::Evidence)
}

fn errno_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

fn nix_errno_to_io(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;

    const BWRAP: &str = "/usr/bin/bwrap";

    struct Fixture {
        _temp: TempDir,
        launcher: WorkerLauncherConfigV1,
    }

    fn executable_identity(path: &Path) -> ExecutableIdentityV1 {
        let bytes = fs::read(path).expect("read fixture executable");
        ExecutableIdentityV1::new(Digest::hash_bytes(&bytes), bytes.len() as u64, None)
    }

    fn install_read_only(source: &Path, destination: &Path) {
        fs::copy(source, destination).expect("copy reviewed executable");
        fs::set_permissions(destination, fs::Permissions::from_mode(0o555))
            .expect("make reviewed executable immutable by mode");
    }

    fn fixture(worker_source: &Path, arguments: &[&str]) -> Fixture {
        assert!(Path::new(BWRAP).is_file(), "Bubblewrap fixture is required");
        let temp = TempDir::new().expect("temporary launch fixture");
        let review = temp.path().join("review");
        let workspaces = temp.path().join("workspaces");
        fs::create_dir(&review).expect("review directory");
        fs::create_dir(&workspaces).expect("workspace directory");
        fs::set_permissions(&review, fs::Permissions::from_mode(0o700)).expect("review mode");
        fs::set_permissions(&workspaces, fs::Permissions::from_mode(0o700))
            .expect("workspace mode");
        let worker = review.join("worker");
        install_read_only(worker_source, &worker);
        let workspace_metadata = fs::metadata(&workspaces).expect("workspace metadata");
        let launcher = WorkerLauncherConfigV1 {
            governor_principal_root: Digest::hash_domain("ag-ng/test", b"governor"),
            governor_challenge_maximum_clock_skew_ms: 30_000,
            workspace_root: workspaces,
            workspace_root_custody: FilesystemNodeCustodyV1 {
                uid: workspace_metadata.uid(),
                gid: workspace_metadata.gid(),
                mode: workspace_metadata.mode() & 0o7777,
            },
            sandbox_executable: PathBuf::from(BWRAP),
            sandbox_identity: executable_identity(Path::new(BWRAP)),
            runtime_roots: vec![PathBuf::from("/usr")],
            profiles: vec![WorkerProfileConfigV1 {
                profile_id: "fixture".to_owned(),
                project: "fixture".to_owned(),
                executable: worker.clone(),
                executable_identity: executable_identity(&worker),
                fixed_arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
                candidate_effect: WorkerCandidateEffectV1::ManagedFilePut,
                candidate_target: "fixture.target".to_owned(),
                candidate_semantic_type: "managed_file_content_v1".to_owned(),
                timeout_ms: 2_000,
                output_budget_bytes: 1024,
                provider_access: None,
            }],
        };
        Fixture {
            _temp: temp,
            launcher,
        }
    }

    fn prepare(fixture: &Fixture, workspace: &str) -> PreparedWorkerLaunchV1 {
        prepare_worker_launch(
            SecurityProfileV1::Development,
            &fixture.launcher,
            "fixture",
            workspace,
            4096,
            &[],
        )
        .expect("prepare fixture worker")
    }

    #[test]
    fn fixed_worker_remains_gated_then_returns_candidate() {
        let fixture = fixture(Path::new("/usr/bin/printf"), &["candidate"]);
        let mut prepared = prepare(&fixture, "fixed-worker");
        assert_eq!(
            prepared.evidence.argv,
            [WORKER_PATH.to_owned(), "candidate".to_owned()]
        );
        thread::sleep(Duration::from_millis(25));
        assert!(
            prepared
                .process
                .try_wait()
                .expect("poll gated worker")
                .is_none()
        );
        prepared.release.release().expect("release worker");
        let completed = prepared.process.wait().expect("wait for worker");
        assert!(completed.status.success());
        assert_eq!(completed.candidate, b"candidate");
    }

    #[test]
    fn rename_substitution_refuses_before_spawn() {
        let fixture = fixture(Path::new("/usr/bin/printf"), &["candidate"]);
        let worker = fixture.launcher.profiles[0].executable.clone();
        let replacement = worker.with_extension("replacement");
        install_read_only(Path::new("/usr/bin/false"), &replacement);
        let error = prepare_worker_launch_inner(
            SecurityProfileV1::Development,
            &fixture.launcher,
            "fixture",
            "rename-substitution",
            4096,
            &[],
            false,
            || fs::rename(&replacement, &worker).expect("replace worker path"),
        )
        .expect_err("renamed executable must refuse");
        assert!(matches!(
            error,
            WorkerLaunchError::ExecutableSubstituted {
                role: WorkerExecutableRoleV1::Worker,
                ..
            }
        ));
    }

    #[test]
    fn same_inode_overwrite_refuses_before_spawn() {
        let fixture = fixture(Path::new("/usr/bin/printf"), &["candidate"]);
        let worker = fixture.launcher.profiles[0].executable.clone();
        let error = prepare_worker_launch_inner(
            SecurityProfileV1::Development,
            &fixture.launcher,
            "fixture",
            "same-inode-overwrite",
            4096,
            &[],
            false,
            || {
                fs::set_permissions(&worker, fs::Permissions::from_mode(0o755))
                    .expect("temporarily enable fixture mutation");
                let mut file = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&worker)
                    .expect("open same inode");
                file.write_all(b"mutated executable")
                    .expect("mutate retained inode");
                file.sync_all().expect("sync mutation");
                fs::set_permissions(&worker, fs::Permissions::from_mode(0o555))
                    .expect("restore immutable mode");
            },
        )
        .expect_err("same-inode mutation must refuse");
        assert!(matches!(
            error,
            WorkerLaunchError::ExecutableSubstituted {
                role: WorkerExecutableRoleV1::Worker,
                ..
            }
        ));
    }

    #[test]
    fn target_is_absent_and_environment_is_sanitized() {
        let target_root = TempDir::new().expect("governed target fixture");
        let target = target_root.path().join("governed");
        fs::write(&target, b"unchanged").expect("write governed target");
        let target_text = target.to_str().expect("UTF-8 target");
        let target_fixture = fixture(Path::new("/usr/bin/test"), &["!", "-e", target_text]);
        let prepared = prepare(&target_fixture, "target-absent");
        prepared.release.release().expect("release target probe");
        let completed = prepared.process.wait().expect("wait target probe");
        assert!(completed.status.success());
        assert_eq!(fs::read(&target).expect("reread target"), b"unchanged");

        let environment_fixture = fixture(Path::new("/usr/bin/env"), &[]);
        let prepared = prepare(&environment_fixture, "empty-environment");
        prepared
            .release
            .release()
            .expect("release environment probe");
        let completed = prepared.process.wait().expect("wait environment probe");
        assert!(completed.status.success());
        assert_eq!(completed.candidate, b"PWD=/work\n");
    }

    #[test]
    fn workspace_is_writable_while_synthetic_root_is_read_only() {
        let writable_fixture = fixture(Path::new("/usr/bin/touch"), &["/work/created"]);
        let prepared = prepare(&writable_fixture, "workspace-write");
        let created = prepared.workspace.path.join("created");
        prepared
            .release
            .release()
            .expect("release workspace writer");
        let completed = prepared.process.wait().expect("wait workspace writer");
        assert!(completed.status.success());
        assert!(created.is_file());

        let root_fixture = fixture(Path::new("/usr/bin/touch"), &["/escape"]);
        let prepared = prepare(&root_fixture, "root-write");
        prepared.release.release().expect("release root writer");
        let completed = prepared.process.wait().expect("wait root writer");
        assert!(!completed.status.success());
    }

    #[test]
    fn timeout_is_reported_before_explicit_termination() {
        let mut fixture = fixture(Path::new("/usr/bin/sleep"), &["10"]);
        fixture.launcher.profiles[0].timeout_ms = 50;
        let mut prepared = prepare(&fixture, "timeout");
        prepared.release.release().expect("release sleeper");
        loop {
            match prepared.process.try_wait() {
                Err(WorkerLaunchError::TimedOut) => break,
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                other => panic!("unexpected timeout poll result: {other:?}"),
            }
        }
        assert!(prepared.process.id().is_some());
        prepared
            .process
            .terminate()
            .expect("terminate and reap timed-out worker");
        assert!(prepared.process.id().is_none());
    }

    #[test]
    fn output_limit_is_reported_before_explicit_termination() {
        let fixture = fixture(Path::new("/usr/bin/printf"), &["too-large"]);
        let mut prepared = prepare_worker_launch(
            SecurityProfileV1::Development,
            &fixture.launcher,
            "fixture",
            "output-limit",
            3,
            &[],
        )
        .expect("prepare output-bound worker");
        prepared.release.release().expect("release output worker");
        loop {
            match prepared.process.try_wait() {
                Err(WorkerLaunchError::CandidateLimitExceeded { .. }) => break,
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                other => panic!("unexpected output-limit poll result: {other:?}"),
            }
        }
        assert!(prepared.process.id().is_some());
        prepared
            .process
            .terminate()
            .expect("terminate and reap output-bound worker");
        assert!(prepared.process.id().is_none());
    }

    #[test]
    fn explicit_termination_confirms_reap_and_is_idempotent() {
        let fixture = fixture(Path::new("/usr/bin/sleep"), &["10"]);
        let mut prepared = prepare(&fixture, "checked-termination");
        prepared.release.release().expect("release sleeper");
        assert!(prepared.process.id().is_some());

        prepared
            .process
            .terminate()
            .expect("terminate and reap live worker");
        assert!(prepared.process.id().is_none());
        prepared
            .process
            .terminate()
            .expect("repeated termination is idempotent");
    }

    #[test]
    fn gated_process_exposes_retained_monotonic_deadline() {
        let mut fixture = fixture(Path::new("/usr/bin/true"), &[]);
        fixture.launcher.profiles[0].timeout_ms = 25;
        let mut prepared = prepare(&fixture, "gated-deadline");
        let test_deadline = Instant::now() + Duration::from_secs(1);
        while !prepared.process.deadline_expired() && Instant::now() < test_deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(prepared.process.deadline_expired());
        assert!(prepared.process.id().is_some());
        prepared.release.abort();
        prepared
            .process
            .terminate()
            .expect("terminate and reap expired gated worker");
    }

    #[test]
    fn startup_script_refuses_native_elf_gate() {
        let source = TempDir::new().expect("temporary script fixture");
        let script = source.path().join("worker.sh");
        fs::write(&script, b"#!/bin/sh\nprintf candidate\n").expect("write script fixture");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o555))
            .expect("make script fixture executable");
        let fixture = fixture(&script, &[]);

        let error = prepare_worker_launch(
            SecurityProfileV1::Development,
            &fixture.launcher,
            "fixture",
            "script-refusal",
            4096,
            &[],
        )
        .expect_err("startup scripts must refuse");
        assert!(matches!(
            error,
            WorkerLaunchError::UnsafeExecutable {
                role: WorkerExecutableRoleV1::Worker,
                reason: "startup scripts and non-ELF executables are forbidden",
                ..
            }
        ));
    }

    #[test]
    fn activation_pipes_arrive_on_exact_descriptors() {
        let python = Path::new("/usr/bin/python3");
        assert!(python.is_file(), "Python fixture is required");
        let script = concat!(
            "import array,os,socket;",
            "s=socket.socket(fileno=0);",
            "m,a,fl,ad=s.recvmsg(2048,socket.CMSG_SPACE(32));",
            "f=array.array('i');",
            "[f.frombytes(d[:len(d)-len(d)%f.itemsize]) for l,t,d in a ",
            "if l==socket.SOL_SOCKET and t==socket.SCM_RIGHTS];",
            "os.write(1,os.read(f[0],64)+b'|'+os.read(f[1],64))"
        );
        let fixture = fixture(python, &["-c", script]);
        let admitted = [
            AdmittedWorkerInputV1 {
                descriptor: 3,
                purpose: "session-credential".to_owned(),
                maximum_bytes: 64,
            },
            AdmittedWorkerInputV1 {
                descriptor: 4,
                purpose: "activation-challenge".to_owned(),
                maximum_bytes: 64,
            },
        ];
        let mut prepared = prepare_worker_launch(
            SecurityProfileV1::Development,
            &fixture.launcher,
            "fixture",
            "activation-inputs",
            4096,
            &admitted,
        )
        .expect("prepare activation worker");
        let mut credential = prepared.admitted_inputs.remove(0);
        let mut challenge = prepared.admitted_inputs.remove(0);
        credential
            .write_all(b"credential")
            .expect("write credential");
        challenge.write_all(b"challenge").expect("write challenge");
        credential.close();
        challenge.close();
        prepared
            .release
            .release()
            .expect("release activation worker");
        let completed = prepared.process.wait().expect("wait activation worker");
        assert!(completed.status.success());
        assert_eq!(completed.candidate, b"credential|challenge");
    }

    #[test]
    fn provider_channel_arrives_on_exact_directional_descriptors() {
        let admitted = [
            AdmittedWorkerInputV1 {
                descriptor: 3,
                purpose: "session-credential".to_owned(),
                maximum_bytes: 64,
            },
            AdmittedWorkerInputV1 {
                descriptor: 4,
                purpose: "activation-challenge".to_owned(),
                maximum_bytes: 64,
            },
        ];
        let (_, _, mut child_endpoints, _, channel) =
            prepare_input_transport(&admitted, true).expect("prepare provider channel");
        assert_eq!(child_endpoints.len(), 4);
        let mut manifest = admitted.to_vec();
        manifest.extend([
            AdmittedWorkerInputV1 {
                descriptor: PROVIDER_REQUEST_DESCRIPTOR,
                purpose: PROVIDER_REQUEST_PURPOSE.to_owned(),
                maximum_bytes: 4096,
            },
            AdmittedWorkerInputV1 {
                descriptor: PROVIDER_RESPONSE_DESCRIPTOR,
                purpose: PROVIDER_RESPONSE_PURPOSE.to_owned(),
                maximum_bytes: 4096,
            },
        ]);
        assert_eq!(
            parse_activation_payload(&activation_payload(&manifest).expect("activation payload"))
                .expect("exact provider descriptor manifest"),
            manifest
        );
        let response_child = child_endpoints.pop().expect("response child");
        let request_child = child_endpoints.pop().expect("request child");
        let channel = channel.expect("provider channel");
        let sent = nix::unistd::write(&request_child, b"provider-request")
            .expect("worker sends provider request");
        assert_eq!(sent, b"provider-request".len());
        let mut request = [0_u8; 64];
        let request_length = channel
            .receive_request(&mut request)
            .expect("receive provider request");
        assert_eq!(&request[..request_length], b"provider-request");
        channel
            .send_response(b"provider-response")
            .expect("send provider response");
        let mut response = [0_u8; 64];
        let response_length = nix::unistd::read(response_child.as_raw_fd(), &mut response)
            .expect("worker receives provider response");
        assert_eq!(&response[..response_length], b"provider-response");
        assert!(nix::unistd::read(request_child.as_raw_fd(), &mut response).is_err());
        assert!(nix::unistd::write(&response_child, b"wrong-direction").is_err());
    }

    #[test]
    fn provider_channel_requires_exact_bootstrap_descriptors() {
        let fixture = fixture(Path::new("/usr/bin/true"), &[]);
        let error = prepare_worker_launch_with_provider(
            SecurityProfileV1::Development,
            &fixture.launcher,
            "fixture",
            "provider-channel-refusal",
            4096,
            &[],
        )
        .expect_err("provider launch without exact bootstrap must refuse");
        assert!(matches!(
            error,
            WorkerLaunchError::InvalidReview(
                "provider channel requires exact fd 3/4 bootstrap inputs"
            )
        ));
    }

    #[test]
    fn production_profiles_refuse_without_claiming_isolation() {
        let fixture = fixture(Path::new("/usr/bin/true"), &[]);
        let error = prepare_worker_launch(
            SecurityProfileV1::Production,
            &fixture.launcher,
            "fixture",
            "production-refusal",
            4096,
            &[],
        )
        .expect_err("production must fail closed");
        assert!(matches!(
            error,
            WorkerLaunchError::IsolationUnproven(SecurityProfileV1::Production)
        ));
    }
}
