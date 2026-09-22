//! One-shot, role-sealed runner service loop.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use cap_fs_ext::DirExt;
#[cfg(test)]
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use grok_build_core::{
    CommandOutputCaptureStoreHeadV1, CompiledExecutionPolicy, Digest, ExecutionNetwork,
    ExecutionOrigin, ExecutionPolicyCompiler, IssuedWorkspaceGrant, MutationMode, SprintSpec,
    WorkerLease, WorkspaceGrantIssuer,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use sha2::{Digest as _, Sha256};

use crate::cleanup_proof::ValidatedCommandDomainCleanupProof;
use crate::command::contained_boundary::{
    ContainedExecutionEvidence, authenticated_output_capture_maximum,
};
use crate::command::{SupervisorError, SupervisorPaths};
use crate::command_output_store::{
    CapabilityCommandOutputStore, CommandOutputCaptureJournalStateV1,
};
use crate::stage_bundle::StageBundleError;
use crate::wire::{
    COMMAND_TERMINAL_CAPTURE_SCHEMA, CommandEffectAuthorityV1, CommandEffectAuthorityV2,
    InitializationReceipt, MAX_WIRE_FRAME_BYTES, MAX_WIRE_SEARCH_MATCHES,
    RUNNER_WIRE_PROTOCOL_VERSION, RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequest,
    RunnerRequestEnvelope, RunnerRequestEnvelopeV12, RunnerRequestEnvelopeV14,
    RunnerRequestEnvelopeV15, RunnerResponse, RunnerResponseEnvelope, RunnerResponseEnvelopeV12,
    RunnerResponseV12, RunnerRole, RunnerRoleInputAuthority, ShutdownPreparedAcknowledgement,
    WireApplicationEvidence, WireBinaryIdentity, WireCommandFailureCodeV12,
    WireCommandOutputCaptureTerminalV1, WireCommandTerminalEvidence,
    WireContainedCommandReleaseAuthorityV1, WireContainmentRefusalEvidenceV12, WireEffectContext,
    WireExplicitRollbackEvidence, WireFailureClass, WireProtocolError, WireReconciliationReference,
    WireRollbackArtifactReference, WireRollbackEvidence, WireRollbackLiveConflict,
    WireRootIdentity, WireRunnerLaunchPreparationV1, WireWorkspaceCapture,
    command_terminal_record_bytes, decode_request_frame, decode_request_frame_v12,
    decode_request_frame_v14, decode_request_frame_v15, encode_response_frame_v12, read_request,
    sprint_spec_digest, validate_bundle_change_set, validate_live_state_finalization_plan,
    write_response,
};
use crate::{
    CancellationToken, CapabilityApplyError, CapabilityApplyOutcome, CapabilityApplyReconciliation,
    CapabilityRollbackAttempt, CapabilityRollbackOutcome, CapabilitySafeApplier,
    CapabilityShadowStore, CapabilityShadowWorkspace, CapabilityStageBundleStore,
    CapabilityVerifierWorkspace, CapabilityWorkspace, CapabilityWorkspaceError, FileToolError,
    FileToolLimits, ManifestEntry, RunnerProcessSeal, ShadowFileTools, StageBundleReference,
    StagedChangeSet, WorkspaceManifest,
};

const MAX_SESSION_REQUESTS: usize = 100_000;
const MAX_RUNNER_BINARY_BYTES: u64 = 256 * 1_024 * 1_024;
const ACTIVE_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);
const APPLICATION_JOURNAL_CHILD: &str = "application-journal";
#[cfg(target_os = "linux")]
const SEALED_RUNNER_MEMFD_TARGET: &str = "/memfd:grok-build-runner-exec-v1 (deleted)";
const PROTOCOL_DESCRIPTOR: &[u8] = b"grok-build.runner-service.v12\0u32be\0canonical-strict-json\0max-frame=8388608\0routing=exact-leading-protocol-version-prefix\0v11=initialization,controls,non-command,historical-codec-exact\0v11-run-command=failed-before-effect\0v12=run-command-only\0v12-command-effect-authority=full-envelope-policy-and-transport-commitment\0v12-detector-policy=gb.sensitive-output-detector.v1\0v12-clean-scan-receipt=runner-v2\0v12-core-dump-profile=zero-limit-pre-launch\0v12-sensitive-staging=neutralized-before-abandonment\0v12-rejection=no-output-fields\0v12-containment-refusal=untouched-capture-head-and-kernel-read-no-domain-proof\0roles=worker,final-verifier,applier,live-state-verifier\0durable-integrate-change-set\0stage-bundle=v1\0typed-rollback-precondition-and-conflict\0mode-bound-rollback-target-contract\0effect-contract-version\0worker-lease=v1\0sprint-spec=v1\0sprint-spec-digest-domain=grok-build/sprint-spec/v1\0role-input-authority=v2-live-state-finalization\0live-state-capture-request=core-v23-effect-required\0live-workspace-manifest=descriptor-relative-core-v1-capture-interval\0failure-class=after-known-effect\0command-output-capture=core-v1-acquired-anchor-required\0command-output-capture-identities=path-free\0command-output-capture-terminal=v1-finished,published,terminal-prepared-then-v2-clean-terminal-prepared\0command-terminal=contained-evidence-v1-artifact-reference-required\0command-output=stream-separated-complete-commitment-v1\0command-output-artifact-reference=core-v1\0command-cleanup-proof=canonical-readback-v1\0shutdown-command-count=effects-admitted-v2\0no-shell\0no-credentials\0";
const PRIVATE_STATE_DIGEST_DOMAIN: &[u8] = b"grok-build/private-state-identity/v1\0";
const V11_REQUEST_PAYLOAD_PREFIX: &[u8] = b"{\"protocol_version\":11,";
const V12_REQUEST_PAYLOAD_PREFIX: &[u8] = b"{\"protocol_version\":12,";
/// Version **14**, not 13.
///
/// 13 belongs to the dormant `wire_v13` sprint-authority boundary, which is
/// deliberately unrouted and whose own tests pin that fact. Routing 13 here
/// would deliver its initialization frames to the contained-command decoder,
/// and those tests caught exactly that when this router first tried it.
const V14_REQUEST_PAYLOAD_PREFIX: &[u8] = b"{\"protocol_version\":14,";
const V15_REQUEST_PAYLOAD_PREFIX: &[u8] = b"{\"protocol_version\":15,";

/// One exact wire envelope after the live service has joined it to its
/// initialized session, restored grant, role, nonce, sequence, effect scope,
/// policy, and input snapshot.
///
/// The fields and production constructor are private to this module. Other
/// runner modules may consume the proof but cannot mint it from wire data.
#[allow(
    dead_code,
    reason = "v11 command envelopes remain a frozen test-only compatibility proof after production command admission moved exclusively to v12"
)]
pub(crate) struct SessionValidatedCommandEnvelope {
    envelope: RunnerRequestEnvelope,
    grant_hash: Digest,
}

impl SessionValidatedCommandEnvelope {
    #[allow(
        dead_code,
        reason = "consumed only by the frozen v11 command-authority compatibility constructor exercised in tests"
    )]
    pub(crate) fn into_parts(self) -> (RunnerRequestEnvelope, Digest) {
        (self.envelope, self.grant_hash)
    }
}

/// Non-cloneable proof that the live mixed-protocol service joined one exact
/// v12 command envelope to its initialized session and independently restored
/// workspace grant. Wire code consumes this proof to mint v12 command-effect
/// authority; arbitrary callers cannot construct it.
pub(crate) struct SessionValidatedCommandEnvelopeV12 {
    envelope: RunnerRequestEnvelopeV12,
    grant_hash: Digest,
}

impl SessionValidatedCommandEnvelopeV12 {
    pub(crate) fn into_parts(self) -> (RunnerRequestEnvelopeV12, Digest) {
        (self.envelope, self.grant_hash)
    }
}

/// Non-cloneable command-root custody minted only from an initialized worker's
/// retained shadow and private-state capabilities.
///
/// The production constructor is private to [`WorkerSession`]. Command
/// preparation may consume this proof, but cannot select or reopen a different
/// same-content root and cannot reuse the proof for another effect authority.
pub(crate) struct SessionValidatedWorkerExecutionRoot {
    command_effect_authority: CommandEffectAuthorityV1,
    private_state_root: PathBuf,
    private_state_descriptor: Dir,
    execution_root: PathBuf,
    execution_root_descriptor: Dir,
}

impl SessionValidatedWorkerExecutionRoot {
    pub(crate) fn into_command_capabilities(
        self,
        authority: &CommandEffectAuthorityV1,
    ) -> Result<(PathBuf, Dir, PathBuf, Dir), String> {
        if &self.command_effect_authority != authority {
            return Err(
                "session-minted Worker execution root belongs to a different command effect".into(),
            );
        }
        Ok((
            self.private_state_root,
            self.private_state_descriptor,
            self.execution_root,
            self.execution_root_descriptor,
        ))
    }
}

#[cfg(test)]
pub(crate) fn test_session_validated_command_envelope(
    envelope: &RunnerRequestEnvelope,
    grant_hash: &Digest,
) -> SessionValidatedCommandEnvelope {
    SessionValidatedCommandEnvelope {
        envelope: envelope.clone(),
        grant_hash: grant_hash.clone(),
    }
}

#[cfg(test)]
pub(crate) fn test_session_validated_worker_execution_root(
    authority: &CommandEffectAuthorityV1,
    private_state_root: &Path,
    execution_root: &Path,
) -> Result<SessionValidatedWorkerExecutionRoot, String> {
    fn open_exact_directory(path: &Path) -> Result<Dir, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "test command root has no parent".to_string())?;
        let leaf = path
            .file_name()
            .ok_or_else(|| "test command root has no leaf".to_string())?;
        Dir::open_ambient_dir(parent, ambient_authority())
            .and_then(|parent| parent.open_dir_nofollow(leaf))
            .map_err(|error| format!("cannot retain test command directory: {error}"))
    }

    Ok(SessionValidatedWorkerExecutionRoot {
        command_effect_authority: authority.clone(),
        private_state_root: private_state_root.to_path_buf(),
        private_state_descriptor: open_exact_directory(private_state_root)?,
        execution_root: execution_root.to_path_buf(),
        execution_root_descriptor: open_exact_directory(execution_root)?,
    })
}

/// Returns the immutable digest of the runner wire schema admitted by this binary.
///
/// A coordinator persists this value in [`grok_build_core::RunnerLaunchIntent`]
/// before spawning a runner. Initialization must return the same digest before
/// the session can be registered or receive effect authority.
#[must_use]
pub fn runner_protocol_digest() -> Digest {
    Digest::sha256(PROTOCOL_DESCRIPTOR)
}

/// Fatal service-loop error. Operation failures with a safe correlated response
/// remain protocol responses and are not represented here.
#[derive(Debug)]
pub enum RunnerServiceError {
    /// A malformed, non-canonical, partial, or unsupported frame was received.
    Protocol(WireProtocolError),
    /// Input closed without an orderly shutdown or cancellation request.
    UnexpectedEndOfStream,
    /// Initialization was missing, repeated, or otherwise reordered.
    InitializationOrder,
    /// A request crossed the immutable session boundary.
    SessionMismatch,
    /// A request identity was reused.
    DuplicateRequestId,
    /// A durable effect or idempotency identity was reused.
    DuplicateEffectIdentity,
    /// A request used a nonce from another runner process.
    RunnerNonceMismatch,
    /// A request was replayed, skipped, reordered, or exhausted sequence space.
    SequenceMismatch,
    /// Durable effect authority or snapshot context differed from this session.
    EffectContextMismatch,
    /// The request set did not match the immutable runner role.
    RoleConfusion,
    /// Initialization authority or capability acquisition failed.
    Initialization(String),
    /// A second ordinary request arrived while one command job was active.
    CommandJobAlreadyActive,
    /// The active command crossed the launch boundary but did not produce
    /// terminal cleanup-proven evidence.
    CommandJobUnprovenAfterLaunch,
    /// The active command worker panicked or disappeared without one outcome.
    CommandJobPanicked,
    /// A test/native command seam returned an outcome of the wrong shape.
    CommandJobProtocol,
    /// Complete command evidence could not be durably joined to its exact
    /// `TerminalPrepared` capture record, so no response can be emitted.
    CommandTerminalPreparation(String),
    /// The active command worker could not be joined before session teardown.
    CommandWorkerJoin,
    /// The operating system refused to create the bounded command worker.
    CommandWorkerSpawn(String),
}

impl Display for RunnerServiceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "runner protocol terminated: {error}"),
            Self::UnexpectedEndOfStream => {
                formatter.write_str("runner input closed without orderly shutdown")
            }
            Self::InitializationOrder => {
                formatter.write_str("runner initialization was missing, repeated, or reordered")
            }
            Self::SessionMismatch => formatter.write_str("runner request crossed session identity"),
            Self::DuplicateRequestId => formatter.write_str("runner request identity was reused"),
            Self::DuplicateEffectIdentity => {
                formatter.write_str("runner durable effect identity was reused")
            }
            Self::RunnerNonceMismatch => {
                formatter.write_str("runner request used a stale process nonce")
            }
            Self::SequenceMismatch => {
                formatter.write_str("runner request sequence was replayed, skipped, or reordered")
            }
            Self::EffectContextMismatch => {
                formatter.write_str("runner durable effect context differs from session state")
            }
            Self::RoleConfusion => formatter.write_str("runner request did not match session role"),
            Self::Initialization(message) => {
                write!(formatter, "runner initialization failed: {message}")
            }
            Self::CommandJobAlreadyActive => formatter.write_str(
                "runner received a second ordinary request while a command job was active",
            ),
            Self::CommandJobUnprovenAfterLaunch => formatter
                .write_str("runner command job ended without cleanup-proven terminal evidence"),
            Self::CommandJobPanicked => {
                formatter.write_str("runner command job panicked or lost its outcome")
            }
            Self::CommandJobProtocol => {
                formatter.write_str("runner command job returned an invalid outcome shape")
            }
            Self::CommandTerminalPreparation(message) => write!(
                formatter,
                "runner command terminal could not be durably prepared: {message}"
            ),
            Self::CommandWorkerJoin => {
                formatter.write_str("runner command worker could not be joined")
            }
            Self::CommandWorkerSpawn(message) => {
                write!(
                    formatter,
                    "runner command worker could not start: {message}"
                )
            }
        }
    }
}

impl std::error::Error for RunnerServiceError {}

impl From<WireProtocolError> for RunnerServiceError {
    fn from(error: WireProtocolError) -> Self {
        Self::Protocol(error)
    }
}

enum IncrementalRequestEvent {
    Pending,
    EndOfStream,
    Request(Box<ServiceRequestEnvelope>),
}

/// One request admitted by the service-level mixed protocol router.
///
/// The frozen v11 decoder remains unchanged. The service selects a decoder
/// only from the exact first canonical JSON field, so a reordered, padded, or
/// ambiguous version spelling cannot be interpreted under either contract.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one decoded request is produced per frame and consumed once; boxing it would move an owned envelope to the heap for no benefit"
)]
enum ServiceRequestEnvelope {
    V11(RunnerRequestEnvelope),
    V12(RunnerRequestEnvelopeV12),
    V14(RunnerRequestEnvelopeV14),
    V15(RunnerRequestEnvelopeV15),
}

fn decode_service_request_frame(frame: &[u8]) -> Result<ServiceRequestEnvelope, WireProtocolError> {
    let payload = frame.get(4..).ok_or(WireProtocolError::TruncatedPrefix)?;
    if payload.starts_with(V11_REQUEST_PAYLOAD_PREFIX) {
        return decode_request_frame(frame).map(ServiceRequestEnvelope::V11);
    }
    if payload.starts_with(V12_REQUEST_PAYLOAD_PREFIX) {
        return decode_request_frame_v12(frame).map(ServiceRequestEnvelope::V12);
    }
    if payload.starts_with(V14_REQUEST_PAYLOAD_PREFIX) {
        return decode_request_frame_v14(frame).map(ServiceRequestEnvelope::V14);
    }
    if payload.starts_with(V15_REQUEST_PAYLOAD_PREFIX) {
        return decode_request_frame_v15(frame).map(ServiceRequestEnvelope::V15);
    }
    Err(WireProtocolError::InvalidContract(
        // Worded so it still contains the exact phrase the dormant `wire_v13`
        // router pins assert on. Those pins are about v13 being unrouted, which
        // is still true; only the set of routed versions grew, and rewording
        // them to accommodate this would be editing a guard to fit the change
        // it exists to catch.
        "runner service requires an exact leading canonical v11 or v12 protocol-version field, \
         or v14/v15 for a request the desktop admitted for contained release"
            .into(),
    ))
}

#[cfg(all(test, feature = "future-contracts"))]
pub(crate) fn test_decode_service_request_frame(frame: &[u8]) -> Result<(), WireProtocolError> {
    decode_service_request_frame(frame).map(|_| ())
}

enum IncrementalRequestState {
    Prefix { bytes: [u8; 4], received: usize },
    Payload { frame: Vec<u8>, received: usize },
}

struct IncrementalRequestDecoder {
    state: IncrementalRequestState,
}

impl IncrementalRequestDecoder {
    const fn new() -> Self {
        Self {
            state: IncrementalRequestState::Prefix {
                bytes: [0; 4],
                received: 0,
            },
        }
    }

    fn read_available<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<IncrementalRequestEvent, WireProtocolError> {
        loop {
            match &mut self.state {
                IncrementalRequestState::Prefix { bytes, received } => {
                    match reader.read(&mut bytes[*received..]) {
                        Ok(0) if *received == 0 => {
                            return Ok(IncrementalRequestEvent::EndOfStream);
                        }
                        Ok(0) => return Err(WireProtocolError::TruncatedPrefix),
                        Ok(count) => {
                            *received += count;
                            if *received == bytes.len() {
                                let length = u32::from_be_bytes(*bytes);
                                let payload_length = usize::try_from(length)
                                    .map_err(|_| WireProtocolError::InvalidLength(length))?;
                                if payload_length == 0 || payload_length > MAX_WIRE_FRAME_BYTES {
                                    return Err(WireProtocolError::InvalidLength(length));
                                }
                                let mut frame = vec![0; 4 + payload_length];
                                frame[..4].copy_from_slice(bytes);
                                self.state =
                                    IncrementalRequestState::Payload { frame, received: 0 };
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            return Ok(IncrementalRequestEvent::Pending);
                        }
                        Err(error) => return Err(WireProtocolError::Io(error)),
                    }
                }
                IncrementalRequestState::Payload { frame, received } => {
                    let payload_length = frame.len() - 4;
                    match reader.read(&mut frame[4 + *received..]) {
                        Ok(0) => {
                            return Err(WireProtocolError::TruncatedPayload {
                                expected: payload_length,
                                actual: *received,
                            });
                        }
                        Ok(count) => {
                            *received += count;
                            if *received == payload_length {
                                let complete = std::mem::take(frame);
                                self.state = IncrementalRequestState::Prefix {
                                    bytes: [0; 4],
                                    received: 0,
                                };
                                return decode_service_request_frame(&complete)
                                    .map(Box::new)
                                    .map(IncrementalRequestEvent::Request);
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            return Ok(IncrementalRequestEvent::Pending);
                        }
                        Err(error) => return Err(WireProtocolError::Io(error)),
                    }
                }
            }
        }
    }

    fn has_partial_frame(&self) -> bool {
        match &self.state {
            IncrementalRequestState::Prefix { received, .. } => *received != 0,
            IncrementalRequestState::Payload { .. } => true,
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "the production native command seam retains direct one-shot terminal evidence and each outcome is consumed exactly once"
)]
enum CommandTerminalOutcome {
    Contained(ContainedExecutionEvidence),
    SensitiveOutputRejected(
        crate::command::contained_boundary::ContainedSensitiveOutputRejectionEvidence,
    ),
    #[cfg(test)]
    PreparedV12(RunnerResponseV12),
}

enum CommandJobOutcome {
    Terminal(Box<CommandTerminalOutcome>),
    RefusedBeforeLaunch {
        code: WireCommandFailureCodeV12,
    },
    ReconciliationRequired {
        reference: WireReconciliationReference,
    },
    UnprovenAfterLaunch,
    Panicked,
}

type CommandJob = Box<dyn FnOnce(CancellationToken) -> CommandJobOutcome + Send + 'static>;

trait CommandJobFactory {
    fn create(
        &mut self,
        envelope: &RunnerRequestEnvelopeV12,
        authority: &CommandEffectAuthorityV2,
    ) -> Option<CommandJob>;
}

struct DisabledCommandJobFactory;

impl CommandJobFactory for DisabledCommandJobFactory {
    fn create(
        &mut self,
        _envelope: &RunnerRequestEnvelopeV12,
        _authority: &CommandEffectAuthorityV2,
    ) -> Option<CommandJob> {
        None
    }
}

struct ActiveCommandJob {
    envelope: RunnerRequestEnvelopeV12,
    cancellation: CancellationToken,
    receiver: Receiver<CommandJobOutcome>,
    worker: JoinHandle<()>,
    pending_control: Option<RunnerRequestEnvelope>,
    input_closed: bool,
}

impl ActiveCommandJob {
    fn spawn(
        envelope: RunnerRequestEnvelopeV12,
        job: CommandJob,
    ) -> Result<Self, RunnerServiceError> {
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("grok-build-command-job".into())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| job(worker_cancellation)))
                    .unwrap_or(CommandJobOutcome::Panicked);
                let _ = sender.send(outcome);
            })
            .map_err(|error| RunnerServiceError::CommandWorkerSpawn(error.to_string()))?;
        Ok(Self {
            envelope,
            cancellation,
            receiver,
            worker,
            pending_control: None,
            input_closed: false,
        })
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn try_outcome(&self) -> Result<Option<CommandJobOutcome>, RunnerServiceError> {
        match self.receiver.try_recv() {
            Ok(outcome) => Ok(Some(outcome)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(RunnerServiceError::CommandJobPanicked),
        }
    }

    fn wait_outcome(
        &self,
        timeout: Duration,
    ) -> Result<Option<CommandJobOutcome>, RunnerServiceError> {
        match self.receiver.recv_timeout(timeout) {
            Ok(outcome) => Ok(Some(outcome)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(RunnerServiceError::CommandJobPanicked),
        }
    }

    fn join(
        self,
        outcome: Option<CommandJobOutcome>,
    ) -> Result<CommandJobOutcome, RunnerServiceError> {
        let outcome = match outcome {
            Some(outcome) => outcome,
            None => self.receiver.recv().unwrap_or(CommandJobOutcome::Panicked),
        };
        self.worker
            .join()
            .map_err(|_| RunnerServiceError::CommandWorkerJoin)?;
        Ok(outcome)
    }
}

fn set_nonblocking(fd: &impl AsFd) -> Result<(), RunnerServiceError> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|error| {
        RunnerServiceError::Protocol(WireProtocolError::Io(io::Error::from(error)))
    })?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|error| {
        RunnerServiceError::Protocol(WireProtocolError::Io(io::Error::from(error)))
    })?;
    Ok(())
}

fn poll_request_fd(fd: &impl AsFd, timeout: Option<Duration>) -> Result<bool, RunnerServiceError> {
    let timeout = timeout.map(|duration| Timespec {
        tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: duration.subsec_nanos().into(),
    });
    loop {
        let mut descriptor = [PollFd::new(
            fd,
            PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
        )];
        match poll(&mut descriptor, timeout.as_ref()) {
            Ok(0) => return Ok(false),
            Ok(_) => {
                let ready = descriptor[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(WireProtocolError::Io(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "runner request descriptor is invalid",
                    ))
                    .into());
                }
                return Ok(ready.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR));
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(WireProtocolError::Io(io::Error::from(error)).into()),
        }
    }
}

/// Serves one immutable runner session on arbitrary framed streams.
///
/// The caller must retain the startup process seal for the full call. Production
/// uses locked standard input/output; generic streams exist for deterministic
/// protocol tests and do not weaken the process entry point.
///
/// # Errors
///
/// Returns a fatal error for malformed framing/contracts, EOF before shutdown,
/// session or role confusion, duplicate identities, reordered initialization,
/// or failed authority/capability acquisition.
pub fn serve_runner_session<R: Read + AsFd, W: Write>(
    process_seal: &RunnerProcessSeal,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), RunnerServiceError> {
    serve_runner_session_on_installed_linux_service(process_seal, reader, writer, None)
}

/// Runs the sealed stdio service used by both shipped runner entry points.
#[must_use]
pub fn run_stdio_runner_process() -> std::process::ExitCode {
    let seal = match crate::seal_stdio_runner_process() {
        Ok(seal) => seal,
        Err(error) => {
            eprintln!("runner startup refused: {error}");
            return std::process::ExitCode::from(78);
        }
    };
    let install_root = match linux_native_service_install_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("runner startup refused: {error}");
            return std::process::ExitCode::from(78);
        }
    };
    let mut stdin = UnbufferedStdin(std::io::stdin());
    let stdout = std::io::stdout();
    match serve_runner_session_on_installed_linux_service(
        &seal,
        &mut stdin,
        &mut stdout.lock(),
        install_root,
    ) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            emit_bounded_diagnostic(&error.to_string());
            std::process::ExitCode::from(78)
        }
    }
}

struct UnbufferedStdin(std::io::Stdin);

impl Read for UnbufferedStdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        rustix::io::read(self.0.as_fd(), buffer).map_err(io::Error::from)
    }
}

impl AsFd for UnbufferedStdin {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

fn linux_native_service_install_root() -> Result<Option<PathBuf>, String> {
    const FLAG: &str = "--linux-native-service-install-root";
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut root = None;
    while let Some(argument) = arguments.next() {
        if argument != std::ffi::OsStr::new(FLAG) {
            return Err(format!(
                "unrecognized runner argument; the ordinary session accepts only {FLAG}"
            ));
        }
        if root.is_some() {
            return Err(format!("{FLAG} was given more than once"));
        }
        let path = PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| format!("{FLAG} requires an absolute path"))?,
        );
        if !path.is_absolute() {
            return Err(format!("{FLAG} requires an absolute path"));
        }
        root = Some(path);
    }
    Ok(root)
}

fn emit_bounded_diagnostic(message: &str) {
    const LIMIT: usize = 1_024;
    let mut diagnostic = message
        .chars()
        .map(|character| {
            if character.is_control() && character != '\t' {
                ' '
            } else {
                character
            }
        })
        .take(LIMIT)
        .collect::<String>();
    if message.chars().count() > LIMIT {
        diagnostic.push('…');
    }
    eprintln!("runner refused: {diagnostic}");
}

/// Serves one session that may compose contained commands onto an **installed**
/// Linux native service.
///
/// `linux_native_service_install_root` names the directory an installer wrote
/// its anchor into. It is a place to look and nothing more: whether a service is
/// actually installed there, whether the anchor is genuine, and whether the path
/// is one this runner is allowed to trust are all decided by re-observation
/// inside `open_installed_linux_native_service_handoff`, which requires every
/// component of the chain to be owned by an identity other than this runner.
///
/// `None` -- the ordinary case -- composes contained commands the in-process
/// way. There is no default and no search: a runner that is not told where the
/// service is does not go looking for one.
///
/// # Errors
///
/// The same fatal errors [`serve_runner_session`] returns.
pub fn serve_runner_session_on_installed_linux_service<R: Read + AsFd, W: Write>(
    _process_seal: &RunnerProcessSeal,
    reader: &mut R,
    writer: &mut W,
    linux_native_service_install_root: Option<std::path::PathBuf>,
) -> Result<(), RunnerServiceError> {
    let runner_nonce = fresh_runner_nonce().map_err(|error| {
        RunnerServiceError::Initialization(format!("cannot acquire OS runner nonce: {error}"))
    })?;
    set_nonblocking(reader)?;
    let mut service = RunnerService::new(runner_nonce);
    service.linux_native_service_install_root = linux_native_service_install_root;
    service.serve_nonblocking(reader, writer, &mut DisabledCommandJobFactory)
}

struct RunnerService {
    /// This runner's own launch preparation, once the desktop has told it.
    ///
    /// Retained on the session rather than per-request because it states who
    /// this runner *is*, which does not change between requests. `None` until a
    /// v15 frame carries one, and a runner that is never told stays `None` and
    /// composes no service -- which is the honest outcome, not a defect.
    retained_launch_preparation: Option<WireRunnerLaunchPreparationV1>,
    /// Where an installer wrote its Linux native-service anchor, when this
    /// runner was told. Never defaulted and never searched for.
    linux_native_service_install_root: Option<std::path::PathBuf>,
    runner_nonce: Digest,
    session: Option<InitializedSession>,
    seen_request_ids: BTreeSet<String>,
    seen_effect_ids: BTreeSet<String>,
    seen_idempotency_keys: BTreeSet<String>,
    expected_sequence: u64,
    command_effects_admitted: u64,
    command_capture_private_state_digest: Option<Digest>,
    command_capture_max_aggregate_output_bytes: Option<u64>,
    command_capture_store: Option<CapabilityCommandOutputStore>,
}

enum CoordinatorTransition {
    Idle,
    Active(Box<ActiveCommandJob>),
    Stop,
}

include!("service/coordination.rs");
enum InitializedSession {
    Worker(Box<WorkerSession>),
    FinalVerifier(Box<FinalVerifierSession>),
    Applier(Box<ApplierSession>),
    LiveStateVerifier(Box<LiveStateVerifierSession>),
    #[cfg(test)]
    Test(Box<TestInitializedSession>),
}

#[cfg(test)]
struct TestInitializedSession {
    role: RunnerRole,
    session_id: String,
    launch_id: String,
    sprint_id: String,
    logical_worker_id: Option<String>,
    worker_lease: Option<WorkerLease>,
    policy_hash: Digest,
    grant_hash: Digest,
    input_snapshot: Digest,
}

#[cfg(test)]
impl TestInitializedSession {
    fn dispatch(
        &self,
        request: &RunnerRequest,
        runner_nonce: &Digest,
        accepted_request_count: u64,
        command_effects_admitted: u64,
    ) -> (RunnerResponse, bool) {
        let acknowledgement = || {
            ShutdownPreparedAcknowledgement::new(
                &self.session_id,
                runner_nonce.clone(),
                self.role,
                accepted_request_count,
                command_effects_admitted,
                self.role == RunnerRole::Worker,
            )
        };
        match request {
            RunnerRequest::WorkerCancel if self.role == RunnerRole::Worker => (
                RunnerResponse::CancellationPrepared {
                    acknowledgement: acknowledgement(),
                },
                true,
            ),
            RunnerRequest::Shutdown => (
                RunnerResponse::ShutdownPrepared {
                    acknowledgement: acknowledgement(),
                },
                true,
            ),
            _ => (
                RunnerResponse::failed_before_effect(
                    "test_session_unexpected_dispatch",
                    "the coordinator fixture received a non-control request",
                ),
                false,
            ),
        }
    }
}

impl InitializedSession {
    fn role(&self) -> RunnerRole {
        match self {
            Self::Worker(_) => RunnerRole::Worker,
            Self::FinalVerifier(_) => RunnerRole::FinalVerifier,
            Self::Applier(_) => RunnerRole::Applier,
            Self::LiveStateVerifier(_) => RunnerRole::LiveStateVerifier,
            #[cfg(test)]
            Self::Test(session) => session.role,
        }
    }

    fn session_id(&self) -> &str {
        match self {
            Self::Worker(worker) => &worker.session_id,
            Self::FinalVerifier(verifier) => &verifier.session_id,
            Self::Applier(applier) => &applier.session_id,
            Self::LiveStateVerifier(verifier) => &verifier.session_id,
            #[cfg(test)]
            Self::Test(session) => &session.session_id,
        }
    }

    fn policy_hash(&self) -> &Digest {
        match self {
            Self::Worker(worker) => &worker.policy.contract().policy_hash,
            Self::FinalVerifier(verifier) => &verifier.policy.contract().policy_hash,
            Self::Applier(applier) => &applier.policy.contract().policy_hash,
            Self::LiveStateVerifier(verifier) => &verifier.policy.contract().policy_hash,
            #[cfg(test)]
            Self::Test(session) => &session.policy_hash,
        }
    }

    fn grant_hash(&self) -> &Digest {
        match self {
            Self::Worker(worker) => &worker.grant.contract().grant_hash,
            Self::FinalVerifier(verifier) => &verifier.grant.contract().grant_hash,
            Self::Applier(applier) => &applier.grant.contract().grant_hash,
            Self::LiveStateVerifier(verifier) => &verifier.grant.contract().grant_hash,
            #[cfg(test)]
            Self::Test(session) => &session.grant_hash,
        }
    }

    fn effect_identity_matches(&self, effect: &WireEffectContext) -> bool {
        match self {
            Self::Worker(worker) => {
                effect.launch_id == worker.launch_id
                    && effect.sprint_id == worker.sprint_spec.sprint_id
                    && effect.worker_id.as_deref() == Some(&worker.logical_worker_id)
                    && effect.task_id.as_deref() == Some(&worker.worker_lease.task_id)
                    && effect.worker_lease.as_ref() == Some(&worker.worker_lease)
            }
            Self::FinalVerifier(verifier) => {
                effect.launch_id == verifier.launch_id
                    && effect.sprint_id == verifier.sprint_spec.sprint_id
                    && effect.worker_id.is_none()
                    && effect.task_id.is_none()
                    && effect.worker_lease.is_none()
            }
            Self::Applier(applier) => {
                effect.launch_id == applier.launch_id
                    && effect.sprint_id == applier.sprint_spec.sprint_id
                    && effect.worker_id.is_none()
                    && effect.task_id.is_none()
                    && effect.worker_lease.is_none()
            }
            Self::LiveStateVerifier(verifier) => {
                effect.launch_id == verifier.launch_id
                    && effect.sprint_id == verifier.sprint_spec.sprint_id
                    && effect.worker_id.is_none()
                    && effect.task_id.is_none()
                    && effect.worker_lease.is_none()
            }
            #[cfg(test)]
            Self::Test(session) => {
                effect.launch_id == session.launch_id
                    && effect.sprint_id == session.sprint_id
                    && effect.worker_id.as_deref() == session.logical_worker_id.as_deref()
                    && effect.task_id.as_deref()
                        == session
                            .worker_lease
                            .as_ref()
                            .map(|lease| lease.task_id.as_str())
                    && effect.worker_lease.as_ref() == session.worker_lease.as_ref()
            }
        }
    }

    fn validate_retained_sprint_authority(&self) -> Result<(), RunnerServiceError> {
        let retained_is_valid = match self {
            Self::Worker(worker) => {
                sprint_spec_digest(&worker.sprint_spec).ok()
                    == Some(worker.sprint_spec_digest.clone())
                    && worker.sprint_spec.workspace_grant == *worker.grant.contract()
                    && worker.sprint_spec.provider.execution_origin == ExecutionOrigin::HostIsolated
                    && worker.policy.contract().resource_limits.wall_time_ms
                        <= worker.sprint_spec.budget.max_duration_ms
                    && worker.role_input_authority == RunnerRoleInputAuthority::IntegrationHead
                    && worker
                        .worker_lease
                        .validate_assignment(
                            &worker.sprint_spec.sprint_id,
                            &worker.worker_lease.task_id,
                            &worker.logical_worker_id,
                        )
                        .is_ok()
            }
            Self::FinalVerifier(verifier) => {
                sprint_spec_digest(&verifier.sprint_spec).ok()
                    == Some(verifier.sprint_spec_digest.clone())
                    && verifier.sprint_spec.workspace_grant == *verifier.grant.contract()
                    && verifier.sprint_spec.provider.execution_origin
                        == ExecutionOrigin::HostIsolated
                    && verifier.policy.contract().resource_limits.wall_time_ms
                        <= verifier.sprint_spec.budget.max_duration_ms
                    && verifier.role_input_authority == RunnerRoleInputAuthority::IntegrationHead
            }
            Self::Applier(applier) => {
                sprint_spec_digest(&applier.sprint_spec).ok()
                    == Some(applier.sprint_spec_digest.clone())
                    && applier.sprint_spec.workspace_grant == *applier.grant.contract()
                    && applier.sprint_spec.provider.execution_origin
                        == ExecutionOrigin::HostIsolated
                    && applier.policy.contract().resource_limits.wall_time_ms
                        <= applier.sprint_spec.budget.max_duration_ms
                    && match &applier.role_input_authority {
                        RunnerRoleInputAuthority::PlanningBase => {
                            applier.sprint_spec.base_snapshot == applier.initialized_input_snapshot
                        }
                        RunnerRoleInputAuthority::PostCompletionAppliedResult {
                            authority,
                            authority_digest,
                        } => {
                            authority.validate().is_ok()
                                && serde_json::to_vec(authority).ok().is_some_and(|canonical| {
                                    Digest::sha256(&canonical) == *authority_digest
                                })
                                && authority.sprint_id == applier.sprint_spec.sprint_id
                                && authority.artifact.base_snapshot
                                    == applier.sprint_spec.base_snapshot
                                && authority.artifact.result_snapshot
                                    == applier.initialized_input_snapshot
                        }
                        RunnerRoleInputAuthority::IntegrationHead
                        | RunnerRoleInputAuthority::LiveStateFinalization { .. } => false,
                    }
            }
            Self::LiveStateVerifier(verifier) => {
                sprint_spec_digest(&verifier.sprint_spec).ok()
                    == Some(verifier.sprint_spec_digest.clone())
                    && verifier.sprint_spec.workspace_grant == *verifier.grant.contract()
                    && verifier.sprint_spec.provider.execution_origin
                        == ExecutionOrigin::HostIsolated
                    && verifier.policy.contract().resource_limits.wall_time_ms
                        <= verifier.sprint_spec.budget.max_duration_ms
                    && match &verifier.role_input_authority {
                        RunnerRoleInputAuthority::LiveStateFinalization { plan, plan_digest } => {
                            validate_live_state_finalization_plan(
                                plan,
                                plan_digest,
                                &verifier.sprint_spec.sprint_id,
                                &verifier.sprint_spec,
                                &verifier.policy.contract().policy_hash,
                                &verifier.expected_snapshot,
                            )
                            .is_ok()
                        }
                        RunnerRoleInputAuthority::PlanningBase
                        | RunnerRoleInputAuthority::IntegrationHead
                        | RunnerRoleInputAuthority::PostCompletionAppliedResult { .. } => false,
                    }
            }
            #[cfg(test)]
            Self::Test(_) => true,
        };
        retained_is_valid
            .then_some(())
            .ok_or(RunnerServiceError::SessionMismatch)
    }

    fn expected_input_snapshot(
        &self,
        request: &RunnerRequest,
    ) -> Result<Option<Digest>, RunnerServiceError> {
        match self {
            Self::Worker(worker) => worker.expected_input_snapshot(request),
            Self::FinalVerifier(verifier) => Ok(verifier.expected_input_snapshot(request)),
            Self::Applier(_) => Ok(ApplierSession::expected_input_snapshot(request)),
            Self::LiveStateVerifier(verifier) => verifier.expected_input_snapshot(request),
            #[cfg(test)]
            Self::Test(session) => Ok(match request {
                RunnerRequest::WorkerRunCommand { .. }
                | RunnerRequest::FinalVerifierRunCommand { .. } => {
                    Some(session.input_snapshot.clone())
                }
                _ => None,
            }),
        }
    }
}

struct WorkerSession {
    session_id: String,
    launch_id: String,
    sprint_spec: SprintSpec,
    sprint_spec_digest: Digest,
    role_input_authority: RunnerRoleInputAuthority,
    logical_worker_id: String,
    worker_lease: WorkerLease,
    expected_base_snapshot: Digest,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    workspace: CapabilityWorkspace,
    shadow_store: CapabilityShadowStore,
    bundle_store: CapabilityStageBundleStore,
    shadow_leaf: String,
    captured_base: Option<WorkspaceManifest>,
    shadow: Option<CapabilityShadowWorkspace>,
    tools: Option<ShadowFileTools>,
    current_shadow_snapshot: Option<Digest>,
}

include!("service/worker.rs");
struct FinalVerifierSession {
    session_id: String,
    launch_id: String,
    sprint_spec: SprintSpec,
    sprint_spec_digest: Digest,
    role_input_authority: RunnerRoleInputAuthority,
    expected_snapshot: Digest,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    verifier: CapabilityVerifierWorkspace,
}

impl FinalVerifierSession {
    fn expected_input_snapshot(&self, request: &RunnerRequest) -> Option<Digest> {
        match request {
            RunnerRequest::FinalVerifierCapture { .. }
            | RunnerRequest::FinalVerifierRunCommand { .. } => Some(self.expected_snapshot.clone()),
            _ => None,
        }
    }

    fn dispatch(
        &mut self,
        request: &RunnerRequest,
        effect_input: Option<&Digest>,
        command_effect_authority: Option<&CommandEffectAuthorityV1>,
        runner_nonce: &Digest,
        accepted_request_count: u64,
        command_effects_admitted: u64,
    ) -> (RunnerResponse, bool) {
        match request {
            RunnerRequest::FinalVerifierCapture { created_at_unix_ms } => {
                match self.verifier.capture(&self.grant, *created_at_unix_ms) {
                    Ok(manifest) => match WireWorkspaceCapture::from_native(&manifest) {
                        Ok(capture) => (RunnerResponse::WorkspaceCaptured { capture }, false),
                        Err(error) => (wire_failure(error), false),
                    },
                    Err(error) => (workspace_failure(error), false),
                }
            }
            RunnerRequest::FinalVerifierRunCommand { .. } => (
                if !command_effect_authority
                    .as_ref()
                    .is_some_and(|authority| authority.role() == RunnerRole::FinalVerifier)
                {
                    RunnerResponse::failed_before_effect(
                        "command_effect_authority_missing",
                        "the complete role-exact command-effect authority was not retained",
                    )
                } else if effect_input == Some(&self.expected_snapshot) {
                    RunnerResponse::failed_before_effect(
                        "verification_containment_unavailable",
                        "repository verification remains fail-closed until the platform backend proves a read-only mount of the exact verifier snapshot and concurrent cancellation",
                    )
                } else {
                    RunnerResponse::failed_before_effect(
                        "verifier_snapshot_mismatch",
                        "final-verifier effect input differs from initialized snapshot",
                    )
                },
                false,
            ),
            RunnerRequest::Shutdown => {
                let acknowledgement = ShutdownPreparedAcknowledgement::new(
                    &self.session_id,
                    runner_nonce.clone(),
                    RunnerRole::FinalVerifier,
                    accepted_request_count,
                    command_effects_admitted,
                    true,
                );
                (RunnerResponse::ShutdownPrepared { acknowledgement }, true)
            }
            _ => (
                RunnerResponse::failed_before_effect(
                    "runner_role_confusion",
                    "request does not belong to the immutable final-verifier role",
                ),
                false,
            ),
        }
    }
}

struct LiveStateVerifierSession {
    session_id: String,
    launch_id: String,
    sprint_spec: SprintSpec,
    sprint_spec_digest: Digest,
    role_input_authority: RunnerRoleInputAuthority,
    expected_snapshot: Digest,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    workspace: CapabilityWorkspace,
}

impl LiveStateVerifierSession {
    fn expected_input_snapshot(
        &self,
        request: &RunnerRequest,
    ) -> Result<Option<Digest>, RunnerServiceError> {
        match request {
            RunnerRequest::LiveStateVerifierCapture { request } => {
                let RunnerRoleInputAuthority::LiveStateFinalization { plan, plan_digest } =
                    &self.role_input_authority
                else {
                    return Err(RunnerServiceError::SessionMismatch);
                };
                let request_plan_digest = request
                    .plan
                    .plan_digest()
                    .map_err(|_| RunnerServiceError::EffectContextMismatch)?;
                if request.plan != **plan || request_plan_digest != *plan_digest {
                    return Err(RunnerServiceError::EffectContextMismatch);
                }
                Ok(Some(self.expected_snapshot.clone()))
            }
            RunnerRequest::Shutdown => Ok(None),
            RunnerRequest::InitializeSession { .. }
            | RunnerRequest::WorkerCaptureLive { .. }
            | RunnerRequest::WorkerCreateShadow { .. }
            | RunnerRequest::WorkerReadFile { .. }
            | RunnerRequest::WorkerSearchLiteral { .. }
            | RunnerRequest::WorkerCreateFile { .. }
            | RunnerRequest::WorkerReplaceFile { .. }
            | RunnerRequest::WorkerDeleteFile { .. }
            | RunnerRequest::WorkerReconcileFile { .. }
            | RunnerRequest::WorkerPrepareStage { .. }
            | RunnerRequest::WorkerStageChanges { .. }
            | RunnerRequest::WorkerReconcileStage { .. }
            | RunnerRequest::WorkerRunCommand { .. }
            | RunnerRequest::WorkerCancel
            | RunnerRequest::FinalVerifierCapture { .. }
            | RunnerRequest::FinalVerifierRunCommand { .. }
            | RunnerRequest::ApplierRecoverPending
            | RunnerRequest::ApplierReconcileStageBundle { .. }
            | RunnerRequest::ApplierApplyBundle { .. }
            | RunnerRequest::ApplierReconcile { .. }
            | RunnerRequest::ApplierRollback { .. }
            | RunnerRequest::ApplierCaptureLive { .. } => Err(RunnerServiceError::RoleConfusion),
        }
    }

    fn dispatch(
        &mut self,
        request: RunnerRequest,
        runner_nonce: &Digest,
        accepted_request_count: u64,
        command_effects_admitted: u64,
    ) -> (RunnerResponse, bool) {
        match request {
            RunnerRequest::LiveStateVerifierCapture { request } => {
                if let Err(error) = self.workspace.validate_capture_authority(&self.grant) {
                    return (workspace_failure(error), false);
                }
                let capture_started_at_unix_ms = match observed_at_unix_ms() {
                    Ok(timestamp) if timestamp >= request.plan.planned_at_unix_ms => timestamp,
                    Ok(_) => {
                        return (
                            RunnerResponse::failed_before_effect(
                                "capture_time_precedes_plan",
                                "runner capture time precedes the retained live-state finalization plan",
                            ),
                            false,
                        );
                    }
                    Err(error) => return (workspace_failure(error), false),
                };
                match self
                    .workspace
                    .capture_after_authority_validation(&self.grant, capture_started_at_unix_ms)
                {
                    Ok(manifest) => {
                        let captured_at_unix_ms = match observed_at_unix_ms() {
                            Ok(timestamp)
                                if timestamp >= capture_started_at_unix_ms
                                    && timestamp >= request.plan.planned_at_unix_ms =>
                            {
                                timestamp
                            }
                            Ok(_) => {
                                return (
                                    RunnerResponse::failed_after_known_effect(
                                        "capture_completion_time_invalid",
                                        "runner completion time moved behind the completed descriptor capture or retained plan",
                                    ),
                                    false,
                                );
                            }
                            Err(error) => {
                                return (
                                    RunnerResponse::failed_after_known_effect(
                                        "capture_completion_time_unavailable",
                                        error,
                                    ),
                                    false,
                                );
                            }
                        };
                        match RunnerResponse::live_workspace_captured(
                            &manifest,
                            capture_started_at_unix_ms,
                            captured_at_unix_ms,
                        ) {
                            Ok(response) => (response, false),
                            Err(error) => (
                                RunnerResponse::failed_after_known_effect(
                                    "live_workspace_evidence_unavailable",
                                    error,
                                ),
                                false,
                            ),
                        }
                    }
                    Err(error) => (live_state_capture_failure(error), false),
                }
            }
            RunnerRequest::Shutdown => {
                let acknowledgement = ShutdownPreparedAcknowledgement::new(
                    &self.session_id,
                    runner_nonce.clone(),
                    RunnerRole::LiveStateVerifier,
                    accepted_request_count,
                    command_effects_admitted,
                    false,
                );
                (RunnerResponse::ShutdownPrepared { acknowledgement }, true)
            }
            _ => (
                RunnerResponse::failed_before_effect(
                    "runner_role_confusion",
                    "request does not belong to the immutable live-state-verifier role",
                ),
                false,
            ),
        }
    }
}

struct ApplierSession {
    session_id: String,
    launch_id: String,
    sprint_spec: SprintSpec,
    sprint_spec_digest: Digest,
    role_input_authority: RunnerRoleInputAuthority,
    initialized_input_snapshot: Digest,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    workspace: CapabilityWorkspace,
    bundle_store: CapabilityStageBundleStore,
    applier: CapabilitySafeApplier,
    recovery_complete: bool,
}

impl ApplierSession {
    fn expected_input_snapshot(request: &RunnerRequest) -> Option<Digest> {
        match request {
            RunnerRequest::ApplierApplyBundle { bundle } => Some(bundle.base_snapshot.clone()),
            RunnerRequest::ApplierRollback { bundle, .. } => Some(bundle.result_snapshot.clone()),
            _ => None,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "closed applier dispatch keeps recovery gating and every effect classification auditable"
    )]
    fn dispatch(
        &mut self,
        request: RunnerRequest,
        runner_nonce: &Digest,
        accepted_request_count: u64,
        command_effects_admitted: u64,
    ) -> (RunnerResponse, bool) {
        if !self.recovery_complete
            && !matches!(
                request,
                RunnerRequest::ApplierRecoverPending | RunnerRequest::Shutdown
            )
        {
            return (
                RunnerResponse::failed_before_effect(
                    "applier_recovery_required",
                    "recover pending application state before every other applier operation",
                ),
                false,
            );
        }
        match request {
            RunnerRequest::ApplierRecoverPending => {
                if self.recovery_complete {
                    return (
                        RunnerResponse::failed_before_effect(
                            "applier_recovery_already_completed",
                            "startup recovery is admitted exactly once after success",
                        ),
                        false,
                    );
                }
                match self.applier.recover_pending(&self.grant) {
                    Ok(result) => match RunnerResponse::recovery(&result) {
                        Ok(response) => {
                            self.recovery_complete = true;
                            (response, false)
                        }
                        Err(error) => (
                            RunnerResponse::failed_requiring_reconciliation(
                                "recovery_evidence_requires_reconciliation",
                                WireReconciliationReference::ApplicationRecovery,
                                error,
                            ),
                            false,
                        ),
                    },
                    Err(error) => (
                        RunnerResponse::failed_requiring_reconciliation(
                            "application_recovery_requires_reconciliation",
                            WireReconciliationReference::ApplicationRecovery,
                            error,
                        ),
                        false,
                    ),
                }
            }
            RunnerRequest::ApplierReconcileStageBundle { expected_bundle } => {
                match self.bundle_store.reconcile(&expected_bundle) {
                    Ok(bundle) if bundle == expected_bundle => {
                        (RunnerResponse::StageBundleReconciled { bundle }, false)
                    }
                    Ok(_) => (
                        RunnerResponse::failed_before_effect(
                            "stage_reconciliation_mismatch",
                            "read-only applier stage reconciliation returned a different bundle reference",
                        ),
                        false,
                    ),
                    Err(error) => (stage_failure(error), false),
                }
            }
            RunnerRequest::ApplierApplyBundle { bundle } => {
                let staged = match self.load_bundle(&bundle) {
                    Ok(staged) => staged,
                    Err(response) => return (response, false),
                };
                match self.applier.apply(&self.grant, &staged) {
                    Ok(outcome) => (self.committed_response(&bundle, &staged, &outcome), false),
                    Err(error) => (apply_failure(error, Some(&bundle)), false),
                }
            }
            RunnerRequest::ApplierReconcile { bundle } => {
                let staged = match self.load_bundle(&bundle) {
                    Ok(staged) => staged,
                    Err(response) => return (response, false),
                };
                match self.applier.reconcile(&self.grant, &bundle.change_set_id) {
                    Ok(CapabilityApplyReconciliation::Committed(outcome)) => {
                        (self.committed_response(&bundle, &staged, &outcome), false)
                    }
                    Ok(CapabilityApplyReconciliation::TargetsRestored(outcome)) => (
                        self.restored_response(&bundle, &staged, &outcome, false),
                        false,
                    ),
                    Err(error) => (apply_failure(error, Some(&bundle)), false),
                }
            }
            RunnerRequest::ApplierRollback { bundle, rollback } => {
                let staged = match self.load_bundle(&bundle) {
                    Ok(staged) => staged,
                    Err(response) => return (response, false),
                };
                if let Err(error) = rollback.validate_for_change_set(staged.change_set()) {
                    return (wire_failure(error), false);
                }
                let reopened = match self
                    .applier
                    .reopen_rollback_artifacts(&self.grant, &bundle.change_set_id)
                {
                    Ok(reopened) => reopened,
                    Err(error) => return (apply_failure(error, Some(&bundle)), false),
                };
                let reopened_wire = match WireRollbackArtifactReference::from_native(&reopened) {
                    Ok(reference) => reference,
                    Err(error) => return (wire_failure(error), false),
                };
                if reopened_wire != rollback {
                    return (
                        RunnerResponse::failed_before_effect(
                            "rollback_reference_mismatch",
                            "supplied rollback-artifact reference differs from exact reopened journal evidence",
                        ),
                        false,
                    );
                }
                if let Err(error) = self
                    .applier
                    .validate_rollback_artifacts(&self.grant, &reopened)
                {
                    return (apply_failure(error, Some(&bundle)), false);
                }
                match self
                    .applier
                    .rollback_with_evidence(&self.grant, &bundle, &reopened)
                {
                    Ok(CapabilityRollbackAttempt::Completed(evidence)) => {
                        let response = match WireExplicitRollbackEvidence::from_native(
                            &evidence,
                            staged.change_set(),
                        ) {
                            Ok(evidence) => {
                                RunnerResponse::RollbackCompletedWithEvidence { evidence }
                            }
                            Err(error) => {
                                return (post_effect_evidence_failure(&bundle, error), false);
                            }
                        };
                        (bounded_post_effect_response(&bundle, response), false)
                    }
                    Ok(CapabilityRollbackAttempt::LiveConflict(conflict)) => {
                        let response = match WireRollbackLiveConflict::from_native(
                            &conflict,
                            staged.change_set(),
                        ) {
                            Ok(conflict) => RunnerResponse::RollbackLiveConflict { conflict },
                            Err(error) => return (wire_failure(error), false),
                        };
                        (response, false)
                    }
                    Err(error) => (apply_failure(error, Some(&bundle)), false),
                }
            }
            RunnerRequest::ApplierCaptureLive { created_at_unix_ms } => {
                match self.workspace.capture(&self.grant, created_at_unix_ms) {
                    Ok(manifest) => match WireWorkspaceCapture::from_native(&manifest) {
                        Ok(capture) => (RunnerResponse::WorkspaceCaptured { capture }, false),
                        Err(error) => (wire_failure(error), false),
                    },
                    Err(error) => (workspace_failure(error), false),
                }
            }
            RunnerRequest::Shutdown => {
                let acknowledgement = ShutdownPreparedAcknowledgement::new(
                    &self.session_id,
                    runner_nonce.clone(),
                    RunnerRole::Applier,
                    accepted_request_count,
                    command_effects_admitted,
                    false,
                );
                (RunnerResponse::ShutdownPrepared { acknowledgement }, true)
            }
            _ => (
                RunnerResponse::failed_before_effect(
                    "runner_role_confusion",
                    "request does not belong to the immutable applier role",
                ),
                false,
            ),
        }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the local helper returns the already-typed protocol refusal without boxing the public response schema"
    )]
    fn load_bundle(
        &self,
        bundle: &StageBundleReference,
    ) -> Result<StagedChangeSet, RunnerResponse> {
        let staged = self.bundle_store.load(bundle).map_err(stage_failure)?;
        validate_bundle_change_set(bundle, staged.change_set()).map_err(wire_failure)?;
        Ok(staged)
    }

    fn committed_response(
        &self,
        bundle: &StageBundleReference,
        staged: &StagedChangeSet,
        outcome: &CapabilityApplyOutcome,
    ) -> RunnerResponse {
        let rollback = match self
            .applier
            .reopen_rollback_artifacts(&self.grant, &bundle.change_set_id)
        {
            Ok(reference) => reference,
            Err(error) => return post_effect_evidence_failure(bundle, error),
        };
        if let Err(error) = self
            .applier
            .validate_rollback_artifacts(&self.grant, &rollback)
        {
            return post_effect_evidence_failure(bundle, error);
        }
        let live_manifest = match self.capture_live() {
            Ok(manifest) => manifest,
            Err(error) => return post_effect_evidence_failure(bundle, error),
        };
        let evidence = match WireApplicationEvidence::from_native(
            bundle,
            staged.change_set(),
            outcome,
            &rollback,
            &live_manifest,
        ) {
            Ok(evidence) => evidence,
            Err(error) => return post_effect_evidence_failure(bundle, error),
        };
        bounded_post_effect_response(bundle, RunnerResponse::ApplicationApplied { evidence })
    }

    fn restored_response(
        &self,
        bundle: &StageBundleReference,
        staged: &StagedChangeSet,
        outcome: &CapabilityRollbackOutcome,
        explicit_rollback: bool,
    ) -> RunnerResponse {
        let live_manifest = match self.capture_live() {
            Ok(manifest) => manifest,
            Err(error) => return post_effect_evidence_failure(bundle, error),
        };
        let evidence = match WireRollbackEvidence::from_native(
            bundle,
            staged.change_set(),
            outcome,
            &live_manifest,
        ) {
            Ok(evidence) => evidence,
            Err(error) => return post_effect_evidence_failure(bundle, error),
        };
        let response = if explicit_rollback {
            RunnerResponse::RollbackCompleted { evidence }
        } else {
            RunnerResponse::TargetsRestored { evidence }
        };
        bounded_post_effect_response(bundle, response)
    }

    fn capture_live(&self) -> Result<WorkspaceManifest, CapabilityWorkspaceError> {
        let timestamp = observed_at_unix_ms()?;
        self.workspace.capture(&self.grant, timestamp)
    }
}

fn validate_role_policy(role: RunnerRole, policy: &CompiledExecutionPolicy) -> Result<(), String> {
    match role {
        RunnerRole::Worker => {
            if policy.contract().mutation_mode != MutationMode::ShadowWorkspace {
                return Err("worker role requires shadow-workspace mutation mode".into());
            }
        }
        RunnerRole::FinalVerifier | RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
            if policy.contract().mutation_mode != MutationMode::ReadOnly
                || !policy.contract().write_scopes.is_empty()
                || policy.contract().network != ExecutionNetwork::None
            {
                return Err(
                    "final-verifier, applier, and live-state-verifier roles require a read-only, no-write, no-network execution policy"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

fn exact_private_state_root(text: &str, grant: &IssuedWorkspaceGrant) -> Result<PathBuf, String> {
    let requested = PathBuf::from(text);
    let canonical = fs::canonicalize(&requested)
        .map_err(|error| format!("cannot canonicalize private-state root: {error}"))?;
    if canonical != requested {
        return Err("private-state root must use its exact canonical path".into());
    }
    let live = &grant.contract().canonical_root;
    if canonical.starts_with(live) || live.starts_with(&canonical) {
        return Err("private-state root and trusted workspace must be disjoint".into());
    }
    Ok(canonical)
}

fn fixed_shadow_leaf(private_root: &Path, shadow_text: &str) -> Result<String, String> {
    let leaf = validated_shadow_leaf(private_root, shadow_text)?;
    let shadow = private_root.join(&leaf);
    match fs::symlink_metadata(&shadow) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect fixed shadow destination: {error}")),
        Ok(_) => return Err("fixed shadow destination must not already exist".into()),
    }
    Ok(leaf)
}

fn fixed_existing_shadow_leaf(private_root: &Path, shadow_text: &str) -> Result<String, String> {
    let leaf = validated_shadow_leaf(private_root, shadow_text)?;
    let metadata = fs::symlink_metadata(private_root.join(&leaf))
        .map_err(|error| format!("cannot inspect verifier shadow: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("verifier shadow must be one existing real directory".into());
    }
    Ok(leaf)
}

fn validated_shadow_leaf(private_root: &Path, shadow_text: &str) -> Result<String, String> {
    let shadow = PathBuf::from(shadow_text);
    let leaf = shadow
        .file_name()
        .and_then(|leaf| leaf.to_str())
        .ok_or_else(|| "fixed shadow root must have a UTF-8 leaf".to_string())?;
    if shadow.parent() != Some(private_root)
        || private_root.join(leaf) != shadow
        || leaf.is_empty()
        || leaf.len() > 256
        || leaf.eq_ignore_ascii_case(".git")
        || leaf == APPLICATION_JOURNAL_CHILD
        || leaf.starts_with("stage-")
        || leaf.starts_with(".stage-tmp-")
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("fixed shadow root must be one safe child of private_state_root".into());
    }
    Ok(leaf.into())
}

/// Computes the launcher's stable digest for every named directory edge from
/// the filesystem root through the exact private-state root.
///
/// # Errors
///
/// Returns an error when the path is non-canonical, contains a link/non-directory,
/// changes between independent observations, or cannot be inspected.
pub fn inspect_private_state_digest(path: impl AsRef<Path>) -> Result<Digest, io::Error> {
    let path = path.as_ref();
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private-state path must be exact and canonical",
        ));
    }
    let first = private_state_digest_once(path)?;
    let second = private_state_digest_once(path)?;
    if first != second {
        return Err(io::Error::other(
            "private-state path chain changed during inspection",
        ));
    }
    Ok(first)
}

fn private_state_digest_once(path: &Path) -> Result<Digest, io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(PRIVATE_STATE_DIGEST_DOMAIN);
        let encoded_path = path.as_os_str().as_encoded_bytes();
        preimage.extend_from_slice(
            &u64::try_from(encoded_path.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        preimage.extend_from_slice(encoded_path);
        let mut current = PathBuf::from("/");
        let components = path.components().filter_map(|component| {
            if let std::path::Component::Normal(name) = component {
                Some(name)
            } else {
                None
            }
        });
        for component in components {
            current.push(component);
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private-state path chain must contain only real directories",
                ));
            }
            let name = component.as_encoded_bytes();
            preimage
                .extend_from_slice(&u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
            preimage.extend_from_slice(name);
            preimage.extend_from_slice(&metadata.dev().to_be_bytes());
            preimage.extend_from_slice(&metadata.ino().to_be_bytes());
            preimage.extend_from_slice(&metadata.uid().to_be_bytes());
            preimage.extend_from_slice(&metadata.mode().to_be_bytes());
        }
        Ok(Digest::sha256(&preimage))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private-state identity requires Unix metadata",
        ))
    }
}

/// Hashes a stable, real runner executable and returns its exact Unix identity.
///
/// The launcher calls this on the named source before spawn. Linux production
/// subsequently binds initialization to a distinct, immutable executable
/// memfd identity opened through authenticated `/proc/self/exe`; other Unix
/// targets repeat named-file inspection on `current_exe`. Initialization
/// requires the executing bytes and identity to match the launcher evidence.
///
/// # Errors
///
/// Returns an error for a non-canonical path, link/non-file, identity drift,
/// concurrent content/metadata mutation, or I/O failure.
pub fn inspect_runner_binary(
    path: impl AsRef<Path>,
) -> Result<(Digest, WireBinaryIdentity), io::Error> {
    let path = path.as_ref();
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runner binary path must be exact and canonical",
        ));
    }
    inspect_runner_binary_once(path)
}

#[cfg(not(target_os = "linux"))]
fn inspect_current_runner_binary() -> Result<(Digest, WireBinaryIdentity), io::Error> {
    let path = std::env::current_exe()?;
    inspect_runner_binary(&path)
}

#[cfg(target_os = "linux")]
fn inspect_current_runner_binary() -> Result<(Digest, WireBinaryIdentity), io::Error> {
    let proc_self = Path::new("/proc/self");
    let proc_executable = Path::new("/proc/self/exe");
    let filesystem = rustix::fs::statfs(proc_self).map_err(io::Error::from)?;
    if filesystem.f_type != rustix::fs::PROC_SUPER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "/proc/self is not backed by genuine procfs",
        ));
    }
    if !fs::symlink_metadata(proc_executable)?
        .file_type()
        .is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "/proc/self/exe is not a procfs executable magic link",
        ));
    }

    let proc_target = fs::read_link(proc_executable)?;
    let target_before = fs::metadata(proc_executable)?;
    let descriptor = rustix::fs::open(
        proc_executable,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut file = fs::File::from(descriptor);
    let descriptor_before = file.metadata()?;
    if !same_binary_metadata(&target_before, &descriptor_before) {
        return Err(io::Error::other(
            "procfs runner executable changed while its descriptor was acquired",
        ));
    }
    validate_executing_binary_admission(&file, &descriptor_before, &proc_target)?;
    let identity = binary_identity(&descriptor_before);
    let digest = digest_binary_descriptor(&mut file)?;
    let descriptor_after = file.metadata()?;
    let proc_target_after = fs::read_link(proc_executable)?;
    let target_after = fs::metadata(proc_executable)?;
    validate_executing_binary_admission(&file, &descriptor_after, &proc_target_after)?;
    if !same_binary_metadata(&descriptor_before, &descriptor_after)
        || !same_binary_metadata(&descriptor_after, &target_after)
        || proc_target != proc_target_after
    {
        return Err(io::Error::other(
            "procfs runner executable changed while its bytes were hashed",
        ));
    }
    Ok((digest, identity))
}

#[cfg(target_os = "linux")]
fn required_executable_memfd_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::FUTURE_WRITE
        | rustix::fs::SealFlags::EXEC
}

#[cfg(target_os = "linux")]
fn validate_executing_binary_admission(
    file: &fs::File,
    metadata: &fs::Metadata,
    proc_target: &Path,
) -> Result<(), io::Error> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.nlink() != 0 {
        return validate_binary_admission(metadata);
    }
    if proc_target != Path::new(SEALED_RUNNER_MEMFD_TARGET)
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.len() == 0
        || metadata.len() > MAX_RUNNER_BINARY_BYTES
        || metadata.mode() & 0o7_777 != 0o500
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "anonymous runner executable is not the exact admitted owner-only executable memfd",
        ));
    }
    let seals = rustix::fs::fcntl_get_seals(file).map_err(io::Error::from)?;
    if seals != required_executable_memfd_seals() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "anonymous runner executable does not have the exact immutable memfd seal set",
        ));
    }
    Ok(())
}

fn inspect_runner_binary_once(path: &Path) -> Result<(Digest, WireBinaryIdentity), io::Error> {
    #[cfg(unix)]
    {
        let named_before = fs::symlink_metadata(path)?;
        if named_before.file_type().is_symlink() || !named_before.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runner binary must be one real regular file",
            ));
        }
        validate_binary_admission(&named_before)?;
        let mut file = fs::File::open(path)?;
        let descriptor_before = file.metadata()?;
        if !same_binary_metadata(&named_before, &descriptor_before) {
            return Err(io::Error::other(
                "runner binary changed while its descriptor was acquired",
            ));
        }
        let identity = binary_identity(&descriptor_before);
        let digest = digest_binary_descriptor(&mut file)?;
        let descriptor_after = file.metadata()?;
        let named_after = fs::symlink_metadata(path)?;
        if !same_binary_metadata(&descriptor_before, &descriptor_after)
            || !same_binary_metadata(&descriptor_after, &named_after)
        {
            return Err(io::Error::other(
                "runner binary changed while its bytes were hashed",
            ));
        }
        Ok((digest, identity))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "runner binary identity requires Unix metadata",
        ))
    }
}

#[cfg(unix)]
fn binary_identity(metadata: &fs::Metadata) -> WireBinaryIdentity {
    use std::os::unix::fs::MetadataExt as _;

    WireBinaryIdentity {
        device_id: metadata.dev(),
        inode: metadata.ino(),
        byte_length: metadata.len(),
        mode: metadata.mode(),
        owner_uid: metadata.uid(),
        link_count: metadata.nlink(),
    }
}

#[cfg(unix)]
fn digest_binary_descriptor(file: &mut fs::File) -> Result<Digest, io::Error> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let bytes = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    Digest::parse(text).map_err(io::Error::other)
}

#[cfg(unix)]
fn validate_binary_admission(metadata: &fs::Metadata) -> Result<(), io::Error> {
    use std::os::unix::fs::MetadataExt as _;

    let mode = metadata.mode();
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_RUNNER_BINARY_BYTES
        || mode & 0o7_000 != 0
        || mode & 0o022 != 0
        || mode & 0o100 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runner binary must be bounded, nonempty, singly linked, owned by the execution user, owner-executable, non-setid, and not group/world writable",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn same_binary_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn fresh_runner_nonce() -> Result<Digest, io::Error> {
    let mut source = fs::File::open("/dev/urandom")?;
    let mut bytes = [0_u8; 32];
    source.read_exact(&mut bytes)?;
    let mut text = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    Digest::parse(text).map_err(io::Error::other)
}

fn observed_at_unix_ms() -> Result<u64, CapabilityWorkspaceError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            CapabilityWorkspaceError::Contract(format!("system clock predates Unix epoch: {error}"))
        })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        CapabilityWorkspaceError::Contract("system clock exceeds u64 milliseconds".into())
    })
}

fn response_envelope(
    session_id: &str,
    runner_nonce: &Digest,
    sequence: u64,
    request_id: &str,
    effect: Option<WireEffectContext>,
    response: RunnerResponse,
) -> RunnerResponseEnvelope {
    RunnerResponseEnvelope {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
        session_id: session_id.into(),
        runner_nonce: runner_nonce.clone(),
        sequence,
        request_id: request_id.into(),
        effect,
        response,
    }
}

fn response_envelope_v12(
    request: &RunnerRequestEnvelopeV12,
    response: RunnerResponseV12,
) -> RunnerResponseEnvelopeV12 {
    RunnerResponseEnvelopeV12 {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
        session_id: request.session_id.clone(),
        runner_nonce: request.runner_nonce.clone(),
        sequence: request.sequence,
        request_id: request.request_id.clone(),
        effect: request.effect.clone(),
        response,
    }
}

fn write_response_v12<W: Write>(
    writer: &mut W,
    response: &RunnerResponseEnvelopeV12,
) -> Result<(), RunnerServiceError> {
    let frame = encode_response_frame_v12(response)?;
    writer.write_all(&frame).map_err(WireProtocolError::Io)?;
    writer.flush().map_err(WireProtocolError::Io)?;
    Ok(())
}

fn shadow_required() -> RunnerResponse {
    RunnerResponse::failed_before_effect(
        "shadow_required",
        "create the fixed private shadow before using worker file operations",
    )
}

fn file_failure(error: FileToolError) -> RunnerResponse {
    if let FileToolError::EffectAppliedButUnverified { path, .. } = &error {
        let reconciliation = path.to_str().map_or_else(
            || WireReconciliationReference::SessionPrivateState {
                state_id: "worker-shadow".into(),
            },
            |path| WireReconciliationReference::File { path: path.into() },
        );
        return RunnerResponse::failed_requiring_reconciliation(
            "file_operation_rejected",
            reconciliation,
            error,
        );
    }
    RunnerResponse::failed_before_effect("file_operation_rejected", error)
}

fn workspace_failure(error: CapabilityWorkspaceError) -> RunnerResponse {
    RunnerResponse::failed_before_effect("workspace_operation_rejected", error)
}

fn live_state_capture_failure(error: CapabilityWorkspaceError) -> RunnerResponse {
    RunnerResponse::failed_after_known_effect("live_workspace_capture_incomplete", error)
}

fn stage_failure(error: StageBundleError) -> RunnerResponse {
    if let StageBundleError::ReconciliationRequired { reference, .. } = &error {
        return RunnerResponse::failed_requiring_reconciliation(
            "stage_bundle_rejected",
            WireReconciliationReference::StageBundle {
                bundle: reference.as_ref().clone(),
            },
            &error,
        );
    }
    RunnerResponse::failed_before_effect("stage_bundle_rejected", error)
}

fn apply_failure(
    error: CapabilityApplyError,
    fallback_bundle: Option<&StageBundleReference>,
) -> RunnerResponse {
    let reference = match &error {
        CapabilityApplyError::ReconciliationRequired { change_set_id, .. } => fallback_bundle
            .filter(|bundle| bundle.change_set_id == *change_set_id)
            .map(|bundle| WireReconciliationReference::Application {
                bundle: bundle.clone(),
            })
            .or(Some(WireReconciliationReference::ApplicationRecovery)),
        CapabilityApplyError::InjectedCrash { .. } => Some(fallback_bundle.map_or(
            WireReconciliationReference::ApplicationRecovery,
            |bundle| WireReconciliationReference::Application {
                bundle: bundle.clone(),
            },
        )),
        CapabilityApplyError::PreparationCleanupRequired { .. }
        | CapabilityApplyError::InjectedPreparationCrash { .. } => {
            Some(WireReconciliationReference::ApplicationRecovery)
        }
        _ => None,
    };
    if let Some(reference) = reference {
        RunnerResponse::failed_requiring_reconciliation(
            "application_operation_rejected",
            reference,
            error,
        )
    } else {
        RunnerResponse::failed_before_effect("application_operation_rejected", error)
    }
}

fn post_effect_evidence_failure(
    bundle: &StageBundleReference,
    error: impl Display,
) -> RunnerResponse {
    RunnerResponse::failed_requiring_reconciliation(
        "application_evidence_requires_reconciliation",
        WireReconciliationReference::Application {
            bundle: bundle.clone(),
        },
        error,
    )
}

fn bounded_post_effect_response(
    bundle: &StageBundleReference,
    response: RunnerResponse,
) -> RunnerResponse {
    const ENVELOPE_RESERVE_BYTES: usize = 64 * 1024;

    match serde_json::to_vec(&response) {
        Ok(encoded)
            if encoded.len() <= MAX_WIRE_FRAME_BYTES.saturating_sub(ENVELOPE_RESERVE_BYTES) =>
        {
            response
        }
        Ok(_) => post_effect_evidence_failure(
            bundle,
            "application evidence exceeds the bounded runner response frame",
        ),
        Err(error) => post_effect_evidence_failure(bundle, error),
    }
}

fn wire_failure(error: WireProtocolError) -> RunnerResponse {
    RunnerResponse::failed_before_effect("response_contract_rejected", error)
}

include!("service/contained_jobs.rs");
#[cfg(test)]
mod tests;
