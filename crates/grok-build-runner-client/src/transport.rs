//! Framed runner transport, process I/O, deadlines, and teardown.

use super::*;

#[doc(hidden)]
pub trait RunnerTransport {
    /// Validates response-stream availability before a durable effect claim is
    /// created. Ordinary controls do not use this effect-only precheck.
    fn precheck_effect_exchange(&self) -> Result<(), RunnerClientError> {
        Ok(())
    }

    fn exchange_frame(
        &mut self,
        outbound: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, RunnerTransportExchangeFailure>;

    fn finish_direct(self: Box<Self>) -> DirectChildOutcome;

    /// Service-authenticated operating-system identity for an ordinary held
    /// launch. Operation-local transports and unreleased processes return
    /// `None`.
    fn native_process_identity_digest(&self) -> Option<&Digest> {
        None
    }

    /// Drained runner stderr. Empty for scripted transports.
    fn stderr_diagnostics(&self) -> &[u8] {
        b""
    }

    /// Operating-system pid of a live runner child. Scripted transports: none.
    fn os_pid(&self) -> Option<u32> {
        None
    }

    fn exchange(
        &mut self,
        request: &RunnerRequestEnvelope,
    ) -> Result<RunnerResponseEnvelope, RunnerClientError> {
        let outbound = encode_request_frame(request)?;
        self.exchange_encoded_frame(&outbound)
    }

    /// Exchanges one already validated canonical request frame without
    /// re-encoding it after a durable dispatch claim has authenticated those
    /// exact bytes.
    fn exchange_encoded_frame(
        &mut self,
        outbound: &[u8],
    ) -> Result<RunnerResponseEnvelope, RunnerClientError> {
        self.exchange_encoded_frame_with_progress(outbound)
            .map(|exchange| exchange.response)
            .map_err(|failure| failure.error)
    }

    /// Exchanges claimed bytes while retaining exact successful-write
    /// progress and the exact inbound frame digest for failure evidence.
    fn exchange_encoded_frame_with_progress(
        &mut self,
        outbound: &[u8],
    ) -> Result<RunnerTransportResponse, RunnerTransportExchangeFailure> {
        self.exchange_encoded_frame_with_deadline(
            outbound,
            Instant::now() + RUNNER_EXCHANGE_DEADLINE,
        )
    }

    fn exchange_encoded_frame_with_deadline(
        &mut self,
        outbound: &[u8],
        deadline: Instant,
    ) -> Result<RunnerTransportResponse, RunnerTransportExchangeFailure> {
        let inbound = self.exchange_frame(outbound, deadline)?;
        let response_frame_digest = Digest::sha256(&inbound);
        let response = decode_response_frame(&inbound).map_err(|error| {
            RunnerTransportExchangeFailure::completed(error.into(), outbound.len())
        })?;
        Ok(RunnerTransportResponse {
            response,
            response_frame_digest,
        })
    }

    /// Exchanges one already claim-authenticated additive-v12 command frame.
    /// The frozen v11 decoder is never attempted as a fallback.
    fn exchange_encoded_command_frame_with_progress(
        &mut self,
        outbound: &[u8],
    ) -> Result<RunnerCommandTransportResponse, RunnerTransportExchangeFailure> {
        self.exchange_encoded_command_frame_with_deadline(
            outbound,
            Instant::now() + RUNNER_EXCHANGE_DEADLINE,
        )
    }

    fn exchange_encoded_command_frame_with_deadline(
        &mut self,
        outbound: &[u8],
        deadline: Instant,
    ) -> Result<RunnerCommandTransportResponse, RunnerTransportExchangeFailure> {
        let inbound = self.exchange_frame(outbound, deadline)?;
        let response_frame_digest = Digest::sha256(&inbound);
        let response = decode_response_frame_v12(&inbound).map_err(|error| {
            RunnerTransportExchangeFailure::completed(error.into(), outbound.len())
        })?;
        Ok(RunnerCommandTransportResponse {
            response,
            response_frame_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RunnerRequestWriteProgress {
    NotStarted,
    Started {
        written: NonZeroUsize,
        total: NonZeroUsize,
    },
}

impl RunnerRequestWriteProgress {
    fn from_count(written: usize, total: usize) -> Self {
        let total = NonZeroUsize::new(total).expect("validated runner frames are nonempty");
        match NonZeroUsize::new(written) {
            Some(written) => Self::Started { written, total },
            None => Self::NotStarted,
        }
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct RunnerTransportExchangeFailure {
    pub(super) error: RunnerClientError,
    pub(super) progress: RunnerRequestWriteProgress,
}

impl RunnerTransportExchangeFailure {
    pub(super) fn new(error: RunnerClientError, written: usize, total: usize) -> Self {
        Self {
            error,
            progress: RunnerRequestWriteProgress::from_count(written, total),
        }
    }

    pub(super) fn completed(error: RunnerClientError, total: usize) -> Self {
        Self::new(error, total, total)
    }
}

#[doc(hidden)]
pub struct RunnerTransportResponse {
    pub(super) response: RunnerResponseEnvelope,
    pub(super) response_frame_digest: Digest,
}

#[doc(hidden)]
pub struct RunnerCommandTransportResponse {
    pub(super) response: RunnerResponseEnvelopeV12,
    pub(super) response_frame_digest: Digest,
}

pub(super) struct RunnerSpawnOutcome {
    pub(super) process: Box<dyn RunnerTransport>,
    pub(super) platform_binding: Option<Box<PlatformLaunchBinding>>,
    pub(super) native_cleanup_custody: Option<Box<dyn NativeLaunchCleanupCustody>>,
}

pub(super) struct RunnerLaunchBoundaryFailure {
    pub(super) error: RunnerClientError,
    pub(super) direct_child: DirectChildOutcome,
    pub(super) platform_binding: Option<Box<PlatformLaunchBinding>>,
    pub(super) native_cleanup_custody: Option<Box<dyn NativeLaunchCleanupCustody>>,
    pub(super) cleanup_required: bool,
}

pub(super) type RunnerLaunchBoundaryResult =
    Result<RunnerSpawnOutcome, Box<RunnerLaunchBoundaryFailure>>;

#[cfg(test)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScriptedNativeCleanupMutation {
    Exact,
    CrossedObservation,
    SurvivorsRemain,
    FailOnceBeforeObservation,
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) struct ScriptedNativeCleanupCustody {
    authority: NativeLaunchCleanupAuthority,
    held_transport: Option<Box<dyn RunnerTransport>>,
    native_cleanup_count: Rc<Cell<u64>>,
    mutation: ScriptedNativeCleanupMutation,
    reconciled_observation: Option<NativeLaunchCleanupObservation>,
}

#[cfg(test)]
#[allow(dead_code)]
impl ScriptedNativeCleanupCustody {
    pub(super) fn new(
        authority: NativeLaunchCleanupAuthority,
        held_transport: Option<Box<dyn RunnerTransport>>,
        native_cleanup_count: Rc<Cell<u64>>,
        mutation: ScriptedNativeCleanupMutation,
    ) -> Self {
        Self {
            authority,
            held_transport,
            native_cleanup_count,
            mutation,
            reconciled_observation: None,
        }
    }
}

#[cfg(test)]
impl NativeLaunchCleanupCustody for ScriptedNativeCleanupCustody {
    fn authority(&self) -> &NativeLaunchCleanupAuthority {
        &self.authority
    }

    fn cleanup_or_reconcile(
        &mut self,
        request: NativeLaunchCleanupRequest<'_>,
    ) -> Result<NativeLaunchCleanupObservation, LedgerError> {
        if let Some(observation) = &self.reconciled_observation {
            return Ok(observation.clone());
        }
        let cleanup_invocation = self.native_cleanup_count.get().saturating_add(1);
        self.native_cleanup_count.set(cleanup_invocation);
        if self.mutation == ScriptedNativeCleanupMutation::FailOnceBeforeObservation
            && cleanup_invocation == 1
        {
            return Err(LedgerError::ReferenceMismatch {
                entity: "scripted native cleanup",
                detail: "injected transient failure before native cleanup observation".into(),
            });
        }
        if let Some(transport) = self.held_transport.take() {
            let _ = transport.finish_direct();
        }

        let admission = request.claim().admission();
        let mut os_evidence_bytes = b"grok-build/scripted-native-cleanup/v1\0".to_vec();
        os_evidence_bytes.extend_from_slice(admission.launch.launch_id.as_bytes());
        os_evidence_bytes.push(0);
        os_evidence_bytes.extend_from_slice(admission.cleanup_effect.intent.effect_id.as_bytes());
        let mut authority = self.authority.clone();
        let surviving_processes = match self.mutation {
            ScriptedNativeCleanupMutation::Exact
            | ScriptedNativeCleanupMutation::CrossedObservation
            | ScriptedNativeCleanupMutation::FailOnceBeforeObservation => 0,
            ScriptedNativeCleanupMutation::SurvivorsRemain => 1,
        };
        if self.mutation == ScriptedNativeCleanupMutation::CrossedObservation {
            authority.expected_platform_binding_digest =
                Digest::sha256(b"crossed-scripted-cleanup-platform-binding");
        }
        let observation = NativeLaunchCleanupObservation {
            authority,
            os_evidence_bytes,
            surviving_processes,
            cleaned_at_unix_ms: request.requested_at_unix_ms(),
        };
        self.reconciled_observation = Some(observation.clone());
        Ok(observation)
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) struct SpawnerBackedNativeLaunchService<F> {
    spawn: Option<F>,
    prepared: Option<RunnerSpawnOutcome>,
    preparation_failure: Option<NativeLaunchReleaseFailure>,
    native_cleanup_count: Rc<Cell<u64>>,
}

#[cfg(test)]
#[allow(dead_code)]
impl<F> SpawnerBackedNativeLaunchService<F> {
    pub(super) fn new(spawn: F) -> Self {
        Self {
            spawn: Some(spawn),
            prepared: None,
            preparation_failure: None,
            native_cleanup_count: Rc::new(Cell::new(0)),
        }
    }
}
#[cfg(test)]
impl<F> NativeLaunchService for SpawnerBackedNativeLaunchService<F>
where
    F: FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError>,
{
    fn prepare(
        &mut self,
        mut request: native_launch_service::NativeLaunchPreparationRequest<'_>,
    ) -> NativeLaunchPreparationResponse {
        let claimed_at_unix_ms = request.claim().attempt().claimed_at_unix_ms;
        let binding = request.binding().clone();
        let executable_digest = binding.runner_binary_digest().clone();
        debug_assert_eq!(request.executable().digest, executable_digest);
        let spawn = self
            .spawn
            .take()
            .expect("scripted native preparation is one-shot");
        let disposition = match spawn(request.executable(), Some(&binding)) {
            Ok(spawned) if spawned.platform_binding.as_deref() == Some(&binding) => {
                self.prepared = Some(spawned);
                RunnerLaunchPreparationDisposition::HeldChildPrepared
            }
            Ok(spawned) => {
                self.preparation_failure = Some(NativeLaunchReleaseFailure {
                    error: RunnerClientError::InvalidLifecycle(
                        "prepared transport substituted the exact expected platform launch state"
                            .into(),
                    ),
                    direct_child: spawned.process.finish_direct(),
                });
                RunnerLaunchPreparationDisposition::NativeEffectUncertain
            }
            Err(failure) => {
                let binding_matches = spawn_failure_binding_matches(
                    &failure.direct_child,
                    Some(&binding),
                    failure.platform_binding.as_deref(),
                );
                let disposition = if matches!(
                    &failure.direct_child,
                    DirectChildOutcome::LaunchRefusedBeforeSpawn
                ) && binding_matches
                {
                    RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect
                } else {
                    RunnerLaunchPreparationDisposition::NativeEffectUncertain
                };
                self.preparation_failure = Some(NativeLaunchReleaseFailure {
                    error: if binding_matches {
                        failure.error.into()
                    } else {
                        RunnerClientError::InvalidLifecycle(
                            "prepared transport failure omitted or substituted the exact expected platform launch state"
                                .into(),
                        )
                    },
                    direct_child: failure.direct_child,
                });
                disposition
            }
        };
        NativeLaunchPreparationResponse {
            disposition,
            service_evidence_bytes: b"scripted-service-native-preparation-journal-state".to_vec(),
            finished_at_unix_ms: claimed_at_unix_ms,
        }
    }

    fn take_preparation_failure(&mut self) -> Option<NativeLaunchReleaseFailure> {
        self.preparation_failure.take()
    }

    fn into_cleanup_custody(
        mut self: Box<Self>,
        authority: NativeLaunchCleanupAuthority,
    ) -> Box<dyn NativeLaunchCleanupCustody> {
        let held_transport = self.prepared.take().map(|spawned| spawned.process);
        Box::new(ScriptedNativeCleanupCustody::new(
            authority,
            held_transport,
            self.native_cleanup_count,
            ScriptedNativeCleanupMutation::Exact,
        ))
    }

    fn release(
        mut self: Box<Self>,
        request: NativeLaunchReleaseRequest<'_>,
    ) -> NativeLaunchReleaseAttempt {
        let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
            request.claim().admission(),
            Some(request.preparation()),
            request.binding(),
        );
        let preparation = request.preparation().clone();
        let binding = request.binding().clone();
        debug_assert_eq!(request.claim().admission().launch, *binding.launch());
        debug_assert_eq!(
            request.validated_preparation().service_evidence_bytes(),
            b"scripted-service-native-preparation-journal-state"
        );
        let preparation_evidence_digest = request
            .validated_preparation()
            .native_evidence_digest()
            .clone();
        let released_at_unix_ms = request
            .validated_preparation()
            .finished_at_unix_ms()
            .saturating_add(1);
        let Some(spawned) = self.prepared.take() else {
            return NativeLaunchReleaseAttempt {
                cleanup_custody: Box::new(ScriptedNativeCleanupCustody::new(
                    cleanup_authority,
                    None,
                    self.native_cleanup_count,
                    ScriptedNativeCleanupMutation::Exact,
                )),
                outcome: Err(NativeLaunchReleaseFailure {
                    error: RunnerClientError::InvalidLifecycle(
                        "held-child release had no service-owned prepared transport".into(),
                    ),
                    direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                }),
            };
        };
        let process_identity_digest = native_transport_identity_digest(
            &preparation.attempt,
            &preparation_evidence_digest,
            &binding,
        );
        let mut journal_evidence_bytes =
            b"grok-build/scripted-native-release-journal/v1\0".to_vec();
        journal_evidence_bytes.extend_from_slice(preparation.attempt.native_journal_id.as_bytes());
        journal_evidence_bytes.push(0);
        journal_evidence_bytes.extend_from_slice(process_identity_digest.as_str().as_bytes());
        NativeLaunchReleaseAttempt {
            cleanup_custody: Box::new(ScriptedNativeCleanupCustody::new(
                cleanup_authority,
                None,
                self.native_cleanup_count,
                ScriptedNativeCleanupMutation::Exact,
            )),
            outcome: Ok(NativeLaunchReleaseResponse {
                attempt_id: preparation.attempt.attempt_id.clone(),
                native_journal_id: preparation.attempt.native_journal_id.clone(),
                expected_platform_binding_digest: binding.binding_digest().clone(),
                preparation_evidence_digest,
                process_identity_digest: process_identity_digest.clone(),
                journal_evidence_bytes,
                released_at_unix_ms,
                transport: Box::new(NativeIdentityBoundTransport {
                    inner: spawned.process,
                    process_identity_digest,
                }),
            }),
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn native_transport_identity_digest(
    attempt: &RunnerLaunchPreparationAttempt,
    preparation_evidence_digest: &Digest,
    binding: &PlatformLaunchBinding,
) -> Digest {
    let mut preimage = b"grok-build/native-released-transport-identity/v1\0".to_vec();
    preimage.extend_from_slice(attempt.attempt_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(attempt.native_journal_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(binding.binding_digest().as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(preparation_evidence_digest.as_str().as_bytes());
    Digest::sha256(&preimage)
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) struct NativeIdentityBoundTransport {
    pub(super) inner: Box<dyn RunnerTransport>,
    pub(super) process_identity_digest: Digest,
}

#[cfg(test)]
impl RunnerTransport for NativeIdentityBoundTransport {
    fn exchange_frame(
        &mut self,
        outbound: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, RunnerTransportExchangeFailure> {
        self.inner.exchange_frame(outbound, deadline)
    }

    fn precheck_effect_exchange(&self) -> Result<(), RunnerClientError> {
        self.inner.precheck_effect_exchange()
    }

    fn finish_direct(self: Box<Self>) -> DirectChildOutcome {
        self.inner.finish_direct()
    }

    fn native_process_identity_digest(&self) -> Option<&Digest> {
        Some(&self.process_identity_digest)
    }
}

impl From<RunnerProcessSpawnError> for RunnerLaunchBoundaryFailure {
    fn from(failure: RunnerProcessSpawnError) -> Self {
        Self {
            error: failure.error.into(),
            direct_child: failure.direct_child,
            platform_binding: failure.platform_binding,
            native_cleanup_custody: None,
            cleanup_required: true,
        }
    }
}

#[derive(Debug)]
pub(super) struct RunnerProcessSpawnError {
    pub(super) error: io::Error,
    pub(super) direct_child: DirectChildOutcome,
    pub(super) platform_binding: Option<Box<PlatformLaunchBinding>>,
}

pub(super) struct RunnerProcess {
    pub(super) child: Option<Child>,
    pub(super) stdin: Option<ChildStdin>,
    pub(super) stdout: Option<ChildStdout>,
    pub(super) stderr: Option<ChildStderr>,
    pub(super) stderr_diagnostics: Vec<u8>,
    pub(super) stderr_eof: bool,
}

impl RunnerProcess {
    pub(super) fn spawn(
        executable: &mut RetainedRunnerExecutable,
    ) -> Result<Self, RunnerProcessSpawnError> {
        let command =
            descriptor_launch_command(executable).map_err(|error| RunnerProcessSpawnError {
                error,
                direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                platform_binding: None,
            })?;
        Self::spawn_std_command(command, true)
    }

    /// Spawn an already-built runner command (stdin/stdout/stderr piped).
    ///
    /// Used for `--linux-native-service-install-root` so the runner receives
    /// that flag. This still launches `grok-build-runner`, not the contained
    /// task program. `clean_env` matches descriptor-exec; the installed-service
    /// session keeps the process environment so `/proc/self/exe` identity
    /// matches the inspected named file (same as the 12/12 runner-wire spawn).
    fn spawn_std_command(
        mut command: Command,
        clean_env: bool,
    ) -> Result<Self, RunnerProcessSpawnError> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if clean_env {
            command.env_clear().current_dir("/");
        }
        let mut child = command.spawn().map_err(|error| RunnerProcessSpawnError {
            error,
            direct_child: DirectChildOutcome::SpawnFailed,
            platform_binding: None,
        })?;
        if child.stdin.is_none() || child.stdout.is_none() || child.stderr.is_none() {
            drop(child.stdin.take());
            drop(child.stdout.take());
            drop(child.stderr.take());
            let direct_child = terminate_after_transport_setup_failure(&mut child);
            return Err(RunnerProcessSpawnError {
                error: io::Error::other("runner stdin/stdout/stderr pipe was not created"),
                direct_child,
                platform_binding: None,
            });
        }
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let direct_child = terminate_after_transport_setup_failure(&mut child);
            return Err(RunnerProcessSpawnError {
                error: io::Error::other("runner stdin/stdout/stderr pipe disappeared during setup"),
                direct_child,
                platform_binding: None,
            });
        };
        if let Err(error) = set_nonblocking(&stdin)
            .and_then(|()| set_nonblocking(&stdout))
            .and_then(|()| set_nonblocking(&stderr))
        {
            drop(stdin);
            drop(stdout);
            drop(stderr);
            let direct_child = terminate_after_transport_setup_failure(&mut child);
            return Err(RunnerProcessSpawnError {
                error,
                direct_child,
                platform_binding: None,
            });
        }
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
            stderr_diagnostics: Vec::new(),
            stderr_eof: false,
        })
    }
}

pub(super) fn installed_service_launch_command(
    executable: &mut RetainedRunnerExecutable,
) -> Result<Command, io::Error> {
    #[cfg(target_os = "linux")]
    {
        executable.revalidate()?;
        // Named-file spawn so the runner's `/proc/self/exe` is a re-openable
        // path. Memfd exec leaves a deleted memfd name, and
        // `open-native-service-process-image` then fails ENOENT. The plus
        // staging copy is already nlink=1 mode 0700, matching the 12/12 test.
        Ok(Command::new(&executable.canonical_path))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = executable;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed-service runner spawn requires the Linux descriptor-exec bridge",
        ))
    }
}

#[cfg(target_os = "linux")]
pub(super) fn descriptor_launch_command(
    executable: &mut RetainedRunnerExecutable,
) -> Result<Command, io::Error> {
    executable.revalidate()?;
    let descriptor_path = authenticated_proc_descriptor_path(executable)?;
    let mut command = Command::new(descriptor_path);
    command.arg0(executable.canonical_path.as_os_str());
    Ok(command)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn descriptor_launch_command(
    _executable: &mut RetainedRunnerExecutable,
) -> Result<Command, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this target has no audited retained-descriptor execution bridge",
    ))
}

impl RunnerTransport for RunnerProcess {
    fn precheck_effect_exchange(&self) -> Result<(), RunnerClientError> {
        if self.stdout.is_none() {
            return Err(RunnerClientError::InvalidLifecycle(
                "runner stdout is already closed".into(),
            ));
        }
        Ok(())
    }

    fn stderr_diagnostics(&self) -> &[u8] {
        &self.stderr_diagnostics
    }

    fn os_pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    fn exchange_frame(
        &mut self,
        outbound: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, RunnerTransportExchangeFailure> {
        let Self {
            stdin,
            stdout,
            stderr,
            stderr_diagnostics,
            stderr_eof,
            ..
        } = self;
        let stdin = stdin.as_mut().ok_or_else(|| {
            RunnerTransportExchangeFailure::new(
                RunnerClientError::InvalidLifecycle("runner stdin is already closed".into()),
                0,
                outbound.len(),
            )
        })?;
        let stderr = stderr.as_mut().ok_or_else(|| {
            RunnerTransportExchangeFailure::new(
                RunnerClientError::InvalidLifecycle("runner stderr is already closed".into()),
                0,
                outbound.len(),
            )
        })?;
        write_all_until_with_stderr(
            stdin,
            stderr,
            stderr_diagnostics,
            stderr_eof,
            outbound,
            deadline,
        )?;
        let stdout = stdout.as_mut().ok_or_else(|| {
            RunnerTransportExchangeFailure::completed(
                RunnerClientError::InvalidLifecycle("runner stdout is already closed".into()),
                outbound.len(),
            )
        })?;
        read_frame_until_with_stderr(stdout, stderr, stderr_diagnostics, stderr_eof, deadline)
            .map_err(|error| RunnerTransportExchangeFailure::completed(error, outbound.len()))
    }

    fn finish_direct(mut self: Box<Self>) -> DirectChildOutcome {
        drop(self.stdin.take());
        drop(self.stdout.take());
        let outcome = match self.child.take() {
            Some(mut child) => wait_for_direct_child_with_stderr(
                &mut child,
                self.stderr.as_mut(),
                &mut self.stderr_diagnostics,
                &mut self.stderr_eof,
            ),
            None => DirectChildOutcome::WaitFailed {
                message: "direct child handle was already consumed".into(),
            },
        };
        if !self.stderr_eof
            && let Some(stderr) = self.stderr.as_mut()
        {
            self.stderr_eof =
                drain_runner_stderr(stderr, &mut self.stderr_diagnostics).unwrap_or(false);
        }
        drop(self.stderr.take());
        outcome
    }
}

impl Drop for RunnerProcess {
    fn drop(&mut self) {
        drop(self.stdin.take());
        drop(self.stdout.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = bounded_try_wait_with_stderr(
                &mut child,
                self.stderr.as_mut(),
                &mut self.stderr_diagnostics,
                &mut self.stderr_eof,
                Instant::now() + PROCESS_KILL_GRACE,
            );
        }
        if !self.stderr_eof
            && let Some(stderr) = self.stderr.as_mut()
        {
            self.stderr_eof =
                drain_runner_stderr(stderr, &mut self.stderr_diagnostics).unwrap_or(false);
        }
        drop(self.stderr.take());
    }
}

pub(super) fn finish_transport(
    process: Box<dyn RunnerTransport>,
    launch: RunnerLaunchIntent,
    launch_cleanup_admission: Option<Box<PersistedRunnerLaunchCleanupAdmission>>,
    platform_launch_binding: Option<Box<PlatformLaunchBinding>>,
    native_cleanup_custody: Option<Box<dyn NativeLaunchCleanupCustody>>,
    session_registration: RunnerSessionRegistrationState,
    shutdown_prepared: Option<ShutdownPreparedAcknowledgement>,
) -> RunnerCleanupRequired {
    RunnerCleanupRequired {
        launch,
        launch_cleanup_admission,
        platform_launch_binding,
        native_cleanup_custody,
        session_registration,
        direct_child: process.finish_direct(),
        shutdown_prepared,
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn write_all_until(
    writer: &mut (impl Write + rustix::fd::AsFd),
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), RunnerClientError> {
    while !bytes.is_empty() {
        wait_for_fd(writer, PollFlags::OUT, deadline)?;
        match writer.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(super) fn write_all_until_with_stderr(
    writer: &mut (impl Write + rustix::fd::AsFd),
    stderr: &mut (impl Read + rustix::fd::AsFd),
    diagnostics: &mut Vec<u8>,
    stderr_eof: &mut bool,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), RunnerTransportExchangeFailure> {
    let total = bytes.len();
    let mut written_total = 0_usize;
    while !bytes.is_empty() {
        wait_for_fd_with_stderr(
            writer,
            PollFlags::OUT,
            stderr,
            diagnostics,
            stderr_eof,
            deadline,
        )
        .map_err(|error| RunnerTransportExchangeFailure::new(error.into(), written_total, total))?;
        match writer.write(bytes) {
            Ok(0) => {
                return Err(RunnerTransportExchangeFailure::new(
                    io::Error::from(io::ErrorKind::WriteZero).into(),
                    written_total,
                    total,
                ));
            }
            Ok(written) => {
                written_total = written_total.checked_add(written).ok_or_else(|| {
                    RunnerTransportExchangeFailure::new(
                        RunnerClientError::InvalidLifecycle(
                            "runner request write progress overflow".into(),
                        ),
                        written_total,
                        total,
                    )
                })?;
                bytes = &bytes[written..];
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => {
                return Err(RunnerTransportExchangeFailure::new(
                    error.into(),
                    written_total,
                    total,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn read_frame_until(
    reader: &mut (impl Read + rustix::fd::AsFd),
    deadline: Instant,
) -> Result<Vec<u8>, RunnerClientError> {
    let mut prefix = [0_u8; 4];
    if read_until_eof(reader, &mut prefix, deadline)? != prefix.len() {
        return Err(WireProtocolError::TruncatedPrefix.into());
    }
    let wire_length = u32::from_be_bytes(prefix);
    let length =
        usize::try_from(wire_length).map_err(|_| WireProtocolError::InvalidLength(wire_length))?;
    if length == 0 || length > MAX_WIRE_FRAME_BYTES {
        return Err(WireProtocolError::InvalidLength(wire_length).into());
    }
    let mut payload = vec![0_u8; length];
    let actual = read_until_eof(reader, &mut payload, deadline)?;
    if actual != length {
        return Err(WireProtocolError::TruncatedPayload {
            expected: length,
            actual,
        }
        .into());
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub(super) fn read_frame_until_with_stderr(
    reader: &mut (impl Read + rustix::fd::AsFd),
    stderr: &mut (impl Read + rustix::fd::AsFd),
    diagnostics: &mut Vec<u8>,
    stderr_eof: &mut bool,
    deadline: Instant,
) -> Result<Vec<u8>, RunnerClientError> {
    let mut prefix = [0_u8; 4];
    if read_until_eof_with_stderr(
        reader,
        stderr,
        diagnostics,
        stderr_eof,
        &mut prefix,
        deadline,
    )? != prefix.len()
    {
        return Err(WireProtocolError::TruncatedPrefix.into());
    }
    let wire_length = u32::from_be_bytes(prefix);
    let length =
        usize::try_from(wire_length).map_err(|_| WireProtocolError::InvalidLength(wire_length))?;
    if length == 0 || length > MAX_WIRE_FRAME_BYTES {
        return Err(WireProtocolError::InvalidLength(wire_length).into());
    }
    let mut payload = vec![0_u8; length];
    let actual = read_until_eof_with_stderr(
        reader,
        stderr,
        diagnostics,
        stderr_eof,
        &mut payload,
        deadline,
    )?;
    if actual != length {
        return Err(WireProtocolError::TruncatedPayload {
            expected: length,
            actual,
        }
        .into());
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn read_until_eof(
    reader: &mut (impl Read + rustix::fd::AsFd),
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, RunnerClientError> {
    let mut offset = 0;
    while offset < buffer.len() {
        wait_for_fd(reader, PollFlags::IN, deadline)?;
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => break,
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(offset)
}

pub(super) fn read_until_eof_with_stderr(
    reader: &mut (impl Read + rustix::fd::AsFd),
    stderr: &mut (impl Read + rustix::fd::AsFd),
    diagnostics: &mut Vec<u8>,
    stderr_eof: &mut bool,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, RunnerClientError> {
    let mut offset = 0;
    while offset < buffer.len() {
        wait_for_fd_with_stderr(
            reader,
            PollFlags::IN,
            stderr,
            diagnostics,
            stderr_eof,
            deadline,
        )?;
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => break,
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(offset)
}

pub(super) fn set_nonblocking(fd: &impl rustix::fd::AsFd) -> Result<(), io::Error> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(io::Error::from)
}

pub(super) fn wait_for_fd(
    fd: &impl rustix::fd::AsFd,
    wanted: PollFlags,
    deadline: Instant,
) -> Result<(), io::Error> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runner framed exchange exceeded its bounded deadline",
            ));
        }
        let remaining = deadline.duration_since(now);
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: remaining.subsec_nanos().into(),
        };
        let mut descriptor = [PollFd::new(fd, wanted | PollFlags::HUP | PollFlags::ERR)];
        match poll(&mut descriptor, Some(&timeout)) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "runner framed exchange exceeded its bounded deadline",
                ));
            }
            Ok(_) => {
                let ready = descriptor[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "runner transport descriptor is invalid",
                    ));
                }
                if ready.intersects(wanted | PollFlags::HUP | PollFlags::ERR) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

pub(super) fn wait_for_fd_with_stderr(
    fd: &impl rustix::fd::AsFd,
    wanted: PollFlags,
    stderr: &mut (impl Read + rustix::fd::AsFd),
    diagnostics: &mut Vec<u8>,
    stderr_eof: &mut bool,
    deadline: Instant,
) -> Result<(), io::Error> {
    loop {
        if *stderr_eof {
            return wait_for_fd(fd, wanted, deadline);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runner framed exchange exceeded its bounded deadline",
            ));
        }
        let remaining = deadline.duration_since(now);
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: remaining.subsec_nanos().into(),
        };
        let (primary_ready, stderr_ready) = {
            let mut descriptors = [
                PollFd::new(fd, wanted | PollFlags::HUP | PollFlags::ERR),
                PollFd::new(&*stderr, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
            ];
            match poll(&mut descriptors, Some(&timeout)) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "runner framed exchange exceeded its bounded deadline",
                    ));
                }
                Ok(_) => {
                    let primary = descriptors[0].revents();
                    let diagnostic = descriptors[1].revents();
                    if primary.contains(PollFlags::NVAL) || diagnostic.contains(PollFlags::NVAL) {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "runner transport descriptor is invalid",
                        ));
                    }
                    (
                        primary.intersects(wanted | PollFlags::HUP | PollFlags::ERR),
                        diagnostic.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
                    )
                }
                Err(error) if error == rustix::io::Errno::INTR => (false, false),
                Err(error) => return Err(io::Error::from(error)),
            }
        };
        if stderr_ready {
            *stderr_eof = drain_runner_stderr(stderr, diagnostics)?;
        }
        if primary_ready {
            return Ok(());
        }
    }
}

pub(super) fn drain_runner_stderr(
    stderr: &mut impl Read,
    diagnostics: &mut Vec<u8>,
) -> Result<bool, io::Error> {
    let mut buffer = [0_u8; 1_024];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(read) => {
                let retained = MAX_RUNNER_STDERR_BYTES.saturating_sub(diagnostics.len());
                diagnostics.extend_from_slice(&buffer[..read.min(retained)]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn wait_for_direct_child_with_stderr(
    child: &mut Child,
    stderr: Option<&mut ChildStderr>,
    diagnostics: &mut Vec<u8>,
    stderr_eof: &mut bool,
) -> DirectChildOutcome {
    let mut stderr = stderr;
    match bounded_try_wait_with_stderr(
        child,
        stderr.as_deref_mut(),
        diagnostics,
        stderr_eof,
        Instant::now() + PROCESS_EXIT_GRACE,
    ) {
        Ok(Some(status)) => direct_exit(status),
        Err(error) => DirectChildOutcome::WaitFailed {
            message: bounded_error(&error),
        },
        Ok(None) => {
            if let Err(error) = child.kill() {
                return DirectChildOutcome::WaitFailed {
                    message: bounded_error(&error),
                };
            }
            match bounded_try_wait_with_stderr(
                child,
                stderr,
                diagnostics,
                stderr_eof,
                Instant::now() + PROCESS_KILL_GRACE,
            ) {
                Ok(Some(status)) => DirectChildOutcome::KilledAfterTimeout {
                    code: status.code(),
                },
                Ok(None) => DirectChildOutcome::WaitFailed {
                    message: "direct child did not become waitable after bounded kill grace".into(),
                },
                Err(error) => DirectChildOutcome::WaitFailed {
                    message: bounded_error(&error),
                },
            }
        }
    }
}

pub(super) fn direct_exit(status: ExitStatus) -> DirectChildOutcome {
    DirectChildOutcome::Exited {
        code: status.code(),
        success: status.success(),
    }
}

pub(super) fn terminate_after_transport_setup_failure(child: &mut Child) -> DirectChildOutcome {
    match child.try_wait() {
        Ok(Some(status)) => direct_exit(status),
        Ok(None) => {
            if let Err(error) = child.kill() {
                return DirectChildOutcome::WaitFailed {
                    message: bounded_error(&error),
                };
            }
            match bounded_try_wait(child, Instant::now() + PROCESS_KILL_GRACE) {
                Ok(Some(status)) => DirectChildOutcome::KilledAfterTransportSetupFailure {
                    code: status.code(),
                },
                Ok(None) => DirectChildOutcome::WaitFailed {
                    message:
                        "setup-failed direct child did not become waitable after bounded kill grace"
                            .into(),
                },
                Err(error) => DirectChildOutcome::WaitFailed {
                    message: bounded_error(&error),
                },
            }
        }
        Err(error) => DirectChildOutcome::WaitFailed {
            message: bounded_error(&error),
        },
    }
}

pub(super) fn bounded_try_wait(
    child: &mut Child,
    deadline: Instant,
) -> Result<Option<ExitStatus>, io::Error> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        thread::sleep(PROCESS_EXIT_POLL.min(deadline.duration_since(now)));
    }
}

pub(super) fn bounded_try_wait_with_stderr(
    child: &mut Child,
    mut stderr: Option<&mut ChildStderr>,
    diagnostics: &mut Vec<u8>,
    stderr_eof: &mut bool,
    deadline: Instant,
) -> Result<Option<ExitStatus>, io::Error> {
    loop {
        if !*stderr_eof && let Some(stderr) = stderr.as_deref_mut() {
            *stderr_eof = drain_runner_stderr(stderr, diagnostics)?;
        }
        if let Some(status) = child.try_wait()? {
            if !*stderr_eof && let Some(stderr) = stderr.as_deref_mut() {
                *stderr_eof = drain_runner_stderr(stderr, diagnostics)?;
            }
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        thread::sleep(PROCESS_EXIT_POLL.min(deadline.duration_since(now)));
    }
}

pub(super) fn bounded_error(error: &io::Error) -> String {
    error.to_string().chars().take(1_024).collect()
}

impl RunnerLifecycleClient {
    /// Launch a worker whose runner is started with
    /// `--linux-native-service-install-root` (the installed-service
    /// session). Does not require local descriptor-exec; the runner still
    /// mints execution authority on its host.
    ///
    /// This is not the held-child prepare/release client.
    ///
    /// # Errors
    ///
    /// Same launch failures as ordinary launch, plus a non-absolute install
    /// root or a spawn/pipe failure of the runner process.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "mirrors launch: the request is consumed so a caller cannot reuse one identity"
    )]
    pub fn launch_linux_installed_service_session(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        request: RunnerClientLaunch,
        linux_native_service_install_root: PathBuf,
    ) -> Result<Self, RunnerLaunchFailure> {
        if !linux_native_service_install_root.is_absolute() {
            return Err(launch_failure(
                RunnerClientError::InvalidLifecycle(
                    "--linux-native-service-install-root must be an absolute path".into(),
                ),
                None,
            ));
        }
        INSTALLED_SERVICE_NAMED_EXEC.store(true, Ordering::SeqCst);
        let launched = Self::launch_with_ledger_and_spawner(
            RunnerLaunchLedger::Ordinary(ledger),
            authority,
            compiled_policy,
            request,
            None,
            move |launch_ledger, executable, admission, binding, input_snapshot| {
                let RunnerLaunchLedger::Ordinary(_) = launch_ledger else {
                    return Err(Box::new(RunnerLaunchBoundaryFailure {
                        error: RunnerClientError::InvalidLifecycle(
                            "installed-service launch received operation-local authority".into(),
                        ),
                        direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                        platform_binding: None,
                        native_cleanup_custody: None,
                        cleanup_required: false,
                    }));
                };
                let (admission, binding) = installed_service_launch_inputs(admission, binding)?;
                spawn_installed_linux_native_service_child(
                    admission,
                    binding,
                    input_snapshot,
                    executable,
                    &linux_native_service_install_root,
                )
            },
        );
        INSTALLED_SERVICE_NAMED_EXEC.store(false, Ordering::SeqCst);
        let mut client = launched?;
        client.installed_service_command_release = true;
        Ok(client)
    }
}

pub(super) fn installed_service_launch_inputs<'a>(
    admission: Option<&'a PersistedRunnerLaunchCleanupAdmission>,
    binding: Option<&'a PlatformLaunchBinding>,
) -> Result<
    (
        &'a PersistedRunnerLaunchCleanupAdmission,
        &'a PlatformLaunchBinding,
    ),
    Box<RunnerLaunchBoundaryFailure>,
> {
    let Some(admission) = admission else {
        return Err(Box::new(RunnerLaunchBoundaryFailure {
            error: RunnerClientError::InvalidLifecycle(
                "installed-service launch is missing its durable cleanup admission".into(),
            ),
            direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
            platform_binding: binding.cloned().map(Box::new),
            native_cleanup_custody: None,
            cleanup_required: true,
        }));
    };
    let Some(binding) = binding else {
        return Err(Box::new(RunnerLaunchBoundaryFailure {
            error: RunnerClientError::InvalidLifecycle(
                "installed-service launch is missing its authenticated platform binding".into(),
            ),
            direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
            platform_binding: None,
            native_cleanup_custody: None,
            cleanup_required: true,
        }));
    };
    Ok((admission, binding))
}

pub(super) fn spawn_installed_linux_native_service_child(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    binding: &PlatformLaunchBinding,
    input_snapshot: &Digest,
    executable: &mut RetainedRunnerExecutable,
    install_root: &Path,
) -> RunnerLaunchBoundaryResult {
    if admission.cleanup_effect.intent.input_snapshot != *input_snapshot
        || admission.launch != *binding.launch()
        || admission.cleanup_effect.intent != *binding.cleanup_intent()
    {
        return Err(Box::new(RunnerLaunchBoundaryFailure {
            error: RunnerClientError::InvalidLifecycle(
                "installed-service launch crossed its exact launch, cleanup effect, or input snapshot"
                    .into(),
            ),
            direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
            platform_binding: Some(Box::new(binding.clone())),
            native_cleanup_custody: None,
            cleanup_required: true,
        }));
    }
    let mut command = match installed_service_launch_command(executable) {
        Ok(command) => command,
        Err(error) => {
            return Err(Box::new(RunnerLaunchBoundaryFailure {
                error: error.into(),
                direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: None,
                cleanup_required: true,
            }));
        }
    };
    command
        .arg("--linux-native-service-install-root")
        .arg(install_root);
    match RunnerProcess::spawn_std_command(command, true) {
        Ok(process) => Ok(RunnerSpawnOutcome {
            process: Box::new(process) as Box<dyn RunnerTransport>,
            platform_binding: Some(Box::new(binding.clone())),
            native_cleanup_custody: None,
        }),
        Err(RunnerProcessSpawnError {
            error,
            direct_child,
            platform_binding,
        }) => {
            debug_assert!(platform_binding.is_none());
            Err(Box::new(RunnerLaunchBoundaryFailure {
                error: error.into(),
                direct_child,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: None,
                cleanup_required: true,
            }))
        }
    }
}

#[cfg(test)]
mod installed_service_launch_input_tests {
    use super::*;

    #[test]
    fn missing_installed_service_launch_authority_refuses_before_spawn_without_panic() {
        let result = installed_service_launch_inputs(None, None);
        let Err(failure) = result else {
            panic!("missing launch authority must refuse");
        };
        assert!(matches!(
            failure.error,
            RunnerClientError::InvalidLifecycle(ref detail)
                if detail.contains("missing its durable cleanup admission")
        ));
        assert_eq!(
            failure.direct_child,
            DirectChildOutcome::LaunchRefusedBeforeSpawn
        );
        assert!(failure.cleanup_required);
        assert!(failure.platform_binding.is_none());
        assert!(failure.native_cleanup_custody.is_none());
    }
}
