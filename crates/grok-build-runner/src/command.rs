//! Fail-closed command supervision behind authenticated runner authority.
//!
//! The supervisor never invokes a shell. It resolves one exact executable,
//! preserves the supplied argument vector, clears the inherited environment,
//! supplies null stdin, and launches the process in a fresh process group. Static
//! sandbox discovery is never treated as authority: macOS execution additionally
//! requires active filesystem, credential, network, descriptor, profile, and fork
//! canaries. Linux remains deliberately blocked until Landlock and seccomp filters
//! can be installed and actively proven by an audited launcher.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
// The private credential-canary layout is the only writer in this module and it
// exists only on macOS; importing these unconditionally left a Linux build
// carrying two unused names.
#[cfg(target_os = "macos")]
use std::fs::OpenOptions;
#[cfg(target_os = "macos")]
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
// Only the macOS inherited-descriptor canary stamps a wall-clock instant into
// its evidence; nothing else in this module reads the system clock.
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
// `DirBuilder::mode` is called by the macOS private-instance layout and by the
// crate's own scratch-directory helper in tests; `OpenOptions::mode` only by the
// former.
#[cfg(any(target_os = "macos", test))]
use std::os::unix::fs::DirBuilderExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use grok_build_core::{
    CommandOutputArtifactSetReferenceV1, CommandOutputArtifactSourceV1,
    CommandOutputCaptureAcquiredV1, CommandOutputCaptureStoreHeadV1, CommandSpec,
    CompiledExecutionPolicy, Digest, ExecutionNetwork, IssuedWorkspaceGrant, MutationMode,
    PathScope, ResourceLimits, SensitiveOutputDetectionPolicyReferenceV1,
};
use rustix::fs::{Mode, OFlags, open};
use rustix::io::{FdFlags, fcntl_getfd};
use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};

use crate::capability_workspace::capture_manifest;
use crate::cleanup_proof::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, CommandDomainCleanupProofError,
    ValidatedCommandDomainCleanupProof,
};
use crate::command_output_store::{
    CapabilityCommandOutputStore, CommandOutputPublisher, CommandOutputStoreError,
    CommandOutputStreamCapture, FinishedCommandOutputStream,
    SensitiveOutputRejectionJournalReceiptV2,
};
use crate::process_boundary::{ClosedExecDescriptorSet, validate_closed_exec_descriptor_report};
use crate::sensitive_output::{
    ScreenedSensitiveOutputChunkV1, SensitiveOutputCoreDumpSuppressionV1, SensitiveOutputError,
    SensitiveOutputStreamScannerV1, enforce_core_dump_suppression_v1,
    read_core_dump_suppression_v1,
};
use crate::sensitive_output_terminal_observation::{
    SensitiveOutputCleanTerminalResponseV1, SensitiveOutputTerminalObservationError,
    SensitiveOutputTerminalObservationV1,
};
use crate::service::SessionValidatedWorkerExecutionRoot;
use crate::wire::{
    CONTAINED_CAPTURE_LAUNCH_SCHEMA, CommandEffectAuthorityV1, CommandEffectAuthorityV2,
    MAX_INLINE_COMMAND_RETAINED_BYTES, RunnerRequest, RunnerRole, WireCommandBackendIdentity,
    WireCommandStreamEvidence, command_output_capture_maximum,
};
use crate::{
    CapabilityState, EnvironmentPolicy, HostPlatform, PreflightDisposition, ScrubbedEnvironment,
    WorkspaceManifest, inspect_host_sandbox,
};

const MACOS_SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
// These system paths are macOS-only; Unix tests also need the kill helper.
#[cfg(target_os = "macos")]
const MACOS_SYSTEM_PROFILE: &str = "/System/Library/Sandbox/Profiles/system.sb";
#[cfg(any(target_os = "macos", test))]
const KILL_PROGRAM: &str = "/bin/kill";
#[cfg(target_os = "macos")]
const CANARY_TRUE: &str = "/usr/bin/true";
#[cfg(target_os = "macos")]
const CANARY_CAT: &str = "/bin/cat";
#[cfg(target_os = "macos")]
const CANARY_TOUCH: &str = "/usr/bin/touch";
#[cfg(target_os = "macos")]
const CANARY_CURL: &str = "/usr/bin/curl";
#[cfg(target_os = "macos")]
const CANARY_FIND: &str = "/usr/bin/find";
#[cfg(target_os = "macos")]
const CANARY_OUTPUT_LIMIT: u64 = 64 * 1024;
const MAX_CAPTURE_LIMIT: u64 = 64 * 1024 * 1024;
#[cfg(target_os = "macos")]
const CANARY_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const CONTAINED_BACKEND_POLL_CHUNK_LIMIT: usize = 64 * 1024;
const CONTAINED_BACKEND_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
// One crossing observation plus at most 400 observations during the two-second
// five-millisecond cleanup window. Making the count explicit turns the
// time-based drain into an authenticated byte bound even if a clock or backend
// schedules observations more aggressively than expected.
const CONTAINED_CLEANUP_OBSERVATION_LIMIT: u64 = 400;
const CONTAINED_LAUNCH_DIGEST_DOMAIN: &[u8] = b"grok-build/contained-launch/v3";
const CONTAINED_PREFLIGHT_DIGEST_DOMAIN: &[u8] = b"grok-build/contained-preflight/v2";
#[cfg(target_os = "macos")]
const CREDENTIAL_CANARY_BYTES: &[u8] = b"grok-build-credential-canary-v1\n";
const OUTPUT_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output/v1";
const LINUX_BLOCK_REASON: &str = "Bubblewrap arguments can be generated, but the runner has no audited safe launcher that installs and actively proves both a Landlock ruleset and a seccomp-BPF syscall filter; no_new_privs and namespace visibility alone are insufficient";
#[cfg(target_os = "macos")]
const MACOS_INHERITED_FD_BLOCK_REASON: &str = "Seatbelt permits reads from a file descriptor inherited before sandbox activation, while std::process cannot close arbitrary non-CLOEXEC descriptors atomically; an audited closefrom-style launcher is required before real command execution";
#[cfg(target_os = "macos")]
const LEGACY_MACOS_LAUNCH_BLOCK_REASON: &str = "the legacy path-based Seatbelt command adapter cannot consume the retained executable, root, and cwd descriptors or the single-use contained-backend permit; only the signed helper bridge may implement production launch";

// The macOS supervisor allocates private instance directories from this
// counter; the crate's own tests reuse it to name their scratch directories on
// every host, so the gate admits `test` as well as macOS.
#[cfg(any(target_os = "macos", test))]
static NEXT_PRIVATE_DIRECTORY: AtomicU64 = AtomicU64::new(1);

/// Filesystem roots supplied to the command supervisor.
#[allow(
    clippy::struct_field_names,
    reason = "the shared `root` postfix is the security-relevant subject: every field names the exact directory from which traversal is permitted"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorPaths {
    private_state_root: PathBuf,
    shadow_root: Option<PathBuf>,
    linux_native_service_install_root: Option<PathBuf>,
}

impl SupervisorPaths {
    /// Constructs paths for read-only execution.
    #[must_use]
    pub fn read_only(private_state_root: impl Into<PathBuf>) -> Self {
        Self {
            private_state_root: private_state_root.into(),
            shadow_root: None,
            linux_native_service_install_root: None,
        }
    }

    /// Constructs paths for private-shadow execution.
    #[must_use]
    pub fn shadow(private_state_root: impl Into<PathBuf>, shadow_root: impl Into<PathBuf>) -> Self {
        Self {
            private_state_root: private_state_root.into(),
            shadow_root: Some(shadow_root.into()),
            linux_native_service_install_root: None,
        }
    }

    /// Names the directory an installer wrote its Linux native-service anchor
    /// into.
    ///
    /// Supplying this is an assertion about *where* to look, and nothing more.
    /// It is not an assertion that a service is installed there, that the
    /// anchor is genuine, or that the path is trustworthy: every one of those
    /// is decided by re-observation inside
    /// `open_installed_linux_native_service_handoff`, which walks the whole
    /// chain `O_NOFOLLOW`, requires every component to be owned by an identity
    /// other than this runner, re-`statx`'s each absolute name the anchor
    /// commits to, and refuses when a committed name resolves to a different
    /// object. A runner that could point this at a directory it owns still
    /// gets no service.
    ///
    /// There is deliberately no default and no fallback. An absent install root
    /// means the contained backend is composed the in-process way, not that one
    /// is guessed.
    #[must_use]
    pub fn with_linux_native_service_install_root(
        mut self,
        install_root: impl Into<PathBuf>,
    ) -> Self {
        self.linux_native_service_install_root = Some(install_root.into());
        self
    }

    /// Returns the configured Linux native-service install root, when one was
    /// supplied.
    #[must_use]
    pub fn linux_native_service_install_root(&self) -> Option<&Path> {
        self.linux_native_service_install_root.as_deref()
    }

    /// Returns the caller-managed private state root.
    #[must_use]
    pub fn private_state_root(&self) -> &Path {
        &self.private_state_root
    }

    /// Returns the private shadow root, when configured.
    #[must_use]
    pub fn shadow_root(&self) -> Option<&Path> {
        self.shadow_root.as_deref()
    }
}

/// A clonable, one-way cancellation signal.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a token in the non-cancelled state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. The operation is idempotent.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Bounded bytes and a digest of the complete observed stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedOutput {
    bytes: Vec<u8>,
    complete_digest: Digest,
    complete_length: u64,
    truncated: bool,
}

impl CapturedOutput {
    /// Returns retained bytes. Across both streams, retention is bounded by
    /// both authenticated policy and the versioned terminal-wire ceiling.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 digest of every observed byte on this stream.
    #[must_use]
    pub const fn complete_digest(&self) -> &Digest {
        &self.complete_digest
    }

    /// Returns the complete number of bytes observed before termination.
    #[must_use]
    pub const fn complete_length(&self) -> u64 {
        self.complete_length
    }

    /// Returns whether bounded retention omitted observed bytes.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Why a supervised command stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandTermination {
    /// The process returned an exit code.
    Exited(i32),
    /// The process ended because of a Unix signal.
    Signaled(i32),
    /// The authenticated wall-time ceiling elapsed.
    TimedOut,
    /// The caller requested cancellation.
    Cancelled,
    /// Combined output crossed the authenticated ceiling.
    OutputLimitExceeded,
}

/// Active sandbox evidence produced before a real command spawn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxEvidence {
    profile_digest: Digest,
    launcher_digest: Digest,
    system_profile_digest: Digest,
    network_enabled: bool,
    checked_at_unix_ms: u64,
}

impl SandboxEvidence {
    /// Returns the exact actively exercised profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> &Digest {
        &self.profile_digest
    }

    /// Returns the verified sandbox-launcher content digest.
    #[must_use]
    pub const fn launcher_digest(&self) -> &Digest {
        &self.launcher_digest
    }

    /// Returns the verified imported system-profile content digest.
    #[must_use]
    pub const fn system_profile_digest(&self) -> &Digest {
        &self.system_profile_digest
    }

    /// Returns whether the profile actively proved network enabled rather than denied.
    #[must_use]
    pub const fn network_enabled(&self) -> bool {
        self.network_enabled
    }

    /// Returns when active checks finished.
    #[must_use]
    pub const fn checked_at_unix_ms(&self) -> u64 {
        self.checked_at_unix_ms
    }
}

/// Command evidence suitable for constructing a verification receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    command: CommandSpec,
    policy_hash: Digest,
    resolved_program: PathBuf,
    working_directory: PathBuf,
    termination: CommandTermination,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    output_digest: Digest,
    duration_ms: u64,
    sandbox_evidence: SandboxEvidence,
}

impl CommandResult {
    /// Returns the exact caller-supplied command contract.
    #[must_use]
    pub const fn command(&self) -> &CommandSpec {
        &self.command
    }

    /// Returns the immutable compiled policy digest that authorized the spawn.
    #[must_use]
    pub const fn policy_hash(&self) -> &Digest {
        &self.policy_hash
    }

    /// Returns the selected canonical executable.
    #[must_use]
    pub fn resolved_program(&self) -> &Path {
        &self.resolved_program
    }

    /// Returns the canonical working directory used by the child.
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Returns why execution stopped.
    #[must_use]
    pub const fn termination(&self) -> CommandTermination {
        self.termination
    }

    /// Returns bounded stdout and its complete digest.
    #[must_use]
    pub const fn stdout(&self) -> &CapturedOutput {
        &self.stdout
    }

    /// Returns bounded stderr and its complete digest.
    #[must_use]
    pub const fn stderr(&self) -> &CapturedOutput {
        &self.stderr
    }

    /// Returns a stream-framed digest of complete stdout and stderr.
    #[must_use]
    pub const fn output_digest(&self) -> &Digest {
        &self.output_digest
    }

    /// Returns measured wall time in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    /// Returns active containment evidence collected for this spawn.
    #[must_use]
    pub const fn sandbox_evidence(&self) -> &SandboxEvidence {
        &self.sandbox_evidence
    }

    /// Returns an exit status only for a normal process exit.
    #[must_use]
    pub const fn exit_status(&self) -> Option<i32> {
        match self.termination {
            CommandTermination::Exited(status) => Some(status),
            CommandTermination::Signaled(_)
            | CommandTermination::TimedOut
            | CommandTermination::Cancelled
            | CommandTermination::OutputLimitExceeded => None,
        }
    }
}

/// A generated Bubblewrap command line that is intentionally not executable yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSandboxPlan {
    arguments: Vec<OsString>,
    blocked_reason: &'static str,
}

impl LinuxSandboxPlan {
    /// Returns exact arguments that would follow `/usr/bin/bwrap`.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Returns why the plan cannot authorize execution.
    #[must_use]
    pub const fn blocked_reason(&self) -> &'static str {
        self.blocked_reason
    }

    /// Remains false until mandatory kernel enforcement is actively proven.
    #[must_use]
    pub const fn permits_execution(&self) -> bool {
        false
    }
}

/// Typed command boundary shared by future macOS and Linux launch bridges.
///
/// No production implementation is registered yet. In particular, this module
/// deliberately contains no `std::process::Command` adapter: a path-based host
/// spawn cannot satisfy descriptor-exec, descriptor-relative cwd, inherited-FD
/// closure, or whole-domain cleanup. The contract is exercised with deterministic
/// backends in unit tests and is ready for the signed helper / held Linux launcher
/// to implement without creating an unrestricted fallback.
#[allow(
    dead_code,
    reason = "production dispatch now reaches preparation and the backend's own preflight refusal; everything past that boundary stays unreachable until a platform launcher can satisfy every control"
)]
pub(crate) mod contained_boundary;

/// macOS dedicated-identity containment backend.
/// Launch requires an admitted helper and proof of every required control;
/// unavailable capabilities return typed refusals.
#[cfg(target_os = "macos")]
#[allow(
    dead_code,
    reason = "production dispatch now composes this backend and stops at its transport-unavailable preflight refusal; the launch-path members past that stay exercised only by tests"
)]
pub(crate) mod macos_backend;

/// Linux cgroup-v2 implementation of the contained backend contract.
///
/// The backend composes what already exists: the delegated cgroup-v2 domain,
/// the sealed-memfd image custody the held launcher established, and the
/// supervisor-validated command authority. Its production arm returns a typed
/// capability refusal until the authenticated native command service exists,
/// and its development arm claims only the controls its live canaries proved
/// inside a reserved cgroup leaf, because a backend that cannot enforce a
/// control must never claim it.
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "production dispatch now composes this backend and stops at its service-unavailable preflight refusal; the development arm and the launch path past that stay exercised by the canary suite only"
)]
pub(crate) mod linux_backend;

/// Command-supervisor failure.
#[derive(Debug)]
pub enum SupervisorError {
    /// Authenticated grant or policy validation failed.
    Authority(String),
    /// A command, path, executable, or environment invariant failed.
    InvalidCommand(String),
    /// A required host capability is missing.
    Capability(String),
    /// A resource ceiling cannot be proven.
    UnenforceableLimit(String),
    /// An active containment canary failed.
    Canary(String),
    /// A terminal command-domain cleanup proof failed validation or binding.
    CommandDomainCleanupProof(CommandDomainCleanupProofError),
    /// Immutable complete command-output capture, publication, or readback failed.
    CommandOutputStore(CommandOutputStoreError),
    /// A primary command attempt failed and exact unpublished-output cleanup
    /// independently failed. Both authorities are retained without flattening.
    CommandOutputCleanup {
        /// Original command, supervision, commitment, or capture failure.
        primary: Box<SupervisorError>,
        /// Full exact-custody cleanup failure, including reconciliation source.
        cleanup: Box<CommandOutputStoreError>,
    },
    /// Linux remains blocked on mandatory kernel enforcement.
    LinuxBlocked(&'static str),
    /// Filesystem or process I/O failed.
    Io(io::Error),
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(message) => write!(formatter, "runner authority rejected: {message}"),
            Self::InvalidCommand(message) => write!(formatter, "invalid command: {message}"),
            Self::Capability(message) => write!(formatter, "sandbox capability missing: {message}"),
            Self::UnenforceableLimit(message) => {
                write!(formatter, "resource limit cannot be enforced: {message}")
            }
            Self::Canary(message) => write!(formatter, "sandbox canary failed: {message}"),
            Self::CommandDomainCleanupProof(error) => {
                write!(formatter, "command-domain cleanup proof rejected: {error}")
            }
            Self::CommandOutputStore(error) => {
                write!(formatter, "command-output artifact custody failed: {error}")
            }
            Self::CommandOutputCleanup { primary, cleanup } => write!(
                formatter,
                "{primary}; unpublished command-output custody also failed to close safely: {cleanup}"
            ),
            Self::LinuxBlocked(message) => write!(formatter, "Linux execution blocked: {message}"),
            Self::Io(error) => write!(formatter, "runner I/O failed: {error}"),
        }
    }
}

impl std::error::Error for SupervisorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CommandDomainCleanupProof(error) => Some(error),
            Self::CommandOutputStore(error) => Some(error),
            Self::CommandOutputCleanup { cleanup, .. } => Some(cleanup.as_ref()),
            Self::Io(error) => Some(error),
            Self::Authority(_)
            | Self::InvalidCommand(_)
            | Self::Capability(_)
            | Self::UnenforceableLimit(_)
            | Self::Canary(_)
            | Self::LinuxBlocked(_) => None,
        }
    }
}

impl From<io::Error> for SupervisorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CommandDomainCleanupProofError> for SupervisorError {
    fn from(error: CommandDomainCleanupProofError) -> Self {
        Self::CommandDomainCleanupProof(error)
    }
}

impl From<CommandOutputStoreError> for SupervisorError {
    fn from(error: CommandOutputStoreError) -> Self {
        Self::CommandOutputStore(error)
    }
}

/// An authorized command supervisor holding immutable authority wrappers.
pub struct CommandSupervisor {
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    live_root: PathBuf,
    shadow_root: Option<PathBuf>,
    instance_root: PathBuf,
    home_root: PathBuf,
    temporary_root: PathBuf,
    // Only the macOS Seatbelt canaries read these two roots, and only the macOS
    // arm of `authorize` ever populates them: on every other host `authorize`
    // refuses before the struct is built. Gating them keeps the type honest
    // about which platform's supervisor it is describing.
    #[cfg(target_os = "macos")]
    canary_root: PathBuf,
    #[cfg(target_os = "macos")]
    credential_canary: PathBuf,
    launcher: ExecutableIdentity,
    kill_program: ExecutableIdentity,
    system_profile_identity: FileIdentity,
}

impl CommandSupervisor {
    /// Authenticates authority, prepares private state, and runs active canaries.
    ///
    /// # Errors
    ///
    /// Fails for stale authority, unsafe roots, missing capability, an
    /// unenforceable ceiling, or any failed active canary. Linux is blocked until
    /// Landlock and seccomp enforcement exists and passes active probes.
    // The macOS supervisor owns the grant and policy. Other targets need the
    // allowance because they do not compile that supervisor.
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::needless_pass_by_value,
            reason = "the macOS arm of this function moves both values into the constructed supervisor"
        )
    )]
    pub fn authorize(
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        paths: &SupervisorPaths,
    ) -> Result<Self, SupervisorError> {
        validate_authority(&grant, &policy)?;
        let preflight = inspect_host_sandbox();
        if preflight.disposition() == PreflightDisposition::FailClosed {
            let reasons = preflight
                .checks()
                .iter()
                .filter_map(|check| match check.state() {
                    CapabilityState::Missing(reason) => Some(reason.as_str()),
                    CapabilityState::Detected(_) | CapabilityState::ActiveProbeRequired(_) => None,
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(SupervisorError::Capability(reasons));
        }
        match preflight.platform() {
            HostPlatform::LinuxBubblewrap => {
                return Err(SupervisorError::LinuxBlocked(LINUX_BLOCK_REASON));
            }
            HostPlatform::Unsupported => {
                return Err(SupervisorError::Capability(
                    "no production sandbox backend exists for this platform".into(),
                ));
            }
            HostPlatform::MacOsSeatbelt => {}
        }
        validate_resource_limits(policy.contract().resource_limits)?;

        #[cfg(not(target_os = "macos"))]
        {
            let _ = paths;
            Err(SupervisorError::Capability(
                "macOS Seatbelt backend selected on a non-macOS build".into(),
            ))
        }
        #[cfg(target_os = "macos")]
        {
            let live_root = grant.identity().canonical_root().to_path_buf();
            let (state_root, shadow_root) = validate_supervisor_paths(paths, &live_root, &policy)?;
            let instance_root = create_private_instance(&state_root)?;
            let prepared = prepare_private_layout(&instance_root);
            let (home_root, temporary_root, canary_root, credential_canary) = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    let _ = fs::remove_dir_all(&instance_root);
                    return Err(error);
                }
            };
            let constructed = (|| {
                let supervisor = Self {
                    grant,
                    policy,
                    live_root,
                    shadow_root,
                    instance_root: instance_root.clone(),
                    home_root,
                    temporary_root,
                    canary_root,
                    credential_canary,
                    launcher: ExecutableIdentity::capture(Path::new(MACOS_SANDBOX_EXEC))?,
                    kill_program: ExecutableIdentity::capture(Path::new(KILL_PROGRAM))?,
                    system_profile_identity: FileIdentity::capture(Path::new(
                        MACOS_SYSTEM_PROFILE,
                    ))?,
                };
                supervisor.validate_fixed_host_identity()?;
                let profile = supervisor.build_macos_profile(Path::new(CANARY_TRUE))?;
                supervisor.run_active_canaries(&profile)?;
                Err(SupervisorError::Capability(
                    LEGACY_MACOS_LAUNCH_BLOCK_REASON.into(),
                ))
            })();
            if constructed.is_err() {
                let _ = fs::remove_dir_all(&instance_root);
            }
            constructed
        }
    }

    /// Executes one exact no-shell command under the authenticated policy.
    ///
    /// # Errors
    ///
    /// Fails before spawn for stale authority, identity drift, unsafe cwd or
    /// environment, failed canaries, or capability drift. Runtime termination is
    /// returned as evidence after process-group cleanup.
    pub fn execute(
        &self,
        spec: &CommandSpec,
        cancellation: &CancellationToken,
    ) -> Result<CommandResult, SupervisorError> {
        if cancellation.is_cancelled() {
            return Err(SupervisorError::InvalidCommand(
                "cancellation was already requested before spawn".into(),
            ));
        }
        spec.validate()
            .map_err(|error| SupervisorError::InvalidCommand(error.to_string()))?;
        validate_arguments(spec)?;
        reject_explicit_shell(&spec.program)?;
        validate_authority(&self.grant, &self.policy)?;
        self.validate_fixed_host_identity()?;

        let environment = self.build_environment()?;
        let executable = resolve_executable(&spec.program, &environment)?;
        reject_explicit_shell_path(&executable.canonical_path)?;
        let working_directory = self.resolve_working_directory(spec)?;
        let profile = self.build_macos_profile(&executable.canonical_path)?;
        let sandbox_evidence = self.run_active_canaries(&profile)?;

        let mut command = seatbelt_command(
            &profile,
            &executable.canonical_path,
            &spec.arguments,
            &working_directory,
            &environment,
        );
        let limits = self.policy.contract().resource_limits;
        let raw = spawn_monitored(
            &mut command,
            limits,
            cancellation,
            &self.kill_program,
            || {
                // Final operation before `spawn`: never rely on a prior check.
                validate_authority(&self.grant, &self.policy)?;
                self.validate_fixed_host_identity()?;
                executable.validate_current()?;
                Ok(())
            },
        )?;
        let (stdout, stderr) =
            bound_retained_output(raw.stdout, raw.stderr, limits.max_output_bytes);
        let output_digest = combined_output_digest(&stdout, &stderr);
        Ok(CommandResult {
            command: spec.clone(),
            policy_hash: self.policy.contract().policy_hash.clone(),
            resolved_program: executable.canonical_path,
            working_directory,
            termination: raw.termination,
            stdout,
            stderr,
            output_digest,
            duration_ms: raw.duration_ms,
            sandbox_evidence,
        })
    }

    fn build_environment(&self) -> Result<ScrubbedEnvironment, SupervisorError> {
        let mut environment = EnvironmentPolicy::empty().scrub([] as [(&str, &str); 0]);
        for variable in &self.policy.contract().environment {
            if is_reserved_policy_environment(&variable.name) {
                return Err(SupervisorError::InvalidCommand(format!(
                    "policy environment variable `{}` is a host channel or supervisor-owned value",
                    variable.name
                )));
            }
            environment
                .set_trusted_override(variable.name.clone(), variable.value.clone())
                .map_err(|error| SupervisorError::InvalidCommand(error.to_string()))?;
        }
        for (name, value) in [
            ("HOME", self.home_root.as_os_str()),
            ("TMPDIR", self.temporary_root.as_os_str()),
            ("TMP", self.temporary_root.as_os_str()),
            ("TEMP", self.temporary_root.as_os_str()),
        ] {
            environment
                .set_trusted_override(name, value)
                .map_err(|error| SupervisorError::InvalidCommand(error.to_string()))?;
        }
        Ok(environment)
    }

    fn resolve_working_directory(&self, spec: &CommandSpec) -> Result<PathBuf, SupervisorError> {
        let execution_root = match self.policy.contract().mutation_mode {
            MutationMode::ReadOnly => &self.live_root,
            MutationMode::ShadowWorkspace => self.shadow_root.as_ref().ok_or_else(|| {
                SupervisorError::InvalidCommand("shadow policy has no private shadow root".into())
            })?,
        };
        let requested = execution_root.join(&spec.working_directory);
        let canonical = fs::canonicalize(&requested).map_err(|error| {
            SupervisorError::InvalidCommand(format!(
                "cannot canonicalize working directory {}: {error}",
                requested.display()
            ))
        })?;
        if canonical != requested || !canonical.starts_with(execution_root) {
            return Err(SupervisorError::InvalidCommand(
                "working directory must not traverse a symlink or leave the execution root".into(),
            ));
        }
        if !fs::metadata(&canonical)?.is_dir() {
            return Err(SupervisorError::InvalidCommand(
                "working directory is not a directory".into(),
            ));
        }
        if contains_git_component(&spec.working_directory) {
            return Err(SupervisorError::InvalidCommand(
                "working directory cannot enter protected .git metadata".into(),
            ));
        }
        Ok(canonical)
    }

    fn validate_fixed_host_identity(&self) -> Result<(), SupervisorError> {
        self.launcher.validate_current()?;
        self.kill_program.validate_current()?;
        self.system_profile_identity.validate_current()?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn build_macos_profile(&self, program: &Path) -> Result<String, SupervisorError> {
        let executables = BTreeSet::from([
            canonical_existing_path(Path::new(CANARY_TRUE))?,
            canonical_existing_path(Path::new(CANARY_CAT))?,
            canonical_existing_path(Path::new(CANARY_TOUCH))?,
            canonical_existing_path(Path::new(CANARY_CURL))?,
            canonical_existing_path(Path::new(CANARY_FIND))?,
            program.to_path_buf(),
        ]);
        let mut readable = scope_paths(&self.live_root, &self.policy.contract().read_scopes);
        if let Some(shadow_root) = &self.shadow_root {
            readable.extend(scope_paths(
                shadow_root,
                &self.policy.contract().read_scopes,
            ));
        }
        readable.push(self.home_root.clone());
        readable.push(self.temporary_root.clone());
        let mut writable = vec![self.home_root.clone(), self.temporary_root.clone()];
        if let Some(shadow_root) = &self.shadow_root {
            writable.extend(scope_paths(
                shadow_root,
                &self.policy.contract().write_scopes,
            ));
        }
        let mut denied = credential_roots();
        push_denied_root(&mut denied, self.live_root.join(".git"));
        if let Some(shadow_root) = &self.shadow_root {
            push_denied_root(&mut denied, shadow_root.join(".git"));
        }
        denied.push(self.canary_root.clone());
        render_seatbelt_profile(
            &executables,
            &readable,
            &writable,
            &denied,
            &self.live_root,
            self.policy.contract().network == ExecutionNetwork::FullForAction,
        )
    }

    #[cfg(not(target_os = "macos"))]
    #[expect(
        clippy::unused_self,
        reason = "the non-macOS arm must keep the macOS arm's signature; `execute` calls it as a method on either host and a free function here would make the two arms diverge"
    )]
    fn build_macos_profile(&self, _program: &Path) -> Result<String, SupervisorError> {
        Err(SupervisorError::Capability(
            "Seatbelt profiles are available only on macOS".into(),
        ))
    }

    #[cfg(target_os = "macos")]
    #[expect(
        clippy::too_many_lines,
        reason = "ordered active controls and restrictive canaries stay adjacent for security review"
    )]
    fn run_active_canaries(&self, profile: &str) -> Result<SandboxEvidence, SupervisorError> {
        validate_authority(&self.grant, &self.policy)?;
        self.validate_fixed_host_identity()?;
        let control_profile = "(version 1) (allow default)";
        let environment = self.build_environment()?;
        let cancellation = CancellationToken::new();
        let limits = ResourceLimits {
            wall_time_ms: u64::try_from(CANARY_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            max_output_bytes: CANARY_OUTPUT_LIMIT,
            max_processes: 1,
            max_memory_bytes: None,
        };

        let escape_path = self.canary_root.join("escape-created");
        remove_if_present(&escape_path)?;
        let control = run_canary_process(
            control_profile,
            Path::new(CANARY_TOUCH),
            &[escape_path.as_os_str().to_owned()],
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if !normal_success(&control) || !escape_path.is_file() {
            return Err(SupervisorError::Canary(
                "escape control could not create its private sentinel".into(),
            ));
        }
        fs::remove_file(&escape_path)?;
        let restricted = run_canary_process(
            profile,
            Path::new(CANARY_TOUCH),
            &[escape_path.as_os_str().to_owned()],
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if normal_success(&restricted) || escape_path.exists() {
            return Err(SupervisorError::Canary(
                "Seatbelt permitted a write outside shadow and private scratch roots".into(),
            ));
        }

        let control = run_canary_process(
            control_profile,
            Path::new(CANARY_CAT),
            &[self.credential_canary.as_os_str().to_owned()],
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if !normal_success(&control) || control.stdout.retained != CREDENTIAL_CANARY_BYTES {
            return Err(SupervisorError::Canary(
                "credential control could not read its synthetic sentinel".into(),
            ));
        }
        let restricted = run_canary_process(
            profile,
            Path::new(CANARY_CAT),
            &[self.credential_canary.as_os_str().to_owned()],
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if normal_success(&restricted) || restricted.stdout.retained == CREDENTIAL_CANARY_BYTES {
            return Err(SupervisorError::Canary(
                "Seatbelt permitted a synthetic credential-root read".into(),
            ));
        }

        let credential_file = File::open(&self.credential_canary)?;
        #[cfg(unix)]
        let descriptor_path = PathBuf::from(format!(
            "/dev/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&credential_file)
        ));
        let descriptor = run_canary_process(
            control_profile,
            Path::new(CANARY_CAT),
            &[descriptor_path.into_os_string()],
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if normal_success(&descriptor) || descriptor.stdout.retained == CREDENTIAL_CANARY_BYTES {
            return Err(SupervisorError::Canary(
                "a supervisor file descriptor leaked through exec".into(),
            ));
        }
        drop(credential_file);

        let profile_check = run_canary_process(
            profile,
            Path::new(CANARY_TRUE),
            &[],
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if !normal_success(&profile_check) {
            return Err(SupervisorError::Canary(
                "the restrictive profile could not execute its viability canary".into(),
            ));
        }
        let fork_sentinel = self.temporary_root.join("fork-canary");
        fs::write(&fork_sentinel, b"fork canary\n")?;
        let fork_arguments = [
            fork_sentinel.as_os_str().to_owned(),
            OsString::from("-exec"),
            OsString::from(CANARY_TRUE),
            OsString::from("{}"),
            OsString::from(";"),
        ];
        let fork_control = run_canary_process(
            control_profile,
            Path::new(CANARY_FIND),
            &fork_arguments,
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if !normal_success(&fork_control) {
            return Err(SupervisorError::Canary(
                "process-fork control could not launch its fixed child".into(),
            ));
        }
        let fork_restricted = run_canary_process(
            profile,
            Path::new(CANARY_FIND),
            &fork_arguments,
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
        )?;
        if normal_success(&fork_restricted) {
            return Err(SupervisorError::Canary(
                "Seatbelt permitted process-fork despite max_processes=1".into(),
            ));
        }
        fs::remove_file(fork_sentinel)?;
        let network_expected = self.policy.contract().network == ExecutionNetwork::FullForAction;
        run_network_control_and_canary(
            profile,
            &self.instance_root,
            &environment,
            limits,
            &cancellation,
            &self.kill_program,
            network_expected,
        )?;
        self.run_inherited_descriptor_canary(profile, &environment)?;
        self.validate_fixed_host_identity()?;
        validate_authority(&self.grant, &self.policy)?;
        Ok(SandboxEvidence {
            profile_digest: hash_bytes(profile.as_bytes()),
            launcher_digest: self.launcher.content_digest.clone(),
            system_profile_digest: self.system_profile_identity.content_digest.clone(),
            network_enabled: network_expected,
            checked_at_unix_ms: unix_time_ms()?,
        })
    }

    #[cfg(target_os = "macos")]
    fn run_inherited_descriptor_canary(
        &self,
        profile: &str,
        environment: &ScrubbedEnvironment,
    ) -> Result<(), SupervisorError> {
        let run = |candidate_profile: &str| -> Result<std::process::Output, SupervisorError> {
            let credential = File::open(&self.credential_canary)?;
            let mut command = Command::new(&self.launcher.canonical_path);
            command
                .arg("-p")
                .arg(candidate_profile)
                .arg(CANARY_CAT)
                .current_dir(&self.instance_root)
                .stdin(Stdio::from(credential))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            environment.apply_to(&mut command);
            command.output().map_err(SupervisorError::Io)
        };
        let control = run("(version 1) (allow default)")?;
        if !control.status.success() || control.stdout != CREDENTIAL_CANARY_BYTES {
            return Err(SupervisorError::Canary(
                "inherited-descriptor control could not read its synthetic sentinel".into(),
            ));
        }
        let restricted = run(profile)?;
        if restricted.status.success() && restricted.stdout == CREDENTIAL_CANARY_BYTES {
            return Err(SupervisorError::Capability(
                MACOS_INHERITED_FD_BLOCK_REASON.into(),
            ));
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    #[expect(
        clippy::unused_self,
        reason = "the non-macOS arm must keep the macOS arm's signature; `execute` calls it as a method on either host and a free function here would make the two arms diverge"
    )]
    fn run_active_canaries(&self, _profile: &str) -> Result<SandboxEvidence, SupervisorError> {
        Err(SupervisorError::LinuxBlocked(LINUX_BLOCK_REASON))
    }
}

impl Drop for CommandSupervisor {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.instance_root);
    }
}

/// Generates the namespace and mount arguments for the planned Linux backend.
///
/// The plan authenticates both wrappers and includes user/mount/PID/IPC/UTS/
/// cgroup namespaces, an isolated network namespace unless jointly authorized,
/// a read-only live workspace, only the private shadow as writable project state,
/// and an empty environment. It never authorizes execution because Landlock and
/// seccomp filters are not yet installed and actively proven.
///
/// # Errors
///
/// Fails for stale authority, inconsistent roots, invalid command contracts, or
/// an unsafe cwd.
pub fn plan_linux_bubblewrap(
    grant: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    paths: &SupervisorPaths,
    spec: &CommandSpec,
) -> Result<LinuxSandboxPlan, SupervisorError> {
    validate_authority(grant, policy)?;
    spec.validate()
        .map_err(|error| SupervisorError::InvalidCommand(error.to_string()))?;
    validate_arguments(spec)?;
    reject_explicit_shell(&spec.program)?;
    let live = grant.identity().canonical_root();
    let shadow = match policy.contract().mutation_mode {
        MutationMode::ReadOnly => {
            if paths.shadow_root.is_some() {
                return Err(SupervisorError::InvalidCommand(
                    "read-only Linux plan must not include a writable shadow".into(),
                ));
            }
            None
        }
        MutationMode::ShadowWorkspace => Some(paths.shadow_root.as_ref().ok_or_else(|| {
            SupervisorError::InvalidCommand("shadow Linux plan requires a shadow root".into())
        })?),
    };
    let execution_root = shadow.map_or(live, PathBuf::as_path);
    let cwd = execution_root.join(&spec.working_directory);
    if !cwd.starts_with(execution_root) || contains_git_component(&spec.working_directory) {
        return Err(SupervisorError::InvalidCommand(
            "Linux working directory leaves the execution root or enters .git".into(),
        ));
    }
    let mut arguments: Vec<OsString> = [
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if policy.contract().network == ExecutionNetwork::None {
        arguments.push("--unshare-net".into());
    }
    arguments.extend([
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        "--ro-bind".into(),
        "/bin".into(),
        "/bin".into(),
        "--ro-bind".into(),
        live.as_os_str().to_owned(),
        live.as_os_str().to_owned(),
    ]);
    if let Some(shadow) = shadow {
        arguments.extend([
            "--bind".into(),
            shadow.as_os_str().to_owned(),
            shadow.as_os_str().to_owned(),
        ]);
    }
    arguments.extend([
        "--tmpfs".into(),
        "/tmp".into(),
        "--chdir".into(),
        cwd.into_os_string(),
        "--clearenv".into(),
    ]);
    for variable in &policy.contract().environment {
        if is_reserved_policy_environment(&variable.name) {
            return Err(SupervisorError::InvalidCommand(format!(
                "policy environment variable `{}` is reserved",
                variable.name
            )));
        }
        arguments.extend([
            "--setenv".into(),
            OsString::from(&variable.name),
            OsString::from(&variable.value),
        ]);
    }
    arguments.push("--".into());
    arguments.push(OsString::from(&spec.program));
    arguments.extend(spec.arguments.iter().map(OsString::from));
    Ok(LinuxSandboxPlan {
        arguments,
        blocked_reason: LINUX_BLOCK_REASON,
    })
}

fn validate_authority(
    grant: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
) -> Result<(), SupervisorError> {
    grant
        .validate_integrity()
        .map_err(|error| SupervisorError::Authority(error.to_string()))?;
    policy
        .validate_integrity(grant)
        .map_err(|error| SupervisorError::Authority(error.to_string()))
}

fn validate_resource_limits(limits: ResourceLimits) -> Result<(), SupervisorError> {
    if limits.max_output_bytes > MAX_CAPTURE_LIMIT {
        return Err(SupervisorError::UnenforceableLimit(format!(
            "max_output_bytes exceeds the supervisor's bounded {MAX_CAPTURE_LIMIT}-byte capture ceiling"
        )));
    }
    if limits.max_processes != 1 {
        return Err(SupervisorError::UnenforceableLimit(
            "Seatbelt can currently prove only max_processes=1 by actively denying process-fork; a larger finite ceiling requires an audited cgroup/job-style launcher"
                .into(),
        ));
    }
    if limits.max_memory_bytes.is_some() {
        return Err(SupervisorError::UnenforceableLimit(
            "the safe standard-library launcher cannot install a per-process address-space limit; specifying max_memory_bytes blocks execution"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn validate_supervisor_paths(
    paths: &SupervisorPaths,
    live_root: &Path,
    policy: &CompiledExecutionPolicy,
) -> Result<(PathBuf, Option<PathBuf>), SupervisorError> {
    let state_root = canonical_private_directory(&paths.private_state_root)?;
    if state_root.starts_with(live_root) {
        return Err(SupervisorError::InvalidCommand(
            "private runner state cannot be inside the live workspace".into(),
        ));
    }
    let shadow_root = match policy.contract().mutation_mode {
        MutationMode::ReadOnly => {
            if paths.shadow_root.is_some() {
                return Err(SupervisorError::InvalidCommand(
                    "read-only policy must not supply a shadow root".into(),
                ));
            }
            None
        }
        MutationMode::ShadowWorkspace => {
            let shadow = paths.shadow_root.as_ref().ok_or_else(|| {
                SupervisorError::InvalidCommand("shadow policy requires a shadow root".into())
            })?;
            let shadow = canonical_private_directory(shadow)?;
            if shadow.starts_with(live_root) || live_root.starts_with(&shadow) {
                return Err(SupervisorError::InvalidCommand(
                    "private shadow must be disjoint from the live workspace".into(),
                ));
            }
            Some(shadow)
        }
    };
    Ok((state_root, shadow_root))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn canonical_private_directory(path: &Path) -> Result<PathBuf, SupervisorError> {
    if !path.is_absolute() {
        return Err(SupervisorError::InvalidCommand(format!(
            "private directory {} is not absolute",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(SupervisorError::InvalidCommand(format!(
            "private path {} is not a real directory",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SupervisorError::InvalidCommand(format!(
            "private directory {} permits group or other access",
            path.display()
        )));
    }
    fs::canonicalize(path).map_err(SupervisorError::Io)
}

#[cfg(target_os = "macos")]
fn create_private_instance(state_root: &Path) -> Result<PathBuf, SupervisorError> {
    for _ in 0..64 {
        let sequence = NEXT_PRIVATE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = state_root.join(format!(
            "command-supervisor-{}-{sequence}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return fs::canonicalize(path).map_err(SupervisorError::Io),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(SupervisorError::Io(error)),
        }
    }
    Err(SupervisorError::InvalidCommand(
        "could not allocate a unique private supervisor directory".into(),
    ))
}

#[cfg(target_os = "macos")]
fn prepare_private_layout(
    instance_root: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf), SupervisorError> {
    let home = instance_root.join("home");
    let temporary = instance_root.join("tmp");
    let canary = instance_root.join("credential-canary-root");
    for directory in [&home, &temporary, &canary] {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(directory)?;
    }
    let credential = canary.join("token");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&credential)?;
    file.write_all(CREDENTIAL_CANARY_BYTES)?;
    file.sync_all()?;
    Ok((home, temporary, canary, credential))
}

fn validate_arguments(spec: &CommandSpec) -> Result<(), SupervisorError> {
    if spec.program.as_bytes().contains(&0)
        || spec
            .arguments
            .iter()
            .any(|argument| argument.as_bytes().contains(&0))
    {
        return Err(SupervisorError::InvalidCommand(
            "program and arguments must not contain NUL".into(),
        ));
    }
    Ok(())
}

fn reject_explicit_shell(program: &str) -> Result<(), SupervisorError> {
    let path = Path::new(program);
    if !path.is_absolute() && path.components().count() != 1 {
        return Err(SupervisorError::InvalidCommand(
            "program must be an absolute path or a bare executable name".into(),
        ));
    }
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or(program);
    if is_shell_name(name) {
        return Err(SupervisorError::InvalidCommand(format!(
            "shell executable `{name}` is rejected by the no-shell supervisor"
        )));
    }
    Ok(())
}

fn reject_explicit_shell_path(program: &Path) -> Result<(), SupervisorError> {
    let name = program.file_name().and_then(OsStr::to_str).ok_or_else(|| {
        SupervisorError::InvalidCommand("executable basename is not UTF-8".into())
    })?;
    if is_shell_name(name) {
        return Err(SupervisorError::InvalidCommand(format!(
            "resolved shell executable `{}` is forbidden",
            program.display()
        )));
    }
    Ok(())
}

fn is_shell_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "csh" | "tcsh" | "fish" | "nu" | "xonsh"
    )
}

fn is_reserved_policy_environment(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "DBUS_SESSION_BUS_ADDRESS"
            | "CARGO_HOME"
            | "DISPLAY"
            | "DOCKER_CONFIG"
            | "DOCKER_HOST"
            | "GIT_ASKPASS"
            | "HOME"
            | "GNUPGHOME"
            | "OLDPWD"
            | "PWD"
            | "RUSTUP_HOME"
            | "SECURITYSESSIONID"
            | "SHELL"
            | "SSH_ASKPASS"
            | "SSH_AUTH_SOCK"
            | "TEMP"
            | "TMP"
            | "TMPDIR"
            | "WAYLAND_DISPLAY"
            | "XAUTHORITY"
            | "XDG_RUNTIME_DIR"
            | "XDG_CACHE_HOME"
            | "XDG_CONFIG_HOME"
            | "XDG_DATA_HOME"
            | "__CF_USER_TEXT_ENCODING"
    )
}

fn contains_git_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(component, Component::Normal(name)
            if name.to_str().is_some_and(|text| text.eq_ignore_ascii_case(".git")))
    })
}

fn scope_paths(root: &Path, scopes: &[PathScope]) -> Vec<PathBuf> {
    scopes
        .iter()
        .map(|scope| match scope {
            PathScope::Workspace => root.to_path_buf(),
            PathScope::Relative(path) => root.join(path),
        })
        .collect()
}

#[derive(Clone, Debug)]
struct FileIdentity {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    content_digest: Digest,
}

impl FileIdentity {
    fn capture(path: &Path) -> Result<Self, SupervisorError> {
        let canonical_path = canonical_existing_path(path)?;
        let metadata = fs::metadata(&canonical_path)?;
        if !metadata.is_file() {
            return Err(SupervisorError::Capability(format!(
                "{} is not a regular file",
                canonical_path.display()
            )));
        }
        #[cfg(unix)]
        {
            Ok(Self {
                requested_path: path.to_path_buf(),
                canonical_path: canonical_path.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                content_digest: hash_file(&canonical_path)?,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(SupervisorError::Capability(
                "file identity requires Unix metadata".into(),
            ))
        }
    }

    fn validate_current(&self) -> Result<(), SupervisorError> {
        let current = Self::capture(&self.requested_path)?;
        if self.canonical_path != current.canonical_path
            || self.device != current.device
            || self.inode != current.inode
            || self.length != current.length
            || self.modified_seconds != current.modified_seconds
            || self.modified_nanoseconds != current.modified_nanoseconds
            || self.content_digest != current.content_digest
        {
            return Err(SupervisorError::Capability(format!(
                "file identity changed after authorization: {}",
                self.requested_path.display()
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ExecutableIdentity {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    content_digest: Digest,
}

impl ExecutableIdentity {
    fn capture(path: &Path) -> Result<Self, SupervisorError> {
        let file = FileIdentity::capture(path)?;
        let metadata = fs::metadata(&file.canonical_path)?;
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(SupervisorError::InvalidCommand(format!(
                "{} is not executable",
                file.canonical_path.display()
            )));
        }
        Ok(Self {
            requested_path: file.requested_path,
            canonical_path: file.canonical_path,
            device: file.device,
            inode: file.inode,
            length: file.length,
            modified_seconds: file.modified_seconds,
            modified_nanoseconds: file.modified_nanoseconds,
            content_digest: file.content_digest,
        })
    }

    fn validate_current(&self) -> Result<(), SupervisorError> {
        let current = Self::capture(&self.requested_path)?;
        if self.canonical_path != current.canonical_path
            || self.device != current.device
            || self.inode != current.inode
            || self.length != current.length
            || self.modified_seconds != current.modified_seconds
            || self.modified_nanoseconds != current.modified_nanoseconds
            || self.content_digest != current.content_digest
        {
            return Err(SupervisorError::Capability(format!(
                "executable identity changed after authorization: {}",
                self.requested_path.display()
            )));
        }
        Ok(())
    }
}

fn resolve_executable(
    program: &str,
    environment: &ScrubbedEnvironment,
) -> Result<ExecutableIdentity, SupervisorError> {
    let path = Path::new(program);
    if path.is_absolute() {
        return ExecutableIdentity::capture(path);
    }
    if path.components().count() != 1 {
        return Err(SupervisorError::InvalidCommand(
            "relative executable paths with separators are forbidden".into(),
        ));
    }
    let path_value = environment
        .variables()
        .get(OsStr::new("PATH"))
        .ok_or_else(|| {
            SupervisorError::InvalidCommand(
                "a bare executable name requires an explicit controlled PATH".into(),
            )
        })?;
    let mut candidate = None;
    for directory in std::env::split_paths(path_value) {
        if !directory.is_absolute()
            || directory.components().any(|component| {
                component == Component::CurDir || component == Component::ParentDir
            })
        {
            return Err(SupervisorError::InvalidCommand(
                "PATH must contain only normalized absolute directories".into(),
            ));
        }
        let possible = directory.join(program);
        if possible.is_file() {
            candidate = Some(possible);
            break;
        }
    }
    let candidate = candidate.ok_or_else(|| {
        SupervisorError::InvalidCommand(format!(
            "executable `{program}` was not found on the controlled PATH"
        ))
    })?;
    ExecutableIdentity::capture(&candidate)
}

fn canonical_existing_path(path: &Path) -> Result<PathBuf, SupervisorError> {
    fs::canonicalize(path).map_err(|error| {
        SupervisorError::Capability(format!(
            "cannot canonicalize required path {}: {error}",
            path.display()
        ))
    })
}

/// Pushes one deny root and, when it resolves elsewhere, its real location.
///
/// Seatbelt path filters match the **resolved** vnode path. A deny written
/// against a symlink's logical name therefore leaves the content readable at
/// its target. Every deny site must include both locations.
///
/// A path that does not resolve still has a parent. Canonicalizing that parent
/// and re-joining the leaf closes the case where `.git` is absent under a
/// symlinked workspace: Seatbelt would otherwise match only the logical name
/// and leave the content readable at the resolved location once the leaf
/// appears. A parent that itself does not resolve contributes only the
/// logical name, there is then no second location to close.
#[cfg(target_os = "macos")]
fn push_denied_root(roots: &mut Vec<PathBuf>, lexical: PathBuf) {
    if let Ok(canonical) = fs::canonicalize(&lexical) {
        if canonical != lexical {
            roots.push(canonical);
        }
    } else if let Some(parent) = lexical.parent()
        && let Some(name) = lexical.file_name()
        && let Ok(canonical_parent) = fs::canonicalize(parent)
    {
        let resolved = canonical_parent.join(name);
        if resolved != lexical {
            roots.push(resolved);
        }
    }
    roots.push(lexical);
}

#[cfg(target_os = "macos")]
fn credential_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/Library/Keychains"),
        PathBuf::from("/private/etc/ssh"),
        PathBuf::from("/private/var/db/SystemKey"),
    ];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from)
        && home.is_absolute()
    {
        for relative in [
            ".aws",
            ".azure",
            ".config/gcloud",
            ".config/gh",
            ".docker",
            ".gnupg",
            ".kube",
            ".netrc",
            ".npmrc",
            ".ssh",
            "Library/Keychains",
        ] {
            push_denied_root(&mut roots, home.join(relative));
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

#[cfg(target_os = "macos")]
fn render_seatbelt_profile(
    executables: &BTreeSet<PathBuf>,
    readable: &[PathBuf],
    writable: &[PathBuf],
    denied: &[PathBuf],
    live_root: &Path,
    network_enabled: bool,
) -> Result<String, SupervisorError> {
    let mut profile = String::from(
        "(version 1)\n(deny default)\n(import \"system.sb\")\n(allow signal (target self))\n(deny process-fork)\n",
    );
    append_path_rule(
        &mut profile,
        "allow",
        "process-exec",
        "literal",
        executables.iter().map(PathBuf::as_path),
    )?;
    append_path_rule(
        &mut profile,
        "allow",
        "file-map-executable",
        "literal",
        executables.iter().map(PathBuf::as_path),
    )?;
    append_path_rule(
        &mut profile,
        "allow",
        "file-read* file-test-existence",
        "literal",
        executables.iter().map(PathBuf::as_path),
    )?;
    profile.push_str("(allow file-read-metadata file-test-existence)\n");
    append_path_rule(
        &mut profile,
        "allow",
        "file-read* file-test-existence",
        "subpath",
        readable.iter().map(PathBuf::as_path),
    )?;
    append_path_rule(
        &mut profile,
        "allow",
        "file-write*",
        "subpath",
        writable.iter().map(PathBuf::as_path),
    )?;
    append_path_rule(&mut profile, "deny", "file-write*", "subpath", [live_root])?;
    append_path_rule(
        &mut profile,
        "deny",
        "file-read* file-write*",
        "subpath",
        denied.iter().map(PathBuf::as_path),
    )?;
    // Fixed, non-user-derived regex blocks nested repositories as well as the
    // workspace-root `.git`; path text is never interpolated into this rule.
    profile.push_str("(deny file-read* file-write* (regex #\"/\\.git(/|$)\"))\n");
    for forbidden_program in [
        "/usr/bin/security",
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "/usr/bin/sftp",
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
    ] {
        append_path_rule(
            &mut profile,
            "deny",
            "process-exec",
            "literal",
            [Path::new(forbidden_program)],
        )?;
    }
    profile.push_str(if network_enabled {
        "(allow network*)\n"
    } else {
        "(deny network*)\n"
    });
    Ok(profile)
}

#[cfg(target_os = "macos")]
fn append_path_rule<'a, I>(
    profile: &mut String,
    disposition: &str,
    operations: &str,
    filter: &str,
    paths: I,
) -> Result<(), SupervisorError>
where
    I: IntoIterator<Item = &'a Path>,
{
    let rendered = paths
        .into_iter()
        .map(|path| seatbelt_quote(path).map(|path| format!("({filter} {path})")))
        .collect::<Result<Vec<_>, _>>()?;
    if rendered.is_empty() {
        return Ok(());
    }
    profile.push('(');
    profile.push_str(disposition);
    profile.push(' ');
    profile.push_str(operations);
    for path in rendered {
        profile.push(' ');
        profile.push_str(&path);
    }
    profile.push_str(")\n");
    Ok(())
}

#[cfg(target_os = "macos")]
fn seatbelt_quote(path: &Path) -> Result<String, SupervisorError> {
    let text = path.to_str().ok_or_else(|| {
        SupervisorError::InvalidCommand(format!("Seatbelt path is not UTF-8: {}", path.display()))
    })?;
    if text.chars().any(char::is_control) {
        return Err(SupervisorError::InvalidCommand(
            "Seatbelt paths cannot contain control characters".into(),
        ));
    }
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn seatbelt_command(
    profile: &str,
    program: &Path,
    arguments: &[String],
    working_directory: &Path,
    environment: &ScrubbedEnvironment,
) -> Command {
    let mut command = Command::new(MACOS_SANDBOX_EXEC);
    command.arg("-p").arg(profile).arg(program).args(arguments);
    command.current_dir(working_directory);
    environment.apply_to(&mut command);
    command
}

#[cfg(target_os = "macos")]
#[expect(
    clippy::too_many_arguments,
    reason = "canary runner receives every security-sensitive input explicitly"
)]
fn run_canary_process(
    profile: &str,
    program: &Path,
    arguments: &[OsString],
    working_directory: &Path,
    environment: &ScrubbedEnvironment,
    limits: ResourceLimits,
    cancellation: &CancellationToken,
    kill_program: &ExecutableIdentity,
) -> Result<RawProcessResult, SupervisorError> {
    let mut command = Command::new(MACOS_SANDBOX_EXEC);
    command.arg("-p").arg(profile).arg(program).args(arguments);
    command.current_dir(working_directory);
    environment.apply_to(&mut command);
    spawn_monitored(&mut command, limits, cancellation, kill_program, || Ok(()))
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn run_network_control_and_canary(
    restrictive_profile: &str,
    working_directory: &Path,
    environment: &ScrubbedEnvironment,
    limits: ResourceLimits,
    cancellation: &CancellationToken,
    kill_program: &ExecutableIdentity,
    network_expected: bool,
) -> Result<(), SupervisorError> {
    if !run_network_canary(
        "(version 1) (allow default)",
        working_directory,
        environment,
        limits,
        cancellation,
        kill_program,
    )? {
        return Err(SupervisorError::Canary(
            "network control could not reach its private loopback listener".into(),
        ));
    }
    let restricted_connected = run_network_canary(
        restrictive_profile,
        working_directory,
        environment,
        limits,
        cancellation,
        kill_program,
    )?;
    if restricted_connected != network_expected {
        return Err(SupervisorError::Canary(if network_expected {
            "network was jointly authorized but the profile did not prove loopback access".into()
        } else {
            "network was denied but the profile reached a loopback listener".into()
        }));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_network_canary(
    profile: &str,
    working_directory: &Path,
    environment: &ScrubbedEnvironment,
    limits: ResourceLimits,
    cancellation: &CancellationToken,
    kill_program: &ExecutableIdentity,
) -> Result<bool, SupervisorError> {
    use std::net::TcpListener;

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let accepted = Arc::new(AtomicBool::new(false));
    let accepted_for_thread = Arc::clone(&accepted);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let server = thread::spawn(move || {
        let deadline = Instant::now() + CANARY_TIMEOUT;
        while Instant::now() < deadline && !stop_for_thread.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    accepted_for_thread.store(true, Ordering::Release);
                    let mut request = [0_u8; 512];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(_) => return,
            }
        }
    });
    let url = format!("http://127.0.0.1:{}/", address.port());
    let result = run_canary_process(
        profile,
        Path::new(CANARY_CURL),
        &[
            "--silent".into(),
            "--show-error".into(),
            "--max-time".into(),
            "2".into(),
            "--output".into(),
            "/dev/null".into(),
            url.into(),
        ],
        working_directory,
        environment,
        limits,
        cancellation,
        kill_program,
    )?;
    stop.store(true, Ordering::Release);
    server
        .join()
        .map_err(|_| SupervisorError::Canary("network canary server panicked".into()))?;
    Ok(normal_success(&result) && accepted.load(Ordering::Acquire))
}

// Read only by the macOS Seatbelt canaries, which are the only callers that
// distinguish "the control process exited 0" from any other termination.
#[cfg(target_os = "macos")]
fn normal_success(result: &RawProcessResult) -> bool {
    result.termination == CommandTermination::Exited(0)
}

#[derive(Debug)]
struct StreamCapture {
    retained: Vec<u8>,
    complete_digest: Digest,
    complete_length: u64,
}

#[derive(Debug)]
struct RawProcessResult {
    termination: CommandTermination,
    stdout: StreamCapture,
    stderr: StreamCapture,
    duration_ms: u64,
}

fn spawn_monitored<F>(
    command: &mut Command,
    limits: ResourceLimits,
    cancellation: &CancellationToken,
    kill_program: &ExecutableIdentity,
    before_spawn: F,
) -> Result<RawProcessResult, SupervisorError>
where
    F: FnOnce() -> Result<(), SupervisorError>,
{
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    before_spawn()?;
    let start = Instant::now();
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| {
        SupervisorError::InvalidCommand("child stdout pipe was unavailable".into())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        SupervisorError::InvalidCommand("child stderr pipe was unavailable".into())
    })?;
    let observed = Arc::new(AtomicU64::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_output_reader(
        stdout,
        limits.max_output_bytes,
        Arc::clone(&observed),
        Arc::clone(&exceeded),
    );
    let stderr_reader = spawn_output_reader(
        stderr,
        limits.max_output_bytes,
        Arc::clone(&observed),
        Arc::clone(&exceeded),
    );
    let process_group = child.id();
    let deadline = start + Duration::from_millis(limits.wall_time_ms);
    let (mut termination, already_waited) = loop {
        if let Some(status) = child.try_wait()? {
            break (termination_from_status(status)?, true);
        }
        if cancellation.is_cancelled() {
            terminate_child_and_group(&mut child, process_group, kill_program)?;
            break (CommandTermination::Cancelled, false);
        }
        if exceeded.load(Ordering::Acquire) {
            terminate_child_and_group(&mut child, process_group, kill_program)?;
            break (CommandTermination::OutputLimitExceeded, false);
        }
        if Instant::now() >= deadline {
            terminate_child_and_group(&mut child, process_group, kill_program)?;
            break (CommandTermination::TimedOut, false);
        }
        thread::sleep(POLL_INTERVAL);
    };
    if !already_waited {
        child.wait()?;
    }
    reconcile_process_group(process_group, kill_program)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| SupervisorError::InvalidCommand("stdout reader panicked".into()))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| SupervisorError::InvalidCommand("stderr reader panicked".into()))??;
    if matches!(
        termination,
        CommandTermination::Exited(_) | CommandTermination::Signaled(_)
    ) && stdout
        .complete_length
        .saturating_add(stderr.complete_length)
        > limits.max_output_bytes
    {
        termination = CommandTermination::OutputLimitExceeded;
    }
    Ok(RawProcessResult {
        termination,
        stdout,
        stderr,
        duration_ms: duration_ms(start.elapsed()),
    })
}

fn spawn_output_reader<R>(
    mut reader: R,
    retain_limit: u64,
    observed: Arc<AtomicU64>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<StreamCapture, SupervisorError>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut hasher = Sha256::new();
        let mut complete_length = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let count_u64 = u64::try_from(count).expect("read buffer length fits u64");
            complete_length = complete_length.saturating_add(count_u64);
            hasher.update(&buffer[..count]);
            let prior = atomic_saturating_add(&observed, count_u64);
            if prior.saturating_add(count_u64) > retain_limit {
                exceeded.store(true, Ordering::Release);
            }
            let retained_len = u64::try_from(retained.len()).expect("usize fits u64");
            let copy = usize::try_from(retain_limit.saturating_sub(retained_len).min(count_u64))
                .expect("copy count fits usize");
            retained.extend_from_slice(&buffer[..copy]);
        }
        Ok(StreamCapture {
            retained,
            complete_digest: digest_from_sha(hasher.finalize().into()),
            complete_length,
        })
    })
}

fn atomic_saturating_add(value: &AtomicU64, increment: u64) -> u64 {
    let mut current = value.load(Ordering::Acquire);
    loop {
        let next = current.saturating_add(increment);
        match value.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(previous) => return previous,
            Err(actual) => current = actual,
        }
    }
}

fn signal_process_group(
    process_group: u32,
    kill_program: &ExecutableIdentity,
    signal: &str,
) -> Result<(), SupervisorError> {
    kill_program.validate_current()?;
    let group = format!("-{process_group}");
    let _status = Command::new(&kill_program.canonical_path)
        // Negative group IDs must bypass kill(1)'s option parser.
        .args([signal, "--", group.as_str()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(())
}

fn terminate_child_and_group(
    child: &mut Child,
    process_group: u32,
    kill_program: &ExecutableIdentity,
) -> Result<(), SupervisorError> {
    signal_process_group(process_group, kill_program, "-KILL")?;
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    Ok(())
}

fn reconcile_process_group(
    process_group: u32,
    kill_program: &ExecutableIdentity,
) -> Result<(), SupervisorError> {
    if process_group_exists(process_group, kill_program)? {
        signal_process_group(process_group, kill_program, "-KILL")?;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_group_exists(process_group, kill_program)? {
        if Instant::now() >= deadline {
            return Err(SupervisorError::Capability(format!(
                "process group {process_group} remained observable after forced cleanup"
            )));
        }
        thread::sleep(POLL_INTERVAL);
    }
    Ok(())
}

fn process_group_exists(
    process_group: u32,
    kill_program: &ExecutableIdentity,
) -> Result<bool, SupervisorError> {
    kill_program.validate_current()?;
    let group = format!("-{process_group}");
    let status = Command::new(&kill_program.canonical_path)
        .args(["-0", "--", group.as_str()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

#[cfg(unix)]
fn termination_from_status(status: ExitStatus) -> Result<CommandTermination, SupervisorError> {
    if let Some(code) = status.code() {
        return Ok(CommandTermination::Exited(code));
    }
    status
        .signal()
        .map(CommandTermination::Signaled)
        .ok_or_else(|| {
            SupervisorError::Capability(
                "terminal Unix process status carried neither an exit code nor a signal".into(),
            )
        })
}

#[cfg(not(unix))]
fn termination_from_status(status: ExitStatus) -> Result<CommandTermination, SupervisorError> {
    status
        .code()
        .map(CommandTermination::Exited)
        .ok_or_else(|| {
            SupervisorError::Capability(
                "terminal process status did not carry a normal exit code".into(),
            )
        })
}

fn bound_retained_output(
    stdout: StreamCapture,
    stderr: StreamCapture,
    limit: u64,
) -> (CapturedOutput, CapturedOutput) {
    let stdout_count =
        usize::try_from(limit.min(u64::try_from(stdout.retained.len()).expect("usize fits u64")))
            .unwrap_or(stdout.retained.len());
    let remaining = limit.saturating_sub(u64::try_from(stdout_count).expect("usize fits u64"));
    let stderr_count = usize::try_from(
        remaining.min(u64::try_from(stderr.retained.len()).expect("usize fits u64")),
    )
    .unwrap_or(stderr.retained.len());
    let stdout_output = CapturedOutput {
        truncated: stdout.complete_length > u64::try_from(stdout_count).expect("usize fits u64"),
        bytes: stdout.retained[..stdout_count].to_vec(),
        complete_digest: stdout.complete_digest,
        complete_length: stdout.complete_length,
    };
    let stderr_output = CapturedOutput {
        truncated: stderr.complete_length > u64::try_from(stderr_count).expect("usize fits u64"),
        bytes: stderr.retained[..stderr_count].to_vec(),
        complete_digest: stderr.complete_digest,
        complete_length: stderr.complete_length,
    };
    (stdout_output, stderr_output)
}

fn combined_output_digest(stdout: &CapturedOutput, stderr: &CapturedOutput) -> Digest {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, OUTPUT_DIGEST_DOMAIN);
    for (name, output) in [
        (b"stdout".as_slice(), stdout),
        (b"stderr".as_slice(), stderr),
    ] {
        hash_frame(&mut hasher, name);
        hash_frame(&mut hasher, &output.complete_length.to_be_bytes());
        hash_frame(&mut hasher, output.complete_digest.as_str().as_bytes());
    }
    digest_from_sha(hasher.finalize().into())
}

fn hash_frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    hasher.update(bytes);
}

fn hash_file(path: &Path) -> Result<Digest, SupervisorError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(digest_from_sha(hasher.finalize().into()))
}

fn hash_bytes(bytes: &[u8]) -> Digest {
    digest_from_sha(Sha256::digest(bytes).into())
}

fn digest_from_sha(bytes: [u8; 32]) -> Digest {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Digest::parse(text).expect("SHA-256 always has canonical digest form")
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

// Stamped into `SandboxEvidence` by the macOS inherited-descriptor canary; no
// other supervisor path in this module records a wall-clock instant.
#[cfg(target_os = "macos")]
fn unix_time_ms() -> Result<u64, SupervisorError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            SupervisorError::Capability(format!("system clock precedes Unix epoch: {error}"))
        })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        SupervisorError::Capability("current Unix time does not fit u64 milliseconds".into())
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn remove_if_present(path: &Path) -> Result<(), SupervisorError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SupervisorError::Io(error)),
    }
}

#[cfg(test)]
pub(crate) mod tests;
