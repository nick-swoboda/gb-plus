#[allow(
    clippy::wildcard_imports,
    reason = "the nested boundary intentionally shares only this parent module's private audited primitives"
)]
use super::*;
use crate::linux_containment::ContainedCommandReleaseAuthorityV1;

/// One independently proved property required from every platform backend.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum BackendControl {
    /// The held executable descriptor, not a reopened pathname, is executed.
    DescriptorExec,
    /// The exact program and argument vector is passed without a shell.
    ExactArgv,
    /// The inherited environment is cleared before exact entries are added.
    ReplacedEnvironment,
    /// The final target exec has only descriptors 0, 1, and 2.
    ClosedInheritedDescriptors,
    /// The working directory is selected from the retained cwd descriptor.
    DescriptorWorkingDirectory,
    /// Read/write mounts or Seatbelt rules implement the compiled scopes.
    FilesystemPolicy,
    /// Network behavior exactly implements the compiled network mode.
    NetworkPolicy,
    /// A launcher-external monotonic wall-time limit is active.
    ExternalWallClock,
    /// Output pipes are drained completely with bounded chunks.
    CompleteBoundedOutput,
    /// The configured descendant-count limit is kernel/helper enforced.
    DescendantLimit,
    /// Cancellation can kill and prove empty the complete descendant domain.
    DescendantDomainKill,
    /// The optional memory ceiling is kernel/helper enforced.
    MemoryLimit,
    /// Escape canaries ran inside the same backend generation used to launch.
    ActiveCanaries,
}

impl BackendControl {
    fn label(self) -> &'static [u8] {
        match self {
            Self::DescriptorExec => b"descriptor_exec",
            Self::ExactArgv => b"exact_argv",
            Self::ReplacedEnvironment => b"replaced_environment",
            Self::ClosedInheritedDescriptors => b"closed_inherited_descriptors",
            Self::DescriptorWorkingDirectory => b"descriptor_working_directory",
            Self::FilesystemPolicy => b"filesystem_policy",
            Self::NetworkPolicy => b"network_policy",
            Self::ExternalWallClock => b"external_wall_clock",
            Self::CompleteBoundedOutput => b"complete_bounded_output",
            Self::DescendantLimit => b"descendant_limit",
            Self::DescendantDomainKill => b"descendant_domain_kill",
            Self::MemoryLimit => b"memory_limit",
            Self::ActiveCanaries => b"active_canaries",
        }
    }
}

/// Immutable identity of one installed containment backend generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BackendIdentity {
    command_domain_backend: CommandDomainCleanupBackend,
    backend_id: String,
    implementation_digest: Digest,
}

impl BackendIdentity {
    pub(crate) fn new(
        command_domain_backend: CommandDomainCleanupBackend,
        backend_id: impl Into<String>,
        implementation_digest: Digest,
    ) -> Self {
        Self {
            command_domain_backend,
            backend_id: backend_id.into(),
            implementation_digest,
        }
    }

    pub(crate) const fn command_domain_backend(&self) -> CommandDomainCleanupBackend {
        self.command_domain_backend
    }

    pub(crate) fn backend_id(&self) -> &str {
        &self.backend_id
    }

    pub(crate) const fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    fn validate(&self) -> Result<(), SupervisorError> {
        if self.backend_id.trim().is_empty()
            || self.backend_id.chars().any(char::is_control)
            || self.backend_id.len() > 128
        {
            return Err(SupervisorError::Capability(
                "containment backend identity is blank, unbounded, or contains control characters"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Result of active backend canaries for the exact launch generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BackendCanaryStatus {
    /// Every mandatory positive control and restrictive escape probe passed.
    Passed(Digest),
    /// At least one mandatory canary failed; the bounded reason is diagnostic.
    Failed(String),
}

/// Untrusted report returned by a backend's active preflight.
///
/// The supervisor validates every field and converts it into a single-use
/// permit. A report alone never authorizes `launch`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BackendPreflightReport {
    launch_digest: Digest,
    backend: BackendIdentity,
    controls: BTreeSet<BackendControl>,
    target_descriptors: Vec<i32>,
    canary_status: BackendCanaryStatus,
}

impl BackendPreflightReport {
    pub(crate) fn new(
        launch_digest: Digest,
        backend: BackendIdentity,
        controls: BTreeSet<BackendControl>,
        target_descriptors: Vec<i32>,
        canary_status: BackendCanaryStatus,
    ) -> Self {
        Self {
            launch_digest,
            backend,
            controls,
            target_descriptors,
            canary_status,
        }
    }
}

/// Single-use result of validating an active backend preflight.
#[derive(Debug)]
pub(crate) struct ValidatedBackendPermit {
    launch_digest: Digest,
    backend: BackendIdentity,
    preflight_digest: Digest,
    closed_descriptors: ClosedExecDescriptorSet,
}

impl ValidatedBackendPermit {
    pub(crate) const fn launch_digest(&self) -> &Digest {
        &self.launch_digest
    }

    pub(crate) const fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    pub(crate) const fn preflight_digest(&self) -> &Digest {
        &self.preflight_digest
    }

    pub(crate) fn closed_descriptors(&self) -> &[i32; 3] {
        self.closed_descriptors.descriptors()
    }
}

#[derive(Serialize)]
struct CanonicalCaptureLaunchBinding<'a> {
    schema_version: u32,
    command_effect_authority_digest: &'a Digest,
    role: RunnerRole,
    grant_hash: &'a Digest,
    runner_session_id: &'a str,
    runner_nonce: Option<&'a Digest>,
    request_sequence: u64,
    request_id: &'a str,
    effect_contract_version: u32,
    runner_launch_id: &'a str,
    effect_id: &'a str,
    idempotency_key: &'a str,
    sprint_id: &'a str,
    task_id: Option<&'a str>,
    worker_id: Option<&'a str>,
    policy_hash: &'a Digest,
    input_snapshot: &'a Digest,
    command_request_digest: &'a Digest,
    transport_commitment_digest: &'a Digest,
    capture_id: &'a str,
    capture_intent_digest: &'a Digest,
    capture_acquired_anchor_digest: &'a Digest,
    capture_acquired_store_head: &'a CommandOutputCaptureStoreHeadV1,
    capture_dispatch_claim_id: &'a str,
    capture_private_state_digest: &'a Digest,
    capture_max_aggregate_output_bytes: u64,
    launch_digest: &'a Digest,
    preflight_digest: &'a Digest,
    command_domain_backend: CommandDomainCleanupBackend,
    backend_id: &'a str,
    backend_implementation_digest: &'a Digest,
    closed_exec_descriptors: &'a [i32; 3],
}

/// Move-only output custody that can exist only after `LaunchIntended` is
/// durably appended for the exact validated command/preflight generation.
///
/// Native backends receive this value by shared reference. They therefore
/// cannot manufacture launch authorization or take stdout/stderr/publisher
/// custody away from the supervisor that must either publish or abandon it.
pub(crate) struct DurablyAnchoredCapture {
    stdout: CommandOutputStreamCapture,
    stderr: CommandOutputStreamCapture,
    publisher: CommandOutputPublisher,
    capture_id: String,
    acquired_anchor_digest: Digest,
    launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
}

impl DurablyAnchoredCapture {
    pub(crate) fn capture_id(&self) -> &str {
        &self.capture_id
    }

    pub(crate) const fn acquired_anchor_digest(&self) -> &Digest {
        &self.acquired_anchor_digest
    }

    pub(crate) const fn launch_intended_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        &self.launch_intended_store_head
    }

    pub(crate) const fn core_dump_suppression(&self) -> &SensitiveOutputCoreDumpSuppressionV1 {
        &self.core_dump_suppression
    }

    fn into_parts(
        self,
    ) -> (
        CommandOutputStreamCapture,
        CommandOutputStreamCapture,
        CommandOutputPublisher,
        String,
        Digest,
        CommandOutputCaptureStoreHeadV1,
    ) {
        (
            self.stdout,
            self.stderr,
            self.publisher,
            self.capture_id,
            self.acquired_anchor_digest,
            self.launch_intended_store_head,
        )
    }

    fn retain_unclassified_for_reconciliation(self) -> CommandOutputStoreError {
        let reconciliation = self
            .publisher
            .unclassified_sensitive_output_reconciliation_required();
        drop(self.stdout);
        drop(self.stderr);
        drop(self.publisher);
        reconciliation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
}

impl DirectoryIdentity {
    fn from_capability(directory: &Dir) -> Result<Self, SupervisorError> {
        let metadata = directory.dir_metadata()?;
        Ok(Self {
            device: cap_fs_ext::OsMetadataExt::dev(&metadata),
            inode: cap_fs_ext::OsMetadataExt::ino(&metadata),
            owner_uid: cap_fs_ext::OsMetadataExt::uid(&metadata),
            mode: cap_fs_ext::OsMetadataExt::mode(&metadata) & 0o777,
        })
    }

    fn from_named(path: &Path) -> Result<Self, SupervisorError> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_dir() {
            return Err(SupervisorError::InvalidCommand(format!(
                "contained command directory is no longer a directory: {}",
                path.display()
            )));
        }
        Ok(Self {
            device: std::os::unix::fs::MetadataExt::dev(&metadata),
            inode: std::os::unix::fs::MetadataExt::ino(&metadata),
            owner_uid: std::os::unix::fs::MetadataExt::uid(&metadata),
            mode: std::os::unix::fs::MetadataExt::mode(&metadata) & 0o777,
        })
    }
}

struct RetainedDirectory {
    path: PathBuf,
    identity: DirectoryIdentity,
    descriptor: Dir,
}

impl fmt::Debug for RetainedDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedDirectory")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("descriptor", &self.descriptor.as_fd().as_raw_fd())
            .finish()
    }
}

impl RetainedDirectory {
    fn revalidate(&self) -> Result<(), SupervisorError> {
        require_descriptor_cloexec(self.descriptor.as_fd(), "directory")?;
        let descriptor = DirectoryIdentity::from_capability(&self.descriptor)?;
        let named = DirectoryIdentity::from_named(&self.path)?;
        let canonical = fs::canonicalize(&self.path)?;
        if descriptor != self.identity || named != self.identity || canonical != self.path {
            return Err(SupervisorError::Capability(format!(
                "retained directory identity changed before launch: {}",
                self.path.display()
            )));
        }
        Ok(())
    }
}

struct RetainedExecutable {
    identity: ExecutableIdentity,
    descriptor: File,
}

impl fmt::Debug for RetainedExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedExecutable")
            .field("identity", &self.identity)
            .field("descriptor", &self.descriptor.as_raw_fd())
            .finish()
    }
}

impl RetainedExecutable {
    fn revalidate(&self) -> Result<(), SupervisorError> {
        require_descriptor_cloexec(self.descriptor.as_fd(), "executable")?;
        self.identity.validate_current()?;
        let metadata = self.descriptor.metadata()?;
        if metadata.dev() != self.identity.device
            || metadata.ino() != self.identity.inode
            || metadata.len() != self.identity.length
            || metadata.mtime() != self.identity.modified_seconds
            || metadata.mtime_nsec() != self.identity.modified_nanoseconds
            || hash_open_file(&self.descriptor)? != self.identity.content_digest
        {
            return Err(SupervisorError::Capability(format!(
                "retained executable descriptor changed before launch: {}",
                self.identity.canonical_path.display()
            )));
        }
        Ok(())
    }
}

/// Exact, retained authority consumed by one contained launch.
pub(crate) struct PreparedContainedCommand {
    command_effect_authority: CommandEffectAuthorityV1,
    command_effect_authority_v2: Option<CommandEffectAuthorityV2>,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    command: CommandSpec,
    environment: ScrubbedEnvironment,
    private_state_root: RetainedDirectory,
    execution_root: RetainedDirectory,
    working_directory: RetainedDirectory,
    executable: RetainedExecutable,
    execution_snapshot: Digest,
    launch_digest: Digest,
    /// The desktop's release admission for this command, when it sent one.
    ///
    /// `None` is ordinary and is not a defect: a request that was never
    /// admitted for contained release simply has none, and the backend
    /// refuses to launch rather than inventing one. Nothing in the runner
    /// can construct this -- it is only ever moved in from a decoded v13
    /// envelope.
    contained_command_release: Option<ContainedCommandReleaseAuthorityV1>,
}

impl fmt::Debug for PreparedContainedCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedContainedCommand")
            .field(
                "contained_command_release",
                &self
                    .contained_command_release
                    .as_ref()
                    .map(|authority| authority.command_effect_id.as_str()),
            )
            .field("role", &self.command_effect_authority.role())
            .field(
                "command_effect_authority_v2",
                &self.command_effect_authority_v2.is_some(),
            )
            .field("grant_hash", &self.grant.contract().grant_hash)
            .field("policy_hash", &self.policy.contract().policy_hash)
            .field("detector_policy", &self.detector_policy)
            .field("command", &self.command)
            .field("environment", &self.environment.variables().keys())
            .field("private_state_root", &self.private_state_root)
            .field("execution_root", &self.execution_root)
            .field("working_directory", &self.working_directory)
            .field("executable", &self.executable)
            .field("execution_snapshot", &self.execution_snapshot)
            .field("launch_digest", &self.launch_digest)
            .finish()
    }
}

impl PreparedContainedCommand {
    /// The desktop's release admission, when this command carries one.
    pub(crate) const fn contained_command_release(
        &self,
    ) -> Option<&ContainedCommandReleaseAuthorityV1> {
        self.contained_command_release.as_ref()
    }

    /// Installs the admission decoded from this command's own v13 envelope.
    ///
    /// Takes `self` by value and returns it, so an admission cannot be
    /// added to a command that is already in flight, and cannot be swapped:
    /// there is no `&mut` path to this field anywhere.
    #[must_use]
    pub(crate) fn with_contained_command_release(
        mut self,
        authority: ContainedCommandReleaseAuthorityV1,
    ) -> Self {
        self.contained_command_release = Some(authority);
        self
    }

    pub(crate) const fn command_effect_authority(&self) -> &CommandEffectAuthorityV1 {
        &self.command_effect_authority
    }

    pub(crate) const fn command_effect_authority_v2(&self) -> Option<&CommandEffectAuthorityV2> {
        self.command_effect_authority_v2.as_ref()
    }

    fn canonical_authority_bytes(&self) -> Result<Vec<u8>, SupervisorError> {
        if let Some(authority) = &self.command_effect_authority_v2 {
            serde_json::to_vec(authority)
        } else {
            serde_json::to_vec(&self.command_effect_authority)
        }
        .map_err(|error| {
            SupervisorError::Authority(format!("command-effect authority encoding failed: {error}"))
        })
    }

    pub(crate) const fn command(&self) -> &CommandSpec {
        &self.command
    }

    pub(crate) const fn policy(&self) -> &CompiledExecutionPolicy {
        &self.policy
    }

    pub(crate) const fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        &self.detector_policy
    }

    pub(crate) fn environment(&self) -> &BTreeMap<OsString, OsString> {
        self.environment.variables()
    }

    pub(crate) fn executable_path(&self) -> &Path {
        &self.executable.identity.canonical_path
    }

    pub(crate) fn execution_root_path(&self) -> &Path {
        &self.execution_root.path
    }

    pub(crate) fn working_directory_path(&self) -> &Path {
        &self.working_directory.path
    }

    pub(crate) const fn launch_digest(&self) -> &Digest {
        &self.launch_digest
    }

    pub(crate) fn executable_descriptor(&self) -> impl AsFd + '_ {
        self.executable.descriptor.as_fd()
    }

    pub(crate) fn execution_root_descriptor(&self) -> impl AsFd + '_ {
        self.execution_root.descriptor.as_fd()
    }

    pub(crate) fn private_state_root_descriptor(&self) -> impl AsFd + '_ {
        self.private_state_root.descriptor.as_fd()
    }

    pub(crate) fn working_directory_descriptor(&self) -> impl AsFd + '_ {
        self.working_directory.descriptor.as_fd()
    }

    pub(crate) fn revalidate(&self) -> Result<(), SupervisorError> {
        validate_authority(&self.grant, &self.policy)?;
        crate::sensitive_output::validate_matcher_policy_v1(&self.detector_policy)
            .map_err(sensitive_output_error)?;
        if let Some(authority_v2) = &self.command_effect_authority_v2 {
            authority_v2.validate_integrity().map_err(|error| {
                SupervisorError::Authority(format!(
                    "v12 command-effect authority failed integrity validation: {error}"
                ))
            })?;
            let projection = authority_v2.v11_execution_projection().map_err(|error| {
                SupervisorError::Authority(format!(
                    "v12 command-effect authority projection failed: {error}"
                ))
            })?;
            if projection != self.command_effect_authority
                || authority_v2.detector_policy() != &self.detector_policy
            {
                return Err(SupervisorError::Authority(
                    "prepared command crossed its retained full v12 authority".into(),
                ));
            }
        }
        if command_from_effect_authority(&self.command_effect_authority, &self.grant, &self.policy)?
            != self.command
        {
            return Err(SupervisorError::Authority(
                "prepared command differs from its retained command-effect authority".into(),
            ));
        }
        self.private_state_root.revalidate()?;
        self.execution_root.revalidate()?;
        validate_retained_root_topology(
            &self.private_state_root,
            &self.execution_root,
            self.grant.identity().canonical_root(),
        )?;
        validate_retained_execution_snapshot(
            &self.execution_root,
            &self.grant,
            &self.execution_snapshot,
        )?;
        self.working_directory.revalidate()?;
        self.executable.revalidate()?;
        if compute_contained_launch_digest(self)? != self.launch_digest {
            return Err(SupervisorError::Authority(
                "prepared contained launch changed after policy compilation".into(),
            ));
        }
        Ok(())
    }
}

/// Direct process status reported by the held descendant domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendTermination {
    Exited(i32),
    Signaled(i32),
}

/// One nonblocking observation from a contained descendant domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DomainObservation {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) leader: Option<BackendTermination>,
    pub(crate) stdout_closed: bool,
    pub(crate) stderr_closed: bool,
    pub(crate) domain_empty: bool,
}

/// Why the supervisor ordered whole-domain termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainTerminationRequest {
    TimedOut,
    Cancelled,
    OutputLimitExceeded,
    SensitiveOutputRejected,
    LeaderExitedWithDescendants,
}

/// Backend-owned live descendant domain. Every operation must be nonblocking.
pub(crate) trait ContainedDescendantDomain {
    fn poll(&mut self, maximum_chunk_bytes: usize) -> Result<DomainObservation, SupervisorError>;

    fn terminate_all(&mut self, reason: DomainTerminationRequest) -> Result<(), SupervisorError>;

    fn into_cleanup_proof(self) -> Result<ValidatedCommandDomainCleanupProof, SupervisorError>;
}

/// Platform bridge capable of satisfying every mandatory control.
pub(crate) trait ContainedCommandBackend {
    type Domain: ContainedDescendantDomain;

    fn identity(&self) -> Result<BackendIdentity, SupervisorError>;

    fn active_preflight(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<BackendPreflightReport, SupervisorError>;

    fn launch(
        &mut self,
        command: PreparedContainedCommand,
        permit: ValidatedBackendPermit,
        output_capture: &DurablyAnchoredCapture,
    ) -> Result<Self::Domain, SupervisorError>;
}

/// Evidence returned only after the leader, streams, and descendant domain
/// all reached a terminal state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainedExecutionEvidence {
    termination: CommandTermination,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    output_digest: Digest,
    output_artifacts: CommandOutputArtifactSetReferenceV1,
    output_capture_id: String,
    output_capture_acquired_anchor_digest: Digest,
    output_capture_launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    output_capture_finished_store_head: CommandOutputCaptureStoreHeadV1,
    output_capture_published_store_head: CommandOutputCaptureStoreHeadV1,
    launch_digest: Digest,
    preflight_digest: Digest,
    backend: BackendIdentity,
    cleanup_proof: ValidatedCommandDomainCleanupProof,
    duration_ms: u64,
}

impl ContainedExecutionEvidence {
    pub(crate) const fn termination(&self) -> CommandTermination {
        self.termination
    }

    pub(crate) const fn stdout(&self) -> &CapturedOutput {
        &self.stdout
    }

    pub(crate) const fn stderr(&self) -> &CapturedOutput {
        &self.stderr
    }

    pub(crate) const fn output_digest(&self) -> &Digest {
        &self.output_digest
    }

    pub(crate) const fn output_artifacts(&self) -> &CommandOutputArtifactSetReferenceV1 {
        &self.output_artifacts
    }

    pub(crate) fn output_capture_id(&self) -> &str {
        &self.output_capture_id
    }

    pub(crate) const fn output_capture_acquired_anchor_digest(&self) -> &Digest {
        &self.output_capture_acquired_anchor_digest
    }

    pub(crate) const fn output_capture_launch_intended_store_head(
        &self,
    ) -> &CommandOutputCaptureStoreHeadV1 {
        &self.output_capture_launch_intended_store_head
    }

    pub(crate) const fn output_capture_finished_store_head(
        &self,
    ) -> &CommandOutputCaptureStoreHeadV1 {
        &self.output_capture_finished_store_head
    }

    pub(crate) const fn output_capture_published_store_head(
        &self,
    ) -> &CommandOutputCaptureStoreHeadV1 {
        &self.output_capture_published_store_head
    }

    pub(crate) const fn launch_digest(&self) -> &Digest {
        &self.launch_digest
    }

    pub(crate) const fn preflight_digest(&self) -> &Digest {
        &self.preflight_digest
    }

    pub(crate) const fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    pub(crate) const fn cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.cleanup_proof
    }

    pub(crate) const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
}

/// Secret-free terminal evidence for a fixed-policy output rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainedSensitiveOutputRejectionEvidence {
    termination: CommandTermination,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    output_capture_id: String,
    output_capture_acquired_anchor_digest: Digest,
    output_capture_launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    output_capture_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
    journal_receipt: SensitiveOutputRejectionJournalReceiptV2,
    backend: BackendIdentity,
    cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl ContainedSensitiveOutputRejectionEvidence {
    pub(crate) const fn termination(&self) -> CommandTermination {
        self.termination
    }

    pub(crate) const fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        &self.detector_policy
    }

    pub(crate) fn output_capture_id(&self) -> &str {
        &self.output_capture_id
    }

    pub(crate) const fn output_capture_acquired_anchor_digest(&self) -> &Digest {
        &self.output_capture_acquired_anchor_digest
    }

    pub(crate) const fn output_capture_launch_intended_store_head(
        &self,
    ) -> &CommandOutputCaptureStoreHeadV1 {
        &self.output_capture_launch_intended_store_head
    }

    pub(crate) const fn output_capture_cleaned_store_head(
        &self,
    ) -> &CommandOutputCaptureStoreHeadV1 {
        &self.output_capture_cleaned_store_head
    }

    pub(crate) const fn journal_receipt(&self) -> &SensitiveOutputRejectionJournalReceiptV2 {
        &self.journal_receipt
    }

    pub(crate) const fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    pub(crate) const fn cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.cleanup_proof
    }
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "the test constructor mirrors every independently persisted contained-evidence field"
)]
pub(crate) fn test_contained_execution_evidence(
    termination: CommandTermination,
    stdout_bytes: Vec<u8>,
    stderr_bytes: Vec<u8>,
    output_artifacts: CommandOutputArtifactSetReferenceV1,
    output_capture_id: String,
    output_capture_acquired_anchor_digest: Digest,
    output_capture_launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    output_capture_finished_store_head: CommandOutputCaptureStoreHeadV1,
    output_capture_published_store_head: CommandOutputCaptureStoreHeadV1,
    launch_digest: Digest,
    preflight_digest: Digest,
    cleanup_proof: ValidatedCommandDomainCleanupProof,
) -> ContainedExecutionEvidence {
    let stdout = CapturedOutput {
        complete_digest: Digest::sha256(&stdout_bytes),
        complete_length: u64::try_from(stdout_bytes.len()).expect("test stdout length fits u64"),
        bytes: stdout_bytes,
        truncated: false,
    };
    let stderr = CapturedOutput {
        complete_digest: Digest::sha256(&stderr_bytes),
        complete_length: u64::try_from(stderr_bytes.len()).expect("test stderr length fits u64"),
        bytes: stderr_bytes,
        truncated: false,
    };
    assert_eq!(
        output_artifacts.stdout.byte_length,
        stdout.complete_length()
    );
    assert_eq!(
        output_artifacts.stdout.content_digest,
        *stdout.complete_digest()
    );
    assert_eq!(
        output_artifacts.stderr.byte_length,
        stderr.complete_length()
    );
    assert_eq!(
        output_artifacts.stderr.content_digest,
        *stderr.complete_digest()
    );
    cleanup_proof
        .validate()
        .expect("test contained cleanup proof remains valid");
    let output_digest = super::combined_output_digest(&stdout, &stderr);
    ContainedExecutionEvidence {
        termination,
        stdout,
        stderr,
        output_digest,
        output_artifacts,
        output_capture_id,
        output_capture_acquired_anchor_digest,
        output_capture_launch_intended_store_head,
        output_capture_finished_store_head,
        output_capture_published_store_head,
        launch_digest,
        preflight_digest,
        backend: BackendIdentity::new(
            CommandDomainCleanupBackend::LinuxCgroupV2,
            "service-terminal-test-backend",
            Digest::sha256(b"service-terminal-test-backend/v1"),
        ),
        cleanup_proof,
        duration_ms: 1,
    }
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "the test constructor checks every independently retained rejection-evidence join"
)]
pub(crate) fn test_contained_sensitive_output_rejection_evidence(
    termination: CommandTermination,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    output_capture_id: String,
    output_capture_acquired_anchor_digest: Digest,
    output_capture_launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    output_capture_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
    journal_receipt: SensitiveOutputRejectionJournalReceiptV2,
    backend: BackendIdentity,
    cleanup_proof: ValidatedCommandDomainCleanupProof,
) -> ContainedSensitiveOutputRejectionEvidence {
    journal_receipt
        .validate()
        .expect("test rejection receipt remains self-authenticating");
    cleanup_proof
        .validate()
        .expect("test rejection cleanup proof remains valid");
    assert_eq!(journal_receipt.detector_policy, detector_policy);
    assert_eq!(journal_receipt.capture_id, output_capture_id);
    assert_eq!(
        journal_receipt.acquired_anchor_digest,
        output_capture_acquired_anchor_digest
    );
    assert_eq!(
        journal_receipt.launch_intended_store_head,
        output_capture_launch_intended_store_head
    );
    assert_eq!(
        journal_receipt.v1_cleaned_store_head,
        output_capture_cleaned_store_head
    );
    assert_eq!(
        journal_receipt.command_domain_cleanup_proof_id,
        cleanup_proof.os_evidence_digest().as_str()
    );
    assert_eq!(
        cleanup_proof.backend(),
        backend.command_domain_backend(),
        "test rejection cleanup proof must bind the reported backend"
    );
    assert_eq!(
        journal_receipt.termination,
        command_termination_v1(termination)
            .expect("test rejection termination maps to the durable contract")
    );
    ContainedSensitiveOutputRejectionEvidence {
        termination,
        detector_policy,
        output_capture_id,
        output_capture_acquired_anchor_digest,
        output_capture_launch_intended_store_head,
        output_capture_cleaned_store_head,
        journal_receipt,
        backend,
        cleanup_proof,
    }
}

/// Phase-preserving result of one contained execution attempt.
///
/// Only [`Self::Terminal`] carries evidence that the launched descendant
/// domain reached a fully drained, cleanup-proven terminal state. A
/// backend launch error is deliberately classified as post-launch
/// uncertainty because the backend may have created native state before
/// returning the error.
#[allow(
    clippy::large_enum_variant,
    reason = "the phase boundary retains the requested direct terminal-evidence variant and each outcome is consumed exactly once"
)]
#[derive(Debug)]
pub(crate) enum ContainedExecutionOutcome {
    Terminal(ContainedExecutionEvidence),
    SensitiveOutputRejected(ContainedSensitiveOutputRejectionEvidence),
    RefusedBeforeLaunch(SupervisorError),
    UnprovenAfterLaunch(SupervisorError),
}

/// Prepares exact command authority without creating a process.
#[cfg(test)]
pub(crate) fn prepare(
    command_effect_authority: CommandEffectAuthorityV1,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    execution_root_authority: SessionValidatedWorkerExecutionRoot,
    paths: &SupervisorPaths,
    execution_root_manifest: &WorkspaceManifest,
) -> Result<PreparedContainedCommand, SupervisorError> {
    prepare_internal(
        command_effect_authority,
        None,
        grant,
        policy,
        SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
        execution_root_authority,
        paths,
        execution_root_manifest,
    )
}

#[cfg(test)]
pub(crate) fn prepare_with_sensitive_output_policy(
    command_effect_authority: CommandEffectAuthorityV1,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    execution_root_authority: SessionValidatedWorkerExecutionRoot,
    paths: &SupervisorPaths,
    execution_root_manifest: &WorkspaceManifest,
) -> Result<PreparedContainedCommand, SupervisorError> {
    prepare_internal(
        command_effect_authority,
        None,
        grant,
        policy,
        detector_policy,
        execution_root_authority,
        paths,
        execution_root_manifest,
    )
}

/// Prepares production containment only from the exact service-validated
/// full v12 authority. The legacy command authority is derived internally
/// and retained solely as the execution projection used by established
/// grant/policy/root validators.
pub(crate) fn prepare_v12(
    command_effect_authority_v2: CommandEffectAuthorityV2,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    execution_root_authority: SessionValidatedWorkerExecutionRoot,
    paths: &SupervisorPaths,
    execution_root_manifest: &WorkspaceManifest,
) -> Result<PreparedContainedCommand, SupervisorError> {
    command_effect_authority_v2
        .validate_integrity()
        .map_err(|error| SupervisorError::Authority(error.to_string()))?;
    let detector_policy = command_effect_authority_v2.detector_policy().clone();
    let command_effect_authority = command_effect_authority_v2
        .v11_execution_projection()
        .map_err(|error| SupervisorError::Authority(error.to_string()))?;
    prepare_internal(
        command_effect_authority,
        Some(command_effect_authority_v2),
        grant,
        policy,
        detector_policy,
        execution_root_authority,
        paths,
        execution_root_manifest,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one internal join retains both full v12 authority and its derived legacy execution projection"
)]
fn prepare_internal(
    command_effect_authority: CommandEffectAuthorityV1,
    command_effect_authority_v2: Option<CommandEffectAuthorityV2>,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    execution_root_authority: SessionValidatedWorkerExecutionRoot,
    paths: &SupervisorPaths,
    execution_root_manifest: &WorkspaceManifest,
) -> Result<PreparedContainedCommand, SupervisorError> {
    validate_authority(&grant, &policy)?;
    crate::sensitive_output::validate_matcher_policy_v1(&detector_policy)
        .map_err(sensitive_output_error)?;
    let command = command_from_effect_authority(&command_effect_authority, &grant, &policy)?;
    command
        .validate()
        .map_err(|error| SupervisorError::InvalidCommand(error.to_string()))?;
    validate_arguments(&command)?;
    reject_explicit_shell(&command.program)?;
    validate_contained_resource_limits(policy.contract().resource_limits)?;
    let environment = build_contained_environment(&policy)?;
    let (
        authenticated_private_state_path,
        authenticated_private_state_descriptor,
        authenticated_execution_root_path,
        authenticated_execution_root_descriptor,
    ) = execution_root_authority
        .into_command_capabilities(&command_effect_authority)
        .map_err(SupervisorError::Authority)?;
    let execution_root_path = validate_contained_execution_root(
        &grant,
        &policy,
        paths,
        command_effect_authority.role(),
        execution_root_manifest,
        &authenticated_private_state_path,
        &authenticated_execution_root_path,
    )?;
    let execution_snapshot = command_effect_authority
        .envelope()
        .effect
        .as_ref()
        .ok_or_else(|| {
            SupervisorError::Authority("command-effect authority has no execution snapshot".into())
        })?
        .input_snapshot
        .clone();
    validate_execution_root_manifest(
        execution_root_manifest,
        &grant,
        &execution_root_path,
        &execution_snapshot,
    )?;
    let private_state_root = retain_proved_directory(
        &authenticated_private_state_path,
        authenticated_private_state_descriptor,
    )?;
    let execution_root = retain_proved_directory(
        &execution_root_path,
        authenticated_execution_root_descriptor,
    )?;
    validate_retained_root_topology(
        &private_state_root,
        &execution_root,
        grant.identity().canonical_root(),
    )?;
    validate_retained_execution_snapshot(&execution_root, &grant, &execution_snapshot)?;
    let working_directory = retain_relative_directory(
        &execution_root,
        &command.working_directory,
        &execution_root_path,
    )?;
    let executable_identity = resolve_executable(&command.program, &environment)?;
    reject_explicit_shell_path(&executable_identity.canonical_path)?;
    let executable = retain_executable(executable_identity)?;
    let mut prepared = PreparedContainedCommand {
        contained_command_release: None,
        command_effect_authority,
        command_effect_authority_v2,
        grant,
        policy,
        detector_policy,
        command,
        environment,
        private_state_root,
        execution_root,
        working_directory,
        executable,
        execution_snapshot,
        launch_digest: hash_bytes(b"uninitialized-contained-launch"),
    };
    prepared.launch_digest = compute_contained_launch_digest(&prepared)?;
    prepared.revalidate()?;
    Ok(prepared)
}

fn command_from_effect_authority(
    authority: &CommandEffectAuthorityV1,
    grant: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
) -> Result<CommandSpec, SupervisorError> {
    authority.validate_integrity().map_err(|error| {
        SupervisorError::Authority(format!(
            "command-effect authority failed integrity validation: {error}"
        ))
    })?;
    if authority.grant_hash() != &grant.contract().grant_hash {
        return Err(SupervisorError::Authority(
            "command-effect authority grant differs from the issued workspace grant".into(),
        ));
    }
    let effect = authority.envelope().effect.as_ref().ok_or_else(|| {
        SupervisorError::Authority("command-effect authority has no durable effect context".into())
    })?;
    if effect.policy_hash != policy.contract().policy_hash {
        return Err(SupervisorError::Authority(
            "command-effect authority policy differs from the compiled execution policy".into(),
        ));
    }
    let (
        RunnerRole::Worker,
        MutationMode::ShadowWorkspace,
        RunnerRequest::WorkerRunCommand {
            command: wire_command,
            ..
        },
    ) = (
        authority.role(),
        policy.contract().mutation_mode,
        &authority.envelope().request,
    )
    else {
        return Err(SupervisorError::Authority(
            "contained preparation currently requires a Worker command with the live service's exact shadow-workspace policy; FinalVerifier remains blocked until its retained snapshot execution boundary lands"
                .into(),
        ));
    };
    Ok(CommandSpec {
        program: wire_command.program.clone(),
        arguments: wire_command.arguments.clone(),
        working_directory: PathBuf::from(&wire_command.working_directory),
    })
}

fn command_domain_cleanup_binding(
    authority: &CommandEffectAuthorityV1,
) -> Result<CommandDomainCleanupBinding, SupervisorError> {
    authority.validate_integrity().map_err(|error| {
        SupervisorError::Authority(format!(
            "command-effect authority failed cleanup-binding validation: {error}"
        ))
    })?;
    let effect = authority.envelope().effect.as_ref().ok_or_else(|| {
        SupervisorError::Authority(
            "command-effect authority has no cleanup-binding effect context".into(),
        )
    })?;
    CommandDomainCleanupBinding::try_new(
        authority.envelope().session_id.clone(),
        effect.effect_id.clone(),
        effect.request_digest.clone(),
    )
    .map_err(SupervisorError::from)
}

fn command_output_artifact_source(
    authority: &CommandEffectAuthorityV1,
) -> Result<CommandOutputArtifactSourceV1, SupervisorError> {
    authority.validate_integrity().map_err(|error| {
        SupervisorError::Authority(format!(
            "command-effect authority failed output-artifact validation: {error}"
        ))
    })?;
    let effect = authority.envelope().effect.as_ref().ok_or_else(|| {
        SupervisorError::Authority(
            "command-effect authority has no output-artifact effect context".into(),
        )
    })?;
    Ok(CommandOutputArtifactSourceV1 {
        sprint_id: effect.sprint_id.clone(),
        runner_launch_id: effect.launch_id.clone(),
        runner_session_id: authority.envelope().session_id.clone(),
        effect_id: effect.effect_id.clone(),
        request_digest: effect.request_digest.clone(),
    })
}

pub(crate) fn authenticated_output_capture_maximum(
    limits: ResourceLimits,
) -> Result<u64, SupervisorError> {
    command_output_capture_maximum(limits.max_output_bytes).map_err(|error| {
        SupervisorError::UnenforceableLimit(format!(
            "authenticated command-output capture ceiling is invalid: {error}"
        ))
    })
}

fn acquired_output_capture(
    prepared: &PreparedContainedCommand,
    limits: ResourceLimits,
) -> Result<CommandOutputCaptureAcquiredV1, SupervisorError> {
    let authority = prepared.command_effect_authority();
    authority.validate_integrity().map_err(|error| {
        SupervisorError::Authority(format!(
            "command-effect authority failed acquired-capture validation: {error}"
        ))
    })?;
    let acquired = match &authority.envelope().request {
        RunnerRequest::WorkerRunCommand { output_capture, .. }
        | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
            output_capture.acquired().clone()
        }
        _ => {
            return Err(SupervisorError::Authority(
                "contained command authority has no exact acquired output capture".into(),
            ));
        }
    };
    acquired.validate().map_err(|error| {
        SupervisorError::Authority(format!(
            "acquired command-output capture failed validation: {error}"
        ))
    })?;
    let source = command_output_artifact_source(authority)?;
    let maximum = authenticated_output_capture_maximum(limits)?;
    if acquired.source != source || acquired.max_aggregate_output_bytes != maximum {
        return Err(SupervisorError::Authority(
            "acquired command-output capture differs from the exact command source or authenticated aggregate limit"
                .into(),
        ));
    }
    Ok(acquired)
}

fn canonical_capture_launch_binding(
    prepared: &PreparedContainedCommand,
    acquired: &CommandOutputCaptureAcquiredV1,
    permit: &ValidatedBackendPermit,
) -> Result<Vec<u8>, SupervisorError> {
    let authority = prepared.command_effect_authority();
    let authority_bytes = prepared.canonical_authority_bytes()?;
    let authority_digest = Digest::sha256(&authority_bytes);
    let (runner_session_id, runner_nonce, request_sequence, request_id, effect, role, grant_hash) =
        if let Some(authority_v2) = prepared.command_effect_authority_v2() {
            let envelope = authority_v2.envelope();
            (
                envelope.session_id.as_str(),
                Some(&envelope.runner_nonce),
                envelope.sequence,
                envelope.request_id.as_str(),
                &envelope.effect,
                authority_v2.role(),
                authority_v2.grant_hash(),
            )
        } else {
            let envelope = authority.envelope();
            let effect = envelope.effect.as_ref().ok_or_else(|| {
                SupervisorError::Authority(
                    "command-effect authority has no durable launch-binding context".into(),
                )
            })?;
            (
                envelope.session_id.as_str(),
                envelope.runner_nonce.as_ref(),
                envelope.sequence,
                envelope.request_id.as_str(),
                effect,
                authority.role(),
                authority.grant_hash(),
            )
        };
    let binding = CanonicalCaptureLaunchBinding {
        schema_version: 1,
        command_effect_authority_digest: &authority_digest,
        role,
        grant_hash,
        runner_session_id,
        runner_nonce,
        request_sequence,
        request_id,
        effect_contract_version: effect.contract_version,
        runner_launch_id: &effect.launch_id,
        effect_id: &effect.effect_id,
        idempotency_key: &effect.idempotency_key,
        sprint_id: &effect.sprint_id,
        task_id: effect.task_id.as_deref(),
        worker_id: effect.worker_id.as_deref(),
        policy_hash: &effect.policy_hash,
        input_snapshot: &effect.input_snapshot,
        command_request_digest: &effect.request_digest,
        transport_commitment_digest: &effect.transport_commitment_digest,
        capture_id: &acquired.capture_id,
        capture_intent_digest: &acquired.intent_digest,
        capture_acquired_anchor_digest: &acquired.acquired_anchor_digest,
        capture_acquired_store_head: &acquired.store_head,
        capture_dispatch_claim_id: &acquired.dispatch_claim_id,
        capture_private_state_digest: &acquired.private_state_digest,
        capture_max_aggregate_output_bytes: acquired.max_aggregate_output_bytes,
        launch_digest: permit.launch_digest(),
        preflight_digest: permit.preflight_digest(),
        command_domain_backend: permit.backend().command_domain_backend(),
        backend_id: permit.backend().backend_id(),
        backend_implementation_digest: permit.backend().implementation_digest(),
        closed_exec_descriptors: permit.closed_descriptors(),
    };
    serde_json::to_vec(&binding).map_err(|error| {
        SupervisorError::Authority(format!(
            "cannot canonically encode path-free command launch binding: {error}"
        ))
    })
}

fn durably_anchor_output_capture(
    prepared: &PreparedContainedCommand,
    limits: ResourceLimits,
    permit: &ValidatedBackendPermit,
    core_dump_suppression: &SensitiveOutputCoreDumpSuppressionV1,
) -> Result<DurablyAnchoredCapture, SupervisorError> {
    let acquired = acquired_output_capture(prepared, limits)?;
    prepared.revalidate()?;
    let store = CapabilityCommandOutputStore::open(&prepared.private_state_root.path)?;
    let capture = store.reopen_anchored_capture_v2(&acquired, prepared.detector_policy())?;
    if let Err(error) = prepared.revalidate() {
        return Err(match capture.abandon_sensitive_output_prelaunch_v2() {
            Ok(()) => error,
            Err(cleanup) => combine_attempt_and_capture_cleanup_errors(error, cleanup),
        });
    }
    let binding = match canonical_capture_launch_binding(prepared, &acquired, permit) {
        Ok(binding) => binding,
        Err(primary) => {
            return Err(match capture.abandon_sensitive_output_prelaunch_v2() {
                Ok(()) => primary,
                Err(cleanup) => combine_attempt_and_capture_cleanup_errors(primary, cleanup),
            });
        }
    };
    let (stdout, stderr, mut publisher) = capture.split();
    let live_core_dump_suppression = match read_core_dump_suppression_v1() {
        Ok(profile) if &profile == core_dump_suppression => profile,
        Ok(_) => {
            let primary = SupervisorError::Capability(
                "core-dump suppression changed before durable launch admission".into(),
            );
            let cleanup = publisher.abandon_sensitive_output_prelaunch_v2(
                stdout.into_custody(),
                stderr.into_custody(),
            );
            return Err(match cleanup {
                Ok(()) => primary,
                Err(cleanup) => combine_attempt_and_capture_cleanup_errors(primary, cleanup),
            });
        }
        Err(error) => {
            let primary = sensitive_output_error(error);
            let cleanup = publisher.abandon_sensitive_output_prelaunch_v2(
                stdout.into_custody(),
                stderr.into_custody(),
            );
            return Err(match cleanup {
                Ok(()) => primary,
                Err(cleanup) => combine_attempt_and_capture_cleanup_errors(primary, cleanup),
            });
        }
    };
    let launch_intended_store_head = match publisher.record_launch_intended_v2(
        CONTAINED_CAPTURE_LAUNCH_SCHEMA,
        binding,
        &live_core_dump_suppression,
    ) {
        Ok(head) => head,
        Err(primary) => {
            let primary = SupervisorError::CommandOutputStore(primary);
            let cleanup =
                publisher.abandon_unpublished(stdout.into_custody(), stderr.into_custody());
            return Err(match cleanup {
                Ok(()) => primary,
                Err(cleanup) => combine_attempt_and_capture_cleanup_errors(primary, cleanup),
            });
        }
    };
    Ok(DurablyAnchoredCapture {
        stdout,
        stderr,
        publisher,
        capture_id: acquired.capture_id,
        acquired_anchor_digest: acquired.acquired_anchor_digest,
        launch_intended_store_head,
        core_dump_suppression: live_core_dump_suppression,
    })
}

fn combine_attempt_and_capture_cleanup_errors(
    primary: SupervisorError,
    cleanup: CommandOutputStoreError,
) -> SupervisorError {
    SupervisorError::CommandOutputCleanup {
        primary: Box::new(primary),
        cleanup: Box::new(cleanup),
    }
}

/// Runs a prepared command while preserving whether failure occurred
/// before or after the native launch boundary.
pub(crate) fn execute_classified<B: ContainedCommandBackend>(
    backend: B,
    prepared: PreparedContainedCommand,
    cancellation: &CancellationToken,
) -> ContainedExecutionOutcome {
    execute_classified_with_timing(
        backend,
        prepared,
        cancellation,
        CONTAINED_BACKEND_CLEANUP_TIMEOUT,
        POLL_INTERVAL,
        Instant::now,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the prelaunch sequence keeps preflight, durable capture anchoring, final cancellation/identity checks, launch, and supervision visibly ordered"
)]
pub(super) fn execute_classified_with_timing<B, N>(
    mut backend: B,
    prepared: PreparedContainedCommand,
    cancellation: &CancellationToken,
    cleanup_timeout: Duration,
    poll_interval: Duration,
    mut monotonic_now: N,
) -> ContainedExecutionOutcome
where
    B: ContainedCommandBackend,
    N: FnMut() -> Instant,
{
    let before_launch = (|| {
        let detector_policy = prepared.detector_policy().clone();
        let stdout_scanner = SensitiveOutputStreamScannerV1::try_new(
            &detector_policy,
            CONTAINED_BACKEND_POLL_CHUNK_LIMIT,
        )
        .map_err(sensitive_output_error)?;
        let stderr_scanner = SensitiveOutputStreamScannerV1::try_new(
            &detector_policy,
            CONTAINED_BACKEND_POLL_CHUNK_LIMIT,
        )
        .map_err(sensitive_output_error)?;
        if cancellation.is_cancelled() {
            return Err(SupervisorError::InvalidCommand(
                "cancellation was already requested before contained preflight".into(),
            ));
        }
        prepared.revalidate()?;
        let expected_cleanup_binding =
            command_domain_cleanup_binding(prepared.command_effect_authority())?;
        let expected_backend = backend.identity()?;
        expected_backend.validate()?;
        let report = backend.active_preflight(&prepared)?;
        let permit = validate_preflight(&prepared, &expected_backend, report)?;
        if cancellation.is_cancelled() {
            return Err(SupervisorError::InvalidCommand(
                "cancellation was requested before contained launch".into(),
            ));
        }
        prepared.revalidate()?;
        if backend.identity()? != expected_backend {
            return Err(SupervisorError::Capability(
                "containment backend identity changed between preflight and launch".into(),
            ));
        }
        let limits = prepared.policy.contract().resource_limits;
        let launch_digest = prepared.launch_digest.clone();
        let preflight_digest = permit.preflight_digest.clone();
        let backend_identity = permit.backend.clone();
        let supervision_authority = SupervisionAuthority {
            launch_digest,
            preflight_digest,
            backend: backend_identity,
            cleanup_binding: expected_cleanup_binding,
        };
        if cancellation.is_cancelled() {
            return Err(SupervisorError::InvalidCommand(
                "cancellation was requested before durable launch admission".into(),
            ));
        }
        prepared.revalidate()?;
        match backend.identity() {
            Ok(identity) if identity == expected_backend => {}
            Ok(_) => {
                return Err(SupervisorError::Capability(
                    "containment backend identity changed before durable launch admission".into(),
                ));
            }
            Err(primary) => return Err(primary),
        }
        let core_dump_suppression =
            enforce_core_dump_suppression_v1().map_err(sensitive_output_error)?;
        if cancellation.is_cancelled() {
            return Err(SupervisorError::InvalidCommand(
                "cancellation was requested before durable launch admission".into(),
            ));
        }
        prepared.revalidate()?;
        if backend.identity()? != expected_backend {
            return Err(SupervisorError::Capability(
                "containment backend identity changed before durable launch admission".into(),
            ));
        }
        let output_capture =
            durably_anchor_output_capture(&prepared, limits, &permit, &core_dump_suppression)?;
        Ok((
            limits,
            permit,
            supervision_authority,
            output_capture,
            detector_policy,
            stdout_scanner,
            stderr_scanner,
        ))
    })();
    let (
        limits,
        permit,
        supervision_authority,
        output_capture,
        detector_policy,
        stdout_scanner,
        stderr_scanner,
    ) = match before_launch {
        Ok(prepared) => prepared,
        Err(error) => return ContainedExecutionOutcome::RefusedBeforeLaunch(error),
    };

    let started = monotonic_now();
    let domain = match backend.launch(prepared, permit, &output_capture) {
        Ok(domain) => domain,
        Err(error) => {
            let cleanup = output_capture.retain_unclassified_for_reconciliation();
            let error = combine_attempt_and_capture_cleanup_errors(error, cleanup);
            return ContainedExecutionOutcome::UnprovenAfterLaunch(error);
        }
    };
    match supervise_domain(
        domain,
        limits,
        cancellation,
        supervision_authority,
        output_capture,
        detector_policy,
        stdout_scanner,
        stderr_scanner,
        started,
        cleanup_timeout,
        poll_interval,
        &mut monotonic_now,
    ) {
        Ok(SupervisedExecution::Completed(evidence)) => {
            ContainedExecutionOutcome::Terminal(evidence)
        }
        Ok(SupervisedExecution::SensitiveOutputRejected(evidence)) => {
            ContainedExecutionOutcome::SensitiveOutputRejected(evidence)
        }
        Err(error) => ContainedExecutionOutcome::UnprovenAfterLaunch(error),
    }
}

/// Runs a prepared command only through a backend that proves every control.
///
/// This compatibility surface intentionally flattens phase information.
/// Service routing must use [`execute_classified`] before deciding whether
/// a failure can truthfully be reported as occurring before native launch.
pub(crate) fn execute<B: ContainedCommandBackend>(
    backend: B,
    prepared: PreparedContainedCommand,
    cancellation: &CancellationToken,
) -> Result<ContainedExecutionEvidence, SupervisorError> {
    match execute_classified(backend, prepared, cancellation) {
        ContainedExecutionOutcome::Terminal(evidence) => Ok(evidence),
        ContainedExecutionOutcome::SensitiveOutputRejected(_) => Err(SupervisorError::Capability(
            "command output matched the admitted sensitive-output policy".into(),
        )),
        ContainedExecutionOutcome::RefusedBeforeLaunch(error)
        | ContainedExecutionOutcome::UnprovenAfterLaunch(error) => Err(error),
    }
}

pub(crate) fn required_controls(limits: ResourceLimits) -> BTreeSet<BackendControl> {
    let mut controls = BTreeSet::from([
        BackendControl::DescriptorExec,
        BackendControl::ExactArgv,
        BackendControl::ReplacedEnvironment,
        BackendControl::ClosedInheritedDescriptors,
        BackendControl::DescriptorWorkingDirectory,
        BackendControl::FilesystemPolicy,
        BackendControl::NetworkPolicy,
        BackendControl::ExternalWallClock,
        BackendControl::CompleteBoundedOutput,
        BackendControl::DescendantLimit,
        BackendControl::DescendantDomainKill,
        BackendControl::ActiveCanaries,
    ]);
    if limits.max_memory_bytes.is_some() {
        controls.insert(BackendControl::MemoryLimit);
    }
    controls
}

/// Crate-visible so a live measurement can mint a real permit rather than
/// assert that one could be minted. Widening the visibility does not weaken
/// the gate: this is still the only constructor of `ValidatedBackendPermit`
/// and it still requires exact-set equality.
pub(crate) fn validate_preflight(
    command: &PreparedContainedCommand,
    expected_backend: &BackendIdentity,
    report: BackendPreflightReport,
) -> Result<ValidatedBackendPermit, SupervisorError> {
    command.revalidate()?;
    report.backend.validate()?;
    if report.launch_digest != command.launch_digest {
        return Err(SupervisorError::Canary(
            "backend preflight was not bound to the exact contained launch".into(),
        ));
    }
    if &report.backend != expected_backend {
        return Err(SupervisorError::Capability(
            "backend preflight identity differs from the inspected implementation".into(),
        ));
    }
    let required = required_controls(command.policy.contract().resource_limits);
    if report.controls != required {
        let missing = required
            .difference(&report.controls)
            .copied()
            .collect::<Vec<_>>();
        let unexpected = report
            .controls
            .difference(&required)
            .copied()
            .collect::<Vec<_>>();
        return Err(SupervisorError::Capability(format!(
            "containment preflight controls differ from the exact policy: missing {missing:?}, unexpected {unexpected:?}"
        )));
    }
    let closed_descriptors = validate_closed_exec_descriptor_report(&report.target_descriptors)
        .map_err(|error| SupervisorError::Canary(error.to_string()))?;
    let canary_digest = match report.canary_status {
        BackendCanaryStatus::Passed(digest) => digest,
        BackendCanaryStatus::Failed(reason) => {
            return Err(SupervisorError::Canary(bounded_backend_reason(&reason)));
        }
    };
    let preflight_digest = compute_preflight_digest(
        &report.launch_digest,
        &report.backend,
        &report.controls,
        closed_descriptors.descriptors(),
        &canary_digest,
    );
    Ok(ValidatedBackendPermit {
        launch_digest: report.launch_digest,
        backend: report.backend,
        preflight_digest,
        closed_descriptors,
    })
}

fn bounded_backend_reason(reason: &str) -> String {
    const MAX_REASON_BYTES: usize = 512;
    if reason.len() <= MAX_REASON_BYTES {
        return reason.to_owned();
    }
    let mut end = MAX_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &reason[..end])
}

#[derive(Debug)]
struct StreamAccumulator {
    retained: Vec<u8>,
    hasher: Sha256,
    complete_length: u64,
}

impl StreamAccumulator {
    fn new() -> Self {
        Self {
            retained: Vec::new(),
            hasher: Sha256::new(),
            complete_length: 0,
        }
    }

    fn append(
        &mut self,
        bytes: &[u8],
        remaining_retention: &mut u64,
    ) -> Result<(), SupervisorError> {
        let length = u64::try_from(bytes.len()).map_err(|_| {
            SupervisorError::Capability("backend output chunk length does not fit u64".into())
        })?;
        self.complete_length = self.complete_length.checked_add(length).ok_or_else(|| {
            SupervisorError::Capability("backend output length overflowed u64".into())
        })?;
        self.hasher.update(bytes);
        let retained = usize::try_from((*remaining_retention).min(length)).map_err(|_| {
            SupervisorError::Capability("retained output length does not fit usize".into())
        })?;
        self.retained.extend_from_slice(&bytes[..retained]);
        *remaining_retention = remaining_retention
            .saturating_sub(u64::try_from(retained).expect("retained slice length fits u64"));
        Ok(())
    }

    fn finish(self) -> StreamCapture {
        StreamCapture {
            retained: self.retained,
            complete_digest: digest_from_sha(self.hasher.finalize().into()),
            complete_length: self.complete_length,
        }
    }
}

#[derive(Default)]
struct DomainStateTracker {
    leader: Option<BackendTermination>,
    stdout_closed: bool,
    stderr_closed: bool,
    domain_empty: bool,
}

impl DomainStateTracker {
    fn validate(&mut self, observation: &DomainObservation) -> Result<(), SupervisorError> {
        if observation.stdout.len() > CONTAINED_BACKEND_POLL_CHUNK_LIMIT
            || observation.stderr.len() > CONTAINED_BACKEND_POLL_CHUNK_LIMIT
        {
            return Err(SupervisorError::Capability(
                "containment backend exceeded the bounded poll chunk ABI".into(),
            ));
        }
        if (self.stdout_closed && (!observation.stdout.is_empty() || !observation.stdout_closed))
            || (self.stderr_closed
                && (!observation.stderr.is_empty() || !observation.stderr_closed))
            || (self.domain_empty && !observation.domain_empty)
        {
            return Err(SupervisorError::Capability(
                "containment backend reported non-monotonic stream or descendant state".into(),
            ));
        }
        match observation.leader {
            Some(BackendTermination::Exited(code)) if code < 0 => {
                return Err(SupervisorError::Capability(
                    "containment backend reported a negative exit code".into(),
                ));
            }
            Some(BackendTermination::Signaled(signal)) if signal <= 0 => {
                return Err(SupervisorError::Capability(
                    "containment backend reported a nonpositive signal".into(),
                ));
            }
            Some(BackendTermination::Exited(_) | BackendTermination::Signaled(_)) | None => {}
        }
        if let Some(previous) = self.leader
            && observation.leader != Some(previous)
        {
            return Err(SupervisorError::Capability(
                "containment backend changed a terminal leader status".into(),
            ));
        }
        if observation.domain_empty && observation.leader.is_none() {
            return Err(SupervisorError::Capability(
                "containment backend claimed an empty domain before leader termination".into(),
            ));
        }
        if observation.domain_empty && (!observation.stdout_closed || !observation.stderr_closed) {
            return Err(SupervisorError::Capability(
                "containment backend claimed an empty domain while command output pipes remained open"
                    .into(),
            ));
        }
        self.leader = observation.leader;
        self.stdout_closed = observation.stdout_closed;
        self.stderr_closed = observation.stderr_closed;
        self.domain_empty = observation.domain_empty;
        Ok(())
    }

    fn complete(&self) -> bool {
        self.leader.is_some() && self.stdout_closed && self.stderr_closed && self.domain_empty
    }
}

struct SupervisionAuthority {
    launch_digest: Digest,
    preflight_digest: Digest,
    backend: BackendIdentity,
    cleanup_binding: CommandDomainCleanupBinding,
}

struct CleanSupervisedTerminal {
    termination: CommandTermination,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    output_digest: Digest,
    cleanup_proof: ValidatedCommandDomainCleanupProof,
    duration_ms: u64,
}

struct SensitiveSupervisedTerminal {
    termination: CommandTermination,
    cleanup_proof: ValidatedCommandDomainCleanupProof,
}

enum SupervisedTerminal {
    Clean(CleanSupervisedTerminal),
    SensitiveOutputRejected(SensitiveSupervisedTerminal),
}

#[allow(
    clippy::large_enum_variant,
    reason = "each terminal evidence variant is consumed exactly once at the phase boundary"
)]
enum SupervisedExecution {
    Completed(ContainedExecutionEvidence),
    SensitiveOutputRejected(ContainedSensitiveOutputRejectionEvidence),
}

#[derive(Debug)]
pub(super) struct PublishedCommandOutput {
    reference: CommandOutputArtifactSetReferenceV1,
    capture_id: String,
    finished_store_head: CommandOutputCaptureStoreHeadV1,
    published_store_head: CommandOutputCaptureStoreHeadV1,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "supervision keeps the domain, authenticated authority, durable output custody, publication heads, and injectable monotonic timing explicit"
)]
fn supervise_domain<D, N>(
    domain: D,
    limits: ResourceLimits,
    cancellation: &CancellationToken,
    authority: SupervisionAuthority,
    output_capture: DurablyAnchoredCapture,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    stdout_scanner: SensitiveOutputStreamScannerV1,
    stderr_scanner: SensitiveOutputStreamScannerV1,
    started: Instant,
    cleanup_timeout: Duration,
    poll_interval: Duration,
    monotonic_now: &mut N,
) -> Result<SupervisedExecution, SupervisorError>
where
    D: ContainedDescendantDomain,
    N: FnMut() -> Instant,
{
    let (
        mut raw_stdout,
        mut raw_stderr,
        publisher,
        output_capture_id,
        output_capture_acquired_anchor_digest,
        output_capture_launch_intended_store_head,
    ) = output_capture.into_parts();
    let mut record_sensitive_output_detected = || {
        publisher
            .record_sensitive_output_detected_v2(
                &output_capture_launch_intended_store_head,
                &detector_policy,
            )
            .map(|_| ())
            .map_err(SupervisorError::from)
    };
    let mut sensitive_output_match_seen = false;
    let terminal = supervise_domain_inner(
        domain,
        limits,
        cancellation,
        &authority,
        &mut raw_stdout,
        &mut raw_stderr,
        stdout_scanner,
        stderr_scanner,
        &mut record_sensitive_output_detected,
        &mut sensitive_output_match_seen,
        started,
        cleanup_timeout,
        poll_interval,
        monotonic_now,
    );
    let terminal = match terminal {
        Ok(terminal) => terminal,
        Err(error) => {
            if sensitive_output_match_seen {
                let reconciliation = publisher.sensitive_output_reconciliation_required();
                drop(raw_stdout);
                drop(raw_stderr);
                drop(publisher);
                return Err(SupervisorError::CommandOutputStore(reconciliation));
            }
            let cleanup = publisher.unclassified_sensitive_output_reconciliation_required();
            drop(raw_stdout);
            drop(raw_stderr);
            drop(publisher);
            return Err(combine_attempt_and_capture_cleanup_errors(error, cleanup));
        }
    };
    let terminal = match terminal {
        SupervisedTerminal::Clean(terminal) => terminal,
        SupervisedTerminal::SensitiveOutputRejected(terminal) => {
            let termination = command_termination_v1(terminal.termination)?;
            let command_domain_cleanup_proof_id = terminal
                .cleanup_proof
                .os_evidence_digest()
                .as_str()
                .to_owned();
            let acquired = publisher.sensitive_output_acquired_evidence_v1()?;
            let terminal_observation = SensitiveOutputTerminalObservationV1::try_new_rejection(
                output_capture_id.clone(),
                termination,
                authority.backend.command_domain_backend(),
                &authority.cleanup_binding,
                &terminal.cleanup_proof,
            )
            .map_err(|error| {
                terminal_observation_reconciliation(
                    &output_capture_id,
                    &acquired,
                    None,
                    "construct exact rejection terminal observation",
                    &error,
                )
            })?;
            terminal_observation
                .validate_expected(
                    &output_capture_id,
                    crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Rejection,
                    authority.backend.command_domain_backend(),
                    &authority.cleanup_binding,
                    &terminal.cleanup_proof,
                )
                .map_err(|error| {
                    terminal_observation_reconciliation(
                        &output_capture_id,
                        &acquired,
                        None,
                        "cross rejection terminal observation with live authority",
                        &error,
                    )
                })?;
            let persisted_observation = publisher
                .publish_sensitive_output_terminal_observation_v1(&terminal_observation)?;
            if persisted_observation != terminal_observation {
                return Err(terminal_observation_reconciliation_message(
                    &output_capture_id,
                    &acquired,
                    None,
                    "read back exact rejection terminal observation",
                    "published sidecar differs from the constructed observation",
                ));
            }
            let staging_neutralization = publisher
                .neutralize_sensitive_output_staging_v2(&mut raw_stdout, &mut raw_stderr)?;
            let abandonment = publisher.abandon_sensitive_output_v2(
                raw_stdout.into_custody(),
                raw_stderr.into_custody(),
                termination,
                &command_domain_cleanup_proof_id,
                &detector_policy,
                &staging_neutralization,
            )?;
            let cleaned_store_head = abandonment
                .recovery
                .cleaned_store_head()
                .cloned()
                .ok_or_else(|| {
                    SupervisorError::CommandOutputStore(
                        CommandOutputStoreError::ReconciliationRequired {
                            capture_id: Some(output_capture_id.clone()),
                            source: Box::new(abandonment.recovery.source().clone()),
                            expected_reference: None,
                            reason: "sensitive-output cleanup lost its exact Cleaned journal head"
                                .into(),
                        },
                    )
                })?;
            return Ok(SupervisedExecution::SensitiveOutputRejected(
                ContainedSensitiveOutputRejectionEvidence {
                    termination: terminal.termination,
                    detector_policy,
                    output_capture_id,
                    output_capture_acquired_anchor_digest,
                    output_capture_launch_intended_store_head,
                    output_capture_cleaned_store_head: cleaned_store_head,
                    journal_receipt: abandonment.journal_receipt,
                    backend: authority.backend,
                    cleanup_proof: terminal.cleanup_proof,
                },
            ));
        }
    };

    publisher.record_sensitive_output_scanned_clean_v2()?;

    let raw_stdout = match raw_stdout.finish() {
        Ok(finished) => finished,
        Err(failure) => {
            let (error, stdout_custody) = failure.into_parts();
            let cleanup = publisher.abandon_unpublished(stdout_custody, raw_stderr.into_custody());
            return Err(match cleanup {
                Ok(()) => error.into(),
                Err(cleanup) => combine_attempt_and_capture_cleanup_errors(
                    SupervisorError::from(error),
                    cleanup,
                ),
            });
        }
    };
    let raw_stderr = match raw_stderr.finish() {
        Ok(finished) => finished,
        Err(failure) => {
            let (error, stderr_custody) = failure.into_parts();
            let cleanup = publisher.abandon_unpublished(raw_stdout.into_custody(), stderr_custody);
            return Err(match cleanup {
                Ok(()) => error.into(),
                Err(cleanup) => combine_attempt_and_capture_cleanup_errors(
                    SupervisorError::from(error),
                    cleanup,
                ),
            });
        }
    };
    let acquired = publisher.sensitive_output_acquired_evidence_v1()?;
    let expected_output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
        acquired.source.clone(),
        raw_stdout.artifact(),
        raw_stderr.artifact(),
    )
    .map_err(|error| {
        terminal_observation_reconciliation_message(
            &output_capture_id,
            &acquired,
            None,
            "construct exact clean terminal artifact reference",
            &error.to_string(),
        )
    })?;
    if expected_output_artifacts.stdout.byte_length != terminal.stdout.complete_length()
        || expected_output_artifacts.stdout.content_digest != *terminal.stdout.complete_digest()
        || expected_output_artifacts.stderr.byte_length != terminal.stderr.complete_length()
        || expected_output_artifacts.stderr.content_digest != *terminal.stderr.complete_digest()
    {
        return Err(terminal_observation_reconciliation_message(
            &output_capture_id,
            &acquired,
            Some(&expected_output_artifacts),
            "cross finished clean streams with independently accumulated output",
            "finished stream commitments differ",
        ));
    }
    let wire_stdout = wire_command_stream_evidence(&terminal.stdout);
    let wire_stderr = wire_command_stream_evidence(&terminal.stderr);
    let wire_backend = wire_command_backend_identity(&authority.backend);
    let clean_response = SensitiveOutputCleanTerminalResponseV1::try_new(
        wire_stdout,
        wire_stderr,
        expected_output_artifacts.clone(),
        terminal.output_digest.clone(),
        authority.launch_digest.clone(),
        authority.preflight_digest.clone(),
        wire_backend.clone(),
        terminal.duration_ms,
    )
    .map_err(|error| {
        terminal_observation_reconciliation(
            &output_capture_id,
            &acquired,
            Some(&expected_output_artifacts),
            "construct exact clean terminal response",
            &error,
        )
    })?;
    let termination = command_termination_v1(terminal.termination)?;
    let terminal_observation = SensitiveOutputTerminalObservationV1::try_new_clean(
        output_capture_id.clone(),
        termination,
        authority.backend.command_domain_backend(),
        &authority.cleanup_binding,
        &terminal.cleanup_proof,
        clean_response,
    )
    .map_err(|error| {
        terminal_observation_reconciliation(
            &output_capture_id,
            &acquired,
            Some(&expected_output_artifacts),
            "construct exact clean terminal observation",
            &error,
        )
    })?;
    terminal_observation
        .validate_expected_clean_live(
            &output_capture_id,
            authority.backend.command_domain_backend(),
            &authority.cleanup_binding,
            &terminal.cleanup_proof,
            &acquired,
            &authority.launch_digest,
            &authority.preflight_digest,
            &wire_backend,
        )
        .map_err(|error| {
            terminal_observation_reconciliation(
                &output_capture_id,
                &acquired,
                Some(&expected_output_artifacts),
                "cross clean terminal observation with live authority",
                &error,
            )
        })?;
    let persisted_observation =
        publisher.publish_sensitive_output_terminal_observation_v1(&terminal_observation)?;
    if persisted_observation != terminal_observation {
        return Err(terminal_observation_reconciliation_message(
            &output_capture_id,
            &acquired,
            Some(&expected_output_artifacts),
            "read back exact clean terminal observation",
            "published sidecar differs from the constructed observation",
        ));
    }
    let published_output = publish_matching_output(
        publisher,
        raw_stdout,
        raw_stderr,
        &terminal.stdout,
        &terminal.stderr,
    )?;
    if published_output.capture_id != output_capture_id
        || output_capture_launch_intended_store_head.generation
            >= published_output.finished_store_head.generation
        || published_output.finished_store_head.generation
            >= published_output.published_store_head.generation
    {
        return Err(SupervisorError::CommandOutputStore(
            CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(output_capture_id),
                source: Box::new(published_output.reference.source.clone()),
                expected_reference: Some(Box::new(published_output.reference)),
                reason: "published command output crossed capture identity or non-monotonic LaunchIntended/Finished/Published journal heads"
                    .into(),
            },
        ));
    }
    Ok(SupervisedExecution::Completed(ContainedExecutionEvidence {
        termination: terminal.termination,
        stdout: terminal.stdout,
        stderr: terminal.stderr,
        output_digest: terminal.output_digest,
        output_artifacts: published_output.reference,
        output_capture_id: published_output.capture_id,
        output_capture_acquired_anchor_digest,
        output_capture_launch_intended_store_head,
        output_capture_finished_store_head: published_output.finished_store_head,
        output_capture_published_store_head: published_output.published_store_head,
        launch_digest: authority.launch_digest,
        preflight_digest: authority.preflight_digest,
        backend: authority.backend,
        cleanup_proof: terminal.cleanup_proof,
        duration_ms: terminal.duration_ms,
    }))
}

pub(super) fn publish_matching_output(
    publisher: CommandOutputPublisher,
    raw_stdout: FinishedCommandOutputStream,
    raw_stderr: FinishedCommandOutputStream,
    expected_stdout: &CapturedOutput,
    expected_stderr: &CapturedOutput,
) -> Result<PublishedCommandOutput, SupervisorError> {
    let stdout_artifact = raw_stdout.artifact();
    let stderr_artifact = raw_stderr.artifact();
    if stdout_artifact.byte_length != expected_stdout.complete_length()
        || stdout_artifact.content_digest != *expected_stdout.complete_digest()
        || stderr_artifact.byte_length != expected_stderr.complete_length()
        || stderr_artifact.content_digest != *expected_stderr.complete_digest()
    {
        let primary = SupervisorError::CommandOutputStore(CommandOutputStoreError::Reference(
            "unpublished raw streams differ from independently accumulated command output".into(),
        ));
        let cleanup =
            publisher.abandon_unpublished(raw_stdout.into_custody(), raw_stderr.into_custody());
        return Err(match cleanup {
            Ok(()) => primary,
            Err(cleanup) => combine_attempt_and_capture_cleanup_errors(primary, cleanup),
        });
    }
    let artifacts = publisher.publish(raw_stdout, raw_stderr)?;
    let reference = artifacts.reference().clone();
    let capture_id = artifacts.capture_id().ok_or_else(|| {
        SupervisorError::CommandOutputStore(CommandOutputStoreError::ReconciliationRequired {
            capture_id: None,
            source: Box::new(reference.source.clone()),
            expected_reference: Some(Box::new(reference.clone())),
            reason: "published current command output lost its capture identity".into(),
        })
    })?;
    let finished_store_head = artifacts
        .capture_finished_store_head()
        .cloned()
        .ok_or_else(|| {
            SupervisorError::CommandOutputStore(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id.to_owned()),
                source: Box::new(reference.source.clone()),
                expected_reference: Some(Box::new(reference.clone())),
                reason: "published current command output lost its durable Finished head".into(),
            })
        })?;
    let published_store_head = artifacts
        .capture_published_store_head()
        .cloned()
        .ok_or_else(|| {
            SupervisorError::CommandOutputStore(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id.to_owned()),
                source: Box::new(reference.source.clone()),
                expected_reference: Some(Box::new(reference.clone())),
                reason: "published current command output lost its durable Published head".into(),
            })
        })?;
    Ok(PublishedCommandOutput {
        reference,
        capture_id: capture_id.to_owned(),
        finished_store_head,
        published_store_head,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "supervision keeps native domain, immutable authority, two independent raw streams, policy, cancellation, and monotonic time explicit"
)]
fn supervise_domain_inner<D, N>(
    mut domain: D,
    limits: ResourceLimits,
    cancellation: &CancellationToken,
    authority: &SupervisionAuthority,
    raw_stdout: &mut CommandOutputStreamCapture,
    raw_stderr: &mut CommandOutputStreamCapture,
    mut stdout_scanner: SensitiveOutputStreamScannerV1,
    mut stderr_scanner: SensitiveOutputStreamScannerV1,
    record_sensitive_output_detected: &mut impl FnMut() -> Result<(), SupervisorError>,
    sensitive_output_match_seen: &mut bool,
    started: Instant,
    cleanup_timeout: Duration,
    poll_interval: Duration,
    monotonic_now: &mut N,
) -> Result<SupervisedTerminal, SupervisorError>
where
    D: ContainedDescendantDomain,
    N: FnMut() -> Instant,
{
    let deadline = started + Duration::from_millis(limits.wall_time_ms);
    let mut cleanup_deadline = None;
    let mut requested_termination = None;
    let mut cleanup_observations = 0_u64;
    let mut state = DomainStateTracker::default();
    let mut stdout = StreamAccumulator::new();
    let mut stderr = StreamAccumulator::new();
    let wire_retention_ceiling = limits.max_output_bytes.min(
        u64::try_from(MAX_INLINE_COMMAND_RETAINED_BYTES)
            .expect("terminal-wire retention ceiling fits u64"),
    );
    let mut remaining_retention = wire_retention_ceiling;
    let mut total_output = 0_u64;
    let mut detection_journal_error = None;

    loop {
        reject_expired_cleanup_deadline(cleanup_deadline, monotonic_now())?;
        if requested_termination.is_some()
            && cleanup_observations >= CONTAINED_CLEANUP_OBSERVATION_LIMIT
        {
            return Err(SupervisorError::Capability(format!(
                "containment backend exceeded the bounded {CONTAINED_CLEANUP_OBSERVATION_LIMIT}-observation cleanup drain"
            )));
        }
        let mut observation = domain.poll(CONTAINED_BACKEND_POLL_CHUNK_LIMIT)?;
        let observed_at = monotonic_now();
        reject_expired_cleanup_deadline(cleanup_deadline, observed_at)?;
        if requested_termination.is_some() {
            cleanup_observations = cleanup_observations.saturating_add(1);
        }
        state.validate(&observation)?;
        let observed_now = u64::try_from(
            observation
                .stdout
                .len()
                .saturating_add(observation.stderr.len()),
        )
        .map_err(|_| {
            SupervisorError::Capability("combined output chunk does not fit u64".into())
        })?;
        if !*sensitive_output_match_seen {
            match stdout_scanner.screen(&observation.stdout) {
                ScreenedSensitiveOutputChunkV1::CleanPrefix(prefix) => {
                    raw_stdout.append(prefix)?;
                    stdout.append(prefix, &mut remaining_retention)?;
                }
                ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected => {
                    *sensitive_output_match_seen = true;
                    if let Err(error) = record_sensitive_output_detected() {
                        detection_journal_error = Some(error);
                    }
                }
                ScreenedSensitiveOutputChunkV1::ChunkTooLarge => {
                    return Err(SupervisorError::Capability(
                        "sensitive-output scanner received an oversized backend chunk".into(),
                    ));
                }
                ScreenedSensitiveOutputChunkV1::Closed => {
                    return Err(SupervisorError::Capability(
                        "sensitive-output stdout scanner was reused after terminal closure".into(),
                    ));
                }
            }
        }
        if !*sensitive_output_match_seen {
            match stderr_scanner.screen(&observation.stderr) {
                ScreenedSensitiveOutputChunkV1::CleanPrefix(prefix) => {
                    raw_stderr.append(prefix)?;
                    stderr.append(prefix, &mut remaining_retention)?;
                }
                ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected => {
                    *sensitive_output_match_seen = true;
                    if let Err(error) = record_sensitive_output_detected() {
                        detection_journal_error = Some(error);
                    }
                }
                ScreenedSensitiveOutputChunkV1::ChunkTooLarge => {
                    return Err(SupervisorError::Capability(
                        "sensitive-output scanner received an oversized backend chunk".into(),
                    ));
                }
                ScreenedSensitiveOutputChunkV1::Closed => {
                    return Err(SupervisorError::Capability(
                        "sensitive-output stderr scanner was reused after terminal closure".into(),
                    ));
                }
            }
        }
        // Best-effort in-process hygiene only: retained-artifact safety is
        // established by screening before both sinks and by proven capture
        // cleanup. Wipe the backend-owned observations once rejection is
        // known, including every later cleanup-drain chunk, before drop.
        if *sensitive_output_match_seen {
            observation.stdout.fill(0);
            observation.stderr.fill(0);
        }
        total_output = total_output.checked_add(observed_now).ok_or_else(|| {
            SupervisorError::Capability("combined output length overflowed u64".into())
        })?;

        let requested = if *sensitive_output_match_seen {
            Some(DomainTerminationRequest::SensitiveOutputRejected)
        } else if cancellation.is_cancelled() {
            Some(DomainTerminationRequest::Cancelled)
        } else if total_output > limits.max_output_bytes {
            Some(DomainTerminationRequest::OutputLimitExceeded)
        } else if observed_at >= deadline {
            Some(DomainTerminationRequest::TimedOut)
        } else if observation.leader.is_some() && !observation.domain_empty {
            Some(DomainTerminationRequest::LeaderExitedWithDescendants)
        } else {
            None
        };
        if requested_termination.is_none()
            && let Some(reason) = requested
        {
            domain.terminate_all(reason)?;
            requested_termination = Some(reason);
            cleanup_deadline = Some(observed_at.checked_add(cleanup_timeout).ok_or_else(|| {
                SupervisorError::Capability(
                    "containment cleanup deadline overflowed monotonic time".into(),
                )
            })?);
        }

        if state.complete() {
            let cleanup_proof = domain.into_cleanup_proof()?;
            cleanup_proof.validate()?;
            if cleanup_proof.backend() != authority.backend.command_domain_backend() {
                return Err(CommandDomainCleanupProofError::ExpectedBackendMismatch.into());
            }
            if cleanup_proof.binding() != &authority.cleanup_binding {
                return Err(CommandDomainCleanupProofError::ExpectedBindingMismatch.into());
            }
            if let Some(error) = detection_journal_error {
                return Err(error);
            }
            let backend_termination = state
                .leader
                .expect("complete state necessarily has leader termination");
            let actual_termination = match backend_termination {
                BackendTermination::Exited(status) => CommandTermination::Exited(status),
                BackendTermination::Signaled(signal) => CommandTermination::Signaled(signal),
            };
            let termination = match requested_termination {
                Some(DomainTerminationRequest::Cancelled) => CommandTermination::Cancelled,
                Some(DomainTerminationRequest::TimedOut) => CommandTermination::TimedOut,
                Some(DomainTerminationRequest::OutputLimitExceeded) => {
                    CommandTermination::OutputLimitExceeded
                }
                Some(
                    DomainTerminationRequest::SensitiveOutputRejected
                    | DomainTerminationRequest::LeaderExitedWithDescendants,
                )
                | None => actual_termination,
            };
            if *sensitive_output_match_seen {
                return Ok(SupervisedTerminal::SensitiveOutputRejected(
                    SensitiveSupervisedTerminal {
                        termination: actual_termination,
                        cleanup_proof,
                    },
                ));
            }
            let stdout_tail = stdout_scanner
                .finish()
                .ok_or_else(|| sensitive_output_error(SensitiveOutputError::PreallocationFailed))?;
            raw_stdout.append(stdout_tail)?;
            stdout.append(stdout_tail, &mut remaining_retention)?;
            let stderr_tail = stderr_scanner
                .finish()
                .ok_or_else(|| sensitive_output_error(SensitiveOutputError::PreallocationFailed))?;
            raw_stderr.append(stderr_tail)?;
            stderr.append(stderr_tail, &mut remaining_retention)?;
            let (stdout, stderr) =
                bound_retained_output(stdout.finish(), stderr.finish(), wire_retention_ceiling);
            let output_digest = combined_output_digest(&stdout, &stderr);
            return Ok(SupervisedTerminal::Clean(CleanSupervisedTerminal {
                termination,
                stdout,
                stderr,
                output_digest,
                cleanup_proof,
                duration_ms: duration_ms(started.elapsed()),
            }));
        }

        if poll_interval.is_zero() {
            thread::yield_now();
        } else {
            thread::sleep(poll_interval);
        }
    }
}

fn reject_expired_cleanup_deadline(
    cleanup_deadline: Option<Instant>,
    observed_at: Instant,
) -> Result<(), SupervisorError> {
    if cleanup_deadline.is_some_and(|deadline| observed_at >= deadline) {
        return Err(SupervisorError::Capability(
            "containment backend could not prove the descendant domain empty before the cleanup deadline"
                .into(),
        ));
    }
    Ok(())
}

fn sensitive_output_error(error: SensitiveOutputError) -> SupervisorError {
    let message = match error {
        SensitiveOutputError::PolicyMismatch => {
            "sensitive-output detector policy differs from the compiled fixed matcher"
        }
        SensitiveOutputError::PreallocationFailed => {
            "bounded sensitive-output suffix preallocation failed"
        }
        SensitiveOutputError::CoreDumpSuppressionFailed => {
            "runner core-dump suppression could not be installed and read back"
        }
    };
    SupervisorError::Capability(message.into())
}

fn wire_command_stream_evidence(output: &CapturedOutput) -> WireCommandStreamEvidence {
    WireCommandStreamEvidence {
        retained_bytes: output.bytes().to_vec(),
        complete_digest: output.complete_digest().clone(),
        complete_length: output.complete_length(),
        truncated: output.truncated(),
    }
}

fn wire_command_backend_identity(backend: &BackendIdentity) -> WireCommandBackendIdentity {
    WireCommandBackendIdentity {
        command_domain_backend: backend.command_domain_backend(),
        backend_id: backend.backend_id().to_owned(),
        implementation_digest: backend.implementation_digest().clone(),
    }
}

fn terminal_observation_reconciliation(
    capture_id: &str,
    acquired: &CommandOutputCaptureAcquiredV1,
    expected_reference: Option<&CommandOutputArtifactSetReferenceV1>,
    operation: &'static str,
    error: &SensitiveOutputTerminalObservationError,
) -> SupervisorError {
    terminal_observation_reconciliation_message(
        capture_id,
        acquired,
        expected_reference,
        operation,
        &error.to_string(),
    )
}

fn terminal_observation_reconciliation_message(
    capture_id: &str,
    acquired: &CommandOutputCaptureAcquiredV1,
    expected_reference: Option<&CommandOutputArtifactSetReferenceV1>,
    operation: &'static str,
    error: &str,
) -> SupervisorError {
    SupervisorError::CommandOutputStore(CommandOutputStoreError::ReconciliationRequired {
        capture_id: Some(capture_id.to_owned()),
        source: Box::new(acquired.source.clone()),
        expected_reference: expected_reference.cloned().map(Box::new),
        reason: format!(
            "{operation} failed after terminal branch classification; private custody remains retained: {error}"
        ),
    })
}

fn command_termination_v1(
    termination: CommandTermination,
) -> Result<grok_build_core::CommandTerminationV1, SupervisorError> {
    let termination = match termination {
        CommandTermination::Exited(code) => grok_build_core::CommandTerminationV1::Exited { code },
        CommandTermination::Signaled(signal) => {
            grok_build_core::CommandTerminationV1::Signaled { signal }
        }
        CommandTermination::TimedOut => grok_build_core::CommandTerminationV1::TimedOut,
        CommandTermination::Cancelled => grok_build_core::CommandTerminationV1::Canceled,
        CommandTermination::OutputLimitExceeded => {
            grok_build_core::CommandTerminationV1::OutputLimitExceeded
        }
    };
    termination
        .validate()
        .map_err(|error| SupervisorError::Capability(error.to_string()))?;
    Ok(termination)
}

include!("contained_boundary/validation.rs");
