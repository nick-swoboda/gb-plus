//! Execution policy, mutation artifacts, verification, and acceptance evidence.

use super::{
    BTreeSet, COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION, COMMAND_OUTPUT_ARTIFACT_SET_DIGEST_DOMAIN,
    COMMAND_STREAM_OUTPUT_DIGEST_DOMAIN, CONTRACT_VERSION, CommandSpec, ContractError, Deserialize,
    Digest, MAX_COMMAND_OUTPUT_ARTIFACT_ID_BYTES, Path, PathBuf, PathScope, Serialize, WorkerLease,
    WorkspaceGrant, WorkspaceNetworkPolicy, require_bounded_nonblank, require_contract_envelope,
    require_nonblank, require_nonzero_timestamp, require_normalized_relative,
    require_unique_nonblank,
};

/// Network mode for one runner process.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ExecutionNetwork {
    /// Create a sandbox without host networking.
    None,
    /// Permit host networking for this action only.
    FullForAction,
}

/// Filesystem mutation mode for one runner process.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MutationMode {
    /// The workspace is mounted read-only.
    ReadOnly,
    /// Writes target a private shadow workspace.
    ShadowWorkspace,
}

/// A sanitized environment entry explicitly passed to a runner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentVariable {
    /// Case-sensitive environment name.
    pub name: String,
    /// Non-secret value selected by the trusted policy compiler.
    pub value: String,
}

impl EnvironmentVariable {
    fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("execution_policy.environment.name", &self.name)?;
        if self.name.contains('=') || self.name.as_bytes().contains(&0) {
            return Err(ContractError::new(
                "execution_policy.environment.name",
                "must not contain `=` or NUL",
            ));
        }
        if self.value.as_bytes().contains(&0) {
            return Err(ContractError::new(
                "execution_policy.environment.value",
                "must not contain NUL",
            ));
        }
        Ok(())
    }
}

/// Runner resource ceilings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceLimits {
    /// Maximum process wall time.
    pub wall_time_ms: u64,
    /// Maximum captured output before spooling or truncation.
    pub max_output_bytes: u64,
    /// Maximum number of descendant processes.
    pub max_processes: u32,
    /// Optional address-space ceiling.
    pub max_memory_bytes: Option<u64>,
}

impl ResourceLimits {
    fn validate(self) -> Result<(), ContractError> {
        if self.wall_time_ms == 0 || self.max_output_bytes == 0 || self.max_processes == 0 {
            return Err(ContractError::new(
                "execution_policy.resource_limits",
                "time, output, and process limits must be greater than zero",
            ));
        }
        if self.max_memory_bytes == Some(0) {
            return Err(ContractError::new(
                "execution_policy.resource_limits.max_memory_bytes",
                "must be greater than zero when present",
            ));
        }
        Ok(())
    }
}

/// Immutable runner authority derived from a workspace grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    /// Stable policy identifier.
    pub policy_id: String,
    /// Digest of the authorizing grant.
    pub grant_hash: Digest,
    /// Exact canonical workspace root.
    pub workspace_root: PathBuf,
    /// Workspace-relative readable scopes.
    pub read_scopes: Vec<PathScope>,
    /// Workspace-relative writable scopes.
    pub write_scopes: Vec<PathScope>,
    /// Explicit sanitized environment.
    pub environment: Vec<EnvironmentVariable>,
    /// Per-action network authority.
    pub network: ExecutionNetwork,
    /// Filesystem mutation mode.
    pub mutation_mode: MutationMode,
    /// Process resource ceilings.
    pub resource_limits: ResourceLimits,
    /// Optional one-time approval for a separately authorized external effect.
    pub approval_id: Option<String>,
    /// Digest over the canonical serialized policy.
    pub policy_hash: Digest,
}

impl ExecutionPolicy {
    /// Performs legacy structural compatibility checks against a workspace grant.
    ///
    /// This method does not authenticate either hash, bind the grant to a live
    /// filesystem identity, or apply the production compiler's protected-path,
    /// environment, command-execution, and external-effect checks. Production
    /// execution must consume a compiled policy from the integrity-checked trust
    /// APIs exported by this crate.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the policy is malformed or requests any
    /// root, write, network, environment, or resource authority not permitted
    /// by the supplied grant.
    pub fn validate_against(&self, grant: &WorkspaceGrant) -> Result<(), ContractError> {
        grant.validate()?;
        require_nonblank("execution_policy.policy_id", &self.policy_id)?;
        if self.grant_hash != grant.grant_hash {
            return Err(ContractError::new(
                "execution_policy.grant_hash",
                "does not match the authorizing grant",
            ));
        }
        if self.workspace_root != grant.canonical_root {
            return Err(ContractError::new(
                "execution_policy.workspace_root",
                "does not exactly match the canonical grant root",
            ));
        }
        if self.read_scopes.is_empty() {
            return Err(ContractError::new(
                "execution_policy.read_scopes",
                "must contain at least one scope",
            ));
        }
        for scope in self.read_scopes.iter().chain(&self.write_scopes) {
            scope.validate()?;
        }
        if !grant.permissions.write_regular_files && !self.write_scopes.is_empty() {
            return Err(ContractError::new(
                "execution_policy.write_scopes",
                "grant does not authorize regular-file writes",
            ));
        }
        match self.mutation_mode {
            MutationMode::ReadOnly if !self.write_scopes.is_empty() => {
                return Err(ContractError::new(
                    "execution_policy.write_scopes",
                    "read-only execution cannot declare writable scopes",
                ));
            }
            MutationMode::ShadowWorkspace if self.write_scopes.is_empty() => {
                return Err(ContractError::new(
                    "execution_policy.write_scopes",
                    "shadow-workspace execution requires a writable scope",
                ));
            }
            MutationMode::ReadOnly | MutationMode::ShadowWorkspace => {}
        }
        if self.network == ExecutionNetwork::FullForAction
            && grant.network != WorkspaceNetworkPolicy::Allowed
        {
            return Err(ContractError::new(
                "execution_policy.network",
                "grant does not authorize command networking",
            ));
        }
        if let Some(approval_id) = &self.approval_id {
            require_nonblank("execution_policy.approval_id", approval_id)?;
        }
        let mut environment_names = BTreeSet::new();
        for variable in &self.environment {
            variable.validate()?;
            if !environment_names.insert(variable.name.as_str()) {
                return Err(ContractError::new(
                    "execution_policy.environment",
                    format!("duplicate environment variable `{}`", variable.name),
                ));
            }
        }
        self.resource_limits.validate()
    }
}

/// One regular-file operation in a staged change set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FileOperation {
    /// Create a file that was absent in the base snapshot.
    Create {
        /// Workspace-relative file path.
        path: PathBuf,
        /// Digest of the new contents.
        result_hash: Digest,
    },
    /// Replace a file whose base digest still matches.
    Modify {
        /// Workspace-relative file path.
        path: PathBuf,
        /// Expected base-content digest.
        base_hash: Digest,
        /// Digest of the new contents.
        result_hash: Digest,
    },
    /// Delete a file whose base digest still matches.
    Delete {
        /// Workspace-relative file path.
        path: PathBuf,
        /// Expected base-content digest.
        base_hash: Digest,
    },
}

impl FileOperation {
    /// Returns the workspace-relative target path.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Create { path, .. } | Self::Modify { path, .. } | Self::Delete { path, .. } => {
                path
            }
        }
    }

    fn validate(&self) -> Result<(), ContractError> {
        require_normalized_relative("change_set.operation.path", self.path())?;
        if let Self::Modify {
            base_hash,
            result_hash,
            ..
        } = self
            && base_hash == result_hash
        {
            return Err(ContractError::new(
                "change_set.operation",
                "a modification must change the content digest",
            ));
        }
        Ok(())
    }
}

/// Staged regular-file changes between two workspace snapshots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangeSet {
    /// Stable change-set identifier.
    pub change_set_id: String,
    /// Snapshot against which base hashes were computed.
    pub base_snapshot: Digest,
    /// Snapshot produced by the operations.
    pub result_snapshot: Digest,
    /// Ordered regular-file operations.
    pub operations: Vec<FileOperation>,
}

impl ChangeSet {
    /// Validates paths, hashes, and operation uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when snapshot equality and operation
    /// emptiness disagree, or for an invalid relative path, duplicate target,
    /// or no-op modification. An explicit task-level verified no-op is the
    /// sole empty shape: `base_snapshot == result_snapshot` and no operations.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("change_set.change_set_id", &self.change_set_id)?;
        let snapshots_equal = self.base_snapshot == self.result_snapshot;
        let operations_empty = self.operations.is_empty();
        if snapshots_equal != operations_empty {
            return Err(ContractError::new(
                "change_set.operations",
                "must be empty exactly when base and result snapshots are identical",
            ));
        }
        let mut paths = BTreeSet::new();
        for operation in &self.operations {
            operation.validate()?;
            if !paths.insert(operation.path()) {
                return Err(ContractError::new(
                    "change_set.operations",
                    format!("duplicate target path `{}`", operation.path().display()),
                ));
            }
        }
        Ok(())
    }

    /// Computes the domain-separated digest of the exact ordered operation
    /// envelopes.
    ///
    /// The digest is stable because it uses the same canonical `serde_json`
    /// representation persisted by the ledger. Operation order is evidence:
    /// callers must not sort or otherwise normalize a change set after it has
    /// been authorized.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if an operation path cannot be represented by
    /// the canonical contract encoding.
    pub fn applied_operations_digest(&self) -> Result<Digest, ContractError> {
        digest_canonical_contract(
            b"grok-build.applied-operations.v1\0",
            &self.operations,
            "change_set.operations",
        )
    }

    /// Computes the domain-separated digest of the exact ordered touched-path
    /// base and result endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if a path cannot be represented by the
    /// canonical contract encoding.
    pub fn touched_path_endpoints_digest(&self) -> Result<Digest, ContractError> {
        let endpoints = self
            .operations
            .iter()
            .map(CanonicalTouchedEndpoint::from)
            .collect::<Vec<_>>();
        digest_canonical_contract(
            b"grok-build.touched-path-endpoints.v1\0",
            &endpoints,
            "change_set.operations",
        )
    }

    /// Computes the domain-separated digest of the ordered set of touched
    /// paths, independent of their endpoint contents.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if a path cannot be represented by the
    /// canonical contract encoding.
    pub fn touched_target_set_digest(&self) -> Result<Digest, ContractError> {
        let paths = self
            .operations
            .iter()
            .map(FileOperation::path)
            .collect::<Vec<_>>();
        digest_canonical_contract(
            b"grok-build.touched-target-set.v1\0",
            &paths,
            "change_set.operations",
        )
    }

    /// Computes the domain-separated digest of the ordered base endpoints that
    /// a successful rollback must restore.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if a path cannot be represented by the
    /// canonical contract encoding.
    pub fn restored_base_endpoints_digest(&self) -> Result<Digest, ContractError> {
        let endpoints = self
            .operations
            .iter()
            .map(CanonicalRestoredEndpoint::from)
            .collect::<Vec<_>>();
        digest_canonical_contract(
            b"grok-build.restored-base-endpoints.v1\0",
            &endpoints,
            "change_set.operations",
        )
    }
}

#[derive(Serialize)]
pub(super) struct CanonicalTouchedEndpoint<'a> {
    path: &'a Path,
    base_hash: Option<&'a Digest>,
    result_hash: Option<&'a Digest>,
}

impl<'a> From<&'a FileOperation> for CanonicalTouchedEndpoint<'a> {
    fn from(operation: &'a FileOperation) -> Self {
        match operation {
            FileOperation::Create { path, result_hash } => Self {
                path,
                base_hash: None,
                result_hash: Some(result_hash),
            },
            FileOperation::Modify {
                path,
                base_hash,
                result_hash,
            } => Self {
                path,
                base_hash: Some(base_hash),
                result_hash: Some(result_hash),
            },
            FileOperation::Delete { path, base_hash } => Self {
                path,
                base_hash: Some(base_hash),
                result_hash: None,
            },
        }
    }
}

#[derive(Serialize)]
pub(super) struct CanonicalRestoredEndpoint<'a> {
    path: &'a Path,
    restored_hash: Option<&'a Digest>,
}

impl<'a> From<&'a FileOperation> for CanonicalRestoredEndpoint<'a> {
    fn from(operation: &'a FileOperation) -> Self {
        match operation {
            FileOperation::Create { path, .. } => Self {
                path,
                restored_hash: None,
            },
            FileOperation::Modify {
                path, base_hash, ..
            }
            | FileOperation::Delete { path, base_hash } => Self {
                path,
                restored_hash: Some(base_hash),
            },
        }
    }
}

pub(super) fn digest_canonical_contract<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
    field: &'static str,
) -> Result<Digest, ContractError> {
    let encoded = serde_json::to_vec(value).map_err(|error| {
        ContractError::new(field, format!("cannot encode canonically: {error}"))
    })?;
    let mut preimage = Vec::with_capacity(domain.len() + encoded.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&encoded);
    Ok(Digest::sha256(&preimage))
}

/// Exact durable relationship between a successful regular-file mutation and
/// the workspace artifacts it produced.
///
/// `input_snapshot` is the snapshot authorized by the effect intent. The
/// linked change set is the exact one-operation regular-file delta from that
/// input to `result_snapshot`. A separately persisted cumulative change set is
/// used when the finished sprint is applied to the trusted workspace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationArtifactLink {
    /// Wire-contract version used to encode the link.
    pub contract_version: u32,
    /// Sprint that owns the mutation and both workspace artifacts.
    pub sprint_id: String,
    /// Successful mutation effect identity.
    pub effect_id: String,
    /// Exact successful observation identity.
    pub observation_id: String,
    /// Snapshot authorized by the effect intent.
    pub input_snapshot: Digest,
    /// Exact snapshot produced by the mutation.
    pub result_snapshot: Digest,
    /// Exact per-effect change-set identity producing `result_snapshot`.
    pub change_set_id: String,
}

impl MutationArtifactLink {
    /// Validates version, stable identities, and snapshot progression.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the version is unsupported, an identity
    /// is blank, or the mutation claims no snapshot change.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "mutation_artifact_link.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("mutation_artifact_link.sprint_id", &self.sprint_id)?;
        require_nonblank("mutation_artifact_link.effect_id", &self.effect_id)?;
        require_nonblank(
            "mutation_artifact_link.observation_id",
            &self.observation_id,
        )?;
        require_nonblank("mutation_artifact_link.change_set_id", &self.change_set_id)?;
        if self.input_snapshot == self.result_snapshot {
            return Err(ContractError::new(
                "mutation_artifact_link.result_snapshot",
                "must differ from the intent input snapshot",
            ));
        }
        Ok(())
    }
}

/// Canonical reason a supervised command stopped.
///
/// The version suffix freezes the durable and runner-facing spelling of this
/// closed set independently of platform-specific process APIs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandTerminationV1 {
    /// The process returned a normal exit code.
    Exited {
        /// Nonnegative process exit code.
        code: i32,
    },
    /// The process ended because of a platform signal.
    Signaled {
        /// Positive platform signal number.
        signal: i32,
    },
    /// The authenticated wall-time ceiling elapsed.
    TimedOut,
    /// The coordinator requested cancellation.
    Canceled,
    /// The authenticated output ceiling was exceeded.
    OutputLimitExceeded,
}

impl CommandTerminationV1 {
    /// Returns the normal exit code, when the command exited normally.
    #[must_use]
    pub const fn exit_status(self) -> Option<i32> {
        match self {
            Self::Exited { code } => Some(code),
            Self::Signaled { .. } | Self::TimedOut | Self::Canceled | Self::OutputLimitExceeded => {
                None
            }
        }
    }

    /// Returns whether this terminal reason is a successful normal exit.
    #[must_use]
    pub const fn passed(self) -> bool {
        matches!(self, Self::Exited { code: 0 })
    }

    /// Validates values carried by platform-specific terminal variants.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a negative exit code or nonpositive signal.
    pub fn validate(self) -> Result<(), ContractError> {
        match self {
            Self::Exited { code } if code < 0 => Err(ContractError::new(
                "command_termination_v1.code",
                "must be nonnegative",
            )),
            Self::Signaled { signal } if signal <= 0 => Err(ContractError::new(
                "command_termination_v1.signal",
                "must be greater than zero",
            )),
            Self::Exited { .. }
            | Self::Signaled { .. }
            | Self::TimedOut
            | Self::Canceled
            | Self::OutputLimitExceeded => Ok(()),
        }
    }
}

/// Exact complete-output stream committed by an artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputStreamV1 {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Exact execution authority that produced a command-output artifact set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputArtifactSourceV1 {
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact pre-spawn runner launch.
    pub runner_launch_id: String,
    /// Exact initialized runner session.
    pub runner_session_id: String,
    /// Exact `RunCommand` effect.
    pub effect_id: String,
    /// Digest of the canonical command request.
    pub request_digest: Digest,
}

impl CommandOutputArtifactSourceV1 {
    /// Validates every bounded, stable execution identity.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an identity is blank or exceeds the
    /// command-output artifact identity bound.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_bounded_nonblank(
            "command_output_artifact_source_v1.sprint_id",
            &self.sprint_id,
            MAX_COMMAND_OUTPUT_ARTIFACT_ID_BYTES,
        )?;
        require_bounded_nonblank(
            "command_output_artifact_source_v1.runner_launch_id",
            &self.runner_launch_id,
            MAX_COMMAND_OUTPUT_ARTIFACT_ID_BYTES,
        )?;
        require_bounded_nonblank(
            "command_output_artifact_source_v1.runner_session_id",
            &self.runner_session_id,
            MAX_COMMAND_OUTPUT_ARTIFACT_ID_BYTES,
        )?;
        require_bounded_nonblank(
            "command_output_artifact_source_v1.effect_id",
            &self.effect_id,
            MAX_COMMAND_OUTPUT_ARTIFACT_ID_BYTES,
        )
    }
}

/// Complete byte length and digest for one immutable command-output stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputStreamArtifactV1 {
    /// Exact stream role.
    pub stream: CommandOutputStreamV1,
    /// Complete stream length in bytes. Zero is valid.
    pub byte_length: u64,
    /// SHA-256 digest of all bytes in the stream.
    pub content_digest: Digest,
}

impl CommandOutputStreamArtifactV1 {
    /// Validates length/digest consistency, including the unique empty-stream
    /// commitment.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when a zero-length stream does not carry the
    /// SHA-256 digest of the empty byte sequence.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.byte_length == 0 && self.content_digest != Digest::sha256(&[]) {
            return Err(ContractError::new(
                "command_output_stream_artifact_v1.content_digest",
                "a zero-length stream must carry the SHA-256 digest of empty bytes",
            ));
        }
        Ok(())
    }
}

/// Canonical immutable reference to both complete command-output streams.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputArtifactSetReferenceV1 {
    /// Exact manifest format. Version 1 is the only admitted value.
    pub format_version: u32,
    /// Exact execution authority behind both streams.
    pub source: CommandOutputArtifactSourceV1,
    /// Complete stdout commitment; the stream role must be `stdout`.
    pub stdout: CommandOutputStreamArtifactV1,
    /// Complete stderr commitment; the stream role must be `stderr`.
    pub stderr: CommandOutputStreamArtifactV1,
    /// Domain-separated digest of the canonical fields above.
    pub manifest_digest: Digest,
}

#[derive(Serialize)]
pub(super) struct CanonicalCommandOutputArtifactSetManifest<'a> {
    format_version: u32,
    source: &'a CommandOutputArtifactSourceV1,
    stdout: &'a CommandOutputStreamArtifactV1,
    stderr: &'a CommandOutputStreamArtifactV1,
}

impl CommandOutputArtifactSetReferenceV1 {
    /// Constructs and self-authenticates a canonical version-1 artifact set.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid source metadata, crossed stream
    /// roles, inconsistent empty-stream metadata, or canonical encoding
    /// failure.
    pub fn try_new(
        source: CommandOutputArtifactSourceV1,
        stdout: CommandOutputStreamArtifactV1,
        stderr: CommandOutputStreamArtifactV1,
    ) -> Result<Self, ContractError> {
        let manifest_digest = Self::compute_manifest_digest(
            COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION,
            &source,
            &stdout,
            &stderr,
        )?;
        let reference = Self {
            format_version: COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION,
            source,
            stdout,
            stderr,
            manifest_digest,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validates the complete reference and its canonical manifest digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for any invalid identity, format, stream
    /// role, stream metadata, or manifest digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.format_version != COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION {
            return Err(ContractError::new(
                "command_output_artifact_set_reference_v1.format_version",
                format!(
                    "expected version {COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION}, got {}",
                    self.format_version
                ),
            ));
        }
        self.source.validate()?;
        self.stdout.validate()?;
        self.stderr.validate()?;
        if self.stdout.stream != CommandOutputStreamV1::Stdout {
            return Err(ContractError::new(
                "command_output_artifact_set_reference_v1.stdout.stream",
                "must be stdout",
            ));
        }
        if self.stderr.stream != CommandOutputStreamV1::Stderr {
            return Err(ContractError::new(
                "command_output_artifact_set_reference_v1.stderr.stream",
                "must be stderr",
            ));
        }
        let expected = Self::compute_manifest_digest(
            self.format_version,
            &self.source,
            &self.stdout,
            &self.stderr,
        )?;
        if self.manifest_digest != expected {
            return Err(ContractError::new(
                "command_output_artifact_set_reference_v1.manifest_digest",
                "does not match the canonical artifact-set manifest",
            ));
        }
        Ok(())
    }

    /// Reconstructs the existing canonical complete-stream commitment preimage
    /// from the exact artifact lengths and digests.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the artifact reference is invalid.
    pub fn output_evidence_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut preimage = Vec::with_capacity(256);
        append_command_output_frame(&mut preimage, COMMAND_STREAM_OUTPUT_DIGEST_DOMAIN);
        for (name, stream) in [
            (b"stdout".as_slice(), &self.stdout),
            (b"stderr".as_slice(), &self.stderr),
        ] {
            append_command_output_frame(&mut preimage, name);
            append_command_output_frame(&mut preimage, &stream.byte_length.to_be_bytes());
            append_command_output_frame(&mut preimage, stream.content_digest.as_str().as_bytes());
        }
        Ok(preimage)
    }

    fn compute_manifest_digest(
        format_version: u32,
        source: &CommandOutputArtifactSourceV1,
        stdout: &CommandOutputStreamArtifactV1,
        stderr: &CommandOutputStreamArtifactV1,
    ) -> Result<Digest, ContractError> {
        let canonical = serde_json::to_vec(&CanonicalCommandOutputArtifactSetManifest {
            format_version,
            source,
            stdout,
            stderr,
        })
        .map_err(|error| {
            ContractError::new(
                "command_output_artifact_set_reference_v1",
                format!("cannot encode canonical manifest: {error}"),
            )
        })?;
        let canonical_length = u64::try_from(canonical.len()).map_err(|_| {
            ContractError::new(
                "command_output_artifact_set_reference_v1",
                "canonical manifest exceeds the supported 64-bit length",
            )
        })?;
        let mut preimage = Vec::with_capacity(
            COMMAND_OUTPUT_ARTIFACT_SET_DIGEST_DOMAIN.len() + 8 + canonical.len(),
        );
        preimage.extend_from_slice(COMMAND_OUTPUT_ARTIFACT_SET_DIGEST_DOMAIN);
        preimage.extend_from_slice(&canonical_length.to_be_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(Digest::sha256(&preimage))
    }
}

pub(super) fn append_command_output_frame(preimage: &mut Vec<u8>, bytes: &[u8]) {
    preimage.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(bytes);
}

/// Durable evidence for one verification command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationReceipt {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Owning sprint identifier.
    pub sprint_id: String,
    /// Optional task identifier for task-local checks.
    pub task_id: Option<String>,
    /// Exact verified snapshot.
    pub snapshot_id: Digest,
    /// Exact command invocation.
    pub command: CommandSpec,
    /// Runner policy digest.
    pub policy_hash: Digest,
    /// Legacy process exit status.
    ///
    /// Historical receipts contain this field without `termination`. Current
    /// normal-exit receipts retain the exact matching value for forward and
    /// backward decoding; current non-exit terminals omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    /// Typed command terminal reason, required for every current write.
    ///
    /// Absence is admitted only when reading a historical receipt carrying a
    /// legacy `exit_status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination: Option<CommandTerminationV1>,
    /// Digest of the canonical complete-stream output commitment preimage.
    pub output_digest: Digest,
    /// Verification wall time.
    pub duration_ms: u64,
    /// Completion time in Unix milliseconds.
    pub finished_at_unix_ms: u64,
}

impl VerificationReceipt {
    /// Returns whether the command has a proven successful normal exit.
    ///
    /// Historical receipts fall back to their legacy exit status. Current
    /// receipts pass only when the typed and compatibility exits both prove
    /// zero; malformed or non-exit terminal shapes fail closed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(
            (self.termination, self.exit_status),
            (
                None | Some(CommandTerminationV1::Exited { code: 0 }),
                Some(0)
            )
        )
    }

    /// Validates durable receipt metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for blank identity, an invalid command, or a
    /// zero completion timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("verification_receipt.receipt_id", &self.receipt_id)?;
        require_nonblank("verification_receipt.sprint_id", &self.sprint_id)?;
        if let Some(task_id) = &self.task_id {
            require_nonblank("verification_receipt.task_id", task_id)?;
        }
        self.command.validate()?;
        match (self.termination, self.exit_status) {
            (None, Some(_)) => {}
            (None, None) => {
                return Err(ContractError::new(
                    "verification_receipt.termination",
                    "historical receipts require exit_status and current receipts require typed termination",
                ));
            }
            (Some(termination @ CommandTerminationV1::Exited { code }), Some(exit_status)) => {
                termination.validate()?;
                if code != exit_status {
                    return Err(ContractError::new(
                        "verification_receipt.exit_status",
                        "must exactly match the typed normal-exit code",
                    ));
                }
            }
            (Some(CommandTerminationV1::Exited { .. }), None) => {
                return Err(ContractError::new(
                    "verification_receipt.exit_status",
                    "typed normal exit requires its matching legacy exit status",
                ));
            }
            (Some(termination), None) => termination.validate()?,
            (Some(termination), Some(_)) => {
                termination.validate()?;
                return Err(ContractError::new(
                    "verification_receipt.exit_status",
                    "must be absent for a typed non-exit terminal",
                ));
            }
        }
        require_nonzero_timestamp(
            "verification_receipt.finished_at_unix_ms",
            self.finished_at_unix_ms,
        )
    }

    /// Validates a receipt for a new durable write by the current product.
    ///
    /// Historical untyped receipts remain readable through [`Self::validate`]
    /// but cannot be minted after typed command termination became mandatory.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when ordinary receipt validation fails or the
    /// typed terminal reason is absent.
    pub fn validate_current(&self) -> Result<(), ContractError> {
        self.validate()?;
        if self.termination.is_none() {
            return Err(ContractError::new(
                "verification_receipt.termination",
                "is required for current persistence",
            ));
        }
        Ok(())
    }
}

/// Maximum complete command-output evidence retained by one authoritative
/// verification effect.
pub const MAX_VERIFICATION_OUTPUT_EVIDENCE_BYTES: usize = 8 * 1_048_576;

/// Atomic effect-bound evidence for one verification command.
///
/// This envelope is the exact successful `RunCommand` observation preimage.
/// The retained output bytes authenticate `verification.output_digest`; the
/// indexed receipt alone is not execution authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEffectEvidence {
    /// Wire-contract version used to encode the evidence.
    pub contract_version: u32,
    /// Indexed verification result.
    pub verification: VerificationReceipt,
    /// Exact `RunCommand` effect.
    pub effect_id: String,
    /// Exact successful effect observation.
    pub observation_id: String,
    /// Exact pre-spawn launch attempt behind execution.
    pub runner_launch_id: String,
    /// Exact initialized runner session behind execution.
    pub runner_session_id: String,
    /// Immutable complete stdout/stderr artifact commitment. Historical
    /// evidence predating artifact-set persistence omits this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_artifacts: Option<CommandOutputArtifactSetReferenceV1>,
    /// Nonempty canonical preimage that commits the complete stdout/stderr
    /// lengths and digests. Raw retained bytes and any immutable complete-output
    /// artifact remain separate evidence and are never implied by this field.
    pub output_evidence_bytes: Vec<u8>,
}

impl VerificationEffectEvidence {
    /// Validates the strict execution-evidence envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid receipt, unsupported version,
    /// blank lifecycle identity, empty/oversized output evidence, or a digest
    /// mismatch.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "verification_effect_evidence.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.verification.validate()?;
        require_nonblank("verification_effect_evidence.effect_id", &self.effect_id)?;
        require_nonblank(
            "verification_effect_evidence.observation_id",
            &self.observation_id,
        )?;
        require_nonblank(
            "verification_effect_evidence.runner_launch_id",
            &self.runner_launch_id,
        )?;
        require_nonblank(
            "verification_effect_evidence.runner_session_id",
            &self.runner_session_id,
        )?;
        if self.output_evidence_bytes.is_empty() {
            return Err(ContractError::new(
                "verification_effect_evidence.output_evidence_bytes",
                "must retain the canonical complete-stream output commitment preimage",
            ));
        }
        if self.output_evidence_bytes.len() > MAX_VERIFICATION_OUTPUT_EVIDENCE_BYTES {
            return Err(ContractError::new(
                "verification_effect_evidence.output_evidence_bytes",
                format!("must not exceed {MAX_VERIFICATION_OUTPUT_EVIDENCE_BYTES} bytes"),
            ));
        }
        if Digest::sha256(&self.output_evidence_bytes) != self.verification.output_digest {
            return Err(ContractError::new(
                "verification_effect_evidence.output_evidence_bytes",
                "digest does not match the canonical complete-stream output commitment",
            ));
        }
        if let Some(artifacts) = &self.output_artifacts {
            self.validate_output_artifacts(artifacts)?;
        }
        Ok(())
    }

    /// Validates evidence for a new authoritative write by the current
    /// product.
    ///
    /// Historical evidence remains readable through [`Self::validate`], but
    /// only evidence carrying a typed terminal and exact complete-output
    /// artifact binding may mint current authority.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when ordinary validation fails, the typed
    /// terminal is absent, or complete-output artifacts are absent.
    pub fn validate_current(&self) -> Result<(), ContractError> {
        self.validate()?;
        self.verification.validate_current()?;
        self.output_artifacts.as_ref().ok_or_else(|| {
            ContractError::new(
                "verification_effect_evidence.output_artifacts",
                "is required for current persistence",
            )
        })?;
        Ok(())
    }

    fn validate_output_artifacts(
        &self,
        artifacts: &CommandOutputArtifactSetReferenceV1,
    ) -> Result<(), ContractError> {
        artifacts.validate()?;
        if artifacts.source.sprint_id != self.verification.sprint_id {
            return Err(ContractError::new(
                "verification_effect_evidence.output_artifacts.source.sprint_id",
                "must match the verification sprint",
            ));
        }
        if artifacts.source.runner_launch_id != self.runner_launch_id {
            return Err(ContractError::new(
                "verification_effect_evidence.output_artifacts.source.runner_launch_id",
                "must match the evidence runner launch",
            ));
        }
        if artifacts.source.runner_session_id != self.runner_session_id {
            return Err(ContractError::new(
                "verification_effect_evidence.output_artifacts.source.runner_session_id",
                "must match the evidence runner session",
            ));
        }
        if artifacts.source.effect_id != self.effect_id {
            return Err(ContractError::new(
                "verification_effect_evidence.output_artifacts.source.effect_id",
                "must match the evidence effect",
            ));
        }
        let canonical_request =
            serde_json::to_vec(&self.verification.command).map_err(|error| {
                ContractError::new(
                    "verification_effect_evidence.verification.command",
                    format!("cannot encode canonical command request: {error}"),
                )
            })?;
        if artifacts.source.request_digest != Digest::sha256(&canonical_request) {
            return Err(ContractError::new(
                "verification_effect_evidence.output_artifacts.source.request_digest",
                "must match the canonical verification command",
            ));
        }
        if artifacts.output_evidence_bytes()? != self.output_evidence_bytes {
            return Err(ContractError::new(
                "verification_effect_evidence.output_evidence_bytes",
                "must exactly commit the artifact stdout/stderr lengths and digests",
            ));
        }
        Ok(())
    }
}

/// The backing represented by a v0.1 human-acceptance prompt.
///
/// The enum is deliberately closed. Later RULE, SAMPLE, or DELEGATE
/// instruments require a versioned contract instead of widening one click.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HumanAcceptanceBackingV1 {
    /// One rendered criterion requires one explicit human action.
    OneToOne,
}

/// One immutable human-acceptance claim minted by the coordinator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAcceptancePromptV1 {
    /// Globally unique prompt identity.
    pub prompt_id: String,
    /// Trusted desktop UI session allowed to present and consume the prompt.
    pub ui_session_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact human criterion from the immutable sprint specification.
    pub criterion_id: String,
    /// SHA-256 of the exact criterion text rendered to the human.
    pub criterion_text_digest: Digest,
    /// Exact immutable snapshot being judged.
    pub snapshot_digest: Digest,
    /// Exact authenticated workspace grant in force for the sprint.
    pub workspace_grant_hash: Digest,
    /// SHA-256 of the complete rendered claim, including its backing label.
    pub rendered_claim_digest: Digest,
    /// Attention-to-claim backing. v0.1 permits only one-to-one.
    pub backing: HumanAcceptanceBackingV1,
    /// Latest durable sprint event when the prompt was minted.
    pub issued_event_sequence: u64,
}

impl HumanAcceptancePromptV1 {
    /// Validates the prompt's local shape.
    ///
    /// Criterion text, snapshot, grant, phase, session, and event bindings are
    /// re-derived by durable persistence rather than trusted from this value.
    ///
    /// # Errors
    ///
    /// Returns a contract error for blank identities or a zero event sequence.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("human_acceptance_prompt.prompt_id", &self.prompt_id)?;
        require_nonblank("human_acceptance_prompt.ui_session_id", &self.ui_session_id)?;
        require_nonblank("human_acceptance_prompt.sprint_id", &self.sprint_id)?;
        require_nonblank("human_acceptance_prompt.criterion_id", &self.criterion_id)?;
        if self.issued_event_sequence == 0 {
            return Err(ContractError::new(
                "human_acceptance_prompt.issued_event_sequence",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Exact outcome of one consumed human-acceptance prompt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HumanAcceptanceDecisionOutcomeV1 {
    /// The human accepted the one rendered criterion and snapshot.
    AcceptedByYou,
    /// The human rejected the one rendered criterion and snapshot.
    RejectedByYou,
}

/// Immutable result of consuming exactly one human-acceptance prompt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAcceptanceDecisionV1 {
    /// Core-derived globally unique decision identity.
    pub decision_id: String,
    /// Exact prompt consumed by the decision.
    pub prompt_id: String,
    /// Accepted-by-you or rejected-by-you; never machine verification.
    pub outcome: HumanAcceptanceDecisionOutcomeV1,
    /// Latest durable sprint event at the atomic consumption cut.
    pub consumed_event_sequence: u64,
    /// Human action time in Unix milliseconds.
    pub decided_at: u64,
}

impl HumanAcceptanceDecisionV1 {
    /// Validates the decision's local shape.
    ///
    /// Prompt identity, one-shot consumption, UI session, event, snapshot, and
    /// sprint bindings are checked by durable persistence.
    ///
    /// # Errors
    ///
    /// Returns a contract error for blank identities, a zero sequence, or a
    /// zero decision timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("human_acceptance_decision.decision_id", &self.decision_id)?;
        require_nonblank("human_acceptance_decision.prompt_id", &self.prompt_id)?;
        if self.consumed_event_sequence == 0 {
            return Err(ContractError::new(
                "human_acceptance_decision.consumed_event_sequence",
                "must be greater than zero",
            ));
        }
        require_nonzero_timestamp("human_acceptance_decision.decided_at", self.decided_at)
    }
}

/// Current typed evidence that satisfies exactly one sprint criterion.
///
/// Machine verification and human acceptance are separate variants and never
/// share the words `accepted` or `verified` on the wire.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CriterionEvidenceReceiptV2 {
    /// An automated criterion was verified on the exact snapshot.
    Verified {
        /// Stable criterion-evidence receipt identity.
        receipt_id: String,
        /// Owning sprint.
        sprint_id: String,
        /// Exact criterion from the sprint specification.
        criterion_id: String,
        /// Snapshot on which verification ran.
        snapshot_digest: Digest,
        /// Same-sprint passing verification receipt.
        verification_receipt_id: String,
        /// Evidence-recording time in Unix milliseconds.
        recorded_at: u64,
    },
    /// A human accepted one exact rendered claim.
    AcceptedByYou {
        /// Stable criterion-evidence receipt identity.
        receipt_id: String,
        /// Owning sprint.
        sprint_id: String,
        /// Exact criterion from the sprint specification.
        criterion_id: String,
        /// Snapshot shown in the consumed prompt.
        snapshot_digest: Digest,
        /// Exact accepted human decision.
        human_decision_id: String,
        /// Exact one-to-one prompt consumed by the decision.
        prompt_id: String,
        /// Attention-to-claim backing printed in the prompt.
        backing: HumanAcceptanceBackingV1,
        /// Evidence-recording time in Unix milliseconds.
        recorded_at: u64,
    },
}

impl CriterionEvidenceReceiptV2 {
    /// Stable evidence-receipt identity.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        match self {
            Self::Verified { receipt_id, .. } | Self::AcceptedByYou { receipt_id, .. } => {
                receipt_id
            }
        }
    }

    /// Owning sprint identity.
    #[must_use]
    pub fn sprint_id(&self) -> &str {
        match self {
            Self::Verified { sprint_id, .. } | Self::AcceptedByYou { sprint_id, .. } => sprint_id,
        }
    }

    /// Exact criterion identity.
    #[must_use]
    pub fn criterion_id(&self) -> &str {
        match self {
            Self::Verified { criterion_id, .. } | Self::AcceptedByYou { criterion_id, .. } => {
                criterion_id
            }
        }
    }

    /// Snapshot on which the criterion is satisfied.
    #[must_use]
    pub const fn snapshot_digest(&self) -> &Digest {
        match self {
            Self::Verified {
                snapshot_digest, ..
            }
            | Self::AcceptedByYou {
                snapshot_digest, ..
            } => snapshot_digest,
        }
    }

    /// Time at which the typed evidence was recorded.
    #[must_use]
    pub const fn recorded_at(&self) -> u64 {
        match self {
            Self::Verified { recorded_at, .. } | Self::AcceptedByYou { recorded_at, .. } => {
                *recorded_at
            }
        }
    }

    /// Validates local identity and variant-specific fields.
    ///
    /// The referenced verification or authenticated human decision is resolved
    /// by durable persistence.
    ///
    /// # Errors
    ///
    /// Returns a contract error for blank identifiers or a zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("criterion_evidence_receipt.receipt_id", self.receipt_id())?;
        require_nonblank("criterion_evidence_receipt.sprint_id", self.sprint_id())?;
        require_nonblank(
            "criterion_evidence_receipt.criterion_id",
            self.criterion_id(),
        )?;
        match self {
            Self::Verified {
                verification_receipt_id,
                ..
            } => require_nonblank(
                "criterion_evidence_receipt.verification_receipt_id",
                verification_receipt_id,
            )?,
            Self::AcceptedByYou {
                human_decision_id,
                prompt_id,
                ..
            } => {
                require_nonblank(
                    "criterion_evidence_receipt.human_decision_id",
                    human_decision_id,
                )?;
                require_nonblank("criterion_evidence_receipt.prompt_id", prompt_id)?;
            }
        }
        require_nonzero_timestamp("criterion_evidence_receipt.recorded_at", self.recorded_at())
    }
}

/// Legacy criterion-specific evidence retained for diagnostic readback only.
///
/// Schema v28 rejects new caller-authored human judgments and does not allow
/// this type to satisfy a current completion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AcceptanceEvidence {
    /// An automated criterion was satisfied by an exact verification receipt.
    Automated {
        /// Same-sprint passing verification receipt identifier.
        verification_receipt_id: String,
    },
    /// A human explicitly accepted a human-judgment criterion.
    HumanJudgment {
        /// Stable identifier for the explicit human decision.
        decision_id: String,
        /// Must be true for an acceptance receipt.
        accepted: bool,
    },
}

/// Legacy durable criterion result retained for diagnostic readback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptanceReceipt {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Owning sprint identifier.
    pub sprint_id: String,
    /// Exact criterion identifier from the sprint specification.
    pub criterion_id: String,
    /// Snapshot on which the criterion was accepted.
    pub snapshot_id: Digest,
    /// Criterion-kind-specific evidence.
    pub evidence: AcceptanceEvidence,
    /// Acceptance time in Unix milliseconds.
    pub accepted_at_unix_ms: u64,
}

impl AcceptanceReceipt {
    /// Validates receipt identity, evidence identity, and acceptance timestamp.
    ///
    /// Sprint criterion kind, command equality, snapshot existence, and
    /// referenced verification integrity are checked by durable persistence.
    ///
    /// # Errors
    ///
    /// Returns a contract error for blank identifiers, a non-accepted human
    /// decision, or a zero acceptance timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("acceptance_receipt.receipt_id", &self.receipt_id)?;
        require_nonblank("acceptance_receipt.sprint_id", &self.sprint_id)?;
        require_nonblank("acceptance_receipt.criterion_id", &self.criterion_id)?;
        match &self.evidence {
            AcceptanceEvidence::Automated {
                verification_receipt_id,
            } => require_nonblank(
                "acceptance_receipt.verification_receipt_id",
                verification_receipt_id,
            )?,
            AcceptanceEvidence::HumanJudgment {
                decision_id,
                accepted,
            } => {
                require_nonblank("acceptance_receipt.decision_id", decision_id)?;
                if !accepted {
                    return Err(ContractError::new(
                        "acceptance_receipt.accepted",
                        "an acceptance receipt must record an accepted decision",
                    ));
                }
            }
        }
        require_nonzero_timestamp(
            "acceptance_receipt.accepted_at_unix_ms",
            self.accepted_at_unix_ms,
        )
    }
}

/// Durable proof that one graph task was integrated and verified against
/// the exact resulting integration snapshot.
///
/// Persistence accepts this envelope only in the same transaction as the
/// matching successful [`crate::EffectObservation`]. The effect request is the exact
/// canonical [`crate::TaskIntegrationRequest`], and every verification identifier is
/// resolved to a passing same-task receipt bound to this worker session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIntegrationReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Globally unique receipt identity.
    pub receipt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Required or optional graph task whose result was integrated.
    pub task_id: String,
    /// Exact logical worker that produced and integrated the task result.
    pub worker_id: String,
    /// Exact durable lease that authorized this worker assignment.
    ///
    /// The optional wire shape preserves decoding of pre-v14 immutable bytes;
    /// [`Self::validate`] rejects an absent lease for every new receipt.
    #[serde(default)]
    pub worker_lease: Option<WorkerLease>,
    /// Exact pre-spawn launch attempt behind the worker session.
    pub worker_launch_id: String,
    /// Exact initialized worker session.
    pub worker_session_id: String,
    /// Exact compiler-produced worker policy.
    pub worker_policy_hash: Digest,
    /// Exact successful `IntegrateChangeSet` effect.
    pub effect_id: String,
    /// Exact successful effect observation.
    pub observation_id: String,
    /// Exact task change set integrated by the effect.
    pub change_set_id: String,
    /// Integration snapshot required before this ordered step.
    pub input_snapshot: Digest,
    /// Integration snapshot produced and verified by this ordered step.
    pub result_snapshot: Digest,
    /// Exact passing automated-verification receipts in declared criterion order.
    /// Empty exactly when this task names no automated criterion.
    pub task_verification_receipt_ids: Vec<String>,
    /// Zero-based position in the sprint's complete integration chain.
    pub integration_ordinal: u32,
    /// Successful integration observation time.
    pub integrated_at_unix_ms: u64,
}

impl TaskIntegrationReceipt {
    /// Validates the strict task-integration envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// duplicate verification identities, or a zero timestamp. Snapshot
    /// equality is allowed only through the ledger-joined explicit empty
    /// change-set path. Graph-aware validation enforces the exact declared
    /// automated-criterion set and order.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "task_integration_receipt.contract_version",
            self.contract_version,
            "task_integration_receipt.receipt_id",
            &self.receipt_id,
            "task_integration_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank("task_integration_receipt.task_id", &self.task_id)?;
        require_nonblank("task_integration_receipt.worker_id", &self.worker_id)?;
        let worker_lease = self.worker_lease.as_ref().ok_or_else(|| {
            ContractError::new(
                "task_integration_receipt.worker_lease",
                "v14 receipts require one exact durable worker lease",
            )
        })?;
        worker_lease.validate_assignment(&self.sprint_id, &self.task_id, &self.worker_id)?;
        require_nonblank(
            "task_integration_receipt.worker_launch_id",
            &self.worker_launch_id,
        )?;
        require_nonblank(
            "task_integration_receipt.worker_session_id",
            &self.worker_session_id,
        )?;
        require_nonblank("task_integration_receipt.effect_id", &self.effect_id)?;
        require_nonblank(
            "task_integration_receipt.observation_id",
            &self.observation_id,
        )?;
        require_nonblank(
            "task_integration_receipt.change_set_id",
            &self.change_set_id,
        )?;
        require_unique_nonblank(
            "task_integration_receipt.task_verification_receipt_ids",
            &self.task_verification_receipt_ids,
        )?;
        require_nonzero_timestamp(
            "task_integration_receipt.integrated_at_unix_ms",
            self.integrated_at_unix_ms,
        )?;
        if self.integrated_at_unix_ms < worker_lease.acquired_at_unix_ms {
            return Err(ContractError::new(
                "task_integration_receipt.integrated_at_unix_ms",
                "must not precede lease acquisition",
            ));
        }
        Ok(())
    }
}

/// Path-free identity of the immutable private artifact that carries one
/// integrated task change set between trusted runner roles.
///
/// The runner owns the artifact format and storage location. Core persistence
/// owns this bounded identity so a coordinator restart can reconstruct the
/// exact reference without trusting process memory or a filesystem search.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIntegrationArtifactReference {
    /// On-disk artifact format version understood by the runner.
    pub format_version: u32,
    /// Domain-separated digest of the artifact's canonical manifest.
    pub artifact_digest: Digest,
    /// Exact change-set identity carried by the artifact.
    pub change_set_id: String,
    /// Exact snapshot against which the artifact was produced.
    pub base_snapshot: Digest,
    /// Exact snapshot produced by the artifact's operations.
    pub result_snapshot: Digest,
}

impl TaskIntegrationArtifactReference {
    /// Validates the path-free artifact identity and snapshot transition.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a zero format version or blank change-set
    /// identity. Snapshot equality is admitted only when the enclosing task
    /// integration request carries the exact explicit empty change set.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.format_version == 0 {
            return Err(ContractError::new(
                "task_integration_artifact_reference.format_version",
                "must be greater than zero",
            ));
        }
        require_nonblank(
            "task_integration_artifact_reference.change_set_id",
            &self.change_set_id,
        )?;
        Ok(())
    }
}
