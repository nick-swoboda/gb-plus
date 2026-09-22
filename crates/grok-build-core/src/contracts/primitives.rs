//! Foundational identities, workspace policy, commands, and sprint contracts.

use super::{
    BTreeMap, BTreeSet, CONTRACT_VERSION, Component, Deserialize, Deserializer, Display, Error,
    Formatter, Path, PathBuf, Serialize, Sha2Digest, Sha256, VecDeque, fmt, require_nonblank,
    require_nonzero_timestamp, require_normalized_absolute, require_normalized_relative,
    require_unique_nonblank,
};

/// Maximum UTF-8 byte length accepted for one durable terminal reason.
pub const MAX_TERMINAL_REASON_BYTES: usize = 64 * 1024;

/// Maximum canonical bytes for one pre-publication task-integration request.
///
/// The 64-KiB reserve below the 8-MiB ledger/wire frame ceiling leaves room for
/// the authenticated runner envelope, effect context, and framing metadata.
pub const MAX_TASK_INTEGRATION_REQUEST_BYTES: usize = (8 * 1_048_576) - (64 * 1_024);
/// Maximum canonical bytes accepted for one artifact-bound application request.
pub const MAX_APPLICATION_REQUEST_BYTES: usize = (8 * 1_048_576) - (64 * 1_024);

/// Maximum ASCII byte length accepted for one worker identifier.
pub const MAX_WORKER_ID_BYTES: usize = 256;
/// Exact ASCII byte length of a canonical `lease-<sha256>` identifier.
pub const WORKER_LEASE_ID_BYTES: usize = 70;

/// Maximum retained canonical evidence bytes for one task-attempt outcome.
pub const MAX_TASK_ATTEMPT_EVIDENCE_BYTES: usize = 1_048_576;
/// Maximum UTF-8 bytes accepted for one task-attempt authority identity.
pub const MAX_TASK_ATTEMPT_ID_BYTES: usize = 4 * 1_024;

/// Maximum UTF-8 byte length accepted for an identity carried by a complete
/// command-output artifact reference.
pub const MAX_COMMAND_OUTPUT_ARTIFACT_ID_BYTES: usize = 256;
/// Current canonical command-output artifact-set manifest format.
pub const COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION: u32 = 1;

pub(super) const WORKER_LEASE_ID_DOMAIN: &[u8] = b"grok-build.worker-lease.v1\0";
pub(super) const WORKER_LEASE_ID_PREFIX: &str = "lease-";
pub(super) const COMMAND_OUTPUT_ARTIFACT_SET_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-artifact-set/v1\0";
pub(super) const COMMAND_STREAM_OUTPUT_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output/v1";

/// A validation error for a public contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractError {
    field: &'static str,
    message: String,
}

impl ContractError {
    pub(crate) fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the contract field that failed validation.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns a human-readable explanation of the invariant violation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for ContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for ContractError {}

/// A lowercase hexadecimal SHA-256 digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    /// Calculates the canonical lowercase SHA-256 digest of exact bytes.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = Sha256::digest(bytes);
        let mut encoded = String::with_capacity(64);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(encoded)
    }

    /// Parses and validates a lowercase hexadecimal SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the text is not exactly 64 lowercase
    /// hexadecimal characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ContractError::new(
                "digest",
                "must contain exactly 64 hexadecimal characters",
            ));
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(ContractError::new(
                "digest",
                "must use canonical lowercase hexadecimal",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the canonical digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Network authority persisted with a workspace grant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WorkspaceNetworkPolicy {
    /// Sandboxed commands may not use the host network.
    Denied,
    /// A policy may grant host networking for a single action.
    Allowed,
}

/// Capabilities authorized by a workspace grant.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkspacePermissions {
    /// Allow reads inside the workspace.
    pub read: bool,
    /// Allow regular-file changes through the safe applier.
    pub write_regular_files: bool,
    /// Allow non-interactive sandboxed commands.
    pub execute_commands: bool,
    /// Allow worker changes to be integrated into a private snapshot.
    pub integrate_changes: bool,
    /// Allow verified changes to be applied to the live workspace.
    pub apply_verified_changes: bool,
}

impl WorkspacePermissions {
    /// Returns the standard trusted-project permission set.
    #[must_use]
    pub const fn trusted() -> Self {
        Self {
            read: true,
            write_regular_files: true,
            execute_commands: true,
            integrate_changes: true,
            apply_verified_changes: true,
        }
    }

    /// Returns a read-only permission set.
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write_regular_files: false,
            execute_commands: false,
            integrate_changes: false,
            apply_verified_changes: false,
        }
    }

    fn validate(self) -> Result<(), ContractError> {
        if !self.read {
            return Err(ContractError::new(
                "workspace_grant.permissions.read",
                "all workspace grants must permit reads",
            ));
        }
        if self.integrate_changes && !self.write_regular_files {
            return Err(ContractError::new(
                "workspace_grant.permissions.integrate_changes",
                "integration requires regular-file write permission",
            ));
        }
        if self.apply_verified_changes && !self.integrate_changes {
            return Err(ContractError::new(
                "workspace_grant.permissions.apply_verified_changes",
                "application requires integration permission",
            ));
        }
        Ok(())
    }
}

/// Persistent authority for one canonical workspace root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkspaceGrant {
    /// Stable grant identifier.
    pub grant_id: String,
    /// Canonical absolute workspace root.
    pub canonical_root: PathBuf,
    /// Capabilities granted inside the root.
    pub permissions: WorkspacePermissions,
    /// Command network authority.
    pub network: WorkspaceNetworkPolicy,
    /// Security-policy version under which trust was granted.
    pub policy_version: u32,
    /// Digest over the canonical serialized grant.
    pub grant_hash: Digest,
}

impl WorkspaceGrant {
    /// Validates only the grant's structural shape and permission relationships.
    ///
    /// This method does not authenticate [`Self::grant_hash`] or verify that the
    /// directory currently at [`Self::canonical_root`] is the directory the user
    /// trusted. Production code must use the integrity-checked APIs exported by
    /// the crate's trust module.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid identity, root, policy version,
    /// or internally inconsistent permission set.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("workspace_grant.grant_id", &self.grant_id)?;
        require_normalized_absolute("workspace_grant.canonical_root", &self.canonical_root)?;
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "workspace_grant.policy_version",
                "must be greater than zero",
            ));
        }
        self.permissions.validate()
    }
}

/// Identifies who owns tool execution for a provider backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ExecutionOrigin {
    /// Grok Build mediates tools through its native runner.
    HostIsolated,
    /// An external vendor runtime owns execution semantics.
    VendorManaged,
    /// This backend cannot execute commands or write files.
    ReadOnly,
}

/// A provider and model selection persisted in a sprint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderProfile {
    /// Stable backend identifier.
    pub backend_id: String,
    /// Provider-specific model identifier.
    pub model_id: String,
    /// Execution ownership advertised by the backend.
    pub execution_origin: ExecutionOrigin,
}

impl ProviderProfile {
    fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("provider.backend_id", &self.backend_id)?;
        require_nonblank("provider.model_id", &self.model_id)
    }
}

/// An exact non-interactive command invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandSpec {
    /// Executable name or approved absolute executable path.
    pub program: String,
    /// Exact argument vector; no shell parsing is implied.
    pub arguments: Vec<String>,
    /// Normalized workspace-relative directory, or an empty path for the root.
    pub working_directory: PathBuf,
}

pub(super) const CURRENT_DIRECT_EXEC_MAX_ARGUMENTS_V1: usize = 256;
pub(super) const CURRENT_DIRECT_EXEC_MAX_TEXT_BYTES_V1: usize = 4_096;
pub(super) const CURRENT_DIRECT_EXEC_MAX_PATH_BYTES_V1: usize = 4_096;
pub(super) const CURRENT_DIRECT_EXEC_FORBIDDEN_PROGRAMS_V1: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "nu",
    "xonsh",
    "pwsh",
    "powershell",
    "powershell.exe",
    "cmd",
    "cmd.exe",
    "env",
];

/// Validates the closed direct-exec command subset shared by current core
/// admission and runner wire V13.
///
/// Version one admits an absolute executable path or one bare executable name
/// and an empty working directory as the workspace root, but otherwise
/// requires normalized UTF-8 relative components. It rejects shell and
/// command-wrapper basenames, protected `.git` components
/// case-insensitively, NUL, and every fixed text/count overflow. Keeping this
/// policy in core gives launch admission and the runner one exact validator.
///
/// # Errors
///
/// Returns [`ContractError`] when the command cannot be represented by the
/// current direct-exec V1 wire contract.
pub fn validate_current_direct_exec_command_v1(command: &CommandSpec) -> Result<(), ContractError> {
    if command.program.is_empty()
        || command.program.len() > CURRENT_DIRECT_EXEC_MAX_TEXT_BYTES_V1
        || command.program.as_bytes().contains(&0)
        || command.arguments.len() > CURRENT_DIRECT_EXEC_MAX_ARGUMENTS_V1
    {
        return Err(ContractError::new(
            "current_direct_exec_command_v1.command",
            "command program or argument count is outside bounds",
        ));
    }

    let program_path = Path::new(&command.program);
    if !program_path.is_absolute() {
        let mut components = program_path.components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(ContractError::new(
                "current_direct_exec_command_v1.program",
                "program must be an absolute path or a bare executable name",
            ));
        }
    }

    let basename = program_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&command.program)
        .to_ascii_lowercase();
    if CURRENT_DIRECT_EXEC_FORBIDDEN_PROGRAMS_V1.contains(&basename.as_str()) {
        return Err(ContractError::new(
            "current_direct_exec_command_v1.program",
            "shell and command-wrapper programs are forbidden",
        ));
    }
    if command.arguments.iter().any(|argument| {
        argument.len() > CURRENT_DIRECT_EXEC_MAX_TEXT_BYTES_V1 || argument.as_bytes().contains(&0)
    }) {
        return Err(ContractError::new(
            "current_direct_exec_command_v1.arguments",
            "command argument is outside the text bound",
        ));
    }

    let working_directory = command.working_directory.to_str().ok_or_else(|| {
        ContractError::new(
            "current_direct_exec_command_v1.working_directory",
            "working directory is not UTF-8",
        )
    })?;
    if working_directory.len() > CURRENT_DIRECT_EXEC_MAX_PATH_BYTES_V1
        || working_directory.as_bytes().contains(&0)
    {
        return Err(ContractError::new(
            "current_direct_exec_command_v1.working_directory",
            "working directory is oversized or contains NUL",
        ));
    }
    if !working_directory.is_empty() {
        let path = Path::new(working_directory);
        if path.is_absolute() {
            return Err(ContractError::new(
                "current_direct_exec_command_v1.working_directory",
                "path must be normalized and workspace-relative",
            ));
        }
        for component in path.components() {
            match component {
                Component::Normal(name)
                    if !name
                        .to_str()
                        .is_some_and(|text| text.eq_ignore_ascii_case(".git")) => {}
                Component::Normal(_) => {
                    return Err(ContractError::new(
                        "current_direct_exec_command_v1.working_directory",
                        "protected .git paths are forbidden case-insensitively",
                    ));
                }
                Component::Prefix(_)
                | Component::RootDir
                | Component::CurDir
                | Component::ParentDir => {
                    return Err(ContractError::new(
                        "current_direct_exec_command_v1.working_directory",
                        "path contains a non-normal component",
                    ));
                }
            }
        }
    }

    command.validate()
}

impl CommandSpec {
    /// Validates the executable and working directory.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a blank executable or a working directory
    /// that is not normalized and workspace-relative.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("command.program", &self.program)?;
        if !self.working_directory.as_os_str().is_empty() {
            require_normalized_relative("command.working_directory", &self.working_directory)?;
        }
        Ok(())
    }
}

/// How an acceptance criterion must be evaluated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AcceptanceKind {
    /// A sandboxed command must exit successfully.
    Automated(CommandSpec),
    /// A human must record a decision before completion.
    HumanJudgment,
}

/// One user-visible condition of sprint success.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptanceCriterion {
    /// Stable criterion identifier.
    pub criterion_id: String,
    /// Observable success condition.
    pub description: String,
    /// Evaluation mechanism.
    pub kind: AcceptanceKind,
}

impl AcceptanceCriterion {
    fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("acceptance.criterion_id", &self.criterion_id)?;
        require_nonblank("acceptance.description", &self.description)?;
        if let AcceptanceKind::Automated(command) = &self.kind {
            command.validate()?;
        }
        Ok(())
    }
}

/// Hard limits for one sprint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SprintBudget {
    /// Maximum number of graph tasks.
    pub max_tasks: usize,
    /// Maximum execution attempts for each task.
    pub max_attempts_per_task: u8,
    /// Maximum provider-requested tool calls.
    pub max_tool_calls: u32,
    /// Maximum sprint wall-clock duration.
    pub max_duration_ms: u64,
}

impl SprintBudget {
    fn validate(self) -> Result<(), ContractError> {
        if self.max_tasks == 0 {
            return Err(ContractError::new(
                "sprint.budget.max_tasks",
                "must be greater than zero",
            ));
        }
        if self.max_attempts_per_task == 0 {
            return Err(ContractError::new(
                "sprint.budget.max_attempts_per_task",
                "must be greater than zero",
            ));
        }
        if self.max_tool_calls == 0 {
            return Err(ContractError::new(
                "sprint.budget.max_tool_calls",
                "must be greater than zero",
            ));
        }
        if self.max_duration_ms == 0 {
            return Err(ContractError::new(
                "sprint.budget.max_duration_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Immutable sprint input shared by fake and real providers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SprintSpec {
    /// Stable sprint identifier.
    pub sprint_id: String,
    /// User-requested outcome.
    pub objective: String,
    /// Conditions required for computed completion.
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    /// Provider and model configuration.
    pub provider: ProviderProfile,
    /// Resource and retry ceilings.
    pub budget: SprintBudget,
    /// Maximum concurrent workers; v0.1 permits one through three.
    pub max_workers: u8,
    /// Persistent project authority.
    pub workspace_grant: WorkspaceGrant,
    /// Content-addressed snapshot from which planning began.
    pub base_snapshot: Digest,
}

impl SprintSpec {
    /// Validates all sprint inputs and identifier uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when any sprint input is invalid, duplicated,
    /// empty, or outside the supported one-to-three worker range.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("sprint.sprint_id", &self.sprint_id)?;
        require_nonblank("sprint.objective", &self.objective)?;
        if self.acceptance_criteria.is_empty() {
            return Err(ContractError::new(
                "sprint.acceptance_criteria",
                "must contain at least one criterion",
            ));
        }
        let mut criterion_ids = BTreeSet::new();
        for criterion in &self.acceptance_criteria {
            criterion.validate()?;
            if !criterion_ids.insert(criterion.criterion_id.as_str()) {
                return Err(ContractError::new(
                    "sprint.acceptance_criteria",
                    format!("duplicate criterion id `{}`", criterion.criterion_id),
                ));
            }
        }
        self.provider.validate()?;
        self.budget.validate()?;
        if !(1..=3).contains(&self.max_workers) {
            return Err(ContractError::new(
                "sprint.max_workers",
                "must be between one and three",
            ));
        }
        self.workspace_grant.validate()
    }
}

/// A task's tentative write boundary.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PathScope {
    /// The complete trusted workspace.
    Workspace,
    /// One normalized workspace-relative path and its descendants.
    Relative(PathBuf),
}

impl PathScope {
    pub(super) fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Workspace => Ok(()),
            Self::Relative(path) => require_normalized_relative("task.path_scope", path),
        }
    }
}

/// One node in a sprint task graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskSpec {
    /// Stable task identifier.
    pub task_id: String,
    /// Observable task outcome.
    pub goal: String,
    /// Task identifiers that must integrate first.
    pub dependencies: Vec<String>,
    /// Tentative write scopes used for scheduling and leases.
    pub path_scopes: Vec<PathScope>,
    /// Sprint acceptance criterion identifiers this task contributes to.
    pub acceptance_checks: Vec<String>,
    /// Snapshot on which the task was planned.
    pub base_snapshot: Digest,
    /// Whether sprint completion requires this task to integrate.
    pub required: bool,
}

impl TaskSpec {
    /// Validates task-local invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid identity, paths, scopes,
    /// dependencies, or acceptance references.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("task.task_id", &self.task_id)?;
        require_nonblank("task.goal", &self.goal)?;
        if self.path_scopes.is_empty() {
            return Err(ContractError::new(
                "task.path_scopes",
                "must declare at least one scope",
            ));
        }
        let mut scopes = BTreeSet::new();
        for scope in &self.path_scopes {
            scope.validate()?;
            if !scopes.insert(scope) {
                return Err(ContractError::new(
                    "task.path_scopes",
                    "must not contain duplicate scopes",
                ));
            }
        }
        if self.acceptance_checks.is_empty() {
            return Err(ContractError::new(
                "task.acceptance_checks",
                "must contain at least one criterion id",
            ));
        }
        require_unique_nonblank("task.dependencies", &self.dependencies)?;
        require_unique_nonblank("task.acceptance_checks", &self.acceptance_checks)
    }
}

/// A validated directed acyclic graph of sprint tasks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskGraph {
    /// Stable graph identifier.
    pub graph_id: String,
    /// Graph nodes.
    pub tasks: Vec<TaskSpec>,
}

impl TaskGraph {
    /// Validates graph structure against its owning sprint.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid sprint inputs, unknown or cyclic
    /// dependencies, duplicate tasks, budget excess, or acceptance gaps.
    pub fn validate_for_sprint(&self, sprint: &SprintSpec) -> Result<(), ContractError> {
        sprint.validate()?;
        require_nonblank("task_graph.graph_id", &self.graph_id)?;
        if self.tasks.is_empty() {
            return Err(ContractError::new(
                "task_graph.tasks",
                "must contain at least one task",
            ));
        }
        if self.tasks.len() > sprint.budget.max_tasks {
            return Err(ContractError::new(
                "task_graph.tasks",
                "exceeds the sprint task budget",
            ));
        }

        let mut task_indices = BTreeMap::new();
        for (index, task) in self.tasks.iter().enumerate() {
            task.validate()?;
            if task.base_snapshot != sprint.base_snapshot {
                return Err(ContractError::new(
                    "task.base_snapshot",
                    format!("task `{}` must use the sprint base snapshot", task.task_id),
                ));
            }
            if task_indices.insert(task.task_id.as_str(), index).is_some() {
                return Err(ContractError::new(
                    "task_graph.tasks",
                    format!("duplicate task id `{}`", task.task_id),
                ));
            }
        }

        let criterion_ids: BTreeSet<&str> = sprint
            .acceptance_criteria
            .iter()
            .map(|criterion| criterion.criterion_id.as_str())
            .collect();
        let mut covered_criteria = BTreeSet::new();
        let mut indegrees = vec![0_usize; self.tasks.len()];
        let mut dependents = vec![Vec::new(); self.tasks.len()];

        for (index, task) in self.tasks.iter().enumerate() {
            for criterion_id in &task.acceptance_checks {
                if !criterion_ids.contains(criterion_id.as_str()) {
                    return Err(ContractError::new(
                        "task.acceptance_checks",
                        format!("unknown criterion id `{criterion_id}`"),
                    ));
                }
                covered_criteria.insert(criterion_id.as_str());
            }
            for dependency_id in &task.dependencies {
                let Some(&dependency_index) = task_indices.get(dependency_id.as_str()) else {
                    return Err(ContractError::new(
                        "task.dependencies",
                        format!("unknown dependency `{dependency_id}`"),
                    ));
                };
                if dependency_index == index {
                    return Err(ContractError::new(
                        "task.dependencies",
                        "a task cannot depend on itself",
                    ));
                }
                indegrees[index] += 1;
                dependents[dependency_index].push(index);
            }
        }

        if covered_criteria != criterion_ids {
            let missing = criterion_ids
                .difference(&covered_criteria)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ContractError::new(
                "task_graph.acceptance_coverage",
                format!("criteria not covered by any task: {missing}"),
            ));
        }

        let mut ready: VecDeque<usize> = indegrees
            .iter()
            .enumerate()
            .filter_map(|(index, &degree)| (degree == 0).then_some(index))
            .collect();
        let mut visited = 0_usize;
        while let Some(index) = ready.pop_front() {
            visited += 1;
            for &dependent in &dependents[index] {
                indegrees[dependent] -= 1;
                if indegrees[dependent] == 0 {
                    ready.push_back(dependent);
                }
            }
        }
        if visited != self.tasks.len() {
            return Err(ContractError::new(
                "task_graph.tasks",
                "dependencies must form an acyclic graph",
            ));
        }
        Ok(())
    }

    /// Returns the task with the requested identifier.
    #[must_use]
    pub fn task(&self, task_id: &str) -> Option<&TaskSpec> {
        self.tasks.iter().find(|task| task.task_id == task_id)
    }
}

/// Versioned provider response accepted as durable planning evidence.
///
/// This deliberately narrow core envelope is independent of any provider
/// adapter. Schema v6 accepts only its canonical JSON encoding when binding a
/// provider effect to an attached task graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResponse {
    /// Wire-contract version used to encode the response.
    pub contract_version: u32,
    /// Sprint whose planning request produced the response.
    pub sprint_id: String,
    /// Strict terminal provider result.
    pub result: ProviderResponseResult,
}

/// Closed set of provider results that core may use as graph provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ProviderResponseResult {
    /// Planning completed with the exact proposed task graph.
    PlanningComplete {
        /// Graph produced by the successful provider request.
        task_graph: TaskGraph,
    },
}

impl ProviderResponse {
    /// Validates response identity and its planning graph against a sprint.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the version or sprint identity differs,
    /// or the contained graph is invalid for the sprint.
    pub fn validate_for_sprint(&self, sprint: &SprintSpec) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "provider_response.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("provider_response.sprint_id", &self.sprint_id)?;
        if self.sprint_id != sprint.sprint_id {
            return Err(ContractError::new(
                "provider_response.sprint_id",
                "must match the planned sprint",
            ));
        }
        self.planning_graph().validate_for_sprint(sprint)
    }

    /// Returns the exact graph carried by `PlanningComplete`.
    #[must_use]
    pub const fn planning_graph(&self) -> &TaskGraph {
        match &self.result {
            ProviderResponseResult::PlanningComplete { task_graph } => task_graph,
        }
    }
}

/// Closed set of unsuccessful sprint terminal states.
///
/// [`SprintState::Completed`](crate::SprintState::Completed) is deliberately
/// absent because successful completion requires its separate computed finish
/// contract and receipt chain.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NonSuccessTerminalState {
    /// Progress requires new authority or user input.
    Blocked,
    /// Bounded work or repair attempts failed.
    Failed,
    /// The sprint was deliberately canceled.
    Canceled,
    /// Live side effects or their results cannot be proven.
    Unknown,
}

/// Exact typed evidence for an unsuccessful sprint terminal outcome.
///
/// The ledger stores the canonical JSON preimage of this contract and its
/// SHA-256 digest. `Failed`, `Canceled`, and a `Blocked` outcome recorded
/// before application do not claim that live workspace bytes are unchanged;
/// such a claim requires separate durable application or rollback evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintTerminalEvidence {
    /// Wire-contract version used to encode the evidence.
    pub contract_version: u32,
    /// Stable record identity, also used for the normalized terminal event.
    pub record_id: String,
    /// Sprint receiving the terminal outcome.
    pub sprint_id: String,
    /// Exact unsuccessful terminal state.
    pub state: NonSuccessTerminalState,
    /// Human-readable reason bounded by [`MAX_TERMINAL_REASON_BYTES`].
    pub reason: String,
    /// Time at which the outcome became terminal.
    pub terminal_at_unix_ms: u64,
}

impl SprintTerminalEvidence {
    /// Validates version, stable identities, reason, and timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when any field is unsupported, blank,
    /// oversized, or zero.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "sprint_terminal_evidence.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("sprint_terminal_evidence.record_id", &self.record_id)?;
        require_nonblank("sprint_terminal_evidence.sprint_id", &self.sprint_id)?;
        require_nonblank("sprint_terminal_evidence.reason", &self.reason)?;
        if self.reason.len() > MAX_TERMINAL_REASON_BYTES {
            return Err(ContractError::new(
                "sprint_terminal_evidence.reason",
                format!("must not exceed {MAX_TERMINAL_REASON_BYTES} UTF-8 bytes"),
            ));
        }
        require_nonzero_timestamp(
            "sprint_terminal_evidence.terminal_at_unix_ms",
            self.terminal_at_unix_ms,
        )
    }
}

/// Immutable content-addressed workspace state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkspaceSnapshot {
    /// Snapshot content digest and identifier.
    pub snapshot_id: Digest,
    /// Grant whose root this snapshot represents.
    pub grant_hash: Digest,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_unix_ms: u64,
}

impl WorkspaceSnapshot {
    /// Validates timestamp-bearing snapshot metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the creation timestamp is zero.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonzero_timestamp(
            "workspace_snapshot.created_at_unix_ms",
            self.created_at_unix_ms,
        )
    }
}

/// Exclusive assignment of canonical write scopes to one worker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLease {
    /// Wire-contract version used to encode the lease.
    pub contract_version: u32,
    /// Stable lease identifier.
    pub lease_id: String,
    /// Sprint that owns the lease.
    pub sprint_id: String,
    /// Nonzero durable monotonic epoch assigned to this lease.
    pub lease_epoch: u64,
    /// Owning task identifier.
    pub task_id: String,
    /// Assigned worker identifier.
    pub worker_id: String,
    /// Exclusively leased scopes.
    pub path_scopes: Vec<PathScope>,
    /// Lease acquisition time in Unix milliseconds.
    pub acquired_at_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerLeaseWire {
    contract_version: u32,
    lease_id: String,
    sprint_id: String,
    lease_epoch: u64,
    task_id: String,
    worker_id: String,
    path_scopes: Vec<PathScope>,
    acquired_at_unix_ms: u64,
}

impl<'de> Deserialize<'de> for WorkerLease {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WorkerLeaseWire::deserialize(deserializer)?;
        let lease = Self {
            contract_version: wire.contract_version,
            lease_id: wire.lease_id,
            sprint_id: wire.sprint_id,
            lease_epoch: wire.lease_epoch,
            task_id: wire.task_id,
            worker_id: wire.worker_id,
            path_scopes: wire.path_scopes,
            acquired_at_unix_ms: wire.acquired_at_unix_ms,
        };
        lease.validate().map_err(serde::de::Error::custom)?;
        Ok(lease)
    }
}

impl WorkerLease {
    /// Constructs a canonical lease whose identifier is derived from its
    /// sprint, task, worker, and epoch identity.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when any input would make an invalid lease.
    pub fn new(
        sprint_id: String,
        lease_epoch: u64,
        task_id: String,
        worker_id: String,
        path_scopes: Vec<PathScope>,
        acquired_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let lease_id = Self::derive_lease_id(&sprint_id, &task_id, &worker_id, lease_epoch)?;
        let lease = Self {
            contract_version: CONTRACT_VERSION,
            lease_id,
            sprint_id,
            lease_epoch,
            task_id,
            worker_id,
            path_scopes,
            acquired_at_unix_ms,
        };
        lease.validate()?;
        Ok(lease)
    }

    /// Derives the canonical identifier for one exact lease identity.
    ///
    /// The formula is domain separated and length prefixed. Its stable byte
    /// layout is documented in `deterministic-worker-scheduler.md`.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an identity is blank, the worker
    /// identifier is not bounded canonical ASCII, the epoch is zero, or a
    /// component cannot be represented by the canonical length encoding.
    pub fn derive_lease_id(
        sprint_id: &str,
        task_id: &str,
        worker_id: &str,
        lease_epoch: u64,
    ) -> Result<String, ContractError> {
        require_nonblank("worker_lease.sprint_id", sprint_id)?;
        require_nonblank("worker_lease.task_id", task_id)?;
        Self::validate_worker_id(worker_id)?;
        if lease_epoch == 0 {
            return Err(ContractError::new(
                "worker_lease.lease_epoch",
                "must be greater than zero",
            ));
        }

        let mut preimage = Vec::new();
        preimage.extend_from_slice(WORKER_LEASE_ID_DOMAIN);
        append_worker_lease_identity_component(&mut preimage, sprint_id.as_bytes())?;
        append_worker_lease_identity_component(&mut preimage, task_id.as_bytes())?;
        append_worker_lease_identity_component(&mut preimage, worker_id.as_bytes())?;
        preimage.extend_from_slice(&lease_epoch.to_be_bytes());
        Ok(format!(
            "{WORKER_LEASE_ID_PREFIX}{}",
            Digest::sha256(&preimage)
        ))
    }

    /// Validates one worker identifier independently of a complete lease.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] unless the value contains 1 through
    /// [`MAX_WORKER_ID_BYTES`] bytes drawn from the supported ASCII identity
    /// alphabet.
    pub fn validate_worker_id(worker_id: &str) -> Result<(), ContractError> {
        if worker_id.is_empty()
            || worker_id.len() > MAX_WORKER_ID_BYTES
            || !worker_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(ContractError::new(
                "worker_lease.worker_id",
                format!(
                    "must contain 1..={MAX_WORKER_ID_BYTES} ASCII alphanumeric, hyphen, underscore, period, or colon bytes"
                ),
            ));
        }
        Ok(())
    }

    /// Validates this lease against one exact sprint/task/worker assignment.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the lease is invalid or any assignment
    /// identity differs.
    pub fn validate_assignment(
        &self,
        sprint_id: &str,
        task_id: &str,
        worker_id: &str,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if self.sprint_id != sprint_id || self.task_id != task_id || self.worker_id != worker_id {
            return Err(ContractError::new(
                "worker_lease.assignment",
                "must exactly match the owning sprint, task, and worker",
            ));
        }
        Ok(())
    }

    /// Validates lease version, canonical identity, epoch, scopes, and timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a mismatched version, non-canonical or
    /// substituted identity, zero epoch, empty or invalid scopes, duplicate
    /// scopes, or a zero acquisition timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "worker_lease.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("worker_lease.sprint_id", &self.sprint_id)?;
        if self.lease_epoch == 0 {
            return Err(ContractError::new(
                "worker_lease.lease_epoch",
                "must be greater than zero",
            ));
        }
        require_nonblank("worker_lease.task_id", &self.task_id)?;
        Self::validate_worker_id(&self.worker_id)?;
        validate_worker_lease_id_shape(&self.lease_id)?;
        let expected_lease_id = Self::derive_lease_id(
            &self.sprint_id,
            &self.task_id,
            &self.worker_id,
            self.lease_epoch,
        )?;
        if self.lease_id != expected_lease_id {
            return Err(ContractError::new(
                "worker_lease.lease_id",
                "does not match the canonical sprint, task, worker, and epoch identity",
            ));
        }
        if self.path_scopes.is_empty() {
            return Err(ContractError::new(
                "worker_lease.path_scopes",
                "must contain at least one scope",
            ));
        }
        let mut scopes = BTreeSet::new();
        for scope in &self.path_scopes {
            scope.validate()?;
            if !scopes.insert(scope) {
                return Err(ContractError::new(
                    "worker_lease.path_scopes",
                    "must not contain duplicate scopes",
                ));
            }
        }
        require_nonzero_timestamp("worker_lease.acquired_at_unix_ms", self.acquired_at_unix_ms)
    }
}

pub(super) fn validate_worker_lease_id_shape(lease_id: &str) -> Result<(), ContractError> {
    let Some(digest) = lease_id.strip_prefix(WORKER_LEASE_ID_PREFIX) else {
        return Err(ContractError::new(
            "worker_lease.lease_id",
            "must use canonical lease-<lowercase-sha256> form",
        ));
    };
    if lease_id.len() != WORKER_LEASE_ID_BYTES
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ContractError::new(
            "worker_lease.lease_id",
            "must use canonical lease-<lowercase-sha256> form",
        ));
    }
    Ok(())
}

pub(super) fn append_worker_lease_identity_component(
    preimage: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), ContractError> {
    let length = u64::try_from(value.len()).map_err(|_| {
        ContractError::new(
            "worker_lease.lease_id",
            "identity component length exceeds canonical u64 encoding",
        )
    })?;
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(value);
    Ok(())
}
