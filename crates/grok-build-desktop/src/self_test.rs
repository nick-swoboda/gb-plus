//! Read-only, planning-only production-contract self-test used by the CLI.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use grok_build_core::{
    AcceptanceCriterion, AcceptanceKind, CommandSpec, ContractError, Digest, SprintBudget,
    SprintSpec, WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy,
    WorkspacePermissions,
};
use grok_build_providers::{FakeProvider, ModelProvider, ProviderError};

/// Result of planning the deterministic walking-skeleton fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractSelfTestReport {
    /// Production sprint identifier used by the fixture.
    pub sprint_id: String,
    /// Production graph identifier returned by the fake provider.
    pub graph_id: String,
    /// Number of graph tasks; Milestone 1 requires exactly one.
    pub task_count: usize,
    /// Number of globally sequenced production events.
    pub event_count: usize,
    /// Explicit reminder that this test did not execute host commands.
    pub commands_executed: usize,
}

/// Closed failure from the planning-only contract self-test.
#[derive(Debug)]
pub enum ContractSelfTestError {
    /// The requested workspace path is not absolute.
    RelativeWorkspace,
    /// A production core contract was rejected.
    Contract(ContractError),
    /// The deterministic planning provider rejected the request or response.
    Provider(ProviderError),
    /// The provider returned a graph outside the one-node walking-skeleton
    /// contract.
    InvalidPlanningShape(String),
}

impl Display for ContractSelfTestError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeWorkspace => {
                formatter.write_str("contract self-test workspace root must be absolute")
            }
            Self::Contract(error) => write!(formatter, "contract rejected: {error}"),
            Self::Provider(error) => write!(formatter, "provider rejected planning: {error}"),
            Self::InvalidPlanningShape(reason) => {
                write!(formatter, "planning shape rejected: {reason}")
            }
        }
    }
}

impl Error for ContractSelfTestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::RelativeWorkspace | Self::InvalidPlanningShape(_) => None,
        }
    }
}

impl From<ContractError> for ContractSelfTestError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<ProviderError> for ContractSelfTestError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

/// Plans one deterministic sprint using the exact production contracts.
///
/// This function captures only the live directory identity needed to issue and
/// validate project trust. It reads no workspace file content, runs no commands,
/// and makes no containment claim.
///
/// # Errors
///
/// Returns an error when the root is not absolute or contract planning fails.
pub fn run_contract_self_test(
    workspace_root: impl Into<PathBuf>,
) -> Result<ContractSelfTestReport, ContractSelfTestError> {
    let workspace_root = workspace_root.into();
    if !workspace_root.is_absolute() {
        return Err(ContractSelfTestError::RelativeWorkspace);
    }
    let sprint = self_test_sprint(&workspace_root)?;
    sprint.validate()?;
    let response = FakeProvider::new().plan_sprint(&sprint)?;
    response.validate_for_sprint(&sprint)?;
    let graph = response.task_graph;
    if graph.tasks.len() != 1 || !graph.tasks[0].required {
        return Err(ContractSelfTestError::InvalidPlanningShape(
            "fake provider must return exactly one required task".into(),
        ));
    }
    Ok(ContractSelfTestReport {
        sprint_id: sprint.sprint_id,
        graph_id: graph.graph_id.clone(),
        task_count: graph.tasks.len(),
        event_count: response.events.len(),
        commands_executed: 0,
    })
}

fn self_test_sprint(workspace_root: &Path) -> Result<SprintSpec, ContractSelfTestError> {
    let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
        grant_id: "contract-self-test-grant".into(),
        workspace_root: workspace_root.to_path_buf(),
        permissions: WorkspacePermissions::read_only(),
        network: WorkspaceNetworkPolicy::Denied,
        policy_version: 1,
    })?;
    Ok(SprintSpec {
        sprint_id: "contract-self-test".into(),
        objective: "Validate the Milestone 1 production-contract planning path".into(),
        acceptance_criteria: vec![AcceptanceCriterion {
            criterion_id: "contract-plan".into(),
            description: "The fake provider returns one valid production task".into(),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "contract-self-test-only".into(),
                arguments: Vec::new(),
                working_directory: PathBuf::new(),
            }),
        }],
        provider: FakeProvider::new().profile(),
        budget: SprintBudget {
            max_tasks: 1,
            max_attempts_per_task: 1,
            max_tool_calls: 8,
            max_duration_ms: 30_000,
        },
        max_workers: 1,
        workspace_grant: authority.contract().clone(),
        base_snapshot: fixture_digest('b')?,
    })
}

fn fixture_digest(character: char) -> Result<Digest, ContractSelfTestError> {
    Ok(Digest::parse(character.to_string().repeat(64))?)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(1);

    struct TestWorkspace(PathBuf);

    impl TestWorkspace {
        fn new() -> Self {
            let unique = NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-desktop-self-test-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create self-test workspace");
            Self(path)
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn self_test_proves_contract_planning_without_claiming_execution() {
        let workspace = TestWorkspace::new();
        let report = run_contract_self_test(workspace.0.clone()).expect("contract self-test");

        assert_eq!(report.task_count, 1);
        assert!(report.event_count > 0);
        assert_eq!(report.commands_executed, 0);

        let sprint = self_test_sprint(&workspace.0).expect("production sprint fixture");
        let response = FakeProvider::new()
            .plan_sprint(&sprint)
            .expect("contract planning");
        assert_eq!(response.task_graph.tasks.len(), 1);
    }

    #[test]
    fn self_test_rejects_relative_workspace_contracts() {
        assert!(matches!(
            run_contract_self_test(PathBuf::from("relative/workspace")),
            Err(ContractSelfTestError::RelativeWorkspace)
        ));
    }
}
