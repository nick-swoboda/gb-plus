//! Workflow roots have their own explicit budget and the same child authority.
use super::{
    Arc, BoundProject, FamilyController, FamilyInput, GrokRunner, Mutex, Path, ProjectId,
    QueueCoordinator, RunId, RuntimeManager, WakeScheduler, Workspaces,
};

pub(crate) struct WorkflowFamilyInput<'a> {
    pub(crate) state: &'a Path,
    pub(crate) project: ProjectId,
    pub(crate) parent: RunId,
    pub(crate) bound: BoundProject,
    pub(crate) queue: QueueCoordinator,
    pub(crate) workflow: String,
    pub(crate) maximum: u16,
}
impl FamilyController {
    pub(crate) fn prepare_workflow(
        input: WorkflowFamilyInput<'_>,
        runtime: &RuntimeManager,
        wake: WakeScheduler,
    ) -> Result<Self, String> {
        let template = runtime
            .child_runtime_template(input.state.join("workflow-templates").join(&input.workflow))?;
        Self::new(
            FamilyInput {
                state: input.state,
                project: input.project,
                parent: input.parent,
                bound: input.bound,
                queue: input.queue,
                workflow: Some((input.workflow, input.maximum)),
            },
            runtime.cancel_handle(),
            Arc::new(GrokRunner(Mutex::new(template))),
            wake,
        )
    }
    pub(crate) fn freeze_workflow_snapshot(
        &self,
        expected: Option<&str>,
    ) -> Result<String, String> {
        let mut state = self.state()?;
        if state.workspaces.is_some() {
            return Err("Workflow snapshot must be fixed before its first child.".into());
        }
        let workspaces = Workspaces::capture(
            &self.0.state_root,
            self.0.parent.as_str(),
            &self.0.bound,
            &self.0.cancel,
        )?;
        let digest = workspaces.digest();
        if expected.is_some_and(|expected| expected != digest) {
            return Err("Workflow source snapshot changed. Restore the saved source or explicitly start a new workflow; resume cannot switch workspaces.".into());
        }
        state.workspaces = Some(workspaces);
        Ok(digest)
    }
}
