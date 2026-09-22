//! Authentication stays behind the existing runtime lease; children own no store credentials.
use crate::queue::children::ChildRecord;
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::manager::RuntimeManager;
use crate::runtime::types::{
    AdapterContext, AdapterTurn, RuntimeInvocationScope, RuntimeSteeringSource,
};
use grok_build_plus_host::{BoundProject, PlusSessionStore};
use std::path::Path;
use std::sync::Mutex;

pub(super) trait ChildRunner: Send + Sync {
    fn run(
        &self,
        state: &Path,
        child: &ChildRecord,
        bound: &BoundProject,
        prompt: &str,
        cancel: RuntimeCancelHandle,
        steering: &RuntimeSteeringSource<'_>,
    ) -> Result<AdapterTurn, String>;
}
pub(super) struct GrokRunner(pub(super) Mutex<RuntimeManager>);
impl ChildRunner for GrokRunner {
    fn run(
        &self,
        state: &Path,
        child: &ChildRecord,
        bound: &BoundProject,
        prompt: &str,
        cancel: RuntimeCancelHandle,
        steering: &RuntimeSteeringSource<'_>,
    ) -> Result<AdapterTurn, String> {
        let mut runtime = self
            .0
            .lock()
            .map_err(|_| "Child transport template is unavailable.")?
            .prepare_child_runtime(state, child, bound, cancel)?;
        let store = PlusSessionStore::from_state_root(state.join("child-run-stores").join(
            grok_build_plus_host::worktree_recovery_digest(child.id.as_str().as_bytes()),
        ));
        let result = (|| {
            let hooks = runtime.prepare_hooks()?;
            let context = AdapterContext {
                scope: RuntimeInvocationScope {
                    project_id: child.project.clone(),
                    workspace_id: child.workspace.clone(),
                    session_id: child.session.clone(),
                    run_id: child.id.clone(),
                },
                bound,
                store: &store,
                extension_context: "",
                hooks,
            };
            runtime
                .start_connected_run_session()
                .and_then(|()| runtime.send_turn(&context, prompt, steering, &|_| Ok(())))
        })();
        let cleanup = runtime.disconnect();
        match (result, cleanup) {
            (Ok(turn), Ok(())) => Ok(turn),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}
