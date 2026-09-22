//! Bounded in-process context retention plus read-only access to completed journals.
use super::{
    Arc, BoundProject, FamilyController, Journal, Mutex, Ordering, Path, PathBuf, ProjectId, RunId,
    Value,
};

#[derive(Clone)]
pub(crate) struct CollaborationRegistry {
    state_root: PathBuf,
    families: Arc<Mutex<Vec<FamilyController>>>,
}
impl CollaborationRegistry {
    pub(crate) fn decide(
        &self,
        project: &ProjectId,
        parent: &RunId,
        run: &RunId,
        accept: bool,
        bound: &BoundProject,
        conflicts: &std::collections::BTreeSet<PathBuf>,
    ) -> Result<(), String> {
        let families = self
            .families
            .lock()
            .map_err(|_| "Agent family registry is unavailable.")?;
        if let Some(family) = families
            .iter()
            .find(|family| family.0.parent == *parent && family.0.project == *project)
        {
            return family
                .state()?
                .journal
                .decide(&self.state_root, run, accept, bound, conflicts);
        }
        Journal::load(&self.state_root, project, parent)?.decide(
            &self.state_root,
            run,
            accept,
            bound,
            conflicts,
        )
    }
    pub(crate) fn new(state_root: &Path) -> Self {
        Self {
            state_root: state_root.into(),
            families: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub(crate) fn retain(&self, controller: FamilyController) -> Result<(), String> {
        let mut families = self
            .families
            .lock()
            .map_err(|_| "Agent family registry is unavailable.")?;
        if families
            .iter()
            .any(|family| family.0.parent == controller.0.parent)
        {
            return Err("Agent family was registered twice.".into());
        }
        while families.len() >= 4 {
            let removable =
                families
                    .iter()
                    .position(|family| {
                        family.0.closed.load(Ordering::Acquire)
                            && family.0.queue.child_records(&family.0.parent).is_ok_and(
                                |children| children.iter().all(|child| !child.state.active()),
                            )
                    })
                    .ok_or("Agent family cleanup capacity is occupied.")?;
            families.remove(removable);
        }
        families.push(controller);
        Ok(())
    }
    pub(crate) fn result(
        &self,
        project: &ProjectId,
        parent: &RunId,
        run: &RunId,
    ) -> Result<Value, String> {
        let families = self
            .families
            .lock()
            .map_err(|_| "Agent family registry is unavailable.")?;
        if let Some(family) = families
            .iter()
            .find(|family| family.0.parent == *parent && family.0.project == *project)
        {
            return family.state()?.journal.result(run);
        }
        Journal::load(&self.state_root, project, parent)?.result(run)
    }
    pub(crate) fn stop(
        &self,
        project: &ProjectId,
        parent: &RunId,
        run: &RunId,
    ) -> Result<(), String> {
        let families = self
            .families
            .lock()
            .map_err(|_| "Agent family registry is unavailable.")?;
        let family = families
            .iter()
            .find(|family| family.0.parent == *parent && family.0.project == *project)
            .ok_or("The selected family has no live app owner.")?;
        family.0.queue.stop_child(parent, run)
    }
}
