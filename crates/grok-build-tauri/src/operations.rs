//! Per-project serialization for blocking workspace and Git effects.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::contracts::ProjectId;

#[derive(Clone, Default)]
pub(crate) struct ProjectOperationPermits {
    gates: Arc<Mutex<HashMap<ProjectId, Arc<Mutex<()>>>>>,
    transitions: Arc<Mutex<()>>,
}

impl ProjectOperationPermits {
    pub(crate) fn gate(&self, project: &ProjectId) -> Result<Arc<Mutex<()>>, String> {
        let mut gates = self
            .gates
            .lock()
            .map_err(|_| "Project operation registry is unavailable.".to_owned())?;
        Ok(gates
            .entry(project.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone())
    }

    pub(crate) fn transition_gate(&self) -> Arc<Mutex<()>> {
        self.transitions.clone()
    }
}
