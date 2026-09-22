//! Bounded job retention with transient values kept only in this app process.
use super::{Job, JobInput};
use crate::contracts::ProjectId;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct WorkflowRegistry {
    state: PathBuf,
    jobs: Arc<Mutex<BTreeMap<String, Arc<Mutex<Job>>>>>,
}
impl WorkflowRegistry {
    pub(crate) fn new(state: &Path) -> Self {
        Self {
            state: state.into(),
            jobs: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    pub(crate) fn create(&self, input: JobInput) -> Result<Arc<Mutex<Job>>, String> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| "Workflow registry is unavailable.")?;
        if self.ids()?.len() >= 32 || jobs.len() >= 32 {
            return Err("Workflow history is full at 32 retained jobs.".into());
        }
        let job = Job::new(input)?;
        if jobs.contains_key(&job.id) || self.ids()?.contains(&job.id) {
            return Err("Workflow identity collision refused.".into());
        }
        job.save(&self.state)?;
        let id = job.id.clone();
        let job = Arc::new(Mutex::new(job));
        jobs.insert(id, job.clone());
        Ok(job)
    }
    pub(crate) fn get(&self, project: &ProjectId, id: &str) -> Result<Arc<Mutex<Job>>, String> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| "Workflow registry is unavailable.")?;
        if !jobs.contains_key(id) {
            if jobs.len() >= 32 {
                return Err("Workflow history is full.".into());
            }
            jobs.insert(id.into(), Arc::new(Mutex::new(Job::load(&self.state, id)?)));
        }
        let job = jobs.get(id).cloned().ok_or("Workflow job is unknown.")?;
        if job
            .lock()
            .map_err(|_| "Workflow job is unavailable.")?
            .input
            .project
            != *project
        {
            return Err("Workflow job belongs to another project.".into());
        }
        Ok(job)
    }
    pub(crate) fn view(
        &self,
        project: &ProjectId,
        queue: &crate::queue::QueueCoordinator,
    ) -> Result<Vec<Job>, String> {
        let mut output = Vec::new();
        for id in self.ids()? {
            let stored = {
                let jobs = self
                    .jobs
                    .lock()
                    .map_err(|_| "Workflow registry is unavailable.")?;
                jobs.get(&id).cloned()
            };
            let mut job = match stored {
                Some(stored) => {
                    let mut job = stored.lock().map_err(|_| "Workflow job is unavailable.")?;
                    if job.input.project == *project {
                        job.reconcile_ready(&self.state, queue)?;
                    }
                    job.clone()
                }
                None => Job::load(&self.state, &id)?,
            };
            if job.input.project == *project {
                job.reconcile_ready(&self.state, queue)?;
                output.push(job);
            }
        }
        Ok(output)
    }
    fn ids(&self) -> Result<Vec<String>, String> {
        let dir = self.state.join("workflow-records-v1");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
        };
        let mut ids = Vec::new();
        for (count, entry) in entries.enumerate() {
            if count >= 64 {
                return Err("Workflow directory inventory exceeds its bound.".into());
            }
            let name = entry.map_err(|e| e.to_string())?.file_name();
            let name = name.to_str().ok_or("Invalid workflow file identity.")?;
            if let Some(id) = name.strip_suffix(".json") {
                if !crate::extensions::valid_digest(id) {
                    return Err("Unknown workflow file remains recoverable.".into());
                }
                ids.push(id.to_owned());
            }
        }
        if ids.len() > 32 {
            return Err("Workflow retained-job bound exceeded.".into());
        }
        Ok(ids)
    }
}
