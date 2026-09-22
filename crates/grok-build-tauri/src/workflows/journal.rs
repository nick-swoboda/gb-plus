//! Durable intent precedes each host effect; uncertain entries cannot replay.
use crate::contracts::{ProjectId, QueueItemId, RunId, SessionId, WorkspaceId};
use crate::owner_state::OwnerStateRoot;
use crate::runtime::types::RuntimeTransport;
use grok_build_workflow::{HostCall, WorkflowOutcome, validate_value};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) const MAX_JOB_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JobState {
    Ready,
    Running,
    Completed,
    Paused,
    Interrupted,
    Failed,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JobInput {
    pub(crate) project: ProjectId,
    pub(crate) workspace: WorkspaceId,
    pub(crate) session: SessionId,
    pub(crate) transport: RuntimeTransport,
    pub(crate) extension: String,
    pub(crate) component: String,
    pub(crate) name: String,
    pub(crate) script: String,
    pub(crate) args: Value,
    pub(crate) maximum: u16,
    pub(crate) transient: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Effect {
    fingerprint: String,
    completed: bool,
    result: Option<CompletedValue>,
}

// An outer object preserves Some(JSON null) across serde's Option decoding.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletedValue {
    value: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Job {
    version: u16,
    pub(crate) id: String,
    pub(crate) input: JobInput,
    pub(crate) state: JobState,
    pub(crate) attempt: u16,
    pub(crate) queue_item: Option<QueueItemId>,
    pub(crate) run: Option<RunId>,
    pub(crate) snapshot: Option<String>,
    pub(crate) used: u16,
    pub(crate) phase: Option<String>,
    pub(crate) outcome: Option<WorkflowOutcome>,
    effects: Vec<Effect>,
    scratch: BTreeMap<String, String>,
    pub(crate) available: bool,
}
impl Job {
    pub(super) fn new(input: JobInput) -> Result<Self, String> {
        validate_value(&input.args)?;
        if input.script.is_empty()
            || input.script.len() > grok_build_workflow::MAX_BYTES
            || !(1..=32).contains(&input.maximum)
            || input.name.is_empty()
            || input.name.len() > 256
            || !crate::extensions::valid_digest(&input.extension)
            || !crate::extensions::valid_digest(&input.component)
        {
            return Err("Workflow input or immutable source binding is invalid.".into());
        }
        let nonce = format!(
            "{}:{}:{}:{}",
            input.project.as_str(),
            std::process::id(),
            crate::runtime::types::unix_time_millis(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos()
        );
        Ok(Self {
            version: 1,
            id: digest(nonce.as_bytes()),
            input,
            state: JobState::Ready,
            attempt: 1,
            queue_item: None,
            run: None,
            snapshot: None,
            used: 0,
            phase: None,
            outcome: None,
            effects: Vec::new(),
            scratch: BTreeMap::new(),
            available: true,
        })
    }
    pub(super) fn load(state: &Path, id: &str) -> Result<Self, String> {
        let bytes = file(state, id)?
            .read()
            .map_err(|e| e.to_string())?
            .ok_or("Workflow checkpoint is unavailable.")?;
        let mut job: Self = serde_json::from_slice(&bytes).map_err(
            |_| "Workflow checkpoint is unreadable; its original bytes remain recoverable.",
        )?;
        job.validate(id)?;
        if job.state == JobState::Running {
            job.state = JobState::Interrupted;
            job.save(state)?;
        }
        Ok(job)
    }
    fn validate(&self, expected: &str) -> Result<(), String> {
        let identity =
            |id: &str| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control);
        if !identity(self.input.project.as_str())
            || !identity(self.input.workspace.as_str())
            || !identity(self.input.session.as_str())
            || !crate::extensions::valid_digest(&self.input.extension)
            || !crate::extensions::valid_digest(&self.input.component)
            || self.input.script.is_empty()
            || self.input.script.len() > grok_build_workflow::MAX_BYTES
            || !identity(&self.input.name)
        {
            return Err("Workflow source or app identity binding is invalid.".into());
        }
        validate_value(&self.input.args)?;
        if self.version != 1
            || self.id != expected
            || self.effects.len() > 256
            || !(1..=32).contains(&self.attempt)
            || !(1..=32).contains(&self.input.maximum)
            || self.used > self.input.maximum
            || self.scratch.len() > 32
            || self.scratch.values().map(String::len).sum::<usize>() > 256 * 1024
            || self
                .snapshot
                .as_ref()
                .is_some_and(|s| !crate::extensions::valid_digest(s))
        {
            return Err("Workflow checkpoint has unknown version, identity or bounds.".into());
        }
        if self.input.transient
            && (self.available
                || self.input.args != Value::Null
                || self.phase.is_some()
                || self.outcome.is_some()
                || !self.scratch.is_empty()
                || self.effects.iter().any(|effect| effect.result.is_some()))
        {
            return Err(
                "Durable workflow checkpoint contains forbidden transient payloads.".into(),
            );
        }
        for effect in &self.effects {
            if !crate::extensions::valid_digest(&effect.fingerprint)
                || (effect.completed && effect.result.is_none() && !self.input.transient)
            {
                return Err("Workflow effect checkpoint is inconsistent.".into());
            }
            if let Some(result) = &effect.result {
                validate_value(&result.value)?;
            }
        }
        Ok(())
    }
    pub(crate) fn save(&self, state: &Path) -> Result<(), String> {
        let mut disk = self.clone();
        if disk.input.transient {
            disk.input.args = Value::Null;
            disk.available = false;
            disk.phase = None;
            disk.outcome = None;
            disk.scratch.clear();
            for effect in &mut disk.effects {
                effect.result = None;
            }
        }
        disk.validate(&self.id)?;
        file(state, &self.id)?
            .replace(&serde_json::to_vec(&disk).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
    pub(crate) fn mutate<T>(
        &mut self,
        state: &Path,
        change: impl FnOnce(&mut Self) -> Result<T, String>,
    ) -> Result<T, String> {
        let before = self.clone();
        match change(self).and_then(|result| self.save(state).map(|()| result)) {
            Ok(result) => Ok(result),
            Err(error) => {
                *self = before;
                Err(error)
            }
        }
    }
    pub(crate) fn begin(
        &mut self,
        state: &Path,
        sequence: u64,
        request: &HostCall,
    ) -> Result<Option<Value>, String> {
        if self.state != JobState::Running || !self.available {
            return Err("Workflow is not active or its context is unavailable.".into());
        }
        let index = usize::try_from(sequence).map_err(|_| "Workflow sequence overflow")?;
        let fingerprint = digest(&serde_json::to_vec(request).map_err(|e| e.to_string())?);
        if let Some(effect) = self.effects.get(index) {
            if effect.fingerprint != fingerprint {
                return Err("Workflow replay diverged from its exact completed checkpoint.".into());
            }
            return effect.result.clone().filter(|_|effect.completed).map(|result|Some(result.value)).ok_or("An earlier workflow effect has uncertain completion; automatic replay is refused.".into());
        }
        if index != self.effects.len() || index >= 256 {
            return Err("Workflow host sequence exceeds its fixed bound.".into());
        }
        let count = match request {
            HostCall::Agent(_) => 1,
            HostCall::Parallel { agents } => {
                u16::try_from(agents.len()).map_err(|_| "Workflow fan-out overflow")?
            }
            _ => 0,
        };
        self.mutate(state, |job| {
            if count > job.input.maximum.saturating_sub(job.used) {
                return Err("Workflow agent-call budget is exhausted.".into());
            }
            job.used += count;
            job.effects.push(Effect {
                fingerprint,
                completed: false,
                result: None,
            });
            Ok(None)
        })
    }
    pub(crate) fn complete(
        &mut self,
        state: &Path,
        sequence: u64,
        result: Value,
    ) -> Result<(), String> {
        validate_value(&result)?;
        self.mutate(state, |job| {
            let effect = job
                .effects
                .get_mut(usize::try_from(sequence).map_err(|_| "Workflow sequence overflow")?)
                .ok_or("Workflow effect intent is missing.")?;
            if effect.completed {
                return Err("Workflow effect completed twice.".into());
            }
            effect.completed = true;
            effect.result = Some(CompletedValue { value: result });
            Ok(())
        })
    }
    pub(crate) fn resume(&mut self, state: &Path) -> Result<(), String> {
        if !self.available
            || !matches!(
                self.state,
                JobState::Paused | JobState::Interrupted | JobState::Stopped | JobState::Failed
            )
            || self.attempt >= 32
            || self.effects.iter().any(|e| !e.completed)
        {
            return Err("Workflow cannot resume with missing context, uncertain effects or an exhausted attempt bound.".into());
        }
        self.mutate(state, |job| {
            job.attempt += 1;
            job.state = JobState::Ready;
            job.queue_item = None;
            job.run = None;
            job.outcome = None;
            Ok(())
        })
    }
    pub(crate) fn local_call(&mut self, state: &Path, request: HostCall) -> Result<Value, String> {
        self.mutate(state,|job|match request {
            HostCall::Phase {text}=>{job.phase=Some(text);Ok(Value::Null)},
            HostCall::Log {..}=>Ok(Value::Null),
            HostCall::Pause {message,..}=>{job.phase=Some(message);Ok(Value::Null)},
            HostCall::Budget=>Ok(serde_json::json!({"total":job.input.maximum,"spent":job.used,"remaining":job.input.maximum-job.used})),
            HostCall::WriteScratch {name,content}=>{
                if !job.scratch.contains_key(&name) && job.scratch.len()>=32 {return Err("Workflow scratch has 32 retained values.".into());}
                job.scratch.insert(name.clone(),content);
                if job.scratch.values().map(String::len).sum::<usize>()>256*1024 {return Err("Workflow scratch exceeds 256 KiB.".into());}
                Ok(Value::String(name))
            },
            HostCall::ReadScratch {name}=>job.scratch.get(&name).cloned().map(Value::String).ok_or("Workflow scratch value is absent.".into()),
            HostCall::Agent(_)|HostCall::Parallel {..}=>Err("Child operation requires the app scheduler.".into()),
        })
    }
}
fn digest(bytes: &[u8]) -> String {
    grok_build_plus_host::worktree_recovery_digest(bytes)
}
fn file(state: &Path, id: &str) -> Result<crate::owner_state::OwnerStateFile, String> {
    if !crate::extensions::valid_digest(id) {
        return Err("Workflow identity is invalid.".into());
    }
    OwnerStateRoot::new(state.join("workflow-records-v1"))
        .file(format!("{id}.json"), MAX_JOB_BYTES)
        .map_err(|e| e.to_string())
}
