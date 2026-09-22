//! Rhai never owns execution slots; child calls use the app's existing family.
use super::{Job, JobState};
use crate::collaboration::FamilyController;
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::types::{AdapterTurn, AdapterTurnOutcome};
use grok_build_plus_host::{
    PendingFileSet, PlusChildRole, PlusCollaborationCommand, PlusCollaborationExecutor,
};
use grok_build_workflow::{
    AgentOptions, CancelCheck, HostCall, HostReply, WorkflowHost, WorkflowOutcome,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Host {
    state: PathBuf,
    job: Arc<Mutex<Job>>,
    family: FamilyController,
    transient: bool,
    hooks: Option<Arc<dyn crate::extensions::hooks::ToolHookExecutor>>,
    scope: crate::runtime::types::RuntimeInvocationScope,
}
impl WorkflowHost for Host {
    fn call(
        &self,
        sequence: u64,
        request: HostCall,
        cancel: &CancelCheck,
    ) -> Result<HostReply, String> {
        if cancel() {
            return Err("Workflow stopped before its next host request.".into());
        }
        if let Some(value) = self
            .job
            .lock()
            .map_err(|_| "Workflow checkpoint lock failed.")?
            .begin(&self.state, sequence, &request)?
        {
            return Ok(HostReply {
                value,
                replayed: true,
            });
        }
        if !matches!(request, HostCall::Agent(_)) {
            let name = match &request {
                HostCall::Parallel { .. } => "app_workflow_parallel",
                HostCall::Phase { .. } => "app_workflow_phase",
                HostCall::Log { .. } => "app_workflow_log",
                HostCall::Budget => "app_workflow_budget",
                HostCall::Pause { .. } => "app_workflow_pause",
                HostCall::ReadScratch { .. } => "app_workflow_read_scratch",
                HostCall::WriteScratch { .. } => "app_workflow_write_scratch",
                HostCall::Agent(_) => unreachable!(),
            };
            self.gate(
                name,
                &serde_json::to_value(&request).map_err(|e| e.to_string())?,
            )?;
        }
        let value = match request {
            HostCall::Agent(agent) => self
                .agents(sequence, vec![agent], cancel)?
                .into_iter()
                .next()
                .ok_or("Workflow child result is absent.")?,
            HostCall::Parallel { agents } => Value::Array(self.agents(sequence, agents, cancel)?),
            request => self
                .job
                .lock()
                .map_err(|_| "Workflow checkpoint lock failed.")?
                .local_call(&self.state, request)?,
        };
        self.job
            .lock()
            .map_err(|_| "Workflow checkpoint lock failed.")?
            .complete(&self.state, sequence, value.clone())?;
        Ok(HostReply {
            value,
            replayed: false,
        })
    }
}
impl Host {
    fn gate(&self, name: &str, arguments: &Value) -> Result<(), String> {
        if let Some(hook) = &self.hooks {
            match hook.before_tool(&self.scope, name, arguments)? {
                crate::extensions::hooks::HookGateDecision::Proceed => {}
                crate::extensions::hooks::HookGateDecision::Refuse(reason) => return Err(reason),
            }
        }
        Ok(())
    }

    fn agents(
        &self,
        sequence: u64,
        agents: Vec<AgentOptions>,
        cancel: &CancelCheck,
    ) -> Result<Vec<Value>, String> {
        let mut ids = Vec::new();
        for (index, agent) in agents.into_iter().enumerate() {
            if cancel() {
                return Err("Workflow cancelled during child admission.".into());
            }
            let role = match agent.agent_type.as_deref().unwrap_or("plan") {
                "explore" => PlusChildRole::Explore,
                "plan" => PlusChildRole::Plan,
                "worker" => PlusChildRole::Worker,
                _ => return Err("Workflow child role is not admitted.".into()),
            };
            self.gate(
                "app_agent_spawn",
                &json!({"role":role,"prompt":agent.prompt}),
            )?;
            let value = self.family.execute(
                &format!("workflow-{sequence}-spawn-{index}"),
                PlusCollaborationCommand::Spawn {
                    role,
                    prompt: agent.prompt,
                },
                self.transient,
            )?;
            let id = value
                .pointer("/children/0/agentId")
                .and_then(Value::as_str)
                .ok_or("Workflow child admission was refused; its checkpoint cannot replay.")?;
            ids.push(id.to_owned());
        }
        self.wait(sequence, &ids, cancel)?;
        let rows = self.family.rows(Some(&ids))?;
        let children = rows["children"]
            .as_array()
            .ok_or("Workflow child inventory is malformed.")?;
        ids.iter().map(|id|{
            let child=children.iter().find(|child|child["agentId"].as_str()==Some(id)).ok_or("Workflow child result is missing.")?;
            let text=child["assistant"].as_str().unwrap_or("");
            let mut end=text.len().min(4096);while !text.is_char_boundary(end) {end-=1;}
            Ok(json!({"agent_id":id,"run_id":child["runId"],"success":matches!(child["state"].as_str(),Some("done"|"needs_review")),"cancelled":child["state"]=="stopped","output":&text[..end],"output_truncated":end<text.len() || child["assistantTruncated"]==true,"proposal_count":child["proposalCount"]}))
        }).collect()
    }
    fn wait(&self, sequence: u64, ids: &[String], cancel: &CancelCheck) -> Result<(), String> {
        // At most eight completions plus bounded 60-second progress waits.
        for attempt in 0..40 {
            if cancel() {
                return Err("Workflow child wait was cancelled.".into());
            }
            let rows = self.family.rows(Some(ids))?;
            let active = rows["children"]
                .as_array()
                .ok_or("Workflow children are unavailable.")?
                .iter()
                .filter(|child| {
                    matches!(
                        child["state"].as_str(),
                        Some("waiting" | "running" | "stop_requested")
                    )
                })
                .filter_map(|child| child["agentId"].as_str().map(str::to_owned))
                .collect::<Vec<_>>();
            if active.is_empty() {
                return Ok(());
            }
            self.family.execute(
                &format!("workflow-{sequence}-wait-{attempt}"),
                PlusCollaborationCommand::Wait {
                    agent_ids: active,
                    timeout_seconds: 60,
                },
                self.transient,
            )?;
        }
        Err("Workflow children exceeded the bounded wait count.".into())
    }
}

pub(crate) fn execute(
    state: &Path,
    job: &Arc<Mutex<Job>>,
    family: FamilyController,
    cancel: &RuntimeCancelHandle,
    hooks: Option<Arc<dyn crate::extensions::hooks::ToolHookExecutor>>,
) -> Result<AdapterTurn, String> {
    let (input, snapshot) = {
        let job = job.lock().map_err(|_| "Workflow checkpoint lock failed.")?;
        (job.input.clone(), job.snapshot.clone())
    };
    let snapshot = family.freeze_workflow_snapshot(snapshot.as_deref())?;
    job.lock()
        .map_err(|_| "Workflow checkpoint lock failed.")?
        .mutate(state, |job| {
            job.snapshot = Some(snapshot);
            Ok(())
        })?;
    let deadline = Instant::now() + Duration::from_mins(30);
    let observed = cancel.clone();
    let check: CancelCheck = Arc::new(move || observed.cancelled() || Instant::now() >= deadline);
    let (finished, wait) = std::sync::mpsc::sync_channel::<()>(1);
    let timed_cancel = cancel.clone();
    let timer = std::thread::Builder::new()
        .name("gbplus-workflow-deadline".into())
        .spawn(move || {
            if matches!(
                wait.recv_timeout(Duration::from_mins(30)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                let _ = timed_cancel.request_cancel();
            }
        })
        .map_err(|_| "Workflow deadline monitor could not start.")?;
    let scope = {
        let job = job.lock().map_err(|_| "Workflow checkpoint lock failed.")?;
        crate::runtime::types::RuntimeInvocationScope {
            project_id: job.input.project.clone(),
            workspace_id: job.input.workspace.clone(),
            session_id: job.input.session.clone(),
            run_id: job
                .run
                .clone()
                .ok_or("Workflow run authority is missing.")?,
        }
    };
    let host = std::rc::Rc::new(Host {
        state: state.into(),
        job: job.clone(),
        family,
        transient: input.transient,
        hooks,
        scope,
    });
    let outcome = grok_build_workflow::run_workflow(&input.script, &input.args, host, check);
    drop(finished);
    timer
        .join()
        .map_err(|_| "Workflow deadline monitor failed.")?;
    let state_outcome = match &outcome {
        WorkflowOutcome::Completed { .. } => JobState::Completed,
        WorkflowOutcome::Paused { .. } => JobState::Paused,
        WorkflowOutcome::Cancelled => JobState::Stopped,
        WorkflowOutcome::Failed { .. } => JobState::Failed,
    };
    job.lock()
        .map_err(|_| "Workflow checkpoint lock failed.")?
        .mutate(state, |job| {
            job.state = state_outcome;
            job.outcome = Some(outcome.clone());
            Ok(())
        })?;
    let turn_outcome = match &outcome {
        WorkflowOutcome::Failed { .. } | WorkflowOutcome::Cancelled => AdapterTurnOutcome::Failed(
            "Workflow stopped; inspect its checkpoint before explicit resume.".into(),
        ),
        _ => AdapterTurnOutcome::Completed,
    };
    Ok(AdapterTurn {
        // Results remain in the workflow checkpoint, including temporary ones.
        assistant_text: String::new(),
        pending: PendingFileSet::default(),
        provider_session_id: None,
        usage: None,
        outcome: turn_outcome,
    })
}
