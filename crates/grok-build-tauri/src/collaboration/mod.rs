//! App-owned Grok families. All new execution authority is disabled by default.
mod journal;
mod messages;
mod registry;
mod runner;
mod settings;
pub(crate) use registry::CollaborationRegistry;
mod workflow;
mod workspaces;
pub(crate) use settings::AgentSettings;
pub(crate) use workflow::WorkflowFamilyInput;

use crate::contracts::{ProjectId, RunId, WorkspaceId};
use crate::queue::QueueCoordinator;
use crate::queue::children::{ChildAdmission, ChildRecord, ChildState};
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::manager::RuntimeManager;
use crate::runtime::types::AdapterTurnOutcome;
use grok_build_plus_host::{
    BoundProject, PlusChildRole, PlusCollaborationCommand, PlusCollaborationExecutor,
    worktree_recovery_digest,
};
use journal::{Journal, Payload};
use runner::{ChildRunner, GrokRunner};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use workspaces::{ChildWorkspace, Workspaces};

type WakeScheduler = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;
struct Slot {
    record: ChildRecord,
    workspace: Option<Arc<ChildWorkspace>>,
    finished: Option<ChildState>,
}
struct FamilyState {
    workspaces: Option<Workspaces>,
    slots: Vec<Slot>,
    journal: Journal,
}
struct FamilyInput<'a> {
    state: &'a Path,
    project: ProjectId,
    parent: RunId,
    bound: BoundProject,
    queue: QueueCoordinator,
    workflow: Option<(String, u16)>,
}
struct Family {
    parent: RunId,
    project: ProjectId,
    state_root: PathBuf,
    bound: BoundProject,
    queue: QueueCoordinator,
    cancel: RuntimeCancelHandle,
    runner: Arc<dyn ChildRunner>,
    wake: WakeScheduler,
    closed: AtomicBool,
    operation: Mutex<()>,
    state: Mutex<FamilyState>,
}

#[derive(Clone)]
pub(crate) struct FamilyController(Arc<Family>);

impl FamilyController {
    pub(crate) fn prepare(
        state: &Path,
        project: ProjectId,
        parent: RunId,
        bound: BoundProject,
        queue: QueueCoordinator,
        runtime: &RuntimeManager,
        wake: WakeScheduler,
    ) -> Result<Option<Self>, String> {
        if !AgentSettings::load(state, &project)?.enabled {
            return Ok(None);
        }
        let template = runtime.child_runtime_template(
            state
                .join("child-templates")
                .join(worktree_recovery_digest(parent.as_str().as_bytes())),
        )?;
        let runner = Arc::new(GrokRunner(Mutex::new(template)));
        let cancel = runtime.cancel_handle();
        let controller = Self::new(
            FamilyInput {
                state,
                project,
                parent,
                bound,
                queue,
                workflow: None,
            },
            cancel,
            runner,
            wake,
        )?;
        Ok(Some(controller))
    }

    fn new(
        input: FamilyInput<'_>,
        cancel: RuntimeCancelHandle,
        runner: Arc<dyn ChildRunner>,
        wake: WakeScheduler,
    ) -> Result<Self, String> {
        let FamilyInput {
            state,
            project,
            parent,
            bound,
            queue,
            workflow,
        } = input;
        let (workflow, maximum) = match workflow {
            Some((id, maximum)) => (Some(id), maximum),
            None => (None, 8),
        };
        queue.configure_family(&parent, workflow, maximum)?;
        let journal = Journal::create(project.clone(), parent.clone());
        journal.start(state)?;
        Ok(Self(Arc::new(Family {
            parent,
            project,
            state_root: state.into(),
            bound,
            queue,
            cancel,
            runner,
            wake,
            closed: AtomicBool::new(false),
            operation: Mutex::new(()),
            state: Mutex::new(FamilyState {
                workspaces: None,
                slots: Vec::new(),
                journal,
            }),
        })))
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, FamilyState>, String> {
        self.0
            .state
            .lock()
            .map_err(|_| "Grok family state is unavailable.".into())
    }

    fn workspace(
        &self,
        state: &mut FamilyState,
        previous: Option<&ChildRecord>,
    ) -> Result<Arc<ChildWorkspace>, String> {
        let workspace = if let Some(previous) = previous {
            state
                .slots
                .iter()
                .find(|slot| slot.record.id == previous.id)
                .and_then(|slot| slot.workspace.clone())
                .ok_or("Child workspace is no longer available for continuation.")?
        } else {
            if state.workspaces.is_none() {
                state.workspaces = Some(Workspaces::capture(
                    &self.0.state_root,
                    self.0.parent.as_str(),
                    &self.0.bound,
                    &self.0.cancel,
                )?);
            }
            Arc::new(
                state
                    .workspaces
                    .as_mut()
                    .ok_or("Family snapshot is unavailable.")?
                    .create_child(&self.0.cancel)?,
            )
        };
        Ok(workspace)
    }

    fn spawn(
        &self,
        invocation: &str,
        role: PlusChildRole,
        prompt: &str,
        transient: bool,
        previous: Option<&ChildRecord>,
    ) -> Result<Value, String> {
        self.0.cancel.ensure_not_cancelled()?;
        let mut state = self.state()?;
        let (guidance, guidance_transient) = match previous {
            Some(previous) => state.journal.pending_guidance(&previous.agent_id)?,
            None => (String::new(), false),
        };
        let prompt = format!("{prompt}{guidance}");
        if prompt.len() > 12_000 {
            return Err("Child prompt and queued guidance exceed one bounded continuation.".into());
        }
        let transient = transient || guidance_transient;

        let workspace = self.workspace(&mut state, previous)?;
        let workspace_id = previous.as_ref().map_or_else(
            || {
                WorkspaceId::new(format!(
                    "child-workspace-{}",
                    worktree_recovery_digest(
                        workspace.bound.folder().as_os_str().as_encoded_bytes()
                    )
                ))
            },
            |previous| previous.workspace.clone(),
        );
        let cancel = RuntimeCancelHandle::new();
        let record = self.0.queue.admit_child(
            &self.0.parent,
            ChildAdmission {
                workspace: workspace_id,
                role,
                snapshot: workspace.snapshot.clone(),
                isolated: workspace.isolated,
                invocation: invocation.into(),
                predecessor: previous.as_ref().map(|previous| previous.id.clone()),
                transient,
            },
            cancel.clone(),
        )?;
        let role_prompt = format!(
            "You are an app-owned Grok {role:?} child. Work only on the task below. Your app-issued tools enforce your role. Report findings with file evidence; any Worker changes must remain staged for separate user review. Do not delegate or request inherited credentials or machine access.\n\n{prompt}"
        );
        if let Err(error) = state.journal.begin_child(
            &self.0.state_root,
            record.id.clone(),
            role_prompt.clone(),
            transient,
        ) {
            self.0
                .queue
                .finish_child(&self.0.parent, &record.id, ChildState::Failed)?;
            return Err(error);
        }
        if let Some(previous) = previous
            && let Err(error) = state
                .journal
                .promote_guidance(&self.0.state_root, &previous.agent_id)
        {
            self.0
                .queue
                .finish_child(&self.0.parent, &record.id, ChildState::Failed)?;
            return Err(error);
        }
        state.slots.push(Slot {
            record: record.clone(),
            workspace: Some(workspace.clone()),
            finished: None,
        });
        drop(state);
        let controller = self.clone();
        let worker_record = record.clone();
        let worker = std::thread::Builder::new()
            .name("gbplus-grok-child".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    controller.run_child(&worker_record, &workspace, &role_prompt, &cancel);
                }));
                if result.is_err() {
                    let _ = controller
                        .0
                        .queue
                        .stop_child(&controller.0.parent, &worker_record.id);
                    if let Ok(mut state) = controller.state()
                        && let Some(slot) = state
                            .slots
                            .iter_mut()
                            .find(|slot| slot.record.id == worker_record.id)
                    {
                        slot.finished = Some(ChildState::Failed);
                    }
                    let _ = controller.finish_ready();
                }
            });
        if worker.is_err() {
            self.0
                .queue
                .finish_child(&self.0.parent, &record.id, ChildState::Failed)?;
            return Err("The app could not start its bounded child worker.".into());
        }
        self.rows(Some(&[record.agent_id.as_str().into()]))
    }

    fn run_child(
        &self,
        child: &ChildRecord,
        workspace: &ChildWorkspace,
        prompt: &str,
        cancel: &RuntimeCancelHandle,
    ) {
        let result = (|| {
            loop {
                if self.0.closed.load(Ordering::Acquire) {
                    let _ = cancel.request_cancel();
                }
                cancel.ensure_not_cancelled()?;
                if self.0.queue.try_acquire_execution(&child.id)? {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let steering = |action| {
                self.state()?
                    .journal
                    .steer(&self.0.state_root, &child.id, action)
            };
            self.0.runner.run(
                &self.0.state_root,
                child,
                &workspace.bound,
                prompt,
                cancel.clone(),
                &steering,
            )
        })();
        // Normal adapter shutdown also marks its cancellation handle. Only an
        // app stop intent decides the user-visible Stopped outcome.
        let stopped = self.0.closed.load(Ordering::Acquire)
            || self
                .0
                .queue
                .child_records(&self.0.parent)
                .is_ok_and(|children| {
                    children.iter().any(|record| {
                        record.id == child.id && record.state == ChildState::StopRequested
                    })
                });
        let mut outcome = if stopped {
            ChildState::Stopped
        } else {
            ChildState::Failed
        };
        if let Ok(turn) = result {
            let has_pending = !turn.pending.items.is_empty();
            if !stopped && turn.outcome == AdapterTurnOutcome::Completed {
                outcome = if turn.pending.items.is_empty() {
                    ChildState::Done
                } else {
                    ChildState::NeedsReview
                };
            }
            if self
                .state()
                .and_then(|mut state| {
                    state.journal.complete_child(
                        &self.0.state_root,
                        &child.id,
                        turn.assistant_text,
                        turn.pending,
                    )
                })
                .and_then(|()| {
                    self.0
                        .queue
                        .child_review_result(&self.0.parent, &child.id, has_pending)
                })
                .is_err()
            {
                outcome = ChildState::Failed;
            }
        }
        if self
            .state()
            .and_then(|mut state| state.journal.finish_messages(&self.0.state_root, &child.id))
            .is_err()
        {
            outcome = ChildState::Failed;
        }
        if let Ok(mut state) = self.state()
            && let Some(slot) = state
                .slots
                .iter_mut()
                .find(|slot| slot.record.id == child.id)
        {
            slot.finished = Some(outcome);
        }
        let _ = self.finish_ready();
        let _ = (self.0.wake)();
    }

    fn finish_ready(&self) -> Result<(), String> {
        // Completion callers share this lock through the queue transition.
        let state = self.state()?;
        let candidates = state.slots.iter().filter_map(|slot| {
            slot.finished
                .map(|outcome| (slot.record.id.clone(), outcome))
        });
        let current = self.0.queue.child_records(&self.0.parent)?;
        for (id, outcome) in candidates {
            if current
                .iter()
                .any(|child| child.id == id && child.state.active())
                && self.0.queue.run_cleanup_proven(&id)
            {
                // A concurrent stop wins over a completed success result.
                let outcome = if current
                    .iter()
                    .any(|child| child.id == id && child.state == ChildState::StopRequested)
                {
                    ChildState::Stopped
                } else {
                    outcome
                };
                self.0.queue.finish_child(&self.0.parent, &id, outcome)?;
            }
        }
        Ok(())
    }

    fn latest(&self, agent: &str) -> Result<ChildRecord, String> {
        self.0
            .queue
            .child_records(&self.0.parent)?
            .into_iter()
            .rev()
            .find(|child| child.agent_id.as_str() == agent)
            .ok_or("The requested Grok child does not belong to this family.".into())
    }

    pub(crate) fn rows(&self, agents: Option<&[String]>) -> Result<Value, String> {
        let records = self.0.queue.child_records(&self.0.parent)?;
        let state = self.state()?;
        let rows = records.iter().filter(|child| agents.is_none_or(|agents| agents.iter().any(|agent| child.agent_id.as_str() == agent))).map(|child| {
            let payload = state.journal.entries.iter().find(|entry| entry.run == child.id).and_then(|entry| match &entry.payload { Payload::Available { assistant, pending, .. } => Some((assistant.clone(), pending.items.len())), Payload::Unavailable => None });
            let serial_reason = state.slots.iter().find(|slot| slot.record.id == child.id).and_then(|slot| slot.workspace.as_ref()).and_then(|workspace| workspace.serial_reason.clone());
            let excluded_paths = state.slots.iter().find(|slot|slot.record.id==child.id).and_then(|slot|slot.workspace.as_ref()).map(|workspace|workspace.excluded_paths.clone()).unwrap_or_default();
            json!({"agentId":child.agent_id,"runId":child.id,"role":child.role,"state":child.state,"isolated":child.isolated,"serialReason":serial_reason,"excludedPaths":excluded_paths,"assistant":payload.as_ref().and_then(|payload| payload.0.as_deref().map(child_summary)),"assistantTruncated":payload.as_ref().and_then(|payload| payload.0.as_ref()).is_some_and(|text| text.len() > 8192),"proposalCount":payload.map_or(0, |payload| payload.1),"transient":child.transient})
        }).collect::<Vec<_>>();
        Ok(json!({"projectId":self.0.project,"parentRunId":self.0.parent,"children":rows}))
    }

    fn wait(&self, agents: &[String], seconds: u16) -> Result<Value, String> {
        for agent in agents {
            self.latest(agent)?;
        }
        let deadline = Instant::now() + Duration::from_secs(u64::from(seconds));
        loop {
            self.0.cancel.ensure_not_cancelled()?;
            self.finish_ready()?;
            if Instant::now() >= deadline
                || agents
                    .iter()
                    .any(|agent| self.latest(agent).is_ok_and(|child| !child.state.active()))
            {
                return self.rows(Some(agents));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub(crate) fn close(&self) -> Result<(), String> {
        self.0.closed.store(true, Ordering::Release);
        for child in self.0.queue.child_records(&self.0.parent)? {
            if child.state.active() {
                self.0.queue.stop_child(&self.0.parent, &child.id)?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            self.finish_ready()?;
            if self
                .0
                .queue
                .child_records(&self.0.parent)?
                .iter()
                .all(|child| !child.state.active())
            {
                let mut state = self.state()?;
                for slot in &mut state.slots {
                    slot.workspace = None;
                }
                state.workspaces = None;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "Grok family retains scheduler ownership while child cleanup remains unproven."
                        .into(),
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub(crate) fn finish_after_parent(&self, succeeded: bool) -> Result<(), String> {
        if !succeeded || !self.0.cancel.cleanup_proven() {
            return self.close();
        }
        if self
            .0
            .queue
            .child_records(&self.0.parent)?
            .iter()
            .any(|child| child.state.active())
        {
            // The parent transport is closed and proven clean. Its family keeps
            // project ownership while the children finish in the released slot.
            if self.0.queue.yield_parent(&self.0.parent).is_err() {
                return self.close();
            }
            (self.0.wake)()?;
            let deadline = Instant::now() + Duration::from_mins(15);
            loop {
                self.finish_ready()?;
                if self
                    .0
                    .queue
                    .child_records(&self.0.parent)?
                    .iter()
                    .all(|child| !child.state.active())
                {
                    break;
                }
                if Instant::now() >= deadline {
                    self.close()?;
                    return Err("Grok child family exceeded its bounded completion time.".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        self.close()
    }
}

impl PlusCollaborationExecutor for FamilyController {
    fn binding(&self) -> &str {
        self.0.parent.as_str()
    }
    fn execute(
        &self,
        invocation: &str,
        command: PlusCollaborationCommand,
        transient: bool,
    ) -> Result<Value, String> {
        let _operation = self
            .0
            .operation
            .lock()
            .map_err(|_| "Grok family operation boundary is unavailable.")?;
        if self.0.closed.load(Ordering::Acquire) {
            return Err("Grok family is closed.".into());
        }
        self.0.cancel.ensure_not_cancelled()?;
        let identity = worktree_recovery_digest(invocation.as_bytes());
        if !transient
            && self
                .0
                .queue
                .child_records(&self.0.parent)?
                .iter()
                .any(|child| child.transient)
        {
            return Err("This family contains transient provider context; a durable parent context cannot receive those results.".into());
        }
        let fingerprint =
            worktree_recovery_digest(&serde_json::to_vec(&command).map_err(|e| e.to_string())?);
        if let Some(result) = self.state()?.journal.begin(
            &self.0.state_root,
            identity.clone(),
            fingerprint,
            transient,
        )? {
            return Ok(result);
        }
        self.0.queue.yield_parent(&self.0.parent)?;
        let wake = (self.0.wake)();
        let result = wake.and_then(|()| match command {
            PlusCollaborationCommand::Spawn { role, prompt } => self.spawn(&identity, role, &prompt, transient, None),
            PlusCollaborationCommand::Message { agent_id, message } => self.message(&identity, &agent_id, message, transient),
            PlusCollaborationCommand::Continue { agent_id, prompt } => {
                let previous = self.latest(&agent_id)?;
                if previous.state.active() { return Err("This child is active. Wait for completion before submitting its next identified continuation.".into()); }
                self.spawn(&identity, previous.role, &prompt, transient || previous.transient, Some(&previous))
            }
            PlusCollaborationCommand::Wait { agent_ids, timeout_seconds } => self.wait(&agent_ids, timeout_seconds),
            PlusCollaborationCommand::Stop { agent_id } => {
                let child = self.latest(&agent_id)?;
                if child.state.active() { self.0.queue.stop_child(&self.0.parent, &child.id)?; }
                self.rows(Some(&[agent_id]))
            }
        });
        self.0.queue.request_parent_resume(&self.0.parent)?;
        loop {
            self.0.cancel.ensure_not_cancelled()?;
            self.finish_ready()?;
            if self.0.queue.try_acquire_execution(&self.0.parent)? {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => json!({"isError":true,"error":error}),
        };
        self.state()?
            .journal
            .complete(&self.0.state_root, &identity, result.clone())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "macos"))]
pub(crate) mod live_fixture;
#[cfg(all(test, target_os = "macos"))]
pub(crate) mod live_parent;

fn child_summary(text: &str) -> String {
    let mut end = text.len().min(8192);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
