//! Durable per-project prompt queue and global run scheduler.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use grok_build_plus_host::{
    MAX_PLUS_MODEL_EXECUTIONS, PlusExecutionBook, worktree_recovery_digest,
};
use serde::{Deserialize, Serialize};

use crate::contracts::{ProjectId, QueueItemId, RunId, SessionId, SteerIntentId, WorkspaceId};
use crate::owner_state::{OwnerStateErrorKind, OwnerStateRoot};
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::types::RuntimeTransport;

pub(crate) const PLUS_QUEUE_FILE: &str = "plus-queue.json";
const PLUS_QUEUE_LOCK_FILE: &str = "plus-queue.lock";
mod cancellation;
pub(crate) mod children;
mod cli_interactions;
mod executions;
pub(crate) mod workflows;

const QUEUE_SCHEMA_VERSION: u16 = 9;
const MAX_GLOBAL_RUNS: usize = MAX_PLUS_MODEL_EXECUTIONS;
const MAX_QUEUE_ITEMS: usize = 5_000;
const MAX_RUN_RECORDS: usize = 10_000;
const MAX_STEER_RECORDS: usize = 2_000;
const MAX_QUEUE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROMPT_BYTES: usize = 12_000;
const MAX_REASON_BYTES: usize = 1_024;

const MAX_ID_BYTES: usize = 256;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
type BeforeCancelRegisterHook = (String, Box<dyn FnOnce() + Send>);
#[cfg(test)]
static BEFORE_CANCEL_REGISTER_HOOK: Mutex<Option<BeforeCancelRegisterHook>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueueItemState {
    Queued,
    Running,
    NeedsReview,
    Done,
    Failed,
    Stopped,
    Interrupted,
}

impl QueueItemState {
    const fn terminal(self) -> bool {
        matches!(
            self,
            Self::NeedsReview | Self::Done | Self::Failed | Self::Stopped | Self::Interrupted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunState {
    Running,
    StopRequested,
    NeedsReview,
    Done,
    Failed,
    Stopped,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SteerIntentState {
    Pending,
    Submitted,
    AcknowledgedByCli,
    ObservedInProviderHistory,
    Uncertain,
    /// Legacy version-five claim; migration treats this as uncertain delivery.
    Consumed,
    PromotedToNext,
    Refused,
}

impl RunState {
    const fn active(self) -> bool {
        matches!(self, Self::Running | Self::StopRequested)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QueueItem {
    pub(crate) id: QueueItemId,
    pub(crate) project_id: ProjectId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) workspace_root: String,
    pub(crate) session_id: SessionId,
    pub(crate) transport: RuntimeTransport,
    #[serde(default)]
    pub(crate) workflow: Option<workflows::WorkflowTicket>,
    pub(crate) prompt: String,
    pub(crate) auto_start: bool,
    pub(crate) state: QueueItemState,
    pub(crate) enqueued_at_unix_ms: u64,
    pub(crate) ordinal: u64,
    pub(crate) retry_of_run_id: Option<RunId>,
    #[serde(default)]
    pub(crate) predecessor_run_id: Option<RunId>,
    pub(crate) blocked_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SteerIntent {
    pub(crate) id: SteerIntentId,
    pub(crate) project_id: ProjectId,
    pub(crate) session_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) message: String,
    pub(crate) created_at_unix_ms: u64,
    #[serde(default)]
    pub(crate) ordinal: u64,
    pub(crate) state: SteerIntentState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RunRecord {
    pub(crate) id: RunId,
    pub(crate) queue_item_id: QueueItemId,
    pub(crate) project_id: ProjectId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) session_id: SessionId,
    pub(crate) transport: RuntimeTransport,
    pub(crate) state: RunState,
    pub(crate) started_at_unix_ms: u64,
    pub(crate) ended_at_unix_ms: Option<u64>,
    pub(crate) stop_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QueueBook {
    schema_version: u16,
    next_ordinal: u64,
    paused_projects: BTreeSet<ProjectId>,
    #[serde(default)]
    review_blocked_projects: BTreeSet<ProjectId>,
    #[serde(default)]
    remove_after_stop_item_ids: BTreeSet<QueueItemId>,
    #[serde(default)]
    steer_intents: Vec<SteerIntent>,
    items: Vec<QueueItem>,
    runs: Vec<RunRecord>,
    #[serde(default)]
    executions: PlusExecutionBook,
    #[serde(default)]
    children: Vec<children::ChildRecord>,
}

impl Default for QueueBook {
    fn default() -> Self {
        Self {
            schema_version: QUEUE_SCHEMA_VERSION,
            next_ordinal: 1,
            paused_projects: BTreeSet::new(),
            review_blocked_projects: BTreeSet::new(),
            remove_after_stop_item_ids: BTreeSet::new(),
            steer_intents: Vec::new(),
            items: Vec::new(),
            runs: Vec::new(),
            executions: PlusExecutionBook::default(),
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnqueueRequest {
    pub(crate) project_id: ProjectId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) workspace_root: String,
    pub(crate) session_id: SessionId,
    pub(crate) transport: RuntimeTransport,
    pub(crate) prompt: String,
    pub(crate) auto_start: bool,
    pub(crate) retry_of_run_id: Option<RunId>,
    pub(crate) predecessor_run_id: Option<RunId>,
}

#[derive(Clone, Debug)]
pub(crate) struct BegunRun {
    pub(crate) item: QueueItem,
    pub(crate) run: RunRecord,
}

#[derive(Clone, Debug)]
pub(crate) enum RunCompletion {
    NeedsReview,
    Done,
    Failed(String),
    Stopped(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueRemovalOutcome {
    Removed,
    StopRequested,
}

#[derive(Clone, Debug)]
pub(crate) struct QueueRemoval {
    pub(crate) item: QueueItem,
    pub(crate) run_id: Option<RunId>,
    pub(crate) outcome: QueueRemovalOutcome,
}

#[derive(Clone, Debug)]
pub(crate) struct PromotedSteer {
    pub(crate) intent_id: SteerIntentId,
    pub(crate) item: QueueItem,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueueView {
    pub(crate) available: bool,
    pub(crate) status: String,
    pub(crate) max_global_runs: usize,
    pub(crate) active_global_runs: usize,
    pub(crate) paused_project_ids: Vec<String>,
    pub(crate) review_blocked_project_ids: Vec<String>,
    pub(crate) items: Vec<QueueItemView>,
    pub(crate) runs: Vec<RunView>,
    pub(crate) steering: Vec<SteerIntentView>,
    pub(crate) children: Vec<children::ChildRecord>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueueItemView {
    pub(crate) id: String,
    pub(crate) project_id: String,
    pub(crate) workspace_id: String,
    pub(crate) workspace_root: String,
    pub(crate) session_id: String,
    pub(crate) transport: RuntimeTransport,
    pub(crate) workflow: Option<workflows::WorkflowTicket>,
    pub(crate) prompt: String,
    pub(crate) auto_start: bool,
    pub(crate) state: QueueItemState,
    pub(crate) enqueued_at_unix_ms: u64,
    pub(crate) ordinal: u64,
    pub(crate) retry_of_run_id: Option<String>,
    pub(crate) predecessor_run_id: Option<String>,
    pub(crate) blocked_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SteerIntentView {
    pub(crate) id: String,
    pub(crate) project_id: String,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) message: String,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) ordinal: u64,
    pub(crate) state: SteerIntentState,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunView {
    pub(crate) id: String,
    pub(crate) queue_item_id: String,
    pub(crate) project_id: String,
    pub(crate) session_id: String,
    pub(crate) transport: RuntimeTransport,
    pub(crate) state: RunState,
    pub(crate) started_at_unix_ms: u64,
    pub(crate) ended_at_unix_ms: Option<u64>,
    pub(crate) stop_reason: Option<String>,
}

#[derive(Clone)]
struct QueueStore {
    state_root: PathBuf,
}

struct QueueProcessLease {
    file: File,
}

impl Drop for QueueProcessLease {
    fn drop(&mut self) {
        // Release the advisory lock before closing the descriptor. A process
        // may fork while the app is running; an explicit unlock prevents a
        // briefly inherited descriptor from extending queue ownership after
        // the final in-process coordinator is gone.
        let _ = self.file.unlock();
    }
}

struct CoordinatorState {
    book: Result<QueueBook, String>,
    recovered_interruptions: Vec<RunRecord>,
}

#[derive(Clone)]
pub(crate) struct QueueCoordinator {
    store: QueueStore,
    state: Arc<Mutex<CoordinatorState>>,
    cancels: Arc<Mutex<HashMap<RunId, RuntimeCancelHandle>>>,
    scheduler: Arc<Mutex<()>>,
    lifecycle_suspended: Arc<AtomicBool>,
    _process_lease: Option<Arc<QueueProcessLease>>,
}

impl QueueCoordinator {
    pub(crate) fn open(state_root: PathBuf) -> Self {
        let store = QueueStore { state_root };
        let lease = store.acquire_process_lease();
        let mut recovered_interruptions = Vec::new();
        let book = lease.as_ref().map_err(Clone::clone).and_then(|_| {
            store
                .cleanup_queue_temps()
                .and_then(|()| store.load())
                .and_then(|mut book| {
                    recovered_interruptions = recover_interrupted(&mut book);
                    let finalized_removals = finalize_requested_removals(&mut book);
                    let recovered_steers = recover_terminal_steers(&mut book)?;
                    if !recovered_interruptions.is_empty() || finalized_removals || recovered_steers
                    {
                        store.save(&book)?;
                    }
                    store.cleanup_orphan_run_state()?;
                    Ok(book)
                })
        });
        Self {
            store,
            state: Arc::new(Mutex::new(CoordinatorState {
                book,
                recovered_interruptions,
            })),
            cancels: Arc::new(Mutex::new(HashMap::new())),
            scheduler: Arc::new(Mutex::new(())),
            lifecycle_suspended: Arc::new(AtomicBool::new(false)),
            _process_lease: lease.ok().map(Arc::new),
        }
    }

    pub(crate) fn lock_scheduler(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.scheduler
            .lock()
            .map_err(|_| "Queue scheduler lock is unavailable.".to_owned())
    }

    pub(crate) fn lock_idle_scheduler(&self) -> Result<MutexGuard<'_, ()>, String> {
        let guard = self.lock_scheduler()?;
        if crate::bounded_process::model_cleanup_pending() {
            return Err("A previous CLI is still stopping. Model and connection probes remain paused until cleanup is confirmed.".into());
        }
        let view = self.view();
        if !view.available
            || view.active_global_runs != 0
            || self.lifecycle_suspended.load(Ordering::Acquire)
        {
            return Err(
                "Finish or stop active runs before starting a connection or model probe.".into(),
            );
        }
        Ok(guard)
    }

    pub(crate) fn set_lifecycle_suspended(&self, suspended: bool) {
        self.lifecycle_suspended.store(suspended, Ordering::Release);
    }

    pub(crate) fn view(&self) -> QueueView {
        let Ok(state) = self.state.lock() else {
            return unavailable_view("Queue state lock is unavailable.");
        };
        let mut view = match &state.book {
            Ok(book) => queue_view(book),
            Err(reason) => unavailable_view(reason),
        };
        if view.available && crate::bounded_process::model_cleanup_pending() {
            view.status = "A previous CLI is still stopping. New model work remains queued until cleanup is confirmed.".into();
        }
        view
    }

    pub(crate) fn take_recovered_interruptions(&self) -> Result<Vec<RunRecord>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Queue state lock is unavailable.".to_owned())?;
        state.book.as_ref().map_err(Clone::clone)?;
        Ok(std::mem::take(&mut state.recovered_interruptions))
    }

    pub(crate) fn enqueue(&self, request: EnqueueRequest) -> Result<QueueItem, String> {
        validate_enqueue_request(&request)?;
        self.mutate(|book| enqueue_in_book(book, request))
    }

    pub(crate) fn enqueue_send_next(
        &self,
        mut request: EnqueueRequest,
        predecessor: &RunId,
    ) -> Result<QueueItem, String> {
        request.auto_start = true;
        request.predecessor_run_id = Some(predecessor.clone());
        validate_enqueue_request(&request)?;
        self.mutate(|book| {
            let run = book
                .runs
                .iter()
                .find(|run| &run.id == predecessor && run.state.active())
                .ok_or_else(|| {
                    "Send next refused because the selected run is no longer active.".to_owned()
                })?;
            if run.project_id != request.project_id
                || run.session_id != request.session_id
                || run.transport != request.transport
            {
                return Err("Send next refused because the active run identity changed.".into());
            }
            enqueue_in_book(book, request)
        })
    }

    pub(crate) fn enqueue_steer(
        &self,
        project: &ProjectId,
        session: &SessionId,
        run_id: &RunId,
        message: &str,
    ) -> Result<SteerIntent, String> {
        validate_prompt(message)?;
        self.mutate(|book| {
            let run = book
                .runs
                .iter()
                .find(|run| &run.id == run_id && run.state == RunState::Running)
                .ok_or_else(|| {
                    "Send now refused because the selected run is no longer active.".to_owned()
                })?;
            if &run.project_id != project || &run.session_id != session {
                return Err("Send now refused because the active run identity changed.".into());
            }
            workflows::require_chat_run(book, &run.queue_item_id)?;
            trim_steer_history(book, MAX_STEER_RECORDS.saturating_sub(1));
            if book.steer_intents.len() >= MAX_STEER_RECORDS {
                return Err(
                    "Send-now history is full; resolve or restart before steering again.".into(),
                );
            }
            if book.items.len().saturating_add(pending_steer_count(book)) >= MAX_QUEUE_ITEMS {
                return Err(
                    "Send now is full because no durable next-turn recovery slot remains.".into(),
                );
            }
            let created_at_unix_ms = unix_time_millis();
            let ordinal = book.next_ordinal;
            book.next_ordinal = book
                .next_ordinal
                .checked_add(1)
                .ok_or_else(|| "Prompt scheduling ordering exhausted.".to_owned())?;
            let id = SteerIntentId::new(new_id(
                "steer",
                &[
                    run_id.as_str(),
                    session.as_str(),
                    &ordinal.to_string(),
                    message,
                ],
            ));
            let intent = SteerIntent {
                id,
                project_id: project.clone(),
                session_id: session.clone(),
                run_id: run_id.clone(),
                message: message.to_owned(),
                created_at_unix_ms,
                ordinal,
                state: SteerIntentState::Pending,
            };
            book.steer_intents.push(intent.clone());
            Ok(intent)
        })
    }

    pub(crate) fn steer_queued_item(
        &self,
        item_id: &QueueItemId,
        project: &ProjectId,
        session: &SessionId,
        run_id: &RunId,
    ) -> Result<SteerIntent, String> {
        self.mutate(|book| {
            let run = book
                .runs
                .iter()
                .find(|run| &run.id == run_id && run.state == RunState::Running)
                .cloned()
                .ok_or_else(|| {
                    "Send now refused because the selected run is no longer active.".to_owned()
                })?;
            if &run.project_id != project || &run.session_id != session {
                return Err("Send now refused because the active run identity changed.".into());
            }

            let item_index = book
                .items
                .iter()
                .position(|item| &item.id == item_id)
                .ok_or_else(|| "The waiting message is no longer available.".to_owned())?;
            let item = book.items[item_index].clone();
            if item.state != QueueItemState::Queued {
                return Err("Send now refused because the message is no longer waiting.".into());
            }
            if item.project_id != run.project_id
                || item.workspace_id != run.workspace_id
                || item.session_id != run.session_id
                || item.transport != run.transport
            {
                return Err(
                    "Send now refused because the waiting message and run identities differ."
                        .into(),
                );
            }

            if let Some(previous_index) = book
                .steer_intents
                .iter()
                .position(|intent| intent.ordinal == item.ordinal)
            {
                let previous = &book.steer_intents[previous_index];
                if previous.state != SteerIntentState::PromotedToNext
                    || previous.project_id != item.project_id
                    || previous.session_id != item.session_id
                    || previous.message != item.prompt
                    || item.predecessor_run_id.as_ref() != Some(&previous.run_id)
                {
                    return Err(
                        "Send now refused because the message's steering history changed.".into(),
                    );
                }
                book.steer_intents.remove(previous_index);
            }
            workflows::require_chat_run(book, &run.queue_item_id)?;
            workflows::require_chat_run(book, item_id)?;
            trim_steer_history(book, MAX_STEER_RECORDS.saturating_sub(1));
            if book.steer_intents.len() >= MAX_STEER_RECORDS {
                return Err(
                    "Send-now history is full; resolve or restart before steering again.".into(),
                );
            }
            let intent = SteerIntent {
                id: SteerIntentId::new(new_id(
                    "steer",
                    &[
                        run_id.as_str(),
                        item.id.as_str(),
                        &item.ordinal.to_string(),
                        &item.prompt,
                    ],
                )),
                project_id: item.project_id.clone(),
                session_id: item.session_id.clone(),
                run_id: run_id.clone(),
                message: item.prompt.clone(),
                created_at_unix_ms: unix_time_millis(),
                ordinal: item.ordinal,
                state: SteerIntentState::Pending,
            };
            book.items.remove(item_index);
            book.steer_intents.push(intent.clone());
            Ok(intent)
        })
    }

    pub(crate) fn submit_pending_steers(&self, run_id: &RunId) -> Result<Vec<SteerIntent>, String> {
        if !self.read(|book| {
            Ok(book.steer_intents.iter().any(|intent| {
                &intent.run_id == run_id && intent.state == SteerIntentState::Pending
            }))
        })? {
            return Ok(Vec::new());
        }
        self.mutate(|book| {
            if !book
                .runs
                .iter()
                .any(|run| &run.id == run_id && run.state == RunState::Running)
            {
                return Ok(Vec::new());
            }
            let mut consumed = Vec::new();
            for intent in &mut book.steer_intents {
                if &intent.run_id == run_id && intent.state == SteerIntentState::Pending {
                    intent.state = SteerIntentState::Submitted;
                    consumed.push(intent.clone());
                }
            }
            consumed.sort_by_key(|intent| intent.ordinal);
            Ok(consumed)
        })
    }

    pub(crate) fn record_steer_delivery(
        &self,
        run_id: &RunId,
        id: &SteerIntentId,
        next: SteerIntentState,
    ) -> Result<(), String> {
        use SteerIntentState::{
            AcknowledgedByCli, ObservedInProviderHistory, Refused, Submitted, Uncertain,
        };
        self.mutate(|book| {
            let run = book
                .runs
                .iter()
                .find(|run| &run.id == run_id)
                .ok_or("Steering delivery references a missing run.")?;
            if !run.state.active() {
                return Err("Steering delivery arrived after its execution ended.".into());
            }
            let intent = book
                .steer_intents
                .iter_mut()
                .find(|intent| &intent.id == id && &intent.run_id == run_id)
                .ok_or("Steering delivery does not belong to this run.")?;
            if intent.state == next {
                return Ok(());
            }
            if !matches!(
                (intent.state, next),
                (
                    Submitted,
                    AcknowledgedByCli | ObservedInProviderHistory | Refused | Uncertain
                ) | (AcknowledgedByCli, ObservedInProviderHistory | Uncertain)
                    | (Uncertain, ObservedInProviderHistory)
            ) {
                return Err("Steering delivery would regress or invent transport evidence.".into());
            }
            intent.state = next;
            Ok(())
        })
    }

    pub(crate) fn release_held(&self, item_id: &QueueItemId) -> Result<QueueItem, String> {
        self.mutate(|book| {
            let item = book
                .items
                .iter_mut()
                .find(|item| &item.id == item_id)
                .ok_or_else(|| "The held message is no longer available.".to_owned())?;
            if item.state != QueueItemState::Queued || item.auto_start {
                return Err("Only an exact held message can be sent next.".into());
            }
            item.auto_start = true;
            if item.blocked_reason.as_deref() == Some("Held from an earlier version.") {
                item.blocked_reason = None;
            }
            Ok(item.clone())
        })
    }

    pub(crate) fn rebind_waiting_transport(
        &self,
        transport: RuntimeTransport,
    ) -> Result<usize, String> {
        self.mutate(|book| {
            let mut rebound = 0;
            for item in &mut book.items {
                if item.state != QueueItemState::Queued || item.transport == transport {
                    continue;
                }
                item.transport = transport;
                if item.auto_start {
                    item.blocked_reason = None;
                }
                rebound += 1;
            }
            Ok(rebound)
        })
    }

    pub(crate) fn candidates(
        &self,
        project: Option<&ProjectId>,
        include_manual: bool,
    ) -> Result<Vec<QueueItem>, String> {
        if self.lifecycle_suspended.load(Ordering::Acquire)
            || crate::bounded_process::model_cleanup_pending()
        {
            return Ok(Vec::new());
        }
        self.read(|book| {
            let available = MAX_GLOBAL_RUNS
                .saturating_sub(book.executions.held())
                .min(MAX_GLOBAL_RUNS.saturating_sub(active_run_count(book)));
            if available == 0 {
                return Ok(Vec::new());
            }
            let mut active_projects = active_project_ids(book);
            let mut candidates = Vec::new();
            let mut queued = book
                .items
                .iter()
                .filter(|item| item.state == QueueItemState::Queued)
                .collect::<Vec<_>>();
            queued.sort_by_key(|item| item.ordinal);
            for item in queued {
                if candidates.len() == available {
                    break;
                }
                if project.is_some_and(|project| project != &item.project_id)
                    || (!include_manual && !item.auto_start)
                    || book.paused_projects.contains(&item.project_id)
                    || book.review_blocked_projects.contains(&item.project_id)
                    || book
                        .executions
                        .first_eligible_ordinal()
                        .is_some_and(|ordinal| ordinal < item.ordinal)
                    || !active_projects.insert(item.project_id.clone())
                {
                    continue;
                }
                candidates.push(item.clone());
            }
            Ok(candidates)
        })
    }

    pub(crate) fn begin_run(
        &self,
        item_id: &QueueItemId,
        cancel: RuntimeCancelHandle,
    ) -> Result<BegunRun, String> {
        if crate::bounded_process::model_cleanup_pending() {
            return Err(
                "A previous CLI still owns cleanup resources; model execution remains paused."
                    .into(),
            );
        }
        if self.lifecycle_suspended.load(Ordering::Acquire) {
            return Err("Agent scheduling is suspended for the macOS lock transition.".into());
        }
        // Hold the cancellation registry lock across the durable Running
        // transition. Stop may observe Running only after this critical
        // section, and then blocks here until the exact handle is present.
        let mut cancels = self
            .cancels
            .lock()
            .map_err(|_| "Queue cancellation registry is unavailable.".to_owned())?;
        let begun = self.mutate(|book| {
            if active_run_count(book) >= MAX_GLOBAL_RUNS
                || book.executions.held() >= MAX_GLOBAL_RUNS
            {
                return Err("Two agent runs are already active globally.".into());
            }
            let item_index = book
                .items
                .iter()
                .position(|item| &item.id == item_id)
                .ok_or_else(|| "Queued prompt is unknown.".to_owned())?;
            let item = &book.items[item_index];
            if item.state != QueueItemState::Queued {
                return Err("Only a queued prompt can start a run.".into());
            }
            if book.paused_projects.contains(&item.project_id) {
                return Err("This project's prompt queue is paused.".into());
            }
            if book.review_blocked_projects.contains(&item.project_id) {
                return Err(
                    "This project's next run is waiting for every Agent change to be Accepted or Rejected."
                        .into(),
                );
            }
            if active_project_ids(book).contains(&item.project_id) {
                return Err("This project already has an active agent run.".into());
            }
            if book.executions.first_eligible_ordinal().is_some_and(|ordinal| ordinal < item.ordinal) {
                return Err("An earlier family continuation has the next eligible model lease.".into());
            }
            let now = unix_time_millis();
            let run_id = RunId::new(new_id(
                "run",
                &[item.id.as_str(), item.project_id.as_str(), &now.to_string()],
            ));
            let run = RunRecord {
                id: run_id,
                queue_item_id: item.id.clone(),
                project_id: item.project_id.clone(),
                workspace_id: item.workspace_id.clone(),
                session_id: item.session_id.clone(),
                transport: item.transport,
                state: RunState::Running,
                started_at_unix_ms: now,
                ended_at_unix_ms: None,
                stop_reason: None,
            };
            book.executions.admit_parent(
                run.id.clone(),
                run.project_id.clone(),
                run.workspace_id.clone(),
            )?;
            let item = &mut book.items[item_index];
            item.state = QueueItemState::Running;
            item.blocked_reason = None;
            let begun_item = item.clone();
            book.runs.push(run.clone());
            trim_terminal_history(book);
            Ok(BegunRun {
                item: begun_item,
                run,
            })
        })?;
        #[cfg(test)]
        run_before_cancel_register_hook(item_id);
        if cancels.insert(begun.run.id.clone(), cancel).is_some() {
            return Err("Agent run cancellation identity was registered twice.".into());
        }
        Ok(begun)
    }

    pub(crate) fn mark_blocked(&self, item_id: &QueueItemId, reason: &str) -> Result<(), String> {
        let reason = bounded_reason(reason)?;
        self.mutate(|book| {
            let item = book
                .items
                .iter_mut()
                .find(|item| &item.id == item_id)
                .ok_or_else(|| "Queued prompt is unknown.".to_owned())?;
            if item.state != QueueItemState::Queued {
                return Err("Only a queued prompt can carry a blocked reason.".into());
            }
            item.blocked_reason = Some(reason);
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn set_paused(&self, project: &ProjectId, paused: bool) -> Result<(), String> {
        self.mutate(|book| {
            if paused {
                book.paused_projects.insert(project.clone());
            } else {
                book.paused_projects.remove(project);
            }
            Ok(())
        })
    }

    pub(crate) fn set_review_blocked(
        &self,
        project: &ProjectId,
        blocked: bool,
    ) -> Result<(), String> {
        self.mutate(|book| {
            let blocked = blocked
                || book
                    .children
                    .iter()
                    .any(|child| &child.project == project && child.review_pending);
            if blocked {
                book.review_blocked_projects.insert(project.clone());
            } else {
                book.review_blocked_projects.remove(project);
            }
            for item in &mut book.items {
                if item.project_id == *project && item.state == QueueItemState::Queued {
                    if blocked {
                        item.blocked_reason =
                            Some("Waiting for Agent changes to be Accepted or Rejected.".into());
                    } else if item.blocked_reason.as_deref()
                        == Some("Waiting for Agent changes to be Accepted or Rejected.")
                    {
                        item.blocked_reason = None;
                    }
                }
            }
            Ok(())
        })
    }

    pub(crate) fn reconcile_review_blocks(
        &self,
        projects: BTreeSet<ProjectId>,
    ) -> Result<(), String> {
        self.mutate(|book| {
            book.review_blocked_projects = projects;
            book.review_blocked_projects.extend(
                book.children
                    .iter()
                    .filter(|child| child.review_pending)
                    .map(|child| child.project.clone()),
            );
            for item in &mut book.items {
                if item.state != QueueItemState::Queued {
                    continue;
                }
                if book.review_blocked_projects.contains(&item.project_id) {
                    item.blocked_reason =
                        Some("Waiting for Agent changes to be Accepted or Rejected.".into());
                } else if item.blocked_reason.as_deref()
                    == Some("Waiting for Agent changes to be Accepted or Rejected.")
                {
                    item.blocked_reason = None;
                }
            }
            Ok(())
        })
    }

    pub(crate) fn request_stop(&self, project: &ProjectId) -> Result<RunId, String> {
        let run_id = self.mutate(|book| {
            let run = book
                .runs
                .iter_mut()
                .find(|run| {
                    &run.project_id == project
                        && matches!(run.state, RunState::Running | RunState::StopRequested)
                })
                .ok_or_else(|| "This project has no running agent run to stop.".to_owned())?;
            if run.state == RunState::Running {
                run.state = RunState::StopRequested;
            }
            Ok(run.id.clone())
        })?;
        self.cancel_run_ids(std::slice::from_ref(&run_id))?;
        Ok(run_id)
    }

    pub(crate) fn request_stop_all(&self) -> Result<Vec<RunId>, String> {
        let run_ids = self.persist_stop_all_intents()?;
        self.cancel_run_ids(&run_ids)?;
        Ok(run_ids)
    }

    pub(crate) fn persist_stop_all_intents(&self) -> Result<Vec<RunId>, String> {
        self.mutate(|book| {
            let mut run_ids = Vec::new();
            for run in &mut book.runs {
                if run.state == RunState::Running {
                    run.state = RunState::StopRequested;
                    run_ids.push(run.id.clone());
                } else if run.state == RunState::StopRequested {
                    run_ids.push(run.id.clone());
                }
            }
            Ok(run_ids)
        })
    }

    pub(crate) fn complete_run(
        &self,
        run_id: &RunId,
        completion: RunCompletion,
    ) -> Result<Vec<PromotedSteer>, String> {
        let mut cancels = self
            .cancels
            .lock()
            .map_err(|_| "Queue cleanup registry is unavailable.")?;
        if !cancels
            .get(run_id)
            .is_some_and(RuntimeCancelHandle::cleanup_proven)
        {
            return Err(
                "The run retains its scheduler reservation until CLI cleanup is proven.".into(),
            );
        }
        let promoted = self.mutate(|book| {
            let run_index = book
                .runs
                .iter()
                .position(|run| &run.id == run_id)
                .ok_or_else(|| "Agent run is unknown.".to_owned())?;
            if !book.runs[run_index].state.active() {
                return Err("Agent run already has a terminal outcome.".into());
            }
            book.executions.finish(run_id, true)?;
            let item_id = book.runs[run_index].queue_item_id.clone();
            let project_id = book.runs[run_index].project_id.clone();
            let child_review = book
                .children
                .iter()
                .any(|child| child.parent == *run_id && child.review_pending);
            if child_review {
                book.review_blocked_projects.insert(project_id.clone());
            }
            let completion = if child_review && matches!(completion, RunCompletion::Done) {
                RunCompletion::NeedsReview
            } else {
                completion
            };
            let item = book
                .items
                .iter_mut()
                .find(|item| item.id == item_id)
                .ok_or_else(|| "Agent run's queued prompt is missing.".to_owned())?;
            let (item_state, run_state, reason) = match completion {
                RunCompletion::NeedsReview => {
                    book.review_blocked_projects.insert(project_id);
                    (QueueItemState::NeedsReview, RunState::NeedsReview, None)
                }
                RunCompletion::Done => (QueueItemState::Done, RunState::Done, None),
                RunCompletion::Failed(reason) => (
                    QueueItemState::Failed,
                    RunState::Failed,
                    Some(bounded_reason(&reason)?),
                ),
                RunCompletion::Stopped(reason) => (
                    QueueItemState::Stopped,
                    RunState::Stopped,
                    Some(bounded_reason(&reason)?),
                ),
            };
            item.state = item_state;
            item.blocked_reason = None;
            let run = &mut book.runs[run_index];
            run.state = run_state;
            run.ended_at_unix_ms = Some(unix_time_millis());
            run.stop_reason = reason;
            let promoted = promote_pending_steers_in_book(book, run_id)?;
            if book.remove_after_stop_item_ids.remove(&item_id) && !child_review {
                book.items.retain(|item| item.id != item_id);
                book.runs.retain(|run| run.queue_item_id != item_id);
            }
            Ok(promoted)
        })?;
        cancels.remove(run_id);
        Ok(promoted)
    }

    pub(crate) fn run_cleanup_proven(&self, run_id: &RunId) -> bool {
        self.cancels.lock().is_ok_and(|cancels| {
            cancels
                .get(run_id)
                .is_some_and(RuntimeCancelHandle::cleanup_proven)
        })
    }

    pub(crate) fn retry(&self, run_id: &RunId) -> Result<QueueItem, String> {
        let request = self.read(|book| {
            let run = book
                .runs
                .iter()
                .find(|run| &run.id == run_id)
                .ok_or_else(|| "Agent run is unknown.".to_owned())?;
            if !matches!(
                run.state,
                RunState::Failed | RunState::Stopped | RunState::Interrupted
            ) {
                return Err("Only a Failed, Stopped, or Interrupted run can be retried.".into());
            }
            let item = book
                .items
                .iter()
                .find(|item| item.id == run.queue_item_id)
                .ok_or_else(|| "Agent run's queued prompt is missing.".to_owned())?;
            if item.workflow.is_some() {
                return Err("Use the workflow's explicit Resume control; a workflow cannot retry as a chat prompt.".into());
            }
            Ok(EnqueueRequest {
                project_id: item.project_id.clone(),
                workspace_id: item.workspace_id.clone(),
                workspace_root: item.workspace_root.clone(),
                session_id: item.session_id.clone(),
                transport: item.transport,
                prompt: item.prompt.clone(),
                auto_start: true,
                retry_of_run_id: Some(run.id.clone()),
                predecessor_run_id: None,
            })
        })?;
        self.enqueue(request)
    }

    pub(crate) fn remove_item(&self, item_id: &QueueItemId) -> Result<QueueRemoval, String> {
        let removal = self.mutate(|book| {
            if book.children.iter().any(|child| {
                child.review_pending
                    && book.runs.iter().any(|run| {
                        run.id == child.parent
                            && &run.queue_item_id == item_id
                            && !run.state.active()
                    })
            }) {
                return Err(
                    "Review or discard this task's child changes before removing its history."
                        .into(),
                );
            }
            let item_index = book
                .items
                .iter()
                .position(|item| &item.id == item_id)
                .ok_or_else(|| "Task is no longer retained in the durable queue.".to_owned())?;
            let item = book.items[item_index].clone();
            let run_index = book
                .runs
                .iter()
                .position(|run| run.queue_item_id == item.id);

            if item.state == QueueItemState::Running {
                let run_index = run_index.ok_or_else(|| {
                    "Running task removal refused because its exact run record is missing."
                        .to_owned()
                })?;
                let run = &mut book.runs[run_index];
                if !run.state.active() {
                    return Err(
                        "Running task removal refused because its run is already terminal.".into(),
                    );
                }
                run.state = RunState::StopRequested;
                book.remove_after_stop_item_ids.insert(item.id.clone());
                return Ok(QueueRemoval {
                    item,
                    run_id: Some(run.id.clone()),
                    outcome: QueueRemovalOutcome::StopRequested,
                });
            }

            let run_id = run_index.map(|index| book.runs[index].id.clone());
            book.items.remove(item_index);
            book.runs.retain(|run| run.queue_item_id != item.id);
            book.remove_after_stop_item_ids.remove(&item.id);
            Ok(QueueRemoval {
                item,
                run_id,
                outcome: QueueRemovalOutcome::Removed,
            })
        })?;

        if removal.outcome == QueueRemovalOutcome::StopRequested {
            let run_id = removal.run_id.as_ref().ok_or_else(|| {
                "Running task removal lost its exact cancellation identity.".to_owned()
            })?;
            let cancel = self
                .cancels
                .lock()
                .map_err(|_| "Queue cancellation registry is unavailable.".to_owned())?
                .get(run_id)
                .cloned()
                .ok_or_else(|| {
                    "Running task removal is durable, but its cancellation handle is unavailable."
                        .to_owned()
                })?;
            if !cancel.cancelled() {
                cancel.request_cancel()?;
            }
        }
        Ok(removal)
    }

    pub(crate) fn is_stop_requested(&self, run_id: &RunId) -> bool {
        self.read(|book| {
            Ok(book
                .runs
                .iter()
                .find(|run| &run.id == run_id)
                .is_some_and(|run| run.state == RunState::StopRequested))
        })
        .unwrap_or(false)
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&QueueBook) -> Result<T, String>,
    ) -> Result<T, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Queue state lock is unavailable.".to_owned())?;
        let book = state.book.as_ref().map_err(Clone::clone)?;
        operation(book)
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut QueueBook) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Queue state lock is unavailable.".to_owned())?;
        let book = state.book.as_mut().map_err(|reason| reason.clone())?;
        let before = book.clone();
        let result = match operation(book) {
            Ok(result) => result,
            Err(error) => {
                *book = before;
                return Err(error);
            }
        };
        // Child histories have the same retention lifetime as their parent row.
        book.children
            .retain(|child| book.runs.iter().any(|run| run.id == child.parent));
        if let Err(error) = validate_book(book).and_then(|()| self.store.save(book)) {
            *book = before;
            return Err(error);
        }
        Ok(result)
    }
}

#[cfg(test)]
fn run_before_cancel_register_hook(item_id: &QueueItemId) {
    let hook = BEFORE_CANCEL_REGISTER_HOOK
        .lock()
        .expect("queue test hook lock")
        .take();
    if let Some((expected_item, hook)) = hook {
        if expected_item == item_id.as_str() {
            hook();
        } else {
            *BEFORE_CANCEL_REGISTER_HOOK
                .lock()
                .expect("restore queue test hook") = Some((expected_item, hook));
        }
    }
}

impl QueueStore {
    fn validate_state_root(&self) -> Result<(), String> {
        let metadata = match fs::symlink_metadata(&self.state_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("Cannot inspect queue state root: {error}")),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Queue state root is not an owner directory.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("Queue state root permissions are not owner-only.".into());
            }
        }
        Ok(())
    }

    fn acquire_process_lease(&self) -> Result<QueueProcessLease, String> {
        self.validate_state_root()?;
        let file = OwnerStateRoot::new(&self.state_root)
            .file(PLUS_QUEUE_LOCK_FILE, 0)
            .and_then(|file| file.open_process_file())
            .map_err(|error| match error.kind {
                OwnerStateErrorKind::Type => "Queue process lease is not a regular file.".into(),
                OwnerStateErrorKind::Owner => {
                    "Queue process lease permissions are not owner-only.".into()
                }
                _ => format!("Cannot open queue process lease: {error}"),
            })?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => {
                "Prompt queue is already owned by another GB Plus process; this app instance cannot start or recover agent runs."
                    .to_owned()
            }
            std::fs::TryLockError::Error(error) => {
                format!("Cannot acquire queue process lease: {error}")
            }
        })?;
        Ok(QueueProcessLease { file })
    }

    fn cleanup_queue_temps(&self) -> Result<(), String> {
        let entries = match fs::read_dir(&self.state_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("Cannot list queue state root: {error}")),
        };
        for entry in entries {
            let entry = entry.map_err(|error| format!("Cannot read queue temp entry: {error}"))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".tmp") else {
                continue;
            };
            if !stem.starts_with(&format!(".{PLUS_QUEUE_FILE}.")) {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("Cannot inspect stale queue temp: {error}"))?;
            if metadata.file_type().is_symlink() || metadata.is_file() {
                fs::remove_file(&path)
                    .map_err(|error| format!("Cannot remove stale queue temp: {error}"))?;
            } else {
                return Err("Stale queue temp path is not a regular file.".into());
            }
        }
        sync_directory(&self.state_root)
            .map_err(|error| format!("Cannot sync stale queue temp cleanup: {error}"))
    }

    fn load(&self) -> Result<QueueBook, String> {
        let file = OwnerStateRoot::new(&self.state_root)
            .file(PLUS_QUEUE_FILE, MAX_QUEUE_BYTES)
            .map_err(|error| format!("Cannot inspect {PLUS_QUEUE_FILE}: {error}"))?;
        let Some(bytes) = file.read().map_err(|error| match error.kind {
            OwnerStateErrorKind::Type => {
                format!("{PLUS_QUEUE_FILE} is not a regular owner file.")
            }
            OwnerStateErrorKind::Owner => {
                format!("{PLUS_QUEUE_FILE} permissions are not owner-only.")
            }
            OwnerStateErrorKind::Oversized => {
                format!("{PLUS_QUEUE_FILE} exceeded {MAX_QUEUE_BYTES} bytes.")
            }
            OwnerStateErrorKind::Read => format!("Cannot read {PLUS_QUEUE_FILE}: {error}"),
            _ => format!("Cannot inspect {PLUS_QUEUE_FILE}: {error}"),
        })?
        else {
            return Ok(QueueBook::default());
        };
        let mut book: QueueBook = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{PLUS_QUEUE_FILE} is not valid schema JSON: {error}"))?;
        let previous_schema = book.schema_version;
        let migrated = matches!(previous_schema, 1..=8);
        if previous_schema <= 7 && !book.children.is_empty() {
            return Err("Legacy queue data cannot contain newer child authority.".into());
        }
        if migrated && book.items.iter().any(|item| item.workflow.is_some()) {
            return Err("Legacy queue data cannot contain newer workflow authority.".into());
        }
        match book.schema_version {
            1..=3 => {
                let paused = book.paused_projects.clone();
                for item in &mut book.items {
                    if item.state == QueueItemState::Queued
                        && (!item.auto_start || paused.contains(&item.project_id))
                    {
                        item.auto_start = false;
                        item.blocked_reason = Some("Held from an earlier version.".into());
                    }
                }
                book.paused_projects.clear();
                book.schema_version = QUEUE_SCHEMA_VERSION;
            }
            4 => {
                if !book.steer_intents.is_empty() {
                    return Err(
                        "plus-queue.json schema 4 steering lacks a shared durable order; automatic migration is refused."
                            .into(),
                    );
                }
                book.schema_version = QUEUE_SCHEMA_VERSION;
            }
            5 => {
                for intent in &mut book.steer_intents {
                    if intent.state == SteerIntentState::Consumed {
                        intent.state = SteerIntentState::Uncertain;
                    }
                }
                book.schema_version = QUEUE_SCHEMA_VERSION;
            }
            _ => {}
        }
        if matches!(previous_schema, 1..=6) {
            executions::migrate_legacy(&mut book)?;
        } else if previous_schema == 7 {
            if book
                .executions
                .members()
                .any(|member| member.role.is_some())
            {
                return Err("Version-seven child execution lacks an admitted journal.".into());
            }
            book.schema_version = QUEUE_SCHEMA_VERSION;
        } else if previous_schema == 8 {
            book.schema_version = QUEUE_SCHEMA_VERSION;
        }
        validate_book(&book)?;
        if migrated {
            if previous_schema < 6 {
                self.preserve_migration_backup("plus-queue.before-v6.json", &bytes)?;
            }
            if previous_schema < 7 {
                self.preserve_migration_backup("plus-queue.before-v7.json", &bytes)?;
            }
            if previous_schema < 8 {
                self.preserve_migration_backup("plus-queue.before-v8.json", &bytes)?;
            }
            self.preserve_migration_backup("plus-queue.before-v9.json", &bytes)?;
            self.save(&book)?;
        }
        Ok(book)
    }

    fn save(&self, book: &QueueBook) -> Result<(), String> {
        validate_book(book)?;
        let mut bytes = serde_json::to_vec_pretty(book)
            .map_err(|error| format!("Cannot encode {PLUS_QUEUE_FILE}: {error}"))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_QUEUE_BYTES {
            return Err(format!(
                "{PLUS_QUEUE_FILE} exceeded {MAX_QUEUE_BYTES} bytes."
            ));
        }
        OwnerStateRoot::new(&self.state_root)
            .file(PLUS_QUEUE_FILE, MAX_QUEUE_BYTES)
            .and_then(|file| file.replace(&bytes))
            .map_err(|error| format!("Cannot atomically save {PLUS_QUEUE_FILE}: {error}"))
    }

    fn cleanup_orphan_run_state(&self) -> Result<(), String> {
        let root = self.state_root.join("queue-run-state");
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("Cannot inspect orphan queue run state: {error}")),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Orphan queue run-state root is not an app-owned directory.".into());
        }
        for entry in fs::read_dir(&root)
            .map_err(|error| format!("Cannot list orphan queue run state: {error}"))?
        {
            let entry = entry.map_err(|error| format!("Cannot read orphan run entry: {error}"))?;
            let name = entry.file_name();
            let valid_name = name.to_str().is_some_and(|name| {
                name.len() == 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
            if !valid_name {
                return Err("Orphan queue run-state root contains an unexpected identity.".into());
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("Cannot inspect orphan queue run entry: {error}"))?;
            if metadata.file_type().is_symlink() || metadata.is_file() {
                fs::remove_file(&path)
                    .map_err(|error| format!("Cannot remove orphan queue run file: {error}"))?;
            } else if metadata.is_dir() {
                fs::remove_dir_all(&path).map_err(|error| {
                    format!("Cannot remove orphan queue run directory: {error}")
                })?;
            } else {
                return Err("Orphan queue run state contains a special file.".into());
            }
        }
        sync_directory(&root)
            .map_err(|error| format!("Cannot sync orphan queue run-state cleanup: {error}"))
    }
}

fn enqueue_in_book(book: &mut QueueBook, request: EnqueueRequest) -> Result<QueueItem, String> {
    validate_enqueue_request(&request)?;
    if book.items.len().saturating_add(pending_steer_count(book)) >= MAX_QUEUE_ITEMS {
        return Err(format!(
            "Prompt scheduling is full at {MAX_QUEUE_ITEMS} retained or recovery-reserved items."
        ));
    }
    let ordinal = book.next_ordinal;
    book.next_ordinal = book
        .next_ordinal
        .checked_add(1)
        .ok_or_else(|| "Prompt queue ordering exhausted.".to_owned())?;
    let id = QueueItemId::new(new_id(
        "queue",
        &[
            request.project_id.as_str(),
            request.session_id.as_str(),
            &ordinal.to_string(),
            &request.prompt,
        ],
    ));
    let item = QueueItem {
        id,
        project_id: request.project_id,
        workspace_id: request.workspace_id,
        workspace_root: request.workspace_root,
        session_id: request.session_id,
        transport: request.transport,
        workflow: None,
        prompt: request.prompt,
        auto_start: request.auto_start,
        state: QueueItemState::Queued,
        enqueued_at_unix_ms: unix_time_millis(),
        ordinal,
        retry_of_run_id: request.retry_of_run_id,
        predecessor_run_id: request.predecessor_run_id,
        blocked_reason: None,
    };
    book.items.push(item.clone());
    Ok(item)
}

fn enqueue_promoted_steer_in_book(
    book: &mut QueueBook,
    source: &QueueItem,
    intent: &SteerIntent,
    predecessor: &RunId,
) -> Result<QueueItem, String> {
    if book.items.len().saturating_add(pending_steer_count(book)) >= MAX_QUEUE_ITEMS {
        return Err(format!(
            "Prompt scheduling is full at {MAX_QUEUE_ITEMS} retained or recovery-reserved items."
        ));
    }
    if book.items.iter().any(|item| item.ordinal == intent.ordinal) {
        return Err("Send-now promotion found a conflicting durable order.".into());
    }
    let item = QueueItem {
        id: QueueItemId::new(new_id(
            "queue",
            &[
                intent.project_id.as_str(),
                intent.session_id.as_str(),
                &intent.ordinal.to_string(),
                &intent.message,
            ],
        )),
        project_id: intent.project_id.clone(),
        workspace_id: source.workspace_id.clone(),
        workspace_root: source.workspace_root.clone(),
        session_id: intent.session_id.clone(),
        transport: source.transport,
        workflow: None,
        prompt: intent.message.clone(),
        auto_start: true,
        state: QueueItemState::Queued,
        enqueued_at_unix_ms: intent.created_at_unix_ms,
        ordinal: intent.ordinal,
        retry_of_run_id: None,
        predecessor_run_id: Some(predecessor.clone()),
        blocked_reason: None,
    };
    book.items.push(item.clone());
    Ok(item)
}

fn validate_enqueue_request(request: &EnqueueRequest) -> Result<(), String> {
    validate_id(request.project_id.as_str(), "project")?;
    validate_id(request.workspace_id.as_str(), "workspace")?;
    validate_id(request.session_id.as_str(), "session")?;
    validate_workspace_root(&request.workspace_root)?;
    validate_prompt(&request.prompt)?;
    if let Some(run_id) = &request.retry_of_run_id {
        validate_id(run_id.as_str(), "retry run")?;
    }
    if let Some(run_id) = &request.predecessor_run_id {
        validate_id(run_id.as_str(), "predecessor run")?;
    }
    Ok(())
}

fn validate_book(book: &QueueBook) -> Result<(), String> {
    if book.schema_version != QUEUE_SCHEMA_VERSION {
        return Err(format!(
            "{PLUS_QUEUE_FILE} schema {} is not supported; expected {QUEUE_SCHEMA_VERSION}.",
            book.schema_version
        ));
    }
    if book.next_ordinal == 0
        || book.items.len() > MAX_QUEUE_ITEMS
        || book.runs.len() > MAX_RUN_RECORDS
        || book.steer_intents.len() > MAX_STEER_RECORDS
        || book.items.len().saturating_add(pending_steer_count(book)) > MAX_QUEUE_ITEMS
    {
        return Err(format!(
            "{PLUS_QUEUE_FILE} violates its bounded record counts."
        ));
    }
    validate_items(book)?;
    let item_runs = validate_runs(book)?;
    children::validate(book)?;
    executions::validate_bindings(book)?;
    for item in &book.items {
        let expected_run_state = match item.state {
            QueueItemState::Queued => None,
            QueueItemState::Running => Some(RunState::Running),
            QueueItemState::NeedsReview => Some(RunState::NeedsReview),
            QueueItemState::Done => Some(RunState::Done),
            QueueItemState::Failed => Some(RunState::Failed),
            QueueItemState::Stopped => Some(RunState::Stopped),
            QueueItemState::Interrupted => Some(RunState::Interrupted),
        };
        let actual = item_runs.get(&item.id).copied();
        let matches = matches!(
            (expected_run_state, actual),
            (None, None)
                | (
                    Some(RunState::Running),
                    Some(RunState::Running | RunState::StopRequested)
                )
                | (Some(RunState::NeedsReview), Some(RunState::NeedsReview))
                | (Some(RunState::Done), Some(RunState::Done))
                | (Some(RunState::Failed), Some(RunState::Failed))
                | (Some(RunState::Stopped), Some(RunState::Stopped))
                | (Some(RunState::Interrupted), Some(RunState::Interrupted))
        );
        if !matches {
            return Err("Queue item state does not match its exact run record.".into());
        }
    }
    Ok(())
}

fn validate_items(book: &QueueBook) -> Result<(), String> {
    let mut item_ids = HashSet::new();
    let mut ordinals = HashSet::new();
    let mut workflow_tickets = HashSet::new();
    for item in &book.items {
        if let Some(ticket) = &item.workflow {
            ticket.validate()?;
            if !workflow_tickets.insert((&ticket.job_id, ticket.attempt))
                || item.retry_of_run_id.is_some()
                || item.predecessor_run_id.is_some()
            {
                return Err(
                    "Workflow tickets cannot duplicate or inherit chat retry/steering authority."
                        .into(),
                );
            }
        }
        validate_id(item.id.as_str(), "queue item")?;
        validate_id(item.project_id.as_str(), "project")?;
        validate_id(item.workspace_id.as_str(), "workspace")?;
        validate_id(item.session_id.as_str(), "session")?;
        validate_workspace_root(&item.workspace_root)?;
        validate_prompt(&item.prompt)?;
        if item.enqueued_at_unix_ms == 0
            || item.ordinal == 0
            || !item_ids.insert(item.id.clone())
            || !ordinals.insert(item.ordinal)
        {
            return Err(format!(
                "{PLUS_QUEUE_FILE} contains a duplicate or invalid queue identity."
            ));
        }
        if let Some(reason) = &item.blocked_reason {
            bounded_reason(reason)?;
            if item.state != QueueItemState::Queued {
                return Err("Only queued work may retain a blocked reason.".into());
            }
        }
        if let Some(run_id) = &item.retry_of_run_id {
            validate_id(run_id.as_str(), "retry run")?;
        }
        if let Some(run_id) = &item.predecessor_run_id {
            validate_id(run_id.as_str(), "predecessor run")?;
        }
    }
    for project in &book.paused_projects {
        validate_id(project.as_str(), "paused project")?;
    }
    for project in &book.review_blocked_projects {
        validate_id(project.as_str(), "review-blocked project")?;
    }
    for item_id in &book.remove_after_stop_item_ids {
        validate_id(item_id.as_str(), "remove-after-stop item")?;
        let item = book
            .items
            .iter()
            .find(|item| &item.id == item_id)
            .ok_or_else(|| "Remove-after-stop intent references a missing task.".to_owned())?;
        let run = book
            .runs
            .iter()
            .find(|run| &run.queue_item_id == item_id)
            .ok_or_else(|| "Remove-after-stop intent references a missing run.".to_owned())?;
        if item.state != QueueItemState::Running || run.state != RunState::StopRequested {
            return Err("Remove-after-stop intent is not bound to one stopping run.".into());
        }
    }
    validate_steering(book)
}

fn validate_steering(book: &QueueBook) -> Result<(), String> {
    let mut steer_ids = HashSet::new();
    let mut steer_ordinals = HashSet::new();
    for intent in &book.steer_intents {
        validate_id(intent.id.as_str(), "steer intent")?;
        validate_id(intent.project_id.as_str(), "steer project")?;
        validate_id(intent.session_id.as_str(), "steer session")?;
        validate_id(intent.run_id.as_str(), "steer run")?;
        validate_prompt(&intent.message)?;
        if intent.created_at_unix_ms == 0
            || intent.ordinal == 0
            || intent.ordinal >= book.next_ordinal
            || !steer_ids.insert(intent.id.clone())
            || !steer_ordinals.insert(intent.ordinal)
        {
            return Err("Steering contains a duplicate or invalid identity.".into());
        }
        let run = book
            .runs
            .iter()
            .find(|run| run.id == intent.run_id)
            .ok_or_else(|| "Steering references a missing run.".to_owned())?;
        if run.project_id != intent.project_id || run.session_id != intent.session_id {
            return Err("Steering identity does not match its exact run.".into());
        }
        if intent.state == SteerIntentState::Pending && !run.state.active() {
            return Err("Pending steering is not bound to an active run.".into());
        }
        match book
            .items
            .iter()
            .find(|item| item.ordinal == intent.ordinal)
        {
            Some(item)
                if intent.state != SteerIntentState::PromotedToNext
                    || item.project_id != intent.project_id
                    || item.session_id != intent.session_id
                    || item.prompt != intent.message
                    || item.predecessor_run_id.as_ref() != Some(&intent.run_id) =>
            {
                return Err("Steering durable order crosses an unrelated queue item.".into());
            }
            _ => {}
        }
    }
    if book
        .items
        .iter()
        .map(|item| item.ordinal)
        .chain(book.steer_intents.iter().map(|intent| intent.ordinal))
        .max()
        .is_some_and(|maximum| maximum >= book.next_ordinal)
    {
        return Err("Queue next ordinal does not advance past retained work.".into());
    }
    Ok(())
}

fn validate_runs(book: &QueueBook) -> Result<HashMap<QueueItemId, RunState>, String> {
    let mut run_ids = HashSet::new();
    let mut active_projects = HashSet::new();
    let mut item_runs = HashMap::new();
    for run in &book.runs {
        validate_id(run.id.as_str(), "run")?;
        validate_id(run.queue_item_id.as_str(), "run queue item")?;
        validate_id(run.project_id.as_str(), "run project")?;
        validate_id(run.workspace_id.as_str(), "run workspace")?;
        validate_id(run.session_id.as_str(), "run session")?;
        if run.started_at_unix_ms == 0
            || !run_ids.insert(run.id.clone())
            || item_runs
                .insert(run.queue_item_id.clone(), run.state)
                .is_some()
        {
            return Err(format!(
                "{PLUS_QUEUE_FILE} contains a duplicate or invalid run identity."
            ));
        }
        let item = book
            .items
            .iter()
            .find(|item| item.id == run.queue_item_id)
            .ok_or_else(|| "Run record references a missing queue item.".to_owned())?;
        if item.project_id != run.project_id
            || item.workspace_id != run.workspace_id
            || item.session_id != run.session_id
            || item.transport != run.transport
        {
            return Err("Run record identity does not match its queued prompt.".into());
        }
        if run.state.active() {
            if run.ended_at_unix_ms.is_some()
                || run.stop_reason.is_some()
                || item.state != QueueItemState::Running
                || !active_projects.insert(run.project_id.clone())
            {
                return Err("Active run violates project/item serialization.".into());
            }
        } else if run.ended_at_unix_ms.is_none() {
            return Err("Terminal run is missing its end timestamp.".into());
        }
    }
    if active_projects.len() > MAX_GLOBAL_RUNS {
        return Err("Persisted queue exceeds two global active runs.".into());
    }
    Ok(item_runs)
}

fn recover_interrupted(book: &mut QueueBook) -> Vec<RunRecord> {
    let _ = book.executions.recover_interrupted();
    let now = unix_time_millis();
    for child in &mut book.children {
        if child.state.active() {
            child.state = children::ChildState::Interrupted;
            child.ended_at_unix_ms = Some(now);
        }
        if child.review_pending {
            book.review_blocked_projects.insert(child.project.clone());
        }
    }
    let mut recovered = Vec::new();
    let mut interrupted_items = HashSet::new();
    for run in &mut book.runs {
        if run.state.active() {
            run.state = RunState::Interrupted;
            run.ended_at_unix_ms = Some(now);
            run.stop_reason =
                Some("App restarted before the run reached a terminal outcome.".into());
            interrupted_items.insert(run.queue_item_id.clone());
            recovered.push(run.clone());
        }
    }
    for item in &mut book.items {
        if item.state == QueueItemState::Running || interrupted_items.contains(&item.id) {
            item.state = QueueItemState::Interrupted;
            item.blocked_reason = None;
        }
    }
    recovered
}

fn promote_pending_steers_in_book(
    book: &mut QueueBook,
    run_id: &RunId,
) -> Result<Vec<PromotedSteer>, String> {
    for intent in &mut book.steer_intents {
        if &intent.run_id == run_id
            && matches!(
                intent.state,
                SteerIntentState::Submitted
                    | SteerIntentState::AcknowledgedByCli
                    | SteerIntentState::Consumed
            )
        {
            intent.state = SteerIntentState::Uncertain;
        }
    }
    let run = book
        .runs
        .iter()
        .find(|run| &run.id == run_id)
        .cloned()
        .ok_or_else(|| "Send-now recovery cannot find its exact run.".to_owned())?;
    let source = book
        .items
        .iter()
        .find(|item| item.id == run.queue_item_id)
        .cloned()
        .ok_or_else(|| "Send-now recovery cannot find its exact queued prompt.".to_owned())?;
    let pending = book
        .steer_intents
        .iter()
        .filter(|intent| &intent.run_id == run_id && intent.state == SteerIntentState::Pending)
        .cloned()
        .collect::<Vec<_>>();
    let mut promoted = Vec::new();
    for intent in pending {
        let stored = book
            .steer_intents
            .iter_mut()
            .find(|candidate| candidate.id == intent.id)
            .ok_or_else(|| "Send-now recovery lost its exact intent.".to_owned())?;
        stored.state = SteerIntentState::PromotedToNext;
        let item = enqueue_promoted_steer_in_book(book, &source, &intent, run_id)?;
        promoted.push(PromotedSteer {
            intent_id: intent.id,
            item,
        });
    }
    trim_steer_history(book, MAX_STEER_RECORDS);
    Ok(promoted)
}

fn recover_terminal_steers(book: &mut QueueBook) -> Result<bool, String> {
    let terminal_runs = book
        .steer_intents
        .iter()
        .filter(|intent| {
            matches!(
                intent.state,
                SteerIntentState::Pending
                    | SteerIntentState::Submitted
                    | SteerIntentState::AcknowledgedByCli
                    | SteerIntentState::Consumed
            )
        })
        .filter_map(|intent| {
            book.runs
                .iter()
                .find(|run| run.id == intent.run_id && !run.state.active())
                .map(|run| run.id.clone())
        })
        .collect::<BTreeSet<_>>();
    let changed = !terminal_runs.is_empty();
    for run_id in terminal_runs {
        let _ = promote_pending_steers_in_book(book, &run_id)?;
    }
    Ok(changed)
}

fn pending_steer_count(book: &QueueBook) -> usize {
    book.steer_intents
        .iter()
        .filter(|intent| intent.state == SteerIntentState::Pending)
        .count()
}

fn trim_steer_history(book: &mut QueueBook, target_len: usize) {
    if book.steer_intents.len() <= target_len {
        return;
    }
    let removable = book.steer_intents.len() - target_len;
    let remove_ids = book
        .steer_intents
        .iter()
        .filter(|intent| {
            matches!(
                intent.state,
                SteerIntentState::ObservedInProviderHistory
                    | SteerIntentState::PromotedToNext
                    | SteerIntentState::Refused
            )
        })
        .take(removable)
        .map(|intent| intent.id.clone())
        .collect::<HashSet<_>>();
    book.steer_intents
        .retain(|intent| !remove_ids.contains(&intent.id));
}

fn finalize_requested_removals(book: &mut QueueBook) -> bool {
    if book.remove_after_stop_item_ids.is_empty() {
        return false;
    }
    let remove = std::mem::take(&mut book.remove_after_stop_item_ids);
    let remove = remove
        .into_iter()
        .filter(|item| {
            !book.children.iter().any(|child| {
                child.review_pending
                    && book
                        .runs
                        .iter()
                        .any(|run| run.id == child.parent && &run.queue_item_id == item)
            })
        })
        .collect::<BTreeSet<_>>();
    book.items.retain(|item| !remove.contains(&item.id));
    book.runs.retain(|run| !remove.contains(&run.queue_item_id));
    book.children
        .retain(|child| book.runs.iter().any(|run| run.id == child.parent));
    true
}

fn queue_view(book: &QueueBook) -> QueueView {
    let queued_count = book
        .items
        .iter()
        .filter(|item| item.state == QueueItemState::Queued)
        .count();
    let visible_item_ids = book
        .items
        .iter()
        .rev()
        .take(200)
        .map(|item| item.id.clone())
        .chain(
            book.runs
                .iter()
                .filter(|run| run.state.active())
                .map(|run| run.queue_item_id.clone()),
        )
        .collect::<HashSet<_>>();
    QueueView {
        available: true,
        children: book.children.clone(),
        status: if queued_count > 0 {
            format!("{queued_count} queued")
        } else {
            "Queue empty".into()
        },
        max_global_runs: MAX_GLOBAL_RUNS,
        active_global_runs: active_run_count(book),
        paused_project_ids: book
            .paused_projects
            .iter()
            .map(|project| project.as_str().to_owned())
            .collect(),
        review_blocked_project_ids: book
            .review_blocked_projects
            .iter()
            .map(|project| project.as_str().to_owned())
            .collect(),
        items: book
            .items
            .iter()
            .map(|item| QueueItemView {
                id: item.id.as_str().to_owned(),
                project_id: item.project_id.as_str().to_owned(),
                workspace_id: item.workspace_id.as_str().to_owned(),
                workspace_root: item.workspace_root.clone(),
                session_id: item.session_id.as_str().to_owned(),
                transport: item.transport,
                workflow: item.workflow.clone(),
                prompt: item.prompt.clone(),
                auto_start: item.auto_start,
                state: item.state,
                enqueued_at_unix_ms: item.enqueued_at_unix_ms,
                ordinal: item.ordinal,
                retry_of_run_id: item
                    .retry_of_run_id
                    .as_ref()
                    .map(|run| run.as_str().to_owned()),
                predecessor_run_id: item
                    .predecessor_run_id
                    .as_ref()
                    .map(|run| run.as_str().to_owned()),
                blocked_reason: item.blocked_reason.clone(),
            })
            .collect(),
        runs: book
            .runs
            .iter()
            .rev()
            .filter(|run| visible_item_ids.contains(&run.queue_item_id))
            .map(|run| RunView {
                id: run.id.as_str().to_owned(),
                queue_item_id: run.queue_item_id.as_str().to_owned(),
                project_id: run.project_id.as_str().to_owned(),
                session_id: run.session_id.as_str().to_owned(),
                transport: run.transport,
                state: run.state,
                started_at_unix_ms: run.started_at_unix_ms,
                ended_at_unix_ms: run.ended_at_unix_ms,
                stop_reason: run.stop_reason.clone(),
            })
            .collect(),
        steering: book
            .steer_intents
            .iter()
            .skip(book.steer_intents.len().saturating_sub(200))
            .map(|intent| SteerIntentView {
                id: intent.id.as_str().to_owned(),
                project_id: intent.project_id.as_str().to_owned(),
                session_id: intent.session_id.as_str().to_owned(),
                run_id: intent.run_id.as_str().to_owned(),
                message: intent.message.clone(),
                created_at_unix_ms: intent.created_at_unix_ms,
                ordinal: intent.ordinal,
                state: intent.state,
            })
            .collect(),
    }
}

fn unavailable_view(reason: &str) -> QueueView {
    QueueView {
        available: false,
        status: bounded_reason(reason).unwrap_or_else(|_| "Prompt queue is unavailable.".into()),
        max_global_runs: MAX_GLOBAL_RUNS,
        active_global_runs: 0,
        paused_project_ids: Vec::new(),
        review_blocked_project_ids: Vec::new(),
        items: Vec::new(),
        runs: Vec::new(),
        steering: Vec::new(),
        children: Vec::new(),
    }
}

fn active_run_count(book: &QueueBook) -> usize {
    book.runs.iter().filter(|run| run.state.active()).count()
}

fn active_project_ids(book: &QueueBook) -> HashSet<ProjectId> {
    book.runs
        .iter()
        .filter(|run| run.state.active())
        .map(|run| run.project_id.clone())
        .collect()
}

fn trim_terminal_history(book: &mut QueueBook) {
    if book.runs.len() <= MAX_RUN_RECORDS {
        return;
    }
    let removable = book.runs.len() - MAX_RUN_RECORDS;
    let remove_ids = book
        .runs
        .iter()
        .filter(|run| !run.state.active())
        .filter(|run| {
            !book
                .children
                .iter()
                .any(|child| child.parent == run.id && child.review_pending)
        })
        .take(removable)
        .map(|run| run.id.clone())
        .collect::<HashSet<_>>();
    book.runs.retain(|run| !remove_ids.contains(&run.id));
    book.items.retain(|item| {
        item.retry_of_run_id
            .as_ref()
            .is_none_or(|run_id| !remove_ids.contains(run_id))
            || !item.state.terminal()
    });
}

fn validate_prompt(prompt: &str) -> Result<(), String> {
    if prompt.trim().is_empty()
        || prompt.len() > MAX_PROMPT_BYTES
        || prompt.contains('\0')
        || prompt
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(format!(
            "Prompt must be 1–{MAX_PROMPT_BYTES} UTF-8 bytes without NUL or unsupported control characters."
        ));
    }
    Ok(())
}

fn validate_workspace_root(root: &str) -> Result<(), String> {
    if root.is_empty()
        || root.len() > 4_096
        || !Path::new(root).is_absolute()
        || root.contains('\0')
        || root.chars().any(char::is_control)
    {
        return Err("Queued workspace root must be a bounded absolute UTF-8 path.".into());
    }
    Ok(())
}

fn validate_id(id: &str, label: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > MAX_ID_BYTES
        || id.contains('\0')
        || id.chars().any(char::is_control)
    {
        return Err(format!("Queued {label} identity is invalid."));
    }
    Ok(())
}

fn bounded_reason(reason: &str) -> Result<String, String> {
    let reason = reason.trim();
    if reason.is_empty()
        || reason.len() > MAX_REASON_BYTES
        || reason.contains('\0')
        || reason
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(format!(
            "Queue reason must be 1–{MAX_REASON_BYTES} safe UTF-8 bytes."
        ));
    }
    Ok(reason.to_owned())
}

fn new_id(prefix: &str, parts: &[&str]) -> String {
    let mut material = format!("grok-build-plus-{prefix}/v1\0").into_bytes();
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_be_bytes());
        material.extend_from_slice(part.as_bytes());
    }
    material.extend_from_slice(&std::process::id().to_be_bytes());
    material.extend_from_slice(&unix_time_millis().to_be_bytes());
    material.extend_from_slice(&NEXT_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    format!("{prefix}-{}", &worktree_recovery_digest(&material)[..32])
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1)
}

#[cfg(test)]
fn create_owner_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("Cannot create queue state root: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Cannot restrict queue state root: {error}"))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests;
