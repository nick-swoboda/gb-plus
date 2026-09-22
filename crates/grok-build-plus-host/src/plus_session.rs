//! Last-workspace and plus chat/run restore for GB Plus.
//!
//! Plus chat turns and contained-run presentation are not `EventLedger` /
//! `DurableUiProjection` events (those would need a schema change). They
//! live in the same documented desktop state root as last-workspace.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
static NEXT_STATE_WRITE: AtomicU64 = AtomicU64::new(1);

use serde::{Deserialize, Serialize};

use super::plus_command_security::{
    PLUS_COMMAND_SECURITY_FILE, PlusCommandSecurityPreference, encode_command_security_preference,
    parse_command_security_preference,
};
use super::plus_proposal::{PendingFileSet, present_needs_accept_inbox};
use super::{
    BoundProject, CommandOutcomeClass, Digest, PlusHostError, PresentedCommandOutcome, ProjectId,
    SessionId, WorktreeId, bind_project_folder,
};

/// Window-start presentation produced by [`restore_plus_session`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusRestoredSession {
    /// Last remembered workspace, when the state-root file exists.
    pub last_workspace: Option<PathBuf>,
    /// Folder status line for the window.
    pub folder_status: String,
    /// Chat surface: persisted plus turns, empty, or a could-not-restore reason.
    pub chat: String,
    /// Contained-run surface: persisted outcome, empty-state, or a reason.
    pub command_outcome: String,
    /// Persisted authority class carried separately from presentation.
    pub command_outcome_class: CommandOutcomeClass,
    /// Still-pending file set restored with this session.
    pub pending: PendingFileSet,
    /// Inbox presentation of still-pending Accept work.
    pub needs_accept: String,
}

/// Legacy non-durable label. Restored chat or run state that persisted must
/// not carry this phrase.
pub const PLUS_NOT_YET_DURABLE: &str = "not yet durable";

/// Required GUI phrase when last-path, chat, or command text cannot be read.
pub const PLUS_COULD_NOT_RESTORE: &str = "could not restore";

/// Owner-only file under the desktop state root that holds the last folder.
pub const PLUS_LAST_WORKSPACE_FILE: &str = "plus-last-workspace";

/// Owner-only file that holds the accumulated plus chat transcript.
pub const PLUS_CHAT_TRANSCRIPT_FILE: &str = "plus-chat-transcript";

/// Owner-only file that holds the last contained-run presentation.
pub const PLUS_COMMAND_OUTCOME_FILE: &str = "plus-command-outcome";

/// Owner-only JSON book of named chat sessions on this state root.
pub const PLUS_SESSIONS_FILE: &str = "plus-sessions.json";

/// Owner-only JSON of the active session's pending file set.
pub const PLUS_PENDING_FILE: &str = "plus-pending.json";

/// Owner-only JSON list of known projects and the active project id.
pub const PLUS_PROJECTS_FILE: &str = "plus-projects.json";

/// Current project/worktree persistence schema.
pub const PLUS_PROJECTS_SCHEMA_VERSION: u16 = 2;

/// Read-only copy retained when the legacy unversioned project book migrates.
pub const PLUS_PROJECTS_LEGACY_BACKUP_FILE: &str = "plus-projects.json.legacy-v0.bak";

/// Owner-only receipt for the one-way project-book migration.
pub const PLUS_PROJECTS_MIGRATION_RECEIPT_FILE: &str = "plus-projects-migration.json";

/// App-owned directory containing managed worktrees, beneath state root.
pub const PLUS_WORKTREES_DIR: &str = "worktrees";

const PLUS_UNBOUND_SESSION_ID: &str = "project-unbound";

/// Sidebar status: no pending work and no in-flight Send/Run.
pub const PLUS_SESSION_IDLE: &str = "idle";

/// Sidebar status: live Send or contained Run in flight.
pub const PLUS_SESSION_RUNNING: &str = "running";

/// Sidebar status: this session still has a pending file set.
pub const PLUS_SESSION_NEEDS_ACCEPT: &str = "needs accept";

/// One durable plus chat session (not a ledger event).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlusChatSession {
    /// Stable id used to switch.
    pub id: SessionId,
    /// User-visible name.
    pub name: String,
    /// Persisted chat transcript for this session.
    pub chat: String,
    /// Persisted contained-run presentation for this session.
    pub command_outcome: String,
    /// Authority class for `command_outcome`; legacy records default to Idle.
    #[serde(default = "default_command_outcome_class")]
    pub command_outcome_class: CommandOutcomeClass,
    /// Still-pending file proposals for this session.
    #[serde(default)]
    pub pending: PendingFileSet,
    /// True while Send or contained Run is in flight on this session.
    #[serde(default)]
    pub in_flight: bool,
}

/// All plus sessions under one desktop state root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlusSessionBook {
    /// Active session id.
    pub active_id: SessionId,
    /// Sessions in creation order.
    pub sessions: Vec<PlusChatSession>,
}

/// One canonical project known to the desktop host.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlusKnownProject {
    /// Stable SHA-256 identity derived from the canonical root path.
    pub id: ProjectId,
    /// User-visible final path component.
    pub name: String,
    /// Canonical absolute project root.
    pub root: PathBuf,
    /// Managed worktree selected inside this stable base project.
    #[serde(default)]
    pub active_worktree_id: Option<WorktreeId>,
    /// Worktrees owned by this project and managed below Application Support.
    #[serde(default)]
    pub worktrees: Vec<PlusManagedWorktree>,
}

impl PlusKnownProject {
    /// Active workspace root without changing the stable base-project identity.
    #[must_use]
    pub fn active_root(&self) -> &Path {
        self.active_worktree_id
            .as_deref()
            .and_then(|id| self.worktrees.iter().find(|worktree| worktree.id == id))
            .map_or(self.root.as_path(), |worktree| worktree.path.as_path())
    }

    /// Active managed worktree, or `None` for the base project.
    #[must_use]
    pub fn active_worktree(&self) -> Option<&PlusManagedWorktree> {
        let id = self.active_worktree_id.as_deref()?;
        self.worktrees.iter().find(|worktree| worktree.id == id)
    }

    /// Session identity bound to this project's selected workspace.
    #[must_use]
    pub fn workspace_session_id(&self) -> SessionId {
        project_session_id(self)
    }
}

/// One app-managed Git worktree associated with a stable base project.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlusManagedWorktree {
    /// Stable deterministic identity derived from project and task.
    pub id: WorktreeId,
    /// User-visible task label.
    pub task: String,
    /// App-owned branch name.
    pub branch: String,
    /// Canonical absolute managed worktree path.
    pub path: PathBuf,
    /// Base commit selected when the worktree was created.
    pub base_commit: String,
    /// Creation time as Unix milliseconds.
    pub created_at: u64,
    /// Most recent verified recovery-manifest digest, when exported.
    #[serde(default)]
    pub recovery_manifest: Option<String>,
    /// Git-status digest bound to the most recent recovery export.
    #[serde(default)]
    pub recovery_state: Option<String>,
}

/// Persistent project source list and its active selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlusProjectBook {
    /// Persistence schema. Missing means legacy unversioned schema 0.
    #[serde(default)]
    pub schema_version: u16,
    /// Active project id, or `None` when no project is selected.
    #[serde(default)]
    pub active_id: Option<ProjectId>,
    /// Known projects in first-add order.
    #[serde(default)]
    pub projects: Vec<PlusKnownProject>,
}

#[derive(Serialize)]
struct PlusProjectMigrationReceipt {
    from_schema: u16,
    to_schema: u16,
    source_sha256: String,
    migrated_at_unix_ms: u64,
}

impl Default for PlusProjectBook {
    fn default() -> Self {
        Self {
            schema_version: PLUS_PROJECTS_SCHEMA_VERSION,
            active_id: None,
            projects: Vec::new(),
        }
    }
}

/// Documented desktop state root used for last-workspace, chat, and command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusSessionStore {
    state_root: PathBuf,
}

impl PlusSessionStore {
    /// macOS Application Support / Linux XDG state `grok-build` root.
    #[must_use]
    pub fn documented_desktop_state_root() -> PathBuf {
        documented_desktop_state_root()
    }

    /// Production store under the documented desktop state root.
    #[must_use]
    pub fn from_process_environment() -> Self {
        Self {
            state_root: documented_desktop_state_root(),
        }
    }

    /// Explicit root for tests and `--plus-smoke` so they do not write home.
    #[must_use]
    pub fn from_state_root(state_root: impl Into<PathBuf>) -> Self {
        Self {
            state_root: state_root.into(),
        }
    }

    /// Directory that holds last-workspace, chat, and command files.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Records the last bound absolute folder. Creates the state root at 0700.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the directory or file cannot be
    /// written.
    pub fn remember_last_workspace(&self, folder: &Path) -> Result<(), PlusHostError> {
        if !folder.is_absolute() {
            return Err(PlusHostError::Session(
                "last workspace path must be absolute".into(),
            ));
        }
        let text = folder
            .to_str()
            .ok_or_else(|| PlusHostError::Session("last workspace path is not UTF-8".into()))?;
        let mut body = String::from(text);
        body.push('\n');
        self.write_owner_only_text(PLUS_LAST_WORKSPACE_FILE, &body)
    }

    /// Last remembered absolute folder, if the file exists and is readable.
    #[must_use]
    pub fn last_workspace(&self) -> Option<PathBuf> {
        self.load_last_workspace().ok().flatten()
    }

    /// Last remembered absolute folder, or a session error when the file is
    /// present but unreadable.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file exists but is not
    /// UTF-8, not absolute, or cannot be read.
    pub fn load_last_workspace(&self) -> Result<Option<PathBuf>, PlusHostError> {
        let Some(text) = self.read_owner_only_text(PLUS_LAST_WORKSPACE_FILE)? else {
            return Ok(None);
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let path = PathBuf::from(trimmed);
        if path.is_absolute() {
            Ok(Some(path))
        } else {
            Err(PlusHostError::Session(
                "last workspace path is not absolute".into(),
            ))
        }
    }

    /// Loads the known-project source list. Before the projects file exists,
    /// the legacy last-workspace path is represented as the sole active entry.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when persisted JSON or project
    /// identities are invalid.
    pub fn load_project_book(&self) -> Result<PlusProjectBook, PlusHostError> {
        let (mut book, legacy_source) = match self.read_owner_only_text(PLUS_PROJECTS_FILE)? {
            Some(text) => {
                let book = serde_json::from_str(&text).map_err(|error| {
                    PlusHostError::Session(format!(
                        "{PLUS_PROJECTS_FILE} is not valid JSON: {error}"
                    ))
                })?;
                (book, Some(text))
            }
            None => (self.project_book_from_last_workspace()?, None),
        };
        if book.schema_version > PLUS_PROJECTS_SCHEMA_VERSION {
            return Err(PlusHostError::Session(format!(
                "{PLUS_PROJECTS_FILE} schema {} is newer than supported schema {PLUS_PROJECTS_SCHEMA_VERSION}",
                book.schema_version
            )));
        }
        let from_schema = book.schema_version;
        book.schema_version = PLUS_PROJECTS_SCHEMA_VERSION;
        validate_project_book(&book)?;
        self.validate_managed_worktree_roots(&book)?;
        if let Some(source) = legacy_source
            && from_schema < PLUS_PROJECTS_SCHEMA_VERSION
        {
            self.commit_project_book_migration(&source, from_schema, &book)?;
        } else {
            self.restore_missing_project_migration_receipt()?;
        }
        Ok(book)
    }

    /// Persists the project book, adopting the legacy active session for a
    /// pre-existing last-workspace entry on first migration.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] on invalid or unwritable state.
    pub fn ensure_project_book(&self) -> Result<PlusProjectBook, PlusHostError> {
        if self.read_owner_only_text(PLUS_PROJECTS_FILE)?.is_some() {
            return self.load_project_book();
        }
        let book = self.project_book_from_last_workspace()?;
        if let Some(project) = active_project_in(&book) {
            self.adopt_active_session_for_project(project)?;
        }
        self.save_project_book(&book)?;
        Ok(book)
    }

    /// Adds or re-lists a validated project, selects it, and switches to its
    /// stable chat/pending session.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when persistence fails.
    pub fn remember_known_project(
        &self,
        bound: &BoundProject,
    ) -> Result<PlusProjectBook, PlusHostError> {
        let mut book = self.ensure_project_book()?;
        if let Some(project) = book.projects.iter_mut().find(|project| {
            project
                .worktrees
                .iter()
                .any(|worktree| worktree.path == bound.folder())
        }) {
            let worktree_id = project
                .worktrees
                .iter()
                .find(|worktree| worktree.path == bound.folder())
                .map(|worktree| worktree.id.clone())
                .ok_or_else(|| {
                    PlusHostError::Session("known worktree lookup changed unexpectedly".into())
                })?;
            project.active_worktree_id = Some(worktree_id);
            let selected = project.clone();
            self.ensure_plus_session_with_id(
                &project_session_id(&selected),
                &workspace_session_name(&selected),
            )?;
            book.active_id = Some(selected.id);
            self.save_project_book(&book)?;
            self.remember_last_workspace(bound.folder())?;
            return Ok(book);
        }
        if bound.folder().join(".git").is_file() {
            return Err(PlusHostError::Session(
                "this folder is a Git worktree; open its base project and manage it in Worktrees so it cannot become a separate project".into(),
            ));
        }
        let project = known_project_from_root(bound.folder())?;
        if let Some(existing) = book
            .projects
            .iter_mut()
            .find(|existing| existing.id == project.id)
        {
            existing.name.clone_from(&project.name);
            existing.root.clone_from(&project.root);
            existing.active_worktree_id = None;
        } else {
            book.projects.push(project.clone());
        }
        self.ensure_plus_session_with_id(
            &project_session_id(&project),
            &workspace_session_name(&project),
        )?;
        book.active_id = Some(project.id);
        self.save_project_book(&book)?;
        self.remember_last_workspace(bound.folder())?;
        Ok(book)
    }

    /// Selects a known project and restores its chat, pending proposals, and
    /// last command outcome into the live session files.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError`] when the id is unknown, the folder no longer
    /// binds canonically, or session persistence fails.
    pub fn activate_known_project(
        &self,
        id: &str,
    ) -> Result<(PlusProjectBook, BoundProject), PlusHostError> {
        let mut book = self.ensure_project_book()?;
        let project = book
            .projects
            .iter()
            .find(|project| project.id == id)
            .cloned()
            .ok_or_else(|| PlusHostError::Session(format!("no known project with id {id}")))?;
        let active_root = project.active_root();
        let bound = bind_project_folder(active_root)?;
        if bound.folder() != active_root {
            return Err(PlusHostError::Session(format!(
                "known active workspace no longer resolves canonically: {}",
                active_root.display()
            )));
        }
        self.ensure_plus_session_with_id(
            &project_session_id(&project),
            &workspace_session_name(&project),
        )?;
        book.active_id = Some(project.id);
        self.save_project_book(&book)?;
        self.remember_last_workspace(bound.folder())?;
        Ok((book, bound))
    }

    /// Removes one project from the source list only. Disk files and the
    /// project's retained chat session are not deleted. If it was active, the
    /// first remaining bindable project becomes active; otherwise the host is
    /// left with no active project and an empty unbound session.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the id is unknown or state
    /// cannot be persisted.
    pub fn unlist_known_project(&self, id: &str) -> Result<PlusProjectBook, PlusHostError> {
        let mut book = self.ensure_project_book()?;
        let index = book
            .projects
            .iter()
            .position(|project| project.id == id)
            .ok_or_else(|| PlusHostError::Session(format!("no known project with id {id}")))?;
        if !book.projects[index].worktrees.is_empty() {
            return Err(PlusHostError::Session(
                "remove managed worktrees before removing this base project from the list".into(),
            ));
        }
        let was_active = book.active_id.as_deref() == Some(id);
        book.projects.remove(index);
        if was_active {
            book.active_id = None;
            for project in &book.projects {
                let Ok(bound) = bind_project_folder(project.active_root()) else {
                    continue;
                };
                self.ensure_plus_session_with_id(
                    &project_session_id(project),
                    &workspace_session_name(project),
                )?;
                self.remember_last_workspace(bound.folder())?;
                book.active_id = Some(project.id.clone());
                break;
            }
            if book.active_id.is_none() {
                self.deactivate_project_context()?;
            }
        }
        self.save_project_book(&book)?;
        Ok(book)
    }

    /// Returns the selected stable base project.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when no project is active.
    pub fn active_known_project(&self) -> Result<PlusKnownProject, PlusHostError> {
        let book = self.ensure_project_book()?;
        active_project_in(&book).cloned().ok_or_else(|| {
            PlusHostError::Session("no active project is available for Worktrees".into())
        })
    }

    /// Deterministic app-owned path for one managed worktree.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] for malformed identities.
    pub fn managed_worktree_path(
        &self,
        project_id: &str,
        worktree_id: &str,
    ) -> Result<PathBuf, PlusHostError> {
        require_hex_id(project_id, "project")?;
        require_hex_id(worktree_id, "worktree")?;
        let state_root = self.state_root.canonicalize().map_err(|error| {
            PlusHostError::Session(format!(
                "cannot resolve desktop state root for managed worktree: {error}"
            ))
        })?;
        Ok(state_root
            .join(PLUS_WORKTREES_DIR)
            .join(project_id)
            .join(worktree_id))
    }

    /// Records a Git-created managed worktree and optionally activates it.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError`] when identity, binding, or persistence fails.
    pub fn register_managed_worktree(
        &self,
        project_id: &str,
        worktree: PlusManagedWorktree,
        activate: bool,
    ) -> Result<(PlusProjectBook, BoundProject), PlusHostError> {
        let expected = self.managed_worktree_path(project_id, &worktree.id)?;
        if worktree.path != expected {
            return Err(PlusHostError::Session(format!(
                "managed worktree path is not the app-owned path: {}",
                worktree.path.display()
            )));
        }
        let bound = bind_project_folder(&worktree.path)?;
        if bound.folder() != worktree.path {
            return Err(PlusHostError::Session(
                "managed worktree path is not canonical".into(),
            ));
        }
        let mut book = self.ensure_project_book()?;
        let project = book
            .projects
            .iter_mut()
            .find(|project| project.id == project_id)
            .ok_or_else(|| PlusHostError::Session("managed worktree project is unknown".into()))?;
        if let Some(existing) = project
            .worktrees
            .iter_mut()
            .find(|existing| existing.id == worktree.id)
        {
            if existing.path != worktree.path || existing.branch != worktree.branch {
                return Err(PlusHostError::Session(
                    "managed worktree identity conflicts with an existing record".into(),
                ));
            }
            *existing = worktree.clone();
        } else {
            project.worktrees.push(worktree.clone());
        }
        if activate {
            project.active_worktree_id = Some(worktree.id);
            let selected = project.clone();
            self.ensure_plus_session_with_id(
                &project_session_id(&selected),
                &workspace_session_name(&selected),
            )?;
            book.active_id = Some(selected.id);
            self.remember_last_workspace(bound.folder())?;
        }
        self.save_project_book(&book)?;
        Ok((book, bound))
    }

    /// Activates the base workspace or one known worktree under a project.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError`] for an unknown or unbindable workspace.
    pub fn activate_project_workspace(
        &self,
        project_id: &str,
        worktree_id: Option<&str>,
    ) -> Result<(PlusProjectBook, BoundProject), PlusHostError> {
        let mut book = self.ensure_project_book()?;
        let project = book
            .projects
            .iter_mut()
            .find(|project| project.id == project_id)
            .ok_or_else(|| PlusHostError::Session("workspace project is unknown".into()))?;
        if let Some(worktree_id) = worktree_id
            && !project
                .worktrees
                .iter()
                .any(|worktree| worktree.id == worktree_id)
        {
            return Err(PlusHostError::Session(
                "managed worktree is not associated with this project".into(),
            ));
        }
        project.active_worktree_id = worktree_id.map(WorktreeId::from);
        let selected = project.clone();
        let bound = bind_project_folder(selected.active_root())?;
        if bound.folder() != selected.active_root() {
            return Err(PlusHostError::Session(
                "active workspace no longer resolves canonically".into(),
            ));
        }
        self.ensure_plus_session_with_id(
            &project_session_id(&selected),
            &workspace_session_name(&selected),
        )?;
        book.active_id = Some(selected.id);
        self.save_project_book(&book)?;
        self.remember_last_workspace(bound.folder())?;
        Ok((book, bound))
    }

    /// Forgets a worktree only after Git removal has succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError`] when the association is missing or persistence
    /// fails.
    pub fn forget_managed_worktree(
        &self,
        project_id: &str,
        worktree_id: &str,
    ) -> Result<(PlusProjectBook, Option<BoundProject>), PlusHostError> {
        let mut book = self.ensure_project_book()?;
        let project_is_active = book.active_id.as_deref() == Some(project_id);
        let project = book
            .projects
            .iter_mut()
            .find(|project| project.id == project_id)
            .ok_or_else(|| PlusHostError::Session("worktree project is unknown".into()))?;
        let index = project
            .worktrees
            .iter()
            .position(|worktree| worktree.id == worktree_id)
            .ok_or_else(|| PlusHostError::Session("managed worktree is unknown".into()))?;
        let was_active = project.active_worktree_id.as_deref() == Some(worktree_id);
        project.worktrees.remove(index);
        if was_active {
            project.active_worktree_id = None;
        }
        let selected = project.clone();
        let bound = if project_is_active {
            let bound = bind_project_folder(selected.active_root())?;
            if was_active {
                self.ensure_plus_session_with_id(
                    &project_session_id(&selected),
                    &workspace_session_name(&selected),
                )?;
                self.remember_last_workspace(bound.folder())?;
            }
            Some(bound)
        } else {
            None
        };
        self.save_project_book(&book)?;
        Ok((book, bound))
    }

    /// Records the hash of a user-requested recovery export.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] for an unknown worktree or digest.
    pub fn remember_worktree_recovery(
        &self,
        project_id: &str,
        worktree_id: &str,
        manifest: &str,
        state: &str,
    ) -> Result<PlusProjectBook, PlusHostError> {
        require_hex_id(manifest, "recovery manifest")?;
        require_hex_id(state, "recovery state")?;
        let mut book = self.ensure_project_book()?;
        let worktree = book
            .projects
            .iter_mut()
            .find(|project| project.id == project_id)
            .and_then(|project| {
                project
                    .worktrees
                    .iter_mut()
                    .find(|worktree| worktree.id == worktree_id)
            })
            .ok_or_else(|| PlusHostError::Session("managed worktree is unknown".into()))?;
        worktree.recovery_manifest = Some(manifest.to_owned());
        worktree.recovery_state = Some(state.to_owned());
        self.save_project_book(&book)?;
        Ok(book)
    }

    /// Replaces the persisted chat transcript with `text`.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file cannot be written.
    pub fn remember_chat_transcript(&self, text: &str) -> Result<(), PlusHostError> {
        self.write_owner_only_text(PLUS_CHAT_TRANSCRIPT_FILE, text)?;
        self.sync_active_session(Some(text), None, None, None)
    }

    /// Replaces the persisted contained-run presentation with `text`.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file cannot be written.
    pub fn remember_command_outcome(&self, text: &str) -> Result<(), PlusHostError> {
        self.remember_presented_command_outcome(&PresentedCommandOutcome::new(
            CommandOutcomeClass::Idle,
            text,
        ))
    }

    /// Persists typed authority beside unchanged contained-run presentation.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when state cannot be replaced.
    pub fn remember_presented_command_outcome(
        &self,
        outcome: &PresentedCommandOutcome,
    ) -> Result<(), PlusHostError> {
        self.write_owner_only_text(PLUS_COMMAND_OUTCOME_FILE, &outcome.text)?;
        self.sync_active_session(None, Some(&outcome.text), Some(outcome.class), None)
    }

    /// Persists the Command security first-run choice. Missing file is Off.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file cannot be written.
    pub fn remember_command_security_preference(
        &self,
        preference: PlusCommandSecurityPreference,
    ) -> Result<(), PlusHostError> {
        let mut body = encode_command_security_preference(preference).to_owned();
        body.push('\n');
        self.write_owner_only_text(PLUS_COMMAND_SECURITY_FILE, &body)
    }

    /// Stored Command security choice. Missing or unreadable is Off.
    #[must_use]
    pub fn command_security_preference(&self) -> PlusCommandSecurityPreference {
        match self.read_owner_only_text(PLUS_COMMAND_SECURITY_FILE) {
            Ok(Some(text)) => parse_command_security_preference(&text),
            Ok(None) | Err(_) => PlusCommandSecurityPreference::Off,
        }
    }

    /// Replaces the persisted pending file set for the active session.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file cannot be written.
    pub fn remember_pending_set(&self, set: &PendingFileSet) -> Result<(), PlusHostError> {
        let text = serde_json::to_string_pretty(set).map_err(|error| {
            PlusHostError::Session(format!("cannot encode pending set: {error}"))
        })?;
        self.write_owner_only_text(PLUS_PENDING_FILE, &text)?;
        self.sync_active_session(None, None, None, Some(set))
    }

    /// Persisted pending set, empty when the file is absent.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file exists but is not JSON.
    pub fn load_pending_set(&self) -> Result<PendingFileSet, PlusHostError> {
        match self.read_owner_only_text(PLUS_PENDING_FILE)? {
            None => Ok(PendingFileSet::default()),
            Some(text) => serde_json::from_str(&text).map_err(|error| {
                PlusHostError::Session(format!("{PLUS_PENDING_FILE} is not valid JSON: {error}"))
            }),
        }
    }

    /// Marks the active session as having a live Send or contained Run in flight.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the book cannot be written.
    pub fn mark_plus_session_in_flight(&self, in_flight: bool) -> Result<(), PlusHostError> {
        let mut book = self.load_session_book()?;
        if let Some(session) = book
            .sessions
            .iter_mut()
            .find(|session| session.id == book.active_id)
        {
            session.in_flight = in_flight;
        }
        self.save_session_book(&book)
    }

    /// Appends one Send turn to the persisted chat transcript.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file cannot be written.
    pub fn append_chat_turn(&self, turn_text: &str) -> Result<String, PlusHostError> {
        let mut log = match self.load_chat_transcript() {
            Ok(Some(existing)) if !existing.contains(PLUS_COULD_NOT_RESTORE) => existing,
            Ok(Some(_) | None) | Err(_) => String::new(),
        };
        if !turn_text.is_empty() {
            if !log.is_empty() {
                log.push('\n');
            }
            log.push_str(turn_text);
        }
        self.remember_chat_transcript(&log)?;
        Ok(log)
    }

    /// Returns the exact active application session id.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the session book is unreadable.
    pub fn active_plus_session_id(&self) -> Result<String, PlusHostError> {
        Ok(self.load_session_book()?.active_id.into_string())
    }

    /// Appends an assistant turn to one exact session without switching the
    /// process-global active project/session surface.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the session is missing or state
    /// cannot be persisted.
    pub fn append_chat_turn_to_session(
        &self,
        session_id: &str,
        turn_text: &str,
    ) -> Result<String, PlusHostError> {
        let mut book = self.load_session_book()?;
        let active = book.active_id == session_id;
        let session = book
            .sessions
            .iter_mut()
            .find(|session| session.id == session_id)
            .ok_or_else(|| PlusHostError::Session(format!("no session with id {session_id}")))?;
        if !turn_text.is_empty() {
            if !session.chat.is_empty() {
                session.chat.push('\n');
            }
            session.chat.push_str(turn_text);
        }
        let chat = session.chat.clone();
        self.save_session_book(&book)?;
        if active {
            self.write_owner_only_text(PLUS_CHAT_TRANSCRIPT_FILE, &chat)?;
        }
        Ok(chat)
    }

    /// Merges staged proposals into one exact session without switching it.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the session is missing or state
    /// cannot be persisted.
    pub fn merge_pending_into_session(
        &self,
        session_id: &str,
        pending: &PendingFileSet,
    ) -> Result<PendingFileSet, PlusHostError> {
        let mut book = self.load_session_book()?;
        let active = book.active_id == session_id;
        let session = book
            .sessions
            .iter_mut()
            .find(|session| session.id == session_id)
            .ok_or_else(|| PlusHostError::Session(format!("no session with id {session_id}")))?;
        for proposal in &pending.items {
            session.pending.upsert(proposal.clone());
        }
        let merged = session.pending.clone();
        self.save_session_book(&book)?;
        if active {
            let text = serde_json::to_string_pretty(&merged).map_err(|error| {
                PlusHostError::Session(format!("cannot encode pending set: {error}"))
            })?;
            self.write_owner_only_text(PLUS_PENDING_FILE, &text)?;
        }
        Ok(merged)
    }

    /// Marks one exact session in-flight without changing the active session.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the session is missing or state
    /// cannot be persisted.
    pub fn mark_plus_session_in_flight_by_id(
        &self,
        session_id: &str,
        in_flight: bool,
    ) -> Result<(), PlusHostError> {
        let mut book = self.load_session_book()?;
        let session = book
            .sessions
            .iter_mut()
            .find(|session| session.id == session_id)
            .ok_or_else(|| PlusHostError::Session(format!("no session with id {session_id}")))?;
        session.in_flight = in_flight;
        self.save_session_book(&book)
    }

    /// Clears stale in-flight flags during app restart recovery.
    ///
    /// Queue/run persistence owns the corresponding Interrupted terminal; this
    /// method only prevents a recovered session from remaining visually
    /// Running after no process can still own it.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when session state cannot be read or
    /// persisted.
    pub fn clear_stale_plus_session_runs(&self) -> Result<Vec<String>, PlusHostError> {
        let mut book = self.load_session_book()?;
        let mut cleared = Vec::new();
        for session in &mut book.sessions {
            if session.in_flight {
                session.in_flight = false;
                cleared.push(session.id.to_string());
            }
        }
        if !cleared.is_empty() {
            self.save_session_book(&book)?;
        }
        Ok(cleared)
    }

    /// Persisted chat transcript, when the file exists and is readable.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file exists but cannot be
    /// decoded.
    pub fn load_chat_transcript(&self) -> Result<Option<String>, PlusHostError> {
        self.read_owner_only_text(PLUS_CHAT_TRANSCRIPT_FILE)
    }

    /// Persisted contained-run presentation, when the file exists and is
    /// readable.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the file exists but cannot be
    /// decoded.
    pub fn load_command_outcome(&self) -> Result<Option<String>, PlusHostError> {
        self.read_owner_only_text(PLUS_COMMAND_OUTCOME_FILE)
    }

    /// Loads the session book, creating a default session if none exists.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the JSON is unreadable.
    pub fn load_session_book(&self) -> Result<PlusSessionBook, PlusHostError> {
        match self.read_owner_only_text(PLUS_SESSIONS_FILE)? {
            None => Ok(default_session_book()),
            Some(text) => serde_json::from_str(&text).map_err(|error| {
                PlusHostError::Session(format!("{PLUS_SESSIONS_FILE} is not valid JSON: {error}"))
            }),
        }
    }

    /// Creates a session, makes it active, and clears the live transcript.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] on persist failure.
    pub fn create_plus_session(&self, name: &str) -> Result<PlusChatSession, PlusHostError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(PlusHostError::Session(
                "session name must not be empty".into(),
            ));
        }
        let mut book = self.load_session_book()?;
        self.capture_active_into_book(&mut book);
        if book.sessions.len() == 1
            && book.sessions[0].id == "session-1"
            && book.sessions[0].chat.is_empty()
        {
            book.sessions.clear();
        }
        let session = PlusChatSession {
            id: format!("session-{}", next_session_id()).into(),
            name: name.to_owned(),
            chat: String::new(),
            command_outcome: String::new(),
            command_outcome_class: CommandOutcomeClass::Idle,
            pending: PendingFileSet::default(),
            in_flight: false,
        };
        book.active_id.clone_from(&session.id);
        book.sessions.push(session.clone());
        self.save_session_book(&book)?;
        self.write_owner_only_text(PLUS_CHAT_TRANSCRIPT_FILE, "")?;
        self.write_owner_only_text(PLUS_COMMAND_OUTCOME_FILE, "")?;
        self.write_owner_only_text(PLUS_PENDING_FILE, "")?;
        Ok(session)
    }

    /// Switches the active session by id or name.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the session is missing.
    pub fn switch_plus_session(&self, id_or_name: &str) -> Result<PlusChatSession, PlusHostError> {
        let mut book = self.load_session_book()?;
        self.capture_active_into_book(&mut book);
        let session = book
            .sessions
            .iter()
            .find(|session| session.id == id_or_name || session.name == id_or_name)
            .cloned()
            .ok_or_else(|| PlusHostError::Session(format!("no session named {id_or_name}")))?;
        book.active_id.clone_from(&session.id);
        self.save_session_book(&book)?;
        self.write_owner_only_text(PLUS_CHAT_TRANSCRIPT_FILE, &session.chat)?;
        self.write_owner_only_text(PLUS_COMMAND_OUTCOME_FILE, &session.command_outcome)?;
        let pending_text = serde_json::to_string_pretty(&session.pending).map_err(|error| {
            PlusHostError::Session(format!("cannot encode pending set: {error}"))
        })?;
        self.write_owner_only_text(PLUS_PENDING_FILE, &pending_text)?;
        Ok(session)
    }

    /// Renames a session identified by id or current name.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Session`] when the session is missing.
    pub fn rename_plus_session(
        &self,
        id_or_name: &str,
        new_name: &str,
    ) -> Result<PlusChatSession, PlusHostError> {
        let new_name = new_name.trim();
        if new_name.is_empty() {
            return Err(PlusHostError::Session(
                "session name must not be empty".into(),
            ));
        }
        let mut book = self.load_session_book()?;
        let session = book
            .sessions
            .iter_mut()
            .find(|session| session.id == id_or_name || session.name == id_or_name)
            .ok_or_else(|| PlusHostError::Session(format!("no session named {id_or_name}")))?;
        new_name.clone_into(&mut session.name);
        let renamed = session.clone();
        self.save_session_book(&book)?;
        Ok(renamed)
    }

    /// Sidebar listing: `*` marks the active session. Each line names exactly
    /// one of [`PLUS_SESSION_IDLE`], [`PLUS_SESSION_RUNNING`], or
    /// [`PLUS_SESSION_NEEDS_ACCEPT`].
    #[must_use]
    pub fn present_plus_session_list(&self) -> String {
        match self.load_session_book() {
            Ok(book) => present_plus_session_book(&book),
            Err(error) => format!("{PLUS_COULD_NOT_RESTORE} sessions: {error}"),
        }
    }

    fn project_book_from_last_workspace(&self) -> Result<PlusProjectBook, PlusHostError> {
        let Some(root) = self.load_last_workspace()? else {
            return Ok(PlusProjectBook::default());
        };
        let project = known_project_from_root(&root)?;
        Ok(PlusProjectBook {
            schema_version: PLUS_PROJECTS_SCHEMA_VERSION,
            active_id: Some(project.id.clone()),
            projects: vec![project],
        })
    }

    fn save_project_book(&self, book: &PlusProjectBook) -> Result<(), PlusHostError> {
        validate_project_book(book)?;
        self.validate_managed_worktree_roots(book)?;
        let text = serde_json::to_string_pretty(book).map_err(|error| {
            PlusHostError::Session(format!("cannot encode known projects: {error}"))
        })?;
        self.write_owner_only_text(PLUS_PROJECTS_FILE, &text)
    }

    fn validate_managed_worktree_roots(&self, book: &PlusProjectBook) -> Result<(), PlusHostError> {
        for project in &book.projects {
            for worktree in &project.worktrees {
                let expected = self.managed_worktree_path(&project.id, &worktree.id)?;
                if worktree.path != expected {
                    return Err(PlusHostError::Session(format!(
                        "managed worktree escaped its app-owned path: {}",
                        worktree.path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    fn commit_project_book_migration(
        &self,
        source: &str,
        from_schema: u16,
        book: &PlusProjectBook,
    ) -> Result<(), PlusHostError> {
        self.write_legacy_project_backup(source)?;
        self.save_project_book(book)?;
        self.write_project_migration_receipt(source, from_schema)
    }

    fn restore_missing_project_migration_receipt(&self) -> Result<(), PlusHostError> {
        if self
            .read_owner_only_text(PLUS_PROJECTS_MIGRATION_RECEIPT_FILE)?
            .is_some()
        {
            return Ok(());
        }
        let Some(source) = self.read_owner_only_text(PLUS_PROJECTS_LEGACY_BACKUP_FILE)? else {
            return Ok(());
        };
        self.write_project_migration_receipt(&source, 0)
    }

    fn write_legacy_project_backup(&self, source: &str) -> Result<(), PlusHostError> {
        create_owner_only_dir(&self.state_root).map_err(|error| {
            PlusHostError::Session(format!("cannot create desktop state root: {error}"))
        })?;
        let path = self.state_root.join(PLUS_PROJECTS_LEGACY_BACKUP_FILE);
        match fs::read(&path) {
            Ok(existing) if existing == source.as_bytes() => return Ok(()),
            Ok(_) => {
                return Err(PlusHostError::Session(
                    "legacy project backup already exists with different bytes".into(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(PlusHostError::Session(format!(
                    "cannot read legacy project backup: {error}"
                )));
            }
        }
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| {
                PlusHostError::Session(format!("cannot create legacy project backup: {error}"))
            })?;
        restrict_owner_only_file(&file).map_err(|error| {
            PlusHostError::Session(format!("cannot restrict legacy project backup: {error}"))
        })?;
        file.write_all(source.as_bytes()).map_err(|error| {
            PlusHostError::Session(format!("cannot write legacy project backup: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            PlusHostError::Session(format!("cannot sync legacy project backup: {error}"))
        })?;
        set_read_only_owner_file(&path).map_err(|error| {
            PlusHostError::Session(format!(
                "cannot make legacy project backup read-only: {error}"
            ))
        })?;
        sync_directory(&self.state_root).map_err(|error| {
            PlusHostError::Session(format!("cannot sync desktop state root: {error}"))
        })
    }

    fn write_project_migration_receipt(
        &self,
        source: &str,
        from_schema: u16,
    ) -> Result<(), PlusHostError> {
        let receipt = PlusProjectMigrationReceipt {
            from_schema,
            to_schema: PLUS_PROJECTS_SCHEMA_VERSION,
            source_sha256: Digest::sha256(source.as_bytes()).to_string(),
            migrated_at_unix_ms: unix_time_millis(),
        };
        let text = serde_json::to_string_pretty(&receipt).map_err(|error| {
            PlusHostError::Session(format!("cannot encode project migration receipt: {error}"))
        })?;
        self.write_owner_only_text(PLUS_PROJECTS_MIGRATION_RECEIPT_FILE, &text)
    }

    fn adopt_active_session_for_project(
        &self,
        project: &PlusKnownProject,
    ) -> Result<(), PlusHostError> {
        let target_id = project_session_id(project);
        let mut book = self.load_session_book()?;
        self.capture_active_into_book(&mut book);
        if !book.sessions.iter().any(|session| session.id == target_id) {
            if let Some(active) = book
                .sessions
                .iter_mut()
                .find(|session| session.id == book.active_id)
            {
                active.id.clone_from(&target_id);
                active.name.clone_from(&project.name);
            } else {
                book.sessions
                    .push(empty_plus_session(target_id.clone(), project.name.clone()));
            }
        }
        book.active_id.clone_from(&target_id);
        let selected = book
            .sessions
            .iter()
            .find(|session| session.id == target_id)
            .cloned()
            .ok_or_else(|| {
                PlusHostError::Session("project session migration produced no session".into())
            })?;
        self.save_session_book(&book)?;
        self.write_session_surfaces(&selected)
    }

    fn ensure_plus_session_with_id(
        &self,
        id: &str,
        name: &str,
    ) -> Result<PlusChatSession, PlusHostError> {
        let mut book = self.load_session_book()?;
        self.capture_active_into_book(&mut book);
        let selected =
            if let Some(existing) = book.sessions.iter_mut().find(|session| session.id == id) {
                name.clone_into(&mut existing.name);
                existing.clone()
            } else if book.sessions.len() == 1 && pristine_default_session(&book.sessions[0]) {
                let existing = &mut book.sessions[0];
                existing.id = SessionId::from(id);
                name.clone_into(&mut existing.name);
                existing.clone()
            } else {
                let session = empty_plus_session(SessionId::from(id), name.to_owned());
                book.sessions.push(session.clone());
                session
            };
        book.active_id.clone_from(&selected.id);
        self.save_session_book(&book)?;
        self.write_session_surfaces(&selected)?;
        Ok(selected)
    }

    fn write_session_surfaces(&self, session: &PlusChatSession) -> Result<(), PlusHostError> {
        self.write_owner_only_text(PLUS_CHAT_TRANSCRIPT_FILE, &session.chat)?;
        self.write_owner_only_text(PLUS_COMMAND_OUTCOME_FILE, &session.command_outcome)?;
        let pending = serde_json::to_string_pretty(&session.pending).map_err(|error| {
            PlusHostError::Session(format!("cannot encode pending set: {error}"))
        })?;
        self.write_owner_only_text(PLUS_PENDING_FILE, &pending)
    }

    fn deactivate_project_context(&self) -> Result<(), PlusHostError> {
        self.ensure_plus_session_with_id(PLUS_UNBOUND_SESSION_ID, "No active project")?;
        self.remember_chat_transcript("")?;
        self.remember_command_outcome("")?;
        self.remember_pending_set(&PendingFileSet::default())?;
        self.write_owner_only_text(PLUS_LAST_WORKSPACE_FILE, "")
    }

    fn save_session_book(&self, book: &PlusSessionBook) -> Result<(), PlusHostError> {
        let text = serde_json::to_string_pretty(book)
            .map_err(|error| PlusHostError::Session(format!("cannot encode sessions: {error}")))?;
        self.write_owner_only_text(PLUS_SESSIONS_FILE, &text)
    }

    fn sync_active_session(
        &self,
        chat: Option<&str>,
        command: Option<&str>,
        command_class: Option<CommandOutcomeClass>,
        pending: Option<&PendingFileSet>,
    ) -> Result<(), PlusHostError> {
        let mut book = self.load_session_book()?;
        if book.sessions.is_empty() {
            book = default_session_book();
        }
        if let Some(session) = book
            .sessions
            .iter_mut()
            .find(|session| session.id == book.active_id)
        {
            if let Some(chat) = chat {
                chat.clone_into(&mut session.chat);
            }
            if let Some(command) = command {
                command.clone_into(&mut session.command_outcome);
            }
            if let Some(command_class) = command_class {
                session.command_outcome_class = command_class;
            }
            if let Some(pending) = pending {
                session.pending = pending.clone();
            }
        }
        self.save_session_book(&book)
    }

    fn capture_active_into_book(&self, book: &mut PlusSessionBook) {
        let chat = self
            .read_owner_only_text(PLUS_CHAT_TRANSCRIPT_FILE)
            .ok()
            .flatten()
            .unwrap_or_default();
        let command = self
            .read_owner_only_text(PLUS_COMMAND_OUTCOME_FILE)
            .ok()
            .flatten()
            .unwrap_or_default();
        let pending = self.load_pending_set().unwrap_or_default();
        if let Some(session) = book
            .sessions
            .iter_mut()
            .find(|session| session.id == book.active_id)
        {
            session.chat = chat;
            session.command_outcome = command;
            session.pending = pending;
        }
    }

    pub(crate) fn write_owner_only_text(
        &self,
        name: &str,
        text: &str,
    ) -> Result<(), PlusHostError> {
        validate_state_file_name(name)?;
        create_owner_only_dir(&self.state_root).map_err(|error| {
            PlusHostError::Session(format!("cannot create desktop state root: {error}"))
        })?;
        let path = self.state_root.join(name);
        let temporary = self.state_root.join(format!(
            ".plus-state-{}-{}.tmp",
            std::process::id(),
            NEXT_STATE_WRITE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| PlusHostError::Session(format!("cannot open {name} temp: {error}")))?;
        let result = (|| {
            restrict_owner_only_file(&file).map_err(|error| {
                PlusHostError::Session(format!("cannot restrict {name} temp: {error}"))
            })?;
            file.write_all(text.as_bytes()).map_err(|error| {
                PlusHostError::Session(format!("cannot write {name} temp: {error}"))
            })?;
            file.sync_all().map_err(|error| {
                PlusHostError::Session(format!("cannot sync {name} temp: {error}"))
            })?;
            drop(file);
            fs::rename(&temporary, &path).map_err(|error| {
                PlusHostError::Session(format!("cannot atomically replace {name}: {error}"))
            })?;
            sync_directory(&self.state_root).map_err(|error| {
                PlusHostError::Session(format!("cannot sync desktop state root: {error}"))
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(crate) fn read_owner_only_text(&self, name: &str) -> Result<Option<String>, PlusHostError> {
        match fs::read(self.state_root.join(name)) {
            Ok(bytes) => {
                let text = String::from_utf8(bytes)
                    .map_err(|_| PlusHostError::Session(format!("{name} is not UTF-8")))?;
                if text.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(text))
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(PlusHostError::Session(format!(
                "cannot read {name}: {error}"
            ))),
        }
    }
}

/// Window-start presentation from the documented state root.
///
/// Chat and contained-run text come from the desktop-local store. A
/// present-but-unreadable file is [`PLUS_COULD_NOT_RESTORE`], not
/// [`PLUS_NOT_YET_DURABLE`].
#[must_use]
pub fn restore_plus_session(store: &PlusSessionStore) -> PlusRestoredSession {
    let last_workspace = store.load_last_workspace();
    let chat = present_restored_surface("chat", store.load_chat_transcript());
    let command = present_restored_surface("command", store.load_command_outcome());
    let (pending, command_outcome_class) = match store.load_session_book() {
        Ok(book) => book
            .sessions
            .iter()
            .find(|session| session.id == book.active_id)
            .map_or_else(
                || {
                    (
                        store.load_pending_set().unwrap_or_default(),
                        CommandOutcomeClass::Idle,
                    )
                },
                |session| (session.pending.clone(), session.command_outcome_class),
            ),
        Err(_) => (
            store.load_pending_set().unwrap_or_default(),
            CommandOutcomeClass::Idle,
        ),
    };
    let needs_accept = present_needs_accept_inbox(&pending);
    match last_workspace {
        Ok(Some(last_workspace)) => PlusRestoredSession {
            folder_status: format!("Last workspace: {}", last_workspace.display()),
            chat: if chat.is_empty() {
                "No chat yet.".into()
            } else {
                chat
            },
            command_outcome: if command.is_empty() {
                "No contained command has been attempted.".into()
            } else {
                command
            },
            command_outcome_class,
            last_workspace: Some(last_workspace),
            pending,
            needs_accept,
        },
        Ok(None) => PlusRestoredSession {
            last_workspace: None,
            folder_status: "No project folder bound.".into(),
            chat,
            command_outcome: if command.is_empty() {
                "No contained command has been attempted.".into()
            } else {
                command
            },
            command_outcome_class,
            pending,
            needs_accept,
        },
        Err(error) => PlusRestoredSession {
            last_workspace: None,
            folder_status: restore_reason("last workspace", &error),
            chat: if chat.is_empty() {
                restore_reason("last workspace", &error)
            } else {
                chat
            },
            command_outcome: if command.is_empty() {
                "No contained command has been attempted.".into()
            } else {
                command
            },
            command_outcome_class,
            pending,
            needs_accept,
        },
    }
}

/// Binds a folder and remembers it as the last workspace.
///
/// # Errors
///
/// Returns [`PlusHostError`] from bind or last-path write.
pub fn bind_and_remember_project_folder(
    store: &PlusSessionStore,
    path: impl Into<PathBuf>,
) -> Result<BoundProject, PlusHostError> {
    let bound = bind_project_folder(path)?;
    store.remember_known_project(&bound)?;
    Ok(bound)
}

/// Derives the stable managed-worktree id and app-owned branch from a task.
///
/// # Errors
///
/// Returns [`PlusHostError::Session`] for malformed project ids or task names.
pub fn managed_worktree_identity(
    project_id: &str,
    task: &str,
) -> Result<(String, String), PlusHostError> {
    require_hex_id(project_id, "project")?;
    let task = normalized_worktree_task(task)?;
    let mut material = b"grok-build-plus-worktree/v1\0".to_vec();
    material.extend_from_slice(project_id.as_bytes());
    material.push(0);
    material.extend_from_slice(task.as_bytes());
    let id = Digest::sha256(&material).to_string();
    let slug = worktree_task_slug(&task);
    let branch = format!("grok-build-plus/{slug}-{}", &id[..12]);
    Ok((id, branch))
}

/// Builds a validated managed-worktree record after Git has created it.
///
/// # Errors
///
/// Returns [`PlusHostError::Session`] for invalid identity, path, or commit.
pub fn managed_worktree_record(
    project_id: &str,
    task: &str,
    path: PathBuf,
    base_commit: &str,
) -> Result<PlusManagedWorktree, PlusHostError> {
    let task = normalized_worktree_task(task)?;
    let (id, branch) = managed_worktree_identity(project_id, &task)?;
    if !path.is_absolute() {
        return Err(PlusHostError::Session(
            "managed worktree path must be absolute".into(),
        ));
    }
    require_git_object_id(base_commit)?;
    Ok(PlusManagedWorktree {
        id: id.into(),
        task,
        branch,
        path,
        base_commit: base_commit.to_owned(),
        created_at: unix_time_millis(),
        recovery_manifest: None,
        recovery_state: None,
    })
}

/// SHA-256 encoding used to bind recovery manifests and dirty-state bytes.
#[must_use]
pub fn worktree_recovery_digest(bytes: &[u8]) -> String {
    Digest::sha256(bytes).to_string()
}

fn present_restored_surface(
    surface: &str,
    loaded: Result<Option<String>, PlusHostError>,
) -> String {
    match loaded {
        Ok(Some(text)) => text,
        Ok(None) => String::new(),
        Err(error) => restore_reason(surface, &error),
    }
}

fn restore_reason(surface: &str, error: &PlusHostError) -> String {
    match error {
        PlusHostError::Session(detail) => {
            format!("{PLUS_COULD_NOT_RESTORE} {surface}: {detail}")
        }
        other => format!("{PLUS_COULD_NOT_RESTORE} {surface}: {other}"),
    }
}

/// Status word for one session: running, needs accept, or idle.
#[must_use]
pub fn plus_session_status(session: &PlusChatSession) -> &'static str {
    if session.in_flight {
        PLUS_SESSION_RUNNING
    } else if !session.pending.items.is_empty() {
        PLUS_SESSION_NEEDS_ACCEPT
    } else {
        PLUS_SESSION_IDLE
    }
}

/// Sidebar listing for a loaded book. I/O-free so tests can fixture status.
#[must_use]
pub fn present_plus_session_book(book: &PlusSessionBook) -> String {
    if book.sessions.is_empty() {
        return "No sessions.".into();
    }
    book.sessions
        .iter()
        .map(|session| {
            let mark = if session.id == book.active_id {
                "*"
            } else {
                " "
            };
            format!(
                "{mark} {} ({}) {}",
                session.name,
                session.id,
                plus_session_status(session)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn known_project_from_root(root: &Path) -> Result<PlusKnownProject, PlusHostError> {
    if !root.is_absolute() {
        return Err(PlusHostError::Session(
            "known project root must be absolute".into(),
        ));
    }
    let root_text = root
        .to_str()
        .ok_or_else(|| PlusHostError::Session("known project root is not UTF-8".into()))?;
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(root_text)
        .to_owned();
    let mut identity_material = b"grok-build-plus-project/v1\0".to_vec();
    identity_material.extend_from_slice(root_text.as_bytes());
    Ok(PlusKnownProject {
        id: Digest::sha256(&identity_material).to_string().into(),
        name,
        root: root.to_path_buf(),
        active_worktree_id: None,
        worktrees: Vec::new(),
    })
}

fn normalized_worktree_task(task: &str) -> Result<String, PlusHostError> {
    let task = task.trim();
    if task.is_empty()
        || task.len() > 128
        || task.chars().any(char::is_control)
        || task.contains('\0')
    {
        return Err(PlusHostError::Session(
            "worktree task must be 1–128 non-control UTF-8 bytes".into(),
        ));
    }
    Ok(task.to_owned())
}

fn worktree_task_slug(task: &str) -> String {
    let mut slug = String::new();
    let mut prior_dash = false;
    for character in task.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
            prior_dash = false;
        } else if !prior_dash && !slug.is_empty() {
            slug.push('-');
            prior_dash = true;
        }
        if slug.len() >= 32 {
            break;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() { "task".into() } else { slug }
}

fn require_hex_id(value: &str, label: &str) -> Result<(), PlusHostError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(PlusHostError::Session(format!(
            "{label} identity is not a lowercase SHA-256 digest"
        )))
    }
}

fn require_git_object_id(value: &str) -> Result<(), PlusHostError> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(PlusHostError::Session(
            "Git base commit is not a full object id".into(),
        ))
    }
}

fn project_session_id(project: &PlusKnownProject) -> SessionId {
    project.active_worktree_id.as_ref().map_or_else(
        || SessionId::new(format!("project-{}", project.id)),
        |worktree_id| SessionId::new(format!("project-{}-worktree-{worktree_id}", project.id)),
    )
}

fn workspace_session_name(project: &PlusKnownProject) -> String {
    project.active_worktree().map_or_else(
        || project.name.clone(),
        |worktree| format!("{} · {}", project.name, worktree.task),
    )
}

fn active_project_in(book: &PlusProjectBook) -> Option<&PlusKnownProject> {
    let active_id = book.active_id.as_deref()?;
    book.projects.iter().find(|project| project.id == active_id)
}

fn validate_project_book(book: &PlusProjectBook) -> Result<(), PlusHostError> {
    if book.schema_version != PLUS_PROJECTS_SCHEMA_VERSION {
        return Err(PlusHostError::Session(format!(
            "project book schema is {}, expected {PLUS_PROJECTS_SCHEMA_VERSION}",
            book.schema_version
        )));
    }
    let mut ids = HashSet::new();
    let mut roots = HashSet::new();
    let mut worktree_paths = HashSet::new();
    for project in &book.projects {
        let expected = known_project_from_root(&project.root)?;
        if project.id != expected.id {
            return Err(PlusHostError::Session(format!(
                "known project id does not match root: {}",
                project.root.display()
            )));
        }
        if project.name.trim().is_empty() {
            return Err(PlusHostError::Session(
                "known project name must not be empty".into(),
            ));
        }
        if !ids.insert(project.id.clone()) || !roots.insert(project.root.clone()) {
            return Err(PlusHostError::Session(
                "known project list contains a duplicate id or root".into(),
            ));
        }
        let mut worktree_ids = HashSet::new();
        for worktree in &project.worktrees {
            let (expected_id, expected_branch) =
                managed_worktree_identity(&project.id, &worktree.task)?;
            if worktree.id != expected_id || worktree.branch != expected_branch {
                return Err(PlusHostError::Session(format!(
                    "managed worktree identity does not match task `{}`",
                    worktree.task
                )));
            }
            require_git_object_id(&worktree.base_commit)?;
            if !worktree.path.is_absolute()
                || worktree.path == project.root
                || !worktree_ids.insert(worktree.id.clone())
                || !worktree_paths.insert(worktree.path.clone())
            {
                return Err(PlusHostError::Session(
                    "managed worktree list contains an invalid or duplicate id/path".into(),
                ));
            }
            if worktree.created_at == 0 {
                return Err(PlusHostError::Session(
                    "managed worktree creation time is missing".into(),
                ));
            }
            if let Some(manifest) = &worktree.recovery_manifest {
                require_hex_id(manifest, "recovery manifest")?;
            }
            if let Some(state) = &worktree.recovery_state {
                require_hex_id(state, "recovery state")?;
            }
            if worktree.recovery_manifest.is_some() != worktree.recovery_state.is_some() {
                return Err(PlusHostError::Session(
                    "worktree recovery manifest/state must be recorded together".into(),
                ));
            }
        }
        if let Some(active_worktree_id) = &project.active_worktree_id
            && !worktree_ids.contains(active_worktree_id)
        {
            return Err(PlusHostError::Session(
                "active worktree id is not present in its project".into(),
            ));
        }
    }
    if let Some(active_id) = &book.active_id
        && !ids.contains(active_id)
    {
        return Err(PlusHostError::Session(
            "active project id is not present in the known-project list".into(),
        ));
    }
    Ok(())
}

fn empty_plus_session(id: SessionId, name: String) -> PlusChatSession {
    PlusChatSession {
        id,
        name,
        chat: String::new(),
        command_outcome: String::new(),
        command_outcome_class: CommandOutcomeClass::Idle,
        pending: PendingFileSet::default(),
        in_flight: false,
    }
}

const fn default_command_outcome_class() -> CommandOutcomeClass {
    CommandOutcomeClass::Idle
}

fn pristine_default_session(session: &PlusChatSession) -> bool {
    session.id == "session-1"
        && session.chat.is_empty()
        && session.command_outcome.is_empty()
        && session.pending.items.is_empty()
        && !session.in_flight
}

fn default_session_book() -> PlusSessionBook {
    PlusSessionBook {
        active_id: "session-1".into(),
        sessions: vec![empty_plus_session("session-1".into(), "Session 1".into())],
    }
}

fn next_session_id() -> u64 {
    let stamp = unix_time_millis();
    let n = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
    stamp.saturating_add(n)
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1)
}

fn validate_state_file_name(name: &str) -> Result<(), PlusHostError> {
    let mut components = Path::new(name).components();
    if matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
    {
        Ok(())
    } else {
        Err(PlusHostError::Session(
            "desktop state filename must be one normal path component".into(),
        ))
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

fn set_read_only_owner_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn documented_desktop_state_root() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        home.unwrap_or_else(|| PathBuf::from("/"))
            .join("Library/Application Support/Grok Build")
    } else if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(xdg).join("grok-build")
    } else {
        home.unwrap_or_else(|| PathBuf::from("/"))
            .join(".local/state/grok-build")
    }
}

fn create_owner_only_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_owner_only_file(file: &fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}
