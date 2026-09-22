//! Durable, content-minimal in-app notifications.

#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use grok_build_plus_host::worktree_recovery_digest;
use serde::{Deserialize, Serialize};

use crate::contracts::{NotificationId, ProjectId, RunId, SessionId};
use crate::owner_state::{OwnerStateErrorKind, OwnerStateRoot};

pub(crate) const PLUS_NOTIFICATIONS_FILE: &str = "plus-notifications.json";
const NOTIFICATION_SCHEMA_VERSION: u16 = 1;
const MAX_NOTIFICATIONS: usize = 200;
const MAX_NOTIFICATION_BYTES: u64 = 256 * 1024;
const MAX_LABEL_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_ID_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NotificationCategory {
    Chat,
    Checks,
    Reviews,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NotificationRecord {
    pub(crate) id: NotificationId,
    pub(crate) category: NotificationCategory,
    pub(crate) source_sequence: Option<u64>,
    pub(crate) project_id: ProjectId,
    pub(crate) session_id: SessionId,
    pub(crate) run_id: Option<RunId>,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) read: bool,
    pub(crate) title: String,
    pub(crate) detail: String,
    pub(crate) relative_path: Option<String>,
    pub(crate) proposal_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotificationBook {
    schema_version: u16,
    records: Vec<NotificationRecord>,
}

impl Default for NotificationBook {
    fn default() -> Self {
        Self {
            schema_version: NOTIFICATION_SCHEMA_VERSION,
            records: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NotificationView {
    pub(crate) available: bool,
    pub(crate) status: String,
    pub(crate) unread_count: usize,
    pub(crate) records: Vec<NotificationRecord>,
}

#[derive(Clone)]
pub(crate) struct NotificationCenter {
    state_root: PathBuf,
    state: Arc<Mutex<Result<NotificationBook, String>>>,
}

impl NotificationCenter {
    pub(crate) fn open(state_root: PathBuf) -> Self {
        let loaded = load_book(&state_root);
        Self {
            state_root,
            state: Arc::new(Mutex::new(loaded)),
        }
    }

    pub(crate) fn view(&self) -> NotificationView {
        let Ok(state) = self.state.lock() else {
            return unavailable("Notification state lock is unavailable.");
        };
        match state.as_ref() {
            Ok(book) => NotificationView {
                available: true,
                status: if book.records.is_empty() {
                    "No notifications".into()
                } else {
                    format!("{} notifications", book.records.len())
                },
                unread_count: book.records.iter().filter(|record| !record.read).count(),
                records: book.records.iter().rev().cloned().collect(),
            },
            Err(reason) => unavailable(reason),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push(
        &self,
        category: NotificationCategory,
        source_sequence: Option<u64>,
        project_id: ProjectId,
        session_id: SessionId,
        run_id: Option<RunId>,
        title: &str,
        detail: &str,
        relative_path: Option<&str>,
        proposal_fingerprint: Option<&str>,
    ) -> Result<NotificationId, String> {
        validate_label(title, "title")?;
        validate_label(detail, "detail")?;
        if let Some(path) = relative_path {
            validate_path(path)?;
        }
        if let Some(fingerprint) = proposal_fingerprint {
            validate_fingerprint(fingerprint)?;
        }
        let dedupe = notification_identity_material(
            category,
            source_sequence,
            &project_id,
            &session_id,
            run_id.as_ref(),
            relative_path,
            proposal_fingerprint,
        );
        let id = NotificationId::new(format!(
            "notification-{}",
            &worktree_recovery_digest(&dedupe)[..32]
        ));
        self.mutate(|book| {
            if book.records.iter().any(|record| record.id == id) {
                return Ok(());
            }
            book.records.push(NotificationRecord {
                id: id.clone(),
                category,
                source_sequence,
                project_id,
                session_id,
                run_id,
                created_at_unix_ms: unix_time_millis(),
                read: false,
                title: title.to_owned(),
                detail: detail.to_owned(),
                relative_path: relative_path.map(str::to_owned),
                proposal_fingerprint: proposal_fingerprint.map(str::to_owned),
            });
            while book.records.len() > MAX_NOTIFICATIONS
                || encoded_book_len(book)? > MAX_NOTIFICATION_BYTES
            {
                let remove = book
                    .records
                    .iter()
                    .position(|record| record.read)
                    .unwrap_or(0);
                book.records.remove(remove);
            }
            Ok(())
        })?;
        Ok(id)
    }

    pub(crate) fn mark_project_read(&self, id: &NotificationId) -> Result<usize, String> {
        self.mutate(|book| {
            let project = book
                .records
                .iter()
                .find(|record| &record.id == id)
                .map(|record| record.project_id.clone())
                .ok_or_else(|| "Notification is no longer available.".to_owned())?;
            let mut count = 0;
            for record in &mut book.records {
                if record.project_id == project {
                    record.read = true;
                    count += 1;
                }
            }
            Ok(count)
        })
    }

    pub(crate) fn dismiss_project_notifications(
        &self,
        id: &NotificationId,
    ) -> Result<usize, String> {
        self.mutate(|book| {
            let project = book
                .records
                .iter()
                .find(|record| &record.id == id)
                .map(|record| record.project_id.clone())
                .ok_or_else(|| "Notification is no longer available.".to_owned())?;
            let before = book.records.len();
            book.records.retain(|record| record.project_id != project);
            Ok(before - book.records.len())
        })
    }

    pub(crate) fn resolve_proposal(&self, fingerprint: &str) -> Result<(), String> {
        validate_fingerprint(fingerprint)?;
        self.mutate(|book| {
            for record in &mut book.records {
                if record.proposal_fingerprint.as_deref() == Some(fingerprint) {
                    record.read = true;
                    record.detail = "Review resolved".into();
                }
            }
            Ok(())
        })
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut NotificationBook) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Notification state lock is unavailable.".to_owned())?;
        let book = state.as_mut().map_err(|reason| reason.clone())?;
        let before = book.clone();
        let result = match operation(book) {
            Ok(result) => result,
            Err(error) => {
                *book = before;
                return Err(error);
            }
        };
        if let Err(error) = validate_book(book).and_then(|()| save_book(&self.state_root, book)) {
            *book = before;
            return Err(error);
        }
        Ok(result)
    }
}

fn notification_identity_material(
    category: NotificationCategory,
    source_sequence: Option<u64>,
    project_id: &ProjectId,
    session_id: &SessionId,
    run_id: Option<&RunId>,
    relative_path: Option<&str>,
    proposal_fingerprint: Option<&str>,
) -> Vec<u8> {
    format!(
        "grok-build-plus-notification/v1\0{category:?}\0{}\0{}\0{}\0{}\0{}\0{}",
        source_sequence.unwrap_or_default(),
        project_id.as_str(),
        session_id.as_str(),
        run_id.map_or("", RunId::as_str),
        relative_path.unwrap_or(""),
        proposal_fingerprint.unwrap_or("")
    )
    .into_bytes()
}

fn load_book(state_root: &Path) -> Result<NotificationBook, String> {
    let file = OwnerStateRoot::new(state_root)
        .file(PLUS_NOTIFICATIONS_FILE, MAX_NOTIFICATION_BYTES)
        .map_err(|error| format!("Cannot inspect {PLUS_NOTIFICATIONS_FILE}: {error}"))?;
    let Some(bytes) = file.read().map_err(|error| match error.kind {
        OwnerStateErrorKind::Type => {
            format!("{PLUS_NOTIFICATIONS_FILE} is not a regular owner file.")
        }
        OwnerStateErrorKind::Owner => {
            format!("{PLUS_NOTIFICATIONS_FILE} permissions are not owner-only.")
        }
        OwnerStateErrorKind::Oversized => format!("{PLUS_NOTIFICATIONS_FILE} is oversized."),
        OwnerStateErrorKind::Read => format!("Cannot read {PLUS_NOTIFICATIONS_FILE}: {error}"),
        _ => format!("Cannot inspect {PLUS_NOTIFICATIONS_FILE}: {error}"),
    })?
    else {
        return Ok(NotificationBook::default());
    };
    let book = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{PLUS_NOTIFICATIONS_FILE} is invalid: {error}"))?;
    validate_book(&book)?;
    Ok(book)
}

fn save_book(state_root: &Path, book: &NotificationBook) -> Result<(), String> {
    validate_book(book)?;
    let mut bytes = serde_json::to_vec_pretty(book)
        .map_err(|error| format!("Cannot encode {PLUS_NOTIFICATIONS_FILE}: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_NOTIFICATION_BYTES {
        return Err(format!("{PLUS_NOTIFICATIONS_FILE} is oversized."));
    }
    OwnerStateRoot::new(state_root)
        .file(PLUS_NOTIFICATIONS_FILE, MAX_NOTIFICATION_BYTES)
        .and_then(|file| file.replace(&bytes))
        .map_err(|error| format!("Cannot atomically save {PLUS_NOTIFICATIONS_FILE}: {error}"))
}

fn validate_book(book: &NotificationBook) -> Result<(), String> {
    if book.schema_version != NOTIFICATION_SCHEMA_VERSION
        || book.records.len() > MAX_NOTIFICATIONS
        || encoded_book_len(book)? > MAX_NOTIFICATION_BYTES
    {
        return Err(format!(
            "{PLUS_NOTIFICATIONS_FILE} violates its schema bounds."
        ));
    }
    let mut ids = std::collections::HashSet::new();
    for record in &book.records {
        validate_notification_id(&record.id)?;
        validate_identity(record.project_id.as_str(), "project")?;
        validate_identity(record.session_id.as_str(), "session")?;
        if let Some(run_id) = &record.run_id {
            validate_identity(run_id.as_str(), "run")?;
        }
        if !ids.insert(record.id.clone())
            || record.created_at_unix_ms == 0
            || record.source_sequence == Some(0)
        {
            return Err(format!("{PLUS_NOTIFICATIONS_FILE} has invalid identities."));
        }
        validate_label(&record.title, "title")?;
        validate_label(&record.detail, "detail")?;
        if let Some(path) = &record.relative_path {
            validate_path(path)?;
        }
        if let Some(fingerprint) = &record.proposal_fingerprint {
            validate_fingerprint(fingerprint)?;
        }
        let review_binding =
            record.relative_path.is_some() && record.proposal_fingerprint.is_some();
        if (record.category == NotificationCategory::Reviews) != review_binding {
            return Err(
                "Review notification binding is incomplete or attached to another category.".into(),
            );
        }
    }
    Ok(())
}

fn encoded_book_len(book: &NotificationBook) -> Result<u64, String> {
    serde_json::to_vec_pretty(book)
        .map(|bytes| bytes.len().saturating_add(1) as u64)
        .map_err(|error| format!("Cannot encode {PLUS_NOTIFICATIONS_FILE}: {error}"))
}

fn validate_notification_id(id: &NotificationId) -> Result<(), String> {
    let value = id.as_str();
    let Some(digest) = value.strip_prefix("notification-") else {
        return Err("Notification identity is invalid.".into());
    };
    if digest.len() != 32 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Notification identity is invalid.".into());
    }
    Ok(())
}

fn validate_identity(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(format!("Notification {label} identity is invalid."));
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err("Notification relative path is invalid.".into());
    }
    Ok(())
}

fn validate_label(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(format!("Notification {label} is invalid."));
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Notification proposal fingerprint is invalid.".into());
    }
    Ok(())
}

fn unavailable(reason: &str) -> NotificationView {
    NotificationView {
        available: false,
        status: reason.to_owned(),
        unread_count: 0,
        records: Vec::new(),
    }
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::WorkspaceId;
    use crate::queue::{EnqueueRequest, QueueCoordinator};
    use crate::runtime::types::RuntimeTransport;

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "grok-build-notifications-{label}-{}-{}",
            std::process::id(),
            unix_time_millis()
        ))
    }

    #[test]
    fn notifications_are_durable_deduplicated_dismissible_and_content_minimal() {
        let root = root("roundtrip");
        let center = NotificationCenter::open(root.clone());
        let id = center
            .push(
                NotificationCategory::Reviews,
                Some(41),
                ProjectId::new("project-a"),
                SessionId::new("session-a"),
                Some(RunId::new("run-a")),
                "Review changes",
                "project-a · proposed.txt",
                Some("proposed.txt"),
                Some(&"a".repeat(64)),
            )
            .expect("push");
        center
            .push(
                NotificationCategory::Reviews,
                Some(41),
                ProjectId::new("project-a"),
                SessionId::new("session-a"),
                Some(RunId::new("run-a")),
                "Review changes",
                "project-a · proposed.txt",
                Some("proposed.txt"),
                Some(&"a".repeat(64)),
            )
            .expect("dedupe");
        assert_eq!(center.view().records.len(), 1);
        center.mark_project_read(&id).expect("read project");
        assert_eq!(center.view().unread_count, 0);
        let restored = NotificationCenter::open(root.clone());
        assert_eq!(restored.view().records.len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(root.join(PLUS_NOTIFICATIONS_FILE))
                .expect("notification metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        restored
            .dismiss_project_notifications(&id)
            .expect("dismiss project notifications");
        assert!(restored.view().records.is_empty());
        let bytes = fs::read(root.join(PLUS_NOTIFICATIONS_FILE)).expect("state");
        assert!(!bytes.windows(6).any(|window| window == b"prompt"));
        assert!(!bytes.windows(4).any(|window| window == b"diff"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn project_group_actions_are_atomic_and_do_not_cross_projects() {
        let root = root("project-groups");
        let center = NotificationCenter::open(root.clone());
        let push = |sequence, project: &str, session: &str| {
            center
                .push(
                    NotificationCategory::Chat,
                    Some(sequence),
                    ProjectId::new(project),
                    SessionId::new(session),
                    Some(RunId::new(format!("run-{sequence}"))),
                    "New reply",
                    project,
                    None,
                    None,
                )
                .expect("project notification")
        };
        let project_a_first = push(1, "project-a", "session-a");
        let project_a_second = push(2, "project-a", "session-a");
        let project_b = push(3, "project-b", "session-b");

        assert_eq!(center.mark_project_read(&project_a_first), Ok(2));
        let view = center.view();
        assert!(
            view.records
                .iter()
                .filter(|record| record.project_id.as_str() == "project-a")
                .all(|record| record.read)
        );
        assert!(
            view.records
                .iter()
                .find(|record| record.id == project_b)
                .is_some_and(|record| !record.read)
        );
        assert_eq!(
            center.dismiss_project_notifications(&project_a_second),
            Ok(2)
        );
        let remaining = center.view().records;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, project_b);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn notification_capacity_is_bounded_and_evicts_read_records_first() {
        let root = root("capacity");
        let center = NotificationCenter::open(root.clone());
        let first = center
            .push(
                NotificationCategory::Chat,
                Some(1),
                ProjectId::new("project-a"),
                SessionId::new("session-a"),
                Some(RunId::new("run-1")),
                "New reply",
                "Project A",
                None,
                None,
            )
            .expect("first notification");
        center
            .mark_project_read(&first)
            .expect("mark first project read");
        for sequence in 2..=205 {
            center
                .push(
                    NotificationCategory::Chat,
                    Some(sequence),
                    ProjectId::new("project-a"),
                    SessionId::new("session-a"),
                    Some(RunId::new(format!("run-{sequence}"))),
                    "New reply",
                    "Project A",
                    None,
                    None,
                )
                .expect("bounded notification");
        }
        let view = center.view();
        assert_eq!(view.records.len(), MAX_NOTIFICATIONS);
        assert!(!view.records.iter().any(|record| record.id == first));
        assert!(
            fs::metadata(root.join(PLUS_NOTIFICATIONS_FILE))
                .expect("notification metadata")
                .len()
                <= MAX_NOTIFICATION_BYTES
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn dismissed_review_notification_does_not_release_accept_gate() {
        let root = root("dismiss-review-gate");
        let queue = QueueCoordinator::open(root.clone());
        let project = ProjectId::new("project-a");
        queue
            .enqueue(EnqueueRequest {
                project_id: project.clone(),
                workspace_id: WorkspaceId::new("workspace-a"),
                workspace_root: "/tmp/project-a".into(),
                session_id: SessionId::new("session-a"),
                transport: RuntimeTransport::GrokCliAcp,
                prompt: "queued after review".into(),
                auto_start: true,
                retry_of_run_id: None,
                predecessor_run_id: None,
            })
            .expect("enqueue");
        queue.set_review_blocked(&project, true).expect("gate");
        let center = NotificationCenter::open(root.clone());
        let id = center
            .push(
                NotificationCategory::Reviews,
                Some(7),
                project.clone(),
                SessionId::new("session-a"),
                Some(RunId::new("run-a")),
                "Review changes",
                "project-a · pending.txt",
                Some("pending.txt"),
                Some(&"b".repeat(64)),
            )
            .expect("push");
        center
            .dismiss_project_notifications(&id)
            .expect("dismiss project notifications");
        assert!(queue.candidates(None, true).expect("candidates").is_empty());
        assert!(
            queue
                .view()
                .review_blocked_project_ids
                .contains(&project.as_str().to_owned())
        );
        drop(queue);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
