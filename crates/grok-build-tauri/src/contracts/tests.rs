use grok_build_plus_host::{PlusProjectBook, PlusSessionBook};
use serde::Serialize;

use super::{
    EventSequence, NotificationId, ProjectId, ProviderSessionId, QueueItemId, RunId, SessionId,
    SteerIntentId, WorkspaceId, WorktreeId,
};

fn exact_json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("serialize transparent ID")
}

#[test]
fn typed_ids_serialize_byte_for_byte_identically() {
    assert_eq!(exact_json(&ProjectId::new("project-a")), br#""project-a""#);
    assert_eq!(
        exact_json(&WorkspaceId::new("workspace-a")),
        br#""workspace-a""#
    );
    assert_eq!(
        exact_json(&WorktreeId::new("worktree-a")),
        br#""worktree-a""#
    );
    assert_eq!(exact_json(&SessionId::new("session-a")), br#""session-a""#);
    assert_eq!(
        exact_json(&ProviderSessionId::new("provider-a")),
        br#""provider-a""#
    );
    assert_eq!(exact_json(&QueueItemId::new("queue-a")), br#""queue-a""#);
    assert_eq!(exact_json(&RunId::new("run-a")), br#""run-a""#);
    assert_eq!(exact_json(&SteerIntentId::new("steer-a")), br#""steer-a""#);
    assert_eq!(
        exact_json(&NotificationId::new("notice-a")),
        br#""notice-a""#
    );
    assert_eq!(exact_json(&EventSequence::new(41)), b"41");

    let projects = br#"{"schema_version":2,"active_id":"project-a","projects":[]}"#;
    let project_book: PlusProjectBook = serde_json::from_slice(projects).expect("legacy projects");
    assert_eq!(exact_json(&project_book), projects);

    let sessions = br#"{"active_id":"session-a","sessions":[]}"#;
    let session_book: PlusSessionBook = serde_json::from_slice(sessions).expect("legacy sessions");
    assert_eq!(exact_json(&session_book), sessions);
}
