use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

fn root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "grok-build-tool-lifecycle-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn todo_request() -> PlusToolRequest {
    PlusToolRequest {
        name: PlusToolName::TodoWrite,
        path: PathBuf::new(),
        after: Some(
            serde_json::to_vec(&json!({
                "merge": false,
                "todos": [{"id": "one", "content": "fixture", "status": "pending"}]
            }))
            .expect("encode todo fixture"),
        ),
        query: None,
        case_insensitive: false,
        replace_all: false,
    }
}

fn run_contained_request() -> PlusToolRequest {
    PlusToolRequest {
        name: PlusToolName::RunContained,
        path: PathBuf::new(),
        after: None,
        query: None,
        case_insensitive: false,
        replace_all: false,
    }
}

#[test]
fn observer_failure_before_dispatch_prevents_the_tool_effect() {
    let root = root("pre-effect");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let bound = super::super::bind_project_folder(&workspace).expect("bind workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let error = run_plus_tool_loop_on_store_in_mode_observed(
        &bound,
        Some(&store),
        &[todo_request()],
        PlusSessionMode::Agent,
        &mut |_| Err(PlusHostError::Session("event journal unavailable".into())),
    )
    .expect_err("observer must stop dispatch");
    assert!(error.to_string().contains("event journal unavailable"));
    assert!(
        !store
            .state_root()
            .join(super::super::PLUS_TODOS_FILE)
            .exists()
    );
    fs::remove_dir_all(root).expect("remove pre-effect fixture");
}

#[test]
fn observer_brackets_the_exact_tool_outcome() {
    let root = root("ordered");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let bound = super::super::bind_project_folder(&workspace).expect("bind workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut events = Vec::new();
    let report = run_plus_tool_loop_on_store_in_mode_observed(
        &bound,
        Some(&store),
        &[todo_request()],
        PlusSessionMode::Agent,
        &mut |event| {
            events.push(event);
            Ok(())
        },
    )
    .expect("observed tool loop");
    assert!(report.steps[0].ok);
    assert_eq!(
        events,
        vec![
            PlusToolLifecycleEvent::Requested {
                name: "todo_write".into()
            },
            PlusToolLifecycleEvent::Completed {
                name: "todo_write".into()
            }
        ]
    );
    assert!(
        store
            .state_root()
            .join(super::super::PLUS_TODOS_FILE)
            .is_file()
    );
    fs::remove_dir_all(root).expect("remove ordered fixture");
}

#[test]
fn contained_refusal_is_failed_and_emits_refused_not_completed() {
    let root = root("contained-refusal");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let bound = super::super::bind_project_folder(&workspace).expect("bind workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut events = Vec::new();
    let report = run_plus_tool_loop_on_store_in_mode_observed(
        &bound,
        Some(&store),
        &[run_contained_request()],
        PlusSessionMode::Agent,
        &mut |event| {
            events.push(event);
            Ok(())
        },
    )
    .expect("observe contained refusal");
    assert!(!report.steps[0].ok);
    assert!(
        report.steps[0]
            .result
            .contains("This is not a successful command.")
    );
    assert!(present_plus_tool_steps(&report.steps).contains("run_contained → failed:"));
    assert_eq!(
        events,
        vec![
            PlusToolLifecycleEvent::Requested {
                name: "run_contained".into()
            },
            PlusToolLifecycleEvent::Refused {
                name: "run_contained".into()
            }
        ]
    );
    fs::remove_dir_all(root).expect("remove contained-refusal fixture");
}
