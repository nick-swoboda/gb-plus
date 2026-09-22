use std::ffi::OsStr;
use std::path::PathBuf;

use super::{bounded_error, workspace_paths_include_content};
use crate::git_process::git_command;

#[test]
fn watcher_errors_are_utf8_bounded() {
    let detail = "é".repeat(400);
    let bounded = bounded_error(&detail);
    assert!(bounded.len() <= 515);
    assert!(bounded.ends_with('…'));
}

#[test]
fn base_workspace_git_metadata_does_not_trigger_refresh_feedback() {
    let root = PathBuf::from("/private/tmp/grok-build-plus-watcher-fixture");
    for metadata_path in [
        root.join(".git/index"),
        root.join(".git/worktrees/task/index"),
        root.join("nested/.grok-build-transaction-000001.tmp"),
        root.join(":memory:.ses"),
    ] {
        assert!(
            !workspace_paths_include_content(&root, &[metadata_path]),
            "Git/app metadata must not become a Workspace content event"
        );
    }
    assert!(!workspace_paths_include_content(
        &root,
        &[PathBuf::from("/private/tmp/outside-project/.git/index")]
    ));
    assert!(workspace_paths_include_content(
        &root,
        &[root.join("project-a.txt")]
    ));
    assert!(workspace_paths_include_content(
        &root,
        &[root.join(".git/index"), root.join("src/lib.rs")]
    ));

    let command = git_command(&root);
    let optional_locks = command
        .get_envs()
        .find(|(name, _)| *name == OsStr::new("GIT_OPTIONAL_LOCKS"))
        .and_then(|(_, value)| value);
    assert_eq!(optional_locks, Some(OsStr::new("0")));

    let app_js = include_str!("../../ui/app.js");
    assert!(app_js.contains("workspaceBrowser.handleEvent(event.payload);"));
    assert!(!app_js.contains("worktreeManager.handleEvent(event.payload);"));
    assert!(!app_js.contains("gitReview.handleEvent(event.payload);"));
}
