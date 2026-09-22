use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use grok_build_plus_host::{PlusKnownProject, PlusSessionStore, bind_project_folder};

use crate::git_process::{MAX_GIT_METADATA_BYTES, git_command, require_git_success, run_git};

use super::{
    BEFORE_HUNK_APPLY_HOOK, discard_git_hunk, list_git_review, stage_git_hunk, unstage_git_hunk,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

fn fixture() -> PathBuf {
    std::env::temp_dir().join(format!(
        "grok-build-git-review-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn git(root: &Path, args: &[&str]) {
    let mut command = git_command(root);
    command.args(args);
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES).expect("run fixture Git");
    require_git_success(output, "prepare Git Review fixture").expect("fixture Git success");
}

fn git_fails(root: &Path, args: &[&str]) {
    let mut command = git_command(root);
    command.args(args);
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES).expect("run failing Git");
    assert!(require_git_success(output, "produce fixture conflict").is_err());
}

fn baseline() -> String {
    use std::fmt::Write as _;

    let mut text = String::new();
    for line in 1..=20 {
        writeln!(text, "line {line}").expect("write baseline line");
    }
    text
}

fn prepare() -> (PathBuf, PlusSessionStore, PlusKnownProject) {
    let root = fixture();
    let source = root.join("source");
    fs::create_dir_all(&source).expect("create source");
    git(&source, &["init", "--quiet", "--initial-branch=main"]);
    git(&source, &["config", "user.name", "Grok Build Test"]);
    git(
        &source,
        &["config", "user.email", "grok-build-test@invalid"],
    );
    fs::write(source.join("tracked.txt"), baseline()).expect("write baseline");
    git(&source, &["add", "--", "tracked.txt"]);
    git(&source, &["commit", "--quiet", "-m", "baseline"]);
    let source = source.canonicalize().expect("canonical source");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let bound = bind_project_folder(&source).expect("bind source");
    store
        .remember_known_project(&bound)
        .expect("remember source");
    let project = store.active_known_project().expect("active project");
    (root, store, project)
}

#[test]
fn hunk_stage_unstage_and_discard_are_separate_from_proposals() {
    let (root, store, project) = prepare();
    let mut changed = baseline().lines().map(str::to_owned).collect::<Vec<_>>();
    changed[0] = "LINE ONE".into();
    changed[19] = "LINE TWENTY".into();
    fs::write(
        project.root.join("tracked.txt"),
        format!("{}\n", changed.join("\n")),
    )
    .expect("write two hunks");

    let review = list_git_review(&project);
    let hunks = &review.unstaged_files[0].hunks;
    assert_eq!(hunks.len(), 2, "distant edits must remain separate hunks");
    let first_id = hunks[0].id.clone();
    let staged = stage_git_hunk(&store, &project, &first_id).expect("stage first hunk");
    assert_eq!(staged.outcome, "staged");
    assert_eq!(staged.review.staged_files[0].hunks.len(), 1);
    assert_eq!(staged.review.unstaged_files[0].hunks.len(), 1);

    let staged_id = staged.review.staged_files[0].hunks[0].id.clone();
    let unstaged = unstage_git_hunk(&store, &project, &staged_id).expect("unstage hunk");
    assert_eq!(unstaged.outcome, "unstaged");
    assert_eq!(unstaged.review.unstaged_files[0].hunks.len(), 2);

    let discard_id = unstaged.review.unstaged_files[0].hunks[0].id.clone();
    assert!(discard_git_hunk(&store, &project, &discard_id, "wrong").is_err());
    let confirmation = format!("DISCARD HUNK {}", &discard_id[..12]);
    let partly_discarded =
        discard_git_hunk(&store, &project, &discard_id, &confirmation).expect("discard first hunk");
    assert_eq!(partly_discarded.outcome, "discarded");
    assert_eq!(partly_discarded.review.unstaged_files[0].hunks.len(), 1);

    let final_id = partly_discarded.review.unstaged_files[0].hunks[0]
        .id
        .clone();
    let confirmation = format!("DISCARD HUNK {}", &final_id[..12]);
    let discarded =
        discard_git_hunk(&store, &project, &final_id, &confirmation).expect("discard final hunk");
    assert_eq!(discarded.outcome, "discarded");
    assert!(discarded.review.staged_files.is_empty());
    assert!(discarded.review.unstaged_files.is_empty());
    assert_eq!(
        fs::read_to_string(project.root.join("tracked.txt")).expect("read restored file"),
        baseline()
    );
    fs::remove_dir_all(root).expect("clean fixture");
}

#[test]
fn stale_binary_and_untracked_paths_never_fake_success() {
    let (root, store, project) = prepare();
    fs::write(
        project.root.join("tracked.txt"),
        baseline().replacen("line 1", "changed", 1),
    )
    .expect("modify text");
    let review = list_git_review(&project);
    let stale_id = review.unstaged_files[0].hunks[0].id.clone();
    fs::write(
        project.root.join("tracked.txt"),
        baseline().replacen("line 1", "drifted", 1),
    )
    .expect("drift text");
    let refused = stage_git_hunk(&store, &project, &stale_id).expect("stale refusal");
    assert_eq!(refused.outcome, "refused");

    fs::write(project.root.join("binary.bin"), [0_u8, 1, 2, 3]).expect("binary untracked");
    fs::write(project.root.join("new.txt"), "new line\n").expect("text untracked");
    let review = list_git_review(&project);
    let binary = review
        .unstaged_files
        .iter()
        .find(|file| file.path == "binary.bin")
        .expect("binary listed");
    assert!(binary.binary);
    assert!(binary.hunks.is_empty());
    let new_file = review
        .unstaged_files
        .iter()
        .find(|file| file.path == "new.txt")
        .expect("untracked text listed");
    assert_eq!(new_file.change_kind, "untracked");
    assert_eq!(new_file.hunks.len(), 1);
    fs::remove_dir_all(root).expect("clean fixture");
}

#[test]
fn drift_during_hunk_effect_is_refused_and_selected_effect_is_rolled_back() {
    let (root, store, project) = prepare();
    let mut selected = baseline().lines().map(str::to_owned).collect::<Vec<_>>();
    selected[0] = "SELECTED EDIT".into();
    fs::write(
        project.root.join("tracked.txt"),
        format!("{}\n", selected.join("\n")),
    )
    .expect("write selected edit");
    let review = list_git_review(&project);
    let hunk_id = review.unstaged_files[0].hunks[0].id.clone();

    let target = project.root.join("tracked.txt");
    let mut drifted = selected;
    drifted[19] = "CONCURRENT EDIT".into();
    *BEFORE_HUNK_APPLY_HOOK.lock().expect("set test hook") = Some((
        hunk_id.clone(),
        Box::new(move || {
            fs::write(target, format!("{}\n", drifted.join("\n"))).expect("inject same-path drift");
        }),
    ));

    let response = stage_git_hunk(&store, &project, &hunk_id).expect("drift response");
    assert_eq!(response.outcome, "refused");
    assert!(response.detail.contains("rolled back"));
    let after = list_git_review(&project);
    assert!(
        after.staged_files.is_empty(),
        "selected stage must be undone"
    );
    assert_eq!(
        after.unstaged_files[0].hunks.len(),
        2,
        "both worktree edits remain unstaged after rollback"
    );
    let bytes = fs::read_to_string(project.root.join("tracked.txt")).expect("drifted file");
    assert!(bytes.contains("SELECTED EDIT") && bytes.contains("CONCURRENT EDIT"));
    fs::remove_dir_all(root).expect("clean fixture");
}

#[test]
fn unresolved_conflict_refuses_every_hunk_action() {
    let (root, store, project) = prepare();
    git(&project.root, &["checkout", "-q", "-b", "other"]);
    fs::write(
        project.root.join("tracked.txt"),
        baseline().replacen("line 10", "other", 1),
    )
    .expect("other change");
    git(&project.root, &["add", "--", "tracked.txt"]);
    git(&project.root, &["commit", "--quiet", "-m", "other"]);
    git(&project.root, &["checkout", "-q", "main"]);
    fs::write(
        project.root.join("tracked.txt"),
        baseline().replacen("line 10", "main", 1),
    )
    .expect("main change");
    git(&project.root, &["add", "--", "tracked.txt"]);
    git(&project.root, &["commit", "--quiet", "-m", "main"]);
    git_fails(&project.root, &["merge", "--no-edit", "other"]);

    let review = list_git_review(&project);
    assert_eq!(review.conflict_paths, ["tracked.txt"]);
    let refused = stage_git_hunk(&store, &project, &"a".repeat(64)).expect("conflict refusal");
    assert_eq!(refused.outcome, "refused");
    assert!(refused.detail.contains("conflict"));
    git(&project.root, &["merge", "--abort"]);
    fs::remove_dir_all(root).expect("clean fixture");
}
