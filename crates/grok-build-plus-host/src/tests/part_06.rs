use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

use super::{
    PLUS_GH_MISSING, PLUS_GH_OPEN_PR, PLUS_NEEDS_ACCEPT, PLUS_SESSION_IDLE,
    PLUS_SESSION_NEEDS_ACCEPT, PLUS_SESSION_RUNNING, PendingFileProposal, PlusChatSession,
    PlusSessionBook, accept_pending_group_in_set, normalize_group_id, pending_line_groups,
    plus_github_open_pr_on_path,
    plus_github_status_on_path, present_needs_accept_inbox, present_plus_session_book,
    reject_pending_group_in_set, remaining_pending_groups,
};

fn two_group_before_after(unique: u64) -> (String, String) {
    let before = format!(
        "header-{unique}\nkeep-a\nOLD-ONE-{unique}\nkeep-b\nOLD-TWO-{unique}\nkeep-c\n"
    );
    let after = format!(
        "header-{unique}\nkeep-a\nNEW-ONE-{unique}\nkeep-b\nNEW-TWO-{unique}\nkeep-c\n"
    );
    (before, after)
}

#[test]
fn plus_p2_1_group_accept_reject_keeps_sibling_groups() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::path::PathBuf::from(format!("groups-{unique}.txt"));
    let (before, after) = two_group_before_after(unique);
    fs::write(folder.join(&path), &before).expect("seed");
    let set = propose_pending_files(&bound, [(path.clone(), after.clone().into_bytes())])
        .expect("propose");
    assert_eq!(
        fs::read_to_string(folder.join(&path)).expect("disk after propose"),
        before,
        "propose must not write"
    );
    let proposal = set.items.first().expect("one file");
    let groups = pending_line_groups(proposal);
    assert!(
        groups.len() >= 2,
        "fixture must produce two disjoint groups: {groups:?}"
    );
    let group_1 = groups[0].id.clone();
    let group_2 = groups[1].id.clone();
    assert_ne!(group_1, group_2);

    assert_eq!(normalize_group_id(&format!("group {group_1}")), group_1);
    let remaining = accept_pending_group_in_set(&bound, &set, &path, &format!("group {group_1}"))
        .expect("accept 1");
    let disk = fs::read_to_string(folder.join(&path)).expect("disk after group 1");
    assert!(
        disk.contains(&format!("NEW-ONE-{unique}")) && disk.contains(&format!("OLD-TWO-{unique}")),
        "Accept group 1 must write group 1 after and leave group 2 before: {disk}"
    );
    assert!(
        !disk.contains(&format!("OLD-ONE-{unique}")) && !disk.contains(&format!("NEW-TWO-{unique}")),
        "Accept group 1 must not write group 2 after or keep group 1 before: {disk}"
    );
    let presented = present_pending_file_set(&remaining);
    assert!(
        presented.contains(&format!("{}: pending", path.display()))
            && presented.contains(&format!("group {group_2}: pending")),
        "remaining presentation must still name the file and group 2: {presented}"
    );
    assert!(
        remaining_pending_groups(remaining.items.first().expect("still pending"))
            .iter()
            .any(|group| group.id == group_2),
        "group 2 must remain pending"
    );

    let leftover =
        reject_pending_group_in_set(&bound, &remaining, &path, &group_2).expect("reject 2");
    let disk = fs::read_to_string(folder.join(&path)).expect("disk after reject 2");
    assert!(
        disk.contains(&format!("NEW-ONE-{unique}")) && disk.contains(&format!("OLD-TWO-{unique}")),
        "Reject group 2 must keep group 1 after and group 2 before: {disk}"
    );
    assert!(
        leftover.items.is_empty(),
        "rejecting the last remaining group must drop the file from the set"
    );

    fs::write(folder.join(&path), &before).expect("reset");
    let set = propose_pending_files(&bound, [(path.clone(), after.clone().into_bytes())])
        .expect("propose file-level");
    accept_pending_file_in_set(&bound, &set, &path).expect("accept file");
    assert_eq!(
        fs::read_to_string(folder.join(&path)).expect("full after"),
        after
    );
    fs::write(folder.join(&path), &before).expect("restore before");
    let set = propose_pending_files(&bound, [(path.clone(), after.clone().into_bytes())])
        .expect("propose reject-file");
    reject_pending_file_in_set(&bound, &set, &path).expect("reject file");
    assert_eq!(
        fs::read_to_string(folder.join(&path)).expect("full before"),
        before
    );

    let path_b = std::path::PathBuf::from(format!("other-{unique}.txt"));
    fs::write(folder.join(&path_b), "b-before\n").expect("seed b");
    let multi = propose_pending_files(
        &bound,
        [
            (path.clone(), after.clone().into_bytes()),
            (path_b.clone(), b"b-after\n".to_vec()),
        ],
    )
    .expect("multi");
    reject_pending_file_set(&bound, &multi).expect("reject all");
    assert_eq!(fs::read_to_string(folder.join(&path)).expect("a"), before);
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b"),
        "b-before\n"
    );
    accept_pending_file_set(&bound, &multi).expect("accept all");
    assert_eq!(fs::read_to_string(folder.join(&path)).expect("a"), after);
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b"),
        "b-after\n"
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    for needle in ["Accept group", "Reject group", "Accept file", "Accept all"] {
        assert!(window.contains(needle), "window must show {needle}");
    }
}

#[test]
fn plus_p2_2_needs_accept_inbox_survives_switch_and_restore() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let root = unique_state_root();
    let store = PlusSessionStore::from_state_root(&root);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::path::PathBuf::from(format!("inbox-{unique}.txt"));
    let before = format!("inbox-before-{unique}\n");
    let after = format!("inbox-after-{unique}\n");
    fs::write(folder.join(&path), &before).expect("seed");
    let alpha = store
        .create_plus_session(&format!("Alpha-{unique}"))
        .expect("alpha");
    let set = propose_pending_files(&bound, [(path.clone(), after.clone().into_bytes())])
        .expect("propose");
    store.remember_pending_set(&set).expect("persist A");
    let inbox = present_needs_accept_inbox(&set);
    assert!(
        inbox.contains(PLUS_NEEDS_ACCEPT) && inbox.contains(&path.display().to_string()),
        "inbox must name the pending path: {inbox}"
    );

    let beta = store
        .create_plus_session(&format!("Beta-{unique}"))
        .expect("beta");
    let beta_pending = store.load_pending_set().expect("B pending");
    let beta_inbox = present_needs_accept_inbox(&beta_pending);
    assert!(
        !beta_inbox.contains(&path.display().to_string()) || beta_pending.items.is_empty(),
        "session B must not list A's path as needing accept: {beta_inbox}"
    );
    let _ = (alpha, beta);

    let switched = store
        .switch_plus_session(&format!("Alpha-{unique}"))
        .expect("switch A");
    assert!(
        switched
            .pending
            .items
            .iter()
            .any(|item| item.relative_path == path),
        "switch back must restore A's pending: {:?}",
        switched.pending
    );
    let restored_inbox = present_needs_accept_inbox(&switched.pending);
    assert!(
        restored_inbox.contains(PLUS_NEEDS_ACCEPT)
            && restored_inbox.contains(&path.display().to_string()),
        "{restored_inbox}"
    );

    let other = PlusSessionStore::from_state_root(&root);
    let restored = restore_plus_session(&other);
    assert!(
        restored.needs_accept.contains(PLUS_NEEDS_ACCEPT)
            && restored
                .needs_accept
                .contains(&path.display().to_string())
            && restored
                .pending
                .items
                .iter()
                .any(|item| item.relative_path == path),
        "second process on the same root must restore Needs Accept: {}",
        restored.needs_accept
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path)).expect("still before"),
        before,
        "restore must not write"
    );
    accept_pending_file_set(&bound, &restored.pending).expect("accept from inbox");
    assert_eq!(
        fs::read_to_string(folder.join(&path)).expect("after accept"),
        after
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("Needs Accept") && window.contains("present_needs_accept_inbox"),
        "window must show Needs Accept"
    );
}

#[test]
fn plus_p2_3_session_sidebar_idle_running_needs_accept() {
    let idle = PlusChatSession {
        id: "session-idle".into(),
        name: "Idle".into(),
        chat: String::new(),
        command_outcome: String::new(),
        command_outcome_class: super::CommandOutcomeClass::Idle,
        pending: PendingFileSet::default(),
        in_flight: false,
    };
    let mut needs = idle.clone();
    needs.id = "session-needs".into();
    needs.name = "Needs".into();
    needs.pending.items.push(PendingFileProposal {
        relative_path: std::path::PathBuf::from("pending.txt"),
        before: b"b\n".to_vec(),
        before_existed: Some(true),
        after: b"a\n".to_vec(),
        group_decisions: Vec::new(),
    });
    let mut running = idle.clone();
    running.id = "session-run".into();
    running.name = "Run".into();
    running.in_flight = true;
    let book = PlusSessionBook {
        active_id: idle.id.clone(),
        sessions: vec![idle, needs, running],
    };
    let presented = present_plus_session_book(&book);
    let idle_line = presented
        .lines()
        .find(|line| line.contains("session-idle"))
        .expect("idle line");
    let needs_line = presented
        .lines()
        .find(|line| line.contains("session-needs"))
        .expect("needs line");
    let run_line = presented
        .lines()
        .find(|line| line.contains("session-run"))
        .expect("run line");
    assert!(
        idle_line.contains(PLUS_SESSION_IDLE)
            && !idle_line.contains(PLUS_SESSION_RUNNING)
            && !idle_line.contains(PLUS_SESSION_NEEDS_ACCEPT),
        "{idle_line}"
    );
    assert!(
        needs_line.contains(PLUS_SESSION_NEEDS_ACCEPT)
            && !needs_line.contains(PLUS_SESSION_IDLE)
            && !needs_line.contains(PLUS_SESSION_RUNNING),
        "{needs_line}"
    );
    assert!(
        run_line.contains(PLUS_SESSION_RUNNING)
            && !run_line.contains(PLUS_SESSION_IDLE)
            && !run_line.contains(PLUS_SESSION_NEEDS_ACCEPT),
        "{run_line}"
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    for needle in [
        "Create session",
        "Switch session",
        "Rename session",
        "idle",
        "running",
        "needs accept",
    ] {
        assert!(window.contains(needle), "window must contain {needle}");
    }
}

#[test]
fn plus_p2_4_github_helper_skips_without_gh_and_invokes_stub() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let missing = plus_github_status_on_path(&bound, Some(std::ffi::OsStr::new("")));
    assert!(
        missing.skipped && missing.text.contains(PLUS_GH_MISSING),
        "missing gh must skip, not fail core: {missing:?}"
    );
    let missing_pr = plus_github_open_pr_on_path(&bound, Some(std::ffi::OsStr::new("")));
    assert!(
        missing_pr.skipped && missing_pr.text.contains(PLUS_GH_MISSING),
        "{missing_pr:?}"
    );

    let stub_dir = unique_folder();
    let stub = stub_dir.join("gh");
    let script = "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\" >> \"$(dirname \"$0\")/gh-argv\"\necho \"GitHub status: stub-ok\"\necho \"https://example.test/pr/1\"\n";
    fs::write(&stub, script).expect("stub");
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod");
    let path = stub_dir.as_os_str();
    let status = plus_github_status_on_path(&bound, Some(path));
    assert!(
        !status.skipped
            && status.text.contains("GitHub status")
            && (status.text.contains("stub-ok") || status.text.contains("gh pr status")),
        "{status:?}"
    );
    let opened = plus_github_open_pr_on_path(&bound, Some(path));
    assert!(
        !opened.skipped && opened.text.contains(PLUS_GH_OPEN_PR),
        "{opened:?}"
    );
    let argv = fs::read_to_string(stub_dir.join("gh-argv")).expect("argv");
    assert!(
        argv.contains("pr") && argv.contains("status") && argv.contains("view"),
        "stub gh must have been invoked: {argv}"
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    for needle in ["Git status", "Commit accepted", "GitHub status", "Open PR"] {
        assert!(window.contains(needle), "window must keep {needle}");
    }
}

#[test]
fn plus_p2_5_hot_path_latency() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::path::PathBuf::from(format!("p2-lat-{unique}.txt"));
    let (before, after) = two_group_before_after(unique);
    fs::write(folder.join(&path), &before).expect("seed");
    let set = propose_pending_files(&bound, [(path.clone(), after.into_bytes())]).expect("propose");

    let t0 = Instant::now();
    let presented = present_pending_file_set(&set);
    let present_us = t0.elapsed().as_micros();
    assert!(
        presented.contains("Pending review") && presented.contains(&path.display().to_string()),
        "{presented}"
    );

    let root = unique_state_root();
    let store = PlusSessionStore::from_state_root(&root);
    store
        .create_plus_session(&format!("lat-{unique}"))
        .expect("session");
    store
        .remember_chat_transcript(&format!("chat-{unique}"))
        .expect("chat");
    store.remember_pending_set(&set).expect("pending");
    let t1 = Instant::now();
    let list = store.present_plus_session_list();
    let list_us = t1.elapsed().as_micros();
    let t2 = Instant::now();
    let restored = restore_plus_session(&store);
    let restore_us = t2.elapsed().as_micros();
    assert!(list.contains(&format!("lat-{unique}")), "{list}");
    assert!(
        restored.chat.contains(&format!("chat-{unique}")),
        "{}",
        restored.chat
    );

    let t3 = Instant::now();
    let git = plus_git_status_report(&bound);
    let git_us = t3.elapsed().as_micros();
    assert!(!git.is_empty(), "{git}");

    let t4 = Instant::now();
    let github = plus_github_status_on_path(&bound, Some(std::ffi::OsStr::new("")));
    let gh_us = t4.elapsed().as_micros();
    assert!(github.skipped, "{github:?}");

    println!(
        "P2-5 hot-path us present={present_us} session_list={list_us} restore={restore_us} git={git_us} gh={gh_us}"
    );
}
