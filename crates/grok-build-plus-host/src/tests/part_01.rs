use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use grok_build_core::CommandTerminationV1;
use grok_build_providers::{FakeProvider, ModelProvider};

use super::{
    PLUS_ACCEPT_REQUIRED, PLUS_ASSISTANT_PROPOSAL_PATH, PLUS_ATTACH_MAX_BYTES,
    PLUS_CHAT_TRANSCRIPT_FILE, PLUS_COMMAND_OUTCOME_FILE, PLUS_COULD_NOT_RESTORE,
    PLUS_GLOB_MAX_MATCHES, PLUS_GLOB_NO_MATCHES, PLUS_GLOB_TRUNCATED, PLUS_LIVE_ENDPOINT,
    PLUS_LIVE_PROVIDER_LABEL, PLUS_LIVE_TOOL_PARSE_ERROR,
    PLUS_MAX_TOOL_STEPS,
    PLUS_NOT_YET_DURABLE, PLUS_PROVIDER_LABEL, PLUS_SEARCH_MAX_FILES, PLUS_SEARCH_NO_MATCHES,
    PLUS_SEARCH_TRUNCATED, PLUS_SKETCH_MAX_ENTRIES, PLUS_SKETCH_TRUNCATED, PLUS_STATUS_PLANNING,
    PLUS_STATUS_PROPOSING, PLUS_STATUS_READING, PLUS_STATUS_RUNNING,
    PLUS_STATUS_WAITING_FOR_ACCEPT, PLUS_TODO_NOT_WORKSPACE, PLUS_TODOS_FILE, PLUS_TOOL_COMPLETED,
    PLUS_TOOL_FAILED, PLUS_TOOL_LOOP_NOT_RUN, PLUS_TOOL_NOT_WRITTEN, PLUS_TOOL_NOTE_PATH,
    PLUS_TOOL_PROPOSE_PATH, PlusAgentStatus, PlusHostError, PlusLiveIdentity, PlusLiveImage,
    PlusSessionStore, PlusTodoStatus, PlusTodoUpdate, PlusToolLifecycleEvent, PlusToolName,
    PlusToolRequest,
    accept_pending_file_in_set,
    accept_pending_file_proposal, accept_pending_file_set, attach_plus_file,
    bind_and_remember_project_folder, bind_project_folder, decode_plus_live_chat_response,
    drive_plus_click_path_and_remember, drive_plus_click_path_with_identity,
    encode_plus_live_chat_request, encode_plus_live_chat_request_with_image,
    encode_plus_live_tool_requests, load_plus_todos,
    parse_live_tool_requests, parse_plus_live_tool_reply, plus_chat_turn,
    plus_chat_turn_and_remember_with_attachments, plus_chat_turn_with_identity,
    plus_chat_turn_with_identity_and_remember, plus_compose_send_context,
    plus_live_tool_instructions,
    plus_compose_user_with_attachments, plus_directory_sketch, plus_git_commit_accepted,
    plus_git_status_report, plus_gui_contained_command, plus_run_checks_after_accept,
    plus_todo_write, plus_tool_glob, plus_tool_grep, plus_tool_propose_replace,
    plus_tool_read_file,
    present_command_termination, present_pending_file_diff, present_pending_file_set,
    present_plus_agent_status, present_plus_agent_status_trail, present_plus_file_pane,
    present_plus_permission_copy, present_plus_tool_steps, propose_assistant_response_as_file,
    propose_pending_file, propose_pending_files, reject_pending_file_in_set,
    reject_pending_file_proposal, reject_pending_file_set, restore_plus_session,
    run_plus_live_harness_observed_external_with_image_and_steering, run_plus_tool_loop,
};
use grok_build_runner_client::containment_reason;

static NEXT: AtomicU64 = AtomicU64::new(1);

fn unique_folder() -> std::path::PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("grok-build-plus-host-{}-{n}", std::process::id()));
    fs::create_dir_all(&root).expect("create plus host fixture");
    fs::canonicalize(&root).expect("canonicalize plus host fixture")
}

fn unique_state_root() -> std::path::PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("grok-build-plus-state-{}-{n}", std::process::id()))
}

fn live_follow_up_bytes(text: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "object": "response",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "output_text", "text": text }]
        }]
    }))
    .expect("follow-up body")
}

fn then_follow_up(
    first: impl FnMut(&super::PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
) -> impl FnMut(&super::PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError> {
    then_follow_up_text(first, "follow-up after tool results")
}

fn then_follow_up_text(
    mut first: impl FnMut(&super::PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    text: &'static str,
) -> impl FnMut(&super::PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError> {
    let follow = live_follow_up_bytes(text);
    let mut n = 0_u32;
    move |request| {
        n += 1;
        if n == 1 {
            first(request)
        } else {
            Ok(follow.clone())
        }
    }
}

#[test]
fn bind_project_folder_uses_workspace_grant_issuer() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind absolute folder");
    assert_eq!(bound.folder(), folder.as_path());
    assert_eq!(
        bound.grant.contract().canonical_root.as_path(),
        folder.as_path()
    );
    let relative = bind_project_folder("relative-not-a-project");
    assert!(relative.is_err(), "relative paths must not bind");
}

#[test]
fn plus_chat_turn_uses_fake_provider_and_labels_the_stub() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let turn = if PlusLiveIdentity::from_process_env().is_some() {
        plus_chat_turn_with_identity(&bound, "what is in this project?", None, |_| {
            unreachable!("unconfigured chat must not call live transport")
        })
    } else {
        plus_chat_turn(&bound, "what is in this project?")
    }
    .expect("stub chat");
    assert_eq!(turn.user_text, "what is in this project?");
    assert!(
        turn.assistant_text
            .contains("not configured → FakeProvider"),
        "chat must show not configured → FakeProvider: {}",
        turn.assistant_text
    );
    assert!(
        turn.assistant_text.contains(PLUS_PROVIDER_LABEL),
        "chat must label FakeProvider as a stub: {}",
        turn.assistant_text
    );
    let planned = FakeProvider::new()
        .plan_sprint(&super::plus_sprint(&bound, "what is in this project?"))
        .expect("plan");
    let delta = planned
        .events
        .iter()
        .find_map(|event| match &event.payload {
            grok_build_providers::ProviderEventKind::AssistantDelta(text) => Some(text.as_str()),
            _ => None,
        });
    let delta = delta.expect("FakeProvider emits AssistantDelta");
    assert!(
        turn.assistant_text.contains(delta),
        "assistant text must carry the real FakeProvider delta {delta:?}, got {}",
        turn.assistant_text
    );
}

#[test]
fn plus_chat_turn_send_function_delegates_to_identity_path() {
    let source = include_str!("../lib.rs");
    assert!(
        source.contains("plus_chat_turn_with_identity"),
        "Send wrapper must call plus_chat_turn_with_identity"
    );
    assert!(
        source.contains("PlusLiveIdentity::from_process_env()"),
        "Send wrapper must read XAI_API_KEY via from_process_env"
    );
    assert!(
        source.contains("post_plus_live_chat"),
        "Send wrapper must use the shipped live transport"
    );
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("plus_chat_turn_and_remember_with_attachments_in_mode("),
        "Send button must call plus_chat_turn_and_remember_with_attachments_in_mode"
    );
}

#[test]
fn plus_chat_turn_live_identity_uses_request_response_not_fake() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let user = format!("plus-live-user-{unique}");
    let assistant = format!("plus-live-assistant-{unique}");
    let identity = PlusLiveIdentity::from_configured_key("gbplus4-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let expected = assistant.clone();
    let user_for_transport = user.clone();
    let turn = plus_chat_turn_with_identity(&bound, &user, Some(identity), move |request| {
        assert_eq!(request.endpoint, PLUS_LIVE_ENDPOINT);
        assert!(
            request.json_body().contains(&user_for_transport),
            "shipped request must carry the user text: {}",
            request.json_body()
        );
        assert!(
            !request
                .json_body()
                .contains("gbplus4-test-key-SHOULD-NOT-LEAK"),
            "request JSON must not contain the API key"
        );
        let debug = format!("{request:?}");
        assert!(
            !debug.contains("gbplus4-test-key-SHOULD-NOT-LEAK"),
            "Debug must redact the API key: {debug}"
        );
        let body = serde_json::json!({
            "id": format!("resp-{unique}"),
            "object": "response",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": expected
                }]
            }]
        });
        Ok(serde_json::to_vec(&body).expect("fixture response"))
    })
    .expect("live chat");
    assert_eq!(turn.user_text, user);
    assert!(
        turn.assistant_text.contains(&assistant),
        "assistant text must be the live response content, got {}",
        turn.assistant_text
    );
    assert!(
        turn.assistant_text.contains(PLUS_LIVE_PROVIDER_LABEL),
        "live turn must label the live provider: {}",
        turn.assistant_text
    );
    assert!(
        !turn.assistant_text.contains("FakeProvider"),
        "configured live must not be the Fake stub: {}",
        turn.assistant_text
    );
    assert!(
        !turn.assistant_text.contains("Created deterministic plan"),
        "configured live must not emit the Fake planning transcript: {}",
        turn.assistant_text
    );
    assert!(
        turn.assistant_text.contains(PLUS_TOOL_LOOP_NOT_RUN),
        "plain live text must say the tool loop was not run: {}",
        turn.assistant_text
    );
    assert!(
        turn.steps.is_empty(),
        "plain live text must not invent tool steps"
    );
}

#[test]
fn plus_chat_turn_live_transport_error_does_not_fall_back_to_fake() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let identity = PlusLiveIdentity::from_configured_key("gbplus4-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let error = plus_chat_turn_with_identity(&bound, "hello live", Some(identity), |_| {
        Err(PlusHostError::Live(
            "representative transport failure".into(),
        ))
    })
    .expect_err("live failure must surface");
    let text = error.to_string();
    assert!(text.contains("live"), "honest live error required: {text}");
    assert!(
        !text.contains("FakeProvider"),
        "live failure must not fall back to FakeProvider: {text}"
    );
    assert!(
        !text.contains("Created deterministic plan"),
        "live failure must not emit Fake planning text: {text}"
    );
}

#[test]
fn encode_and_decode_plus_live_chat_use_xai_responses_json() {
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let user = format!("encode-user-{unique}");
    let assistant = format!("decode-assistant-{unique}");
    let identity = PlusLiveIdentity::from_configured_key("gbplus4-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let request = encode_plus_live_chat_request(&user, &identity).expect("encode");
    assert_eq!(request.endpoint, PLUS_LIVE_ENDPOINT);
    let body: serde_json::Value = serde_json::from_str(request.json_body()).expect("json");
    assert_eq!(body["model"], "grok-4.6");
    assert_eq!(body["input"], user);
    assert_eq!(body["store"], false);
    assert_eq!(body["instructions"], plus_live_tool_instructions());
    let tools = body["tools"]
        .as_array()
        .expect("live request must declare tools");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
        .collect();
    for name in [
        "list_dir",
        "read_file",
        "grep",
        "glob",
        "propose_write",
        "propose_replace",
        "todo_write",
        "run_contained",
    ] {
        assert!(
            names.contains(&name),
            "live request must declare {name}: {names:?}"
        );
    }
    assert!(
        body["instructions"]
            .as_str()
            .is_some_and(|text| text.contains("plus_tool")),
        "live request instructions must carry the plus_tool format"
    );
    assert!(
        body.get("search_parameters").is_none(),
        "search_parameters is deprecated on /v1/responses and must not be sent"
    );
    let responses = serde_json::json!({
        "object": "response",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "output_text", "text": assistant }]
        }]
    });
    let decoded = decode_plus_live_chat_response(&serde_json::to_vec(&responses).expect("bytes"))
        .expect("decode responses");
    assert_eq!(decoded, assistant);
    let chat = serde_json::json!({
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": assistant }
        }]
    });
    let decoded_chat = decode_plus_live_chat_response(&serde_json::to_vec(&chat).expect("bytes"))
        .expect("decode chat");
    assert_eq!(decoded_chat, assistant);
}

#[test]
fn native_responses_image_is_bounded_transient_and_debug_redacted() {
    let identity = PlusLiveIdentity::from_configured_key("gbplus4-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let image_marker = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB";
    let image = PlusLiveImage {
        base64_png: image_marker,
    };
    let request = encode_plus_live_chat_request_with_image("inspect this still", Some(&image), &identity)
        .expect("image request");
    let body: serde_json::Value = serde_json::from_str(request.json_body()).expect("json");
    assert_eq!(body["store"], false);
    assert_eq!(body["input"][0]["role"], "user");
    assert_eq!(body["input"][0]["content"][0]["type"], "input_image");
    assert_eq!(
        body["input"][0]["content"][0]["image_url"],
        format!("data:image/png;base64,{image_marker}")
    );
    assert_eq!(body["input"][0]["content"][1]["text"], "inspect this still");
    let debug = format!("{request:?}");
    assert!(!debug.contains(image_marker));
    assert!(!debug.contains("inspect this still"));
    assert!(debug.contains("[redacted;"));
}

#[test]
fn present_command_termination_uses_the_real_enum_spelling() {
    let timed_out = CommandTerminationV1::TimedOut;
    let presented = present_command_termination(timed_out);
    assert!(
        presented.contains(&format!("{timed_out:?}")),
        "timeout text must include the real CommandTerminationV1 spelling: {presented}"
    );
    let ok = CommandTerminationV1::Exited { code: 0 };
    let presented_ok = present_command_termination(ok);
    assert!(
        presented_ok.contains(&format!("{ok:?}")),
        "success text must include the real termination: {presented_ok}"
    );
}

#[test]
fn plus_gui_contained_command_shows_real_refusal_and_containment_reason() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let text = plus_gui_contained_command(&bound);
    assert!(
        crate::plus_outcome_is_real_command_terminal(&text)
            || text.contains(&containment_reason()),
        "GUI contained path must show a real terminal or the coordinator refusal: {text}"
    );
    assert!(
        !text.contains("grant does not authorize non-interactive commands"),
        "execute_commands grant must not fail at policy compile: {text}"
    );
    assert!(
        crate::plus_outcome_is_real_command_terminal(&text)
            || text.contains("unavailable")
            || text.contains("descriptor")
            || text.contains("launch")
            || text.contains("macOS")
            || text.contains("lifecycle")
            || text.contains("runner")
            || text.contains("WorkerRunCommand")
            || text.contains("/usr/bin/true")
            || text.contains("plus-contained-probe")
            || text.contains("guest down")
            || text.contains("service missing")
            || text.contains("ready"),
        "GUI contained path must include the real launch or send outcome: {text}"
    );
}

#[test]
fn drive_plus_click_path_uses_shipped_bind_chat_and_contained_entry() {
    let folder = unique_folder();
    let report = drive_plus_click_path_with_identity(&folder, "what is in this project?", None)
        .expect("click path");
    assert_eq!(report.folder, folder);
    assert!(
        report.chat.contains("not configured → FakeProvider"),
        "click-path chat must show not configured → FakeProvider: {}",
        report.chat
    );
    assert!(
        report.chat.contains(PLUS_PROVIDER_LABEL),
        "click-path chat must label the stub: {}",
        report.chat
    );
    assert!(
        report.command_outcome.contains(&containment_reason())
            || report.command_outcome.contains("/usr/bin/true")
            || report.command_outcome.contains("plus-contained-probe")
            || report.command_outcome.contains("guest down")
            || report.command_outcome.contains("service missing")
            || report.command_outcome.contains("ready"),
        "click-path command must be the shipped contained entry: {}",
        report.command_outcome
    );
}

#[test]
fn plus_gui_contained_command_source_calls_send() {
    let source = include_str!("../lib.rs");
    assert!(
        source.contains("plus_gui_contained_command_with_session"),
        "window entry must share the dispatch that tests inject"
    );
    assert!(
        source.contains("send_plus_precommitted_worker_command"),
        "window dispatch must call the send wrapper"
    );
    assert!(
        source.contains("send_precommitted_task_command"),
        "send wrapper must call the existing runner-client send"
    );
}

#[test]
fn restore_plus_session_returns_last_path_and_persisted_chat_run() {
    let root = unique_state_root();
    let store = PlusSessionStore::from_state_root(&root);
    let empty = restore_plus_session(&store);
    assert!(
        empty.last_workspace.is_none(),
        "fresh store has no last workspace"
    );

    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let user = format!("durable-chat-{unique}");
    let report = drive_plus_click_path_and_remember(&store, &folder, &user, None)
        .expect("first process click path");
    assert_eq!(report.folder, folder);
    assert!(
        report.chat.contains(&user),
        "first process chat must carry the user text {user}: {}",
        report.chat
    );
    assert!(
        !report.command_outcome.is_empty(),
        "first process must produce a contained-run outcome"
    );

    let second = PlusSessionStore::from_state_root(&root);
    let restored = restore_plus_session(&second);
    assert_eq!(
        restored.last_workspace.as_deref(),
        Some(folder.as_path()),
        "second process must restore the last workspace path"
    );
    assert!(
        restored
            .folder_status
            .contains(&folder.display().to_string()),
        "folder status must name the last path: {}",
        restored.folder_status
    );
    assert!(
        restored.chat.contains(&report.chat),
        "restored chat must contain the first-call chat text: restored={} first={}",
        restored.chat,
        report.chat
    );
    assert!(
        restored.command_outcome.contains(&report.command_outcome),
        "restored command must contain the first-call outcome: restored={} first={}",
        restored.command_outcome,
        report.command_outcome
    );
    assert!(
        !restored.chat.contains(PLUS_NOT_YET_DURABLE),
        "persisted chat must not be labeled not yet durable: {}",
        restored.chat
    );
    assert!(
        !restored.command_outcome.contains(PLUS_NOT_YET_DURABLE),
        "persisted command must not be labeled not yet durable: {}",
        restored.command_outcome
    );
}

#[test]
fn restore_plus_session_surfaces_could_not_restore_on_unreadable_store() {
    let store = PlusSessionStore::from_state_root(unique_state_root());
    let folder = unique_folder();
    bind_and_remember_project_folder(&store, &folder).expect("remember bind");
    fs::write(
        store.state_root().join(PLUS_CHAT_TRANSCRIPT_FILE),
        [0xFF, 0xFE],
    )
    .expect("write unreadable chat");
    fs::write(
        store.state_root().join(PLUS_COMMAND_OUTCOME_FILE),
        [0xFF, 0xFE],
    )
    .expect("write unreadable command");

    let restored = restore_plus_session(&store);
    assert!(
        restored.chat.contains(PLUS_COULD_NOT_RESTORE),
        "unreadable chat must say could not restore: {}",
        restored.chat
    );
    assert!(
        restored.command_outcome.contains(PLUS_COULD_NOT_RESTORE),
        "unreadable command must say could not restore: {}",
        restored.command_outcome
    );
    assert!(
        restored.last_workspace.as_deref() == Some(folder.as_path()),
        "folder restore must still succeed when only transcripts are broken"
    );
}

#[test]
fn window_start_uses_restore_plus_session() {
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    let shipped = window
        .split("#[cfg(test)]")
        .next()
        .expect("shipped window source");
    assert!(
        shipped.contains("restore_plus_session"),
        "window start must call restore_plus_session"
    );
    assert!(
        shipped.contains("bind_and_remember_project_folder"),
        "Bind must remember last workspace"
    );
    assert!(
        shipped.contains("plus_chat_turn_and_remember"),
        "Send must persist chat through plus_chat_turn_and_remember"
    );
    assert!(
        shipped.contains("plus_gui_contained_command_and_remember"),
        "Run must persist the contained-run outcome"
    );
}

#[test]
fn accept_and_reject_pending_file_proposal_apply_or_leave_bytes() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("note-{unique}.txt"));
    let before = format!("before-{unique}\n");
    let after = format!("after-{unique}\n");
    fs::write(folder.join(&relative), &before).expect("seed before");

    let proposal =
        propose_pending_file(&bound, &relative, after.clone().into_bytes()).expect("propose");
    let diff = present_pending_file_diff(&proposal);
    assert!(
        diff.contains(&relative.display().to_string()),
        "diff must name the path: {diff}"
    );
    assert!(
        diff.contains(before.trim_end()),
        "diff must include the before side: {diff}"
    );
    assert!(
        diff.contains(after.trim_end()),
        "diff must include the after side: {diff}"
    );

    reject_pending_file_proposal(&bound, &proposal).expect("reject");
    let rejected = fs::read_to_string(folder.join(&relative)).expect("read after reject");
    assert_eq!(rejected, before, "reject must not apply proposed bytes");

    accept_pending_file_proposal(&bound, &proposal).expect("accept");
    let accepted = fs::read_to_string(folder.join(&relative)).expect("read after accept");
    assert_eq!(accepted, after, "accept must write proposed bytes");

    reject_pending_file_proposal(&bound, &proposal).expect("reject old intent");
    let unchanged = fs::read_to_string(folder.join(&relative)).expect("read after late reject");
    assert_eq!(
        unchanged, after,
        "Reject is a no-write decision and must never roll workspace bytes back"
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("accept_pending_file_set"),
        "Accept all must call accept_pending_file_set"
    );
    assert!(
        window.contains("reject_pending_file_set"),
        "Reject all must call reject_pending_file_set"
    );
}

#[cfg(unix)]
#[test]
fn workspace_reads_and_accept_fail_closed_on_stale_or_symlinked_paths() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let target = std::path::PathBuf::from("safe/note.txt");
    fs::create_dir_all(folder.join("safe")).expect("safe parent");
    fs::write(folder.join(&target), b"before\n").expect("seed target");

    let stale = propose_pending_file(&bound, &target, b"after\n".to_vec()).expect("stage");
    fs::write(folder.join(&target), b"external edit\n").expect("external edit");
    let error = accept_pending_file_proposal(&bound, &stale).expect_err("stale accept refuses");
    assert!(error.to_string().contains("changed after staging"));
    assert_eq!(fs::read(folder.join(&target)).expect("stale bytes"), b"external edit\n");

    fs::write(folder.join(&target), b"before\n").expect("reset target");
    let swapped = propose_pending_file(&bound, &target, b"after\n".to_vec()).expect("restage");
    let outside = unique_folder().join("outside.txt");
    fs::write(&outside, b"outside\n").expect("outside seed");
    fs::remove_file(folder.join(&target)).expect("remove target for symlink swap");
    symlink(&outside, folder.join(&target)).expect("swap final component");
    let error = accept_pending_file_proposal(&bound, &swapped).expect_err("symlink accept refuses");
    assert!(error.to_string().contains("unsafe"));
    assert_eq!(fs::read(&outside).expect("outside remains"), b"outside\n");
    reject_pending_file_proposal(&bound, &swapped).expect("Reject remains no-write");
    assert_eq!(fs::read(&outside).expect("outside after reject"), b"outside\n");
    assert!(plus_tool_read_file(&bound, &target).is_err());

    fs::remove_file(folder.join(&target)).expect("remove final symlink");
    fs::write(folder.join(&target), b"before\n").expect("seed intermediate fixture");
    let intermediate =
        propose_pending_file(&bound, &target, b"after\n".to_vec()).expect("stage nested");
    fs::rename(folder.join("safe"), folder.join("safe-original")).expect("rename safe parent");
    let outside_dir = unique_folder();
    fs::write(outside_dir.join("note.txt"), b"outside parent\n").expect("outside parent seed");
    symlink(&outside_dir, folder.join("safe")).expect("swap intermediate component");
    let error =
        accept_pending_file_proposal(&bound, &intermediate).expect_err("parent symlink refuses");
    assert!(error.to_string().contains("unsafe"));
    assert_eq!(
        fs::read(outside_dir.join("note.txt")).expect("outside parent remains"),
        b"outside parent\n"
    );
    assert!(plus_tool_read_file(&bound, &target).is_err());
}

#[test]
fn propose_assistant_response_as_file_does_not_write_until_accept() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let user = format!("propose-user-{unique}");
    let turn = plus_chat_turn_with_identity(&bound, &user, None, |_| {
        unreachable!("unconfigured chat must not call live transport")
    })
    .expect("fake assistant");
    assert!(
        turn.assistant_text.contains(&user),
        "assistant text must carry the user prompt {user}: {}",
        turn.assistant_text
    );

    let target = folder.join(PLUS_ASSISTANT_PROPOSAL_PATH);
    assert!(
        !target.exists(),
        "fixture must start without the assistant file"
    );

    let proposal = propose_assistant_response_as_file(&bound, &turn).expect("propose");
    assert_eq!(
        proposal.relative_path.as_os_str(),
        std::ffi::OsStr::new(PLUS_ASSISTANT_PROPOSAL_PATH)
    );
    assert!(
        !target.exists(),
        "propose must not write the proposed bytes"
    );
    let on_disk_before = fs::read(&target).ok();
    assert!(
        on_disk_before.is_none(),
        "workspace file must stay absent after propose"
    );

    let diff = present_pending_file_diff(&proposal);
    assert!(
        diff.contains(PLUS_ASSISTANT_PROPOSAL_PATH),
        "diff must name the path: {diff}"
    );
    for line in turn.assistant_text.lines() {
        assert!(
            diff.contains(line),
            "diff must include the proposed assistant line {line:?}: {diff}"
        );
    }

    reject_pending_file_proposal(&bound, &proposal).expect("reject before accept");
    assert!(
        !target.exists(),
        "reject of a new file must leave it absent"
    );

    accept_pending_file_proposal(&bound, &proposal).expect("accept");
    let written = fs::read_to_string(&target).expect("read accepted");
    assert_eq!(written, turn.assistant_text, "accept must write after");

    reject_pending_file_proposal(&bound, &proposal).expect("reject after accept");
    assert!(
        target.exists(),
        "Reject is not a rollback operation and must leave accepted bytes unchanged"
    );
    assert_eq!(
        fs::read_to_string(&target).expect("accepted file after late reject"),
        turn.assistant_text
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("propose_assistant_text_as_file"),
        "Propose button must call propose_assistant_text_as_file"
    );
    assert!(
        window.contains("Propose as file change"),
        "window must label Propose as file change"
    );
}

#[test]
fn pending_file_set_accept_reject_all_and_per_file() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let path_a = std::path::PathBuf::from(format!("multi-a-{unique}.txt"));
    let path_b = std::path::PathBuf::from(format!("multi-b-{unique}.txt"));
    let before_a = format!("before-a-{unique}\n");
    let before_b = format!("before-b-{unique}\n");
    let after_a = format!("after-a-{unique}\n");
    let after_b = format!("after-b-{unique}\n");
    fs::write(folder.join(&path_a), &before_a).expect("seed a");
    fs::write(folder.join(&path_b), &before_b).expect("seed b");

    let set = propose_pending_files(
        &bound,
        [
            (path_a.clone(), after_a.clone().into_bytes()),
            (path_b.clone(), after_b.clone().into_bytes()),
        ],
    )
    .expect("propose two");
    let presented = present_pending_file_set(&set);
    assert!(
        presented.contains(&path_a.display().to_string())
            && presented.contains(&path_b.display().to_string()),
        "unified diffs must name both paths: {presented}"
    );
    assert!(
        presented.contains(after_a.trim_end()) && presented.contains(after_b.trim_end()),
        "unified diffs must include both after sides: {presented}"
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a after propose"),
        before_a
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b after propose"),
        before_b
    );

    reject_pending_file_set(&bound, &set).expect("reject all");
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a after reject-all"),
        before_a
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b after reject-all"),
        before_b
    );

    accept_pending_file_set(&bound, &set).expect("accept all");
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a after accept-all"),
        after_a
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b after accept-all"),
        after_b
    );

    reject_pending_file_set(&bound, &set).expect("reject old accepted intents");
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a after late reject"),
        after_a,
        "Reject all must not roll back already accepted bytes"
    );
    fs::write(folder.join(&path_a), &before_a).expect("reset a for per-file decisions");
    fs::write(folder.join(&path_b), &before_b).expect("reset b for per-file decisions");
    let set = propose_pending_files(
        &bound,
        [
            (path_a.clone(), after_a.clone().into_bytes()),
            (path_b.clone(), after_b.clone().into_bytes()),
        ],
    )
    .expect("restage two for per-file decisions");
    let remaining = accept_pending_file_in_set(&bound, &set, &path_a).expect("accept a");
    let remaining = reject_pending_file_in_set(&bound, &remaining, &path_b).expect("reject b");
    assert!(remaining.items.is_empty(), "both paths handled");
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("per-file accept a"),
        after_a
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("per-file reject b"),
        before_b
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("accept_pending_file_in_set"),
        "per-file Accept must call accept_pending_file_in_set"
    );
    assert!(
        window.contains("Accept all") && window.contains("Accept file"),
        "window must expose all and per-file accept"
    );
}

#[test]
fn plus_chat_turn_fake_runs_bounded_tool_loop_without_writing() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let note = format!("tool-note-{unique}\n");
    fs::write(folder.join(PLUS_TOOL_NOTE_PATH), &note).expect("seed note");
    let bound = bind_project_folder(&folder).expect("bind");
    let user = format!("tool-user-{unique}");
    let turn = plus_chat_turn_with_identity(&bound, &user, None, |_| {
        unreachable!("unconfigured chat must not call live transport")
    })
    .expect("fake tool loop");

    assert!(
        turn.assistant_text.contains(&user),
        "transcript must carry the user text: {}",
        turn.assistant_text
    );
    assert_eq!(
        turn.steps.len(),
        5,
        "Fake script is list/grep/read/propose/run"
    );
    let list = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ListDir)
        .expect("list_dir ran");
    assert!(
        list.result.contains(PLUS_TOOL_NOTE_PATH),
        "list_dir must return the real directory entry: {}",
        list.result
    );
    let grep = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::Grep)
        .expect("grep ran");
    assert!(
        grep.result.contains(note.trim()),
        "grep must return the real seeded line: {}",
        grep.result
    );
    let read = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ReadFile)
        .expect("read_file ran");
    assert!(
        read.result.contains(note.trim()),
        "read_file must return the seeded bytes: {}",
        read.result
    );
    assert!(
        turn.assistant_text.contains(note.trim()),
        "chat must show the real read_file result: {}",
        turn.assistant_text
    );
    let propose = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ProposeWrite)
        .expect("propose_write ran");
    assert!(
        propose.result.contains(PLUS_TOOL_NOT_WRITTEN),
        "propose_write must say it did not write: {}",
        propose.result
    );
    assert!(
        !folder.join(PLUS_TOOL_PROPOSE_PATH).exists(),
        "propose_write must not create the target file"
    );
    let run = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::RunContained)
        .expect("run_contained ran");
    assert!(
        run.result.contains(&containment_reason())
            || run.result.contains("/usr/bin/true")
            || run.result.contains("plus-contained-probe")
            || run.result.contains("WorkerRunCommand")
            || run.result.contains("launch")
            || run.result.contains("unavailable")
            || run.result.contains("guest down")
            || run.result.contains("ready"),
        "run_contained must be the real contained presentation: {}",
        run.result
    );
    assert!(
        turn.pending.is_some(),
        "Fake loop must stage a pending proposal"
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("plus_chat_turn_and_remember_with_attachments_in_mode("),
        "Send must still call plus_chat_turn_and_remember_with_attachments_in_mode"
    );
    assert!(
        window.contains("present_plus_tool_steps"),
        "window must present the shipped tool steps"
    );
}

#[test]
fn plus_chat_turn_grep_hits_real_workspace_bytes() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let hit = format!("search-hit-{unique}");
    let miss = format!("search-miss-{unique}");
    fs::write(folder.join("hit.txt"), format!("alpha {hit} omega\n")).expect("seed hit");
    fs::write(folder.join("miss.txt"), format!("{miss}\n")).expect("seed miss");
    let bound = bind_project_folder(&folder).expect("bind");

    let direct = plus_tool_grep(&bound, &hit, ".", false).expect("direct grep");
    assert!(
        direct.contains(&hit) && direct.contains("hit.txt"),
        "grep must report the real matching line: {direct}"
    );
    assert!(
        !direct.contains(&miss),
        "grep must not invent the miss file: {direct}"
    );
    let empty = plus_tool_grep(&bound, &format!("absent-{unique}"), ".", false).expect("no hit");
    assert!(
        empty.contains(PLUS_SEARCH_NO_MATCHES),
        "no hit must be explicit: {empty}"
    );
    let refused = plus_tool_grep(&bound, "", ".", false).expect_err("empty pattern");
    assert!(
        refused.to_string().contains("pattern"),
        "empty pattern must refuse: {refused}"
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus24-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let pattern = hit.clone();
    let turn = plus_chat_turn_with_identity(
        &bound,
        "find the hit",
        Some(identity),
        then_follow_up(move |request| {
            assert!(
                request.json_body().contains("\"name\":\"grep\"")
                    || request.json_body().contains("\"name\": \"grep\""),
                "live request must declare grep: {}",
                request.json_body()
            );
            let body = serde_json::json!({
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "grep",
                    "arguments": format!("{{\"pattern\":\"{pattern}\",\"path\":\".\"}}")
                }]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        }),
    )
    .expect("live grep");
    assert!(
        !turn.assistant_text.contains("FakeProvider"),
        "live grep must not fall back to Fake: {}",
        turn.assistant_text
    );
    let grep = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::Grep)
        .expect("live grep ran");
    assert!(
        grep.result.contains(&hit) && grep.result.contains("hit.txt"),
        "live Send grep must return the seeded hit: {}",
        grep.result
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus24-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let error = plus_chat_turn_with_identity(&bound, "bad grep", Some(identity), |_| {
        let body = serde_json::json!({
            "object": "response",
            "output": [{
                "type": "function_call",
                "name": "grep",
                "arguments": "{\"path\":\".\"}"
            }]
        });
        Ok(serde_json::to_vec(&body).expect("fixture"))
    })
    .expect_err("grep without pattern is a parse error");
    assert!(
        error.to_string().contains(PLUS_LIVE_TOOL_PARSE_ERROR),
        "missing pattern must be a live parse error: {error}"
    );
}

#[test]
fn plus_tool_grep_skips_unsearchable_files_and_reports_truncation() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let hit = format!("late-hit-{unique}");
    for index in 0..PLUS_SEARCH_MAX_FILES {
        fs::write(folder.join(format!("aaa-{index:03}.bin")), [0_u8]).expect("seed binary");
    }
    fs::write(folder.join("z.txt"), format!("found {hit}\n")).expect("seed late hit");
    let bound = bind_project_folder(&folder).expect("bind");
    let direct = plus_tool_grep(&bound, &hit, ".", false).expect("skip then hit");
    assert!(
        direct.contains(&hit) && direct.contains("z.txt"),
        "grep must search past binary/oversize fillers to the real hit: {direct}"
    );
    assert!(
        !direct.contains(PLUS_SEARCH_NO_MATCHES),
        "a real hit must not be reported as no matches: {direct}"
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus24-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let pattern = hit.clone();
    let turn = plus_chat_turn_with_identity(
        &bound,
        "find late hit",
        Some(identity),
        then_follow_up(move |request| {
            assert!(
                request.json_body().contains("grep"),
                "Send must declare grep: {}",
                request.json_body()
            );
            let body = serde_json::json!({
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "grep",
                    "arguments": format!("{{\"pattern\":\"{pattern}\",\"path\":\".\"}}")
                }]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        }),
    )
    .expect("live grep past fillers");
    let grep = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::Grep)
        .expect("live grep ran");
    assert!(
        grep.result.contains(&hit) && grep.result.contains("z.txt"),
        "shipped Send grep must return the late hit: {}",
        grep.result
    );

    let cap_folder = unique_folder();
    let hidden = format!("hidden-{unique}");
    for index in 0..PLUS_SEARCH_MAX_FILES {
        fs::write(
            cap_folder.join(format!("bbb-{index:03}.txt")),
            format!("filler-{index}\n"),
        )
        .expect("seed searchable filler");
    }
    fs::write(cap_folder.join("z-hidden.txt"), format!("{hidden}\n")).expect("seed hidden");
    let cap_bound = bind_project_folder(&cap_folder).expect("bind cap");
    let capped = plus_tool_grep(&cap_bound, &hidden, ".", false).expect("capped walk");
    assert!(
        capped.contains(PLUS_SEARCH_NO_MATCHES) && capped.contains(PLUS_SEARCH_TRUNCATED),
        "file cap must not pretend the later file was fully searched: {capped}"
    );
    assert!(
        !capped.contains("z-hidden.txt"),
        "truncated walk must not silently include the unvisited file: {capped}"
    );
}

#[test]
fn plus_chat_turn_propose_replace_stages_and_does_not_write() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("edit-{unique}.txt"));
    let old = format!("old-{unique}");
    let new = format!("new-{unique}");
    let before = format!("keep {old} keep\n");
    fs::write(folder.join(&relative), &before).expect("seed");
    let bound = bind_project_folder(&folder).expect("bind");

    let staged =
        plus_tool_propose_replace(&bound, &relative, &old, &new, false).expect("stage replace");
    assert_eq!(staged.before, before.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&staged.after),
        format!("keep {new} keep\n")
    );
    assert_eq!(
        fs::read_to_string(folder.join(&relative)).expect("unchanged"),
        before,
        "propose_replace must not write"
    );
    let twice = format!("{old} and {old}");
    fs::write(folder.join(&relative), &twice).expect("two hits");
    let ambiguous =
        plus_tool_propose_replace(&bound, &relative, &old, &new, false).expect_err("ambiguous");
    assert!(ambiguous.to_string().contains("ambiguous"), "{ambiguous}");
    let all = plus_tool_propose_replace(&bound, &relative, &old, &new, true).expect("replace all");
    assert_eq!(
        String::from_utf8_lossy(&all.after),
        format!("{new} and {new}")
    );
    assert_eq!(
        fs::read_to_string(folder.join(&relative)).expect("still"),
        twice
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus25-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    fs::write(folder.join(&relative), &before).expect("reset");
    let path = relative.display().to_string();
    let old_c = old.clone();
    let new_c = new.clone();
    let turn = plus_chat_turn_with_identity(
        &bound,
        "edit",
        Some(identity),
        then_follow_up(move |request| {
            assert!(
                request.json_body().contains("propose_replace"),
                "live request must declare propose_replace: {}",
                request.json_body()
            );
            let body = serde_json::json!({
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "propose_replace",
                    "arguments": format!(
                        "{{\"path\":\"{path}\",\"old\":\"{old_c}\",\"new\":\"{new_c}\"}}"
                    )
                }]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        }),
    )
    .expect("live replace");
    assert!(
        !turn.assistant_text.contains("FakeProvider"),
        "{}",
        turn.assistant_text
    );
    let pending = turn.pending.expect("staged");
    assert_eq!(
        String::from_utf8_lossy(&pending.after),
        format!("keep {new} keep\n")
    );
    assert_eq!(
        fs::read_to_string(folder.join(&relative)).expect("unwritten"),
        before
    );
    accept_pending_file_proposal(&bound, &pending).expect("accept");
    assert_eq!(
        fs::read_to_string(folder.join(&relative)).expect("accepted"),
        format!("keep {new} keep\n")
    );
}

#[test]
fn plus_chat_turn_live_tool_requests_run_loop_not_fake() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let note = format!("live-tool-note-{unique}\n");
    fs::write(folder.join(PLUS_TOOL_NOTE_PATH), &note).expect("seed note");
    let bound = bind_project_folder(&folder).expect("bind");
    let user = format!("live-tool-user-{unique}");
    let identity = PlusLiveIdentity::from_configured_key("gbplus14-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let live_body = format!(
        "tool list_dir .\ntool read_file {PLUS_TOOL_NOTE_PATH}\ntool propose_write {PLUS_TOOL_PROPOSE_PATH} live-after-{unique}\ntool run_contained"
    );
    let expected = live_body.clone();
    let turn = plus_chat_turn_with_identity(
        &bound,
        &user,
        Some(identity),
        then_follow_up(move |request| {
            assert!(
                request.json_body().contains("plus_tool")
                    && request.json_body().contains("list_dir")
                    && request.json_body().contains("read_file")
                    && request.json_body().contains("grep")
                    && request.json_body().contains("propose_write")
                    && request.json_body().contains("run_contained"),
                "Send live request must carry the tool format: {}",
                request.json_body()
            );
            let body = serde_json::json!({
                "object": "response",
                "output": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{ "type": "output_text", "text": expected }]
                }]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        }),
    )
    .expect("live tool loop");
    assert!(
        !turn.assistant_text.contains("FakeProvider"),
        "live tool loop must not fall back to Fake: {}",
        turn.assistant_text
    );
    assert!(
        !turn.assistant_text.contains("Created deterministic plan"),
        "live tool loop must not emit Fake planning text: {}",
        turn.assistant_text
    );
    let read = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ReadFile)
        .expect("live read_file");
    assert!(
        read.result.contains(note.trim()),
        "live read_file must return the seeded file: {}",
        read.result
    );
    assert!(
        !folder.join(PLUS_TOOL_PROPOSE_PATH).exists(),
        "live propose_write must not write"
    );
    assert!(
        turn.assistant_text.contains(PLUS_LIVE_PROVIDER_LABEL),
        "live tool loop must keep the live label: {}",
        turn.assistant_text
    );
}

#[test]
fn native_send_now_reaches_the_provider_only_after_the_tool_boundary() {
    let folder = unique_folder();
    fs::write(folder.join(PLUS_TOOL_NOTE_PATH), b"safe boundary\n").expect("seed note");
    let bound = bind_project_folder(&folder).expect("bind");
    let identity = PlusLiveIdentity::from_configured_key("gbplus-steer-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let completed = Arc::new(AtomicBool::new(false));
    let completed_for_events = Arc::clone(&completed);
    let mut event_observer = move |event| {
        if matches!(event, PlusToolLifecycleEvent::Completed { .. }) {
            completed_for_events.store(true, Ordering::SeqCst);
        }
        Ok(())
    };
    let consumed = Arc::new(AtomicBool::new(false));
    let consumed_marker = Arc::clone(&consumed);
    let boundary = Arc::clone(&completed);
    let mut steering = move || {
        assert!(
            boundary.load(Ordering::SeqCst),
            "Send now was consumed before the app-owned tool completed"
        );
        assert!(
            !consumed_marker.swap(true, Ordering::SeqCst),
            "Send now was consumed more than once"
        );
        Ok(vec!["use the newly supplied direction".to_owned()])
    };
    let mut completion = 0_u8;
    let turn = run_plus_live_harness_observed_external_with_image_and_steering(
        &bound,
        "read the note".to_owned(),
        &identity,
        |request| {
            completion += 1;
            if completion == 1 {
                return serde_json::to_vec(&serde_json::json!({
                    "object": "response",
                    "output": [{
                        "type": "function_call",
                        "name": "read_file",
                        "arguments": format!("{{\"path\":\"{PLUS_TOOL_NOTE_PATH}\"}}")
                    }]
                }))
                .map_err(|error| PlusHostError::Live(error.to_string()));
            }
            assert!(completed.load(Ordering::SeqCst));
            assert!(request.json_body().contains("safe boundary"));
            assert!(request.json_body().contains("use the newly supplied direction"));
            Ok(live_follow_up_bytes("steering consumed after the tool"))
        },
        None,
        super::PlusSessionMode::Agent,
        &mut event_observer,
        None,
        None,
        &mut steering,
    )
    .expect("steered native turn");
    assert!(consumed.load(Ordering::SeqCst));
    assert_eq!(completion, 2);
    assert!(turn.assistant_text.contains("steering consumed after the tool"));
}

#[test]
fn attach_plus_file_is_carried_on_next_send_or_refused() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("attach-{unique}.txt"));
    let body = format!("attached-body-{unique}\n");
    fs::write(folder.join(&relative), &body).expect("seed attach");

    let attachment = attach_plus_file(&bound, &relative).expect("attach");
    assert_eq!(attachment.text, body);
    let user = format!("attach-user-{unique}");
    let composed = plus_compose_user_with_attachments(
        &user,
        std::slice::from_ref(&attachment),
    )
    .expect("compose");
    assert!(
        composed.contains(&body),
        "next Send must carry attached bytes: {composed}"
    );

    let store = PlusSessionStore::from_state_root(unique_state_root());
    let turn = plus_chat_turn_and_remember_with_attachments(&store, &bound, &user, &[attachment])
        .expect("send with attach");
    assert!(
        turn.user_text.contains(&body),
        "shipped Send must include the attached file: {}",
        turn.user_text
    );
    assert!(
        turn.assistant_text.contains(&user) || turn.assistant_text.contains(&body),
        "chat must see the attached context: {}",
        turn.assistant_text
    );

    let huge = folder.join(format!("huge-{unique}.bin"));
    fs::write(&huge, vec![b'x'; PLUS_ATTACH_MAX_BYTES + 1]).expect("seed huge");
    let refused = attach_plus_file(&bound, format!("huge-{unique}.bin"));
    let refused = refused.expect_err("oversize must refuse");
    let text = refused.to_string();
    assert!(
        text.contains("size-limit refusal"),
        "oversize attach must be an explicit refusal: {text}"
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("attach_plus_file"),
        "Attach button must call attach_plus_file"
    );
    assert!(
        window.contains("plus_chat_turn_and_remember_with_attachments"),
        "Send must include attachments"
    );
}

#[test]
fn plus_sessions_create_switch_rename_round_trip() {
    let root = unique_state_root();
    let store = PlusSessionStore::from_state_root(&root);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let first_name = format!("Alpha-{unique}");
    let second_name = format!("Beta-{unique}");
    let first_chat = format!("chat-alpha-{unique}");
    let second_chat = format!("chat-beta-{unique}");

    let first = store
        .create_plus_session(&first_name)
        .expect("create alpha");
    store
        .remember_chat_transcript(&first_chat)
        .expect("persist alpha");
    let second = store
        .create_plus_session(&second_name)
        .expect("create beta");
    store
        .remember_chat_transcript(&second_chat)
        .expect("persist beta");

    let switched = store
        .switch_plus_session(&first_name)
        .expect("switch alpha");
    assert_eq!(switched.id, first.id);
    assert!(
        switched.chat.contains(&first_chat),
        "switch must restore first session chat: {}",
        switched.chat
    );
    let loaded = store.load_chat_transcript().expect("load after switch");
    assert_eq!(loaded.as_deref(), Some(first_chat.as_str()));

    let renamed = store
        .rename_plus_session(&first.id, &format!("Gamma-{unique}"))
        .expect("rename");
    assert!(renamed.name.contains("Gamma"));

    let other = PlusSessionStore::from_state_root(&root);
    let book = other.load_session_book().expect("second process book");
    assert!(
        book.sessions.iter().any(|session| session.id == first.id)
            && book.sessions.iter().any(|session| session.id == second.id),
        "second store must see both sessions"
    );
    assert!(
        other
            .present_plus_session_list()
            .contains(&format!("Gamma-{unique}")),
        "renamed session must persist: {}",
        other.present_plus_session_list()
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("create_plus_session") && window.contains("switch_plus_session"),
        "sidebar must call create/switch"
    );
}

#[test]
fn plus_git_status_and_commit_accepted_paths_only() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("accepted-{unique}.txt"));
    let other = std::path::PathBuf::from(format!("other-{unique}.txt"));
    fs::write(folder.join(&relative), format!("ok-{unique}\n")).expect("seed accepted");
    fs::write(folder.join(&other), format!("skip-{unique}\n")).expect("seed other");

    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&folder)
            .args(args)
            .output()
            .expect("git")
    };
    assert!(git(&["init"]).status.success());
    assert!(
        git(&["config", "user.email", "plus@example.test"])
            .status
            .success()
    );
    assert!(git(&["config", "user.name", "Plus Test"]).status.success());

    let report = plus_git_status_report(&bound);
    assert!(
        report.contains(relative.to_str().unwrap()) && report.contains(other.to_str().unwrap()),
        "status/diffstat must name the real repo files: {report}"
    );

    let committed = plus_git_commit_accepted(
        &bound,
        std::slice::from_ref(&relative),
        &format!("msg-{unique}"),
    )
    .expect("commit accepted");
    assert!(
        committed.contains("committed accepted files"),
        "{committed}"
    );
    let after = plus_git_status_report(&bound);
    assert!(
        !after.contains(relative.to_str().unwrap()) || after.contains("??"),
        "accepted file should be committed; leftover status: {after}"
    );
    assert!(
        after.contains(other.to_str().unwrap()),
        "unaccepted file must remain uncommitted: {after}"
    );

    let empty = plus_git_commit_accepted(&bound, &[], "nope").expect_err("empty refused");
    assert!(empty.to_string().contains("no accepted files"), "{empty}");
}

#[test]
fn present_plus_file_pane_highlights_pending_path() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("pane-{unique}.txt"));
    let before = format!("pane-before-{unique}\n");
    let after = format!("pane-after-{unique}\n");
    fs::write(folder.join(&relative), &before).expect("seed pane");
    let set = propose_pending_files(&bound, [(relative.clone(), after.clone().into_bytes())])
        .expect("propose");
    let view = present_plus_file_pane(&bound, &relative, &set);
    assert!(
        view.contains(before.trim_end()),
        "file pane must show the on-disk file: {view}"
    );
    assert!(
        view.contains("Pending proposal:") && view.contains(after.trim_end()),
        "file pane must highlight the pending after side: {view}"
    );
    assert_eq!(
        fs::read_to_string(folder.join(&relative)).expect("unchanged"),
        before
    );
}

#[test]
fn plus_run_checks_after_accept_uses_contained_path_and_does_not_write() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let one = std::path::PathBuf::from(format!("check-one-{unique}.txt"));
    let two = std::path::PathBuf::from(format!("check-two-{unique}.txt"));
    let after_one = format!("accepted-one-{unique}\n");
    let after_two = format!("accepted-two-{unique}\n");

    let proposal =
        propose_pending_file(&bound, &one, after_one.clone().into_bytes()).expect("propose one");
    assert!(
        !folder.join(&one).exists(),
        "propose must not write before Accept"
    );
    accept_pending_file_proposal(&bound, &proposal).expect("accept one");
    assert_eq!(
        fs::read_to_string(folder.join(&one)).expect("accepted one"),
        after_one
    );
    let expected = plus_gui_contained_command(&bound);
    let checks = plus_run_checks_after_accept(&bound);
    let host = include_str!("../lib.rs");
    assert!(
        host.contains("pub fn plus_run_checks_after_accept(bound: &BoundProject) -> String {\n    plus_gui_contained_command(bound)\n}"),
        "checks must be the same shipped contained entry as Run"
    );
    assert_eq!(
        crate::plus_presentation_is_known_good_terminal(&checks),
        crate::plus_presentation_is_known_good_terminal(&expected),
        "checks and Run must share known-good vs honest-failure class: run={expected} checks={checks}"
    );
    assert!(
        checks.contains(&containment_reason())
            || checks.contains("/usr/bin/true")
            || checks.contains("plus-contained-probe")
            || checks.contains("WorkerRunCommand")
            || checks.contains("launch")
            || checks.contains("unavailable")
            || checks.contains("guest down")
            || checks.contains("ready"),
        "checks must show the real contained outcome: {checks}"
    );
    assert!(
        !checks.contains("FakeProvider") && !expected.contains("FakeProvider"),
        "checks must not use FakeProvider as exec: {checks}"
    );
    assert_eq!(
        fs::read_to_string(folder.join(&one)).expect("one unchanged by checks"),
        after_one,
        "optional checks must not apply further writes"
    );

    let set = propose_pending_files(
        &bound,
        [
            (one.clone(), format!("again-one-{unique}\n").into_bytes()),
            (two.clone(), after_two.clone().into_bytes()),
        ],
    )
    .expect("propose set");
    accept_pending_file_set(&bound, &set).expect("accept all");
    let after_one_again = format!("again-one-{unique}\n");
    assert_eq!(
        fs::read_to_string(folder.join(&one)).expect("accept-all one"),
        after_one_again
    );
    assert_eq!(
        fs::read_to_string(folder.join(&two)).expect("accept-all two"),
        after_two
    );
    let checks_all = plus_run_checks_after_accept(&bound);
    assert_eq!(
        crate::plus_presentation_is_known_good_terminal(&checks_all),
        crate::plus_presentation_is_known_good_terminal(&checks),
        "accept-all checks must stay on the same contained class: {checks_all}"
    );
    assert!(
        checks_all.contains("plus-contained-probe")
            || checks_all.contains(&containment_reason())
            || checks_all.contains("ready")
            || checks_all.contains("guest down")
            || checks_all.contains("service missing"),
        "accept-all checks must stay on the contained path: {checks_all}"
    );
    assert_eq!(
        fs::read_to_string(folder.join(&one)).expect("one after checks"),
        after_one_again
    );
    assert_eq!(
        fs::read_to_string(folder.join(&two)).expect("two after checks"),
        after_two
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("plus_run_checks_after_accept_and_remember"),
        "Run tests/build must call plus_run_checks_after_accept_and_remember"
    );
    assert!(
        window.contains("Run tests/build"),
        "window must expose Run tests/build"
    );
}

#[test]
fn plus_agent_status_trail_names_planning_reading_proposing_waiting_running() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let note = format!("status-note-{unique}\n");
    fs::write(folder.join(PLUS_TOOL_NOTE_PATH), &note).expect("seed note");
    let bound = bind_project_folder(&folder).expect("bind");
    let user = format!("status-user-{unique}");
    let turn = plus_chat_turn_with_identity(&bound, &user, None, |_| {
        unreachable!("unconfigured chat must not call live transport")
    })
    .expect("fake send");
    let presented = present_plus_agent_status_trail(&turn.steps, turn.pending.as_ref());
    for word in [
        PLUS_STATUS_PLANNING,
        PLUS_STATUS_READING,
        PLUS_STATUS_PROPOSING,
        PLUS_STATUS_WAITING_FOR_ACCEPT,
        PLUS_STATUS_RUNNING,
    ] {
        assert!(
            presented.contains(word),
            "status trail must include {word}: {presented}"
        );
    }
    assert_eq!(
        present_plus_agent_status(PlusAgentStatus::Planning),
        "planning"
    );
    assert_eq!(
        present_plus_agent_status(PlusAgentStatus::Reading),
        "reading"
    );
    assert_eq!(
        present_plus_agent_status(PlusAgentStatus::Proposing),
        "proposing"
    );
    assert_eq!(
        present_plus_agent_status(PlusAgentStatus::WaitingForAccept),
        "waiting for accept"
    );
    assert_eq!(
        present_plus_agent_status(PlusAgentStatus::Running),
        "running"
    );
    let trail = present_plus_tool_steps(&turn.steps);
    for name in [
        "list_dir",
        "grep",
        "read_file",
        "propose_write",
        "run_contained",
    ] {
        assert!(
            trail.contains(name),
            "tool trail must still name {name}: {trail}"
        );
    }
    let contained = plus_gui_contained_command(&bound);
    assert!(
        crate::plus_outcome_is_real_command_terminal(&contained)
            || contained.contains(&containment_reason()),
        "contained path must be a real terminal or the shipped refusal: {contained}"
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("present_plus_agent_status_trail"),
        "Send must present the shipped status trail"
    );
    assert!(
        window.contains("agent-status") && window.contains("planning"),
        "window must show the status surface"
    );
}

#[test]
fn plus_send_context_includes_attach_and_capped_directory_sketch() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("sketch-attach-{unique}.txt"));
    let body = format!("sketch-body-{unique}\n");
    fs::write(folder.join(&relative), &body).expect("seed attach");
    let attachment = attach_plus_file(&bound, &relative).expect("attach");
    let user = format!("sketch-user-{unique}");
    let composed = plus_compose_send_context(
        &bound,
        &user,
        std::slice::from_ref(&attachment),
    )
    .expect("compose");
    assert!(
        composed.contains(&body),
        "Send context must carry attached bytes: {composed}"
    );
    assert!(
        composed.contains(relative.to_str().unwrap()),
        "directory sketch must list the attached file: {composed}"
    );
    assert!(
        composed.contains("Directory sketch:"),
        "Send context must include the list_dir sketch heading: {composed}"
    );

    for index in 0..(PLUS_SKETCH_MAX_ENTRIES + 8) {
        fs::write(
            folder.join(format!("sketch-extra-{unique}-{index:02}.txt")),
            b"x",
        )
        .expect("seed extra");
    }
    let sketch = plus_directory_sketch(&bound);
    assert!(
        sketch.contains(PLUS_SKETCH_TRUNCATED),
        "oversize listing must be a truncation notice: {sketch}"
    );
    let extra_count = sketch.matches("sketch-extra-").count();
    assert!(
        extra_count <= PLUS_SKETCH_MAX_ENTRIES,
        "sketch must not dump every name: {extra_count} extras in {sketch}"
    );

    let store = PlusSessionStore::from_state_root(unique_state_root());
    let turn = plus_chat_turn_and_remember_with_attachments(&store, &bound, &user, &[attachment])
        .expect("send with sketch");
    assert!(
        turn.user_text.contains(&body) && turn.user_text.contains("Directory sketch:"),
        "shipped Send must compose attachments plus sketch: {}",
        turn.user_text
    );

    let host = include_str!("../lib.rs");
    assert!(
        host.contains("plus_compose_send_context"),
        "Send wrapper must call plus_compose_send_context"
    );
}

#[test]
fn plus_live_tool_format_round_trips_all_four_tools() {
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let after = format!("live-after-{unique}\n");
    let requests = vec![
        PlusToolRequest {
            name: PlusToolName::ListDir,
            path: std::path::PathBuf::from("."),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::ReadFile,
            path: std::path::PathBuf::from(PLUS_TOOL_NOTE_PATH),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::Grep,
            path: std::path::PathBuf::from("."),
            after: None,
            query: Some(format!("needle-{unique}")),
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::ProposeWrite,
            path: std::path::PathBuf::from(PLUS_TOOL_PROPOSE_PATH),
            after: Some(after.clone().into_bytes()),
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::RunContained,
            path: std::path::PathBuf::new(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
    ];
    let encoded = encode_plus_live_tool_requests(&requests);
    for name in [
        "list_dir",
        "read_file",
        "grep",
        "propose_write",
        "run_contained",
    ] {
        assert!(
            encoded.contains(&format!("plus_tool {name}")),
            "encoded format must name {name}: {encoded}"
        );
    }
    let parsed = parse_live_tool_requests(&encoded).expect("round-trip parse");
    assert_eq!(parsed, requests);
    let block = serde_json::json!({
        "plus_tools": [
            { "name": "list_dir", "path": "." },
            { "name": "read_file", "path": PLUS_TOOL_NOTE_PATH },
            { "name": "grep", "pattern": format!("needle-{unique}"), "path": "." },
            { "name": "propose_write", "path": PLUS_TOOL_PROPOSE_PATH, "after": after },
            { "name": "run_contained" }
        ]
    })
    .to_string();
    let from_block = parse_live_tool_requests(&block).expect("plus_tools block");
    assert_eq!(from_block, requests);
}

#[test]
fn live_tool_protocol_refuses_every_request_shape_above_the_step_cap() {
    let lines = (0..=PLUS_MAX_TOOL_STEPS)
        .map(|_| "plus_tool list_dir {\"path\":\".\"}")
        .collect::<Vec<_>>()
        .join("\n");
    let line_error = parse_live_tool_requests(&lines).expect_err("line overflow must refuse");
    assert!(line_error.to_string().contains("step cap"));

    let calls = (0..=PLUS_MAX_TOOL_STEPS)
        .map(|_| ("list_dir".to_owned(), "{\"path\":\".\"}".to_owned()))
        .collect::<Vec<_>>();
    let call_error =
        parse_plus_live_tool_reply("", &calls).expect_err("function overflow must refuse");
    assert!(call_error.to_string().contains("step cap"));

    let items = (0..=PLUS_MAX_TOOL_STEPS)
        .map(|_| serde_json::json!({ "name": "list_dir", "path": "." }))
        .collect::<Vec<_>>();
    let block = serde_json::json!({ "plus_tools": items }).to_string();
    let block_error = parse_live_tool_requests(&block).expect_err("array overflow must refuse");
    assert!(block_error.to_string().contains("step cap"));
}

#[test]
fn proposal_protocol_missing_replacement_text_refuses_instead_of_inventing_bytes() {
    for attempted in [
        "plus_tool propose_write {\"path\":\"missing-after.txt\"}",
        "tool propose_write missing-after.txt",
    ] {
        let error = parse_live_tool_requests(attempted)
            .expect_err("missing propose_write after must refuse");
        assert!(error.to_string().contains("requires exact replacement text"));
    }
    let native = vec![(
        "propose_write".to_owned(),
        "{\"path\":\"missing-after.txt\"}".to_owned(),
    )];
    let error = parse_plus_live_tool_reply("", &native)
        .expect_err("native propose_write missing after must refuse");
    assert!(error.to_string().contains("requires exact replacement text"));

    let replace = parse_live_tool_requests(
        "plus_tool propose_replace {\"path\":\"file.txt\",\"old\":\"a\"}",
    )
    .expect_err("missing propose_replace new must refuse");
    assert!(replace.to_string().contains("propose_replace requires new"));

    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind missing-after fixture");
    let report = run_plus_tool_loop(
        &bound,
        &[PlusToolRequest {
            name: PlusToolName::ProposeWrite,
            path: std::path::PathBuf::from("missing-after.txt"),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        }],
    );
    assert_eq!(report.steps.len(), 1);
    assert!(!report.steps[0].ok);
    assert!(report.pending_set.items.is_empty());
    assert!(!folder.join("missing-after.txt").exists());
    fs::remove_dir_all(folder).expect("remove missing-after fixture");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this test drives the shipped Send path and asserts each real tool result"
)]
fn plus_chat_turn_live_conforming_function_calls_run_real_loop() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let note = format!("live-protocol-note-{unique}\n");
    fs::write(folder.join(PLUS_TOOL_NOTE_PATH), &note).expect("seed note");
    let bound = bind_project_folder(&folder).expect("bind");
    let user = format!("live-protocol-user-{unique}");
    let after = format!("live-protocol-after-{unique}");
    let identity = PlusLiveIdentity::from_configured_key("gbplus20-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let turn = plus_chat_turn_with_identity(
        &bound,
        &user,
        Some(identity),
        then_follow_up(move |request| {
            let body_json: serde_json::Value =
                serde_json::from_str(request.json_body()).expect("request json");
            assert_eq!(body_json["instructions"], plus_live_tool_instructions());
            let names: Vec<&str> = body_json["tools"]
                .as_array()
                .expect("tools")
                .iter()
                .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
                .collect();
            for name in [
                "list_dir",
                "read_file",
                "grep",
                "glob",
                "propose_write",
                "propose_replace",
                "todo_write",
                "run_contained",
            ] {
                assert!(names.contains(&name), "request must declare {name}");
            }
            let body = serde_json::json!({
                "object": "response",
                "output": [
                    {
                        "type": "function_call",
                        "name": "list_dir",
                        "arguments": "{\"path\":\".\"}"
                    },
                    {
                        "type": "function_call",
                        "name": "read_file",
                        "arguments": format!("{{\"path\":\"{PLUS_TOOL_NOTE_PATH}\"}}")
                    },
                    {
                        "type": "function_call",
                        "name": "propose_write",
                        "arguments": format!(
                            "{{\"path\":\"{PLUS_TOOL_PROPOSE_PATH}\",\"after\":\"{after}\"}}"
                        )
                    },
                    {
                        "type": "function_call",
                        "name": "run_contained",
                        "arguments": "{}"
                    }
                ]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        }),
    )
    .expect("live function-call loop");
    assert!(
        !turn.assistant_text.contains("FakeProvider")
            && !turn.assistant_text.contains("Created deterministic plan"),
        "conforming live tools must not fall back to Fake: {}",
        turn.assistant_text
    );
    assert!(
        turn.assistant_text.contains(PLUS_LIVE_PROVIDER_LABEL),
        "live label required: {}",
        turn.assistant_text
    );
    assert_eq!(turn.steps.len(), 4, "all four native calls must run");
    let list = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ListDir)
        .expect("list_dir");
    assert!(
        list.result.contains(PLUS_TOOL_NOTE_PATH),
        "list_dir must return the real directory entry: {}",
        list.result
    );
    let read = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ReadFile)
        .expect("read_file");
    assert!(
        read.result.contains(note.trim()),
        "read_file must return the seeded bytes: {}",
        read.result
    );
    let propose = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ProposeWrite)
        .expect("propose_write");
    assert!(
        propose.result.contains(PLUS_TOOL_NOT_WRITTEN),
        "propose_write must stay staged: {}",
        propose.result
    );
    assert!(
        !folder.join(PLUS_TOOL_PROPOSE_PATH).exists(),
        "propose_write must not create the target file"
    );
    let pending = turn.pending.expect("staged proposal");
    assert_eq!(
        pending.before,
        Vec::<u8>::new(),
        "new propose target must report empty before"
    );
    let run = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::RunContained)
        .expect("run_contained");
    assert!(
        run.result.contains(&containment_reason())
            || run.result.contains("/usr/bin/true")
            || run.result.contains("plus-contained-probe")
            || run.result.contains("WorkerRunCommand")
            || run.result.contains("launch")
            || run.result.contains("unavailable")
            || run.result.contains("guest down")
            || run.result.contains("ready"),
        "run_contained must be the shipped contained presentation: {}",
        run.result
    );
}

#[test]
fn plus_chat_turn_live_malformed_tool_attempt_is_explicit_error() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let identity = PlusLiveIdentity::from_configured_key("gbplus20-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let error = plus_chat_turn_with_identity(&bound, "please run tools", Some(identity), |_| {
        let body = serde_json::json!({
            "object": "response",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": "plus_tool bash {\"cmd\":\"echo hi\"}"
                }]
            }]
        });
        Ok(serde_json::to_vec(&body).expect("fixture"))
    })
    .expect_err("malformed tool attempt must fail");
    let text = error.to_string();
    assert!(
        text.contains("live") && text.contains(PLUS_LIVE_TOOL_PARSE_ERROR),
        "parse failure must be an explicit live tool-protocol error: {text}"
    );
    assert!(
        text.contains("unknown tool bash"),
        "error must name the invalid tool: {text}"
    );
    assert!(
        !text.contains("FakeProvider") && !text.contains("Created deterministic plan"),
        "parse failure must not fall back to Fake: {text}"
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus20-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let error = plus_chat_turn_with_identity(&bound, "please run tools", Some(identity), |_| {
        let body = serde_json::json!({
            "object": "response",
            "output": [{
                "type": "function_call",
                "name": "read_file",
                "arguments": "{\"not_path\":true}"
            }]
        });
        Ok(serde_json::to_vec(&body).expect("fixture"))
    })
    .expect_err("invalid function-call args must fail");
    let text = error.to_string();
    assert!(
        text.contains(PLUS_LIVE_TOOL_PARSE_ERROR) && text.contains("read_file"),
        "missing path must be a live parse error: {text}"
    );
    assert!(
        !text.contains("FakeProvider"),
        "invalid native call must not fall back to Fake: {text}"
    );

    let empty = parse_live_tool_requests("here is a plan with no tool requests")
        .expect("plain prose is not an error");
    assert!(empty.is_empty(), "no attempt markers means no tools");
    let from_calls = parse_plus_live_tool_reply("plain prose", &[]).expect("no calls");
    assert!(from_calls.is_empty());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this test seeds a real tree and drives shipped glob plus live Send"
)]
fn plus_chat_turn_glob_lists_names_without_content_needle() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let hit = format!("keep-{unique}.rs");
    let nested = format!("nested-{unique}.rs");
    let skip = format!("skip-{unique}.txt");
    let other = format!("other-{unique}.md");
    fs::create_dir_all(folder.join("src").join("deep")).expect("nested dir");
    fs::write(folder.join(&hit), b"fn keep() {}\n").expect("seed hit");
    fs::write(
        folder.join("src").join("deep").join(&nested),
        b"fn deep() {}\n",
    )
    .expect("seed nested");
    fs::write(folder.join(&skip), b"this file has no rust name\n").expect("seed skip");
    fs::write(folder.join(&other), b"notes\n").expect("seed other");
    let bound = bind_project_folder(&folder).expect("bind");

    let starred = plus_tool_glob(&bound, "*.rs", ".").expect("star rs");
    assert!(
        starred.contains(&hit) && starred.contains(&nested),
        "filename glob must list matching names with no content needle: {starred}"
    );
    assert!(
        !starred.contains(&skip) && !starred.contains(&other),
        "filename glob must omit non-matching names: {starred}"
    );

    let deep = plus_tool_glob(&bound, "src/**/*.rs", ".").expect("deep glob");
    assert!(
        deep.contains(&nested) && !deep.contains(&hit),
        "path glob must honor directory prefix: {deep}"
    );

    let braces = plus_tool_glob(&bound, "*.{md,txt}", ".").expect("braces");
    assert!(
        braces.contains(&skip) && braces.contains(&other) && !braces.contains(&hit),
        "brace glob must match either suffix: {braces}"
    );

    let empty = plus_tool_glob(&bound, &format!("absent-{unique}-*.nope"), ".").expect("no hit");
    assert!(
        empty.contains(PLUS_GLOB_NO_MATCHES),
        "no matching paths must be explicit: {empty}"
    );

    let refused = plus_tool_glob(&bound, "", ".").expect_err("empty pattern");
    assert!(
        refused
            .to_string()
            .contains("glob requires a non-empty pattern"),
        "empty pattern must be an explicit error: {refused}"
    );
    let malformed = plus_tool_glob(&bound, "src/{*.rs", ".").expect_err("unclosed brace");
    assert!(
        malformed.to_string().contains("malformed"),
        "unclosed brace must be malformed: {malformed}"
    );
    let escape = plus_tool_glob(&bound, "*.rs", "../").expect_err("escape");
    assert!(
        escape.to_string().contains("relative workspace"),
        "bound-folder escape must be refused: {escape}"
    );

    let cap_folder = unique_folder();
    for index in 0..=PLUS_GLOB_MAX_MATCHES {
        fs::write(
            cap_folder.join(format!("cap-{unique}-{index:03}.rs")),
            b"fn cap() {}\n",
        )
        .expect("seed cap");
    }
    fs::write(cap_folder.join(format!("nope-{unique}.txt")), b"skip\n").expect("seed nope");
    let cap_bound = bind_project_folder(&cap_folder).expect("bind cap");
    let capped = plus_tool_glob(&cap_bound, "*.rs", ".").expect("capped glob");
    let hits = capped
        .lines()
        .filter(|line| {
            std::path::Path::new(line)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        })
        .count();
    assert_eq!(
        hits, PLUS_GLOB_MAX_MATCHES,
        "glob must honor the match cap: {capped}"
    );
    assert!(
        capped.contains(PLUS_GLOB_TRUNCATED),
        "fired cap must be visible: {capped}"
    );
    assert!(
        !capped.contains(&format!("nope-{unique}.txt")),
        "cap walk must still omit non-matching names: {capped}"
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus26-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let user = format!("glob-user-{unique}");
    let pattern = "*.rs".to_owned();
    let turn = plus_chat_turn_with_identity(
        &bound,
        &user,
        Some(identity),
        then_follow_up(move |request| {
            let body_json: serde_json::Value =
                serde_json::from_str(request.json_body()).expect("request json");
            assert_eq!(body_json["instructions"], plus_live_tool_instructions());
            let names: Vec<&str> = body_json["tools"]
                .as_array()
                .expect("tools")
                .iter()
                .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
                .collect();
            assert!(
                names.contains(&"glob"),
                "live request must declare glob: {names:?}"
            );
            let body = serde_json::json!({
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "glob",
                    "arguments": format!("{{\"pattern\":\"{pattern}\",\"path\":\".\"}}")
                }]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        }),
    )
    .expect("live glob");
    assert!(
        !turn.assistant_text.contains("FakeProvider"),
        "conforming glob must not fall back to Fake: {}",
        turn.assistant_text
    );
    let step = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::Glob)
        .expect("glob ran");
    assert!(
        step.result.contains(&hit) && step.result.contains(&nested) && !step.result.contains(&skip),
        "injected glob must run the real host walk: {}",
        step.result
    );
    assert!(
        present_plus_tool_steps(&turn.steps).contains(&hit),
        "tool trail must show glob hits: {}",
        turn.assistant_text
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus26-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let error = plus_chat_turn_with_identity(&bound, "please glob", Some(identity), |_| {
        let body = serde_json::json!({
            "object": "response",
            "output": [{
                "type": "function_call",
                "name": "glob",
                "arguments": "{\"pattern\":\"\"}"
            }]
        });
        Ok(serde_json::to_vec(&body).expect("fixture"))
    })
    .expect_err("empty glob pattern must fail closed");
    let text = error.to_string();
    assert!(
        text.contains(PLUS_LIVE_TOOL_PARSE_ERROR) && text.contains("glob requires pattern"),
        "empty glob payload must be a live parse error: {text}"
    );
    assert!(
        !text.contains("FakeProvider"),
        "glob parse failure must not fall back to Fake: {text}"
    );
}

#[test]
fn plus_tool_trail_shows_grep_hits_and_completed_failed() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let hit = format!("trail-hit-{unique}");
    fs::write(folder.join("trail.txt"), format!("{hit}\n")).expect("seed trail");
    let bound = bind_project_folder(&folder).expect("bind");
    let report = run_plus_tool_loop(
        &bound,
        &[
            PlusToolRequest {
                name: PlusToolName::Grep,
                path: std::path::PathBuf::from("."),
                after: None,
                query: Some(hit.clone()),
                case_insensitive: false,
                replace_all: false,
            },
            PlusToolRequest {
                name: PlusToolName::ReadFile,
                path: std::path::PathBuf::from(format!("missing-{unique}.txt")),
                after: None,
                query: None,
                case_insensitive: false,
                replace_all: false,
            },
        ],
    );
    let trail = present_plus_tool_steps(&report.steps);
    assert!(
        trail.contains(&hit) && trail.contains("trail.txt"),
        "trail must show real grep hits: {trail}"
    );
    assert!(
        trail.contains(&format!("tool grep {hit} . → {PLUS_TOOL_COMPLETED}:")),
        "successful grep must say completed: {trail}"
    );
    assert!(
        trail.contains(&format!(
            "tool read_file missing-{unique}.txt → {PLUS_TOOL_FAILED}:"
        )),
        "missing read must say failed: {trail}"
    );
    assert!(
        report.steps[0].ok && !report.steps[1].ok,
        "ok flags must match completed/failed"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this test drives replace, merge, restore, and live Send persist"
)]
fn plus_todo_write_merge_and_replace_persist_on_state_root() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let root = unique_state_root();
    let store = PlusSessionStore::from_state_root(&root);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let first = format!("todo-first-{unique}");
    let second = format!("todo-second-{unique}");
    let replaced = plus_todo_write(
        &store,
        &[
            PlusTodoUpdate {
                id: "a".into(),
                content: Some(first.clone()),
                status: Some(PlusTodoStatus::Pending),
            },
            PlusTodoUpdate {
                id: "b".into(),
                content: Some(second.clone()),
                status: Some(PlusTodoStatus::InProgress),
            },
        ],
        false,
    )
    .expect("replace");
    assert_eq!(replaced.items.len(), 2);
    assert_eq!(replaced.items[0].content, first);
    let merged = plus_todo_write(
        &store,
        &[PlusTodoUpdate {
            id: "a".into(),
            content: None,
            status: Some(PlusTodoStatus::Completed),
        }],
        true,
    )
    .expect("merge");
    assert_eq!(merged.items.len(), 2, "merge must keep the existing row");
    assert_eq!(merged.items[0].status, PlusTodoStatus::Completed);
    assert_eq!(
        merged.items[0].content, first,
        "merge without content keeps text"
    );
    assert_eq!(merged.items[1].content, second);

    let restored = PlusSessionStore::from_state_root(&root);
    let loaded = load_plus_todos(&restored).expect("restore");
    assert_eq!(loaded, merged);
    assert!(
        root.join(PLUS_TODOS_FILE).is_file(),
        "todos must live on the plus state root"
    );
    let workspace_names: Vec<_> = fs::read_dir(&folder)
        .expect("workspace")
        .filter_map(|entry| entry.ok().map(|item| item.file_name()))
        .collect();
    assert!(
        workspace_names.is_empty(),
        "todo_write must not write the bound folder: {workspace_names:?}"
    );

    let dup = plus_todo_write(
        &store,
        &[
            PlusTodoUpdate {
                id: "dup".into(),
                content: Some("one".into()),
                status: None,
            },
            PlusTodoUpdate {
                id: "dup".into(),
                content: Some("two".into()),
                status: None,
            },
        ],
        false,
    )
    .expect_err("duplicate ids");
    assert!(
        dup.to_string().contains("duplicate id"),
        "duplicate ids must fail: {dup}"
    );

    let identity = PlusLiveIdentity::from_configured_key("gbplus28-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let turn = plus_chat_turn_with_identity_and_remember(
        &store,
        &bound,
        "track the work",
        Some(identity),
        then_follow_up(|request| {
            let body_json: serde_json::Value =
                serde_json::from_str(request.json_body()).expect("request json");
            let names: Vec<&str> = body_json["tools"]
                .as_array()
                .expect("tools")
                .iter()
                .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
                .collect();
            assert!(
                names.contains(&"todo_write"),
                "live request must declare todo_write: {names:?}"
            );
            let body = serde_json::json!({
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "todo_write",
                    "arguments": format!(
                        "{{\"merge\":false,\"todos\":[{{\"id\":\"live\",\"content\":\"{first}\",\"status\":\"pending\"}}]}}"
                    )
                }]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        }),
    )
    .expect("live todo");
    assert!(
        !turn.assistant_text.contains("FakeProvider"),
        "todo_write must not fall back to Fake: {}",
        turn.assistant_text
    );
    let step = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::TodoWrite)
        .expect("todo_write ran");
    assert!(
        step.ok && step.result.contains(&first) && step.result.contains(PLUS_TODO_NOT_WORKSPACE),
        "todo trail must show the item and not-workspace: {}",
        step.result
    );
    let after_send =
        load_plus_todos(&PlusSessionStore::from_state_root(&root)).expect("after send");
    assert!(
        after_send.items.iter().any(|item| item.content == first),
        "Send todo_write must persist: {after_send:?}"
    );

    let missing_todos = plus_chat_turn_with_identity(
        &bound,
        "broken todo",
        Some(
            PlusLiveIdentity::from_configured_key("gbplus28-test-key-SHOULD-NOT-LEAK")
                .expect("key"),
        ),
        |_| {
            let body = serde_json::json!({
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "todo_write",
                    "arguments": "{\"merge\":true}"
                }]
            });
            Ok(serde_json::to_vec(&body).expect("fixture"))
        },
    )
    .expect_err("missing todos");
    let text = missing_todos.to_string();
    assert!(
        text.contains(PLUS_LIVE_TOOL_PARSE_ERROR) && text.contains("todo_write requires todos"),
        "malformed todo_write must fail closed: {text}"
    );
    assert!(!text.contains("FakeProvider"));
}

#[test]
fn plus_permission_copy_is_labels_only() {
    let copy = present_plus_permission_copy();
    assert!(
        copy.contains(PLUS_ACCEPT_REQUIRED) && copy.contains(&containment_reason()),
        "permission copy must name Accept required and the shipped refusal: {copy}"
    );
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("Accept required"),
        "admitted window must show Accept required"
    );
    for source in [
        include_str!("../lib.rs"),
        include_str!("../plus_tools.rs"),
        include_str!("../plus_status.rs"),
        include_str!("../../../grok-build-desktop/src/plus_window.rs"),
        include_str!("../plus_todo.rs"),
        include_str!("../plus_guest.rs"),
        include_str!("../plus_probe.rs"),
        include_str!("../plus_proof.rs"),
        include_str!("../plus_lifecycle.rs"),
        include_str!("../plus_harness.rs"),
        include_str!("../plus_mode.rs"),
    ] {
        assert!(
            !source.contains("PermissionClassifier") && !source.contains("SandboxManager"),
            "product plus sources must not treat PermissionClassifier as authority"
        );
    }
}

#[test]
fn plus_run_path_stays_on_shipped_launch_not_a_new_native_service() {
    let host = include_str!("../lib.rs");
    assert!(
        host.contains("RunnerLifecycleClient::launch("),
        "plus Run must still call the shipped launch entry as native fallback"
    );
    assert!(
        host.contains("plus_gui_contained_command(")
            && host.contains("plus_run_checks_after_accept("),
        "Run and post-accept checks must stay on the same plus entry"
    );
    assert!(
        !host.contains("launch_with_native_service"),
        "plus must not invent an admitted held-child native-service launch"
    );
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let run = plus_gui_contained_command(&bound);
    let checks = plus_run_checks_after_accept(&bound);
    assert!(
        crate::plus_outcome_is_real_command_terminal(&run)
            || run.contains(&containment_reason()),
        "Run must be a real terminal or the shipped refusal: run={run}"
    );
    assert!(
        crate::plus_outcome_is_real_command_terminal(&checks)
            || checks.contains(&containment_reason()),
        "checks must be a real terminal or the shipped refusal: checks={checks}"
    );
    for text in [&run, &checks] {
        assert!(
            !text.contains("12/12 achieved") && !text.contains("this is 12/12"),
            "this host must not present a fabricated 12/12: {text}"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this soak drives shipped live Send then Accept then Run"
)]
fn plus_live_soak_read_grep_propose_accept_run() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let hit = format!("soak-hit-{unique}");
    let after = format!("soak-after-{unique}\n");
    fs::write(folder.join("soak.txt"), format!("{hit}\n")).expect("seed soak");
    let bound = bind_project_folder(&folder).expect("bind");
    let store = PlusSessionStore::from_state_root(unique_state_root());
    let identity = PlusLiveIdentity::from_configured_key("gbplus31-test-key-SHOULD-NOT-LEAK")
        .expect("test key");
    let turn = plus_chat_turn_with_identity_and_remember(
        &store,
        &bound,
        format!("soak-{unique}"),
        Some(identity),
        then_follow_up({
            let hit = hit.clone();
            let after = after.clone();
            move |request| {
                let body_json: serde_json::Value =
                    serde_json::from_str(request.json_body()).expect("request json");
                assert_eq!(body_json["instructions"], plus_live_tool_instructions());
                assert!(
                    !request.json_body().contains("FakeProvider"),
                    "live request must not be the Fake stub"
                );
                let body = serde_json::json!({
                    "object": "response",
                    "output": [
                        {
                            "type": "function_call",
                            "name": "read_file",
                            "arguments": "{\"path\":\"soak.txt\"}"
                        },
                        {
                            "type": "function_call",
                            "name": "grep",
                            "arguments": format!("{{\"pattern\":\"{hit}\",\"path\":\".\"}}")
                        },
                        {
                            "type": "function_call",
                            "name": "propose_write",
                            "arguments": format!(
                                "{{\"path\":\"{PLUS_TOOL_PROPOSE_PATH}\",\"after\":{}}}",
                                serde_json::to_string(&after).expect("after json")
                            )
                        }
                    ]
                });
                Ok(serde_json::to_vec(&body).expect("fixture"))
            }
        }),
    )
    .expect("live soak send");
    assert!(
        !turn.assistant_text.contains("FakeProvider")
            && !turn.assistant_text.contains("Created deterministic plan"),
        "configured live soak must not fall back to Fake: {}",
        turn.assistant_text
    );
    assert!(
        turn.assistant_text.contains(PLUS_LIVE_PROVIDER_LABEL),
        "live soak must carry the live label: {}",
        turn.assistant_text
    );
    let read = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ReadFile)
        .expect("read_file");
    assert!(
        read.ok && read.result.contains(&hit),
        "read_file must return the seeded bytes: {}",
        read.result
    );
    let grep = turn
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::Grep)
        .expect("grep");
    assert!(
        grep.ok && grep.result.contains(&hit) && grep.result.contains("soak.txt"),
        "grep must hit the real file: {}",
        grep.result
    );
    assert!(
        !folder.join(PLUS_TOOL_PROPOSE_PATH).exists(),
        "propose must not write before Accept"
    );
    let pending = turn.pending.expect("staged proposal");
    accept_pending_file_proposal(&bound, &pending).expect("accept");
    let written = fs::read(folder.join(PLUS_TOOL_PROPOSE_PATH)).expect("accepted bytes");
    assert_eq!(
        written,
        after.as_bytes(),
        "Accept must write the proposed text"
    );
    let checks = plus_run_checks_after_accept(&bound);
    assert!(
        checks.contains(&containment_reason())
            || checks.contains("/usr/bin/true")
            || checks.contains("plus-contained-probe")
            || checks.contains("WorkerRunCommand")
            || checks.contains("launch")
            || checks.contains("unavailable")
            || checks.contains("guest down")
            || checks.contains("ready"),
        "post-accept Run must stay on the shipped contained path: {checks}"
    );
    assert!(
        !checks.contains("FakeProvider"),
        "contained Run is not a Fake fallback: {checks}"
    );
}
