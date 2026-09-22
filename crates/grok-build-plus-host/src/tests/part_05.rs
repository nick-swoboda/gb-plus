use super::{
    PLUS_AT_FILE, PLUS_ATTACH_MAX_FILES, PLUS_CONTEXT_EMPTY, PLUS_LIVE_TOOL_RESULTS_HEADING,
    PLUS_MODE_AGENT, PLUS_MODE_ASK, PLUS_MODE_CHECKS, PLUS_PLAN_HEADING, PLUS_TURN_CONTINUE,
    PLUS_TURN_RETRY, PLUS_TURN_STUCK, PlusSessionMode, PlusTurnStuck,
    plus_chat_turn_with_identity_in_mode, plus_continue_stuck_turn, plus_retry_stuck_step,
    plus_tool_propose_write, prepare_plus_guest, present_plus_context_chips,
    present_plus_session_mode, present_plus_turn_plan, push_plus_attachment,
};

#[test]
fn plus_n1_live_send_runs_a_further_completion_after_real_tools() {
    let folder = unique_folder();
    fs::write(folder.join("n1-note.txt"), b"n1-bytes\n").expect("seed");
    let bound = bind_project_folder(&folder).expect("bind");
    let identity =
        PlusLiveIdentity::from_configured_key("gbplus-n1-live-SHOULD-NOT-LEAK").expect("key");
    let mut completions = 0_u32;
    let turn = plus_chat_turn_with_identity(&bound, "list the project", Some(identity), {
        move |request| {
            completions += 1;
            let body = request.json_body();
            assert!(
                !body.contains("FakeProvider") && !body.contains("Created deterministic plan"),
                "live request must not be Fake: {body}"
            );
            if completions == 1 {
                assert!(
                    body.contains("list the project"),
                    "first completion must carry the user text: {body}"
                );
                let reply = serde_json::json!({
                    "object": "response",
                    "output": [{
                        "type": "function_call",
                        "name": "list_dir",
                        "arguments": "{\"path\":\".\"}"
                    }]
                });
                return Ok(serde_json::to_vec(&reply).expect("first body"));
            }
            assert_eq!(
                completions, 2,
                "one Send must consume a follow-on completion"
            );
            assert!(
                body.contains(PLUS_LIVE_TOOL_RESULTS_HEADING)
                    && body.contains("list_dir")
                    && (body.contains("completed") || body.contains("n1-note.txt")),
                "follow-on input must include the real tool results: {body}"
            );
            Ok(live_follow_up_bytes("saw the listing after tools"))
        }
    })
    .expect("live multi-step");
    assert!(
        turn.live_completions >= 2,
        "one Send must consume ≥2 live completions: {}",
        turn.live_completions
    );
    assert!(
        turn.steps
            .iter()
            .any(|step| step.name == PlusToolName::ListDir && step.ok),
        "executed tool trail must be non-empty: {:?}",
        turn.steps
    );
    assert!(
        turn.assistant_text.contains("saw the listing after tools"),
        "follow-up assistant text must be present: {}",
        turn.assistant_text
    );
    assert!(
        turn.assistant_text.contains(PLUS_LIVE_PROVIDER_LABEL)
            && !turn.assistant_text.contains("FakeProvider")
            && !turn.assistant_text.contains("Created deterministic plan"),
        "configured live must not be Fake: {}",
        turn.assistant_text
    );
    assert!(turn.stuck.is_none(), "successful follow-up is not stuck");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture verifies the ordered plan, progress, continue, and retry projection"
)]
fn plus_n1_plan_progress_and_continue_retry_never_fake() {
    let empty = present_plus_turn_plan(&[], None);
    assert!(
        empty.contains(PLUS_PLAN_HEADING)
            && empty.contains("planning")
            && empty.contains("in_progress"),
        "empty plan must show in-progress planning: {empty}"
    );

    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let identity =
        PlusLiveIdentity::from_configured_key("gbplus-n1-stuck-SHOULD-NOT-LEAK").expect("key");
    let missing = format!("missing-n1-{}.txt", NEXT.fetch_add(1, Ordering::Relaxed));
    let turn =
        plus_chat_turn_with_identity(&bound, "read the missing file", Some(identity.clone()), {
            let missing = missing.clone();
            move |request| {
                assert!(
                    !request.json_body().contains("FakeProvider"),
                    "stuck live must not be Fake"
                );
                let reply = serde_json::json!({
                    "object": "response",
                    "output": [{
                        "type": "function_call",
                        "name": "read_file",
                        "arguments": format!("{{\"path\":\"{missing}\"}}")
                    }]
                });
                Ok(serde_json::to_vec(&reply).expect("failed tool body"))
            }
        })
        .expect("failed tool is a stuck turn, not a Fake fallback");
    assert_eq!(
        turn.live_completions, 1,
        "failed tool must not auto-follow-up"
    );
    assert!(
        matches!(turn.stuck, Some(PlusTurnStuck::FailedTool { .. })),
        "failed tool must mark the turn stuck: {:?}",
        turn.stuck
    );
    let plan = present_plus_turn_plan(&turn.steps, turn.stuck.as_ref());
    assert!(
        plan.contains(PLUS_PLAN_HEADING)
            && plan.contains("read_file")
            && plan.contains("failed")
            && plan.contains(PLUS_TURN_STUCK)
            && plan.contains(PLUS_TURN_CONTINUE)
            && plan.contains(PLUS_TURN_RETRY),
        "plan/steps must show failed progress and continue/retry: {plan}"
    );
    assert!(
        !turn.assistant_text.contains("FakeProvider"),
        "stuck live must not name Fake: {}",
        turn.assistant_text
    );

    let continued = plus_continue_stuck_turn(
        &bound,
        turn.clone(),
        Some(&identity),
        |request| {
            let body = request.json_body();
            assert!(
                body.contains(PLUS_LIVE_TOOL_RESULTS_HEADING) && body.contains("read_file"),
                "continue must resume the same turn with tool results: {body}"
            );
            assert!(!body.contains("FakeProvider"), "continue must not be Fake");
            Ok(live_follow_up_bytes("continued without Fake"))
        },
        None,
        PlusSessionMode::Agent,
    )
    .expect("continue");
    assert!(
        continued.live_completions >= 2
            && continued.assistant_text.contains("continued without Fake")
            && !continued.assistant_text.contains("FakeProvider"),
        "continue must consume another live completion without Fake: {}",
        continued.assistant_text
    );

    fs::write(folder.join(&missing), b"now-present\n").expect("create failed path");
    let retried = plus_retry_stuck_step(
        &bound,
        turn,
        Some(&identity),
        |request| {
            assert!(
                request.json_body().contains(PLUS_LIVE_TOOL_RESULTS_HEADING),
                "retry follow-on must use real tool results: {}",
                request.json_body()
            );
            Ok(live_follow_up_bytes("retried from the real read_file"))
        },
        None,
        PlusSessionMode::Agent,
    )
    .expect("retry");
    let read = retried
        .steps
        .iter()
        .find(|step| step.name == PlusToolName::ReadFile)
        .expect("retried read_file");
    assert!(
        read.ok && read.result.contains("now-present"),
        "retry must re-run plus_tool_read_file from its real start: {}",
        read.result
    );
    assert!(
        retried
            .assistant_text
            .contains("retried from the real read_file")
            && !retried.assistant_text.contains("FakeProvider"),
        "retry must not fall back to Fake: {}",
        retried.assistant_text
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    for needle in [
        "Continue",
        "Retry",
        "Plan",
        "present_plus_turn_plan",
        "plus_continue_stuck_turn_and_remember",
        "plus_retry_stuck_step_and_remember",
        "plus_chat_turn_and_remember_with_attachments_in_mode",
    ] {
        assert!(window.contains(needle), "window must wire {needle}");
    }
}

#[test]
fn plus_n2_pending_review_lists_paths_and_accept_reject_are_first_class() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let path_a = std::path::PathBuf::from(format!("review-a-{unique}.txt"));
    let path_b = std::path::PathBuf::from(format!("review-b-{unique}.txt"));
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
        presented.contains("Pending review")
            && presented.contains(&format!("{}: pending", path_a.display()))
            && presented.contains(&format!("{}: pending", path_b.display())),
        "pending state must name each path as pending: {presented}"
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a"),
        before_a,
        "propose must not write"
    );

    reject_pending_file_set(&bound, &set).expect("reject all");
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a"),
        before_a
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b"),
        before_b
    );

    accept_pending_file_set(&bound, &set).expect("accept all");
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a"),
        after_a
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b"),
        after_b
    );

    reject_pending_file_set(&bound, &set).expect("reject old accepted intents");
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a"),
        after_a,
        "Reject is not a rollback operation"
    );
    fs::write(folder.join(&path_a), &before_a).expect("reset a");
    fs::write(folder.join(&path_b), &before_b).expect("reset b");
    let set = propose_pending_files(
        &bound,
        [
            (path_a.clone(), after_a.clone().into_bytes()),
            (path_b.clone(), after_b.clone().into_bytes()),
        ],
    )
    .expect("restage for per-file decisions");
    let remaining = accept_pending_file_in_set(&bound, &set, &path_a).expect("accept a");
    let remaining_text = present_pending_file_set(&remaining);
    assert!(
        remaining_text.contains(&format!("{}: pending", path_b.display()))
            && !remaining_text.contains(&format!("{}: pending", path_a.display())),
        "per-file Accept must leave the other path pending: {remaining_text}"
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_a)).expect("a"),
        after_a
    );
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b"),
        before_b
    );
    let leftover = reject_pending_file_in_set(&bound, &remaining, &path_b).expect("reject b");
    assert!(leftover.items.is_empty());
    assert_eq!(
        fs::read_to_string(folder.join(&path_b)).expect("b"),
        before_b
    );

    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    for needle in [
        "Pending review",
        "Accept all",
        "Reject all",
        "Accept file",
        "Reject file",
    ] {
        assert!(window.contains(needle), "window must show {needle}");
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture verifies the Ask-mode gate, proposal, and contained-run sequence"
)]
fn plus_n3_ask_agent_checks_gate_propose_and_guest_run() {
    let folder = unique_folder();
    fs::write(folder.join(PLUS_TOOL_NOTE_PATH), b"ask-note\n").expect("seed");
    let bound = bind_project_folder(&folder).expect("bind");
    let identity =
        PlusLiveIdentity::from_configured_key("gbplus-n3-mode-SHOULD-NOT-LEAK").expect("key");
    let proposed = format!("ask-proposed-{}.txt", NEXT.fetch_add(1, Ordering::Relaxed));
    let ask = plus_chat_turn_with_identity_in_mode(
        &bound,
        "please edit",
        Some(identity.clone()),
        then_follow_up({
            let proposed = proposed.clone();
            move |_| {
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
                            "name": "propose_write",
                            "arguments": format!(
                                "{{\"path\":\"{proposed}\",\"after\":\"should-not-stage\"}}"
                            )
                        }
                    ]
                });
                Ok(serde_json::to_vec(&body).expect("ask body"))
            }
        }),
        PlusSessionMode::Ask,
    )
    .expect("Ask send");
    assert!(
        ask.pending.is_none() && ask.pending_set.items.is_empty(),
        "Ask must not stage a pending set: {:?}",
        ask.pending_set
    );
    assert!(
        !folder.join(&proposed).exists(),
        "Ask must not write workspace files"
    );
    assert!(
        ask.steps
            .iter()
            .any(|step| step.name == PlusToolName::ListDir && step.ok),
        "Ask may still run read tools: {:?}",
        ask.steps
    );
    assert!(
        ask.steps
            .iter()
            .any(|step| step.result.contains("Ask mode skipped propose_write")),
        "Ask must skip propose_write: {:?}",
        ask.steps
    );

    let agent = plus_chat_turn_with_identity_in_mode(
        &bound,
        "please edit",
        Some(identity),
        then_follow_up({
            let proposed = proposed.clone();
            move |_| {
                let body = serde_json::json!({
                    "object": "response",
                    "output": [{
                        "type": "function_call",
                        "name": "propose_write",
                        "arguments": format!(
                            "{{\"path\":\"{proposed}\",\"after\":\"staged-by-agent\"}}"
                        )
                    }]
                });
                Ok(serde_json::to_vec(&body).expect("agent body"))
            }
        }),
        PlusSessionMode::Agent,
    )
    .expect("Agent send");
    assert!(
        agent.pending.is_some() && !folder.join(&proposed).exists(),
        "Agent must stage until Accept without writing"
    );

    let host = include_str!("../lib.rs");
    assert!(
        host.contains("PlusSessionMode::Checks")
            && host.contains("plus_checks_chat_turn")
            && host.contains("plus_gui_contained_command_outcome(bound)"),
        "Checks Send must call plus_checks_chat_turn → plus_gui_contained_command"
    );
    let checks_fn = host
        .split("fn plus_checks_chat_turn")
        .nth(1)
        .unwrap_or("")
        .split("fn plus_fake_chat_turn")
        .next()
        .unwrap_or("");
    assert!(
        checks_fn.contains("plus_gui_contained_command_outcome(bound)")
            && !checks_fn.contains("Command::spawn")
            && !checks_fn.contains("FakeProvider"),
        "Checks must be the contained path, not spawn or Fake: {checks_fn}"
    );
    let run_checks = host
        .split("pub fn plus_run_checks_after_accept(")
        .nth(1)
        .unwrap_or("")
        .split("pub fn ")
        .next()
        .unwrap_or("");
    assert!(
        run_checks.contains("plus_gui_contained_command(bound)")
            && !run_checks.contains("Command::spawn"),
        "post-accept Checks must stay on plus_gui_contained_command"
    );
    assert_eq!(
        present_plus_session_mode(PlusSessionMode::Ask),
        PLUS_MODE_ASK
    );
    assert_eq!(
        present_plus_session_mode(PlusSessionMode::Agent),
        PLUS_MODE_AGENT
    );
    assert_eq!(
        present_plus_session_mode(PlusSessionMode::Checks),
        PLUS_MODE_CHECKS
    );
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    for needle in ["Ask", "Agent", "Checks"] {
        assert!(window.contains(needle), "window must contain {needle}");
    }
}

#[test]
fn plus_n4_context_chips_stay_visible_and_feed_send() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("chip-{unique}.txt"));
    let body = format!("chip-body-{unique}\n");
    fs::write(folder.join(&relative), &body).expect("seed");
    let empty_draft = "";
    assert_eq!(present_plus_context_chips(&[]), PLUS_CONTEXT_EMPTY);
    assert!(
        present_plus_context_chips(&[]).contains(PLUS_AT_FILE),
        "empty draft still shows the @file chip surface"
    );
    let attachment = attach_plus_file(&bound, &relative).expect("attach");
    let chips = present_plus_context_chips(std::slice::from_ref(&attachment));
    assert!(
        chips.contains(PLUS_AT_FILE) && chips.contains(&relative.display().to_string()),
        "chips must name the attached file: {chips}"
    );
    let composed = plus_compose_user_with_attachments(
        empty_draft,
        std::slice::from_ref(&attachment),
    )
    .expect("compose empty draft");
    assert!(
        composed.contains(&body),
        "Send must include the chip bodies even with an empty draft: {composed}"
    );
    let mut attachments = Vec::new();
    for index in 0..PLUS_ATTACH_MAX_FILES {
        let path = folder.join(format!("cap-{unique}-{index}.txt"));
        fs::write(&path, b"cap\n").expect("seed cap");
        let item =
            attach_plus_file(&bound, format!("cap-{unique}-{index}.txt")).expect("attach cap");
        push_plus_attachment(&mut attachments, item).expect("under cap");
    }
    let overflow = crate::PlusAttachment {
        relative_path: std::path::PathBuf::from(format!("overflow-{unique}.txt")),
        text: "x".into(),
    };
    let error = push_plus_attachment(&mut attachments, overflow).expect_err("cap");
    assert!(
        error.to_string().contains("size-limit refusal"),
        "over-cap attach must be a size-limit refusal: {error}"
    );
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("@file")
            && window.contains("Context: @file")
            && window.contains("present_plus_context_chips")
            && window.contains("Send"),
        "window must show an always-visible @file surface next to Send"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture verifies that one guest preparation is reused by its run"
)]
fn plus_n5_run_reuses_ready_guest_without_a_second_prepare() {
    let host = include_str!("../lib.rs");
    let run_fn = host
        .split("pub fn plus_gui_contained_command(")
        .nth(1)
        .unwrap_or("")
        .split("pub fn ")
        .next()
        .unwrap_or("");
    assert!(
        !run_fn.contains("prepare_plus_guest"),
        "Run must re-probe lifecycle, not call prepare_plus_guest"
    );
    let checks_fn = host
        .split("pub fn plus_run_checks_after_accept(")
        .nth(1)
        .unwrap_or("")
        .split("pub fn ")
        .next()
        .unwrap_or("");
    assert!(
        checks_fn.contains("plus_gui_contained_command")
            && !checks_fn.contains("prepare_plus_guest"),
        "Checks must reuse Run without prepare"
    );
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    let run_cb = window
        .split("fn wire_run_contained")
        .nth(1)
        .unwrap_or("")
        .split("fn wire_")
        .next()
        .unwrap_or("");
    assert!(
        !run_cb.contains("prepare_plus_guest"),
        "window Run must not babysit prepare guest"
    );

    let prepared = prepare_plus_guest();
    assert!(
        prepared.contains(PLUS_GUEST_ACTION_PREPARE)
            || prepared.contains(PLUS_GUEST_STATUS_READY)
            || prepared.contains(PLUS_GUEST_STATUS_DOWN)
            || prepared.contains(PLUS_GUEST_STATUS_SERVICE_MISSING),
        "first prepare guest must present lifecycle, not a fake terminal: {prepared}"
    );
    assert!(
        !prepared.contains("Command succeeded") || prepared.contains(PLUS_GUEST_STATUS_READY),
        "prepare must not print Command succeeded unless the guest is ready: {prepared}"
    );
    let run_src = host
        .split("pub fn plus_gui_contained_command_outcome(")
        .nth(1)
        .unwrap_or("")
        .split("pub fn ")
        .next()
        .unwrap_or("");
    assert!(
        run_src.contains("probe_plus_guest_lifecycle")
            && run_src.contains("PlusGuestLifecycle::Ready")
            && run_src.contains("plus_contained_on_available_guest"),
        "after prepare, Run re-probes and uses the ready guest path without a second prepare"
    );
    let unavailable = crate::present_plus_guest_unavailable_outcome(
        "PlatformLaunchBindingUnavailable",
        &crate::PlusGuestUnavailable {
            reasons: vec!["colima is not running (`colima start`)".into()],
        },
    );
    assert!(
        unavailable.contains(PLUS_GUEST_STATUS_DOWN)
            && unavailable.contains("start Colima (if safe)")
            && unavailable.contains("verify install root")
            && unavailable.contains("repair hints")
            && !unavailable.contains("Command succeeded"),
        "unready Run must stay actionable and not Command succeeded: {unavailable}"
    );
    let missing = crate::present_plus_guest_unavailable_outcome_with_kind(
        PlusGuestLifecycleKind::ServiceMissing,
        "",
        &crate::PlusGuestUnavailable {
            reasons: vec!["install root is missing handoff-commitment.v1.json".into()],
        },
    );
    assert!(
        missing.contains(PLUS_GUEST_STATUS_SERVICE_MISSING)
            && missing.contains("verify install root")
            && !missing.contains("Command succeeded"),
        "service missing must stay actionable: {missing}"
    );

    assert_eq!(
        present_plus_guest_lifecycle_kind(PlusGuestLifecycleKind::GuestDown),
        PLUS_GUEST_STATUS_DOWN
    );
    assert_eq!(
        present_plus_guest_lifecycle_kind(PlusGuestLifecycleKind::ServiceMissing),
        PLUS_GUEST_STATUS_SERVICE_MISSING
    );
    assert_eq!(
        present_plus_guest_lifecycle_kind(PlusGuestLifecycleKind::Ready),
        PLUS_GUEST_STATUS_READY
    );
    for needle in [
        "Command security: Off | Setting up | On | Needs attention",
        "Turn on extra security",
        "Not now",
        "guest down",
        "service missing",
        "ready",
        "prepare guest",
        "start Colima (if safe)",
        "verify install root",
        "repair hints",
    ] {
        assert!(window.contains(needle), "window must keep {needle}");
    }
}

#[test]
fn plus_n2_tool_loop_accumulates_a_multi_file_pending_set() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let a = plus_tool_propose_write(&bound, "one.txt", b"a\n".to_vec()).expect("a");
    let b = plus_tool_propose_write(&bound, "two.txt", b"b\n".to_vec()).expect("b");
    let mut set = crate::PendingFileSet::default();
    set.upsert(a);
    set.upsert(b);
    let presented = present_pending_file_set(&set);
    assert!(
        presented.contains("one.txt: pending") && presented.contains("two.txt: pending"),
        "{presented}"
    );
    assert!(!folder.join("one.txt").exists() && !folder.join("two.txt").exists());
}
