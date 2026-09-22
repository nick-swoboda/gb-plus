use super::{
    PLUS_CONTAINED_SPRINT_MAX_DURATION_MS, PLUS_CONTAINED_WALL_TIME_MS, PLUS_GUEST_ACTION_PREPARE,
    PLUS_REFUSAL_GUEST_HEADING, PLUS_REFUSAL_LIVE_HEADING, PLUS_REFUSAL_NOT_SUCCESS,
    PLUS_REFUSAL_TOOL_HEADING, PLUS_REFUSAL_WHAT_HAPPENED, PLUS_REFUSAL_WHAT_TO_DO, PendingFileSet,
    PlusInstallRootReport, PlusToolStep, plus_file_path_from_tool_steps, plus_first_grep_hit_path,
    plus_presentation_is_success_class_terminal, present_plus_guest_prepare,
    present_plus_host_error,
};

fn assert_plain_language_refusal(label: &str, text: &str, class_words: &[&str]) {
    for word in class_words {
        assert!(
            text.to_ascii_lowercase()
                .contains(&word.to_ascii_lowercase()),
            "{label} must name {word:?} in ordinary words: {text}"
        );
    }
    assert!(
        text.contains(PLUS_REFUSAL_WHAT_HAPPENED),
        "{label} must say what happened: {text}"
    );
    assert!(
        text.contains(PLUS_REFUSAL_WHAT_TO_DO),
        "{label} must say what to do next: {text}"
    );
    assert!(
        text.contains(PLUS_REFUSAL_NOT_SUCCESS),
        "{label} must not look like success: {text}"
    );
    assert!(
        !text.contains("Fake"),
        "{label} must not contain Fake: {text}"
    );
    assert!(
        !text.contains("Command succeeded"),
        "{label} must not present Command succeeded: {text}"
    );
    assert!(
        !plus_presentation_is_known_good_terminal(text),
        "{label} must not look known-good: {text}"
    );
}

#[test]
fn plus_guest_refusal_is_plain_language_not_fake_green() {
    let presented = present_plus_guest_unavailable_outcome(
        "PlatformLaunchBindingUnavailable: fexecve/execveat unavailable",
        &PlusGuestUnavailable {
            reasons: vec!["colima is not running (`colima start`)".into()],
        },
    );
    assert_plain_language_refusal(
        "guest down",
        &presented,
        &["guest", "not ready", PLUS_GUEST_STATUS_DOWN],
    );
    assert!(
        presented.contains(PLUS_REFUSAL_GUEST_HEADING),
        "guest down must lead with the non-dev heading: {presented}"
    );
    assert!(
        presented.contains(PLUS_GUEST_ACTION_START_COLIMA)
            && presented.contains(PLUS_GUEST_ACTION_VERIFY_INSTALL)
            && presented.contains(PLUS_GUEST_ACTION_REPAIR_HINTS),
        "guest down must name the repair actions: {presented}"
    );
    assert!(
        !crate::plus_outcome_is_real_command_terminal(&presented),
        "guest down must not look like a wire terminal: {presented}"
    );

    let missing = present_plus_guest_unavailable_outcome_with_kind(
        PlusGuestLifecycleKind::ServiceMissing,
        "",
        &PlusGuestUnavailable {
            reasons: vec!["install root is missing handoff-commitment.v1.json".into()],
        },
    );
    assert_plain_language_refusal(
        "service missing",
        &missing,
        &["guest", "not ready", PLUS_GUEST_STATUS_SERVICE_MISSING],
    );
    assert!(
        missing.contains(PLUS_GUEST_ACTION_VERIFY_INSTALL),
        "service missing must name verify install root: {missing}"
    );
}

#[test]
fn plus_live_refusal_is_plain_language_not_fake() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let identity =
        PlusLiveIdentity::from_configured_key("gbplus-o1a-live-SHOULD-NOT-LEAK").expect("test key");
    let error = plus_chat_turn_with_identity(&bound, "hello live", Some(identity), |_| {
        Err(PlusHostError::Live(
            "representative transport failure".into(),
        ))
    })
    .expect_err("live failure must surface");
    let presented = present_plus_host_error(&error);
    assert_plain_language_refusal(
        "live transport",
        &presented,
        &["live", "chat", "did not complete"],
    );
    assert!(
        presented.contains(PLUS_REFUSAL_LIVE_HEADING),
        "live refusal must lead with the non-dev heading: {presented}"
    );
    assert!(
        presented.contains("XAI_API_KEY"),
        "live refusal must name the key to check: {presented}"
    );
    assert!(
        presented.contains("representative transport failure"),
        "live refusal must keep the honest detail: {presented}"
    );
    assert_eq!(
        error.to_string(),
        "live provider refused: representative transport failure",
        "fail-closed Display must stay a live error, not a stub"
    );
}

#[test]
fn plus_tool_refusal_is_plain_language_and_fail_closed_parse() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let identity =
        PlusLiveIdentity::from_configured_key("gbplus-o1a-tool-SHOULD-NOT-LEAK").expect("test key");
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
    let raw = error.to_string();
    assert!(
        raw.contains(PLUS_LIVE_TOOL_PARSE_ERROR) && raw.contains("unknown tool bash"),
        "shipped parse path must stay fail-closed: {raw}"
    );
    let presented = present_plus_host_error(&error);
    assert_plain_language_refusal(
        "tool parse",
        &presented,
        &["tool", "cannot run", "parse failure"],
    );
    assert!(
        presented.contains(PLUS_REFUSAL_TOOL_HEADING)
            && presented.contains(PLUS_LIVE_TOOL_PARSE_ERROR)
            && presented.contains("unknown tool bash"),
        "tool refusal must keep the parse class: {presented}"
    );
    assert!(
        !presented.contains(PLUS_TOOL_LOOP_NOT_RUN),
        "parse failure must not present as no tools: {presented}"
    );
}

#[test]
fn plus_window_send_presents_host_error_on_the_real_path() {
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("present_plus_host_error(&error)"),
        "Send and smoke chat failures must present through present_plus_host_error"
    );
    assert!(
        window.contains("plus_chat_turn_and_remember_with_attachments_in_mode"),
        "Send must stay on the shipped remember path"
    );
    let host = include_str!("../lib.rs");
    assert!(
        host.contains("plus_gui_contained_command(")
            && host.contains("present_plus_guest_unavailable_outcome_with_kind("),
        "guest Run must still present through the shipped unavailable path"
    );
}

#[test]
fn plus_success_class_and_timed_out_stay_distinct_known_good() {
    let succeeded = present_command_termination(CommandTerminationV1::Exited { code: 0 });
    let timed_out = present_command_termination(CommandTerminationV1::TimedOut);
    assert!(
        plus_presentation_is_success_class_terminal(&succeeded)
            && succeeded.contains("Command succeeded")
            && succeeded.contains("Exited { code: 0 }"),
        "exit 0 must be success-class: {succeeded}"
    );
    assert!(
        plus_presentation_is_known_good_terminal(&timed_out)
            && timed_out.contains("Command timed out")
            && !plus_presentation_is_success_class_terminal(&timed_out),
        "TimedOut must stay known-good and not success-class: {timed_out}"
    );
}

#[test]
fn plus_contained_wall_clock_is_wide_enough_for_empty_main() {
    const {
        assert!(
            PLUS_CONTAINED_WALL_TIME_MS > 1_000
                && PLUS_CONTAINED_WALL_TIME_MS <= PLUS_CONTAINED_SPRINT_MAX_DURATION_MS,
            "plus wall clock must exceed the TimedOut-only budget and stay within the sprint"
        );
    }
    let host = include_str!("../lib.rs");
    assert!(
        host.contains("PLUS_CONTAINED_WALL_TIME_MS"),
        "plus contained policy must use PLUS_CONTAINED_WALL_TIME_MS, not a 1s literal"
    );
    assert!(
        !host.contains("wall_time_ms: 1_000"),
        "plus contained policy must not pin wall_time_ms at 1s"
    );
}

#[test]
fn plus_success_class_probe_presents_command_succeeded_when_guest_ready() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let run = plus_gui_contained_command(&bound);
    match probe_plus_guest_lifecycle() {
        super::PlusGuestLifecycle::Ready(_) => {
            assert!(
                plus_presentation_is_success_class_terminal(&run),
                "ready guest must present Command succeeded (Exited 0), not only TimedOut: {run}"
            );
            assert!(
                run.contains(PLUS_GUEST_STATUS_READY) && run.contains("permit minted"),
                "success-class ready guest must keep ready + permit: {run}"
            );
            assert!(
                !run.contains("12/12 achieved") && !run.contains("this is 12/12"),
                "success-class probe must not claim 12/12: {run}"
            );
            assert!(
                !run.contains("FakeProvider"),
                "success-class probe is not a Fake terminal: {run}"
            );
        }
        super::PlusGuestLifecycle::GuestDown { .. } => {
            assert!(
                run.contains(PLUS_GUEST_STATUS_DOWN)
                    && !plus_presentation_is_success_class_terminal(&run),
                "guest down must not fake Command succeeded: {run}"
            );
        }
        super::PlusGuestLifecycle::ServiceMissing { .. } => {
            assert!(
                run.contains(PLUS_GUEST_STATUS_SERVICE_MISSING)
                    && !plus_presentation_is_success_class_terminal(&run),
                "service missing must not fake Command succeeded: {run}"
            );
        }
    }
}

#[test]
fn plus_guest_prepare_is_one_step_and_refuses_unsafe_start() {
    let missing = PlusInstallRootReport {
        root: std::path::PathBuf::from("/opt/grok-build/phase1/install"),
        handoff_present: false,
        via: "local path".into(),
    };
    let presented = present_plus_guest_prepare(
        Err("COLIMA_HOME is unset; start Colima (if safe) refuses to clobber the default profile"),
        &missing,
        PlusGuestLifecycleKind::GuestDown,
    );
    assert!(
        presented.contains(PLUS_GUEST_ACTION_PREPARE)
            && presented.contains(PLUS_GUEST_ACTION_START_COLIMA)
            && presented.contains("refused")
            && presented.contains(PLUS_GUEST_ACTION_VERIFY_INSTALL)
            && presented.contains(PLUS_GUEST_ACTION_REPAIR_HINTS)
            && presented.contains(PLUS_GUEST_STATUS_DOWN),
        "prepare must sequence the three actions and keep the status word: {presented}"
    );
    assert!(
        !presented.contains("Fake") && !presented.contains("Command succeeded"),
        "prepare must not fake a terminal: {presented}"
    );
    let ready_install = PlusInstallRootReport {
        root: std::path::PathBuf::from("/opt/grok-build/phase1/install"),
        handoff_present: true,
        via: "local path".into(),
    };
    let ready = present_plus_guest_prepare(
        Ok("colima already considered by start Colima (if safe)"),
        &ready_install,
        PlusGuestLifecycleKind::Ready,
    );
    assert!(
        ready.contains(PLUS_GUEST_STATUS_READY) && ready.contains("handoff present"),
        "ready prepare must name ready + handoff: {ready}"
    );
}

#[test]
fn plus_grep_hit_opens_that_file_in_the_file_pane() {
    let folder = unique_folder();
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let hit = format!("open-hit-{unique}");
    fs::write(folder.join("open-me.txt"), format!("{hit}\n")).expect("seed");
    let bound = bind_project_folder(&folder).expect("bind");
    let grep = plus_tool_grep(&bound, &hit, ".", false).expect("grep");
    let path = plus_first_grep_hit_path(&grep).expect("hit path");
    assert_eq!(path, "open-me.txt", "grep hit must name the file: {grep}");
    let pane = present_plus_file_pane(&bound, path, &PendingFileSet::default());
    assert!(
        pane.contains("file open-me.txt") && pane.contains(&hit),
        "file pane must open the grep hit: {pane}"
    );
    let steps = [PlusToolStep {
        name: PlusToolName::Grep,
        request: hit.clone(),
        result: grep,
        ok: true,
    }];
    assert_eq!(plus_file_path_from_tool_steps(&steps), Some("open-me.txt"));
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains("plus_file_path_from_tool_steps(&turn.steps)"),
        "Send must open the grep hit on the shipped file pane"
    );
}
