use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

struct RecordingBrowser {
    calls: Mutex<Vec<PlusToolName>>,
}

impl PlusExternalToolExecutor for RecordingBrowser {
    fn execute(&self, request: &PlusToolRequest) -> Option<Result<String, PlusHostError>> {
        if !request.name.is_external() {
            return None;
        }
        self.calls.lock().expect("calls").push(request.name);
        Some(Ok("TRANSIENT_BROWSER_RESULT".into()))
    }
}

fn bound() -> BoundProject {
    let root = std::env::temp_dir().join(format!(
        "grok-build-browser-tool-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("workspace");
    super::super::bind_project_folder(root).expect("bind")
}

#[test]
fn all_browser_native_calls_parse_and_are_declared() {
    let calls = vec![
        (
            "browser_navigate".into(),
            r#"{"url":"https://example.test/path"}"#.into(),
        ),
        ("browser_inspect".into(), "{}".into()),
        ("browser_click".into(), r#"{"node_id":7}"#.into()),
        (
            "browser_type".into(),
            r#"{"node_id":8,"text":"private input"}"#.into(),
        ),
        ("browser_key".into(), r#"{"key":"Enter"}"#.into()),
        ("browser_scroll".into(), r#"{"delta_y":400}"#.into()),
        ("browser_screenshot".into(), "{}".into()),
    ];
    let requests = parse_plus_live_tool_reply("", &calls).expect("parse Browser calls");
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests
            .iter()
            .map(|request| request.name)
            .collect::<Vec<_>>(),
        vec![
            PlusToolName::BrowserNavigate,
            PlusToolName::BrowserInspect,
            PlusToolName::BrowserClick,
            PlusToolName::BrowserType,
            PlusToolName::BrowserKey,
            PlusToolName::BrowserScroll,
            PlusToolName::BrowserScreenshot,
        ]
    );
    assert_eq!(
        requests[3].after.as_deref(),
        Some(b"private input".as_slice())
    );

    let declarations = plus_live_tool_declarations();
    let names = declarations
        .as_array()
        .expect("declarations")
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    for name in [
        "browser_navigate",
        "browser_inspect",
        "browser_click",
        "browser_type",
        "browser_key",
        "browser_scroll",
        "browser_screenshot",
    ] {
        assert!(names.contains(&name), "missing Browser declaration {name}");
    }
}

#[test]
fn browser_dispatch_is_absent_by_default_and_scoped_when_supplied() {
    let bound = bound();
    let request =
        plus_tool_request_from_name_and_args("browser_inspect", "{}").expect("Browser request");
    let mut events = Vec::new();
    let refused = run_plus_tool_loop_on_store_in_mode_observed(
        &bound,
        None,
        std::slice::from_ref(&request),
        PlusSessionMode::Agent,
        &mut |event| {
            events.push(event);
            Ok(())
        },
    )
    .expect("fail-closed report");
    assert!(!refused.steps[0].ok);
    assert!(
        refused.steps[0]
            .result
            .contains("no armed app-owned Browser dispatcher")
    );
    assert!(matches!(
        events.last(),
        Some(PlusToolLifecycleEvent::Refused { .. })
    ));

    let external = RecordingBrowser {
        calls: Mutex::new(Vec::new()),
    };
    events.clear();
    let completed = run_plus_tool_loop_on_store_in_mode_observed_external(
        &bound,
        None,
        &[request],
        PlusSessionMode::Agent,
        &mut |event| {
            events.push(event);
            Ok(())
        },
        Some(&external),
    )
    .expect("scoped Browser report");
    assert!(completed.steps[0].ok);
    assert_eq!(completed.steps[0].result, "TRANSIENT_BROWSER_RESULT");
    assert_eq!(
        *external.calls.lock().expect("calls"),
        vec![PlusToolName::BrowserInspect]
    );
    assert!(matches!(
        events.as_slice(),
        [
            PlusToolLifecycleEvent::Requested { .. },
            PlusToolLifecycleEvent::Completed { .. }
        ]
    ));
}

#[test]
fn desktop_calls_are_declared_strictly_parsed_and_text_is_not_labeled() {
    let calls = vec![
        (
            "desktop_click".into(),
            r#"{"x":12.5,"y":44,"button":"left"}"#.into(),
        ),
        (
            "desktop_type".into(),
            r#"{"text":"TRANSIENT_DESKTOP_SENTINEL"}"#.into(),
        ),
        (
            "desktop_key".into(),
            r#"{"key":"a","modifiers":["command","shift"]}"#.into(),
        ),
        (
            "desktop_scroll".into(),
            r#"{"delta_x":-50,"delta_y":400}"#.into(),
        ),
    ];
    let requests = parse_plus_live_tool_reply("", &calls).expect("parse Desktop calls");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.name)
            .collect::<Vec<_>>(),
        vec![
            PlusToolName::DesktopClick,
            PlusToolName::DesktopType,
            PlusToolName::DesktopKey,
            PlusToolName::DesktopScroll,
        ]
    );
    assert_eq!(requests[0].path, PathBuf::from("12.5,44"));
    assert_eq!(requests[2].query.as_deref(), Some("command,shift"));
    assert_eq!(tool_request_label(&requests[1]), "bounded transient text");
    assert!(!tool_request_label(&requests[1]).contains("SENTINEL"));

    let declarations = plus_live_tool_declarations();
    let names = declarations
        .as_array()
        .expect("declarations")
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    for name in [
        "desktop_click",
        "desktop_type",
        "desktop_key",
        "desktop_scroll",
    ] {
        assert!(names.contains(&name), "missing Desktop declaration {name}");
    }

    for (name, args) in [
        ("desktop_click", r#"{"x":-1,"y":0}"#),
        ("desktop_click", r#"{"x":1e309,"y":0}"#),
        ("desktop_type", r#"{"text":""}"#),
        ("desktop_key", r#"{"key":"F12"}"#),
        (
            "desktop_key",
            r#"{"key":"a","modifiers":["command","command"]}"#,
        ),
        ("desktop_scroll", r#"{"delta_x":0,"delta_y":0}"#),
        ("desktop_scroll", r#"{"delta_x":0,"delta_y":2001}"#),
    ] {
        assert!(
            plus_tool_request_from_name_and_args(name, args).is_err(),
            "malformed {name} must refuse"
        );
    }
}

#[test]
fn desktop_dispatch_is_off_by_default_and_uses_only_external_grant_owner() {
    let bound = bound();
    let request =
        plus_tool_request_from_name_and_args("desktop_key", r#"{"key":"Enter","modifiers":[]}"#)
            .expect("Desktop request");
    let mut events = Vec::new();
    let refused = run_plus_tool_loop_on_store_in_mode_observed(
        &bound,
        None,
        std::slice::from_ref(&request),
        PlusSessionMode::Agent,
        &mut |event| {
            events.push(event);
            Ok(())
        },
    )
    .expect("fail-closed Desktop report");
    assert!(!refused.steps[0].ok);
    assert!(
        refused.steps[0]
            .result
            .contains("Desktop Control tool refused")
    );
    assert!(matches!(
        events.last(),
        Some(PlusToolLifecycleEvent::Refused { .. })
    ));

    let external = RecordingBrowser {
        calls: Mutex::new(Vec::new()),
    };
    let completed = run_plus_tool_loop_on_store_in_mode_observed_external(
        &bound,
        None,
        &[request],
        PlusSessionMode::Agent,
        &mut |_| Ok(()),
        Some(&external),
    )
    .expect("scoped Desktop report");
    assert!(completed.steps[0].ok);
    assert_eq!(
        *external.calls.lock().expect("calls"),
        vec![PlusToolName::DesktopKey]
    );
}
