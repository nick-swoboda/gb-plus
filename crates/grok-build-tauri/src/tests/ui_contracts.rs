use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    Backend, PLUS_PROVIDER_LABEL, PlusSessionStore, backend::reconcile_review_blocks_from_sessions,
    smoke_tauri_host,
};
use crate::backend::{NO_CHAT_YET, NO_TERMINAL_YET, chat_without_stub_banner};
use crate::contracts::{ProjectId, SessionId};
use crate::project_transition_support::BackendProjectTransitions as _;
use crate::queue::QueueCoordinator;
use crate::runtime::cancel::RuntimeCancelHandle;
use grok_build_plus_host::{PlusCommandSecurityPreference, PlusProjectBook};

#[path = "frontend_contract.rs"]
mod frontend_contract;
use frontend_contract::{CssContract, HtmlContract, assert_no_forbidden_javascript_apis};

static NEXT_TEST: AtomicU64 = AtomicU64::new(1);
const REQUIRED_DESTINATIONS: [&str; 8] = [
    "Project",
    "Chat",
    "Workspace",
    "Terminal",
    "Review",
    "Activity",
    "Checks",
    "Account",
];

fn assert_registered_command(name: &str) {
    let registry = include_str!("../../tests/fixtures/tauri-command-registry.txt");
    assert!(
        registry.lines().any(|candidate| candidate == name),
        "missing registered Tauri command {name}"
    );
}

fn assert_workspace_browser_assets(html: &str, css: &str, javascript: &str) {
    let document = HtmlContract::parse(html);
    assert!(javascript.contains("list_workspace_directory"));
    assert!(javascript.contains("open_workspace_file"));
    assert_no_forbidden_javascript_apis(&[javascript]);
    assert!(css.contains(".workspace-browser-shell"));
    document.require_id("workspace-tree");
    document.require_id("workspace-file-content");
    assert!(!html.contains("Symlinks are shown but never followed"));
}

fn assert_worktree_assets(html: &str, javascript: &str) {
    for command in [
        "list_worktrees",
        "create_worktree",
        "activate_workspace",
        "remove_worktree",
        "commit_worktree",
        "discard_worktree",
        "export_worktree_recovery",
        "remove_worktree_after_export",
    ] {
        assert!(javascript.contains(command), "missing {command} UI route");
    }
    assert_no_forbidden_javascript_apis(&[javascript]);
    HtmlContract::parse(html).require_id("worktree-manager");
    assert!(html.contains("User-only Git actions; agents cannot call them"));
}

fn assert_git_review_assets(html: &str, css: &str, javascript: &str) {
    for command in [
        "list_git_review",
        "stage_git_hunk",
        "unstage_git_hunk",
        "discard_git_hunk",
    ] {
        assert!(javascript.contains(command), "missing {command} UI route");
    }
    assert_no_forbidden_javascript_apis(&[javascript]);
    assert!(!html.contains("id=\"agent-proposals-title\""));
    assert!(html.contains("id=\"chat-change-card\""));
    assert!(html.contains("id=\"git-review-title\""));
    assert!(html.contains("agents cannot call them"));
    assert!(css.contains(".git-hunk-card"));
    assert!(css.contains("#git-review-status[data-kind=\"refused\"]"));
}

fn assert_activity_assets(
    html: &str,
    app_javascript: &str,
    diagnostic_javascript: &str,
    timeline_javascript: &str,
    usage_javascript: &str,
) {
    assert!(diagnostic_javascript.contains("export_diagnostics"));
    assert_no_forbidden_javascript_apis(&[
        diagnostic_javascript,
        timeline_javascript,
        usage_javascript,
    ]);
    assert!(timeline_javascript.contains("Durable metadata only"));
    assert!(timeline_javascript.contains("SHA-256"));
    assert!(timeline_javascript.contains("frame_captured"));
    assert!(usage_javascript.contains("BigInt"));
    assert!(usage_javascript.contains("tokensVisible"));
    assert!(app_javascript.contains("grok-build-plus-activity-event"));
    assert!(app_javascript.contains("usagePresentation.render(snapshot.usage)"));
    assert!(html.contains("id=\"export-diagnostics\""));
    assert!(html.contains("id=\"timeline-list\""));
    assert!(html.contains("id=\"chat-context-meter\""));
    assert!(!html.contains("id=\"chat-context-track\" role=\"progressbar\""));
    assert!(usage_javascript.contains("setAttribute(\"role\", \"progressbar\")"));
    assert!(usage_javascript.contains("removeAttribute(\"aria-valuenow\")"));
    assert!(html.contains("id=\"usage-token-chart\""));
    assert!(
        html.contains("Provider-reported token categories; categories are not assumed additive")
    );
    assert!(html.contains("No usage data"));
    assert!(html.contains("No prompts, secrets, or media."));
    assert!(!html.contains("PROVIDER-REPORTED ONLY"));
    assert!(!html.contains("DURABLE EVENT STREAM"));
    let document = HtmlContract::parse(html);
    for id in [
        "activity-title",
        "export-diagnostics",
        "timeline-list",
        "usage-token-chart",
    ] {
        document.require_id(id);
    }
}

fn assert_chat_scheduling_assets(html: &str, app_javascript: &str, queue_javascript: &str) {
    for command in [
        "send_now",
        "steer_queue_item",
        "send_next",
        "release_held_message",
        "retry_queue_run",
        "remove_queue_item",
    ] {
        assert!(
            app_javascript.contains(command) || queue_javascript.contains(command),
            "missing {command} Chat scheduling route"
        );
    }
    assert_no_forbidden_javascript_apis(&[app_javascript, queue_javascript]);
    for retired in [
        "data-view=\"tasks\"",
        "data-view-panel=\"tasks\"",
        "id=\"enqueue-chat\"",
        "Queue message",
        "id=\"task-board\"",
        "id=\"queue-pause\"",
        "id=\"queue-run-next\"",
    ] {
        assert!(
            !html.contains(retired),
            "retired Tasks/queue UI remains: {retired}"
        );
    }
    for retired_command in ["enqueue_chat", "set_queue_paused", "run_next_queued"] {
        assert!(!app_javascript.contains(retired_command));
        assert!(!queue_javascript.contains(retired_command));
    }
    for control in [
        "id=\"send-control\"",
        "id=\"send-menu-toggle\"",
        "id=\"send-next\"",
        "id=\"chat-next-strip\"",
        "id=\"chat-steer-confirmation\"",
        "id=\"chat-steer-submit\"",
        "id=\"chat-change-card\"",
    ] {
        assert!(
            html.contains(control),
            "missing Chat-first control {control}"
        );
    }
    assert!(queue_javascript.contains("Held from an earlier version"));
    assert!(queue_javascript.contains("predecessorRunId"));
    assert!(queue_javascript.contains("Send now"));
    assert!(queue_javascript.contains("Send next"));
}

#[test]
fn steer_popover_is_countless_confirmed_and_retry_is_failed_only() {
    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/modules/queue.js");
    let css = include_str!("../../ui/styles.css");

    let document = HtmlContract::parse(html);
    for id in [
        "chat-next-summary",
        "chat-next-popover",
        "chat-steer-confirmation",
        "chat-steer-preview",
        "chat-steer-cancel",
        "chat-steer-submit",
    ] {
        document.require_id(id);
    }
    assert!(html.contains(">Steer</button>"));
    assert!(html.contains("<strong>Steer this run?</strong>"));
    assert!(html.contains("title=\"Send at the next safe step\">Send now</button>"));
    assert!(javascript.contains("const RETRY_STATES = new Set([\"failed\"]);"));
    assert!(javascript.contains("runMatchesItem(currentRun, item)"));
    assert!(javascript.contains("\"steer_queue_item\""));
    assert!(javascript.contains("const visible = run ? ["));
    assert!(javascript.contains("elements.chatNextSummary.textContent = \"Steer\";"));
    assert!(!javascript.contains("Waiting for changes"));
    assert!(!javascript.contains("${visible.length} next"));
    assert!(!javascript.contains("is-inline"));
    assert!(!html.contains("Interrupt?"));
    assert!(!javascript.contains("Interrupt?"));
    assert!(css.contains(".chat-steer-confirmation {"));
    assert_registered_command("steer_queue_item");
}

#[test]
fn waiting_message_is_visible_in_chat_and_idle_gate_is_not_steering() {
    let html = include_str!("../../ui/index.html");
    let app = include_str!("../../ui/app.js");
    let queue = include_str!("../../ui/modules/queue.js");
    let read_aloud = include_str!("../../ui/modules/read_aloud.js");
    let review = include_str!("../../ui/modules/review.js");
    let run_status = include_str!("../../ui/modules/run_status.js");
    let turn_status = include_str!("../../ui/modules/turn_status.js");
    let css = include_str!("../../ui/styles.css");

    HtmlContract::parse(html).require_id("chat-pending-turns");
    assert!(app.contains("chatScheduling.hasPendingTurns(snapshot)"));
    assert!(queue.contains("item.projectId === next.activeProjectId"));
    assert!(queue.contains("item.sessionId === sessionId"));
    assert!(queue.contains("article.dataset.role = \"user\";"));
    assert!(queue.contains("elements.chatPendingTurns.replaceChildren"));
    assert!(queue.contains("const visible = run ? ["));
    assert!(queue.contains("status.dataset.runId = entry.runId"));
    assert!(queue.contains("setRunPresentation(presentation)"));
    assert!(queue.contains("perform(\"remove_queue_item\""));
    assert!(queue.contains("import { parseChatMessages } from \"./read_aloud.js\""));
    assert!(queue.contains("retainedItems(queue, currentItems, next.chat)"));
    assert!(
        queue.contains(
            "const RETAINED_STATES = new Set([\"failed\", \"stopped\", \"interrupted\"])"
        )
    );
    assert!(queue.contains("[\"done\", \"needs_review\"].includes(entry.run?.state)"));
    assert!(queue.contains("? \"Waiting\" : null"));
    assert!(!queue.contains("Waiting for changes"));
    assert!(app.contains("chatScheduling.setRunPresentation(presentation)"));
    assert!(turn_status.contains("window.setInterval(paint, 100)"));
    assert!(turn_status.contains("terminalRunText(terminal)"));
    assert!(!turn_status.contains("Waiting for review"));
    assert!(!turn_status.contains("Accept or reject"));
    assert!(read_aloud.contains("export function annotateCompletedRuns(messages, snapshot)"));
    assert!(
        read_aloud.contains(
            "messageFromText(match.item.prompt, match.item.ordinal, \"user\", \"queue\")"
        )
    );
    assert!(read_aloud.contains("summary += ` · ${contextUsed} / ${contextSize}`"));
    assert!(review.contains("count === 1 ? \"Change\""));
    assert!(review.contains("`View pending change to ${items[0].path}`"));
    assert!(review.contains("elements.chatPendingTurns.querySelector(\".chat-pending-message\")"));
    assert!(run_status.contains("export function terminalRunText(run)"));
    assert!(css.contains(".chat-pending-turns {"));
    assert!(css.contains(".chat-pending-status,"));
    assert!(css.contains(".chat-run-summary {"));
}

#[test]
fn resolving_chat_changes_immediately_resumes_durable_waiting_work() {
    let scheduling = include_str!("../commands/scheduling.rs");
    let helper = scheduling
        .split_once("async fn resolve_proposal_and_resume(")
        .expect("proposal-resume helper")
        .1
        .split_once("#[tauri::command]")
        .expect("bounded proposal-resume helper")
        .0;

    assert!(helper.contains("with_backend(state, operation).await?"));
    assert!(helper.contains("schedule_available(&app, &shared, None, false)?"));
    assert!(helper.contains("current_snapshot(&shared).await"));
    assert_eq!(
        scheduling
            .matches("resolve_proposal_and_resume(app, state")
            .count(),
        6,
        "every single-file and batch Accept/Reject path must wake eligible waiting work"
    );
}

fn assert_required_destinations(html: &str) {
    for destination in REQUIRED_DESTINATIONS {
        assert!(
            html.contains(destination),
            "missing {destination} destination"
        );
    }
}

fn assert_terminal_assets(html: &str, javascript: &str, css: &str) {
    assert!(html.contains("id=\"terminal-form\""));
    assert!(html.contains("Interactive user shell. Not contained."));
    assert_eq!(html.matches("data-view-panel=\"terminal\"").count(), 1);
    assert!(html.contains("id=\"terminal-xterm\""));
    assert!(html.contains("id=\"pty-start\""));
    assert!(html.contains("Contained project command"));
    assert!(javascript.contains("../vendor/xterm/xterm.mjs"));
    assert!(javascript.contains("../vendor/xterm/addon-fit.mjs"));
    assert!(javascript.contains("linkHandler: INERT_LINK_HANDLER"));
    assert!(javascript.contains("allowNonHttpProtocols: false"));
    assert!(javascript.contains("screenReaderMode: true"));
    assert!(!javascript.contains("window.open"));
    assert!(!javascript.contains("registerLinkProvider"));
    assert!(css.contains(".terminal-state[data-state=\"failed\"]"));
    assert!(css.contains(".terminal-state[data-state=\"live\"]"));
    assert_eq!(
        grok_build_plus_host::worktree_recovery_digest(include_bytes!(
            "../../ui/vendor/xterm/xterm.mjs"
        )),
        "b336ec65a086c056d4804b3d4c2347da5663d3f23c3f25be866467bd8857ad59"
    );
    assert_eq!(
        grok_build_plus_host::worktree_recovery_digest(include_bytes!(
            "../../ui/vendor/xterm/addon-fit.mjs"
        )),
        "2d87e1bddc73be9111de8beee5370c3bb7aac9c94e18e6f245f02ca741ef1769"
    );
}

fn assert_account_assets(html: &str, javascript: &str, account_css: &str) {
    assert!(html.contains("id=\"account-status\""));
    assert!(html.contains(">Connect with Grok Subscription</button>"));
    assert!(html.contains(">Connect with API key</button>"));
    assert!(html.contains("id=\"replace-xai-key\""));
    assert!(!html.contains("id=\"account-skip\""));
    assert!(html.find("id=\"account-disconnect\"") < html.find("class=\"account-reconnect-row\""));
    assert!(html.contains("id=\"account-cli-details\""));
    assert!(!javascript.contains(
        "if (!account.connected && !account.onboardingAcknowledged) setView(\"account\")"
    ));
    assert!(javascript.contains("connect_saved_xai_key"));
    assert!(!javascript.contains("acknowledge_account_onboarding"));
    assert!(javascript.contains("Connect with saved API key"));
    assert!(
        javascript.contains("cliConnected ? \"Connected\" : \"Connect with Grok Subscription\"")
    );
    assert!(javascript.contains("xaiConnected\n    ? \"Connected\""));
    assert!(javascript.contains("elements.accountDisconnect.hidden = !account.connected"));
    assert!(javascript.contains("update.kind === \"account_onboarding\""));
    assert!(!javascript.contains("elements.loginGrokCli.hidden"));
    let startup = javascript
        .split("async function start()")
        .nth(1)
        .expect("frontend startup function");
    assert!(
        !startup.contains("\"login_grok_cli\""),
        "launch must not auto-run the CLI OAuth flow"
    );
    assert!(account_css.contains(".account-onboarding-status[data-phase=\"failed\"]"));
    assert!(account_css.contains("border-color: var(--refuse)"));
    assert!(!account_css.contains("[data-phase=\"idle\"] {\n  border-color: var(--refuse)"));
}

fn fixture_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "grok-build-tauri-{label}-{}-{}",
        std::process::id(),
        NEXT_TEST.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn first_run_is_not_connected_with_honest_off_status() {
    let root = fixture_root("first-run");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    let snapshot = backend.snapshot();
    assert_eq!(snapshot.version, "0.2.2-plus");
    assert_eq!(snapshot.security.kind, "off");
    assert_eq!(snapshot.security.status, "Command security: Off");
    assert_eq!(snapshot.security.copy, "Adds isolation to agent commands.");
    assert!(!snapshot.security.checked);
    assert!(!snapshot.security.can_run_commands);
    assert_eq!(snapshot.security.action_label, "Check for Container");
    assert_eq!(snapshot.chat, NO_CHAT_YET);
    assert_eq!(snapshot.terminal_output, NO_TERMINAL_YET);
    assert!(snapshot.staged.is_empty());
    assert_eq!(snapshot.account.status, "Not connected");
    assert!(!snapshot.account.connected);
    assert!(!snapshot.account.onboarding_acknowledged);
    assert!(snapshot.account.auto_reconnect_enabled);
    assert!(matches!(
        snapshot.account.reconnect_state,
        crate::runtime::types::ReconnectState::NeedsConnection
    ));
    assert!(snapshot.account.preference_issue.is_none());
    assert_eq!(snapshot.usage.context.state, "unknown");
    assert_eq!(snapshot.usage.context.label, "Unknown");
    assert!(!snapshot.usage.tokens_visible);
    assert!(!snapshot.usage.cost_visible);
}

#[test]
fn queued_prompt_transport_mismatch_refuses_before_any_run() {
    use crate::contracts::{ProjectId, QueueItemId, SessionId, WorkspaceId};
    use crate::queue::{QueueItem, QueueItemState};
    use crate::runtime::types::RuntimeTransport;

    let root = fixture_root("queued-transport-mismatch");
    let backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    let item = QueueItem {
        id: QueueItemId::new("queue-other-transport"),
        project_id: ProjectId::new("project-other-transport"),
        workspace_id: WorkspaceId::new("workspace-other-transport"),
        workspace_root: root.join("workspace").display().to_string(),
        session_id: SessionId::new("session-other-transport"),
        transport: RuntimeTransport::XaiKeychain,
        workflow: None,
        prompt: "hello".into(),
        auto_start: true,
        state: QueueItemState::Queued,
        enqueued_at_unix_ms: 1,
        ordinal: 1,
        retry_of_run_id: None,
        predecessor_run_id: None,
        blocked_reason: None,
    };
    let Err(error) = backend.prepare_queued_run(&item) else {
        panic!("transport mismatch must refuse before preparing a run");
    };
    assert_eq!(
        error.kind,
        crate::backend::PrepareQueuedRunErrorKind::TransportUnavailable
    );
    assert!(error.detail.contains("bound to XaiKeychain"));
    assert!(error.detail.contains("selected GrokCliAcp"));
    drop(backend);
    fs::remove_dir_all(root).expect("remove transport mismatch fixture");
}

#[test]
fn subscription_turn_persists_user_before_assistant_for_chronological_chat() {
    use crate::backend::persisted_queued_chat_turn;
    use crate::runtime::types::RuntimeTransport;

    let subscription =
        persisted_queued_chat_turn(RuntimeTransport::GrokCliAcp, "Hi", "Assistant: Hello.");
    assert_eq!(subscription, "You: Hi\nAssistant: Hello.");
    let direct = "Provider: live xAI (XaiKeychain)\nYou: Hi\nAssistant: Hello.";
    assert_eq!(
        persisted_queued_chat_turn(RuntimeTransport::XaiKeychain, "Hi", direct),
        direct
    );
    let read_aloud = include_str!("../../ui/modules/read_aloud.js");
    assert!(read_aloud.contains("...chatMessages.map("));
    assert!(!read_aloud.contains("[...chatMessages].reverse()"));
}

#[test]
fn workflow_completion_preserves_chat_across_transports_and_reload() {
    use crate::backend::PreparedQueuedRun;
    use crate::contracts::{QueueItemId, WorkspaceId};
    use crate::queue::workflows::WorkflowTicket;
    use crate::runtime::engine::{EngineMode, EngineSettings};
    use crate::runtime::manager::RuntimeManager;
    use crate::runtime::types::{AdapterTurn, AdapterTurnOutcome, RuntimeTransport};
    use grok_build_plus_host::{PendingFileSet, bind_project_folder};

    for (mode, transport) in [
        (EngineMode::GrokCliStandard, RuntimeTransport::GrokCliAcp),
        (EngineMode::GbPlusContained, RuntimeTransport::GrokCliAcp),
        (EngineMode::GbPlusContained, RuntimeTransport::XaiKeychain),
    ] {
        let root = fixture_root("workflow-chat-boundary");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
        let settings = EngineSettings {
            mode,
            ..Default::default()
        };
        backend.set_engine(settings.clone()).unwrap();
        backend.bind_project(workspace.to_str().unwrap()).unwrap();
        let session = SessionId::new(backend.store.active_plus_session_id().unwrap());
        let original = "You: earlier question\nAssistant: earlier reply";
        backend
            .store
            .append_chat_turn_to_session(session.as_str(), original)
            .unwrap();
        let mut runtime = RuntimeManager::offline(root.join("runtime"));
        runtime.set_engine(settings).unwrap();
        runtime.select(transport).unwrap();
        let prepared = PreparedQueuedRun {
            queue_item_id: QueueItemId::new("workflow-attempt"),
            workflow: Some(WorkflowTicket {
                job_id: "a".repeat(64),
                attempt: 1,
            }),
            project_id: backend.active_project_typed_id().unwrap(),
            workspace_id: WorkspaceId::new("fixture-workspace"),
            session_id: session.clone(),
            prompt: "Workflow: reviewed example".into(),
            bound: bind_project_folder(&workspace).unwrap(),
            run_store: PlusSessionStore::from_state_root(root.join("run")),
            run_state_root: root.join("run"),
            extension_context: String::new(),
            runtime,
        };
        backend.mark_queued_session_running(&session).unwrap();
        let turn = AdapterTurn {
            assistant_text: "{\"outcome\":\"completed\",\"result\":\"workflow-only\"}".into(),
            pending: PendingFileSet::default(),
            provider_session_id: None,
            usage: None,
            outcome: AdapterTurnOutcome::Completed,
        };
        assert!(!backend.apply_queued_turn(&prepared, &turn).unwrap());
        assert_eq!(backend.chat, original);
        assert_eq!(
            backend.store.load_chat_transcript().unwrap().as_deref(),
            Some(original)
        );
        drop(prepared);
        drop(backend);
        let reloaded = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
        assert_eq!(reloaded.chat, original);
        drop(reloaded);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn returning_keychain_user_gets_saved_key_connect_without_secure_reentry() {
    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/app.js");
    assert!(html.contains(">Connect with API key</button>"));
    assert!(html.contains(">Replace API key…</button>"));
    assert!(javascript.contains("Connect with saved API key"));
    assert!(javascript.contains("hasSavedKey ? \"connect_saved_xai_key\" : \"configure_xai_key\""));
    assert_registered_command("connect_saved_xai_key");
    assert_registered_command("configure_xai_key");
}

#[test]
fn first_run_without_key_keeps_secure_api_key_entry() {
    let javascript = include_str!("../../ui/app.js");
    assert!(javascript.contains("keychainPresence: { state: \"unchecked\" }"));
    assert!(javascript.contains("onboardingAcknowledged: false"));
    assert!(javascript.contains("autoReconnectEnabled: true"));
    assert!(javascript.contains("set_auto_reconnect"));
    assert!(javascript.contains("reconnect_authorized_account"));
    assert!(javascript.contains(": \"Connect with API key\""));
    assert_registered_command("configure_xai_key");
}

#[test]
fn legacy_chat_contained_rows_are_presented_from_their_real_outcome() {
    let legacy_refusal = "tool run_contained → completed: Command security: Off\nContained command runs are unavailable.\nThis is not a successful command.\nYou: next";
    let corrected = chat_without_stub_banner(legacy_refusal);
    assert!(corrected.contains("tool run_contained → failed:"));
    assert!(!corrected.contains("tool run_contained → completed:"));

    let genuine_success =
        "tool run_contained → completed: Command security: On\nCommand succeeded\nYou: next";
    let preserved = chat_without_stub_banner(genuine_success);
    assert!(preserved.contains("tool run_contained → completed:"));
    assert!(!preserved.contains("tool run_contained → failed:"));
}

#[test]
fn snapshot_usage_is_exact_provider_data_from_the_latest_bound_run_only() {
    use crate::contracts::{QueueItemId, RunId};
    use crate::events::{EventContext, EventPayload, RunEventAction};
    use crate::runtime::types::{RuntimeTransport, RuntimeUsage};

    let root = fixture_root("snapshot-usage");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create usage workspace");
    let workspace = workspace.canonicalize().expect("canonical usage workspace");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind usage workspace");
    let active = backend
        .active_event_context()
        .expect("active usage context");
    let project = active.project.clone().expect("active project id");
    let session = active.session.clone().expect("active session id");
    let first_run = RunId::new("run-usage-one");
    let first_context = EventContext::run(project.clone(), session.clone(), first_run.clone());
    backend
        .events
        .record(
            first_context.clone(),
            EventPayload::Run {
                action: RunEventAction::Started,
                queue_item_id: QueueItemId::new("queue-usage-one"),
                transport: RuntimeTransport::GrokCliAcp,
            },
        )
        .expect("record usage run start");
    backend
        .events
        .record(
            first_context,
            EventPayload::Usage {
                transport: RuntimeTransport::GrokCliAcp,
                usage: RuntimeUsage {
                    input_tokens: Some(u64::MAX),
                    context_used: Some(1),
                    context_size: Some(4),
                    ..RuntimeUsage::default()
                },
            },
        )
        .expect("record provider usage");
    let snapshot = backend.snapshot();
    assert_eq!(snapshot.usage.run_id.as_deref(), Some(first_run.as_str()));
    assert_eq!(
        snapshot.usage.source_transport.as_deref(),
        Some("GrokCliAcp")
    );
    assert_eq!(
        snapshot.usage.input_tokens.as_deref(),
        Some("18446744073709551615")
    );
    assert_eq!(snapshot.usage.context.basis_points, Some(2_500));

    backend
        .events
        .record(
            EventContext::run(project, session, RunId::new("run-usage-two")),
            EventPayload::Run {
                action: RunEventAction::Started,
                queue_item_id: QueueItemId::new("queue-usage-two"),
                transport: RuntimeTransport::GrokCliAcp,
            },
        )
        .expect("record newer run without usage");
    let latest = backend.snapshot();
    assert_eq!(latest.usage.context.state, "unknown");
    assert!(!latest.usage.tokens_visible);
    fs::remove_dir_all(root).expect("remove snapshot usage fixture");
}

#[test]
fn tauri_smoke_keeps_writes_staged_and_refuses_contained_off() {
    let report = smoke_tauri_host().expect("Tauri host smoke should pass");
    assert!(report.contains("TAURI HOST SMOKE PASSED"));
    assert!(report.contains("staged-until-Accept=true"));
    assert!(report.contains("contained-refused=true"));
    assert!(report.contains("tool-refusal-not-success=true"));
    assert!(report.contains("pty-control-executed=true"));
    assert!(report.contains("pty-enforced-refuse=true"));
    assert!(report.contains("pty-private-probe=true"));
    assert!(report.contains("pty-live=true"));
    assert!(report.contains("pty-resize=true"));
    assert!(report.contains("pty-io=true"));
    assert!(report.contains("pty-not-contained=true"));
    assert!(report.contains("chat-scheduling-durable=true"));
    assert!(report.contains("send-now-recovered-as-next=true"));
    assert!(report.contains("send-next-predecessor-bound=true"));
    assert!(report.contains("queue-crash-interrupted=true"));
    assert!(report.contains("queue-auto-replay=false"));
    assert!(!report.contains("task-board"));
    assert!(report.contains("activity-durable=true"));
    assert!(report.contains("activity-monotonic=true"));
    assert!(report.contains("activity-content-redacted=true"));
    assert!(report.contains("context-unknown-honest=true"));
    assert!(report.contains("usage-hidden-when-absent=true"));
    assert!(report.contains("usage-provider-only=true"));
}

#[test]
fn project_license_is_mit_while_third_party_notices_remain_truthful() {
    let license = include_str!("../../../../LICENSE");
    let manifest = include_str!("../../../../Cargo.toml");
    let readme = include_str!("../../../../README.md");
    let attribution = include_str!("../../../../ATTRIBUTION.md");
    let eframe_manifest = include_str!("../../../../tests/ui-toolkit/eframe-spike/Cargo.toml");
    let slint_manifest = include_str!("../../../../tests/ui-toolkit/slint-1.17.1/Cargo.toml");
    let xterm_license = include_str!("../../ui/vendor/xterm/LICENSE.xterm");

    assert!(license.starts_with("MIT License\n\nCopyright (c) 2026 GB Plus contributors"));
    assert!(manifest.contains("license = \"MIT\""));
    assert!(readme.contains("Contributions require Developer Certificate of Origin"));
    assert!(readme.contains("license of the component being changed"));
    assert!(attribution.contains("GB Plus's original components are licensed under MIT."));
    assert!(attribution.contains("The root license does not replace the licenses"));
    assert!(attribution.contains("Apache-2.0 OR MIT"));
    let host_manifest = include_str!("../../../grok-build-plus-host/Cargo.toml");
    let workflow_manifest = include_str!("../../../grok-build-workflow/Cargo.toml");
    let prompt = include_str!("../../../grok-build-plus-host/prompts/system.md");
    assert!(host_manifest.contains("license = \"MIT AND Apache-2.0\""));
    assert!(workflow_manifest.contains("license = \"Apache-2.0\""));
    assert!(prompt.starts_with("<!-- SPDX-License-Identifier: Apache-2.0"));
    assert!(prompt.contains("Modified for GB Plus"));
    assert!(eframe_manifest.contains("license = \"MIT\""));
    assert!(slint_manifest.contains("license = \"MIT\""));
    assert!(xterm_license.contains("Copyright (c) 2017-2019, The xterm.js authors"));
    assert!(xterm_license.contains("Permission is hereby granted, free of charge"));
}

#[test]
fn managed_git_mutations_are_absent_from_agent_tool_declarations() {
    let declarations = grok_build_plus_host::plus_live_tool_declarations().to_string();
    for forbidden in [
        "create_worktree",
        "remove_worktree",
        "commit_worktree",
        "discard_worktree",
        "stage_hunk",
        "discard_hunk",
        "stage_git_hunk",
        "unstage_git_hunk",
        "discard_git_hunk",
        "git_commit",
    ] {
        assert!(
            !declarations.contains(forbidden),
            "agent tool surface unexpectedly contains {forbidden}"
        );
    }
}

#[test]
fn reject_leaves_a_new_proposal_off_disk() {
    let root = fixture_root("reject");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind workspace");
    let staged = backend
        .send_fake_chat_for_smoke("stage a local note")
        .expect("FakeProvider turn")
        .present_current();
    let relative = staged.staged[0].path.clone();
    assert!(!workspace.join(&relative).exists());
    let rejected = backend
        .reject_file(&relative)
        .expect("reject proposal")
        .present_current();
    assert!(rejected.staged.is_empty());
    assert!(!workspace.join(relative).exists());
    fs::remove_dir_all(root).expect("remove reject fixture");
}

#[test]
fn scoped_review_refuses_project_session_path_and_fingerprint_drift() {
    let root = fixture_root("scoped-review");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind workspace");
    let staged = backend
        .send_fake_chat_for_smoke("stage an identity-bound note")
        .expect("stage proposal")
        .present_current();
    let item = staged.staged.first().expect("one staged proposal");
    let project = ProjectId::new(&item.project_id);
    let session = SessionId::new(&item.session_id);
    let path = item.path.clone();
    let fingerprint = item.proposal_fingerprint.clone();

    assert!(
        backend
            .accept_scoped_file(
                &ProjectId::new("project-wrong"),
                &session,
                &path,
                &fingerprint,
            )
            .is_err()
    );
    assert!(
        backend
            .accept_scoped_file(
                &project,
                &SessionId::new("session-wrong"),
                &path,
                &fingerprint,
            )
            .is_err()
    );
    assert!(
        backend
            .accept_scoped_file(&project, &session, "wrong.txt", &fingerprint)
            .is_err()
    );
    assert!(
        backend
            .accept_scoped_file(&project, &session, &path, &"f".repeat(64))
            .is_err()
    );
    assert!(
        backend
            .reject_scoped_file(&project, &session, &path, &"e".repeat(64))
            .is_err()
    );
    let binding = vec![(path.clone(), fingerprint.clone())];
    assert!(
        backend
            .accept_all_scoped(&ProjectId::new("project-wrong"), &session, &binding)
            .is_err()
    );
    assert!(
        backend
            .accept_all_scoped(&project, &SessionId::new("session-wrong"), &binding)
            .is_err()
    );
    assert!(
        backend
            .accept_all_scoped(
                &project,
                &session,
                &[("wrong.txt".into(), fingerprint.clone())],
            )
            .is_err()
    );
    assert!(
        backend
            .accept_all_scoped(&project, &session, &[(path.clone(), "d".repeat(64))],)
            .is_err()
    );
    assert!(!workspace.join(&path).exists());

    backend
        .reject_all_scoped(&project, &session, &binding)
        .expect("exact scoped batch reject");
    assert!(!workspace.join(path).exists());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn unavailable_session_state_never_clears_a_durable_review_gate() {
    let root = fixture_root("review-reconcile-fail-closed");
    let queue = QueueCoordinator::open(root.clone());
    let project = ProjectId::new("project-a");
    queue.set_review_blocked(&project, true).expect("seed gate");

    reconcile_review_blocks_from_sessions(&queue, &PlusProjectBook::default(), None)
        .expect("unavailable session state preserves queue");
    assert!(
        queue
            .view()
            .review_blocked_project_ids
            .contains(&project.as_str().to_owned())
    );
    drop(queue);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn accept_clears_review_gate_even_when_notification_state_is_unavailable() {
    let root = fixture_root("review-notification-failure");
    let workspace = root.join("workspace");
    let state_root = root.join("state");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    {
        let mut backend = Backend::new(PlusSessionStore::from_state_root(&state_root));
        backend
            .bind_project(&workspace.display().to_string())
            .expect("bind workspace");
        backend
            .send_fake_chat_for_smoke("stage a notification-failure note")
            .expect("stage proposal");
        assert!(!backend.queue.view().review_blocked_project_ids.is_empty());
    }
    let notification_path = state_root.join("plus-notifications.json");
    fs::write(&notification_path, b"not-json\n").expect("corrupt notification fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&notification_path, fs::Permissions::from_mode(0o600))
            .expect("restrict corrupt notification fixture");
    }

    let mut backend = Backend::new(PlusSessionStore::from_state_root(&state_root));
    let staged = backend.snapshot().staged[0].clone();
    let error = backend
        .accept_scoped_file(
            &ProjectId::new(&staged.project_id),
            &SessionId::new(&staged.session_id),
            &staged.path,
            &staged.proposal_fingerprint,
        )
        .expect_err("notification failure must remain explicit");
    assert!(error.contains("proposal decision is durable"));
    assert!(workspace.join(&staged.path).is_file());
    assert!(backend.queue.view().review_blocked_project_ids.is_empty());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn projects_persist_and_switch_chat_without_cross_project_bleed() {
    let root = fixture_root("project-switch");
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    fs::create_dir_all(&alpha).expect("create alpha");
    fs::create_dir_all(&beta).expect("create beta");
    fs::write(alpha.join("keep.txt"), "alpha stays\n").expect("seed alpha");
    let alpha = alpha.canonicalize().expect("canonical alpha");
    let beta = beta.canonicalize().expect("canonical beta");
    let state_root = root.join("state");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(&state_root));

    let alpha_bound = backend
        .bind_project(&alpha.display().to_string())
        .expect("bind alpha")
        .present_current();
    let alpha_id = alpha_bound.active_project_id.expect("active alpha id");
    let alpha_chat = backend
        .send_fake_chat_for_smoke("alpha-only-message")
        .expect("alpha chat")
        .present_current();
    assert!(alpha_chat.chat.contains("alpha-only-message"));
    assert!(!alpha_chat.chat.contains(PLUS_PROVIDER_LABEL));
    assert_eq!(alpha_chat.staged.len(), 1);
    backend
        .store
        .remember_command_outcome("alpha-command-output")
        .expect("remember alpha command");
    backend.command_outcome = "alpha-command-output".into();

    let beta_bound = backend
        .bind_project(&beta.display().to_string())
        .expect("bind beta")
        .present_current();
    let beta_id = beta_bound.active_project_id.expect("active beta id");
    assert_ne!(alpha_id, beta_id);
    assert_eq!(beta_bound.projects.len(), 2);
    assert_eq!(beta_bound.chat, NO_CHAT_YET);
    assert!(!beta_bound.terminal_output.contains("alpha-command-output"));
    assert!(beta_bound.staged.is_empty());
    let beta_chat = backend
        .send_fake_chat_for_smoke("beta-only-message")
        .expect("beta chat")
        .present_current();
    assert!(beta_chat.chat.contains("beta-only-message"));
    assert!(!beta_chat.chat.contains("alpha-only-message"));
    backend
        .store
        .remember_command_outcome("beta-command-output")
        .expect("remember beta command");
    backend.command_outcome = "beta-command-output".into();

    let alpha_again = backend
        .switch_project(&alpha_id)
        .expect("switch alpha")
        .present_current();
    assert!(alpha_again.chat.contains("alpha-only-message"));
    assert!(!alpha_again.chat.contains("beta-only-message"));
    assert_eq!(alpha_again.staged.len(), 1);
    assert_eq!(alpha_again.terminal_output, "alpha-command-output");

    let beta_again = backend
        .switch_project(&beta_id)
        .expect("switch beta")
        .present_current();
    assert!(beta_again.chat.contains("beta-only-message"));
    assert!(!beta_again.chat.contains("alpha-only-message"));
    assert_eq!(beta_again.terminal_output, "beta-command-output");
    drop(backend);

    let mut restored = Backend::new(PlusSessionStore::from_state_root(&state_root));
    assert_eq!(
        restored.snapshot().active_project_id.as_deref(),
        Some(beta_id.as_str())
    );
    assert!(restored.snapshot().chat.contains("beta-only-message"));
    let after_unlist = restored
        .remove_project(&beta_id)
        .expect("unlist beta")
        .present_current();
    assert_eq!(after_unlist.projects.len(), 1);
    assert_eq!(
        after_unlist.active_project_id.as_deref(),
        Some(alpha_id.as_str())
    );
    assert!(after_unlist.chat.contains("alpha-only-message"));
    let no_projects = restored
        .remove_project(&alpha_id)
        .expect("unlist alpha")
        .present_current();
    assert!(no_projects.projects.is_empty());
    assert!(no_projects.active_project_id.is_none());
    assert_eq!(no_projects.chat, NO_CHAT_YET);
    assert_eq!(
        fs::read_to_string(alpha.join("keep.txt")).expect("alpha remains"),
        "alpha stays\n",
        "unlisting must not delete project files"
    );
    fs::remove_dir_all(root).expect("remove project-switch fixture");
}

#[test]
fn disconnected_send_intent_stays_queued_without_starting_a_run() {
    use crate::queue::QueueItemState;

    let root = fixture_root("queue-disconnected");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create queued workspace");
    let workspace = workspace
        .canonicalize()
        .expect("canonical queued workspace");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind queued workspace");
    let queue = backend.queue.clone();
    let request = backend
        .queue_request("wait for an explicit live transport", true)
        .expect("build queue request");
    let item = queue.enqueue(request).expect("persist queued intent");
    let candidates = queue
        .candidates(None, false)
        .expect("read queued candidate");
    assert_eq!(candidates.len(), 1);
    let Err(refusal) = backend.prepare_queued_run(&candidates[0]) else {
        panic!("disconnected transport must not prepare a run");
    };
    assert_eq!(
        refusal.kind,
        crate::backend::PrepareQueuedRunErrorKind::TransportUnavailable
    );
    assert!(refusal.detail.contains("not connected"));
    queue
        .mark_blocked(
            &item.id,
            "GrokCliAcp cannot start this queued prompt until Account reconnects.",
        )
        .expect("persist exact blocked state");
    let snapshot = backend.snapshot();
    assert_eq!(snapshot.queue.active_global_runs, 0);
    assert!(snapshot.queue.runs.is_empty());
    assert_eq!(snapshot.queue.items[0].state, QueueItemState::Queued);
    assert!(
        snapshot.queue.items[0]
            .blocked_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("until Account reconnects"))
    );
    assert!(!root.join("state/queue-run-state").exists());
    fs::remove_dir_all(root).expect("remove disconnected queue fixture");
}

#[test]
fn exact_session_append_does_not_bleed_into_the_active_project() {
    let root = fixture_root("queue-session-isolation");
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    fs::create_dir_all(&alpha).expect("create alpha");
    fs::create_dir_all(&beta).expect("create beta");
    let alpha = alpha.canonicalize().expect("canonical alpha");
    let beta = beta.canonicalize().expect("canonical beta");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut backend = Backend::new(store.clone());
    backend
        .bind_project(&alpha.display().to_string())
        .expect("bind alpha");
    let alpha_session = store
        .active_plus_session_id()
        .expect("read alpha session id");
    backend
        .bind_project(&beta.display().to_string())
        .expect("bind beta");
    let beta_session = store
        .active_plus_session_id()
        .expect("read beta session id");
    assert_ne!(alpha_session, beta_session);
    store
        .append_chat_turn_to_session(&alpha_session, "alpha-background-result")
        .expect("append exact alpha result");
    assert!(!backend.snapshot().chat.contains("alpha-background-result"));
    let book = store.load_session_book().expect("load isolated sessions");
    assert!(
        book.sessions
            .iter()
            .find(|session| session.id == alpha_session)
            .expect("alpha session")
            .chat
            .contains("alpha-background-result")
    );
    assert!(
        !book
            .sessions
            .iter()
            .find(|session| session.id == beta_session)
            .expect("beta session")
            .chat
            .contains("alpha-background-result")
    );
    fs::remove_dir_all(root).expect("remove session-isolation fixture");
}

#[test]
fn backend_restart_interrupts_running_queue_and_clears_session_flag() {
    use crate::queue::{QueueItemState, RunState};

    let root = fixture_root("queue-backend-restart");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create restart workspace");
    let workspace = workspace
        .canonicalize()
        .expect("canonical restart workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut backend = Backend::new(store.clone());
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind restart workspace");
    let request = backend
        .queue_request("must never auto replay", true)
        .expect("queue restart request");
    let queue = backend.queue.clone();
    let item = queue.enqueue(request).expect("enqueue restart item");
    let begun = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("begin restart run");
    backend
        .mark_queued_session_running(&begun.item.session_id)
        .expect("mark exact session running");
    drop(backend);
    drop(queue);

    let mut restored = Backend::new(store.clone());
    let snapshot = restored.snapshot();
    assert_eq!(snapshot.queue.active_global_runs, 0);
    assert_eq!(snapshot.queue.items[0].state, QueueItemState::Interrupted);
    assert_eq!(snapshot.queue.runs[0].state, RunState::Interrupted);
    assert!(
        restored
            .queue
            .candidates(None, false)
            .expect("no recovered replay")
            .is_empty()
    );
    assert!(
        store
            .load_session_book()
            .expect("load recovered sessions")
            .sessions
            .iter()
            .all(|session| !session.in_flight)
    );
    fs::remove_dir_all(root).expect("remove backend-restart fixture");
}

#[test]
fn legacy_project_book_migrates_atomically_without_touching_pending_bytes() {
    use grok_build_plus_host::{
        PLUS_PENDING_FILE, PLUS_PROJECTS_FILE, PLUS_PROJECTS_LEGACY_BACKUP_FILE,
        PLUS_PROJECTS_MIGRATION_RECEIPT_FILE, PLUS_PROJECTS_SCHEMA_VERSION, bind_project_folder,
        worktree_recovery_digest,
    };

    let root = fixture_root("project-migration");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create migration workspace");
    let workspace = workspace
        .canonicalize()
        .expect("canonical migration workspace");
    let state_root = root.join("state");
    let store = PlusSessionStore::from_state_root(&state_root);
    let bound = bind_project_folder(&workspace).expect("bind migration workspace");
    store
        .remember_known_project(&bound)
        .expect("create current project book");

    let project_path = state_root.join(PLUS_PROJECTS_FILE);
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&fs::read(&project_path).expect("read current project book"))
            .expect("decode current project book");
    legacy
        .as_object_mut()
        .expect("project book object")
        .remove("schema_version");
    for project in legacy["projects"].as_array_mut().expect("projects array") {
        let project = project.as_object_mut().expect("project object");
        project.remove("active_worktree_id");
        project.remove("worktrees");
    }
    let legacy_bytes = serde_json::to_vec_pretty(&legacy).expect("encode legacy project book");
    fs::write(&project_path, &legacy_bytes).expect("install legacy project book");
    let pending_sentinel = b"pending-proposal-bytes-must-not-change\n";
    fs::write(state_root.join(PLUS_PENDING_FILE), pending_sentinel)
        .expect("write pending sentinel");

    let migrated = store
        .load_project_book()
        .expect("migrate legacy project book");
    assert_eq!(migrated.schema_version, PLUS_PROJECTS_SCHEMA_VERSION);
    assert_eq!(migrated.projects.len(), 1);
    assert_eq!(migrated.projects[0].root, workspace);
    assert!(migrated.projects[0].worktrees.is_empty());
    assert_eq!(
        fs::read(state_root.join(PLUS_PROJECTS_LEGACY_BACKUP_FILE)).expect("read legacy backup"),
        legacy_bytes
    );
    assert_eq!(
        fs::read(state_root.join(PLUS_PENDING_FILE)).expect("read pending sentinel"),
        pending_sentinel
    );
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state_root.join(PLUS_PROJECTS_MIGRATION_RECEIPT_FILE))
            .expect("read migration receipt"),
    )
    .expect("decode migration receipt");
    assert_eq!(receipt["from_schema"], 0);
    assert_eq!(receipt["to_schema"], PLUS_PROJECTS_SCHEMA_VERSION);
    assert_eq!(
        receipt["source_sha256"],
        worktree_recovery_digest(&legacy_bytes)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(state_root.join(PLUS_PROJECTS_LEGACY_BACKUP_FILE))
            .expect("backup metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400);
    }
    assert!(
        fs::read_dir(&state_root)
            .expect("list state root")
            .all(|entry| !entry
                .expect("state entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".plus-state-"))
    );
    fs::remove_dir_all(root).expect("remove migration fixture");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one static contract test covers the complete bundled UI asset and accessibility surface"
)]
fn config_and_assets_lock_the_required_mac_window_contract() {
    let config: serde_json::Value = serde_json::from_str(include_str!("../../tauri.conf.json"))
        .expect("valid Tauri configuration");
    let window = &config["app"]["windows"][0];
    assert_eq!(window["width"], 1040);
    assert_eq!(window["height"], 720);
    assert_eq!(window["minWidth"], 900);
    assert_eq!(window["minHeight"], 600);
    assert_eq!(window["maximized"], false);
    assert_eq!(window["center"], false);
    assert_eq!(window["visible"], false);
    assert_eq!(window["fullscreen"], false);
    assert_eq!(window["titleBarStyle"], "Overlay");
    assert_eq!(window["decorations"], true);
    assert_eq!(config["app"]["withGlobalTauri"], true);
    assert_eq!(
        config["app"]["security"]["csp"],
        "default-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' data:; media-src 'self' blob:; font-src 'self'; style-src 'self'; script-src 'self'"
    );

    let html = include_str!("../../ui/index.html");
    let css = include_str!("../../ui/styles.css");
    let account_css = include_str!("../../ui/styles/account.css");
    let workspace_css = include_str!("../../ui/styles/workspace.css");
    let javascript = include_str!("../../ui/app.js");
    let workspace_javascript = include_str!("../../ui/modules/workspace.js");
    let worktree_javascript = include_str!("../../ui/modules/worktrees.js");
    let terminal_javascript = include_str!("../../ui/modules/terminal.js");
    let terminal_css = include_str!("../../ui/styles/terminal.css");
    let browser_javascript = include_str!("../../ui/modules/browser.js");
    let capture_javascript = include_str!("../../ui/modules/capture.js");
    let desktop_javascript = include_str!("../../ui/modules/desktop.js");
    let notifications_javascript = include_str!("../../ui/modules/notifications.js");
    let browser_css = include_str!("../../ui/styles/browser.css");
    assert_required_destinations(html);
    for color in ["#121312", "#FFFFFF", "#F9D993", "#6786AB", "#560C07"] {
        assert!(css.contains(color), "missing locked palette color {color}");
    }
    assert!(terminal_css.contains("--terminal-positive: #275E17;"));
    assert!(!css.contains("#007aff"));
    assert!(!html.contains("id=\"provider-pill\""));
    assert!(!html.contains("id=\"transcript-provider\""));
    assert!(!html.contains("FakeProvider"));
    assert!(!html.contains("Appearance"));
    assert!(javascript.contains("lastContentView"));
    assert!(javascript.contains("[data-security-toggle]"));
    assert!(!css.contains(".toolbar-security-chip"));
    assert!(!css.contains(".toolbar-project-chip"));
    assert!(css.contains(
            ".security-chip[data-kind=\"off\"],\n.security-chip[data-kind=\"unchecked\"],\n.security-chip[data-kind=\"setting-up\"],\n.security-chip[data-kind=\"needs-attention\"],\n.value-warn {\n  border-color: var(--secondary)"
        ));
    assert!(!css.contains(".security-chip[data-kind=\"off\"] {\n  background: var(--refuse)"));
    assert!(javascript.contains("accept_all_scoped"));
    assert!(javascript.contains("reject_all_scoped"));
    assert!(javascript.contains("run_contained_check"));
    assert!(javascript.contains("run_terminal"));
    assert!(javascript.contains("switch_project"));
    assert!(javascript.contains("remove_project"));
    assert!(javascript.contains("connect_account"));
    assert!(javascript.contains("refresh_account"));
    assert!(javascript.contains("choose_project_folder"));
    assert!(javascript.contains("startDragging"));
    assert!(javascript.contains("startResizeDragging"));
    assert!(html.contains("id=\"notification-bell\""));
    assert!(html.contains("id=\"notification-popover\""));
    assert!(notifications_javascript.contains("mark_notification_read"));
    assert!(notifications_javascript.contains("dismiss_notification"));
    assert!(!notifications_javascript.contains("onAccept"));
    assert!(!notifications_javascript.contains("onReject"));
    assert_activity_assets(
        html,
        javascript,
        include_str!("../../ui/modules/diagnostics.js"),
        include_str!("../../ui/modules/timeline.js"),
        include_str!("../../ui/modules/usage.js"),
    );
    assert_chat_scheduling_assets(html, javascript, include_str!("../../ui/modules/queue.js"));
    assert_workspace_browser_assets(html, workspace_css, workspace_javascript);
    assert_worktree_assets(html, worktree_javascript);
    assert!(html.contains("id=\"choose-folder\""));
    assert!(html.contains("id=\"create-folder\""));
    assert!(html.contains("id=\"project-list\""));
    assert_terminal_assets(html, terminal_javascript, terminal_css);
    assert_account_assets(html, javascript, account_css);
    let voice_javascript = include_str!("../../ui/modules/voice.js");
    for voice_id in [
        "id=\"voice-model\"",
        "id=\"voice-install\"",
        "id=\"voice-record\"",
        "id=\"voice-status\"",
    ] {
        assert!(html.contains(voice_id), "missing Voice control {voice_id}");
    }
    assert!(javascript.contains("createVoiceInput"));
    assert!(voice_javascript.contains("voice_stop_and_transcribe"));
    assert!(voice_javascript.contains("Transcript ready"));
    assert!(html.contains(">Refresh</button>"));
    assert!(html.contains("does not reload, clear, or reset Voice"));
    assert!(voice_javascript.contains("Voice status refreshed"));
    assert!(voice_javascript.contains("onRecordingStart();"));
    assert!(javascript.contains("onRecordingStart()"));
    assert!(javascript.contains("onTranscriptInserted()"));
    assert!(javascript.contains("readAloud?.stop()"));
    assert!(!voice_javascript.contains("requestSubmit"));
    assert!(!voice_javascript.contains("enqueue_chat"));
    let read_aloud_javascript = include_str!("../../ui/modules/read_aloud.js");
    assert!(html.contains("id=\"read-aloud-auto\""));
    assert!(html.contains("<span>Auto-read</span>"));
    assert!(html.contains("id=\"read-aloud-status\""));
    assert!(html.contains("class=\"panel account-voice-panel\""));
    assert!(javascript.contains("createReadAloud"));
    assert!(javascript.contains("readAloud.renderStreaming"));
    assert!(read_aloud_javascript.contains("read_aloud_synthesize"));
    assert!(read_aloud_javascript.contains("Reply is too long; use Read Aloud"));
    assert!(read_aloud_javascript.contains("direct xAI TTS authorization"));
    assert!(read_aloud_javascript.contains("credentialSource"));
    assert!(css.contains(
        ".auto-read-toggle {\n  appearance: none;\n  display: inline-flex;\n  min-height: 32px;\n  align-items: center;\n  gap: 6px;\n  padding: 5px 10px;\n  border: 1px solid var(--primary);\n  border-radius: 6px;"
        ));
    assert!(account_css.contains(".account-voice-panel"));
    assert!(read_aloud_javascript.contains("completedReplyTransition"));
    assert!(!read_aloud_javascript.contains("speechSynthesis"));
    assert!(!read_aloud_javascript.contains("webkitSpeech"));
    for capture_id in [
        "id=\"capture-toolbar-chip\"",
        "id=\"capture-chip\"",
        "id=\"capture-arm\"",
        "id=\"capture-take\"",
        "id=\"capture-stop\"",
        "id=\"capture-preview\"",
        "id=\"global-capability-stop\"",
    ] {
        assert!(
            html.contains(capture_id),
            "missing Capture control {capture_id}"
        );
    }
    assert!(javascript.contains("createCaptureControl"));
    assert!(javascript.contains("stopHighPowerCapabilities"));
    assert!(browser_javascript.contains("onCapabilityState(\"browser\""));
    assert!(browser_javascript.contains("browser_pointer"));
    assert!(browser_javascript.contains("browser_insert_text"));
    assert!(browser_javascript.contains("browser_release_user_control"));
    assert!(browser_javascript.contains("const currentToken = view?.interactionToken"));
    assert!(!html.contains("id=\"browser-node-id\""));
    assert!(!html.contains("id=\"browser-click\""));
    assert!(!browser_javascript.contains("globalCapabilityStop.addEventListener"));
    assert!(capture_javascript.contains("capture_arm"));
    assert!(capture_javascript.contains("capture_take"));
    assert!(capture_javascript.contains("capture_stop"));
    assert!(capture_javascript.contains("data:image/png;base64,"));
    assert!(!capture_javascript.contains("localStorage"));
    assert!(!capture_javascript.contains("requestSubmit"));
    assert!(browser_css.contains(".capture-preview"));
    for desktop_id in [
        "id=\"desktop-toolbar-chip\"",
        "id=\"desktop-chip\"",
        "id=\"desktop-select\"",
        "id=\"desktop-arm\"",
        "id=\"desktop-stop\"",
        "id=\"desktop-target\"",
    ] {
        assert!(
            html.contains(desktop_id),
            "missing Desktop Control {desktop_id}"
        );
    }
    assert!(javascript.contains("createDesktopControl"));
    assert!(javascript.contains("desktopControl.stop"));
    assert!(desktop_javascript.contains("desktop_select_target"));
    assert!(desktop_javascript.contains("desktop_arm"));
    assert!(desktop_javascript.contains("desktop_stop"));
    assert!(desktop_javascript.contains("PID"));
    assert!(desktop_javascript.contains("windowId"));
    assert!(!desktop_javascript.contains("localStorage"));
    assert!(!desktop_javascript.contains("requestSubmit"));
    assert!(browser_css.contains(".desktop-target"));

    let document = HtmlContract::parse(html);
    document.assert_unique_ids();
    for id in [
        "sidebar-project",
        "workspace-browser-title",
        "terminal-title",
        "account-title",
    ] {
        document.require_id(id);
    }
    assert_eq!(document.module_sources(), ["app.js"]);

    let icon = include_bytes!("../../icons/icon.png");
    assert_eq!(&icon[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&icon[12..16], b"IHDR");
    assert_eq!(u32::from_be_bytes(icon[16..20].try_into().unwrap()), 1024);
    assert_eq!(u32::from_be_bytes(icon[20..24].try_into().unwrap()), 1024);
    assert_eq!(icon[24], 8, "Tauri requires an 8-bit app icon");
    assert_eq!(icon[25], 6, "Tauri requires an RGBA app icon");
}

#[test]
fn notification_popover_groups_records_by_project() {
    let javascript = include_str!("../../ui/modules/notifications.js");
    assert!(javascript.contains("groupProjectNotifications"));
    assert!(javascript.contains("group.records.length"));
    assert!(javascript.contains("snapshot?.projects"));
    assert!(javascript.contains("group.records.find((record) => !record.read)"));
    assert!(javascript.contains("updateGroup(\"dismiss_notification\", group.records[0])"));
    assert!(!javascript.contains("notification-category"));
    assert!(!javascript.contains("CATEGORY_LABELS"));
}

fn assert_only_locked_hex_colors(label: &str, source: &str) {
    const LOCKED: [&str; 6] = [
        "#121312", "#FFFFFF", "#F9D993", "#6786AB", "#560C07", "#275E17",
    ];
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'#' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        let digits = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_hexdigit() {
            cursor += 1;
        }
        let count = cursor - digits;
        let continues_identifier = bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'));
        if matches!(count, 3 | 4 | 6 | 8) && !continues_identifier {
            let color = &source[start..cursor];
            assert!(
                LOCKED
                    .iter()
                    .any(|allowed| color.eq_ignore_ascii_case(allowed)),
                "{label} contains unlocked color {color}"
            );
        }
    }
    let lower = source.to_ascii_lowercase();
    assert!(
        !lower.contains("rgba("),
        "{label} contains rgba color syntax"
    );
    assert!(!lower.contains("rgb("), "{label} contains rgb color syntax");
    assert!(
        !lower.contains("color-mix("),
        "{label} derives an unlocked shade"
    );
    assert!(
        !lower.contains("gradient("),
        "{label} derives an unlocked shade"
    );
}

#[test]
fn shipped_ui_uses_only_locked_flat_palette_and_rounded_finder_icon() {
    for (label, stylesheet) in [
        ("base", include_str!("../../ui/styles.css")),
        ("account", include_str!("../../ui/styles/account.css")),
        ("activity", include_str!("../../ui/styles/activity.css")),
        ("browser", include_str!("../../ui/styles/browser.css")),
        ("terminal", include_str!("../../ui/styles/terminal.css")),
        ("workspace", include_str!("../../ui/styles/workspace.css")),
    ] {
        assert_only_locked_hex_colors(label, stylesheet);
    }

    let terminal = include_str!("../../ui/modules/terminal.js");
    assert_only_locked_hex_colors("terminal theme", terminal);
    assert!(terminal.contains("background: \"#F9D993\""));
    assert!(terminal.contains("foreground: \"#121312\""));
    assert!(terminal.contains("red: \"#560C07\""));
    assert!(terminal.contains("green: \"#275E17\""));

    let css = include_str!("../../ui/styles.css");
    let read_aloud = include_str!("../../ui/modules/read_aloud.js");
    let workspace_css = include_str!("../../ui/styles/workspace.css");
    let workspace_javascript = include_str!("../../ui/modules/workspace.js");
    assert!(css.contains(".chat-file-name,"));
    assert!(css.contains("color: var(--file);"));
    assert!(
        !css.lines()
            .any(|line| line.trim() == "color: var(--negative);")
    );
    assert!(!css.contains("var(--positive)"));
    assert!(workspace_css.contains(".workspace-tree-name.has-extension,"));
    assert!(workspace_javascript.contains("name.classList.add(\"has-extension\")"));
    let brand_mark = css
        .split_once(".brand-mark {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(rule, _)| rule)
        .expect("in-app brand mark rule");
    assert!(brand_mark.contains("border: 1px solid var(--primary);"));
    assert!(brand_mark.contains("background: var(--ink);"));
    assert!(brand_mark.contains("box-shadow: none;"));
    for stylesheet in [
        include_str!("../../ui/styles/account.css"),
        include_str!("../../ui/styles/activity.css"),
        include_str!("../../ui/styles/browser.css"),
        include_str!("../../ui/styles/workspace.css"),
    ] {
        assert!(!stylesheet.contains("var(--positive)"));
        assert!(
            !stylesheet
                .lines()
                .any(|line| line.trim() == "color: var(--negative);")
        );
    }
    assert!(read_aloud.contains("FILE_REFERENCE_PATTERN"));
    assert!(read_aloud.contains("export function messageFileSegments"));
    assert!(read_aloud.contains("fileName.className = \"chat-file-name\""));

    let config: serde_json::Value = serde_json::from_str(include_str!("../../tauri.conf.json"))
        .expect("valid Tauri configuration");
    assert_eq!(config["app"]["windows"][0]["backgroundColor"], "#121312");
    assert!(
        include_str!("../../ui/index.html")
            .contains("<meta name=\"theme-color\" content=\"#121312\" />")
    );

    let icon_svg = include_str!("../../icons/icon.svg");
    assert_only_locked_hex_colors("Finder icon", icon_svg);
    assert!(icon_svg.contains(
        "<rect x=\"64\" y=\"64\" width=\"896\" height=\"896\" rx=\"200\" fill=\"#121312\"/>"
    ));
    assert_eq!(icon_svg, include_str!("../../ui/assets/gb-plus.svg"));
    assert!(!icon_svg.contains("transparent"));
    assert!(!icon_svg.contains("stroke="));
    assert!(icon_svg.contains("<path id=\"brand-g\" fill=\"#FFFFFF\" d=\"M"));
    let icon_script = include_str!("../../../../scripts/plus-macos-icon.sh");
    for representation in [
        "icon_16x16.png",
        "icon_16x16@2x.png",
        "icon_32x32.png",
        "icon_32x32@2x.png",
        "icon_128x128.png",
        "icon_128x128@2x.png",
        "icon_256x256.png",
        "icon_256x256@2x.png",
        "icon_512x512.png",
        "icon_512x512@2x.png",
    ] {
        assert!(icon_script.contains(representation));
    }
    assert!(icon_script.contains("/usr/bin/iconutil -c icns"));
}

#[test]
fn locked_palette_keeps_white_primary_and_yellow_for_interaction_and_terminal() {
    let html = include_str!("../../ui/index.html");
    let css = include_str!("../../ui/styles.css");
    let account_css = include_str!("../../ui/styles/account.css");
    let terminal = include_str!("../../ui/modules/terminal.js");

    for contract in [
        "--muted: var(--primary);",
        "--accent: var(--primary);",
        "--accent-hover: var(--secondary);",
        "button:hover:not(:disabled):not(.button-quiet-danger)",
        "background: var(--secondary);\n  color: var(--ink);",
        ".send-button {",
        "background: var(--accent);",
        "color: var(--ink);",
    ] {
        assert!(
            css.contains(contract),
            "missing white-first contract: {contract}"
        );
    }
    assert!(terminal.contains("background: \"#F9D993\""));
    assert!(!html.contains("composer-context-label"));
    let composer_context = html
        .split_once("<div class=\"composer-context\">")
        .and_then(|(_, rest)| rest.split_once("</div>"))
        .map(|(context, _)| context)
        .expect("composer context markup");
    let project_name = composer_context
        .find("id=\"composer-context\"")
        .expect("project name in composer context");
    let context_dot = composer_context
        .find("id=\"composer-context-dot\"")
        .expect("context dot in composer context");
    assert!(project_name < context_dot);
    assert!(html.contains("class=\"view-inner account-layout\""));
    assert!(!account_css.contains(".account-layout {\n  width:"));
    assert!(
        account_css.contains("grid-template-columns: minmax(220px, 1fr) repeat(4, max-content);")
    );
    assert!(html.contains("id=\"send-menu-toggle\""));
    assert!(css.contains(".send-control[data-running=\"true\"] .send-button"));
}

#[test]
fn concise_page_chrome_and_browser_setup_keep_failures_visible() {
    let html = include_str!("../../ui/index.html");
    let css = include_str!("../../ui/styles.css");
    let browser_css = include_str!("../../ui/styles/browser.css");
    let browser = include_str!("../../ui/modules/browser.js");
    let dom = include_str!("../../ui/modules/dom.js");

    for contract in [
        "--line: var(--primary);",
        "--line-strong: var(--primary);",
        "--text: var(--primary);",
        "--text-muted: var(--primary);",
        "padding: 0 22px 0 34px;",
        "border-bottom: 0;",
        ".view-heading:not(.compact) {\n  display: none;",
        ".review-heading {\n  display: none !important;",
        ".project-active-chip {",
        "background: var(--accent);\n  color: var(--ink);",
    ] {
        assert!(
            css.contains(contract),
            "missing concise chrome contract: {contract}"
        );
    }
    for contract in [
        ".browser-surface-tabs button[aria-selected=\"true\"] {\n  background: var(--primary);\n  color: var(--ink);",
        ".browser-refresh-button {",
        ".capture-panel h2 {\n  display: none;",
    ] {
        assert!(
            browser_css.contains(contract),
            "missing compact Browser contract: {contract}"
        );
    }
    for removed_copy in [
        "Browser setup",
        "No inspection yet.",
        "Controlled page",
        "about:blank",
        "id=\"browser-page-title\"",
        "id=\"browser-page-url\"",
        "id=\"browser-inspection\"",
    ] {
        assert!(
            !html.contains(removed_copy),
            "obsolete Browser chrome remains: {removed_copy}"
        );
    }
    assert!(html.contains("id=\"browser-install\" type=\"button\">Download</button>"));
    assert!(html.contains(">Google terms</a>"));
    assert!(html.contains("aria-label=\"Refresh preview\""));
    assert!(html.contains("id=\"browser-status\"") && html.contains("hidden></p>"));
    assert!(browser.contains("elements.browserInstall.hidden = runtimeReady || runtimeActive;"));
    assert!(browser.contains("elements.browserRefresh.hidden = !armed;"));
    assert!(browser.contains("if (view?.lastRefusal) return view.lastRefusal;"));
    assert!(browser.contains("if (error) return view?.detail || runtime?.detail"));
    assert!(!dom.contains("browserPageTitle"));
    assert!(!dom.contains("browserPageUrl"));
    assert!(!dom.contains("browserInspection"));
}

#[test]
fn daily_polish_uses_official_context_shape_and_full_row_project_states() {
    let html = include_str!("../../ui/index.html");
    let css = include_str!("../../ui/styles.css");
    let account_css = include_str!("../../ui/styles/account.css");
    let usage = include_str!("../../ui/modules/usage.js");

    assert!(html.contains("class=\"project-mini\" id=\"project-mini\" type=\"button\""));
    assert!(html.contains("data-view-jump=\"project\""));
    assert!(css.contains(
            ".project-source-row.is-active {\n  background: var(--secondary);\n  color: var(--ink);\n  box-shadow: none;"
        ));
    assert!(css.contains(".project-source-row:hover {\n  background: var(--secondary);"));
    assert!(css.contains(".project-source-row:hover .project-unlist,"));
    assert!(css.contains(
            "border: 1px solid var(--secondary);\n  border-radius: 10px;\n  background: var(--ink);\n  color: var(--primary);\n  box-shadow: inset 0 0 0 1px var(--ink), inset 0 0 0 2px var(--secondary);"
        ));

    assert!(!html.contains("class=\"chat-context-name\""));
    assert!(html.contains("class=\"chat-context-tokens\" id=\"chat-context-label\""));
    assert!(html.contains("id=\"chat-context-percent\""));
    assert!(
        html.contains("id=\"chat-context-meter\" data-state=\"unknown\" tabindex=\"0\" hidden")
    );
    assert!(usage.contains("export function compactContextTokens"));
    assert!(usage.contains("`${tenths / 10n}.${tenths % 10n}K`"));
    assert!(usage.contains("`${tenths / 10n}.${tenths % 10n}M`"));
    assert!(usage.contains("elements.chatContextMeter.hidden = !known;"));
    assert!(usage.contains("elements.chatContextPercent.textContent"));
    assert!(css.contains(".chat-context-meter:hover .chat-context-track:not([hidden])"));

    assert!(!html.contains("Proposals require Accept"));
    assert!(!html.contains("Queue message"));
    assert!(!html.contains("data-view=\"tasks\""));
    assert!(html.contains("id=\"send-next\""));
    assert!(html.contains("id=\"chat-next-strip\""));
    assert!(account_css.contains(".account-layout .about-card {"));
    assert!(account_css.contains("padding-left: clamp(24px, 3vw, 34px);"));

    let document = HtmlContract::parse(html);
    document.require_id("sidebar-project");
    document.require_attribute("project-mini", "data-view-jump", "project");
}

#[test]
fn chat_dark_surface_keeps_double_border_and_turn_status_is_runtime_bound() {
    let html = include_str!("../../ui/index.html");
    let css = include_str!("../../ui/styles.css");
    let app = include_str!("../../ui/app.js");
    let dom = include_str!("../../ui/modules/dom.js");
    let turn_status = include_str!("../../ui/modules/turn_status.js");

    assert!(html.contains("id=\"chat-turn-status\" data-phase=\"idle\""));
    assert!(html.contains("id=\"chat-turn-status-label\""));
    assert!(!html.contains("composer-shortcut"));
    assert!(!html.contains("⌘ ↵"));
    assert!(dom.contains("chatTurnStatus: document.querySelector(\"#chat-turn-status\")"));
    assert!(
        dom.contains("chatTurnStatusLabel: document.querySelector(\"#chat-turn-status-label\")")
    );

    for contract in [
        ".chat-canvas {",
        "background: var(--ink);\n  color: var(--primary);\n  box-shadow: inset 0 0 0 1px var(--ink), inset 0 0 0 2px var(--secondary);",
        ".chat-message[data-role=\"user\"] {",
        "border: 1px solid var(--secondary);\n  border-radius: 10px;\n  background: var(--ink);\n  color: var(--primary);",
        ".chat-message {\n  position: relative;",
        "border: 1px solid var(--primary);\n  border-radius: 10px;\n  background: var(--ink);\n  color: var(--primary);",
        ".welcome-state h2 {\n  color: var(--primary);",
        ".welcome-state p {\n  color: var(--primary);",
        ".composer {\n  padding: 12px 0 10px;\n  background: var(--ink);",
        ".composer-context {\n  min-height: 30px;",
        "border: 1px solid var(--primary);\n  border-radius: 7px;\n  background: var(--ink);",
        ".composer-row textarea {\n  padding-right: 78px;\n  border-color: var(--primary);\n  background: var(--ink);\n  color: var(--primary);",
        ".send-control {\n  position: absolute;",
        ".chat-next-strip {\n  position: relative;",
    ] {
        assert!(
            css.contains(contract),
            "missing Chat theme contract: {contract}"
        );
    }

    for exact_phase in [
        "Waiting for response…",
        "Thinking…",
        "Responding…",
        "Preparing changes…",
        "Updating plan…",
        "Running command…",
        "Cancelling…",
    ] {
        assert!(
            turn_status.contains(exact_phase),
            "missing honest live phase: {exact_phase}"
        );
    }
    assert!(turn_status.contains("if (!event || !runId) return;"));
    assert!(turn_status.contains("if (!activeRunId) activeRunId = runId;"));
    assert!(turn_status.contains("if (runId && runId !== activeRunId) return;"));
    assert!(turn_status.contains("terminalRunText(terminal)"));
    assert!(turn_status.contains("elapsedText(activeRunStartedAt)"));
    assert!(!turn_status.contains("set(\"Planning…\""));
    assert!(app.contains("turnStatus.renderSnapshot(snapshot);"));
    assert!(app.contains("applyRuntimeEvent({ payload: envelope.event }, envelope.runId);"));
    assert!(html.contains("id=\"chat-draft\" rows=\"2\" maxlength=\"12000\""));
    assert!(!html.contains("id=\"draft-count\""));
    assert!(!dom.contains("draftCount"));
}

#[test]
fn git_review_assets_lock_user_only_lane_separation() {
    assert_git_review_assets(
        include_str!("../../ui/index.html"),
        include_str!("../../ui/styles.css"),
        include_str!("../../ui/modules/git_review.js"),
    );
}

#[test]
fn chat_first_run_control_removes_tasks_and_keeps_agent_approval_in_chat() {
    let html = include_str!("../../ui/index.html");
    let app = include_str!("../../ui/app.js");
    let scheduling = include_str!("../../ui/modules/queue.js");
    let changes = include_str!("../../ui/modules/review.js");
    let timeline = include_str!("../../ui/modules/timeline.js");
    let notifications = include_str!("../../ui/modules/notifications.js");
    let review = html
        .split_once("data-view-panel=\"review\"")
        .and_then(|(_, rest)| rest.split_once("data-view-panel=\"activity\""))
        .map(|(review, _)| review)
        .expect("Review view");

    for retired in [
        "data-view=\"tasks\"",
        "data-view-panel=\"tasks\"",
        "Queue message",
        "id=\"queue-pause\"",
        "id=\"queue-run-next\"",
        "id=\"task-board\"",
    ] {
        assert!(!html.contains(retired), "retired UI remains: {retired}");
    }
    assert_eq!(review.matches("<section class=\"review-lane").count(), 1);
    assert!(review.contains("id=\"git-review-title\">Git changes"));
    assert!(!review.contains("Agent changes"));
    assert!(html.contains("id=\"chat-change-card\""));
    assert!(changes.contains("createChatChanges"));
    assert!(changes.contains("friendlyDiff"));
    assert!(changes.contains("proposalFingerprint"));
    assert!(app.contains("accept_all_scoped"));
    assert!(app.contains("reject_all_scoped"));
    assert!(app.contains("message === \"apply changes\""));
    assert!(app.contains("[\"remove changes\", \"reject changes\"].includes(message)"));
    assert!(html.contains("id=\"chat-change-reject\" type=\"button\">Remove</button>"));
    assert!(timeline.contains("payload.action === \"rejected\"\n      ? \"Removed\""));
    assert!(app.contains("activeRun.projectId"));
    assert!(app.contains("activeRun.sessionId"));
    assert!(app.contains("activeRun.id"));
    assert!(scheduling.contains("intent.state !== \"promoted_to_next\""));
    assert!(scheduling.contains("Delivery uncertain · not sent again"));
    assert!(scheduling.contains("Held from an earlier version"));
    assert!(!notifications.contains("onAccept"));
    assert!(!notifications.contains("onReject"));
}

#[test]
fn pending_change_card_follows_its_assistant_reply_and_chat_widths_match() {
    let app = include_str!("../../ui/app.js");
    let changes = include_str!("../../ui/modules/review.js");
    let css = include_str!("../../ui/styles.css");

    let messages = app
        .find("readAloud.handleSnapshot(snapshot, previousSnapshot);")
        .expect("Chat messages render from the snapshot");
    let proposals = app
        .find("chatChanges.render(snapshot.staged, state.busy);")
        .expect("pending changes render from the same snapshot");
    assert!(
        messages < proposals,
        "the message anchor must exist before the pending-change row is placed"
    );
    assert!(changes.contains("elements.transcriptBody.querySelector"));
    assert!(changes.contains("chat-message[data-role"));
    assert!(changes.contains("reply.insertAdjacentElement"));
    assert!(changes.contains("afterend"));
    assert!(css.contains(".composer {\n  padding: 12px 0 10px;"));
}

#[test]
fn every_routed_page_uses_one_content_measure_and_stable_gutter() {
    let html = include_str!("../../ui/index.html");
    let css = include_str!("../../ui/styles.css");
    let account = include_str!("../../ui/styles/account.css");
    let activity = include_str!("../../ui/styles/activity.css");
    let browser = include_str!("../../ui/styles/browser.css");

    assert_eq!(html.matches("class=\"view-inner").count(), 9);
    assert!(!html.contains("view-inner narrow"));
    assert!(css.contains("--page-content-max: 1120px;"));
    assert!(css.contains("--page-gutter-x: 34px;"));
    assert!(css.contains("--page-gutter-x: 25px;"));
    assert!(css.contains("scrollbar-gutter: stable both-edges;"));
    assert!(css.contains("width: min(100%, var(--page-content-max));"));
    assert!(css.contains("padding: 29px var(--page-gutter-x) 34px;"));
    assert!(
        css.contains(".review-scroll {\n  min-height: 0;\n  overflow: auto;\n  padding-right: 0;")
    );
    assert!(!account.contains("width: min(100%, 1040px);"));
    assert!(!activity.contains("max-width: 920px;"));
    assert!(!browser.contains("max-width: 1180px;"));
}

#[test]
fn review_add_account_states_and_task_removal_keep_daily_controls_honest() {
    let html = include_str!("../../ui/index.html");
    let workspace = html;
    let account = html;
    let account_css = include_str!("../../ui/styles/account.css");
    let worktrees = include_str!("../../ui/modules/worktrees.js");
    let git_review = include_str!("../../ui/modules/git_review.js");
    let dom = include_str!("../../ui/modules/dom.js");
    let backend = include_str!("../backend.rs");

    assert!(HtmlContract::parse(html).before("git-review-add", "git-review-refresh"));
    assert!(git_review.contains("elements.gitReviewAdd.addEventListener(\"click\", onAdd)"));
    assert!(worktrees.contains("async function openGitSetup()"));
    assert!(worktrees.contains("elements.worktreeManager.open = true;"));
    assert!(worktrees.contains("elements.gitSetupStart.focus"));
    assert!(!workspace.contains("id=\"worktree-status-details\""));
    assert!(!html.contains("id=\"worktree-status-details\""));
    assert!(!dom.contains("worktreeStatusDetails"));
    assert_eq!(html.matches("id=\"git-setup-detail\"").count(), 1);

    assert!(account.contains("XaiKeychain · Direct xAI"));
    assert!(account.contains("GrokCliAcp · Grok sign-in"));
    assert!(!account.contains("Connection details"));
    assert!(!account.contains("Grok CLI access stays constrained"));
    assert!(account_css.contains(
        ".account-chip[data-connected=\"true\"] {\n  border-color: #275E17;\n  background: #275E17;"
    ));
    assert!(account_css.contains(
            ".account-onboarding-status[data-phase=\"connected\"] {\n  border-color: #275E17;\n  background: #275E17;"
        ));
    assert!(
        account_css
            .contains(".read-aloud-status[data-available=\"true\"] {\n  background: #275E17;")
    );
    assert!(account_css.contains(".transport-option.is-selected:hover"));
    assert!(account_css.contains(".transport-option:hover span"));
    assert!(backend.contains("Live Chat verified through {}."));
    assert!(!backend.contains("using {model} at {verified_at}"));

    assert_registered_command("remove_queue_item");
}

#[test]
fn account_transport_selection_is_one_click_live_check_without_oauth_or_fallback() {
    let app = include_str!("../../ui/app.js");
    let account = include_str!("../../ui/index.html");
    let handler = app
        .split_once(concat!(
            "document.querySelectorAll(\"[data-transport]\").forEach((button) => {\n",
            "  button.addEventListener(\"click\", async () => {"
        ))
        .expect("transport selection handler")
        .1
        .split_once("elements.configureXaiKey.addEventListener")
        .expect("bounded transport selection handler")
        .0;
    let select = handler
        .find("runCommand(\"select_transport\"")
        .expect("explicit selection must remain first");
    let connect = handler
        .find("? \"connect_saved_xai_key\"")
        .expect("saved-key connection path");
    assert!(select < connect, "selection must precede its live check");
    assert!(handler.contains(": \"connect_account\""));
    assert!(!handler.contains("login_grok_cli"));
    assert_eq!(
        handler.matches("runCommand(").count(),
        1,
        "selection may invoke only its explicit transport mutation directly"
    );
    assert_eq!(handler.matches("runConnectionCommand(").count(), 1);
    assert!(!account.contains("id=\"account-connect\""));
    assert!(account.contains("<summary>Other ways to connect</summary>"));
    assert!(!account.contains("<summary>Connection options</summary>"));
    assert!(account.contains("Check connection"));
    assert!(account.contains("API key"));
    assert!(account.contains("Grok Subscription"));
    assert!(account.contains("XaiKeychain"));
    assert!(account.contains("GrokCliAcp"));
    assert!(!account.to_ascii_lowercase().contains("probe"));
    for jargon in ["Automatic probes", "live probe", "until probed", "Re-probe"] {
        assert!(
            !app.contains(jargon),
            "user-facing jargon remains: {jargon}"
        );
    }
}

#[test]
fn account_connection_progress_is_immediate_and_brand_copy_is_concise() {
    let html = include_str!("../../ui/index.html");
    let app = include_str!("../../ui/app.js");
    let css = include_str!("../../ui/styles.css");
    let account_css = include_str!("../../ui/styles/account.css");

    assert!(!html.contains("Local coding agent"));
    assert!(!css.contains(".brand-caption"));
    assert!(app.contains("async function runConnectionCommand"));
    assert!(app.contains("setAccountOnboardingStatus(\"connecting\", \"Connecting…\""));
    assert!(app.contains("elements.accountChip.textContent = \"Connecting…\""));
    assert!(app.contains("await new Promise((resolve) => window.requestAnimationFrame(resolve))"));
    assert!(app.contains("runConnectionCommand(\"refresh_account\")"));
    assert!(app.contains("runConnectionCommand(\"reconnect_authorized_account\")"));
    assert!(account_css.contains("[data-pending=\"true\"] strong::before"));
    assert!(account_css.contains("animation: chat-turn-spin 0.8s linear infinite"));
}

#[test]
fn chat_scrollbar_and_workspace_long_names_stay_out_of_the_way() {
    let html = include_str!("../../ui/index.html");
    let app = include_str!("../../ui/app.js");
    let css = include_str!("../../ui/styles.css");
    let workspace_css = include_str!("../../ui/styles/workspace.css");
    let worktrees = include_str!("../../ui/modules/worktrees.js");

    assert!(app.contains("chatCanvas.classList.add(\"is-scrolling\")"));
    assert!(app.contains("chatCanvas.classList.remove(\"is-scrolling\")"));
    assert!(css.contains(":is(:hover, :focus-within, .is-scrolling)"));
    assert!(css.contains("scrollbar-color: transparent transparent"));
    assert!(workspace_css.contains("grid-template-columns: minmax(0, 1fr) auto"));
    assert!(workspace_css.contains(".worktree-state-chip {\n  flex: 0 0 auto"));
    assert!(worktrees.contains("querySelector(\".worktree-advanced\")"));
    assert!(worktrees.contains("input:focus, :focus-visible"));
    assert!(worktrees.contains("}, 3000);"));
    assert!(!worktrees.contains("worktreeBaseRef.value ="));
    assert!(html.contains("Select a project file"));
    assert!(!html.contains("Select a text file"));
}

#[test]
fn bound_empty_chat_does_not_offer_rebinding() {
    let html = include_str!("../../ui/index.html");
    let app = include_str!("../../ui/app.js");
    let dom = include_str!("../../ui/modules/dom.js");

    assert!(html.contains("id=\"welcome-bind-project\""));
    assert!(dom.contains("welcomeBindProject: document.querySelector(\"#welcome-bind-project\")"));
    assert!(app.contains("elements.welcomeBindProject.hidden = bound;"));
}

#[test]
fn pending_change_card_survives_async_chat_rerender() {
    let app = include_str!("../../ui/app.js");
    let read_aloud = include_str!("../../ui/modules/read_aloud.js");
    let review = include_str!("../../ui/modules/review.js");

    assert!(read_aloud.contains("onMessagesRendered = () => {}"));
    assert!(read_aloud.matches("onMessagesRendered();").count() >= 2);
    assert!(review.contains("reattach: attachToOriginatingReply"));
    assert!(review.contains("if (elements.chatChangeCard.hidden) return;"));
    assert!(app.contains("chatChanges.reattach();"));
}

#[test]
fn product_brand_is_gb_plus_without_rotating_security_identity() {
    let config: serde_json::Value = serde_json::from_str(include_str!("../../tauri.conf.json"))
        .expect("valid Tauri configuration");
    let html = include_str!("../../ui/index.html");
    let plist = include_str!("../../macos/Info.plist");
    let main = include_str!("../main.rs");
    let release = include_str!("../../../../scripts/plus-macos-release.sh");

    assert_eq!(config["productName"], "GB Plus");
    assert_eq!(config["app"]["windows"][0]["title"], "GB Plus");
    assert_eq!(config["bundle"]["macOS"]["bundleName"], "GB Plus");
    assert!(html.contains("<title>GB Plus</title>"));
    assert!(html.contains("<div class=\"brand-name\">GB Plus</div>"));
    assert!(!html.contains("Grok Build+"));
    assert!(plist.contains("<key>CFBundleDisplayName</key>\n  <string>GB Plus</string>"));
    assert!(plist.contains("<key>CFBundleName</key>\n  <string>GB Plus</string>"));
    assert!(main.contains("println!(\"GB Plus {}\""));
    assert!(release.contains("app_path=\"$dist_root/GB Plus.app\""));
    assert!(release.contains("zip_path=\"$dist_root/gb-plus-macos-arm64.zip\""));
    assert!(release.contains("/bin/rm -rf -- \"$previous_app_path\""));
    assert!(release.contains("local_signing_name=\"Grok Build+ Local Signing\""));
    assert!(plist.contains("<string>com.grokbuild.plus</string>"));
    assert_eq!(
        grok_build_keychain_broker::PROVIDER_KEYCHAIN_SERVICE,
        "org.grok-build.desktop.provider"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one static contract test locks the complete bundled macOS source and signing boundary"
)]
fn bundle_sources_lock_the_primary_macos_app_contract() {
    let config: serde_json::Value = serde_json::from_str(include_str!("../../tauri.conf.json"))
        .expect("valid Tauri configuration");
    assert_eq!(config["bundle"]["active"], true);
    assert_eq!(config["bundle"]["targets"][0], "app");
    assert_eq!(config["bundle"]["icon"][0], "macos/GrokBuildPlus.icns");
    assert_eq!(config["bundle"]["macOS"]["minimumSystemVersion"], "15.0");
    assert_eq!(config["bundle"]["macOS"]["signingIdentity"], "-");
    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../../capabilities/main.json"))
            .expect("valid main-window capability");
    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    assert_eq!(
        capability["permissions"],
        serde_json::json!([
            "core:event:allow-listen",
            "core:event:allow-unlisten",
            "core:window:allow-start-dragging",
            "core:window:allow-start-resize-dragging"
        ])
    );

    let bundle_icon = include_bytes!("../../macos/GrokBuildPlus.icns");
    assert_eq!(&bundle_icon[..4], b"icns");
    assert_eq!(
        u32::from_be_bytes(bundle_icon[4..8].try_into().unwrap()) as usize,
        bundle_icon.len()
    );
    let plist = include_str!("../../macos/Info.plist");
    for locked_value in [
        "<string>grok-build-tauri</string>",
        "<string>com.grokbuild.plus</string>",
        "<string>15.0</string>",
    ] {
        assert!(plist.contains(locked_value), "missing {locked_value}");
    }
    assert!(plist.contains("NSMicrophoneUsageDescription"));
    assert!(plist.contains("discards audio from memory after transcription"));
    assert!(plist.contains("<key>CFBundleIconFile</key>\n  <string>GrokBuildPlus.icns</string>"));
    assert!(plist.contains(
        "<key>CFBundleIconFiles</key>\n  <array>\n    <string>GrokBuildPlus.icns</string>"
    ));
    let release_script = include_str!("../../../../scripts/plus-macos-release.sh");
    assert!(
        release_script.contains(
            "source_identity=$(python3 \"$repo_root/scripts/release-source.py\" identity)"
        )
    );
    assert!(release_script.contains("read -r build_revision bundle_build_number build_dirty"));
    assert!(release_script.contains("[ \"$bundle_build_number\" -gt 0 ]"));
    assert!(release_script.contains("Set :CFBundleVersion $bundle_build_number"));
    assert!(release_script.contains("bundled Finder icon differs from the checked-in icon"));
    assert!(release_script.contains("checksum_path=\"$dist_root/SHA256SUMS\""));
    assert!(release_script.contains("checksum_line=\"$zip_sha256  gb-plus-macos-arm64.zip\""));
    assert!(release_script.contains("release checksum readback changed"));
    let entitlements = include_str!("../../macos/GrokBuildPlus.entitlements");
    assert!(entitlements.contains("com.apple.security.device.audio-input"));
    assert!(entitlements.contains("<true/>"));
    let product_lock = include_str!("../../../../Cargo.lock");
    for required_package in [
        "name = \"cpal\"",
        "name = \"whisper-rs\"",
        "name = \"whisper-rs-sys\"",
        "name = \"objc2-av-foundation\"",
    ] {
        assert!(
            product_lock.contains(required_package),
            "admitted Voice dependency is absent: {required_package}"
        );
    }
    for forbidden_package in [
        "name = \"faster-whisper\"",
        "name = \"ctranslate2\"",
        "name = \"av\"",
    ] {
        assert!(
            !product_lock.contains(forbidden_package),
            "rejected Voice dependency entered the product lock: {forbidden_package}"
        );
    }
    let workspace_manifest = include_str!("../../../../Cargo.toml");
    assert!(workspace_manifest.contains("vendor/whisper-rs-sys-0.15.0-grok"));
    let release_script = include_str!("../../../../scripts/plus-macos-release.sh");
    let build_script = include_str!("../../build.rs");
    assert!(build_script.contains("rustc-link-arg=-mmacosx-version-min=15.0"));
    assert!(release_script.contains("cargo build --locked --release -p grok-build-tauri"));
    assert!(release_script.contains("codesign --verify --deep --strict"));
    assert!(release_script.contains("--local-signing"));
    assert!(release_script.contains("Grok Build+ Local Signing"));
    assert!(release_script.contains("security find-identity -v -p codesigning"));
    assert!(release_script.contains("login\\.keychain-db"));
    assert!(release_script.contains("signature_posture=\"local-self-signed\""));
    assert!(release_script.contains("GROK_BUILD_SIGNING_IDENTITY"));
    assert!(release_script.contains("GROK_BUILD_KEYCHAIN_BROKER_CDHASH"));
    assert!(release_script.contains("launchd-one-shot-private-unix-peer-validated"));
    assert!(
        release_script
            .contains("stable Keychain broker designated requirement is not its exact CDHash")
    );
    assert!(release_script.contains("local-signed app retained an ad-hoc cdhash-only"));
    assert!(release_script.contains("ad-hoc signed app did not expose its expected cdhash"));
    assert!(release_script.contains("s/^# designated => //p"));
    assert!(build_script.contains("GROK_BUILD_SIGNING_IDENTITY"));
    assert!(build_script.contains("GROK_BUILD_KEYCHAIN_BROKER_CDHASH"));
    assert!(build_script.contains("exact 40-character public certificate fingerprint"));
    assert!(release_script.contains("--tauri-smoke"));
    assert!(release_script.contains("GrokBuildReleaseReceipt.json"));
    assert!(
        release_script.contains("b336ec65a086c056d4804b3d4c2347da5663d3f23c3f25be866467bd8857ad59")
    );
    assert!(
        release_script.contains("2d87e1bddc73be9111de8beee5370c3bb7aac9c94e18e6f245f02ca741ef1769")
    );
    assert!(release_script.contains("\"rawSmoke\": \"passed\""));
    assert!(release_script.contains("zip contains the legacy Slint front door"));
    assert!(release_script.contains("real Voice requires NSMicrophoneUsageDescription"));
    assert!(release_script.contains("patched whisper-rs-sys relative source manifest changed"));
    assert!(release_script.contains("unexpected executable/sidecar payload count"));
    assert!(release_script.contains("zip contains a rejected Voice sidecar or lazy model payload"));
    assert!(!release_script.contains("-p grok-build-desktop --bin grok-build"));
}

#[test]
fn release_bundle_separates_helper_identifier_from_adhoc_cdhash_requirement() {
    let release_script = include_str!("../../../../scripts/plus-macos-release.sh");
    assert!(release_script.contains("broker_observed_identifier=$("));
    assert!(release_script.contains("s/^Identifier=//p"));
    assert!(release_script.contains("Keychain broker code signature lost its exact identifier"));
    assert!(
        release_script
            .contains("stable Keychain broker designated requirement is not its exact CDHash")
    );
    assert!(
        !release_script
            .contains("Keychain broker designated requirement lost its exact identifier")
    );
}

#[test]
fn chat_voice_controls_are_compact_and_status_copy_lives_in_account() {
    let html = include_str!("../../ui/index.html");
    let css = include_str!("../../ui/styles.css");
    let account_css = include_str!("../../ui/styles/account.css");
    let javascript = include_str!("../../ui/modules/read_aloud.js");
    let controls = html
        .split_once("<div class=\"chat-run-controls\">")
        .and_then(|(_, rest)| rest.split_once("</header>"))
        .map(|(controls, _)| controls)
        .expect("Chat controls markup");
    assert!(controls.contains("id=\"cancel-chat\""));
    assert!(controls.contains("id=\"read-aloud-auto\""));
    assert!(controls.contains("data-mode=\"connect\""));
    assert!(controls.contains("Open Account to connect Grok voice"));
    assert!(!controls.contains("id=\"read-aloud-status\""));
    assert!(!controls.contains(">AGENT</span>"));
    let account = html
        .split_once("data-view-panel=\"account\"")
        .map(|(_, account)| account)
        .expect("Account view");
    assert!(account.contains("id=\"read-aloud-status\""));
    assert_eq!(html.matches("id=\"read-aloud-status\"").count(), 1);
    assert!(css.contains(".view-heading.compact > div:first-child"));
    assert!(css.contains(".chat-run-controls {\n  display: flex;"));
    assert!(css.contains(
        ".auto-read-toggle {\n  appearance: none;\n  display: inline-flex;\n  min-height: 32px;"
    ));
    assert!(css.contains(".chat-stop-button {\n  display: inline-grid;\n  flex: 0 0 32px;"));
    assert!(css.contains(
        "min-height: 32px;\n  padding: 0;\n  place-items: center;\n  border-radius: 6px;"
    ));
    assert!(css.contains("border-radius: 999px;"));
    assert!(!css.contains("max-width: 58%;"));
    assert!(account_css.contains(".account-voice-panel"));
    assert!(!javascript.contains("readAloudAuto.checked"));
    assert!(javascript.contains("setAutoRead(!view.autoReadEnabled)"));
    assert!(javascript.contains("setAttribute(\"aria-pressed\""));
}

#[test]
fn active_chat_stop_preserves_its_compact_icon() {
    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/app.js");
    let stop_button = html
        .split_once("id=\"cancel-chat\"")
        .and_then(|(_, rest)| rest.split_once("</button>"))
        .map(|(button, _)| button)
        .expect("Chat Stop button markup");

    assert!(stop_button.contains("<svg"));
    assert!(!javascript.contains("elements.cancelChat.textContent"));
    assert!(javascript.contains("stopRequested ? \"Stopping agent run\" : \"Stop agent run\""));
    assert!(
        javascript.contains("elements.cancelChat.title = stopRequested ? \"Stopping…\" : \"Stop\"")
    );
}

#[test]
fn contained_outcome_is_brief_with_exact_details_on_demand() {
    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/app.js");
    let presentation = include_str!("../../ui/modules/presentation.js");

    assert!(html.contains("id=\"command-outcome-summary\" role=\"status\""));
    assert!(html.contains("<details class=\"security-detail\"><summary>Details</summary>"));
    assert!(html.contains("<pre id=\"command-outcome\">"));
    assert!(javascript.contains(
        "elements.commandOutcomeSummary.textContent = commandOutcomeSummary(snapshot.commandOutcomeClass)"
    ));
    for copy in [
        "Contained run completed. No action needed.",
        "Stopped at the time limit. Retry if needed.",
        "Command blocked. Follow the step above or open Details.",
        "Run failed. Open Details before retrying.",
    ] {
        assert!(presentation.contains(copy));
    }
}

#[test]
fn command_security_setup_is_actionable_and_persisted_before_effects() {
    let root = fixture_root("command-security-choice");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut backend = Backend::new(store.clone());
    backend
        .set_command_security_enabled(true)
        .expect("persist enabled preference");
    assert_eq!(
        store.command_security_preference(),
        PlusCommandSecurityPreference::Extra
    );
    backend
        .set_command_security_enabled(false)
        .expect("persist disabled preference");
    assert_eq!(
        store.command_security_preference(),
        PlusCommandSecurityPreference::Off
    );

    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/app.js");
    assert!(html.contains(
        "id=\"run-contained\" type=\"button\" data-security-action>Check for Container</button>"
    ));
    assert!(html.contains("id=\"command-security-off\""));
    assert!(javascript.contains("check_command_security_container"));
    assert!(javascript.contains("install_command_security_container"));
    assert!(javascript.contains("configure_command_security"));
    assert!(javascript.contains("snapshot.security.actionLabel"));
    assert!(javascript.contains("snapshot.security.actionFailed"));
    assert!(javascript.contains("elements.securityCopy.textContent = snapshot.security.copy"));
    assert!(!javascript.contains("Contained run refused honestly"));
    assert_registered_command("check_command_security_container");
    assert_registered_command("install_command_security_container");
    assert_registered_command("configure_command_security");
    fs::remove_dir_all(root).expect("remove command-security fixture");
}

#[test]
fn command_security_busy_state_is_checks_local() {
    let styles = include_str!("../../ui/styles.css");
    let javascript = include_str!("../../ui/app.js");
    assert!(
        styles.contains(".security-mini-copy strong {\n  overflow: hidden;\n  color: inherit;")
    );
    assert!(styles.contains(".security-mini > svg {"));
    assert!(styles.contains("stroke: currentColor;"));
    assert!(styles.contains("[data-security-action][aria-busy=\"true\"]::after"));
    assert!(styles.contains("animation: chat-turn-spin 1.4s linear infinite;"));
    let handler = javascript
        .split_once("elements.runContained.addEventListener(\"click\", async () => {")
        .and_then(|(_, rest)| rest.split_once("elements.commandSecurityOff.addEventListener"))
        .map(|(handler, _)| handler)
        .expect("contained-check click handler");
    let invoke = handler
        .find("runSecurityCommand(command")
        .expect("contained command invocation");
    assert!(invoke > 0);
    assert!(!handler.contains("runCommand(command"));
    assert!(javascript.contains("function setSecurityBusy"));
    assert!(javascript.contains("document.querySelectorAll(\"[data-security-action]\")"));
    assert!(!javascript.contains("setBusy(true, elements.runContained"));
    assert!(handler.contains("action === \"test\" ? \"Test contained run\""));
}

#[test]
fn contained_controls_render_only_when_commands_are_verified_available() {
    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/app.js");
    assert!(html.contains("id=\"terminal-form\" hidden"));
    assert!(html.contains("id=\"command-outcome-panel\" hidden"));
    assert!(javascript.contains("snapshot.security.canRunCommands !== true"));
    assert!(javascript.contains("snapshot.security.enabled !== true"));
}

#[test]
fn boot_blur_clears_before_account_reconnect_and_on_bootstrap_failure() {
    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/app.js");
    let styles = include_str!("../../ui/styles.css");
    assert!(html.contains("<body class=\"is-booting\">"));
    assert!(html.contains("id=\"boot-overlay\""));
    assert!(styles.contains("body.is-booting .app-shell"));
    assert!(javascript.contains("const BOOT_MINIMUM_MS = 500;"));
    assert!(javascript.contains("await document.fonts?.ready;"));
    assert!(javascript.contains("requestAnimationFrame(() => requestAnimationFrame(resolve))"));
    assert!(javascript.contains("new Promise((resolve) => window.setTimeout(resolve, 100))"));
    assert!(javascript.contains("finally {\n    await finishBoot();\n  }"));
    let startup = javascript
        .split_once("async function start()")
        .expect("startup")
        .1;
    let clear = startup.find("await finishBoot();").expect("boot clear");
    let reconnect = startup
        .find("runConnectionCommand(\"reconnect_authorized_account\")")
        .expect("account reconnect");
    assert!(clear < reconnect);
}

#[test]
fn shipping_copy_contains_no_em_dash() {
    for (name, source) in [
        ("HTML", include_str!("../../ui/index.html")),
        ("JavaScript", include_str!("../../ui/app.js")),
        (
            "presentation",
            include_str!("../../ui/modules/presentation.js"),
        ),
        ("usage", include_str!("../../ui/modules/usage.js")),
        ("read aloud", include_str!("../../ui/modules/read_aloud.js")),
    ] {
        assert!(!source.contains('—'), "{name} contains a visible em dash");
    }
    for copy in [
        crate::pty::INTERACTIVE_SHELL_LABEL,
        grok_build_plus_host::PLUS_GUEST_HOW_TO_FIX,
        grok_build_plus_host::PLUS_PROVIDER_LABEL,
    ] {
        assert!(!copy.contains('—'));
    }
}

#[test]
fn concise_product_chrome_keeps_chat_clean_and_voice_in_account() {
    let html = include_str!("../../ui/index.html");
    let app = include_str!("../../ui/app.js");
    let chat = html
        .split_once("data-view-panel=\"chat\"")
        .and_then(|(_, rest)| rest.split_once("data-view-panel=\"workspace-browser\""))
        .map(|(chat, _)| chat)
        .expect("Chat view");
    let account = html
        .split_once("data-view-panel=\"account\"")
        .map(|(_, account)| account)
        .expect("Account view");
    let read_aloud = include_str!("../../ui/modules/read_aloud.js");
    let voice = include_str!("../../ui/modules/voice.js");

    for fluff in [
        "Keep a local project list",
        "LOCAL SESSION",
        "SCHEDULER",
        "SEPARATE WRITE LANES",
        "SUPPORTABILITY",
        "The Rust host canonicalizes",
    ] {
        assert!(!html.contains(fluff), "obsolete product copy: {fluff}");
    }
    assert!(!chat.contains("id=\"voice-model\""));
    assert!(account.contains("id=\"voice-model\""));
    assert!(!html.contains(">Queue message</button>"));
    assert!(!html.contains("data-view=\"tasks\""));
    assert!(html.contains("id=\"sidebar-security-label\">Command security</strong>"));
    assert!(app.contains("sidebarSecurityLabel.textContent = \"Command security\""));
    assert!(read_aloud.contains("const TOOL_TRACE_LINE"));
    assert!(read_aloud.contains("export function parseChatMessages"));
    assert!(read_aloud.contains("suppressUntilAssistant"));
    assert!(read_aloud.contains("...chatMessages.map("));
    assert!(!read_aloud.contains("[...chatMessages].reverse()"));
    assert!(!read_aloud.contains("Grok Build+ · Responding"));
    assert!(!read_aloud.contains("label.textContent"));
    assert!(voice.contains("function voiceStatusText"));
    assert!(voice.contains("onTranscriptInserted();"));
}

#[test]
fn unavailable_auto_read_routes_to_account_without_changing_the_setting() {
    let app = include_str!("../../ui/app.js");
    let javascript = include_str!("../../ui/modules/read_aloud.js");
    let handler = javascript
        .split_once("elements.readAloudAuto.addEventListener(\"click\", () => {")
        .and_then(|(_, rest)| rest.split_once("});"))
        .map(|(handler, _)| handler)
        .expect("Auto-read click handler");
    let unavailable = handler
        .find("if (!view.available)")
        .expect("unavailable branch");
    let account = handler
        .find("onConnectRequested();")
        .expect("Account navigation callback");
    let toggle = handler
        .find("setAutoRead(!view.autoReadEnabled)")
        .expect("available toggle");
    assert!(unavailable < account && account < toggle);
    assert!(handler[unavailable..toggle].contains("return;"));
    assert!(app.contains("onConnectRequested() {\n    setView(\"account\");"));
    assert!(javascript.contains("removeAttribute(\"aria-pressed\")"));
    assert!(javascript.contains("dataset.mode = \"connect\""));
}

#[test]
fn frontend_semantic_contract_preserves_ids_modules_focus_and_forbidden_apis() {
    let html = include_str!("../../ui/index.html");
    let document = HtmlContract::parse(html);
    document.assert_unique_ids();
    assert_eq!(document.module_sources(), ["app.js"]);
    for (id, attribute, value) in [
        ("project-mini", "data-view-jump", "project"),
        ("notification-bell", "aria-haspopup", "true"),
        (
            "chat-draft",
            "placeholder",
            "Ask about the project or describe a change…",
        ),
        (
            "terminal-xterm",
            "aria-label",
            "Interactive user shell output and input",
        ),
    ] {
        document.require_attribute(id, attribute, value);
    }
    let focus = document.focus_order();
    for id in [
        "project-mini",
        "notification-bell",
        "folder-path",
        "chat-draft",
    ] {
        assert!(
            focus.contains(&id),
            "missing {id} from semantic focus order"
        );
    }
    assert!(document.before("project-mini", "notification-bell"));
    assert!(document.before("folder-path", "chat-draft"));
    assert_no_forbidden_javascript_apis(&[
        include_str!("../../ui/app.js"),
        include_str!("../../ui/modules/browser.js"),
        include_str!("../../ui/modules/capture.js"),
        include_str!("../../ui/modules/desktop.js"),
        include_str!("../../ui/modules/diagnostics.js"),
        include_str!("../../ui/modules/git_review.js"),
        include_str!("../../ui/modules/notifications.js"),
        include_str!("../../ui/modules/queue.js"),
        include_str!("../../ui/modules/read_aloud.js"),
        include_str!("../../ui/modules/terminal.js"),
        include_str!("../../ui/modules/timeline.js"),
        include_str!("../../ui/modules/usage.js"),
        include_str!("../../ui/modules/voice.js"),
        include_str!("../../ui/modules/workspace.js"),
        include_str!("../../ui/modules/worktrees.js"),
    ]);
}

#[test]
fn responsive_readability_keeps_critical_text_legible_without_changing_layout() {
    let base_source = include_str!("../../ui/styles.css");
    let account_source = include_str!("../../ui/styles/account.css");
    let terminal_source = include_str!("../../ui/styles/terminal.css");
    let workspace_source = include_str!("../../ui/styles/workspace.css");
    let base = CssContract::parse(base_source);
    let terminal = CssContract::parse(terminal_source);
    let workspace = CssContract::parse(workspace_source);

    assert_eq!(
        base.property(":root", "--type-caption"),
        "clamp(10px, calc(8.8px + 0.14vw), 11px)"
    );
    assert_eq!(
        base.property(":root", "--type-body"),
        "clamp(13px, calc(11.4px + 0.2vw), 14px)"
    );
    assert_eq!(
        base.property(".project-row-copy span", "font-size"),
        "var(--type-meta)"
    );
    assert_eq!(
        workspace.property(".workspace-tree-name", "font-size"),
        "var(--type-copy)"
    );
    assert_eq!(
        base.property(".review-diff", "font-size"),
        "var(--type-meta)"
    );
    assert_eq!(
        terminal.property(".checks-command-form > label", "font-size"),
        "var(--type-copy)"
    );
    for (name, stylesheet) in [
        ("base", base_source),
        ("Account", account_source),
        ("Activity", include_str!("../../ui/styles/activity.css")),
        ("Browser", include_str!("../../ui/styles/browser.css")),
        ("Terminal", terminal_source),
        ("Workspace", workspace_source),
    ] {
        for size in CssContract::parse(stylesheet).hard_coded_pixel_font_sizes() {
            assert!(size >= 11.0, "{name} retained unreadable {size}px text");
        }
    }
}

#[test]
fn terminal_status_and_account_emphasis_are_bounded_and_transport_derived() {
    let account_css = CssContract::parse(include_str!("../../ui/styles/account.css"));
    let terminal_css = CssContract::parse(include_str!("../../ui/styles/terminal.css"));
    let app = include_str!("../../ui/app.js");
    let terminal = include_str!("../../ui/modules/terminal.js");

    assert_eq!(
        terminal_css.property(".terminal-bar", "grid-template-columns"),
        "48px minmax(0, 1fr) max-content"
    );
    assert_eq!(
        terminal_css.property(".terminal-state", "overflow"),
        "hidden"
    );
    assert_eq!(
        terminal_css.property(".terminal-state", "text-overflow"),
        "ellipsis"
    );
    assert!(terminal.contains("elements.ptyStatus.textContent = conciseStatus;"));
    assert!(terminal.contains("elements.ptyStatus.title = view?.status || conciseStatus;"));
    for label in [
        "Starting…",
        "Live",
        "Stopping…",
        "Stopped",
        "Unavailable",
        "Not started",
    ] {
        assert!(terminal.contains(&format!("return \"{label}\";")));
    }

    assert_eq!(
        account_css.property(
            ".account-onboarding-actions .button[data-connection-role=\"alternate\"]",
            "color"
        ),
        "var(--secondary)"
    );
    assert_eq!(
        account_css.property(
            ".account-onboarding-actions .button[data-connection-role=\"connected\"]:disabled",
            "background"
        ),
        "#275E17"
    );
    assert!(app.contains("loginGrokCli.dataset.connectionRole"));
    assert!(app.contains("configureXaiKey.dataset.connectionRole"));
    assert!(app.contains("account.selectedTransport === \"GrokCliAcp\""));
    assert!(app.contains("account.selectedTransport === \"XaiKeychain\""));
}
