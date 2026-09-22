//! GB Plus desktop interface and runtime integration.

#![cfg(target_os = "macos")]

mod accept_transaction;
mod asset_download;
mod backend;
mod bounded_process;
mod browser;
mod browser_assets;
mod browser_pipe;
mod capture;
mod capture_bridge;
mod child_environment;
mod collaboration;
mod commands;
mod container_runtime;
pub mod contracts;
#[cfg(test)]
mod daily_use_soak;
mod desktop;
mod desktop_bridge;
mod diagnostics;
mod events;
mod extensions;
mod git_process;
mod git_review;
#[cfg(target_os = "macos")]
mod markdown;
mod notifications;
#[cfg(test)]
#[path = "tests/operation_coordination.rs"]
mod operation_coordination_tests;
mod operations;
mod owner_state;
mod project_memory;
#[cfg(test)]
#[path = "tests/project_transition_support.rs"]
mod project_transition_support;
mod pty;
mod queue;
mod read_aloud;
#[cfg(test)]
#[path = "tests/refactor_equivalence.rs"]
mod refactor_equivalence_tests;
mod runtime;
mod session_lifecycle;
#[cfg(test)]
#[path = "tests/snapshot_coordination.rs"]
mod snapshot_coordination_tests;
#[cfg(target_os = "macos")]
mod tts_transport;
mod usage;
mod voice;
mod voice_permission;
mod window_layout;
mod workflows;
mod workspace;
mod workspace_watch;
mod worktrees;

use commands::{
    agent_settings, answer_cli_interaction, begin_mcp_account_signin, cancel_mcp_account_signin,
    child_agent_result, cleanup_mcp_accounts, cli_background_activity, close_mcp_account_review,
    decide_child_changes, disconnect_mcp_account, list_project_workflows, mcp_account_status,
    pending_cli_interactions, render_chat_markdown, resume_project_workflow, review_mcp_account,
    set_agents_enabled, start_project_workflow, stop_child_agent, stop_cli_background,
    workflow_result,
};
use commands::{
    discard_cli_image, get_cli_permission, open_chat_link, set_cli_permission, set_engine_settings,
    stage_cli_image, stop_project_workflow,
};
use std::fs;

use backend::{AppState, Backend};
use commands::{
    accept_all_scoped, accept_file, accept_scoped_file, acknowledge_account_onboarding,
    activate_workspace, answer_mcp_call_approval, answer_mcp_elicitation, bind_project, bootstrap,
    browser_arm, browser_click, browser_focused_key, browser_focused_scroll, browser_insert_text,
    browser_inspect, browser_install_runtime, browser_key, browser_navigate, browser_pointer,
    browser_release_user_control, browser_scroll, browser_status, browser_stop, browser_type,
    cancel_chat, capture_arm, capture_status, capture_stop, capture_take,
    check_command_security_container, choose_project_folder, choose_worktree_recovery_folder,
    close_extension_mcp_review, commit_worktree, configure_command_security, configure_xai_key,
    connect_account, connect_saved_xai_key, create_worktree, delete_xai_key, desktop_arm,
    desktop_select_target, desktop_status, desktop_stop, discard_git_hunk, discard_worktree,
    disconnect_account, dismiss_notification, export_diagnostics, export_worktree_recovery,
    get_session_native_protocol, initialize_git, inspect_extension_mcp_catalog, inspect_grok_cli,
    install_command_security_container, list_extension_mcp_servers, list_git_review,
    list_mcp_call_approvals, list_mcp_elicitations, list_session_models, list_workspace_directory,
    list_worktrees, login_grok_cli, mark_notification_read, open_mcp_elicitation_link,
    open_workspace_file, product_version, pty_interrupt, pty_resize, pty_start, pty_status,
    pty_stop, pty_write, read_aloud_status, read_aloud_stop, read_aloud_synthesize,
    reconnect_authorized_account, refresh_account, reject_all_scoped, reject_file,
    reject_scoped_file, release_held_message, remove_project, remove_queue_item, remove_worktree,
    remove_worktree_after_export, reset_provider_context, retry_queue_run, run_contained_check,
    run_terminal, select_session_model, select_transport, send_chat, send_next, send_now,
    set_auto_reconnect, set_extension_mcp_policy, set_read_aloud_auto_read,
    set_session_native_protocol, stage_git_hunk, steer_queue_item, switch_project,
    unstage_git_hunk, update_grok_cli, voice_cancel_recording, voice_install_model,
    voice_select_model, voice_start_recording, voice_status, voice_stop_and_transcribe,
};
use commands::{
    forget_project_fact, inspect_extension_file, install_extension, list_project_extensions,
    preview_https_extension, preview_local_extension, project_memory_view, remember_project_fact,
    set_extension_component, set_project_memory,
};
use grok_build_plus_host::{PLUS_PROVIDER_LABEL, PLUS_REFUSAL_NOT_SUCCESS, PlusSessionStore};
use runtime::cancel::RuntimeCancelHandle;
use tauri::Manager as _;
use workspace::{
    list_workspace_directory as read_workspace_directory,
    open_workspace_file as read_workspace_file,
};

pub use browser_pipe::run_chrome_pipe_launcher;

/// Runs the fixed local CDP fixture against an already verified Chrome runtime.
///
/// # Errors
///
/// Returns a fail-closed Browser launch, grant, action, or cleanup error.
pub fn smoke_browser(state_root: &std::path::Path) -> Result<String, String> {
    browser::smoke_browser(state_root)
}

/// Exercise the standard CLI in a new fixture project using CLI-owned sign-in.
///
/// # Errors
/// Returns an error if the directory exists, sign-in is needed, or a check fails.
pub fn smoke_cli_standard(state_root: &std::path::Path) -> Result<String, String> {
    runtime::acp::standard_smoke::run(state_root)
}

/// Runs a fixed HTTPS navigation against an already verified Chrome runtime.
///
/// # Errors
///
/// Returns a fail-closed Browser launch, navigation, screenshot, or cleanup error.
pub fn smoke_browser_network(state_root: &std::path::Path) -> Result<String, String> {
    browser::smoke_browser_network(state_root)
}

/// Runs the Tauri window until the user closes it.
///
/// # Errors
///
/// Returns a platform error when Tauri cannot create or run the window.
#[allow(
    clippy::too_many_lines,
    reason = "the explicit Tauri command allowlist and shutdown controls stay together for security review"
)]
pub fn run() -> Result<(), String> {
    let backend = Backend::production(PlusSessionStore::from_process_environment());
    let app = tauri::Builder::default()
        .manage(AppState::new(backend))
        .setup(|app| {
            app.manage(session_lifecycle::SessionLifecycle::install(
                app.handle().clone(),
            ));
            let window = app
                .get_webview_window("main")
                .ok_or_else(|| std::io::Error::other("GB Plus main window is missing"))?;
            window_layout::show(window);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            product_version,
            bootstrap,
            choose_project_folder,
            bind_project,
            switch_project,
            remove_project,
            list_workspace_directory,
            open_workspace_file,
            list_git_review,
            stage_git_hunk,
            unstage_git_hunk,
            discard_git_hunk,
            list_worktrees,
            initialize_git,
            create_worktree,
            activate_workspace,
            remove_worktree,
            commit_worktree,
            discard_worktree,
            choose_worktree_recovery_folder,
            export_worktree_recovery,
            remove_worktree_after_export,
            send_chat,
            send_now,
            steer_queue_item,
            send_next,
            release_held_message,
            retry_queue_run,
            remove_queue_item,
            accept_file,
            accept_scoped_file,
            reject_file,
            reject_scoped_file,
            accept_all_scoped,
            reject_all_scoped,
            mark_notification_read,
            dismiss_notification,
            check_command_security_container,
            install_command_security_container,
            configure_command_security,
            run_contained_check,
            run_terminal,
            pty_status,
            pty_start,
            pty_write,
            pty_resize,
            pty_interrupt,
            pty_stop,
            select_transport,
            refresh_account,
            connect_account,
            connect_saved_xai_key,
            reconnect_authorized_account,
            set_auto_reconnect,
            acknowledge_account_onboarding,
            login_grok_cli,
            set_engine_settings,
            pending_cli_interactions,
            answer_cli_interaction,
            cli_background_activity,
            stop_cli_background,
            render_chat_markdown,
            get_cli_permission,
            set_cli_permission,
            open_chat_link,
            stage_cli_image,
            discard_cli_image,
            inspect_grok_cli,
            update_grok_cli,
            reset_provider_context,
            list_session_models,
            get_session_native_protocol,
            set_session_native_protocol,
            select_session_model,
            list_project_extensions,
            agent_settings,
            set_agents_enabled,
            child_agent_result,
            stop_child_agent,
            decide_child_changes,
            list_project_workflows,
            workflow_result,
            start_project_workflow,
            resume_project_workflow,
            stop_project_workflow,
            preview_local_extension,
            preview_https_extension,
            install_extension,
            set_extension_component,
            inspect_extension_file,
            list_extension_mcp_servers,
            inspect_extension_mcp_catalog,
            set_extension_mcp_policy,
            close_extension_mcp_review,
            list_mcp_call_approvals,
            answer_mcp_call_approval,
            list_mcp_elicitations,
            answer_mcp_elicitation,
            open_mcp_elicitation_link,
            mcp_account_status,
            review_mcp_account,
            begin_mcp_account_signin,
            disconnect_mcp_account,
            cleanup_mcp_accounts,
            cancel_mcp_account_signin,
            close_mcp_account_review,
            project_memory_view,
            set_project_memory,
            remember_project_fact,
            forget_project_fact,
            disconnect_account,
            configure_xai_key,
            delete_xai_key,
            cancel_chat,
            voice_status,
            voice_select_model,
            voice_install_model,
            voice_start_recording,
            voice_stop_and_transcribe,
            voice_cancel_recording,
            read_aloud_status,
            set_read_aloud_auto_read,
            read_aloud_synthesize,
            read_aloud_stop,
            browser_status,
            browser_install_runtime,
            browser_arm,
            browser_stop,
            browser_navigate,
            browser_inspect,
            browser_click,
            browser_type,
            browser_key,
            browser_scroll,
            browser_pointer,
            browser_insert_text,
            browser_focused_key,
            browser_focused_scroll,
            browser_release_user_control,
            capture_status,
            capture_arm,
            capture_take,
            capture_stop,
            desktop_status,
            desktop_select_target,
            desktop_arm,
            desktop_stop,
            export_diagnostics
        ])
        .build(tauri::generate_context!())
        .map_err(|error| format!("cannot build GB Plus Tauri host: {error}"))?;
    app.run(|handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            handle.state::<AppState>().pty.shutdown_all();
            handle.state::<AppState>().voice.shutdown();
            handle.state::<AppState>().read_aloud.stop();
            handle.state::<AppState>().browser.shutdown();
            let _ = handle.state::<AppState>().queue.request_stop_all();
            #[cfg(target_os = "macos")]
            runtime::acp::memory_home::shutdown();
            let _ = handle
                .state::<AppState>()
                .desktop
                .stop("Desktop Control cleared because GB Plus exited.");
        }
    });
    Ok(())
}

/// Exercises bind, bounded Workspace browse/open, `FakeProvider` chat/propose,
/// Off refusal, Accept, and durable queue crash recovery without entering the
/// window event loop.
///
/// # Errors
///
/// Returns a precise failure if any product-owned service violates the smoke
/// contract or the temporary fixture cannot be created or removed.
pub fn smoke_tauri_host() -> Result<String, String> {
    let root = std::env::temp_dir().join(format!("grok-build-tauri-smoke-{}", std::process::id()));
    let state_root = root.join("state");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).map_err(|error| format!("create smoke workspace: {error}"))?;
    fs::write(
        workspace.join("smoke-read.txt"),
        "workspace browser smoke\n",
    )
    .map_err(|error| format!("create Workspace Browser smoke file: {error}"))?;
    let workspace = workspace
        .canonicalize()
        .map_err(|error| format!("canonicalize smoke workspace: {error}"))?;
    let mut backend = Backend::new(PlusSessionStore::from_state_root(&state_root));
    smoke_pristine_state(&root.join("first-run"))?;
    backend.bind_project(&workspace.display().to_string())?;
    let authority = backend.workspace_read_authority()?;
    let listing = read_workspace_directory(&authority, ".")?;
    let opened = read_workspace_file(&authority, "smoke-read.txt")?;
    if !listing.contains_entry("smoke-read.txt", "file")
        || !opened.is_exact_text("smoke-read.txt", "workspace browser smoke\n")
    {
        return Err("Workspace Browser did not list and open its bounded UTF-8 smoke file.".into());
    }
    let staged = backend
        .send_fake_chat_for_smoke("what is in this project?")?
        .present_current();
    if !backend.chat.contains(PLUS_PROVIDER_LABEL)
        || !backend.chat.contains("run_contained → failed:")
        || backend.chat.contains("run_contained → completed:")
        || staged.staged.is_empty()
    {
        return Err(
            "FakeProvider chat did not preserve the Accept-gated proposal and failed contained-tool outcome."
                .into(),
        );
    }
    let relative = staged.staged[0].path.clone();
    let proposed = workspace.join(&relative);
    if proposed.exists() {
        return Err("staged proposal reached disk before Accept.".into());
    }
    let refused = backend.run_contained_check()?.present_current();
    if refused.security.kind != "off"
        || !refused
            .command_outcome
            .contains("Contained command runs are unavailable")
        || !refused.command_outcome.contains(PLUS_REFUSAL_NOT_SUCCESS)
    {
        return Err(format!(
            "Command security Off did not produce the locked refusal: {}",
            refused.command_outcome
        ));
    }
    let terminal_marker = workspace.join("terminal-must-not-run");
    let terminal_refused = backend
        .run_terminal(&format!("/usr/bin/touch {}", terminal_marker.display()))?
        .present_current();
    if terminal_marker.exists()
        || terminal_refused.terminal_cwd.as_deref()
            != Some(workspace.display().to_string().as_str())
        || !terminal_refused
            .terminal_output
            .contains(PLUS_REFUSAL_NOT_SUCCESS)
    {
        return Err(
            "Terminal did not stay in the project cwd and refuse honestly while Off.".into(),
        );
    }
    let pty_proof = pty::smoke_pty_integrity(&workspace)?;
    if !pty_proof.control_executed_without_readiness
        || !pty_proof.enforced_refused
        || !pty_proof.private_probe_absent
        || !pty_proof.positive_live
        || !pty_proof.resize_roundtrip
        || !pty_proof.io_usable
    {
        return Err(format!(
            "PTY integrity controls did not all pass: {pty_proof:?}"
        ));
    }
    let accepted = backend.accept_file(&relative)?.present_current();
    if !proposed.exists() || !accepted.staged.is_empty() {
        return Err("Accept did not write exactly the staged proposal and clear Review.".into());
    }
    smoke_queue_recovery(backend, &state_root)?;
    let report = format!(
        "TAURI HOST SMOKE PASSED version={} security={} chat=FakeProvider workspace-readonly=true staged-until-Accept=true accepted={} contained-refused=true tool-refusal-not-success=true terminal-cwd=true terminal-off-refused=true pty-control-executed=true pty-enforced-refuse=true pty-private-probe=true pty-live=true pty-resize=true pty-io=true pty-not-contained=true chat-scheduling-durable=true send-now-recovered-as-next=true send-next-predecessor-bound=true queue-crash-interrupted=true queue-auto-replay=false activity-durable=true activity-monotonic=true activity-content-redacted=true context-unknown-honest=true usage-hidden-when-absent=true usage-provider-only=true",
        accepted.version, refused.security.status, relative
    );
    fs::remove_dir_all(&root).map_err(|error| format!("remove smoke fixture: {error}"))?;
    Ok(report)
}

fn smoke_pristine_state(root: &std::path::Path) -> Result<(), String> {
    let mut fresh = Backend::production(PlusSessionStore::from_state_root(root));
    let initial = fresh.snapshot_seed().present_current();
    if !initial.projects.is_empty()
        || initial.active_project_id.is_some()
        || initial.chat != "No chat yet."
        || !initial.staged.is_empty()
        || !initial.queue.items.is_empty()
        || !initial.queue.runs.is_empty()
        || initial.account.connected
    {
        return Err(
            "Fresh installation loaded an existing project, conversation, run or account.".into(),
        );
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the smoke keeps scheduling, restart, Activity, and usage truth checks in one auditable transaction"
)]
fn smoke_queue_recovery(backend: Backend, state_root: &std::path::Path) -> Result<(), String> {
    let automatic = backend
        .queue
        .enqueue(backend.queue_request("automatic queue smoke", true)?)?;
    let candidates = backend.queue.candidates(None, false)?;
    if candidates.len() != 1 || candidates[0].id != automatic.id {
        return Err("Idle Send was not the exact eligible Chat item.".into());
    }
    let begun = backend
        .queue
        .begin_run(&automatic.id, RuntimeCancelHandle::new())?;
    backend.mark_queued_session_running(&begun.item.session_id)?;
    let steer = backend.queue.enqueue_steer(
        &begun.run.project_id,
        &begun.run.session_id,
        &begun.run.id,
        "late Send now smoke",
    )?;
    let explicit_next = backend.queue.enqueue_send_next(
        backend.queue_request("explicit Send next smoke", true)?,
        &begun.run.id,
    )?;
    if !state_root.join(queue::PLUS_QUEUE_FILE).is_file() {
        return Err("Queue intent was not durable before the simulated interruption.".into());
    }
    drop(backend);

    let mut recovered = Backend::new(PlusSessionStore::from_state_root(state_root));
    let queue = recovered.queue.view();
    let interrupted_item = queue
        .items
        .iter()
        .find(|item| item.id == automatic.id.as_str());
    let interrupted_run = queue
        .runs
        .iter()
        .find(|run| run.id == begun.run.id.as_str());
    let explicit_next_item = queue
        .items
        .iter()
        .find(|item| item.id == explicit_next.id.as_str());
    let promoted_item = queue.items.iter().find(|item| {
        item.prompt == "late Send now smoke"
            && item.predecessor_run_id.as_deref() == Some(begun.run.id.as_str())
    });
    let promoted_steer = queue
        .steering
        .iter()
        .find(|intent| intent.id == steer.id.as_str());
    let candidates = recovered.queue.candidates(None, false)?;
    let preserved_user_order = candidates
        .first()
        .zip(promoted_item)
        .zip(explicit_next_item)
        .is_some_and(|((candidate, promoted), explicit)| {
            candidate.id.as_str() == promoted.id.as_str() && promoted.ordinal < explicit.ordinal
        });
    if !queue.available
        || queue.active_global_runs != 0
        || interrupted_item.is_none_or(|item| item.state != queue::QueueItemState::Interrupted)
        || interrupted_run.is_none_or(|run| run.state != queue::RunState::Interrupted)
        || explicit_next_item.is_none_or(|item| {
            item.state != queue::QueueItemState::Queued
                || item.predecessor_run_id.as_deref() != Some(begun.run.id.as_str())
        })
        || promoted_item.is_none_or(|item| item.state != queue::QueueItemState::Queued)
        || promoted_steer
            .is_none_or(|intent| intent.state != queue::SteerIntentState::PromotedToNext)
        || candidates.len() != 1
        || !preserved_user_order
        || queue
            .runs
            .iter()
            .any(|run| run.state == queue::RunState::Running)
    {
        return Err(
            "Restart did not interrupt the old run, preserve Send next, and promote the unconsumed Send now without replay."
                .into(),
        );
    }
    let recovered_snapshot = recovered.snapshot_seed().present_current();
    if recovered_snapshot.usage.context.state != "unknown"
        || recovered_snapshot.usage.context.label != "Unknown"
        || recovered_snapshot.usage.tokens_visible
        || recovered_snapshot.usage.cost_visible
    {
        return Err(
            "Missing provider context/usage did not remain Unknown with charts hidden.".into(),
        );
    }
    let active_project_id = recovered_snapshot.active_project_id;
    let timeline = recovered.events.timeline(active_project_id.as_deref());
    let sequences = timeline
        .events
        .iter()
        .map(|event| event.sequence.get())
        .collect::<Vec<_>>();
    let event_bytes = serde_json::to_vec(&timeline.events)
        .map_err(|error| format!("encode smoke Activity events: {error}"))?;
    if !timeline.available
        || timeline.events.len() < 6
        || sequences.windows(2).any(|pair| pair[0] >= pair[1])
        || !timeline
            .events
            .iter()
            .any(|event| event.kind == contracts::AppEventKind::Proposal)
        || !timeline
            .events
            .iter()
            .any(|event| event.kind == contracts::AppEventKind::Security)
        || !timeline.events.iter().any(|event| {
            event.kind == contracts::AppEventKind::Run
                && event
                    .payload
                    .get("action")
                    .and_then(serde_json::Value::as_str)
                    == Some("interrupted")
        })
        || event_bytes
            .windows("what is in this project?".len())
            .any(|window| window == b"what is in this project?")
        || event_bytes
            .windows("/usr/bin/touch".len())
            .any(|window| window == b"/usr/bin/touch")
    {
        return Err(
            "Activity did not durably restore monotonic Proposal, Security, and Interrupted metadata."
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/ui_contracts.rs"]
mod tests;
