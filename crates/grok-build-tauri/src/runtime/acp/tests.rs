use std::fs;
use std::sync::Mutex;

use grok_build_plus_host::{PlusSessionStore, accept_pending_file_proposal, bind_project_folder};

use super::*;

#[test]
fn cli_internal_reload_replies_do_not_collide_with_app_rpc_or_add_authority() {
    for id in ["skills-reload", "workflows-reload"] {
        let mut frame = json!({"jsonrpc":"2.0","id":id,"result":{"result":{"reloaded":1}}});
        assert!(super::protocol::internal_reload_observation(&frame).unwrap());
        frame["result"]["result"]["execute"] = json!("anything");
        assert!(super::protocol::internal_reload_observation(&frame).is_err());
    }
    assert!(
        !super::protocol::internal_reload_observation(
            &json!({"jsonrpc":"2.0","id":11,"result":{"result":{"reloaded":1}}})
        )
        .unwrap()
    );
}

#[test]
fn persisted_acp_replies_have_one_explicit_assistant_boundary() {
    assert_eq!(
        present_acp_assistant_boundary("plain reply\nsecond line"),
        "Assistant: plain reply\nsecond line"
    );
    assert_eq!(
        present_acp_assistant_boundary("Assistant: already marked"),
        "Assistant: already marked"
    );
    assert_eq!(present_acp_assistant_boundary("  "), "");
}

#[test]
fn structured_acp_http_status_is_classified_without_parsing_display_copy() {
    for (status, kind, clears) in [
        (401, AdapterFailureKind::Authentication, true),
        (403, AdapterFailureKind::Authorization, true),
        (429, AdapterFailureKind::RateLimit, false),
        (503, AdapterFailureKind::ProviderUnavailable, false),
    ] {
        let failure = classify_acp_failure("arbitrary provider copy".into(), Some(status));
        assert_eq!(failure.kind, kind);
        assert_eq!(failure.http_status, Some(status));
        assert_eq!(failure.clears_reconnect_grant(), clears);
    }
}

#[test]
fn profile_has_no_cli_machine_capabilities_and_child_environment_excludes_secrets() {
    let profile = strict_acp_profile();
    let (_, body) = profile.split_once("\n---\n\n").unwrap();
    assert_eq!(body, super::protocol::strict_acp_system_prompt());
    assert!(body.starts_with(grok_build_plus_host::PLUS_APP_SYSTEM_PROMPT));
    assert_eq!(body.matches("You are Grok released by xAI.").count(), 1);
    assert!(profile.contains("promptMode: full"));
    assert!(!profile.contains("{APP_"));
    assert!(!profile.contains("${"));
    assert!(profile.contains("tools: [search_tool, use_tool]"));
    assert!(profile.contains("injectDefaultTools: false"));
    assert!(profile.contains("discoverSkills: false"));
    assert!(profile.contains("permissionMode: dontAsk"));
    assert!(profile.contains("agentsMd: false"));
    assert!(profile.contains("Do not emit textual tool requests."));
    assert!(profile.contains("stage proposals"));
    assert!(!profile.contains("always-approve"));

    let mut command = Command::new("/usr/bin/true");
    ChildEnvironmentProfile::Acp.apply(&mut command);
    let debug = format!("{command:?}");
    for forbidden in [
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROK_DEPLOYMENT_KEY",
        "AWS_SECRET_ACCESS_KEY",
    ] {
        assert!(!debug.contains(forbidden), "child env leaked {forbidden}");
    }
}

#[test]
fn bounded_reader_rejects_malformed_and_oversized_lines() {
    let mut malformed = BufReader::new(&b"not-json\n"[..]);
    assert!(read_bounded_json_line(&mut malformed).is_err());
    let oversized = vec![b'x'; ACP_MAX_LINE_BYTES + 1];
    let mut oversized = BufReader::new(oversized.as_slice());
    let error = read_bounded_json_line(&mut oversized).expect_err("oversized ACP line");
    assert!(error.contains("12 MiB") && !error.contains("1 MiB"));
}

#[test]
fn model_catalog_notification_is_narrowly_validated_without_granting_capabilities() {
    let valid = json!({
        "jsonrpc": "2.0",
        "method": "_x.ai/models/update",
        "params": {
            "currentModelId": "fixture-model",
            "availableModels": [
                { "modelId": "fixture-model", "name": "Fixture" }
            ]
        }
    });
    validate_models_update(&valid).expect("valid model metadata");
    let malformed = json!({
        "params": {
            "currentModelId": "missing-from-list",
            "availableModels": [{ "modelId": "other" }]
        }
    });
    assert!(validate_models_update(&malformed).is_err());
}

#[test]
fn settings_notification_accepts_only_bounded_metadata() {
    let valid = json!({
        "params": {
            "allow_access": true,
            "gate_message": null,
            "permission_mode": null,
            "auto_permission_mode_enabled": false
        }
    });
    validate_settings_update(&valid).expect("valid settings metadata");
    let malformed = json!({ "params": { "allow_access": "yes" } });
    assert!(validate_settings_update(&malformed).is_err());
}

#[test]
fn announcements_notification_is_bounded_metadata_only() {
    let valid = json!({
        "params": {
            "method": "x.ai/announcements/update",
            "params": { "gen": 2, "announcements": [] }
        }
    });
    validate_announcements_update(&valid).expect("valid announcement metadata");
    let malformed = json!({ "params": { "gen": "new", "announcements": [] } });
    assert!(validate_announcements_update(&malformed).is_err());
}

#[test]
fn mcp_lifecycle_is_accepted_only_when_every_capability_count_is_zero() {
    let initialized = json!({
        "params": {
            "sessionId": "fixture-session",
            "mcpToolCount": 0,
            "elapsedMs": 0
        }
    });
    validate_zero_mcp_notification(&initialized, "_x.ai/mcp_initialized")
        .expect("zero-MCP lifecycle metadata");
    let nonzero = json!({
        "params": {
            "sessionId": "fixture-session",
            "mcpToolCount": 1,
            "elapsedMs": 0
        }
    });
    assert!(validate_zero_mcp_notification(&nonzero, "_x.ai/mcp_initialized").is_err());
    let empty_catalog = json!({
        "params": {
            "method": "x.ai/mcp/servers_updated",
            "params": { "mcpServers": [] }
        }
    });
    validate_zero_mcp_notification(&empty_catalog, "_x.ai/mcp/servers_updated")
        .expect("empty MCP catalog");
}

#[test]
fn session_roster_cannot_escape_neutral_cwd_or_enable_yolo() {
    let neutral = Path::new("/tmp/grok-build-plus-neutral-fixture");
    let valid = json!({
        "params": {
            "upserted": [{
                "sessionId": "fixture-session",
                "cwd": "/tmp/grok-build-plus-neutral-fixture",
                "isWorktree": false,
                "yolo": false
            }],
            "removed": []
        }
    });
    validate_sessions_changed(&valid, neutral).expect("strict roster metadata");
    let escaped = json!({
        "params": {
            "upserted": [{
                "sessionId": "fixture-session",
                "cwd": "/tmp/other",
                "isWorktree": false,
                "yolo": false
            }],
            "removed": []
        }
    });
    assert!(validate_sessions_changed(&escaped, neutral).is_err());
}

#[test]
fn cli_queue_may_report_current_run_but_cannot_own_queued_items() {
    let current = json!({
        "params": {
            "sessionId": "fixture-session",
            "entries": [],
            "runningPromptId": "fixture-prompt",
            "runningText": "probe",
            "runningKind": "prompt"
        }
    });
    validate_cli_queue_is_not_owning_work(&current).expect("current prompt metadata");
    let submitted = json!({
        "params": {
            "sessionId": "fixture-session",
            "entries": [{
                "id": "fixture-prompt",
                "text": "probe",
                "position": 0,
                "kind": "prompt"
            }]
        }
    });
    validate_cli_queue_is_not_owning_work(&submitted).expect("submitted prompt metadata");
    let queued = json!({
        "params": {
            "sessionId": "fixture-session",
            "entries": [
                { "id": "one", "text": "one", "position": 0, "kind": "prompt" },
                { "id": "two", "text": "two", "position": 1, "kind": "prompt" }
            ]
        }
    });
    assert!(validate_cli_queue_is_not_owning_work(&queued).is_err());
}

#[test]
fn strict_session_notifications_allow_usage_but_refuse_machine_capabilities() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let completed = json!({
        "params": {
            "sessionId": "fixture-session",
            "update": {
                "sessionUpdate": "turn_completed",
                "prompt_id": "fixture-prompt",
                "stop_reason": "end_turn",
                "usage": {
                    "inputTokens": 100,
                    "outputTokens": 20,
                    "cachedReadTokens": 7,
                    "reasoningTokens": 3,
                    "costUsdTicks": 125_000_000
                }
            }
        }
    });
    handle_strict_session_notification(&completed, &move |event| {
        captured.lock().expect("events").push(event);
        Ok(())
    })
    .expect("turn lifecycle");
    assert_eq!(
        events.lock().expect("events").as_slice(),
        &[RuntimeEvent::Usage(RuntimeUsage {
            input_tokens: Some(100),
            output_tokens: Some(20),
            thought_tokens: Some(3),
            cached_tokens: Some(7),
            context_used: None,
            context_size: None,
            cost_amount: Some("0.0125".into()),
            cost_currency: Some("USD".into()),
        })]
    );
    let subagent = json!({
        "params": {
            "sessionId": "fixture-session",
            "update": { "sessionUpdate": "subagent_spawned" }
        }
    });
    assert!(handle_strict_session_notification(&subagent, &|_| Ok(())).is_err());
}

#[test]
fn unknown_provider_variant_is_preserved_as_unsupported_metadata() {
    let update = json!({
        "params": {
            "sessionId": "fixture-session",
            "update": { "sessionUpdate": "future_provider_variant", "private": "omitted" }
        }
    });
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let error = handle_strict_session_notification(&update, &move |event| {
        captured.lock().expect("events").push(event);
        Ok(())
    })
    .expect_err("unknown strict notification must remain unsupported");
    assert!(!error.contains("future_provider_variant"));
    let discriminator = bounded_event_discriminator("future_provider_variant");
    assert_eq!(
        events.lock().expect("events").as_slice(),
        &[RuntimeEvent::UnsupportedProviderEvent {
            provider: "GrokCliAcp".into(),
            discriminator,
            byte_count: serde_json::to_vec(&json!({
                "sessionUpdate": "future_provider_variant",
                "private": "omitted"
            }))
            .expect("encode fixture update")
            .len(),
        }]
    );
}

#[test]
fn usage_update_preserves_exact_context_and_direct_cost_only() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    emit_acp_context_usage(
        &json!({
            "sessionUpdate": "usage_update",
            "used": 32_000,
            "size": 128_000,
            "cost": {"amount": 0.0125, "currency": "USD"},
            "_meta": {"ignored": true}
        }),
        &move |event| {
            captured.lock().expect("events").push(event);
            Ok(())
        },
    )
    .expect("valid usage update");
    assert_eq!(
        events.lock().expect("events").as_slice(),
        &[RuntimeEvent::Usage(RuntimeUsage {
            input_tokens: None,
            output_tokens: None,
            thought_tokens: None,
            cached_tokens: None,
            context_used: Some(32_000),
            context_size: Some(128_000),
            cost_amount: Some("0.0125".into()),
            cost_currency: Some("USD".into()),
        })]
    );
    for invalid in [
        json!({"sessionUpdate": "usage_update", "used": 1}),
        json!({"sessionUpdate": "usage_update", "used": 1, "size": 2, "cost": {"amount": -1, "currency": "USD"}}),
        json!({"sessionUpdate": "usage_update", "used": 1, "size": 2, "cost": {"amount": 1, "currency": "usd"}}),
        json!({"sessionUpdate": "usage_update", "used": 1, "size": 2, "invented": 50}),
    ] {
        assert!(emit_acp_context_usage(&invalid, &|_| Ok(())).is_err());
    }
}

#[test]
fn available_commands_are_bounded_display_metadata_without_execution_authority() {
    let update = json!({
        "params": {
            "sessionId": "fixture-session",
            "update": {
                "sessionUpdate": "available_commands_update",
                "availableCommands": [{
                    "name": "help",
                    "description": "Show agent-owned help text",
                    "input": { "hint": "optional topic" },
                    "_meta": { "source": "fixture" }
                }]
            }
        }
    });
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    handle_strict_session_notification(&update, &move |event| {
        captured.lock().expect("events").push(event);
        Ok(())
    })
    .expect("bounded display metadata");
    assert!(events.lock().expect("events").is_empty());

    let executable = json!({
        "sessionUpdate": "available_commands_update",
        "availableCommands": [{
            "name": "run",
            "description": "must not gain execution authority",
            "executable": "/bin/sh"
        }]
    });
    assert!(validate_available_commands_update(&executable).is_err());
    let oversized = json!({
        "sessionUpdate": "available_commands_update",
        "availableCommands": [{
            "name": "help",
            "description": "x".repeat(2 * 1024 + 1)
        }]
    });
    assert!(validate_available_commands_update(&oversized).is_err());
}

#[test]
fn user_message_echo_accepts_bounded_text_and_exact_png_only() {
    let valid = json!({
        "sessionUpdate": "user_message_chunk",
        "messageId": "fixture-message",
        "content": {
            "type": "text",
            "text": "hello",
            "annotations": { "audience": ["user"] }
        }
    });
    validate_user_message_chunk(&valid).expect("bounded text echo");
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.resize(64, 1);
    let image = json!({
        "sessionUpdate": "user_message_chunk",
        "content": {
            "type": "image",
            "data": base64::engine::general_purpose::STANDARD.encode(&png),
            "mimeType": "image/png"
        }
    });
    validate_user_message_chunk(&image).expect("bounded PNG echo");
    let invalid_image = json!({
        "sessionUpdate": "user_message_chunk",
        "content": { "type": "image", "data": "not-a-png", "mimeType": "image/jpeg" }
    });
    assert!(validate_user_message_chunk(&invalid_image).is_err());
    let oversized = json!({
        "sessionUpdate": "user_message_chunk",
        "content": { "type": "text", "text": "x".repeat(16 * 1024 + 1) }
    });
    assert!(validate_user_message_chunk(&oversized).is_err());
}

#[test]
fn image_prompt_requires_explicit_agent_capability_and_never_uses_a_uri() {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.resize(64, 1);
    let image = AdapterImage {
        png: &png,
        width: 2,
        height: 2,
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    assert!(acp_prompt_content("inspect", Some(&image), false).is_err());
    let prompt = acp_prompt_content("inspect", Some(&image), true).expect("image prompt");
    assert_eq!(prompt.len(), 2);
    assert_eq!(prompt[0]["type"], "image");
    assert_eq!(prompt[0]["mimeType"], "image/png");
    assert!(prompt[0].get("uri").is_none());
    assert_eq!(prompt[1]["text"], "inspect");
}

#[test]
fn session_info_accepts_only_bounded_non_authoritative_metadata() {
    let valid = json!({
        "sessionUpdate": "session_info_update",
        "title": "Fixture conversation",
        "updatedAt": "2026-08-21T23:00:00Z",
        "_meta": { "source": "fixture" }
    });
    validate_session_info_update(&valid).expect("bounded session metadata");
    let authority = json!({
        "sessionUpdate": "session_info_update",
        "title": "must not change authority",
        "cwd": "/tmp/escape"
    });
    assert!(validate_session_info_update(&authority).is_err());
    let control = json!({
        "sessionUpdate": "session_info_update",
        "title": "bad\ncontrol"
    });
    assert!(validate_session_info_update(&control).is_err());
}

#[test]
fn prompt_complete_cannot_turn_cancel_or_tool_use_into_success() {
    let completed = json!({
        "params": {
            "sessionId": "fixture-session",
            "promptId": "fixture-prompt",
            "stopReason": "end_turn",
            "agentResult": "ok"
        }
    });
    validate_prompt_complete(&completed).expect("end-turn completion");
    validate_authoritative_prompt_result(&json!({ "stopReason": "end_turn" }))
        .expect("authoritative end turn");
    for stop_reason in [
        "cancelled",
        "tool_use",
        "error",
        "rate_limit",
        "max_tokens",
        "unknown",
    ] {
        let refused = json!({
            "params": {
                "sessionId": "fixture-session",
                "stopReason": stop_reason
            }
        });
        assert!(validate_prompt_complete(&refused).is_err());
        assert!(
            validate_authoritative_prompt_result(&json!({ "stopReason": stop_reason })).is_err()
        );
    }
    assert!(validate_authoritative_prompt_result(&json!({})).is_err());
}

#[test]
fn session_scoped_notifications_require_the_exact_active_session() {
    let exact = json!({ "params": { "sessionId": "fixture-session" } });
    validate_active_session(&exact, Some("fixture-session"), "fixture").expect("exact session");
    let mismatch = json!({ "params": { "sessionId": "other-session" } });
    assert!(validate_active_session(&mismatch, Some("fixture-session"), "fixture").is_err());
    let missing = json!({ "params": {} });
    assert!(validate_active_session(&missing, Some("fixture-session"), "fixture").is_err());
    assert!(validate_active_session(&exact, None, "fixture").is_err());
}

#[test]
fn session_new_provisional_updates_commit_only_to_the_matching_response_identity() {
    let update = json!({
        "params": {
            "sessionId": "fixture-session",
            "update": { "sessionUpdate": "session_info_update" }
        }
    });
    let mut provisional = None;
    validate_provisional_session_update(&update, "session/new", &mut provisional)
        .expect("bind one provisional session/new update");
    assert_eq!(provisional.as_deref(), Some("fixture-session"));
    validate_provisional_session_update(&update, "session/new", &mut provisional)
        .expect("same provisional identity remains valid");
    validate_session_new_result(
        "session/new",
        &json!({ "sessionId": "fixture-session" }),
        provisional.as_deref(),
    )
    .expect("matching response commits provisional identity");

    let mismatch = json!({
        "params": {
            "sessionId": "other-session",
            "update": { "sessionUpdate": "session_info_update" }
        }
    });
    assert!(
        validate_provisional_session_update(&mismatch, "session/new", &mut provisional)
            .expect_err("identity drift must refuse")
            .contains("more than one provisional")
    );
    assert!(
        validate_session_new_result(
            "session/new",
            &json!({ "sessionId": "other-session" }),
            provisional.as_deref(),
        )
        .expect_err("response drift must refuse")
        .contains("did not match")
    );
}

#[test]
fn provisional_session_update_is_never_admitted_outside_session_new() {
    let update = json!({
        "params": {
            "sessionId": "fixture-session",
            "update": { "sessionUpdate": "session_info_update" }
        }
    });
    let mut provisional = None;
    let error = validate_provisional_session_update(&update, "initialize", &mut provisional)
        .expect_err("non-session/new provisional update must refuse");
    assert!(error.contains("before an exact session was bound"));
    assert!(provisional.is_none());
}

#[test]
fn test_launch_config_keeps_cli_and_runtime_explicit() {
    let config = AcpLaunchConfig::for_test(
        PathBuf::from("/bin/echo"),
        PathBuf::from("/tmp/grok-build-plus-acp-test"),
    );
    assert_eq!(config.cli_path, PathBuf::from("/bin/echo"));
    assert_eq!(
        config.runtime_root,
        PathBuf::from("/tmp/grok-build-plus-acp-test")
    );
}

#[cfg(unix)]
#[test]
fn oauth_uses_fixed_argv_and_sanitized_environment() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = std::env::temp_dir().join(format!(
        "grok-build-plus-oauth-fixture-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("fixture root");
    let cli = root.join("grok");
    fs::write(
            &cli,
            "#!/bin/sh\nfixture_dir=${0%/*}\n/usr/bin/printf '%s\\n' \"$@\" > \"$fixture_dir/oauth-argv.txt\"\n/usr/bin/env > \"$fixture_dir/oauth-env.txt\"\n",
        )
        .expect("fixture CLI");
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).expect("fixture executable");
    let phases = Mutex::new(Vec::new());
    run_grok_cli_oauth_at(&cli, |phase| {
        phases.lock().expect("OAuth phases").push(phase);
    })
    .expect("OAuth fixture");
    assert_eq!(
        *phases.lock().expect("OAuth phases"),
        [
            GrokCliOAuthPhase::OpeningBrowser,
            GrokCliOAuthPhase::WaitingForSignIn
        ]
    );
    assert_eq!(
        fs::read_to_string(root.join("oauth-argv.txt")).expect("OAuth argv"),
        "login\n--oauth\n"
    );
    let environment = fs::read_to_string(root.join("oauth-env.txt")).expect("OAuth env");
    for forbidden in [
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROK_DEPLOYMENT_KEY",
    ] {
        assert!(
            !environment.contains(forbidden),
            "OAuth child env leaked {forbidden}"
        );
    }
    fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn oauth_details_redact_credentials_codes_urls_and_long_entropy() {
    let sanitized = sanitize_oauth_output(
            b"Opening https://login.example/callback?code=do-not-show\nsafe status\n",
            b"access_token=secret-sentinel\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
    assert!(sanitized.contains("safe status"));
    assert!(sanitized.contains("[URL withheld]"));
    for forbidden in [
        "do-not-show",
        "secret-sentinel",
        "access_token",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(!sanitized.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn acp_completed_result_follow_up_is_structured_and_non_executable() {
    match classify_acp_app_tool_reply("plus_tool list_dir {\"path\":\".\"}", &[]).unwrap() {
        AcpAppToolReply::Requests(requests) => assert_eq!(requests.len(), 1),
        _ => panic!("legacy diagnostics should recognize the old wire format"),
    }
    let step = PlusToolStep {
        name: grok_build_plus_host::PlusToolName::DesktopType,
        request: "bounded transient text".into(),
        result: "Desktop type event posted after exact validation; completion is unknown.".into(),
        ok: true,
    };
    let follow_up = compose_acp_app_tool_follow_up(std::slice::from_ref(&step));
    assert!(follow_up.contains(ACP_APP_TOOL_RESULTS_HEADING));
    assert!(follow_up.contains("completedAppToolResults"));
    assert!(
        !follow_up
            .lines()
            .any(|line| line.starts_with("tool ") || line.starts_with("plus_tool "))
    );
    assert!(
        parse_plus_live_tool_reply(&follow_up, &[])
            .expect("follow-up must remain prose/data")
            .is_empty()
    );

    let exact_echo = present_plus_tool_steps(std::slice::from_ref(&step));
    assert!(matches!(
        classify_acp_app_tool_reply(&exact_echo, std::slice::from_ref(&step)),
        Ok(AcpAppToolReply::CompletedResultEcho)
    ));
    assert!(
        classify_acp_app_tool_reply(&format!("{exact_echo} extra"), std::slice::from_ref(&step))
            .is_err(),
        "a non-exact command-like line must remain a strict refusal"
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires authenticated admitted Grok CLI; live ACP probes, workflows, children, and model-issued delegation"]
fn installed_cli_completes_one_strict_live_path_probe() {
    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            super::memory_home::shutdown();
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "grok-build-plus-real-acp-{}-{unique}",
        std::process::id()
    ));
    let _cleanup = Cleanup(root.clone());
    let config = AcpLaunchConfig::production(&root).expect("installed Grok CLI");
    let mut adapter = GrokCliAcpAdapter::new(config, RuntimeCancelHandle::new());
    let assistant = Arc::new(Mutex::new(String::new()));
    let captured = Arc::clone(&assistant);
    let probe = adapter
        .probe(&move |event| {
            if let RuntimeEvent::AssistantDelta(delta) = event
                && let Ok(mut text) = captured.lock()
            {
                text.push_str(&delta);
            }
            Ok(())
        })
        .expect("strict live ACP probe");
    assert!(!probe.model.trim().is_empty());
    assert!(
        !assistant
            .lock()
            .expect("assistant capture")
            .trim()
            .is_empty(),
        "live connection check returned no assistant text"
    );
    adapter.close_session().expect("close live ACP session");
    let mut runtime = crate::runtime::manager::RuntimeManager::offline(root.join("parent-runtime"));
    runtime
        .select(RuntimeTransport::GrokCliAcp)
        .expect("select CLI");
    runtime
        .connect(&|_| Ok(()))
        .expect("verify parent transport");
    crate::workflows::live_fixture::qualify(&root, &runtime);
    crate::collaboration::live_fixture::qualify(&root, &runtime);
    crate::collaboration::live_parent::qualify(&root, &runtime);
    runtime.disconnect().expect("close parent transport");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires an installed authenticated Grok CLI; performs initialize/authenticate only"]
fn installed_cli_has_advertised_or_exact_binary_verified_image_support() {
    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            super::memory_home::shutdown();
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "grok-build-plus-real-acp-image-capability-{}-{unique}",
        std::process::id()
    ));
    let _cleanup = Cleanup(root.clone());
    let config = AcpLaunchConfig::production(&root).expect("installed Grok CLI");
    let mut adapter = GrokCliAcpAdapter::new(config, RuntimeCancelHandle::new());
    adapter
        .ensure_initialized(&|_| Ok(()))
        .expect("strict ACP initialize/authenticate");
    assert!(
        adapter.supports_image,
        "installed Grok CLI has neither advertised nor exact-binary-verified image input"
    );
    adapter.close_session().expect("close ACP capability probe");
}

#[cfg(unix)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture proves reverse RPC ID collision handling and the production tool boundary end to end"
)]
fn structured_desktop_call_runs_once_and_textual_effect_requests_remain_prose() {
    use std::os::unix::fs::PermissionsExt as _;
    #[derive(Default)]
    struct RecordingDesktopExecutor(Mutex<usize>);
    impl PlusExternalToolExecutor for RecordingDesktopExecutor {
        fn execute(&self, request: &PlusToolRequest) -> Option<Result<String, PlusHostError>> {
            if request.name.as_str() != "desktop_type" {
                return None;
            }
            *self.0.lock().unwrap() += 1;
            Some(Ok(
                "Desktop event posted after validation; application completion is unknown.".into(),
            ))
        }
    }
    let root = std::env::temp_dir().join(format!(
        "gbplus-reverse-mcp-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("grok");
    fs::write(&script, r#"#!/bin/sh
if [ "$1" = "--version" ]; then /usr/bin/printf 'grok 1.0.25 (fixture) [stable]\n'; exit 0; fi
server=''
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"authMethods":[{"id":"cached_token"}],"_meta":{"x.ai/mcp/sdk":true,"mcpServers":[],"modelState":{"currentModelId":"fixture-model"}}}}' ;;
    *'"method":"authenticate"'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}' ;;
    *'"method":"session/new"'*)
      server=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"serverId":"\([^"]*\)".*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"sessionId":"fixture-session"}}' ;;
    *'"method":"session/load"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      server=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"serverId":"\([^"]*\)".*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{}}' ;;
    *'"method":"_x.ai/session/rename"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"success":true}}' ;;
    *'"method":"_x.ai/session/info"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"sessionId":"fixture-session","cwd":"'"$(pwd)"'","agentName":"grok-build-plus-gui","context":{"toolDefinitionsCount":2}}}}' ;;
    *'"method":"_x.ai/mcp/list"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"servers":[{"name":"gbplus","source":"local","type":"stdio","command":"","session":{"enabled":true,"status":"ready","tools":[{"name":"browser_click","enabled":true},{"name":"browser_inspect","enabled":true},{"name":"browser_key","enabled":true},{"name":"browser_navigate","enabled":true},{"name":"browser_screenshot","enabled":true},{"name":"browser_scroll","enabled":true},{"name":"browser_type","enabled":true},{"name":"desktop_click","enabled":true},{"name":"desktop_key","enabled":true},{"name":"desktop_scroll","enabled":true},{"name":"desktop_type","enabled":true},{"name":"glob","enabled":true},{"name":"grep","enabled":true},{"name":"list_dir","enabled":true},{"name":"propose_replace","enabled":true},{"name":"propose_write","enabled":true},{"name":"read_file","enabled":true},{"name":"run_contained","enabled":true},{"name":"todo_write","enabled":true}]}}]}}}' ;;
    *'"method":"session/prompt"'*)
      prompt_id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":900,"method":"_x.ai/mcp/sdk_call","params":{"serverId":"'"$server"'","message":{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}}}' ;;
    *'"id":900'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$prompt_id"',"method":"_x.ai/mcp/sdk_call","params":{"serverId":"'"$server"'","message":{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"desktop_type","arguments":{"text":"transient input"}}}}}' ;;
    *'"method":"_x.ai/session/close"'*)
      close_id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":908,"method":"_x.ai/mcp/sdk_call","params":{"serverId":"'"$server"'","message":{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"desktop_type","arguments":{"text":"late rejected input"}}}}}' ;;
    *'"id":908'*)
      case "$line" in *'registration is inactive'*) ;; *) exit 66 ;; esac
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$close_id"',"result":{"result":{"success":true,"outcome":"closed"}}}' ;;
    *'"id":'"$prompt_id"*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"plus_tool propose_write {\"path\":\"unexpected.txt\",\"after\":\"must not run\"}"}}}}'
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$prompt_id"',"result":{"stopReason":"end_turn"}}' ;;
  esac
done
"#).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let external = Arc::new(RecordingDesktopExecutor::default());
    let mut adapter = GrokCliAcpAdapter::new_with_external(
        AcpLaunchConfig::for_test(script, root.join("runtime")),
        RuntimeCancelHandle::new(),
        external.clone(),
    );
    let turn = adapter
        .send_turn(
            &AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            },
            "Type once",
            None,
            &|_| Ok(Vec::new()),
            &|_| Ok(()),
        )
        .unwrap();
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    assert_eq!(*external.0.lock().unwrap(), 1);
    assert!(turn.assistant_text.contains("plus_tool propose_write"));
    assert!(!workspace.join("unexpected.txt").exists());
    assert!(turn.pending.items.is_empty());
    assert!(
        !adapter.has_live_process(),
        "completed executions must revoke their reverse registrations"
    );
    drop(adapter);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn fake_acp_covers_strict_lifecycle_stream_cancel_and_close() {
    use std::os::unix::fs::PermissionsExt as _;

    let root =
        std::env::temp_dir().join(format!("grok-build-plus-fake-acp-{}", std::process::id()));
    let script = root.join("fake-grok");
    fs::create_dir_all(&root).expect("fake root");
    fs::write(
            &script,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then /usr/bin/printf 'grok 1.0.25 (fixture) [stable]\n'; exit 0; fi
/usr/bin/env > child-env.txt
/usr/bin/printf '%s\n' "$@" > child-argv.txt
prompt_count=0
server=''
while IFS= read -r line; do
  /usr/bin/printf '%s\n' "$line" >> requests.log
  case "$line" in
    *'"method":"initialize"'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"authMethods":[{"id":"cached_token"}],"_meta":{"x.ai/mcp/sdk":true,"mcpServers":[],"modelState":{"currentModelId":"fixture-model"}}}}'
      ;;
    *'"method":"authenticate"'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}'
      ;;
    *'"method":"session/new"'*)
      server=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"serverId":"\([^"]*\)".*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"session_info_update","title":"Provisional fixture session"}}}'
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"sessionId":"fixture-session"}}'
      ;;
    *'"method":"session/load"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      server=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"serverId":"\([^"]*\)".*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{}}' ;;
    *'"method":"_x.ai/session/rename"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"success":true}}' ;;
    *'"method":"_x.ai/session/info"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"sessionId":"fixture-session","cwd":"'"$(pwd)"'","agentName":"grok-build-plus-gui","context":{"toolDefinitionsCount":2}}}}' ;;
    *'"method":"_x.ai/mcp/list"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"servers":[{"name":"gbplus","source":"local","type":"stdio","command":"","session":{"enabled":true,"status":"ready","tools":[{"name":"browser_click","enabled":true},{"name":"browser_inspect","enabled":true},{"name":"browser_key","enabled":true},{"name":"browser_navigate","enabled":true},{"name":"browser_screenshot","enabled":true},{"name":"browser_scroll","enabled":true},{"name":"browser_type","enabled":true},{"name":"desktop_click","enabled":true},{"name":"desktop_key","enabled":true},{"name":"desktop_scroll","enabled":true},{"name":"desktop_type","enabled":true},{"name":"glob","enabled":true},{"name":"grep","enabled":true},{"name":"list_dir","enabled":true},{"name":"propose_replace","enabled":true},{"name":"propose_write","enabled":true},{"name":"read_file","enabled":true},{"name":"run_contained","enabled":true},{"name":"todo_write","enabled":true}]}}]}}}' ;;
    *'"method":"session/prompt"'*)
      prompt_id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      prompt_count=$((prompt_count + 1))
      if [ "$prompt_count" -eq 1 ]; then
        text=probe-ok
        id=$prompt_id
        /usr/bin/printf '%s\n' "{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"sessionId\":\"fixture-session\",\"update\":{\"sessionUpdate\":\"agent_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"$text\"}}}}"
      elif [ "$prompt_count" -eq 2 ]; then
        /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":900,"method":"_x.ai/mcp/sdk_call","params":{"serverId":"'"$server"'","message":{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}}}'
        continue
      else
        text=proposal-staged-awaiting-accept
        id=$prompt_id
        /usr/bin/printf '%s\n' "{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"sessionId\":\"fixture-session\",\"update\":{\"sessionUpdate\":\"agent_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"$text\"}}}}"
      fi
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"usage_update","used":25,"size":100,"cost":{"amount":0.0005,"currency":"USD"}}}}'
      /usr/bin/printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"stopReason\":\"end_turn\"}}"
      ;;
    *'"id":900'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":901,"method":"_x.ai/mcp/sdk_call","params":{"serverId":"'"$server"'","message":{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"propose_write","arguments":{"path":"agent-e2e.txt","after":"staged by strict ACP\n"}}}}}'
      ;;
    *'"id":901'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"proposal-staged-awaiting-accept"}}}}'
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"usage_update","used":25,"size":100,"cost":{"amount":0.0005,"currency":"USD"}}}}'
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$prompt_id"',"result":{"stopReason":"end_turn"}}'
      ;;
    *'"method":"_x.ai/session/close"'*)
      id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"success":true,"outcome":"closed"}}}'
      ;;
  esac
done
"#,
        )
        .expect("fake script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("executable");

    let config = AcpLaunchConfig::for_test(script, root.join("runtime"));
    let mut adapter = GrokCliAcpAdapter::new(config, RuntimeCancelHandle::new());
    let streamed = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&streamed);
    let probe = adapter
        .probe(&move |event| {
            capture.lock().expect("events").push(event);
            Ok(())
        })
        .expect("probe");
    assert_eq!(probe.model, "fixture-model");

    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let bound = bind_project_folder(&workspace).expect("bound");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let turn_events = Arc::new(Mutex::new(Vec::new()));
    let turn_capture = Arc::clone(&turn_events);
    let turn = adapter
        .send_turn(
            &AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            },
            "hello",
            None,
            &|_| Ok(Vec::new()),
            &move |event| {
                turn_capture.lock().expect("turn events").push(event);
                Ok(())
            },
        )
        .expect("turn");
    assert!(
        turn.assistant_text.contains(
            "tool propose_write agent-e2e.txt → completed: staged agent-e2e.txt (not written)"
        ),
        "missing honest proposal trail: {}",
        turn.assistant_text
    );
    assert!(
        turn.assistant_text
            .contains("Assistant: proposal-staged-awaiting-accept")
    );
    assert!(!turn.assistant_text.contains("plus_tool propose_write"));
    assert_eq!(turn.pending.items.len(), 1);
    assert!(
        !workspace.join("agent-e2e.txt").exists(),
        "adapter tool dispatch must not write before Accept"
    );
    assert_eq!(turn.provider_session_id.as_deref(), Some("fixture-session"));
    let recorded = turn_events.lock().expect("turn events");
    assert!(recorded.iter().any(|event| matches!(
        event,
        RuntimeEvent::Usage(RuntimeUsage {
            context_used: Some(25),
            context_size: Some(100),
            cost_amount: Some(amount),
            cost_currency: Some(currency),
            ..
        }) if amount == "0.0005" && currency == "USD"
    )));
    assert!(recorded.iter().any(|event| matches!(
        event,
        RuntimeEvent::ToolRequest { name, .. } if name == "propose_write"
    )));
    assert!(recorded.iter().any(|event| matches!(
        event,
        RuntimeEvent::ToolCompleted { name, .. } if name == "propose_write"
    )));
    drop(recorded);
    accept_pending_file_proposal(&bound, &turn.pending.items[0]).expect("Accept proposal");
    assert_eq!(
        fs::read(workspace.join("agent-e2e.txt")).expect("accepted bytes"),
        b"staged by strict ACP\n"
    );
    adapter
        .start_or_restore_session(Some(&crate::contracts::ProviderSessionId::new(
            "fixture-session",
        )))
        .expect("restore with the current app prompt");
    adapter.cancel_run().expect("cancel");
    adapter.close_session().expect("close");

    let neutral = root.join("runtime/neutral-cwd");
    let requests = fs::read_to_string(neutral.join("requests.log")).expect("requests");
    let frames: Vec<Value> = requests
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for method in ["session/new", "session/load"] {
        let matching: Vec<_> = frames
            .iter()
            .filter(|frame| frame["method"] == method)
            .collect();
        assert!(!matching.is_empty(), "missing {method}");
        for frame in matching {
            assert_eq!(
                frame["params"]["_meta"]["systemPromptOverride"],
                super::protocol::strict_acp_system_prompt()
            );
        }
    }
    assert!(!requests.contains(ACP_APP_TOOL_RESULTS_HEADING));
    assert!(requests.contains("staged agent-e2e.txt (not written)"));
    for method in [
        "initialize",
        "authenticate",
        "session/new",
        "session/prompt",
    ] {
        assert!(requests.contains(method), "missing {method}: {requests}");
    }
    assert!(!adapter.has_live_process());
    let child_env = fs::read_to_string(neutral.join("child-env.txt")).expect("child env");
    for forbidden in [
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROK_DEPLOYMENT_KEY",
    ] {
        assert!(
            !child_env.contains(forbidden),
            "child env leaked {forbidden}"
        );
    }
    let argv = fs::read_to_string(neutral.join("child-argv.txt")).expect("argv");
    assert!(argv.contains("--agent-profile") && argv.contains("stdio"));
    assert!(!argv.contains("hello") && !argv.contains("xai-"));
    let profile = fs::read_to_string(root.join("runtime/grok-build-plus-gui.md")).expect("profile");
    assert_eq!(profile, strict_acp_profile());
    assert_eq!(
        fs::metadata(root.join("runtime"))
            .expect("runtime metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("runtime/grok-build-plus-gui.md"))
            .expect("profile metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn late_interjection_waits_for_history_terminal_and_idle_before_revoking_the_connection() {
    use crate::contracts::SteerIntentId;
    use crate::queue::SteerIntentState;
    use crate::runtime::types::{RuntimeSteeringAction, RuntimeSteeringMessage};
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!(
        "gbplus-acp-steering-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    ));
    fs::create_dir_all(root.join("workspace")).unwrap();
    let script = root.join("grok");
    fs::write(
        &script,
        include_str!("../../../tests/fixtures/grok-acp-steering.sh"),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let bound = bind_project_folder(root.join("workspace")).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("store"));
    let state = Mutex::new((false, Vec::new()));
    let steering = |action| {
        let mut state = state.lock().unwrap();
        match action {
            RuntimeSteeringAction::SubmitPending if !state.0 => {
                state.0 = true;
                state.1.push(SteerIntentState::Submitted);
                Ok(vec![RuntimeSteeringMessage {
                    id: SteerIntentId::new("steer-one"),
                    text: "Finish the follow-up.".into(),
                    transient: false,
                }])
            }
            RuntimeSteeringAction::Record(id, delivery) => {
                assert_eq!(id.as_str(), "steer-one");
                state.1.push(delivery);
                Ok(Vec::new())
            }
            RuntimeSteeringAction::SubmitPending => Ok(Vec::new()),
        }
    };
    let mut adapter = GrokCliAcpAdapter::new(
        AcpLaunchConfig::for_test(script, root.join("runtime")),
        RuntimeCancelHandle::new(),
    );
    let turn = adapter
        .send_turn(
            &AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            },
            "Original prompt.",
            None,
            &steering,
            &|_| Ok(()),
        )
        .unwrap();
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    assert!(
        turn.assistant_text
            .contains("Original completion. Follow-up completed.")
    );
    assert_eq!(
        state.lock().unwrap().1,
        vec![
            SteerIntentState::Submitted,
            SteerIntentState::AcknowledgedByCli,
            SteerIntentState::ObservedInProviderHistory
        ]
    );
    assert!(!adapter.has_live_process());
    assert_eq!(
        fs::read_to_string(root.join("runtime/neutral-cwd/close-observed.txt")).unwrap(),
        "closed\n"
    );
    fs::remove_dir_all(root).unwrap();
}

// Append to runtime/acp/tests.rs before applying the implementation fix.
#[test]
fn temporary_acp_child_reply_does_not_create_secondary_session_store_files() {
    fn inspect(path: &std::path::Path) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                inspect(&path);
            } else {
                assert!(
                    !String::from_utf8_lossy(&fs::read(&path).unwrap())
                        .contains("TEMPORARY_ACP_CHILD_REPLY_CANARY"),
                    "Temporary child output reached {}",
                    path.display()
                );
            }
        }
    }
    use crate::runtime::extension_tools::fixtures::Restricted;
    use grok_build_plus_host::PlusRuntimeToolPolicy;
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!(
        "gbplus-temporary-acp-child-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    ));
    fs::create_dir_all(root.join("workspace")).unwrap();
    let state = root.join("state");
    let script = root.join("fixture-grok");
    fs::write(&script,r#"#!/bin/sh
if [ "$1" = "--version" ]; then /usr/bin/printf 'grok 1.0.25 (fixture) [stable]\n'; exit 0; fi
while IFS= read -r line; do
 id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
 case "$line" in
 *'"method":"initialize"'*) result='{"protocolVersion":1,"authMethods":[{"id":"cached_token"}],"_meta":{"x.ai/mcp/sdk":true,"mcpServers":[],"modelState":{"currentModelId":"fixture-model"}}}' ;;
 *'"method":"authenticate"'*) result='{}' ;;
 *'"method":"session/new"'*) result='{"sessionId":"fixture-session"}' ;;
 *'"method":"session/load"'*) result='{}' ;;
 *'"method":"_x.ai/session/rename"'*) result='{"success":true}' ;;
 *'"method":"_x.ai/session/info"'*) result='{"result":{"sessionId":"fixture-session","cwd":"'"$(pwd)"'","agentName":"grok-build-plus-gui","context":{"toolDefinitionsCount":2}}}' ;;
 *'"method":"_x.ai/mcp/list"'*) result='{"result":{"servers":[{"name":"gbplus","source":"local","type":"stdio","command":"","session":{"enabled":true,"status":"ready","tools":[{"name":"glob","enabled":true},{"name":"grep","enabled":true},{"name":"list_dir","enabled":true},{"name":"read_file","enabled":true}]}}]}}' ;;
 *'"method":"session/prompt"'*)
 /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"TEMPORARY_ACP_CHILD_REPLY_CANARY"}}}}'
 result='{"stopReason":"end_turn"}' ;;
 *'"method":"_x.ai/session/close"'*) result='{"result":{"success":true,"outcome":"closed"}}' ;;
 *) /usr/bin/printf '%s\n' "$line" > ../../../unknown-request.json; exit 74 ;;
 esac
 /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":'"$result"'}'
done
"#).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let bound = bind_project_folder(root.join("workspace")).unwrap();
    let store = PlusSessionStore::from_state_root(state.join("child-run-stores"));
    let mut adapter = GrokCliAcpAdapter::new_with_external(
        AcpLaunchConfig::for_test(script, state.join("runtime")),
        RuntimeCancelHandle::new(),
        Arc::new(Restricted(PlusRuntimeToolPolicy::Explore)),
    );
    adapter.require_transient_context(true);
    let turn = adapter
        .send_turn(
            &AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            },
            "Temporary child fixture",
            None,
            &|_| Ok(Vec::new()),
            &|_| Ok(()),
        )
        .unwrap();
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    assert!(
        turn.assistant_text
            .contains("TEMPORARY_ACP_CHILD_REPLY_CANARY")
    );
    assert!(!adapter.has_live_process());
    assert!(
        store.load_chat_transcript().unwrap().is_none(),
        "Temporary child output reached a duplicate persistent app session store"
    );

    inspect(&state);
    drop(adapter);
    fs::remove_dir_all(root).unwrap();
}
