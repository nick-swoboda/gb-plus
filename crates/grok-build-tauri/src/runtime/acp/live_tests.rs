//! Opt-in exact-binary integration fixtures; no real project is modified.

use super::*;
use grok_build_plus_host::{PlusSessionStore, bind_project_folder};

struct FixtureRoot(PathBuf);
impl Drop for FixtureRoot {
    fn drop(&mut self) {
        super::memory_home::shutdown();
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires authenticated admitted CLI; verifies prompt replacement without model inference"]
fn installed_cli_refreshes_existing_system_prompt_without_inference() {
    let root = FixtureRoot(std::env::temp_dir().join(format!(
        "gbplus-live-prompt-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    )));
    let mut adapter = GrokCliAcpAdapter::new(
        AcpLaunchConfig::production(&root.0).unwrap(),
        RuntimeCancelHandle::new(),
    );
    let session_id = adapter.open_session(None, &|_| Ok(())).unwrap();
    let process = adapter.process.as_mut().unwrap();
    let mut pending = vec![process.home.join("sessions")];
    let mut visited = 0;
    let mut prompt_path = None;
    while let Some(directory) = pending.pop() {
        visited += 1;
        assert!(visited <= 128, "fixture home exceeded its directory bound");
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry.file_name() == "system_prompt.txt"
                && entry.path().parent().unwrap().file_name().unwrap() == session_id.as_str()
            {
                prompt_path = Some(entry.path());
            }
        }
    }
    let prompt_path = prompt_path.expect("exact CLI persisted its current system prompt");
    let expect_prompt = |expected: &str| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if fs::read_to_string(&prompt_path).is_ok_and(|text| text == expected) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "CLI prompt replacement did not persist"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    };
    expect_prompt(super::protocol::strict_acp_system_prompt());
    process
        .request(
            "session/load",
            &json!({"sessionId":session_id,"cwd":process.neutral_cwd,"mcpServers":[],
                "_meta":{"systemPromptOverride":"Previous fixture system prompt",
                    "x.ai/mcp/servers":[process.app_tools.registration()]}}),
            &|_| Ok(()),
        )
        .unwrap();
    expect_prompt("Previous fixture system prompt");
    process.active_session_id = None;
    adapter
        .open_session(Some(&session_id), &|_| Ok(()))
        .unwrap();
    expect_prompt(super::protocol::strict_acp_system_prompt());
    adapter.close_session().unwrap();
}

#[test]
#[ignore = "requires authenticated admitted CLI; verifies the enabled extension catalog and reverse invocation"]
fn installed_cli_invokes_enabled_extension_through_reverse_gateway() {
    use crate::runtime::extension_tools::fixtures::Executor;
    let root = FixtureRoot(std::env::temp_dir().join(format!(
        "gbplus-live-extension-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    )));
    let workspace = root.0.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.0.join("store"));
    let external = Arc::new(Executor::default());
    let mut adapter = GrokCliAcpAdapter::new_with_external(
        AcpLaunchConfig::production(&root.0).unwrap(),
        RuntimeCancelHandle::new(),
        external.clone(),
    );
    let prompt = format!(
        "Use the app's enabled extension tool named {} exactly once, with the JSON arguments {{\"value\":\"approved-fixture\"}}. The tool is available through the app MCP gateway. Discover it if necessary. After it returns, briefly report its exact result text. Do not call any other app tool.",
        Executor::name()
    );
    let events = Mutex::new(Vec::new());
    let turn = adapter
        .send_turn(
            &AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            },
            &prompt,
            None,
            &|_| Ok(Vec::new()),
            &|event| {
                events.lock().unwrap().push(event);
                Ok(())
            },
        )
        .expect("exact CLI enabled extension round trip");
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    let calls = external.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2["value"], "approved-fixture");
    assert!(turn.assistant_text.contains("TRANSIENT_MCP_RESULT"));
    assert!(events.lock().unwrap().iter().any(|event| matches!(event,
        RuntimeEvent::ToolCompleted { name, .. } if name == &Executor::name())));
    assert!(!adapter.has_live_process());
    let marker = fs::read_to_string(root.0.join("acp-runtime/acp-context-v1.json")).unwrap();
    assert!(marker.contains("unavailable"));
    assert!(!marker.contains("TRANSIENT_MCP_RESULT"));
    adapter.close_session().unwrap();
}

#[test]
#[ignore = "requires authenticated admitted CLI; verifies exact model, effort, and gateway tool support"]
fn installed_cli_verifies_explicit_model_and_effort() {
    let root = FixtureRoot(std::env::temp_dir().join(format!(
        "gbplus-live-model-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    )));
    let mut adapter = GrokCliAcpAdapter::new(
        AcpLaunchConfig::production(&root.0).unwrap(),
        RuntimeCancelHandle::new(),
    );
    let model = adapter
        .discover_models()
        .unwrap()
        .into_iter()
        .find(|model| model.id == grok_build_plus_host::PLUS_LIVE_MODEL)
        .expect("authenticated catalog offers the app's baseline Grok model");
    let reasoning_effort = model
        .reasoning_efforts
        .iter()
        .find(|level| level.as_str() == "medium")
        .or_else(|| model.reasoning_efforts.first())
        .cloned();
    adapter
        .configure_model(crate::runtime::models::ModelSelection {
            schema_version: 1,
            transport: RuntimeTransport::GrokCliAcp,
            model,
            reasoning_effort,
            verified_at: 0,
        })
        .unwrap();
    adapter
        .probe_model_tools(&|_| Ok(()))
        .expect("exact model and effort gateway probe");
    adapter.close_session().unwrap();
}

#[test]
#[ignore = "requires authenticated admitted CLI; verifies actual image input despite incomplete initialization metadata"]
fn installed_cli_reads_image_content_without_persisting_raw_capture() {
    let root = FixtureRoot(std::env::temp_dir().join(format!(
        "gbplus-live-image-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    )));
    let workspace = root.0.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.0.join("store"));
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 128, 128);
        encoder.set_color(png::ColorType::Rgb);
        let mut writer = encoder.write_header().unwrap();
        let mut pixels = vec![0; 128 * 128 * 3];
        for row in 0..128 {
            for col in 0..128 {
                let color = if col < 64 { [255, 0, 0] } else { [0, 0, 255] };
                pixels[(row * 128 + col) * 3..(row * 128 + col + 1) * 3].copy_from_slice(&color);
            }
        }
        writer.write_image_data(&pixels).unwrap();
    }
    let mut adapter = GrokCliAcpAdapter::new(
        AcpLaunchConfig::production(&root.0).unwrap(),
        RuntimeCancelHandle::new(),
    );
    adapter.ensure_initialized(&|_| Ok(())).unwrap();
    assert!(
        adapter.supports_image,
        "the exact admitted binary has verified image input"
    );
    let digest = worktree_recovery_digest(&bytes);
    let image = AdapterImage {
        png: &bytes,
        width: 128,
        height: 128,
        sha256: &digest,
    };
    let turn = adapter.send_turn(&AdapterContext { scope: crate::runtime::types::RuntimeInvocationScope::fixture(), extension_context: "", hooks: None, bound: &bound, store: &store },
        "Name the two colors in this attached image, in left-to-right order. Reply only with the two color names separated by a comma. Do not call tools.",
        Some(&image), &|_| Ok(Vec::new()), &|_| Ok(())).expect("actual CLI image round trip");
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    let text = turn.assistant_text.to_ascii_lowercase();
    let answer = text.split("assistant:").last().unwrap();
    assert!(answer.find("red").unwrap() < answer.find("blue").unwrap());
    let marker = fs::read_to_string(root.0.join("acp-runtime/acp-context-v1.json")).unwrap();
    assert!(marker.contains("unavailable"));
    assert!(!marker.contains("data:image"));
    adapter.close_session().unwrap();
}

#[test]
#[ignore = "requires authenticated admitted CLI; two prompts verify app tools and post-RAM-reset continuity"]
fn installed_cli_reads_fixture_and_stages_without_writing() {
    let root = FixtureRoot(std::env::temp_dir().join(format!(
        "gbplus-live-tools-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    )));
    let workspace = root.0.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    // The value is absent from the prompt: a real tool read is necessary.
    let content = format!(
        "fixture-secret-{}\n",
        super::super::types::unix_time_millis()
    );
    fs::write(workspace.join("note.txt"), &content).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.0.join("store"));
    let mut adapter = GrokCliAcpAdapter::new(
        AcpLaunchConfig::production(&root.0).unwrap(),
        RuntimeCancelHandle::new(),
    );
    let events = Mutex::new(Vec::new());
    let turn = adapter.send_turn(
        &AdapterContext { scope: crate::runtime::types::RuntimeInvocationScope::fixture(), extension_context: "", hooks: None, bound: &bound, store: &store },
        "Use the app tools to read note.txt, then stage result.txt with exactly those bytes using propose_write. Preserve all whitespace: note.txt has one final LF newline, so the JSON after argument must end with the escaped newline \\n. Do not request Accept. Reply briefly when the proposal is staged.",
        None,
        &|_| Ok(Vec::new()),
        &|event| { events.lock().unwrap().push(event); Ok(()) },
    ).expect("exact admitted CLI structured tool round trip");
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    assert_eq!(turn.pending.items.len(), 1, "{}", turn.assistant_text);
    assert_eq!(
        turn.pending.items[0].relative_path,
        PathBuf::from("result.txt")
    );
    assert_eq!(turn.pending.items[0].after, content.as_bytes());
    assert!(!workspace.join("result.txt").exists());
    assert!(events.lock().unwrap().iter().any(
        |event| matches!(event, RuntimeEvent::ToolCompleted { name, .. } if name == "read_file")
    ));
    assert!(!adapter.has_live_process());
    let provider_id = turn
        .provider_session_id
        .expect("durable CLI session identity");
    drop(adapter);
    super::memory_home::shutdown();
    let mut restored = GrokCliAcpAdapter::new(
        AcpLaunchConfig::production(&root.0).unwrap(),
        RuntimeCancelHandle::new(),
    );
    restored
        .start_or_restore_session(Some(&provider_id))
        .expect("restore from app mirror into a new RAM home");
    let continued = restored.send_turn(
        &AdapterContext { scope: crate::runtime::types::RuntimeInvocationScope::fixture(), extension_context: "", hooks: None, bound: &bound,store: &store },
        "Repeat the exact fixture-secret value that you read from note.txt in the previous turn. Use the previous tool result; do not call any tools.",
        None,&|_| Ok(Vec::new()),&|_| Ok(()),
    ).expect("post-restart second turn");
    assert!(
        continued.assistant_text.contains(content.trim()),
        "{}",
        continued.assistant_text
    );
    assert!(!workspace.join("result.txt").exists());
    restored.close_session().unwrap();
}

#[test]
#[ignore = "requires the admitted authenticated CLI; verifies a real explicitly enabled app skill"]
fn installed_cli_uses_enabled_frozen_skill_context() {
    let root = FixtureRoot(std::env::temp_dir().join(format!(
        "gbplus-live-skill-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    )));
    let workspace = root.0.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.0.join("store"));
    let extensions = crate::extensions::ExtensionStore::new(&root.0.join("app-state"));
    let project = crate::contracts::ProjectId::new("live-skill-project");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/gbplus-extensions/facts")
        .canonicalize()
        .unwrap();
    let preview = extensions.preview_local(&source).unwrap();
    assert!(extensions.skill_context(&project).unwrap().is_empty());
    extensions.install(&preview.digest).unwrap();
    let skill = preview
        .components
        .iter()
        .find(|c| c.kind == crate::extensions::ComponentKind::Skills)
        .unwrap();
    extensions
        .set_enabled(&project, &preview.digest, &skill.id, true)
        .unwrap();
    let frozen = extensions.skill_context(&project).unwrap();
    assert!(frozen.contains("BERYL-42"));
    let mut adapter = GrokCliAcpAdapter::new(
        AcpLaunchConfig::production(&root.0).unwrap(),
        RuntimeCancelHandle::new(),
    );
    let events = Mutex::new(Vec::new());
    let turn = adapter.send_turn(
        &AdapterContext { scope: crate::runtime::types::RuntimeInvocationScope::fixture(), bound: &bound, store: &store, extension_context: &frozen, hooks: None, },
        "What is the GB Plus extension example code? Use the enabled skill. Reply briefly and do not call tools.",
        None, &|_| Ok(Vec::new()), &|event| { events.lock().unwrap().push(event); Ok(()) },
    ).expect("real enabled skill round trip");
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    assert!(
        turn.assistant_text.contains("BERYL-42"),
        "{}",
        turn.assistant_text
    );
    assert!(turn.pending.items.is_empty());
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, RuntimeEvent::ToolRequest { .. }))
    );
    let provider_id = turn.provider_session_id.unwrap();
    adapter.close_session().unwrap();
    extensions
        .set_enabled(&project, &preview.digest, &skill.id, false)
        .unwrap();
    let empty = extensions.skill_context(&project).unwrap();
    assert!(empty.is_empty());
    adapter
        .start_or_restore_session(Some(&provider_id))
        .unwrap();
    let mut scope = crate::runtime::types::RuntimeInvocationScope::fixture();
    scope.run_id = crate::contracts::RunId::new("fixture-second-run");
    let disabled = adapter.send_turn(
        &AdapterContext { scope, bound: &bound, store: &store, extension_context: &empty, hooks: None, },
        "Without calling tools, identify whether an app-loaded skill is active for this turn. Reply exactly SKILLS-OFF if none is active, otherwise SKILLS-ON.",
        None, &|_| Ok(Vec::new()), &|_| Ok(()),
    ).expect("disabled skill state in an existing provider conversation");
    assert_eq!(disabled.outcome, AdapterTurnOutcome::Completed);
    assert!(
        disabled.assistant_text.contains("SKILLS-OFF"),
        "{}",
        disabled.assistant_text
    );
    adapter.close_session().unwrap();
}
