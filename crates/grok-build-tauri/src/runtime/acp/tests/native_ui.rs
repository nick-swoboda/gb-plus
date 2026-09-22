use super::*;
use crate::runtime::cli_permissions::{CliPermissionChoice, CliPermissionMode};

#[test]
fn accept_edits_uses_only_the_cli_offered_session_grant() {
    let (root, workspace, pool, mut config) = super::standard_tests::fixture();
    config.standard.as_mut().unwrap().permission = CliPermissionMode::AcceptEdits;
    let mut adapter = GrokCliAcpAdapter::new(config, RuntimeCancelHandle::new());
    adapter.start_or_restore_session(None).unwrap();
    let result = adapter
        .prompt(
            "permission-fixture",
            None,
            &|event| {
                assert!(!matches!(event, RuntimeEvent::CliInteraction(_)));
                Ok(())
            },
            None,
        )
        .unwrap();
    assert_eq!(result.1, "permission finished");
    let wire = fs::read_to_string(workspace.join("requests.jsonl")).unwrap();
    assert!(wire.contains("\"optionId\":\"allow-edits-session\""));
    assert!(!wire.contains("\"optionId\":\"yes\""));
    assert_eq!(
        CliPermissionChoice::load(&root).unwrap().mode,
        CliPermissionMode::AcceptEdits
    );
    adapter.close_session().unwrap();
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accept_edits_cannot_answer_command_permissions_even_with_an_edit_option_id() {
    let (root, workspace, pool, mut config) = super::standard_tests::fixture();
    let script = fs::read_to_string(&config.cli_path)
        .unwrap()
        .replace("\"kind\":\"edit\"", "\"kind\":\"execute\"");
    fs::write(&config.cli_path, script).unwrap();
    config.standard.as_mut().unwrap().permission = CliPermissionMode::AcceptEdits;
    let cancel = RuntimeCancelHandle::new();
    let mut adapter = GrokCliAcpAdapter::new(config, cancel.clone());
    adapter.start_or_restore_session(None).unwrap();
    let worker =
        std::thread::spawn(move || adapter.prompt("permission-fixture", None, &|_| Ok(()), None));
    let started = Instant::now();
    loop {
        if !cancel.cli_interactions.snapshot().unwrap().is_empty() {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!workspace.join("permission-effect.txt").exists());
    cancel.request_cancel().unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(!workspace.join("permission-effect.txt").exists());
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn attached_images_are_scoped_consumed_once_and_unavailable_after_restart() {
    let root = std::env::temp_dir().join(format!(
        "gbplus-image-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    ));
    let mut png = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png, 2, 2);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&[42; 12])
            .unwrap();
    }
    let images = super::super::cli_images::CliImages::new(&root);
    let scope = super::super::types::RuntimeInvocationScope::fixture();
    let marker = images
        .stage(
            scope.project_id.as_str(),
            scope.workspace_id.as_str(),
            scope.session_id.as_str(),
            png.clone(),
        )
        .unwrap();
    let prompt = format!("Describe this{marker}");
    let mut wrong = scope.clone();
    wrong.project_id = crate::contracts::ProjectId::new("another-project");
    assert!(images.take(&prompt, &wrong).is_err());
    let (text, frame) = images.take(&prompt, &scope).unwrap();
    assert_eq!(text, "Describe this");
    assert_eq!(frame.unwrap().bytes, png);
    assert!(images.take(&prompt, &scope).is_err());
    let next = images
        .stage(
            scope.project_id.as_str(),
            scope.workspace_id.as_str(),
            scope.session_id.as_str(),
            png,
        )
        .unwrap();
    let restarted = super::super::cli_images::CliImages::new(&root);
    assert!(restarted.take(&format!("Describe{next}"), &scope).is_err());
    for entry in fs::read_dir(root.join("cli-image-intents")).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert!(value.get("pixels").is_none());
        assert!(value.get("bytes").is_none());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_write_preview_reads_only_the_bound_workspace_without_writing() {
    let (root, workspace, pool, _) = super::standard_tests::fixture();
    let bound = grok_build_plus_host::bind_project_folder(workspace.to_str().unwrap()).unwrap();
    let path = workspace.join("fact.txt");
    let mut params =
        json!({"toolCall":{"kind":"edit","rawInput":{"file_path":path,"content":"after"}}});
    super::native_edit::preview(Some(&bound), &mut params);
    assert_eq!(params["appPreview"]["oldText"], "shared context");
    assert_eq!(params["appPreview"]["newText"], "after");
    assert_eq!(fs::read_to_string(&path).unwrap(), "shared context");
    params["toolCall"]["rawInput"]["file_path"] = json!(root.join("outside.txt"));
    fs::write(root.join("outside.txt"), "outside workspace").unwrap();
    super::native_edit::preview(Some(&bound), &mut params);
    assert!(params["appPreview"]["oldText"].is_null());
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}
