//! Durable binding, migration cuts and reservation recovery.
use super::super::*;

pub(in crate::queue) fn fixture(label: &str) -> (PathBuf, QueueCoordinator, BegunRun) {
    let root = std::env::temp_dir().join(format!(
        "gbplus-execution-{label}-{}-{}",
        std::process::id(),
        unix_time_millis()
    ));
    let queue = QueueCoordinator::open(root.clone());
    let item = queue
        .enqueue(EnqueueRequest {
            project_id: ProjectId::new("project"),
            workspace_id: WorkspaceId::new("workspace"),
            workspace_root: "/tmp/fixture-project".into(),
            session_id: SessionId::new("session"),
            transport: RuntimeTransport::GrokCliAcp,
            prompt: "fixture".into(),
            auto_start: true,
            retry_of_run_id: None,
            predecessor_run_id: None,
        })
        .unwrap();
    let run = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .unwrap();
    (root, queue, run)
}

fn legacy(root: &Path) -> Vec<u8> {
    let path = root.join(PLUS_QUEUE_FILE);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["schemaVersion"] = serde_json::json!(6);
    value.as_object_mut().unwrap().remove("executions");
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(path, &bytes).unwrap();
    bytes
}

#[test]
fn legacy_active_run_migrates_with_exact_backup_then_interrupts_without_resuming() {
    let (root, queue, run) = fixture("legacy-active");
    drop(queue);
    let original = legacy(&root);
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available, "{}", queue.view().status);
    assert_eq!(queue.view().runs[0].state, RunState::Interrupted);
    assert_eq!(
        fs::read(root.join("plus-queue.before-v7.json")).unwrap(),
        original
    );
    assert!(!root.join("plus-queue.before-v6.json").exists());
    queue
        .read(|book| {
            assert!(book.executions.is_empty());
            assert_eq!(book.schema_version, QUEUE_SCHEMA_VERSION);
            assert_eq!(book.runs[0].id, run.run.id);
            Ok(())
        })
        .unwrap();
    assert!(queue.candidates(None, false).unwrap().is_empty());
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_migration_does_not_replace_the_source_or_enable_execution() {
    let (root, queue, _) = fixture("backup-cut");
    drop(queue);
    let original = legacy(&root);
    let backup = root.join("plus-queue.before-v7.json");
    fs::create_dir(&backup).unwrap();
    let queue = QueueCoordinator::open(root.clone());
    assert!(!queue.view().available);
    assert!(queue.candidates(None, false).is_err());
    assert_eq!(fs::read(root.join(PLUS_QUEUE_FILE)).unwrap(), original);
    drop(queue);
    fs::remove_dir(backup).unwrap();
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available, "{}", queue.view().status);
    assert_eq!(queue.view().active_global_runs, 0);
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_preexisting_migration_backup_is_preserved_byte_for_byte() {
    let (root, queue, _) = fixture("backup-retained");
    drop(queue);
    legacy(&root);
    let marker = b"Earlier queue backup retained for explicit recovery.\n";
    OwnerStateRoot::new(&root)
        .file("plus-queue.before-v7.json", MAX_QUEUE_BYTES)
        .unwrap()
        .replace(marker)
        .unwrap();
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available, "{}", queue.view().status);
    assert_eq!(
        fs::read(root.join("plus-queue.before-v7.json")).unwrap(),
        marker
    );
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn current_active_run_missing_or_changing_execution_binding_is_unavailable() {
    for variation in [
        "missing",
        "project",
        "workspace",
        "legacy-forged",
        "terminal",
    ] {
        let (root, queue, _) = fixture(variation);
        drop(queue);
        let path = root.join(PLUS_QUEUE_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match variation {
            "missing" => {
                value.as_object_mut().unwrap().remove("executions");
            }
            "legacy-forged" => value["schemaVersion"] = serde_json::json!(6),
            "terminal" => {
                value["executions"]["members"][0]["execution"]["state"] =
                    serde_json::json!("terminal");
            }
            field => value["executions"]["members"][0][field] = serde_json::json!("forged"),
        }
        let original = serde_json::to_vec_pretty(&value).unwrap();
        fs::write(&path, &original).unwrap();
        let queue = QueueCoordinator::open(root.clone());
        assert!(!queue.view().available, "{variation}");
        assert_eq!(fs::read(path).unwrap(), original);
        assert!(!root.join("plus-queue.before-v7.json").exists());
        drop(queue);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn yielded_parent_retains_project_and_probe_barriers_and_restarts_interrupted() {
    let (root, queue, run) = fixture("yielded-recovery");
    queue
        .mutate(|book| book.executions.yield_parent(&run.run.id))
        .unwrap();
    assert_eq!(queue.view().active_global_runs, 1);
    assert!(queue.lock_idle_scheduler().is_err());
    queue
        .read(|book| {
            assert_eq!(book.executions.held(), 0);
            Ok(())
        })
        .unwrap();
    let mut next = run.item.clone();
    next.prompt = "another prompt".into();
    let item = queue
        .enqueue(EnqueueRequest {
            project_id: next.project_id,
            workspace_id: next.workspace_id,
            workspace_root: next.workspace_root,
            session_id: next.session_id,
            transport: next.transport,
            prompt: next.prompt,
            auto_start: true,
            retry_of_run_id: None,
            predecessor_run_id: None,
        })
        .unwrap();
    assert!(queue.candidates(None, false).unwrap().is_empty());
    assert!(
        queue
            .begin_run(&item.id, RuntimeCancelHandle::new())
            .is_err()
    );
    drop(queue);
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available, "{}", queue.view().status);
    assert_eq!(queue.view().active_global_runs, 0);
    queue
        .read(|book| {
            assert!(book.executions.is_empty());
            Ok(())
        })
        .unwrap();
    assert_eq!(queue.candidates(None, false).unwrap()[0].id, item.id);
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_completion_commit_keeps_model_lease_and_original_cancel_owner() {
    let (root, queue, run) = fixture("failed-finish");
    let target = root.join(PLUS_QUEUE_FILE);
    let original = root.join("saved-queue.json");
    fs::rename(&target, &original).unwrap();
    fs::create_dir(&target).unwrap();
    assert!(
        queue
            .complete_run(&run.run.id, RunCompletion::Done)
            .is_err()
    );
    queue
        .read(|book| {
            assert_eq!(book.executions.held(), 1);
            assert!(book.executions.member(&run.run.id).is_ok());
            Ok(())
        })
        .unwrap();
    assert!(queue.cancels.lock().unwrap().contains_key(&run.run.id));
    fs::remove_dir(&target).unwrap();
    fs::rename(original, target).unwrap();
    queue
        .complete_run(&run.run.id, RunCompletion::Done)
        .unwrap();
    queue
        .read(|book| {
            assert!(book.executions.is_empty());
            Ok(())
        })
        .unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}
