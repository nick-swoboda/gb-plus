// GB Plus bridge execution contract (tests only).
//
// The user-facing desktop crate cannot mint ValidatedBackendPermit or
// bypass validate_preflight. It cannot treat SandboxManager /
// PermissionClassifier as execution authority. Contained worker commands
// are wire WorkerRunCommand via send_precommitted_task_command, not a
// task-level Command::spawn of the worker program.
//
// Runner-process spawn remains allowed as the service boundary:
// RunnerProcess::spawn / descriptor_launch_command in runner-client launch
// code launches grok-build-runner, not the contained task. That is not a
// second sandbox.

fn desktop_crate_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn runner_client_crate_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../grok-build-runner-client/src")
}

fn is_rust_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn preceding_is_ident(source: &str, cursor: usize) -> bool {
    cursor != 0
        && source[..cursor]
            .chars()
            .next_back()
            .is_some_and(is_rust_ident_char)
}

fn identifier_present(source: &str, ident: &str) -> bool {
    for (cursor, _) in source.char_indices() {
        if !source[cursor..].starts_with(ident) {
            continue;
        }
        let after = cursor + ident.len();
        let after_is_ident = source[after..]
            .chars()
            .next()
            .is_some_and(is_rust_ident_char);
        if !preceding_is_ident(source, cursor) && !after_is_ident {
            return true;
        }
    }
    false
}

fn shipped_desktop_rust_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![desktop_crate_src(), runner_client_crate_src()];
    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir).unwrap_or_else(|error| {
            panic!(
                "read {} for desktop exec-contract fence: {error}",
                dir.display()
            )
        });
        for entry in entries {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            let file_type = entry.file_type().expect("entry type");
            if file_type.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Desktop shipped sources must not name the runner permit mint or 1.05
/// sandbox/permission apply types as an alternate execution authority.
#[test]
fn desktop_shipped_sources_cannot_mint_permit_or_treat_upstream_apply_as_authority() {
    let sources = shipped_desktop_rust_sources();
    assert!(
        sources
            .iter()
            .any(|path| path == &runner_client_crate_src().join("launch.rs")),
        "must scan the shipped WorkerRunCommand dispatch module"
    );
    let mut hits = Vec::new();
    for path in &sources {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for ident in [
            "ValidatedBackendPermit",
            "validate_preflight",
            "SandboxManager",
            "PermissionClassifier",
        ] {
            if identifier_present(&text, ident) {
                hits.push(format!("{}:{ident}", path.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "desktop shipped sources named a permit mint or 1.05 apply/allow path: {hits:?}"
    );
}

/// Contained worker commands are built by `send_precommitted_task_command`
/// as `WorkerRunCommand`. Task-level `Command::spawn` is not that path.
/// `RunnerProcess::spawn` / `descriptor_launch_command` remain the allowed
/// runner-process service boundary (not a second sandbox).
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the GB+-1 contract keeps the shipped send_precommitted_task_command drive, WorkerRunCommand assertion, and allowed RunnerProcess spawn boundary in one proof"
)]
fn send_precommitted_task_command_builds_wire_worker_run_command_not_task_spawn() {
    let command = CommandSpec {
        program: "/usr/bin/true".into(),
        arguments: vec!["--gbplus1".into()],
        working_directory: PathBuf::new(),
    };
    let (harness, mut ledger) = TestHarness::new("gbplus1-worker-wire");
    let exchange_count = Rc::new(Cell::new(0));
    let command_domain_backend = match ordinary_cleanup_backend(RunnerSessionPurpose::TaskWorker)
        .expect("ordinary worker backend is admitted on this host")
    {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            RunnerCommandDomainCleanupBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::LinuxCgroupV2 => RunnerCommandDomainCleanupBackend::LinuxCgroupV2,
        WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            panic!("contained worker commands cannot use the trusted-applier backend")
        }
    };
    let wire_backend = WireCommandBackendIdentity {
        command_domain_backend,
        backend_id: "gbplus1-worker-wire-native-contract".into(),
        implementation_digest: Digest::sha256(b"gbplus1-worker-wire-native-contract/v1"),
    };
    let mut client = RunnerLifecycleClient::launch_with_spawner(
        &mut ledger,
        &harness.authority,
        &harness.policy,
        harness.launch("gbplus1-worker-wire"),
        transport_with_clean_command_v12(
            unique_nonce("gbplus1-worker-wire"),
            harness.identity(),
            harness.private_state.clone(),
            wire_backend,
            Rc::clone(&exchange_count),
        ),
    )
    .expect("initialize worker for GB+-1 wire contract");
    client.shadow_created = true;
    client.shadow_snapshot = Some(harness.base_snapshot.clone());
    let running = client
        .task_attempt_running_boundary()
        .expect("worker entered Running")
        .clone();
    let provider_call = ProviderToolCall {
        sprint_id: harness.sprint_id.clone(),
        task_id: running.attempt.worker_lease.task_id.clone(),
        sequence: 1,
        call_id: "gbplus1-worker-call".into(),
        idempotency_key: "gbplus1-worker-key".into(),
        intent: ProviderToolIntent::RunCommand {
            command: command.clone(),
        },
    };
    let request_bytes = serde_json::to_vec(&command).expect("encode exact worker command");
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: "effect-gbplus1-worker-wire".into(),
        idempotency_key: crate::durable_coordinator::task_lease_provider_call_effect_key(
            &running.attempt.worker_lease.lease_id,
            &provider_call.idempotency_key,
        ),
        sprint_id: harness.sprint_id.clone(),
        task_id: Some(running.attempt.worker_lease.task_id.clone()),
        worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
        worker_lease: Some(running.attempt.worker_lease.clone()),
        causation_event_id: Some(running.transition_event_id.clone()),
        correlation_id: "correlation-gbplus1-worker-wire".into(),
        kind: EffectKind::RunCommand,
        request_digest: Digest::sha256(&request_bytes),
        policy_hash: harness.policy.contract().policy_hash.clone(),
        input_snapshot: harness.base_snapshot.clone(),
        created_at_unix_ms: client.session().registered_at_unix_ms + 1,
    };
    let proposed = proposal(
        &intent,
        ledger
            .next_sequence(&harness.sprint_id)
            .expect("next GB+-1 proposal sequence"),
    );
    let capture_intent = fresh_command_output_capture_intent(
        &intent,
        &client.launch,
        &client.session,
        &harness.policy,
    )
    .expect("construct exact worker output-capture intent");
    let permit = match ledger
        .admit_runner_command_output_capture_intent_for_dispatch(
            &intent,
            &request_bytes,
            &proposed,
            &client.session.session_id,
            &capture_intent,
        )
        .expect("admit ordinary worker command")
    {
        CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
        other => panic!("new worker command must retain fresh authority, got {other:?}"),
    };
    let (_client, claimed) = client
        .send_precommitted_task_command(
            &mut ledger,
            permit,
            &intent,
            &request_bytes,
            &provider_call,
        )
        .expect("ordinary command must cross the shipped WorkerRunCommand path");
    let (exchange, request_frame, _response_digest, _claimed_effect, _authority) =
        claimed.into_parts();
    assert_eq!(
        request_frame,
        encode_request_frame_v12(&exchange.request)
            .expect("re-encode the claimed v12 worker request")
    );
    let RunnerRequestV12::RunCommand {
        request:
            RunnerRequest::WorkerRunCommand {
                command: wire_command,
                ..
            },
        ..
    } = &exchange.request.request
    else {
        panic!(
            "send_precommitted_task_command must emit WorkerRunCommand, observed {:?}",
            exchange.request.request
        );
    };
    assert_eq!(wire_command.program, command.program);
    assert_eq!(wire_command.arguments, command.arguments);
    assert_eq!(
        wire_command.working_directory,
        command
            .working_directory
            .to_str()
            .expect("UTF-8 working directory")
    );
    assert_eq!(
        exchange_count.get(),
        2,
        "initialization plus one WorkerRunCommand must cross transport"
    );
}
