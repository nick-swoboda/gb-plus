use super::RuntimeCancelHandle;

#[test]
fn cancellation_is_one_shot_and_cannot_be_cleared_by_worker_start() {
    let cancel = RuntimeCancelHandle::new();
    cancel.request_cancel().expect("request cancel");
    assert!(cancel.cancelled());
    assert!(cancel.ensure_not_cancelled().is_err());
    assert!(cancel.cancelled(), "worker start must never clear Stop");
}

#[test]
fn hook_cleanup_uncertainty_survives_stop_and_capacity_is_bounded() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let cancel = RuntimeCancelHandle::new();
    let proofs = (0..8)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect::<Vec<_>>();
    for proof in &proofs {
        cancel
            .retain_hook_cleanup_fixture(Arc::clone(proof))
            .unwrap();
    }
    assert!(!cancel.cleanup_proven());
    assert!(
        cancel
            .retain_hook_cleanup_fixture(Arc::new(AtomicBool::new(false)))
            .is_err()
    );
    for proof in &proofs {
        proof.store(true, Ordering::Release);
    }
    assert!(cancel.cleanup_proven());
    let uncertain = Arc::new(AtomicBool::new(false));
    cancel
        .retain_hook_cleanup_fixture(Arc::clone(&uncertain))
        .unwrap();
    cancel.request_cancel().unwrap();
    assert!(!cancel.cleanup_proven());
    assert!(
        cancel
            .retain_hook_cleanup_fixture(Arc::new(AtomicBool::new(false)))
            .is_err()
    );
    uncertain.store(true, Ordering::Release);
    assert!(cancel.cleanup_proven());
}

#[test]
fn unstarted_hook_admissions_release_scheduler_custody_and_remain_retryable() {
    use grok_build_plus_host::{
        ContainedServiceRequest, Digest, PlusCommandSecurityPreference, PlusContainedService,
        PlusGuestLifecycle, ServiceArchitecture, ServiceLimits, ServicePurpose, ServiceScope,
        ServiceSnapshot, service_environment,
    };
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!(
        "gbplus-unstarted-hook-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = root.canonicalize().unwrap();
    let view = ServiceSnapshot::from_files(&[], &root, "view", &|| false).unwrap();
    let request = ContainedServiceRequest {
        schema_version: 1,
        lease_id: "unstarted-fixture".into(),
        scope: ServiceScope {
            project_id: "fixture-project".into(),
            operation_id: "fixture-run".into(),
            workspace_digest: view.digest().clone(),
            extension_digest: view.digest().clone(),
            containment_digest: Digest::sha256(b"fixture"),
        },
        purpose: ServicePurpose::Hook,
        executable: "/extension/bin/guard".into(),
        content_root: "/extension".into(),
        executable_digest: Digest::sha256(b"fixture"),
        executable_bytes: 64,
        architecture: ServiceArchitecture::LinuxAarch64,
        arguments: Vec::new(),
        environment: service_environment(),
        workspace: "/workspace".into(),
        limits: ServiceLimits {
            lifetime_ms: 10_000,
            ..ServiceLimits::default()
        },
    };
    request.validate_shape().unwrap();
    let lifecycle = PlusGuestLifecycle::GuestDown {
        reasons: vec!["Fixture has no guest".into()],
    };
    let cancel = RuntimeCancelHandle::new();
    for index in 0..16 {
        let mut candidate = request.clone();
        if index % 2 == 0 {
            candidate.schema_version = 0;
        }
        let result = PlusContainedService::open_tracked(
            candidate,
            PlusCommandSecurityPreference::Off,
            &lifecycle,
            (&view, &view),
            &|| false,
            &mut |proof| {
                assert!(
                    !proof.proven(),
                    "Pending admission cannot be pruned as completed."
                );
                cancel.retain_hook_cleanup(proof)?;
                assert!(!cancel.cleanup_proven());
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(
            cancel.cleanup_proven(),
            "A definitely unstarted admission cannot strand a scheduler slot."
        );
    }
    let result = PlusContainedService::open_tracked(
        request,
        PlusCommandSecurityPreference::Extra,
        &lifecycle,
        (&view, &view),
        &|| cancel.cancelled(),
        &mut |proof| {
            cancel.retain_hook_cleanup(proof)?;
            cancel.request_cancel()?;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(cancel.cleanup_proven());
    drop(view);
    std::fs::remove_dir_all(root).unwrap();
}
