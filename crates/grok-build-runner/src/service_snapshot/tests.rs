use super::*;
use std::cell::Cell;
use std::os::unix::fs::{PermissionsExt as _, symlink};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "gb-service-snapshot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["source", "private"] {
            std::fs::create_dir(path.join(name)).unwrap();
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        Self(path.canonicalize().unwrap())
    }

    fn capture(&self, policy: ServiceSnapshotPolicy) -> Result<ServiceSnapshot, String> {
        ServiceSnapshot::capture(
            &self.0.join("source"),
            &self.0.join("private"),
            "view",
            policy,
            &|| false,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn immutable_inventory_materialization_matches_capture_and_removes_partial_work() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source");
    std::fs::create_dir(source.join("bin")).unwrap();
    std::fs::write(source.join("bin/server"), b"inert fixture image").unwrap();
    std::fs::set_permissions(
        source.join("bin/server"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(source.join("readme.txt"), b"fixture docs").unwrap();
    let expected = crate::service_tree_digest(&source).unwrap();
    let files = [
        ServiceSnapshotFile {
            path: "readme.txt",
            bytes: b"fixture docs",
            executable: false,
        },
        ServiceSnapshotFile {
            path: "bin/server",
            bytes: b"inert fixture image",
            executable: true,
        },
    ];
    let view =
        ServiceSnapshot::from_files(&files, &fixture.0.join("private"), "view", &|| false).unwrap();
    assert_eq!(view.digest(), &expected);
    assert_eq!(view.size(), (2, 31));
    view.remove().unwrap();
    let result = ServiceSnapshot::from_files(&files, &fixture.0.join("private"), "view", &|| {
        fixture.0.join("private/view/readme.txt").exists()
    });
    assert!(result.is_err());
    assert!(!fixture.0.join("private/view").exists());
}

#[test]
fn immutable_inventory_refuses_aliases_traversal_credentials_and_file_directory_overlap() {
    let fixture = Fixture::new();
    for (first, second) in [
        ("a", "a"),
        ("a", "A"),
        ("a", "a/file"),
        ("Dir/a", "dir/b"),
        ("a", "../outside"),
        ("a", "/absolute"),
        ("a", ".env"),
        ("a", "a//b"),
    ] {
        let files = [
            ServiceSnapshotFile {
                path: first,
                bytes: b"first",
                executable: false,
            },
            ServiceSnapshotFile {
                path: second,
                bytes: b"second",
                executable: false,
            },
        ];
        assert!(
            ServiceSnapshot::from_files(&files, &fixture.0.join("private"), "view", &|| false)
                .is_err(),
            "{first} {second}"
        );
        assert!(!fixture.0.join("private/view").exists());
    }
}

#[test]
fn workspace_projection_omits_custom_auth_state_and_generated_trees_before_reading() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source");
    for name in ["target", "nested", "app-data", "ordinary"] {
        std::fs::create_dir(source.join(name)).unwrap();
    }
    // Traversing either tree would refuse on the symlink/oversized file.
    symlink("/etc/passwd", source.join("target/link")).unwrap();
    std::fs::File::create(source.join("app-data/large"))
        .unwrap()
        .set_len(256 * 1024 * 1024 + 1)
        .unwrap();
    std::fs::write(source.join("nested/login.data"), b"private fixture").unwrap();
    std::fs::write(source.join("ordinary/login.data"), b"ordinary dirty source").unwrap();
    let snapshot = ServiceSnapshot::capture_workspace(
        &source,
        &fixture.0.join("private"),
        "view",
        &[source.join("nested/login.data"), source.join("app-data")],
        &|| false,
    )
    .unwrap();
    assert_eq!(
        snapshot.exclusions(),
        ["app-data", "nested/login.data", "target"]
    );
    assert_eq!(snapshot.size().0, 1);
    assert_eq!(
        std::fs::read(snapshot.path().join("ordinary/login.data")).unwrap(),
        b"ordinary dirty source"
    );
    assert!(!snapshot.path().join("nested/login.data").exists());
    snapshot.revalidate().unwrap();
}

#[test]
fn workspace_protection_resolves_aliases_and_future_paths_and_refuses_protected_roots() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source");
    std::fs::create_dir(source.join("data")).unwrap();
    symlink(source.join("data"), fixture.0.join("alias")).unwrap();
    let protected = fixture.0.join("alias/future.data");
    let filter = workspace::Filter::new(&source, std::slice::from_ref(&protected)).unwrap();
    assert!(filter.excludes_path("data/future.data"));
    assert!(!filter.excludes_path("data/future.data.txt"));
    std::fs::write(source.join("data/future.data"), b"must be excluded").unwrap();
    let snapshot = ServiceSnapshot::capture_workspace(
        &source,
        &fixture.0.join("private"),
        "view",
        &[protected],
        &|| false,
    )
    .unwrap();
    assert_eq!(snapshot.exclusions(), ["data/future.data"]);
    snapshot.remove().unwrap();
    for path in [
        source.clone(),
        fixture.0.clone(),
        PathBuf::from("relative"),
        source.join("../private"),
    ] {
        assert!(
            ServiceSnapshot::capture_workspace(
                &source,
                &fixture.0.join("private"),
                "view",
                &[path],
                &|| false,
            )
            .is_err()
        );
        assert!(!fixture.0.join("private/view").exists());
    }
    symlink(source.join("absent"), fixture.0.join("dangling")).unwrap();
    assert!(workspace::Filter::new(&source, &[fixture.0.join("dangling/file")]).is_err());
}

#[test]
fn workspace_captures_dirty_bytes_and_executable_status_without_repository_or_credentials() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source");
    std::fs::create_dir(source.join(".git")).unwrap();
    std::fs::write(source.join(".git/config"), b"must not be read").unwrap();
    std::fs::write(source.join(".env"), b"must not be read either").unwrap();
    std::fs::write(source.join("edited.txt"), b"current uncommitted bytes").unwrap();
    std::fs::write(
        source.join("server"),
        b"opaque fixture bytes; never executed",
    )
    .unwrap();
    std::fs::set_permissions(
        source.join("server"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Workspace).unwrap();
    assert_eq!(snapshot.exclusions(), [".env", ".git"]);
    assert_eq!(snapshot.size().0, 2);
    assert_eq!(
        std::fs::read(snapshot.path().join("edited.txt")).unwrap(),
        b"current uncommitted bytes"
    );
    assert_eq!(
        std::fs::metadata(snapshot.path().join("edited.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
    assert_eq!(
        std::fs::metadata(snapshot.path().join("server"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o500
    );
    assert!(!snapshot.path().join(".env").exists());
    assert!(!snapshot.path().join(".git").exists());
    snapshot.revalidate().unwrap();
    assert_eq!(
        &crate::service_tree_digest(snapshot.path()).unwrap(),
        snapshot.digest()
    );
    std::fs::write(source.join("edited.txt"), b"a later edit").unwrap();
    snapshot.revalidate().unwrap();
    assert_eq!(
        std::fs::read(snapshot.path().join("edited.txt")).unwrap(),
        b"current uncommitted bytes"
    );
    snapshot.remove().unwrap();
    assert!(!fixture.0.join("private/view").exists());
    assert_eq!(
        std::fs::read(source.join("edited.txt")).unwrap(),
        b"a later edit"
    );
}

#[test]
fn extensions_are_exact_and_never_silently_filter_their_admitted_inventory() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("source/server"), b"unchanged content").unwrap();
    let expected = crate::service_tree_digest(&fixture.0.join("source")).unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Extension).unwrap();
    assert!(snapshot.exclusions().is_empty());
    assert_eq!(snapshot.digest(), &expected);
    snapshot.remove().unwrap();
    std::fs::write(fixture.0.join("source/auth.json"), b"unavailable").unwrap();
    assert!(fixture.capture(ServiceSnapshotPolicy::Extension).is_err());
    assert!(!fixture.0.join("private/view").exists());
}

#[test]
fn both_policies_refuse_links_sockets_fifos_and_oversized_files_without_partial_views() {
    for policy in [
        ServiceSnapshotPolicy::Workspace,
        ServiceSnapshotPolicy::Extension,
    ] {
        for kind in ["symlink", "hardlink", "socket", "fifo", "oversized"] {
            let fixture = Fixture::new();
            let path = fixture.0.join("source/unsafe");
            let _socket = match kind {
                "symlink" => {
                    symlink("/etc/passwd", &path).unwrap();
                    None
                }
                "hardlink" => {
                    std::fs::write(fixture.0.join("original"), b"aliased bytes").unwrap();
                    std::fs::hard_link(fixture.0.join("original"), &path).unwrap();
                    None
                }
                "socket" => Some(std::os::unix::net::UnixListener::bind(&path).unwrap()),
                "fifo" => {
                    assert!(
                        std::process::Command::new("/usr/bin/mkfifo")
                            .arg(&path)
                            .status()
                            .unwrap()
                            .success()
                    );
                    None
                }
                "oversized" => {
                    std::fs::File::create(&path)
                        .unwrap()
                        .set_len(128 * 1024 * 1024 + 1)
                        .unwrap();
                    None
                }
                _ => unreachable!(),
            };
            assert!(fixture.capture(policy).is_err(), "{kind} {policy:?}");
            assert!(
                !fixture.0.join("private/view").exists(),
                "{kind} {policy:?}"
            );
        }
    }
}

#[test]
fn capture_refuses_a_late_source_edit_and_cancellation_removes_partial_files() {
    for edit_source in [false, true] {
        let fixture = Fixture::new();
        for name in ["a", "b"] {
            std::fs::write(fixture.0.join("source").join(name), b"before").unwrap();
        }
        let injected = Cell::new(false);
        let result = ServiceSnapshot::capture(
            &fixture.0.join("source"),
            &fixture.0.join("private"),
            "view",
            ServiceSnapshotPolicy::Workspace,
            &|| {
                if fixture.0.join("private/view/a").exists() && !injected.replace(true) {
                    if edit_source {
                        std::fs::write(fixture.0.join("source/a"), b"after capture").unwrap();
                    } else {
                        return true;
                    }
                }
                false
            },
        );
        assert!(injected.get());
        assert!(result.is_err());
        assert!(!fixture.0.join("private/view").exists());
    }
}

#[test]
fn source_and_destination_aliases_never_authorize_copy_or_cleanup_of_another_tree() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("source/keep"), b"original").unwrap();
    for name in ["..", "a/b", "", ".hidden"] {
        assert!(
            ServiceSnapshot::capture(
                &fixture.0.join("source"),
                &fixture.0.join("private"),
                name,
                ServiceSnapshotPolicy::Workspace,
                &|| false
            )
            .is_err()
        );
    }
    std::fs::create_dir(fixture.0.join("private/view")).unwrap();
    std::fs::write(fixture.0.join("private/view/keep"), b"preexisting").unwrap();
    assert!(fixture.capture(ServiceSnapshotPolicy::Workspace).is_err());
    assert_eq!(
        std::fs::read(fixture.0.join("private/view/keep")).unwrap(),
        b"preexisting"
    );
    std::fs::remove_dir_all(fixture.0.join("private/view")).unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Workspace).unwrap();
    std::fs::rename(snapshot.path(), fixture.0.join("private/original-view")).unwrap();
    std::fs::create_dir(snapshot.path()).unwrap();
    std::fs::write(snapshot.path().join("keep"), b"replacement").unwrap();
    assert!(snapshot.revalidate().is_err());
    assert!(snapshot.remove().is_err());
    assert_eq!(
        std::fs::read(fixture.0.join("private/view/keep")).unwrap(),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(fixture.0.join("source/keep")).unwrap(),
        b"original"
    );
}

#[test]
fn parent_permissions_and_private_copy_modification_are_checked_again_before_use() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("source/item"), b"admitted").unwrap();
    std::fs::set_permissions(
        fixture.0.join("private"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(fixture.capture(ServiceSnapshotPolicy::Workspace).is_err());
    std::fs::set_permissions(
        fixture.0.join("private"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Workspace).unwrap();
    std::fs::set_permissions(
        fixture.0.join("private"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(snapshot.revalidate().is_err());
    std::fs::set_permissions(
        fixture.0.join("private"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    snapshot.revalidate().unwrap();
    std::fs::set_permissions(
        snapshot.path().join("item"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(snapshot.path().join("item"), b"changed").unwrap();
    assert!(snapshot.revalidate().is_err());
    snapshot.remove().unwrap();
}

#[test]
fn transfer_round_trip_preserves_empty_nested_and_multichunk_files_and_executable_bits() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.0.join("source/a")).unwrap();
    std::fs::write(fixture.0.join("source/a/chunks"), vec![255_u8; 130 * 1024]).unwrap();
    std::fs::write(fixture.0.join("source/a.txt"), b"following a directory").unwrap();
    std::fs::write(fixture.0.join("source/empty"), []).unwrap();
    std::fs::set_permissions(
        fixture.0.join("source/a/chunks"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Extension).unwrap();
    let mut receiver = ServiceSnapshotReceiver::new(
        &fixture.0.join("private"),
        "received",
        snapshot.digest().clone(),
    )
    .unwrap();
    let mut finished = None;
    let mut chunks = 0;
    snapshot
        .transfer(
            &mut |frame| {
                if matches!(frame.operation, ServiceSnapshotOperation::Data { .. }) {
                    chunks += 1;
                }
                let bytes = serde_json::to_vec(frame).unwrap();
                assert!(bytes.len() < MAX_SERVICE_VIEW_FRAME_BYTES);
                let decoded = serde_json::from_slice(&bytes).unwrap();
                if let Some(view) = receiver.accept(&decoded)? {
                    finished = Some(view);
                }
                Ok(())
            },
            &|| false,
        )
        .unwrap();
    assert_eq!(chunks, 4);
    let complete = finished.unwrap();
    assert_eq!(complete.digest(), snapshot.digest());
    assert_eq!(complete.size(), snapshot.size());
    complete.revalidate().unwrap();
    assert_eq!(
        std::fs::read(complete.path().join("a/chunks")).unwrap(),
        vec![255_u8; 130 * 1024]
    );
    assert!(
        receiver
            .accept(&ServiceSnapshotFrame {
                version: 1,
                sequence: 0,
                operation: ServiceSnapshotOperation::Finish {
                    digest: snapshot.digest().clone()
                }
            })
            .is_err()
    );
    complete.remove().unwrap();
}

#[test]
fn transfer_refuses_path_escape_repetition_and_missing_parents_without_touching_other_files() {
    for path in [
        "/absolute",
        "../outside",
        "a/../b",
        ".git/config",
        "a//b",
        "missing/file",
        "a\n",
    ] {
        let fixture = Fixture::new();
        let mut receiver = ServiceSnapshotReceiver::new(
            &fixture.0.join("private"),
            "received",
            Digest::sha256(b"bound"),
        )
        .unwrap();
        let frame = ServiceSnapshotFrame {
            version: 1,
            sequence: 0,
            operation: ServiceSnapshotOperation::Directory { path: path.into() },
        };
        assert!(receiver.accept(&frame).is_err(), "{path}");
        let retry = ServiceSnapshotFrame {
            version: 1,
            sequence: 1,
            operation: ServiceSnapshotOperation::Directory {
                path: "safe".into(),
            },
        };
        assert!(receiver.accept(&retry).is_err());
        drop(receiver);
        assert!(!fixture.0.join("private/received").exists());
        assert!(!fixture.0.join("outside").exists());
    }
    let fixture = Fixture::new();
    let mut receiver = ServiceSnapshotReceiver::new(
        &fixture.0.join("private"),
        "received",
        Digest::sha256(b"bound"),
    )
    .unwrap();
    let mut frame = ServiceSnapshotFrame {
        version: 1,
        sequence: 0,
        operation: ServiceSnapshotOperation::Directory {
            path: "directory".into(),
        },
    };
    assert!(receiver.accept(&frame).unwrap().is_none());
    frame.sequence += 1;
    assert!(receiver.accept(&frame).is_err());
}

#[test]
fn transfer_refuses_incomplete_altered_reordered_or_unadmitted_views() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("source/file"), b"data").unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Extension).unwrap();
    let mut frames = Vec::new();
    snapshot
        .transfer(
            &mut |frame| {
                frames.push(frame.clone());
                Ok(())
            },
            &|| false,
        )
        .unwrap();
    assert_eq!(frames.len(), 4);
    for mutation in 0..8 {
        let mut changed = frames.clone();
        match mutation {
            0 => changed[0].version = 2,
            1 => changed[1].sequence = 0,
            2 => {
                changed[1].operation = ServiceSnapshotOperation::Data {
                    bytes: vec![0; 64 * 1024 + 1],
                }
            }
            3 => changed[1].operation = ServiceSnapshotOperation::Data { bytes: vec![0] },
            4 => {
                changed[1].operation = ServiceSnapshotOperation::Data {
                    bytes: b"evil".to_vec(),
                }
            }
            5 => {
                changed[1].operation = ServiceSnapshotOperation::Finish {
                    digest: snapshot.digest().clone(),
                }
            }
            6 => {
                changed[3].operation = ServiceSnapshotOperation::Finish {
                    digest: Digest::sha256(b"another admission"),
                }
            }
            7 => {
                changed[0].operation = ServiceSnapshotOperation::File {
                    path: "file".into(),
                    executable: false,
                    bytes: 128 * 1024 * 1024 + 1,
                    digest: Digest::sha256(b"data"),
                }
            }
            _ => unreachable!(),
        }
        let mut receiver = ServiceSnapshotReceiver::new(
            &fixture.0.join("private"),
            "received",
            snapshot.digest().clone(),
        )
        .unwrap();
        let mut refused = false;
        for frame in &changed {
            match receiver.accept(frame) {
                Ok(None) => {}
                Ok(Some(_)) => panic!("Invalid transfer {mutation} completed"),
                Err(_) => {
                    refused = true;
                    break;
                }
            }
        }
        assert!(refused, "mutation {mutation}");
        drop(receiver);
        assert!(!fixture.0.join("private/received").exists());
    }
    assert!(
        serde_json::from_value::<ServiceSnapshotFrame>(serde_json::json!({
            "version": 1, "sequence": 0, "operation": {"kind": "execute", "program": "/bin/sh"}
        }))
        .is_err()
    );
}

#[test]
fn cancelled_or_failed_transfer_never_emits_completion() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("source/file"), vec![1; 130 * 1024]).unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Extension).unwrap();
    let frames = Cell::new(0);
    assert!(
        snapshot
            .transfer(
                &mut |frame| {
                    assert!(!matches!(
                        frame.operation,
                        ServiceSnapshotOperation::Finish { .. }
                    ));
                    frames.set(frames.get() + 1);
                    Ok(())
                },
                &|| frames.get() >= 2
            )
            .is_err()
    );
    assert_eq!(frames.get(), 2);
    let mut frames = 0;
    assert!(
        snapshot
            .transfer(
                &mut |_| {
                    frames += 1;
                    Err("Uncertain write".into())
                },
                &|| false
            )
            .is_err()
    );
    assert_eq!(frames, 1);
}

fn staging_request(root: &Path, digest: &Digest) -> crate::ContainedServiceRequest {
    crate::ContainedServiceRequest {
        schema_version: crate::CONTAINED_SERVICE_CONTRACT_VERSION,
        lease_id: "app-issued-lease".into(),
        scope: crate::ServiceScope {
            project_id: "owned-project".into(),
            operation_id: "owned-run".into(),
            workspace_digest: digest.clone(),
            extension_digest: digest.clone(),
            containment_digest: Digest::sha256(b"guest"),
        },
        purpose: crate::ServicePurpose::Mcp,
        executable: root.join("extension/server").to_str().unwrap().into(),
        content_root: root.join("extension").to_str().unwrap().into(),
        executable_digest: Digest::sha256(b"image"),
        executable_bytes: 64,
        architecture: crate::ServiceArchitecture::LinuxAarch64,
        arguments: Vec::new(),
        environment: crate::service_environment(),
        workspace: root.join("workspace").to_str().unwrap().into(),
        limits: crate::ServiceLimits::default(),
    }
}

#[test]
fn service_staging_requires_two_complete_views_and_carries_the_next_control_identity() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("source/file"), b"captured bytes").unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Extension).unwrap();
    let root = fixture.0.join("private/stage");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let request = staging_request(&root, snapshot.digest());
    let mut stage = crate::ServiceStagingReceiver::new(&root, &request).unwrap();
    let mut sequence = 1;
    for view in [crate::ServiceView::Workspace, crate::ServiceView::Extension] {
        snapshot
            .transfer(
                &mut |frame| {
                    let complete = stage
                        .accept(&crate::ServiceControl {
                            version: 1,
                            lease_id: request.lease_id.clone(),
                            sequence,
                            operation: crate::ServiceOperation::Snapshot {
                                view,
                                frame: frame.clone(),
                            },
                        })
                        .unwrap();
                    assert_eq!(
                        complete,
                        view == crate::ServiceView::Extension
                            && matches!(frame.operation, ServiceSnapshotOperation::Finish { .. })
                    );
                    sequence += 1;
                    Ok(())
                },
                &|| false,
            )
            .unwrap();
    }
    let (views, next) = stage.finish().unwrap();
    assert_eq!(next, sequence);
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].path(), root.join("workspace"));
    assert_eq!(views[1].path(), root.join("extension"));
    for view in &views {
        assert_eq!(view.digest(), snapshot.digest());
        view.revalidate().unwrap();
    }
    drop(views);
    assert!(!root.join("workspace").exists());
    assert!(!root.join("extension").exists());
}

#[test]
fn service_staging_refuses_foreign_or_duplicate_controls_premature_input_and_swapped_views() {
    for mutation in 0..9 {
        let fixture = Fixture::new();
        let root = fixture.0.join("private");
        let digest = crate::service_tree_digest(&fixture.0.join("source")).unwrap();
        let request = staging_request(&root, &digest);
        let valid = crate::ServiceControl {
            version: 1,
            lease_id: request.lease_id.clone(),
            sequence: 1,
            operation: crate::ServiceOperation::Snapshot {
                view: crate::ServiceView::Workspace,
                frame: ServiceSnapshotFrame {
                    version: 1,
                    sequence: 0,
                    operation: ServiceSnapshotOperation::Finish { digest },
                },
            },
        };
        let mut altered = valid.clone();
        match mutation {
            0 => altered.lease_id = "foreign-lease".into(),
            1 => altered.version = 2,
            2 => altered.sequence = 0,
            3 => {
                altered.operation = crate::ServiceOperation::Input {
                    bytes: b"premature call".to_vec(),
                }
            }
            4 => altered.operation = crate::ServiceOperation::Ready,
            5 => {
                altered.operation = crate::ServiceOperation::Start {
                    request: Box::new(request.clone()),
                }
            }
            6 => {
                if let crate::ServiceOperation::Snapshot { view, .. } = &mut altered.operation {
                    *view = crate::ServiceView::Extension;
                }
            }
            7 => altered.operation = crate::ServiceOperation::Cancel,
            8 => {}
            _ => unreachable!(),
        }
        let mut stage = crate::ServiceStagingReceiver::new(&root, &request).unwrap();
        if mutation == 8 {
            assert!(!stage.accept(&valid).unwrap());
        }
        let outcome = stage.accept(&altered);
        assert!(outcome.is_err(), "{mutation}");
        assert_eq!(
            outcome == Err(crate::ServiceStagingError::Cancelled),
            mutation == 7
        );
        assert!(stage.accept(&valid).is_err());
        assert!(stage.finish().is_err());
        assert!(!root.join("workspace").exists());
        assert!(!root.join("extension").exists());
    }
}

#[test]
fn service_staging_cannot_finish_after_only_one_view_or_a_changed_destination_root() {
    let fixture = Fixture::new();
    let root = fixture.0.join("private");
    let digest = crate::service_tree_digest(&fixture.0.join("source")).unwrap();
    let mut request = staging_request(&root, &digest);
    request.workspace = "/another/project/workspace".into();
    assert!(crate::ServiceStagingReceiver::new(&root, &request).is_err());
    request.workspace = root.join("workspace").to_str().unwrap().into();
    let mut stage = crate::ServiceStagingReceiver::new(&root, &request).unwrap();
    assert!(
        !stage
            .accept(&crate::ServiceControl {
                version: 1,
                lease_id: request.lease_id.clone(),
                sequence: 1,
                operation: crate::ServiceOperation::Snapshot {
                    view: crate::ServiceView::Workspace,
                    frame: ServiceSnapshotFrame {
                        version: 1,
                        sequence: 0,
                        operation: ServiceSnapshotOperation::Finish { digest }
                    }
                }
            })
            .unwrap()
    );
    assert!(stage.finish().is_err());
    assert!(!root.join("workspace").exists());
}

#[test]
fn native_image_verification_binds_guest_architecture_executable_status_bytes_and_digest() {
    let fixture = Fixture::new();
    let mut header = [0_u8; 64];
    header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    header[16] = 2;
    header[18..20].copy_from_slice(&183_u16.to_le_bytes());
    std::fs::write(fixture.0.join("source/server"), header).unwrap();
    let digest = Digest::sha256(&header);
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Extension).unwrap();
    assert!(
        snapshot
            .verify_image(
                Path::new("server"),
                64,
                &digest,
                crate::ServiceArchitecture::LinuxAarch64
            )
            .is_err()
    );
    snapshot.remove().unwrap();
    std::fs::set_permissions(
        fixture.0.join("source/server"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let snapshot = fixture.capture(ServiceSnapshotPolicy::Extension).unwrap();
    snapshot
        .verify_image(
            Path::new("server"),
            64,
            &digest,
            crate::ServiceArchitecture::LinuxAarch64,
        )
        .unwrap();
    for (path, length, expected, architecture) in [
        (
            "server",
            64,
            digest.clone(),
            crate::ServiceArchitecture::LinuxX86_64,
        ),
        (
            "server",
            65,
            digest.clone(),
            crate::ServiceArchitecture::LinuxAarch64,
        ),
        (
            "server",
            64,
            Digest::sha256(b"changed"),
            crate::ServiceArchitecture::LinuxAarch64,
        ),
        (
            "../server",
            64,
            digest.clone(),
            crate::ServiceArchitecture::LinuxAarch64,
        ),
        (
            "/server",
            64,
            digest,
            crate::ServiceArchitecture::LinuxAarch64,
        ),
    ] {
        assert!(
            snapshot
                .verify_image(Path::new(path), length, &expected, architecture)
                .is_err()
        );
    }
}
