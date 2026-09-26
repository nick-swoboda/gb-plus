// Workspace isolation and permit-authority boundaries.
// Upstream sandbox and permission-classifier paths cannot bypass
// `validate_preflight` to authorize execution.

fn workspace_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = crate_dir
        .join("../..")
        .canonicalize()
        .expect("canonicalize workspace root from grok-build-runner manifest");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read workspace Cargo.toml");
    assert!(
        manifest.contains("grok-build-runner") && manifest.contains("[workspace]"),
        "CARGO_MANIFEST_DIR/../.. must be the grok-build-* workspace root"
    );
    root
}

fn lockfile_package_names(lockfile: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_package = false;
    let mut seen_name_in_package = false;
    for line in lockfile.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            in_package = true;
            seen_name_in_package = false;
            continue;
        }
        if trimmed.starts_with('[') {
            in_package = false;
            continue;
        }
        if !in_package || seen_name_in_package {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("name = \"") else {
            continue;
        };
        let Some(name) = rest.strip_suffix('"') else {
            continue;
        };
        names.push(name.to_owned());
        seen_name_in_package = true;
    }
    names
}

fn is_xai_lock_package(name: &str) -> bool {
    name == "xai" || name.starts_with("xai-") || name.starts_with("xai_")
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

fn identifier_prefix_present(source: &str, prefix: &str) -> bool {
    for (cursor, _) in source.char_indices() {
        if source[cursor..].starts_with(prefix) && !preceding_is_ident(source, cursor) {
            return true;
        }
    }
    false
}

fn shipped_rust_sources(workspace: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![workspace.join("crates")];
    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir).unwrap_or_else(|error| {
            panic!("read {} for shipped-source fence: {error}", dir.display())
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

fn permit_refusal_names_exact_set_mismatch(error: &SupervisorError) -> bool {
    let text = error.to_string();
    text.contains("containment preflight controls differ from the exact policy")
}

/// The workspace lockfile is the Option B crate-graph fence. A later A-fork
/// would delete this test; absorbing `xai-*` without that authorization
/// must fail the suite.
#[test]
fn workspace_lockfile_contains_no_xai_crates() {
    assert!(
        is_xai_lock_package("xai-grok-sandbox"),
        "the detector must treat the 1.05 sandbox crate name as forbidden"
    );
    assert!(is_xai_lock_package("xai_grok_workspace"));
    assert!(is_xai_lock_package("xai"));
    assert!(!is_xai_lock_package("serde"));
    assert!(!is_xai_lock_package("cap-std"));
    assert!(
        !is_xai_lock_package("ambient-authority"),
        "unrelated lock packages must not match the xai-* prefix"
    );

    let root = workspace_root();
    let lock_path = root.join("Cargo.lock");
    let lockfile = fs::read_to_string(&lock_path)
        .unwrap_or_else(|error| panic!("read workspace lockfile {}: {error}", lock_path.display()));
    let names = lockfile_package_names(&lockfile);
    assert!(
        names.iter().any(|name| name == "grok-build-runner")
            && names.iter().any(|name| name == "grok-build-core"),
        "parsed {} package names from {} but missing this workspace's crates",
        names.len(),
        lock_path.display()
    );

    let forbidden: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| is_xai_lock_package(name))
        .collect();
    assert!(
        forbidden.is_empty(),
        "workspace Cargo.lock must not contain xai-* packages; found {forbidden:?}"
    );
}

/// `SandboxManager::apply` (1.05) is "the profile is on." That is
/// `FilesystemPolicy` at most. It cannot mint a permit, and `launch` is
/// not reached.
#[test]
fn sandbox_apply_report_cannot_mint_a_validated_backend_permit() {
    let limits = ResourceLimits {
        wall_time_ms: 1_000,
        max_output_bytes: 1024,
        max_processes: 1,
        max_memory_bytes: None,
    };
    let (_workspace, _private, paths, grant, policy, command) =
        contained_fixture("slice21-sandbox-apply", limits);
    let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
    let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
    let expected_backend = backend.identity().expect("fake backend identity");
    let sandbox_only = BTreeSet::from([BackendControl::FilesystemPolicy]);
    let report = BackendPreflightReport::new(
        prepared.launch_digest().clone(),
        expected_backend.clone(),
        sandbox_only.clone(),
        vec![0, 1, 2],
        BackendCanaryStatus::Passed(hash_bytes(b"sandbox-apply analogue canaries")),
    );
    let mint_error = contained_boundary::validate_preflight(&prepared, &expected_backend, report)
        .expect_err("a sandbox-apply control set must not mint ValidatedBackendPermit");
    assert!(
        permit_refusal_names_exact_set_mismatch(&mint_error),
        "sandbox-apply refusal must be the exact-set permit gate, not another path: {mint_error}"
    );

    backend.controls = sandbox_only;
    let outcome =
        contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
    match outcome {
        ContainedExecutionOutcome::RefusedBeforeLaunch(error) => {
            assert!(
                permit_refusal_names_exact_set_mismatch(&error),
                "execute_classified must refuse at validate_preflight: {error}"
            );
        }
        other => {
            panic!("sandbox-apply analogue must stay RefusedBeforeLaunch, observed: {other:?}")
        }
    }
    assert_eq!(
        state.launch_count.load(Ordering::Acquire),
        0,
        "SandboxManager-shaped preflight must never reach launch"
    );
}

/// A permission-classifier "allow" is an empty (or otherwise non-exact)
/// control set. It cannot mint, and `launch` is not reached.
#[test]
fn permission_classifier_allow_cannot_mint_a_validated_backend_permit() {
    let limits = ResourceLimits {
        wall_time_ms: 1_000,
        max_output_bytes: 1024,
        max_processes: 1,
        max_memory_bytes: None,
    };
    let (_workspace, _private, paths, grant, policy, command) =
        contained_fixture("slice21-permission-allow", limits);
    let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
    let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
    let expected_backend = backend.identity().expect("fake backend identity");
    let allow_without_controls = BTreeSet::new();
    let report = BackendPreflightReport::new(
        prepared.launch_digest().clone(),
        expected_backend.clone(),
        allow_without_controls.clone(),
        vec![0, 1, 2],
        BackendCanaryStatus::Passed(hash_bytes(b"permission-classifier analogue canaries")),
    );
    let mint_error = contained_boundary::validate_preflight(&prepared, &expected_backend, report)
        .expect_err("a permission-classifier allow must not mint ValidatedBackendPermit");
    assert!(
        permit_refusal_names_exact_set_mismatch(&mint_error),
        "permission-allow refusal must be the exact-set permit gate: {mint_error}"
    );

    backend.controls = allow_without_controls;
    let outcome =
        contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
    match outcome {
        ContainedExecutionOutcome::RefusedBeforeLaunch(error) => {
            assert!(
                permit_refusal_names_exact_set_mismatch(&error),
                "execute_classified must refuse at validate_preflight: {error}"
            );
        }
        other => panic!(
            "permission-classifier analogue must stay RefusedBeforeLaunch, observed: {other:?}"
        ),
    }
    assert_eq!(
        state.launch_count.load(Ordering::Acquire),
        0,
        "PermissionClassifier-shaped preflight must never reach launch"
    );
}

/// `ValidatedBackendPermit { ... }` exists once, inside `validate_preflight`.
/// A second mint (Default, From, or a 1.05 apply path) fails this test.
#[test]
fn validated_backend_permit_is_constructed_only_by_validate_preflight() {
    let root = workspace_root();
    let sources = shipped_rust_sources(&root);
    assert!(
        sources
            .iter()
            .any(|path| path.ends_with("command/contained_boundary.rs")),
        "must scan the shipped permit module"
    );

    let mut constructions = Vec::new();
    let mut validate_preflight_files = 0;
    for path in &sources {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        if text.contains("pub(crate) fn validate_preflight(") {
            validate_preflight_files += 1;
        }
        for (index, line) in text.lines().enumerate() {
            if !line.contains("ValidatedBackendPermit {") {
                continue;
            }
            if line.contains("struct ValidatedBackendPermit")
                || line.contains("impl ValidatedBackendPermit")
            {
                continue;
            }
            constructions.push((path.clone(), index + 1, line.trim().to_owned()));
        }
    }

    assert_eq!(
        validate_preflight_files, 1,
        "exactly one shipped validate_preflight definition"
    );
    assert_eq!(
        constructions.len(),
        1,
        "ValidatedBackendPermit must have exactly one value constructor; found {constructions:?}"
    );
    let (path, line, snippet) = &constructions[0];
    assert!(
        path.ends_with("command/contained_boundary.rs"),
        "sole permit constructor must stay in contained_boundary, not {}:{}",
        path.display(),
        line
    );
    let permit_module = fs::read_to_string(path).expect("re-read permit module");
    let fn_at = permit_module
        .find("pub(crate) fn validate_preflight(")
        .expect("validate_preflight in the constructor's file");
    let ctor_at = permit_module
        .find("Ok(ValidatedBackendPermit {")
        .expect("constructor expression");
    assert!(
        ctor_at > fn_at,
        "sole constructor at {}:{} ({snippet}) is not inside validate_preflight",
        path.display(),
        line
    );
    assert!(
        !identifier_present(&permit_module, "Default")
            || !permit_module.contains("impl Default for ValidatedBackendPermit"),
        "ValidatedBackendPermit must not grow a Default mint"
    );
}

/// Shipped sources (not this test module) must not name 1.05's sandbox or
/// permission-LLM apply APIs. Those names appearing is how an alternate
/// mint would be wired.
#[test]
fn shipped_sources_do_not_name_upstream_sandbox_or_permission_authority() {
    let root = workspace_root();
    let mut hits = Vec::new();
    for path in shipped_rust_sources(&root) {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for ident in ["SandboxManager", "PermissionClassifier"] {
            if identifier_present(&text, ident) {
                hits.push(format!("{}:{ident}", path.display()));
            }
        }
        if identifier_prefix_present(&text, "xai_grok_") {
            hits.push(format!("{}:xai_grok_*", path.display()));
        }
    }
    assert!(
        hits.is_empty(),
        "shipped sources named a 1.05 sandbox/permission apply path: {hits:?}"
    );
}
