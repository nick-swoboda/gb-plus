use super::*;

#[test]
fn admitted_container_runtime_has_fixed_https_identity() {
    for spec in [COLIMA_ASSET, LIMA_ASSET] {
        assert!(spec.url.starts_with("https://github.com/"));
        assert!(!spec.url.contains("latest"));
        assert_eq!(spec.sha256.len(), 64);
    }
    assert_eq!(COLIMA_VERSION, "0.10.3");
    assert_eq!(LIMA_VERSION, "2.2.0");
    assert_eq!(LIMA_FILES, 137);
    assert_eq!(LIMA_DIRECTORIES, 10);
    assert_eq!(LIMA_FILE_BYTES, 80_765_607);
}

#[test]
fn archive_paths_fail_closed() {
    for unsafe_path in [
        "../escape",
        "./bin/../../escape",
        "/absolute",
        ".\\bin\\tool",
        "./bin/tool\nnext",
        "",
    ] {
        assert!(unsafe_archive_path(unsafe_path), "accepted {unsafe_path:?}");
    }
    for safe_path in [
        "./",
        "./bin/",
        "./bin/limactl",
        "./share/lima/template.yaml",
    ] {
        assert!(!unsafe_archive_path(safe_path), "refused {safe_path:?}");
    }
}

#[test]
fn manager_paths_stay_below_the_explicit_state_root() {
    let root = std::env::temp_dir().join(format!(
        "gb-plus-container-runtime-test-{}",
        std::process::id()
    ));
    let manager = ContainerRuntimeManager::new(&root);
    assert_eq!(
        manager.final_root(),
        root.join(PLUS_MANAGED_CONTAINER_RUNTIME_RELATIVE)
    );
    assert!(manager.archives.root().starts_with(&root));
    assert!(!manager.final_root().exists());
}

#[test]
fn missing_managed_runtime_does_not_create_a_profile() {
    let root = std::env::temp_dir().join(format!(
        "gb-plus-container-profile-test-{}",
        std::process::id()
    ));
    let manager = ContainerRuntimeManager::new(&root);
    manager
        .prepare_profile()
        .expect("missing runtime is a no-op");
    assert!(!root.exists());
}

#[test]
fn installer_uses_only_the_fixed_guest_privilege_boundary() {
    let source = include_str!("../container_runtime.rs");
    for forbidden in ["brew install", "port install", "nix-env", "/usr/local"] {
        assert!(!source.contains(forbidden), "found forbidden {forbidden}");
    }
    assert!(source.contains("/usr/bin/tar"));
    assert!(source.contains("env_clear()"));
    assert!(source.contains(".args([\"ssh\", \"--\", \"sudo\", \"-n\", \"sh\", \"-s\", \"--\"])"));
}

#[test]
fn post_colima_service_setup_requires_verified_payload_and_live_contained_probe() {
    let source = include_str!("../container_runtime.rs");
    let installer = include_str!("../../../../scripts/gb-plus-linux-command-security-install.sh");
    assert!(ServicePayloadSpec::compiled().is_err());
    assert!(source.contains("open_service_payload(&spec)"));
    assert!(source.contains("probe.class != CommandOutcomeClass::Completed"));
    assert!(installer.contains("sha256sum \"$stage/payload.tar.gz\""));
    assert!(installer.contains("test \"$runner_uid\" -ne 0"));
    assert!(installer.contains("--grok-build-open-linux-native-service"));
    assert!(installer.contains("GROK_BUILD_PLUS_PREBUILT_PROBE=\"$9\""));
    assert!(
        include_str!("../../../../scripts/plus-macos-release.sh")
            .contains("verify_bwrap_source \"$extracted_app/Contents/Resources/BubblewrapSource\"")
    );
    let probe = installer
        .find("probe_output=$(sh -c")
        .expect("installer must run contained probe");
    let publish = installer
        .find("mv -f -- \"$current_tmp\" \"$phase_root/current\"")
        .expect("installer must publish current selector");
    assert!(
        probe < publish,
        "contained probe must precede selector publish"
    );
    for forbidden in ["apt install", "apt-get", "brew install", "curl |", "wget |"] {
        assert!(!installer.contains(forbidden), "found {forbidden}");
    }
    assert!(
        std::process::Command::new("/bin/sh")
            .args([
                "-n",
                "../../scripts/gb-plus-linux-command-security-install.sh"
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("run shell syntax check")
            .success()
    );
}

#[test]
fn stdio_installation_keeps_checks_and_active_generations_separate() {
    let installer = include_str!("../../../../scripts/gb-plus-linux-command-security-install.sh");
    for required in [
        "stdio_install_root=$release_root/stdio-install",
        "stdio_state_root=/var/lib/grok-build/phase1/releases/$helper_sha/stdio-state",
        "stdio_cgroup_parent=$stdio_releases/$helper_sha",
        "printf '1073741824\\n' > \"$stdio_releases/memory.max\"",
        "printf '0\\n' > \"$stdio_releases/memory.swap.max\"",
        "printf '128\\n' > \"$stdio_releases/pids.max\"",
        "test \"$(cat \"$stdio_releases/memory.max\")\" = 1073741824",
        "test \"$(cat \"$stdio_releases/memory.swap.max\")\" = 0",
        "test \"$(cat \"$stdio_releases/pids.max\")\" = 128",
        "\"$stdio_install_root\" \"$stdio_state_root\" \"$stdio_cgroup_parent\" stdio",
        "if test ! -d \"$private_root\"; then",
        "install -d -o root -g root -m 0700 \"$private_root\"",
    ] {
        assert!(installer.contains(required), "missing {required}");
    }
    let last_readback = installer
        .rfind("\"$binary_root/grok-build-runner\" \"$stdio_install_root\"")
        .expect("stdio anchor must be authenticated by the unprivileged helper");
    let contained_probe = installer.find("probe_output=$(sh -c").unwrap();
    let publish = installer
        .find("mv -f -- \"$current_tmp\" \"$phase_root/current\"")
        .unwrap();
    assert!(last_readback < contained_probe && contained_probe < publish);
    for forbidden in [
        "apparmor_parser",
        "apparmor_restrict_unprivileged_userns",
        "sysctl",
        "rm -rf -- \"$state_root\"",
        "rm -rf -- \"$stdio_state_root\"",
    ] {
        assert!(!installer.contains(forbidden), "found {forbidden}");
    }
    assert!(!installer.contains("-m 0755 \"$state_root\""));
}

#[test]
#[ignore = "requires the separately downloaded immutable admission fixtures"]
fn exact_admission_fixture_extracts_to_the_enforced_manifest() {
    let fixture = PathBuf::from(
        std::env::var_os("GROK_BUILD_CONTAINER_ADMISSION_FIXTURE")
            .expect("set GROK_BUILD_CONTAINER_ADMISSION_FIXTURE"),
    );
    let temporary = std::env::temp_dir().join(format!(
        ".container-runtime-test-{}-{}",
        std::process::id(),
        nonce()
    ));
    ensure_private_directory(&temporary).expect("create private fixture output");
    let colima = temporary.join(PLUS_MANAGED_COLIMA_RELATIVE);
    fs::copy(fixture.join("colima-Darwin-arm64"), &colima).expect("copy Colima fixture");
    fs::set_permissions(&colima, fs::Permissions::from_mode(0o700))
        .expect("make Colima executable");
    let archive = fixture.join("lima-2.2.0-Darwin-arm64.tar.gz");
    validate_lima_archive(File::open(&archive).expect("open Lima fixture"))
        .expect("validate exact archive inventory");
    extract_lima(
        File::open(&archive).expect("reopen Lima fixture"),
        &temporary.join("lima"),
    )
    .expect("extract admitted Lima subset");
    secure_tree(&temporary).expect("secure extracted runtime");
    validate_runtime(&temporary).expect("verify complete admitted runtime");
    remove_temporary(&std::env::temp_dir(), &temporary).expect("remove fixture output");
}
