use super::*;

#[test]
fn probe_filter_removes_split_private_material() {
    let token = ProbeToken::fixture(b"split-private-token");
    let mut filter = ProbeFilter::new(&token);
    let mut visible = filter.push(b"before split-pri", false);
    visible.extend(filter.push(
        b"vate-token and GROK_BUILD_PTY_READY and GBPTY: after",
        true,
    ));
    assert_eq!(visible, b"before  and  and  after");
}

#[test]
fn command_environment_is_cleared_then_allowlisted() {
    let target = PtyTarget {
        key: PtySessionKey {
            project_id: ProjectId::new("project"),
            workspace_id: WorkspaceId::new("workspace"),
        },
        cwd: PathBuf::from("/private/tmp"),
    };
    let shell = ShellSpec {
        path: PathBuf::from("/bin/zsh"),
        family: ShellFamily::Posix,
        args: vec!["-l".to_owned()],
    };
    let token = ProbeToken::fixture(b"environment-fixture-token");
    let command = build_command(&target, &shell, &token);
    let keys = command
        .iter_full_env_as_str()
        .map(|(key, _)| key.to_owned())
        .collect::<Vec<_>>();
    for key in &keys {
        assert!(
            matches!(
                key.as_str(),
                "HOME"
                    | "PATH"
                    | "USER"
                    | "LOGNAME"
                    | "LANG"
                    | "LC_ALL"
                    | "LC_CTYPE"
                    | "SHELL"
                    | "TERM"
                    | "COLORTERM"
                    | READY_ENV
            ),
            "unexpected inherited child environment key {key}"
        );
    }
    for forbidden in [
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
    ] {
        assert!(!keys.iter().any(|key| key == forbidden));
    }
}

#[test]
fn spawn_ok_without_readiness_is_refused_and_positive_shell_is_live() {
    let root = std::env::temp_dir().join(format!(
        "grok-build-pty-integrity-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create PTY test root");
    let proof = smoke_pty_integrity(&root).expect("run PTY integrity controls");
    assert!(proof.control_executed_without_readiness);
    assert!(proof.enforced_refused);
    assert!(proof.private_probe_absent);
    assert!(proof.positive_live);
    assert!(proof.resize_roundtrip);
    assert!(proof.io_usable);
    std::fs::remove_dir_all(root).expect("remove PTY test root");
}
