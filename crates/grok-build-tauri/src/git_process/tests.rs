use std::path::Path;

use super::git_command;

#[test]
fn fixed_git_boundary_disables_repository_fsmonitor_commands() {
    let command = git_command(Path::new("/tmp/grok-build-git-boundary-fixture"));
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(
        args.windows(2)
            .any(|pair| pair == ["-c", "core.fsmonitor=false"]),
        "every fixed Git invocation must override repository-local core.fsmonitor"
    );
}
