use std::ffi::OsString;

use super::ChildEnvironmentProfile;

fn keys(profile: ChildEnvironmentProfile) -> Vec<OsString> {
    profile.allowed_keys()
}

#[test]
fn child_profiles_expose_only_their_exact_allowlisted_environment_keys() {
    assert_eq!(
        keys(ChildEnvironmentProfile::Browser),
        ["PATH"].map(OsString::from)
    );
    assert!(keys(ChildEnvironmentProfile::Diagnostics).is_empty());
    assert_eq!(
        keys(ChildEnvironmentProfile::Git),
        [
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_EDITOR",
            "GIT_LITERAL_PATHSPECS",
            "GIT_OPTIONAL_LOCKS",
            "GIT_PAGER",
            "GIT_TERMINAL_PROMPT",
            "LC_ALL",
            "PATH",
        ]
        .map(OsString::from)
    );
    assert_eq!(
        keys(ChildEnvironmentProfile::Pty),
        [
            "COLORTERM",
            "GROK_BUILD_PTY_READY",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LOGNAME",
            "PATH",
            "SHELL",
            "TERM",
            "USER",
        ]
        .map(OsString::from)
    );
    for profile in [ChildEnvironmentProfile::Acp, ChildEnvironmentProfile::OAuth] {
        let allowed = keys(profile);
        assert!(allowed.contains(&OsString::from("GROK_HOME")));
        for forbidden in ["XAI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
            assert!(!allowed.contains(&OsString::from(forbidden)));
        }
    }
}
