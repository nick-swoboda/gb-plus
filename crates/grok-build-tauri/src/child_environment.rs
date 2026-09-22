//! Exact, non-composable child-process environment policies.

use std::ffi::OsStr;
#[cfg(test)]
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use portable_pty::CommandBuilder;

pub(crate) const PTY_READY_ENV: &str = "GROK_BUILD_PTY_READY";
const ACP_INHERITED: &[&str] = &[
    "HOME",
    "PATH",
    "SHELL",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "GROK_HOME",
];
const OAUTH_INHERITED: &[&str] = &[
    "HOME",
    "PATH",
    "SHELL",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "GROK_HOME",
];
const PTY_INHERITED: &[&str] = &[
    "HOME", "PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
];
const ACP_FIXED: &[(&str, &str)] = &[
    ("GROK_AGENT", "grok-build-plus-gui"),
    ("GROK_DISABLE_AUTOUPDATER", "1"),
    ("GROK_SUBAGENTS", "0"),
    ("GROK_MEMORY", "0"),
    ("GROK_WEB_FETCH", "0"),
    ("GROK_WORKFLOWS", "0"),
    ("GROK_GOAL", "0"),
    ("GROK_AUTO_WAKE", "0"),
    ("GROK_SESSION_RECAP", "0"),
    ("GROK_TURN_SUMMARY", "0"),
    ("GROK_GOAL_SUMMARY", "0"),
    ("GROK_TITLE_REFRESH", "0"),
    ("GROK_IMAGE_GEN", "0"),
    ("GROK_IMAGE_EDIT", "0"),
    ("GROK_VIDEO_GEN", "0"),
    ("GROK_TELEMETRY_ENABLED", "0"),
    ("GROK_TELEMETRY_TRACE_UPLOAD", "0"),
    ("GROK_TELEMETRY_MIXPANEL_ENABLED", "0"),
    ("GROK_EXTERNAL_OTEL", "0"),
    ("GROK_OFFICIAL_MARKETPLACE_AUTO_REGISTER", "0"),
    ("GROK_MCP_RECURSIVE_CONFIG_WATCH", "0"),
    ("GROK_STORAGE_MODE", "local"),
    ("GROK_CLAUDE_SKILLS_ENABLED", "0"),
    ("GROK_CLAUDE_RULES_ENABLED", "0"),
    ("GROK_CLAUDE_AGENTS_ENABLED", "0"),
    ("GROK_CLAUDE_MCPS_ENABLED", "0"),
    ("GROK_CLAUDE_HOOKS_ENABLED", "0"),
    ("GROK_CLAUDE_SESSIONS_ENABLED", "0"),
    ("GROK_CURSOR_SKILLS_ENABLED", "0"),
    ("GROK_CURSOR_RULES_ENABLED", "0"),
    ("GROK_CURSOR_AGENTS_ENABLED", "0"),
    ("GROK_CURSOR_MCPS_ENABLED", "0"),
    ("GROK_CURSOR_HOOKS_ENABLED", "0"),
    ("GROK_CURSOR_SESSIONS_ENABLED", "0"),
    ("GROK_CODEX_SESSIONS_ENABLED", "0"),
    ("RUST_LOG", "off"),
];
const OAUTH_FIXED: &[(&str, &str)] = &[
    ("GROK_DISABLE_AUTOUPDATER", "1"),
    ("GROK_SUBAGENTS", "0"),
    ("GROK_MEMORY", "0"),
    ("GROK_WEB_FETCH", "0"),
    ("RUST_LOG", "off"),
];
const BROWSER_FIXED: &[(&str, &str)] = &[("PATH", "/usr/bin:/bin")];
const GIT_FIXED: &[(&str, &str)] = &[
    ("PATH", "/usr/bin:/bin"),
    ("LC_ALL", "C"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_LITERAL_PATHSPECS", "1"),
    ("GIT_PAGER", "cat"),
    ("GIT_EDITOR", "false"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildEnvironmentProfile {
    Acp,
    OAuth,
    Pty,
    Browser,
    Diagnostics,
    Git,
}

impl ChildEnvironmentProfile {
    pub(crate) fn apply(self, command: &mut Command) {
        command.env_clear();
        for name in self.inherited_names() {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.envs(self.fixed_values().iter().copied());
    }

    pub(crate) fn apply_pty(self, command: &mut CommandBuilder, shell: &Path, readiness: &OsStr) {
        debug_assert_eq!(self, Self::Pty);
        command.env_clear();
        for name in self.inherited_names() {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.env("SHELL", shell);
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        command.env(PTY_READY_ENV, readiness);
    }

    fn inherited_names(self) -> &'static [&'static str] {
        match self {
            Self::Acp => ACP_INHERITED,
            Self::OAuth => OAUTH_INHERITED,
            Self::Pty => PTY_INHERITED,
            Self::Browser | Self::Diagnostics | Self::Git => &[],
        }
    }

    fn fixed_values(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Acp => ACP_FIXED,
            Self::OAuth => OAUTH_FIXED,
            Self::Pty | Self::Diagnostics => &[],
            Self::Browser => BROWSER_FIXED,
            Self::Git => GIT_FIXED,
        }
    }

    #[cfg(test)]
    fn allowed_keys(self) -> Vec<OsString> {
        let mut keys: Vec<_> = self.inherited_names().iter().map(OsString::from).collect();
        keys.extend(
            self.fixed_values()
                .iter()
                .map(|(name, _)| OsString::from(name)),
        );
        if self == Self::Pty {
            keys.extend(["SHELL", "TERM", "COLORTERM", PTY_READY_ENV].map(OsString::from));
        }
        keys.sort();
        keys.dedup();
        keys
    }
}

#[cfg(test)]
#[path = "child_environment/tests.rs"]
mod tests;
