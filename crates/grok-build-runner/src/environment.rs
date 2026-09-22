//! Construction of intentionally small command environments.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::process::Command;

const SECRET_EXACT: &[&str] = &[
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "DOCKER_AUTH_CONFIG",
    "KUBECONFIG",
    "NETRC",
];
const SECRET_PREFIXES: &[&str] = &[
    "ANTHROPIC_",
    "AWS_",
    "AZURE_",
    "CLOUDFLARE_",
    "DIGITALOCEAN_",
    "GITHUB_",
    "GITLAB_",
    "GOOGLE_",
    "NPM_",
    "OPENAI_",
    "XAI_",
];
const SECRET_SUFFIXES: &[&str] = &[
    "_API_KEY",
    "_ACCESS_KEY",
    "_AUTH",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_PASSWORD",
    "_PRIVATE_KEY",
    "_SECRET",
    "_TOKEN",
];

/// A policy describing which non-sensitive variables may be inherited by a command.
///
/// Inheritance is opt-in. Secret-like variables, dynamic-loader controls, host home
/// paths, and host IPC endpoints are removed even if their names appear in the
/// allowlist. Synthetic values such as a private `HOME` can be added afterward with
/// [`ScrubbedEnvironment::set_trusted_override`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentPolicy {
    allowed_inherited: BTreeSet<OsString>,
}

impl EnvironmentPolicy {
    /// Creates an environment policy with no inherited variables.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates an environment policy from an explicit inherited-variable allowlist.
    #[must_use]
    pub fn allowing<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            allowed_inherited: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Scrubs a source environment according to this policy.
    ///
    /// The returned environment is suitable for application to a
    /// [`std::process::Command`] with an environment clear. Removal records contain
    /// names only; values are never retained in diagnostics.
    #[must_use]
    pub fn scrub<I, K, V>(&self, source: I) -> ScrubbedEnvironment
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        let mut variables = BTreeMap::new();
        let mut removed = BTreeSet::new();

        for (name, value) in source {
            let name = name.into();
            let value = value.into();
            if self.allowed_inherited.contains(&name)
                && is_valid_name(&name)
                && is_valid_value(&value)
                && !is_forbidden_inherited_name(&name)
            {
                variables.insert(name, value);
            } else {
                removed.insert(name);
            }
        }

        ScrubbedEnvironment { variables, removed }
    }

    /// Scrubs the current process environment.
    #[must_use]
    pub fn scrub_current(&self) -> ScrubbedEnvironment {
        self.scrub(std::env::vars_os())
    }
}

/// A command environment after allowlisting and secret removal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScrubbedEnvironment {
    variables: BTreeMap<OsString, OsString>,
    removed: BTreeSet<OsString>,
}

impl ScrubbedEnvironment {
    /// Returns the variables that will be supplied to the command.
    #[must_use]
    pub fn variables(&self) -> &BTreeMap<OsString, OsString> {
        &self.variables
    }

    /// Returns removed variable names. Removed values are never retained.
    #[must_use]
    pub fn removed_names(&self) -> &BTreeSet<OsString> {
        &self.removed
    }

    /// Adds an explicitly constructed value such as a private `HOME` or controlled
    /// `PATH`.
    ///
    /// Secret-looking names and dynamic-loader controls remain forbidden. This
    /// method is intentionally separate from host inheritance so callers must make
    /// synthetic environment construction explicit.
    ///
    /// # Errors
    ///
    /// Returns an error when a name or value is invalid, or when the name could
    /// inject code or convey authentication material.
    pub fn set_trusted_override(
        &mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Result<(), EnvironmentError> {
        let name = name.into();
        let value = value.into();

        if !is_valid_name(&name) {
            return Err(EnvironmentError::InvalidName(name));
        }
        if !is_valid_value(&value) {
            return Err(EnvironmentError::InvalidValue { name });
        }
        if is_secret_environment_name(&name) || is_loader_control(&name) {
            return Err(EnvironmentError::ForbiddenOverride(name));
        }

        self.removed.remove(&name);
        self.variables.insert(name, value);
        Ok(())
    }

    /// Clears a command's inherited environment and applies only scrubbed values.
    pub fn apply_to(&self, command: &mut Command) {
        command.env_clear();
        command.envs(&self.variables);
    }
}

/// An error constructing a command environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvironmentError {
    /// The variable name is empty, non-Unicode, or contains a forbidden delimiter.
    InvalidName(OsString),
    /// The value contains a NUL byte.
    InvalidValue {
        /// Name associated with the invalid value.
        name: OsString,
    },
    /// A secret-like or dynamic-loader variable was supplied as an override.
    ForbiddenOverride(OsString),
}

impl fmt::Display for EnvironmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => {
                write!(
                    formatter,
                    "invalid environment variable name {}",
                    name.display()
                )
            }
            Self::InvalidValue { name } => {
                write!(
                    formatter,
                    "environment variable {} contains a NUL byte",
                    name.display()
                )
            }
            Self::ForbiddenOverride(name) => {
                write!(
                    formatter,
                    "environment variable {} is forbidden",
                    name.display()
                )
            }
        }
    }
}

impl std::error::Error for EnvironmentError {}

/// Returns whether a variable name is likely to contain authentication material.
///
/// Matching is ASCII case-insensitive. This is a final defense, not a substitute
/// for the positive inheritance allowlist.
#[must_use]
pub fn is_secret_environment_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return true;
    };
    let upper = name.to_ascii_uppercase();

    SECRET_EXACT.contains(&upper.as_str())
        || SECRET_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        || SECRET_SUFFIXES.iter().any(|suffix| upper.ends_with(suffix))
        || upper == "API_KEY"
        || upper == "PASSWORD"
        || upper == "TOKEN"
}

fn is_forbidden_inherited_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return true;
    };
    let upper = name.to_ascii_uppercase();

    is_secret_environment_name(OsStr::new(name))
        || is_loader_control(OsStr::new(name))
        || matches!(
            upper.as_str(),
            "DBUS_SESSION_BUS_ADDRESS"
                | "DISPLAY"
                | "DOCKER_HOST"
                | "GIT_ASKPASS"
                | "HOME"
                | "SECURITYSESSIONID"
                | "TMP"
                | "TMPDIR"
                | "WAYLAND_DISPLAY"
                | "XAUTHORITY"
                | "XDG_RUNTIME_DIR"
                | "__CF_USER_TEXT_ENCODING"
        )
}

fn is_loader_control(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return true;
    };
    let upper = name.to_ascii_uppercase();
    upper.starts_with("DYLD_")
        || upper.starts_with("LD_")
        || matches!(upper.as_str(), "RUSTC_WRAPPER" | "RUSTC_WORKSPACE_WRAPPER")
}

fn is_valid_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| !name.is_empty() && !name.contains(['=', '\0']))
}

fn is_valid_value(value: &OsStr) -> bool {
    value.to_str().is_some_and(|value| !value.contains('\0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inheritance_is_allowlist_only() {
        let policy = EnvironmentPolicy::allowing(["PATH", "LANG"]);
        let scrubbed = policy.scrub([
            ("PATH", "/usr/bin"),
            ("LANG", "en_US.UTF-8"),
            ("UNLISTED", "discard"),
        ]);

        assert_eq!(
            scrubbed.variables().get(OsStr::new("PATH")),
            Some(&OsString::from("/usr/bin"))
        );
        assert!(scrubbed.variables().contains_key(OsStr::new("LANG")));
        assert!(scrubbed.removed_names().contains(OsStr::new("UNLISTED")));
    }

    #[test]
    fn secrets_and_host_channels_are_removed_even_when_allowlisted() {
        let policy = EnvironmentPolicy::allowing([
            "OPENAI_API_KEY",
            "HOME",
            "SSH_AUTH_SOCK",
            "DBUS_SESSION_BUS_ADDRESS",
            "LD_PRELOAD",
            "PATH",
        ]);
        let scrubbed = policy.scrub([
            ("OPENAI_API_KEY", "secret"),
            ("HOME", "/Users/person"),
            ("SSH_AUTH_SOCK", "/tmp/agent"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1/bus"),
            ("LD_PRELOAD", "/tmp/inject.so"),
            ("PATH", "/usr/bin"),
        ]);

        assert_eq!(scrubbed.variables().len(), 1);
        assert!(scrubbed.variables().contains_key(OsStr::new("PATH")));
        assert_eq!(scrubbed.removed_names().len(), 5);
    }

    #[test]
    fn trusted_overrides_support_synthetic_paths_but_not_secrets() {
        let mut scrubbed = EnvironmentPolicy::empty().scrub([] as [(&str, &str); 0]);

        scrubbed
            .set_trusted_override("HOME", "/private/synthetic-home")
            .expect("synthetic home should be accepted");
        scrubbed
            .set_trusted_override("PATH", "/usr/bin:/bin")
            .expect("controlled path should be accepted");

        assert_eq!(scrubbed.variables().len(), 2);
        assert!(matches!(
            scrubbed.set_trusted_override("GITHUB_TOKEN", "secret"),
            Err(EnvironmentError::ForbiddenOverride(_))
        ));
        assert!(matches!(
            scrubbed.set_trusted_override("DYLD_INSERT_LIBRARIES", "/tmp/inject"),
            Err(EnvironmentError::ForbiddenOverride(_))
        ));
    }

    #[test]
    fn secret_name_matching_is_case_insensitive() {
        assert!(is_secret_environment_name(OsStr::new("service_token")));
        assert!(is_secret_environment_name(OsStr::new("OpenAI_Base_Url")));
        assert!(!is_secret_environment_name(OsStr::new("LANG")));
    }
}
