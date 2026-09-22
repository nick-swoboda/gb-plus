//! One resolution rule for the CLI-owned OAuth file; credentials are never copied.

use std::ffi::OsString;
use std::path::{Component, PathBuf};
use std::sync::OnceLock;

static AUTH_PATH: OnceLock<Result<PathBuf, String>> = OnceLock::new();

pub(crate) fn cli_auth_path() -> Result<PathBuf, String> {
    AUTH_PATH
        .get_or_init(|| {
            resolve_cli_auth_path(
                std::env::var_os("GROK_AUTH_PATH"),
                std::env::var_os("GROK_HOME"),
                std::env::var_os("HOME"),
            )
        })
        .clone()
}

fn absolute_path(value: OsString, name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(format!(
            "{name} must be an absolute path without parent traversal."
        ));
    }
    Ok(path)
}

fn resolve_cli_auth_path(
    explicit: Option<OsString>,
    grok_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        let path = absolute_path(path, "GROK_AUTH_PATH")?;
        if path.file_name().is_none() {
            return Err("GROK_AUTH_PATH must identify an authentication file.".into());
        }
        return Ok(path);
    }
    if let Some(path) = grok_home {
        return Ok(absolute_path(path, "GROK_HOME")?.join("auth.json"));
    }
    let home = home.ok_or("The user home is unavailable; no CLI OAuth file was selected.")?;
    Ok(absolute_path(home, "HOME")?.join(".grok/auth.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_auth_path_wins_without_requiring_a_usable_home() {
        assert_eq!(
            resolve_cli_auth_path(
                Some("/private/auth.json".into()),
                Some("relative".into()),
                None
            )
            .unwrap(),
            PathBuf::from("/private/auth.json")
        );
    }

    #[test]
    fn inherited_home_and_default_home_resolve_consistently() {
        assert_eq!(
            resolve_cli_auth_path(None, Some("/grok".into()), None).unwrap(),
            PathBuf::from("/grok/auth.json")
        );
        assert_eq!(
            resolve_cli_auth_path(None, None, Some("/user".into())).unwrap(),
            PathBuf::from("/user/.grok/auth.json")
        );
    }

    #[test]
    fn invalid_explicit_override_never_falls_back_to_another_identity() {
        for path in ["", "relative/auth.json", "/grok/../other/auth.json", "/"] {
            assert!(
                resolve_cli_auth_path(
                    Some(path.into()),
                    Some("/valid".into()),
                    Some("/user".into())
                )
                .is_err()
            );
        }
        assert!(resolve_cli_auth_path(None, None, None).is_err());
    }
}
