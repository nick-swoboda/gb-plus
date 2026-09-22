//! Never turn known app/authentication state into immutable extension content.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use grok_build_plus_host::PlusSessionStore;

pub(crate) fn paths(state: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = vec![
        state.to_owned(),
        PlusSessionStore::documented_desktop_state_root(),
        crate::runtime::auth_paths::cli_auth_path()?,
        grok_build_plus_host::managed_container_runtime_root(),
        grok_build_plus_host::managed_colima_home(),
    ];
    for name in ["COLIMA_HOME", "LIMA_HOME", "SSH_AUTH_SOCK"] {
        if let Some(path) = std::env::var_os(name).filter(|path| !path.is_empty()) {
            paths.push(PathBuf::from(path));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        paths.extend([
            home.join(".colima"),
            home.join(".docker"),
            home.join(".lima"),
        ]);
    }
    Ok(paths)
}

pub(super) fn validate_local_root(source: &Path, state: &Path) -> Result<(), String> {
    validate(source, &paths(state)?)
}

fn validate(source: &Path, protected: &[PathBuf]) -> Result<(), String> {
    let source = resolve(source)?;
    for path in protected {
        let path = resolve(path)?;
        if source.starts_with(&path)
            || path.starts_with(&source)
            || ancestor_identity_matches(&source, &path)?
            || ancestor_identity_matches(&path, &source)?
        {
            return Err("This local extension source overlaps protected app, authentication or runtime state. Choose a separate plugin folder before preview or use.".into());
        }
    }
    Ok(())
}

fn resolve(path: &Path) -> Result<PathBuf, String> {
    let text = path.to_str().ok_or("Protected source path is not UTF-8.")?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(
            "Protected source paths must be bounded absolute paths without parent traversal."
                .into(),
        );
    }
    let mut existing = path;
    let mut suffix = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(mut resolved) => {
                for part in suffix.into_iter().rev() {
                    resolved.push(part);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if std::fs::symlink_metadata(existing).is_ok() {
                    return Err("Protected source contains an unresolved alias.".into());
                }
                suffix.push(
                    existing
                        .file_name()
                        .ok_or("Protected source has no existing ancestor.")?,
                );
                if suffix.len() > 128 {
                    return Err("Protected source depth exceeded its bound.".into());
                }
                existing = existing.parent().ok_or("Protected source has no parent.")?;
            }
            Err(error) => return Err(super::failure(error)),
        }
    }
}

fn object(path: &Path) -> Result<Option<(u64, u64)>, String> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(super::failure(error)),
    }
}

fn ancestor_identity_matches(parent: &Path, child: &Path) -> Result<bool, String> {
    let Some(expected) = object(parent)? else {
        return Ok(false);
    };
    for ancestor in child.ancestors() {
        if object(ancestor)? == Some(expected) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_sources_refuse_ancestors_children_aliases_and_future_files() {
        let root =
            std::env::temp_dir().join(format!("gbplus-source-protection-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        for name in ["plugin", "state", "other"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        std::os::unix::fs::symlink(root.join("state"), root.join("alias")).unwrap();
        let protected = [root.join("state"), root.join("plugin/future-auth.data")];
        for source in [
            &root,
            &root.join("state"),
            &root.join("state/subdir"),
            &root.join("alias"),
            &root.join("plugin"),
        ] {
            assert!(validate(source, &protected).is_err());
        }
        validate(&root.join("other"), &protected).unwrap();
        validate(&root.join("plugin"), &[root.join("other/future-auth.data")]).unwrap();
        assert!(validate(&root.join("other"), &[root.join("../elsewhere")]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
