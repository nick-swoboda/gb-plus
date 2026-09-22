//! App-selected exclusions augment the generic snapshot's credential-name policy.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::OsMetadataExt as _;
use std::os::unix::fs::MetadataExt as _;

pub(super) struct Filter {
    source: PathBuf,
    paths: BTreeSet<PathBuf>,
    objects: BTreeSet<(u64, u64)>,
}

impl Filter {
    pub(super) fn new(source: &Path, protected: &[PathBuf]) -> Result<Self, String> {
        super::canonical_directory(source)?;
        if protected.len() > 64
            || protected
                .iter()
                .map(|path| path.as_os_str().len())
                .sum::<usize>()
                > 32 * 1024
        {
            return Err("Service workspace protection inventory exceeded its bound.".into());
        }
        let mut filter = Self {
            source: source.to_path_buf(),
            paths: BTreeSet::new(),
            objects: BTreeSet::new(),
        };
        for path in protected {
            validate_absolute(path)?;
            filter.paths.insert(path.clone());
            // Resolve an existing ancestor as well as the literal path. This
            // covers a configured path through a symlink and a not-yet-created
            // authentication file without opening that file's contents.
            let resolved = resolve_missing(path)?;
            filter.paths.insert(resolved.clone());
            match std::fs::metadata(&resolved) {
                Ok(metadata) => {
                    filter.objects.insert((metadata.dev(), metadata.ino()));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(super::failure(error)),
            }
        }
        let root = std::fs::metadata(source).map_err(super::failure)?;
        if filter.paths.iter().any(|path| source.starts_with(path))
            || filter.objects.contains(&(root.dev(), root.ino()))
        {
            return Err("This workspace is inside protected app or authentication state.".into());
        }
        Ok(filter)
    }

    pub(super) fn excludes_path(&self, relative: &str) -> bool {
        let path = Path::new(relative);
        path.components().any(|part| {
            part.as_os_str().to_str().is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "target"
                        | ".claude"
                        | "node_modules"
                        | ".cache"
                        | ".venv"
                        | "venv"
                        | "__pycache__"
                        | ".next"
                        | ".nuxt"
                        | ".turbo"
                        | ".gradle"
                        | ".idea"
                        | ".ds_store"
                )
            })
        }) || self
            .paths
            .iter()
            .any(|protected| self.source.join(path).starts_with(protected))
    }

    pub(super) fn excludes_object(&self, metadata: &cap_std::fs::Metadata) -> bool {
        self.objects.contains(&(metadata.dev(), metadata.ino()))
    }
}

fn validate_absolute(path: &Path) -> Result<(), String> {
    let text = path
        .to_str()
        .ok_or("Protected service path is not UTF-8.")?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(
            "Protected service paths must be bounded absolute paths without traversal.".into(),
        );
    }
    Ok(())
}

fn resolve_missing(path: &Path) -> Result<PathBuf, String> {
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
                // A dangling symlink is an unresolved identity, not permission
                // to fall back to its lexical location.
                if std::fs::symlink_metadata(existing).is_ok() {
                    return Err("Protected service path contains an unresolved alias.".into());
                }
                suffix.push(
                    existing
                        .file_name()
                        .ok_or("Protected path has no existing ancestor.")?,
                );
                existing = existing.parent().ok_or("Protected path has no parent.")?;
            }
            Err(error) => return Err(super::failure(error)),
        }
    }
}
