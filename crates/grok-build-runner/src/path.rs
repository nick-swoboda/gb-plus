//! Canonical workspace containment checks.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// A canonical, existing directory that bounds runner filesystem operations.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalRoot {
    path: PathBuf,
}

impl CanonicalRoot {
    /// Opens and canonicalizes an absolute workspace root.
    ///
    /// # Errors
    ///
    /// Returns an error if the root is relative, unavailable, or not a directory.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, PathValidationError> {
        let requested = root.as_ref();
        if !requested.is_absolute() {
            return Err(PathValidationError::RootNotAbsolute(
                requested.to_path_buf(),
            ));
        }

        let path = fs::canonicalize(requested)
            .map_err(|error| io_error("canonicalize workspace root", requested, &error))?;
        let metadata = fs::metadata(&path)
            .map_err(|error| io_error("inspect workspace root", &path, &error))?;
        if !metadata.is_dir() {
            return Err(PathValidationError::RootNotDirectory(path));
        }

        Ok(Self { path })
    }

    /// Returns the canonical workspace path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// Resolves an existing relative path and proves its canonical target remains
    /// inside the workspace.
    ///
    /// Symlinks may be followed for reads only when their final canonical target is
    /// contained. Mutation validation is intentionally stricter.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid, unavailable, or resolves outside
    /// the workspace.
    pub fn validate_existing(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<ValidatedPath, PathValidationError> {
        let relative = normalize_relative(relative.as_ref(), true)?;
        let requested = self.path.join(&relative);
        let absolute = fs::canonicalize(&requested)
            .map_err(|error| io_error("canonicalize existing path", &requested, &error))?;
        self.require_contained(&absolute)?;

        Ok(ValidatedPath { relative, absolute })
    }

    /// Validates a relative path intended for creation, replacement, or deletion.
    ///
    /// Existing symlink components, hard-linked regular files, and special-file
    /// targets are rejected. Missing trailing components are permitted. This check
    /// is fail-closed validation, but it is not race-proof authorization: mutation
    /// must still use descriptor-relative, no-follow operations at the point of use.
    ///
    /// # Errors
    ///
    /// Returns an error if the path escapes the workspace, contains an unsafe
    /// component, targets a hard-linked or special file, or cannot be inspected.
    pub fn validate_mutation_target(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<ValidatedPath, PathValidationError> {
        let relative = normalize_relative(relative.as_ref(), false)?;
        if relative.components().any(|component| {
            matches!(component, Component::Normal(name)
                if name.to_str().is_some_and(|text| text.eq_ignore_ascii_case(".git")))
        }) {
            return Err(PathValidationError::ProtectedGitPath(relative));
        }
        let absolute = self.path.join(&relative);
        self.require_contained(&absolute)?;

        let component_count = relative.components().count();
        let mut current = self.path.clone();
        let mut deepest_existing = self.path.clone();

        for (index, component) in relative.components().enumerate() {
            let Component::Normal(component) = component else {
                return Err(PathValidationError::InvalidComponent(relative.clone()));
            };
            current.push(component);

            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(PathValidationError::SymlinkComponent(current));
                    }
                    let is_leaf = index + 1 == component_count;
                    if !is_leaf && !metadata.is_dir() {
                        return Err(PathValidationError::NonDirectoryComponent(current));
                    }
                    if is_leaf {
                        validate_leaf_type(&current, &metadata)?;
                    }
                    deepest_existing.clone_from(&current);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(io_error("inspect mutation path", &current, &error));
                }
            }
        }

        let canonical_ancestor = fs::canonicalize(&deepest_existing).map_err(|error| {
            io_error(
                "canonicalize mutation-path ancestor",
                &deepest_existing,
                &error,
            )
        })?;
        self.require_contained(&canonical_ancestor)?;

        Ok(ValidatedPath { relative, absolute })
    }

    fn require_contained(&self, candidate: &Path) -> Result<(), PathValidationError> {
        if candidate.starts_with(&self.path) {
            Ok(())
        } else {
            Err(PathValidationError::OutsideRoot {
                root: self.path.clone(),
                candidate: candidate.to_path_buf(),
            })
        }
    }
}

/// A validated relative path and its absolute workspace location.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ValidatedPath {
    relative: PathBuf,
    absolute: PathBuf,
}

impl ValidatedPath {
    /// Returns the normalized path relative to the workspace.
    #[must_use]
    pub fn relative(&self) -> &Path {
        &self.relative
    }

    /// Returns the absolute path beneath the canonical workspace root.
    #[must_use]
    pub fn absolute(&self) -> &Path {
        &self.absolute
    }
}

/// A fail-closed path validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathValidationError {
    /// Workspace roots must be explicit absolute paths.
    RootNotAbsolute(PathBuf),
    /// The canonical workspace root is not a directory.
    RootNotDirectory(PathBuf),
    /// Absolute tool paths are not accepted.
    AbsolutePath(PathBuf),
    /// Parent traversal is not accepted, even when it would resolve inside the root.
    ParentTraversal(PathBuf),
    /// A mutation cannot target the workspace root itself.
    EmptyMutationPath,
    /// Git administrative state is never a runner mutation target.
    ProtectedGitPath(PathBuf),
    /// A path contains a component unsupported by the normalized representation.
    InvalidComponent(PathBuf),
    /// Canonical resolution left the trusted workspace.
    OutsideRoot {
        /// Canonical workspace root.
        root: PathBuf,
        /// Candidate path that escaped the root.
        candidate: PathBuf,
    },
    /// A mutation path contains a symlink.
    SymlinkComponent(PathBuf),
    /// An intermediate mutation component is not a directory.
    NonDirectoryComponent(PathBuf),
    /// A mutation target is a special file.
    SpecialFile(PathBuf),
    /// A mutation target has more than one hard link.
    HardLinkedTarget(PathBuf),
    /// A filesystem operation failed.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Path being operated on.
        path: PathBuf,
        /// Redacted operating-system error description.
        message: String,
    },
}

impl fmt::Display for PathValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNotAbsolute(path) => {
                write!(
                    formatter,
                    "workspace root must be absolute: {}",
                    path.display()
                )
            }
            Self::RootNotDirectory(path) => {
                write!(
                    formatter,
                    "workspace root is not a directory: {}",
                    path.display()
                )
            }
            Self::AbsolutePath(path) => {
                write!(formatter, "tool path must be relative: {}", path.display())
            }
            Self::ParentTraversal(path) => {
                write!(
                    formatter,
                    "parent traversal is forbidden: {}",
                    path.display()
                )
            }
            Self::EmptyMutationPath => write!(formatter, "mutation cannot target workspace root"),
            Self::ProtectedGitPath(path) => write!(
                formatter,
                "mutation cannot target Git administrative state: {}",
                path.display()
            ),
            Self::InvalidComponent(path) => {
                write!(
                    formatter,
                    "path contains an invalid component: {}",
                    path.display()
                )
            }
            Self::OutsideRoot { root, candidate } => write!(
                formatter,
                "path {} is outside workspace {}",
                candidate.display(),
                root.display()
            ),
            Self::SymlinkComponent(path) => {
                write!(
                    formatter,
                    "mutation path contains a symlink: {}",
                    path.display()
                )
            }
            Self::NonDirectoryComponent(path) => write!(
                formatter,
                "intermediate path is not a directory: {}",
                path.display()
            ),
            Self::SpecialFile(path) => {
                write!(
                    formatter,
                    "mutation target is a special file: {}",
                    path.display()
                )
            }
            Self::HardLinkedTarget(path) => write!(
                formatter,
                "mutation target has multiple hard links: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "{operation} failed for {}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PathValidationError {}

fn normalize_relative(
    path: &Path,
    allow_workspace_root: bool,
) -> Result<PathBuf, PathValidationError> {
    if path.is_absolute() {
        return Err(PathValidationError::AbsolutePath(path.to_path_buf()));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => normalized.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(PathValidationError::ParentTraversal(path.to_path_buf()));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(PathValidationError::AbsolutePath(path.to_path_buf()));
            }
        }
    }

    if normalized.as_os_str().is_empty() && !allow_workspace_root {
        return Err(PathValidationError::EmptyMutationPath);
    }
    Ok(normalized)
}

fn validate_leaf_type(path: &Path, metadata: &fs::Metadata) -> Result<(), PathValidationError> {
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(PathValidationError::SpecialFile(path.to_path_buf()));
    }

    #[cfg(unix)]
    if metadata.is_file() {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(PathValidationError::HardLinkedTarget(path.to_path_buf()));
        }
    }

    Ok(())
}

fn io_error(operation: &'static str, path: &Path, error: &io::Error) -> PathValidationError {
    PathValidationError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-runner-{label}-{}-{number}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test directory should be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn existing_paths_are_canonical_and_contained() {
        let directory = TestDirectory::new("existing");
        fs::create_dir_all(directory.0.join("src")).unwrap();
        fs::write(directory.0.join("src/lib.rs"), "fn example() {}\n").unwrap();
        let root = CanonicalRoot::open(&directory.0).unwrap();

        let validated = root.validate_existing("src/./lib.rs").unwrap();

        assert_eq!(validated.relative(), Path::new("src/lib.rs"));
        assert_eq!(validated.absolute(), root.as_path().join("src/lib.rs"));
    }

    #[test]
    fn absolute_and_parent_paths_are_rejected() {
        let directory = TestDirectory::new("lexical");
        let root = CanonicalRoot::open(&directory.0).unwrap();

        assert!(matches!(
            root.validate_existing("../outside"),
            Err(PathValidationError::ParentTraversal(_))
        ));
        assert!(matches!(
            root.validate_existing(&directory.0),
            Err(PathValidationError::AbsolutePath(_))
        ));
    }

    #[test]
    fn missing_mutation_targets_inside_root_are_accepted() {
        let directory = TestDirectory::new("create");
        fs::create_dir(directory.0.join("src")).unwrap();
        let root = CanonicalRoot::open(&directory.0).unwrap();

        let validated = root
            .validate_mutation_target("src/generated/module.rs")
            .unwrap();

        assert_eq!(
            validated.absolute(),
            root.as_path().join("src/generated/module.rs")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected_for_reads_and_mutations() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("symlink-root");
        let outside = TestDirectory::new("symlink-outside");
        fs::write(outside.0.join("secret"), "not visible").unwrap();
        symlink(&outside.0, directory.0.join("link")).unwrap();
        let root = CanonicalRoot::open(&directory.0).unwrap();

        assert!(matches!(
            root.validate_existing("link/secret"),
            Err(PathValidationError::OutsideRoot { .. })
        ));
        assert!(matches!(
            root.validate_mutation_target("link/new-file"),
            Err(PathValidationError::SymlinkComponent(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_targets_are_rejected_for_mutation() {
        let directory = TestDirectory::new("hardlink");
        let first = directory.0.join("first");
        fs::write(&first, "shared inode").unwrap();
        fs::hard_link(&first, directory.0.join("second")).unwrap();
        let root = CanonicalRoot::open(&directory.0).unwrap();

        assert!(matches!(
            root.validate_mutation_target("first"),
            Err(PathValidationError::HardLinkedTarget(_))
        ));
    }

    #[test]
    fn mutation_cannot_target_workspace_root() {
        let directory = TestDirectory::new("root-target");
        let root = CanonicalRoot::open(&directory.0).unwrap();

        assert_eq!(
            root.validate_mutation_target("."),
            Err(PathValidationError::EmptyMutationPath)
        );
    }

    #[test]
    fn mutation_cannot_target_git_administrative_state() {
        let directory = TestDirectory::new("git-path");
        fs::create_dir(directory.0.join(".git")).unwrap();
        let root = CanonicalRoot::open(&directory.0).unwrap();

        assert!(matches!(
            root.validate_mutation_target(".git/config"),
            Err(PathValidationError::ProtectedGitPath(_))
        ));
        assert!(matches!(
            root.validate_mutation_target("nested/.git/index"),
            Err(PathValidationError::ProtectedGitPath(_))
        ));
        assert!(matches!(
            root.validate_mutation_target(".GIT/config"),
            Err(PathValidationError::ProtectedGitPath(_))
        ));
    }
}
