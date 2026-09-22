//! Read-only, bounded Workspace Browser filesystem boundary.

use std::fs::{self, File, Metadata};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use grok_build_plus_host::BoundProject;
use serde::Serialize;

const MAX_RELATIVE_PATH_BYTES: usize = 4 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 2_000;
const MAX_OPEN_FILE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceEntryView {
    name: String,
    path: Option<String>,
    kind: &'static str,
    size: Option<u64>,
    detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceDirectoryView {
    path: String,
    entries: Vec<WorkspaceEntryView>,
    truncated: bool,
    limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceFileView {
    path: String,
    status: &'static str,
    content: Option<String>,
    byte_count: Option<u64>,
    limit: usize,
    detail: String,
}

impl WorkspaceDirectoryView {
    pub(crate) fn contains_entry(&self, path: &str, kind: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.path.as_deref() == Some(path) && entry.kind == kind)
    }
}

impl WorkspaceFileView {
    pub(crate) fn is_exact_text(&self, path: &str, content: &str) -> bool {
        self.path == path && self.status == "text" && self.content.as_deref() == Some(content)
    }
}

pub(crate) fn list_workspace_directory(
    bound: &BoundProject,
    relative: &str,
) -> Result<WorkspaceDirectoryView, String> {
    let (shown, absolute, before) = resolve_existing_directory(bound, relative)?;
    let mut entries = Vec::new();
    let iterator = fs::read_dir(&absolute)
        .map_err(|error| format!("Cannot list workspace directory `{shown}`: {error}"))?;
    let mut truncated = false;
    for result in iterator {
        let entry =
            result.map_err(|error| format!("Cannot read an entry in `{shown}`: {error}"))?;
        if entry.file_name() == ".git" {
            continue;
        }
        if entries.len() >= MAX_DIRECTORY_ENTRIES {
            truncated = true;
            break;
        }
        entries.push(workspace_entry(&shown, &entry));
    }
    let after = fs::symlink_metadata(&absolute)
        .map_err(|error| format!("Workspace directory `{shown}` changed while listing: {error}"))?;
    if after.file_type().is_symlink() || !same_file_identity(&before, &after) {
        return Err(format!(
            "Workspace directory `{shown}` changed while listing. Refresh and try again."
        ));
    }
    entries.sort_by(|left, right| {
        entry_rank(left.kind)
            .cmp(&entry_rank(right.kind))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(WorkspaceDirectoryView {
        path: shown,
        entries,
        truncated,
        limit: MAX_DIRECTORY_ENTRIES,
    })
}

pub(crate) fn open_workspace_file(
    bound: &BoundProject,
    relative: &str,
) -> Result<WorkspaceFileView, String> {
    match resolve_workspace_file(bound, relative)? {
        ResolvedWorkspaceFile::Regular(target) => read_workspace_file(bound, target),
        ResolvedWorkspaceFile::State(state) => Ok(state),
    }
}

struct WorkspaceFileTarget {
    shown: String,
    absolute: PathBuf,
    metadata: Metadata,
}

enum ResolvedWorkspaceFile {
    Regular(WorkspaceFileTarget),
    State(WorkspaceFileView),
}

fn resolve_workspace_file(
    bound: &BoundProject,
    relative: &str,
) -> Result<ResolvedWorkspaceFile, String> {
    validate_workspace_authority(bound)?;
    let components = normal_relative_components(relative, false)?;
    let shown = components.join("/");
    let mut absolute = bound.folder().to_path_buf();
    let mut final_metadata = None;
    for (index, component) in components.iter().enumerate() {
        absolute.push(component);
        let is_final = index + 1 == components.len();
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ResolvedWorkspaceFile::State(file_state(
                    shown,
                    "missing",
                    None,
                    None,
                    "The file no longer exists. Refresh the Workspace tree.",
                )));
            }
            Err(error) => {
                return Ok(ResolvedWorkspaceFile::State(file_state(
                    shown,
                    "unreadable",
                    None,
                    None,
                    format!("The file cannot be inspected: {error}"),
                )));
            }
        };
        if metadata.file_type().is_symlink() {
            return Ok(ResolvedWorkspaceFile::State(file_state(
                shown,
                "symlink",
                None,
                None,
                "Symlinks are shown but never opened by the Workspace Browser.",
            )));
        }
        if !is_final && !metadata.is_dir() {
            return Ok(ResolvedWorkspaceFile::State(file_state(
                shown,
                "unreadable",
                None,
                None,
                "A parent component is not a directory.",
            )));
        }
        if is_final {
            final_metadata = Some(metadata);
        }
    }
    let metadata = final_metadata.ok_or_else(|| "Workspace file path was empty.".to_owned())?;
    if !metadata.is_file() {
        return Ok(ResolvedWorkspaceFile::State(file_state(
            shown,
            "notFile",
            None,
            Some(metadata.len()),
            "This Workspace entry is not a regular file.",
        )));
    }
    Ok(ResolvedWorkspaceFile::Regular(WorkspaceFileTarget {
        shown,
        absolute,
        metadata,
    }))
}

fn read_workspace_file(
    bound: &BoundProject,
    target: WorkspaceFileTarget,
) -> Result<WorkspaceFileView, String> {
    let WorkspaceFileTarget {
        shown,
        absolute,
        metadata,
    } = target;
    let canonical = absolute
        .canonicalize()
        .map_err(|error| format!("Cannot resolve workspace file `{shown}`: {error}"))?;
    if !canonical.starts_with(bound.folder()) {
        return Err(format!(
            "Workspace file `{shown}` resolves outside the active workspace."
        ));
    }
    if metadata.len() > MAX_OPEN_FILE_BYTES as u64 {
        return Ok(file_state(
            shown,
            "oversized",
            None,
            Some(metadata.len()),
            format!(
                "The file is {} bytes; the read-only viewer limit is {MAX_OPEN_FILE_BYTES} bytes.",
                metadata.len()
            ),
        ));
    }

    let mut file = match File::open(&canonical) {
        Ok(file) => file,
        Err(error) => {
            return Ok(file_state(
                shown,
                "unreadable",
                None,
                Some(metadata.len()),
                format!("The file cannot be opened: {error}"),
            ));
        }
    };
    let opened = file
        .metadata()
        .map_err(|error| format!("Cannot inspect opened workspace file `{shown}`: {error}"))?;
    let path_after_open = fs::symlink_metadata(&absolute)
        .map_err(|error| format!("Workspace file `{shown}` changed while opening: {error}"))?;
    if path_after_open.file_type().is_symlink()
        || !same_file_identity(&opened, &path_after_open)
        || !same_file_identity(&metadata, &opened)
    {
        return Ok(file_state(
            shown,
            "changed",
            None,
            Some(opened.len()),
            "The file changed while opening. Refresh and try again.",
        ));
    }

    let capacity = usize::try_from(opened.len()).unwrap_or(MAX_OPEN_FILE_BYTES);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take((MAX_OPEN_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read workspace file `{shown}`: {error}"))?;
    let after_read = file
        .metadata()
        .map_err(|error| format!("Cannot recheck workspace file `{shown}`: {error}"))?;
    if bytes.len() > MAX_OPEN_FILE_BYTES || !same_file_snapshot(&opened, &after_read) {
        return Ok(file_state(
            shown,
            "changed",
            None,
            Some(after_read.len()),
            "The file changed while reading. Refresh and try again.",
        ));
    }
    if bytes.contains(&0) {
        return Ok(file_state(
            shown,
            "binary",
            None,
            Some(bytes.len() as u64),
            "The file contains binary data and is not rendered as text.",
        ));
    }
    match String::from_utf8(bytes) {
        Ok(content) => Ok(file_state(
            shown,
            "text",
            Some(content),
            Some(after_read.len()),
            "Read-only UTF-8 workspace file.",
        )),
        Err(error) => Ok(file_state(
            shown,
            "binary",
            None,
            Some(error.as_bytes().len() as u64),
            "The file is not valid UTF-8 and is not rendered as text.",
        )),
    }
}

fn workspace_entry(parent: &str, entry: &fs::DirEntry) -> WorkspaceEntryView {
    let Ok(name) = entry.file_name().into_string() else {
        return WorkspaceEntryView {
            name: "[non-UTF-8 name]".into(),
            path: None,
            kind: "unreadable",
            size: None,
            detail: Some("This filename cannot cross the UTF-8 UI boundary.".into()),
        };
    };
    let path = if parent == "." {
        name.clone()
    } else {
        format!("{parent}/{name}")
    };
    match entry.file_type() {
        Ok(file_type) if file_type.is_symlink() => WorkspaceEntryView {
            name,
            path: Some(path),
            kind: "symlink",
            size: None,
            detail: Some("Symlink · not followed".into()),
        },
        Ok(file_type) if file_type.is_dir() => WorkspaceEntryView {
            name,
            path: Some(path),
            kind: "directory",
            size: None,
            detail: None,
        },
        Ok(file_type) if file_type.is_file() => match entry.metadata() {
            Ok(metadata) => WorkspaceEntryView {
                name,
                path: Some(path),
                kind: "file",
                size: Some(metadata.len()),
                detail: None,
            },
            Err(error) => WorkspaceEntryView {
                name,
                path: Some(path),
                kind: "unreadable",
                size: None,
                detail: Some(format!("Cannot inspect entry: {error}")),
            },
        },
        Ok(_) => WorkspaceEntryView {
            name,
            path: Some(path),
            kind: "other",
            size: None,
            detail: Some("Not a regular file or directory".into()),
        },
        Err(error) => WorkspaceEntryView {
            name,
            path: Some(path),
            kind: "unreadable",
            size: None,
            detail: Some(format!("Cannot inspect entry type: {error}")),
        },
    }
}

fn resolve_existing_directory(
    bound: &BoundProject,
    relative: &str,
) -> Result<(String, PathBuf, Metadata), String> {
    validate_workspace_authority(bound)?;
    let components = normal_relative_components(relative, true)?;
    let shown = if components.is_empty() {
        ".".to_owned()
    } else {
        components.join("/")
    };
    let mut absolute = bound.folder().to_path_buf();
    for component in components {
        absolute.push(component);
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect workspace directory `{shown}`: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Workspace directory `{shown}` is a symlink and is not followed."
            ));
        }
        if !metadata.is_dir() {
            return Err(format!("Workspace path `{shown}` is not a directory."));
        }
    }
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|error| format!("Cannot inspect workspace directory `{shown}`: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("Workspace path `{shown}` is not a real directory."));
    }
    let canonical = absolute
        .canonicalize()
        .map_err(|error| format!("Cannot resolve workspace directory `{shown}`: {error}"))?;
    if !canonical.starts_with(bound.folder()) {
        return Err(format!(
            "Workspace directory `{shown}` resolves outside the active workspace."
        ));
    }
    Ok((shown, canonical, metadata))
}

fn validate_workspace_authority(bound: &BoundProject) -> Result<(), String> {
    bound
        .grant
        .validate_integrity()
        .map_err(|error| format!("Workspace authority is no longer valid: {error}"))
}

fn normal_relative_components(relative: &str, allow_root: bool) -> Result<Vec<String>, String> {
    if relative.len() > MAX_RELATIVE_PATH_BYTES || relative.contains('\0') {
        return Err("Workspace path is empty, oversized, or contains NUL.".into());
    }
    if allow_root && (relative.is_empty() || relative == ".") {
        return Ok(Vec::new());
    }
    if relative.is_empty() || relative == "." {
        return Err("Choose a workspace file before opening.".into());
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err("Workspace paths must be relative to the active project.".into());
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or_else(|| "Workspace path is not valid UTF-8.".to_owned())?;
                components.push(component.to_owned());
            }
            _ => {
                return Err(
                    "Workspace paths cannot contain `.`, `..`, root, or prefix components.".into(),
                );
            }
        }
    }
    if components.is_empty() {
        return Err("Workspace path has no normal components.".into());
    }
    Ok(components)
}

fn file_state(
    path: String,
    status: &'static str,
    content: Option<String>,
    byte_count: Option<u64>,
    detail: impl Into<String>,
) -> WorkspaceFileView {
    WorkspaceFileView {
        path,
        status,
        content,
        byte_count,
        limit: MAX_OPEN_FILE_BYTES,
        detail: detail.into(),
    }
}

const fn entry_rank(kind: &str) -> u8 {
    match kind.as_bytes() {
        b"directory" => 0,
        b"file" => 1,
        b"symlink" => 2,
        _ => 3,
    }
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.is_file() == right.is_file()
}

fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    same_file_identity(left, right)
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_plus_host::bind_project_folder;

    use super::{list_workspace_directory, open_workspace_file};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn fixture(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "grok-build-workspace-{label}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn tree_and_open_are_bounded_and_utf8_strict() {
        let root = fixture("tree");
        fs::create_dir_all(root.join("src")).expect("fixture directory");
        fs::create_dir_all(root.join(".git")).expect("git directory");
        fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("text fixture");
        fs::write(root.join("binary.bin"), [0xff, 0x00, 0x01]).expect("binary fixture");
        fs::write(root.join("large.txt"), vec![b'x'; 64 * 1024 + 1]).expect("large fixture");
        let bound = bind_project_folder(&root).expect("bind fixture");

        let listed = list_workspace_directory(&bound, ".").expect("list root");
        assert!(listed.entries.iter().any(|entry| entry.name == "src"));
        assert!(!listed.entries.iter().any(|entry| entry.name == ".git"));
        let text = open_workspace_file(&bound, "src/main.rs").expect("open text");
        assert_eq!(text.status, "text");
        assert_eq!(text.content.as_deref(), Some("fn main() {}\n"));
        assert_eq!(
            open_workspace_file(&bound, "binary.bin")
                .expect("open binary")
                .status,
            "binary"
        );
        assert_eq!(
            open_workspace_file(&bound, "large.txt")
                .expect("open large")
                .status,
            "oversized"
        );
        assert_eq!(
            open_workspace_file(&bound, "missing.txt")
                .expect("open missing")
                .status,
            "missing"
        );
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_path_escape_are_never_followed() {
        use std::os::unix::fs::symlink;

        let root = fixture("symlink");
        let outside = fixture("outside");
        fs::create_dir_all(&root).expect("workspace root");
        fs::create_dir_all(&outside).expect("outside root");
        fs::write(outside.join("secret.txt"), "outside\n").expect("outside file");
        symlink(&outside, root.join("outside-link")).expect("directory symlink");
        symlink(outside.join("secret.txt"), root.join("file-link")).expect("file symlink");
        let bound = bind_project_folder(&root).expect("bind fixture");

        let listed = list_workspace_directory(&bound, ".").expect("list root");
        assert!(
            listed
                .entries
                .iter()
                .any(|entry| { entry.name == "outside-link" && entry.kind == "symlink" })
        );
        assert!(list_workspace_directory(&bound, "outside-link").is_err());
        assert_eq!(
            open_workspace_file(&bound, "file-link")
                .expect("symlink status")
                .status,
            "symlink"
        );
        assert!(open_workspace_file(&bound, "../outside/secret.txt").is_err());
        assert!(
            open_workspace_file(&bound, &outside.join("secret.txt").display().to_string()).is_err()
        );
        fs::remove_dir_all(root).expect("workspace cleanup");
        fs::remove_dir_all(outside).expect("outside cleanup");
    }
}
