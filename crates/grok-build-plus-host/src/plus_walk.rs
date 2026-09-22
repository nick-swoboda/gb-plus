//! Descriptor-bound workspace file walk shared by host `grep` and `glob`.

use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

use super::PlusHostError;
use super::plus_proposal::{open_workspace_directory, open_workspace_node};

const MAX_WALK_FILES_PLUS_SENTINEL: usize = 4_097;
const MAX_WALK_ENTRIES: usize = 16_384;

/// Collects workspace-relative regular files under `start_relative`, skipping
/// `.git`. Every traversed component is opened from a retained parent
/// descriptor with `O_NOFOLLOW`; path-based symlink swaps are refused.
pub(crate) fn collect_search_files(
    workspace: &Path,
    start_relative: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), PlusHostError> {
    if start_relative != Path::new(".") && !start_relative.as_os_str().is_empty() {
        let node = open_workspace_node(workspace, start_relative)?;
        let metadata = node.metadata().map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot inspect search path {}: {error}",
                start_relative.display()
            ))
        })?;
        if metadata.is_file() {
            files.push(start_relative.to_path_buf());
            return Ok(());
        }
        if !metadata.is_dir() {
            return Err(PlusHostError::Proposal(format!(
                "search path is not a regular file or directory: {}",
                start_relative.display()
            )));
        }
    }

    let normalized_start = if start_relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        start_relative.to_path_buf()
    };
    let mut stack = vec![normalized_start];
    let mut visited = 0_usize;
    while let Some(relative_dir) = stack.pop() {
        let directory = open_workspace_directory(workspace, &relative_dir)?;
        let mut entries = rustix::fs::Dir::read_from(&directory).map_err(|error| {
            PlusHostError::Proposal(format!("cannot search {}: {error}", relative_dir.display()))
        })?;
        while let Some(entry) = entries.read() {
            let entry = entry.map_err(|error| {
                PlusHostError::Proposal(format!(
                    "cannot search {}: {error}",
                    relative_dir.display()
                ))
            })?;
            let name = directory_entry_name(entry.file_name().to_bytes());
            if name == "." || name == ".." || name == ".git" {
                continue;
            }
            visited = visited.saturating_add(1);
            if visited > MAX_WALK_ENTRIES {
                return Err(PlusHostError::Proposal(format!(
                    "workspace walk exceeded its {MAX_WALK_ENTRIES}-entry safety limit"
                )));
            }
            let child = if relative_dir == Path::new(".") {
                PathBuf::from(&name)
            } else {
                relative_dir.join(&name)
            };
            let Ok(node) = open_workspace_node(workspace, &child) else {
                continue;
            };
            let metadata = node.metadata().map_err(|error| {
                PlusHostError::Proposal(format!(
                    "cannot inspect search path {}: {error}",
                    child.display()
                ))
            })?;
            if metadata.is_dir() {
                stack.push(child);
            } else if metadata.is_file() {
                files.push(child);
                if files.len() >= MAX_WALK_FILES_PLUS_SENTINEL {
                    files.sort();
                    return Ok(());
                }
            }
        }
    }
    files.sort();
    Ok(())
}

#[cfg(unix)]
fn directory_entry_name(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

#[cfg(not(unix))]
fn directory_entry_name(bytes: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(bytes).into_owned())
}
