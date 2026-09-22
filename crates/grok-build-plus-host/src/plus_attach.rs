//! Attach relative workspace files into the next Chat Send.

use std::fs;
use std::path::{Path, PathBuf};

use super::plus_proposal::workspace_file;
use super::plus_tools::plus_tool_list_dir;
use super::{BoundProject, PlusHostError};

/// Per-file cap for attached context.
pub const PLUS_ATTACH_MAX_BYTES: usize = 64 * 1024;

/// Cap on how many files one Send may carry.
pub const PLUS_ATTACH_MAX_FILES: usize = 8;

/// Hard cap on the default `list_dir` sketch included in Send.
pub const PLUS_SKETCH_MAX_BYTES: usize = 4 * 1024;

/// Hard cap on how many directory names the sketch may list.
pub const PLUS_SKETCH_MAX_ENTRIES: usize = 32;

/// Notice when the sketch was cut to stay under the cap.
pub const PLUS_SKETCH_TRUNCATED: &str = "directory sketch truncated";

/// Notice when `list_dir` could not produce a sketch.
pub const PLUS_SKETCH_SKIPPED: &str = "directory sketch skipped";

/// One attached workspace file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusAttachment {
    /// Workspace-relative path shown in the UI and prompt.
    pub relative_path: PathBuf,
    /// UTF-8 (lossy) file text included in the next Send.
    pub text: String,
}

/// Reads a relative file for the next model request.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the path is invalid, missing, or
/// larger than [`PLUS_ATTACH_MAX_BYTES`]. Oversized files are refused, not
/// silently dropped.
pub fn attach_plus_file(
    bound: &BoundProject,
    relative: impl AsRef<Path>,
) -> Result<PlusAttachment, PlusHostError> {
    let relative = relative.as_ref();
    let absolute = workspace_file(bound.folder(), relative)?;
    let metadata = fs::metadata(&absolute).map_err(|error| {
        PlusHostError::Proposal(format!("cannot attach {}: {error}", relative.display()))
    })?;
    if !metadata.is_file() {
        return Err(PlusHostError::Proposal(format!(
            "attach path is not a file: {}",
            relative.display()
        )));
    }
    if metadata.len() > PLUS_ATTACH_MAX_BYTES as u64 {
        return Err(PlusHostError::Proposal(format!(
            "size-limit refusal: {} exceeds {PLUS_ATTACH_MAX_BYTES} bytes",
            relative.display()
        )));
    }
    let bytes = fs::read(&absolute).map_err(|error| {
        PlusHostError::Proposal(format!("cannot attach {}: {error}", relative.display()))
    })?;
    Ok(PlusAttachment {
        relative_path: relative.to_path_buf(),
        text: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

/// Adds an attachment if the set is under [`PLUS_ATTACH_MAX_FILES`].
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the file cap is exceeded.
pub fn push_plus_attachment(
    attachments: &mut Vec<PlusAttachment>,
    attachment: PlusAttachment,
) -> Result<(), PlusHostError> {
    if attachments.len() >= PLUS_ATTACH_MAX_FILES {
        return Err(PlusHostError::Proposal(format!(
            "size-limit refusal: at most {PLUS_ATTACH_MAX_FILES} attached files"
        )));
    }
    if let Some(existing) = attachments
        .iter_mut()
        .find(|item| item.relative_path == attachment.relative_path)
    {
        *existing = attachment;
    } else {
        attachments.push(attachment);
    }
    Ok(())
}

/// Context-bar heading. Always visible, including with an empty draft.
pub const PLUS_CONTEXT_BAR: &str = "Context";

/// Cursor-style chip prefix for an attached file.
pub const PLUS_AT_FILE: &str = "@file";

/// Empty context bar so the chip surface stays visible with no attaches.
pub const PLUS_CONTEXT_EMPTY: &str = "Context: @file";

/// UI listing of currently attached paths.
#[must_use]
pub fn present_plus_attachments(attachments: &[PlusAttachment]) -> String {
    if attachments.is_empty() {
        return "No files attached.".into();
    }
    let mut out = String::from("Attached:");
    for attachment in attachments {
        out.push('\n');
        out.push_str(&attachment.relative_path.display().to_string());
    }
    out
}

/// Always-visible `@file` chips. Empty draft still shows [`PLUS_CONTEXT_EMPTY`].
#[must_use]
pub fn present_plus_context_chips(attachments: &[PlusAttachment]) -> String {
    if attachments.is_empty() {
        return PLUS_CONTEXT_EMPTY.into();
    }
    let mut out = format!("{PLUS_CONTEXT_BAR}:");
    for attachment in attachments {
        out.push(' ');
        out.push_str(PLUS_AT_FILE);
        out.push(' ');
        out.push_str(&attachment.relative_path.display().to_string());
    }
    out
}

/// Prefixes the user draft with attached file bodies. Never drops a file.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the set is over the file cap or a
/// body exceeds [`PLUS_ATTACH_MAX_BYTES`].
pub fn plus_compose_user_with_attachments(
    user_text: &str,
    attachments: &[PlusAttachment],
) -> Result<String, PlusHostError> {
    if attachments.len() > PLUS_ATTACH_MAX_FILES {
        return Err(PlusHostError::Proposal(format!(
            "size-limit refusal: at most {PLUS_ATTACH_MAX_FILES} attached files"
        )));
    }
    if attachments.is_empty() {
        return Ok(user_text.to_owned());
    }
    let mut composed = user_text.to_owned();
    for attachment in attachments {
        if attachment.text.len() > PLUS_ATTACH_MAX_BYTES {
            return Err(PlusHostError::Proposal(format!(
                "size-limit refusal: {} exceeds {PLUS_ATTACH_MAX_BYTES} bytes",
                attachment.relative_path.display()
            )));
        }
        composed.push_str("\n\nAttached ");
        composed.push_str(&attachment.relative_path.display().to_string());
        composed.push_str(":\n");
        composed.push_str(&attachment.text);
    }
    Ok(composed)
}

/// Short `list_dir` of the bound root, capped by entry count and bytes.
#[must_use]
pub fn plus_directory_sketch(bound: &BoundProject) -> String {
    match plus_tool_list_dir(bound, ".") {
        Ok(listing) => cap_directory_sketch(&listing),
        Err(error) => format!("{PLUS_SKETCH_SKIPPED}: {error}"),
    }
}

/// Attachments plus a capped directory sketch for the shipped Send path.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when attachments exceed the file or
/// size caps. An oversize sketch is truncated with a notice, not dumped.
pub fn plus_compose_send_context(
    bound: &BoundProject,
    user_text: &str,
    attachments: &[PlusAttachment],
) -> Result<String, PlusHostError> {
    let composed = plus_compose_user_with_attachments(user_text, attachments)?;
    let sketch = plus_directory_sketch(bound);
    Ok(format!("{composed}\n\nDirectory sketch:\n{sketch}"))
}

fn cap_directory_sketch(listing: &str) -> String {
    let mut names: Vec<&str> = listing.lines().collect();
    let mut truncated = false;
    if names.len() > PLUS_SKETCH_MAX_ENTRIES {
        names.truncate(PLUS_SKETCH_MAX_ENTRIES);
        truncated = true;
    }
    let mut out = names.join("\n");
    if out.len() > PLUS_SKETCH_MAX_BYTES {
        let mut end = PLUS_SKETCH_MAX_BYTES;
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        truncated = true;
    }
    if truncated {
        format!("{out}\n{PLUS_SKETCH_TRUNCATED}")
    } else {
        out
    }
}
