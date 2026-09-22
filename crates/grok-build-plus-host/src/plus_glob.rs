//! Host filename glob for GB Plus Send.
//!
//! Lists bound-folder paths by name/path pattern. This is not content
//! `grep` and does not spawn a shell or call ripgrep.

use std::path::Path;

use super::plus_walk::collect_search_files;
use super::{BoundProject, PlusHostError};

/// Hard cap on paths returned by [`plus_tool_glob`].
pub const PLUS_GLOB_MAX_MATCHES: usize = 100;

/// Hard cap on files considered during one `glob` walk.
pub const PLUS_GLOB_MAX_WALKED: usize = 4096;

/// Notice when `glob` hit a cap instead of dumping the tree.
pub const PLUS_GLOB_TRUNCATED: &str = "glob truncated";

/// Phrase when `glob` finds no matching path.
pub const PLUS_GLOB_NO_MATCHES: &str = "no matching paths";

/// Lists relative workspace files whose names or paths match `pattern`.
///
/// The pattern is a glob (`*`, `?`, `**`, `{a,b}`). There is no content
/// needle. The walk uses the same bound-folder guards as `list_dir` /
/// `read_file`.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the pattern is empty or
/// malformed, or the path escapes the bound folder.
pub fn plus_tool_glob(
    bound: &BoundProject,
    pattern: &str,
    relative: impl AsRef<Path>,
) -> Result<String, PlusHostError> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(PlusHostError::Proposal(
            "glob requires a non-empty pattern".into(),
        ));
    }
    validate_glob_pattern(pattern)?;
    let relative = relative.as_ref();
    let mut files = Vec::new();
    collect_search_files(bound.folder(), relative, &mut files)?;
    let mut truncated = files.len() > PLUS_GLOB_MAX_WALKED;
    if files.len() > PLUS_GLOB_MAX_WALKED {
        files.truncate(PLUS_GLOB_MAX_WALKED);
    }
    let mut hits = Vec::new();
    for (index, relative_file) in files.iter().enumerate() {
        let shown = relative_workspace_path(relative_file);
        if !glob_path_matches(pattern, &shown) {
            continue;
        }
        hits.push(shown);
        if hits.len() >= PLUS_GLOB_MAX_MATCHES {
            if index + 1 < files.len() {
                truncated = true;
            }
            break;
        }
    }
    if hits.is_empty() {
        let mut out = format!("{PLUS_GLOB_NO_MATCHES} for {pattern}");
        if truncated {
            out.push('\n');
            out.push_str(PLUS_GLOB_TRUNCATED);
        }
        return Ok(out);
    }
    let mut out = hits.join("\n");
    if truncated {
        out.push('\n');
        out.push_str(PLUS_GLOB_TRUNCATED);
    }
    Ok(out)
}

fn relative_workspace_path(relative: &Path) -> String {
    let shown = relative.display().to_string().replace('\\', "/");
    shown.trim_start_matches("./").to_owned()
}

fn validate_glob_pattern(pattern: &str) -> Result<(), PlusHostError> {
    let mut depth = 0_i32;
    for character in pattern.chars() {
        match character {
            '{' => depth += 1,
            '}' => {
                if depth == 0 {
                    return Err(malformed_glob());
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(malformed_glob());
    }
    Ok(())
}

fn malformed_glob() -> PlusHostError {
    PlusHostError::Proposal("glob pattern is malformed".into())
}

fn glob_path_matches(pattern: &str, relative: &str) -> bool {
    for alternative in expand_braces(pattern) {
        let alternative = alternative.replace('\\', "/");
        if match_glob(&alternative, relative) {
            return true;
        }
        if !alternative.contains('/')
            && let Some(name) = relative.rsplit('/').next()
            && match_glob(&alternative, name)
        {
            return true;
        }
    }
    false
}

fn expand_braces(pattern: &str) -> Vec<String> {
    expand_braces_one(pattern).unwrap_or_else(|()| vec![pattern.to_owned()])
}

fn expand_braces_one(pattern: &str) -> Result<Vec<String>, ()> {
    let Some(start) = pattern.find('{') else {
        return Ok(vec![pattern.to_owned()]);
    };
    let bytes = pattern.as_bytes();
    let mut depth = 0_i32;
    let mut parts = vec![String::new()];
    let mut end = None;
    let mut index = start + 1;
    while index < pattern.len() {
        let character = bytes[index] as char;
        match character {
            '{' => {
                depth += 1;
                parts
                    .last_mut()
                    .expect("brace parts stay non-empty")
                    .push(character);
            }
            '}' => {
                if depth == 0 {
                    end = Some(index);
                    break;
                }
                depth -= 1;
                parts
                    .last_mut()
                    .expect("brace parts stay non-empty")
                    .push(character);
            }
            ',' if depth == 0 => parts.push(String::new()),
            _ => parts
                .last_mut()
                .expect("brace parts stay non-empty")
                .push(character),
        }
        index += 1;
    }
    let end = end.ok_or(())?;
    let prefix = &pattern[..start];
    let suffix = &pattern[end + 1..];
    let mut out = Vec::new();
    for part in parts {
        let combined = format!("{prefix}{part}{suffix}");
        out.extend(expand_braces_one(&combined)?);
    }
    Ok(out)
}

fn match_glob(pattern: &str, text: &str) -> bool {
    match_glob_bytes(pattern.as_bytes(), text.as_bytes())
}

fn match_glob_bytes(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern.starts_with(b"**/") {
        if match_glob_bytes(&pattern[3..], text) {
            return true;
        }
        for (index, byte) in text.iter().enumerate() {
            if *byte == b'/' && match_glob_bytes(&pattern[3..], &text[index + 1..]) {
                return true;
            }
        }
        return false;
    }
    if pattern == b"**" {
        return true;
    }
    if pattern.starts_with(b"**") {
        for index in 0..=text.len() {
            if match_glob_bytes(&pattern[2..], &text[index..]) {
                return true;
            }
        }
        return false;
    }
    if pattern[0] == b'*' {
        if match_glob_bytes(&pattern[1..], text) {
            return true;
        }
        if !text.is_empty() && text[0] != b'/' {
            return match_glob_bytes(pattern, &text[1..]);
        }
        return false;
    }
    if pattern[0] == b'?' {
        if text.is_empty() || text[0] == b'/' {
            return false;
        }
        return match_glob_bytes(&pattern[1..], &text[1..]);
    }
    !text.is_empty() && text[0] == pattern[0] && match_glob_bytes(&pattern[1..], &text[1..])
}
