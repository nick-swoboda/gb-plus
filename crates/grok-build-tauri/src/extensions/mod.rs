//! App-owned extension admission. Provider input never installs or enables code.

mod archive;
mod content;
mod credentials;
pub(crate) mod hooks;
mod manifest;
pub(crate) mod mcp;
pub(crate) mod protected_sources;
mod service_views;
mod store;

#[cfg(test)]
pub(crate) use manifest::ComponentKind;
pub(crate) use manifest::ExtensionPreview;
pub(crate) use store::{ExtensionStore, ExtensionView};

fn digest(bytes: &[u8]) -> String {
    grok_build_plus_host::worktree_recovery_digest(bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests;
