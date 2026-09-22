//! Explicit live-runtime adapters and their secret/process boundaries.

pub(crate) mod account_preferences;
pub(crate) mod acp;
pub(crate) mod auth_paths;
pub(crate) mod cancel;
pub(crate) mod cli;
pub(crate) mod cli_images;
pub(crate) mod cli_interactions;
#[cfg(test)]
mod cli_interactions_tests;
pub(crate) mod cli_permissions;
mod collaboration_tools;
pub(crate) mod conversation;
pub(crate) mod engine;
mod extension_tools;
pub(crate) mod keychain;
pub(crate) mod manager;
pub(crate) mod models;
pub(crate) mod native_protocol;
pub(crate) mod native_secret;
pub(crate) mod oauth_tts;
pub(crate) mod responses;
mod role_tools;
pub(crate) mod system_process;
pub(crate) mod types;
pub(crate) mod xai;
