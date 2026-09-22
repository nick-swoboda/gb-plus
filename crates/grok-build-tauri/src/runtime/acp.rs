//! Strict Grok CLI ACP adapter with no client machine capabilities.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use grok_build_plus_host::{
    PendingFileSet, PlusExternalToolExecutor, PlusToolLifecycleEvent, PlusToolStep,
    plus_tool_acp_name_clause, present_plus_tool_steps, worktree_recovery_digest,
};
#[cfg(test)]
use grok_build_plus_host::{PlusHostError, PlusToolRequest, parse_plus_live_tool_reply};
use serde_json::{Value, json};

use crate::child_environment::ChildEnvironmentProfile;
use crate::contracts::ProviderSessionId;

use super::cancel::RuntimeCancelHandle;
use super::types::{
    AdapterContext, AdapterFailure, AdapterFailureKind, AdapterImage, AdapterProbe, AdapterSession,
    AdapterTurn, AdapterTurnOutcome, LiveRuntimeAdapter, RuntimeEvent, RuntimeEventSink,
    RuntimeSteeringSource, RuntimeTransport, RuntimeUsage,
};

const ACP_PROFILE_FILE: &str = "grok-build-plus-gui.md";
const ACP_NEUTRAL_CWD: &str = "neutral-cwd";
const ACP_MAX_LINE_BYTES: usize = 12 * 1024 * 1024;
const ACP_MAX_IMAGE_BASE64_BYTES: usize = 8 * 1024 * 1024;
const ACP_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const ACP_CANCEL_POLL: Duration = Duration::from_millis(100);
const ACP_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const ACP_MAX_RESPONSE_MESSAGES: usize = 4_096;
const ACP_MAX_ASSISTANT_BYTES: usize = 4 * 1024 * 1024;
const ACP_OAUTH_TIMEOUT: Duration = Duration::from_mins(5);
const ACP_OAUTH_OUTPUT_STREAM_CAP: usize = 32 * 1024;
const ACP_OAUTH_LOG_CAP: usize = 64 * 1024;
const ACP_PROBE_PROMPT: &str =
    "GB Plus connection check. Reply with a short acknowledgement. No tools are available.";
#[cfg(test)]
const ACP_APP_TOOL_RESULTS_HEADING: &str = "GB Plus app-owned tool results:";

mod capabilities;
mod invocations;
mod isolation;
mod mcp;
#[cfg(target_os = "macos")]
pub(crate) mod memory_home;
mod mirror;
mod models;
mod native_edit;
mod native_ui;
mod oauth;
mod process;
mod protocol;
mod session;
pub(crate) mod standard;
mod standard_idle;
pub(crate) mod standard_smoke;
mod steering;
pub(super) mod tools;

pub(crate) use oauth::{GrokCliOAuthPhase, run_grok_cli_oauth};
pub(crate) use process::AcpLaunchConfig;
pub(crate) use protocol::strict_acp_profile;
pub(crate) use session::GrokCliAcpAdapter;

#[cfg(test)]
use oauth::{run_grok_cli_oauth_at, sanitize_oauth_output};
#[cfg(test)]
use process::read_bounded_json_line;
#[cfg(test)]
use protocol::{
    acp_prompt_content, bounded_event_discriminator, emit_acp_context_usage,
    handle_strict_session_notification, validate_active_session, validate_announcements_update,
    validate_available_commands_update, validate_cli_queue_is_not_owning_work,
    validate_models_update, validate_prompt_complete, validate_provisional_session_update,
    validate_session_info_update, validate_session_new_result, validate_sessions_changed,
    validate_settings_update, validate_user_message_chunk, validate_zero_mcp_notification,
};
#[cfg(test)]
use session::validate_authoritative_prompt_result;
#[cfg(test)]
use tools::{
    AcpAppToolReply, classify_acp_app_tool_reply, classify_acp_failure,
    compose_acp_app_tool_follow_up, present_acp_assistant_boundary,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod standard_tests;

#[cfg(all(test, target_os = "macos"))]
mod live_tests;

#[cfg(test)]
#[path = "acp/tests/native_ui.rs"]
mod native_ui_tests;

#[cfg(test)]
#[path = "acp/tests/standard_idle.rs"]
mod standard_idle_tests;
