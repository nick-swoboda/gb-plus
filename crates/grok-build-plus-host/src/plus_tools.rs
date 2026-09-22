//! Bounded GB Plus tool loop used by Chat Send.
//!
//! `propose_write` stages a pending proposal and does not write. `run_contained`
//! is the existing contained entry, not a new execution authority.

use std::fmt::{self, Display, Formatter};
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{Value, json};

use super::plus_command_security::plus_contained_command_with_security_typed;
use super::plus_glob::plus_tool_glob;
use super::plus_guest::probe_plus_guest_lifecycle;
use super::plus_mode::PlusSessionMode;
use super::plus_proposal::{
    open_workspace_directory, propose_pending_file, read_workspace_file_bytes,
};
use super::plus_todo::{
    encode_plus_todo_args, plus_todo_updates_from_args, plus_todo_write, present_plus_todos,
};
use super::plus_walk::collect_search_files;
use super::{
    BoundProject, PendingFileProposal, PendingFileSet, PlusHostError, PlusSessionStore,
    PresentedCommandOutcome, plus_gui_contained_command, plus_gui_contained_command_outcome,
};

/// Seed file the Fake script reads when the test or smoke wrote it.
pub const PLUS_TOOL_NOTE_PATH: &str = "plus-tool-note.txt";

/// Relative path the Fake script proposes. Must stay unwritten until Accept.
pub const PLUS_TOOL_PROPOSE_PATH: &str = "plus-tool-proposed.txt";

/// Hard cap on tools per Send.
pub const PLUS_MAX_TOOL_STEPS: usize = 8;

/// Read size cap so attach/read cannot dump a huge file into chat.
pub const PLUS_MAX_READ_BYTES: usize = 64 * 1024;

/// Phrase when live text contains no tool lines.
pub const PLUS_TOOL_LOOP_NOT_RUN: &str = "tool loop not run: live response had no tool requests";

/// Phrase proving `propose_write` did not touch disk.
pub const PLUS_TOOL_NOT_WRITTEN: &str = "not written";

/// Trail wording when a tool ran without a host error.
pub const PLUS_TOOL_COMPLETED: &str = "completed";

/// Trail wording when a tool returned a host error.
pub const PLUS_TOOL_FAILED: &str = "failed";

/// Hard cap on content matches returned by [`plus_tool_grep`].
pub const PLUS_SEARCH_MAX_MATCHES: usize = 200;

/// Hard cap on files opened during one `grep`.
pub const PLUS_SEARCH_MAX_FILES: usize = 256;

/// Notice when `grep` hit a cap instead of dumping the tree.
pub const PLUS_SEARCH_TRUNCATED: &str = "search truncated";

/// Phrase when `grep` finds no matching line.
pub const PLUS_SEARCH_NO_MATCHES: &str = "no matches";

/// Explicit live error when the reply attempts tools but fails the format.
pub const PLUS_LIVE_TOOL_PARSE_ERROR: &str = "live tool protocol parse error";

const PLUS_LIVE_TOOL_INSTRUCTIONS_PREFIX: &str = "GB Plus live tool protocol. Use only ";
const PLUS_LIVE_TOOL_INSTRUCTIONS_SUFFIX: &str = ". Emit native function calls with those names, or one plus_tool NAME {json} line per call, or a plus_tools JSON array. propose_write requires both path and after; after is the complete exact UTF-8 replacement text and is never defaulted. propose_replace requires path, old, and new. Browser and Desktop Control require separate explicit project/run-bound grants and never imply Command security On. Desktop coordinates are relative to the exact armed frontmost window; every input is refused on permission, focus, PID, window, display, or geometry drift. A successful desktop tool result means only that a bounded event was posted after exact pre/post validation, not that the target application completed it. Browser content and desktop input text are transient and omitted from the persisted chat transcript. grep/glob are bounded reads; propose_write/propose_replace remain staged until Accept; run_contained stays on the permit/containment spine. Unknown names, missing required fields, or malformed JSON are rejected. Plain prose with no tool requests is allowed.";

/// The only tools Send may request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusToolName {
    /// Read one relative workspace file.
    ReadFile,
    /// List one relative workspace directory.
    ListDir,
    /// Search file contents under a relative path (host walk, not a shell).
    Grep,
    /// List bound-folder paths by name/path pattern (host walk, not a shell).
    Glob,
    /// Stage a pending proposal. Does not write.
    ProposeWrite,
    /// Stage an exact search/replace. Does not write.
    ProposeReplace,
    /// Merge or replace the desktop-local todo list. Not a workspace write.
    TodoWrite,
    /// Existing contained `WorkerRunCommand` / launch-refusal path.
    RunContained,
    /// Navigate the separately armed app-owned Browser context.
    BrowserNavigate,
    /// Return bounded DOM/action state from the armed Browser context.
    BrowserInspect,
    /// Click one current bounded Browser node identity.
    BrowserClick,
    /// Type bounded text into one current editable Browser node.
    BrowserType,
    /// Send one fixed-allowlist Browser key.
    BrowserKey,
    /// Scroll the armed Browser viewport by a bounded delta.
    BrowserScroll,
    /// Refresh the in-app Browser screenshot and bounded DOM state.
    BrowserScreenshot,
    /// Click a bounded coordinate relative to the separately armed window.
    DesktopClick,
    /// Post bounded Unicode text to the separately armed PID/window.
    DesktopType,
    /// Post one fixed-allowlist key/chord to the separately armed PID/window.
    DesktopKey,
    /// Post one bounded two-axis scroll to the separately armed PID/window.
    DesktopScroll,
}

/// Host-side effect class; it does not grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolClass {
    /// Bounded workspace read.
    WorkspaceRead,
    /// Accept-gated file proposal.
    Proposal,
    /// App-owned non-workspace state.
    LocalState,
    /// Existing permit/containment command path.
    ContainedCommand,
    /// Separately granted Browser action.
    Browser,
    /// Separately granted Desktop action.
    Desktop,
}

/// Independent authority required before dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolGrant {
    /// No high-power grant; other typed policy still applies.
    None,
    /// Command-security permit/containment path.
    CommandSecurity,
    /// Project/run-bound Browser grant.
    Browser,
    /// PID/window-bound Desktop grant.
    Desktop,
}

/// Provider protocol surfaces that may request a tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolProtocolAvailability {
    /// Native Responses and strict ACP text continuation.
    NativeAndAcp,
}

/// Immutable projection data for one app-owned tool.
pub struct ToolDescriptor {
    /// Typed dispatch identity.
    pub name: PlusToolName,
    /// Exact provider and text-protocol name.
    pub wire_name: &'static str,
    /// Effect class.
    pub class: ToolClass,
    /// Independent grant class.
    pub grant: ToolGrant,
    /// Bounded label safe for persisted metadata.
    pub persistence_safe_label: &'static str,
    /// Admitted provider protocols.
    pub protocol: ToolProtocolAvailability,
    schema_builder: fn(&ToolDescriptor, Value) -> Value,
}

macro_rules! descriptor {
    ($name:ident, $wire:literal, $class:ident, $grant:ident) => {
        ToolDescriptor {
            name: PlusToolName::$name,
            wire_name: $wire,
            class: ToolClass::$class,
            grant: ToolGrant::$grant,
            persistence_safe_label: $wire,
            protocol: ToolProtocolAvailability::NativeAndAcp,
            schema_builder: bind_provider_schema,
        }
    };
}

/// The sole ordered app-tool catalog.
pub static PLUS_TOOL_DESCRIPTORS: &[ToolDescriptor] = &[
    descriptor!(ListDir, "list_dir", WorkspaceRead, None),
    descriptor!(ReadFile, "read_file", WorkspaceRead, None),
    descriptor!(Grep, "grep", WorkspaceRead, None),
    descriptor!(Glob, "glob", WorkspaceRead, None),
    descriptor!(ProposeWrite, "propose_write", Proposal, None),
    descriptor!(ProposeReplace, "propose_replace", Proposal, None),
    descriptor!(TodoWrite, "todo_write", LocalState, None),
    descriptor!(
        RunContained,
        "run_contained",
        ContainedCommand,
        CommandSecurity
    ),
    descriptor!(BrowserNavigate, "browser_navigate", Browser, Browser),
    descriptor!(BrowserInspect, "browser_inspect", Browser, Browser),
    descriptor!(BrowserClick, "browser_click", Browser, Browser),
    descriptor!(BrowserType, "browser_type", Browser, Browser),
    descriptor!(BrowserKey, "browser_key", Browser, Browser),
    descriptor!(BrowserScroll, "browser_scroll", Browser, Browser),
    descriptor!(BrowserScreenshot, "browser_screenshot", Browser, Browser),
    descriptor!(DesktopClick, "desktop_click", Desktop, Desktop),
    descriptor!(DesktopType, "desktop_type", Desktop, Desktop),
    descriptor!(DesktopKey, "desktop_key", Desktop, Desktop),
    descriptor!(DesktopScroll, "desktop_scroll", Desktop, Desktop),
];

impl PlusToolName {
    /// Wire / UI spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.descriptor().wire_name
    }

    #[must_use]
    /// Parses one exact catalog wire name.
    pub fn from_wire(value: &str) -> Option<Self> {
        PLUS_TOOL_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.wire_name == value)
            .map(|descriptor| descriptor.name)
    }

    #[must_use]
    /// Returns this tool's catalog entry.
    ///
    /// # Panics
    ///
    /// Panics only if the exhaustive static catalog omits this enum variant.
    pub fn descriptor(self) -> &'static ToolDescriptor {
        PLUS_TOOL_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.name == self)
            .expect("every PlusToolName has one descriptor")
    }

    /// Whether this request must use the separately armed Tauri Browser
    /// dispatcher instead of a desktop filesystem or command function.
    #[must_use]
    pub fn is_browser(self) -> bool {
        self.descriptor().grant == ToolGrant::Browser
    }

    /// Whether this request must use the separately armed Tauri Desktop
    /// Control dispatcher instead of a desktop filesystem or command function.
    #[must_use]
    pub fn is_desktop(self) -> bool {
        self.descriptor().grant == ToolGrant::Desktop
    }

    /// Whether this request belongs to an independent high-power grant spine.
    #[must_use]
    pub fn is_external(self) -> bool {
        self.is_browser() || self.is_desktop()
    }
}

#[must_use]
/// Returns the exact native instruction name clause.
pub fn plus_tool_name_clause() -> &'static str {
    static CLAUSE: OnceLock<String> = OnceLock::new();
    CLAUSE.get_or_init(|| {
        let Some((last, leading)) = PLUS_TOOL_DESCRIPTORS.split_last() else {
            return String::new();
        };
        format!(
            "{}, and {}",
            leading
                .iter()
                .map(|descriptor| descriptor.wire_name)
                .collect::<Vec<_>>()
                .join(", "),
            last.wire_name
        )
    })
}

#[must_use]
/// Returns the exact line-wrapped ACP profile name clause.
pub fn plus_tool_acp_name_clause() -> &'static str {
    static CLAUSE: OnceLock<String> = OnceLock::new();
    CLAUSE.get_or_init(|| {
        let mut clause = String::new();
        for (index, descriptor) in PLUS_TOOL_DESCRIPTORS.iter().enumerate() {
            if index > 0 {
                if matches!(index, 4 | 9 | 14) {
                    clause.push_str(",\n");
                } else {
                    clause.push_str(", ");
                }
            }
            if index + 1 == PLUS_TOOL_DESCRIPTORS.len() {
                clause.push_str("and ");
            }
            clause.push_str(descriptor.wire_name);
        }
        clause
    })
}

#[must_use]
/// Returns provider instructions projected from the catalog.
pub fn plus_live_tool_instructions() -> &'static str {
    static INSTRUCTIONS: OnceLock<String> = OnceLock::new();
    INSTRUCTIONS.get_or_init(|| {
        format!(
            "{PLUS_LIVE_TOOL_INSTRUCTIONS_PREFIX}{}{PLUS_LIVE_TOOL_INSTRUCTIONS_SUFFIX}",
            plus_tool_name_clause()
        )
    })
}

/// Instructions for the durable, native Responses item protocol.
pub(crate) fn native_tool_instructions() -> &'static str {
    static INSTRUCTIONS: OnceLock<String> = OnceLock::new();
    INSTRUCTIONS.get_or_init(|| {
        plus_live_tool_instructions().replace(
            "Emit native function calls with those names, or one plus_tool NAME {json} line per call, or a plus_tools JSON array.",
            "Emit only native function_call items with those names. Textual tool commands are plain prose and never execute.",
        )
    })
}

impl Display for PlusToolName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One tool the loop should run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusToolRequest {
    /// Which tool.
    pub name: PlusToolName,
    /// Relative path (ignored for [`PlusToolName::RunContained`]).
    pub path: PathBuf,
    /// Replacement bytes for [`PlusToolName::ProposeWrite`].
    pub after: Option<Vec<u8>>,
    /// Search pattern for [`PlusToolName::Grep`] or [`PlusToolName::Glob`].
    pub query: Option<String>,
    /// Case-insensitive `grep` when true.
    pub case_insensitive: bool,
    /// Replace every `old` hit for [`PlusToolName::ProposeReplace`].
    pub replace_all: bool,
}

/// Narrow callback for high-power tools owned outside this desktop crate.
/// Returning `None` means the executor does not own the requested tool.
pub trait PlusExternalToolExecutor: Send + Sync {
    /// App-owned Grok family controller. External MCP servers cannot supply this capability.
    fn collaboration(&self) -> Option<&dyn crate::PlusCollaborationExecutor> {
        None
    }

    /// App-issued role ceiling; provider arguments never choose this value.
    fn tool_policy(&self) -> crate::PlusRuntimeToolPolicy {
        crate::PlusRuntimeToolPolicy::Parent
    }

    /// Executes one already parsed request through its independent grant spine.
    fn execute(&self, request: &PlusToolRequest) -> Option<Result<String, PlusHostError>>;

    /// Frozen app-issued extension declarations for this execution. Empty by
    /// default; metadata never grants permission to call a tool.
    ///
    /// # Errors
    /// Refuses unavailable, changed or invalid app-owned extension bindings.
    fn extension_tools(&self) -> Result<Vec<PlusExtensionTool>, PlusHostError> {
        Ok(Vec::new())
    }

    /// Dispatch an identified extension call through its independent approval
    /// broker. The provider supplies only a name and arguments; owning project,
    /// run, server and credential authority belong to this executor.
    fn execute_extension(
        &self,
        _invocation: &str,
        _name: &str,
        _arguments: &Value,
    ) -> Option<Result<Value, PlusHostError>> {
        None
    }
}

/// Bounded metadata supplied by the app's independent extension broker.
#[derive(Clone, Debug)]
pub struct PlusExtensionTool {
    /// App namespace; cannot replace a built-in tool name.
    pub name: String,
    /// Server description, treated as untrusted context.
    pub description: String,
    /// Schema text; never a source of project or execution authority.
    pub parameters: Value,
    /// Exact server/project/schema binding selected for this run.
    pub fingerprint: String,
}

impl PlusExtensionTool {
    /// Validate the representation before adding it to a provider's tool list.
    ///
    /// # Errors
    /// Refuses names outside the app namespace, unbounded text or malformed
    /// fingerprints. This check grants no permission and evaluates no schema.
    pub fn validate(&self) -> Result<(), PlusHostError> {
        let hex = |text: &str, length: usize| {
            text.len() == length
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self
            .name
            .strip_prefix("gbext_")
            .is_none_or(|name| !hex(name, super::plus_mcp::MCP_APP_TOOL_HASH_HEX_LENGTH))
            || !hex(&self.fingerprint, 64)
            || self.description.len() > 16 * 1024
            || !self.parameters.is_object()
            || serde_json::to_vec(&self.parameters)
                .map_err(|_| PlusHostError::Live("Cannot bound extension schema.".into()))?
                .len()
                > 64 * 1024
        {
            return Err(PlusHostError::Live(
                "Extension declaration has an invalid app binding or size.".into(),
            ));
        }
        Ok(())
    }
}

/// One executed step, with the real tool result text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusToolStep {
    /// Tool that ran.
    pub name: PlusToolName,
    /// Path or command shown in the UI.
    pub request: String,
    /// Real listing, file bytes, stage notice, or contained outcome.
    pub result: String,
    /// False when the host function returned [`PlusHostError`].
    pub ok: bool,
}

/// Outcome of a bounded tool loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusToolLoopReport {
    /// Steps in order, at most [`PLUS_MAX_TOOL_STEPS`].
    pub steps: Vec<PlusToolStep>,
    /// Requests that produced [`Self::steps`], in the same order.
    pub requests: Vec<PlusToolRequest>,
    /// Last successful `propose_write` / `propose_replace`, if any.
    pub pending: Option<PendingFileProposal>,
    /// Every staged path from this loop.
    pub pending_set: PendingFileSet,
}

/// Reads a relative workspace file. Does not escape the bound folder.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] on path, size, or I/O failure.
pub fn plus_tool_read_file(
    bound: &BoundProject,
    relative: impl AsRef<Path>,
) -> Result<String, PlusHostError> {
    let relative = relative.as_ref();
    let bytes = read_workspace_file_bytes(bound.folder(), relative, PLUS_MAX_READ_BYTES)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Lists a relative workspace directory. `.` is the bound root.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] on path or I/O failure.
pub fn plus_tool_list_dir(
    bound: &BoundProject,
    relative: impl AsRef<Path>,
) -> Result<String, PlusHostError> {
    let relative = relative.as_ref();
    let directory = open_workspace_directory(bound.folder(), relative)?;
    let mut names = Vec::new();
    let mut entries = rustix::fs::Dir::read_from(&directory).map_err(|error| {
        PlusHostError::Proposal(format!("cannot list {}: {error}", relative.display()))
    })?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|error| {
            PlusHostError::Proposal(format!("cannot list {}: {error}", relative.display()))
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    names.sort();
    Ok(names.join("\n"))
}

/// Searches file contents under a relative workspace path.
///
/// This is a host walk (same path guards as [`plus_tool_read_file`]), not
/// ripgrep and not a contained command. The pattern is a literal substring.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the pattern is empty or the
/// path escapes the bound folder.
pub fn plus_tool_grep(
    bound: &BoundProject,
    pattern: &str,
    relative: impl AsRef<Path>,
    case_insensitive: bool,
) -> Result<String, PlusHostError> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(PlusHostError::Proposal(
            "grep requires a non-empty pattern".into(),
        ));
    }
    let relative = relative.as_ref();
    let mut files = Vec::new();
    collect_search_files(bound.folder(), relative, &mut files)?;
    let needle = if case_insensitive {
        pattern.to_lowercase()
    } else {
        pattern.to_owned()
    };
    let mut lines = Vec::new();
    let mut searched = 0_usize;
    let mut truncated = false;
    for relative_file in files {
        let Some(bytes) = read_searchable_file(bound, &relative_file) else {
            continue;
        };
        if searched >= PLUS_SEARCH_MAX_FILES {
            truncated = true;
            break;
        }
        searched += 1;
        let text = String::from_utf8_lossy(&bytes);
        let shown = relative_file.display().to_string();
        for (index, line) in text.lines().enumerate() {
            let haystack = if case_insensitive {
                line.to_lowercase()
            } else {
                line.to_owned()
            };
            if !haystack.contains(&needle) {
                continue;
            }
            let mut content = line.to_owned();
            if content.len() > 200 {
                content.truncate(200);
            }
            lines.push(format!("{shown}:{}:{content}", index + 1));
            if lines.len() >= PLUS_SEARCH_MAX_MATCHES {
                truncated = true;
                break;
            }
        }
        if lines.len() >= PLUS_SEARCH_MAX_MATCHES {
            break;
        }
    }
    if lines.is_empty() {
        let mut out = format!("{PLUS_SEARCH_NO_MATCHES} for {pattern}");
        if truncated {
            out.push('\n');
            out.push_str(PLUS_SEARCH_TRUNCATED);
        }
        return Ok(out);
    }
    let mut out = lines.join("\n");
    if truncated {
        out.push('\n');
        out.push_str(PLUS_SEARCH_TRUNCATED);
    }
    Ok(out)
}

fn read_searchable_file(bound: &BoundProject, relative: &Path) -> Option<Vec<u8>> {
    let bytes = read_workspace_file_bytes(bound.folder(), relative, PLUS_MAX_READ_BYTES).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    Some(bytes)
}

/// Stages a pending write. Does not write the proposed bytes.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the path is invalid.
pub fn plus_tool_propose_write(
    bound: &BoundProject,
    relative: impl Into<PathBuf>,
    after: impl Into<Vec<u8>>,
) -> Result<PendingFileProposal, PlusHostError> {
    propose_pending_file(bound, relative, after)
}

/// Stages an exact search/replace. Does not write the file.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when `old` is missing, ambiguous, or
/// the path is invalid.
pub fn plus_tool_propose_replace(
    bound: &BoundProject,
    relative: impl Into<PathBuf>,
    old: &str,
    new: &str,
    replace_all: bool,
) -> Result<PendingFileProposal, PlusHostError> {
    let relative = relative.into();
    let proposal = propose_pending_file(bound, relative.clone(), Vec::new())?;
    let before = String::from_utf8_lossy(&proposal.before);
    if old.is_empty() {
        if !proposal.before.is_empty() {
            return Err(PlusHostError::Proposal(
                "propose_replace empty old cannot overwrite a non-empty file".into(),
            ));
        }
        return propose_pending_file(bound, relative, new.as_bytes().to_vec());
    }
    let hits = before.matches(old).count();
    if hits == 0 {
        return Err(PlusHostError::Proposal(format!(
            "propose_replace old not found in {}",
            relative.display()
        )));
    }
    if hits > 1 && !replace_all {
        return Err(PlusHostError::Proposal(format!(
            "propose_replace old is ambiguous ({hits} hits) in {}",
            relative.display()
        )));
    }
    let after = if replace_all {
        before.replace(old, new)
    } else {
        before.replacen(old, new, 1)
    };
    propose_pending_file(bound, relative, after.into_bytes())
}

/// Existing contained-run presentation (refusal or `WorkerRunCommand` outcome).
#[must_use]
pub fn plus_tool_run_contained(bound: &BoundProject) -> String {
    plus_gui_contained_command(bound)
}

fn plus_tool_run_contained_for_store(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
) -> PresentedCommandOutcome {
    match store {
        Some(store) => plus_contained_command_with_security_typed(
            bound,
            store.command_security_preference(),
            false,
            &probe_plus_guest_lifecycle(),
        ),
        None => plus_gui_contained_command_outcome(bound),
    }
}

fn plus_tool_run_or_skip(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
) -> (String, Option<PendingFileProposal>, bool) {
    if !mode.allows_run_contained() {
        return (
            format!("Ask mode skipped {}", PlusToolName::RunContained.as_str()),
            None,
            false,
        );
    }
    let result = plus_tool_run_contained_for_store(bound, store);
    let succeeded = result.class.is_success();
    (result.text, None, succeeded)
}

/// Deterministic Fake script: list → grep → read → propose → contained.
#[must_use]
pub fn fake_plus_tool_script() -> Vec<PlusToolRequest> {
    vec![
        PlusToolRequest {
            name: PlusToolName::ListDir,
            path: PathBuf::from("."),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::Grep,
            path: PathBuf::from("."),
            after: None,
            query: Some("tool-note".into()),
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::ReadFile,
            path: PathBuf::from(PLUS_TOOL_NOTE_PATH),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::ProposeWrite,
            path: PathBuf::from(PLUS_TOOL_PROPOSE_PATH),
            after: Some(b"Proposed by plus tool loop\n".to_vec()),
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
        PlusToolRequest {
            name: PlusToolName::RunContained,
            path: PathBuf::new(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        },
    ]
}

/// Encodes requests as `plus_tool NAME {json}` lines (the live text format).
#[must_use]
pub fn encode_plus_live_tool_requests(requests: &[PlusToolRequest]) -> String {
    let mut lines = Vec::new();
    for request in requests {
        lines.push(encode_plus_live_tool_request(request));
    }
    lines.join("\n")
}

/// One `plus_tool NAME {json}` line for a single request.
#[must_use]
pub fn encode_plus_live_tool_request(request: &PlusToolRequest) -> String {
    let args = match request.name {
        PlusToolName::ListDir | PlusToolName::ReadFile => {
            json!({ "path": request.path.display().to_string() })
        }
        PlusToolName::Grep => json!({
            "pattern": request.query.as_deref().unwrap_or(""),
            "path": request.path.display().to_string(),
            "case_insensitive": request.case_insensitive,
        }),
        PlusToolName::Glob => json!({
            "pattern": request.query.as_deref().unwrap_or(""),
            "path": request.path.display().to_string(),
        }),
        PlusToolName::ProposeWrite => json!({
            "path": request.path.display().to_string(),
            "after": String::from_utf8_lossy(request.after.as_deref().unwrap_or(b"")),
        }),
        PlusToolName::ProposeReplace => json!({
            "path": request.path.display().to_string(),
            "old": request.query.as_deref().unwrap_or(""),
            "new": String::from_utf8_lossy(request.after.as_deref().unwrap_or(b"")),
            "replace_all": request.replace_all,
        }),
        PlusToolName::TodoWrite => {
            serde_json::from_slice(request.after.as_deref().unwrap_or(b"{}"))
                .unwrap_or_else(|_| json!({"merge": request.replace_all, "todos": []}))
        }
        PlusToolName::RunContained
        | PlusToolName::BrowserInspect
        | PlusToolName::BrowserScreenshot => json!({}),
        PlusToolName::BrowserNavigate => {
            json!({ "url": request.path.display().to_string() })
        }
        PlusToolName::BrowserClick => json!({
            "node_id": request
                .path
                .to_string_lossy()
                .parse::<u64>()
                .unwrap_or_default(),
        }),
        PlusToolName::BrowserType => json!({
            "node_id": request
                .path
                .to_string_lossy()
                .parse::<u64>()
                .unwrap_or_default(),
            "text": String::from_utf8_lossy(request.after.as_deref().unwrap_or(b"")),
        }),
        PlusToolName::BrowserKey => {
            json!({ "key": request.query.as_deref().unwrap_or("") })
        }
        PlusToolName::BrowserScroll => json!({
            "delta_y": request
                .query
                .as_deref()
                .unwrap_or("0")
                .parse::<i64>()
                .unwrap_or_default(),
        }),
        PlusToolName::DesktopClick => {
            let (x, y) = encoded_pair_f64(&request.path);
            json!({
                "x": x,
                "y": y,
                "button": request.query.as_deref().unwrap_or("left"),
            })
        }
        PlusToolName::DesktopType => json!({
            "text": String::from_utf8_lossy(request.after.as_deref().unwrap_or(b"")),
        }),
        PlusToolName::DesktopKey => json!({
            "key": request.path.to_string_lossy(),
            "modifiers": request
                .query
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter(|modifier| !modifier.is_empty())
                .collect::<Vec<_>>(),
        }),
        PlusToolName::DesktopScroll => {
            let (delta_x, delta_y) = encoded_pair_i64(&request.path);
            json!({ "delta_x": delta_x, "delta_y": delta_y })
        }
    };
    format!("plus_tool {} {args}", request.name.as_str())
}

fn encoded_pair_f64(path: &Path) -> (f64, f64) {
    path.to_str()
        .and_then(|value| value.split_once(','))
        .and_then(|(first, second)| Some((first.parse::<f64>().ok()?, second.parse::<f64>().ok()?)))
        .unwrap_or_default()
}

fn encoded_pair_i64(path: &Path) -> (i64, i64) {
    path.to_str()
        .and_then(|value| value.split_once(','))
        .and_then(|(first, second)| Some((first.parse::<i64>().ok()?, second.parse::<i64>().ok()?)))
        .unwrap_or_default()
}

fn bind_provider_schema(descriptor: &ToolDescriptor, mut schema: Value) -> Value {
    schema["name"] = Value::String(descriptor.wire_name.to_owned());
    schema
}

/// Tool declarations placed on the live `/v1/responses` request.
#[must_use]
pub fn plus_live_tool_declarations() -> Value {
    let Value::Array(templates) = plus_live_tool_schema_templates() else {
        unreachable!("the typed provider schemas are an array")
    };
    if templates.len() != PLUS_TOOL_DESCRIPTORS.len() {
        return Value::Array(Vec::new());
    }
    Value::Array(
        PLUS_TOOL_DESCRIPTORS
            .iter()
            .zip(templates)
            .map(|(descriptor, template)| (descriptor.schema_builder)(descriptor, template))
            .collect(),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the provider schema keeps every admitted tool and bounded field explicit in one reviewable declaration"
)]
fn plus_live_tool_schema_templates() -> Value {
    json!([
        {
            "type": "function",
            "description": "List a relative workspace directory. Path \".\" is the bound root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace-relative directory" }
                },
                "required": ["path"]
            }
        },
        {
            "type": "function",
            "description": "Read a relative workspace file. Cap 64 KiB. Does not write.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace-relative file" }
                },
                "required": ["path"]
            }
        },
        {
            "type": "function",
            "description": "Search file contents under a relative workspace path. Literal pattern. Does not write and does not spawn a shell.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Literal substring to find" },
                    "path": { "type": "string", "description": "Workspace-relative file or directory. Default ." },
                    "case_insensitive": { "type": "boolean" }
                },
                "required": ["pattern"]
            }
        },
        {
            "type": "function",
            "description": "List relative workspace files by name or path pattern. No content needle. Does not write and does not spawn a shell.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Filename or path glob (* ? ** {a,b})" },
                    "path": { "type": "string", "description": "Workspace-relative file or directory. Default ." }
                },
                "required": ["pattern"]
            }
        },
        {
            "type": "function",
            "description": "Stage a pending file proposal. Does not write disk until Accept.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace-relative file" },
                    "after": { "type": "string", "description": "Proposed replacement text" }
                },
                "required": ["path", "after"]
            }
        },
        {
            "type": "function",
            "description": "Stage an exact search/replace as a pending file. Does not write disk until Accept. If old appears more than once, set replace_all or make old unique.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "old": { "type": "string", "description": "Exact text to replace" },
                    "new": { "type": "string", "description": "Replacement text" },
                    "replace_all": { "type": "boolean" }
                },
                "required": ["path", "old", "new"]
            }
        },
        {
            "type": "function",
            "description": "Merge or replace the in-turn todo list on the plus state root. Not a workspace write. Does not skip Accept.",
            "parameters": {
                "type": "object",
                "properties": {
                    "merge": { "type": "boolean", "description": "true merges by id; false replaces the list" },
                    "todos": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string" },
                                "content": { "type": "string" },
                                "status": { "type": "string", "description": "pending, in_progress, or completed" }
                            },
                            "required": ["id"]
                        }
                    }
                },
                "required": ["todos"]
            }
        },
        {
            "type": "function",
            "description": "Run the existing contained WorkerRunCommand / launch-refusal path.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "type": "function",
            "description": "Navigate the separately armed project/run-bound Browser to an explicit HTTP(S) URL.",
            "parameters": {
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"]
            }
        },
        {
            "type": "function",
            "description": "Read bounded transient DOM text and interactive node identities from the armed Browser.",
            "parameters": { "type": "object", "properties": {} }
        },
        {
            "type": "function",
            "description": "Click one current node identity returned by browser_inspect.",
            "parameters": {
                "type": "object",
                "properties": { "node_id": { "type": "integer", "minimum": 1, "maximum": 1_000_000 } },
                "required": ["node_id"]
            }
        },
        {
            "type": "function",
            "description": "Type bounded text into one current editable Browser node. Does not press Enter.",
            "parameters": {
                "type": "object",
                "properties": {
                    "node_id": { "type": "integer", "minimum": 1, "maximum": 1_000_000 },
                    "text": { "type": "string", "maxLength": 4096 }
                },
                "required": ["node_id", "text"]
            }
        },
        {
            "type": "function",
            "description": "Send one fixed-allowlist key to the focused Browser element.",
            "parameters": {
                "type": "object",
                "properties": { "key": { "type": "string" } },
                "required": ["key"]
            }
        },
        {
            "type": "function",
            "description": "Scroll the armed Browser viewport by a bounded vertical delta.",
            "parameters": {
                "type": "object",
                "properties": { "delta_y": { "type": "integer", "minimum": -2000, "maximum": 2000 } },
                "required": ["delta_y"]
            }
        },
        {
            "type": "function",
            "description": "Refresh the visible in-app Browser screenshot and bounded DOM state.",
            "parameters": { "type": "object", "properties": {} }
        },
        {
            "type": "function",
            "description": "Post one click at a coordinate relative to the exact armed frontmost window. Refuses on permission, focus, PID, window, display, or geometry drift.",
            "parameters": {
                "type": "object",
                "properties": {
                    "x": { "type": "number", "minimum": 0, "maximum": 100_000 },
                    "y": { "type": "number", "minimum": 0, "maximum": 100_000 },
                    "button": { "type": "string", "enum": ["left", "right", "center"] }
                },
                "required": ["x", "y"]
            }
        },
        {
            "type": "function",
            "description": "Post bounded Unicode text to the exact armed PID/window. Does not press Enter and is never persisted in tool output.",
            "parameters": {
                "type": "object",
                "properties": { "text": { "type": "string", "minLength": 1, "maxLength": 4096 } },
                "required": ["text"]
            }
        },
        {
            "type": "function",
            "description": "Post one fixed-allowlist key or modifier chord to the exact armed PID/window.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "One alphanumeric key or Enter, Tab, Escape, Backspace, Delete, Space, ArrowUp/Down/Left/Right, Home, End, PageUp, or PageDown" },
                    "modifiers": {
                        "type": "array",
                        "maxItems": 4,
                        "uniqueItems": true,
                        "items": { "type": "string", "enum": ["command", "control", "option", "shift"] }
                    }
                },
                "required": ["key"]
            }
        },
        {
            "type": "function",
            "description": "Post one bounded two-axis pixel scroll to the exact armed PID/window.",
            "parameters": {
                "type": "object",
                "properties": {
                    "delta_x": { "type": "integer", "minimum": -2000, "maximum": 2000 },
                    "delta_y": { "type": "integer", "minimum": -2000, "maximum": 2000 }
                },
                "required": ["delta_x", "delta_y"]
            }
        }
    ])
}

/// Parses live tool requests from assistant text and optional native calls.
///
/// Empty with no attempt markers is `Ok([])` (loop not run). An attempted
/// but invalid payload is [`PlusHostError::Live`].
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when the reply attempts tools but fails
/// the defined format.
pub fn parse_plus_live_tool_reply(
    text: &str,
    function_calls: &[(String, String)],
) -> Result<Vec<PlusToolRequest>, PlusHostError> {
    if !function_calls.is_empty() {
        if function_calls.len() > PLUS_MAX_TOOL_STEPS {
            return Err(live_tool_parse_error(&format!(
                "tool request count exceeds the {PLUS_MAX_TOOL_STEPS}-step cap"
            )));
        }
        let mut requests = Vec::new();
        for (name, arguments_json) in function_calls {
            requests.push(plus_tool_request_from_name_and_args(name, arguments_json)?);
        }
        return Ok(requests);
    }
    parse_live_tool_requests(text)
}

/// Parses the live text format: `plus_tool` lines, a `plus_tools` JSON
/// array, or well-formed legacy `tool <name>` lines.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when the text attempts tools but is not
/// valid. A reply with no attempt markers returns an empty list.
pub fn parse_live_tool_requests(text: &str) -> Result<Vec<PlusToolRequest>, PlusHostError> {
    if let Some(from_block) = parse_plus_tools_json_block(text) {
        return from_block;
    }
    let mut requests = Vec::new();
    let mut attempted = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !line_attempts_live_tool(trimmed) {
            continue;
        }
        attempted = true;
        let request = parse_one_live_tool_line(trimmed)?;
        requests.push(request);
        if requests.len() > PLUS_MAX_TOOL_STEPS {
            return Err(live_tool_parse_error(&format!(
                "tool request count exceeds the {PLUS_MAX_TOOL_STEPS}-step cap"
            )));
        }
    }
    if attempted && requests.is_empty() {
        return Err(live_tool_parse_error(
            "tool attempt produced no valid requests",
        ));
    }
    Ok(requests)
}

fn line_attempts_live_tool(line: &str) -> bool {
    line == "plus_tool"
        || line == "tool"
        || line.starts_with("plus_tool ")
        || line.starts_with("tool ")
}

fn parse_plus_tools_json_block(text: &str) -> Option<Result<Vec<PlusToolRequest>, PlusHostError>> {
    if !text.contains("\"plus_tools\"") {
        return None;
    }
    if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
        return Some(requests_from_plus_tools_value(&value));
    }
    let Some(start) = text.find('{') else {
        return Some(Err(live_tool_parse_error(
            "plus_tools marker present without a JSON object",
        )));
    };
    let slice = &text[start..];
    if let Some(end) = slice.rfind('}') {
        let candidate = &slice[..=end];
        if let Ok(value) = serde_json::from_str::<Value>(candidate) {
            return Some(requests_from_plus_tools_value(&value));
        }
    }
    Some(Err(live_tool_parse_error("plus_tools JSON is not valid")))
}

fn requests_from_plus_tools_value(value: &Value) -> Result<Vec<PlusToolRequest>, PlusHostError> {
    let items = value
        .get("plus_tools")
        .and_then(Value::as_array)
        .ok_or_else(|| live_tool_parse_error("plus_tools must be a JSON array"))?;
    if items.len() > PLUS_MAX_TOOL_STEPS {
        return Err(live_tool_parse_error(&format!(
            "tool request count exceeds the {PLUS_MAX_TOOL_STEPS}-step cap"
        )));
    }
    let mut requests = Vec::new();
    for item in items {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| live_tool_parse_error("plus_tools item is missing name"))?;
        let args = match item {
            Value::Object(map) => {
                let mut object = serde_json::Map::new();
                for (key, val) in map {
                    if key != "name" {
                        object.insert(key.clone(), val.clone());
                    }
                }
                Value::Object(object)
            }
            _ => json!({}),
        };
        requests.push(plus_tool_request_from_name_and_value(name, &args)?);
    }
    Ok(requests)
}

fn parse_one_live_tool_line(line: &str) -> Result<PlusToolRequest, PlusHostError> {
    if let Some(rest) = line.strip_prefix("plus_tool") {
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(live_tool_parse_error("plus_tool line is missing a name"));
        }
        let (name, args) = rest
            .split_once(char::is_whitespace)
            .map_or((rest, "{}"), |(name, args)| (name, args.trim()));
        return plus_tool_request_from_name_and_args(name, args);
    }
    if let Some(rest) = line.strip_prefix("tool") {
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(live_tool_parse_error("tool line is missing a name"));
        }
        let mut parts = rest.splitn(3, ' ');
        let name = parts
            .next()
            .ok_or_else(|| live_tool_parse_error("tool line is missing a name"))?;
        let path = parts.next();
        let after = parts.next();
        return plus_tool_request_from_legacy_parts(name, path, after);
    }
    Err(live_tool_parse_error("line is not a live tool request"))
}

fn plus_tool_request_from_legacy_parts(
    name: &str,
    path: Option<&str>,
    after: Option<&str>,
) -> Result<PlusToolRequest, PlusHostError> {
    let Some(tool_name) = PlusToolName::from_wire(name) else {
        return Err(live_tool_parse_error(&format!("unknown tool {name}")));
    };
    match tool_name {
        PlusToolName::ListDir => Ok(PlusToolRequest {
            name: PlusToolName::ListDir,
            path: PathBuf::from(path.unwrap_or(".")),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        }),
        PlusToolName::ReadFile => {
            let path = path.ok_or_else(|| live_tool_parse_error("read_file requires path"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::ReadFile,
                path: PathBuf::from(path),
                after: None,
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::Grep => {
            let pattern = path.ok_or_else(|| live_tool_parse_error("grep requires pattern"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::Grep,
                path: PathBuf::from(after.unwrap_or(".")),
                after: None,
                query: Some(pattern.to_owned()),
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::Glob => {
            let pattern = path.ok_or_else(|| live_tool_parse_error("glob requires pattern"))?;
            if pattern.trim().is_empty() {
                return Err(live_tool_parse_error("glob requires pattern"));
            }
            Ok(PlusToolRequest {
                name: PlusToolName::Glob,
                path: PathBuf::from(after.unwrap_or(".")),
                after: None,
                query: Some(pattern.to_owned()),
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::ProposeWrite => {
            let path = path.ok_or_else(|| live_tool_parse_error("propose_write requires path"))?;
            let after = after.ok_or_else(|| {
                live_tool_parse_error("propose_write requires exact replacement text in after")
            })?;
            Ok(PlusToolRequest {
                name: PlusToolName::ProposeWrite,
                path: PathBuf::from(path),
                after: Some(after.as_bytes().to_vec()),
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::TodoWrite => todo_write_request_from_args(&json!({
            "merge": false,
            "todos": after.map(|text| json!([{"id": "legacy", "content": text}])).unwrap_or(json!([]))
        })),
        PlusToolName::RunContained => Ok(PlusToolRequest {
            name: PlusToolName::RunContained,
            path: PathBuf::new(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        }),
        _ => Err(live_tool_parse_error(&format!("unknown tool {name}"))),
    }
}

fn browser_node_id(args: &Value) -> Result<u64, PlusHostError> {
    args.get("node_id")
        .and_then(Value::as_u64)
        .filter(|node_id| (1..=1_000_000).contains(node_id))
        .ok_or_else(|| live_tool_parse_error("Browser action requires bounded node_id"))
}

/// Builds one request from a tool name and JSON arguments object.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] for unknown names or missing fields.
pub fn plus_tool_request_from_name_and_args(
    name: &str,
    arguments_json: &str,
) -> Result<PlusToolRequest, PlusHostError> {
    let trimmed = arguments_json.trim();
    let value = if trimmed.is_empty() {
        json!({})
    } else {
        serde_json::from_str(trimmed).map_err(|error| {
            live_tool_parse_error(&format!("{name} arguments are not JSON: {error}"))
        })?
    };
    plus_tool_request_from_name_and_value(name, &value)
}

#[allow(
    clippy::too_many_lines,
    reason = "the strict parser validates every admitted tool shape explicitly and refuses all unknown or missing fields"
)]
fn plus_tool_request_from_name_and_value(
    name: &str,
    args: &Value,
) -> Result<PlusToolRequest, PlusHostError> {
    let tool_name = PlusToolName::from_wire(name)
        .ok_or_else(|| live_tool_parse_error(&format!("unknown tool {name}")))?;
    match tool_name {
        PlusToolName::ListDir => Ok(PlusToolRequest {
            name: PlusToolName::ListDir,
            path: PathBuf::from(args.get("path").and_then(Value::as_str).unwrap_or(".")),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        }),
        PlusToolName::ReadFile => {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| live_tool_parse_error("read_file requires path"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::ReadFile,
                path: PathBuf::from(path),
                after: None,
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::Grep => {
            let pattern = args
                .get("pattern")
                .and_then(Value::as_str)
                .ok_or_else(|| live_tool_parse_error("grep requires pattern"))?;
            if pattern.trim().is_empty() {
                return Err(live_tool_parse_error("grep requires pattern"));
            }
            Ok(PlusToolRequest {
                name: PlusToolName::Grep,
                path: PathBuf::from(args.get("path").and_then(Value::as_str).unwrap_or(".")),
                after: None,
                query: Some(pattern.to_owned()),
                case_insensitive: args
                    .get("case_insensitive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                replace_all: false,
            })
        }
        PlusToolName::Glob => {
            let pattern = args
                .get("pattern")
                .and_then(Value::as_str)
                .ok_or_else(|| live_tool_parse_error("glob requires pattern"))?;
            if pattern.trim().is_empty() {
                return Err(live_tool_parse_error("glob requires pattern"));
            }
            Ok(PlusToolRequest {
                name: PlusToolName::Glob,
                path: PathBuf::from(args.get("path").and_then(Value::as_str).unwrap_or(".")),
                after: None,
                query: Some(pattern.to_owned()),
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::ProposeWrite => {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| live_tool_parse_error("propose_write requires path"))?;
            let after = args.get("after").and_then(Value::as_str).ok_or_else(|| {
                live_tool_parse_error("propose_write requires exact replacement text in after")
            })?;
            Ok(PlusToolRequest {
                name: PlusToolName::ProposeWrite,
                path: PathBuf::from(path),
                after: Some(after.as_bytes().to_vec()),
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::ProposeReplace => {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| live_tool_parse_error("propose_replace requires path"))?;
            let old = args
                .get("old")
                .and_then(Value::as_str)
                .ok_or_else(|| live_tool_parse_error("propose_replace requires old"))?;
            let new = args
                .get("new")
                .and_then(Value::as_str)
                .ok_or_else(|| live_tool_parse_error("propose_replace requires new"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::ProposeReplace,
                path: PathBuf::from(path),
                after: Some(new.as_bytes().to_vec()),
                query: Some(old.to_owned()),
                case_insensitive: false,
                replace_all: args
                    .get("replace_all")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        }
        PlusToolName::TodoWrite => todo_write_request_from_args(args),
        PlusToolName::RunContained => Ok(PlusToolRequest {
            name: PlusToolName::RunContained,
            path: PathBuf::new(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        }),
        PlusToolName::BrowserNavigate => {
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .filter(|url| !url.is_empty() && url.len() <= 4096 && !url.contains('\0'))
                .ok_or_else(|| live_tool_parse_error("browser_navigate requires bounded url"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::BrowserNavigate,
                path: PathBuf::from(url),
                after: None,
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::BrowserInspect | PlusToolName::BrowserScreenshot => Ok(PlusToolRequest {
            name: tool_name,
            path: PathBuf::new(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        }),
        PlusToolName::BrowserClick => {
            let node_id = browser_node_id(args)?;
            Ok(PlusToolRequest {
                name: PlusToolName::BrowserClick,
                path: PathBuf::from(node_id.to_string()),
                after: None,
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::BrowserType => {
            let node_id = browser_node_id(args)?;
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty() && text.len() <= 4096 && !text.contains('\0'))
                .ok_or_else(|| live_tool_parse_error("browser_type requires bounded text"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::BrowserType,
                path: PathBuf::from(node_id.to_string()),
                after: Some(text.as_bytes().to_vec()),
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::BrowserKey => {
            let key = args
                .get("key")
                .and_then(Value::as_str)
                .filter(|key| !key.is_empty() && key.len() <= 32 && !key.contains('\0'))
                .ok_or_else(|| live_tool_parse_error("browser_key requires key"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::BrowserKey,
                path: PathBuf::new(),
                after: None,
                query: Some(key.to_owned()),
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::BrowserScroll => {
            let delta = args
                .get("delta_y")
                .and_then(Value::as_i64)
                .filter(|delta| (-2000..=2000).contains(delta))
                .ok_or_else(|| live_tool_parse_error("browser_scroll requires bounded delta_y"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::BrowserScroll,
                path: PathBuf::new(),
                after: None,
                query: Some(delta.to_string()),
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::DesktopClick => {
            let x = bounded_desktop_coordinate(args, "x")?;
            let y = bounded_desktop_coordinate(args, "y")?;
            let button = args.get("button").and_then(Value::as_str).unwrap_or("left");
            if !matches!(button, "left" | "right" | "center") {
                return Err(live_tool_parse_error(
                    "desktop_click button must be left, right, or center",
                ));
            }
            Ok(PlusToolRequest {
                name: PlusToolName::DesktopClick,
                path: PathBuf::from(format!("{x},{y}")),
                after: None,
                query: Some(button.to_owned()),
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::DesktopType => {
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty() && text.len() <= 4096 && !text.contains('\0'))
                .ok_or_else(|| {
                    live_tool_parse_error(
                        "desktop_type requires nonempty NUL-free text of at most 4 KiB",
                    )
                })?;
            Ok(PlusToolRequest {
                name: PlusToolName::DesktopType,
                path: PathBuf::new(),
                after: Some(text.as_bytes().to_vec()),
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::DesktopKey => {
            let key = args
                .get("key")
                .and_then(Value::as_str)
                .filter(|key| desktop_key_allowed(key))
                .ok_or_else(|| live_tool_parse_error("desktop_key key is outside the allowlist"))?;
            let modifiers = desktop_modifiers(args.get("modifiers"))?;
            Ok(PlusToolRequest {
                name: PlusToolName::DesktopKey,
                path: PathBuf::from(key),
                after: None,
                query: Some(modifiers.join(",")),
                case_insensitive: false,
                replace_all: false,
            })
        }
        PlusToolName::DesktopScroll => {
            let delta_x = bounded_desktop_delta(args, "delta_x")?;
            let delta_y = bounded_desktop_delta(args, "delta_y")?;
            if delta_x == 0 && delta_y == 0 {
                return Err(live_tool_parse_error(
                    "desktop_scroll requires at least one nonzero delta",
                ));
            }
            Ok(PlusToolRequest {
                name: PlusToolName::DesktopScroll,
                path: PathBuf::from(format!("{delta_x},{delta_y}")),
                after: None,
                query: None,
                case_insensitive: false,
                replace_all: false,
            })
        }
    }
}

fn bounded_desktop_coordinate(args: &Value, name: &str) -> Result<f64, PlusHostError> {
    args.get(name)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && (0.0..=100_000.0).contains(value))
        .ok_or_else(|| {
            live_tool_parse_error(&format!(
                "desktop_click {name} must be a finite coordinate from 0 through 100000"
            ))
        })
}

fn bounded_desktop_delta(args: &Value, name: &str) -> Result<i64, PlusHostError> {
    args.get(name)
        .and_then(Value::as_i64)
        .filter(|value| (-2000..=2000).contains(value))
        .ok_or_else(|| {
            live_tool_parse_error(&format!(
                "desktop_scroll {name} must be an integer from -2000 through 2000"
            ))
        })
}

fn desktop_key_allowed(key: &str) -> bool {
    matches!(
        key,
        "Enter"
            | "Tab"
            | "Escape"
            | "Backspace"
            | "Delete"
            | "Space"
            | "ArrowUp"
            | "ArrowDown"
            | "ArrowLeft"
            | "ArrowRight"
            | "Home"
            | "End"
            | "PageUp"
            | "PageDown"
    ) || (key.len() == 1
        && key
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric()))
}

fn desktop_modifiers(value: Option<&Value>) -> Result<Vec<&str>, PlusHostError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| live_tool_parse_error("desktop_key modifiers must be an array"))?;
    if array.len() > 4 {
        return Err(live_tool_parse_error(
            "desktop_key modifiers exceed the four-item bound",
        ));
    }
    let mut modifiers = Vec::new();
    for value in array {
        let modifier = value
            .as_str()
            .filter(|modifier| matches!(*modifier, "command" | "control" | "option" | "shift"));
        let Some(modifier) = modifier else {
            return Err(live_tool_parse_error(
                "desktop_key modifier is outside the allowlist",
            ));
        };
        if modifiers.contains(&modifier) {
            return Err(live_tool_parse_error(
                "desktop_key modifiers cannot contain duplicates",
            ));
        }
        modifiers.push(modifier);
    }
    Ok(modifiers)
}

fn todo_write_request_from_args(args: &Value) -> Result<PlusToolRequest, PlusHostError> {
    let (updates, merge) = plus_todo_updates_from_args(args).map_err(|error| match error {
        PlusHostError::Live(detail) => live_tool_parse_error(&detail),
        other => live_tool_parse_error(&other.to_string()),
    })?;
    let encoded = encode_plus_todo_args(&updates, merge);
    Ok(PlusToolRequest {
        name: PlusToolName::TodoWrite,
        path: PathBuf::new(),
        after: Some(serde_json::to_vec(&encoded).unwrap_or_else(|_| b"{\"todos\":[]}".to_vec())),
        query: None,
        case_insensitive: false,
        replace_all: merge,
    })
}

fn live_tool_parse_error(detail: &str) -> PlusHostError {
    PlusHostError::Live(format!("{PLUS_LIVE_TOOL_PARSE_ERROR}: {detail}"))
}

/// Metadata-only tool lifecycle emitted immediately around the app-owned tool
/// dispatcher. Request arguments and result bodies are deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlusToolLifecycleEvent {
    /// Persisted before the dispatcher starts the tool effect.
    Requested {
        /// Stable tool name; arguments are intentionally omitted.
        name: String,
    },
    /// Emitted after an honestly successful tool result.
    Completed {
        /// Stable tool name; result content is intentionally omitted.
        name: String,
    },
    /// Emitted after a refused or failed tool result.
    Refused {
        /// Stable tool name; refusal detail is intentionally omitted.
        name: String,
    },
}

/// Runs at most [`PLUS_MAX_TOOL_STEPS`] tools. Per-tool errors become step text.
#[must_use]
pub fn run_plus_tool_loop(
    bound: &BoundProject,
    requests: &[PlusToolRequest],
) -> PlusToolLoopReport {
    run_plus_tool_loop_on_store(bound, None, requests)
}

/// Same as [`run_plus_tool_loop`], with a plus state root for `todo_write`.
#[must_use]
pub fn run_plus_tool_loop_on_store(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
    requests: &[PlusToolRequest],
) -> PlusToolLoopReport {
    run_plus_tool_loop_on_store_in_mode(bound, store, requests, PlusSessionMode::Agent)
}

/// Same as [`run_plus_tool_loop_on_store`], gated by [`PlusSessionMode`].
#[must_use]
pub fn run_plus_tool_loop_on_store_in_mode(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
    requests: &[PlusToolRequest],
    mode: PlusSessionMode,
) -> PlusToolLoopReport {
    let mut steps = Vec::new();
    let mut executed = Vec::new();
    let mut pending = None;
    let mut pending_set = PendingFileSet::default();
    for request in requests.iter().take(PLUS_MAX_TOOL_STEPS) {
        let (result, staged, ok) = execute_plus_tool(bound, store, request, mode);
        if let Some(proposal) = staged {
            pending_set.upsert(proposal.clone());
            pending = Some(proposal);
        }
        steps.push(PlusToolStep {
            name: request.name,
            request: tool_request_label(request),
            result,
            ok,
        });
        executed.push(request.clone());
    }
    PlusToolLoopReport {
        steps,
        requests: executed,
        pending,
        pending_set,
    }
}

/// Same tool loop with a fallible metadata-only lifecycle observer.
///
/// The observer runs before each effect and after its exact outcome. An
/// observer failure before dispatch prevents the tool from starting; an
/// observer failure after dispatch is returned instead of being represented as
/// a clean completion.
///
/// # Errors
///
/// Returns the observer error without weakening tool or proposal rules.
pub fn run_plus_tool_loop_on_store_in_mode_observed(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
    requests: &[PlusToolRequest],
    mode: PlusSessionMode,
    observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
) -> Result<PlusToolLoopReport, PlusHostError> {
    run_plus_tool_loop_on_store_in_mode_observed_external(
        bound, store, requests, mode, observer, None,
    )
}

/// Same observed loop with a narrowly scoped external high-power dispatcher.
/// Browser requests fail closed when the dispatcher is absent or declines.
///
/// # Errors
///
/// Returns an observer or dispatcher error immediately; no remaining tool is
/// reported as completed after that failure.
pub fn run_plus_tool_loop_on_store_in_mode_observed_external(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
    requests: &[PlusToolRequest],
    mode: PlusSessionMode,
    observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<PlusToolLoopReport, PlusHostError> {
    let mut steps = Vec::new();
    let mut executed = Vec::new();
    let mut pending = None;
    let mut pending_set = PendingFileSet::default();
    for request in requests.iter().take(PLUS_MAX_TOOL_STEPS) {
        let name = request.name.as_str().to_owned();
        observer(PlusToolLifecycleEvent::Requested { name: name.clone() })?;
        let (result, staged, ok) =
            execute_plus_tool_with_external(bound, store, request, mode, external);
        observer(if ok {
            PlusToolLifecycleEvent::Completed { name }
        } else {
            PlusToolLifecycleEvent::Refused { name }
        })?;
        if let Some(proposal) = staged {
            pending_set.upsert(proposal.clone());
            pending = Some(proposal);
        }
        steps.push(PlusToolStep {
            name: request.name,
            request: tool_request_label(request),
            result,
            ok,
        });
        executed.push(request.clone());
    }
    Ok(PlusToolLoopReport {
        steps,
        requests: executed,
        pending,
        pending_set,
    })
}

/// Formats executed steps for the chat / smoke surface.
#[must_use]
pub fn present_plus_tool_steps(steps: &[PlusToolStep]) -> String {
    if steps.is_empty() {
        return PLUS_TOOL_LOOP_NOT_RUN.into();
    }
    let mut out = String::new();
    for step in steps {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("tool ");
        out.push_str(step.name.as_str());
        if !step.request.is_empty() {
            out.push(' ');
            out.push_str(&step.request);
        }
        out.push_str(" → ");
        out.push_str(if step.ok {
            PLUS_TOOL_COMPLETED
        } else {
            PLUS_TOOL_FAILED
        });
        out.push_str(": ");
        out.push_str(&step.result);
    }
    out
}

fn tool_request_label(request: &PlusToolRequest) -> String {
    match request.name {
        PlusToolName::RunContained
        | PlusToolName::BrowserInspect
        | PlusToolName::BrowserScreenshot => String::new(),
        PlusToolName::BrowserNavigate => "explicit HTTP(S) URL".into(),
        PlusToolName::BrowserClick | PlusToolName::BrowserType => {
            format!("node {}", request.path.display())
        }
        PlusToolName::BrowserKey => request.query.clone().unwrap_or_default(),
        PlusToolName::BrowserScroll => format!("delta {}", request.query.as_deref().unwrap_or("0")),
        PlusToolName::DesktopClick => format!(
            "relative coordinate {} · {} button",
            request.path.display(),
            request.query.as_deref().unwrap_or("left")
        ),
        PlusToolName::DesktopType => "bounded transient text".into(),
        PlusToolName::DesktopKey => format!(
            "{}{}",
            request.path.display(),
            request
                .query
                .as_deref()
                .filter(|modifiers| !modifiers.is_empty())
                .map_or_else(String::new, |modifiers| format!(" + {modifiers}"))
        ),
        PlusToolName::DesktopScroll => format!("delta {}", request.path.display()),
        PlusToolName::TodoWrite => {
            if request.replace_all {
                "merge".into()
            } else {
                "replace".into()
            }
        }
        PlusToolName::Grep | PlusToolName::Glob => {
            let pattern = request.query.as_deref().unwrap_or("");
            if request.path.as_os_str().is_empty() {
                pattern.to_owned()
            } else {
                format!("{pattern} {}", request.path.display())
            }
        }
        _ => request.path.display().to_string(),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive match keeps every app-owned tool on an explicit dispatch and refusal path"
)]
pub(crate) fn execute_plus_tool(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
    request: &PlusToolRequest,
    mode: PlusSessionMode,
) -> (String, Option<PendingFileProposal>, bool) {
    match request.name {
        PlusToolName::ReadFile => match plus_tool_read_file(bound, &request.path) {
            Ok(text) => (text, None, true),
            Err(error) => (error.to_string(), None, false),
        },
        PlusToolName::ListDir => match plus_tool_list_dir(bound, &request.path) {
            Ok(text) => (text, None, true),
            Err(error) => (error.to_string(), None, false),
        },
        PlusToolName::Grep => {
            let pattern = request.query.as_deref().unwrap_or("");
            match plus_tool_grep(bound, pattern, &request.path, request.case_insensitive) {
                Ok(text) => (text, None, true),
                Err(error) => (error.to_string(), None, false),
            }
        }
        PlusToolName::Glob => {
            let pattern = request.query.as_deref().unwrap_or("");
            match plus_tool_glob(bound, pattern, &request.path) {
                Ok(text) => (text, None, true),
                Err(error) => (error.to_string(), None, false),
            }
        }
        PlusToolName::ProposeWrite => {
            if !mode.allows_propose() {
                return (
                    format!("Ask mode skipped {}", request.name.as_str()),
                    None,
                    true,
                );
            }
            let Some(after) = request.after.clone() else {
                return (
                    "propose_write refused because exact replacement bytes were absent".into(),
                    None,
                    false,
                );
            };
            match plus_tool_propose_write(bound, request.path.clone(), after) {
                Ok(proposal) => (
                    format!(
                        "staged {} ({PLUS_TOOL_NOT_WRITTEN})",
                        proposal.relative_path.display()
                    ),
                    Some(proposal),
                    true,
                ),
                Err(error) => (error.to_string(), None, false),
            }
        }
        PlusToolName::ProposeReplace => {
            if !mode.allows_propose() {
                return (
                    format!("Ask mode skipped {}", request.name.as_str()),
                    None,
                    true,
                );
            }
            let old = request.query.as_deref().unwrap_or("");
            let new = String::from_utf8_lossy(request.after.as_deref().unwrap_or(b""));
            match plus_tool_propose_replace(
                bound,
                request.path.clone(),
                old,
                &new,
                request.replace_all,
            ) {
                Ok(proposal) => (
                    format!(
                        "staged {} ({PLUS_TOOL_NOT_WRITTEN})",
                        proposal.relative_path.display()
                    ),
                    Some(proposal),
                    true,
                ),
                Err(error) => (error.to_string(), None, false),
            }
        }
        PlusToolName::TodoWrite => match store {
            None => ("todo_write requires plus state root".into(), None, false),
            Some(store) => {
                let args =
                    serde_json::from_slice::<Value>(request.after.as_deref().unwrap_or(b"{}"))
                        .unwrap_or_else(|_| json!({"todos": []}));
                match plus_todo_updates_from_args(&args) {
                    Ok((updates, merge)) => match plus_todo_write(store, &updates, merge) {
                        Ok(list) => (present_plus_todos(&list), None, true),
                        Err(error) => (error.to_string(), None, false),
                    },
                    Err(error) => (error.to_string(), None, false),
                }
            }
        },
        PlusToolName::RunContained => plus_tool_run_or_skip(bound, store, mode),
        PlusToolName::BrowserNavigate
        | PlusToolName::BrowserInspect
        | PlusToolName::BrowserClick
        | PlusToolName::BrowserType
        | PlusToolName::BrowserKey
        | PlusToolName::BrowserScroll
        | PlusToolName::BrowserScreenshot => (
            "Browser tool refused because no armed app-owned Browser dispatcher was bound to this run."
                .into(),
            None,
            false,
        ),
        PlusToolName::DesktopClick
        | PlusToolName::DesktopType
        | PlusToolName::DesktopKey
        | PlusToolName::DesktopScroll => (
            "Desktop Control tool refused because no armed app-owned Desktop dispatcher was bound to this run."
                .into(),
            None,
            false,
        ),
    }
}

fn execute_plus_tool_with_external(
    bound: &BoundProject,
    store: Option<&PlusSessionStore>,
    request: &PlusToolRequest,
    mode: PlusSessionMode,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> (String, Option<PendingFileProposal>, bool) {
    if let Some(reason) =
        external.and_then(|owner| owner.tool_policy().refusal(request.name.as_str()))
    {
        return (reason.into(), None, false);
    }
    if !request.name.is_external() {
        return execute_plus_tool(bound, store, request, mode);
    }
    let Some(external) = external else {
        return execute_plus_tool(bound, store, request, mode);
    };
    match external.execute(request) {
        Some(Ok(result)) => (result, None, true),
        Some(Err(error)) => (error.to_string(), None, false),
        None => (
            "High-power tool refused because the external dispatcher did not own the request."
                .into(),
            None,
            false,
        ),
    }
}

#[cfg(test)]
#[path = "tests/plus_tools_lifecycle.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "tests/plus_tools_browser.rs"]
mod browser_tests;

#[cfg(test)]
#[path = "tests/plus_tool_catalog.rs"]
mod catalog_tests;
