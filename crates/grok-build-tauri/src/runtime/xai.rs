//! Direct xAI Responses adapter using only a Keychain-loaded identity.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use grok_build_plus_host::{
    PLUS_LIVE_MODEL, PlusExternalToolExecutor, PlusHostError, PlusLiveIdentity, PlusToolName,
    PlusToolRequest, decode_plus_live_reply,
};
#[cfg(test)]
use grok_build_plus_host::{
    PLUS_LIVE_PROVIDER_LABEL, PlusChatTurn, PlusSessionStore, PlusTurnStuck,
};

use crate::browser::{BrowserAgentAction, BrowserManager};
use crate::contracts::ProviderSessionId;
use crate::desktop::{DesktopAction, DesktopManager, DesktopModifier, DesktopMouseButton};

use super::cancel::RuntimeCancelHandle;
use super::keychain::XaiCredentialLease;
#[cfg(test)]
use super::types::AdapterTurnOutcome;
use super::types::{
    AdapterContext, AdapterFailure, AdapterImage, AdapterProbe, AdapterSession, AdapterTurn,
    LiveRuntimeAdapter, RuntimeEvent, RuntimeEventSink, RuntimeSteeringSource, RuntimeTransport,
    RuntimeUsage,
};

#[cfg(test)]
mod live_fixture;

const LIVE_PROBE_TEXT: &str =
    "GB Plus connection check. Reply with a short acknowledgement and do not call tools.";
#[cfg(test)]
const XAI_KEYCHAIN_PROVIDER_LABEL: &str = "Provider: live xAI (XaiKeychain)";

pub(crate) struct XaiKeychainAdapter {
    credential: XaiCredentialLease,
    cancel: RuntimeCancelHandle,
    conversation_root: Option<std::path::PathBuf>,
    external: Option<Arc<dyn PlusExternalToolExecutor>>,
    selection: Option<super::models::ModelSelection>,
    context_transient: bool,
    connection: transport::Connection,
}

mod models;
mod transport;
use transport::{StreamEvents, checked_transport};

impl XaiKeychainAdapter {
    pub(crate) fn new(credential: XaiCredentialLease, cancel: RuntimeCancelHandle) -> Self {
        Self {
            credential,
            cancel,
            conversation_root: None,
            external: None,
            selection: None,
            context_transient: false,
            connection: transport::Connection::default(),
        }
    }

    pub(crate) fn new_with_external(
        credential: XaiCredentialLease,
        cancel: RuntimeCancelHandle,
        external: Arc<dyn PlusExternalToolExecutor>,
    ) -> Self {
        Self {
            credential,
            cancel,
            conversation_root: None,
            external: Some(external),
            selection: None,
            context_transient: false,
            connection: transport::Connection::default(),
        }
    }

    pub(crate) fn bind_context_root(&mut self, root: &std::path::Path) {
        self.conversation_root = Some(root.into());
    }
    pub(crate) fn require_transient_context(&mut self, transient: bool) {
        self.context_transient |= transient;
    }

    fn identity(&self) -> Result<PlusLiveIdentity, String> {
        self.credential.clone_identity()
    }

    #[cfg(test)]
    fn normalized_turn(turn: &PlusChatTurn, usage: Option<RuntimeUsage>) -> AdapterTurn {
        let outcome = match turn.stuck.as_ref() {
            None => AdapterTurnOutcome::Completed,
            Some(PlusTurnStuck::FailedTool { .. }) => AdapterTurnOutcome::Failed(
                "Native xAI turn stopped after an app-owned tool refusal.".into(),
            ),
            Some(PlusTurnStuck::LiveError { .. }) => AdapterTurnOutcome::Failed(
                "Native xAI turn stopped after a provider or protocol error.".into(),
            ),
            Some(PlusTurnStuck::Incomplete { .. }) => AdapterTurnOutcome::Failed(
                "Native xAI turn ended without a final assistant completion.".into(),
            ),
        };
        AdapterTurn {
            assistant_text: turn.assistant_text.clone(),
            pending: turn.pending_set.clone(),
            provider_session_id: None,
            usage,
            outcome,
        }
    }

    #[cfg(test)]
    fn presented_turn_and_remember(
        store: &PlusSessionStore,
        turn: &PlusChatTurn,
    ) -> Result<PlusChatTurn, PlusHostError> {
        let mut presented = turn.clone();
        presented.assistant_text = Self::presented_assistant_text(&presented.assistant_text);
        store.append_chat_turn(&presented.assistant_text)?;
        Ok(presented)
    }

    #[cfg(test)]
    fn presented_assistant_text(assistant_text: &str) -> String {
        let Some(remainder) = assistant_text.strip_prefix(PLUS_LIVE_PROVIDER_LABEL) else {
            return assistant_text.to_owned();
        };
        if remainder.is_empty() {
            return XAI_KEYCHAIN_PROVIDER_LABEL.to_owned();
        }
        let Some(remainder) = remainder.strip_prefix('\n') else {
            return assistant_text.to_owned();
        };
        format!("{XAI_KEYCHAIN_PROVIDER_LABEL}\n{remainder}")
    }

    fn latest_usage(usage: &Mutex<Option<RuntimeUsage>>) -> Option<RuntimeUsage> {
        usage.lock().ok().and_then(|latest| latest.clone())
    }
}

impl LiveRuntimeAdapter for XaiKeychainAdapter {
    fn transport(&self) -> RuntimeTransport {
        RuntimeTransport::XaiKeychain
    }

    fn discover_models(&mut self) -> Result<Vec<super::models::ModelDescriptor>, AdapterFailure> {
        self.authenticated_models()
    }

    fn configure_native_protocol(
        &mut self,
        protocol: super::native_protocol::NativeProtocol,
    ) -> Result<(), AdapterFailure> {
        self.connection
            .configure(protocol)
            .map_err(AdapterFailure::from)
    }

    fn configure_model(
        &mut self,
        selection: super::models::ModelSelection,
    ) -> Result<(), AdapterFailure> {
        if selection.transport != self.transport() {
            return Err(AdapterFailure::protocol(
                "Model selection crossed transports.",
            ));
        }
        self.selection = Some(selection);
        Ok(())
    }

    fn probe_model_tools(&mut self, events: &RuntimeEventSink<'_>) -> Result<(), AdapterFailure> {
        self.probe_selected_tools(events)
    }

    fn probe(&mut self, events: &RuntimeEventSink<'_>) -> Result<AdapterProbe, AdapterFailure> {
        self.cancel
            .ensure_not_cancelled()
            .map_err(AdapterFailure::cancellation)?;
        let identity = self.identity()?;
        let request = grok_build_plus_host::encode_plus_live_conversation_request(
            &[serde_json::json!({"role":"user","content":[{"type":"input_text","text":LIVE_PROBE_TEXT}]})],
            PLUS_LIVE_MODEL, None, &identity,
        ).map_err(AdapterFailure::from)?;
        let saw_assistant_delta = AtomicBool::new(false);
        let latest_usage = Mutex::new(None);
        let event_error = Mutex::new(None);
        let body = checked_transport(
            &mut self.connection,
            &self.cancel,
            &self.credential,
            &request,
            &StreamEvents {
                events,
                saw_assistant_delta: &saw_assistant_delta,
                latest_usage: &latest_usage,
                event_error: &event_error,
            },
        )
        .map_err(AdapterFailure::from)?;
        let reply = decode_plus_live_reply(&body).map_err(AdapterFailure::from)?;
        if !saw_assistant_delta.load(Ordering::Acquire) && !reply.assistant_text.is_empty() {
            events(RuntimeEvent::AssistantDelta(reply.assistant_text))?;
        }
        Ok(AdapterProbe {
            model: PLUS_LIVE_MODEL.to_owned(),
        })
    }

    fn start_or_restore_session(
        &mut self,
        provider_session_id: Option<&ProviderSessionId>,
    ) -> Result<AdapterSession, AdapterFailure> {
        let journal = self
            .conversation_root
            .as_ref()
            .map(|root| super::responses::ResponsesJournal::open(root))
            .transpose()?;
        let id = journal
            .as_ref()
            .map(|journal| ProviderSessionId::new(journal.context_id()));
        if provider_session_id.is_some() && provider_session_id != id.as_ref() {
            return Err(AdapterFailure::protocol(
                "Native Responses context identity changed.",
            ));
        }
        Ok(AdapterSession {
            provider_session_id: id,
        })
    }

    fn send_turn(
        &mut self,
        context: &AdapterContext<'_>,
        prompt: &str,
        image: Option<&AdapterImage<'_>>,
        steering: &RuntimeSteeringSource<'_>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure> {
        self.cancel
            .ensure_not_cancelled()
            .map_err(AdapterFailure::cancellation)?;
        let root = self.conversation_root.as_ref().ok_or_else(|| {
            AdapterFailure::protocol("Native Responses has no durable app chat binding.")
        })?;
        let mut journal = super::responses::ResponsesJournal::open(root)?;
        if self.context_transient {
            journal.require_transient_context()?;
        }
        if let Some(selection) = &self.selection {
            journal.select_model(selection)?;
        }
        let model = self.authenticated_models()?.into_iter()
            .find(|model| model.id == journal.model())
            .ok_or_else(|| AdapterFailure::protocol("This context's model is no longer in the authenticated xAI catalog. Select an available model before sending."))?;
        journal.refresh_model_metadata(&model)?;
        let image_base64 =
            image.map(|image| base64::engine::general_purpose::STANDARD.encode(image.png));
        journal.begin_turn(&context.provider_prompt(prompt)?, image_base64.as_deref())?;
        let identity = self.identity()?;
        let saw_assistant_delta = AtomicBool::new(false);
        let latest_usage = Mutex::new(None);
        let event_error = Mutex::new(None);
        let mut turn = super::responses::turn::NativeTurn {
            prompt,
            context,
            identity: &identity,
            external: self.external.as_deref(),
            events,
            steering,
        }
        .run_compacting(
            &mut journal,
            |request| {
                checked_transport(
                    &mut self.connection,
                    &self.cancel,
                    &self.credential,
                    request,
                    &StreamEvents {
                        events,
                        saw_assistant_delta: &saw_assistant_delta,
                        latest_usage: &latest_usage,
                        event_error: &event_error,
                    },
                )
            },
            |input, model| {
                grok_build_plus_host::post_plus_live_compaction(input, model, &identity, || {
                    self.cancel.cancelled() || !self.credential.is_active()
                })
            },
        )?;
        turn.usage = Self::latest_usage(&latest_usage);
        if !saw_assistant_delta.load(Ordering::Acquire) {
            events(RuntimeEvent::AssistantDelta(turn.assistant_text.clone()))?;
        }
        Ok(turn)
    }

    fn continue_with_tool_results(
        &mut self,
        _context: &AdapterContext<'_>,
        _events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure> {
        Err(AdapterFailure::protocol(
            "Native Responses uses completed journal entries. An uncertain request or effect cannot be automatically replayed.",
        ))
    }

    fn cancel_run(&mut self) -> Result<(), String> {
        let cancelled = self.cancel.request_cancel();
        let closed = self.connection.close().map_err(|error| error.to_string());
        cancelled.and(closed)
    }

    fn close_session(&mut self) -> Result<(), String> {
        self.cancel_run()
    }
}

pub(crate) struct HighPowerToolExecutor {
    browser: BrowserManager,
    desktop: DesktopManager,
    project_id: String,
    run_id: String,
    mcp: Option<Arc<crate::extensions::mcp::broker::McpRunExecutor>>,
}

impl HighPowerToolExecutor {
    pub(crate) fn new(
        browser: BrowserManager,
        desktop: DesktopManager,
        project_id: String,
        run_id: String,
    ) -> Self {
        Self {
            browser,
            desktop,
            project_id,
            run_id,
            mcp: None,
        }
    }

    pub(crate) fn with_mcp(
        mut self,
        mcp: Option<Arc<crate::extensions::mcp::broker::McpRunExecutor>>,
    ) -> Self {
        self.mcp = mcp;
        self
    }

    fn execute_browser(&self, request: &PlusToolRequest) -> Result<String, String> {
        let action = match request.name {
            PlusToolName::BrowserNavigate => BrowserAgentAction::Navigate(
                request
                    .path
                    .to_str()
                    .ok_or_else(|| "Browser URL is not valid UTF-8.".to_owned())?,
            ),
            PlusToolName::BrowserInspect => BrowserAgentAction::Inspect,
            PlusToolName::BrowserClick => BrowserAgentAction::Click(browser_node(request)?),
            PlusToolName::BrowserType => BrowserAgentAction::Type {
                node_id: browser_node(request)?,
                text: std::str::from_utf8(request.after.as_deref().unwrap_or_default())
                    .map_err(|_| "Browser type text is not valid UTF-8.".to_owned())?,
            },
            PlusToolName::BrowserKey => BrowserAgentAction::Key(
                request
                    .query
                    .as_deref()
                    .ok_or_else(|| "Browser key is missing.".to_owned())?,
            ),
            PlusToolName::BrowserScroll => BrowserAgentAction::Scroll(
                request
                    .query
                    .as_deref()
                    .ok_or_else(|| "Browser scroll delta is missing.".to_owned())?
                    .parse::<i64>()
                    .map_err(|_| "Browser scroll delta is malformed.".to_owned())?,
            ),
            PlusToolName::BrowserScreenshot => BrowserAgentAction::Screenshot,
            _ => return Err("External Browser dispatcher received a non-Browser tool.".into()),
        };
        self.browser
            .agent_action(&self.project_id, &self.run_id, action)
    }

    fn execute_desktop(&self, request: &PlusToolRequest) -> Result<String, String> {
        let action = match request.name {
            PlusToolName::DesktopClick => {
                let (x, y) = pair_f64(&request.path, "Desktop click coordinates")?;
                let button = DesktopMouseButton::parse(
                    request
                        .query
                        .as_deref()
                        .ok_or_else(|| "Desktop click button is missing.".to_owned())?,
                )?;
                DesktopAction::Click { x, y, button }
            }
            PlusToolName::DesktopType => DesktopAction::Type {
                text: std::str::from_utf8(request.after.as_deref().unwrap_or_default())
                    .map_err(|_| "Desktop type text is not valid UTF-8.".to_owned())?
                    .to_owned(),
            },
            PlusToolName::DesktopKey => DesktopAction::Key {
                key: request
                    .path
                    .to_str()
                    .ok_or_else(|| "Desktop key is not valid UTF-8.".to_owned())?
                    .to_owned(),
                modifiers: DesktopModifier::parse_list(request.query.as_deref().unwrap_or(""))?,
            },
            PlusToolName::DesktopScroll => {
                let (delta_x, delta_y) = pair_i32(&request.path, "Desktop scroll deltas")?;
                DesktopAction::Scroll { delta_x, delta_y }
            }
            _ => {
                return Err(
                    "External Desktop Control dispatcher received a non-Desktop tool.".into(),
                );
            }
        };
        self.desktop
            .agent_action(&self.project_id, &self.run_id, &action)
    }
}

impl PlusExternalToolExecutor for HighPowerToolExecutor {
    fn execute(&self, request: &PlusToolRequest) -> Option<Result<String, PlusHostError>> {
        if request.name.is_browser() {
            return Some(self.execute_browser(request).map_err(PlusHostError::Live));
        }
        if request.name.is_desktop() {
            return Some(self.execute_desktop(request).map_err(PlusHostError::Live));
        }
        None
    }

    fn extension_tools(
        &self,
    ) -> Result<Vec<grok_build_plus_host::PlusExtensionTool>, PlusHostError> {
        Ok(self
            .mcp
            .as_ref()
            .map_or_else(Vec::new, |mcp| mcp.declarations()))
    }

    fn execute_extension(
        &self,
        invocation: &str,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Option<Result<serde_json::Value, PlusHostError>> {
        if !name.starts_with("gbext_") {
            return None;
        }
        Some(
            self.mcp
                .as_ref()
                .ok_or_else(|| PlusHostError::Live("No MCP server is enabled for this run.".into()))
                .and_then(|mcp| {
                    mcp.execute(invocation, name, arguments)
                        .map_err(PlusHostError::Live)
                }),
        )
    }
}

fn browser_node(request: &PlusToolRequest) -> Result<u64, String> {
    request
        .path
        .to_str()
        .ok_or_else(|| "Browser node identity is not valid UTF-8.".to_owned())?
        .parse::<u64>()
        .ok()
        .filter(|node_id| *node_id != 0)
        .ok_or_else(|| "Browser node identity is invalid or stale.".to_owned())
}

fn pair_f64(path: &std::path::Path, label: &str) -> Result<(f64, f64), String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("{label} are not valid UTF-8."))?;
    let (first, second) = value
        .split_once(',')
        .ok_or_else(|| format!("{label} are malformed."))?;
    let first = first
        .parse::<f64>()
        .map_err(|_| format!("{label} are malformed."))?;
    let second = second
        .parse::<f64>()
        .map_err(|_| format!("{label} are malformed."))?;
    if !first.is_finite() || !second.is_finite() {
        return Err(format!("{label} must be finite."));
    }
    Ok((first, second))
}

fn pair_i32(path: &std::path::Path, label: &str) -> Result<(i32, i32), String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("{label} are not valid UTF-8."))?;
    let (first, second) = value
        .split_once(',')
        .ok_or_else(|| format!("{label} are malformed."))?;
    Ok((
        first
            .parse::<i32>()
            .map_err(|_| format!("{label} are malformed."))?,
        second
            .parse::<i32>()
            .map_err(|_| format!("{label} are malformed."))?,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::runtime::keychain::{
        KeychainPresence, ProviderSecretStore, SecretBytes, XaiCredentialBroker,
    };

    struct MemorySecrets(Mutex<Option<Vec<u8>>>);

    impl ProviderSecretStore for MemorySecrets {
        fn inspect_xai_key(&self) -> KeychainPresence {
            if self.0.lock().expect("secret lock").is_some() {
                KeychainPresence::Present
            } else {
                KeychainPresence::Absent
            }
        }

        fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
            self.0
                .lock()
                .expect("secret lock")
                .clone()
                .map(SecretBytes::new)
                .transpose()
        }

        fn store_xai_key(&self, key: &SecretBytes) -> Result<(), String> {
            *self.0.lock().expect("secret lock") = Some(key.as_slice().to_vec());
            Ok(())
        }

        fn delete_xai_key(&self) -> Result<(), String> {
            *self.0.lock().expect("secret lock") = None;
            Ok(())
        }
    }

    #[test]
    fn revoked_credential_is_honest_and_never_selects_another_transport() {
        let secrets = Arc::new(MemorySecrets(Mutex::new(Some(b"fixture-key".to_vec()))));
        let mut broker = XaiCredentialBroker::new(secrets);
        let credential = broker.open_explicit().expect("open credential lease");
        let mut adapter = XaiKeychainAdapter::new(credential, RuntimeCancelHandle::new());
        broker.revoke();
        let error = adapter
            .probe(&|_| Ok(()))
            .expect_err("revoked credential must fail before transport");
        assert!(error.reason.contains("credential lease was revoked"));
        assert_eq!(adapter.transport(), RuntimeTransport::XaiKeychain);
    }

    #[test]
    fn stuck_native_turn_retains_authoritative_failed_outcome() {
        let turn = PlusChatTurn {
            user_text: "fixture".into(),
            assistant_text: "partial".into(),
            steps: Vec::new(),
            pending: None,
            pending_set: grok_build_plus_host::PendingFileSet::default(),
            live_completions: 1,
            stuck: Some(PlusTurnStuck::Incomplete {
                detail: "provider ended early".into(),
            }),
            failed_request: None,
            follow_up_input: String::new(),
        };
        let normalized = XaiKeychainAdapter::normalized_turn(&turn, None);
        assert!(matches!(normalized.outcome, AdapterTurnOutcome::Failed(_)));
        assert_eq!(normalized.assistant_text, "partial");
    }

    #[test]
    fn xai_keychain_turn_never_labels_keychain_identity_as_environment() {
        struct Cleanup(std::path::PathBuf);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "grok-build-plus-xai-provider-label-{}-{unique}",
            std::process::id()
        ));
        let _cleanup = Cleanup(root.clone());
        let store = PlusSessionStore::from_state_root(root);
        let legacy_text = format!(
            "{PLUS_LIVE_PROVIDER_LABEL}\nYou: fixture\ntool loop not run\nAssistant: fixture reply"
        );
        let internal = PlusChatTurn {
            user_text: "fixture".into(),
            assistant_text: legacy_text.clone(),
            steps: Vec::new(),
            pending: None,
            pending_set: grok_build_plus_host::PendingFileSet::default(),
            live_completions: 1,
            stuck: None,
            failed_request: None,
            follow_up_input: String::new(),
        };

        let presented = XaiKeychainAdapter::presented_turn_and_remember(&store, &internal)
            .expect("persist Keychain-labeled turn");
        let expected = format!(
            "{XAI_KEYCHAIN_PROVIDER_LABEL}\nYou: fixture\ntool loop not run\nAssistant: fixture reply"
        );
        assert_eq!(presented.assistant_text, expected);
        assert_eq!(
            internal.assistant_text, legacy_text,
            "internal continuation state must retain the desktop live prefix"
        );
        assert_eq!(
            store
                .load_chat_transcript()
                .expect("load persisted transcript")
                .as_deref(),
            Some(expected.as_str())
        );
        assert!(!presented.assistant_text.contains("(XAI_API_KEY)"));
    }

    #[test]
    fn xai_keychain_provider_label_rewrite_requires_the_exact_leading_line() {
        let quoted = format!("Assistant quoted {PLUS_LIVE_PROVIDER_LABEL} in prose.");
        assert_eq!(
            XaiKeychainAdapter::presented_assistant_text(&quoted),
            quoted,
            "provider-looking text inside assistant prose must not be rewritten"
        );
        let malformed = format!("{PLUS_LIVE_PROVIDER_LABEL}: suffix");
        assert_eq!(
            XaiKeychainAdapter::presented_assistant_text(&malformed),
            malformed,
            "only an exact provider line may be rewritten"
        );
        assert_eq!(
            PLUS_LIVE_PROVIDER_LABEL, "Provider: live xAI (XAI_API_KEY)",
            "the legacy process-environment path remains unchanged"
        );
    }

    #[test]
    fn browser_executor_declines_non_browser_and_refuses_without_an_armed_grant() {
        let state_root =
            std::env::temp_dir().join(format!("grok-browser-executor-{}", std::process::id()));
        let executor = HighPowerToolExecutor::new(
            BrowserManager::new(&state_root),
            DesktopManager::production(),
            "project-a".into(),
            "run-a".into(),
        );
        let non_browser = PlusToolRequest {
            name: PlusToolName::ReadFile,
            path: "README.md".into(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        };
        assert!(executor.execute(&non_browser).is_none());

        let inspect = PlusToolRequest {
            name: PlusToolName::BrowserInspect,
            path: "".into(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        };
        let refusal = executor
            .execute(&inspect)
            .expect("Browser request owned")
            .expect_err("unarmed Browser must refuse");
        assert!(refusal.to_string().contains("Browser is Off"));

        let invalid_node = PlusToolRequest {
            name: PlusToolName::BrowserClick,
            path: "0".into(),
            after: None,
            query: None,
            case_insensitive: false,
            replace_all: false,
        };
        let refusal = executor
            .execute(&invalid_node)
            .expect("Browser request owned")
            .expect_err("invalid node must refuse before CDP");
        assert!(refusal.to_string().contains("invalid or stale"));

        let desktop_key = PlusToolRequest {
            name: PlusToolName::DesktopKey,
            path: "Enter".into(),
            after: None,
            query: Some(String::new()),
            case_insensitive: false,
            replace_all: false,
        };
        let refusal = executor
            .execute(&desktop_key)
            .expect("Desktop request owned")
            .expect_err("unarmed Desktop Control must refuse");
        assert!(refusal.to_string().contains("Desktop Control is Off"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires the existing Keychain account; live synthetic HTTP/WebSocket continuity and isolated child/workflow qualification"]
    fn stored_keychain_item_completes_one_native_live_path_probe() {
        use crate::runtime::keychain::{MacOsKeychainStore, XaiCredentialBroker};

        let mut broker = XaiCredentialBroker::new(Arc::new(MacOsKeychainStore::production()));
        let credential = broker
            .open_automatic()
            .expect("open existing production credential lease without authorization UI");
        let mut adapter = XaiKeychainAdapter::new(credential.clone(), RuntimeCancelHandle::new());
        let assistant = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&assistant);
        let probe = adapter
            .probe(&move |event| {
                if let RuntimeEvent::AssistantDelta(delta) = event
                    && let Ok(mut text) = captured.lock()
                {
                    text.push_str(&delta);
                }
                Ok(())
            })
            .expect("native live xAI probe");
        assert_eq!(probe.model, PLUS_LIVE_MODEL);
        assert!(
            !assistant
                .lock()
                .expect("assistant capture")
                .trim()
                .is_empty(),
            "live xAI connection check returned no assistant text"
        );
        adapter.close_session().expect("close xAI adapter");
        super::live_fixture::continuity(&credential);
        super::live_fixture::collaboration(&credential);
        broker.revoke();
    }
}
