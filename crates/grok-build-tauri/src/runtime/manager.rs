//! Explicit transport selection and honest shared Account/Chat connection state.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;

use crate::browser::BrowserManager;
use crate::capture::CaptureManager;
use crate::contracts::ProviderSessionId;
use crate::desktop::DesktopManager;
use crate::read_aloud::{
    GROK_OAUTH_TTS_DENIED_REASON, GrokOAuthTtsProbe, ReadAloudCredential,
    ReadAloudCredentialSource, probe_grok_oauth_tts,
};

use super::account_preferences::{AccountPreferenceStore, AccountPreferences, ReconnectGrant};
use super::acp::{AcpLaunchConfig, GrokCliAcpAdapter};
use super::cancel::RuntimeCancelHandle;
use super::keychain::{
    KeychainMigrationState, KeychainPresence, MacOsKeychainStore, ProviderSecretStore, SecretBytes,
    XaiCredentialBroker, XaiCredentialLease,
};
use super::oauth_tts::load_cli_oauth_tts_lease;
#[cfg(test)]
use super::types::AdapterTurnOutcome;
use super::types::{
    AdapterContext, AdapterFailure, AdapterFailureKind, AdapterImage, AdapterTurn, ConnectionState,
    LiveRuntimeAdapter, ReconnectState, RuntimeEventSink, RuntimeSteeringSource, RuntimeTransport,
    RuntimeUsage, unix_time_millis,
};
use super::xai::{HighPowerToolExecutor, XaiKeychainAdapter};

mod collaboration;
mod engine;
mod models;
mod native_protocol;

const EMBEDDED_SIGNING_IDENTITY: &str = env!("GROK_BUILD_SIGNING_IDENTITY");
const EMBEDDED_KEYCHAIN_BROKER_SHA256: &str = env!("GROK_BUILD_KEYCHAIN_BROKER_SHA256");
const GROK_CLI_ACP_NO_TTS_REASON: &str = "Grok CLI / ACP has no TTS on that transport.";

fn embedded_signing_identity() -> &'static str {
    EMBEDDED_SIGNING_IDENTITY
}

fn stable_signing_identity() -> Option<&'static str> {
    let identity = embedded_signing_identity();
    (identity.len() == 40 && identity.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(identity)
}

fn binding_matches_identity(binding: Option<&str>, identity: Option<&str>) -> bool {
    matches!((binding, identity), (Some(binding), Some(identity)) if binding == identity)
}

fn binding_matches_stable_identity(binding: Option<&str>) -> bool {
    binding_matches_identity(binding, stable_signing_identity())
}

fn stable_broker_sha256() -> Option<&'static str> {
    (EMBEDDED_KEYCHAIN_BROKER_SHA256.len() == 64
        && EMBEDDED_KEYCHAIN_BROKER_SHA256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()))
    .then_some(EMBEDDED_KEYCHAIN_BROKER_SHA256)
}

fn binding_matches_stable_broker(binding: Option<&str>) -> bool {
    binding_matches_identity(binding, stable_broker_sha256())
}

/// Account-facing runtime status. Presence is never presented as Connected.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeSnapshot {
    pub(crate) engine: super::engine::EngineSettings,
    pub(crate) selected_transport: RuntimeTransport,
    pub(crate) connection: ConnectionState,
    pub(crate) keychain_presence: KeychainPresence,
    pub(crate) keychain_migration_state: KeychainMigrationState,
    pub(crate) onboarding_acknowledged: bool,
    pub(crate) auto_reconnect_enabled: bool,
    pub(crate) reconnect_state: ReconnectState,
    pub(crate) credential_binding_identity: Option<String>,
    pub(crate) keychain_broker_sha256: Option<String>,
    pub(crate) signing_identity: String,
    pub(crate) account_preference_issue: Option<String>,
    pub(crate) cli_available: bool,
    pub(crate) cli_path: Option<PathBuf>,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "onboarding, user preference, lock suspension, and bounded-attempt flags are orthogonal security facts"
)]
pub(crate) struct RuntimeManager {
    engine: engine::EngineState,
    selected: RuntimeTransport,
    connection: ConnectionState,
    adapter: Option<Box<dyn LiveRuntimeAdapter>>,
    credential_broker: Option<XaiCredentialBroker>,
    credential_lease: Option<XaiCredentialLease>,
    read_aloud_credential: Option<ReadAloudCredential>,
    read_aloud_failure: Option<String>,
    keychain_presence: KeychainPresence,
    keychain_migration_state: KeychainMigrationState,
    account_preferences: Option<AccountPreferenceStore>,
    onboarding_acknowledged: bool,
    auto_reconnect_enabled: bool,
    reconnect_grant: Option<ReconnectGrant>,
    credential_binding_identity: Option<String>,
    keychain_broker_sha256: Option<String>,
    reconnecting: bool,
    suspended_for_lock: bool,
    auto_reconnect_attempted: bool,
    last_adapter_failure: Option<AdapterFailure>,
    account_preference_issue: Option<String>,
    state_root: PathBuf,
    cancel: RuntimeCancelHandle,
    provider_session_id: Option<ProviderSessionId>,
    conversation: Option<super::conversation::ConversationBinding>,
    latest_usage: Option<RuntimeUsage>,
    browser: Option<BrowserManager>,
    browser_run_context: Option<(String, String)>,
    capture: Option<CaptureManager>,
    desktop: Option<DesktopManager>,
    mcp: Option<crate::extensions::mcp::broker::McpBroker>,
    service_context: Option<crate::extensions::mcp::service::ServiceContext>,
    hook_policy: Option<crate::extensions::hooks::FrozenHookPolicy>,
    role: grok_build_plus_host::PlusRuntimeToolPolicy,
    collaboration: Option<Arc<dyn grok_build_plus_host::PlusCollaborationExecutor>>,
    context_transient: bool,
}

struct UnavailableSecrets;

impl ProviderSecretStore for UnavailableSecrets {
    fn inspect_xai_key(&self) -> KeychainPresence {
        KeychainPresence::Absent
    }

    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        Ok(None)
    }

    fn store_xai_key(&self, _key: &SecretBytes) -> Result<(), String> {
        Err("The offline smoke runtime cannot store provider secrets.".into())
    }

    fn delete_xai_key(&self) -> Result<(), String> {
        Ok(())
    }
}

impl RuntimeManager {
    pub(crate) fn production(state_root: PathBuf) -> Self {
        Self::with_secret_store(state_root, Arc::new(MacOsKeychainStore::production()))
    }

    pub(crate) fn offline(state_root: PathBuf) -> Self {
        Self::with_secret_store(state_root, Arc::new(UnavailableSecrets))
    }

    fn with_secret_store(state_root: PathBuf, secrets: Arc<dyn ProviderSecretStore>) -> Self {
        let credential_broker = XaiCredentialBroker::new(secrets);
        let keychain_presence = credential_broker.presence().clone();
        let keychain_migration_state = credential_broker.migration_state().clone();
        let account_preferences = AccountPreferenceStore::new(state_root.clone());
        let (saved, account_preference_issue) = match account_preferences.load() {
            Ok(saved) => (saved.unwrap_or_default(), None),
            Err(reason) => (
                AccountPreferences::default(),
                Some(format!(
                    "Saved Account preferences were refused: {reason}. Select a transport explicitly to replace them."
                )),
            ),
        };
        let engine = engine::EngineState::load(&state_root);
        let selected = if engine.settings.mode == super::engine::EngineMode::GrokCliStandard {
            RuntimeTransport::GrokCliAcp
        } else {
            saved.selected_transport
        };
        Self {
            engine,
            selected,
            connection: ConnectionState::Disconnected,
            adapter: None,
            credential_broker: Some(credential_broker),
            credential_lease: None,
            read_aloud_credential: None,
            read_aloud_failure: None,
            keychain_presence,
            keychain_migration_state,
            account_preferences: Some(account_preferences),
            onboarding_acknowledged: saved.onboarding_acknowledged,
            auto_reconnect_enabled: saved.auto_reconnect_enabled,
            reconnect_grant: saved.reconnect_grant,
            credential_binding_identity: saved.credential_binding_identity,
            keychain_broker_sha256: saved.keychain_broker_sha256,
            reconnecting: false,
            suspended_for_lock: false,
            auto_reconnect_attempted: false,
            last_adapter_failure: None,
            account_preference_issue,
            state_root,
            cancel: RuntimeCancelHandle::new(),
            provider_session_id: None,
            conversation: None,
            latest_usage: None,
            browser: None,
            browser_run_context: None,
            capture: None,
            desktop: None,
            mcp: None,
            service_context: None,
            hook_policy: None,
            role: grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
            collaboration: None,
            context_transient: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn selected(&self) -> RuntimeTransport {
        self.selected
    }

    #[cfg(test)]
    pub(crate) fn connection(&self) -> &ConnectionState {
        &self.connection
    }

    pub(crate) fn cancel_handle(&self) -> RuntimeCancelHandle {
        self.cancel.clone()
    }

    pub(crate) fn selected_transport(&self) -> RuntimeTransport {
        self.selected
    }

    /// Resolves one explicit direct xAI TTS credential without changing the
    /// selected Chat transport. A broker-owned API key always wins. Only when
    /// no API key exists may a connected Grok login be checked directly; ACP
    /// itself never becomes a TTS transport.
    pub(crate) fn read_aloud_credential(&mut self) -> Result<ReadAloudCredential, String> {
        if self.suspended_for_lock {
            return Err("Grok Read Aloud is suspended while the macOS session is locked.".into());
        }
        match &self.connection {
            ConnectionState::Connected { transport, .. } if *transport == self.selected => {}
            ConnectionState::Connected { .. } => {
                return Err("Grok Read Aloud refused a mismatched Connected transport.".into());
            }
            ConnectionState::Probing { .. } => {
                return Err("Grok Read Aloud is unavailable while Account is reconnecting.".into());
            }
            ConnectionState::Disconnected | ConnectionState::Failed { .. } => {
                return Err("Connect Account before using the official Grok voice.".into());
            }
        }

        match &self.keychain_migration_state {
            KeychainMigrationState::BrokerV3 => return self.read_aloud_api_key_credential(),
            KeychainMigrationState::LegacyOnly
            | KeychainMigrationState::StableV2
            | KeychainMigrationState::CleanupPending => {
                return Err(
                    "The saved API key requires stable-broker migration before it can be the documented TTS credential."
                        .into(),
                );
            }
            KeychainMigrationState::Unavailable { reason } => return Err(reason.clone()),
            KeychainMigrationState::Unchecked | KeychainMigrationState::Absent => {}
        }

        if self.selected != RuntimeTransport::GrokCliAcp {
            return Err(
                "Connect with an API key in Account to use the official Grok voice.".into(),
            );
        }
        if let Some(reason) = &self.read_aloud_failure {
            return Err(reason.clone());
        }
        if let Some(credential) = self.read_aloud_credential.as_ref().filter(|credential| {
            credential.source() == ReadAloudCredentialSource::GrokOAuth && credential.is_active()
        }) {
            return Ok(credential.clone());
        }

        let oauth = load_cli_oauth_tts_lease()
            .map_err(|reason| format!("{GROK_CLI_ACP_NO_TTS_REASON} {reason}"))?;
        match probe_grok_oauth_tts(&oauth) {
            GrokOAuthTtsProbe::Authorized => {
                let credential = ReadAloudCredential::grok_oauth(oauth);
                self.read_aloud_credential = Some(credential.clone());
                Ok(credential)
            }
            GrokOAuthTtsProbe::Denied => {
                oauth.revoke();
                self.remember_read_aloud_failure(GROK_OAUTH_TTS_DENIED_REASON)
            }
            GrokOAuthTtsProbe::Failed(reason) => {
                oauth.revoke();
                self.remember_read_aloud_failure(&reason)
            }
        }
    }

    fn read_aloud_api_key_credential(&mut self) -> Result<ReadAloudCredential, String> {
        if let Some(credential) = self.read_aloud_credential.as_ref().filter(|credential| {
            credential.source() == ReadAloudCredentialSource::ApiKey && credential.is_active()
        }) {
            return Ok(credential.clone());
        }
        let lease = if let Some(lease) = self
            .credential_lease
            .as_ref()
            .filter(|lease| lease.is_active())
            .cloned()
        {
            lease
        } else {
            let broker = self.credential_broker.as_mut().ok_or_else(|| {
                "Grok Read Aloud inherited no API-key broker for this runtime.".to_owned()
            })?;
            let result = broker.open_automatic();
            self.keychain_presence = broker.presence().clone();
            result?
        };
        let credential = ReadAloudCredential::api_key(lease);
        self.read_aloud_credential = Some(credential.clone());
        self.read_aloud_failure = None;
        Ok(credential)
    }

    fn remember_read_aloud_failure<T>(&mut self, reason: &str) -> Result<T, String> {
        let reason = bounded_reason(reason);
        self.read_aloud_failure = Some(reason.clone());
        Err(reason)
    }

    fn clear_read_aloud_credential(&mut self) {
        if let Some(credential) = self.read_aloud_credential.take() {
            credential.revoke_if_oauth();
        }
        self.read_aloud_failure = None;
    }

    pub(crate) fn attach_browser(&mut self, browser: BrowserManager) {
        self.browser = Some(browser);
    }

    pub(crate) fn attach_capture(&mut self, capture: CaptureManager) {
        self.capture = Some(capture);
    }

    pub(crate) fn attach_desktop(&mut self, desktop: DesktopManager) {
        self.desktop = Some(desktop);
    }

    pub(crate) fn attach_mcp(&mut self, mcp: crate::extensions::mcp::broker::McpBroker) {
        self.mcp = Some(mcp);
    }

    pub(crate) fn prepare_hooks(
        &self,
    ) -> Result<Option<Arc<dyn crate::extensions::hooks::ToolHookExecutor>>, String> {
        match (&self.service_context, &self.hook_policy) {
            (Some(context), Some(policy)) => policy.bind(context, self.cancel.clone()).map(Some),
            _ => Ok(None),
        }
    }

    pub(crate) fn bind_service_context(
        &mut self,
        context: crate::extensions::mcp::service::ServiceContext,
    ) -> Result<(), String> {
        if self.adapter.is_some() {
            return Err("Service authority must be bound before the provider starts.".into());
        }
        self.hook_policy = crate::extensions::hooks::FrozenHookPolicy::freeze(
            &context,
            self.mcp.as_ref().map(|broker| broker.approvals.clone()),
        )?;
        self.service_context = Some(context);
        Ok(())
    }

    pub(crate) fn bind_service_run(&mut self, project: &str, run: &str) -> Result<(), String> {
        if self.adapter.is_some() {
            return Err("Service run must be fixed before the provider starts.".into());
        }
        if let Some(context) = &mut self.service_context {
            context.bind_run(project, run)?;
        }
        Ok(())
    }

    pub(crate) fn bind_browser_run(
        &mut self,
        project_id: &str,
        run_id: &str,
    ) -> Result<(), String> {
        if self.adapter.is_some() {
            return Err("Browser run context must be bound before the live adapter starts.".into());
        }
        if project_id.is_empty() || run_id.is_empty() {
            return Err("Browser run context requires exact project and run identities.".into());
        }
        self.bind_service_run(project_id, run_id)?;
        if let Some(desktop) = &self.desktop {
            desktop.bind_run(project_id, run_id)?;
        }
        self.browser_run_context = Some((project_id.to_owned(), run_id.to_owned()));
        Ok(())
    }

    pub(crate) fn fork_connected_transport_for_run(
        &self,
        run_state_root: PathBuf,
        role: grok_build_plus_host::PlusRuntimeToolPolicy,
    ) -> Result<Self, String> {
        if self.role != grok_build_plus_host::PlusRuntimeToolPolicy::Parent {
            return Err("Child executions cannot fork another runtime or become a parent.".into());
        }
        match &self.connection {
            ConnectionState::Connected { transport, .. } if *transport == self.selected => {}
            ConnectionState::Connected { .. } => {
                return Err("Connected transport does not match the selected transport.".into());
            }
            ConnectionState::Disconnected => {
                return Err(format!(
                    "{} is not connected. Queued work will not run until its exact Chat path passes a live connection check.",
                    self.selected.label()
                ));
            }
            ConnectionState::Probing { .. } => {
                return Err(format!("{} is still connecting.", self.selected.label()));
            }
            ConnectionState::Failed { reason, .. } => return Err(reason.clone()),
        }
        let connection = self.connection.clone();
        let credential_lease = match self.selected {
            RuntimeTransport::XaiKeychain => Some(
                self.credential_lease
                    .as_ref()
                    .filter(|lease| lease.is_active())
                    .cloned()
                    .ok_or_else(|| {
                        "Connected XaiKeychain runtime has no active credential lease.".to_owned()
                    })?,
            ),
            RuntimeTransport::GrokCliAcp => None,
        };
        Ok(Self {
            engine: self.engine.for_run(role),
            selected: self.selected,
            connection,
            adapter: None,
            credential_broker: None,
            credential_lease,
            read_aloud_credential: None,
            read_aloud_failure: None,
            keychain_presence: self.keychain_presence.clone(),
            keychain_migration_state: self.keychain_migration_state.clone(),
            account_preferences: None,
            onboarding_acknowledged: self.onboarding_acknowledged,
            auto_reconnect_enabled: self.auto_reconnect_enabled,
            reconnect_grant: self.reconnect_grant,
            credential_binding_identity: self.credential_binding_identity.clone(),
            keychain_broker_sha256: self.keychain_broker_sha256.clone(),
            reconnecting: false,
            suspended_for_lock: false,
            auto_reconnect_attempted: false,
            last_adapter_failure: None,
            account_preference_issue: self
                .account_preference_issue
                .clone()
                .or_else(|| self.engine.issue.clone()),
            state_root: run_state_root,
            cancel: RuntimeCancelHandle::new(),
            provider_session_id: None,
            conversation: None,
            latest_usage: None,
            browser: if role == grok_build_plus_host::PlusRuntimeToolPolicy::Parent {
                self.browser.clone()
            } else {
                None
            },
            browser_run_context: None,
            capture: if role == grok_build_plus_host::PlusRuntimeToolPolicy::Parent {
                self.capture.clone()
            } else {
                None
            },
            desktop: if role == grok_build_plus_host::PlusRuntimeToolPolicy::Parent {
                self.desktop.clone()
            } else {
                None
            },
            mcp: if role == grok_build_plus_host::PlusRuntimeToolPolicy::Parent {
                self.mcp.clone()
            } else {
                None
            },
            service_context: None,
            hook_policy: None,
            role,
            collaboration: None,
            context_transient: false,
        })
    }

    pub(crate) fn bind_conversation(
        &mut self,
        state_root: &std::path::Path,
        project: &crate::contracts::ProjectId,
        workspace: &crate::contracts::WorkspaceId,
        session: &crate::contracts::SessionId,
    ) -> Result<(), String> {
        if self.adapter.is_some() {
            return Err("Conversation identity must be bound before opening the provider.".into());
        }
        let standard_root = state_root.join("cli-standard");
        let binding = super::conversation::ConversationBinding::open(
            if self.standard_engine() {
                &standard_root
            } else {
                state_root
            },
            project,
            workspace,
            session,
            self.selected,
        )?;
        self.provider_session_id = binding.provider_session_id();
        self.conversation = Some(binding);
        Ok(())
    }

    fn persist_provider_binding(&mut self) -> Result<(), String> {
        if let (Some(binding), Some(id)) = (&mut self.conversation, &self.provider_session_id) {
            binding.remember(id)?;
        }
        Ok(())
    }

    pub(crate) fn start_connected_run_session(&mut self) -> Result<(), String> {
        self.start_connected_run_session_observed(&|_| Ok(()))
    }

    pub(crate) fn start_connected_run_session_observed(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        self.last_adapter_failure = None;
        self.cancel.ensure_not_cancelled()?;
        match &self.connection {
            ConnectionState::Connected { transport, .. } if *transport == self.selected => {}
            ConnectionState::Connected { .. } => {
                return Err("Connected transport does not match the selected transport.".into());
            }
            ConnectionState::Disconnected => {
                return Err("Queued runtime has no inherited live-path verification.".into());
            }
            ConnectionState::Probing { .. } => {
                return Err("Queued runtime cannot start from a probing transport.".into());
            }
            ConnectionState::Failed { reason, .. } => return Err(reason.clone()),
        }
        let result: Result<(), AdapterFailure> = (|| {
            if self.adapter.is_none() {
                self.adapter = Some(
                    self.build_selected_adapter()
                        .map_err(|reason| self.adapter_build_failure(reason))?,
                );
            }
            let adapter = self.adapter.as_mut().ok_or_else(|| {
                AdapterFailure::new(
                    AdapterFailureKind::LocalSecurity,
                    "Selected queued runtime adapter is unavailable.",
                )
            })?;
            if adapter.transport() != self.selected {
                return Err(AdapterFailure::new(
                    AdapterFailureKind::LocalSecurity,
                    "Selected queued runtime adapter identity drifted.",
                ));
            }
            let session = adapter
                .start_or_restore_session_observed(self.provider_session_id.as_ref(), events)?;
            self.provider_session_id = session.provider_session_id;
            self.persist_provider_binding()?;
            Ok(())
        })();
        if let Err(failure) = result {
            self.last_adapter_failure = Some(failure.clone());
            let _ = self.close_adapter();
            self.connection = ConnectionState::Failed {
                transport: self.selected,
                reason: bounded_reason(&failure.reason),
            };
            self.apply_adapter_failure_policy(&failure);
            return Err(failure.reason);
        }
        Ok(())
    }

    pub(crate) fn record_run_failure(
        &mut self,
        transport: RuntimeTransport,
        reason: &str,
        failure: Option<&AdapterFailure>,
    ) {
        if transport == self.selected {
            self.connection = ConnectionState::Failed {
                transport,
                reason: bounded_reason(reason),
            };
            let _ = self.close_adapter();
            if transport == RuntimeTransport::XaiKeychain {
                self.revoke_owned_credential();
            }
            if let Some(failure) = failure {
                self.apply_adapter_failure_policy(failure);
            }
        }
    }

    pub(crate) fn last_adapter_failure(&self) -> Option<&AdapterFailure> {
        self.last_adapter_failure.as_ref()
    }

    pub(crate) fn snapshot(&self) -> RuntimeSnapshot {
        let cli_path = AcpLaunchConfig::production(&self.state_root)
            .ok()
            .map(|config| config.cli_path().to_path_buf());
        RuntimeSnapshot {
            engine: self.engine_settings(),
            selected_transport: self.selected,
            connection: self.connection.clone(),
            keychain_presence: self.keychain_presence.clone(),
            keychain_migration_state: self.keychain_migration_state.clone(),
            onboarding_acknowledged: self.onboarding_acknowledged,
            auto_reconnect_enabled: self.auto_reconnect_enabled,
            reconnect_state: self.reconnect_state_at(unix_time_millis()),
            credential_binding_identity: self.credential_binding_identity.clone(),
            keychain_broker_sha256: self.keychain_broker_sha256.clone(),
            signing_identity: embedded_signing_identity().to_owned(),
            account_preference_issue: self
                .account_preference_issue
                .clone()
                .or_else(|| self.engine.issue.clone()),
            cli_available: cli_path.is_some(),
            cli_path,
        }
    }

    pub(crate) fn select(&mut self, transport: RuntimeTransport) -> Result<(), String> {
        if self.standard_engine() && transport != RuntimeTransport::GrokCliAcp {
            return Err("Use CLI sign-in with the Grok CLI standard engine.".into());
        }
        if self.selected == transport {
            self.persist_account_preferences(self.current_preferences())?;
            return Ok(());
        }
        self.connection = ConnectionState::Disconnected;
        self.clear_read_aloud_credential();
        self.close_adapter()?;
        self.revoke_owned_credential();
        let mut preferences = self.current_preferences();
        preferences.selected_transport = transport;
        preferences.reconnect_grant = None;
        preferences.credential_binding_identity = None;
        self.persist_account_preferences(preferences)?;
        self.selected = transport;
        self.connection = ConnectionState::Disconnected;
        self.provider_session_id = None;
        self.latest_usage = None;
        Ok(())
    }

    pub(crate) fn connect(&mut self, events: &RuntimeEventSink<'_>) -> Result<(), String> {
        self.connect_internal(events, true)
    }

    fn connect_internal(
        &mut self,
        events: &RuntimeEventSink<'_>,
        renew_grant: bool,
    ) -> Result<(), String> {
        self.last_adapter_failure = None;
        self.clear_read_aloud_credential();
        self.connection = ConnectionState::Probing {
            transport: self.selected,
        };
        let standard = self.standard_engine();
        let result: Result<(), AdapterFailure> = (|| {
            if self.adapter.is_none() {
                self.cancel = RuntimeCancelHandle::new();
                if self.selected == RuntimeTransport::XaiKeychain {
                    let credential = if renew_grant {
                        self.ensure_xai_credential_lease()
                    } else {
                        self.ensure_xai_credential_lease_without_ui()
                    };
                    credential.map_err(|reason| {
                        let kind = if matches!(
                            self.keychain_presence,
                            KeychainPresence::Unavailable { .. }
                        ) {
                            AdapterFailureKind::LocalSecurity
                        } else {
                            AdapterFailureKind::MissingCredential
                        };
                        AdapterFailure::new(kind, reason)
                    })?;
                }
                self.adapter = Some(
                    self.build_selected_adapter()
                        .map_err(|reason| self.adapter_build_failure(reason))?,
                );
            }
            let adapter = self.adapter.as_mut().ok_or_else(|| {
                AdapterFailure::new(
                    AdapterFailureKind::LocalSecurity,
                    "Selected runtime adapter is unavailable.",
                )
            })?;
            if adapter.transport() != self.selected {
                return Err(AdapterFailure::new(
                    AdapterFailureKind::LocalSecurity,
                    "Selected runtime adapter identity drifted.",
                ));
            }
            let probe = adapter.probe(events)?;
            if standard {
                adapter.close_session()?;
                self.provider_session_id = None;
            } else {
                let session =
                    adapter.start_or_restore_session(self.provider_session_id.as_ref())?;
                self.provider_session_id = session.provider_session_id;
            }
            self.persist_provider_binding()?;
            self.connection = ConnectionState::Connected {
                transport: self.selected,
                model: probe.model,
                verified_at: unix_time_millis(),
            };
            if renew_grant {
                self.onboarding_acknowledged = true;
                self.renew_reconnect_grant(unix_time_millis())
                    .map_err(|reason| {
                        AdapterFailure::new(AdapterFailureKind::LocalSecurity, reason)
                    })?;
            }
            if let Err(reason) = self.persist_account_preferences(self.current_preferences()) {
                self.account_preference_issue = Some(format!(
                    "Live Chat is connected, but Account onboarding could not be saved: {reason}"
                ));
            }
            Ok(())
        })();
        if let Err(failure) = result {
            self.last_adapter_failure = Some(failure.clone());
            let _ = self.close_adapter();
            if self.selected == RuntimeTransport::XaiKeychain {
                self.revoke_owned_credential();
            }
            self.connection = ConnectionState::Failed {
                transport: self.selected,
                reason: bounded_reason(&failure.reason),
            };
            self.apply_adapter_failure_policy(&failure);
            return Err(failure.reason);
        }
        Ok(())
    }

    pub(crate) fn refresh(&mut self, events: &RuntimeEventSink<'_>) -> Result<(), String> {
        self.connection = ConnectionState::Disconnected;
        if let Err(reason) = self.close_adapter() {
            self.connection = ConnectionState::Failed {
                transport: self.selected,
                reason: bounded_reason(&reason),
            };
            return Err(reason);
        }
        self.connect_internal(events, false)
    }

    pub(crate) fn connect_saved_xai_key(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        self.select(RuntimeTransport::XaiKeychain)?;
        match self.keychain_migration_state {
            KeychainMigrationState::Unchecked => self.connect_unchecked_xai_key(events),
            KeychainMigrationState::BrokerV3
                if binding_matches_stable_broker(self.keychain_broker_sha256.as_deref()) =>
            {
                self.connect(events)
            }
            KeychainMigrationState::BrokerV3 => self.verify_broker_binding_and_connect(events),
            KeychainMigrationState::LegacyOnly
            | KeychainMigrationState::StableV2
            | KeychainMigrationState::CleanupPending => self.migrate_xai_key_and_connect(events),
            KeychainMigrationState::Absent => {
                Err("No xAI API key is stored in macOS Keychain.".into())
            }
            KeychainMigrationState::Unavailable { ref reason } => Err(reason.clone()),
        }
    }

    fn connect_unchecked_xai_key(&mut self, events: &RuntimeEventSink<'_>) -> Result<(), String> {
        let opened = self
            .credential_broker
            .as_mut()
            .ok_or_else(|| "Only the Account runtime may open a saved API key.".to_owned())?
            .open_explicit();
        self.sync_keychain_state();
        match opened {
            Ok(lease) => self.connect_opened_broker_key(events, &lease),
            Err(_)
                if matches!(
                    self.keychain_migration_state,
                    KeychainMigrationState::LegacyOnly
                        | KeychainMigrationState::StableV2
                        | KeychainMigrationState::CleanupPending
                ) =>
            {
                self.migrate_xai_key_and_connect(events)
            }
            Err(reason) => Err(reason),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "live probe, durable intent, Keychain effect, readback, and lease swap stay visibly ordered"
    )]
    pub(crate) fn connect_new_xai_key(
        &mut self,
        key: &SecretBytes,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        self.select(RuntimeTransport::XaiKeychain)?;
        let broker_sha256 = stable_broker_sha256().ok_or_else(|| {
            "This build has no exact stable Keychain broker; the API key was not stored.".to_owned()
        })?;
        if stable_signing_identity().is_none() {
            return Err(
                "Saved API-key reconnect needs a stable local or Apple-issued app signature; this ad-hoc build cannot persist the broker binding."
                    .into(),
            );
        }
        let previous_grant = self.reconnect_grant;
        let previous_binding = self.credential_binding_identity.clone();
        let previous_broker_binding = self.keychain_broker_sha256.clone();
        if !matches!(self.connection, ConnectionState::Disconnected) {
            self.disconnect()?;
        }
        let transient_lease = key.transient_lease()?;
        self.credential_lease = Some(transient_lease.clone());
        if let Err(reason) = self.connect_internal(events, false) {
            transient_lease.revoke();
            self.credential_lease = None;
            self.reconnect_grant = previous_grant;
            self.credential_binding_identity = previous_binding;
            self.keychain_broker_sha256 = previous_broker_binding;
            let _ = self.persist_account_preferences(self.current_preferences());
            return Err(reason);
        }
        self.reconnect_grant = None;
        self.credential_binding_identity = None;
        self.keychain_broker_sha256 = Some(broker_sha256.to_owned());
        if let Err(reason) = self.persist_account_preferences(self.current_preferences()) {
            transient_lease.revoke();
            self.credential_lease = None;
            let _ = self.close_adapter();
            self.reconnect_grant = previous_grant;
            self.credential_binding_identity = previous_binding;
            self.keychain_broker_sha256 = previous_broker_binding;
            let failure = format!(
                "The live API key was verified, but broker migration intent could not be persisted before Keychain effects: {reason}"
            );
            self.connection = ConnectionState::Failed {
                transport: RuntimeTransport::XaiKeychain,
                reason: bounded_reason(&failure),
            };
            return Err(failure);
        }
        let stored = self
            .credential_broker
            .as_mut()
            .ok_or_else(|| "Only the Account runtime may store an xAI credential.".to_owned())?
            .store_verified_and_open(key);
        match stored {
            Ok(stable_lease) => {
                let close = self.close_adapter();
                transient_lease.revoke();
                self.credential_lease = Some(stable_lease);
                self.sync_keychain_state();
                if let Err(reason) = close {
                    self.revoke_owned_credential();
                    self.connection = ConnectionState::Failed {
                        transport: RuntimeTransport::XaiKeychain,
                        reason: bounded_reason(&reason),
                    };
                    return Err(reason);
                }
                self.cancel = RuntimeCancelHandle::new();
                let rebuild: Result<(), String> = (|| {
                    self.adapter = Some(self.build_selected_adapter()?);
                    let session = self
                        .adapter
                        .as_mut()
                        .ok_or_else(|| "Verified XaiKeychain adapter is unavailable.".to_owned())?
                        .start_or_restore_session(self.provider_session_id.as_ref())
                        .map_err(|failure| failure.reason)?;
                    self.provider_session_id = session.provider_session_id;
                    self.persist_provider_binding()?;
                    Ok(())
                })();
                if let Err(reason) = rebuild {
                    let _ = self.close_adapter();
                    self.revoke_owned_credential();
                    self.connection = ConnectionState::Failed {
                        transport: RuntimeTransport::XaiKeychain,
                        reason: bounded_reason(&reason),
                    };
                    return Err(reason);
                }
                self.finish_explicit_connection_preferences()
            }
            Err(reason) => {
                self.reconnect_grant = None;
                self.credential_binding_identity = None;
                let _ = self.persist_account_preferences(self.current_preferences());
                transient_lease.revoke();
                self.credential_lease = None;
                let _ = self.close_adapter();
                self.sync_keychain_state();
                self.connection = ConnectionState::Failed {
                    transport: RuntimeTransport::XaiKeychain,
                    reason: bounded_reason(&reason),
                };
                Err(reason)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "migration probe, durable intent, Keychain effect, cleanup, and lease swap stay visibly ordered"
    )]
    fn migrate_xai_key_and_connect(&mut self, events: &RuntimeEventSink<'_>) -> Result<(), String> {
        let broker_sha256 = stable_broker_sha256().ok_or_else(|| {
            "This build has no exact stable Keychain broker; migration was refused.".to_owned()
        })?;
        if stable_signing_identity().is_none() {
            return Err(
                "Saved API-key migration needs a stable local or Apple-issued app signature; this ad-hoc build was refused."
                    .into(),
            );
        }
        let previous_grant = self.reconnect_grant;
        let previous_binding = self.credential_binding_identity.clone();
        let previous_broker_binding = self.keychain_broker_sha256.clone();
        if !matches!(self.connection, ConnectionState::Disconnected) {
            self.disconnect()?;
        }
        let migration = self
            .credential_broker
            .as_mut()
            .ok_or_else(|| "Only the Account runtime may migrate an xAI credential.".to_owned())?
            .begin_migration();
        self.sync_keychain_state();
        let material = migration?;
        let transient_lease = material.lease();
        self.credential_lease = Some(transient_lease.clone());
        if let Err(reason) = self.connect_internal(events, false) {
            transient_lease.revoke();
            self.credential_lease = None;
            return Err(reason);
        }
        self.reconnect_grant = None;
        self.credential_binding_identity = None;
        self.keychain_broker_sha256 = Some(broker_sha256.to_owned());
        if let Err(reason) = self.persist_account_preferences(self.current_preferences()) {
            transient_lease.revoke();
            self.credential_lease = None;
            let _ = self.close_adapter();
            self.reconnect_grant = previous_grant;
            self.credential_binding_identity = previous_binding;
            self.keychain_broker_sha256 = previous_broker_binding;
            let failure = format!(
                "The predecessor key was live-verified, but broker migration intent could not be persisted before Keychain effects: {reason}"
            );
            self.connection = ConnectionState::Failed {
                transport: RuntimeTransport::XaiKeychain,
                reason: bounded_reason(&failure),
            };
            return Err(failure);
        }
        let finished = self
            .credential_broker
            .as_mut()
            .ok_or_else(|| "Only the Account runtime may finish xAI migration.".to_owned())?
            .finish_migration(material);
        match finished {
            Ok(stable_lease) => {
                let close = self.close_adapter();
                transient_lease.revoke();
                self.credential_lease = Some(stable_lease);
                self.sync_keychain_state();
                if let Err(reason) = close {
                    self.revoke_owned_credential();
                    self.connection = ConnectionState::Failed {
                        transport: RuntimeTransport::XaiKeychain,
                        reason: bounded_reason(&reason),
                    };
                    return Err(reason);
                }
                self.cancel = RuntimeCancelHandle::new();
                let rebuild: Result<(), String> = (|| {
                    self.adapter = Some(self.build_selected_adapter()?);
                    let session = self
                        .adapter
                        .as_mut()
                        .ok_or_else(|| "Verified XaiKeychain adapter is unavailable.".to_owned())?
                        .start_or_restore_session(self.provider_session_id.as_ref())
                        .map_err(|failure| failure.reason)?;
                    self.provider_session_id = session.provider_session_id;
                    self.persist_provider_binding()?;
                    Ok(())
                })();
                if let Err(reason) = rebuild {
                    let _ = self.close_adapter();
                    self.revoke_owned_credential();
                    self.connection = ConnectionState::Failed {
                        transport: RuntimeTransport::XaiKeychain,
                        reason: bounded_reason(&reason),
                    };
                    return Err(reason);
                }
                self.finish_explicit_connection_preferences()
            }
            Err(reason) => {
                transient_lease.revoke();
                self.credential_lease = None;
                let _ = self.close_adapter();
                self.sync_keychain_state();
                self.connection = ConnectionState::Failed {
                    transport: RuntimeTransport::XaiKeychain,
                    reason: bounded_reason(&reason),
                };
                Err(reason)
            }
        }
    }

    fn verify_broker_binding_and_connect(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if !matches!(self.connection, ConnectionState::Disconnected) {
            self.disconnect()?;
        }
        let opened = self
            .credential_broker
            .as_mut()
            .ok_or_else(|| {
                "Only the Account runtime may verify Keychain broker access.".to_owned()
            })?
            .open_explicit();
        self.sync_keychain_state();
        let lease = opened?;
        self.connect_opened_broker_key(events, &lease)
    }

    fn connect_opened_broker_key(
        &mut self,
        events: &RuntimeEventSink<'_>,
        lease: &XaiCredentialLease,
    ) -> Result<(), String> {
        let broker_sha256 = stable_broker_sha256().ok_or_else(|| {
            "This build has no exact stable Keychain broker; binding verification was refused."
                .to_owned()
        })?;
        if stable_signing_identity().is_none() {
            lease.revoke();
            return Err(
                "Saved API-key reconnect needs a stable local or Apple-issued app signature; this ad-hoc build cannot verify the broker binding."
                    .into(),
            );
        }
        self.credential_lease = Some(lease.clone());
        if let Err(reason) = self.connect_internal(events, false) {
            lease.revoke();
            self.credential_lease = None;
            return Err(reason);
        }
        self.keychain_broker_sha256 = Some(broker_sha256.to_owned());
        self.sync_keychain_state();
        self.finish_explicit_connection_preferences()
    }

    fn finish_explicit_connection_preferences(&mut self) -> Result<(), String> {
        self.onboarding_acknowledged = true;
        self.renew_reconnect_grant(unix_time_millis())?;
        if let Err(reason) = self.persist_account_preferences(self.current_preferences()) {
            self.account_preference_issue = Some(format!(
                "Live Chat is connected, but its reconnect authorization could not be saved: {reason}"
            ));
        }
        Ok(())
    }

    pub(crate) fn disconnect(&mut self) -> Result<(), String> {
        if self.credential_broker.is_some() {
            self.engine.pool.clear()?;
        }
        self.connection = ConnectionState::Disconnected;
        self.provider_session_id = None;
        self.latest_usage = None;
        let close = self.close_adapter();
        if self.credential_broker.is_some() {
            self.revoke_owned_credential();
        } else {
            self.clear_read_aloud_credential();
            self.credential_lease = None;
        }
        if let (Some(capture), Some((_, run_id))) = (&self.capture, &self.browser_run_context) {
            capture.finish_run(run_id);
        }
        if let (Some(desktop), Some((_, run_id))) = (&self.desktop, &self.browser_run_context) {
            desktop.finish_run(run_id);
        }
        self.reconnect_grant = None;
        self.credential_binding_identity = None;
        let persist = self.persist_account_preferences(self.current_preferences());
        close.and(persist)
    }

    pub(crate) fn send_turn(
        &mut self,
        context: &AdapterContext<'_>,
        prompt: &str,
        steering: &RuntimeSteeringSource<'_>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, String> {
        self.last_adapter_failure = None;
        self.cancel.ensure_not_cancelled()?;
        if self.role != grok_build_plus_host::PlusRuntimeToolPolicy::Parent
            && context.hooks.is_some()
        {
            return Err("Child execution cannot inherit project command hooks.".into());
        }
        match &self.connection {
            ConnectionState::Connected { transport, .. } if *transport == self.selected => {}
            ConnectionState::Connected { .. } => {
                return Err("Connected transport does not match the selected transport.".into());
            }
            ConnectionState::Disconnected => {
                return Err(
                    "No live Chat transport is connected. Open Account and choose “Connect with Grok Subscription” or “Connect with API key”."
                        .into(),
                );
            }
            ConnectionState::Probing { .. } => {
                return Err(format!("{} is still connecting.", self.selected.label()));
            }
            ConnectionState::Failed { reason, .. } => return Err(reason.clone()),
        }
        let (prompt, user_image) = if self.standard_engine() {
            self.engine.images.take(prompt, &context.scope)?
        } else {
            (prompt, None)
        };
        let attachment = match (&self.capture, &self.browser_run_context) {
            (Some(capture), Some((project_id, run_id))) => {
                capture.take_for_run(project_id, run_id)?
            }
            _ => None,
        };
        let image = attachment.as_ref().map(|attachment| AdapterImage {
            png: attachment.png(),
            width: attachment.width,
            height: attachment.height,
            sha256: &attachment.sha256,
        });
        if image.is_some() && user_image.is_some() {
            return Err("Choose either Capture or an attached image for this message.".into());
        }
        let image = image.or_else(|| {
            user_image.as_ref().map(|image| AdapterImage {
                png: &image.bytes,
                width: image.width,
                height: image.height,
                sha256: &image.sha256,
            })
        });
        if let Some(attachment) = &attachment {
            events(super::types::RuntimeEvent::CaptureAttached {
                display_id: attachment.display_id,
                width: attachment.width,
                height: attachment.height,
                byte_count: attachment.png().len(),
                sha256: attachment.sha256.clone(),
            })?;
        }
        let result = self
            .adapter
            .as_mut()
            .ok_or_else(|| "Connected runtime adapter is unavailable.".to_owned())?
            .send_turn(context, prompt, image.as_ref(), steering, events);
        match result {
            Ok(turn) => {
                if let Some(provider_session_id) = &turn.provider_session_id {
                    self.provider_session_id = Some(provider_session_id.clone());
                }
                self.latest_usage.clone_from(&turn.usage);
                Ok(turn)
            }
            Err(failure) => {
                self.last_adapter_failure = Some(failure.clone());
                self.connection = ConnectionState::Failed {
                    transport: self.selected,
                    reason: bounded_reason(&failure.reason),
                };
                let _ = self.close_adapter();
                if self.selected == RuntimeTransport::XaiKeychain {
                    self.revoke_owned_credential();
                }
                self.apply_adapter_failure_policy(&failure);
                Err(failure.reason)
            }
        }
    }

    pub(crate) fn delete_xai_key(&mut self) -> Result<(), String> {
        if self.selected == RuntimeTransport::XaiKeychain {
            self.disconnect()?;
        }
        let broker = self
            .credential_broker
            .as_mut()
            .ok_or_else(|| "Only the Account runtime may delete an xAI credential.".to_owned())?;
        let result = broker.delete();
        self.sync_keychain_state();
        result?;
        self.credential_lease = None;
        self.keychain_broker_sha256 = None;
        self.persist_account_preferences(self.current_preferences())?;
        Ok(())
    }

    pub(crate) fn acknowledge_onboarding(&mut self) -> Result<(), String> {
        let mut preferences = self.current_preferences();
        preferences.onboarding_acknowledged = true;
        self.persist_account_preferences(preferences)
    }

    fn persist_account_preferences(
        &mut self,
        preferences: AccountPreferences,
    ) -> Result<(), String> {
        if let Some(store) = &self.account_preferences
            && let Err(reason) = store.save(preferences.clone())
        {
            self.account_preference_issue =
                Some(format!("Account preference persistence failed: {reason}"));
            return Err(reason);
        }
        self.selected = preferences.selected_transport;
        self.onboarding_acknowledged = preferences.onboarding_acknowledged;
        self.auto_reconnect_enabled = preferences.auto_reconnect_enabled;
        self.reconnect_grant = preferences.reconnect_grant;
        self.credential_binding_identity = preferences.credential_binding_identity;
        self.keychain_broker_sha256 = preferences.keychain_broker_sha256;
        self.account_preference_issue = None;
        Ok(())
    }

    fn current_preferences(&self) -> AccountPreferences {
        AccountPreferences {
            selected_transport: self.selected,
            onboarding_acknowledged: self.onboarding_acknowledged,
            auto_reconnect_enabled: self.auto_reconnect_enabled,
            reconnect_grant: self.reconnect_grant,
            credential_binding_identity: self.credential_binding_identity.clone(),
            keychain_broker_sha256: self.keychain_broker_sha256.clone(),
        }
    }

    fn renew_reconnect_grant(&mut self, now_utc_ms: u64) -> Result<(), String> {
        if !self.auto_reconnect_enabled {
            self.reconnect_grant = None;
            self.credential_binding_identity = None;
            return Ok(());
        }
        self.reconnect_grant = Some(ReconnectGrant::fixed(self.selected, now_utc_ms)?);
        self.credential_binding_identity = match self.selected {
            RuntimeTransport::XaiKeychain
                if binding_matches_stable_broker(self.keychain_broker_sha256.as_deref()) =>
            {
                stable_signing_identity().map(str::to_owned)
            }
            RuntimeTransport::XaiKeychain | RuntimeTransport::GrokCliAcp => None,
        };
        Ok(())
    }

    pub(crate) fn set_auto_reconnect(&mut self, enabled: bool) -> Result<(), String> {
        self.auto_reconnect_enabled = enabled;
        if !enabled {
            self.reconnect_grant = None;
            self.credential_binding_identity = None;
        } else if self.connection.connected() {
            self.renew_reconnect_grant(unix_time_millis())?;
        }
        self.persist_account_preferences(self.current_preferences())
    }

    pub(crate) fn reconnect_authorized(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if self.auto_reconnect_attempted {
            return Err(
                "Automatic reconnect already made its one allowed attempt for this launch or unlock. Use Check connection for another explicit attempt."
                    .into(),
            );
        }
        let now_utc_ms = unix_time_millis();
        if self
            .reconnect_grant
            .is_some_and(|grant| grant.authorized_at_utc_ms > now_utc_ms)
        {
            self.reconnect_grant = None;
            self.credential_binding_identity = None;
            self.persist_account_preferences(self.current_preferences())?;
            return Err(
                "Automatic reconnect refused a clock rollback relative to the saved authorization. Connect explicitly to create a new fixed window."
                    .into(),
            );
        }
        match self.reconnect_state_at(now_utc_ms) {
            ReconnectState::Active { .. } => {}
            ReconnectState::Disabled => return Err("Automatic reconnect is disabled.".into()),
            ReconnectState::NeedsConnection => {
                return Err("Connect explicitly once to authorize automatic reconnect.".into());
            }
            ReconnectState::Expired { .. } => {
                return Err("The fixed seven-day reconnect authorization expired.".into());
            }
            ReconnectState::BindingRequired => {
                return Err(
                    "XaiKeychain automatic reconnect requires this app's stable local signing identity and a verified credential migration."
                        .into(),
                );
            }
            ReconnectState::Reconnecting { .. } => {
                return Err("Automatic reconnect is already in progress.".into());
            }
            ReconnectState::SuspendedForLock => {
                return Err("Automatic reconnect is suspended while macOS is locked.".into());
            }
        }
        self.auto_reconnect_attempted = true;
        self.reconnecting = true;
        self.suspended_for_lock = false;
        let result = self.connect_internal(events, false);
        self.reconnecting = false;
        result
    }

    pub(crate) fn suspend_for_lock(&mut self) -> Result<(), String> {
        self.connection = ConnectionState::Disconnected;
        self.suspended_for_lock = true;
        self.auto_reconnect_attempted = false;
        self.provider_session_id = None;
        self.latest_usage = None;
        let cancel = self.cancel.request_cancel();
        let close = self.close_adapter();
        self.revoke_owned_credential();
        cancel.and(close)
    }

    pub(crate) fn begin_unlock_reconnect(&mut self) -> Result<bool, String> {
        if !self.suspended_for_lock {
            return Ok(false);
        }
        self.suspended_for_lock = false;
        self.auto_reconnect_attempted = false;
        let now_utc_ms = unix_time_millis();
        if self
            .reconnect_grant
            .is_some_and(|grant| grant.authorized_at_utc_ms > now_utc_ms)
        {
            self.reconnect_grant = None;
            self.credential_binding_identity = None;
            self.persist_account_preferences(self.current_preferences())?;
            return Err(
                "Automatic reconnect refused a clock rollback relative to the saved authorization. Connect explicitly to create a new fixed window."
                    .into(),
            );
        }
        if matches!(
            self.reconnect_state_at(now_utc_ms),
            ReconnectState::Active { .. }
        ) {
            self.auto_reconnect_attempted = true;
            self.reconnecting = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn finish_unlock_reconnect(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if !self.reconnecting {
            return Ok(());
        }
        let result = self.connect_internal(events, false);
        self.reconnecting = false;
        result
    }

    fn sync_keychain_state(&mut self) {
        if let Some(broker) = self.credential_broker.as_ref() {
            self.keychain_presence = broker.presence().clone();
            self.keychain_migration_state = broker.migration_state().clone();
        }
    }

    fn adapter_build_failure(&self, reason: String) -> AdapterFailure {
        let kind = match self.selected {
            RuntimeTransport::GrokCliAcp => AdapterFailureKind::MissingRuntime,
            RuntimeTransport::XaiKeychain => AdapterFailureKind::LocalSecurity,
        };
        AdapterFailure::new(kind, reason)
    }

    fn apply_adapter_failure_policy(&mut self, failure: &AdapterFailure) {
        if failure.clears_reconnect_grant() {
            self.reconnect_grant = None;
            self.credential_binding_identity = None;
            if let Err(reason) = self.persist_account_preferences(self.current_preferences()) {
                self.account_preference_issue = Some(format!(
                    "The reconnect authorization was cleared in memory, but persistence failed: {reason}"
                ));
            }
        }
    }

    fn reconnect_state_at(&self, now_utc_ms: u64) -> ReconnectState {
        if !self.auto_reconnect_enabled {
            return ReconnectState::Disabled;
        }
        if self.suspended_for_lock {
            return ReconnectState::SuspendedForLock;
        }
        if self.reconnecting {
            return ReconnectState::Reconnecting {
                transport: self.selected,
            };
        }
        let Some(grant) = self.reconnect_grant else {
            return ReconnectState::NeedsConnection;
        };
        if grant.authorized_at_utc_ms > now_utc_ms {
            return ReconnectState::NeedsConnection;
        }
        if grant.transport != self.selected {
            return ReconnectState::NeedsConnection;
        }
        if !grant.is_unexpired(now_utc_ms) {
            return ReconnectState::Expired {
                expired_at_utc_ms: grant.expires_at_utc_ms,
            };
        }
        if self.selected == RuntimeTransport::XaiKeychain
            && (!matches!(
                self.keychain_migration_state,
                KeychainMigrationState::Unchecked | KeychainMigrationState::BrokerV3
            ) || !binding_matches_stable_identity(self.credential_binding_identity.as_deref())
                || !binding_matches_stable_broker(self.keychain_broker_sha256.as_deref()))
        {
            return ReconnectState::BindingRequired;
        }
        ReconnectState::Active {
            expires_at_utc_ms: grant.expires_at_utc_ms,
        }
    }

    fn ensure_xai_credential_lease(&mut self) -> Result<(), String> {
        self.ensure_xai_credential_lease_with_interaction(true)
    }

    fn ensure_xai_credential_lease_without_ui(&mut self) -> Result<(), String> {
        self.ensure_xai_credential_lease_with_interaction(false)
    }

    fn ensure_xai_credential_lease_with_interaction(
        &mut self,
        allow_interaction: bool,
    ) -> Result<(), String> {
        if self
            .credential_lease
            .as_ref()
            .is_some_and(XaiCredentialLease::is_active)
        {
            return Ok(());
        }
        let broker = self.credential_broker.as_mut().ok_or_else(|| {
            "Queued XaiKeychain runtime inherited no active credential lease.".to_owned()
        })?;
        let result = if allow_interaction {
            broker.open_explicit()
        } else {
            broker.open_automatic()
        };
        self.sync_keychain_state();
        self.credential_lease = Some(result?);
        Ok(())
    }

    fn revoke_owned_credential(&mut self) {
        self.clear_read_aloud_credential();
        if let Some(broker) = self.credential_broker.as_mut() {
            broker.revoke();
            self.keychain_presence = broker.presence().clone();
        }
        self.credential_lease = None;
    }

    fn child_executor(
        &self,
    ) -> Result<Option<Arc<dyn grok_build_plus_host::PlusExternalToolExecutor>>, String> {
        if self.role == grok_build_plus_host::PlusRuntimeToolPolicy::Parent {
            return Ok(None);
        }
        if self.browser.is_some()
            || self.capture.is_some()
            || self.desktop.is_some()
            || self.mcp.is_some()
            || self.credential_broker.is_some()
            || self.read_aloud_credential.is_some()
            || self.collaboration.is_some()
        {
            return Err(
                "Child runtime unexpectedly inherited a high-power or credential-store handle."
                    .into(),
            );
        }
        Ok(Some(Arc::new(super::role_tools::ChildTools::new(
            self.role,
        )?)))
    }

    fn parent_external(
        &self,
        mcp: Option<Arc<crate::extensions::mcp::broker::McpRunExecutor>>,
    ) -> Option<Arc<dyn grok_build_plus_host::PlusExternalToolExecutor>> {
        match (&self.browser, &self.desktop, &self.browser_run_context) {
            (Some(browser), Some(desktop), Some((project, run))) => Some(Arc::new(
                HighPowerToolExecutor::new(
                    browser.clone(),
                    desktop.clone(),
                    project.clone(),
                    run.clone(),
                )
                .with_mcp(mcp),
            )),
            _ => None,
        }
    }

    fn build_selected_adapter(&self) -> Result<Box<dyn LiveRuntimeAdapter>, String> {
        if let Some(issue) = &self.engine.issue {
            return Err(issue.clone());
        }
        let child_executor = self.child_executor()?;
        let mcp = match (&self.mcp, &self.browser_run_context) {
            (Some(broker), Some((project, run))) => broker.prepare(
                project,
                run,
                self.cancel.clone(),
                self.service_context.as_ref(),
            )?,
            _ => None,
        };
        let mut external = child_executor.or_else(|| self.parent_external(mcp));
        if let Some(controller) = &self.collaboration {
            external = Some(Arc::new(super::collaboration_tools::ParentTools::new(
                external,
                controller.clone(),
            )?));
        }
        match self.selected {
            RuntimeTransport::XaiKeychain => {
                let credential = self
                    .credential_lease
                    .as_ref()
                    .filter(|lease| lease.is_active())
                    .cloned()
                    .ok_or_else(|| {
                        "XaiKeychain adapter requires an active credential lease.".to_owned()
                    })?;
                let mut adapter = match external {
                    Some(executor) => XaiKeychainAdapter::new_with_external(
                        credential,
                        self.cancel.clone(),
                        executor,
                    ),
                    None => XaiKeychainAdapter::new(credential, self.cancel.clone()),
                };
                if let Some(binding) = &self.conversation {
                    adapter.bind_context_root(binding.root());
                    adapter
                        .configure_native_protocol(super::native_protocol::NativeProtocol::load(
                            binding.root(),
                        )?)
                        .map_err(|error| error.to_string())?;
                    if let Some(selection) =
                        super::models::ModelSelection::load(binding.root(), self.selected)?
                    {
                        adapter
                            .configure_model(selection)
                            .map_err(|error| error.to_string())?;
                    }
                }
                adapter.require_transient_context(self.context_transient);
                Ok(Box::new(adapter))
            }
            RuntimeTransport::GrokCliAcp => {
                let root = self.conversation.as_ref().map_or(
                    self.state_root.as_path(),
                    super::conversation::ConversationBinding::root,
                );
                let mut config = if self.standard_engine() {
                    let workspace = self
                        .engine
                        .workspace
                        .as_deref()
                        .ok_or("Open a project before connecting the standard CLI.")?;
                    let lease = self
                        .conversation
                        .as_ref()
                        .map(|binding| self.engine.pool.lease(binding.root()))
                        .transpose()?;
                    AcpLaunchConfig::standard(root, workspace, &self.engine.settings, lease)?
                } else {
                    AcpLaunchConfig::production(root)?
                };
                config.bind_permission(root)?;
                let mut adapter = match external {
                    Some(executor) => {
                        GrokCliAcpAdapter::new_with_external(config, self.cancel.clone(), executor)
                    }
                    None => GrokCliAcpAdapter::new(config, self.cancel.clone()),
                };
                if let Some(binding) = &self.conversation
                    && let Some(selection) =
                        super::models::ModelSelection::load(binding.root(), self.selected)?
                {
                    adapter
                        .configure_model(selection)
                        .map_err(|error| error.to_string())?;
                }
                adapter.require_transient_context(self.context_transient);
                Ok(Box::new(adapter))
            }
        }
    }

    fn close_adapter(&mut self) -> Result<(), String> {
        let Some(mut adapter) = self.adapter.take() else {
            return Ok(());
        };
        let cancel_result = adapter.cancel_run();
        let close_result = adapter.close_session();
        cancel_result.and(close_result)
    }

    #[cfg(test)]
    fn with_adapter(
        selected: RuntimeTransport,
        secrets: Arc<dyn ProviderSecretStore>,
        adapter: Box<dyn LiveRuntimeAdapter>,
    ) -> Self {
        let credential_broker = XaiCredentialBroker::new(secrets);
        let keychain_presence = credential_broker.presence().clone();
        let keychain_migration_state = credential_broker.migration_state().clone();
        Self {
            engine: engine::EngineState::default(),
            selected,
            connection: ConnectionState::Disconnected,
            adapter: Some(adapter),
            credential_broker: Some(credential_broker),
            credential_lease: None,
            read_aloud_credential: None,
            read_aloud_failure: None,
            keychain_presence,
            keychain_migration_state,
            account_preferences: None,
            onboarding_acknowledged: false,
            auto_reconnect_enabled: true,
            reconnect_grant: None,
            credential_binding_identity: None,
            keychain_broker_sha256: None,
            reconnecting: false,
            suspended_for_lock: false,
            auto_reconnect_attempted: false,
            last_adapter_failure: None,
            account_preference_issue: None,
            state_root: PathBuf::from("/not-used"),
            cancel: RuntimeCancelHandle::new(),
            provider_session_id: None,
            conversation: None,
            latest_usage: None,
            browser: None,
            browser_run_context: None,
            capture: None,
            desktop: None,
            mcp: None,
            service_context: None,
            hook_policy: None,
            role: grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
            collaboration: None,
            context_transient: false,
        }
    }
}

fn bounded_reason(reason: &str) -> String {
    const MAX_REASON_BYTES: usize = 4 * 1024;
    if reason.len() <= MAX_REASON_BYTES {
        return reason.to_owned();
    }
    let mut end = MAX_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &reason[..end])
}

#[cfg(test)]
mod tests;
