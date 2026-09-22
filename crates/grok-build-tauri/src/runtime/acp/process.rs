//! ACP process launch, framing, bounded I/O, and profile persistence.

use super::protocol::{
    bounded_event_discriminator, emit_acp_context_usage, emit_unsupported_acp_event,
    handle_strict_session_notification, validate_active_session, validate_announcements_update,
    validate_available_commands_update, validate_cli_queue_is_not_owning_work,
    validate_models_update, validate_prompt_complete, validate_provisional_session_update,
    validate_session_info_update, validate_session_new_result, validate_sessions_changed,
    validate_settings_update, validate_user_message_chunk,
};
use super::{
    ACP_CANCEL_POLL, ACP_MAX_LINE_BYTES, ACP_MAX_RESPONSE_BYTES, ACP_MAX_RESPONSE_MESSAGES,
    ACP_NEUTRAL_CWD, ACP_PROFILE_FILE, ACP_REQUEST_TIMEOUT, Arc, BufRead, BufReader,
    ChildEnvironmentProfile, ChildStdin, Command, File, Instant, Mutex, OpenOptions, Path, PathBuf,
    Receiver, RecvTimeoutError, RuntimeCancelHandle, RuntimeEvent, RuntimeEventSink, Stdio, Value,
    Write, fs, json, mpsc, strict_acp_profile,
};

#[derive(Clone, Debug)]
pub(crate) struct AcpLaunchConfig {
    pub(super) cli_path: PathBuf,
    pub(super) runtime_root: PathBuf,
    memory_backed: bool,
    pub(super) standard: Option<super::standard::StandardLaunch>,
}

impl AcpLaunchConfig {
    pub(crate) fn production(state_root: &Path) -> Result<Self, String> {
        let cli_path = find_grok_cli().ok_or_else(|| {
            "The grok CLI is not installed. GrokCliAcp cannot connect.".to_owned()
        })?;
        Ok(Self {
            cli_path,
            runtime_root: state_root.join("acp-runtime"),
            memory_backed: cfg!(target_os = "macos"),
            standard: None,
        })
    }

    pub(crate) fn standard(
        state_root: &Path,
        cwd: &Path,
        settings: &crate::runtime::engine::EngineSettings,
        lease: Option<super::standard::StandardLease>,
    ) -> Result<Self, String> {
        let home = crate::runtime::engine::managed_home()?;
        let cli_path = settings
            .developer_cli
            .clone()
            .map_or_else(crate::runtime::engine::managed_cli, Ok)?;
        let cwd = fs::canonicalize(cwd)
            .map_err(|e| format!("Cannot open the CLI project folder: {e}"))?;
        if !cwd.is_dir() {
            return Err("The CLI working folder is not a directory.".into());
        }
        Ok(Self {
            cli_path,
            runtime_root: state_root.join("acp-runtime"),
            memory_backed: false,
            standard: Some(super::standard::StandardLaunch {
                home,
                cwd,
                developer: settings.developer_cli.is_some(),
                permission: crate::runtime::cli_permissions::CliPermissionMode::Ask,
                lease,
            }),
        })
    }

    pub(super) fn is_standard(&self) -> bool {
        self.standard.is_some()
    }

    pub(crate) fn bind_permission(&mut self, root: &Path) -> Result<(), String> {
        if let Some(standard) = &mut self.standard {
            standard.permission =
                crate::runtime::cli_permissions::CliPermissionChoice::load(root)?.mode;
        }
        Ok(())
    }

    pub(crate) fn cli_path(&self) -> &Path {
        &self.cli_path
    }

    fn inspect_compatibility(&self) -> Result<crate::runtime::cli::CliCompatibility, String> {
        #[cfg(test)]
        if !self.memory_backed {
            return crate::runtime::cli::inspect_version(&self.cli_path);
        }
        crate::runtime::cli::inspect_cli(&self.cli_path)
    }

    #[cfg(test)]
    pub(super) fn for_test(cli_path: PathBuf, runtime_root: PathBuf) -> Self {
        Self {
            cli_path,
            runtime_root,
            memory_backed: false,
            standard: None,
        }
    }

    pub(super) fn prepare(&self) -> Result<PreparedAcpLaunch, String> {
        if let Some(standard) = &self.standard {
            return Ok(PreparedAcpLaunch {
                cli_path: self.cli_path.clone(),
                cwd: standard.cwd.clone(),
                profile: PathBuf::new(),
                home: standard.home.join(".grok"),
                auth_path: PathBuf::new(),
                #[cfg(target_os = "macos")]
                memory: None,
            });
        }
        ensure_owner_directory(&self.runtime_root)?;
        let cwd = self.runtime_root.join(ACP_NEUTRAL_CWD);
        ensure_owner_directory(&cwd)?;
        // The CLI reports its physical cwd (macOS /var is a /private/var alias).
        // Bind that exact identity consistently in launch, load, and readback.
        let cwd = fs::canonicalize(&cwd)
            .map_err(|error| format!("Cannot identify neutral ACP cwd: {error}"))?;
        let profile = self.runtime_root.join(ACP_PROFILE_FILE);
        write_owner_only_atomic(&profile, strict_acp_profile().as_bytes())?;
        #[cfg(target_os = "macos")]
        let memory = self
            .memory_backed
            .then(|| super::memory_home::MemoryHome::acquire(&self.runtime_root))
            .transpose()?;
        let mut home = self.runtime_root.join("home");
        #[cfg(target_os = "macos")]
        if let Some(memory) = &memory {
            home = memory.path().to_path_buf();
        }
        ensure_owner_directory(&home)?;
        ensure_owner_directory(&home.join("os-home"))?;
        write_owner_only_atomic(
            &home.join("config.toml"),
            super::isolation::ACP_CONFIG.as_bytes(),
        )?;
        Ok(PreparedAcpLaunch {
            cli_path: self.cli_path.clone(),
            cwd,
            profile,
            home,
            auth_path: crate::runtime::auth_paths::cli_auth_path()?,
            #[cfg(target_os = "macos")]
            memory,
        })
    }
}

pub(super) struct PreparedAcpLaunch {
    pub(super) cli_path: PathBuf,
    pub(super) cwd: PathBuf,
    pub(super) profile: PathBuf,
    pub(super) home: PathBuf,
    pub(super) auth_path: PathBuf,
    #[cfg(target_os = "macos")]
    memory: Option<Arc<super::memory_home::MemoryHome>>,
}

impl PreparedAcpLaunch {
    fn command(&self, standard: Option<&super::standard::StandardLaunch>) -> Command {
        let mut command = Command::new(&self.cli_path);
        if let Some(standard) = standard {
            command
                .args(["agent", "stdio"])
                .env("HOME", &standard.home)
                .env("GROK_HOME", &self.home);
        } else {
            command
                .args([
                    "--no-subagents",
                    "--no-plan",
                    "--disable-web-search",
                    "agent",
                    "--no-leader",
                    "--agent-profile",
                ])
                .arg(&self.profile)
                .arg("stdio");
            ChildEnvironmentProfile::Acp.apply(&mut command);
            command.env("GROK_HOME", &self.home);
            command.env("HOME", self.home.join("os-home"));
            command.env("GROK_AUTH_PATH", &self.auth_path);
        }
        command
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command
    }
}

pub(super) struct AcpProcess {
    child: crate::bounded_process::OwnedProcess,
    pub(super) stdin: Arc<Mutex<ChildStdin>>,
    pub(super) messages: Receiver<Result<Value, String>>,
    pub(super) next_id: u64,
    pub(super) neutral_cwd: PathBuf,
    pub(super) cancel: RuntimeCancelHandle,
    pub(super) active_session_id: Option<String>,
    pub(super) last_http_status: Option<u16>,
    pub(super) app_tools: super::mcp::ReverseMcpServer,
    pub(super) runtime_root: PathBuf,
    pub(super) home: PathBuf,
    pub(super) mirrors: bool,
    pub(super) verified_image_input: bool,
    terminated: bool,
    mode: crate::runtime::engine::EngineMode,
    pub(super) initialized: Option<Value>,
    pub(super) session_config: Value,
    pub(super) applied_permission: Option<crate::runtime::cli_permissions::CliPermissionMode>,
    pub(super) native_children: std::collections::BTreeSet<String>,
    #[cfg(target_os = "macos")]
    memory: Option<Arc<super::memory_home::MemoryHome>>,
}

impl AcpProcess {
    pub(super) fn is_standard(&self) -> bool {
        self.mode == crate::runtime::engine::EngineMode::GrokCliStandard
    }

    pub(super) fn spawn(
        config: &AcpLaunchConfig,
        cancel: RuntimeCancelHandle,
    ) -> Result<Self, String> {
        let _operation = crate::runtime::cli::operation_guard()?;
        let compatibility = if let Some(standard) = &config.standard {
            if !standard.developer {
                crate::runtime::cli::verify_standard_publisher(&config.cli_path)?;
            }
            None
        } else {
            let compatibility = config.inspect_compatibility()?;
            if !compatibility.supported {
                return Err(compatibility.detail);
            }
            Some(compatibility)
        };
        let prepared = config.prepare()?;
        let mut command = prepared.command(config.standard.as_ref());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }

        let mut child =
            crate::bounded_process::OwnedProcess::spawn(&mut command).map_err(|error| {
                format!(
                    "cannot start strict Grok CLI ACP at {}: {error}",
                    prepared.cli_path.display()
                )
            })?;
        #[cfg(target_os = "macos")]
        if let Some(memory) = &prepared.memory {
            child.retain_resource(Box::new(Arc::clone(memory)))?;
        }
        cancel.retain_cleanup(child.cleanup_proof()?)?;
        let stdin = child.take_stdin()?;
        #[cfg(unix)]
        {
            let flags = rustix::fs::fcntl_getfl(&stdin)
                .map_err(|error| format!("Cannot inspect ACP pipe: {error}"))?;
            rustix::fs::fcntl_setfl(&stdin, flags | rustix::fs::OFlags::NONBLOCK)
                .map_err(|error| format!("Cannot bound ACP pipe writes: {error}"))?;
        }
        let stdout = child.take_stdout()?;
        // At the maximum frame size, four queued messages reserve at most
        // 48 MiB of encoded input per connection and backpressure the CLI.
        let (sender, messages) = mpsc::sync_channel(4);
        std::thread::Builder::new()
            .name("grok-build-plus-acp-reader".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    match read_bounded_json_line(&mut reader) {
                        Ok(Some(message)) => {
                            if sender.send(Ok(message)).is_err() {
                                break;
                            }
                        }
                        Ok(None) => {
                            let _ = sender.send(Err("Grok CLI ACP closed stdout.".into()));
                            break;
                        }
                        Err(error) => {
                            let _ = sender.send(Err(error));
                            break;
                        }
                    }
                }
            })
            .map_err(|error| format!("cannot start the ACP reader: {error}"))?;
        Ok(Self {
            child,
            stdin: Arc::new(Mutex::new(stdin)),
            messages,
            next_id: 1,
            neutral_cwd: prepared.cwd,
            cancel,
            active_session_id: None,
            last_http_status: None,
            app_tools: super::mcp::ReverseMcpServer::new(),
            runtime_root: config.runtime_root.clone(),
            home: prepared.home,
            mirrors: config.memory_backed,
            // Version-scoped runtime evidence supplements incomplete ACP metadata.
            // Production macOS inspect_cli verified publisher and exact binary digest.
            verified_image_input: cfg!(target_os = "macos")
                && config.memory_backed
                && compatibility
                    .as_ref()
                    .and_then(|value| value.version.as_deref())
                    == Some("1.0.25"),
            terminated: false,
            mode: if config.is_standard() {
                crate::runtime::engine::EngineMode::GrokCliStandard
            } else {
                crate::runtime::engine::EngineMode::GbPlusContained
            },
            initialized: None,
            session_config: Value::Null,
            applied_permission: None,
            native_children: std::collections::BTreeSet::new(),
            #[cfg(target_os = "macos")]
            memory: prepared.memory,
        })
    }

    pub(super) fn request(
        &mut self,
        method: &str,
        params: &Value,
        events: &RuntimeEventSink<'_>,
    ) -> Result<Value, String> {
        self.request_with_steering(method, params, events, None)
    }

    pub(super) fn request_with_steering(
        &mut self,
        method: &str,
        params: &Value,
        events: &RuntimeEventSink<'_>,
        steering: Option<&super::RuntimeSteeringSource<'_>>,
    ) -> Result<Value, String> {
        self.last_http_status = None;
        self.cancel.ensure_not_cancelled()?;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| "ACP request id exhausted.".to_owned())?;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))?;
        self.wait_for_response_bounded(id, method, events, true, steering)
    }

    pub(super) fn send(&self, message: &Value) -> Result<(), String> {
        self.validate_home()?;
        let mut encoded = serde_json::to_vec(message)
            .map_err(|error| format!("cannot encode ACP message: {error}"))?;
        if encoded.len() > ACP_MAX_LINE_BYTES {
            return Err("ACP request exceeded the 12 MiB message cap.".into());
        }
        encoded.push(b'\n');
        let mut stdin = self
            .stdin
            .lock()
            .map_err(|_| "Grok CLI ACP stdin lock is unavailable.".to_owned())?;
        let started = Instant::now();
        let mut sent = 0;
        while sent < encoded.len() {
            if started.elapsed() > std::time::Duration::from_secs(5) {
                return Err("ACP frame write timed out; delivery is uncertain and the connection must stop.".into());
            }
            match stdin.write(&encoded[sent..]) {
                Ok(0) => return Err("ACP stdin closed during its frame.".into()),
                Ok(count) => sent += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(format!("Cannot write ACP frame: {error}")),
            }
        }
        Ok(())
    }

    pub(super) fn request_close_during_teardown(&mut self, session_id: &str) -> Result<(), String> {
        self.app_tools.revoke();
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| "ACP request id exhausted during close.".to_owned())?;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "_x.ai/session/close",
            "params": { "sessionId": session_id },
        }))?;
        self.wait_for_response_bounded(id, "_x.ai/session/close", &|_| Ok(()), false, None)
            .map(|_| ())
    }

    fn wait_for_response_bounded(
        &mut self,
        expected_id: u64,
        request_method: &str,
        events: &RuntimeEventSink<'_>,
        observe_cancel: bool,
        steering: Option<&super::RuntimeSteeringSource<'_>>,
    ) -> Result<Value, String> {
        let mut started = Instant::now();
        let mut aggregate_bytes = 0_usize;
        let mut aggregate_messages = 0_usize;
        let mut provisional_session_id = None;
        let mut pump = steering.map(|source| {
            super::steering::SteeringPump::new(
                source,
                self.active_session_id.clone().unwrap_or_default(),
            )
        });
        let mut terminal_result = None;
        let mut cancel_started = None;
        let mut last_poll = Instant::now();
        loop {
            self.poll_native_controls(events, &mut started, &mut last_poll)?;
            self.validate_home()?;
            if observe_cancel {
                self.observe_cancellation(request_method, &mut cancel_started)?;
            }
            if let Some(pump) = &mut pump
                && cancel_started.is_none()
            {
                pump.poll(self, terminal_result.is_some())?;
                if terminal_result.is_some() && pump.settled() {
                    return terminal_result.ok_or("ACP terminal result disappeared.".into());
                }
            }
            let remaining = self.response_poll_interval(request_method, started)?;
            let Some(message) = self.receive_response_message(remaining)? else {
                continue;
            };
            aggregate_messages = aggregate_messages.saturating_add(1);
            self.validate_response_frame(&message, &mut aggregate_bytes, aggregate_messages)?;
            if super::protocol::internal_reload_observation(&message)? {
                continue;
            }

            // Agent requests have their own ID namespace. Classify by shape
            // before matching a response ID, including during session/new.
            if let Some(method) = message.get("method").and_then(Value::as_str)
                && message.get("id").is_some()
            {
                self.bind_startup_interaction(
                    &message,
                    method,
                    request_method,
                    &mut provisional_session_id,
                )?;
                let effect_started = Instant::now();
                self.handle_agent_request(&message, method, events)?;
                // Waiting for an app tool is not inference inactivity.
                let elapsed = effect_started.elapsed();
                started += elapsed;
                if let Some(pump) = &mut pump {
                    pump.pause_for_app_tool(elapsed);
                }
                continue;
            }

            if let Some(pump) = &mut pump
                && message.get("method").is_none()
                && pump.response(&message, &self.neutral_cwd)?
            {
                continue;
            }

            if message.get("id").and_then(Value::as_u64) == Some(expected_id) {
                let result = self.correlated_result(&message, request_method)?;
                if cancel_started.is_some() {
                    self.terminate()?;
                    return Ok(result);
                }
                validate_session_new_result(
                    request_method,
                    &result,
                    provisional_session_id.as_deref(),
                )?;
                if pump.as_ref().is_some_and(|pump| !pump.settled()) {
                    terminal_result = Some(result);
                    continue;
                }
                return Ok(result);
            }

            if let Some(method) = message.get("method").and_then(Value::as_str) {
                if message.get("id").is_some() {
                    self.refuse_agent_request(&message, method, events)?;
                } else {
                    self.handle_notification(
                        &message,
                        method,
                        request_method,
                        &mut provisional_session_id,
                        events,
                    )?;
                    if request_method == "session/prompt"
                        && matches!(method, "session/update" | "_x.ai/session/update")
                    {
                        started = Instant::now();
                    }
                }
                continue;
            }

            return Err(Self::uncorrelated_message(&message, expected_id));
        }
    }

    fn response_poll_interval(
        &mut self,
        method: &str,
        started: Instant,
    ) -> Result<std::time::Duration, String> {
        if self.is_standard() && method == "session/prompt" {
            return Ok(ACP_CANCEL_POLL);
        }
        let deadline = if self.is_standard() && method == "_x.ai/session/close" {
            std::time::Duration::from_secs(10)
        } else if method == "session/prompt" {
            std::time::Duration::from_mins(5)
        } else {
            ACP_REQUEST_TIMEOUT
        };
        if let Some(remaining) = deadline.checked_sub(started.elapsed()) {
            return Ok(remaining);
        }
        self.terminate()?;
        Err("Grok CLI ACP exceeded its control or model-progress deadline and was stopped.".into())
    }

    fn observe_cancellation(
        &mut self,
        method: &str,
        started: &mut Option<Instant>,
    ) -> Result<(), String> {
        if !self.cancel.cancelled() {
            return Ok(());
        }
        if !self.is_standard() || method != "session/prompt" {
            self.terminate()?;
            return Err("Grok CLI ACP request was cancelled and the child was stopped.".into());
        }
        if let Some(at) = *started {
            if at.elapsed() > std::time::Duration::from_secs(30) {
                self.terminate()?;
                return Err("CLI did not acknowledge Stop. The connection was closed; this turn will not be replayed.".into());
            }
        } else {
            self.app_tools.revoke();
            self.send(&json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":self.active_session_id}}))?;
            *started = Some(Instant::now());
        }
        Ok(())
    }

    fn uncorrelated_message(message: &Value, expected_id: u64) -> String {
        format!(
            "Grok CLI ACP returned an uncorrelated message (expected {expected_id}; received numeric id {:?}; error code {:?}; error message {}; structural shape {}).",
            message.get("id").and_then(Value::as_i64),
            message.pointer("/error/code").and_then(Value::as_i64),
            message
                .pointer("/error/message")
                .and_then(Value::as_str)
                .map_or_else(
                    || "absent".into(),
                    super::protocol::bounded_event_discriminator
                ),
            diagnostic_shape(message, 0)
        )
    }

    pub(super) fn handle_agent_request(
        &mut self,
        message: &Value,
        method: &str,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if method == super::mcp::REVERSE_METHOD {
            let params = message
                .get("params")
                .ok_or("ACP reverse request has no parameters.")?;
            let result =
                if let Some(refusal) = self.app_tools.inactive_response(params, &message["id"])? {
                    refusal
                } else {
                    self.cancel.ensure_not_cancelled()?;
                    self.app_tools
                        .handle_reverse(params, &message["id"], events)?
                };
            self.send(&json!({"jsonrpc":"2.0", "id":message["id"], "result":result}))?;
        } else if self.is_standard() {
            self.handle_native_request(message, method, events)?;
        } else {
            self.refuse_agent_request(message, method, events)?;
        }
        Ok(())
    }

    pub(super) fn receive_response_message(
        &mut self,
        remaining: std::time::Duration,
    ) -> Result<Option<Value>, String> {
        match self.messages.recv_timeout(remaining.min(ACP_CANCEL_POLL)) {
            Ok(Ok(message)) => Ok(Some(message)),
            Ok(Err(error)) => {
                self.terminate()?;
                Err(error)
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.terminate()?;
                Err("Grok CLI ACP reader stopped.".into())
            }
        }
    }

    pub(super) fn validate_response_frame(
        &mut self,
        message: &Value,
        aggregate_bytes: &mut usize,
        aggregate_messages: usize,
    ) -> Result<(), String> {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || message
                .get("id")
                .is_some_and(|id| !super::mcp::valid_rpc_id(id))
            || (message.get("method").is_some()
                && (message.get("result").is_some() || message.get("error").is_some()))
        {
            self.terminate()?;
            return Err("ACP message did not have an unambiguous JSON-RPC envelope.".into());
        }
        *aggregate_bytes = aggregate_bytes.saturating_add(
            serde_json::to_vec(message)
                .map_err(|error| format!("cannot bound ACP response message: {error}"))?
                .len(),
        );
        if !self.is_standard()
            && (aggregate_messages > ACP_MAX_RESPONSE_MESSAGES
                || *aggregate_bytes > ACP_MAX_RESPONSE_BYTES)
        {
            self.terminate()?;
            return Err(format!(
                "Grok CLI ACP exceeded its aggregate response bound ({ACP_MAX_RESPONSE_MESSAGES} messages / {ACP_MAX_RESPONSE_BYTES} bytes) and was stopped."
            ));
        }
        Ok(())
    }

    fn correlated_result(&mut self, message: &Value, method: &str) -> Result<Value, String> {
        if let Some(error) = message.get("error") {
            let detail = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown ACP error");
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .map_or_else(String::new, |code| format!(" (code {code})"));
            let http_status = error
                .pointer("/data/http_status")
                .and_then(Value::as_u64)
                .and_then(|status| u16::try_from(status).ok());
            self.last_http_status = http_status;
            let status = http_status.map_or_else(String::new, |status| format!(" (HTTP {status})"));
            return Err(format!(
                "Grok CLI ACP refused the request: {detail}{code}{status}"
            ));
        }
        let result = message
            .get("result")
            .cloned()
            .ok_or_else(|| "Grok CLI ACP response had no result.".to_owned())?;
        super::protocol::extension_result(method, &result).cloned()
    }

    fn refuse_agent_request(
        &self,
        message: &Value,
        method: &str,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        let id = message
            .get("id")
            .cloned()
            .ok_or_else(|| "ACP request was missing its id.".to_owned())?;
        let reason = format!(
            "Strict GrokCliAcp profile refuses agent request `{method}`; the GUI exposes no client filesystem, terminal, MCP, or machine-effect capability."
        );
        events(RuntimeEvent::ToolRefused {
            name: bounded_event_discriminator(method),
            reason: reason.clone(),
        })?;
        if method == "session/request_permission" {
            self.send(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "outcome": { "outcome": "cancelled" } },
            }))?;
        } else {
            self.send(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": reason },
            }))?;
        }
        Err(reason)
    }

    fn handle_notification(
        &mut self,
        message: &Value,
        method: &str,
        request_method: &str,
        provisional_session_id: &mut Option<String>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if self.is_standard() {
            self.observe_native_family(message);
            return super::standard::notification(
                message,
                method,
                self.active_session_id.as_deref(),
                events,
            );
        }
        if method == "_x.ai/models/update" {
            return validate_models_update(message);
        }
        if method == "_x.ai/settings/update" {
            return validate_settings_update(message);
        }
        if method == "_x.ai/announcements/update" {
            return validate_announcements_update(message);
        }
        if method == "_x.ai/sessions/changed" {
            return validate_sessions_changed(message, &self.neutral_cwd);
        }
        if method == "_x.ai/queue/changed" {
            self.require_active_session(message, "queue notification")?;
            return validate_cli_queue_is_not_owning_work(message);
        }
        if matches!(
            method,
            "_x.ai/session_notification" | "_x.ai/session/update"
        ) {
            if self.active_session_id.is_some() {
                self.require_active_session(message, "session notification")?;
            } else {
                validate_provisional_session_update(
                    message,
                    request_method,
                    provisional_session_id,
                )?;
            }
            return handle_strict_session_notification(message, events);
        }
        if method == "_x.ai/session/interjection" {
            self.require_active_session(message, "interjection acknowledgement")?;
            let params = message
                .get("params")
                .ok_or("Missing interjection parameters.")?;
            if params
                .get("interjectionId")
                .and_then(Value::as_str)
                .is_none_or(|id| id.is_empty() || id.len() > 256)
                || params
                    .get("text")
                    .and_then(Value::as_str)
                    .is_none_or(|text| text.len() > 16 * 1024)
            {
                return Err("ACP interjection acknowledgement exceeded its bounds.".into());
            }
            // Broadcast is a queue echo, never proof of history or consumption.
            return Ok(());
        }
        if method == "_x.ai/session/prompt_complete" {
            self.require_active_session(message, "prompt-complete notification")?;
            return validate_prompt_complete(message);
        }
        if matches!(
            method,
            "_x.ai/mcp/servers_updated"
                | "_x.ai/mcp/server_status"
                | "_x.ai/mcp_initialized"
                | "_x.ai/mcp/init_progress"
                | "_x.ai/mcp/tools_changed"
        ) {
            if method == "_x.ai/mcp/server_status" {
                if self.active_session_id.is_some() {
                    self.require_active_session(message, "MCP server status")?;
                } else {
                    validate_provisional_session_update(
                        message,
                        request_method,
                        provisional_session_id,
                    )?;
                }
            }
            return super::mcp::validate_notification(
                message,
                request_method == "_x.ai/session/close",
                self.app_tools.catalog()?.len(),
            );
        }
        if method != "session/update" {
            emit_unsupported_acp_event(events, method, message)?;
            let method = bounded_event_discriminator(method);
            return Err(format!(
                "Strict GrokCliAcp profile received unsupported notification `{method}`."
            ));
        }
        if let Some(active) = self.active_session_id.as_deref() {
            validate_active_session(message, Some(active), "session update")?;
        } else {
            validate_provisional_session_update(message, request_method, provisional_session_id)?;
        }
        Self::handle_session_update(message, events)
    }

    pub(super) fn handle_session_update(
        message: &Value,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        let update = message
            .pointer("/params/update")
            .ok_or_else(|| "ACP session/update had no update payload.".to_owned())?;
        let kind = update
            .get("sessionUpdate")
            .and_then(Value::as_str)
            .ok_or_else(|| "ACP session/update had no sessionUpdate discriminator.".to_owned())?;
        match kind {
            "agent_message_chunk" => {
                if let Some(text) = update.pointer("/content/text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    events(RuntimeEvent::AssistantDelta(text.to_owned()))?;
                }
                Ok(())
            }
            "agent_thought_chunk" => {
                if let Some(text) = update.pointer("/content/text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    events(RuntimeEvent::ThoughtDelta(text.to_owned()))?;
                }
                Ok(())
            }
            "user_message_chunk" => validate_user_message_chunk(update),
            "usage_update" => emit_acp_context_usage(update, events),
            "available_commands_update" => validate_available_commands_update(update),
            "session_info_update" => validate_session_info_update(update),
            // These are observations of the CLI's MCP gateway. Only the
            // reverse request dispatcher can authorize or complete an app tool.
            "plan" | "tool_call" | "tool_call_update" => Ok(()),
            other => {
                emit_unsupported_acp_event(events, other, update)?;
                Ok(())
            }
        }
    }

    fn require_active_session(&self, message: &Value, label: &str) -> Result<(), String> {
        validate_active_session(message, self.active_session_id.as_deref(), label)
    }

    pub(super) fn reuse_for_turn(&mut self, cancel: RuntimeCancelHandle) -> Result<(), String> {
        cancel.retain_cleanup(self.child.cleanup_proof()?)?;
        self.cancel = cancel;
        Ok(())
    }

    pub(super) fn release_idle_turn(&mut self) -> Result<(), String> {
        self.cancel.release_idle_cli(&self.child.cleanup_proof()?)
    }

    pub(super) fn terminate(&mut self) -> Result<(), String> {
        if !self.terminated {
            self.terminated = true;
            self.cancel.cli_interactions.close();
            self.app_tools.revoke();
            let closed = if self.is_standard() {
                self.active_session_id.clone().map_or(Ok(()), |session| {
                    self.request_close_during_teardown(&session)
                })
            } else {
                Ok(())
            };
            let stopped = self.child.stop();
            stopped?;
            closed?;
        }
        Ok(())
    }

    fn validate_home(&self) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        if let Some(home) = &self.memory {
            home.validate()?;
        }
        Ok(())
    }
}

fn diagnostic_shape(value: &Value, depth: usize) -> Value {
    if depth >= 4 {
        return json!("bounded");
    }
    match value {
        Value::String(text) => json!({"stringBytes":text.len()}),
        Value::Array(values) => {
            json!({"arrayLength":values.len(),"first":values.iter().take(2).map(|value|diagnostic_shape(value,depth+1)).collect::<Vec<_>>()})
        }
        // Unknown keys and scalar values can themselves contain transient
        // Browser/Desktop/Capture data. Diagnostics retain shape only; neither
        // readable-looking keys nor low-entropy payload hashes are persisted.
        Value::Object(values) => {
            json!({"objectFields":values.len(),"values":values.values().take(16).map(|value| diagnostic_shape(value, depth + 1)).collect::<Vec<_>>()})
        }
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("boolean"),
        Value::Null => Value::Null,
    }
}

impl Drop for AcpProcess {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub(super) fn read_bounded_json_line(reader: &mut impl BufRead) -> Result<Option<Value>, String> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| format!("cannot read Grok CLI ACP stdout: {error}"))?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(count) > ACP_MAX_LINE_BYTES {
            return Err("Grok CLI ACP response exceeded the 12 MiB line cap.".into());
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if line.last() == Some(&b'\n') {
            break;
        }
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|error| format!("Grok CLI ACP emitted malformed JSON: {error}"))
}
pub(crate) fn find_grok_cli() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(configured) = std::env::var_os("GROK_BUILD_GROK_CLI") {
        candidates.push(PathBuf::from(configured));
    }
    if let Some(grok_home) = std::env::var_os("GROK_HOME") {
        candidates.push(PathBuf::from(grok_home).join("bin/grok"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".grok/bin/grok"));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(
            std::env::split_paths(&path)
                .filter(|directory| directory.is_absolute())
                .map(|directory| directory.join("grok")),
        );
    }
    candidates
        .into_iter()
        .find(|candidate| executable_file(candidate))
}

pub(super) fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub(super) fn ensure_owner_directory(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("ACP state directory is not a direct directory.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.uid() != rustix::process::geteuid().as_raw() {
                return Err("ACP state directory belongs to another user.".into());
            }
        }
    }
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "cannot create app-owned ACP directory {}: {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "cannot secure app-owned ACP directory {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

pub(super) fn write_owner_only_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "ACP profile path has no parent.".to_owned())?;
    ensure_owner_directory(parent)?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(
        ".{ACP_PROFILE_FILE}.{}.{}.tmp",
        std::process::id(),
        unique
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|error| format!("cannot create temporary ACP profile: {error}"))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|error| format!("cannot write ACP profile: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync ACP profile: {error}"))?;
        fs::rename(&temp, path).map_err(|error| format!("cannot publish ACP profile: {error}"))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot sync ACP profile directory: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn unknown_event_shape_never_retains_payload_keys_scalars_or_payload_hashes() {
        let event = json!({"captured_secret_token_abc": "browser-private-text", "fields": [4_111_222_233_334_444_u64, true, {"clipboard-key": "desktop-private-text"}]});
        let shape = diagnostic_shape(&event, 0).to_string();
        for secret in [
            "captured_secret_token_abc",
            "browser-private-text",
            "4111222233334444",
            "clipboard-key",
            "desktop-private-text",
            "digest",
        ] {
            assert!(!shape.contains(secret), "{shape}");
        }
        assert!(shape.contains("objectFields"));
        assert!(shape.contains("stringBytes"));
        assert!(shape.contains("number"));
    }
}
