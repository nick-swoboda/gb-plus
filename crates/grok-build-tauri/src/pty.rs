//! Direct interactive user PTY with a fail-closed post-spawn readiness gate.
//!
//! `portable-pty 0.9.0` can return `Ok` after `execve` fails on macOS. This
//! module therefore treats spawn success as `Starting` only. The session does
//! not become `Live` until the shell returns a private challenge, remains
//! alive, completes a resize roundtrip, and survives the grace period.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{Child, ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::Serialize;

use crate::child_environment::ChildEnvironmentProfile;
use crate::contracts::{ProjectId, WorkspaceId};

pub(crate) const INTERACTIVE_SHELL_LABEL: &str = "Interactive user shell. Not contained.";

const READY_ENV: &str = "GROK_BUILD_PTY_READY";
const FRAME_PREFIX: &[u8] = b"\x1eGBPTY:";
const FRAME_SUFFIX: u8 = 0x1f;
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_GRACE: Duration = Duration::from_millis(500);
const READINESS_OUTPUT_LIMIT: usize = 64 * 1024;
const MAX_SCROLLBACK_BYTES: usize = 1024 * 1024;
const MAX_WRITE_BYTES: usize = 64 * 1024;
const MAX_SESSIONS: usize = 8;
const MIN_COLS: u16 = 2;
const MAX_COLS: u16 = 500;
const MIN_ROWS: u16 = 1;
const MAX_ROWS: u16 = 500;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PtySessionKey {
    pub(crate) project_id: ProjectId,
    pub(crate) workspace_id: WorkspaceId,
}

#[derive(Clone, Debug)]
pub(crate) struct PtyTarget {
    pub(crate) key: PtySessionKey,
    pub(crate) cwd: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PtyState {
    NotStarted,
    Starting,
    Live,
    Stopping,
    Exited,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PtyView {
    pub(crate) project_id: String,
    pub(crate) workspace_id: String,
    pub(crate) cwd: String,
    pub(crate) shell: Option<String>,
    pub(crate) shell_family: Option<String>,
    pub(crate) state: PtyState,
    pub(crate) status: String,
    pub(crate) rows: u16,
    pub(crate) cols: u16,
    pub(crate) output_sequence: u64,
    pub(crate) scrollback: Vec<u8>,
    pub(crate) label: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PtyEventKind {
    State,
    Output,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PtyUiEvent {
    pub(crate) project_id: String,
    pub(crate) workspace_id: String,
    pub(crate) kind: PtyEventKind,
    pub(crate) state: Option<PtyState>,
    pub(crate) status: Option<String>,
    pub(crate) sequence: Option<u64>,
    pub(crate) data: Option<Vec<u8>>,
}

impl PtyUiEvent {
    pub(crate) fn state(&self) -> Option<PtyState> {
        self.state
    }
}

pub(crate) type PtyEventSink = Arc<dyn Fn(PtyUiEvent) -> Result<(), String> + Send + Sync>;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
// Each predicate is emitted independently in smoke evidence; collapsing them
// into one state would hide which integrity control failed.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct PtySmokeProof {
    pub(crate) control_executed_without_readiness: bool,
    pub(crate) enforced_refused: bool,
    pub(crate) private_probe_absent: bool,
    pub(crate) positive_live: bool,
    pub(crate) resize_roundtrip: bool,
    pub(crate) io_usable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellFamily {
    Posix,
    Fish,
    Csh,
}

impl ShellFamily {
    const fn label(self) -> &'static str {
        match self {
            Self::Posix => "posix",
            Self::Fish => "fish",
            Self::Csh => "csh",
        }
    }

    const fn probe_command(self) -> &'static [u8] {
        match self {
            Self::Posix => {
                b"printf '\\036GBPTY:%s\\037' \"$GROK_BUILD_PTY_READY\"; unset GROK_BUILD_PTY_READY\r"
            }
            Self::Fish => {
                b"printf '\\036GBPTY:%s\\037' \"$GROK_BUILD_PTY_READY\"; set -e GROK_BUILD_PTY_READY\r"
            }
            Self::Csh => {
                b"printf '\\036GBPTY:%s\\037' \"$GROK_BUILD_PTY_READY\"; unsetenv GROK_BUILD_PTY_READY\r"
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ShellSpec {
    path: PathBuf,
    family: ShellFamily,
    args: Vec<String>,
}

struct ProbeToken(Vec<u8>);

impl ProbeToken {
    fn random() -> Result<Self, String> {
        let mut random = [0_u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut random))
            .map_err(|_| "The PTY readiness challenge could not be created.".to_owned())?;
        let mut encoded = Vec::with_capacity(random.len() * 2);
        for byte in random {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 0x0f)]);
        }
        Ok(Self(encoded))
    }

    fn fixture(value: &[u8]) -> Self {
        Self(value.to_vec())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn as_os_string(&self) -> std::ffi::OsString {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(self.0.clone())
    }

    fn frame(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(FRAME_PREFIX.len() + self.0.len() + 1);
        frame.extend_from_slice(FRAME_PREFIX);
        frame.extend_from_slice(&self.0);
        frame.push(FRAME_SUFFIX);
        frame
    }
}

#[derive(Clone)]
pub(crate) struct PtyManager {
    inner: Arc<PtyManagerInner>,
}

struct PtyManagerInner {
    sessions: Mutex<HashMap<PtySessionKey, Arc<PtySession>>>,
}

impl Default for PtyManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(PtyManagerInner {
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl Drop for PtyManagerInner {
    fn drop(&mut self) {
        if let Ok(sessions) = self.sessions.get_mut() {
            for session in sessions.values() {
                session.request_stop("Application shutdown");
            }
        }
    }
}

#[derive(Clone)]
struct Lifecycle {
    state: PtyState,
    status: String,
}

struct OutputBuffer {
    bytes: VecDeque<u8>,
    sequence: u64,
}

struct PtyIo {
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
}

struct PtySession {
    target: PtyTarget,
    shell: ShellSpec,
    lifecycle: Mutex<Lifecycle>,
    output: Mutex<OutputBuffer>,
    io: Mutex<Option<PtyIo>>,
    size: Mutex<PtySize>,
    stop_requested: AtomicBool,
    sink: PtyEventSink,
}

impl PtySession {
    fn new(target: PtyTarget, shell: ShellSpec, size: PtySize, sink: PtyEventSink) -> Self {
        Self {
            target,
            shell,
            lifecycle: Mutex::new(Lifecycle {
                state: PtyState::Starting,
                status: "Starting shell…".to_owned(),
            }),
            output: Mutex::new(OutputBuffer {
                bytes: VecDeque::new(),
                sequence: 0,
            }),
            io: Mutex::new(None),
            size: Mutex::new(size),
            stop_requested: AtomicBool::new(false),
            sink,
        }
    }

    fn view(&self) -> Result<PtyView, String> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "The PTY lifecycle lock is unavailable.".to_owned())?
            .clone();
        let output = self
            .output
            .lock()
            .map_err(|_| "The PTY scrollback lock is unavailable.".to_owned())?;
        let size = *self
            .size
            .lock()
            .map_err(|_| "The PTY size lock is unavailable.".to_owned())?;
        Ok(PtyView {
            project_id: self.target.key.project_id.as_str().to_owned(),
            workspace_id: self.target.key.workspace_id.as_str().to_owned(),
            cwd: self.target.cwd.display().to_string(),
            shell: Some(self.shell.path.display().to_string()),
            shell_family: Some(self.shell.family.label().to_owned()),
            state: lifecycle.state,
            status: lifecycle.status,
            rows: size.rows,
            cols: size.cols,
            output_sequence: output.sequence,
            scrollback: output.bytes.iter().copied().collect(),
            label: INTERACTIVE_SHELL_LABEL,
        })
    }

    fn transition(&self, state: PtyState, status: impl Into<String>) -> Result<(), String> {
        let status = status.into();
        {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .map_err(|_| "The PTY lifecycle lock is unavailable.".to_owned())?;
            lifecycle.state = state;
            lifecycle.status.clone_from(&status);
        }
        (self.sink)(PtyUiEvent {
            project_id: self.target.key.project_id.as_str().to_owned(),
            workspace_id: self.target.key.workspace_id.as_str().to_owned(),
            kind: PtyEventKind::State,
            state: Some(state),
            status: Some(status),
            sequence: None,
            data: None,
        })
    }

    fn append_output(&self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let sequence = {
            let Ok(mut output) = self.output.lock() else {
                return;
            };
            output.sequence = output.sequence.saturating_add(1);
            output.bytes.extend(&data);
            while output.bytes.len() > MAX_SCROLLBACK_BYTES {
                output.bytes.pop_front();
            }
            output.sequence
        };
        let _ = (self.sink)(PtyUiEvent {
            project_id: self.target.key.project_id.as_str().to_owned(),
            workspace_id: self.target.key.workspace_id.as_str().to_owned(),
            kind: PtyEventKind::Output,
            state: None,
            status: None,
            sequence: Some(sequence),
            data: Some(data),
        });
    }

    fn request_stop(&self, status: &str) {
        self.stop_requested.store(true, Ordering::SeqCst);
        let current = self.lifecycle.lock().ok().map(|value| value.state);
        if matches!(current, Some(PtyState::Starting | PtyState::Live)) {
            let _ = self.transition(PtyState::Stopping, status);
        }
        if let Ok(io) = self.io.lock()
            && let Some(io) = io.as_ref()
            && let Ok(mut killer) = io.killer.lock()
        {
            let _ = killer.kill();
        }
    }

    fn is_active(&self) -> bool {
        self.lifecycle.lock().is_ok_and(|lifecycle| {
            matches!(
                lifecycle.state,
                PtyState::Starting | PtyState::Live | PtyState::Stopping
            )
        })
    }
}

struct LaunchedPty {
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    reader_handle: thread::JoinHandle<()>,
    after_marker: Vec<u8>,
    token: ProbeToken,
}

struct FailedLaunchGuard {
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    armed: bool,
}

impl FailedLaunchGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailedLaunchGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        kill_child(&self.killer);
        if let Ok(mut child) = self.child.lock() {
            let _ = child.wait();
        }
    }
}

impl PtyManager {
    pub(crate) fn status(&self, target: &PtyTarget) -> Result<PtyView, String> {
        let sessions = self
            .inner
            .sessions
            .lock()
            .map_err(|_| "The PTY session registry is unavailable.".to_owned())?;
        match sessions.get(&target.key) {
            Some(session) => session.view(),
            None => Ok(not_started_view(target)),
        }
    }

    pub(crate) fn start(
        &self,
        target: PtyTarget,
        rows: u16,
        cols: u16,
        sink: PtyEventSink,
    ) -> Result<PtyView, String> {
        let shell = choose_shell();
        let token = ProbeToken::random()?;
        self.start_with(target, rows, cols, sink, shell, token)
    }

    fn start_with(
        &self,
        target: PtyTarget,
        rows: u16,
        cols: u16,
        sink: PtyEventSink,
        shell: ShellSpec,
        token: ProbeToken,
    ) -> Result<PtyView, String> {
        validate_size(rows, cols)?;
        validate_target(&target)?;
        validate_shell(&shell.path)?;
        let size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        let session = {
            let mut sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| "The PTY session registry is unavailable.".to_owned())?;
            if let Some(existing) = sessions.get(&target.key)
                && existing.is_active()
            {
                return existing.view();
            }
            sessions.remove(&target.key);
            while sessions.len() >= MAX_SESSIONS {
                let inactive = sessions
                    .iter()
                    .find_map(|(key, value)| (!value.is_active()).then(|| key.clone()));
                let Some(inactive) = inactive else {
                    return Err(format!(
                        "The PTY session limit ({MAX_SESSIONS}) is active. Stop another user shell before starting this one."
                    ));
                };
                sessions.remove(&inactive);
            }
            let session = Arc::new(PtySession::new(target, shell, size, sink));
            sessions.insert(session.target.key.clone(), Arc::clone(&session));
            session
        };

        if let Err(error) = session.transition(PtyState::Starting, "Starting shell…") {
            let _ = session.transition(
                PtyState::Failed,
                "The shell did not start because Activity could not record the intent.",
            );
            return Err(error);
        }

        let launched = match launch_and_verify(&session.target, &session.shell, size, token) {
            Ok(launched) => launched,
            Err(reason) => {
                let _ = session.transition(PtyState::Failed, reason.clone());
                return Err(reason);
            }
        };

        {
            let mut io = session
                .io
                .lock()
                .map_err(|_| "The PTY I/O state lock is unavailable.".to_owned())?;
            *io = Some(PtyIo {
                master: Arc::clone(&launched.master),
                writer: Arc::clone(&launched.writer),
                child: Arc::clone(&launched.child),
                killer: Arc::clone(&launched.killer),
            });
        }

        if let Err(error) = session.transition(PtyState::Live, "Shell is live") {
            session.request_stop("Stopping after Activity failure");
            return Err(error);
        }
        start_output_forwarder(Arc::clone(&session), launched);
        start_exit_watcher(Arc::clone(&session));
        session.view()
    }

    pub(crate) fn write(&self, target: &PtyTarget, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > MAX_WRITE_BYTES {
            return Err(format!(
                "PTY input is limited to {MAX_WRITE_BYTES} bytes per message."
            ));
        }
        let session = self.require_live_session(target)?;
        let io_guard = session
            .io
            .lock()
            .map_err(|_| "The PTY I/O state lock is unavailable.".to_owned())?;
        let io = io_guard
            .as_ref()
            .ok_or_else(|| "The user shell is not ready for input.".to_owned())?;
        let mut writer = io
            .writer
            .lock()
            .map_err(|_| "The PTY input lock is unavailable.".to_owned())?;
        writer
            .write_all(data)
            .and_then(|()| writer.flush())
            .map_err(|_| "The user shell stopped while receiving input.".to_owned())
    }

    pub(crate) fn interrupt(&self, target: &PtyTarget) -> Result<(), String> {
        self.write(target, &[0x03])
    }

    pub(crate) fn resize(
        &self,
        target: &PtyTarget,
        rows: u16,
        cols: u16,
    ) -> Result<PtyView, String> {
        validate_size(rows, cols)?;
        let session = self.require_live_session(target)?;
        let requested = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        let io_guard = session
            .io
            .lock()
            .map_err(|_| "The PTY I/O state lock is unavailable.".to_owned())?;
        let io = io_guard
            .as_ref()
            .ok_or_else(|| "The user shell is not ready to resize.".to_owned())?;
        let master = io
            .master
            .lock()
            .map_err(|_| "The PTY resize lock is unavailable.".to_owned())?;
        master
            .resize(requested)
            .map_err(|_| "The user shell refused the requested size.".to_owned())?;
        let actual = master
            .get_size()
            .map_err(|_| "The PTY size could not be verified.".to_owned())?;
        if actual.rows != rows || actual.cols != cols {
            return Err("The PTY did not retain the requested size.".to_owned());
        }
        drop(master);
        drop(io_guard);
        *session
            .size
            .lock()
            .map_err(|_| "The PTY size lock is unavailable.".to_owned())? = actual;
        session.view()
    }

    pub(crate) fn stop(&self, target: &PtyTarget) -> Result<PtyView, String> {
        let session = {
            let sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| "The PTY session registry is unavailable.".to_owned())?;
            sessions.get(&target.key).cloned()
        };
        let Some(session) = session else {
            return Ok(not_started_view(target));
        };
        session.request_stop("Stopping user shell…");
        session.view()
    }

    pub(crate) fn stop_project(&self, project_id: &ProjectId) {
        let sessions = self
            .inner
            .sessions
            .lock()
            .ok()
            .map(|sessions| {
                sessions
                    .values()
                    .filter(|session| session.target.key.project_id == *project_id)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for session in sessions {
            session.request_stop("Project removed");
        }
    }

    pub(crate) fn stop_workspace(&self, key: &PtySessionKey) {
        let session = self
            .inner
            .sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(key).cloned());
        if let Some(session) = session {
            session.request_stop("Workspace removed");
        }
    }

    pub(crate) fn shutdown_all(&self) {
        let sessions = self
            .inner
            .sessions
            .lock()
            .ok()
            .map(|sessions| sessions.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for session in sessions {
            session.request_stop("Application shutdown");
        }
    }

    fn require_live_session(&self, target: &PtyTarget) -> Result<Arc<PtySession>, String> {
        let session = self
            .inner
            .sessions
            .lock()
            .map_err(|_| "The PTY session registry is unavailable.".to_owned())?
            .get(&target.key)
            .cloned()
            .ok_or_else(|| "Start the interactive user shell first.".to_owned())?;
        let state = session
            .lifecycle
            .lock()
            .map_err(|_| "The PTY lifecycle lock is unavailable.".to_owned())?
            .state;
        if state != PtyState::Live {
            return Err("The interactive user shell is not live.".to_owned());
        }
        Ok(session)
    }
}

// Keeping this sequence linear makes the exact order of spawn, private
// challenge, liveness, resize, grace, and guard disarm reviewable.
#[allow(clippy::too_many_lines)]
fn launch_and_verify(
    target: &PtyTarget,
    shell: &ShellSpec,
    initial_size: PtySize,
    token: ProbeToken,
) -> Result<LaunchedPty, String> {
    let system = native_pty_system();
    let pair = system
        .openpty(initial_size)
        .map_err(|_| "The pseudo-terminal could not be opened.".to_owned())?;
    let command = build_command(target, shell, &token);
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|_| "The interactive shell process could not be created.".to_owned())?;
    drop(pair.slave);

    let child = Arc::new(Mutex::new(child));
    let killer = {
        let child_guard = child
            .lock()
            .map_err(|_| "The PTY child lock is unavailable.".to_owned())?;
        Arc::new(Mutex::new(child_guard.clone_killer()))
    };
    let mut failed_launch = FailedLaunchGuard {
        child: Arc::clone(&child),
        killer: Arc::clone(&killer),
        armed: true,
    };
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| "The PTY output stream could not be opened.".to_owned())?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|_| "The PTY input stream could not be opened.".to_owned())?;
    let master = Arc::new(Mutex::new(pair.master));
    let writer = Arc::new(Mutex::new(writer));
    let (output_tx, output_rx) = mpsc::channel();
    let reader_handle = thread::spawn(move || read_output(reader, output_tx));

    {
        let mut writer_guard = writer
            .lock()
            .map_err(|_| "The PTY input lock is unavailable.".to_owned())?;
        writer_guard
            .write_all(shell.family.probe_command())
            .and_then(|()| writer_guard.flush())
            .map_err(|_| "The shell failed before the readiness challenge was sent.".to_owned())?;
    }

    let expected = token.frame();
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut private_output = Vec::new();
    let marker_end = loop {
        if Instant::now() >= deadline {
            kill_child(&killer);
            return Err(
                "The shell did not answer the readiness challenge within 10 seconds.".to_owned(),
            );
        }
        match output_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(chunk) => {
                private_output.extend_from_slice(&chunk);
                if private_output.len() > READINESS_OUTPUT_LIMIT {
                    kill_child(&killer);
                    return Err(
                        "The shell produced too much output before it became ready.".to_owned()
                    );
                }
                if let Some(start) = find_bytes(&private_output, &expected) {
                    break start + expected.len();
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if child_exited(&child)? {
                    kill_child(&killer);
                    return Err(
                        "The shell exited before completing the readiness challenge.".to_owned(),
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                kill_child(&killer);
                return Err(
                    "The shell closed before completing the readiness challenge.".to_owned(),
                );
            }
        }
    };

    if child_exited(&child)? {
        kill_child(&killer);
        return Err("The shell exited immediately after its readiness response.".to_owned());
    }
    let verification_size = PtySize {
        rows: initial_size.rows.saturating_add(1).min(MAX_ROWS),
        cols: initial_size.cols.saturating_add(1).min(MAX_COLS),
        pixel_width: 0,
        pixel_height: 0,
    };
    {
        let master_guard = master
            .lock()
            .map_err(|_| "The PTY resize lock is unavailable.".to_owned())?;
        master_guard
            .resize(verification_size)
            .map_err(|_| "The shell failed its readiness resize check.".to_owned())?;
        let actual = master_guard
            .get_size()
            .map_err(|_| "The shell readiness size could not be verified.".to_owned())?;
        if actual.rows != verification_size.rows || actual.cols != verification_size.cols {
            kill_child(&killer);
            return Err("The shell failed its readiness resize roundtrip.".to_owned());
        }
        master_guard
            .resize(initial_size)
            .map_err(|_| "The shell could not restore its requested size.".to_owned())?;
        let restored = master_guard
            .get_size()
            .map_err(|_| "The restored PTY size could not be verified.".to_owned())?;
        if restored.rows != initial_size.rows || restored.cols != initial_size.cols {
            kill_child(&killer);
            return Err("The shell did not restore its requested size.".to_owned());
        }
    }
    thread::sleep(READINESS_GRACE);
    if child_exited(&child)? {
        kill_child(&killer);
        return Err("The shell exited during the readiness grace period.".to_owned());
    }

    failed_launch.disarm();

    Ok(LaunchedPty {
        master,
        writer,
        child,
        killer,
        output_rx,
        reader_handle,
        after_marker: private_output[marker_end..].to_vec(),
        token,
    })
}

fn build_command(target: &PtyTarget, shell: &ShellSpec, token: &ProbeToken) -> CommandBuilder {
    let mut command = CommandBuilder::new(&shell.path);
    ChildEnvironmentProfile::Pty.apply_pty(&mut command, &shell.path, &token.as_os_string());
    command.cwd(&target.cwd);
    command.args(&shell.args);
    command
}

fn start_output_forwarder(session: Arc<PtySession>, launched: LaunchedPty) {
    thread::spawn(move || {
        let mut filter = ProbeFilter::new(&launched.token);
        let initial = filter.push(&launched.after_marker, false);
        session.append_output(initial);
        while let Ok(chunk) = launched.output_rx.recv() {
            let visible = filter.push(&chunk, false);
            session.append_output(visible);
        }
        session.append_output(filter.push(&[], true));
        let _ = launched.reader_handle.join();
    });
}

fn start_exit_watcher(session: Arc<PtySession>) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(50));
            let status = {
                let Ok(io) = session.io.lock() else {
                    let _ = session
                        .transition(PtyState::Failed, "The PTY I/O state became unavailable.");
                    return;
                };
                let Some(io) = io.as_ref() else {
                    return;
                };
                let Ok(mut child) = io.child.lock() else {
                    let _ = session
                        .transition(PtyState::Failed, "The PTY child state became unavailable.");
                    return;
                };
                child.try_wait()
            };
            match status {
                Ok(Some(exit)) => {
                    if session.stop_requested.load(Ordering::SeqCst) {
                        let _ = session.transition(PtyState::Exited, "User shell stopped");
                    } else {
                        let _ = session.transition(
                            PtyState::Exited,
                            format!("User shell exited with code {}", exit.exit_code()),
                        );
                    }
                    return;
                }
                Ok(None) => {}
                Err(_) => {
                    let _ = session
                        .transition(PtyState::Failed, "The PTY child status could not be read.");
                    return;
                }
            }
        }
    });
}

fn read_output(mut reader: Box<dyn Read + Send>, sender: mpsc::Sender<Vec<u8>>) {
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                if sender.send(chunk[..count].to_vec()).is_err() {
                    break;
                }
            }
        }
    }
    drop(sender);
}

fn child_exited(child: &Arc<Mutex<Box<dyn Child + Send + Sync>>>) -> Result<bool, String> {
    child
        .lock()
        .map_err(|_| "The PTY child lock is unavailable.".to_owned())?
        .try_wait()
        .map(|status| status.is_some())
        .map_err(|_| "The shell process status could not be verified.".to_owned())
}

fn kill_child(killer: &Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>) {
    if let Ok(mut killer) = killer.lock() {
        let _ = killer.kill();
    }
}

struct ProbeFilter {
    pending: Vec<u8>,
    forbidden: Vec<Vec<u8>>,
}

impl ProbeFilter {
    fn new(token: &ProbeToken) -> Self {
        let mut forbidden = vec![
            token.frame(),
            READY_ENV.as_bytes().to_vec(),
            token.as_bytes().to_vec(),
            b"GBPTY:".to_vec(),
        ];
        forbidden.sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
        Self {
            pending: Vec::new(),
            forbidden,
        }
    }

    fn push(&mut self, bytes: &[u8], final_chunk: bool) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        for pattern in &self.forbidden {
            while let Some(index) = find_bytes(&self.pending, pattern) {
                self.pending.drain(index..index + pattern.len());
            }
        }
        let retained_prefix = self
            .forbidden
            .iter()
            .map(|pattern| longest_suffix_prefix(&self.pending, pattern))
            .max()
            .unwrap_or(0);
        let emit_len = if final_chunk {
            if retained_prefix > 0 {
                self.pending
                    .truncate(self.pending.len().saturating_sub(retained_prefix));
            }
            self.pending.len()
        } else {
            self.pending.len().saturating_sub(retained_prefix)
        };
        self.pending.drain(..emit_len).collect()
    }
}

fn longest_suffix_prefix(bytes: &[u8], pattern: &[u8]) -> usize {
    let maximum = bytes.len().min(pattern.len().saturating_sub(1));
    (1..=maximum)
        .rev()
        .find(|length| bytes.ends_with(&pattern[..*length]))
        .unwrap_or(0)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn validate_size(rows: u16, cols: u16) -> Result<(), String> {
    if !(MIN_ROWS..=MAX_ROWS).contains(&rows) || !(MIN_COLS..=MAX_COLS).contains(&cols) {
        return Err(format!(
            "PTY size must be {MIN_COLS}–{MAX_COLS} columns by {MIN_ROWS}–{MAX_ROWS} rows."
        ));
    }
    Ok(())
}

fn validate_target(target: &PtyTarget) -> Result<(), String> {
    let metadata = std::fs::metadata(&target.cwd)
        .map_err(|_| "The active workspace is unavailable for the user shell.".to_owned())?;
    if !target.cwd.is_absolute() || !metadata.is_dir() {
        return Err("The active workspace is not an absolute directory.".to_owned());
    }
    Ok(())
}

fn validate_shell(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)
        .map_err(|_| "The selected user shell is unavailable.".to_owned())?;
    if !path.is_absolute() || !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("The selected user shell is not an executable file.".to_owned());
    }
    Ok(())
}

fn choose_shell() -> ShellSpec {
    let configured = std::env::var_os("SHELL").map(PathBuf::from);
    configured
        .as_deref()
        .and_then(shell_spec_for_path)
        .filter(|shell| validate_shell(&shell.path).is_ok())
        .unwrap_or_else(fallback_shell)
}

fn shell_spec_for_path(path: &Path) -> Option<ShellSpec> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let family = match name.as_str() {
        "zsh" | "bash" | "sh" | "dash" | "ksh" => ShellFamily::Posix,
        "fish" => ShellFamily::Fish,
        "csh" | "tcsh" => ShellFamily::Csh,
        _ => return None,
    };
    Some(ShellSpec {
        path: path.to_path_buf(),
        family,
        args: vec!["-l".to_owned()],
    })
}

fn fallback_shell() -> ShellSpec {
    ShellSpec {
        path: PathBuf::from("/bin/zsh"),
        family: ShellFamily::Posix,
        args: vec!["-l".to_owned()],
    }
}

fn not_started_view(target: &PtyTarget) -> PtyView {
    PtyView {
        project_id: target.key.project_id.as_str().to_owned(),
        workspace_id: target.key.workspace_id.as_str().to_owned(),
        cwd: target.cwd.display().to_string(),
        shell: None,
        shell_family: None,
        state: PtyState::NotStarted,
        status: "Shell not started".to_owned(),
        rows: 24,
        cols: 80,
        output_sequence: 0,
        scrollback: Vec::new(),
        label: INTERACTIVE_SHELL_LABEL,
    }
}

// The smoke receipt deliberately runs every control in one ordered fixture so
// its booleans all describe the same process/target instance.
#[allow(clippy::too_many_lines)]
pub(crate) fn smoke_pty_integrity(cwd: &Path) -> Result<PtySmokeProof, String> {
    use std::os::unix::fs::PermissionsExt;

    let control_program = cwd.join(format!(
        ".grok-build-pty-negative-control-{}",
        std::process::id()
    ));
    let control_marker = cwd.join(format!(
        ".grok-build-pty-negative-control-executed-{}",
        std::process::id()
    ));
    std::fs::write(
        &control_program,
        b"#!/bin/sh\nprintf executed > \"$1\"\nexit 0\n",
    )
    .map_err(|_| "The PTY negative-control executable could not be created.".to_owned())?;
    std::fs::set_permissions(&control_program, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| "The PTY negative-control executable could not be secured.".to_owned())?;

    let manager = PtyManager::default();
    let events = Arc::new(Mutex::new(Vec::<PtyUiEvent>::new()));
    let captured = Arc::clone(&events);
    let sink: PtyEventSink = Arc::new(move |event| {
        captured
            .lock()
            .map_err(|_| "The PTY smoke event lock is unavailable.".to_owned())?
            .push(event);
        Ok(())
    });
    let target = PtyTarget {
        key: PtySessionKey {
            project_id: ProjectId::new("pty-smoke-project"),
            workspace_id: WorkspaceId::new("pty-smoke-workspace"),
        },
        cwd: cwd.to_path_buf(),
    };
    let bad_shell = ShellSpec {
        path: control_program.clone(),
        family: ShellFamily::Posix,
        args: vec![control_marker.display().to_string()],
    };
    let negative_token = ProbeToken::fixture(b"grok-build-negative-probe-token");
    let negative = manager.start_with(
        target.clone(),
        24,
        80,
        Arc::clone(&sink),
        bad_shell,
        negative_token,
    );
    let negative_view = manager.status(&target)?;
    let negative_events = events
        .lock()
        .map_err(|_| "The PTY smoke event lock is unavailable.".to_owned())?
        .clone();
    let control_executed_without_readiness =
        std::fs::read(&control_marker).is_ok_and(|bytes| bytes == b"executed");
    let enforced_refused = negative.is_err()
        && negative_view.state == PtyState::Failed
        && !negative_events
            .iter()
            .any(|event| event.state() == Some(PtyState::Live));

    events
        .lock()
        .map_err(|_| "The PTY smoke event lock is unavailable.".to_owned())?
        .clear();
    let positive_shell = ShellSpec {
        path: PathBuf::from("/bin/zsh"),
        family: ShellFamily::Posix,
        args: vec!["-d".to_owned(), "-f".to_owned()],
    };
    let positive_token_bytes = b"grok-build-positive-probe-token";
    let positive = manager.start_with(
        target.clone(),
        24,
        80,
        Arc::clone(&sink),
        positive_shell,
        ProbeToken::fixture(positive_token_bytes),
    )?;
    manager.write(&target, b"printf 'PTY-IO-USABLE\\n'\r")?;
    let resized = manager.resize(&target, 37, 101)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let observed = loop {
        let view = manager.status(&target)?;
        if find_bytes(&view.scrollback, b"PTY-IO-USABLE").is_some() {
            break view;
        }
        if Instant::now() >= deadline {
            break view;
        }
        thread::sleep(Duration::from_millis(25));
    };
    let serialized_events = serde_json::to_vec(
        &events
            .lock()
            .map_err(|_| "The PTY smoke event lock is unavailable.".to_owned())?
            .clone(),
    )
    .map_err(|_| "The PTY smoke events could not be encoded.".to_owned())?;
    let private_probe_absent = [
        positive_token_bytes.as_slice(),
        READY_ENV.as_bytes(),
        b"GBPTY:",
    ]
    .iter()
    .all(|forbidden| {
        find_bytes(&observed.scrollback, forbidden).is_none()
            && find_bytes(&serialized_events, forbidden).is_none()
    });
    let result = PtySmokeProof {
        control_executed_without_readiness,
        enforced_refused,
        private_probe_absent,
        positive_live: positive.state == PtyState::Live,
        resize_roundtrip: resized.rows == 37 && resized.cols == 101,
        io_usable: find_bytes(&observed.scrollback, b"PTY-IO-USABLE").is_some(),
    };
    let _ = manager.stop(&target);
    manager.shutdown_all();
    std::fs::remove_file(&control_program)
        .map_err(|_| "The PTY negative-control executable could not be removed.".to_owned())?;
    std::fs::remove_file(&control_marker)
        .map_err(|_| "The PTY negative-control marker could not be removed.".to_owned())?;
    Ok(result)
}

#[cfg(test)]
#[path = "pty/tests.rs"]
mod tests;
