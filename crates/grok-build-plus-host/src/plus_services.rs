//! Guest-only contained-service transport. Extension permission is resolved by the app broker.

use std::collections::VecDeque;
use std::io::Write as _;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use grok_build_runner::{
    ContainedServiceProfile, ContainedServiceRequest, MAX_SERVICE_CONTROL_BYTES,
    MAX_SERVICE_EVENTS, ServiceControl, ServiceEvent, ServiceFrameReader, ServiceObservation,
    ServiceOperation, ServiceSnapshot,
};

use super::{
    PlusCommandSecurityKind, PlusCommandSecurityPreference, PlusGuestKind, PlusGuestLifecycle,
    PlusGuestTarget, classify_command_security,
};

mod cleanup;
mod duplex;
mod reaper;
mod staging;

pub use cleanup::ContainedServiceCleanup;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Staging,
    AwaitingViews,
    AwaitingLaunch,
    Starting,
    Contained,
    Ready,
}

/// One connection to one admitted guest process domain. No host executable fallback exists.
pub struct PlusContainedService {
    child: Option<Child>,
    reservation: Option<reaper::Reservation>,
    retired: Option<usize>,
    request: ContainedServiceRequest,
    next_control: u64,
    next_event: u64,
    reader: ServiceFrameReader,
    input_bytes: u64,
    output_bytes: u64,
    terminal: Option<ServiceObservation>,
    phase: Phase,
    input_closed: bool,
    poisoned: bool,
    pending_events: VecDeque<ServiceObservation>,
    cleanup: ContainedServiceCleanup,
}

impl PlusContainedService {
    /// Open the transport after Rust has resolved the enabled extension and its
    /// invocation scope. The guest independently verifies the admitted generation.
    /// This adapter assigns the physical one-use lease ID; the caller's operation
    /// ID is preserved. Admission is serialized, while established services remain concurrent.
    ///
    /// # Errors
    /// Refuses disabled/unavailable containment, stale guest identity, unsafe fixed
    /// launch paths, invalid request bounds, or any transport setup failure.
    pub fn open(
        request: ContainedServiceRequest,
        preference: PlusCommandSecurityPreference,
        lifecycle: &PlusGuestLifecycle,
        views: (&ServiceSnapshot, &ServiceSnapshot),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, String> {
        Self::open_tracked(
            request,
            preference,
            lifecycle,
            views,
            cancelled,
            &mut |_| Ok(()),
        )
    }

    /// Open with an opaque cleanup observation retained by the owning scheduler
    /// before any service process can start. Refusal before spawn proves no
    /// process; failures after spawn retain independent guest and reap evidence.
    ///
    /// # Errors
    /// Refuses retention failure or any admission/startup error. The retained
    /// observation, rather than the error string, determines cleanup status.
    pub fn open_tracked(
        mut request: ContainedServiceRequest,
        preference: PlusCommandSecurityPreference,
        lifecycle: &PlusGuestLifecycle,
        views: (&ServiceSnapshot, &ServiceSnapshot),
        cancelled: &dyn Fn() -> bool,
        retain: &mut dyn FnMut(ContainedServiceCleanup) -> Result<(), String>,
    ) -> Result<Self, String> {
        let mut admission = cleanup::Admission::new();
        retain(admission.cleanup.clone())?;
        request.validate_shape()?;
        let _admission = staging::admission_lock(cancelled)?;
        if classify_command_security(preference, lifecycle.kind(), false)
            != PlusCommandSecurityKind::On
        {
            return Err("Turn on Command security before enabling a local service.".into());
        }
        let PlusGuestLifecycle::Ready(target) = lifecycle else {
            return Err("Contained service guest is unavailable.".into());
        };
        let profile = inspect_contained_service_profile(target)?;
        if profile.containment_digest != request.scope.containment_digest
            || profile.architecture != request.architecture
        {
            return Err("Contained service admission changed; review it again.".into());
        }
        request.lease_id = format!("gb-service-{:020}", profile.next_lease_sequence);
        staging::bind(&mut request, &profile, views)?;
        let mut command = guest_command(target, "--gb-contained-service-v1")?;
        let mut reservation = reaper::Reservation::acquire()?;
        reservation.track(admission.cleanup.clone());
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|e| e.to_string())?;
        admission.spawned();
        let mut service = Self {
            child: Some(child),
            reservation: Some(reservation),
            retired: None,
            request,
            next_control: 0,
            next_event: 0,
            reader: ServiceFrameReader::new(MAX_SERVICE_CONTROL_BYTES),
            input_bytes: 0,
            output_bytes: 0,
            terminal: None,
            phase: Phase::Staging,
            input_closed: false,
            poisoned: false,
            pending_events: VecDeque::new(),
            cleanup: admission.cleanup.clone(),
        };
        let child = service
            .child
            .as_ref()
            .ok_or("Service transport was not retained.")?;
        nonblocking(
            child
                .stdin
                .as_ref()
                .ok_or("Service transport omitted stdin.")?,
        )?;
        nonblocking(
            child
                .stdout
                .as_ref()
                .ok_or("Service transport omitted stdout.")?,
        )?;
        service.control(ServiceOperation::Start {
            request: Box::new(service.request.clone()),
        })?;
        staging::transfer(&mut service, views, cancelled)?;
        Ok(service)
    }

    /// Collect one bounded observation without waiting for model or user input.
    ///
    /// # Errors
    /// Refuses stale/reordered observations, oversized output, broken framing, or
    /// connection loss. Output can never request a new process or control operation.
    pub fn poll(&mut self) -> Result<Option<ServiceObservation>, String> {
        reaper::reap();
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(Some(event));
        }
        if self.poisoned {
            return Err("Contained service transport needs recovery.".into());
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn poll_inner(&mut self) -> Result<Option<ServiceObservation>, String> {
        if self.terminal.is_some() {
            return Ok(None);
        }
        let output = self
            .child
            .as_mut()
            .and_then(|child| child.stdout.as_mut())
            .ok_or("Contained service transport ended.")?;
        let Some(frame) = self.reader.next(output).map_err(|e| e.to_string())? else {
            if self.reader.ended() {
                return Err("Service connection ended without a cleanup receipt.".into());
            }
            return Ok(None);
        };
        let event: ServiceEvent = serde_json::from_slice(&frame).map_err(|e| e.to_string())?;
        if event.version != 1
            || event.lease_id != self.request.lease_id
            || event.sequence != self.next_event
            || self.next_event >= MAX_SERVICE_EVENTS
        {
            return Err("Service observation identity or sequence changed.".into());
        }
        self.next_event = self
            .next_event
            .checked_add(1)
            .ok_or("Service event sequence overflow.")?;
        match &event.observation {
            ServiceObservation::ViewsReady { commitment } => {
                if self.phase != Phase::AwaitingViews || commitment != &self.request.commitment()? {
                    return Err(
                        "Service acknowledged an incomplete or different staged view.".into(),
                    );
                }
                self.phase = Phase::AwaitingLaunch;
            }
            ServiceObservation::Started { commitment } => {
                if self.phase != Phase::Starting || commitment != &self.request.commitment()? {
                    return Err("Service startup commitment or state changed.".into());
                }
                self.phase = Phase::Contained;
            }
            ServiceObservation::Stdout { bytes } | ServiceObservation::Stderr { bytes } => {
                self.output_bytes = self.output_bytes.saturating_add(bytes.len() as u64);
                if bytes.len() > self.request.limits.frame_bytes as usize
                    || self.output_bytes > self.request.limits.output_bytes
                {
                    return Err("Contained service exceeded its output budget.".into());
                }
            }
            ServiceObservation::Refused { reason } if reason.len() > 2048 => {
                return Err("Service refusal exceeded its diagnostic bound.".into());
            }
            ServiceObservation::Terminated { cleanup_proven, .. } => {
                if *cleanup_proven {
                    self.cleanup.guest_clean();
                }
                self.terminal = Some(event.observation.clone());
            }
            ServiceObservation::Refused { .. } => {}
        }
        Ok(Some(event.observation))
    }

    /// Send opaque protocol bytes to the process already owned by this lease.
    ///
    /// # Errors
    /// Refuses terminal leases, excessive input, or a partial/failed write.
    /// A caller must not retry a write whose delivery is uncertain.
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        if !matches!(self.phase, Phase::Contained | Phase::Ready) || self.input_closed {
            return Err("Service input is not available in this state.".into());
        }
        self.input_bytes = self.input_bytes.saturating_add(bytes.len() as u64);
        if bytes.len() > self.request.limits.frame_bytes as usize
            || self.input_bytes > self.request.limits.input_bytes
        {
            return Err("Service input budget exceeded.".into());
        }
        self.control(ServiceOperation::Input {
            bytes: bytes.to_vec(),
        })
    }

    /// Record successful protocol initialization, after the broker validates it.
    ///
    /// # Errors
    /// Refuses a terminal or broken transport.
    pub fn ready(&mut self) -> Result<(), String> {
        if self.phase != Phase::Contained {
            return Err("Service protocol readiness is out of order.".into());
        }
        self.control(ServiceOperation::Ready)?;
        self.phase = Phase::Ready;
        Ok(())
    }

    /// Close service stdin while retaining output and whole-domain supervision.
    ///
    /// # Errors
    /// Refuses a terminal or broken transport.
    pub fn close_input(&mut self) -> Result<(), String> {
        if !matches!(self.phase, Phase::Contained | Phase::Ready) || self.input_closed {
            return Err("Service input is already closed or not started.".into());
        }
        self.control(ServiceOperation::CloseInput)?;
        self.input_closed = true;
        Ok(())
    }

    /// Stop this service and require a whole-domain cleanup receipt.
    ///
    /// # Errors
    /// Reports uncertain cleanup if the guest loses contact or cannot prove that
    /// every descendant ended. The guest retains its durable ownership receipt.
    pub fn stop(&mut self) -> Result<(), String> {
        if self.terminal.is_none() {
            let _ = self.control(ServiceOperation::Cancel);
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.terminal.is_none() && Instant::now() < deadline {
                if self.poll().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let transport_clean = self.end_transport();
        if transport_clean
            && matches!(
                self.terminal,
                Some(ServiceObservation::Terminated {
                    cleanup_proven: true,
                    ..
                })
            )
        {
            Ok(())
        } else {
            Err(
                "Contained service cleanup is uncertain; recovery receipt retained in the guest."
                    .into(),
            )
        }
    }

    fn control(&mut self, operation: ServiceOperation) -> Result<(), String> {
        if self.terminal.is_some() || self.poisoned {
            return Err("Contained service has ended.".into());
        }
        let frame = ServiceControl {
            version: 1,
            lease_id: self.request.lease_id.clone(),
            sequence: self.next_control,
            operation,
        };
        // Reserve identity before writing. A partial write never reuses a sequence.
        self.next_control = self
            .next_control
            .checked_add(1)
            .ok_or("Service input sequence overflow.")?;
        let mut bytes = serde_json::to_vec(&frame).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_SERVICE_CONTROL_BYTES {
            return Err("Service encoded frame budget exceeded.".into());
        }
        let result = duplex::write(self, &bytes, Duration::from_secs(5));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn end_transport(&mut self) -> bool {
        if let Some(child) = self.child.take() {
            self.retired = Some(
                self.reservation
                    .take()
                    .expect("live transport retains its reservation")
                    .retire(child),
            );
        }
        self.retired
            .is_none_or(|identity| !reaper::pending(identity))
    }
}

impl duplex::ControlIo for PlusContainedService {
    fn drain_output(&mut self) -> Result<bool, String> {
        if self.pending_events.len() >= 256 {
            return Err(
                "Service output buffer filled during input delivery; delivery is uncertain.".into(),
            );
        }
        // Validate observations now; poll() delivers them in original order
        // without counting bytes twice. Output never grants control authority.
        let observed = self.poll_inner()?;
        let progress = observed.is_some();
        if let Some(event) = observed {
            self.pending_events.push_back(event);
        }
        if self.terminal.is_some() {
            return Err("Service ended during input delivery; do not retry this frame.".into());
        }
        Ok(progress)
    }

    fn write_input(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.child
            .as_mut()
            .and_then(|child| child.stdin.as_mut())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?
            .write(bytes)
    }
}

impl Drop for PlusContainedService {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.stop();
        }
    }
}

/// Inspect the exact service protocol in the selected managed guest.
///
/// # Errors
/// Refuses host-only targets on macOS, unknown profile versions, excess output,
/// timeout, or a helper that cannot authenticate its installation.
pub fn inspect_contained_service_profile(
    target: &PlusGuestTarget,
) -> Result<ContainedServiceProfile, String> {
    let mut command = guest_command(target, "--gb-contained-service-profile-v1")?;
    let reservation = reaper::Reservation::acquire()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let output = child
            .stdout
            .as_mut()
            .ok_or("Service profile omitted output.")?;
        nonblocking(output)?;
        let mut reader = ServiceFrameReader::new(8192);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(bytes) = reader.next(output).map_err(|e| e.to_string())? {
                let profile: ContainedServiceProfile =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if profile.version != grok_build_runner::CONTAINED_SERVICE_PROFILE_VERSION
                    || profile.next_lease_sequence == 0
                {
                    return Err("Guest service protocol is unsupported.".into());
                }
                return Ok(profile);
            }
            if reader.ended() || Instant::now() >= deadline {
                return Err("Guest service did not return its authenticated profile.".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    reservation.retire(child);
    result
}

fn guest_command(target: &PlusGuestTarget, mode: &str) -> Result<Command, String> {
    fn fixed_path(path: &Path) -> Result<&str, String> {
        let text = path.to_str().ok_or("Guest service path is not UTF-8.")?;
        if !text.starts_with('/')
            || text.len() > 4096
            || !text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
            || text.split('/').any(|s| s == ".." || s == ".")
        {
            return Err("Guest service launch path is not admitted.".into());
        }
        Ok(text)
    }
    // Long-lived service leaves must never occupy the command delegation:
    // its per-command preflight deliberately requires an empty subtree.
    let service_install = target
        .install_root
        .parent()
        .ok_or("Guest installation has no parent.")?
        .join("stdio-install");
    let install = fixed_path(&service_install)?;
    if cfg!(target_os = "macos") && target.kind != PlusGuestKind::Remote {
        return Err("macOS services require the managed Linux guest.".into());
    }
    match target.kind {
        PlusGuestKind::Remote => {
            let colima = target
                .colima
                .as_ref()
                .ok_or("Service guest omitted its transport.")?;
            let helper = fixed_path(
                target
                    .helper
                    .as_deref()
                    .ok_or("Service guest omitted its helper.")?,
            )?;
            let mut command = Command::new(colima);
            super::plus_lifecycle::apply_colima_child_environment(&mut command);
            command.args([
                "ssh",
                "--",
                "env",
                "-i",
                "PATH=/usr/bin:/bin",
                "LANG=C.UTF-8",
                helper,
                mode,
                install,
            ]);
            Ok(command)
        }
        PlusGuestKind::Local if cfg!(target_os = "linux") => {
            let mut command = Command::new(fixed_path(&target.runner)?);
            command
                .env_clear()
                .args([mode, install])
                .env("PATH", "/usr/bin:/bin")
                .env("LANG", "C.UTF-8");
            Ok(command)
        }
        PlusGuestKind::Local => Err("Contained services have no host-only fallback.".into()),
    }
}

fn nonblocking(fd: &impl AsFd) -> Result<(), String> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|e| e.to_string())?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|e| e.to_string())
}
