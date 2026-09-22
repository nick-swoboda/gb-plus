//! MCP framing over the existing app/guest service lease, never a host process.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use grok_build_runner::{
    ContainedServiceRequest, ServiceObservation, ServicePurpose, ServiceSnapshot,
};
use serde_json::{Value, json};

use super::{MCP_MAX_FRAME_BYTES, McpEvent, McpOperation, McpProtocol, McpRequestIdentity};
use crate::{PlusCommandSecurityPreference, PlusContainedService, PlusGuestLifecycle};

/// One independent MCP client backed by a supervised contained stdio service.
/// The app supplies frozen installation/admission and performs permission checks.
pub struct ContainedMcpConnection {
    service: PlusContainedService,
    protocol: McpProtocol,
    input: Vec<u8>,
    events: VecDeque<McpEvent>,
    ready_by: Instant,
    started: bool,
    ready: bool,
    closed: bool,
}

impl ContainedMcpConnection {
    /// Start the exact admitted MCP service. Initialization advances through
    /// `poll`; tool calls cannot start before protocol readiness.
    ///
    /// # Errors
    /// Refuses hook/host-only profiles and all existing service admission failures.
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

    /// Open while retaining scheduler cleanup custody before service startup.
    ///
    /// # Errors
    /// Refuses an invalid purpose or any tracked service admission failure.
    pub fn open_tracked(
        request: ContainedServiceRequest,
        preference: PlusCommandSecurityPreference,
        lifecycle: &PlusGuestLifecycle,
        views: (&ServiceSnapshot, &ServiceSnapshot),
        cancelled: &dyn Fn() -> bool,
        retain: &mut dyn FnMut(crate::ContainedServiceCleanup) -> Result<(), String>,
    ) -> Result<Self, String> {
        if request.purpose != ServicePurpose::Mcp {
            return Err("MCP requires a separately admitted MCP-purpose service.".into());
        }
        let readiness = Duration::from_millis(request.limits.readiness_ms);
        let service = PlusContainedService::open_tracked(
            request, preference, lifecycle, views, cancelled, retain,
        )?;
        let ready_by = Instant::now() + readiness;
        Ok(Self {
            service,
            protocol: McpProtocol::default(),
            input: Vec::new(),
            events: VecDeque::new(),
            ready_by,
            started: false,
            ready: false,
            closed: false,
        })
    }

    /// Poll independently of the model, so elicitation/cancellation keep working
    /// while a reverse ACP request is waiting for its eventual tool result.
    ///
    /// # Errors
    /// Refuses invalid framing, process termination, containment loss, or readiness
    /// timeout. Errors poison this connection; no operation is automatically retried.
    pub fn poll(&mut self) -> Result<Option<McpEvent>, String> {
        let result = self.poll_inner();
        if result.is_err() {
            self.closed = true;
            let _ = self.protocol.interrupt();
        }
        result
    }

    fn poll_inner(&mut self) -> Result<Option<McpEvent>, String> {
        if self.closed {
            return Err("Contained MCP connection needs recovery.".into());
        }
        if !self.ready && Instant::now() >= self.ready_by {
            return Err("Contained MCP initialization exceeded its readiness deadline.".into());
        }
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        if self.consume_frame()? {
            return Ok(self.events.pop_front());
        }
        // Fixed work per poll preserves cancellation and approval responsiveness.
        for _ in 0..4 {
            match self.service.poll()? {
                Some(ServiceObservation::Started { .. }) if !self.started => {
                    self.started = true;
                    let (_, bytes) = self.protocol.begin(McpOperation::Initialize, json!({}))?;
                    self.service.send(&bytes)?;
                }
                Some(ServiceObservation::Stdout { bytes }) => {
                    if !self.started
                        || self.input.len().saturating_add(bytes.len()) > 2 * MCP_MAX_FRAME_BYTES
                    {
                        return Err("Contained MCP input buffer exceeded its framing bound.".into());
                    }
                    self.input.extend_from_slice(&bytes);
                    if self.consume_frame()? {
                        return Ok(self.events.pop_front());
                    }
                }
                Some(ServiceObservation::Stderr { .. }) => {}
                Some(
                    ServiceObservation::Terminated { .. } | ServiceObservation::Refused { .. },
                ) => {
                    return Err(
                        "Contained MCP service ended; pending delivery is uncertain.".into(),
                    );
                }
                Some(
                    ServiceObservation::Started { .. } | ServiceObservation::ViewsReady { .. },
                ) => {
                    return Err("Contained MCP service started twice.".into());
                }
                None => break,
            }
        }
        Ok(None)
    }

    fn consume_frame(&mut self) -> Result<bool, String> {
        let Some(newline) = self.input.iter().position(|byte| *byte == b'\n') else {
            if self.input.len() >= MCP_MAX_FRAME_BYTES {
                return Err("Contained MCP line exceeded its frame limit.".into());
            }
            return Ok(false);
        };
        if newline + 1 > MCP_MAX_FRAME_BYTES {
            return Err("Contained MCP line exceeded its frame limit.".into());
        }
        let bytes: Vec<u8> = self.input.drain(..=newline).collect();
        for event in self.protocol.receive(&bytes)? {
            match event {
                McpEvent::Send(bytes) => self.service.send(&bytes)?,
                McpEvent::Initialized => {
                    self.service.ready()?;
                    self.ready = true;
                    self.events.push_back(McpEvent::Initialized);
                }
                event => self.events.push_back(event),
            }
        }
        Ok(true)
    }

    /// Reserve and send an already-authorized, already-journaled broker request.
    /// The returned identity is only correlation, never an authority token.
    ///
    /// # Errors
    /// Refuses pre-readiness requests, invalid protocol operations or uncertain
    /// writes. Any failed write closes this connection against automatic replay.
    pub fn request(
        &mut self,
        operation: McpOperation,
        params: Value,
    ) -> Result<McpRequestIdentity, String> {
        let (identity, bytes) = self.reserve(operation, params)?;
        self.send(&bytes)?;
        Ok(identity)
    }

    pub(super) fn reserve(
        &mut self,
        operation: McpOperation,
        params: Value,
    ) -> Result<(McpRequestIdentity, Vec<u8>), String> {
        if self.closed || !self.ready {
            return Err("Contained MCP is not ready for requests.".into());
        }
        self.protocol.begin(operation, params)
    }

    #[cfg(feature = "mcp-https")]
    pub(super) fn version(&self) -> Option<super::McpProtocolVersion> {
        self.protocol.negotiated_version()
    }

    /// Deliver an app-validated answer to a pending server elicitation.
    /// Returns false if cancellation or an earlier answer already closed it.
    /// True confirms a successful transport write, not server consumption.
    ///
    /// # Errors
    /// Refuses malformed identities, invalid replies and uncertain writes.
    pub fn answer_elicitation(&mut self, identity: &Value, result: &Value) -> Result<bool, String> {
        if !self.protocol.elicitation_pending(identity)? {
            return Ok(false);
        }
        let bytes = self.protocol.answer_elicitation(identity, result)?;
        self.send(&bytes)?;
        Ok(true)
    }

    /// Request cancellation without claiming delivery, effect rollback or exit.
    ///
    /// # Errors
    /// Refuses invalid IDs or failed writes. Stopping the service remains separate.
    pub fn cancel(&mut self, identity: &McpRequestIdentity) -> Result<(), String> {
        let bytes = self.protocol.cancel(identity)?;
        self.send(&bytes)
    }

    /// Mark unfinished requests uncertain before stopping their owning service.
    #[must_use]
    pub fn interrupt(&mut self) -> Vec<McpRequestIdentity> {
        self.closed = true;
        self.protocol.interrupt()
    }

    /// Stop the complete contained process domain and verify its cleanup receipt.
    /// Call `interrupt` first to persist any pending request identities.
    ///
    /// # Errors
    /// Returns uncertainty when cleanup cannot be proven; guest receipts remain.
    pub fn stop(&mut self) -> Result<(), String> {
        let _ = self.interrupt();
        self.service.stop()
    }

    pub(super) fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.closed {
            return Err("Contained MCP connection is closed.".into());
        }
        let result = self.service.send(bytes);
        if result.is_err() {
            let _ = self.interrupt();
        }
        result
    }
}
