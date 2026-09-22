//! App-owned contained stdio transport. This protocol carries no provider authority.

use std::io::{self, Read};

use serde::{Deserialize, Serialize};

use crate::service_contract::ContainedServiceRequest;

mod staging;
pub use staging::{ServiceStagingError, ServiceStagingReceiver};

#[cfg(any(target_os = "linux", test))]
pub(crate) mod launch;

/// Maximum encoded JSON line, including byte-array expansion.
pub const MAX_SERVICE_CONTROL_BYTES: usize = 5 * 1024 * 1024;

/// Maximum observations per lease, including its reserved terminal receipt.
pub const MAX_SERVICE_EVENTS: u64 = 8192;

/// One control stream is bound to exactly one service lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceControl {
    /// Exact protocol version; currently one.
    pub version: u16,
    /// App-issued identity, matched to the initial request on every operation.
    pub lease_id: String,
    /// Strictly increasing sequence, starting at zero.
    pub sequence: u64,
    /// An app operation, never parsed from server stdout.
    pub operation: ServiceOperation,
}

/// Closed set of operations available to the independent app broker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceOperation {
    /// First frame only. The guest independently validates every expectation.
    Start {
        /// Exact bounded app-issued launch expectation.
        request: Box<ContainedServiceRequest>,
    },
    /// A data-only captured-view frame, accepted only before process startup.
    Snapshot {
        /// Which independently committed view these bytes belong to.
        view: crate::service_contract::ServiceView,
        /// Bounded, sequenced snapshot data; never executable control text.
        frame: crate::service_snapshot::ServiceSnapshotFrame,
    },
    /// Authorize process startup only after the app verifies `ViewsReady` and
    /// rechecks cancellation. Introduced in service profile four.
    Launch {
        /// Exact commitment acknowledged by the guest, including the one-use lease.
        commitment: grok_build_core::Digest,
    },
    /// Bounded bytes for the already admitted process's stdin.
    Input {
        /// Opaque bytes for stdin; never an outer control message.
        bytes: Vec<u8>,
    },
    /// The app completed protocol initialization. This is not execution authority.
    Ready,
    /// Close stdin while continuing bounded output collection.
    CloseInput,
    /// Terminate the entire contained descendant domain.
    Cancel,
}

/// Structured observations from the guest; output bytes are opaque here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceEvent {
    /// Exact protocol version; currently one.
    pub version: u16,
    /// The same lease that owns this transport.
    pub lease_id: String,
    /// Strictly increasing output sequence, independent of control sequence.
    pub sequence: u64,
    /// Containment lifecycle or bounded process output.
    pub observation: ServiceObservation,
}

/// Output and lifecycle never masquerade as control operations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceObservation {
    /// Both copied views match the request, before any service process starts.
    ViewsReady {
        /// The same complete request commitment used by Started.
        commitment: grok_build_core::Digest,
    },
    /// The guest installed and verified containment; MCP initialization follows.
    Started {
        /// Commitment to the complete admitted request.
        commitment: grok_build_core::Digest,
    },
    /// Bytes emitted on the service's standard output.
    Stdout {
        /// Bounded, opaque standard-output bytes.
        bytes: Vec<u8>,
    },
    /// Bytes emitted on the service's standard error.
    Stderr {
        /// Bounded, opaque standard-error bytes.
        bytes: Vec<u8>,
    },
    /// A bounded diagnostic; no argv, environment values, or process output.
    Refused {
        /// Bounded diagnostic without process data or credentials.
        reason: String,
    },
    /// A terminal observation. An absent cleanup proof is never success.
    Terminated {
        /// Supervisor's reason for ending this lease.
        reason: ServiceTermination,
        /// Observed normal exit code, absent for signals or unknown exit.
        exit_code: Option<i32>,
        /// True only after complete descendant-domain cleanup and receipt readback.
        cleanup_proven: bool,
    },
}

/// Why the supervisor stopped collecting process output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTermination {
    /// The service exited and all descendants and streams ended.
    Exited,
    /// Explicit stop from the owning app connection.
    Cancelled,
    /// The owner transport closed or became invalid.
    OwnerLost,
    /// Protocol initialization exceeded its bound.
    ReadinessTimeout,
    /// The private-view transfer exceeded its separate pre-launch deadline.
    StagingTimeout,
    /// Maximum lease lifetime elapsed.
    LifetimeTimeout,
    /// Input/output or protocol framing exceeded its limit.
    LimitExceeded,
    /// The admitted service installation, mount, or runtime changed.
    ContainmentChanged,
    /// A required kernel or transport operation failed.
    Failed,
}

/// An incremental reader that never buffers beyond its admitted frame bound.
pub struct ServiceFrameReader {
    bytes: Vec<u8>,
    maximum: usize,
    ended: bool,
}

impl ServiceFrameReader {
    /// Construct a reader with an explicit encoded-frame ceiling.
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum: maximum.min(MAX_SERVICE_CONTROL_BYTES),
            ended: false,
        }
    }

    /// Returns one complete frame, or no frame when a nonblocking read would wait.
    ///
    /// # Errors
    /// Refuses empty, incomplete or oversized frames and propagates I/O errors.
    pub fn next(&mut self, reader: &mut impl Read) -> Result<Option<Vec<u8>>, io::Error> {
        loop {
            if let Some(index) = self.bytes.iter().position(|byte| *byte == b'\n') {
                let remainder = self.bytes.split_off(index + 1);
                let mut frame = std::mem::replace(&mut self.bytes, remainder);
                frame.pop();
                if frame.is_empty() {
                    return Err(io::Error::other("empty service frame"));
                }
                return Ok(Some(frame));
            }
            if self.ended {
                return if self.bytes.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::other("incomplete service frame"))
                };
            }
            if self.bytes.len() >= self.maximum {
                return Err(io::Error::other("service frame limit"));
            }
            let mut chunk = [0; 8192];
            let limit = chunk.len().min(self.maximum - self.bytes.len());
            match reader.read(&mut chunk[..limit]) {
                Ok(0) => self.ended = true,
                Ok(count) => self.bytes.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Whether the owner closed input with no partial frame remaining.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended && self.bytes.is_empty()
    }
}

/// Recognizes only fixed internal service modes. Ordinary Checks are unchanged.
#[must_use]
pub fn run_contained_stdio_service_if_requested() -> Option<std::process::ExitCode> {
    let mode = std::env::args_os().nth(1)?;
    if !matches!(
        mode.to_str(),
        Some(
            "--gb-contained-service-v1"
                | "--gb-contained-service-child-v1"
                | "--gb-contained-service-guard-v1"
                | "--gb-contained-service-profile-v1"
                | "--gb-contained-service-fixture-v1"
        )
    ) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(crate::linux_cgroup_io::stdio_services::run(&mode))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(std::process::ExitCode::from(78))
    }
}

#[cfg(any(target_os = "linux", test))]
#[path = "contained_service/input.rs"]
mod input;

#[cfg(target_os = "linux")]
pub(crate) use input::ServiceInput;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn framing_preserves_multiple_lines_and_refuses_truncated_or_oversized_input() {
        let mut frames = ServiceFrameReader::new(16);
        let mut bytes = Cursor::new(b"one\ntwo\n");
        assert_eq!(frames.next(&mut bytes).unwrap(), Some(b"one".to_vec()));
        assert_eq!(frames.next(&mut bytes).unwrap(), Some(b"two".to_vec()));
        assert_eq!(frames.next(&mut bytes).unwrap(), None);
        assert!(frames.ended());
        assert!(
            ServiceFrameReader::new(4)
                .next(&mut Cursor::new(b"12345\n"))
                .is_err()
        );
        assert!(
            ServiceFrameReader::new(16)
                .next(&mut Cursor::new(b"partial"))
                .is_err()
        );
        assert!(
            ServiceFrameReader::new(16)
                .next(&mut Cursor::new(b"\n"))
                .is_err()
        );
    }

    #[test]
    fn output_cannot_decode_as_authoritative_control_and_unknown_operations_refuse() {
        let event = ServiceEvent {
            version: 1,
            lease_id: "owned".into(),
            sequence: 0,
            observation: ServiceObservation::Stdout {
                bytes: br#"{"operation":{"kind":"cancel"}}"#.to_vec(),
            },
        };
        assert!(
            serde_json::from_value::<ServiceControl>(serde_json::to_value(event).unwrap()).is_err()
        );
        let unknown = serde_json::json!({"version":1,"lease_id":"owned","sequence":1,"operation":{"kind":"execute","command":"anything"}});
        assert!(serde_json::from_value::<ServiceControl>(unknown).is_err());
    }
}
