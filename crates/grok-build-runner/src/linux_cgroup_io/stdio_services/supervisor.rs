//! Bounded bidirectional stdio and deadlines, independent of MCP elicitation.

use super::*;

struct Events {
    lease: String,
    next: u64,
    output: std::io::Stdout,
}
impl Events {
    fn send(&mut self, observation: ServiceObservation) -> Result<(), String> {
        let maximum = crate::contained_service::MAX_SERVICE_EVENTS;
        if self.next >= maximum
            || (self.next + 1 == maximum
                && !matches!(&observation, ServiceObservation::Terminated { .. }))
        {
            return Err("Service observation budget reached; terminal receipt is reserved.".into());
        }
        let frame = ServiceEvent {
            version: 1,
            lease_id: self.lease.clone(),
            sequence: self.next,
            observation,
        };
        self.next = self
            .next
            .checked_add(1)
            .ok_or("Service event sequence overflow.")?;
        let mut bytes = serde_json::to_vec(&frame).map_err(failure)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_SERVICE_CONTROL_BYTES {
            return Err("Service output frame limit exceeded.".into());
        }
        write_bounded(&mut self.output, &bytes)
    }
}

pub(super) fn run() -> Result<(), String> {
    let installer_root = installer_argument()?;
    let mut input = std::io::stdin();
    nonblocking(&input)?;
    let mut frames = ServiceFrameReader::new(MAX_SERVICE_CONTROL_BYTES);
    let initial_deadline = Instant::now() + Duration::from_secs(10);
    let initial = loop {
        if let Some(bytes) = frames.next(&mut input).map_err(failure)? {
            break serde_json::from_slice::<ServiceControl>(&bytes).map_err(failure)?;
        }
        if frames.ended() || Instant::now() >= initial_deadline {
            return Err("Service start request was not received.".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let ServiceOperation::Start { request } = initial.operation else {
        return Err("Service first frame must be Start.".into());
    };
    request.validate_shape()?;
    if initial.version != 1 || initial.sequence != 0 || initial.lease_id != request.lease_id {
        return Err("Service start identity or sequence is invalid.".into());
    }
    let mut events = Events {
        lease: request.lease_id.clone(),
        next: 0,
        output: std::io::stdout(),
    };
    nonblocking(&events.output)?;
    let installation = Installation::open(&installer_root)?;
    let mut domain = match domain::Domain::prepare(installation, &request) {
        Ok(domain) => domain,
        Err(error) => {
            events.send(ServiceObservation::Refused {
                reason:
                    "Contained service admission or recovery refused. Inspect the guest diagnostic."
                        .into(),
            })?;
            return Err(format!(
                "Contained service was refused before process launch: {error}"
            ));
        }
    };
    let next_control = match staging::receive(&mut domain, &request, &mut input, &mut frames) {
        Ok(next) => next,
        Err(reason) => return finish_unstarted(&mut domain, &mut events, reason),
    };
    events.send(ServiceObservation::ViewsReady {
        commitment: request.commitment()?,
    })?;
    let next_control =
        match staging::confirm_launch(&domain, &request, &mut input, &mut frames, next_control) {
            Ok(next) => next,
            Err(reason) => return finish_unstarted(&mut domain, &mut events, reason),
        };
    if let Err(error) = domain.spawn(&request) {
        let cleanup = domain.terminate().is_ok();
        events.send(ServiceObservation::Terminated {
            reason: ServiceTermination::Failed,
            exit_code: None,
            cleanup_proven: cleanup,
        })?;
        return Err(format!(
            "Contained service setup failed before protocol readiness: {error}"
        ));
    }
    let outcome = drive(
        &mut domain,
        &request,
        &mut input,
        &mut frames,
        &mut events,
        next_control,
    );
    let exit_code = domain
        .child
        .as_mut()
        .and_then(|child| child.try_wait().ok().flatten())
        .and_then(|status| status.code());
    // Cleanup runs on every outcome, including event-write failure and EOF.
    let cleanup = domain.terminate().is_ok();
    let reason = outcome.unwrap_or(ServiceTermination::Failed);
    events.send(ServiceObservation::Terminated {
        reason,
        exit_code,
        cleanup_proven: cleanup,
    })?;
    if cleanup {
        Ok(())
    } else {
        Err("Service cleanup remains uncertain; ownership receipt retained.".into())
    }
}

fn finish_unstarted(
    domain: &mut domain::Domain,
    events: &mut Events,
    reason: ServiceTermination,
) -> Result<(), String> {
    let cleanup = domain.terminate().is_ok();
    events.send(ServiceObservation::Terminated {
        reason,
        exit_code: None,
        cleanup_proven: cleanup,
    })?;
    if cleanup {
        Ok(())
    } else {
        Err("Interrupted service startup retains an uncertain cleanup receipt.".into())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded duplex loop makes control sequencing, output draining, and every stop condition visible together"
)]
fn drive(
    domain: &mut domain::Domain,
    request: &ContainedServiceRequest,
    input: &mut std::io::Stdin,
    frames: &mut ServiceFrameReader,
    events: &mut Events,
    mut next_control: u64,
) -> Result<ServiceTermination, String> {
    let began = Instant::now();
    let mut checked = Instant::now();
    let expected_ready = guard::expected_ready(request)?;
    let mut ready_line = Vec::new();
    let mut contained = false;
    let mut protocol_ready = false;
    let mut input_closed = false;
    let mut pending_input = crate::contained_service::ServiceInput::new(
        usize::try_from(request.limits.input_bytes.min(16 * 1024 * 1024)).map_err(failure)?,
    )?;
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    loop {
        if began.elapsed() >= Duration::from_millis(request.limits.lifetime_ms) {
            return Ok(ServiceTermination::LifetimeTimeout);
        }
        if !protocol_ready && began.elapsed() >= Duration::from_millis(request.limits.readiness_ms)
        {
            return Ok(ServiceTermination::ReadinessTimeout);
        }
        if checked.elapsed() >= Duration::from_secs(1) {
            if domain.installation.revalidate().is_err() {
                return Ok(ServiceTermination::ContainmentChanged);
            }
            checked = Instant::now();
        }
        for _ in 0..16 {
            let frame = match frames.next(input) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => return Ok(ServiceTermination::LimitExceeded),
            };
            let control: ServiceControl = match serde_json::from_slice(&frame) {
                Ok(value) => value,
                Err(_) => return Ok(ServiceTermination::OwnerLost),
            };
            if control.version != 1
                || control.lease_id != request.lease_id
                || control.sequence != next_control
            {
                return Ok(ServiceTermination::OwnerLost);
            }
            next_control = next_control
                .checked_add(1)
                .ok_or("Service control sequence overflow.")?;
            match control.operation {
                ServiceOperation::Cancel => return Ok(ServiceTermination::Cancelled),
                ServiceOperation::Ready if contained && !protocol_ready => protocol_ready = true,
                ServiceOperation::CloseInput if contained && !input_closed => {
                    pending_input.close();
                    input_closed = true;
                }
                ServiceOperation::Input { bytes } if contained && !input_closed => {
                    input_bytes = input_bytes.saturating_add(bytes.len() as u64);
                    if bytes.len() > request.limits.frame_bytes as usize
                        || input_bytes > request.limits.input_bytes
                    {
                        return Ok(ServiceTermination::LimitExceeded);
                    }
                    pending_input.enqueue(bytes)?;
                }
                _ => return Ok(ServiceTermination::OwnerLost),
            }
        }
        if frames.ended() {
            return Ok(ServiceTermination::OwnerLost);
        }
        let child = domain
            .child
            .as_mut()
            .ok_or("Service process is unavailable.")?;
        if let Some(stdin) = child.stdin.as_mut() {
            pending_input.pump(stdin).map_err(failure)?;
            if pending_input.should_close() {
                child.stdin.take();
            }
        } else if pending_input.has_pending() {
            return Ok(ServiceTermination::Failed);
        }
        if !contained {
            let stdout = child.stdout.as_mut().ok_or("Service stdout unavailable.")?;
            loop {
                let mut byte = [0];
                match stdout.read(&mut byte) {
                    Ok(0) => {
                        stdout_closed = true;
                        break;
                    }
                    Ok(_) if byte[0] == b'\n' => {
                        if ready_line != expected_ready {
                            return Ok(ServiceTermination::Failed);
                        }
                        contained = true;
                        events.send(ServiceObservation::Started {
                            commitment: request.commitment()?,
                        })?;
                        break;
                    }
                    Ok(_) => {
                        ready_line.push(byte[0]);
                        if ready_line.len() > 256 {
                            return Ok(ServiceTermination::Failed);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(failure(error)),
                }
            }
        }
        if contained && !stdout_closed {
            let (count, ended) = drain(
                child.stdout.as_mut().unwrap(),
                request,
                events,
                false,
                output_bytes,
            )?;
            output_bytes = output_bytes.saturating_add(count);
            stdout_closed = ended;
        }
        if !stderr_closed {
            let (count, ended) = drain(
                child.stderr.as_mut().unwrap(),
                request,
                events,
                true,
                output_bytes,
            )?;
            output_bytes = output_bytes.saturating_add(count);
            stderr_closed = ended;
        }
        if output_bytes > request.limits.output_bytes {
            return Ok(ServiceTermination::LimitExceeded);
        }
        if child.try_wait().map_err(failure)?.is_some()
            && stdout_closed
            && stderr_closed
            && domain.empty()?
        {
            return Ok(if contained && !pending_input.has_pending() {
                ServiceTermination::Exited
            } else {
                ServiceTermination::Failed
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn drain(
    reader: &mut impl std::io::Read,
    request: &ContainedServiceRequest,
    events: &mut Events,
    stderr: bool,
    already_read: u64,
) -> Result<(u64, bool), String> {
    let mut total = 0_u64;
    for _ in 0..8 {
        let mut chunk = [0; 16 * 1024];
        let limit = chunk.len().min(request.limits.frame_bytes as usize);
        match reader.read(&mut chunk[..limit]) {
            Ok(0) => return Ok((total, true)),
            Ok(count) => {
                total += count as u64;
                if already_read.saturating_add(total) > request.limits.output_bytes {
                    return Ok((total, false));
                }
                let bytes = chunk[..count].to_vec();
                events.send(if stderr {
                    ServiceObservation::Stderr { bytes }
                } else {
                    ServiceObservation::Stdout { bytes }
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(failure(error)),
        }
    }
    Ok((total, false))
}
