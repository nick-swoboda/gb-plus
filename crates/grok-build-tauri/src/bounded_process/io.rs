//! Bounded I/O for fixed, already-authorized helper processes.
use super::{
    CAPTURE_CAPACITY, Limits, MAX_BYTES, MAX_CAPTURE_CAPACITY, Output, OwnedProcess, POLL,
    STOP_WAIT,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

struct CaptureCapacity(usize);

impl CaptureCapacity {
    fn reserve(bytes: usize) -> Result<Self, String> {
        CAPTURE_CAPACITY
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|total| *total <= MAX_CAPTURE_CAPACITY)
            })
            .map_err(|_| "Fixed helper output capacity is occupied by other operations.")?;
        Ok(Self(bytes))
    }
}

impl Drop for CaptureCapacity {
    fn drop(&mut self) {
        CAPTURE_CAPACITY.fetch_sub(self.0, Ordering::AcqRel);
    }
}

/// Keep app-owned scratch authority alive through delayed process-group cleanup.
pub(crate) fn collect_with_resource(
    command: Command,
    input: &[u8],
    limits: &Limits,
    retained: Option<Box<dyn Send>>,
) -> Result<Output, String> {
    collect_with_input_bound(command, input, limits, retained, MAX_BYTES)
}

/// Only the fixed system Git snapshot encoder admits a larger buffered input.
/// Other helpers retain their original 64 MiB ceiling and output reservations.
pub(crate) fn collect_git_snapshot(
    command: Command,
    input: &[u8],
    limits: &Limits,
    retained: Box<dyn Send>,
) -> Result<Output, String> {
    if command.get_program() != std::ffi::OsStr::new("/usr/bin/git") {
        return Err("The snapshot input profile is restricted to fixed system Git.".into());
    }
    collect_with_input_bound(command, input, limits, Some(retained), 160 * 1024 * 1024)
}

fn collect_with_input_bound(
    mut command: Command,
    input: &[u8],
    limits: &Limits,
    retained: Option<Box<dyn Send>>,
    maximum_input: usize,
) -> Result<Output, String> {
    if input.len() > limits.input
        || limits.input > maximum_input
        || [limits.output, limits.error]
            .into_iter()
            .any(|limit| limit > MAX_BYTES)
        || limits.timeout.is_zero()
        || limits.timeout > Duration::from_mins(15)
    {
        return Err("Fixed helper input, output or deadline exceeds its admitted bound.".into());
    }
    let _capacity = CaptureCapacity::reserve(limits.output + limits.error)?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owned = OwnedProcess::spawn(&mut command)?;
    if let Some(resource) = retained {
        owned.retain_resource(resource)?;
    }
    let leader = owned.leader()?;
    let mut stdin = leader.child.stdin.take();
    let mut stdout = leader.child.stdout.take();
    let mut stderr = leader.child.stderr.take();
    nonblocking(stdin.as_ref().ok_or("Fixed helper stdin is unavailable.")?)?;
    nonblocking(
        stdout
            .as_ref()
            .ok_or("Fixed helper stdout is unavailable.")?,
    )?;
    nonblocking(
        stderr
            .as_ref()
            .ok_or("Fixed helper stderr is unavailable.")?,
    )?;
    let started = Instant::now();
    let mut written = 0;
    let mut output = Vec::new();
    let mut errors = Vec::new();
    loop {
        let progress_before = written + output.len() + errors.len();
        if started.elapsed() >= limits.timeout {
            return Err(format!(
                "Fixed helper exceeded its {} ms deadline; cleanup remains owned until exit is verified.",
                limits.timeout.as_millis()
            ));
        }
        read_available(&mut stdout, &mut output, limits.output)?;
        read_available(&mut stderr, &mut errors, limits.error)?;
        if written == input.len() {
            stdin = None;
        } else if let Some(pipe) = &mut stdin {
            let end = input.len().min(written.saturating_add(16 * 1024));
            match pipe.write(&input[written..end]) {
                Ok(0) => return Err("Fixed helper input closed before delivery completed.".into()),
                Ok(count) => written += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(format!("Cannot write bounded helper input: {error}")),
            }
        }
        if owned.leader()?.exited()? {
            if written != input.len() {
                return Err("Fixed helper exited before all input was delivered.".into());
            }
            // Signal descendants before reaping the identity-reserving leader.
            // Drain buffered output after teardown, without waiting for EOF from
            // an escaped descendant or creating unbounded reader threads.
            let status = owned.stop()?;
            read_remaining(&mut stdout, &mut output, limits.output)?;
            read_remaining(&mut stderr, &mut errors, limits.error)?;
            return Ok(Output {
                status,
                stdout: output,
                stderr: errors,
            });
        }
        if progress_before == written + output.len() + errors.len() {
            wait_for_io(
                stdin.as_ref(),
                stdout.as_ref(),
                stderr.as_ref(),
                POLL.min(limits.timeout.saturating_sub(started.elapsed())),
            )?;
        }
    }
}

fn wait_for_io(
    input: Option<&impl AsFd>,
    output: Option<&impl AsFd>,
    error: Option<&impl AsFd>,
    timeout: Duration,
) -> Result<(), String> {
    let mut descriptors = Vec::with_capacity(3);
    if let Some(pipe) = input {
        descriptors.push(PollFd::new(pipe, PollFlags::OUT));
    }
    if let Some(pipe) = output {
        descriptors.push(PollFd::new(pipe, PollFlags::IN));
    }
    if let Some(pipe) = error {
        descriptors.push(PollFd::new(pipe, PollFlags::IN));
    }
    let timeout = Timespec::try_from(timeout).map_err(|_| "Cannot bound helper I/O wait.")?;
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(format!("Cannot wait for bounded helper I/O: {error}")),
    }
}

fn nonblocking(fd: &impl AsFd) -> Result<(), String> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|error| error.to_string())?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| format!("Cannot bound helper pipe I/O: {error}"))
}

fn read_available(
    pipe: &mut Option<impl Read>,
    bytes: &mut Vec<u8>,
    limit: usize,
) -> Result<(), String> {
    let Some(reader) = pipe else {
        return Ok(());
    };
    let mut buffer = [0; 16 * 1024];
    // Four reads per iteration prevent an always-readable pipe from starving
    // input, cancellation/deadline inspection or the other output stream.
    for _ in 0..4 {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *pipe = None;
                return Ok(());
            }
            Ok(count) if bytes.len().saturating_add(count) <= limit => {
                bytes.extend_from_slice(&buffer[..count]);
            }
            Ok(_) => return Err("Fixed helper output exceeded its bounded host limit.".into()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(format!("Cannot read bounded helper output: {error}")),
        }
    }
    Ok(())
}

fn read_remaining(
    pipe: &mut Option<impl Read>,
    bytes: &mut Vec<u8>,
    limit: usize,
) -> Result<(), String> {
    // Finite byte bound also bounds the drain. A stream still open after a
    // quiet read is a cleanup failure, not permission to block on its owner.
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        let before = bytes.len();
        read_available(pipe, bytes, limit)?;
        if pipe.is_none() {
            return Ok(());
        }
        if bytes.len() == before {
            if Instant::now() >= deadline {
                return Err("Fixed helper descendant output did not close after teardown.".into());
            }
            std::thread::sleep(POLL);
        }
    }
}
