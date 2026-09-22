//! Bounded I/O for already-authorized fixed host helpers; no execution authority.
//!
//! The unreaped group leader reserves its PID until group teardown. A numeric
//! process ID is never used for group signalling after reaping that leader.

use std::os::unix::process::CommandExt as _;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

mod io;
pub(crate) use io::{collect_git_snapshot, collect_with_resource};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

const MAX_CHILDREN: usize = 32;
const POLL: Duration = Duration::from_millis(10);
const STOP_WAIT: Duration = Duration::from_millis(250);
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_CAPTURE_CAPACITY: usize = 128 * 1024 * 1024;
static CAPTURE_CAPACITY: AtomicUsize = AtomicUsize::new(0);
static REAPER: OnceLock<Result<Arc<Reaper>, String>> = OnceLock::new();

#[cfg(target_os = "macos")]
#[path = "bounded_process/darwin_group.rs"]
mod darwin_group;

#[derive(Default)]
struct ReaperState {
    allocated: usize,
    pending: Vec<OwnedLeader>,
}

#[derive(Default)]
struct Reaper {
    state: Mutex<ReaperState>,
    changed: Condvar,
}

struct Reservation {
    reaper: Arc<Reaper>,
    armed: bool,
}

struct OwnedLeader {
    child: Child,
    signalled: bool,
    proof: CleanupProof,
    #[cfg(target_os = "macos")]
    retained_resource: Option<Box<dyn Send>>,
}

#[derive(Clone)]
pub(crate) struct CleanupProof(Arc<CleanupState>);

struct CleanupState {
    complete: AtomicBool,
    model: AtomicBool,
}

impl CleanupProof {
    pub(crate) fn same_process(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn proven(&self) -> bool {
        self.0.complete.load(Ordering::Acquire)
    }

    pub(crate) fn mark_model(&self) {
        self.0.model.store(true, Ordering::Release);
    }
}

impl OwnedLeader {
    fn exited(&self) -> Result<bool, String> {
        // WNOWAIT preserves the identity even when the leader has exited and
        // a descendant still holds a pipe. No wait(-1) or foreign PID exists.
        rustix::process::waitid(
            WaitId::Pid(self.pid()?),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .map(|status| status.is_some())
        .map_err(|error| format!("Cannot observe owned helper without reaping it: {error}"))
    }

    fn pid(&self) -> Result<Pid, String> {
        Pid::from_raw(self.child.id().cast_signed())
            .ok_or_else(|| "Owned helper has an invalid process identity.".into())
    }

    fn signal(&mut self) -> Result<(), String> {
        if self.signalled {
            return Ok(());
        }
        // Also refuses ECHILD: if an external wait stole ownership, do not
        // turn a historical PID into authority to signal a possibly new group.
        self.exited()?;
        match rustix::process::kill_process_group(self.pid()?, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            #[cfg(target_os = "macos")]
            Err(rustix::io::Errno::PERM)
                if self.exited()? && darwin_group::only_exited_members(self.child.id())? => {}
            Err(error) => return Err(format!("Cannot stop owned helper group: {error}")),
        }
        // A fixed executable may leave its initial group. The direct-child PID
        // is still reserved by the unreaped leader; it is not a discovered PID.
        match rustix::process::kill_process(self.pid()?, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(format!("Cannot stop owned helper leader: {error}")),
        }
        self.signalled = true;
        Ok(())
    }

    fn reap(&mut self) -> Result<Option<ExitStatus>, String> {
        self.signal()?;
        #[cfg(target_os = "macos")]
        if !self.exited()? || !darwin_group::only_exited_members(self.child.id())? {
            return Ok(None);
        }
        let status = self
            .child
            .try_wait()
            .map_err(|error| format!("Cannot reap owned helper: {error}"))?;
        if status.is_some() {
            self.proof.0.complete.store(true, Ordering::Release);
        }
        Ok(status)
    }
}

impl Reaper {
    fn shared() -> Result<Arc<Self>, String> {
        REAPER
            .get_or_init(|| {
                let reaper = Arc::new(Self::default());
                let worker = Arc::clone(&reaper);
                std::thread::Builder::new()
                    .name("gbplus-fixed-helper-reaper".into())
                    .spawn(move || worker.run())
                    .map_err(|error| format!("Cannot retain helper cleanup ownership: {error}"))?;
                Ok(reaper)
            })
            .clone()
    }

    fn reserve(self: &Arc<Self>) -> Result<Reservation, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.allocated >= MAX_CHILDREN {
            return Err("Fixed helper capacity is occupied, including pending cleanup.".into());
        }
        state.allocated += 1;
        Ok(Reservation {
            reaper: Arc::clone(self),
            armed: true,
        })
    }

    fn run(&self) {
        loop {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while state.pending.is_empty() {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            let mut completed = Vec::new();
            for index in (0..state.pending.len()).rev() {
                if matches!(state.pending[index].reap(), Ok(Some(_))) {
                    completed.push(state.pending.swap_remove(index));
                    state.allocated -= 1;
                }
            }
            drop(state);
            // A retained RAM home can itself use fixed OS helpers on Drop.
            // Never release these resources while holding the reaper lock.
            drop(completed);
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.armed {
            self.reaper
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .allocated -= 1;
        }
    }
}

/// This type never exposes a reapable Child to callers.
pub(crate) struct OwnedProcess {
    leader: Option<OwnedLeader>,
    reservation: Reservation,
}

impl OwnedProcess {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self, String> {
        let reservation = Reaper::shared()?.reserve()?;
        let child = command
            .process_group(0)
            .spawn()
            .map_err(|error| format!("Cannot start fixed helper: {error}"))?;
        Ok(Self {
            leader: Some(OwnedLeader {
                child,
                signalled: false,
                proof: CleanupProof(Arc::new(CleanupState {
                    complete: AtomicBool::new(false),
                    model: AtomicBool::new(false),
                })),
                #[cfg(target_os = "macos")]
                retained_resource: None,
            }),
            reservation,
        })
    }

    fn leader(&mut self) -> Result<&mut OwnedLeader, String> {
        self.leader
            .as_mut()
            .ok_or_else(|| "Fixed helper was already reaped.".into())
    }

    pub(crate) fn cleanup_proof(&mut self) -> Result<CleanupProof, String> {
        Ok(self.leader()?.proof.clone())
    }

    pub(crate) fn take_stdin(&mut self) -> Result<ChildStdin, String> {
        self.leader()?
            .child
            .stdin
            .take()
            .ok_or_else(|| "Owned helper stdin is unavailable.".into())
    }

    pub(crate) fn take_stdout(&mut self) -> Result<ChildStdout, String> {
        self.leader()?
            .child
            .stdout
            .take()
            .ok_or_else(|| "Owned helper stdout is unavailable.".into())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn retain_resource(&mut self, resource: Box<dyn Send>) -> Result<(), String> {
        let leader = self.leader()?;
        if leader.retained_resource.is_some() {
            return Err("Owned helper already has its cleanup resource.".into());
        }
        leader.retained_resource = Some(resource);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> Result<ExitStatus, String> {
        let deadline = Instant::now() + STOP_WAIT;
        loop {
            if let Some(status) = self.leader()?.reap()? {
                self.leader = None;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err("Fixed helper cleanup is still pending; ownership is retained.".into());
            }
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if self.leader.is_none() {
            return;
        }
        let _ = self.stop();
        if let Some(leader) = self.leader.take() {
            let mut state = self
                .reservation
                .reaper
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Its pre-spawn reservation guarantees space even when every other
            // caller is concurrently failing. Cleanup never discards a Child.
            state.pending.push(leader);
            self.reservation.armed = false;
            self.reservation.reaper.changed.notify_one();
        }
    }
}

pub(crate) struct Limits {
    pub(crate) input: usize,
    pub(crate) output: usize,
    pub(crate) error: usize,
    pub(crate) timeout: Duration,
}

/// Covers connection/model probes that do not own a durable queue run record.
pub(crate) fn model_cleanup_pending() -> bool {
    REAPER.get().is_some_and(|result| {
        result.as_ref().is_ok_and(|reaper| {
            reaper.state.lock().map_or(true, |state| {
                state.pending.iter().any(|leader| {
                    leader.proof.0.model.load(Ordering::Acquire) && !leader.proof.proven()
                })
            })
        })
    })
}

pub(crate) struct Output {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

pub(crate) fn collect(command: Command, input: &[u8], limits: &Limits) -> Result<Output, String> {
    collect_with_resource(command, input, limits, None)
}

#[cfg(test)]
#[path = "bounded_process/tests.rs"]
mod tests;
