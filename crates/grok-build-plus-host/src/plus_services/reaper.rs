//! Fixed-capacity ownership of service transports, including delayed reaping.

use std::process::Child;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const MAX_TRANSPORTS: usize = 16;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static NEXT: AtomicUsize = AtomicUsize::new(1);
static PENDING: Mutex<Vec<(Child, Reservation)>> = Mutex::new(Vec::new());

pub(super) struct Reservation {
    identity: usize,
    cleanup: Option<super::ContainedServiceCleanup>,
}

impl Reservation {
    pub(super) fn acquire() -> Result<Self, String> {
        reap();
        ACTIVE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_TRANSPORTS).then_some(count + 1)
            })
            .map_err(|_| {
                "Service transport capacity is occupied, including unreaped processes.".to_string()
            })?;
        Ok(Self {
            identity: NEXT.fetch_add(1, Ordering::Relaxed),
            cleanup: None,
        })
    }

    pub(super) fn track(&mut self, cleanup: super::ContainedServiceCleanup) {
        self.cleanup = Some(cleanup);
    }

    pub(super) fn retire(self, mut child: Child) -> usize {
        let identity = self.identity;
        // No caller reaps this child before retirement, so its PID cannot be
        // reused before this single process-group signal.
        if let Some(pid) = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return identity;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Capacity was reserved before spawn and remains occupied until reap.
        // No unbounded thread or dropped Child can hide a stuck transport.
        PENDING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((child, self));
        identity
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(cleanup) = &self.cleanup {
            cleanup.transport_reaped();
        }
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) fn pending(identity: usize) -> bool {
    reap();
    PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|(_, slot)| slot.identity == identity)
}

pub(super) fn reap() {
    let mut pending = PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < pending.len() {
        if pending[index].0.try_wait().ok().flatten().is_some() {
            pending.swap_remove(index);
        } else {
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    #[test]
    fn delayed_transport_reap_updates_the_retained_cleanup_observation() {
        let mut admission = super::super::cleanup::Admission::new();
        let proof = admission.cleanup.clone();
        let mut reservation = Reservation::acquire().unwrap();
        reservation.track(proof.clone());
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        admission.spawned();
        let input = child.stdin.take().unwrap();
        assert!(child.try_wait().unwrap().is_none());
        proof.guest_clean(); // The independent guest receipt is a fixture here.
        PENDING.lock().unwrap().push((child, reservation));
        drop(admission);
        assert!(
            !proof.proven(),
            "The actual unreaped transport still owns custody."
        );
        drop(input);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !proof.proven() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            proof.proven(),
            "Reaping must update the same externally retained observation."
        );
    }
}
