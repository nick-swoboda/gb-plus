//! Opaque cleanup observation spanning admission, guest termination and delayed reap.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Read-only lifecycle observation issued before a contained-service admission.
/// It grants no launch authority and cannot be constructed from provider data.
#[derive(Clone)]
pub struct ContainedServiceCleanup(Arc<State>);

struct State {
    guest: AtomicBool,
    transport: AtomicBool,
}

impl ContainedServiceCleanup {
    /// True after a definitively unstarted admission, or after both the guest
    /// cleanup receipt and complete local transport reaping have been observed.
    /// Merely requesting Stop never makes this true.
    #[must_use]
    pub fn proven(&self) -> bool {
        super::reaper::reap();
        self.0.guest.load(Ordering::Acquire) && self.0.transport.load(Ordering::Acquire)
    }

    pub(super) fn guest_clean(&self) {
        self.0.guest.store(true, Ordering::Release);
    }

    pub(super) fn transport_reaped(&self) {
        self.0.transport.store(true, Ordering::Release);
    }
}

pub(super) struct Admission {
    pub(super) cleanup: ContainedServiceCleanup,
    spawned: bool,
}

impl Admission {
    pub(super) fn new() -> Self {
        Self {
            cleanup: ContainedServiceCleanup(Arc::new(State {
                guest: AtomicBool::new(false),
                transport: AtomicBool::new(false),
            })),
            spawned: false,
        }
    }

    pub(super) fn spawned(&mut self) {
        self.spawned = true;
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if !self.spawned {
            self.cleanup.guest_clean();
            self.cleanup.transport_reaped();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_refusal_proves_no_process_but_pending_admission_is_not_prunable() {
        let admission = Admission::new();
        let cleanup = admission.cleanup.clone();
        assert!(!cleanup.proven());
        drop(admission);
        assert!(cleanup.proven());
    }

    #[test]
    fn a_started_service_requires_both_guest_receipt_and_transport_reaping() {
        for guest_first in [true, false] {
            let mut admission = Admission::new();
            let cleanup = admission.cleanup.clone();
            admission.spawned();
            drop(admission);
            assert!(!cleanup.proven());
            if guest_first {
                cleanup.guest_clean();
            } else {
                cleanup.transport_reaped();
            }
            assert!(!cleanup.proven());
            if guest_first {
                cleanup.transport_reaped();
            } else {
                cleanup.guest_clean();
            }
            assert!(cleanup.proven());
        }
    }
}
