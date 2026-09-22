//! A hard global bound includes connecting, busy, and warm sockets.
use std::sync::atomic::{AtomicUsize, Ordering};
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(super) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(super) struct SocketLease;
impl SocketLease {
    pub(super) fn acquire() -> Result<Self, &'static str> {
        ACTIVE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < 2).then_some(active + 1)
            })
            .map(|_| Self)
            .map_err(|_| "Two WebSocket connections already hold app leases.")
    }
}
impl Drop for SocketLease {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_third_socket_cannot_start_until_a_previous_socket_releases() {
        let _fixture = TEST_LOCK.lock().unwrap();
        let one = SocketLease::acquire().unwrap();
        let two = SocketLease::acquire().unwrap();
        assert!(SocketLease::acquire().is_err());
        drop(one);
        let next = SocketLease::acquire().unwrap();
        assert_eq!(ACTIVE.load(Ordering::Acquire), 2);
        drop((two, next));
        assert_eq!(ACTIVE.load(Ordering::Acquire), 0);
    }
}
