//! A required logging boundary for the optional transport. No raw log record is
//! ever formatted or stored; application Activity uses its separate event journal.
use std::sync::OnceLock;

struct PrivateLibraryLog;
static LOG: PrivateLibraryLog = PrivateLibraryLog;
static INSTALLED: OnceLock<Result<(), ()>> = OnceLock::new();

impl log::Log for PrivateLibraryLog {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        false
    }
    fn log(&self, _: &log::Record<'_>) {}
    fn flush(&self) {}
}

pub(crate) fn ensure() -> Result<(), String> {
    INSTALLED
        .get_or_init(|| log::set_logger(&LOG).map_err(|_| ()))
        .to_owned()
        .map_err(|()| {
            "WebSocket logging privacy could not be established. This transport remains disabled."
                .into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static FORMATTED: AtomicUsize = AtomicUsize::new(0);
    struct Sensitive;
    impl std::fmt::Display for Sensitive {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            FORMATTED.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[test]
    fn verbose_library_logs_never_format_or_store_sensitive_arguments() {
        ensure().unwrap();
        ensure().unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        for level in [
            log::Level::Error,
            log::Level::Warn,
            log::Level::Info,
            log::Level::Debug,
            log::Level::Trace,
        ] {
            log::log!(target:"tungstenite::handshake::client",level,"Authorization: {Sensitive}");
            log::log!(target:"tokio_tungstenite",level,"Frame: {Sensitive}");
            log::log!(target:"another_library",level,"{Sensitive}");
        }
        assert_eq!(FORMATTED.load(Ordering::SeqCst), 0);
    }
}
