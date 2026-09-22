//! Cancellation handle independent from the Backend state mutex.

use std::io::Write;
use std::process::ChildStdin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;

#[derive(Clone)]
pub(crate) struct RuntimeCancelHandle {
    pub(crate) cli_interactions: super::cli_interactions::CliInteractions,
    cancelled: Arc<AtomicBool>,
    acp_target: Arc<Mutex<Option<AcpCancelTarget>>>,
    cleanup: Arc<Mutex<Vec<crate::bounded_process::CleanupProof>>>,
    service_cleanup: Arc<Mutex<Vec<Arc<grok_build_plus_host::McpStdioConnection>>>>,
    hook_cleanup: Arc<Mutex<Vec<HookCleanup>>>,
}

enum HookCleanup {
    Contained(grok_build_plus_host::ContainedServiceCleanup),
    #[cfg(test)]
    Fixture(Arc<AtomicBool>),
}

impl HookCleanup {
    fn proven(&self) -> bool {
        match self {
            Self::Contained(proof) => proof.proven(),
            #[cfg(test)]
            Self::Fixture(proof) => proof.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone)]
struct AcpCancelTarget {
    stdin: Arc<Mutex<ChildStdin>>,
    session_id: String,
}

impl RuntimeCancelHandle {
    pub(crate) fn new() -> Self {
        Self {
            cli_interactions: super::cli_interactions::CliInteractions::default(),
            cancelled: Arc::new(AtomicBool::new(false)),
            acp_target: Arc::new(Mutex::new(None)),
            cleanup: Arc::new(Mutex::new(Vec::new())),
            service_cleanup: Arc::new(Mutex::new(Vec::new())),
            hook_cleanup: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn ensure_not_cancelled(&self) -> Result<(), String> {
        if self.cancelled() {
            Err("Agent run was stopped before provider execution began.".into())
        } else {
            Ok(())
        }
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub(crate) fn retain_cleanup(
        &self,
        proof: crate::bounded_process::CleanupProof,
    ) -> Result<(), String> {
        proof.mark_model();
        let mut cleanup = self
            .cleanup
            .lock()
            .map_err(|_| "Runtime cleanup registry is unavailable.")?;
        cleanup.retain(|proof| !proof.proven());
        if cleanup.len() >= 4 {
            return Err("Runtime cleanup capacity is occupied; another CLI cannot start.".into());
        }
        cleanup.push(proof);
        Ok(())
    }

    pub(crate) fn cleanup_proven(&self) -> bool {
        self.cleanup.lock().is_ok_and(|cleanup| {
            cleanup
                .iter()
                .all(crate::bounded_process::CleanupProof::proven)
        }) && self
            .service_cleanup
            .lock()
            .is_ok_and(|services| services.iter().all(|service| service.cleanup_proven()))
            && self
                .hook_cleanup
                .lock()
                .is_ok_and(|proofs| proofs.iter().all(HookCleanup::proven))
    }

    pub(crate) fn release_idle_cli(
        &self,
        proof: &crate::bounded_process::CleanupProof,
    ) -> Result<(), String> {
        self.ensure_not_cancelled()?;
        let mut cleanup = self
            .cleanup
            .lock()
            .map_err(|_| "Runtime cleanup registry is unavailable.")?;
        let index = cleanup
            .iter()
            .position(|owned| owned.same_process(proof))
            .ok_or("The idle CLI was not owned by this turn.")?;
        cleanup.remove(index);
        self.clear_acp();
        Ok(())
    }

    pub(crate) fn retain_hook_cleanup(
        &self,
        proof: grok_build_plus_host::ContainedServiceCleanup,
    ) -> Result<(), String> {
        self.retain_hook_cleanup_inner(HookCleanup::Contained(proof))
    }

    #[cfg(test)]
    pub(crate) fn retain_hook_cleanup_fixture(&self, proof: Arc<AtomicBool>) -> Result<(), String> {
        self.retain_hook_cleanup_inner(HookCleanup::Fixture(proof))
    }

    fn retain_hook_cleanup_inner(&self, proof: HookCleanup) -> Result<(), String> {
        self.ensure_not_cancelled()?;
        let mut proofs = self
            .hook_cleanup
            .lock()
            .map_err(|_| "Hook cleanup registry is unavailable.")?;
        proofs.retain(|proof| !proof.proven());
        if proofs.len() >= 8 {
            return Err("Hook cleanup capacity is occupied. No new hook may start.".into());
        }
        proofs.push(proof);
        Ok(())
    }

    pub(crate) fn retain_service_cleanup(
        &self,
        service: Arc<grok_build_plus_host::McpStdioConnection>,
    ) -> Result<(), String> {
        let mut services = self
            .service_cleanup
            .lock()
            .map_err(|_| "Service cleanup ownership is unavailable.")?;
        services.retain(|service| !service.cleanup_proven());
        if services.len() >= 4 {
            service.interrupt();
            return Err(
                "Service cleanup capacity is occupied; another service cannot start.".into(),
            );
        }
        if self.cancelled() {
            service.interrupt();
        }
        services.push(service);
        Ok(())
    }

    pub(crate) fn register_acp(
        &self,
        stdin: Arc<Mutex<ChildStdin>>,
        session_id: String,
    ) -> Result<(), String> {
        *self
            .acp_target
            .lock()
            .map_err(|_| "ACP cancellation target lock is unavailable.".to_owned())? =
            Some(AcpCancelTarget { stdin, session_id });
        if self.cancelled() {
            self.request_cancel()?;
        }
        Ok(())
    }

    pub(crate) fn clear_acp(&self) {
        if let Ok(mut target) = self.acp_target.lock() {
            *target = None;
        }
    }

    pub(crate) fn request_cancel(&self) -> Result<(), String> {
        self.cancelled.store(true, Ordering::Release);
        if let Ok(services) = self.service_cleanup.lock() {
            for service in services.iter() {
                service.interrupt();
            }
        }
        let target = self
            .acp_target
            .lock()
            .map_err(|_| "ACP cancellation target lock is unavailable.".to_owned())?
            .clone();
        let Some(target) = target else {
            return Ok(());
        };
        let message = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "session/cancel",
            "params": { "sessionId": target.session_id },
        }))
        .map_err(|error| format!("cannot encode ACP cancellation: {error}"))?;
        let mut stdin = target
            .stdin
            .lock()
            .map_err(|_| "Grok CLI ACP stdin lock is unavailable.".to_owned())?;
        stdin
            .write_all(&message)
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
            .map_err(|error| format!("cannot cancel Grok CLI ACP: {error}"))
    }
}

impl Default for RuntimeCancelHandle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "cancel/tests.rs"]
mod tests;
