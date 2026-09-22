//! Explicit project-bound OAuth custody, independently of either chat transport.
mod auth_contract;
mod callback;
mod challenge;
mod discovery;
mod exchange;
mod flow;
mod http;
mod intents;
mod keychain;
mod registration;
mod review;
mod signin;
mod store;
mod tokens;

use super::ServerSpec;
use crate::contracts::ProjectId;
use grok_build_plus_host::McpBearerAuthorization;
pub(crate) use review::{ReviewView, SignInChoice};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use store::{Binding, Store};

#[derive(Clone)]
pub(crate) struct Accounts(Arc<Inner>);
struct Inner {
    root: PathBuf,
    busy: Arc<AtomicBool>,
    book: Mutex<Book>,
}
#[derive(Default)]
struct Book {
    reviews: Vec<Arc<review::Review>>,
    flight: Option<Flight>,
    last_error: Option<(String, String)>,
    revoked: BTreeMap<String, Weak<AtomicBool>>,
}
struct Flight {
    project: String,
    id: String,
    cancel: Arc<AtomicBool>,
}
struct Slot(Arc<AtomicBool>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    connected: bool,
    issuer: Option<String>,
    scopes: Vec<String>,
    requires_account: bool,
    sign_in_active: bool,
    phase: Option<intents::Phase>,
    cleanup_pending: usize,
    error: Option<String>,
}
impl Accounts {
    pub(crate) fn new(root: &Path) -> Self {
        Self(Arc::new(Inner {
            root: root.into(),
            busy: Arc::new(AtomicBool::new(false)),
            book: Mutex::new(Book::default()),
        }))
    }
    fn slot(&self) -> Result<Slot, String> {
        if self.0.busy.swap(true, Ordering::AcqRel) {
            return Err("Another MCP account operation is in progress.".into());
        }
        Ok(Slot(Arc::clone(&self.0.busy)))
    }
    fn book(&self) -> Result<std::sync::MutexGuard<'_, Book>, String> {
        self.0
            .book
            .lock()
            .map_err(|_| "MCP account ownership is unavailable.".into())
    }
    fn store(&self, project: &str) -> Result<Store, String> {
        Store::new(&self.0.root, project)
    }
    fn journal(&self, project: &str) -> Result<intents::Journal, String> {
        intents::Journal::new(&self.0.root, project)
    }
    pub(crate) fn status(&self, spec: &ServerSpec) -> Result<Status, String> {
        let book = self.book()?;
        let store = self.store(spec.project.as_str())?;
        let active = store.active(&spec.identity)?;
        let running = book
            .flight
            .as_ref()
            .is_some_and(|f| f.project == spec.project.as_str());
        let phase = self.journal(spec.project.as_str())?.read()?.map(|r| {
            if !running && !matches!(r.phase, intents::Phase::Complete | intents::Phase::Cleared) {
                intents::Phase::Interrupted
            } else {
                r.phase
            }
        });
        Ok(Status {
            error: book
                .last_error
                .as_ref()
                .filter(|(p, _)| p == spec.project.as_str())
                .map(|(_, e)| e.clone()),
            connected: active.is_some(),
            issuer: active.as_ref().map(|b| b.issuer.clone()),
            scopes: active.map_or_else(Vec::new, |b| b.scopes),
            requires_account: store.requires_account(&spec.identity)?,
            sign_in_active: running,
            phase,
            cleanup_pending: store.pending_cleanup()?.len() + store.retired_cleanup()?.len(),
        })
    }
    pub(crate) fn cancel(&self, project: &str) -> Result<(), String> {
        if let Some(flight) = self
            .book()?
            .flight
            .as_ref()
            .filter(|f| f.project == project)
        {
            flight.cancel.store(true, Ordering::Release);
        }
        Ok(())
    }
    pub(crate) async fn authorize(
        &self,
        mut spec: ServerSpec,
        cancel: &AtomicBool,
    ) -> Result<ServerSpec, String> {
        if cancel.load(Ordering::Acquire) {
            return Err("MCP authorization was cancelled before credential lookup.".into());
        }
        if spec.local.is_some() {
            return Ok(spec);
        }
        let binding = {
            let _book = self.book()?;
            let store = self.store(spec.project.as_str())?;
            let binding = store.active(&spec.identity)?;
            if binding.is_none() && store.requires_account(&spec.identity)? {
                return Err(
                    "This MCP server requires account sign-in. Anonymous fallback is disabled."
                        .into(),
                );
            }
            binding
        };
        let Some(binding) = binding else {
            return Ok(spec);
        };
        if binding.resource != spec.endpoint {
            return Err("MCP account endpoint changed. Review sign-in again.".into());
        }
        let credential = binding.clone();
        let tokens = tauri::async_runtime::spawn_blocking(move || keychain::load(&credential))
            .await
            .map_err(|_| "MCP credential helper worker failed.")??;
        let authorization = self.grant(&binding, &tokens, cancel).await?;
        {
            let _book = self.book()?;
            if self
                .store(spec.project.as_str())?
                .active(&spec.identity)?
                .as_ref()
                .map(|b| &b.key)
                != Some(&binding.key)
            {
                return Err("MCP account changed while connecting.".into());
            }
            spec.account_identity = Some(binding.server_identity()?);
            spec.authorization = Some(authorization);
        }
        Ok(spec)
    }
    async fn grant(
        &self,
        binding: &Binding,
        tokens: &tokens::Tokens,
        cancel: &AtomicBool,
    ) -> Result<Arc<McpBearerAuthorization>, String> {
        let endpoint = auth_contract::Endpoint::parse(&binding.resource)?;
        let addresses = http::addresses(&endpoint, cancel).await?;
        let flag = {
            let mut book = self.book()?;
            book.revoked.retain(|_, w| w.strong_count() > 0);
            if let Some(flag) = book.revoked.get(&binding.key).and_then(Weak::upgrade) {
                flag
            } else {
                if book.revoked.len() >= 128 {
                    return Err("MCP credential lease capacity reached.".into());
                }
                let flag = Arc::new(AtomicBool::new(false));
                book.revoked
                    .insert(binding.key.clone(), Arc::downgrade(&flag));
                flag
            }
        };
        Ok(Arc::new(McpBearerAuthorization::new(
            ProjectId::new(&binding.project),
            binding.server_identity()?,
            &binding.resource,
            tokens.access(now())?.as_bytes(),
            addresses,
            Binding::expires_millis(tokens.expires_at)?,
            flag,
        )?))
    }
    /// Explicit cleanup is serialized with the owning sign-in task, including its
    /// blocking helper calls. Cancellation never detaches a late Keychain write.
    pub(crate) fn cleanup(&self, project: &str) -> Result<(), String> {
        let _slot = self.slot()?;
        let mut book = self.book()?;
        if book.flight.is_some() {
            return Err("Wait for the cancelled sign-in worker to stop.".into());
        }
        let store = self.store(project)?;
        let journal = self.journal(project)?;
        let intent = journal.read()?;
        if let Some(r) = &intent
            && !matches!(r.phase, intents::Phase::Complete | intents::Phase::Cleared)
        {
            journal.interrupt(&r.id)?;
            if let Some(b) = &r.binding
                && store.active(&b.server)?.as_ref().map(|a| &a.key) != Some(&b.key)
            {
                revoke(&mut book, &b.key);
                keychain::delete_verified(b)?;
            }
        }
        for binding in store.pending_cleanup()? {
            if store.active(&binding.server)?.as_ref().map(|a| &a.key) == Some(&binding.key) {
                return Err(
                    "Pending MCP credential unexpectedly matches an active account.".into(),
                );
            }
            revoke(&mut book, &binding.key);
            keychain::delete_verified(&binding)?;
            store.forget_pending_after_keychain_absence(&binding.epoch)?;
        }
        for binding in store.retired_cleanup()? {
            revoke(&mut book, &binding.key);
            keychain::delete_verified(&binding)?;
            store.forget_retired_after_keychain_absence(&binding.key)?;
        }
        if let Some(r) = intent
            .filter(|r| !matches!(r.phase, intents::Phase::Complete | intents::Phase::Cleared))
        {
            journal.clear_after_cleanup(&r.id)?;
        }
        if book.last_error.as_ref().is_some_and(|(p, _)| p == project) {
            book.last_error = None;
        }
        Ok(())
    }
    pub(crate) fn disconnect(&self, spec: &ServerSpec) -> Result<(), String> {
        let _slot = self.slot()?;
        let mut book = self.book()?;
        let store = self.store(spec.project.as_str())?;
        let binding = store.retire_active(&spec.identity)?;
        revoke(&mut book, &binding.key);
        keychain::delete_verified(&binding)?;
        store.forget_retired_after_keychain_absence(&binding.key)
    }
}
fn revoke(book: &mut Book, key: &str) {
    if let Some(flag) = book.revoked.get(key).and_then(Weak::upgrade) {
        flag.store(true, Ordering::Release);
    }
}
fn now() -> u64 {
    crate::runtime::types::unix_time_millis() / 1000
}
impl Binding {
    fn expires_millis(seconds: Option<u64>) -> Result<Option<u64>, String> {
        seconds
            .map(|n| {
                n.checked_mul(1000)
                    .ok_or_else(|| "MCP token expiry overflowed.".into())
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests;
