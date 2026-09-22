//! Detached ownership lasts through callback, helper completion and durable terminal state.
use super::super::{ServerSpec, broker};
use super::{
    Accounts, Binding, Flight, SignInChoice, auth_contract, callback::Callback, exchange, flow,
    intents::Phase, keychain, registration, review, revoke,
};
use crate::runtime::cancel::RuntimeCancelHandle;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(crate) type Revalidate = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;
impl Accounts {
    pub(crate) fn begin(
        &self,
        spec: &ServerSpec,
        choice: SignInChoice,
        revalidate: Revalidate,
    ) -> Result<(), String> {
        let slot = self.slot()?;
        revalidate()?;
        let mut book = self.book()?;
        let review = book
            .reviews
            .iter()
            .find(|r| r.id == choice.review_id)
            .cloned()
            .ok_or("MCP account review is absent.")?;
        let scopes = review.validate(spec, &choice)?;
        let id = review::unique_id()?;
        let project = spec.project.as_str().to_owned();
        let journal = self.journal(&project)?;
        journal.begin(&spec.identity, &id)?;
        let cancel = Arc::new(AtomicBool::new(false));
        book.last_error = None;
        book.flight = Some(Flight {
            project: project.clone(),
            id: id.clone(),
            cancel: Arc::clone(&cancel),
        });
        book.reviews.retain(|r| r.id != choice.review_id);
        let owner = self.clone();
        tauri::async_runtime::spawn(async move {
            // This task is never aborted. Cancellation reaches each bounded operation;
            // its reservation is retained until the actual helper/callback worker joins.
            let _slot = slot;
            let result = owner
                .sign_in(
                    &review,
                    choice,
                    scopes,
                    &id,
                    Arc::clone(&cancel),
                    revalidate,
                )
                .await;
            if let Err(reason) = &result {
                if let Ok(mut book) = owner.book() {
                    book.last_error = Some((project.clone(), reason.chars().take(2048).collect()));
                }
                let _ = journal.interrupt(&id);
                if let Ok(store) = owner.store(&project) {
                    let _ = store.interrupt(&id);
                }
            }
            if let Ok(mut book) = owner.book()
                && book.flight.as_ref().is_some_and(|f| f.id == id)
            {
                book.flight = None;
            }
        });
        Ok(())
    }
    async fn sign_in(
        &self,
        review: &review::Review,
        choice: SignInChoice,
        scopes: Vec<String>,
        id: &str,
        cancel: Arc<AtomicBool>,
        revalidate: Revalidate,
    ) -> Result<(), String> {
        let check = || {
            if cancel.load(Ordering::Acquire) {
                return Err("MCP sign-in was cancelled.".into());
            }
            revalidate()
        };
        check()?;
        let journal = self.journal(review.spec.project.as_str())?;
        let callback = Callback::bind()?;
        let issuer = &review.issuers[choice.issuer];
        let redirect = flow::redirect_uri(&issuer.issuer, callback.port()?)?;
        let client_id = if let Some(client) = choice.client_id {
            journal.advance(id, Phase::Prepared, Phase::Authorizing, None)?;
            client
        } else {
            let client = registration::register(issuer, &redirect, &cancel, &mut || {
                check()?;
                journal.advance(id, Phase::Prepared, Phase::Registering, None)
            })
            .await?;
            journal.advance(id, Phase::Registering, Phase::Authorizing, None)?;
            client
        };
        let issuer_copy = auth_contract::IssuerMetadata {
            issuer: issuer.issuer.clone(),
            authorization: issuer.authorization.clone(),
            token: issuer.token.clone(),
            registration: issuer.registration.clone(),
            response_issuer_required: issuer.response_issuer_required,
        };
        let flow = flow::Flow::new(
            issuer_copy,
            review.discovered.resource.resource.clone(),
            scopes.clone(),
            client_id.clone(),
            callback.port()?,
        )?;
        if flow.redirect() != &redirect {
            return Err("OAuth callback differed from its registered redirect.".into());
        }
        let url = flow.authorization_url()?;
        check()?;
        tauri::async_runtime::spawn_blocking(move || open_browser(url.as_str()))
            .await
            .map_err(|_| "MCP browser worker failed.")??;
        let waiting_cancel = Arc::clone(&cancel);
        let exchange =
            tauri::async_runtime::spawn_blocking(move || callback.wait(flow, &waiting_cancel))
                .await
                .map_err(|_| "MCP callback worker failed.")??;
        check()?;
        let tokens = exchange::redeem(exchange, &scopes, &journal, id, &cancel).await?;
        let mut binding = Binding {
            project: review.spec.project.as_str().into(),
            server: review.spec.identity.clone(),
            epoch: id.into(),
            resource: review.spec.endpoint.clone(),
            issuer: issuer.issuer.original().into(),
            client_id,
            metadata_digest: review.digest.clone(),
            scopes: tokens.scopes.clone(),
            key: String::new(),
        };
        binding.key = binding.expected_key()?;
        check()?;
        // Preserve intent first even if a crash lands between the two store commits.
        journal.advance(id, Phase::Exchanging, Phase::Storing, Some(binding.clone()))?;
        let store = self.store(&binding.project)?;
        store.begin(binding.clone())?;
        store.storing(id)?;
        let saved = binding.clone();
        let tokens = tauri::async_runtime::spawn_blocking(move || {
            keychain::store_verified(&saved, &tokens)?;
            keychain::load(&saved)
        })
        .await
        .map_err(|_| "MCP credential worker failed.")??;
        check()?;
        let grant = self.grant(&binding, &tokens, &cancel).await?;
        let mut authenticated = review.spec.clone();
        authenticated.account_identity = Some(binding.server_identity()?);
        authenticated.authorization = Some(grant);
        let readiness_cancel = RuntimeCancelHandle::new();
        // Readiness has its own finite request bounds. Cancellation remains checked
        // before activation; no tools or elicitation input are allowed by this probe.
        broker::inspect_server(&authenticated, None, readiness_cancel).await?;
        check()?;
        let mut book = self.book()?;
        if cancel.load(Ordering::Acquire) {
            return Err("MCP sign-in was cancelled before activation.".into());
        }
        let previous = store.activate_verified(id)?;
        if let Some(previous) = previous {
            revoke(&mut book, &previous.key);
        }
        journal.advance(id, Phase::Storing, Phase::Complete, None)?;
        Ok(())
    }
}
fn open_browser(url: &str) -> Result<(), String> {
    let mut command = std::process::Command::new("/usr/bin/open");
    command.env_clear().args(["--", url]);
    let result = crate::bounded_process::collect(
        command,
        &[],
        &crate::bounded_process::Limits {
            input: 0,
            output: 4096,
            error: 4096,
            timeout: std::time::Duration::from_secs(10),
        },
    )?;
    if !result.status.success() {
        return Err("The system browser did not acknowledge MCP sign-in.".into());
    }
    Ok(())
}
