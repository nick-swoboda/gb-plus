//! Metadata reviews retain exact endpoints in Rust; UI selects only a reviewed entry.
use super::super::ServerSpec;
use super::{Accounts, auth_contract, discovery, store};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

pub(super) struct Review {
    pub(super) id: String,
    pub(super) spec: ServerSpec,
    pub(super) discovered: discovery::Discovery,
    pub(super) issuers: Vec<auth_contract::IssuerMetadata>,
    pub(super) digest: String,
    created: Instant,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewView {
    review_id: String,
    resource: String,
    scopes: Vec<String>,
    issuers: Vec<IssuerView>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IssuerView {
    issuer: String,
    authorization: String,
    token: String,
    registration: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignInChoice {
    pub(super) review_id: String,
    pub(super) issuer: usize,
    pub(super) scopes: Vec<String>,
    pub(super) client_id: Option<String>,
    pub(super) register_client: bool,
}
impl Review {
    pub(super) fn view(&self) -> ReviewView {
        ReviewView {
            review_id: self.id.clone(),
            resource: self.spec.endpoint.clone(),
            scopes: self.discovered.scopes.clone(),
            issuers: self
                .issuers
                .iter()
                .map(|m| IssuerView {
                    issuer: m.issuer.original().into(),
                    authorization: m.authorization.text().into(),
                    token: m.token.text().into(),
                    registration: m.registration.as_ref().map(|e| e.text().into()),
                })
                .collect(),
        }
    }
    pub(super) fn validate(
        &self,
        spec: &ServerSpec,
        choice: &SignInChoice,
    ) -> Result<Vec<String>, String> {
        if self.created.elapsed() >= Duration::from_mins(15)
            || self.spec.project != spec.project
            || self.spec.identity != spec.identity
            || self.id != choice.review_id
            || choice.issuer >= self.issuers.len()
        {
            return Err("MCP account review expired or changed project/server.".into());
        }
        let scopes = auth_contract::validate_scopes(choice.scopes.clone())?;
        if scopes.iter().any(|s| !self.discovered.scopes.contains(s)) {
            return Err("MCP sign-in requested an unreviewed scope.".into());
        }
        if choice.register_client == choice.client_id.is_some() {
            return Err(
                "Select either explicit public-client registration or an existing client ID."
                    .into(),
            );
        }
        if let Some(id) = &choice.client_id {
            if id.is_empty() || id.len() > 1024 || id.chars().any(char::is_control) {
                return Err("MCP public client ID is invalid.".into());
            }
        } else if self.issuers[choice.issuer].registration.is_none() {
            return Err("This issuer requires an existing public client ID.".into());
        }
        Ok(scopes)
    }
}
impl Accounts {
    pub(crate) async fn review(&self, spec: ServerSpec) -> Result<ReviewView, String> {
        let _slot = self.slot()?;
        if spec.local.is_some() {
            return Err("Contained MCP services do not receive OAuth credentials.".into());
        }
        let cancel = AtomicBool::new(false);
        let discovered =
            discovery::discover(&auth_contract::Endpoint::parse(&spec.endpoint)?, &cancel).await?;
        let mut issuers = Vec::new();
        for issuer in &discovered.resource.issuers {
            issuers.push(discovery::select_issuer(&discovered, issuer.text(), &cancel).await?);
        }
        let fields: Vec<_> = issuers
            .iter()
            .map(|m| {
                (
                    m.issuer.original(),
                    m.authorization.text(),
                    m.token.text(),
                    m.registration.as_ref().map(auth_contract::Endpoint::text),
                    m.response_issuer_required,
                )
            })
            .collect();
        let digest = store::hash(
            &serde_json::to_vec(&(&spec.identity, &discovered.scopes, fields))
                .map_err(|_| "Cannot bind MCP metadata review.")?,
        );
        let review = Arc::new(Review {
            id: unique_id()?,
            spec,
            discovered,
            issuers,
            digest,
            created: Instant::now(),
        });
        let view = review.view();
        let mut book = self.book()?;
        book.reviews
            .retain(|r| r.created.elapsed() < Duration::from_mins(15));
        if book.reviews.len() >= 8 {
            return Err("Close an account review before opening another.".into());
        }
        book.reviews.push(review);
        Ok(view)
    }
    pub(crate) fn close_review(&self, project: &str, id: &str) -> Result<(), String> {
        self.book()?
            .reviews
            .retain(|r| r.id != id || r.spec.project.as_str() != project);
        Ok(())
    }
}
pub(super) fn unique_id() -> Result<String, String> {
    use std::io::Read as _;
    let mut bytes = [0; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| "MCP operation identity could not be created.")?;
    Ok(store::hash(&bytes))
}
