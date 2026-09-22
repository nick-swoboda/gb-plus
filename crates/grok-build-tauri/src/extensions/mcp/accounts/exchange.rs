//! Exactly one journaled authorization-code exchange; no uncertain request retry.
use super::{
    flow::Exchange,
    http,
    intents::{Journal, Phase},
    tokens::Tokens,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) async fn redeem(
    exchange: Exchange,
    requested_scopes: &[String],
    journal: &Journal,
    id: &str,
    cancel: &AtomicBool,
) -> Result<Tokens, String> {
    if cancel.load(Ordering::Acquire) {
        return Err("MCP sign-in was cancelled before token exchange.".into());
    }
    journal.advance(id, Phase::Authorizing, Phase::Exchanging, None)?;
    let response = http::request(
        &exchange.endpoint,
        Some(http::RequestBody::Form(exchange.body.into_vec())),
        cancel,
    )
    .await?;
    if response.status != 200 {
        return Err("MCP token exchange was not confirmed. Start a new explicit sign-in; this code is not replayed.".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "MCP credential clock is unavailable.")?
        .as_secs();
    Tokens::parse(&response.body, requested_scopes, now)
}

#[cfg(test)]
mod tests {
    use super::super::auth_contract::Endpoint;
    use super::super::flow::Secret;
    use super::*;
    #[test]
    fn a_missing_or_consumed_intent_prevents_token_network_io() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-auth-exchange-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal = Journal::new(&root, "fixture-project").unwrap();
        let id = "a".repeat(64);
        let exchange = || Exchange {
            endpoint: Endpoint::parse("https://127.0.0.1/token").unwrap(),
            body: Secret::new(b"code=synthetic".to_vec()).unwrap(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(redeem(
            exchange(),
            &[],
            &journal,
            &id,
            &AtomicBool::new(false),
        ));
        assert!(result.err().unwrap().contains("absent"));
        journal.begin(&"b".repeat(64), &id).unwrap();
        journal
            .advance(&id, Phase::Prepared, Phase::Authorizing, None)
            .unwrap();
        journal
            .advance(&id, Phase::Authorizing, Phase::Exchanging, None)
            .unwrap();
        let result = runtime.block_on(redeem(
            exchange(),
            &[],
            &journal,
            &id,
            &AtomicBool::new(false),
        ));
        assert!(result.err().unwrap().contains("already submitted"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
