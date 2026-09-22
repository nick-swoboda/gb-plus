use super::*;
use grok_build_plus_host::McpHttpsConnection;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "gbplus-mcp-accounts-{}",
            review::unique_id().unwrap()
        )))
    }
    fn accounts(&self) -> Accounts {
        Accounts::new(&self.0)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn binding() -> Binding {
    let mut b = Binding {
        project: "project-a".into(),
        server: "a".repeat(64),
        epoch: "b".repeat(64),
        resource: "https://8.8.8.8/mcp".into(),
        issuer: "https://issuer.invalid/".into(),
        client_id: "fixture-public".into(),
        metadata_digest: "c".repeat(64),
        scopes: vec!["read".into()],
        key: String::new(),
    };
    b.key = b.expected_key().unwrap();
    b
}
fn spec() -> ServerSpec {
    ServerSpec {
        project: ProjectId::new("project-a"),
        identity: "a".repeat(64),
        name: "fixture".into(),
        endpoint: "https://8.8.8.8/mcp".into(),
        local: None,
        account_identity: None,
        authorization: None,
    }
}
fn stage(accounts: &Accounts, b: &Binding) {
    let journal = accounts.journal(&b.project).unwrap();
    journal.begin(&b.server, &b.epoch).unwrap();
    journal
        .advance(
            &b.epoch,
            intents::Phase::Prepared,
            intents::Phase::Authorizing,
            None,
        )
        .unwrap();
    journal
        .advance(
            &b.epoch,
            intents::Phase::Authorizing,
            intents::Phase::Exchanging,
            None,
        )
        .unwrap();
    journal
        .advance(
            &b.epoch,
            intents::Phase::Exchanging,
            intents::Phase::Storing,
            Some(b.clone()),
        )
        .unwrap();
    let store = accounts.store(&b.project).unwrap();
    store.begin(b.clone()).unwrap();
    store.storing(&b.epoch).unwrap();
}
#[test]
fn crash_after_account_activation_preserves_the_active_key_during_explicit_cleanup() {
    let fixture = Fixture::new();
    let accounts = fixture.accounts();
    let b = binding();
    stage(&accounts, &b);
    accounts
        .store(&b.project)
        .unwrap()
        .activate_verified(&b.epoch)
        .unwrap();
    // No Keychain helper is present in unit tests. Cleanup must neither load nor
    // delete this active key when the crash cut is before the final journal commit.
    let reopened = fixture.accounts();
    assert_eq!(
        reopened.status(&spec()).unwrap().phase,
        Some(intents::Phase::Interrupted)
    );
    reopened.cleanup(&b.project).unwrap();
    assert_eq!(
        reopened
            .store(&b.project)
            .unwrap()
            .active(&b.server)
            .unwrap()
            .unwrap()
            .key,
        b.key
    );
    assert_eq!(
        reopened.status(&spec()).unwrap().phase,
        Some(intents::Phase::Cleared)
    );
    assert!(reopened.status(&spec()).unwrap().connected);
}
#[test]
fn cleanup_cannot_overtake_an_owned_callback_or_late_helper_worker() {
    let fixture = Fixture::new();
    let accounts = fixture.accounts();
    let b = binding();
    accounts
        .journal(&b.project)
        .unwrap()
        .begin(&b.server, &b.epoch)
        .unwrap();
    let slot = accounts.slot().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    accounts.book().unwrap().flight = Some(Flight {
        project: b.project.clone(),
        id: b.epoch.clone(),
        cancel: Arc::clone(&cancel),
    });
    assert!(accounts.cleanup(&b.project).is_err());
    accounts.cancel("another-project").unwrap();
    assert!(!cancel.load(Ordering::Acquire));
    accounts.cancel(&b.project).unwrap();
    assert!(cancel.load(Ordering::Acquire));
    assert!(accounts.cleanup(&b.project).is_err());
    accounts.book().unwrap().flight = None;
    drop(slot);
    accounts.cleanup(&b.project).unwrap();
    assert_eq!(
        accounts
            .journal(&b.project)
            .unwrap()
            .read()
            .unwrap()
            .unwrap()
            .phase,
        intents::Phase::Cleared
    );
}
#[test]
fn signed_out_account_never_degrades_to_anonymous_and_cancellation_precedes_helper_lookup() {
    let fixture = Fixture::new();
    let accounts = fixture.accounts();
    let b = binding();
    stage(&accounts, &b);
    let store = accounts.store(&b.project).unwrap();
    store.activate_verified(&b.epoch).unwrap();
    store.retire_active(&b.server).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(accounts.authorize(spec(), &AtomicBool::new(false)));
    assert!(
        result
            .err()
            .unwrap()
            .contains("Anonymous fallback is disabled")
    );
    let result = runtime.block_on(accounts.authorize(spec(), &AtomicBool::new(true)));
    assert!(result.err().unwrap().contains("before credential lookup"));
}
#[test]
fn all_frozen_connections_share_revocation_without_network_io() {
    let fixture = Fixture::new();
    let accounts = fixture.accounts();
    let b = binding();
    let tokens = tokens::Tokens::parse(
        br#"{"token_type":"Bearer","access_token":"synthetic","scope":"read"}"#,
        &b.scopes,
        now(),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let grant = runtime
        .block_on(accounts.grant(&b, &tokens, &AtomicBool::new(false)))
        .unwrap();
    let second = Arc::clone(&grant);
    let _entered = runtime.enter();
    if let Err(reason) = McpHttpsConnection::new_authenticated(grant) {
        panic!("authenticated fixture construction failed: {reason}");
    }
    revoke(&mut accounts.book().unwrap(), &b.key);
    assert!(McpHttpsConnection::new_authenticated(second).is_err());
}
