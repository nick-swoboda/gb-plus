/// The frozen v37 fixture, copied so the original is never written.
///
/// `EventLedger::open` migrates in place and journals in WAL mode, so opening
/// the fixture directly would destroy the one artefact that cannot be
/// recreated. `TestDatabase` supplies the isolated directory and removes it on
/// drop, so no new dependency is taken for this.
fn frozen_v37_ledger_copy() -> TestDatabase {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("ledger-schema")
        .canonicalize()
        .expect("canonicalize the frozen ledger fixture directory")
        .join("schema-v37-migrated-ledger.db");
    let bytes = fs::read(&fixture).expect("read the frozen v37 ledger fixture");
    assert_eq!(
        bytes.len(),
        4_808_704,
        "the frozen v37 fixture must be the exact captured artefact"
    );
    let database = TestDatabase::new();
    fs::write(&database.path, &bytes).expect("copy the frozen v37 ledger");
    database
}

fn user_version_of(path: &std::path::Path) -> i64 {
    let connection =
        rusqlite::Connection::open(path).expect("open a ledger database to read its version");
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read a ledger database's schema version")
}

/// A real v37 database migrates to v38, and the new subject arrives with it.
#[test]
fn a_frozen_v37_ledger_migrates_to_v38_and_gains_the_command_release_subject() {
    let database = frozen_v37_ledger_copy();
    let path = &database.path;
    assert_eq!(
        user_version_of(path),
        37,
        "the fixture must still be a v37 database before it is opened"
    );

    let ledger = EventLedger::open(path).expect("migrate the frozen v37 ledger to v38");
    let version: i64 = ledger
        .connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read the migrated schema version");
    assert_eq!(version, SCHEMA_VERSION);
    assert_eq!(version, 38);

    // The migration is not merely "a version number moved": the subject this
    // increment exists to add has to be present and shaped as declared.
    for table in [
        "contained_command_release_admissions",
        "contained_command_release_outcomes",
    ] {
        let found: i64 = ledger
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .expect("query the migrated schema for the new subject");
        assert_eq!(found, 1, "v38 must create {table}");
    }

    // And the v13 runner-launch family must be untouched by it, because the
    // whole premise of a distinct subject is that the existing one is not
    // overloaded.
    for table in [
        "runner_launch_cleanup_admissions",
        "runner_launch_preparation_attempts",
        "runner_launch_preparation_outcomes",
    ] {
        let found: i64 = ledger
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .expect("query the migrated schema for the runner-launch family");
        assert_eq!(found, 1, "v38 must leave {table} in place");
    }
}

/// The migration is idempotent across a reopen, as every other one is.
#[test]
fn a_migrated_v38_ledger_reopens_without_migrating_again() {
    let database = frozen_v37_ledger_copy();
    let path = &database.path;
    drop(EventLedger::open(path).expect("migrate the frozen v37 ledger"));
    assert_eq!(user_version_of(path), 38);
    drop(EventLedger::open(path).expect("reopen the migrated ledger"));
    assert_eq!(user_version_of(path), 38);
}

/// A database from the future is refused, and the refusal names **both**
/// versions.
///
/// This is the case a forward-only chain cannot rescue, and it is the one an
/// older build actually meets after a newer build has migrated a shared ledger.
/// Reporting only the version found would leave that reader unable to say what
/// it expected.
#[test]
fn a_newer_schema_is_refused_by_a_message_naming_both_versions() {
    let database = frozen_v37_ledger_copy();
    let path = &database.path;
    {
        let connection = rusqlite::Connection::open(path).expect("open to stamp a future version");
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("stamp a schema version this build cannot understand");
    }

    let Err(error) = EventLedger::open(path) else {
        panic!("a future schema must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains(&(SCHEMA_VERSION + 1).to_string()),
        "the refusal must name the version it found: {message}"
    );
    assert!(
        message.contains(&SCHEMA_VERSION.to_string()),
        "the refusal must name the version this build understands: {message}"
    );
    assert!(
        matches!(error, LedgerError::UnsupportedSchemaVersion(found) if found == SCHEMA_VERSION + 1),
        "the refusal must carry the version it found: {message}"
    );

    // The database is left exactly as it was found: a refusal is not a
    // migration, and a build that cannot read a ledger must not write one.
    assert_eq!(user_version_of(path), SCHEMA_VERSION + 1);
}
