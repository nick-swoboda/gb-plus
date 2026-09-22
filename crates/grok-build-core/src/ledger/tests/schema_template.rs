//! Process-shared exact-schema template fixtures (D-0002 pilot).
//!
//! Nearly every migration test used to rebuild its schema fixture by
//! replaying the full migration DDL chain from scratch. This module builds
//! each requested schema version at most ONCE per test process — by exactly
//! the same construction the per-module `create_exact_vNN_database` helpers
//! used — then hands every caller a cheap `fs::copy` of the closed template
//! file.
//!
//! Templates live in one process-scoped temporary directory keyed by
//! process id. The libtest harness offers no reliable process-exit hook, so
//! that directory is not removed at exit; leaking it (on abort or on normal
//! exit) is accepted and the operating system's temporary-file cleaner owns
//! it. Copies, in contrast, are owned by [`TestDatabase`] guards and are
//! removed on drop exactly like the pre-existing per-test fixtures.
//!
//! Templates are immutable once registered: callers only ever receive
//! copies, and nothing reopens a template path for writing.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use rusqlite::Connection;

use crate::ledger::{
    LedgerError, MIGRATIONS, SchemaObject, build_expected_schema_objects_through,
    compare_schema_objects_to_migration_source, current_criterion_evidence_v32,
    current_repair_task_authority_v32, current_task_done_source_v32, load_schema_objects,
    register_schema_functions, set_user_only_permissions,
    validate_schema_matches_migrations_through,
};

static NEXT_COPY: AtomicU64 = AtomicU64::new(1);

/// Isolated per-test database copy with the same drop-cleanup contract as
/// the pre-existing per-module `TestDatabase` fixtures.
pub(crate) struct TestDatabase {
    directory: PathBuf,
    pub(crate) path: PathBuf,
}

impl TestDatabase {
    fn new(version: u8, label: &str) -> Self {
        let unique = NEXT_COPY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "grok-build-schema-copy-v{version}-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated schema-copy directory");
        let path = directory.join("ledger.sqlite3");
        Self { directory, path }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Returns a fresh isolated database file holding the exact schema image of
/// the first `version` migrations, copied from the process-shared template.
pub(crate) fn exact_database_at(version: u8, label: &str) -> TestDatabase {
    let database = TestDatabase::new(version, label);
    install_exact_database_at(version, &database.path);
    database
}

/// Installs the exact schema image of the first `version` migrations at a
/// caller-owned path, copied from the process-shared template and restored
/// to user-only permissions exactly like every other template copy.
pub(crate) fn install_exact_database_at(version: u8, path: &Path) {
    let template = template_path(version);
    fs::copy(&template, path).expect("copy exact schema template");
    set_user_only_permissions(path).expect("secure exact schema-template copy");
}

/// Returns the immutable template file for `version`, building and
/// validating it on the first request in this process.
///
/// The registry lock is held across construction so concurrent tests wait
/// for one template build instead of duplicating it. A panic during
/// construction poisons the registry and fails later template requests
/// loudly; that only happens when the migration chain itself is broken, in
/// which case every direct-construction test fails identically.
fn template_path(version: u8) -> PathBuf {
    static TEMPLATES: OnceLock<Mutex<HashMap<u8, PathBuf>>> = OnceLock::new();
    let mut templates = TEMPLATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("schema-template registry is never poisoned");
    if let Some(path) = templates.get(&version) {
        return path.clone();
    }
    let directory = std::env::temp_dir().join(format!(
        "grok-build-schema-templates-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create process-scoped schema-template directory");
    let path = directory.join(format!("v{version}.sqlite3"));
    build_exact_database(version, &path);
    let connection = Connection::open(&path).expect("reopen exact schema template");
    register_schema_functions(&connection).expect("register template validation functions");
    validate_schema_matches_migrations_through(&connection, usize::from(version))
        .expect("schema template is exact");
    drop(connection);
    templates.insert(version, path.clone());
    path
}

/// Test-only cached front-end for `validate_schema_matches_migrations_through`.
///
/// The expected inventory for each requested version is built at most once
/// per test process — by the exact production builder — and reused for every
/// later call; the comparison itself always runs through the exact production
/// comparison path, so successes, failures, and error text are identical to
/// the uncached production validator.
pub(crate) fn validate_schema_cached(
    connection: &Connection,
    migration_count: usize,
) -> Result<(), LedgerError> {
    static EXPECTED: OnceLock<Mutex<HashMap<usize, Vec<SchemaObject>>>> = OnceLock::new();
    let actual = load_schema_objects(connection)?;
    let mut expected = EXPECTED
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("expected schema-inventory cache is never poisoned");
    if let std::collections::hash_map::Entry::Vacant(entry) = expected.entry(migration_count) {
        entry.insert(build_expected_schema_objects_through(migration_count)?);
    }
    compare_schema_objects_to_migration_source(
        &actual,
        &expected[&migration_count],
        migration_count,
    )
}

/// Builds an exact schema-`version` database at `path` by the same
/// construction the per-module `create_exact_vNN_database` helpers used:
/// apply the first `version` migrations with the v32 module interleavings,
/// advance `user_version` after every step, close the connection, and
/// restrict the file to user-only permissions.
fn build_exact_database(version: u8, path: &Path) {
    let _ = fs::remove_file(path);
    let connection = Connection::open(path).expect("create exact schema database");
    register_schema_functions(&connection).expect("register exact schema functions");
    connection
        .execute_batch("PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = OFF;")
        .expect("configure exact schema fixture");
    for (index, migration) in MIGRATIONS.iter().take(usize::from(version)).enumerate() {
        connection
            .execute_batch(migration)
            .expect("apply exact source migration");
        if index == 31 {
            connection
                .execute_batch(current_criterion_evidence_v32::MIGRATION_V32)
                .expect("apply criterion v32 source migration");
            connection
                .execute_batch(current_task_done_source_v32::MIGRATION_V32)
                .expect("apply TaskDone v32 source migration");
            connection
                .execute_batch(current_repair_task_authority_v32::MIGRATION_V32)
                .expect("apply repair-task v32 source migration");
        }
        connection
            .pragma_update(
                None,
                "user_version",
                i64::try_from(index + 1).expect("migration index fits i64"),
            )
            .expect("advance exact source schema version");
    }
    drop(connection);
    set_user_only_permissions(path).expect("secure exact schema database");
}

#[test]
fn template_copies_match_directly_constructed_databases() {
    for version in [32_u8, 33, 34] {
        let copy = exact_database_at(version, "equivalence");
        let direct = TestDatabase::new(version, "equivalence-direct");
        build_exact_database(version, &direct.path);

        let copy_connection = Connection::open(&copy.path).expect("open template copy");
        register_schema_functions(&copy_connection).expect("register copy schema functions");
        let direct_connection =
            Connection::open(&direct.path).expect("open directly-constructed database");
        register_schema_functions(&direct_connection).expect("register direct schema functions");

        let copy_version: i64 = copy_connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read template-copy user_version");
        let direct_version: i64 = direct_connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read direct user_version");
        assert_eq!(copy_version, i64::from(version));
        assert_eq!(direct_version, i64::from(version));

        assert_eq!(
            load_schema_objects(&copy_connection).expect("load template-copy schema objects"),
            load_schema_objects(&direct_connection).expect("load direct schema objects"),
            "template copy schema inventory diverged at v{version}"
        );
        validate_schema_matches_migrations_through(&copy_connection, usize::from(version))
            .expect("template copy matches the exact migration image");
    }
}
