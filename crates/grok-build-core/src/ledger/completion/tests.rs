use super::*;

#[test]
fn warmed_reference_rechecks_each_database_and_detects_subsequent_schema_tampering() {
    let connection = Connection::open_in_memory().unwrap();
    register_schema_functions(&connection).unwrap();
    for (index, migration) in MIGRATIONS.iter().enumerate() {
        connection.execute_batch(migration).unwrap();
        if index == 31 {
            connection
                .execute_batch(current_criterion_evidence_v32::MIGRATION_V32)
                .unwrap();
            connection
                .execute_batch(current_task_done_source_v32::MIGRATION_V32)
                .unwrap();
            connection
                .execute_batch(current_repair_task_authority_v32::MIGRATION_V32)
                .unwrap();
        }
    }
    let first = expected_current_schema().unwrap();
    verify_exact_schema(&connection).unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &first,
        &expected_current_schema().unwrap()
    ));
    connection
        .execute_batch("CREATE TABLE unexpected_schema_cache_fixture(value TEXT);")
        .unwrap();
    assert!(matches!(
        verify_exact_schema(&connection),
        Err(LedgerError::Corrupt {
            entity: "ledger schema",
            ..
        })
    ));
    connection
        .execute_batch("DROP TABLE unexpected_schema_cache_fixture;")
        .unwrap();
    verify_exact_schema(&connection).unwrap();
    let foreign = Connection::open_in_memory().unwrap();
    assert!(verify_exact_schema(&foreign).is_err());
    let trigger: String = connection
        .query_row(
            "SELECT name FROM sqlite_schema WHERE type='trigger' ORDER BY name LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let escaped = trigger.replace('"', "\"\"");
    connection
        .execute_batch(&format!("DROP TRIGGER \"{escaped}\";"))
        .unwrap();
    assert!(matches!(
        verify_exact_schema(&connection),
        Err(LedgerError::Corrupt {
            entity: "ledger schema",
            ..
        })
    ));
    assert!(std::sync::Arc::ptr_eq(
        &first,
        &expected_current_schema().unwrap()
    ));
}

#[test]
fn cached_reference_equals_fresh_migrations_and_reports_text_size_and_read_timings() {
    let started = std::time::Instant::now();
    let fresh = build_expected_schema_objects_through(MIGRATIONS.len()).unwrap();
    let fresh_elapsed = started.elapsed();
    let expected = expected_current_schema().unwrap();
    let started = std::time::Instant::now();
    for _ in 0..10 {
        assert!(std::sync::Arc::ptr_eq(
            &expected,
            &expected_current_schema().unwrap()
        ));
    }
    let cached_elapsed = started.elapsed();
    assert_eq!(fresh.as_slice(), expected.as_ref());
    let text_bytes: usize = expected
        .iter()
        .map(|object| {
            object.object_type.len()
                + object.name.len()
                + object.table_name.len()
                + object.sql.len()
        })
        .sum();
    eprintln!(
        "immutable schema reference: objects={}, text_bytes={text_bytes}, fresh_build_us={}, ten_cached_reads_us={}",
        expected.len(),
        fresh_elapsed.as_micros(),
        cached_elapsed.as_micros()
    );
}
