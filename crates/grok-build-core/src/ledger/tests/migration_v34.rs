// Relocated schema-v34 operational-migration tests; the module itself is
// collapsed to a plain migration constant in `ledger/migrations.rs`.

mod migration_v34 {
    use rusqlite::{Connection, TransactionBehavior};

    use super::schema_template::{exact_database_at, validate_schema_cached};
    use crate::ledger::migrations::MIGRATION_V34;
    use crate::ledger::{
        EventLedger, LedgerError, load_schema_objects, register_schema_functions,
    };

    #[test]
    fn v34_schema_is_strict_append_only_and_reserves_the_closed_lifecycle_set() {
        assert_eq!(MIGRATION_V34.matches("CREATE TABLE ").count(), 2);
        assert_eq!(MIGRATION_V34.matches("STRICT, WITHOUT ROWID").count(), 2);
        assert_eq!(MIGRATION_V34.matches("CREATE TRIGGER ").count(), 9);
        for operation in ["BEFORE UPDATE", "BEFORE DELETE"] {
            assert_eq!(MIGRATION_V34.matches(operation).count(), 2);
        }
        for kind in [
            "AttemptAdmitted",
            "LaunchCommitted",
            "CaptureAcquired",
            "V13Initialized",
            "CommandDispatched",
            "ControlIssued",
            "ControlObserved",
            "ControlReconciled",
            "TerminalObserved",
            "EffectCutObserved",
            "OutputCustodyClosed",
            "CommandDomainCleanupObserved",
            "RunnerDirectChildObserved",
            "RunnerDomainObserved",
            "RunnerCleanupClosed",
            "EvidenceClosed",
            "OutcomeDerived",
        ] {
            assert!(
                MIGRATION_V34.contains(&format!("'{kind}'")),
                "missing {kind}"
            );
        }
        assert!(MIGRATION_V34.contains("NEW.event_kind != 'AttemptAdmitted'"));
        assert!(MIGRATION_V34.contains("NEW.attempt_ordinal != 1"));
        assert!(MIGRATION_V34.contains("length(CAST(request_id AS BLOB)) BETWEEN 1 AND 256"));
        assert!(MIGRATION_V34.contains("length(operational_json) BETWEEN 1 AND 1048576"));
    }

    #[test]
    fn exact_v33_migrates_to_v34_and_matches_fresh_read_only_schema() {
        let upgraded_database = exact_database_at(33, "upgrade");
        let before = Connection::open(&upgraded_database.path).expect("inspect v33 source");
        register_schema_functions(&before).expect("register source inspection functions");
        let before_objects = load_schema_objects(&before).expect("capture v33 objects");
        drop(before);

        let mut upgraded_connection =
            Connection::open(&upgraded_database.path).expect("open v33 source for v34 migration");
        register_schema_functions(&upgraded_connection).expect("register v34 schema functions");
        let transaction = upgraded_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin exact v34 migration");
        transaction
            .execute_batch(MIGRATION_V34)
            .expect("apply exact v34 migration");
        transaction
            .pragma_update(None, "user_version", 34_i64)
            .expect("advance exact v34 version");
        transaction.commit().expect("commit exact v34 migration");
        let upgraded = upgraded_connection;
        let version: i64 = upgraded
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read upgraded version");
        assert_eq!(version, 34);
        validate_schema_cached(&upgraded, 34)
            .expect("upgraded schema is exact v34");
        let upgraded_objects = load_schema_objects(&upgraded).expect("load v34 objects");
        let added = upgraded_objects
            .iter()
            .filter(|object| !before_objects.contains(object))
            .collect::<Vec<_>>();
        assert_eq!(added.len(), 11);
        assert_eq!(
            added
                .iter()
                .filter(|object| object.object_type == "table")
                .count(),
            2
        );
        assert_eq!(
            added
                .iter()
                .filter(|object| object.object_type == "trigger")
                .count(),
            9
        );

        let fresh_database = exact_database_at(33, "fresh");
        let fresh = Connection::open(&fresh_database.path).expect("open fresh v33 source");
        register_schema_functions(&fresh).expect("register fresh v34 functions");
        fresh
            .execute_batch(MIGRATION_V34)
            .expect("apply fresh exact v34 migration");
        assert_eq!(
            upgraded_objects,
            load_schema_objects(&fresh).expect("load fresh v34 objects")
        );
        drop(upgraded);
        let reader = Connection::open_with_flags(
            &upgraded_database.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("reopen upgraded v34 read-only");
        register_schema_functions(&reader).expect("register read-only v34 functions");
        validate_schema_cached(&reader, 34)
            .expect("read-only v34 schema remains exact");
    }

    #[test]
    fn divergent_v33_is_rejected_before_any_v34_object_exists() {
        let database = exact_database_at(33, "divergent");
        let divergent = Connection::open(&database.path).expect("open v33 source for divergence");
        divergent
            .execute_batch("CREATE TABLE unexpected_v33_object (id TEXT PRIMARY KEY) STRICT;")
            .expect("inject divergent v33 object");
        drop(divergent);

        let Err(error) = EventLedger::open(&database.path) else {
            panic!("divergent v33 source must fail before v34");
        };
        assert!(matches!(
            error,
            LedgerError::Corrupt {
                entity: "ledger schema migration source",
                ref detail,
            } if detail.contains("exact version 33 source image")
        ));
        let unchanged = Connection::open(&database.path).expect("reinspect divergent v33");
        let version: i64 = unchanged
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read unchanged source version");
        assert_eq!(version, 33);
        let installed: i64 = unchanged
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name IN (
                    'current_final_verification_events_v34',
                    'current_final_verification_operational_attempts_v34'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("count prematurely installed v34 objects");
        assert_eq!(installed, 0);
    }
}
