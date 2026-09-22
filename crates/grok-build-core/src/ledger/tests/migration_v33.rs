// Relocated schema-v33 collision-guard tests; the module itself is
// collapsed to a plain migration constant in `ledger/migrations.rs`.

mod migration_v33 {
    use std::collections::{BTreeMap, BTreeSet};

    use rusqlite::{Connection, OptionalExtension, params_from_iter};

    use super::schema_template::{exact_database_at, validate_schema_cached};
    use crate::ledger::migrations::MIGRATION_V33;
    use crate::ledger::{
        EventLedger, LedgerError, MIGRATIONS, load_schema_objects, register_schema_functions,
    };

    #[derive(Clone, Copy)]
    struct GuardSpec {
        table: &'static str,
        unique_sets: &'static [&'static [&'static str]],
    }

    const GUARDS: &[GuardSpec] = &[
        GuardSpec {
            table: "current_sprint_authorities_v32",
            unique_sets: &[&["sprint_id"], &["sprint_spec_digest"], &["task_graph_id"]],
        },
        GuardSpec {
            table: "current_task_graph_authorities_v32",
            unique_sets: &[&["graph_id"], &["sprint_id"], &["graph_digest"]],
        },
        GuardSpec {
            table: "current_task_nodes_v32",
            unique_sets: &[
                &["sprint_id", "task_id"],
                &["sprint_id", "declaration_ordinal"],
                &["sprint_id", "repair_slot_ordinal"],
            ],
        },
        GuardSpec {
            table: "current_task_done_sets_v32",
            unique_sets: &[&["set_digest"], &["sprint_id", "set_digest"]],
        },
        GuardSpec {
            table: "current_task_done_members_v32",
            unique_sets: &[
                &["set_digest", "member_ordinal"],
                &["set_digest", "task_id"],
                &["set_digest", "task_done_proof_id"],
                &["set_digest", "integration_receipt_id"],
                &["set_digest", "empty_change_set_id"],
            ],
        },
        GuardSpec {
            table: "current_task_done_set_seals_v32",
            unique_sets: &[&["set_digest"]],
        },
        GuardSpec {
            table: "current_criterion_evidence_sets_v32",
            unique_sets: &[&["set_digest"], &["sprint_id", "set_digest"]],
        },
        GuardSpec {
            table: "current_criterion_evidence_members_v32",
            unique_sets: &[
                &["set_digest", "member_ordinal"],
                &["set_digest", "criterion_id"],
                &["set_digest", "evidence_receipt_id"],
            ],
        },
        GuardSpec {
            table: "current_criterion_evidence_set_seals_v32",
            unique_sets: &[&["set_digest"]],
        },
        GuardSpec {
            table: "current_final_verification_controls_v32",
            unique_sets: &[&["control_id"], &["sprint_id", "control_id"]],
        },
        GuardSpec {
            table: "current_final_verification_attempts_v32",
            unique_sets: &[
                &["attempt_id"],
                &["request_id"],
                &["final_verification_admission_id"],
                &["authority_digest"],
                &["sprint_id", "attempt_ordinal"],
                &["sprint_id", "attempt_id"],
            ],
        },
        GuardSpec {
            table: "current_final_verification_capture_closures_v32",
            unique_sets: &[
                &["closure_id"],
                &["attempt_id"],
                &["sprint_id", "closure_id"],
            ],
        },
        GuardSpec {
            table: "current_final_verification_outcomes_v32",
            unique_sets: &[
                &["outcome_id"],
                &["attempt_id"],
                &["closure_id"],
                &["sprint_id", "outcome_id"],
            ],
        },
        GuardSpec {
            table: "current_final_verification_repair_activations_v32",
            unique_sets: &[
                &["activation_id"],
                &["failed_attempt_id"],
                &["failure_outcome_id"],
                &["sprint_id", "slot_ordinal"],
                &["sprint_id", "repair_task_id"],
            ],
        },
        GuardSpec {
            table: "current_final_verification_repair_completions_v32",
            unique_sets: &[
                &["completion_id"],
                &["request_id"],
                &["activation_id"],
                &["failed_attempt_id"],
                &["repair_task_done_proof_id"],
                &["integration_receipt_id"],
                &["change_set_id"],
                &["sprint_id", "completion_id"],
            ],
        },
        GuardSpec {
            table: "current_sprint_terminal_outcomes_v32",
            unique_sets: &[
                &["sprint_id"],
                &["source_attempt_id"],
                &["source_outcome_id"],
            ],
        },
        GuardSpec {
            table: "current_task_done_sources_v32",
            unique_sets: &[
                &["task_done_proof_id"],
                &["source_digest"],
                &[
                    "task_done_proof_id",
                    "sprint_id",
                    "task_id",
                    "integration_receipt_id",
                    "integration_kind",
                    "empty_change_set_id",
                    "input_snapshot",
                    "result_snapshot",
                ],
            ],
        },
        GuardSpec {
            table: "current_sprint_criteria_v32",
            unique_sets: &[
                &["sprint_id", "criterion_id"],
                &["sprint_id", "criterion_ordinal"],
            ],
        },
        GuardSpec {
            table: "current_automated_verification_sources_v32",
            unique_sets: &[
                &["verification_receipt_id"],
                &[
                    "verification_receipt_id",
                    "sprint_id",
                    "criterion_id",
                    "snapshot_digest",
                ],
            ],
        },
        GuardSpec {
            table: "current_human_acceptance_prompts_v32",
            unique_sets: &[
                &["prompt_id"],
                &["prompt_id", "sprint_id", "criterion_id", "snapshot_digest"],
                &["sprint_id", "criterion_id", "issued_event_sequence"],
            ],
        },
        GuardSpec {
            table: "current_human_acceptance_decisions_v32",
            unique_sets: &[
                &["decision_id"],
                &["prompt_id"],
                &[
                    "decision_id",
                    "prompt_id",
                    "sprint_id",
                    "criterion_id",
                    "snapshot_digest",
                ],
            ],
        },
        GuardSpec {
            table: "current_criterion_evidence_receipts_v32",
            unique_sets: &[
                &["receipt_id"],
                &["sprint_id", "criterion_id", "snapshot_digest"],
                &[
                    "receipt_id",
                    "sprint_id",
                    "criterion_id",
                    "snapshot_digest",
                    "evidence_kind",
                ],
            ],
        },
    ];

    const ALREADY_GUARDED_REPAIR_TABLES: &[&str] = &[
        "current_repair_task_ready_events_v32",
        "current_repair_task_lease_admissions_v32",
        "current_repair_task_attempt_admissions_v32",
    ];

    const MIGRATION_ONLY_LEGACY_TABLES: &[&str] = &["legacy_sprint_authority_exemptions_v32"];

    fn table_columns(spec: GuardSpec) -> Vec<&'static str> {
        spec.unique_sets
            .iter()
            .flat_map(|set| set.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn quoted_columns(columns: &[&str]) -> String {
        columns
            .iter()
            .map(|column| format!("\"{column}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn create_guard_fixture() -> Connection {
        let connection = Connection::open_in_memory().expect("open guard fixture");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = OFF;")
            .expect("configure adversarial guard fixture");
        for spec in GUARDS {
            let columns = table_columns(*spec);
            let declarations = columns
                .iter()
                .map(|column| format!("\"{column}\" TEXT"))
                .collect::<Vec<_>>()
                .join(", ");
            let constraints = spec
                .unique_sets
                .iter()
                .enumerate()
                .map(|(index, set)| {
                    let columns = quoted_columns(set);
                    if index == 0 {
                        format!("PRIMARY KEY ({columns})")
                    } else {
                        format!("UNIQUE ({columns})")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            connection
                .execute_batch(&format!(
                    "CREATE TABLE \"{}\" ({declarations}, {constraints}) STRICT, WITHOUT ROWID;",
                    spec.table
                ))
                .expect("create exact unique-set fixture table");
            let parent_columns = spec.unique_sets[0];
            let child_columns = parent_columns
                .iter()
                .map(|column| format!("\"{column}\" TEXT NOT NULL"))
                .collect::<Vec<_>>()
                .join(", ");
            connection
                .execute_batch(&format!(
                    "CREATE TABLE \"{}_v33_test_children\" (\
                         child_id TEXT PRIMARY KEY NOT NULL, \
                         {child_columns}, \
                         FOREIGN KEY ({}) REFERENCES \"{}\" ({}) ON DELETE RESTRICT\
                     ) STRICT, WITHOUT ROWID;",
                    spec.table,
                    quoted_columns(parent_columns),
                    spec.table,
                    quoted_columns(parent_columns),
                ))
                .expect("create dependent child for guarded table");
        }
        connection
            .execute_batch(MIGRATION_V33)
            .expect("install v33 guards in adversarial fixture");
        connection
    }

    fn insert_values(
        connection: &Connection,
        spec: GuardSpec,
        values: &BTreeMap<&'static str, Option<String>>,
        replace: bool,
    ) -> rusqlite::Result<usize> {
        let columns = table_columns(spec);
        let placeholders = (1..=columns.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let verb = if replace {
            "INSERT OR REPLACE"
        } else {
            "INSERT"
        };
        let sql = format!(
            "{verb} INTO \"{}\" ({}) VALUES ({placeholders})",
            spec.table,
            quoted_columns(&columns)
        );
        connection.execute(
            &sql,
            params_from_iter(
                columns
                    .iter()
                    .map(|column| values.get(column).expect("column value")),
            ),
        )
    }

    fn row_values(spec: GuardSpec, prefix: &str) -> BTreeMap<&'static str, Option<String>> {
        table_columns(spec)
            .into_iter()
            .map(|column| (column, Some(format!("{prefix}:{}:{column}", spec.table))))
            .collect()
    }

    fn insert_dependent_child(
        connection: &Connection,
        spec: GuardSpec,
        baseline: &BTreeMap<&'static str, Option<String>>,
        child_id: &str,
    ) {
        let parent_columns = spec.unique_sets[0];
        let mut values = vec![child_id.to_owned()];
        values.extend(parent_columns.iter().map(|column| {
            baseline
                .get(column)
                .and_then(Option::as_ref)
                .expect("primary-key baseline value")
                .clone()
        }));
        connection
            .execute(
                &format!(
                    "INSERT INTO \"{}_v33_test_children\" (child_id, {}) VALUES ({})",
                    spec.table,
                    quoted_columns(parent_columns),
                    (1..=values.len())
                        .map(|index| format!("?{index}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                params_from_iter(values.iter()),
            )
            .expect("insert exact dependent child");
    }

    fn schema_table_names(connection: &Connection, glob: &str) -> BTreeSet<String> {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name GLOB ?1
                 ORDER BY name",
            )
            .expect("prepare schema table inventory");
        statement
            .query_map([glob], |row| row.get(0))
            .expect("query schema table inventory")
            .collect::<Result<_, _>>()
            .expect("collect schema table inventory")
    }

    fn actual_unique_sets(connection: &Connection, table: &str) -> Vec<Vec<String>> {
        let mut list = connection
            .prepare(&format!("PRAGMA index_list(\"{table}\")"))
            .expect("prepare index inventory");
        let indexes = list
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
            })
            .expect("query index inventory")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect index inventory");
        let mut sets = indexes
            .into_iter()
            .filter(|(_, unique)| *unique == 1)
            .map(|(index, _)| {
                let mut info = connection
                    .prepare(&format!("PRAGMA index_info(\"{index}\")"))
                    .expect("prepare unique index columns");
                info.query_map([], |row| row.get::<_, String>(2))
                    .expect("query unique index columns")
                    .collect::<Result<Vec<_>, _>>()
                    .expect("collect unique index columns")
            })
            .collect::<Vec<_>>();
        sets.sort();
        sets
    }

    fn expected_unique_sets(spec: GuardSpec) -> Vec<Vec<String>> {
        let mut sets = spec
            .unique_sets
            .iter()
            .map(|set| set.iter().map(|column| (*column).to_owned()).collect())
            .collect::<Vec<Vec<String>>>();
        sets.sort();
        sets
    }

    #[test]
    fn migration_is_additive_before_insert_triggers_only() {
        assert_eq!(
            MIGRATION_V33.matches("CREATE TRIGGER ").count(),
            GUARDS.len()
        );
        assert_eq!(
            MIGRATION_V33.matches("BEFORE INSERT ON ").count(),
            GUARDS.len()
        );
        for line in MIGRATION_V33.lines().map(str::trim) {
            assert!(
                ![
                    "CREATE TABLE ",
                    "CREATE VIEW ",
                    "CREATE INDEX ",
                    "CREATE UNIQUE INDEX ",
                    "ALTER TABLE ",
                    "DROP ",
                    "INSERT INTO ",
                    "UPDATE ",
                    "DELETE FROM ",
                    "PRAGMA ",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix)),
                "v33 migration contains a non-additive statement: {line}"
            );
        }
    }

    #[test]
    fn every_v32_current_unique_set_has_a_direct_replace_guard() {
        assert_eq!(GUARDS.len(), 22);
        assert_eq!(
            GUARDS
                .iter()
                .map(|spec| spec.unique_sets.len())
                .sum::<usize>(),
            70
        );
        let connection = create_guard_fixture();
        for spec in GUARDS {
            for (set_index, unique_set) in spec.unique_sets.iter().enumerate() {
                connection
                    .execute(&format!("DELETE FROM \"{}\"", spec.table), [])
                    .expect("reset collision table");
                let baseline = row_values(*spec, "baseline");
                insert_values(&connection, *spec, &baseline, false).expect("insert baseline row");
                let mut candidate = row_values(*spec, &format!("candidate-{set_index}"));
                for column in *unique_set {
                    candidate.insert(
                        column,
                        baseline.get(column).expect("baseline column").clone(),
                    );
                }
                let error = insert_values(&connection, *spec, &candidate, true)
                    .expect_err("v33 guard must reject replacement before conflict resolution");
                let childless_message = error.to_string();
                assert!(
                    childless_message.contains("identity already exists"),
                    "{} unique set {:?} failed through the wrong boundary: {error}",
                    spec.table,
                    unique_set
                );
                insert_dependent_child(
                    &connection,
                    *spec,
                    &baseline,
                    &format!("child-{set_index}"),
                );
                let child_error = insert_values(&connection, *spec, &candidate, true)
                    .expect_err("dependent child must not change the v33 guard boundary");
                assert_eq!(
                    child_error.to_string(),
                    childless_message,
                    "{} unique set {:?} crossed into a child-FK error",
                    spec.table,
                    unique_set
                );
                let row_count: i64 = connection
                    .query_row(
                        &format!("SELECT COUNT(*) FROM \"{}\"", spec.table),
                        [],
                        |row| row.get(0),
                    )
                    .expect("count retained baseline");
                assert_eq!(row_count, 1, "{} replacement changed row count", spec.table);
                connection
                    .execute(
                        &format!("DELETE FROM \"{}_v33_test_children\"", spec.table),
                        [],
                    )
                    .expect("remove dependent child before reset");
            }
        }
    }

    #[test]
    fn nullable_unique_members_preserve_sqlite_null_semantics() {
        let connection = create_guard_fixture();
        for (table, shared, nullable) in [
            (
                "current_task_nodes_v32",
                &["sprint_id"][..],
                "repair_slot_ordinal",
            ),
            (
                "current_task_done_members_v32",
                &["set_digest"][..],
                "empty_change_set_id",
            ),
        ] {
            let spec = *GUARDS
                .iter()
                .find(|spec| spec.table == table)
                .expect("nullable guard spec");
            let mut baseline = row_values(spec, "nullable-baseline");
            baseline.insert(nullable, None);
            insert_values(&connection, spec, &baseline, false).expect("insert nullable baseline");
            let mut candidate = row_values(spec, "nullable-candidate");
            for column in shared {
                candidate.insert(column, baseline.get(column).expect("shared column").clone());
            }
            candidate.insert(nullable, None);
            insert_values(&connection, spec, &candidate, true)
                .expect("NULL in an alternate unique key must remain non-conflicting");
            let row_count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                    row.get(0)
                })
                .expect("count nullable rows");
            assert_eq!(row_count, 2);
        }

        assert_eq!(
            MIGRATION_V33
                .matches("NEW.repair_slot_ordinal IS NOT NULL")
                .count(),
            1,
            "the nullable repair-slot unique declaration needs one explicit NULL guard"
        );
        assert_eq!(
            MIGRATION_V33
                .matches("NEW.empty_change_set_id IS NOT NULL")
                .count(),
            2,
            "both nullable empty-change-set unique declarations need explicit NULL guards"
        );
    }

    #[test]
    fn fresh_schema_unique_inventory_and_v33_triggers_are_exact_after_readback() {
        let database = exact_database_at(33, "fresh");
        let connection = Connection::open(&database.path).expect("open fresh exact v33 ledger");
        register_schema_functions(&connection).expect("register v33 inspection functions");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read fresh schema version");
        assert_eq!(version, 33);
        validate_schema_cached(&connection, 33)
            .expect("fresh v33 schema is exact");

        let mut expected_current_tables = GUARDS
            .iter()
            .map(|spec| spec.table.to_owned())
            .collect::<BTreeSet<_>>();
        expected_current_tables.extend(
            ALREADY_GUARDED_REPAIR_TABLES
                .iter()
                .map(|table| (*table).to_owned()),
        );
        assert_eq!(
            schema_table_names(&connection, "current_*"),
            expected_current_tables,
            "a current-authority table was omitted from the v33 guard inventory"
        );
        for spec in GUARDS {
            assert_eq!(
                actual_unique_sets(&connection, spec.table),
                expected_unique_sets(*spec),
                "{} unique inventory drifted",
                spec.table
            );
            let trigger = format!("{}_no_replace_v33", spec.table);
            let installed: Option<String> = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [trigger.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .expect("query v33 trigger");
            assert!(installed.is_some(), "missing exact v33 trigger {trigger}");
        }
        for table in ALREADY_GUARDED_REPAIR_TABLES {
            let trigger = format!("{table}_no_replace");
            let installed: Option<String> = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [trigger.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .expect("query existing repair-task collision trigger");
            assert!(
                installed.is_some(),
                "current repair table lacks its pre-v33 collision trigger: {table}"
            );
        }
        assert_eq!(
            schema_table_names(&connection, "legacy_*_v32"),
            MIGRATION_ONLY_LEGACY_TABLES
                .iter()
                .map(|table| (*table).to_owned())
                .collect(),
            "the migration-only v32 legacy exemption inventory drifted"
        );
        for suffix in ["no_insert", "no_update", "no_delete"] {
            let trigger = format!("legacy_sprint_authority_exemptions_v32_{suffix}");
            let present: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger' AND name = ?1",
                    [trigger.as_str()],
                    |row| row.get(0),
                )
                .expect("query migration-only exemption guard");
            assert_eq!(
                present, 1,
                "missing migration-only exemption guard {trigger}"
            );
        }
        drop(connection);

        let reopened = Connection::open(&database.path).expect("read back exact v33 ledger");
        register_schema_functions(&reopened).expect("register reopened v33 functions");
        validate_schema_cached(&reopened, 33)
            .expect("reopened v33 schema is exact");
    }

    #[test]
    fn exact_v32_image_migrates_to_v33_by_adding_only_collision_triggers() {
        let database = exact_database_at(32, "migration");
        let before = Connection::open(&database.path).expect("inspect exact v32 image");
        register_schema_functions(&before).expect("register inspection functions");
        let before_objects = load_schema_objects(&before).expect("capture exact v32 objects");
        drop(before);

        let migrated = Connection::open(&database.path).expect("open exact v32 image for v33");
        register_schema_functions(&migrated).expect("register v33 migration functions");
        validate_schema_cached(&migrated, 32).expect("exact v32 source image");
        migrated
            .execute_batch(MIGRATIONS[32])
            .expect("migrate exact v32 image to v33");
        migrated
            .pragma_update(None, "user_version", 33_i64)
            .expect("advance migrated schema version");
        let version: i64 = migrated
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read migrated version");
        assert_eq!(version, 33);
        validate_schema_cached(&migrated, 33)
            .expect("migrated v33 schema is exact");
        let after_objects = load_schema_objects(&migrated).expect("capture v33 objects");
        let added = after_objects
            .iter()
            .filter(|object| !before_objects.contains(object))
            .collect::<Vec<_>>();
        assert_eq!(added.len(), GUARDS.len());
        assert!(added.iter().all(|object| {
            object.object_type == "trigger" && object.name.ends_with("_no_replace_v33")
        }));
        assert!(
            before_objects
                .iter()
                .all(|object| after_objects.contains(object))
        );
    }

    #[test]
    fn divergent_v32_image_is_rejected_before_any_v33_trigger_is_installed() {
        let database = exact_database_at(32, "divergent-migration");
        let divergent = Connection::open(&database.path).expect("open exact v32 for divergence");
        divergent
            .execute_batch("CREATE TABLE unexpected_v32_object (id TEXT PRIMARY KEY) STRICT;")
            .expect("inject one unexpected v32 schema object");
        drop(divergent);

        let Err(error) = EventLedger::open(&database.path) else {
            panic!("divergent v32 source image must fail before v33");
        };
        assert!(matches!(
            error,
            LedgerError::Corrupt {
                entity: "ledger schema migration source",
                ref detail,
            } if detail.contains("exact version 32 source image")
        ));

        let unchanged = Connection::open(&database.path).expect("reinspect rejected v32 image");
        let version: i64 = unchanged
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read rejected source version");
        assert_eq!(version, 32);
        let installed: i64 = unchanged
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'trigger' AND name GLOB '*_no_replace_v33'",
                [],
                |row| row.get(0),
            )
            .expect("count prematurely installed v33 triggers");
        assert_eq!(installed, 0);
    }
}
