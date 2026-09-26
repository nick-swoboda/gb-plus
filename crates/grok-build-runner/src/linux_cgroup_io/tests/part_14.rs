    // What a live canary suite reports, and what the journal will keep of it.
    //
    // The boundary these tests drive is the one the adoption increment added:
    // a suite runs inside a leaf the probe journal created and reports plain
    // data back, and `canary_evidence_from_suite_report` decides what of that
    // report is admissible as durable evidence. Everything asserted here is
    // decided on the journal's side of that boundary, which is the point, a
    // suite that could write its own record could name its own capability.

    /// One suite report, as a live suite would hand it back.
    fn suite_report(
        probe_runs: u32,
        outcomes: Vec<(&str, bool, &str)>,
        probe_name: &str,
    ) -> CanarySuiteOutcome {
        CanarySuiteOutcome {
            probe_runs,
            outcomes: outcomes
                .into_iter()
                .map(|(control, proven, witness)| CanarySuiteControlOutcome {
                    control: control.to_owned(),
                    probe: probe_name.to_owned(),
                    proven,
                    witness_digest: sha256_hex(witness.as_bytes()),
                })
                .collect(),
        }
    }

    fn canary_leaf_identity() -> CgroupObjectIdentity {
        CgroupObjectIdentity {
            device: 0x00fe_0001,
            inode: 987_654,
        }
    }

    /// A suite's report is data, and only the journal's rules make it evidence.
    ///
    /// Each arm varies exactly one thing about what the suite reported and
    /// asserts the journal refuses it, so no arm can pass by accident of a
    /// second defect. The admitted arm is asserted positively too: the digest
    /// is the canonical digest of the outcomes beside it, the outcome order is
    /// the record's own bytewise order regardless of the order the suite
    /// reported in, and `proven_control_names` is exactly the proven set.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "each refusal arm varies exactly one thing about the same report and stays next to the rule it is driving"
    )]
    fn a_live_suites_report_becomes_evidence_only_through_the_journals_own_rules() {
        let identity = canary_leaf_identity();
        let probe = format!(".gb-probe-{}", "a".repeat(32));

        // ---- admitted: a report the journal keeps ---------------------------
        //
        // Reported deliberately out of order, so the canonicalization is
        // observed rather than assumed.
        let admitted = canary_evidence_from_suite_report(
            identity,
            suite_report(
                3,
                vec![
                    ("DescendantLimit", true, "fork-refused-eagain"),
                    ("ActiveCanaries", true, "every-frame-of-this-suite"),
                    ("MemoryLimit", false, "not-proven-here"),
                ],
                &probe,
            ),
        )
        .expect("a report inside every rule is admissible evidence");
        assert_eq!(admitted.generation, CANARY_EPISODE_GENERATION);
        assert_eq!(admitted.root_identity, identity);
        assert_eq!(admitted.probe_runs, 3);
        assert_eq!(
            admitted
                .outcomes
                .iter()
                .map(|outcome| outcome.control.as_str())
                .collect::<Vec<_>>(),
            vec!["ActiveCanaries", "DescendantLimit", "MemoryLimit"],
            "the record's outcomes are bytewise sorted whatever order the suite reported"
        );
        assert_eq!(
            admitted.suite_result_digest,
            admitted.canonical_digest(),
            "the suite digest must be the digest of the outcomes beside it"
        );
        assert_eq!(
            admitted.proven_control_names(),
            ["ActiveCanaries".to_owned(), "DescendantLimit".to_owned()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            "an unproven outcome is journaled and is not a proven control"
        );
        // The evidence is admissible only against the leaf it was measured in.
        assert!(
            admitted
                .validate(Some(CgroupObjectIdentity {
                    device: identity.device,
                    inode: identity.inode + 1,
                }))
                .is_err(),
            "evidence must not validate against a leaf this episode never observed"
        );

        // ---- refused: a control outside the closed compiled vocabulary ------
        let invented = canary_evidence_from_suite_report(
            identity,
            suite_report(1, vec![("RemoteAttestation", true, "invented")], &probe),
        )
        .expect_err("a suite may not name a control the vocabulary does not contain");
        assert!(
            invented.detail.contains("closed compiled vocabulary"),
            "the refusal must name the vocabulary: {}",
            invented.detail
        );

        // ---- refused: proven with the witness an absent probe leaves --------
        let absent_witness = canary_evidence_from_suite_report(
            identity,
            CanarySuiteOutcome {
                probe_runs: 1,
                outcomes: vec![CanarySuiteControlOutcome {
                    control: "DescendantLimit".to_owned(),
                    probe: probe.clone(),
                    proven: true,
                    witness_digest: "0".repeat(64),
                }],
            },
        )
        .expect_err("a control cannot be proven by a probe that left no witness");
        assert!(
            absent_witness.detail.contains("absent witness"),
            "the refusal must name the absent witness: {}",
            absent_witness.detail
        );

        // ---- refused: one control reported twice ---------------------------
        //
        // Sorting cannot make two equal names distinct, which is exactly why
        // canonicalizing before validating admits nothing.
        let duplicated = canary_evidence_from_suite_report(
            identity,
            suite_report(
                2,
                vec![
                    ("DescendantLimit", true, "first"),
                    ("DescendantLimit", true, "second"),
                ],
                &probe,
            ),
        )
        .expect_err("a suite may not report one control twice");
        assert!(
            duplicated.detail.contains("unique and bytewise sorted"),
            "the refusal must name the uniqueness rule: {}",
            duplicated.detail
        );

        // ---- refused: ActiveCanaries with fewer runs than outcomes ----------
        let understated = canary_evidence_from_suite_report(
            identity,
            suite_report(
                1,
                vec![
                    ("ActiveCanaries", true, "suite-frames"),
                    ("DescendantLimit", true, "fork-refused-eagain"),
                    ("MemoryLimit", true, "oom-killed"),
                ],
                &probe,
            ),
        )
        .expect_err("the suite control cannot be proven by fewer runs than outcomes");
        assert!(
            understated.detail.contains("fewer runs than outcomes"),
            "the refusal must name the run-count rule: {}",
            understated.detail
        );

        // ---- refused: a probe name the journal would never have created -----
        let foreign_probe = canary_evidence_from_suite_report(
            identity,
            suite_report(
                1,
                vec![("DescendantLimit", true, "fork-refused-eagain")],
                "gbd-canary-4711-0",
            ),
        )
        .expect_err("a suite-minted leaf name is not a journaled probe name");
        assert_eq!(
            foreign_probe.operation, "validate-probe-name",
            "the refusal must come from the probe-name rule: {foreign_probe:?}"
        );
    }
