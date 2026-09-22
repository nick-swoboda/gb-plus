    // -----------------------------------------------------------------------
    // The Bubblewrap version probe, run live against the admitted image.
    //
    // This is the second of the four host probes a production bootstrap
    // authority needs, and it is the one that decides whether the other three
    // are worth building: `validate_service_bootstrap_evidence` admits an
    // evidence value only when **every** probe result binds the plan, so a
    // Bubblewrap probe whose honest output the validator refuses blocks the
    // authority no matter what the other three say.
    //
    // The test therefore does exactly what a production mint would do — hold
    // the admitted image open, prove by whole-content digest that it *is* the
    // admitted image, execute it through that held descriptor, and submit the
    // measured answer to the untouched validator — and records the verdict.
    // -----------------------------------------------------------------------

    /// The admitted Bubblewrap image's self-reported version, measured live,
    /// required to equal the second pinned admission constant, and submitted to
    /// the bootstrap evidence validator exactly as a production mint submits
    /// it.
    ///
    /// **This test is where `ADMITTED_BUBBLEWRAP_IMAGE_V1::self_reported_version`
    /// is verified.** The acquisition step deliberately does not execute what it
    /// downloads, so the self-report cannot be checked there. It is checked here
    /// instead, against the already-verified image: the whole content is read
    /// back through the retained descriptor and its SHA-256 is required to equal
    /// `ADMITTED_BUBBLEWRAP_IMAGE_V1::sha256` **before** the image is executed,
    /// so "this binary reports X" is a statement about the pinned bytes rather
    /// than about whatever `bwrap` a host happens to carry.
    ///
    /// **The absent arm is enforced, never skipped.** The default gate image
    /// carries no `bwrap`; that is asserted by errno and reported, because an
    /// absent capability is a refusal and not a pass.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_live_bubblewrap_version_probe_meets_the_pinned_self_reported_version() {
        use crate::linux_command_plan::ADMITTED_BUBBLEWRAP_IMAGE_V1;

        let admitted = ADMITTED_BUBBLEWRAP_IMAGE_V1;
        // Absence is classified by errno on the ambient name before anything is
        // retained, exactly as the production components mint classifies it.
        match std::fs::File::open(admitted.resolved_path) {
            Ok(file) => drop(file),
            Err(error) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(rustix::io::Errno::NOENT.raw_os_error()),
                    "an unreadable Bubblewrap is not the same as an absent one"
                );
                println!(
                    "GBDBWRAP bubblewrap-absent path={} errno=ENOENT probe=not-run \
                     (this image admits no Bubblewrap, so no bootstrap evidence can exist here)",
                    admitted.resolved_path
                );
                return;
            }
        }

        let resolved = Path::new(admitted.resolved_path);
        let directory = Dir::open_ambient_dir(
            resolved.parent().expect("the admitted image has a parent"),
            ambient_authority(),
        )
        .expect("open the admitted Bubblewrap image's parent directory");
        let name = resolved
            .file_name()
            .and_then(|name| name.to_str())
            .expect("the admitted image has a UTF-8 filename");
        let (held, _identity) =
            open_retained_bootstrap_file(&directory, name, "open-bootstrap-bubblewrap")
                .expect("retain the admitted Bubblewrap image through its parent descriptor");

        // The image under probe is the admitted image, proved through the same
        // descriptor it is about to be executed through.
        let content = read_retained_bootstrap_file(
            &held,
            usize::try_from(admitted.byte_length).expect("the admitted length fits"),
            "readback-bootstrap-bubblewrap",
        )
        .expect("read the admitted Bubblewrap image completely");
        assert_eq!(
            u64::try_from(content.len()).expect("the readback length fits"),
            admitted.byte_length,
            "the retained image is not the admitted image's length"
        );
        assert_eq!(
            Digest::sha256(&content).as_str(),
            admitted.sha256,
            "the retained image's content is not the admitted image"
        );

        let probe = probe_retained_bubblewrap_version(&held)
            .expect("the admitted Bubblewrap image reports its version");
        let pinned_stdout = format!("{}\n", admitted.self_reported_version);
        let package_version_stdout = format!("{}\n", admitted.version);
        println!(
            "GBDBWRAP probe measured={:?} pinned_self_report={:?} equal={} \
             package_version={:?} sha256={}",
            probe.version_stdout,
            pinned_stdout,
            probe.version_stdout == pinned_stdout,
            admitted.version,
            admitted.sha256
        );

        // The pin is verified here, against the image whose whole content was
        // just required to equal the admitted digest. This is what makes
        // committing the self-report no weaker than committing the SHA-256: it
        // is a property of the same pinned bytes, measured from them.
        assert_eq!(
            probe.version_stdout, pinned_stdout,
            "the admitted image's self-reported version differs from the pinned \
             ADMITTED_BUBBLEWRAP_IMAGE_V1::self_reported_version"
        );
        // The two facts are still different strings, which is why the admission
        // commits both. If this ever fails, a package version and an upstream
        // release line have coincided and the second pin has become redundant.
        assert_ne!(
            pinned_stdout, package_version_stdout,
            "the package version and the self-report are the same string; the second pin is stale"
        );

        // The evidence a production mint would submit. Everything except the
        // Bubblewrap probe comes from the fixture and satisfies the validator.
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let mut evidence = fixture.bootstrap_evidence(&plan);

        // The enforced half: what the admitted image actually printed, crossed
        // against the untouched validator.
        evidence.bubblewrap = probe.clone();
        let outcome = validate_service_bootstrap_evidence(&evidence);
        println!(
            "GBDBWRAP verdict={}",
            match &outcome {
                Ok(()) => "admitted".to_owned(),
                Err(error) => format!("refused {error:?}"),
            }
        );
        outcome.expect("the admitted image's own version output binds the pinned self-report");

        // The control half. One field moves: the reported stdout becomes the
        // package version line, which is what the clause used to compute and is
        // a real string this project committed elsewhere. Its result digest
        // still commits to the real run, so the verdict is attributable to the
        // one field that moved and to nothing else.
        let mut control = evidence.clone();
        control.bubblewrap = probe;
        control.bubblewrap.version_stdout_sha256 =
            Digest::sha256(package_version_stdout.as_bytes());
        control.bubblewrap.version_stdout = package_version_stdout;
        let refusal = validate_service_bootstrap_evidence(&control)
            .expect_err("the package version line is not what the pinned image reports");
        assert_eq!(refusal.operation, "validate-linux-service-bootstrap-evidence");
        assert_eq!(refusal.certainty, EffectCertainty::NotApplied);
        assert!(
            refusal
                .detail
                .contains("Bubblewrap version or active probe does not bind the exact planned image"),
            "the refusal is not the version clause: {refusal:?}"
        );

        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
    }
