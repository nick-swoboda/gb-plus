    // The production source for `LinuxTargetLinkageV1`, proved control versus
    // enforced.
    //
    // The split below is deliberate and is the same one the setup-channel mint
    // uses. The **live half** (`cfg(target_os = "linux")`) measures only real
    // files: a real static ELF, a real dynamic ELF, a real relocatable object,
    // a real non-ELF file, and real truncations of a real binary — every one of
    // them read through a descriptor the test holds open. The **portable half**
    // assembles headers, because no Linux ELF exists on a macOS host and
    // because the geometries it varies (a wrong `e_phentsize`, the `PN_XNUM`
    // escape, a table declared past the end) are ones no real toolchain emits.

    /// The architecture this build targets, which every image below is
    /// measured against.
    fn host_architecture() -> LinuxMachineArchitectureV1 {
        LinuxMachineArchitectureV1::compiled_target()
            .expect("this build targets an architecture the Linux plan schema describes")
    }

    /// The other architecture the schema describes, for the cross-machine arm.
    fn other_architecture() -> LinuxMachineArchitectureV1 {
        match host_architecture() {
            LinuxMachineArchitectureV1::X86_64 => LinuxMachineArchitectureV1::Aarch64,
            LinuxMachineArchitectureV1::Aarch64 => LinuxMachineArchitectureV1::X86_64,
        }
    }

    /// The `e_machine` value denoting one architecture.
    fn elf_machine_of(architecture: LinuxMachineArchitectureV1) -> u16 {
        match architecture {
            LinuxMachineArchitectureV1::X86_64 => ELF_MACHINE_X86_64,
            LinuxMachineArchitectureV1::Aarch64 => ELF_MACHINE_AARCH64,
        }
    }

    /// `p_type` of the program header table's own segment.
    const ELF_SEGMENT_PROGRAM_HEADERS: u32 = 6;
    /// `p_type` of a note segment.
    const ELF_SEGMENT_NOTE: u32 = 4;
    /// `e_type` for a relocatable object, which carries no program headers.
    const ELF_TYPE_RELOCATABLE: u16 = 1;

    /// One assembled ELF64 image, varied one field at a time.
    #[derive(Clone, Debug)]
    struct ElfImage {
        machine: u16,
        elf_type: u16,
        entry_size: u16,
        declared_count: u16,
        table_offset: u64,
        segments: Vec<u32>,
        truncate_to: Option<usize>,
    }

    impl ElfImage {
        /// The control: a well-formed 64-bit little-endian static executable
        /// for this host, four program headers, none of them `PT_INTERP` or
        /// `PT_DYNAMIC`.
        fn control() -> Self {
            Self {
                machine: elf_machine_of(host_architecture()),
                elf_type: ELF_TYPE_EXECUTABLE,
                entry_size: ELF64_PROGRAM_HEADER_ENTRY_BYTES,
                declared_count: 4,
                table_offset: ELF64_HEADER_BYTE_COUNT,
                segments: vec![
                    ELF_SEGMENT_PROGRAM_HEADERS,
                    ELF_SEGMENT_LOADABLE,
                    ELF_SEGMENT_LOADABLE,
                    ELF_SEGMENT_NOTE,
                ],
                truncate_to: None,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let stride = usize::from(self.entry_size).max(1);
            let table_start =
                usize::try_from(self.table_offset).expect("table offset fits this host");
            let span = usize::from(self.declared_count) * stride;
            let mut image = vec![0_u8; table_start.saturating_add(span).max(ELF64_HEADER_BYTES)];

            image[..4].copy_from_slice(&ELF_IDENTIFICATION_MAGIC);
            image[4] = ELF_CLASS_64;
            image[5] = ELF_DATA_LITTLE_ENDIAN;
            image[6] = 1;
            image[ELF64_TYPE_OFFSET..ELF64_TYPE_OFFSET + 2]
                .copy_from_slice(&self.elf_type.to_le_bytes());
            image[ELF64_MACHINE_OFFSET..ELF64_MACHINE_OFFSET + 2]
                .copy_from_slice(&self.machine.to_le_bytes());
            image[ELF64_PROGRAM_HEADER_TABLE_OFFSET..ELF64_PROGRAM_HEADER_TABLE_OFFSET + 8]
                .copy_from_slice(&self.table_offset.to_le_bytes());
            image[ELF64_PROGRAM_HEADER_ENTRY_SIZE_OFFSET..ELF64_PROGRAM_HEADER_ENTRY_SIZE_OFFSET + 2]
                .copy_from_slice(&self.entry_size.to_le_bytes());
            image[ELF64_PROGRAM_HEADER_COUNT_OFFSET..ELF64_PROGRAM_HEADER_COUNT_OFFSET + 2]
                .copy_from_slice(&self.declared_count.to_le_bytes());

            for (index, segment) in self.segments.iter().enumerate() {
                let start = table_start + index * stride;
                if start + 4 <= image.len() {
                    image[start..start + 4].copy_from_slice(&segment.to_le_bytes());
                }
            }
            if let Some(length) = self.truncate_to {
                image.truncate(length);
            }
            image
        }
    }

    /// Measures one assembled image the way a caller holding a complete
    /// readback would.
    fn measure_bytes(
        image: &ElfImage,
    ) -> Result<LinuxMeasuredTargetImageV1, LinuxProductionCommandPlanError> {
        let bytes = image.bytes();
        let length = u64::try_from(bytes.len()).expect("assembled image length fits u64");
        LinuxMeasuredTargetImageV1::measure(
            bytes.as_slice(),
            length,
            host_architecture(),
            "the target executable",
        )
    }

    #[test]
    fn the_target_linkage_prover_refuses_every_image_it_cannot_walk() {
        // Control first.
        let control = measure_bytes(&ElfImage::control()).expect("the control image measures");
        assert_eq!(control.linkage(), &LinuxTargetLinkageV1::StaticElf);
        assert_eq!(
            control.image_format(),
            host_architecture().elf_image_format()
        );
        assert_eq!(control.program_header_count(), 4);
        assert_eq!(control.loadable_segment_count(), 2);

        // Each row varies exactly one thing about the control, and names the
        // fragment of the refusal that must be attributable to it.
        let mut interpreted = ElfImage::control();
        interpreted.segments[3] = ELF_SEGMENT_INTERPRETER;
        let mut dynamic = ElfImage::control();
        dynamic.segments[3] = ELF_SEGMENT_DYNAMIC;
        let mut both = ElfImage::control();
        both.segments[0] = ELF_SEGMENT_INTERPRETER;
        both.segments[3] = ELF_SEGMENT_DYNAMIC;
        let mut no_load = ElfImage::control();
        no_load.segments = vec![
            ELF_SEGMENT_PROGRAM_HEADERS,
            ELF_SEGMENT_NOTE,
            ELF_SEGMENT_NOTE,
            ELF_SEGMENT_NOTE,
        ];
        let mut foreign = ElfImage::control();
        foreign.machine = elf_machine_of(other_architecture());
        let mut undescribable = ElfImage::control();
        undescribable.machine = 0x0028;
        let mut relocatable = ElfImage::control();
        relocatable.elf_type = ELF_TYPE_RELOCATABLE;
        let mut no_headers = ElfImage::control();
        no_headers.declared_count = 0;
        let mut escaped = ElfImage::control();
        escaped.declared_count = ELF_PROGRAM_HEADER_COUNT_ESCAPE;
        let mut over_bound = ElfImage::control();
        over_bound.declared_count = MAX_LINUX_TARGET_PROGRAM_HEADERS + 1;
        let mut wrong_stride = ElfImage::control();
        wrong_stride.entry_size = 32;
        let mut inside_header = ElfImage::control();
        inside_header.table_offset = 32;
        let mut past_end = ElfImage::control();
        past_end.truncate_to = Some(ELF64_HEADER_BYTES + 8);
        let mut short_of_header = ElfImage::control();
        short_of_header.truncate_to = Some(40);
        let mut not_elf_bytes = ElfImage::control().bytes();
        not_elf_bytes[1] = b'X';
        let mut not_64_bit_bytes = ElfImage::control().bytes();
        not_64_bit_bytes[4] = 1;

        let refusals: Vec<(&str, String)> = vec![
            ("one PT_INTERP", refusal(&interpreted)),
            ("one PT_DYNAMIC", refusal(&dynamic)),
            ("both", refusal(&both)),
            ("no PT_LOAD", refusal(&no_load)),
            ("a foreign machine", refusal(&foreign)),
            ("an undescribable machine", refusal(&undescribable)),
            ("a relocatable object", refusal(&relocatable)),
            ("zero program headers", refusal(&no_headers)),
            ("the PN_XNUM escape", refusal(&escaped)),
            ("a count past the bound", refusal(&over_bound)),
            ("a wrong stride", refusal(&wrong_stride)),
            ("a table inside the header", refusal(&inside_header)),
            ("a table past the end", refusal(&past_end)),
            ("an image short of the header", refusal(&short_of_header)),
            ("not an ELF object", refusal_of(&not_elf_bytes)),
            ("not a 64-bit object", refusal_of(&not_64_bit_bytes)),
        ];

        let expected = [
            "1 PT_INTERP and 0 PT_DYNAMIC",
            "0 PT_INTERP and 1 PT_DYNAMIC",
            "1 PT_INTERP and 1 PT_DYNAMIC",
            "found no PT_LOAD segment",
            "this host is",
            "is not an architecture this plan schema can describe",
            "carries no loadable program image",
            "carries no program headers, so the absence of PT_INTERP",
            "PN_XNUM",
            "past this plan's bound",
            "program header stride is 32 bytes",
            "inside its own ELF64 header",
            "program header table spans bytes",
            "shorter than the 64-byte ELF64 header",
            "does not begin with the ELF identification magic",
            "is not a 64-bit little-endian ELF object",
        ];
        for ((label, message), fragment) in refusals.iter().zip(expected) {
            assert!(
                message.contains(fragment),
                "varying {label} must be refused by name: expected {fragment:?} in {message:?}"
            );
        }
        // Every refusal is distinct, so no two of these arms are being served
        // by one catch-all.
        let distinct: BTreeSet<&str> = refusals.iter().map(|(_, message)| message.as_str()).collect();
        assert_eq!(distinct.len(), refusals.len(), "refusals must not collapse");

        // Control again, so every refusal above is attributable to the value
        // that was varied rather than to drift in the fixture.
        assert_eq!(
            measure_bytes(&ElfImage::control()).expect("the control still measures"),
            control
        );
    }

    /// The refusal text one varied image produces, or a panic if it admitted.
    fn refusal(image: &ElfImage) -> String {
        match measure_bytes(image) {
            Ok(measured) => panic!("this image must be refused, and it measured {measured:?}"),
            Err(error) => error.to_string(),
        }
    }

    /// The refusal text one explicit byte string produces.
    fn refusal_of(bytes: &[u8]) -> String {
        let length = u64::try_from(bytes.len()).expect("image length fits u64");
        match LinuxMeasuredTargetImageV1::measure(
            bytes,
            length,
            host_architecture(),
            "the target executable",
        ) {
            Ok(measured) => panic!("this image must be refused, and it measured {measured:?}"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn the_target_linkage_prover_answers_the_same_through_a_held_descriptor() {
        use std::io::Write as _;

        let root = std::env::temp_dir().join(format!(
            "grok-build-linkage-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create the linkage fixture root");

        let control = ElfImage::control().bytes();
        let path = root.join("control-image");
        let mut file = std::fs::File::create(&path).expect("write the control image");
        file.write_all(&control).expect("write the control image");
        drop(file);

        let length = u64::try_from(control.len()).expect("control length fits u64");
        let held = std::fs::File::open(&path).expect("hold the control image open");
        let through_descriptor = LinuxMeasuredTargetImageV1::measure(
            &held,
            length,
            host_architecture(),
            "the target executable",
        )
        .expect("the control image measures through a held descriptor");
        let through_bytes = LinuxMeasuredTargetImageV1::measure(
            control.as_slice(),
            length,
            host_architecture(),
            "the target executable",
        )
        .expect("the control image measures out of a complete readback");
        // One walk, two byte sources, one answer.
        assert_eq!(through_descriptor, through_bytes);
        assert_eq!(through_descriptor.linkage(), &LinuxTargetLinkageV1::StaticElf);

        // An image that shrank under the length it was authenticated at is a
        // refusal from the descriptor itself, not a short answer the walk then
        // reads as an absence of PT_INTERP.
        let shrunk = root.join("shrunk-image");
        std::fs::write(&shrunk, &control[..ELF64_HEADER_BYTES + 16]).expect("write a shrunk image");
        let held_shrunk = std::fs::File::open(&shrunk).expect("hold the shrunk image open");
        let error = LinuxMeasuredTargetImageV1::measure(
            &held_shrunk,
            length,
            host_architecture(),
            "the target executable",
        )
        .expect_err("an image shorter than its authenticated length must be refused");
        assert!(
            error.to_string().contains("is truncated"),
            "the descriptor's own short read must be named: {error}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_measured_target_image_produces_the_plan_target_slot() {
        let measured = measure_bytes(&ElfImage::control()).expect("the control image measures");
        let executable = LinuxAuthenticatedFileV1::from_complete_readback(
            "target-image",
            "/opt/grok-build/target",
            measured.byte_length(),
            digest(7),
        )
        .expect("authenticate the target readback");

        let image = LinuxProgramImageV1::from_measured_image(
            "/opt/grok-build/target",
            executable.clone(),
            &measured,
        )
        .expect("the measured image produces the plan's target slot");
        assert_eq!(image.linkage, LinuxTargetLinkageV1::StaticElf);
        assert_eq!(image.image_format, host_architecture().elf_image_format());
        assert_eq!(image.requested_program, "/opt/grok-build/target");

        // An empty requested program is outside the bound `validate_binaries`
        // applies, so it cannot be minted here either.
        assert!(
            LinuxProgramImageV1::from_measured_image("", executable.clone(), &measured)
                .expect_err("an empty requested program is refused")
                .to_string()
                .contains("outside Linux plan bounds")
        );

        // A readback of one image cannot be paired with another image's
        // program headers.
        let other = LinuxAuthenticatedFileV1::from_complete_readback(
            "target-image",
            "/opt/grok-build/target",
            measured.byte_length() + 1,
            digest(8),
        )
        .expect("authenticate a different readback");
        assert!(
            LinuxProgramImageV1::from_measured_image("/opt/grok-build/target", other, &measured)
                .expect_err("a mismatched readback is refused")
                .to_string()
                .contains("measured image is")
        );
    }

    /// The checked-in source the live half builds its real binaries from.
    #[cfg(target_os = "linux")]
    fn baseline_source() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("walking-skeleton-baseline")
            .join("baseline_exit.rs")
            .canonicalize()
            .expect("canonicalize the walking-skeleton baseline command source")
    }

    /// Compiles the fixture source with `rustc` and returns the artefact path.
    #[cfg(target_os = "linux")]
    fn build_real_image(root: &Path, name: &str, extra: &[&str]) -> PathBuf {
        let artefact = root.join(name);
        let mut rustc = std::process::Command::new("rustc");
        rustc
            .arg("--edition")
            .arg("2021")
            .arg("--crate-name")
            .arg("linkage_probe");
        for argument in extra {
            rustc.arg(argument);
        }
        let output = rustc
            .arg("-o")
            .arg(&artefact)
            .arg(baseline_source())
            .output()
            .expect("run rustc to build a real image for the linkage prover");
        assert!(
            output.status.success(),
            "building {name} must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        artefact
    }

    /// Measures one real file through a descriptor this function holds open,
    /// using the file's own `fstat` length unless one is supplied.
    #[cfg(target_os = "linux")]
    fn measure_real_file(
        path: &Path,
        authenticated_byte_length: Option<u64>,
    ) -> Result<LinuxMeasuredTargetImageV1, LinuxProductionCommandPlanError> {
        let held = std::fs::File::open(path)
            .unwrap_or_else(|error| panic!("hold {} open: {error}", path.display()));
        let length = authenticated_byte_length.unwrap_or_else(|| {
            held.metadata()
                .expect("stat the held descriptor")
                .len()
        });
        LinuxMeasuredTargetImageV1::measure(
            &held,
            length,
            host_architecture(),
            "the target executable",
        )
    }

    /// The linkage prover against real binaries, read through held descriptors.
    ///
    /// Every input here is a real file: a real static ELF and a real dynamic
    /// ELF built by `rustc` from the checked-in fixture, a real relocatable
    /// object, this test binary itself, the fixture's own Rust source as a
    /// non-ELF file, and real truncations of the real static ELF. The only
    /// derived inputs are the two cross-machine copies, because the pinned
    /// image carries no cross toolchain and no foreign-architecture binary —
    /// they are the real static ELF with its two `e_machine` bytes rewritten,
    /// and nothing else about them differs.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the real-binary control and every enforced arm are kept adjacent so the one varied input per arm is visible"
    )]
    fn the_target_linkage_prover_measures_real_binaries_through_held_descriptors() {
        let root = std::env::temp_dir().join(format!(
            "grok-build-linkage-real-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create the real-image fixture root");

        // ---- control: a genuinely static ELF ----------------------------
        let static_elf = build_real_image(
            &root,
            "static-image",
            &[
                "-O",
                "-C",
                "target-feature=+crt-static",
                "-C",
                "relocation-model=static",
            ],
        );
        let measured = measure_real_file(&static_elf, None)
            .expect("a real static ELF must measure as StaticElf");
        assert_eq!(measured.linkage(), &LinuxTargetLinkageV1::StaticElf);
        assert_eq!(
            measured.image_format(),
            host_architecture().elf_image_format()
        );
        assert!(
            measured.program_header_count() > 0 && measured.loadable_segment_count() > 0,
            "the static answer must come from a table that was really walked: {measured:?}"
        );

        // ---- enforced: a real dynamic ELF, same source, one rustc flag ---
        let dynamic_elf = build_real_image(&root, "dynamic-image", &["-O"]);
        let dynamic_refusal = measure_real_file(&dynamic_elf, None)
            .expect_err("a real dynamic ELF must be refused")
            .to_string();
        assert!(
            dynamic_refusal.contains("is dynamically linked")
                && dynamic_refusal.contains("PT_INTERP")
                && dynamic_refusal.contains("PT_DYNAMIC"),
            "the dynamic refusal must name the headers that caused it: {dynamic_refusal}"
        );
        assert!(
            dynamic_refusal.contains("runtime-object closure"),
            "the dynamic refusal must say what a dynamic linkage would additionally require: {dynamic_refusal}"
        );

        // ---- enforced: this very test binary, also a real dynamic ELF ----
        let own_image =
            std::fs::canonicalize("/proc/self/exe").expect("resolve this test binary's own path");
        assert!(
            measure_real_file(&own_image, None)
                .expect_err("this test binary is dynamically linked and must be refused")
                .to_string()
                .contains("is dynamically linked"),
            "the runner's own test binary must be refused for the same measured reason"
        );

        // ---- enforced: a real relocatable object -------------------------
        // This is the arm that distinguishes measuring from assuming. An ELF
        // relocatable object has *no* program header table, so a walk that
        // treated "no PT_INTERP found" as evidence would call it static.
        let relocatable = build_real_image(&root, "relocatable-image.o", &["--emit=obj"]);
        assert!(
            measure_real_file(&relocatable, None)
                .expect_err("a relocatable object must be refused, never read as static")
                .to_string()
                .contains("carries no loadable program image"),
            "a relocatable object must be refused for carrying no loadable image"
        );

        // ---- enforced: a real non-ELF file -------------------------------
        assert!(
            measure_real_file(&baseline_source(), None)
                .expect_err("the fixture's Rust source is not an ELF object")
                .to_string()
                .contains("does not begin with the ELF identification magic"),
            "a real non-ELF file must be refused by name"
        );

        // ---- enforced: real truncations of the real static ELF -----------
        let real_bytes = std::fs::read(&static_elf).expect("read the real static ELF back");
        let real_length = u64::try_from(real_bytes.len()).expect("real image length fits u64");

        let stub = root.join("truncated-below-header");
        std::fs::write(&stub, &real_bytes[..40]).expect("write a 40-byte truncation");
        assert!(
            measure_real_file(&stub, None)
                .expect_err("40 bytes cannot hold an ELF64 header")
                .to_string()
                .contains("shorter than the 64-byte ELF64 header"),
            "a truncation below the ELF header must be refused before any read"
        );

        let clipped = root.join("truncated-inside-table");
        std::fs::write(&clipped, &real_bytes[..ELF64_HEADER_BYTES + 8])
            .expect("write a truncation inside the program header table");
        assert!(
            measure_real_file(&clipped, None)
                .expect_err("a table declared past the end must be refused")
                .to_string()
                .contains("program header table spans bytes"),
            "a table extending past the authenticated length must be refused by name"
        );

        // The same truncation measured at the *original* authenticated length:
        // the refusal now comes from the descriptor's own short read, which is
        // the case where an image shrank after it was authenticated.
        assert!(
            measure_real_file(&clipped, Some(real_length))
                .expect_err("an image that shrank after authentication must be refused")
                .to_string()
                .contains("is truncated"),
            "a descriptor that cannot supply the authenticated bytes must refuse"
        );

        // ---- enforced: cross-machine copies of the real static ELF -------
        let mut foreign = real_bytes.clone();
        foreign[ELF64_MACHINE_OFFSET..ELF64_MACHINE_OFFSET + 2]
            .copy_from_slice(&elf_machine_of(other_architecture()).to_le_bytes());
        let foreign_path = root.join("foreign-machine-image");
        std::fs::write(&foreign_path, &foreign).expect("write the cross-machine copy");
        let foreign_refusal = measure_real_file(&foreign_path, None)
            .expect_err("a target built for another machine must be refused")
            .to_string();
        assert!(
            foreign_refusal.contains(other_architecture().as_str())
                && foreign_refusal.contains(host_architecture().as_str()),
            "the cross-machine refusal must name both machines: {foreign_refusal}"
        );

        let mut undescribable = real_bytes.clone();
        undescribable[ELF64_MACHINE_OFFSET..ELF64_MACHINE_OFFSET + 2]
            .copy_from_slice(&0x0028_u16.to_le_bytes());
        let undescribable_path = root.join("undescribable-machine-image");
        std::fs::write(&undescribable_path, &undescribable)
            .expect("write the undescribable-machine copy");
        assert!(
            measure_real_file(&undescribable_path, None)
                .expect_err("a machine this schema cannot describe must be refused")
                .to_string()
                .contains("is not an architecture this plan schema can describe"),
            "an undescribable machine must be refused distinctly from a describable foreign one"
        );

        // ---- control again ----------------------------------------------
        assert_eq!(
            measure_real_file(&static_elf, None).expect("the real static ELF still measures"),
            measured
        );

        let _ = std::fs::remove_dir_all(&root);
    }
