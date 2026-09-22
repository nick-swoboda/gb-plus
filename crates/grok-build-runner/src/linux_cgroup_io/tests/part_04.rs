    // Externally anchored native-service handoff canaries.
    //
    // The handoff's only previous constructor was `from_test_descriptors`, a
    // bare field move, and its caller also chose the commitment it was compared
    // against. These tests exercise the production mint instead, and the thing
    // they are trying to establish is negative: that a process holding the
    // runner's credentials cannot produce an artifact the mint will accept.
    //
    // Two of them need an installer identity distinct from the test process, so
    // they are driven from outside: an installer pass runs as root and writes
    // the anchor, an unprivileged pass reads it. Each guards with a
    // biconditional rather than a skip, so a misconfigured environment fails
    // instead of quietly proving nothing.

    #[cfg(target_os = "linux")]
    const INSTALL_ROOT_VARIABLE: &str = "GROK_BUILD_SERVICE_INSTALL_ROOT";
    #[cfg(target_os = "linux")]
    const STATE_ROOT_VARIABLE: &str = "GROK_BUILD_SERVICE_STATE_ROOT";
    #[cfg(target_os = "linux")]
    const CGROUP_PARENT_VARIABLE: &str = "GROK_BUILD_SERVICE_CGROUP_PARENT";
    #[cfg(target_os = "linux")]
    const DELEGATION_VARIABLE: &str = "GROK_BUILD_SERVICE_DELEGATION";
    #[cfg(target_os = "linux")]
    const RUNNER_UID_VARIABLE: &str = "GROK_BUILD_SERVICE_RUNNER_UID";
    #[cfg(target_os = "linux")]
    const RUNNER_GID_VARIABLE: &str = "GROK_BUILD_SERVICE_RUNNER_GID";
    /// A directory the *runner* owns, on an installer-owned path chain. It
    /// exists so the ownership clause can be shown to fire on its own, without
    /// a world-writable ancestor such as `/tmp` masking it.
    #[cfg(target_os = "linux")]
    const FORGE_ROOT_VARIABLE: &str = "GROK_BUILD_SERVICE_FORGE_ROOT";

    fn synthetic_install_commitment() -> LinuxNativeServiceInstallCommitmentV1 {
        LinuxNativeServiceInstallCommitmentV1 {
            format_version: LINUX_SERVICE_INSTALL_COMMITMENT_FORMAT_VERSION,
            installer_uid: 0,
            service_state_root_path: "/var/lib/grok-build/state".to_owned(),
            service_cgroup_parent_path: "/sys/fs/cgroup/grok-build".to_owned(),
            delegation_name: "delegation".to_owned(),
            delegation_subtree_control_readback: "memory pids\n".to_owned(),
            journal: LinuxProductionCommandPlanJournalBindingV1 {
                authenticated_platform_service_digest: Digest::sha256(b"anchor-service-image"),
                service_state_root_identity: CgroupObjectIdentity {
                    device: 41,
                    inode: 4_101,
                },
                singleton_journal_root_identity: CgroupObjectIdentity {
                    device: 41,
                    inode: 4_102,
                },
                service_parent_identity: CgroupObjectIdentity {
                    device: 42,
                    inode: 4_201,
                },
                delegation_identity: CgroupObjectIdentity {
                    device: 42,
                    inode: 4_202,
                },
                owner_uid: 1_000,
                delegation_mode: 0o755,
            },
        }
    }

    #[test]
    fn service_install_commitment_envelope_round_trips_and_refuses_noncanonical_bytes() {
        let commitment = synthetic_install_commitment();
        let bytes = encode_service_install_envelope(&commitment).unwrap();
        assert_eq!(decode_service_install_envelope(&bytes).unwrap(), commitment);

        // A single flipped byte anywhere in the envelope.
        for index in [0, bytes.len() / 3, bytes.len() - 1] {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x20;
            assert!(decode_service_install_envelope(&tampered).is_err());
        }

        // A digest that no longer commits to the commitment it ships with.
        let mut envelope: LinuxNativeServiceInstallEnvelopeV1 =
            serde_json::from_slice(&bytes).unwrap();
        envelope.commitment_sha256 = Digest::sha256(b"a different commitment");
        let crossed = serde_json::to_vec(&envelope).unwrap();
        assert!(decode_service_install_envelope(&crossed).is_err());

        // Correct content, non-canonical encoding.
        let envelope: LinuxNativeServiceInstallEnvelopeV1 =
            serde_json::from_slice(&bytes).unwrap();
        let pretty = serde_json::to_vec_pretty(&envelope).unwrap();
        assert_ne!(pretty, bytes);
        assert!(decode_service_install_envelope(&pretty).is_err());

        // Empty and oversized both refuse before parsing.
        assert!(decode_service_install_envelope(&[]).is_err());
        let oversized = vec![b'{'; MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES + 1];
        assert!(decode_service_install_envelope(&oversized).is_err());

        // An unknown field is refused rather than ignored.
        let widened = String::from_utf8(bytes)
            .unwrap()
            .replace("{\"format_version\"", "{\"extra\":1,\"format_version\"");
        assert!(decode_service_install_envelope(widened.as_bytes()).is_err());
    }

    #[test]
    fn service_install_commitment_refuses_every_single_field_that_would_anchor_nothing() {
        assert!(validate_service_install_commitment(&synthetic_install_commitment()).is_ok());

        let mut installer_is_runner = synthetic_install_commitment();
        installer_is_runner.installer_uid = installer_is_runner.journal.owner_uid;
        assert!(validate_service_install_commitment(&installer_is_runner).is_err());

        let mut runner_is_root = synthetic_install_commitment();
        runner_is_root.journal.owner_uid = 0;
        assert!(validate_service_install_commitment(&runner_is_root).is_err());

        let mut zero_identity = synthetic_install_commitment();
        zero_identity.journal.delegation_identity.inode = 0;
        assert!(validate_service_install_commitment(&zero_identity).is_err());

        let mut collapsed_roots = synthetic_install_commitment();
        collapsed_roots.journal.singleton_journal_root_identity =
            collapsed_roots.journal.service_state_root_identity;
        assert!(validate_service_install_commitment(&collapsed_roots).is_err());

        let mut collapsed_delegation = synthetic_install_commitment();
        collapsed_delegation.journal.delegation_identity =
            collapsed_delegation.journal.service_parent_identity;
        assert!(validate_service_install_commitment(&collapsed_delegation).is_err());

        let mut world_writable = synthetic_install_commitment();
        world_writable.journal.delegation_mode = 0o757;
        assert!(validate_service_install_commitment(&world_writable).is_err());

        let mut zero_digest = synthetic_install_commitment();
        zero_digest.journal.authenticated_platform_service_digest =
            Digest::parse("0".repeat(64)).unwrap();
        assert!(validate_service_install_commitment(&zero_digest).is_err());

        let mut relative_path = synthetic_install_commitment();
        relative_path.service_state_root_path = "var/lib/grok-build/state".to_owned();
        assert!(validate_service_install_commitment(&relative_path).is_err());

        let mut traversing_path = synthetic_install_commitment();
        traversing_path.service_cgroup_parent_path = "/sys/fs/cgroup/../cgroup/gb".to_owned();
        assert!(validate_service_install_commitment(&traversing_path).is_err());

        let mut same_path = synthetic_install_commitment();
        same_path.service_cgroup_parent_path = same_path.service_state_root_path.clone();
        assert!(validate_service_install_commitment(&same_path).is_err());

        let mut compound_delegation = synthetic_install_commitment();
        compound_delegation.delegation_name = "outer/inner".to_owned();
        assert!(validate_service_install_commitment(&compound_delegation).is_err());

        for readback in ["memory\n", "pids\n", "cpu memory pids\n", "", "memory pids"] {
            let mut wrong_controllers = synthetic_install_commitment();
            wrong_controllers.delegation_subtree_control_readback = readback.to_owned();
            assert!(
                validate_service_install_commitment(&wrong_controllers).is_err(),
                "subtree-control readback {readback:?} was admitted"
            );
        }

        let mut wrong_version = synthetic_install_commitment();
        wrong_version.format_version = LINUX_SERVICE_INSTALL_COMMITMENT_FORMAT_VERSION + 1;
        assert!(validate_service_install_commitment(&wrong_version).is_err());
    }

    #[cfg(target_os = "linux")]
    fn own_effective_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[cfg(target_os = "linux")]
    fn observed_directory_metadata(path: &Path) -> Metadata {
        Dir::open_ambient_dir(path, ambient_authority())
            .expect("open committed directory")
            .dir_metadata()
            .expect("inspect committed directory")
    }

    #[cfg(target_os = "linux")]
    fn observed_directory_identity(path: &Path) -> CgroupObjectIdentity {
        cgroup_identity(object_identity(&observed_directory_metadata(path)))
    }

    #[cfg(target_os = "linux")]
    fn observed_directory_mode(path: &Path) -> u32 {
        OsMetadataExt::mode(&observed_directory_metadata(path))
    }

    #[cfg(target_os = "linux")]
    fn environment_path(variable: &str) -> Option<String> {
        let value = std::env::var(variable).ok()?;
        (value.starts_with('/') && !value.ends_with('/')).then_some(value)
    }

    /// An install performed by an identity other than this process.
    #[cfg(target_os = "linux")]
    struct InstalledService {
        install_root: String,
        state_root: PathBuf,
        cgroup_parent: PathBuf,
        delegation: String,
    }

    #[cfg(target_os = "linux")]
    impl InstalledService {
        /// `Some` only when an installer really ran *and* this process is
        /// unprivileged. A privileged reader could forge the anchor, so the
        /// mint refuses it, and treating that refusal as a failure here would
        /// be testing the wrong thing.
        fn from_environment() -> Option<Self> {
            if own_effective_uid() == 0 {
                return None;
            }
            Some(Self {
                install_root: environment_path(INSTALL_ROOT_VARIABLE)?,
                state_root: PathBuf::from(environment_path(STATE_ROOT_VARIABLE)?),
                cgroup_parent: PathBuf::from(environment_path(CGROUP_PARENT_VARIABLE)?),
                delegation: std::env::var(DELEGATION_VARIABLE).ok()?,
            })
        }

        /// The binding the anchor must agree with, derived from this process's
        /// own kernel reads rather than from anything the anchor says.
        fn independently_observed_binding(&self) -> LinuxProductionCommandPlanJournalBindingV1 {
            let delegation_path = self.cgroup_parent.join(&self.delegation);
            LinuxProductionCommandPlanJournalBindingV1 {
                authenticated_platform_service_digest:
                    LinuxNativeServiceProcessImageAuthority::observe_current_process()
                        .expect("observe this process image")
                        .content_sha256
                        .clone(),
                service_state_root_identity: observed_directory_identity(&self.state_root),
                singleton_journal_root_identity: observed_directory_identity(
                    &self.state_root.join(SERVICE_COMMAND_JOURNAL_DIRECTORY),
                ),
                service_parent_identity: observed_directory_identity(&self.cgroup_parent),
                delegation_identity: observed_directory_identity(&delegation_path),
                owner_uid: own_effective_uid(),
                delegation_mode: observed_directory_mode(&delegation_path) & 0o7777,
            }
        }

        /// Who delegated, taken from an independent stat of the install root
        /// rather than from anything the anchor says.
        ///
        /// The install root is the directory the anchor lives in, and
        /// `open_installed_linux_native_service_handoff` already requires every
        /// component of the chain to it to be unowned by the runner, so this is
        /// a real second reading of the installing identity.
        fn independently_observed_installer_uid(&self) -> u32 {
            let (_, _, _, uid, _, _) = independent_directory_facts(Path::new(&self.install_root));
            uid
        }

        fn mint(
            &self,
        ) -> Result<
            (
                PendingLinuxNativeServiceAuthenticatedHandoff,
                LinuxNativeServiceInstallAnchorEvidenceV1,
            ),
            CgroupIoFailure,
        > {
            open_installed_linux_native_service_handoff(&self.install_root)
        }
    }

    #[cfg(target_os = "linux")]
    fn write_forged_anchor(directory: &Path, commitment: &LinuxNativeServiceInstallCommitmentV1) {
        let bytes = encode_service_install_envelope(commitment).expect("encode forged anchor");
        let path = directory.join(LINUX_SERVICE_INSTALL_ANCHOR_NAME);
        let _ = fs::remove_file(&path);
        fs::write(&path, &bytes).expect("write forged anchor");
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(LINUX_SERVICE_INSTALL_ANCHOR_MODE),
        )
        .expect("seal forged anchor");
    }

    /// An installer that shares the runner's identity is refused before it
    /// touches the filesystem, because the artifact it would write is one the
    /// runner could have written.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_native_service_install_refuses_an_installer_that_is_the_runner() {
        let request = LinuxNativeServiceInstallRequestV1 {
            installer_root: "/opt/grok-build/service",
            service_state_root_path: "/var/lib/grok-build/state",
            service_cgroup_parent_path: "/sys/fs/cgroup/grok-build",
            delegation_name: "delegation",
            runner_uid: own_effective_uid(),
            runner_gid: rustix::process::getegid().as_raw(),
            delegation_mode: 0o755,
            authenticated_platform_service_digest: Digest::sha256(b"anchor-service-image"),
        };
        let refusal = install_linux_native_service_handoff(&request).unwrap_err();
        assert_eq!(refusal.operation, "install-linux-native-service-handoff");
        assert!(
            refusal.detail.contains("shares the runner identity"),
            "unexpected refusal: {refusal:?}"
        );

        let root_runner = LinuxNativeServiceInstallRequestV1 {
            runner_uid: 0,
            ..request
        };
        assert!(install_linux_native_service_handoff(&root_runner).is_err());
    }

    /// The always-on half: an anchor the runner itself produced is refused.
    ///
    /// Under a privileged reader the refusal is the credential one, because a
    /// process that can bypass DAC could have written any anchor anywhere. Under
    /// an unprivileged reader it is the location one. Both are asserted against
    /// the credentials this process actually holds, so neither can be reached by
    /// accident.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_native_service_handoff_refuses_an_anchor_the_runner_itself_wrote() {
        let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "gb-forged-anchor-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create runner-owned anchor root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("seal runner-owned anchor root");
        // A commitment naming uid 0 as the runner is refused by the encoder
        // itself, so a privileged reader forges one for a plausible unprivileged
        // runner instead. Either way the mint never reads these bytes: the
        // credential and location refusals both precede the readback.
        let mut commitment = synthetic_install_commitment();
        commitment.journal.owner_uid = own_effective_uid().max(1);
        commitment.installer_uid = commitment.journal.owner_uid.wrapping_add(1);
        write_forged_anchor(&root, &commitment);

        let refusal = open_installed_linux_native_service_handoff(
            root.to_str().expect("temporary path is UTF-8"),
        )
        .expect_err("a runner-written anchor was accepted");
        assert_eq!(
            refusal.operation,
            "open-linux-native-service-install-anchor"
        );
        if own_effective_uid() == 0 {
            assert!(
                refusal.detail.contains("uid 0"),
                "unexpected privileged refusal: {refusal:?}"
            );
        } else {
            assert!(
                refusal.detail.contains("owned by the runner")
                    || refusal.detail.contains("writable outside its owner"),
                "unexpected unprivileged refusal: {refusal:?}"
            );
        }
        fs::remove_dir_all(&root).expect("remove runner-owned anchor root");

        // The same bytes placed on an installer-owned path chain, in a
        // directory the runner owns, must still be refused -- and there the
        // only clause left to fire is ownership.
        let Some(forge_root) = environment_path(FORGE_ROOT_VARIABLE) else {
            assert!(std::env::var(FORGE_ROOT_VARIABLE).is_err());
            return;
        };
        write_forged_anchor(Path::new(&forge_root), &commitment);
        let refusal = open_installed_linux_native_service_handoff(&forge_root)
            .expect_err("a runner-owned anchor on an installer-owned chain was accepted");
        if own_effective_uid() != 0 {
            assert!(
                refusal.detail.contains("owned by the runner"),
                "unexpected forge-root refusal: {refusal:?}"
            );
        }
    }

    /// The installer pass. Runs only under the installing identity; every other
    /// caller asserts that it is not that identity rather than skipping.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_native_service_installer_writes_the_external_anchor() {
        let installed = (|| {
            Some((
                environment_path(INSTALL_ROOT_VARIABLE)?,
                environment_path(STATE_ROOT_VARIABLE)?,
                environment_path(CGROUP_PARENT_VARIABLE)?,
                std::env::var(DELEGATION_VARIABLE).ok()?,
                std::env::var(RUNNER_UID_VARIABLE).ok()?.parse::<u32>().ok()?,
                std::env::var(RUNNER_GID_VARIABLE).ok()?.parse::<u32>().ok()?,
            ))
        })();
        let Some((install_root, state_root, cgroup_parent, delegation, runner_uid, group_id)) =
            installed
        else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none());
            return;
        };
        if own_effective_uid() == runner_uid {
            // This process is the runner, not the installer. The refusal that
            // guarantees is already asserted by the test above.
            assert!(install_linux_native_service_handoff(&LinuxNativeServiceInstallRequestV1 {
                installer_root: &install_root,
                service_state_root_path: &state_root,
                service_cgroup_parent_path: &cgroup_parent,
                delegation_name: &delegation,
                runner_uid,
                runner_gid: group_id,
                delegation_mode: 0o755,
                authenticated_platform_service_digest: Digest::sha256(b"unused"),
            })
            .is_err());
            return;
        }

        let digest = LinuxNativeServiceProcessImageAuthority::observe_current_process()
            .expect("observe this process image")
            .content_sha256
            .clone();
        let receipt = install_linux_native_service_handoff(&LinuxNativeServiceInstallRequestV1 {
            installer_root: &install_root,
            service_state_root_path: &state_root,
            service_cgroup_parent_path: &cgroup_parent,
            delegation_name: &delegation,
            runner_uid,
            runner_gid: group_id,
            delegation_mode: 0o755,
            authenticated_platform_service_digest: digest.clone(),
        })
        .expect("install the external native-service anchor");

        assert_eq!(receipt.commitment.installer_uid, own_effective_uid());
        assert_eq!(receipt.commitment.journal.owner_uid, runner_uid);
        assert_eq!(
            receipt.commitment.journal.authenticated_platform_service_digest,
            digest
        );
        assert_eq!(
            receipt.commitment.delegation_subtree_control_readback.trim(),
            "memory pids"
        );

        // The anchor on disk is what the receipt says it is.
        let anchor = Path::new(&receipt.anchor_absolute_path);
        let bytes = fs::read(anchor).expect("read installed anchor");
        assert_eq!(Digest::sha256(&bytes), receipt.anchor_sha256);
        assert_eq!(bytes.len() as u64, receipt.anchor_byte_length);
        let installed = Dir::open_ambient_dir(&install_root, ambient_authority())
            .expect("open install root")
            .open(LINUX_SERVICE_INSTALL_ANCHOR_NAME)
            .expect("open installed anchor");
        let metadata = installed.metadata().expect("inspect installed anchor");
        assert_eq!(
            OsMetadataExt::mode(&metadata) & 0o7777,
            LINUX_SERVICE_INSTALL_ANCHOR_MODE
        );
        assert_eq!(OsMetadataExt::uid(&metadata), own_effective_uid());
        assert_ne!(OsMetadataExt::uid(&metadata), runner_uid);
        assert_eq!(PortableMetadataExt::nlink(&metadata), 1);

        // The delegation really carries the controller set the durable
        // preflight probe needs before `prepare_domain` ever runs.
        let subtree_control = fs::read(
            Path::new(&cgroup_parent)
                .join(&delegation)
                .join("cgroup.subtree_control"),
        )
        .expect("read delegated subtree control");
        assert_eq!(
            parse_controller_set(&subtree_control, true).unwrap(),
            [DomainController::Memory, DomainController::Pids]
                .into_iter()
                .collect()
        );
        let delegation_metadata =
            observed_directory_metadata(&Path::new(&cgroup_parent).join(&delegation));
        assert_eq!(OsMetadataExt::uid(&delegation_metadata), runner_uid);
    }

    /// The forge probes are not constant refusals.
    ///
    /// Run the same two helpers the mint runs, against a directory this process
    /// owns. The kernel answers yes, and the helper turns that yes into a
    /// refusal. Without this control, the `EACCES` the enforced half reports
    /// could be a value the probe always produces.
    #[cfg(target_os = "linux")]
    fn assert_forge_probes_answer_yes_on_a_writable_directory() {
        let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let writable = std::env::temp_dir().join(format!(
            "gb-probe-control-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&writable).expect("create runner-writable probe directory");
        fs::write(writable.join("target"), b"probe control\n").expect("create probe target");
        let control = Dir::open_ambient_dir(&writable, ambient_authority())
            .expect("open runner-writable probe directory");

        let write_control = require_anchor_write_refused(&control, "target", "probe-control")
            .expect_err("a writable anchor was reported as refused");
        assert!(
            write_control
                .detail
                .contains("can open the install anchor for writing"),
            "unexpected write-probe control: {write_control:?}"
        );
        let create_control = require_anchor_directory_create_refused(&control, "probe-control")
            .expect_err("a writable directory was reported as refused");
        assert!(
            create_control
                .detail
                .contains("can create entries beside the install anchor"),
            "unexpected create-probe control: {create_control:?}"
        );

        // The create probe removes its own entry even when the kernel let it
        // through, so a refusal never litters a directory it was auditing.
        let leftovers = fs::read_dir(&writable)
            .expect("scan probe directory")
            .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
            .filter(|name| {
                name.to_string_lossy()
                    .starts_with(LINUX_SERVICE_INSTALL_PROBE_PREFIX)
            })
            .count();
        assert_eq!(leftovers, 0, "the create probe left an entry behind");
        drop(control);
        fs::remove_dir_all(&writable).expect("remove runner-writable probe directory");
    }

    /// The enforced half: an unprivileged runner consumes an anchor written by
    /// a different identity, and the derived capability chain closes.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_installed_anchor_mints_the_handoff_and_derives_the_state_root_capability() {
        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };

        let (handoff, evidence) = service.mint().expect("mint the installed handoff");

        // Credentials: this process could not have bypassed the anchor's
        // permission bits, and the kernel says so rather than the code.
        assert_ne!(evidence.credentials.effective_uid, 0);
        assert_eq!(
            evidence.credentials.effective_capabilities & FORBIDDEN_RUNNER_CAPABILITIES,
            0
        );
        assert_eq!(
            evidence.credentials.permitted_capabilities & FORBIDDEN_RUNNER_CAPABILITIES,
            0
        );

        // The anchor belongs to someone else, and both forge attempts were
        // refused by the kernel with a permission errno.
        assert_ne!(evidence.anchor_owner_uid, evidence.credentials.effective_uid);
        assert_eq!(evidence.anchor_mode & 0o7777, LINUX_SERVICE_INSTALL_ANCHOR_MODE);
        assert_eq!(evidence.anchor_link_count, 1);
        for refusal in [
            evidence.anchor_write_refusal,
            evidence.anchor_directory_create_refusal,
        ] {
            assert_eq!(
                refusal.errno,
                rustix::io::Errno::ACCESS.raw_os_error(),
                "{} did not return EACCES",
                refusal.attempt
            );
        }
        assert!(
            evidence
                .chain
                .iter()
                .all(|component| component.owner_uid != evidence.credentials.effective_uid
                    && component.mode & 0o022 == 0),
            "anchor path chain was runner-owned or loosely permissioned: {:?}",
            evidence.chain
        );

        // The mint's subtree-control readback is the file's real bytes, not a
        // copy of the commitment: read the same file again, independently.
        let live = fs::read(
            service
                .cgroup_parent
                .join(&service.delegation)
                .join("cgroup.subtree_control"),
        )
        .expect("read delegated subtree control");
        assert_eq!(evidence.delegation_subtree_control_readback, live);
        assert_eq!(
            parse_controller_set(&live, true).unwrap(),
            [DomainController::Memory, DomainController::Pids]
                .into_iter()
                .collect()
        );

        // The anchor agrees with what this process observed for itself.
        let expected = service.independently_observed_binding();
        let (capability, host_roots) = handoff
            .into_state_root_capability(&expected)
            .expect("derive the state-root capability from the installed anchor");
        assert_eq!(host_roots.delegation_name, service.delegation);
        assert_eq!(
            cgroup_identity(object_identity(
                &host_roots.service_parent.dir_metadata().unwrap()
            )),
            expected.service_parent_identity
        );

        // And the singleton journal authority opens on the authenticated path,
        // not the synthetic one.
        let authority = LinuxServiceCommandJournalAuthority::open_authenticated_service_singleton(
            capability,
            service_journal_binding_from_plan(&expected),
        )
        .expect("open the authenticated singleton command journal");
        assert!(matches!(
            authority.residual.authentication,
            LinuxServiceCommandJournalAuthentication::AuthenticatedHandoff { .. }
        ));

        println!(
            "GBDANCHOR installed anchor={} bytes={} sha256={} installer_uid={} runner_uid={} \
             capeff={:#018x} write_errno={} create_errno={} chain={}",
            evidence.anchor_absolute_path,
            evidence.anchor_byte_length,
            evidence.anchor_sha256,
            evidence.anchor_owner_uid,
            evidence.credentials.effective_uid,
            evidence.credentials.effective_capabilities,
            evidence.anchor_write_refusal.errno,
            evidence.anchor_directory_create_refusal.errno,
            evidence.chain.len()
        );
    }

    /// Controls. Each varies exactly one input against the run above.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_installed_anchor_refuses_every_single_substitution() {
        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };
        let expected = service.independently_observed_binding();
        assert!(service.mint().is_ok(), "the enforced half did not hold");

        // The sharpest one: the installer's exact bytes, relocated to a
        // directory the runner owns. Nothing about the commitment changed.
        if let Some(forge_root) = environment_path(FORGE_ROOT_VARIABLE) {
            let installed = fs::read(
                Path::new(&service.install_root).join(LINUX_SERVICE_INSTALL_ANCHOR_NAME),
            )
            .expect("read installed anchor");
            let relocated = Path::new(&forge_root).join(LINUX_SERVICE_INSTALL_ANCHOR_NAME);
            let _ = fs::remove_file(&relocated);
            fs::write(&relocated, &installed).expect("relocate installed anchor");
            fs::set_permissions(
                &relocated,
                fs::Permissions::from_mode(LINUX_SERVICE_INSTALL_ANCHOR_MODE),
            )
            .expect("seal relocated anchor");
            let refusal = open_installed_linux_native_service_handoff(&forge_root)
                .expect_err("relocated installer bytes were accepted");
            assert!(
                refusal.detail.contains("owned by the runner"),
                "unexpected relocation refusal: {refusal:?}"
            );
        } else {
            assert!(std::env::var(FORGE_ROOT_VARIABLE).is_err());
        }

        assert_forge_probes_answer_yes_on_a_writable_directory();

        // An installer root with no anchor at all.
        let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let empty = std::env::temp_dir().join(format!(
            "gb-empty-anchor-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&empty).expect("create empty anchor root");
        assert!(
            open_installed_linux_native_service_handoff(empty.to_str().unwrap()).is_err(),
            "an installer root with no anchor was accepted"
        );
        fs::remove_dir_all(&empty).expect("remove empty anchor root");

        // One field of the expectation at a time. Each is a value the anchor
        // was not written against, and each must break the join.
        let mut crossed_digest = expected.clone();
        crossed_digest.authenticated_platform_service_digest =
            Digest::sha256(b"a different service image");
        let mut crossed_owner = expected.clone();
        crossed_owner.owner_uid = expected.owner_uid.wrapping_add(1);
        let mut crossed_mode = expected.clone();
        crossed_mode.delegation_mode = if expected.delegation_mode == 0o700 {
            0o755
        } else {
            0o700
        };
        let mut crossed_state_root = expected.clone();
        crossed_state_root.service_state_root_identity = expected.singleton_journal_root_identity;
        let mut crossed_delegation = expected.clone();
        crossed_delegation.delegation_identity = expected.service_parent_identity;
        let mut crossed_parent = expected.clone();
        crossed_parent.service_parent_identity = expected.delegation_identity;

        for (label, candidate) in [
            ("service image digest", crossed_digest),
            ("owner uid", crossed_owner),
            ("delegation mode", crossed_mode),
            ("service state root", crossed_state_root),
            ("delegation identity", crossed_delegation),
            ("service parent identity", crossed_parent),
        ] {
            let (handoff, _) = service.mint().expect("mint the installed handoff");
            assert!(
                handoff.into_state_root_capability(&candidate).is_err(),
                "a crossed {label} was admitted"
            );
        }

        // And the unmodified expectation still holds afterwards, so the
        // refusals above are attributable to the varied field.
        let (handoff, _) = service.mint().expect("mint the installed handoff");
        assert!(handoff.into_state_root_capability(&expected).is_ok());
    }

    // ---------------------------------------------------------------------
    // Route 1 increment 3: the anchored production plan facts.
    //
    // `LinuxProductionCommandPlanComponentsV1` had exactly one populator, a
    // test fixture. These tests exercise the production mint for the part of it
    // that can only come from installed state, and the thing they establish is
    // that both halves are load bearing: the identities are this process's own
    // kernel reads, and the mint refuses unless they equal what an identity the
    // runner is not committed externally.

    #[cfg(target_os = "linux")]
    const CONTROL_DELEGATION_VARIABLE: &str = "GROK_BUILD_SERVICE_CONTROL_DELEGATION";

    /// An independent observation of one directory, taken through the ordinary
    /// standard-library path API rather than through anything the mint touched.
    #[cfg(target_os = "linux")]
    fn independent_directory_facts(path: &Path) -> (u64, u64, u32, u32, u32, u64) {
        use std::os::unix::fs::MetadataExt as StdMetadataExt;
        let metadata = fs::metadata(path).expect("independently stat committed directory");
        (
            StdMetadataExt::dev(&metadata),
            StdMetadataExt::ino(&metadata),
            StdMetadataExt::mode(&metadata),
            StdMetadataExt::uid(&metadata),
            StdMetadataExt::gid(&metadata),
            StdMetadataExt::nlink(&metadata),
        )
    }

    #[cfg(target_os = "linux")]
    fn open_ambient(path: &Path) -> Dir {
        Dir::open_ambient_dir(path, ambient_authority()).expect("open directory for control")
    }

    /// The enforced half. The anchored facts are minted, and every field is
    /// shown to equal an observation taken independently of the mint.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear canary keeps every anchored field and its independent observation visible together"
    )]
    fn live_anchored_plan_facts_are_kernel_reads_that_agree_with_the_installer() {
        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };
        let expected = service.independently_observed_binding();
        let (handoff, _) = service.mint().expect("mint the installed handoff");
        let (capability, host_roots) = handoff
            .into_state_root_capability(&expected)
            .expect("derive the state-root capability from the installed anchor");

        let facts = match capability.observe_anchored_plan_facts(&host_roots) {
            Ok(facts) => facts,
            Err(error) => {
                // The delegation arm: the harness chowned the cgroup parent to
                // the service, so the parent is no longer the delegator's and
                // no anchored fact exists to check. That refusal is this arm's
                // whole evidence and it is asserted by name in
                // `live_anchored_plan_facts_require_a_cgroup_parent_the_service_does_not_own`.
                assert!(
                    service_owned_cgroup_parent(),
                    "the anchored facts must mint on a delegator-owned parent: {error:?}"
                );
                assert!(
                    format!("{error:?}").contains("not owned by the installing delegator")
                );
                return;
            }
        };

        // Every identity is a live read that equals an independent stat of the
        // same path. The anchor commits device and inode only, so the mode,
        // owner group, link count and mount id below are information no anchor
        // could have supplied and no literal could have been copied from.
        let journal_path = service.state_root.join(SERVICE_COMMAND_JOURNAL_DIRECTORY);
        let delegation_path = service.cgroup_parent.join(&service.delegation);
        for (label, identity, path, kind) in [
            (
                "service-state root",
                &facts.service_state_root,
                service.state_root.clone(),
                LinuxRetainedObjectKindV1::Directory,
            ),
            (
                "singleton journal root",
                &facts.singleton_journal_root,
                journal_path.clone(),
                LinuxRetainedObjectKindV1::Directory,
            ),
            (
                "service cgroup parent",
                &facts.service_cgroup_parent,
                service.cgroup_parent.clone(),
                LinuxRetainedObjectKindV1::CgroupDirectory,
            ),
            (
                "cgroup delegation root",
                &facts.cgroup_delegation_root,
                delegation_path.clone(),
                LinuxRetainedObjectKindV1::CgroupDirectory,
            ),
        ] {
            let (device, inode, mode, uid, gid, nlink) = independent_directory_facts(&path);
            let observed = identity.kernel_observation();
            assert_eq!(identity.kind(), kind, "{label} kind");
            assert_eq!(observed.device_id, device, "{label} device");
            assert_eq!(observed.inode, inode, "{label} inode");
            assert_eq!(observed.mode, mode, "{label} mode");
            assert_eq!(observed.owner_uid, uid, "{label} owner uid");
            assert_eq!(observed.owner_gid, gid, "{label} owner gid");
            assert_eq!(observed.link_count, nlink, "{label} link count");
            assert_eq!(observed.byte_length, None, "{label} byte length");
            assert_ne!(observed.mount_id, 0, "{label} mount id");
        }

        // The two roots the runner owns really are owner-private, and the
        // delegation really is the mode the installer committed.
        assert_eq!(
            facts.service_state_root.kernel_observation().mode & 0o777,
            0o700
        );
        assert_eq!(
            facts.singleton_journal_root.kernel_observation().mode & 0o777,
            0o700
        );
        assert_eq!(
            facts.cgroup_delegation_root.kernel_observation().mode & 0o7777,
            expected.delegation_mode
        );

        // The filesystem magic is a read, not the plan constant: the same
        // helper answers differently for the service-state root, which is not
        // on a cgroup mount.
        assert_eq!(facts.cgroup_filesystem_magic, CGROUP2_SUPER_MAGIC);
        let state_root_magic =
            filesystem_magic(&open_ambient(&service.state_root)).expect("read state-root magic");
        assert_ne!(
            state_root_magic, CGROUP2_SUPER_MAGIC,
            "the magic probe answered cgroup2 for a directory that is not on one"
        );

        // The service image is the running executable, independently confirmed.
        let self_exe = fs::read_link("/proc/self/exe").expect("read /proc/self/exe");
        assert_eq!(
            facts.service_image.resolved_path(),
            self_exe.to_str().expect("self/exe is UTF-8")
        );
        let bytes = fs::read(&self_exe).expect("read the running executable");
        assert_eq!(facts.service_image.byte_length(), bytes.len() as u64);
        assert_eq!(facts.service_image.content_sha256(), &Digest::sha256(&bytes));
        assert_eq!(
            facts.authenticated_platform_service_digest,
            expected.authenticated_platform_service_digest
        );
        assert_eq!(
            facts.service_image_object.kind(),
            LinuxRetainedObjectKindV1::RegularFile
        );
        assert_eq!(
            facts.service_image_object.kernel_observation().byte_length,
            Some(bytes.len() as u64)
        );
        assert_eq!(facts.service_image_object.kernel_observation().link_count, 1);

        // Object identifiers are the plan's semantic role boundaries and are
        // pairwise distinct, as are the kernel inodes behind them.
        let object_ids = [
            facts.service_state_root.object_id(),
            facts.singleton_journal_root.object_id(),
            facts.service_cgroup_parent.object_id(),
            facts.cgroup_delegation_root.object_id(),
            facts.service_image_object.object_id(),
        ];
        assert_eq!(object_ids.iter().collect::<BTreeSet<_>>().len(), 5);
        let inodes = [
            &facts.service_state_root,
            &facts.singleton_journal_root,
            &facts.service_cgroup_parent,
            &facts.cgroup_delegation_root,
            &facts.service_image_object,
        ]
        .map(|identity| {
            let observed = identity.kernel_observation();
            (observed.device_id, observed.inode)
        });
        assert_eq!(inodes.iter().collect::<BTreeSet<_>>().len(), 5);

        println!(
            "GBDFACTS anchored state_root={}:{} journal={}:{} parent={}:{} delegation={}:{} \
             magic={:#x} image={} bytes={} sha256={}",
            facts.service_state_root.kernel_observation().device_id,
            facts.service_state_root.kernel_observation().inode,
            facts.singleton_journal_root.kernel_observation().device_id,
            facts.singleton_journal_root.kernel_observation().inode,
            facts.service_cgroup_parent.kernel_observation().device_id,
            facts.service_cgroup_parent.kernel_observation().inode,
            facts.cgroup_delegation_root.kernel_observation().device_id,
            facts.cgroup_delegation_root.kernel_observation().inode,
            facts.cgroup_filesystem_magic,
            facts.service_image.resolved_path(),
            facts.service_image.byte_length(),
            facts.service_image.content_sha256(),
        );
    }

    /// Controls. Each varies exactly one input against the enforced run above,
    /// and each varied value is a real one taken from somewhere else on the
    /// same host rather than an invented number.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear control table keeps every single-input substitution visible together"
    )]
    fn live_anchored_plan_facts_refuse_every_single_crossed_input() {
        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };
        let committed = service.independently_observed_binding();
        let installer_uid = service.independently_observed_installer_uid();
        let journal_path = service.state_root.join(SERVICE_COMMAND_JOURNAL_DIRECTORY);
        let image = LinuxNativeServiceProcessImageAuthority::observe_current_process()
            .expect("observe this process image");
        let state_root = open_ambient(&service.state_root);
        let cgroup_parent = open_ambient(&service.cgroup_parent);

        // The unvaried inputs mint, so every refusal below is attributable to
        // the one value that changed. In the service-owned-parent arm there is
        // no such control — the parent is itself the varied value — so this
        // test has nothing to establish there and says so rather than skipping.
        match observe_anchored_production_plan_facts(
            &image,
            &state_root,
            &cgroup_parent,
            &service.delegation,
            installer_uid,
            &committed,
        ) {
            Ok(_) => assert!(
                !service_owned_cgroup_parent(),
                "a service-owned cgroup parent must not mint"
            ),
            Err(error) => {
                assert!(
                    service_owned_cgroup_parent(),
                    "the unvaried inputs must mint on a delegator-owned parent: {error:?}"
                );
                assert!(
                    format!("{error:?}").contains("not owned by the installing delegator"),
                    "the refusal moved: {error:?}"
                );
                return;
            }
        }

        // One committed field at a time, each crossed with a real identity
        // taken from another role on the same host.
        let mut crossed_state_root = committed.clone();
        crossed_state_root.service_state_root_identity = committed.singleton_journal_root_identity;
        let mut crossed_journal = committed.clone();
        crossed_journal.singleton_journal_root_identity = committed.service_state_root_identity;
        let mut crossed_parent = committed.clone();
        crossed_parent.service_parent_identity = committed.delegation_identity;
        let mut crossed_delegation = committed.clone();
        crossed_delegation.delegation_identity = committed.service_parent_identity;
        let mut crossed_owner = committed.clone();
        crossed_owner.owner_uid = committed.owner_uid.wrapping_add(1);
        let mut crossed_mode = committed.clone();
        crossed_mode.delegation_mode = if committed.delegation_mode == 0o700 {
            0o755
        } else {
            0o700
        };
        let mut crossed_digest = committed.clone();
        crossed_digest.authenticated_platform_service_digest =
            Digest::sha256(b"a different service image");
        for (label, candidate) in [
            ("service-state root identity", crossed_state_root),
            ("singleton journal identity", crossed_journal),
            ("service parent identity", crossed_parent),
            ("delegation identity", crossed_delegation),
            ("owner uid", crossed_owner),
            ("delegation mode", crossed_mode),
            ("service image digest", crossed_digest),
        ] {
            assert!(
                observe_anchored_production_plan_facts(
                    &image,
                    &state_root,
                    &cgroup_parent,
                    &service.delegation,
                    installer_uid,
                    &candidate,
                )
                .is_err(),
                "a crossed {label} was admitted"
            );
        }

        // A real state root that is not the committed one: the singleton
        // journal directory, which is a genuine owner-private 0700 directory
        // the runner owns.
        assert!(
            observe_anchored_production_plan_facts(
                &image,
                &open_ambient(&journal_path),
                &cgroup_parent,
                &service.delegation,
                installer_uid,
                &committed,
            )
            .is_err(),
            "a real but uncommitted state root was admitted"
        );

        // A real directory that is not on a cgroup-v2 mount, standing in for
        // the service cgroup parent.
        assert!(
            observe_anchored_production_plan_facts(
                &image,
                &state_root,
                &state_root,
                &service.delegation,
                installer_uid,
                &committed,
            )
            .is_err(),
            "a parent that is not on a cgroup-v2 mount was admitted"
        );

        // A second, genuine, runner-owned cgroup-v2 delegation under the same
        // committed parent. Nothing about it is invalid; it is simply not the
        // one the installer committed.
        if let Ok(control) = std::env::var(CONTROL_DELEGATION_VARIABLE) {
            let control_path = service.cgroup_parent.join(&control);
            assert!(
                control_path.is_dir(),
                "the control delegation {control} does not exist"
            );
            assert_ne!(control, service.delegation);
            assert!(
                observe_anchored_production_plan_facts(
                    &image,
                    &state_root,
                    &cgroup_parent,
                    &control,
                    installer_uid,
                    &committed,
                )
                .is_err(),
                "a real but uncommitted delegation was admitted"
            );
        } else {
            assert!(std::env::var(CONTROL_DELEGATION_VARIABLE).is_err());
        }

        // A delegation name that does not resolve at all.
        assert!(
            observe_anchored_production_plan_facts(
                &image,
                &state_root,
                &cgroup_parent,
                "no-such-delegation",
                installer_uid,
                &committed,
            )
            .is_err()
        );

        // And the unvaried inputs still mint afterwards.
        assert!(
            observe_anchored_production_plan_facts(
                &image,
                &state_root,
                &cgroup_parent,
                &service.delegation,
                installer_uid,
                &committed,
            )
            .is_ok()
        );
    }

    // Route 1 increment 4: the measured host architecture, and the refusal of
    // a plan that describes the other one.
    //
    // Every Linux measurement this project has ever taken was on aarch64,
    // while the plan schema could name only x86-64. Schema version 2 can name
    // both, which makes it possible to be wrong, which is the point: the
    // architecture is now a claim a host can refuse.

    /// The enforced half: the architecture is two agreeing live reads, and a
    /// plan built for the other architecture is refused against them.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_host_architecture_is_measured_and_refuses_the_other_architecture() {
        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };
        let expected = service.independently_observed_binding();
        let (handoff, _) = service.mint().expect("mint the installed handoff");
        let (capability, host_roots) = handoff
            .into_state_root_capability(&expected)
            .expect("derive the state-root capability from the installed anchor");
        let facts = match capability.observe_anchored_plan_facts(&host_roots) {
            Ok(facts) => facts,
            Err(error) => {
                // The delegation arm: the harness chowned the cgroup parent to
                // the service, so the parent is no longer the delegator's and
                // no anchored fact exists to check. That refusal is this arm's
                // whole evidence and it is asserted by name in
                // `live_anchored_plan_facts_require_a_cgroup_parent_the_service_does_not_own`.
                assert!(
                    service_owned_cgroup_parent(),
                    "the anchored facts must mint on a delegator-owned parent: {error:?}"
                );
                assert!(
                    format!("{error:?}").contains("not owned by the installing delegator")
                );
                return;
            }
        };
        let measured = &facts.host_architecture;

        // Independent of the mint: read the same image's ELF header again
        // through `std::fs` and a fresh open, rather than through the retained
        // descriptor the mint used.
        let independent = std::fs::read(facts.service_image.resolved_path())
            .expect("independently read the running service image");
        assert_eq!(&independent[..4], b"\x7fELF");
        let independent_machine = u16::from_le_bytes([independent[18], independent[19]]);
        assert_eq!(independent_machine, measured.image_elf_machine());

        // Independent of the mint again: the kernel's own machine name, taken
        // through a second `uname(2)`.
        let kernel = rustix::system::uname();
        assert_eq!(
            kernel.machine().to_str().expect("kernel machine is UTF-8"),
            measured.kernel_machine()
        );
        assert_eq!(measured.architecture().as_str(), measured.kernel_machine());

        println!(
            "GBDARCH measured architecture={} elf_e_machine={:#06x} uname_machine={}",
            measured.architecture().as_str(),
            measured.image_elf_machine(),
            measured.kernel_machine(),
        );

        // Enforced: a plan describing the measured architecture is admitted.
        let workspace = std::env::temp_dir().join(format!(
            "gb-arch-plan-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let matching = crate::linux_command_plan::tests::fixture_at_workspace(
            crate::wire::RunnerRole::Worker,
            &workspace,
        )
        .rebind_test_machine_architecture(measured.architecture())
        .expect("rebind the plan to the measured architecture");
        matching
            .require_measured_host_architecture(measured)
            .expect("a plan describing this host is admitted");

        // Control: exactly one input differs -- the plan's architecture -- and
        // the same measurement now refuses it.
        let other = match measured.architecture() {
            LinuxMachineArchitectureV1::X86_64 => LinuxMachineArchitectureV1::Aarch64,
            LinuxMachineArchitectureV1::Aarch64 => LinuxMachineArchitectureV1::X86_64,
        };
        let crossed = matching
            .clone()
            .rebind_test_machine_architecture(other)
            .expect("rebind the plan to the other architecture");
        assert_ne!(crossed.plan_digest(), matching.plan_digest());
        let refusal = crossed
            .require_measured_host_architecture(measured)
            .expect_err("a plan built for the other architecture must be refused");
        assert!(refusal.to_string().contains(other.as_str()));
        assert!(
            refusal
                .to_string()
                .contains(measured.architecture().as_str())
        );

        // And the matching plan still passes afterwards, so the refusal is
        // attributable to the one value that changed.
        matching
            .require_measured_host_architecture(measured)
            .expect("the unvaried plan still passes");
        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// The service cgroup parent must belong to the identity that delegated.
    ///
    /// This is the live half of the delegation-owner correction. The plan's own
    /// `validate_cgroup` can require the parent not to be the service's and not
    /// to be writable outside its owner, but a plan carries no delegator
    /// identity, so a parent owned by some *third* identity satisfies every
    /// clause a plan can state. The anchor does carry one — `installer_uid`,
    /// which `validate_service_install_commitment` has already required to
    /// differ from the runner's — and this is where it is used.
    ///
    /// The harness varies exactly one `chown` of `/sys/fs/cgroup/gbd` between
    /// the two arms and nothing else.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_anchored_plan_facts_require_a_cgroup_parent_the_service_does_not_own() {
        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };
        let committed = service.independently_observed_binding();
        let installer_uid = service.independently_observed_installer_uid();
        let image = LinuxNativeServiceProcessImageAuthority::observe_current_process()
            .expect("observe this process image");
        let state_root = open_ambient(&service.state_root);
        let cgroup_parent = open_ambient(&service.cgroup_parent);
        let (_, _, parent_mode, parent_uid, _, _) =
            independent_directory_facts(&service.cgroup_parent);

        let verdict = observe_anchored_production_plan_facts(
            &image,
            &state_root,
            &cgroup_parent,
            &service.delegation,
            installer_uid,
            &committed,
        );
        println!(
            "GBDDELEG arm={} parent={} uid={parent_uid} mode={:o} installer={installer_uid} \
             service={} verdict={}",
            if service_owned_cgroup_parent() {
                "service-owned-parent"
            } else {
                "delegator-owned-parent"
            },
            service.cgroup_parent.display(),
            parent_mode & 0o7777,
            committed.owner_uid,
            match &verdict {
                Ok(_) => "minted".to_owned(),
                Err(error) => format!("refused {error:?}"),
            }
        );

        if service_owned_cgroup_parent() {
            // Enforced: a parent the service owns is a parent the service can
            // create siblings in and rmdir this delegation from. The old plan
            // clause *required* this shape; the anchor now refuses it.
            assert_eq!(
                parent_uid, committed.owner_uid,
                "this arm requires a service-owned parent"
            );
            let refusal = verdict.expect_err("a service-owned cgroup parent must be refused");
            let detail = format!("{refusal:?}");
            assert!(
                detail.contains("not owned by the installing delegator"),
                "the refusal moved: {detail}"
            );
        } else {
            // Control: delegation as the kernel documents it — the delegator
            // keeps the parent, the service owns only the delegated subtree.
            assert_eq!(parent_uid, installer_uid, "the delegator owns the parent");
            assert_ne!(
                parent_uid, committed.owner_uid,
                "the parent and the delegation have two owners"
            );
            assert_eq!(parent_mode & 0o022, 0, "the parent denies group/world write");
            verdict.expect("a delegator-owned cgroup parent mints the anchored facts");

            // Enforced, one input varied: an anchor naming a different
            // installer no longer describes this parent.
            assert!(
                observe_anchored_production_plan_facts(
                    &image,
                    &state_root,
                    &cgroup_parent,
                    &service.delegation,
                    installer_uid.wrapping_add(1),
                    &committed,
                )
                .is_err(),
                "a parent owned by someone other than the committed installer was admitted"
            );
        }
    }
