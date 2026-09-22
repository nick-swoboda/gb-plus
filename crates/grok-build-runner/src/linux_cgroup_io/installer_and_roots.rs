impl DurableProbeEffects for LinuxProbeEffects<'_> {
    fn observe_identity(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<Option<CgroupObjectIdentity>, CgroupIoFailure> {
        Ok(open_named_probe(self.delegation, record)?.map(|(_, identity)| identity))
    }

    fn observe_shape(
        &mut self,
        record: &ProbeJournalRecord,
        identity: CgroupObjectIdentity,
    ) -> Result<Option<ProbeDefaultShape>, CgroupIoFailure> {
        let Some((directory, current)) = open_named_probe(self.delegation, record)? else {
            return Ok(None);
        };
        if current != identity {
            return Err(failure(
                "preflight-probe-identity-substitution",
                EffectCertainty::Ambiguous,
                "probe identity changed between identity and shape observations",
            ));
        }
        Ok(Some(observe_probe_shape(&directory)?))
    }

    fn create_no_replace(&mut self, name: &str) -> Result<(), CgroupIoFailure> {
        self.delegation.create_dir(name).map_err(|error| {
            failure(
                "preflight-probe-create",
                EffectCertainty::Ambiguous,
                format!("durable create intent is unresolved after mkdir failure: {error}"),
            )
        })
    }

    fn configure_exact(&mut self, record: &ProbeJournalRecord) -> Result<bool, CgroupIoFailure> {
        let Some(directory) = open_exact_probe(self.delegation, record)? else {
            return Ok(false);
        };
        configure_probe(&directory)?;
        Ok(true)
    }

    fn kill_and_prove_empty(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<bool, CgroupIoFailure> {
        let Some(directory) = open_exact_probe(self.delegation, record)? else {
            return Ok(false);
        };
        kill_and_prove_probe_empty(&directory)?;
        Ok(true)
    }

    fn remove_exact_and_prove(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<(), CgroupIoFailure> {
        let Some(directory) = open_exact_probe(self.delegation, record)? else {
            return Ok(());
        };
        remove_and_prove_named_directory_exact(
            self.delegation,
            &record.probe_name,
            &directory,
            record.observed_identity.ok_or_else(|| {
                failure(
                    "preflight-probe-remove",
                    EffectCertainty::NotApplied,
                    "remove intent lacks an authoritative identity",
                )
            })?,
            "preflight-probe-remove",
        )
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the durable probe machine keeps every synchronized intent and exact recovery branch in one auditable transition loop"
)]
fn drive_durable_probe<E: DurableProbeEffects>(
    journal: &mut CanonicalCgroupJournalStore,
    effects: &mut E,
    expectation: DelegationRootExpectation,
) -> Result<DelegationProbeEvidence, CgroupIoFailure> {
    let mut record = match journal.latest_probe_record() {
        Some(record) if record.state != ProbeJournalState::Removed => record,
        _ => {
            let record = new_probe_intent(expectation, effects.episode_kind())?;
            persist_probe_transition(journal, &record)?;
            record
        }
    };
    for _ in 0..24 {
        match record.state {
            ProbeJournalState::CreateIntended => {
                if let Some(identity) = effects.observe_identity(&record)? {
                    let shape = effects.observe_shape(&record, identity)?;
                    record.state = ProbeJournalState::OwnershipUnknown;
                    record.observed_identity = Some(identity);
                    record.initial_shape = shape;
                    persist_probe_transition(journal, &record)?;
                    return Err(failure(
                        "preflight-probe-ownership-unknown",
                        EffectCertainty::Ambiguous,
                        "a durable create intent has a named candidate but no synchronized authoritative identity; no removal is permitted",
                    ));
                }
                effects.create_no_replace(&record.probe_name)?;
                let Some(identity) = effects.observe_identity(&record)? else {
                    persist_probe_removed(journal, &mut record)?;
                    record = new_probe_intent(expectation, effects.episode_kind())?;
                    persist_probe_transition(journal, &record)?;
                    continue;
                };
                record.state = ProbeJournalState::IdentityObserved;
                record.observed_identity = Some(identity);
                record.identity_authoritative = true;
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::OwnershipUnknown => {
                let Some(identity) = effects.observe_identity(&record)? else {
                    persist_probe_removed(journal, &mut record)?;
                    record = new_probe_intent(expectation, effects.episode_kind())?;
                    persist_probe_transition(journal, &record)?;
                    continue;
                };
                let strict = effects
                    .observe_shape(&record, identity)?
                    .is_some_and(|shape| {
                        validate_strict_probe_default_shape(&shape, expectation).is_ok()
                    });
                return Err(failure(
                    "preflight-probe-ownership-unknown",
                    EffectCertainty::Ambiguous,
                    format!(
                        "probe ownership remains Unknown (identity {identity:?}, strict empty/default shape: {strict}); exact removal is forbidden"
                    ),
                ));
            }
            ProbeJournalState::IdentityObserved => {
                let expected = record.observed_identity.ok_or_else(|| {
                    failure(
                        "preflight-probe-identity",
                        EffectCertainty::NotApplied,
                        "identity-observed state lacks its authoritative identity",
                    )
                })?;
                let Some(identity) = effects.observe_identity(&record)? else {
                    persist_probe_removed(journal, &mut record)?;
                    record = new_probe_intent(expectation, effects.episode_kind())?;
                    persist_probe_transition(journal, &record)?;
                    continue;
                };
                if identity != expected {
                    return Err(failure(
                        "preflight-probe-identity-substitution",
                        EffectCertainty::Ambiguous,
                        "durable probe name no longer denotes the authoritative identity",
                    ));
                }
                let Some(shape) = effects.observe_shape(&record, expected)? else {
                    persist_probe_removed(journal, &mut record)?;
                    record = new_probe_intent(expectation, effects.episode_kind())?;
                    persist_probe_transition(journal, &record)?;
                    continue;
                };
                record.state = ProbeJournalState::ShapeObserved;
                record.initial_shape = Some(shape);
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::ShapeObserved => {
                record.state = if validate_strict_probe_default_shape(
                    record.initial_shape.as_ref().ok_or_else(|| {
                        failure(
                            "preflight-probe-shape",
                            EffectCertainty::NotApplied,
                            "shape-observed state lacks its bounded shape",
                        )
                    })?,
                    expectation,
                )
                .is_ok()
                {
                    ProbeJournalState::ConfigureIntended
                } else {
                    ProbeJournalState::KillIntended
                };
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::ConfigureIntended => {
                if !effects.configure_exact(&record)? {
                    persist_probe_removed(journal, &mut record)?;
                    record = new_probe_intent(expectation, effects.episode_kind())?;
                    persist_probe_transition(journal, &record)?;
                    continue;
                }
                record.state = ProbeJournalState::Configured;
                record.configured_and_read_back = true;
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::Configured => {
                // Run canaries in the configured live leaf and commit their results with
                // the kill intent. A crash cannot recover an uncommitted claim.
                if record.episode_kind == ProbeEpisodeKind::ControlCanary && record.canary.is_none()
                {
                    record.canary = effects.run_canary_suite(&record)?;
                }
                record.state = ProbeJournalState::KillIntended;
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::KillIntended => {
                if !effects.kill_and_prove_empty(&record)? {
                    persist_probe_removed(journal, &mut record)?;
                    record = new_probe_intent(expectation, effects.episode_kind())?;
                    persist_probe_transition(journal, &record)?;
                    continue;
                }
                record.state = ProbeJournalState::EmptyProven;
                record.stable_empty_proven = true;
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::EmptyProven => {
                record.state = ProbeJournalState::RemoveIntended;
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::RemoveIntended => {
                effects.remove_exact_and_prove(&record)?;
                persist_probe_removed(journal, &mut record)?;
                if record.configured_and_read_back && record.stable_empty_proven {
                    return Ok(DelegationProbeEvidence {
                        created_no_replace: true,
                        configured_and_read_back: true,
                        kill_write_accepted: true,
                        populated_zero: true,
                        stable_empty_procs: true,
                        removed_exact_inode: true,
                    });
                }
                record = new_probe_intent(expectation, effects.episode_kind())?;
                persist_probe_transition(journal, &record)?;
            }
            ProbeJournalState::Removed => {
                record = new_probe_intent(expectation, effects.episode_kind())?;
                persist_probe_transition(journal, &record)?;
            }
        }
    }
    Err(failure(
        "drive-preflight-probe",
        EffectCertainty::Ambiguous,
        "probe transition bound was exhausted before an authoritative endpoint",
    ))
}

/// Drives one canary episode to its endpoint and returns what it established.
///
/// This is the same durable machine the delegation probe uses — same journal,
/// same bounded generation ceiling, same create/observe/configure/kill/
/// prove-empty/remove lifecycle, same private directory — differing only in
/// that `effects` declares [`ProbeEpisodeKind::ControlCanary`] and runs a live
/// suite inside the configured leaf.
///
/// It is **not** a command effect and cannot become one. A probe episode
/// carries no `effect_id`, is never entered into `created_command_effects` or
/// `command_effect_history`, and cannot reach [`CanonicalCgroupJournalStore::persist`]
/// at all: that function takes a `DomainJournalRecord`, and this machine only
/// ever produces a `ProbeJournalRecord`. The one-episode-per-effect invariant
/// is therefore untouched by construction rather than by agreement, which is
/// what lets this journal admit repeated episodes where the command journal
/// admits exactly one, forever.
///
/// # Errors
///
/// Fails for every reason [`drive_durable_probe`] fails, and when the episode
/// reached its endpoint without a durable claim — a canary that proved
/// nothing is a refusal here, never an empty success.
fn drive_canary_episode<E: DurableProbeEffects>(
    journal: &mut CanonicalCgroupJournalStore,
    effects: &mut E,
    expectation: DelegationRootExpectation,
) -> Result<CanaryEpisodeEvidenceV1, CgroupIoFailure> {
    if effects.episode_kind() != ProbeEpisodeKind::ControlCanary {
        return Err(failure(
            "drive-canary-episode",
            EffectCertainty::NotApplied,
            "canary episode effects must declare the control-canary episode kind",
        ));
    }
    drive_durable_probe(journal, effects, expectation)?;
    let record = journal.latest_probe_record().ok_or_else(|| {
        failure(
            "drive-canary-episode",
            EffectCertainty::NotApplied,
            "the canary episode left no durable generation",
        )
    })?;
    record.canary.ok_or_else(|| {
        failure(
            "drive-canary-episode",
            EffectCertainty::NotApplied,
            "the canary episode reached its endpoint with no durably journaled claim",
        )
    })
}

fn random_hex(byte_count: usize) -> Result<String, CgroupIoFailure> {
    let device_directory = Dir::open_ambient_dir("/dev", cap_std::ambient_authority())
        .map_err(|error| io_failure("open-device-directory", EffectCertainty::NotApplied, error))?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = device_directory
        .open_with("urandom", &options)
        .map_err(|error| io_failure("open-kernel-random", EffectCertainty::NotApplied, error))?;
    let mut bytes = vec![0u8; byte_count];
    file.read_exact(&mut bytes)
        .map_err(|error| io_failure("read-kernel-random", EffectCertainty::NotApplied, error))?;
    let mut output = String::with_capacity(byte_count.saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "half of a platform pair: the non-Linux arm returns a typed CgroupIoFailure, so the Result is the shared contract, not a redundant wrapper"
)]
fn ensure_linux_host() -> Result<(), CgroupIoFailure> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_linux_host() -> Result<(), CgroupIoFailure> {
    Err(failure(
        "open-linux-cgroup-io",
        EffectCertainty::NotApplied,
        "the retained cgroup-v2 backend is available only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn filesystem_magic(directory: &Dir) -> Result<u64, CgroupIoFailure> {
    let statistics = rustix::fs::fstatfs(directory).map_err(|error| {
        io_failure(
            "inspect-cgroup-filesystem",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    // The signed filesystem-magic value participates in exact equality; a
    // negative value cannot match an admitted filesystem.
    #[expect(
        clippy::cast_sign_loss,
        reason = "statfs f_type is an unsigned filesystem magic typed i64 by the Linux ABI; the only consumer is an exact magic equality"
    )]
    Ok(statistics.f_type as u64)
}

#[cfg(not(target_os = "linux"))]
fn filesystem_magic(_directory: &Dir) -> Result<u64, CgroupIoFailure> {
    Err(failure(
        "inspect-cgroup-filesystem",
        EffectCertainty::NotApplied,
        "cgroup-v2 filesystem identity is unavailable off Linux",
    ))
}

// The trusted installer writes `handoff-commitment.v1.json`, binding the
// plan, service roots, cgroup parent, and delegation readback. Each mint
// requires kernel denial of anchor writes and parent-directory creation.
// Ancestor ownership and capability checks prevent the runner from replacing
// the anchor; retained device/inode identities bind the committed directories.
// This authenticates the installer's output, not the installer's honesty.
// Inode reuse remains possible if an attacker can delete a committed directory;
// the trust model excludes writes to those installer-owned parents.

/// Packaging default for the installer root. Nothing in this crate reads it;
/// it exists so the layout has one written-down name rather than a convention.
const DEFAULT_LINUX_SERVICE_INSTALL_ROOT: &str = "/opt/grok-build/service";
const LINUX_SERVICE_INSTALL_ANCHOR_NAME: &str = "handoff-commitment.v1.json";
const LINUX_SERVICE_INSTALL_ANCHOR_TEMP_NAME: &str = "handoff-commitment.v1.tmp";
const LINUX_SERVICE_INSTALL_COMMITMENT_FORMAT_VERSION: u32 = 1;
const LINUX_SERVICE_INSTALL_COMMITMENT_DOMAIN: &[u8] =
    b"grok-build/linux-native-service-install-commitment/v1\0";
const MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES: usize = 8 * 1_024;
/// The anchor is read-only to everyone, including the installer, so a stray
/// write from the installing identity fails too rather than passing silently.
const LINUX_SERVICE_INSTALL_ANCHOR_MODE: u32 = 0o444;
const LINUX_SERVICE_STATE_ROOT_MODE: u32 = 0o700;
const LINUX_SERVICE_INSTALL_PROBE_PREFIX: &str = ".gb-anchor-probe-";
/// Linux `PROC_SUPER_MAGIC`; the credential read is refused unless the mount it
/// came from really is procfs.
const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
/// `CAP_CHOWN` | `CAP_DAC_OVERRIDE` | `CAP_DAC_READ_SEARCH` | `CAP_FOWNER`,
/// plus `CAP_SYS_ADMIN`. Each lets its holder either bypass the anchor's
/// permission bits or change them; holding any one of them in the permitted set
/// is enough, because a process may raise permitted bits into effective.
const FORBIDDEN_RUNNER_CAPABILITIES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 21);

/// Kernel-reported credentials of the process asking to consume an anchor.
///
/// Read from the process's own `/proc/<pid>/status` on a mount whose superblock
/// magic is checked, and cross-checked against `getuid`/`geteuid` so a forged
/// procfs would have to agree with the syscalls as well.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxRunnerCredentialObservation {
    pub(crate) real_uid: u32,
    pub(crate) effective_uid: u32,
    pub(crate) saved_uid: u32,
    pub(crate) filesystem_uid: u32,
    pub(crate) effective_capabilities: u64,
    pub(crate) permitted_capabilities: u64,
}

impl LinuxRunnerCredentialObservation {
    #[cfg(target_os = "linux")]
    fn observe(operation: &'static str) -> Result<Self, CgroupIoFailure> {
        let procfs = Dir::open_ambient_dir("/proc", cap_std::ambient_authority())
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        if filesystem_magic(&procfs)? != PROC_SUPER_MAGIC {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "/proc is not a procfs mount, so process credentials cannot be read",
            ));
        }
        let own_directory = procfs
            .open_dir_nofollow(std::process::id().to_string())
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let (status, _) = open_retained_nofollow_regular_file(&own_directory, "status", operation)?;
        let bytes = read_retained_bootstrap_file(&status, MAX_BOOTSTRAP_READBACK_BYTES, operation)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let uids = status_uid_line(text, operation)?;
        let observation = Self {
            real_uid: uids[0],
            effective_uid: uids[1],
            saved_uid: uids[2],
            filesystem_uid: uids[3],
            effective_capabilities: status_capability_line(text, "CapEff:", operation)?,
            permitted_capabilities: status_capability_line(text, "CapPrm:", operation)?,
        };
        if observation.real_uid != rustix::process::getuid().as_raw()
            || observation.effective_uid != rustix::process::geteuid().as_raw()
        {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "procfs status credentials disagree with the kernel's own getuid/geteuid answer",
            ));
        }
        Ok(observation)
    }

    /// Refuses every credential under which an on-disk anchor could not be
    /// unforgeable, before any anchor byte is read.
    fn require_cannot_bypass_file_permissions(
        &self,
        operation: &'static str,
    ) -> Result<(), CgroupIoFailure> {
        if self.real_uid == 0
            || self.effective_uid == 0
            || self.saved_uid == 0
            || self.filesystem_uid == 0
        {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "the runner holds uid 0 in one of its credential slots, so no on-disk anchor can be unforgeable by it",
            ));
        }
        if self.effective_capabilities & FORBIDDEN_RUNNER_CAPABILITIES != 0
            || self.permitted_capabilities & FORBIDDEN_RUNNER_CAPABILITIES != 0
        {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "the runner holds a capability that bypasses file ownership or permission checks",
            ));
        }
        Ok(())
    }

    fn owns(&self, owner_uid: u32) -> bool {
        owner_uid == self.real_uid
            || owner_uid == self.effective_uid
            || owner_uid == self.saved_uid
            || owner_uid == self.filesystem_uid
    }
}

fn status_uid_line(text: &str, operation: &'static str) -> Result<[u32; 4], CgroupIoFailure> {
    let invalid = || {
        failure(
            operation,
            EffectCertainty::NotApplied,
            "procfs status did not carry a canonical four-field Uid line",
        )
    };
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(invalid)?;
    let mut fields = line.split_ascii_whitespace();
    let mut uids = [0_u32; 4];
    for slot in &mut uids {
        *slot = fields
            .next()
            .ok_or_else(invalid)?
            .parse::<u32>()
            .map_err(|_| invalid())?;
    }
    if fields.next().is_some() {
        return Err(invalid());
    }
    Ok(uids)
}

fn status_capability_line(
    text: &str,
    prefix: &str,
    operation: &'static str,
) -> Result<u64, CgroupIoFailure> {
    let invalid = || {
        failure(
            operation,
            EffectCertainty::NotApplied,
            "procfs status did not carry a canonical 64-bit capability line",
        )
    };
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(invalid)?
        .trim();
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    u64::from_str_radix(value, 16).map_err(|_| invalid())
}

/// Exactly what the installer committed, and nothing the runner may choose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxNativeServiceInstallCommitmentV1 {
    pub(crate) format_version: u32,
    pub(crate) installer_uid: u32,
    pub(crate) service_state_root_path: String,
    pub(crate) service_cgroup_parent_path: String,
    pub(crate) delegation_name: String,
    pub(crate) delegation_subtree_control_readback: String,
    pub(crate) journal: LinuxProductionCommandPlanJournalBindingV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxNativeServiceInstallEnvelopeV1 {
    format_version: u32,
    commitment_sha256: Digest,
    commitment: LinuxNativeServiceInstallCommitmentV1,
}

fn service_install_commitment_digest(bytes: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(
        LINUX_SERVICE_INSTALL_COMMITMENT_DOMAIN.len() + std::mem::size_of::<u64>() + bytes.len(),
    );
    preimage.extend_from_slice(LINUX_SERVICE_INSTALL_COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(bytes);
    Digest::sha256(&preimage)
}

/// Every content rule the anchor must satisfy, independent of where it was
/// found. Location is checked separately; both must hold.
fn validate_service_install_commitment(
    commitment: &LinuxNativeServiceInstallCommitmentV1,
) -> Result<(), CgroupIoFailure> {
    let operation = "validate-linux-native-service-install-commitment";
    if commitment.format_version != LINUX_SERVICE_INSTALL_COMMITMENT_FORMAT_VERSION {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "native-service install commitment format version is unsupported",
        ));
    }
    let journal = &commitment.journal;
    if journal.owner_uid == 0 {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the committed runner identity is uid 0, which no anchor can constrain",
        ));
    }
    if commitment.installer_uid == journal.owner_uid {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the install commitment names the runner as its own installer, so it anchors nothing",
        ));
    }
    if digest_is_zero(&journal.authenticated_platform_service_digest)
        || journal.service_state_root_identity.device == 0
        || journal.service_state_root_identity.inode == 0
        || journal.singleton_journal_root_identity.device == 0
        || journal.singleton_journal_root_identity.inode == 0
        || journal.service_parent_identity.device == 0
        || journal.service_parent_identity.inode == 0
        || journal.delegation_identity.device == 0
        || journal.delegation_identity.inode == 0
        || journal.service_state_root_identity == journal.singleton_journal_root_identity
        || journal.service_parent_identity == journal.delegation_identity
        || journal.delegation_mode & !0o7777 != 0
        || journal.delegation_mode & 0o002 != 0
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "committed service, journal, cgroup parent, or delegation identities are not exact and distinct",
        ));
    }
    validate_component("native-service delegation", &commitment.delegation_name)?;
    executable_provenance_component_count(&commitment.service_state_root_path, operation)?;
    executable_provenance_component_count(&commitment.service_cgroup_parent_path, operation)?;
    if commitment.service_state_root_path == commitment.service_cgroup_parent_path {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the committed service-state root and cgroup parent are the same path",
        ));
    }
    let required = BTreeSet::from([DomainController::Memory, DomainController::Pids]);
    let enabled = parse_controller_set(
        commitment.delegation_subtree_control_readback.as_bytes(),
        true,
    )?;
    if enabled != required {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the installer did not commit an exact memory+pids delegation subtree-control readback",
        ));
    }
    Ok(())
}

fn encode_service_install_envelope(
    commitment: &LinuxNativeServiceInstallCommitmentV1,
) -> Result<Vec<u8>, CgroupIoFailure> {
    validate_service_install_commitment(commitment)?;
    let commitment_bytes = serde_json::to_vec(commitment).map_err(|error| {
        failure(
            "encode-linux-native-service-install-commitment",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let envelope = LinuxNativeServiceInstallEnvelopeV1 {
        format_version: LINUX_SERVICE_INSTALL_COMMITMENT_FORMAT_VERSION,
        commitment_sha256: service_install_commitment_digest(&commitment_bytes),
        commitment: commitment.clone(),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| {
        failure(
            "encode-linux-native-service-install-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if bytes.is_empty() || bytes.len() > MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES {
        return Err(failure(
            "encode-linux-native-service-install-envelope",
            EffectCertainty::NotApplied,
            "canonical native-service install commitment exceeded its byte bound",
        ));
    }
    Ok(bytes)
}

fn decode_service_install_envelope(
    bytes: &[u8],
) -> Result<LinuxNativeServiceInstallCommitmentV1, CgroupIoFailure> {
    let operation = "decode-linux-native-service-install-envelope";
    if bytes.is_empty() || bytes.len() > MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "native-service install envelope is empty or oversized",
        ));
    }
    let envelope: LinuxNativeServiceInstallEnvelopeV1 = serde_json::from_slice(bytes)
        .map_err(|error| failure(operation, EffectCertainty::NotApplied, error.to_string()))?;
    if envelope.format_version != LINUX_SERVICE_INSTALL_COMMITMENT_FORMAT_VERSION {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "native-service install envelope format version is unsupported",
        ));
    }
    validate_service_install_commitment(&envelope.commitment)?;
    let commitment_bytes = serde_json::to_vec(&envelope.commitment)
        .map_err(|error| failure(operation, EffectCertainty::NotApplied, error.to_string()))?;
    if envelope.commitment_sha256 != service_install_commitment_digest(&commitment_bytes) {
        return Err(failure(
            "authenticate-linux-native-service-install-envelope",
            EffectCertainty::NotApplied,
            "native-service install commitment digest differs from its canonical bytes",
        ));
    }
    let canonical = serde_json::to_vec(&envelope)
        .map_err(|error| failure(operation, EffectCertainty::NotApplied, error.to_string()))?;
    if canonical != bytes {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "native-service install commitment is not canonical JSON",
        ));
    }
    Ok(envelope.commitment)
}

/// One kernel refusal, recorded as the errno the kernel actually returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxAnchorForgeRefusalV1 {
    pub(crate) attempt: &'static str,
    pub(crate) errno: i32,
}

/// One directory of the anchor's retained no-follow chain, as observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxAnchorChainObservationV1 {
    pub(crate) name: String,
    pub(crate) owner_uid: u32,
    pub(crate) mode: u32,
}

/// Everything the mint established by reading the host, retained so a canary
/// can assert against kernel answers instead of against the mint's opinion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxNativeServiceInstallAnchorEvidenceV1 {
    pub(crate) credentials: LinuxRunnerCredentialObservation,
    pub(crate) anchor_absolute_path: String,
    pub(crate) anchor_identity: CgroupObjectIdentity,
    pub(crate) anchor_mount_id: u64,
    pub(crate) anchor_owner_uid: u32,
    pub(crate) anchor_mode: u32,
    pub(crate) anchor_link_count: u64,
    pub(crate) anchor_byte_length: u64,
    pub(crate) anchor_sha256: Digest,
    pub(crate) chain: Vec<LinuxAnchorChainObservationV1>,
    pub(crate) anchor_write_refusal: LinuxAnchorForgeRefusalV1,
    pub(crate) anchor_directory_create_refusal: LinuxAnchorForgeRefusalV1,
    pub(crate) delegation_subtree_control_readback: Vec<u8>,
}

/// The errno set a refusal may carry. `EACCES` and `EPERM` are the permission
/// answers; `EROFS` is admitted because a read-only mount refuses for the same
/// reason and with the same force.
fn require_permission_refusal(
    error: &std::io::Error,
    attempt: &'static str,
    operation: &'static str,
) -> Result<LinuxAnchorForgeRefusalV1, CgroupIoFailure> {
    let errno = error.raw_os_error().unwrap_or_default();
    let admitted = errno == rustix::io::Errno::ACCESS.raw_os_error()
        || errno == rustix::io::Errno::PERM.raw_os_error()
        || errno == rustix::io::Errno::ROFS.raw_os_error();
    if !admitted {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!("{attempt} failed with errno {errno}, which is not a permission refusal"),
        ));
    }
    Ok(LinuxAnchorForgeRefusalV1 { attempt, errno })
}

/// Attempts, for real, to open the anchor for writing. Success means the
/// running process could rewrite the commitment it is about to trust, so the
/// mint refuses instead of recording an assumption.
fn require_anchor_write_refused(
    parent: &Dir,
    name: &str,
    operation: &'static str,
) -> Result<LinuxAnchorForgeRefusalV1, CgroupIoFailure> {
    let mut options = OpenOptions::new();
    options.write(true).follow(FollowSymlinks::No);
    match parent.open_with(name, &options) {
        Ok(_) => Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the runner can open the install anchor for writing, so the anchor commits to nothing",
        )),
        Err(error) => require_permission_refusal(&error, "openat(anchor, O_WRONLY)", operation),
    }
}

/// Attempts, for real, to create a fresh entry beside the anchor. Directory
/// write permission is what `rename` and `unlink` need, so refusing this covers
/// replacement without ever attempting a destructive call on the anchor itself.
fn require_anchor_directory_create_refused(
    parent: &Dir,
    operation: &'static str,
) -> Result<LinuxAnchorForgeRefusalV1, CgroupIoFailure> {
    let name = format!("{LINUX_SERVICE_INSTALL_PROBE_PREFIX}{}", random_hex(16)?);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    match parent.open_with(&name, &options) {
        Ok(file) => {
            drop(file);
            // Leaving the probe entry behind would be litter inside a directory
            // this code has just proved it should not have been able to touch.
            let removal = parent.remove_file(&name);
            Err(failure(
                operation,
                EffectCertainty::NotApplied,
                match removal {
                    Ok(()) => "the runner can create entries beside the install anchor, so the anchor can be replaced".to_owned(),
                    Err(error) => format!(
                        "the runner can create entries beside the install anchor, and the probe entry {name} could not be removed: {error}"
                    ),
                },
            ))
        }
        Err(error) => require_permission_refusal(
            &error,
            "openat(anchor directory, O_CREAT|O_EXCL|O_WRONLY)",
            operation,
        ),
    }
}

fn require_installer_owned_directory(
    observation: &LinuxRetainedDirectoryObservation,
    credentials: &LinuxRunnerCredentialObservation,
    name: &str,
    operation: &'static str,
) -> Result<LinuxAnchorChainObservationV1, CgroupIoFailure> {
    if credentials.owns(observation.owner_uid) || observation.mode & 0o022 != 0 {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!(
                "install-anchor path component {name} is owned by the runner or writable outside its owner"
            ),
        ));
    }
    Ok(LinuxAnchorChainObservationV1 {
        name: name.to_owned(),
        owner_uid: observation.owner_uid,
        mode: observation.mode,
    })
}

/// Retained proof that one normalized absolute *directory* name still resolves
/// through the same no-follow chain, mirroring the executable provenance type
/// whose final component is a regular file.
#[derive(Debug)]
struct LinuxRetainedDirectoryPathProvenance {
    absolute_path: String,
    root: Dir,
    root_observation: LinuxRetainedDirectoryObservation,
    parents: Vec<LinuxRetainedDirectoryComponent>,
    final_name: String,
    directory: Dir,
    observation: LinuxRetainedDirectoryObservation,
}

impl LinuxRetainedDirectoryPathProvenance {
    fn open_absolute(
        absolute_path: &str,
        operation: &'static str,
    ) -> Result<Self, CgroupIoFailure> {
        let components = normalized_executable_provenance_components(absolute_path, operation)?;
        let (final_name, parent_names) = components.split_last().ok_or_else(|| {
            failure(
                operation,
                EffectCertainty::NotApplied,
                "install commitment path does not name a directory",
            )
        })?;
        let root = Dir::open_ambient_dir("/", cap_std::ambient_authority())
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let root_observation = LinuxRetainedDirectoryObservation::observe(&root, operation)?;
        let mut current = root
            .try_clone()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let mut parents = Vec::with_capacity(parent_names.len());
        for name in parent_names {
            let directory = current
                .open_dir_nofollow(name)
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
            let observation = LinuxRetainedDirectoryObservation::observe(&directory, operation)?;
            current = directory
                .try_clone()
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
            parents.push(LinuxRetainedDirectoryComponent {
                name: name.clone(),
                directory,
                observation,
            });
        }
        let directory = current
            .open_dir_nofollow(final_name)
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let observation = LinuxRetainedDirectoryObservation::observe(&directory, operation)?;
        require_named_identity(&current, final_name, observation.identity, operation)?;
        Ok(Self {
            absolute_path: absolute_path.to_owned(),
            root,
            root_observation,
            parents,
            final_name: final_name.clone(),
            directory,
            observation,
        })
    }

    fn validate_named(&self, operation: &'static str) -> Result<(), CgroupIoFailure> {
        let retained_root = LinuxRetainedDirectoryObservation::observe(&self.root, operation)?;
        if retained_root != self.root_observation {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "install commitment path root identity, metadata, or mount changed",
            ));
        }
        let mut current = self
            .root
            .try_clone()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        for component in &self.parents {
            let named = current
                .open_dir_nofollow(&component.name)
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
            if LinuxRetainedDirectoryObservation::observe(&named, operation)?
                != component.observation
                || LinuxRetainedDirectoryObservation::observe(&component.directory, operation)?
                    != component.observation
            {
                return Err(failure(
                    operation,
                    EffectCertainty::NotApplied,
                    "install commitment path parent was renamed, replaced, or mount-crossed",
                ));
            }
            current = component
                .directory
                .try_clone()
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        }
        if LinuxRetainedDirectoryObservation::observe(&self.directory, operation)?
            != self.observation
        {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "install commitment directory identity, metadata, or mount changed",
            ));
        }
        require_named_identity(
            &current,
            &self.final_name,
            self.observation.identity,
            operation,
        )
    }
}

/// Requires the delegation's `cgroup.subtree_control` to contain exactly
/// `memory` and `pids` before handoff, so child-leaf probes have both controllers.
#[cfg(target_os = "linux")]
fn require_delegated_subtree_control(
    service_parent: &Dir,
    commitment: &LinuxNativeServiceInstallCommitmentV1,
    operation: &'static str,
) -> Result<Vec<u8>, CgroupIoFailure> {
    let delegation = service_parent
        .open_dir_nofollow(&commitment.delegation_name)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if filesystem_magic(&delegation)? != CGROUP2_SUPER_MAGIC {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the committed delegation is not on a cgroup-v2 mount",
        ));
    }
    let metadata = delegation
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    validate_delegation_metadata(
        &metadata,
        DelegationRootExpectation {
            service_parent_identity: commitment.journal.service_parent_identity,
            delegation_identity: commitment.journal.delegation_identity,
            owner_uid: commitment.journal.owner_uid,
            delegation_mode: commitment.journal.delegation_mode,
        },
    )?;
    let (subtree_control, _) = open_retained_nofollow_regular_file(
        &delegation,
        DelegationFile::SubtreeControl.name(),
        operation,
    )?;
    let bytes =
        read_retained_bootstrap_file(&subtree_control, MAX_BOOTSTRAP_READBACK_BYTES, operation)?;
    let required = BTreeSet::from([DomainController::Memory, DomainController::Pids]);
    if parse_controller_set(&bytes, true)? != required {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the delegated cgroup does not enable exactly memory+pids for its children",
        ));
    }
    if bytes != commitment.delegation_subtree_control_readback.as_bytes() {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the live delegation subtree-control readback differs from the installed commitment",
        ));
    }
    Ok(bytes)
}

/// Production mint for [`PendingLinuxNativeServiceAuthenticatedHandoff`].
///
/// Consumes an installer-written anchor and the descriptors it names. Every
/// refusal below is a kernel observation, not a configuration flag; the mint
/// never accepts a commitment on the strength of the runner's own assertion
/// about itself.
///
/// The returned handoff is not yet authority. `into_state_root_capability` still
/// has to find that the commitment equals the exact plan journal binding, that
/// the running executable matches the committed service digest, and that every
/// retained descriptor still has the committed identity.
#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_lines,
    reason = "one linear anchor audit keeps every credential, ownership, forge-attempt, and identity refusal visible in the order it happens"
)]
fn open_installed_linux_native_service_handoff(
    installer_root: &str,
) -> Result<
    (
        PendingLinuxNativeServiceAuthenticatedHandoff,
        LinuxNativeServiceInstallAnchorEvidenceV1,
    ),
    CgroupIoFailure,
> {
    let operation = "open-linux-native-service-install-anchor";
    let credentials = LinuxRunnerCredentialObservation::observe(operation)?;
    credentials.require_cannot_bypass_file_permissions(operation)?;

    executable_provenance_component_count(installer_root, operation)?;
    let anchor_absolute_path = format!("{installer_root}/{LINUX_SERVICE_INSTALL_ANCHOR_NAME}");
    let provenance =
        LinuxRetainedExecutablePathProvenance::open_absolute(&anchor_absolute_path, operation)?;

    let mut chain = vec![require_installer_owned_directory(
        &provenance.root_observation,
        &credentials,
        "/",
        operation,
    )?];
    for component in &provenance.parents {
        chain.push(require_installer_owned_directory(
            &component.observation,
            &credentials,
            &component.name,
            operation,
        )?);
    }

    let metadata = provenance
        .file
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let anchor_owner_uid = OsMetadataExt::uid(&metadata);
    let anchor_mode = OsMetadataExt::mode(&metadata);
    let anchor_link_count = PortableMetadataExt::nlink(&metadata);
    let anchor_byte_length = metadata.len();
    if !metadata.is_file()
        || credentials.owns(anchor_owner_uid)
        || anchor_mode & 0o022 != 0
        || anchor_mode & 0o111 != 0
        || anchor_link_count != 1
        || anchor_byte_length == 0
        || anchor_byte_length > MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES as u64
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the install anchor is not a singly linked, runner-unowned, non-executable, owner-write-only regular file of bounded size",
        ));
    }

    let anchor_directory = provenance
        .parents
        .last()
        .map_or(&provenance.root, |component| &component.directory);
    let anchor_write_refusal =
        require_anchor_write_refused(anchor_directory, &provenance.final_name, operation)?;
    let anchor_directory_create_refusal =
        require_anchor_directory_create_refused(anchor_directory, operation)?;

    let bytes = read_retained_bootstrap_file(
        &provenance.file,
        MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES,
        operation,
    )?;
    let commitment = decode_service_install_envelope(&bytes)?;

    // The forge attempts and the decode both took time. Re-walk the whole chain
    // and re-read the bytes so a swap during validation is refused rather than
    // straddled.
    provenance.validate_named(operation)?;
    let reread = read_retained_bootstrap_file(
        &provenance.file,
        MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES,
        operation,
    )?;
    if reread != bytes {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the install anchor changed between its first and second complete readback",
        ));
    }

    if commitment.installer_uid != anchor_owner_uid {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the install anchor is owned by an identity other than the installer it names",
        ));
    }
    if commitment.journal.owner_uid != credentials.effective_uid {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the install anchor commits to a different runner identity than this process holds",
        ));
    }

    let state_root = LinuxRetainedDirectoryPathProvenance::open_absolute(
        &commitment.service_state_root_path,
        operation,
    )?;
    let service_parent = LinuxRetainedDirectoryPathProvenance::open_absolute(
        &commitment.service_cgroup_parent_path,
        operation,
    )?;
    if cgroup_identity(state_root.observation.identity)
        != commitment.journal.service_state_root_identity
        || cgroup_identity(service_parent.observation.identity)
            != commitment.journal.service_parent_identity
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "a committed absolute name resolved to a different filesystem object than the anchor committed",
        ));
    }
    let delegation_subtree_control_readback =
        require_delegated_subtree_control(&service_parent.directory, &commitment, operation)?;
    state_root.validate_named(operation)?;
    service_parent.validate_named(operation)?;

    let service_process_image = LinuxNativeServiceProcessImageAuthority::observe_current_process()?;

    let evidence = LinuxNativeServiceInstallAnchorEvidenceV1 {
        credentials,
        anchor_absolute_path: provenance.absolute_path.clone(),
        anchor_identity: cgroup_identity(provenance.file_identity),
        anchor_mount_id: provenance.file_mount_id,
        anchor_owner_uid,
        anchor_mode,
        anchor_link_count,
        anchor_byte_length,
        anchor_sha256: Digest::sha256(&bytes),
        chain,
        anchor_write_refusal,
        anchor_directory_create_refusal,
        delegation_subtree_control_readback,
    };
    let handoff = PendingLinuxNativeServiceAuthenticatedHandoff {
        service_process_image,
        service_state_root: state_root.directory,
        service_parent: service_parent.directory,
        delegation_name: commitment.delegation_name,
        external_commitment: LinuxNativeServiceHandoffCommitmentV1 {
            installer_uid: commitment.installer_uid,
            journal: commitment.journal,
        },
    };
    Ok((handoff, evidence))
}

/// Everything an installing identity must decide. The runner never supplies
/// any of it.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(crate) struct LinuxNativeServiceInstallRequestV1<'a> {
    pub(crate) installer_root: &'a str,
    pub(crate) service_state_root_path: &'a str,
    pub(crate) service_cgroup_parent_path: &'a str,
    pub(crate) delegation_name: &'a str,
    pub(crate) runner_uid: u32,
    pub(crate) runner_gid: u32,
    pub(crate) delegation_mode: u32,
    pub(crate) authenticated_platform_service_digest: Digest,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxNativeServiceInstallReceiptV1 {
    pub(crate) anchor_absolute_path: String,
    pub(crate) anchor_identity: CgroupObjectIdentity,
    pub(crate) anchor_sha256: Digest,
    pub(crate) anchor_byte_length: u64,
    pub(crate) commitment: LinuxNativeServiceInstallCommitmentV1,
}

/// Writes the external anchor, from an identity that is not the runner's.
///
/// This is the installer side of route 1 item 1. It performs the host
/// modifications a package's post-install step owes -- delegating the cgroup,
/// enabling `+memory +pids` on it, giving the runner its private state root --
/// and then commits the resulting identities to a file the runner cannot write.
///
/// It refuses to run as the runner. An installer that shares the runner's
/// identity produces an artifact the runner could have produced, which is the
/// thing this whole file exists to rule out.
#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_lines,
    reason = "one linear install sequence: delegate, enable controllers, hand over the state root, commit, verify"
)]
pub(crate) fn install_linux_native_service_handoff(
    request: &LinuxNativeServiceInstallRequestV1<'_>,
) -> Result<LinuxNativeServiceInstallReceiptV1, CgroupIoFailure> {
    let operation = "install-linux-native-service-handoff";
    let installer = LinuxRunnerCredentialObservation::observe(operation)?;
    if request.runner_uid == 0 || installer.owns(request.runner_uid) {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the installer shares the runner identity it is installing for, or the runner is uid 0",
        ));
    }
    validate_component("native-service delegation", request.delegation_name)?;

    let install_root = LinuxRetainedDirectoryPathProvenance::open_absolute(
        request.installer_root,
        "open-linux-native-service-install-root",
    )?;
    if install_root.observation.owner_uid != installer.effective_uid
        || install_root.observation.mode & 0o022 != 0
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the install root is not owned by the installing identity or is writable outside it",
        ));
    }

    // Hand the runner its private state root and the singleton journal root.
    let state_root = LinuxRetainedDirectoryPathProvenance::open_absolute(
        request.service_state_root_path,
        "open-linux-native-service-state-root",
    )?;
    chown_to_runner(&state_root.directory, ".", request, operation)?;
    chmod_directory(
        &state_root.directory,
        LINUX_SERVICE_STATE_ROOT_MODE,
        operation,
    )?;
    if state_root
        .directory
        .symlink_metadata(SERVICE_COMMAND_JOURNAL_DIRECTORY)
        .is_err()
    {
        let mut builder = DirBuilder::new();
        builder.mode(LINUX_SERVICE_STATE_ROOT_MODE);
        state_root
            .directory
            .create_dir_with(SERVICE_COMMAND_JOURNAL_DIRECTORY, &builder)
            .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    }
    let journal_root = state_root
        .directory
        .open_dir_nofollow(SERVICE_COMMAND_JOURNAL_DIRECTORY)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    chown_to_runner(&journal_root, ".", request, operation)?;
    chmod_directory(&journal_root, LINUX_SERVICE_STATE_ROOT_MODE, operation)?;

    // Delegate the cgroup and enable the controller set the durable preflight
    // probe requires before `prepare_domain` ever runs.
    let service_parent = LinuxRetainedDirectoryPathProvenance::open_absolute(
        request.service_cgroup_parent_path,
        "open-linux-native-service-cgroup-parent",
    )?;
    if filesystem_magic(&service_parent.directory)? != CGROUP2_SUPER_MAGIC {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the service cgroup parent is not on a cgroup-v2 mount",
        ));
    }
    if service_parent
        .directory
        .symlink_metadata(request.delegation_name)
        .is_err()
    {
        service_parent
            .directory
            .create_dir(request.delegation_name)
            .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    }
    let delegation = service_parent
        .directory
        .open_dir_nofollow(request.delegation_name)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    chmod_directory(&delegation, request.delegation_mode, operation)?;
    chown_to_runner(&delegation, ".", request, operation)?;
    for name in [
        DelegationFile::Procs.name(),
        DelegationFile::SubtreeControl.name(),
    ] {
        chown_to_runner(&delegation, name, request, operation)?;
    }
    write_delegation_subtree_control(&delegation, operation)?;
    let (subtree_control, _) = open_retained_nofollow_regular_file(
        &delegation,
        DelegationFile::SubtreeControl.name(),
        operation,
    )?;
    let readback =
        read_retained_bootstrap_file(&subtree_control, MAX_BOOTSTRAP_READBACK_BYTES, operation)?;
    let required = BTreeSet::from([DomainController::Memory, DomainController::Pids]);
    if parse_controller_set(&readback, true)? != required {
        return Err(failure(
            operation,
            EffectCertainty::Ambiguous,
            "the delegated cgroup did not read back exactly memory+pids after the install write",
        ));
    }
    let delegation_subtree_control_readback = String::from_utf8(readback)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error.utf8_error()))?;

    let journal_root_identity = observed_identity(&journal_root, operation)?;
    let delegation_identity = observed_identity(&delegation, operation)?;
    let state_root_identity = observed_identity(&state_root.directory, operation)?;
    let commitment = LinuxNativeServiceInstallCommitmentV1 {
        format_version: LINUX_SERVICE_INSTALL_COMMITMENT_FORMAT_VERSION,
        installer_uid: installer.effective_uid,
        service_state_root_path: state_root.absolute_path.clone(),
        service_cgroup_parent_path: service_parent.absolute_path.clone(),
        delegation_name: request.delegation_name.to_owned(),
        delegation_subtree_control_readback,
        journal: LinuxProductionCommandPlanJournalBindingV1 {
            authenticated_platform_service_digest: request
                .authenticated_platform_service_digest
                .clone(),
            service_state_root_identity: cgroup_identity(state_root_identity),
            singleton_journal_root_identity: cgroup_identity(journal_root_identity),
            service_parent_identity: cgroup_identity(service_parent.observation.identity),
            delegation_identity: cgroup_identity(delegation_identity),
            owner_uid: request.runner_uid,
            delegation_mode: request.delegation_mode,
        },
    };
    let bytes = encode_service_install_envelope(&commitment)?;
    write_install_anchor(&install_root.directory, &bytes, operation)?;

    let (anchor, anchor_identity) = open_retained_nofollow_regular_file(
        &install_root.directory,
        LINUX_SERVICE_INSTALL_ANCHOR_NAME,
        operation,
    )?;
    let metadata = anchor
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    let written = read_retained_bootstrap_file(
        &anchor,
        MAX_LINUX_SERVICE_INSTALL_COMMITMENT_BYTES,
        operation,
    )?;
    if written != bytes
        || OsMetadataExt::uid(&metadata) != installer.effective_uid
        || OsMetadataExt::mode(&metadata) & 0o7777 != LINUX_SERVICE_INSTALL_ANCHOR_MODE
        || PortableMetadataExt::nlink(&metadata) != 1
        || decode_service_install_envelope(&written)? != commitment
    {
        return Err(failure(
            operation,
            EffectCertainty::Ambiguous,
            "the installed anchor did not read back as the exact bytes, owner, mode, or commitment written",
        ));
    }
    Ok(LinuxNativeServiceInstallReceiptV1 {
        anchor_absolute_path: format!(
            "{}/{LINUX_SERVICE_INSTALL_ANCHOR_NAME}",
            install_root.absolute_path
        ),
        anchor_identity: cgroup_identity(anchor_identity),
        anchor_sha256: Digest::sha256(&bytes),
        anchor_byte_length: metadata.len(),
        commitment,
    })
}

#[cfg(target_os = "linux")]
fn observed_identity(
    directory: &Dir,
    operation: &'static str,
) -> Result<ObjectIdentity, CgroupIoFailure> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    Ok(object_identity(&metadata))
}

#[cfg(target_os = "linux")]
fn chown_to_runner(
    parent: &Dir,
    name: &str,
    request: &LinuxNativeServiceInstallRequestV1<'_>,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    rustix::fs::chownat(
        parent,
        name,
        Some(rustix::process::Uid::from_raw(request.runner_uid)),
        Some(rustix::process::Gid::from_raw(request.runner_gid)),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))
}

#[cfg(target_os = "linux")]
fn chmod_directory(
    directory: &Dir,
    mode: u32,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    rustix::fs::chmodat(
        directory,
        ".",
        rustix::fs::Mode::from_bits_truncate(mode),
        rustix::fs::AtFlags::empty(),
    )
    .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))
}

#[cfg(target_os = "linux")]
fn write_delegation_subtree_control(
    delegation: &Dir,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let mut options = OpenOptions::new();
    options.write(true).follow(FollowSymlinks::No);
    let mut file = delegation
        .open_with(DelegationFile::SubtreeControl.name(), &options)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    file.write_all(b"+memory +pids\n")
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))
}

/// The retained plan identities an installed Linux native service owns, minted
/// from live kernel reads.
///
/// This is the production source for the parts of
/// `LinuxProductionCommandPlanComponentsV1` that can only come from installed
/// state. Every field below was read from a descriptor this process already
/// held and was then required to equal what the installer externally
/// committed; none of it is a value the runner chose.
///
/// It is deliberately not a complete components value. Five of the twelve
/// components have no production source yet.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxProductionPlanAnchoredFactsV1 {
    pub(crate) service_state_root: LinuxRetainedObjectIdentityV1,
    pub(crate) singleton_journal_root: LinuxRetainedObjectIdentityV1,
    pub(crate) service_cgroup_parent: LinuxRetainedObjectIdentityV1,
    pub(crate) cgroup_delegation_root: LinuxRetainedObjectIdentityV1,
    /// `fstatfs` on the retained delegation descriptor, not a plan constant.
    pub(crate) cgroup_filesystem_magic: u64,
    /// The running service image, which is also the plan's inner-launcher
    /// image because the held launcher is a mode of this same executable.
    pub(crate) service_image: LinuxAuthenticatedFileV1,
    pub(crate) service_image_object: LinuxRetainedObjectIdentityV1,
    pub(crate) authenticated_platform_service_digest: Digest,
    /// The measured machine architecture of this host.
    ///
    /// Schema version 2 of the plan can describe two architectures, so a plan
    /// used here must be required to describe *this* one. The value comes from
    /// the running image's own ELF header and the kernel's `uname(2)`, which
    /// must agree; nothing here consults a build-time constant.
    pub(crate) host_architecture: LinuxHostMachineArchitectureFactV1,
}

#[cfg(target_os = "linux")]
impl LinuxProductionPlanAnchoredFactsV1 {
    /// Projects the anchored installed state into the statement one sealed
    /// setup channel commits to.
    ///
    /// This is the route the setup channel's content takes out of the installer
    /// anchor: every identity below was read from a descriptor this process
    /// held and was then required to equal what the installer externally
    /// committed, so the digest a plan takes over the encoding is a digest of
    /// externally anchored state rather than of values the runner chose.
    ///
    /// `role` and `input_snapshot` come from the durable command-effect
    /// authority, which is the only per-command input; everything else is
    /// per-service and identical across the commands one installed service
    /// runs.
    /// Projects the anchored installed state into the form the production
    /// components mint consumes.
    ///
    /// This is the one-method bridge that keeps
    /// `LinuxProductionCommandPlanInputsV1` portable: this type is
    /// `cfg(target_os = "linux")`, so a mint that took it directly could not be
    /// proved on a host with no Linux kernel in front of it. Every field is a
    /// borrow — nothing is re-derived here, so the mint cannot see a value the
    /// anchor did not already require to equal the installer's commitment.
    pub(crate) fn plan_anchored_facts(&self) -> LinuxAnchoredServiceFactsV1<'_> {
        LinuxAnchoredServiceFactsV1 {
            service_state_root: &self.service_state_root,
            singleton_journal_root: &self.singleton_journal_root,
            service_cgroup_parent: &self.service_cgroup_parent,
            cgroup_delegation_root: &self.cgroup_delegation_root,
            cgroup_filesystem_magic: self.cgroup_filesystem_magic,
            service_image: &self.service_image,
            service_image_object: &self.service_image_object,
            authenticated_platform_service_digest: &self.authenticated_platform_service_digest,
            host_architecture: self.host_architecture.architecture(),
        }
    }

    pub(crate) fn setup_channel_statement<'facts>(
        &'facts self,
        role: crate::wire::RunnerRole,
        input_snapshot: &'facts Digest,
    ) -> LinuxSetupChannelStatementV1<'facts> {
        LinuxSetupChannelStatementV1 {
            role,
            input_snapshot,
            host_architecture: self.host_architecture.architecture(),
            cgroup_filesystem_magic: self.cgroup_filesystem_magic,
            authenticated_platform_service_digest: &self.authenticated_platform_service_digest,
            service_state_root: &self.service_state_root,
            singleton_journal_root: &self.singleton_journal_root,
            service_cgroup_parent: &self.service_cgroup_parent,
            cgroup_delegation_root: &self.cgroup_delegation_root,
        }
    }
}

/// Reads the running service image's ELF header and the kernel's machine name.
///
/// The read is positional (`pread` at offset 0) and exactly
/// `LINUX_ELF_HEADER_PREFIX_BYTES` long, so it neither disturbs the retained
/// descriptor's file offset nor reads any part of the image the question does
/// not need.
#[cfg(target_os = "linux")]
fn observe_host_machine_architecture(
    image: &LinuxNativeServiceProcessImageAuthority,
    operation: &'static str,
) -> Result<LinuxHostMachineArchitectureFactV1, CgroupIoFailure> {
    let mut header = [0u8; LINUX_ELF_HEADER_PREFIX_BYTES];
    let mut filled = 0;
    while filled < header.len() {
        let read = rustix::io::pread(&image.file, &mut header[filled..], filled as u64)
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        if read == 0 {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "the retained service image is shorter than an ELF header",
            ));
        }
        filled = filled.saturating_add(read);
    }
    let kernel = rustix::system::uname();
    let kernel_machine = kernel.machine().to_str().map_err(|_| {
        failure(
            operation,
            EffectCertainty::NotApplied,
            "the kernel's uname machine name is not UTF-8",
        )
    })?;
    LinuxHostMachineArchitectureFactV1::from_measurements(&header, kernel_machine)
        .map_err(|error| plan_mint_failure(operation, &error))
}

/// Reads a leaf that `prepare_domain` has already created, through the
/// retained delegation descriptor.
///
/// This is the production source for the identity the plan deliberately does
/// not name. It is not constructible from plan data: every value comes from an
/// `openat`/`statx` on the delegation's own descriptor, each name is
/// re-resolved and required to answer with the same inode, and a name outside
/// the grammar `prepare_domain` mints is refused before anything is opened.
#[cfg(target_os = "linux")]
fn observe_prepared_command_domain_leaf(
    delegation: &Dir,
    leaf_name: &str,
    operation: &'static str,
) -> Result<LinuxPreparedCommandDomainLeafObservationV1, CgroupIoFailure> {
    validate_component("cgroup leaf", leaf_name)?;
    if !crate::linux_containment::is_domain_leaf_name(leaf_name) {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the named directory is not a name prepare_domain could have minted",
        ));
    }
    let leaf = delegation
        .open_dir_nofollow(leaf_name)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if filesystem_magic(&leaf)? != CGROUP2_SUPER_MAGIC {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the prepared leaf is not on a cgroup-v2 mount",
        ));
    }
    let identity = observe_retained_directory_identity(
        &leaf,
        COMMAND_DOMAIN_LEAF_OBJECT_ID,
        LinuxRetainedObjectKindV1::CgroupDirectory,
        operation,
    )?;
    let observed = identity.kernel_observation();
    require_named_cgroup_identity(
        delegation,
        leaf_name,
        CgroupObjectIdentity {
            device: observed.device_id,
            inode: observed.inode,
        },
        operation,
    )?;
    let mut control_files = Vec::with_capacity(LinuxCommandDomainControlFileV1::REQUIRED.len());
    for file in LinuxCommandDomainControlFileV1::REQUIRED {
        control_files.push(LinuxObservedCommandDomainControlFileV1 {
            file,
            identity: observe_leaf_control_file_identity(&leaf, file, operation)?,
        });
    }
    Ok(LinuxPreparedCommandDomainLeafObservationV1 {
        leaf_name: leaf_name.to_owned(),
        leaf: identity,
        control_files,
    })
}

#[cfg(target_os = "linux")]
fn observe_leaf_control_file_identity(
    leaf: &Dir,
    file: LinuxCommandDomainControlFileV1,
    operation: &'static str,
) -> Result<LinuxRetainedObjectIdentityV1, CgroupIoFailure> {
    let name = file.name();
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let handle = leaf
        .open_with(name, &options)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let metadata = handle
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_file() {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "a prepared leaf control file is not a regular file",
        ));
    }
    let identity = object_identity(&metadata);
    require_named_identity(leaf, name, identity, operation)?;
    let observed = LinuxKernelObjectObservationV1 {
        device_id: identity.device,
        inode: identity.inode,
        mount_id: retained_file_mount_id(&handle, operation)?,
        mode: OsMetadataExt::mode(&metadata),
        owner_uid: OsMetadataExt::uid(&metadata),
        owner_gid: OsMetadataExt::gid(&metadata),
        link_count: PortableMetadataExt::nlink(&metadata),
        byte_length: None,
    };
    LinuxRetainedObjectIdentityV1::from_kernel_observation(
        command_domain_control_file_object_id(file),
        LinuxRetainedObjectKindV1::CgroupControlFile,
        observed,
    )
    .map_err(|error| plan_mint_failure(operation, &error))
}

/// Plan-internal role name for the leaf a runtime binding carries.
#[cfg(target_os = "linux")]
const COMMAND_DOMAIN_LEAF_OBJECT_ID: &str = "command-domain-leaf";

#[cfg(target_os = "linux")]
const fn command_domain_control_file_object_id(
    file: LinuxCommandDomainControlFileV1,
) -> &'static str {
    match file {
        LinuxCommandDomainControlFileV1::CgroupProcs => "command-domain-leaf-cgroup-procs",
        LinuxCommandDomainControlFileV1::CgroupEvents => "command-domain-leaf-cgroup-events",
        LinuxCommandDomainControlFileV1::CgroupKill => "command-domain-leaf-cgroup-kill",
    }
}

#[cfg(target_os = "linux")]
fn plan_mint_failure(
    operation: &'static str,
    error: &LinuxProductionCommandPlanError,
) -> CgroupIoFailure {
    failure(
        operation,
        EffectCertainty::NotApplied,
        format!("observed retained identity is not admissible plan data: {error}"),
    )
}

/// Reads one retained directory descriptor and mints the plan identity for it.
///
/// The `mount_id`, `mode`, `owner_gid` and `link_count` in the result are not
/// present in the installer's commitment at all, so a caller can show that the
/// value carries information no anchor could have supplied.
#[cfg(target_os = "linux")]
fn observe_retained_directory_identity(
    directory: &Dir,
    object_id: &str,
    kind: LinuxRetainedObjectKindV1,
    operation: &'static str,
) -> Result<LinuxRetainedObjectIdentityV1, CgroupIoFailure> {
    // One reader of a held directory descriptor in this module, shared with the
    // per-command directories: two readers could disagree about what a
    // directory answered, and a plan built from one could then be checked
    // against the other.
    let observed = observe_directory_kernel_facts(directory, operation)?;
    LinuxRetainedObjectIdentityV1::from_kernel_observation(object_id, kind, observed)
        .map_err(|error| plan_mint_failure(operation, &error))
}

#[cfg(target_os = "linux")]
fn require_committed_identity(
    identity: &LinuxRetainedObjectIdentityV1,
    expected: CgroupObjectIdentity,
    field: &'static str,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let observed = identity.kernel_observation();
    let live = CgroupObjectIdentity {
        device: observed.device_id,
        inode: observed.inode,
    };
    if live != expected {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!("the live {field} identity differs from the externally committed one"),
        ));
    }
    Ok(())
}

/// Authenticates installed plan identities by comparing this process's kernel
/// observations with the installer anchor. Neither input substitutes for the other.
#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_lines,
    reason = "one linear audit keeps every anchored role, its live read, and its cross-check against the installer's commitment visible in the order they happen"
)]
fn observe_anchored_production_plan_facts(
    service_process_image: &LinuxNativeServiceProcessImageAuthority,
    service_state_root: &Dir,
    service_parent: &Dir,
    delegation_name: &str,
    installer_uid: u32,
    committed: &LinuxProductionCommandPlanJournalBindingV1,
) -> Result<LinuxProductionPlanAnchoredFactsV1, CgroupIoFailure> {
    let operation = "observe-anchored-linux-production-plan-facts";
    validate_component("native-service delegation", delegation_name)?;

    let state_root_identity = observe_retained_directory_identity(
        service_state_root,
        SERVICE_STATE_ROOT_OBJECT_ID,
        LinuxRetainedObjectKindV1::Directory,
        operation,
    )?;
    require_committed_identity(
        &state_root_identity,
        committed.service_state_root_identity,
        "service-state root",
        operation,
    )?;
    let state_metadata = service_state_root
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    validate_private_directory(&state_metadata, committed.owner_uid)?;

    let journal_directory = service_state_root
        .open_dir_nofollow(SERVICE_COMMAND_JOURNAL_DIRECTORY)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let journal_identity = observe_retained_directory_identity(
        &journal_directory,
        SINGLETON_JOURNAL_ROOT_OBJECT_ID,
        LinuxRetainedObjectKindV1::Directory,
        operation,
    )?;
    require_committed_identity(
        &journal_identity,
        committed.singleton_journal_root_identity,
        "singleton journal root",
        operation,
    )?;
    let journal_metadata = journal_directory
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    validate_private_directory(&journal_metadata, committed.owner_uid)?;
    require_named_identity(
        service_state_root,
        SERVICE_COMMAND_JOURNAL_DIRECTORY,
        object_identity(&journal_metadata),
        operation,
    )?;

    if filesystem_magic(service_parent)? != CGROUP2_SUPER_MAGIC {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the retained service cgroup parent is not on a cgroup-v2 mount",
        ));
    }
    let parent_identity = observe_retained_directory_identity(
        service_parent,
        SERVICE_CGROUP_PARENT_OBJECT_ID,
        LinuxRetainedObjectKindV1::CgroupDirectory,
        operation,
    )?;
    require_committed_identity(
        &parent_identity,
        committed.service_parent_identity,
        "service cgroup parent",
        operation,
    )?;
    // Require the cgroup parent's owner to match the anchor's installer UID,
    // not merely to differ from the runner UID.
    let parent_observation = parent_identity.kernel_observation();
    if parent_observation.owner_uid != installer_uid || parent_observation.mode & 0o022 != 0 {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the service cgroup parent is not owned by the installing delegator, or is writable outside it",
        ));
    }

    let delegation = service_parent
        .open_dir_nofollow(delegation_name)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let cgroup_filesystem_magic = filesystem_magic(&delegation)?;
    if cgroup_filesystem_magic != CGROUP2_SUPER_MAGIC {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the retained delegation is not on a cgroup-v2 mount",
        ));
    }
    let delegation_identity = observe_retained_directory_identity(
        &delegation,
        CGROUP_DELEGATION_ROOT_OBJECT_ID,
        LinuxRetainedObjectKindV1::CgroupDirectory,
        operation,
    )?;
    require_committed_identity(
        &delegation_identity,
        committed.delegation_identity,
        "cgroup delegation root",
        operation,
    )?;
    let delegation_metadata = delegation
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    validate_delegation_metadata(
        &delegation_metadata,
        DelegationRootExpectation {
            service_parent_identity: committed.service_parent_identity,
            delegation_identity: committed.delegation_identity,
            owner_uid: committed.owner_uid,
            delegation_mode: committed.delegation_mode,
        },
    )?;
    require_named_cgroup_identity(
        service_parent,
        delegation_name,
        committed.delegation_identity,
        operation,
    )?;

    let (service_image, service_image_object) =
        observe_service_image_plan_identity(service_process_image, operation)?;
    if service_image.content_sha256() != &committed.authenticated_platform_service_digest {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the running service image differs from the externally committed service digest",
        ));
    }

    let identities = [
        &state_root_identity,
        &journal_identity,
        &parent_identity,
        &delegation_identity,
        &service_image_object,
    ]
    .map(|identity| {
        let observed = identity.kernel_observation();
        (observed.device_id, observed.inode)
    });
    let distinct = identities.iter().collect::<BTreeSet<_>>();
    if distinct.len() != identities.len() {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "two retained plan roles resolved to one kernel inode",
        ));
    }

    let host_architecture = observe_host_machine_architecture(service_process_image, operation)?;

    Ok(LinuxProductionPlanAnchoredFactsV1 {
        service_state_root: state_root_identity,
        singleton_journal_root: journal_identity,
        service_cgroup_parent: parent_identity,
        cgroup_delegation_root: delegation_identity,
        cgroup_filesystem_magic,
        authenticated_platform_service_digest: service_image.content_sha256().clone(),
        service_image,
        service_image_object,
        host_architecture,
    })
}

/// The running service image, as both an authenticated plan image and a
/// retained-object identity.
///
/// The held launcher is a mode of this same executable, so in production this
/// is also the plan's inner-launcher image. The digest is the one
/// [`LinuxNativeServiceProcessImageAuthority`] took over a complete readback of
/// the retained descriptor; the inode metadata is re-read here so the retained
/// identity is a live observation rather than a copy of an earlier one.
#[cfg(target_os = "linux")]
fn observe_service_image_plan_identity(
    image: &LinuxNativeServiceProcessImageAuthority,
    operation: &'static str,
) -> Result<(LinuxAuthenticatedFileV1, LinuxRetainedObjectIdentityV1), CgroupIoFailure> {
    let metadata = image
        .file
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_file()
        || object_identity(&metadata) != image.identity
        || metadata.len() != image.byte_length
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the retained service image changed identity or length after it was authenticated",
        ));
    }
    let observed = LinuxKernelObjectObservationV1 {
        device_id: image.identity.device,
        inode: image.identity.inode,
        mount_id: image.mount_id,
        mode: OsMetadataExt::mode(&metadata),
        owner_uid: OsMetadataExt::uid(&metadata),
        owner_gid: OsMetadataExt::gid(&metadata),
        link_count: PortableMetadataExt::nlink(&metadata),
        byte_length: Some(metadata.len()),
    };
    let object = LinuxRetainedObjectIdentityV1::from_kernel_observation(
        SERVICE_IMAGE_OBJECT_ID,
        LinuxRetainedObjectKindV1::RegularFile,
        observed,
    )
    .map_err(|error| plan_mint_failure(operation, &error))?;
    let authenticated = LinuxAuthenticatedFileV1::from_complete_readback(
        SERVICE_IMAGE_OBJECT_ID,
        image.retained_absolute_path(),
        image.byte_length,
        image.content_sha256.clone(),
    )
    .map_err(|error| plan_mint_failure(operation, &error))?;
    Ok((authenticated, object))
}

#[cfg(target_os = "linux")]
impl LinuxNativeServiceStateRootCapability {
    /// The production entry point: mint the anchored plan facts from the
    /// capability and host roots `into_state_root_capability` already derived.
    fn observe_anchored_plan_facts(
        &self,
        host_roots: &LinuxNativeServiceBootstrapHostRoots,
    ) -> Result<LinuxProductionPlanAnchoredFactsV1, CgroupIoFailure> {
        observe_anchored_production_plan_facts(
            &self.service_process_image,
            &self.service_state_root,
            &host_roots.service_parent,
            &host_roots.delegation_name,
            self.external_commitment.installer_uid,
            &self.external_commitment.journal,
        )
    }
}

#[cfg(target_os = "linux")]
fn write_install_anchor(
    install_root: &Dir,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    if install_root
        .symlink_metadata(LINUX_SERVICE_INSTALL_ANCHOR_TEMP_NAME)
        .is_ok()
    {
        install_root
            .remove_file(LINUX_SERVICE_INSTALL_ANCHOR_TEMP_NAME)
            .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(LINUX_SERVICE_INSTALL_ANCHOR_MODE)
        .follow(FollowSymlinks::No);
    let mut file = install_root
        .open_with(LINUX_SERVICE_INSTALL_ANCHOR_TEMP_NAME, &options)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    file.write_all(bytes)
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    file.sync_all()
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    drop(file);
    install_root
        .set_permissions(
            LINUX_SERVICE_INSTALL_ANCHOR_TEMP_NAME,
            Permissions::from_mode(LINUX_SERVICE_INSTALL_ANCHOR_MODE),
        )
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    renameat_with(
        install_root,
        LINUX_SERVICE_INSTALL_ANCHOR_TEMP_NAME,
        install_root,
        LINUX_SERVICE_INSTALL_ANCHOR_NAME,
        RenameFlags::empty(),
    )
    .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))?;
    sync_directory(install_root)
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))
}

// Create and reopen through the held parent descriptor with no symlink
// following, then verify that resolution returns the same inode.

/// Name of the per-command retained-directory container under the anchored
/// service state root.
///
/// It sits beside `linux-command-journal-v2` rather than inside it: the journal
/// is a durable singleton the release path depends on, and per-command scratch
/// must not share its directory.
#[cfg(target_os = "linux")]
const SERVICE_PER_COMMAND_RETAINED_ROOT: &str = "linux-command-retained-v1";

/// The four names one per-command root holds, and nothing else.
#[cfg(target_os = "linux")]
const PER_COMMAND_EXECUTION_ROOT_NAME: &str = "execution-root";
#[cfg(target_os = "linux")]
const PER_COMMAND_PRIVATE_TEMP_NAME: &str = "private-temp";
#[cfg(target_os = "linux")]
const PER_COMMAND_OUTPUT_SPOOL_NAME: &str = "output-spool";
#[cfg(target_os = "linux")]
const PER_COMMAND_GIT_MASK_NAME: &str = "git-mask";

/// Held descriptors on one command's retained directories, plus the plan
/// identities they were observed as.
///
/// The descriptors are the authority; the names are revalidation handles only.
/// Nothing here reopens a path after the fact, which is why the mask
/// re-observation below is a second read of the *same* descriptor rather than a
/// second walk of the same name.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct LinuxRetainedPerCommandDirectories {
    command_directory_name: String,
    container: Dir,
    per_command_root: Dir,
    execution_root: Dir,
    private_temp: Dir,
    output_spool: Dir,
    git_mask: Dir,
    identities: LinuxPerCommandRetainedDirectoriesV1,
}

#[cfg(target_os = "linux")]
impl LinuxRetainedPerCommandDirectories {
    /// The name this command's retained root was created under.
    pub(crate) fn command_directory_name(&self) -> &str {
        &self.command_directory_name
    }

    /// The six retained identities the plan's object table needs.
    pub(crate) const fn identities(&self) -> &LinuxPerCommandRetainedDirectoriesV1 {
        &self.identities
    }

    /// Mints one `.git` mask per project view and then proves the replacement
    /// is still the empty directory the digests were taken over.
    ///
    /// The second observation is a complete re-read of the held mask
    /// descriptor: another `statx`, another `fstatfs` and another complete
    /// `getdents64`. A directory that gained an entry, changed mode or crossed
    /// a mount since the mint refuses here instead of being described.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the destinations are not a valid
    /// project-view set, when the re-observation fails or refuses, or when a
    /// re-derived digest differs from the one the mask committed.
    pub(crate) fn mint_git_masks(
        &self,
        project_destinations: &BTreeSet<&str>,
    ) -> Result<Vec<LinuxGitMaskV1>, CgroupIoFailure> {
        let operation = "mint-linux-per-command-git-masks";
        let masks = self
            .identities
            .git_masks_for(project_destinations)
            .map_err(|error| plan_mint_failure(operation, &error))?;
        let second = observe_empty_git_mask_directory(&self.git_mask, operation)?;
        self.identities
            .require_masks_still_observe(&masks, &second)
            .map_err(|error| plan_mint_failure(operation, &error))?;
        Ok(masks)
    }

    /// The retained container the per-command root was created in.
    pub(crate) const fn container(&self) -> &Dir {
        &self.container
    }

    /// The held descriptors, in the order the plan names them.
    pub(crate) const fn descriptors(&self) -> [&Dir; 5] {
        [
            &self.per_command_root,
            &self.execution_root,
            &self.private_temp,
            &self.output_spool,
            &self.git_mask,
        ]
    }
}

/// Creates and observes retained per-command directories.
///
/// Require the canonical command name and an owner-private state root and
/// container. Create the command root exclusively; refuse existing objects with
/// incorrect identity or mode. Reopen each directory without following symlinks
/// and compare its named and held inode. Observe the root after its four children
/// exist so its link count covers the complete layout.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] for invalid names, identities, modes, I/O failures,
/// or refusals from [`LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations`].
#[cfg(target_os = "linux")]
pub(crate) fn create_per_command_retained_directories(
    service_state_root: &Dir,
    workspace_root: &Dir,
    command_directory_name: &str,
    owner_uid: u32,
) -> Result<LinuxRetainedPerCommandDirectories, CgroupIoFailure> {
    let operation = "create-linux-per-command-retained-directories";
    validate_component("per-command retained directory", command_directory_name)?;
    if !crate::linux_containment::is_domain_leaf_name(command_directory_name) {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the per-command retained root must carry the same name grammar prepare_domain mints",
        ));
    }

    let state_metadata = service_state_root
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    validate_private_directory(&state_metadata, owner_uid)?;

    let container = open_or_create_per_command_container(service_state_root, owner_uid, operation)?;
    let per_command_root = create_retained_child_directory(
        &container,
        command_directory_name,
        LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
        owner_uid,
        operation,
    )?;
    let execution_root = create_retained_child_directory(
        &per_command_root,
        PER_COMMAND_EXECUTION_ROOT_NAME,
        LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
        owner_uid,
        operation,
    )?;
    let private_temp = create_retained_child_directory(
        &per_command_root,
        PER_COMMAND_PRIVATE_TEMP_NAME,
        LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
        owner_uid,
        operation,
    )?;
    let output_spool = create_retained_child_directory(
        &per_command_root,
        PER_COMMAND_OUTPUT_SPOOL_NAME,
        LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
        owner_uid,
        operation,
    )?;
    let git_mask = create_retained_child_directory(
        &per_command_root,
        PER_COMMAND_GIT_MASK_NAME,
        LINUX_GIT_MASK_DIRECTORY_MODE,
        owner_uid,
        operation,
    )?;

    let observations = LinuxPerCommandDirectoryObservationsV1 {
        workspace_root: observe_directory_kernel_facts(workspace_root, operation)?,
        // Read last of the private four on purpose: the link count is only
        // evidence about the children once the children exist.
        per_command_root: observe_directory_kernel_facts(&per_command_root, operation)?,
        execution_root: observe_directory_kernel_facts(&execution_root, operation)?,
        private_temp: observe_directory_kernel_facts(&private_temp, operation)?,
        output_spool: observe_directory_kernel_facts(&output_spool, operation)?,
        git_mask: observe_empty_git_mask_directory(&git_mask, operation)?,
    };
    let identities =
        LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations(&observations, owner_uid)
            .map_err(|error| plan_mint_failure(operation, &error))?;

    Ok(LinuxRetainedPerCommandDirectories {
        command_directory_name: command_directory_name.to_owned(),
        container,
        per_command_root,
        execution_root,
        private_temp,
        output_spool,
        git_mask,
        identities,
    })
}

/// Opens the per-command container under the anchored state root, creating it
/// when it does not exist yet.
///
/// This is the one directory here that legitimately survives across commands,
/// so `EEXIST` is not a refusal. What *is* a refusal is a container that does
/// not already satisfy the private contract: chmod-ing a directory found in the
/// wrong mode would erase exactly the evidence that something else had been
/// there.
#[cfg(target_os = "linux")]
fn open_or_create_per_command_container(
    service_state_root: &Dir,
    owner_uid: u32,
    operation: &'static str,
) -> Result<Dir, CgroupIoFailure> {
    let mut builder = DirBuilder::new();
    builder.mode(LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE);
    match service_state_root.create_dir_with(SERVICE_PER_COMMAND_RETAINED_ROOT, &builder) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(io_failure(operation, EffectCertainty::Ambiguous, error));
        }
    }
    let container = service_state_root
        .open_dir_nofollow(SERVICE_PER_COMMAND_RETAINED_ROOT)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    // `mkdirat` masks its mode with the process umask, so a freshly created
    // container can come back more permissive than requested.
    chmod_held_directory(
        &container,
        LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
        operation,
    )?;
    let metadata = container
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    validate_private_directory(&metadata, owner_uid)?;
    require_named_identity(
        service_state_root,
        SERVICE_PER_COMMAND_RETAINED_ROOT,
        object_identity(&metadata),
        operation,
    )?;
    Ok(container)
}

/// `mkdirat` one retained directory, hold it open, and prove the name still
/// means it.
///
/// `EEXIST` is a refusal here. Every directory this creates belongs to one
/// command, and one that already existed either belongs to another command or
/// was placed by something else; either way the plan must not adopt it.
#[cfg(target_os = "linux")]
fn create_retained_child_directory(
    parent: &Dir,
    name: &str,
    mode: u32,
    owner_uid: u32,
    operation: &'static str,
) -> Result<Dir, CgroupIoFailure> {
    validate_component("per-command retained directory", name)?;
    let mut builder = DirBuilder::new();
    builder.mode(mode);
    match parent.create_dir_with(name, &builder) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "a per-command retained directory already existed, so it was not created for this command",
            ));
        }
        Err(error) => {
            return Err(io_failure(operation, EffectCertainty::Ambiguous, error));
        }
    }
    let directory = parent
        .open_dir_nofollow(name)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    chmod_held_directory(&directory, mode, operation)?;
    let metadata = directory
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_dir()
        || OsMetadataExt::mode(&metadata) & 0o7777 != mode
        || OsMetadataExt::uid(&metadata) != owner_uid
    {
        return Err(failure(
            operation,
            EffectCertainty::Ambiguous,
            "a created per-command directory does not carry the exact mode and owner the plan requires",
        ));
    }
    require_named_identity(parent, name, object_identity(&metadata), operation)?;
    Ok(directory)
}

/// Sets one held directory descriptor to an exact mode.
///
/// `mkdirat` masks its requested mode with the process umask, so the mode a
/// directory is created with is not the mode it is required to carry. The only
/// name involved is `.` of the descriptor already open on the directory, which
/// cannot be a symlink and cannot name another object, so this is not a path
/// re-resolution; the caller then compares the kernel's answer against the
/// compiled constant rather than against what was asked for.
///
/// `fchmod` itself is unavailable here: `cap-std` opens directories with
/// `O_PATH`, and `fchmod` on an `O_PATH` descriptor answers `EBADF`. That was
/// measured, not assumed — `cap-primitives` performs the same `chmod` through
/// `/proc/self/fd`, which is what this call reaches.
#[cfg(target_os = "linux")]
fn chmod_held_directory(
    directory: &Dir,
    mode: u32,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    directory
        .set_permissions(Path::new("."), Permissions::from_mode(mode))
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))
}

/// Reads one held directory descriptor into the plan's kernel-observation
/// shape.
///
/// `dir_metadata` is `fstat` on the descriptor and
/// [`retained_directory_mount_id`] is `statx(.., AT_EMPTY_PATH,
/// STATX_MNT_ID_UNIQUE)` on the same one. No path is involved in either.
#[cfg(target_os = "linux")]
fn observe_directory_kernel_facts(
    directory: &Dir,
    operation: &'static str,
) -> Result<LinuxKernelObjectObservationV1, CgroupIoFailure> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_dir() {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "retained plan object is not a directory",
        ));
    }
    Ok(LinuxKernelObjectObservationV1 {
        device_id: PortableMetadataExt::dev(&metadata),
        inode: PortableMetadataExt::ino(&metadata),
        mount_id: retained_directory_mount_id(directory, operation)?,
        mode: OsMetadataExt::mode(&metadata),
        owner_uid: OsMetadataExt::uid(&metadata),
        owner_gid: OsMetadataExt::gid(&metadata),
        link_count: PortableMetadataExt::nlink(&metadata),
        byte_length: None,
    })
}

/// The complete `.git`-mask empty-directory observation the plan's digest is
/// taken over.
///
/// Five reads on one held descriptor, in this order: `statx`, `fstatfs`, a
/// complete `getdents64` walk, and `statx` again. The second `statx` must equal
/// the first, so a directory that gained an entry mid-walk is a refusal rather
/// than a stale "empty" answer.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when any read fails — an error is never read as
/// an absence — when the identity changed across the walk, or when the
/// enumeration is not a well-formed complete walk.
#[cfg(target_os = "linux")]
fn observe_empty_git_mask_directory(
    directory: &Dir,
    operation: &'static str,
) -> Result<LinuxGitMaskEmptyDirectoryObservationV1, CgroupIoFailure> {
    let first = observe_directory_kernel_facts(directory, operation)?;
    let filesystem_magic = filesystem_magic(directory)?;
    let entry_names = enumerate_directory_completely(directory, operation)?;
    let second = observe_directory_kernel_facts(directory, operation)?;
    if first != second {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the .git mask replacement changed identity or metadata during its own enumeration",
        ));
    }
    Ok(LinuxGitMaskEmptyDirectoryObservationV1 {
        object: first,
        filesystem_magic,
        entry_names,
    })
}

/// Walks one held directory descriptor to completion with `getdents64`.
///
/// `Dir::entries` opens `"."` relative to the descriptor it is handed and runs
/// a real `getdents64` loop over the result. `"."` of a directory descriptor
/// cannot be a symlink and cannot name another object, so the walk is of the
/// same inode by construction; the caller brackets it with two `statx` reads of
/// the held descriptor and requires them to agree, which is what turns a
/// directory that changed during its own walk into a refusal.
///
/// There is deliberately no "assume empty on read error" arm: an errored entry
/// refuses. A walk that stopped early would report an absence it never
/// established, which is the failure the whole observation exists to prevent.
#[cfg(target_os = "linux")]
fn enumerate_directory_completely(
    directory: &Dir,
    operation: &'static str,
) -> Result<Vec<String>, CgroupIoFailure> {
    let entries = directory
        .entries()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let mut names = Vec::new();
    for entry in entries {
        // A failed `getdents64` is an error, not an end of directory.
        let entry =
            entry.map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            failure(
                operation,
                EffectCertainty::NotApplied,
                "a directory entry name is not UTF-8, so it cannot be stated in the observation",
            )
        })?;
        if names.len() >= MAX_LINUX_GIT_MASK_OBSERVATION_ENTRIES {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "the directory enumeration reached its hard bound; a bounded walk cannot demonstrate absence",
            ));
        }
        names.push(name.to_owned());
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the directory enumeration returned a duplicated entry name",
        ));
    }
    Ok(names)
}
