//! Authenticated control protocol for the Linux cgroup held launcher.
//!
//! The portable portion defines and tests the bounded canonical protocol. The
//! Linux portion owns the pidfd, genuine-procfs observation capability, child
//! control pipes, and the exact `cgroup.procs` descriptor inherited as fd 2.
//! Only the helper writes `0\n`; the controller never writes a numeric PID.

// The protocol is exercised by portable tests but is instantiated by the
// production backend only on Linux.
#![cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]

use std::process::ExitCode;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const HELD_LAUNCHER_ARGUMENT: &str = "--grok-build-held-launcher-v1";
const INERT_TARGET_ARGUMENT: &str = "--grok-build-held-launcher-inert-target-v1";
/// Protocol version 4 adds the namespace-filter channel beside the artefact
/// channel version 3 already carried.
///
/// Version 3 added the containment artefact and the real-command release
/// target. Older records cannot express the Landlock ruleset, seccomp filter,
/// or user-command target required by `exec_prepared_target`.
///
/// The break is durable, because [`HeldExecReleaseBinding`] is persisted inside
/// `DomainJournalRecord`. It is therefore versioned *in the record*: the binding
/// carries `protocol_version`, `decode_envelope` peeks it before the typed
/// decode, and an older record is refused by a message naming both versions
/// rather than by serde's anonymous `missing field`. Decoding the version
/// before the typed payload is therefore part of the refusal contract.
const HELD_LAUNCHER_PROTOCOL_VERSION: u32 = 4;
/// Version 2 bounded a control frame at 2,048 bytes, which the artefact channel
/// does not fit: a ruleset with its scopes and a filter with its denied-syscall
/// table are together larger than the whole of version 2's release
/// specification. The bound is still a hard one, the helper refuses a longer
/// frame at exactly this number, and the channel is an `AF_UNIX` `SOCK_STREAM`
/// socketpair whose reader already accumulates to the frame terminator, so the
/// only thing that changes is where the refusal is.
const MAX_CONTROL_FRAME_BYTES: usize = 8_192;
const SESSION_NONCE_HEX_BYTES: usize = 64;
const MAX_RELEASE_ARGUMENTS: usize = 16;
const MAX_RELEASE_ENVIRONMENT: usize = 16;
const MAX_RELEASE_TEXT_BYTES: usize = 512;
/// Largest number of scopes one committed release ruleset may grant beneath.
///
/// It *is* the plan-side bound rather than a copy of it: a ruleset the plan may
/// commit and this channel may not carry would be a plan that cannot be
/// installed, and two independently maintained numbers is how that arrives.
const MAX_RELEASE_LANDLOCK_SCOPES: usize = crate::linux_command_plan::MAX_LINUX_LANDLOCK_SCOPES;
/// Largest number of syscalls one committed release filter may deny, taken from
/// the plan side for the same reason.
const MAX_RELEASE_SECCOMP_SYSCALLS: usize =
    crate::linux_command_plan::MAX_LINUX_SECCOMP_DENIED_SYSCALLS;
const MAX_EXECUTABLE_IMAGE_BYTES: u64 = 128 * 1_024 * 1_024;
// Linux F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE |
// F_SEAL_FUTURE_WRITE | F_SEAL_EXEC. This value is protocol data and must
// remain available to portable canonical-frame validation.
const REQUIRED_EXECUTABLE_SEAL_BITS: u32 = 0x0000_003f;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DescriptorIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl DescriptorIdentity {
    fn validate(self, field: &'static str) -> Result<(), ProtocolFailure> {
        if self.device == 0 || self.inode == 0 {
            Err(ProtocolFailure::new(format!(
                "{field} identity must be nonzero"
            )))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LauncherBinding {
    session_nonce: String,
    launch_request_hash: String,
    leaf_identity: DescriptorIdentity,
    cgroup_procs_identity: DescriptorIdentity,
}

impl LauncherBinding {
    fn validate(&self) -> Result<(), ProtocolFailure> {
        if self.session_nonce.len() != SESSION_NONCE_HEX_BYTES
            || !self
                .session_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ProtocolFailure::new(
                "session nonce must be exactly 32 lowercase hexadecimal bytes",
            ));
        }
        validate_identity_text("launch request hash", &self.launch_request_hash)?;
        self.leaf_identity.validate("leaf")?;
        self.cgroup_procs_identity.validate("cgroup.procs")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlEnvelope {
    protocol_version: u32,
    sequence: u64,
    binding: LauncherBinding,
    command: LauncherCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum LauncherCommand {
    SelfAttach { exact_value: Vec<u8> },
    PrepareExec { specification: Box<ReleaseExecSpec> },
    CommitExec { release_spec_hash: String },
}

impl ControlEnvelope {
    fn validate_common(
        &self,
        expected: &LauncherBinding,
        sequence: u64,
    ) -> Result<(), ProtocolFailure> {
        self.binding.validate()?;
        if self.protocol_version != HELD_LAUNCHER_PROTOCOL_VERSION
            || self.sequence != sequence
            || &self.binding != expected
        {
            return Err(ProtocolFailure::new(
                "control frame version, sequence, or binding differs from the retained session",
            ));
        }
        Ok(())
    }

    fn validate_self_attach(&self, expected: &LauncherBinding) -> Result<(), ProtocolFailure> {
        self.validate_common(expected, 1)?;
        match &self.command {
            LauncherCommand::SelfAttach { exact_value } if exact_value == b"0\n" => Ok(()),
            LauncherCommand::SelfAttach { .. } => Err(ProtocolFailure::new(
                "self-attachment requires the exact literal 0\\n",
            )),
            _ => Err(ProtocolFailure::new(
                "sequence 1 requires the self-attachment command",
            )),
        }
    }

    fn validate_prepare_exec(
        &self,
        expected: &LauncherBinding,
    ) -> Result<&ReleaseExecSpec, ProtocolFailure> {
        self.validate_common(expected, 2)?;
        match &self.command {
            LauncherCommand::PrepareExec { specification } => {
                specification.validate()?;
                Ok(specification)
            }
            _ => Err(ProtocolFailure::new(
                "sequence 2 requires the prepare-exec command",
            )),
        }
    }

    fn validate_commit_exec(
        &self,
        expected: &LauncherBinding,
        expected_release_spec_hash: &str,
    ) -> Result<(), ProtocolFailure> {
        self.validate_common(expected, 3)?;
        match &self.command {
            LauncherCommand::CommitExec { release_spec_hash }
                if release_spec_hash == expected_release_spec_hash =>
            {
                Ok(())
            }
            LauncherCommand::CommitExec { .. } => Err(ProtocolFailure::new(
                "commit-exec hash differs from the prepared release specification",
            )),
            _ => Err(ProtocolFailure::new(
                "sequence 3 requires the commit-exec command",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ParentDescriptorBinding {
    descriptor: u32,
    identity: DescriptorIdentity,
}

impl ParentDescriptorBinding {
    fn validate(self, field: &'static str) -> Result<(), ProtocolFailure> {
        if self.descriptor <= 2 || self.descriptor > 2_147_483_647_u32 {
            return Err(ProtocolFailure::new(format!(
                "{field} parent descriptor must be in 3..=i32::MAX"
            )));
        }
        self.identity.validate(field)
    }
}

/// Selects the target that replaces the held launcher.
/// An inert target must carry no containment artefact; a contained command
/// must carry one. Their validators and release dispositions remain separate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReleaseTargetKind {
    InertInternalTest,
    ContainedCommand,
}

/// One `path_beneath` rule of the ruleset a release installs.
///
/// This is the wire form of `LinuxLandlockScopeV1`, and its canonical preimage
/// is that type's byte for byte, so `ruleset_sha256` is the digest the **plan**
/// committed and not one this channel invented.
///
/// `resolved_path` travels for that digest alone. **The helper never opens
/// it.** A scope is installed only through a descriptor the controller passed
/// over `SCM_RIGHTS` whose `fstat` identity equals `identity`, so a substituted
/// directory is refused even when the path string matched, the same property
/// the plan-side mint holds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseLandlockScope {
    object_id: String,
    resolved_path: String,
    identity: DescriptorIdentity,
    access_bits: u64,
}

/// The object the committed ruleset states it does **not** grant.
///
/// A ruleset that grants something proves nothing on its own; the witness is
/// the other half, and the release installer opens it after `restrict_self` and
/// requires the kernel to answer `EACCES`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseLandlockWitness {
    resolved_path: String,
    identity: DescriptorIdentity,
}

/// The exact Landlock ruleset a release installs, as the plan committed it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseLandlockRuleset {
    created_at_kernel_abi: u32,
    handled_access_bits: u64,
    scopes: Vec<ReleaseLandlockScope>,
    denial_witness: ReleaseLandlockWitness,
    ruleset_sha256: String,
}

impl ReleaseLandlockRuleset {
    /// The plan's own canonical preimage, reproduced field for field.
    ///
    /// It is deliberately not a new encoding. `LinuxLandlockRulesetV1`'s digest
    /// is what `validate_mandatory_control_artefacts` already requires a plan's
    /// `ruleset_sha256` to equal and what the live bootstrap probe's result
    /// digest is derived from, so reproducing it here is what makes "this
    /// artefact is the plan's artefact" checkable inside the launcher with no
    /// second source of truth.
    fn canonical_digest(&self) -> String {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(crate::linux_command_plan::LINUX_LANDLOCK_RULESET_DOMAIN);
        preimage.extend_from_slice(&u64::from(self.created_at_kernel_abi).to_be_bytes());
        preimage.extend_from_slice(&self.handled_access_bits.to_be_bytes());
        preimage.extend_from_slice(&(self.scopes.len() as u64).to_be_bytes());
        for scope in &self.scopes {
            push_length_prefixed(&mut preimage, scope.object_id.as_bytes());
            push_length_prefixed(&mut preimage, scope.resolved_path.as_bytes());
            preimage.extend_from_slice(&scope.identity.device.to_be_bytes());
            preimage.extend_from_slice(&scope.identity.inode.to_be_bytes());
            preimage.extend_from_slice(&scope.access_bits.to_be_bytes());
        }
        push_length_prefixed(&mut preimage, self.denial_witness.resolved_path.as_bytes());
        preimage.extend_from_slice(&self.denial_witness.identity.device.to_be_bytes());
        preimage.extend_from_slice(&self.denial_witness.identity.inode.to_be_bytes());
        sha256_hex(&preimage)
    }

    fn validate(&self) -> Result<(), ProtocolFailure> {
        if self.created_at_kernel_abi == 0 || self.handled_access_bits == 0 {
            return Err(ProtocolFailure::new(
                "release ruleset must name the ABI it was created at and a nonempty handled access set",
            ));
        }
        if self.scopes.is_empty() || self.scopes.len() > MAX_RELEASE_LANDLOCK_SCOPES {
            return Err(ProtocolFailure::new(
                "release ruleset grants no scope or exceeds its hard scope bound",
            ));
        }
        let mut previous: Option<&str> = None;
        for scope in &self.scopes {
            validate_identity_text("release ruleset scope object id", &scope.object_id)?;
            validate_absolute_release_path("release ruleset scope path", &scope.resolved_path)?;
            scope.identity.validate("release ruleset scope")?;
            if scope.access_bits == 0 || scope.access_bits & !self.handled_access_bits != 0 {
                return Err(ProtocolFailure::new(
                    "release ruleset scope grants nothing, or grants a right the ruleset does not handle",
                ));
            }
            if previous.is_some_and(|name| name >= scope.object_id.as_str()) {
                return Err(ProtocolFailure::new(
                    "release ruleset scopes must be unique and bytewise sorted by object id",
                ));
            }
            previous = Some(scope.object_id.as_str());
        }
        validate_absolute_release_path(
            "release ruleset denial witness",
            &self.denial_witness.resolved_path,
        )?;
        self.denial_witness
            .identity
            .validate("release ruleset denial witness")?;
        if self
            .scopes
            .iter()
            .any(|scope| scope.identity == self.denial_witness.identity)
        {
            return Err(ProtocolFailure::new(
                "release ruleset denial witness is one of the scopes the ruleset grants",
            ));
        }
        if self.ruleset_sha256 != self.canonical_digest() {
            return Err(ProtocolFailure::new(
                "release ruleset digest is not the digest of the ruleset beside it",
            ));
        }
        Ok(())
    }
}

/// One syscall the committed filter denies, by the number it denies it at on
/// the plan's own audit architecture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSeccompSyscall {
    name: String,
    number: i64,
}

/// The namespace filter a release installs, as the plan committed it.
///
/// The second filter, added by plan schema version 5. It answers `ENOSYS`
/// rather than killing, which is why it is a separate artefact and not more
/// syscalls in `ReleaseSeccompFilter`: one `seccompiler` filter carries one
/// matched action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSeccompNamespaceFilter {
    audit_architecture: String,
    action: String,
    denied_syscalls: Vec<crate::linux_command_plan::LinuxSeccompNamespaceDenialV1>,
    instruction_count: u64,
    program_sha256: String,
    filter_sha256: String,
}

impl ReleaseSeccompNamespaceFilter {
    /// `LinuxSeccompNamespaceFilterV1`'s canonical preimage, field for field.
    fn canonical_digest(&self) -> String {
        let mut preimage = Vec::new();
        preimage
            .extend_from_slice(crate::linux_command_plan::LINUX_SECCOMP_NAMESPACE_FILTER_DOMAIN);
        push_length_prefixed(&mut preimage, self.audit_architecture.as_bytes());
        push_length_prefixed(&mut preimage, self.action.as_bytes());
        preimage.extend_from_slice(&(self.denied_syscalls.len() as u64).to_be_bytes());
        for denied in &self.denied_syscalls {
            push_length_prefixed(&mut preimage, denied.name.as_bytes());
            preimage.extend_from_slice(&denied.number.to_be_bytes());
            match &denied.condition {
                crate::linux_command_plan::LinuxSeccompDenialConditionV1::Always => {
                    push_length_prefixed(&mut preimage, b"always");
                    preimage.extend_from_slice(&0u64.to_be_bytes());
                }
                crate::linux_command_plan::LinuxSeccompDenialConditionV1::AnyArgumentFlagSet {
                    argument,
                    flags,
                } => {
                    push_length_prefixed(&mut preimage, b"any-argument-flag-set");
                    preimage.extend_from_slice(&u64::from(*argument).to_be_bytes());
                    preimage.extend_from_slice(&(flags.len() as u64).to_be_bytes());
                    for flag in flags {
                        push_length_prefixed(&mut preimage, flag.name.as_bytes());
                        preimage.extend_from_slice(&flag.bit.to_be_bytes());
                    }
                }
            }
        }
        preimage.extend_from_slice(&self.instruction_count.to_be_bytes());
        push_length_prefixed(&mut preimage, self.program_sha256.as_bytes());
        sha256_hex(&preimage)
    }

    fn validate(&self) -> Result<(), ProtocolFailure> {
        // The only action a version-5 plan may commit for this filter. It is
        // not `kill-process`, and that is deliberate rather than a weakening:
        // `clone3` must answer `ENOSYS` so glibc falls back to legacy `clone`,
        // where the flags are in a register and can be judged.
        if self.action != "errno-not-implemented" {
            return Err(ProtocolFailure::new(
                "release namespace filter must commit the errno-not-implemented action",
            ));
        }
        if self.audit_architecture != "audit-arch-aarch64"
            && self.audit_architecture != "audit-arch-x86-64"
        {
            return Err(ProtocolFailure::new(
                "release namespace filter names no audit architecture this protocol models",
            ));
        }
        if self.denied_syscalls.is_empty()
            || self.denied_syscalls.len() > MAX_RELEASE_SECCOMP_SYSCALLS
        {
            return Err(ProtocolFailure::new(
                "release namespace filter denies nothing or exceeds its hard syscall bound",
            ));
        }
        // Same ordering key as the network filter, and for the same reason:
        // `filter_sha256` covers this list in order.
        let mut previous: Option<&str> = None;
        for denied in &self.denied_syscalls {
            if denied.name.is_empty() || denied.number < 0 {
                return Err(ProtocolFailure::new(
                    "release namespace denial is unnamed or carries no syscall number",
                ));
            }
            if previous.is_some_and(|earlier| earlier >= denied.name.as_str()) {
                return Err(ProtocolFailure::new(
                    "release namespace denials must be unique and bytewise sorted by name",
                ));
            }
            previous = Some(denied.name.as_str());
        }
        let architecture =
            crate::linux_command_plan::audit_architecture_from_tag(&self.audit_architecture)
                .ok_or_else(|| {
                    ProtocolFailure::new(
                        "release namespace filter names no audit architecture this protocol models",
                    )
                })?;
        if let Err(detail) = crate::linux_command_plan::validate_required_namespace_set(
            architecture,
            &self.denied_syscalls,
        ) {
            return Err(ProtocolFailure::new(detail));
        }
        if self.instruction_count == 0 {
            return Err(ProtocolFailure::new(
                "release namespace filter assembled to no instruction",
            ));
        }
        if self.filter_sha256 != self.canonical_digest() {
            return Err(ProtocolFailure::new(
                "release namespace filter digest is not the digest of the filter it accompanies",
            ));
        }
        Ok(())
    }
}

/// The exact seccomp filter a release installs, as the plan committed it.
///
/// `audit_architecture` and `default_action` are the plan's own canonical tags
/// rather than serde names, because the filter digest covers them: a filter
/// moved to another architecture is a different filter, and version 4 measured
/// that once already.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSeccompFilter {
    audit_architecture: String,
    default_action: String,
    denied_syscalls: Vec<ReleaseSeccompSyscall>,
    instruction_count: u64,
    program_sha256: String,
    filter_sha256: String,
}

impl ReleaseSeccompFilter {
    /// `LinuxSeccompFilterV1`'s canonical preimage, reproduced field for field.
    fn canonical_digest(&self) -> String {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(crate::linux_command_plan::LINUX_SECCOMP_FILTER_DOMAIN);
        push_length_prefixed(&mut preimage, self.audit_architecture.as_bytes());
        push_length_prefixed(&mut preimage, self.default_action.as_bytes());
        preimage.extend_from_slice(&(self.denied_syscalls.len() as u64).to_be_bytes());
        for denied in &self.denied_syscalls {
            push_length_prefixed(&mut preimage, denied.name.as_bytes());
            preimage.extend_from_slice(&denied.number.to_be_bytes());
        }
        preimage.extend_from_slice(&self.instruction_count.to_be_bytes());
        push_length_prefixed(&mut preimage, self.program_sha256.as_bytes());
        sha256_hex(&preimage)
    }

    fn validate(&self) -> Result<(), ProtocolFailure> {
        // The only matched action a plan may commit, required unchanged by
        // `validate_mandatory_kernel_controls` since schema version 2. A filter
        // that merely returned an errno would let a denied syscall be retried.
        if self.default_action != "kill-process" {
            return Err(ProtocolFailure::new(
                "release filter must commit the kill-process matched action",
            ));
        }
        if self.audit_architecture != "audit-arch-aarch64"
            && self.audit_architecture != "audit-arch-x86-64"
        {
            return Err(ProtocolFailure::new(
                "release filter names no audit architecture this protocol models",
            ));
        }
        if self.denied_syscalls.is_empty()
            || self.denied_syscalls.len() > MAX_RELEASE_SECCOMP_SYSCALLS
        {
            return Err(ProtocolFailure::new(
                "release filter denies nothing or exceeds its hard syscall bound",
            ));
        }
        // The plan digest requires unique, bytewise-sorted syscall names. Check
        // number uniqueness independently and reject negative numbers, duplicate
        // names, or out-of-order names.
        let mut previous: Option<&str> = None;
        let mut numbers = std::collections::BTreeSet::new();
        for denied in &self.denied_syscalls {
            validate_identity_text("release filter denied syscall", &denied.name)?;
            if denied.number < 0 {
                return Err(ProtocolFailure::new(
                    "release filter denies a negative syscall number",
                ));
            }
            if !numbers.insert(denied.number) {
                return Err(ProtocolFailure::new(
                    "release filter denies one syscall number more than once",
                ));
            }
            if previous.is_some_and(|name| name >= denied.name.as_str()) {
                return Err(ProtocolFailure::new(
                    "release filter denied syscalls must be unique and bytewise sorted by name",
                ));
            }
            previous = Some(denied.name.as_str());
        }
        if self.instruction_count == 0 {
            return Err(ProtocolFailure::new(
                "release filter assembles to no instructions",
            ));
        }
        validate_sha256_hex("release filter program digest", &self.program_sha256)?;
        if self.filter_sha256 != self.canonical_digest() {
            return Err(ProtocolFailure::new(
                "release filter digest is not the digest of the filter beside it",
            ));
        }
        Ok(())
    }
}

/// The complete containment artefact one contained-command release installs.
///
/// This is the channel version 2 did not have. It carries **what to install**,
/// never **whether to install it**: a `ContainedCommand` release without one is
/// refused by [`ReleaseExecSpec::validate_contained_command`], so there is no
/// reduced-containment shape for a real command to take.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseContainmentArtefact {
    landlock: ReleaseLandlockRuleset,
    seccomp: ReleaseSeccompFilter,
    seccomp_namespace: ReleaseSeccompNamespaceFilter,
}

impl ReleaseContainmentArtefact {
    fn validate(&self) -> Result<(), ProtocolFailure> {
        self.landlock.validate()?;
        self.seccomp.validate()?;
        self.seccomp_namespace.validate()
    }
}

/// Appends one length-prefixed field to a canonical preimage, exactly as the
/// plan side does.
fn push_length_prefixed(preimage: &mut Vec<u8>, field: &[u8]) {
    preimage.extend_from_slice(&(field.len() as u64).to_be_bytes());
    preimage.extend_from_slice(field);
}

/// Requires one absolute, bounded, single-line path with no `.`/`..` component.
///
/// The helper never resolves these, every scope is installed through a
/// descriptor, but a path that could not name a real object has no business in
/// a digest the plan and the launcher both compute.
fn validate_absolute_release_path(field: &'static str, value: &str) -> Result<(), ProtocolFailure> {
    if !value.starts_with('/')
        || value.len() > MAX_RELEASE_TEXT_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
        || value
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return Err(ProtocolFailure::new(format!(
            "{field} must be one absolute, bounded, single-line path with no relative component"
        )));
    }
    Ok(())
}

fn validate_sha256_hex(field: &'static str, value: &str) -> Result<(), ProtocolFailure> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolFailure::new(format!(
            "{field} must be one canonical lowercase SHA-256"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExecutableImageType {
    SealedMemfd,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutableDescriptorBinding {
    authority: ParentDescriptorBinding,
    image_type: ExecutableImageType,
    byte_len: u64,
    content_sha256: String,
    seal_bits: u32,
}

impl ExecutableDescriptorBinding {
    fn validate(&self) -> Result<(), ProtocolFailure> {
        self.authority.validate("release executable")?;
        if self.byte_len == 0 || self.byte_len > MAX_EXECUTABLE_IMAGE_BYTES {
            return Err(ProtocolFailure::new(
                "release executable byte length is zero or exceeds its hard bound",
            ));
        }
        if self.content_sha256.len() != 64
            || !self
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.seal_bits != REQUIRED_EXECUTABLE_SEAL_BITS
        {
            return Err(ProtocolFailure::new(
                "release executable requires a canonical SHA-256 and the exact admitted executable seal set",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEnvironmentEntry {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseExecSpec {
    release_spec_hash: String,
    target_kind: ReleaseTargetKind,
    executable: ExecutableDescriptorBinding,
    working_directory: ParentDescriptorBinding,
    target_stdin: ParentDescriptorBinding,
    target_stdout: ParentDescriptorBinding,
    target_stderr: ParentDescriptorBinding,
    cgroup_membership: ParentDescriptorBinding,
    argv: Vec<String>,
    environment: Vec<ReleaseEnvironmentEntry>,
    /// The containment artefact this release installs before `execve`.
    ///
    /// `None` is the inert internal target's only admitted value and
    /// `Some` is a contained command's only admitted value, so the field is
    /// never a policy switch: it is the artefact channel, and which target
    /// kinds may use it is decided by their own validators.
    containment: Option<ReleaseContainmentArtefact>,
}

/// Complete descriptor-bound process image retained in the durable Linux
/// launch journal before the helper may prepare or release it.
///
/// The nested specification includes the exact executable descriptor,
/// memfd digest and seal set, argv, sorted environment, working directory,
/// stdio descriptors, and read-only cgroup-membership descriptor.  It is
/// deliberately a typed copy rather than only a hash so restart validation
/// can reject a consistently substituted journal record.
///
/// **The version travels with the bytes.** Version 2 recorded no protocol
/// version at all, so a version-2 record met version 3 as a `ReleaseExecSpec`
/// missing a field, an anonymous serde refusal that tells an operator
/// restarting a service nothing about which protocol they are holding.
/// `held_launcher_protocol_version_peek` reads this field out of the raw
/// document before the typed decode, so the refusal names both versions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldExecReleaseBinding {
    protocol_version: u32,
    specification: ReleaseExecSpec,
}

impl HeldExecReleaseBinding {
    fn from_specification(specification: &ReleaseExecSpec) -> Self {
        Self {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            specification: specification.clone(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.protocol_version != HELD_LAUNCHER_PROTOCOL_VERSION {
            return Err(format!(
                "durable held-launcher release binding is protocol version \
                 {} and this runner speaks version {HELD_LAUNCHER_PROTOCOL_VERSION}",
                self.protocol_version
            ));
        }
        self.specification.validate().map_err(|error| error.detail)
    }

    pub(crate) fn release_spec_hash(&self) -> &str {
        &self.specification.release_spec_hash
    }

    pub(crate) fn executable_identity(&self) -> DescriptorIdentity {
        self.specification.executable.authority.identity
    }

    #[cfg(test)]
    pub(crate) fn inert_test_fixture() -> Self {
        let token = "release-token";
        let cwd = ParentDescriptorBinding {
            descriptor: 11,
            identity: DescriptorIdentity {
                device: 21,
                inode: 22,
            },
        };
        let mut specification = ReleaseExecSpec {
            release_spec_hash: String::new(),
            target_kind: ReleaseTargetKind::InertInternalTest,
            executable: ExecutableDescriptorBinding {
                authority: ParentDescriptorBinding {
                    descriptor: 10,
                    identity: DescriptorIdentity {
                        device: 19,
                        inode: 20,
                    },
                },
                image_type: ExecutableImageType::SealedMemfd,
                byte_len: 4_096,
                content_sha256: "ab".repeat(32),
                seal_bits: REQUIRED_EXECUTABLE_SEAL_BITS,
            },
            working_directory: cwd,
            target_stdin: ParentDescriptorBinding {
                descriptor: 12,
                identity: DescriptorIdentity {
                    device: 23,
                    inode: 24,
                },
            },
            target_stdout: ParentDescriptorBinding {
                descriptor: 13,
                identity: DescriptorIdentity {
                    device: 25,
                    inode: 26,
                },
            },
            target_stderr: ParentDescriptorBinding {
                descriptor: 14,
                identity: DescriptorIdentity {
                    device: 27,
                    inode: 28,
                },
            },
            cgroup_membership: ParentDescriptorBinding {
                descriptor: 15,
                identity: DescriptorIdentity {
                    device: 7,
                    inode: 12,
                },
            },
            argv: vec![
                "grok-build-inert-target".into(),
                INERT_TARGET_ARGUMENT.into(),
                token.into(),
                cwd.identity.device.to_string(),
                cwd.identity.inode.to_string(),
            ],
            environment: vec![
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_CWD_DEVICE".into(),
                    value: cwd.identity.device.to_string(),
                },
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_CWD_INODE".into(),
                    value: cwd.identity.inode.to_string(),
                },
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_TOKEN".into(),
                    value: token.into(),
                },
            ],
            containment: None,
        };
        specification
            .seal_hash()
            .expect("test release specification must encode");
        Self::from_specification(&specification)
    }
}

/// Reads the held-launcher protocol version out of one raw durable record.
///
/// This is the ordering lesson plan schema v4 and probe journal format v2 each
/// learned separately, applied a third time. A durable `DomainJournalRecord`
/// carries an optional [`HeldExecReleaseBinding`], every struct on the path
/// denies unknown fields, and a version-2 binding therefore fails the typed
/// decode on a *missing field*, an explicit refusal that names neither
/// version. Peeking here admits nothing: a document that passes still goes
/// through the whole typed decode and every validator behind it, including
/// [`HeldExecReleaseBinding::validate`]'s own version equality.
///
/// The three shapes are kept apart because two of them are indistinguishable to
/// serde and mean opposite things: a record with **no** release binding is the
/// normal shape of every generation before one is planned, while a record whose
/// binding carries no `protocol_version` at all is exactly and only a version-2
/// binding, because version 2 is the one version that never wrote the field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeldLauncherProtocolPeek {
    NoReleaseBinding,
    Unversioned,
    Version(u64),
}

pub(crate) fn held_launcher_protocol_version_peek(
    record: &serde_json::Value,
) -> HeldLauncherProtocolPeek {
    let Some(binding) = record.get("release_binding") else {
        return HeldLauncherProtocolPeek::NoReleaseBinding;
    };
    if binding.is_null() {
        return HeldLauncherProtocolPeek::NoReleaseBinding;
    }
    binding
        .get("protocol_version")
        .and_then(serde_json::Value::as_u64)
        .map_or(
            HeldLauncherProtocolPeek::Unversioned,
            HeldLauncherProtocolPeek::Version,
        )
}

/// The protocol version this runner speaks, for a refusal that names both.
pub(crate) const fn held_launcher_protocol_version() -> u32 {
    HELD_LAUNCHER_PROTOCOL_VERSION
}

/// The one earlier protocol version that exists on disk and wrote no version
/// field, named so a refusal can say which version the operator is holding.
pub(crate) const HELD_LAUNCHER_UNVERSIONED_PROTOCOL_VERSION: u32 = 2;

/// Exact post-commit observation joined to a durable release intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldExecObservation {
    pub(crate) pid: u32,
    pub(crate) process_start_time_ticks: u64,
    pub(crate) release_spec_hash: String,
    pub(crate) executable_identity: DescriptorIdentity,
    pub(crate) same_pid_exec_observed: bool,
    pub(crate) cgroup_membership_revalidated: bool,
    pub(crate) target_continued: bool,
}

impl HeldExecObservation {
    pub(crate) fn validate_against(
        &self,
        launcher: &crate::linux_containment::StagedLauncherIdentity,
        binding: &HeldExecReleaseBinding,
    ) -> Result<(), String> {
        binding.validate()?;
        if self.pid != launcher.pid
            || self.process_start_time_ticks != launcher.process_start_time_ticks
            || self.release_spec_hash != binding.release_spec_hash()
            || self.executable_identity != binding.executable_identity()
            || !self.same_pid_exec_observed
            || !self.cgroup_membership_revalidated
            || !self.target_continued
        {
            return Err(
                "released observation differs from the held launcher or exact release binding"
                    .into(),
            );
        }
        Ok(())
    }
}

impl ReleaseExecSpec {
    fn validate(&self) -> Result<(), ProtocolFailure> {
        validate_identity_text("release spec hash", &self.release_spec_hash)?;
        self.executable.validate()?;
        self.working_directory
            .validate("release working directory")?;
        self.target_stdin.validate("release target stdin")?;
        self.target_stdout.validate("release target stdout")?;
        self.target_stderr.validate("release target stderr")?;
        self.cgroup_membership
            .validate("release cgroup membership")?;
        let descriptors = [
            self.executable.authority.descriptor,
            self.working_directory.descriptor,
            self.target_stdin.descriptor,
            self.target_stdout.descriptor,
            self.target_stderr.descriptor,
            self.cgroup_membership.descriptor,
        ];
        let distinct = descriptors
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if distinct.len() != descriptors.len() {
            return Err(ProtocolFailure::new(
                "release authority contains a substituted or duplicate parent descriptor",
            ));
        }
        if self.cgroup_membership.identity == self.executable.authority.identity
            || self.cgroup_membership.identity == self.working_directory.identity
        {
            return Err(ProtocolFailure::new(
                "cgroup membership authority aliases executable or working-directory authority",
            ));
        }
        if self.argv.is_empty()
            || self.argv.len() > MAX_RELEASE_ARGUMENTS
            || self.argv.iter().any(|value| !valid_release_text(value))
        {
            return Err(ProtocolFailure::new(
                "release argv is empty, oversized, or contains a NUL/control byte",
            ));
        }
        if self.environment.len() > MAX_RELEASE_ENVIRONMENT {
            return Err(ProtocolFailure::new(
                "release environment exceeds its hard entry bound",
            ));
        }
        let mut previous = None;
        for entry in &self.environment {
            if !valid_environment_name(&entry.name) || !valid_release_text(&entry.value) {
                return Err(ProtocolFailure::new(
                    "release environment name or value is invalid",
                ));
            }
            if previous.is_some_and(|name: &str| name >= entry.name.as_str()) {
                return Err(ProtocolFailure::new(
                    "release environment entries must be unique and bytewise sorted",
                ));
            }
            previous = Some(entry.name.as_str());
        }
        if let Some(containment) = &self.containment {
            containment.validate()?;
        }
        if self.computed_hash()? != self.release_spec_hash {
            return Err(ProtocolFailure::new(
                "release specification hash does not match its canonical authority and process image",
            ));
        }
        match self.target_kind {
            ReleaseTargetKind::InertInternalTest => self.validate_inert_target(),
            ReleaseTargetKind::ContainedCommand => self.validate_contained_command(),
        }
    }

    /// The real-command target's own validator.
    ///
    /// It deliberately says nothing about argv or the environment beyond the
    /// bounds every release already carries: expressing a user command is the
    /// entire point of the variant, and a second exact-contract clause here
    /// would reproduce the blocker version 2 had.
    ///
    /// What it does require is the artefact. A contained command with no
    /// ruleset and no filter would be a release that names containment and
    /// installs none, the reduced-containment arm this project does not have,
    /// so its absence is a refusal rather than a downgrade. The working
    /// directory must additionally be one of the ruleset's own granted scopes,
    /// because a target that starts in a directory its policy does not name
    /// cannot read the directory it is standing in.
    fn validate_contained_command(&self) -> Result<(), ProtocolFailure> {
        let Some(containment) = &self.containment else {
            return Err(ProtocolFailure::new(
                "a contained command release must carry the containment artefact it installs",
            ));
        };
        if self.argv.first().is_none_or(String::is_empty) {
            return Err(ProtocolFailure::new(
                "a contained command release must name its own argv0",
            ));
        }
        if !containment
            .landlock
            .scopes
            .iter()
            .any(|scope| scope.identity == self.working_directory.identity)
        {
            return Err(ProtocolFailure::new(
                "a contained command's working directory is not one of the scopes its ruleset grants",
            ));
        }
        Ok(())
    }

    fn validate_inert_target(&self) -> Result<(), ProtocolFailure> {
        if self.containment.is_some() {
            return Err(ProtocolFailure::new(
                "the inert internal target installs no containment and may not carry an artefact",
            ));
        }
        let exact_main = self.argv.len() == 5
            && self.argv[1] == INERT_TARGET_ARGUMENT
            && self.argv[2]
                == self
                    .environment
                    .iter()
                    .find(|entry| entry.name == "GROK_BUILD_INERT_TOKEN")
                    .map_or("", |entry| entry.value.as_str())
            && self.argv[3] == self.working_directory.identity.device.to_string()
            && self.argv[4] == self.working_directory.identity.inode.to_string();
        let exact_environment = self.environment
            == [
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_CWD_DEVICE".into(),
                    value: self.working_directory.identity.device.to_string(),
                },
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_CWD_INODE".into(),
                    value: self.working_directory.identity.inode.to_string(),
                },
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_TOKEN".into(),
                    value: self
                        .environment
                        .iter()
                        .find(|entry| entry.name == "GROK_BUILD_INERT_TOKEN")
                        .map_or_else(String::new, |entry| entry.value.clone()),
                },
            ];
        if !exact_main || !exact_environment {
            return Err(ProtocolFailure::new(
                "this tranche permits only the exact inert internal target contract",
            ));
        }
        Ok(())
    }

    fn computed_hash(&self) -> Result<String, ProtocolFailure> {
        let mut unhashed = self.clone();
        unhashed.release_spec_hash.clear();
        let canonical = serde_json::to_vec(&unhashed).map_err(|error| {
            ProtocolFailure::new(format!("serialize release specification: {error}"))
        })?;
        Ok(sha256_hex(&canonical))
    }

    fn seal_hash(&mut self) -> Result<(), ProtocolFailure> {
        self.release_spec_hash = self.computed_hash()?;
        Ok(())
    }
}

fn valid_release_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RELEASE_TEXT_BYTES
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 128
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    encode_hex(&digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusEnvelope {
    protocol_version: u32,
    sequence: u64,
    binding: LauncherBinding,
    status: LauncherStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum LauncherStatus {
    Ready {
        pid: u32,
        parent_pid: u32,
        parent_death_signal_armed: bool,
        descriptor_set_exact: bool,
    },
    SelfAttached {
        pid: u32,
        bytes_written: usize,
    },
    ExecPrepared {
        pid: u32,
        release_spec_hash: String,
        descriptors: PreparedDescriptorTable,
        descriptor_set_exact: bool,
        cgroup_membership_exact: bool,
    },
    ExecFailed {
        pid: u32,
        release_spec_hash: String,
        operation: String,
        exec_was_attempted: bool,
    },
    Refused {
        operation: String,
        effect_may_have_applied: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeldLauncherState {
    AwaitingSelfAttach,
    AttachedAndHeld,
    ReleasePlannedAndHeld,
    ExecPreparedAndHeld,
    Released,
    TerminalUnknown,
}

/// The exact descriptor numbers the prepared helper holds.
///
/// Protocol version 3 adds `landlock_scopes`, one entry per committed scope in
/// the committed ruleset's own order. Without it the controller could not
/// authenticate the scope descriptors in the helper's `/proc/<pid>/fd`, it
/// would know a scope had been delivered but not where, and the closure proof
/// would have to be weakened to admit descriptors it could not name. The whole
/// point of that proof is that it admits nothing it cannot name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedDescriptorTable {
    executable: u32,
    working_directory: u32,
    target_stdin: u32,
    target_stdout: u32,
    target_stderr: u32,
    cgroup_membership: u32,
    setup_status: u32,
    landlock_scopes: Vec<u32>,
}

impl PreparedDescriptorTable {
    /// Every descriptor number the prepared helper holds, fixed roles first.
    fn all(&self) -> Vec<u32> {
        let mut values = vec![
            self.executable,
            self.working_directory,
            self.target_stdin,
            self.target_stdout,
            self.target_stderr,
            self.cgroup_membership,
            self.setup_status,
        ];
        values.extend(self.landlock_scopes.iter().copied());
        values
    }

    fn validate(&self) -> Result<(), ProtocolFailure> {
        if self.landlock_scopes.len() > MAX_RELEASE_LANDLOCK_SCOPES {
            return Err(ProtocolFailure::new(
                "prepared descriptor table exceeds its hard containment scope bound",
            ));
        }
        let values = self.all();
        if values.iter().any(|descriptor| *descriptor <= 2)
            || values
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != values.len()
        {
            return Err(ProtocolFailure::new(
                "prepared descriptor table contains a standard or duplicate descriptor",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachmentDisposition {
    SendOnce,
    ReconcileAlreadyApplied,
}

impl HeldLauncherState {
    fn attachment_disposition(self) -> Result<AttachmentDisposition, ProtocolFailure> {
        match self {
            Self::AwaitingSelfAttach => Ok(AttachmentDisposition::SendOnce),
            Self::AttachedAndHeld => Ok(AttachmentDisposition::ReconcileAlreadyApplied),
            Self::ReleasePlannedAndHeld
            | Self::ExecPreparedAndHeld
            | Self::Released
            | Self::TerminalUnknown => Err(ProtocolFailure::new(
                "held-launcher attachment is one-shot and no longer available",
            )),
        }
    }

    const fn attached() -> Self {
        Self::AttachedAndHeld
    }

    const fn ambiguous() -> Self {
        Self::TerminalUnknown
    }

    fn require_release_plan(self) -> Result<(), ProtocolFailure> {
        match self {
            Self::AttachedAndHeld => Ok(()),
            Self::AwaitingSelfAttach => Err(ProtocolFailure::new(
                "release is forbidden before exact self-attachment",
            )),
            Self::ReleasePlannedAndHeld | Self::ExecPreparedAndHeld => Err(ProtocolFailure::new(
                "duplicate release planning or preparation is forbidden",
            )),
            Self::Released | Self::TerminalUnknown => Err(ProtocolFailure::new(
                "release is one-shot and no longer available",
            )),
        }
    }

    fn require_helper_preparation(self) -> Result<(), ProtocolFailure> {
        if self == Self::ReleasePlannedAndHeld {
            Ok(())
        } else {
            Err(ProtocolFailure::new(
                "helper preparation requires one exact unreplayed release plan",
            ))
        }
    }

    fn require_release_commit(self) -> Result<(), ProtocolFailure> {
        if self == Self::ExecPreparedAndHeld {
            Ok(())
        } else {
            Err(ProtocolFailure::new(
                "release commit requires one exact helper-prepared held target",
            ))
        }
    }
}

impl StatusEnvelope {
    fn validate_common(
        &self,
        expected: &LauncherBinding,
        sequence: u64,
    ) -> Result<(), ProtocolFailure> {
        self.binding.validate()?;
        if self.protocol_version != HELD_LAUNCHER_PROTOCOL_VERSION
            || self.sequence != sequence
            || &self.binding != expected
        {
            return Err(ProtocolFailure::new(
                "status frame version, sequence, or binding differs from the retained session",
            ));
        }
        Ok(())
    }

    fn validate_ready(
        &self,
        expected: &LauncherBinding,
        expected_pid: u32,
        expected_parent_pid: u32,
    ) -> Result<(), ProtocolFailure> {
        self.validate_common(expected, 0)?;
        match self.status {
            LauncherStatus::Ready {
                pid,
                parent_pid,
                parent_death_signal_armed,
                descriptor_set_exact,
            } if pid == expected_pid
                && parent_pid == expected_parent_pid
                && parent_death_signal_armed
                && descriptor_set_exact =>
            {
                Ok(())
            }
            _ => Err(ProtocolFailure::new(
                "ready status did not prove exact PID, parent, death signal, and descriptor set",
            )),
        }
    }

    fn validate_attached(
        &self,
        expected: &LauncherBinding,
        expected_pid: u32,
    ) -> Result<(), ProtocolFailure> {
        self.validate_common(expected, 1)?;
        match &self.status {
            LauncherStatus::SelfAttached { pid, bytes_written }
                if *pid == expected_pid && *bytes_written == b"0\n".len() =>
            {
                Ok(())
            }
            LauncherStatus::Refused {
                operation,
                effect_may_have_applied,
            } => Err(ProtocolFailure::new(format!(
                "helper refused {operation}; effect_may_have_applied={effect_may_have_applied}"
            ))),
            _ => Err(ProtocolFailure::new(
                "attachment status did not prove the exact self-write",
            )),
        }
    }

    fn validate_exec_prepared(
        &self,
        expected: &LauncherBinding,
        expected_pid: u32,
        expected_release_spec_hash: &str,
    ) -> Result<PreparedDescriptorTable, ProtocolFailure> {
        self.validate_common(expected, 2)?;
        match &self.status {
            LauncherStatus::ExecPrepared {
                pid,
                release_spec_hash,
                descriptors,
                descriptor_set_exact,
                cgroup_membership_exact,
            } if *pid == expected_pid
                && release_spec_hash == expected_release_spec_hash
                && *descriptor_set_exact
                && *cgroup_membership_exact =>
            {
                descriptors.validate()?;
                Ok(descriptors.clone())
            }
            LauncherStatus::Refused {
                operation,
                effect_may_have_applied,
            } => Err(ProtocolFailure::new(format!(
                "helper refused {operation}; effect_may_have_applied={effect_may_have_applied}"
            ))),
            _ => Err(ProtocolFailure::new(
                "prepare status did not prove the exact release specification, descriptor table, and cgroup membership",
            )),
        }
    }

    /// Reads a sequence-3 frame that refused the release **before** the image
    /// replacement, if that is what it is.
    ///
    /// Protocol version 3 needs this because it added a step that can refuse
    /// after the commit is authorized and before the exec is attempted:
    /// installing the containment artefact. That is neither an attempted exec
    /// failure, [`Self::validate_exec_failed`] requires
    /// `exec_was_attempted` and is left byte-identical, nor a released
    /// target. Reporting it as either would be a claim about a process image
    /// that was never replaced.
    ///
    /// `Ok(None)` means the frame is not a refusal, and the caller goes on to
    /// read it as an exec failure exactly as version 2 did.
    fn exec_refusal(
        &self,
        expected: &LauncherBinding,
        expected_pid: u32,
    ) -> Result<Option<String>, ProtocolFailure> {
        self.validate_common(expected, 3)?;
        match &self.status {
            LauncherStatus::Refused {
                operation,
                effect_may_have_applied,
            } if !*effect_may_have_applied && valid_release_text(operation) => {
                Ok(Some(operation.clone()))
            }
            LauncherStatus::Refused { .. } => Err(ProtocolFailure::new(
                "release refusal did not prove a bounded, unapplied pre-exec refusal",
            )),
            _ => {
                let _ = expected_pid;
                Ok(None)
            }
        }
    }

    fn validate_exec_failed(
        &self,
        expected: &LauncherBinding,
        expected_pid: u32,
        expected_release_spec_hash: &str,
    ) -> Result<String, ProtocolFailure> {
        self.validate_common(expected, 3)?;
        match &self.status {
            LauncherStatus::ExecFailed {
                pid,
                release_spec_hash,
                operation,
                exec_was_attempted,
            } if *pid == expected_pid
                && release_spec_hash == expected_release_spec_hash
                && *exec_was_attempted
                && valid_release_text(operation) =>
            {
                Ok(operation.clone())
            }
            _ => Err(ProtocolFailure::new(
                "exec-failure status did not prove an attempted, descriptor-bound exec failure",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProtocolFailure {
    detail: String,
}

impl ProtocolFailure {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

fn validate_identity_text(field: &'static str, value: &str) -> Result<(), ProtocolFailure> {
    if value.is_empty()
        || value.len() > 256
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        Err(ProtocolFailure::new(format!(
            "{field} must be nonblank, bounded, and contain no ASCII whitespace/control bytes"
        )))
    } else {
        Ok(())
    }
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolFailure> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| ProtocolFailure::new(format!("serialize control frame: {error}")))?;
    if bytes.is_empty() || bytes.len() + 1 > MAX_CONTROL_FRAME_BYTES {
        return Err(ProtocolFailure::new(
            "serialized control frame exceeded its hard byte bound",
        ));
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_frame<T>(bytes: &[u8]) -> Result<T, ProtocolFailure>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() < 2
        || bytes.len() > MAX_CONTROL_FRAME_BYTES
        || !bytes.ends_with(b"\n")
        || bytes[..bytes.len() - 1]
            .iter()
            .any(|byte| *byte == b'\n' || *byte == b'\r' || *byte == 0)
    {
        return Err(ProtocolFailure::new(
            "control frame is empty, oversized, multiline, or not newline terminated",
        ));
    }
    let body = &bytes[..bytes.len() - 1];
    let value: T = serde_json::from_slice(body)
        .map_err(|error| ProtocolFailure::new(format!("decode control frame: {error}")))?;
    let canonical = encode_frame(&value)?;
    if canonical != bytes {
        return Err(ProtocolFailure::new(
            "control frame is not in canonical serialized form",
        ));
    }
    Ok(value)
}

/// Runs the fixed held-launcher helper when the exact internal mode argument
/// is present.
///
/// This entry point grants no authority: Linux authority consists solely of
/// the three inherited descriptors and their parent-side retained bindings.
/// Non-Linux builds recognize the argument only to fail closed.
#[doc(hidden)]
#[must_use]
pub fn run_linux_held_launcher_if_requested() -> Option<ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next()?;
    #[cfg(target_os = "linux")]
    {
        if mode == std::ffi::OsStr::new(HELD_LAUNCHER_ARGUMENT) {
            Some(native::run_helper(arguments))
        } else if mode == std::ffi::OsStr::new(INERT_TARGET_ARGUMENT) {
            Some(native::run_inert_target(arguments))
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        if mode == std::ffi::OsStr::new(HELD_LAUNCHER_ARGUMENT)
            || mode == std::ffi::OsStr::new(INERT_TARGET_ARGUMENT)
        {
            Some(ExitCode::from(78))
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
// Re-export the authenticated types used by cgroup callers.
pub(crate) use native::{
    AuthenticatedContainmentRequest, AuthenticatedExecutableDescriptor, AuthenticatedLandlockScope,
    AuthenticatedReleaseDescriptor, ChildContainment, HeldExecCertainty, HeldExecFailure,
    HeldExecRequest, HeldLauncherEffectCertainty, HeldLauncherExpectation, HeldLauncherFailure,
    HeldLauncherRegistry, LinuxProcfs, PlannedHeldExec, PreparedHeldExec,
    ProcessRecoveryObservation, duplicate_onto, spawn_with_child_containment,
};

#[cfg(target_os = "linux")]
mod native {
    include!("linux_held_launcher/native_protocol_and_parent.rs");
    include!("linux_held_launcher/native_release.rs");
    include!("linux_held_launcher/native_fixtures.rs");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> LauncherBinding {
        LauncherBinding {
            session_nonce: "01".repeat(32),
            launch_request_hash: "launch-sha256".into(),
            leaf_identity: DescriptorIdentity {
                device: 7,
                inode: 11,
            },
            cgroup_procs_identity: DescriptorIdentity {
                device: 7,
                inode: 12,
            },
        }
    }

    /// A syntactically complete containment artefact over invented identities.
    ///
    /// Every digest is **computed** rather than written, because a digest a
    /// test could write is a digest a plan could write: the artefact's own
    /// validator is an equality against the canonical preimage, so the fixture
    /// has to go through the same function the launcher does.
    fn containment_artefact(working_directory: DescriptorIdentity) -> ReleaseContainmentArtefact {
        let mut landlock = ReleaseLandlockRuleset {
            created_at_kernel_abi: 4,
            handled_access_bits: 0x1fff,
            scopes: vec![
                ReleaseLandlockScope {
                    object_id: "command-execution-root".into(),
                    resolved_path: "/srv/command/execution".into(),
                    identity: working_directory,
                    access_bits: 0x1fff,
                },
                ReleaseLandlockScope {
                    object_id: "command-output-root".into(),
                    resolved_path: "/srv/command/output".into(),
                    identity: DescriptorIdentity {
                        device: 21,
                        inode: 44,
                    },
                    access_bits: 0xd,
                },
            ],
            denial_witness: ReleaseLandlockWitness {
                resolved_path: "/".into(),
                identity: DescriptorIdentity {
                    device: 1,
                    inode: 2,
                },
            },
            ruleset_sha256: String::new(),
        };
        landlock.ruleset_sha256 = landlock.canonical_digest();
        let mut seccomp = ReleaseSeccompFilter {
            audit_architecture: "audit-arch-aarch64".into(),
            default_action: "kill-process".into(),
            denied_syscalls: vec![
                // Name order, which is what the plan commits.
                ReleaseSeccompSyscall {
                    name: "connect".into(),
                    number: 203,
                },
                ReleaseSeccompSyscall {
                    name: "socket".into(),
                    number: 198,
                },
            ],
            instruction_count: 17,
            program_sha256: "cd".repeat(32),
            filter_sha256: String::new(),
        };
        seccomp.filter_sha256 = seccomp.canonical_digest();
        let mut seccomp_namespace = ReleaseSeccompNamespaceFilter {
            audit_architecture: "audit-arch-aarch64".into(),
            action: "errno-not-implemented".into(),
            denied_syscalls: crate::linux_command_plan::committed_namespace_denials(
                crate::linux_command_plan::LinuxAuditArchitectureV1::Aarch64,
            ),
            instruction_count: 13,
            program_sha256: "ce".repeat(32),
            filter_sha256: String::new(),
        };
        seccomp_namespace.filter_sha256 = seccomp_namespace.canonical_digest();
        ReleaseContainmentArtefact {
            landlock,
            seccomp,
            seccomp_namespace,
        }
    }

    /// The inert release, moved to the contained-command target kind.
    fn contained_command_spec() -> ReleaseExecSpec {
        let mut specification = release_spec();
        specification.target_kind = ReleaseTargetKind::ContainedCommand;
        specification.argv = vec!["/usr/bin/env".into(), "true".into()];
        specification.environment = vec![ReleaseEnvironmentEntry {
            name: "PATH_LIKE_VALUE".into(),
            value: "/usr/bin".into(),
        }];
        specification.containment = Some(containment_artefact(
            specification.working_directory.identity,
        ));
        specification.seal_hash().unwrap();
        specification
    }

    #[test]
    fn an_incomplete_release_namespace_table_is_refused() {
        let drop_unshare = |artefact: &mut ReleaseContainmentArtefact| {
            artefact
                .seccomp_namespace
                .denied_syscalls
                .retain(|denied| denied.name != "unshare");
            artefact.seccomp_namespace.filter_sha256 =
                artefact.seccomp_namespace.canonical_digest();
        };
        let drop_clone = |artefact: &mut ReleaseContainmentArtefact| {
            artefact
                .seccomp_namespace
                .denied_syscalls
                .retain(|denied| denied.name != "clone");
            artefact.seccomp_namespace.filter_sha256 =
                artefact.seccomp_namespace.canonical_digest();
        };
        let drop_flag = |artefact: &mut ReleaseContainmentArtefact| {
            for denied in &mut artefact.seccomp_namespace.denied_syscalls {
                if let crate::linux_command_plan::LinuxSeccompDenialConditionV1::AnyArgumentFlagSet {
                    flags,
                    ..
                } = &mut denied.condition
                {
                    flags.pop();
                }
            }
            artefact.seccomp_namespace.filter_sha256 =
                artefact.seccomp_namespace.canonical_digest();
        };
        let empty_flags = |artefact: &mut ReleaseContainmentArtefact| {
            for denied in &mut artefact.seccomp_namespace.denied_syscalls {
                if let crate::linux_command_plan::LinuxSeccompDenialConditionV1::AnyArgumentFlagSet {
                    flags,
                    ..
                } = &mut denied.condition
                {
                    flags.clear();
                }
            }
            artefact.seccomp_namespace.filter_sha256 =
                artefact.seccomp_namespace.canonical_digest();
        };
        for mutate in [drop_unshare, drop_clone, drop_flag, empty_flags] {
            let mut specification = contained_command_spec();
            mutate(specification.containment.as_mut().unwrap());
            specification.seal_hash().unwrap();
            let failure = specification.validate().unwrap_err();
            assert!(
                failure.detail.contains("exact required set")
                    || failure.detail.contains("lists no flag"),
                "an incomplete namespace table was admitted or refused for the wrong reason: {}",
                failure.detail
            );
        }
    }

    #[test]
    fn a_contained_command_is_expressible_and_must_carry_its_artefact() {
        let exact = contained_command_spec();
        exact.validate().unwrap();
        // The whole point of version 3: a user command, with argv and an
        // environment version 2's single target kind could not describe.
        assert_eq!(exact.argv, ["/usr/bin/env", "true"]);

        let mut without = exact.clone();
        without.containment = None;
        without.seal_hash().unwrap();
        let failure = without.validate().unwrap_err();
        assert!(
            failure
                .detail
                .contains("must carry the containment artefact it installs"),
            "{}",
            failure.detail
        );

        // And the inverse: the inert internal target installs nothing, so it
        // may not claim an artefact either.
        let mut inert = release_spec();
        inert.containment = Some(containment_artefact(inert.working_directory.identity));
        inert.seal_hash().unwrap();
        let failure = inert.validate().unwrap_err();
        assert!(
            failure.detail.contains("may not carry an artefact"),
            "{}",
            failure.detail
        );
    }

    #[test]
    fn a_containment_artefact_digest_cannot_be_invented_or_left_stale() {
        for mutate in [
            |artefact: &mut ReleaseContainmentArtefact| {
                artefact.landlock.scopes[1].identity.inode += 1;
            },
            |artefact: &mut ReleaseContainmentArtefact| {
                "/etc".clone_into(&mut artefact.landlock.scopes[1].resolved_path);
            },
            |artefact: &mut ReleaseContainmentArtefact| {
                artefact.landlock.created_at_kernel_abi = 5;
            },
            |artefact: &mut ReleaseContainmentArtefact| {
                artefact.landlock.ruleset_sha256 = "ef".repeat(32);
            },
            |artefact: &mut ReleaseContainmentArtefact| {
                artefact.seccomp.denied_syscalls[0].number = 199;
            },
            |artefact: &mut ReleaseContainmentArtefact| {
                artefact.seccomp.instruction_count += 1;
            },
            |artefact: &mut ReleaseContainmentArtefact| {
                "audit-arch-x86-64".clone_into(&mut artefact.seccomp.audit_architecture);
            },
            |artefact: &mut ReleaseContainmentArtefact| {
                artefact.seccomp.filter_sha256 = "ef".repeat(32);
            },
        ] {
            let mut specification = contained_command_spec();
            mutate(specification.containment.as_mut().unwrap());
            specification.seal_hash().unwrap();
            let failure = specification.validate().unwrap_err();
            assert!(
                failure.detail.contains("is not the digest of the")
                    || failure
                        .detail
                        .contains("working directory is not one of the scopes"),
                "a mutated artefact was admitted or refused for the wrong reason: {}",
                failure.detail
            );
        }
    }

    #[test]
    fn a_contained_command_ruleset_must_grant_its_own_working_directory() {
        let mut specification = contained_command_spec();
        let containment = specification.containment.as_mut().unwrap();
        containment.landlock.scopes.remove(0);
        containment.landlock.ruleset_sha256 = containment.landlock.canonical_digest();
        specification.seal_hash().unwrap();
        let failure = specification.validate().unwrap_err();
        assert!(
            failure
                .detail
                .contains("working directory is not one of the scopes its ruleset grants"),
            "{}",
            failure.detail
        );
    }

    #[test]
    fn a_ruleset_cannot_grant_beyond_what_it_handles_or_witness_what_it_grants() {
        // A scope granting a right the ruleset does not handle would be a
        // policy whose own handled set does not bound it.
        let mut specification = contained_command_spec();
        {
            let containment = specification.containment.as_mut().unwrap();
            containment.landlock.scopes[1].access_bits = 0x1_ffff;
            containment.landlock.ruleset_sha256 = containment.landlock.canonical_digest();
        }
        specification.seal_hash().unwrap();
        assert!(
            specification
                .validate()
                .unwrap_err()
                .detail
                .contains("grants a right the ruleset does not handle")
        );

        // A witness inside a granted scope proves nothing: the open would
        // succeed under a kernel that enforced the ruleset perfectly.
        let mut specification = contained_command_spec();
        {
            let containment = specification.containment.as_mut().unwrap();
            containment.landlock.denial_witness.identity = containment.landlock.scopes[0].identity;
            containment.landlock.ruleset_sha256 = containment.landlock.canonical_digest();
        }
        specification.seal_hash().unwrap();
        assert!(
            specification
                .validate()
                .unwrap_err()
                .detail
                .contains("denial witness is one of the scopes the ruleset grants")
        );

        // An errno-returning filter would let a denied syscall be retried.
        let mut specification = contained_command_spec();
        {
            let containment = specification.containment.as_mut().unwrap();
            "errno".clone_into(&mut containment.seccomp.default_action);
            containment.seccomp.filter_sha256 = containment.seccomp.canonical_digest();
        }
        specification.seal_hash().unwrap();
        assert!(
            specification
                .validate()
                .unwrap_err()
                .detail
                .contains("must commit the kill-process matched action")
        );
    }

    #[test]
    fn a_durable_release_binding_carries_and_checks_its_protocol_version() {
        let binding = HeldExecReleaseBinding::from_specification(&contained_command_spec());
        binding.validate().unwrap();
        let encoded = serde_json::to_value(&binding).unwrap();
        assert_eq!(
            encoded
                .get("protocol_version")
                .and_then(serde_json::Value::as_u64),
            Some(u64::from(HELD_LAUNCHER_PROTOCOL_VERSION))
        );

        // A record shaped like this one but written by the protocol that never
        // wrote the field is exactly what the peek has to name.
        let mut unversioned = encoded.clone();
        unversioned
            .as_object_mut()
            .unwrap()
            .remove("protocol_version");
        let record = serde_json::json!({ "release_binding": unversioned });
        assert_eq!(
            held_launcher_protocol_version_peek(&record),
            HeldLauncherProtocolPeek::Unversioned
        );
        assert_eq!(
            held_launcher_protocol_version_peek(&serde_json::json!({ "release_binding": encoded })),
            HeldLauncherProtocolPeek::Version(u64::from(HELD_LAUNCHER_PROTOCOL_VERSION))
        );
        // No binding at all is the normal shape of every generation before one
        // is planned, and must not be confused with a stale one.
        assert_eq!(
            held_launcher_protocol_version_peek(&serde_json::json!({ "release_binding": null })),
            HeldLauncherProtocolPeek::NoReleaseBinding
        );
        assert_eq!(
            held_launcher_protocol_version_peek(&serde_json::json!({})),
            HeldLauncherProtocolPeek::NoReleaseBinding
        );

        let mut stale: HeldExecReleaseBinding = binding;
        stale.protocol_version = HELD_LAUNCHER_UNVERSIONED_PROTOCOL_VERSION;
        let refusal = stale.validate().unwrap_err();
        assert!(refusal.contains("protocol version 2"), "{refusal}");
        assert!(refusal.contains("version 4"), "{refusal}");
    }

    #[test]
    fn the_artefact_channel_fits_one_atomic_control_frame() {
        // Shaped like the artefact the production plan actually mints: the
        // command's four per-command data directories, and the nineteen
        // network-endpoint syscalls `LINUX_NETWORK_SYSCALLS` denies. A bound
        // measured against a two-scope fixture would prove nothing about the
        // frame the launcher has to carry.
        let mut specification = contained_command_spec();
        {
            let containment = specification.containment.as_mut().unwrap();
            for (index, object_id) in [
                "command-private-state-root",
                "command-workspace-shadow-root",
            ]
            .into_iter()
            .enumerate()
            {
                containment.landlock.scopes.push(ReleaseLandlockScope {
                    object_id: object_id.to_owned(),
                    resolved_path: format!("/srv/command/{object_id}"),
                    identity: DescriptorIdentity {
                        device: 21,
                        inode: 100 + index as u64,
                    },
                    access_bits: 0x1fff,
                });
            }
            containment
                .landlock
                .scopes
                .sort_by(|left, right| left.object_id.cmp(&right.object_id));
            containment.landlock.ruleset_sha256 = containment.landlock.canonical_digest();
            for number in 204..221 {
                containment
                    .seccomp
                    .denied_syscalls
                    .push(ReleaseSeccompSyscall {
                        name: format!("denied_network_syscall_{number}"),
                        number,
                    });
            }
            containment
                .seccomp
                .denied_syscalls
                .sort_by(|left, right| left.name.cmp(&right.name));
            containment.seccomp.filter_sha256 = containment.seccomp.canonical_digest();
        }
        specification.seal_hash().unwrap();
        specification.validate().unwrap();
        assert_eq!(
            specification
                .containment
                .as_ref()
                .unwrap()
                .seccomp
                .denied_syscalls
                .len(),
            19
        );
        let prepare = ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 2,
            binding: binding(),
            command: LauncherCommand::PrepareExec {
                specification: Box::new(specification),
            },
        };
        let bytes = encode_frame(&prepare).unwrap();
        // Version 2's 2,048-byte bound is what the artefact channel did not fit
        // in; the point of the new bound is that it is still a hard one.
        assert!(bytes.len() > 2_048, "{}", bytes.len());
        assert!(bytes.len() <= MAX_CONTROL_FRAME_BYTES, "{}", bytes.len());
        let decoded: ControlEnvelope = decode_frame(&bytes).unwrap();
        assert_eq!(decoded, prepare);
        decoded.validate_prepare_exec(&binding()).unwrap();
    }

    fn release_spec() -> ReleaseExecSpec {
        let token = "release-token";
        let cwd = ParentDescriptorBinding {
            descriptor: 11,
            identity: DescriptorIdentity {
                device: 21,
                inode: 22,
            },
        };
        let mut specification = ReleaseExecSpec {
            release_spec_hash: String::new(),
            target_kind: ReleaseTargetKind::InertInternalTest,
            executable: ExecutableDescriptorBinding {
                authority: ParentDescriptorBinding {
                    descriptor: 10,
                    identity: DescriptorIdentity {
                        device: 19,
                        inode: 20,
                    },
                },
                image_type: ExecutableImageType::SealedMemfd,
                byte_len: 4_096,
                content_sha256: "ab".repeat(32),
                seal_bits: REQUIRED_EXECUTABLE_SEAL_BITS,
            },
            working_directory: cwd,
            target_stdin: ParentDescriptorBinding {
                descriptor: 12,
                identity: DescriptorIdentity {
                    device: 23,
                    inode: 24,
                },
            },
            target_stdout: ParentDescriptorBinding {
                descriptor: 13,
                identity: DescriptorIdentity {
                    device: 25,
                    inode: 26,
                },
            },
            target_stderr: ParentDescriptorBinding {
                descriptor: 14,
                identity: DescriptorIdentity {
                    device: 27,
                    inode: 28,
                },
            },
            cgroup_membership: ParentDescriptorBinding {
                descriptor: 15,
                identity: binding().cgroup_procs_identity,
            },
            argv: vec![
                "grok-build-inert-target".into(),
                INERT_TARGET_ARGUMENT.into(),
                token.into(),
                cwd.identity.device.to_string(),
                cwd.identity.inode.to_string(),
            ],
            environment: vec![
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_CWD_DEVICE".into(),
                    value: cwd.identity.device.to_string(),
                },
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_CWD_INODE".into(),
                    value: cwd.identity.inode.to_string(),
                },
                ReleaseEnvironmentEntry {
                    name: "GROK_BUILD_INERT_TOKEN".into(),
                    value: token.into(),
                },
            ],
            containment: None,
        };
        specification.seal_hash().unwrap();
        specification
    }

    #[test]
    fn canonical_self_attach_frame_round_trips() {
        let frame = ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 1,
            binding: binding(),
            command: LauncherCommand::SelfAttach {
                exact_value: b"0\n".to_vec(),
            },
        };
        let bytes = encode_frame(&frame).unwrap();
        let decoded: ControlEnvelope = decode_frame(&bytes).unwrap();
        assert_eq!(decoded, frame);
        decoded.validate_self_attach(&binding()).unwrap();
    }

    #[test]
    fn crossed_nonce_and_sequence_are_rejected() {
        let mut frame = ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 2,
            binding: binding(),
            command: LauncherCommand::SelfAttach {
                exact_value: b"0\n".to_vec(),
            },
        };
        assert!(frame.validate_self_attach(&binding()).is_err());
        frame.sequence = 1;
        frame.binding.session_nonce = "02".repeat(32);
        assert!(frame.validate_self_attach(&binding()).is_err());
    }

    #[test]
    fn numeric_pid_and_parent_prose_cannot_replace_self_attach_literal() {
        for value in [b"123\n".as_slice(), b"0".as_slice(), b"0\n1\n".as_slice()] {
            let frame = ControlEnvelope {
                protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
                sequence: 1,
                binding: binding(),
                command: LauncherCommand::SelfAttach {
                    exact_value: value.to_vec(),
                },
            };
            assert!(frame.validate_self_attach(&binding()).is_err());
        }
    }

    #[test]
    fn noncanonical_and_unknown_field_frames_are_rejected() {
        let frame = ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 1,
            binding: binding(),
            command: LauncherCommand::SelfAttach {
                exact_value: b"0\n".to_vec(),
            },
        };
        let canonical = encode_frame(&frame).unwrap();
        let mut spaced = canonical.clone();
        spaced.insert(1, b' ');
        assert!(decode_frame::<ControlEnvelope>(&spaced).is_err());

        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical[..canonical.len() - 1]).unwrap();
        value["forged"] = serde_json::json!(true);
        let mut forged = serde_json::to_vec(&value).unwrap();
        forged.push(b'\n');
        assert!(decode_frame::<ControlEnvelope>(&forged).is_err());
    }

    #[test]
    fn ready_and_attach_status_bind_exact_process_and_descriptor_session() {
        let ready = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 0,
            binding: binding(),
            status: LauncherStatus::Ready {
                pid: 41,
                parent_pid: 17,
                parent_death_signal_armed: true,
                descriptor_set_exact: true,
            },
        };
        ready.validate_ready(&binding(), 41, 17).unwrap();
        assert!(ready.validate_ready(&binding(), 42, 17).is_err());

        let attached = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 1,
            binding: binding(),
            status: LauncherStatus::SelfAttached {
                pid: 41,
                bytes_written: 2,
            },
        };
        attached.validate_attached(&binding(), 41).unwrap();
    }

    #[test]
    fn oversized_multiline_and_trailing_frames_are_rejected() {
        assert!(decode_frame::<ControlEnvelope>(&vec![b'x'; MAX_CONTROL_FRAME_BYTES + 1]).is_err());
        assert!(decode_frame::<ControlEnvelope>(b"{}\n{}\n").is_err());
        assert!(decode_frame::<ControlEnvelope>(b"{}").is_err());
    }

    #[test]
    fn attachment_state_is_one_shot_and_ambiguity_is_terminal() {
        let awaiting = HeldLauncherState::AwaitingSelfAttach;
        assert_eq!(
            awaiting.attachment_disposition().unwrap(),
            AttachmentDisposition::SendOnce
        );
        assert_eq!(
            HeldLauncherState::attached()
                .attachment_disposition()
                .unwrap(),
            AttachmentDisposition::ReconcileAlreadyApplied
        );
        assert!(
            HeldLauncherState::ambiguous()
                .attachment_disposition()
                .is_err()
        );
        assert!(
            HeldLauncherState::ExecPreparedAndHeld
                .attachment_disposition()
                .is_err()
        );
        assert!(
            HeldLauncherState::Released
                .attachment_disposition()
                .is_err()
        );
    }

    #[test]
    fn canonical_two_phase_release_binds_all_authority_and_process_inputs() {
        let specification = release_spec();
        specification.validate().unwrap();
        let prepare = ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 2,
            binding: binding(),
            command: LauncherCommand::PrepareExec {
                specification: Box::new(specification.clone()),
            },
        };
        let bytes = encode_frame(&prepare).unwrap();
        let decoded: ControlEnvelope = decode_frame(&bytes).unwrap();
        assert_eq!(
            decoded.validate_prepare_exec(&binding()).unwrap(),
            &specification
        );

        let commit = ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 3,
            binding: binding(),
            command: LauncherCommand::CommitExec {
                release_spec_hash: specification.release_spec_hash.clone(),
            },
        };
        commit
            .validate_commit_exec(&binding(), &specification.release_spec_hash)
            .unwrap();
    }

    #[test]
    fn release_has_no_source_path_and_rejects_descriptor_substitution() {
        let exact = release_spec();
        let encoded = encode_frame(&ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 2,
            binding: binding(),
            command: LauncherCommand::PrepareExec {
                specification: Box::new(exact.clone()),
            },
        })
        .unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(!text.contains("source_path"));
        assert!(!text.contains("PATH"));

        for mutate in [
            |specification: &mut ReleaseExecSpec| {
                specification.executable.authority.identity.inode += 1;
            },
            |specification: &mut ReleaseExecSpec| {
                specification.working_directory.descriptor =
                    specification.executable.authority.descriptor;
            },
            |specification: &mut ReleaseExecSpec| {
                specification.target_stdout.identity = specification.target_stdin.identity;
                specification.target_stdout.descriptor = specification.target_stdin.descriptor;
            },
        ] {
            let mut substituted = exact.clone();
            mutate(&mut substituted);
            assert!(substituted.validate().is_err());
        }
    }

    #[test]
    fn release_rejects_missing_exec_and_unexpected_seal_bits() {
        for seal_bits in [
            REQUIRED_EXECUTABLE_SEAL_BITS & !0x20,
            REQUIRED_EXECUTABLE_SEAL_BITS | 0x40,
        ] {
            let mut specification = release_spec();
            specification.executable.seal_bits = seal_bits;
            specification.seal_hash().unwrap();
            let failure = specification.validate().unwrap_err();
            assert!(
                failure
                    .detail
                    .contains("exact admitted executable seal set")
            );
        }
    }

    #[test]
    fn malformed_duplicate_and_unexpected_release_transitions_fail_closed() {
        let specification = release_spec();
        let mut wrong_hash = specification.clone();
        wrong_hash.release_spec_hash = "cd".repeat(32);
        assert!(wrong_hash.validate().is_err());

        let duplicate_prepare = ControlEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 3,
            binding: binding(),
            command: LauncherCommand::PrepareExec {
                specification: Box::new(specification),
            },
        };
        assert!(duplicate_prepare.validate_prepare_exec(&binding()).is_err());
        assert!(
            HeldLauncherState::AwaitingSelfAttach
                .require_release_plan()
                .is_err()
        );
        HeldLauncherState::AttachedAndHeld
            .require_release_plan()
            .unwrap();
        assert!(
            HeldLauncherState::ExecPreparedAndHeld
                .require_release_plan()
                .is_err()
        );
        HeldLauncherState::ReleasePlannedAndHeld
            .require_helper_preparation()
            .unwrap();
        HeldLauncherState::ExecPreparedAndHeld
            .require_release_commit()
            .unwrap();
        assert!(
            HeldLauncherState::Released
                .require_release_commit()
                .is_err()
        );
    }

    #[test]
    fn prepared_and_exec_failure_statuses_are_exactly_bound() {
        let specification = release_spec();
        let descriptors = PreparedDescriptorTable {
            executable: 3,
            working_directory: 4,
            target_stdin: 5,
            target_stdout: 6,
            target_stderr: 7,
            cgroup_membership: 8,
            setup_status: 9,
            landlock_scopes: vec![10, 11],
        };
        let prepared = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 2,
            binding: binding(),
            status: LauncherStatus::ExecPrepared {
                pid: 41,
                release_spec_hash: specification.release_spec_hash.clone(),
                descriptors: descriptors.clone(),
                descriptor_set_exact: true,
                cgroup_membership_exact: true,
            },
        };
        assert_eq!(
            prepared
                .validate_exec_prepared(&binding(), 41, &specification.release_spec_hash)
                .unwrap(),
            descriptors
        );
        // The scope descriptors are part of the closure the controller proves,
        // so a table that reuses a fixed role's number for a scope is refused
        // exactly as a duplicated fixed role always was.
        let mut aliased = descriptors.clone();
        aliased.landlock_scopes = vec![9];
        assert!(aliased.validate().is_err());

        let failed = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 3,
            binding: binding(),
            status: LauncherStatus::ExecFailed {
                pid: 41,
                release_spec_hash: specification.release_spec_hash.clone(),
                operation: "descriptor-exec-enoexec".into(),
                exec_was_attempted: true,
            },
        };
        assert_eq!(
            failed
                .validate_exec_failed(&binding(), 41, &specification.release_spec_hash)
                .unwrap(),
            "descriptor-exec-enoexec"
        );
        // An attempted exec failure is not a pre-exec refusal, and the two
        // must not be readable as each other: version 3 added a step that can
        // refuse after the commit and before the image replacement.
        assert_eq!(failed.exec_refusal(&binding(), 41).unwrap(), None);

        let refused = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 3,
            binding: binding(),
            status: LauncherStatus::Refused {
                operation: "install-release-containment: was not denied".into(),
                effect_may_have_applied: false,
            },
        };
        assert_eq!(
            refused.exec_refusal(&binding(), 41).unwrap().as_deref(),
            Some("install-release-containment: was not denied")
        );
        assert!(
            refused
                .validate_exec_failed(&binding(), 41, &specification.release_spec_hash)
                .is_err()
        );

        // A refusal that admits the effect may have applied is not a pre-exec
        // refusal at all, and is refused rather than rounded down.
        let ambiguous = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 3,
            binding: binding(),
            status: LauncherStatus::Refused {
                operation: "install-release-containment: unknown".into(),
                effect_may_have_applied: true,
            },
        };
        assert!(ambiguous.exec_refusal(&binding(), 41).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_stat_parser_uses_final_command_delimiter() {
        let mut fields = vec!["S", "17"];
        fields.extend(std::iter::repeat_n("1", 17));
        fields.push("991");
        let bytes = format!("41 (name with ) delimiter) {}\n", fields.join(" ")).into_bytes();
        let observation = native::parse_proc_stat(&bytes, 41).unwrap();
        assert_eq!(observation.parent_pid, 17);
        assert_eq!(observation.start_time_ticks, 991);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn genuine_procfs_reports_the_exact_current_executable_name() {
        use std::os::unix::fs::MetadataExt as _;

        let procfs = native::LinuxProcfs::open_authenticated().unwrap();
        let (_retained, identity) = procfs.retain_self_executable().unwrap();
        let path = procfs.self_executable_path(identity).unwrap();
        assert!(path.is_absolute());
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.dev(), identity.device);
        assert_eq!(metadata.ino(), identity.inode);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn genuine_procfs_distinguishes_absence_from_pid_reuse() {
        let procfs = native::LinuxProcfs::open_authenticated().unwrap();
        let current = std::process::id();
        assert_eq!(
            procfs.recovery_observation(current, u64::MAX).unwrap(),
            native::ProcessRecoveryObservation::PidReused
        );
        assert_eq!(
            procfs.recovery_observation(u32::MAX, 1).unwrap(),
            native::ProcessRecoveryObservation::Absent
        );
    }
}
