//! Narrow macOS `posix_spawn` bridge for an inert, cleanup-only child observed
//! held at one bounded point in time.
//!
//! This module closes one concrete native-mechanics gap: it applies Darwin's
//! `POSIX_SPAWN_CLOEXEC_DEFAULT`, an explicit five-descriptor allowlist,
//! descriptor-relative working-directory selection, `POSIX_SPAWN_SETSID`, and
//! `POSIX_SPAWN_START_SUSPENDED` in one kernel spawn operation. Two independent
//! `libproc` reads must then agree that the exact direct child was a stopped
//! session leader with only descriptors 0 through 4 at the receipt timestamp.
//!
//! The resulting type deliberately has no release operation. It can only emit
//! bounded canonical point-in-time observation bytes or attempt to kill and
//! reap its exact direct child. Same-UID signalling can resume the child after
//! observation, so neither the Rust handle nor the receipt claims continuing
//! custody or a crash-safe cross-process control channel. This is useful
//! mechanics evidence for the helper's eventual held-launch seam, but is not
//! signed-service, XPC, dedicated-UID, credential-drop, Seatbelt,
//! descendant-domain, or Gate-1 authority.

#![allow(dead_code)] // Wired only after signed helper authority exists.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::CString;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use grok_build_core::Digest;
use rustix::fs::{Mode, OFlags, fstat, open};
use rustix::io::fcntl_dupfd_cloexec;
#[cfg(test)]
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::process::{
    Pid, Signal, WaitOptions, WaitStatus, getpid, getsid, kill_process, waitpid,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::macos_runner_held_protocol::{
    MacosOrdinaryRunnerLaunchAuthority, MacosRetainedRunnerExecutableExpectation,
};
#[cfg(test)]
use crate::wire::WireBinaryIdentity;

const MACOS_NATIVE_HELD_LAUNCH_SCHEMA_VERSION: u32 = 1;
const MACOS_NATIVE_HELD_CLEANUP_SCHEMA_VERSION: u32 = 1;
const RECEIPT_DOMAIN: &[u8] = b"grok-build.macos-native-held-launch-receipt.v1\0";
const CLEANUP_DOMAIN: &[u8] = b"grok-build.macos-native-held-launch-cleanup.v1\0";
const POST_SPAWN_CLEANUP_DOMAIN: &[u8] = b"grok-build.macos-native-post-spawn-cleanup.v1\0";
const BINDING_DOMAIN: &[u8] = b"grok-build.macos-native-held-launch-binding.v1\0";
const AUTHORITY_DOMAIN: &[u8] = b"grok-build.macos-native-held-launch-authority.v1\0";
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1_024 * 1_024;
const MAX_RECEIPT_BYTES: usize = 32 * 1_024;
const MAX_ARGUMENTS: usize = 256;
const MAX_TEXT_BYTES: usize = 4 * 1_024;
const MAX_FAILURE_DETAIL_BYTES: usize = 1_024;
const FIRST_NORMALIZED_DESCRIPTOR: i32 = 10;
const EXPECTED_CHILD_DESCRIPTORS: [i32; 5] = [0, 1, 2, 3, 4];
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Darwin `POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSID |
/// POSIX_SPAWN_CLOEXEC_DEFAULT` from the macOS 15 SDK.
const REQUIRED_SPAWN_FLAGS: i16 = 0x0080 | 0x0400 | 0x4000;

/// Deadline and polling interval for reaping an exact direct child.
/// A `POSIX_SPAWN_START_SUSPENDED` child can retain a pending `SIGKILL` without
/// becoming reapable. Re-signal between `NOHANG` polls and report any child that
/// survives the deadline instead of blocking indefinitely.
const CONDEMNED_CHILD_REAP_DEADLINE: Duration = Duration::from_secs(5);
const CONDEMNED_CHILD_REAP_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Closed assurance vocabulary for this deliberately non-admissible tranche.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MacosNativeHeldLaunchAssurance {
    /// Real kernel launch/readback, but no authenticated signed helper or
    /// aggregate command-domain containment.
    KernelObservedCleanupOnlyNoServiceAuthority,
}

/// Stable descriptor/file identity captured before the native effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosNativeObjectIdentityV1 {
    device_id: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    byte_length: u64,
    link_count: u64,
}

/// One explicit target slot in the child descriptor allowlist.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosNativeDescriptorBindingV1 {
    target_fd: i32,
    source_identity: MacosNativeObjectIdentityV1,
}

/// One environment entry; the enclosing vector is bytewise name-sorted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosNativeEnvironmentEntryV1 {
    name: String,
    value: String,
}

/// Exact path-local executable observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosNativePathLocalExecutableObservationV1 {
    canonical_path_bytes: Vec<u8>,
    object: MacosNativeObjectIdentityV1,
    complete_bytes_digest: Digest,
}

/// One raw `libproc` observation that the direct child was stopped at one time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosNativeHeldProcessObservationV1 {
    pid: u32,
    parent_pid: u32,
    process_group_id: u32,
    session_id: u32,
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    status: u32,
    start_time_seconds: u64,
    start_time_microseconds: u64,
    open_descriptors: Vec<i32>,
    executable_path_bytes: Vec<u8>,
    observed_at_unix_ms: u64,
}

/// Canonical, byte-exact receipt for a real cleanup-only child observed held at
/// two adjacent points in time. It makes no continuing-custody claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosNativeObservedHeldAtReceiptV1 {
    schema_version: u32,
    assurance: MacosNativeHeldLaunchAssurance,
    native_journal_id: String,
    launch_authority_digest: Digest,
    binding_digest: Digest,
    controller_pid: u32,
    path_local_executable: MacosNativePathLocalExecutableObservationV1,
    argv: Vec<String>,
    environment: Vec<MacosNativeEnvironmentEntryV1>,
    working_directory: MacosNativeObjectIdentityV1,
    descriptor_bindings: Vec<MacosNativeDescriptorBindingV1>,
    spawn_flags: i16,
    observations: [MacosNativeHeldProcessObservationV1; 2],
    observed_held_at_unix_ms: u64,
    receipt_digest: Digest,
}

#[derive(Serialize)]
struct LaunchBindingPreimage<'a> {
    schema_version: u32,
    assurance: MacosNativeHeldLaunchAssurance,
    native_journal_id: &'a str,
    launch_authority_digest: &'a Digest,
    controller_pid: u32,
    path_local_executable: &'a MacosNativePathLocalExecutableObservationV1,
    argv: &'a [String],
    environment: &'a [MacosNativeEnvironmentEntryV1],
    working_directory: &'a MacosNativeObjectIdentityV1,
    descriptor_bindings: &'a [MacosNativeDescriptorBindingV1],
    spawn_flags: i16,
}

#[derive(Serialize)]
struct LaunchReceiptPreimage<'a> {
    schema_version: u32,
    assurance: MacosNativeHeldLaunchAssurance,
    native_journal_id: &'a str,
    launch_authority_digest: &'a Digest,
    binding_digest: &'a Digest,
    controller_pid: u32,
    path_local_executable: &'a MacosNativePathLocalExecutableObservationV1,
    argv: &'a [String],
    environment: &'a [MacosNativeEnvironmentEntryV1],
    working_directory: &'a MacosNativeObjectIdentityV1,
    descriptor_bindings: &'a [MacosNativeDescriptorBindingV1],
    spawn_flags: i16,
    observations: &'a [MacosNativeHeldProcessObservationV1; 2],
    observed_held_at_unix_ms: u64,
}

impl MacosNativeObservedHeldAtReceiptV1 {
    /// Returns the domain-separated digest used by the existing held journal's
    /// opaque native-observation join.
    pub(crate) const fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    /// Returns the exact observed-child PID for independent host observation.
    pub(crate) const fn pid(&self) -> u32 {
        self.observations[1].pid
    }

    /// Returns the trusted wall-clock bound of the second stable observation.
    pub(crate) const fn observed_held_at_unix_ms(&self) -> u64 {
        self.observed_held_at_unix_ms
    }

    /// Encodes one canonical bounded receipt.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MacosNativeHeldLaunchError> {
        self.validate()?;
        let json = serde_json::to_vec(self).map_err(|error| {
            MacosNativeHeldLaunchError::Encoding(format!("encode held receipt: {error}"))
        })?;
        let mut bytes = Vec::with_capacity(RECEIPT_DOMAIN.len() + json.len());
        bytes.extend_from_slice(RECEIPT_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "held receipt exceeds its fixed byte bound".into(),
            ));
        }
        Ok(bytes)
    }

    /// Reopens exact canonical bytes and revalidates every redundant join.
    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, MacosNativeHeldLaunchError> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "held receipt is empty or oversized".into(),
            ));
        }
        let json = bytes.strip_prefix(RECEIPT_DOMAIN).ok_or_else(|| {
            MacosNativeHeldLaunchError::Invalid("held receipt domain is absent".into())
        })?;
        let receipt: Self = serde_json::from_slice(json).map_err(|error| {
            MacosNativeHeldLaunchError::Encoding(format!("decode held receipt: {error}"))
        })?;
        if serde_json::to_vec(&receipt).map_err(|error| {
            MacosNativeHeldLaunchError::Encoding(format!("re-encode held receipt: {error}"))
        })? != json
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "held receipt bytes are noncanonical".into(),
            ));
        }
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), MacosNativeHeldLaunchError> {
        validate_identifier(&self.native_journal_id)?;
        validate_argv(&self.argv)?;
        validate_environment(&self.environment)?;
        validate_path_local_executable(&self.path_local_executable)?;
        if self.working_directory.device_id == 0
            || self.working_directory.inode == 0
            || self.working_directory.mode & 0o170_000 != 0o040_000
            || self
                .descriptor_bindings
                .iter()
                .any(|binding| binding.source_identity.inode == 0)
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "working-directory or descriptor-source identity is invalid".into(),
            ));
        }
        if self.schema_version != MACOS_NATIVE_HELD_LAUNCH_SCHEMA_VERSION
            || self.assurance
                != MacosNativeHeldLaunchAssurance::KernelObservedCleanupOnlyNoServiceAuthority
            || self.spawn_flags != REQUIRED_SPAWN_FLAGS
            || self.controller_pid <= 1
            || self.descriptor_bindings.len() != EXPECTED_CHILD_DESCRIPTORS.len()
            || self
                .descriptor_bindings
                .iter()
                .map(|binding| binding.target_fd)
                .ne(EXPECTED_CHILD_DESCRIPTORS)
            || self.binding_digest != self.computed_binding_digest()?
            || self.receipt_digest != self.computed_receipt_digest()?
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "held receipt version, assurance, binding, allowlist, or digest differs".into(),
            ));
        }
        let [first, second] = &self.observations;
        if first.pid <= 1
            || first.pid != second.pid
            || first.parent_pid != self.controller_pid
            || second.parent_pid != self.controller_pid
            || first.process_group_id != first.pid
            || second.process_group_id != second.pid
            || first.session_id != first.pid
            || second.session_id != second.pid
            || first.real_uid != second.real_uid
            || first.effective_uid != second.effective_uid
            || first.saved_uid != second.saved_uid
            || first.real_gid != second.real_gid
            || first.effective_gid != second.effective_gid
            || first.saved_gid != second.saved_gid
            || first.status != darwin_spawn::PROCESS_STATUS_STOPPED
            || second.status != darwin_spawn::PROCESS_STATUS_STOPPED
            || first.start_time_seconds != second.start_time_seconds
            || first.start_time_microseconds != second.start_time_microseconds
            || first.open_descriptors != EXPECTED_CHILD_DESCRIPTORS
            || second.open_descriptors != EXPECTED_CHILD_DESCRIPTORS
            || first.executable_path_bytes != self.path_local_executable.canonical_path_bytes
            || second.executable_path_bytes != self.path_local_executable.canonical_path_bytes
            || first.observed_at_unix_ms == 0
            || second.observed_at_unix_ms < first.observed_at_unix_ms
            || self.observed_held_at_unix_ms != second.observed_at_unix_ms
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "held process observations are crossed, unstable, runnable, or outside the exact descriptor contract".into(),
            ));
        }
        Ok(())
    }

    fn computed_binding_digest(&self) -> Result<Digest, MacosNativeHeldLaunchError> {
        domain_digest(
            BINDING_DOMAIN,
            &LaunchBindingPreimage {
                schema_version: self.schema_version,
                assurance: self.assurance,
                native_journal_id: &self.native_journal_id,
                launch_authority_digest: &self.launch_authority_digest,
                controller_pid: self.controller_pid,
                path_local_executable: &self.path_local_executable,
                argv: &self.argv,
                environment: &self.environment,
                working_directory: &self.working_directory,
                descriptor_bindings: &self.descriptor_bindings,
                spawn_flags: self.spawn_flags,
            },
        )
    }

    fn computed_receipt_digest(&self) -> Result<Digest, MacosNativeHeldLaunchError> {
        domain_digest(
            RECEIPT_DOMAIN,
            &LaunchReceiptPreimage {
                schema_version: self.schema_version,
                assurance: self.assurance,
                native_journal_id: &self.native_journal_id,
                launch_authority_digest: &self.launch_authority_digest,
                binding_digest: &self.binding_digest,
                controller_pid: self.controller_pid,
                path_local_executable: &self.path_local_executable,
                argv: &self.argv,
                environment: &self.environment,
                working_directory: &self.working_directory,
                descriptor_bindings: &self.descriptor_bindings,
                spawn_flags: self.spawn_flags,
                observations: &self.observations,
                observed_held_at_unix_ms: self.observed_held_at_unix_ms,
            },
        )
    }

    pub(crate) fn matches_launch_authority(
        &self,
        authority: &MacosOrdinaryRunnerLaunchAuthority,
    ) -> Result<bool, MacosNativeHeldLaunchError> {
        authority.validate_retained().map_err(|error| {
            MacosNativeHeldLaunchError::Invalid(format!(
                "ordinary launch authority is invalid: {error}"
            ))
        })?;
        Ok(
            self.native_journal_id == authority.attempt().native_journal_id
                && self.launch_authority_digest == launch_authority_digest(authority)?
                && path_local_executable_matches_expected(
                    &self.path_local_executable,
                    authority.executable(),
                ),
        )
    }
}

/// Canonical cleanup receipt. It proves only exact direct-child kill/reap and
/// absence of that same start identity, never dedicated-UID domain emptiness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosNativeHeldCleanupReceiptV1 {
    schema_version: u32,
    native_journal_id: String,
    launch_authority_digest: Digest,
    launch_receipt_digest: Digest,
    pid: u32,
    start_time_seconds: u64,
    start_time_microseconds: u64,
    signal: i32,
    wait_status: i32,
    direct_child_reaped: bool,
    exact_start_identity_absent: bool,
    cleaned_at_unix_ms: u64,
    receipt_digest: Digest,
}

#[derive(Serialize)]
struct CleanupReceiptPreimage<'a> {
    schema_version: u32,
    native_journal_id: &'a str,
    launch_authority_digest: &'a Digest,
    launch_receipt_digest: &'a Digest,
    pid: u32,
    start_time_seconds: u64,
    start_time_microseconds: u64,
    signal: i32,
    wait_status: i32,
    direct_child_reaped: bool,
    exact_start_identity_absent: bool,
    cleaned_at_unix_ms: u64,
}

impl MacosNativeHeldCleanupReceiptV1 {
    fn computed_digest(&self) -> Result<Digest, MacosNativeHeldLaunchError> {
        domain_digest(
            CLEANUP_DOMAIN,
            &CleanupReceiptPreimage {
                schema_version: self.schema_version,
                native_journal_id: &self.native_journal_id,
                launch_authority_digest: &self.launch_authority_digest,
                launch_receipt_digest: &self.launch_receipt_digest,
                pid: self.pid,
                start_time_seconds: self.start_time_seconds,
                start_time_microseconds: self.start_time_microseconds,
                signal: self.signal,
                wait_status: self.wait_status,
                direct_child_reaped: self.direct_child_reaped,
                exact_start_identity_absent: self.exact_start_identity_absent,
                cleaned_at_unix_ms: self.cleaned_at_unix_ms,
            },
        )
    }

    /// Encodes and validates the bounded cleanup receipt.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MacosNativeHeldLaunchError> {
        validate_identifier(&self.native_journal_id)?;
        if self.schema_version != MACOS_NATIVE_HELD_CLEANUP_SCHEMA_VERSION
            || self.pid <= 1
            || self.signal != darwin_spawn::SIGNAL_KILL
            || !self.direct_child_reaped
            || !self.exact_start_identity_absent
            || self.cleaned_at_unix_ms == 0
            || self.receipt_digest != self.computed_digest()?
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "cleanup receipt does not prove exact direct-child reap".into(),
            ));
        }
        let json = serde_json::to_vec(self).map_err(|error| {
            MacosNativeHeldLaunchError::Encoding(format!("encode cleanup receipt: {error}"))
        })?;
        let mut bytes = Vec::with_capacity(CLEANUP_DOMAIN.len() + json.len());
        bytes.extend_from_slice(CLEANUP_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "cleanup receipt exceeds its fixed byte bound".into(),
            ));
        }
        Ok(bytes)
    }
}

/// Exact post-spawn phase at which this non-admissible tranche stopped.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MacosNativePostSpawnFailurePhase {
    InvalidReturnedPid,
    FirstObservation,
    SecondObservation,
    ParentValidation,
    ReceiptEncoding,
    ExecutableReobservation,
    ExplicitCleanup,
}

/// Bounded, typed reason retained only for local reconciliation diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosNativePostSpawnFailureV1 {
    phase: MacosNativePostSpawnFailurePhase,
    detail: String,
}

impl MacosNativePostSpawnFailureV1 {
    fn new(phase: MacosNativePostSpawnFailurePhase, detail: impl Into<String>) -> Self {
        let mut detail = detail.into().replace('\0', "\\0");
        if detail.is_empty() {
            detail = "unspecified native failure".into();
        }
        if detail.len() > MAX_FAILURE_DETAIL_BYTES {
            let mut end = MAX_FAILURE_DETAIL_BYTES;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        let failure = Self { phase, detail };
        debug_assert!(failure.validate().is_ok());
        failure
    }

    fn validate(&self) -> Result<(), MacosNativeHeldLaunchError> {
        if self.detail.is_empty()
            || self.detail.len() > MAX_FAILURE_DETAIL_BYTES
            || self.detail.as_bytes().contains(&0)
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "post-spawn failure detail is empty, oversized, or contains NUL".into(),
            ));
        }
        Ok(())
    }
}

/// Start identity available before a cleanup attempt. Absence is explicit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosNativeAvailableStartIdentityV1 {
    start_time_seconds: u64,
    start_time_microseconds: u64,
}

/// Exact direct-child reap after a typed post-spawn launch failure. This does
/// not prove descendant or dedicated-identity domain emptiness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosNativePostSpawnCleanupReceiptV1 {
    schema_version: u32,
    native_journal_id: String,
    launch_authority_digest: Digest,
    binding_digest: Digest,
    pid: u32,
    available_start_identity: Option<MacosNativeAvailableStartIdentityV1>,
    failure: MacosNativePostSpawnFailureV1,
    signal_requested: i32,
    wait_status: i32,
    direct_child_reaped: bool,
    cleaned_at_unix_ms: u64,
    receipt_digest: Digest,
}

#[derive(Serialize)]
struct PostSpawnCleanupReceiptPreimage<'a> {
    schema_version: u32,
    native_journal_id: &'a str,
    launch_authority_digest: &'a Digest,
    binding_digest: &'a Digest,
    pid: u32,
    available_start_identity: Option<MacosNativeAvailableStartIdentityV1>,
    failure: &'a MacosNativePostSpawnFailureV1,
    signal_requested: i32,
    wait_status: i32,
    direct_child_reaped: bool,
    cleaned_at_unix_ms: u64,
}

impl MacosNativePostSpawnCleanupReceiptV1 {
    fn computed_digest(&self) -> Result<Digest, MacosNativeHeldLaunchError> {
        domain_digest(
            POST_SPAWN_CLEANUP_DOMAIN,
            &PostSpawnCleanupReceiptPreimage {
                schema_version: self.schema_version,
                native_journal_id: &self.native_journal_id,
                launch_authority_digest: &self.launch_authority_digest,
                binding_digest: &self.binding_digest,
                pid: self.pid,
                available_start_identity: self.available_start_identity,
                failure: &self.failure,
                signal_requested: self.signal_requested,
                wait_status: self.wait_status,
                direct_child_reaped: self.direct_child_reaped,
                cleaned_at_unix_ms: self.cleaned_at_unix_ms,
            },
        )
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MacosNativeHeldLaunchError> {
        validate_identifier(&self.native_journal_id)?;
        self.failure.validate()?;
        if self.schema_version != MACOS_NATIVE_HELD_CLEANUP_SCHEMA_VERSION
            || self.pid <= 1
            || self.signal_requested != darwin_spawn::SIGNAL_KILL
            || !self.direct_child_reaped
            || self.cleaned_at_unix_ms == 0
            || self.receipt_digest != self.computed_digest()?
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "post-spawn cleanup receipt does not prove exact direct-child reap".into(),
            ));
        }
        let json = serde_json::to_vec(self).map_err(|error| {
            MacosNativeHeldLaunchError::Encoding(format!(
                "encode post-spawn cleanup receipt: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(POST_SPAWN_CLEANUP_DOMAIN.len() + json.len());
        bytes.extend_from_slice(POST_SPAWN_CLEANUP_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "post-spawn cleanup receipt exceeds its fixed byte bound".into(),
            ));
        }
        Ok(bytes)
    }
}

/// Conservative result when the exact child could not be proven reaped. The
/// PID is absent only for a contract-violating nonpositive `posix_spawn` result;
/// the start identity is present only when an independent pre-cleanup read
/// succeeded. This value is not cleanup evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosNativeHeldLaunchReconciliationRequiredV1 {
    native_journal_id: String,
    launch_authority_digest: Digest,
    binding_digest: Digest,
    observed_held_at_receipt_digest: Option<Digest>,
    pid: Option<u32>,
    available_start_identity: Option<MacosNativeAvailableStartIdentityV1>,
    failure: MacosNativePostSpawnFailureV1,
    cleanup_failure: String,
}

impl MacosNativeHeldLaunchReconciliationRequiredV1 {
    #[cfg(test)]
    const fn pid(&self) -> Option<u32> {
        self.pid
    }

    fn validate(&self) -> Result<(), MacosNativeHeldLaunchError> {
        validate_identifier(&self.native_journal_id)?;
        self.failure.validate()?;
        if self.pid == Some(0)
            || self.pid == Some(1)
            || self.cleanup_failure.is_empty()
            || self.cleanup_failure.len() > MAX_FAILURE_DETAIL_BYTES
            || self.cleanup_failure.as_bytes().contains(&0)
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "reconciliation-required identity or detail is invalid".into(),
            ));
        }
        Ok(())
    }
}

/// Every post-spawn branch is typed. Only `ObservedHeldAt` carries a point-in-
/// time stopped observation; it never means the child remains stopped.
#[must_use = "a native launch outcome must be cleaned or reconciled"]
pub(crate) enum MacosNativeHeldLaunchOutcome {
    ObservedHeldAt(Box<MacosNativeObservedHeldAtChild>),
    FailedAfterSpawnCleaned {
        failure: MacosNativePostSpawnFailureV1,
        cleanup_receipt: MacosNativePostSpawnCleanupReceiptV1,
    },
    ReconciliationRequired(MacosNativeHeldLaunchReconciliationRequiredV1),
}

/// Explicit cleanup of a previously observed child is likewise phase-typed.
#[must_use = "cleanup must either be proven or reconciled"]
pub(crate) enum MacosNativeObservedHeldAtCleanupOutcome {
    Cleaned(MacosNativeHeldCleanupReceiptV1),
    ReconciliationRequired(MacosNativeHeldLaunchReconciliationRequiredV1),
}

/// Borrowed exact inputs to the cleanup-only held launch primitive.
#[derive(Clone, Copy)]
pub(crate) struct MacosNativeHeldLaunchSpec<'a> {
    launch_authority: &'a MacosOrdinaryRunnerLaunchAuthority,
    executable_path: &'a Path,
    argv: &'a [String],
    environment: &'a BTreeMap<String, String>,
    working_directory: BorrowedFd<'a>,
    descriptors: [BorrowedFd<'a>; 5],
}

impl<'a> MacosNativeHeldLaunchSpec<'a> {
    pub(crate) const fn new(
        launch_authority: &'a MacosOrdinaryRunnerLaunchAuthority,
        executable_path: &'a Path,
        argv: &'a [String],
        environment: &'a BTreeMap<String, String>,
        working_directory: BorrowedFd<'a>,
        descriptors: [BorrowedFd<'a>; 5],
    ) -> Self {
        Self {
            launch_authority,
            executable_path,
            argv,
            environment,
            working_directory,
            descriptors,
        }
    }
}

/// Move-only local handle over a direct child observed stopped at the receipt
/// timestamp. It has no release API and does not claim the child remains
/// stopped: another same-UID process can send `SIGCONT` at any later instant.
#[must_use = "an observed child must be terminated or explicitly reconciled"]
pub(crate) struct MacosNativeObservedHeldAtChild {
    pid: Pid,
    receipt: MacosNativeObservedHeldAtReceiptV1,
    cleanup_consumed: bool,
}

impl MacosNativeObservedHeldAtChild {
    pub(crate) const fn receipt(&self) -> &MacosNativeObservedHeldAtReceiptV1 {
        &self.receipt
    }

    /// Attempts to kill and reap the exact direct child. Every failure is a
    /// typed reconciliation result; no failed branch claims cleanup.
    pub(crate) fn terminate_and_reap(mut self) -> MacosNativeObservedHeldAtCleanupOutcome {
        self.cleanup_consumed = true;
        let failure = MacosNativePostSpawnFailureV1::new(
            MacosNativePostSpawnFailurePhase::ExplicitCleanup,
            "explicit cleanup of point-in-time observed child",
        );
        if let Err(error) = kill_process(self.pid, Signal::KILL) {
            return MacosNativeObservedHeldAtCleanupOutcome::ReconciliationRequired(
                reconciliation_required(
                    &self.receipt,
                    self.pid,
                    failure,
                    format!("send SIGKILL to observed child: {error}"),
                ),
            );
        }
        let status = match reap_exact_condemned_child(self.pid) {
            Ok(status) => status,
            Err(detail) => {
                return MacosNativeObservedHeldAtCleanupOutcome::ReconciliationRequired(
                    reconciliation_required(
                        &self.receipt,
                        self.pid,
                        failure,
                        format!("reap observed child: {detail}"),
                    ),
                );
            }
        };
        let exact = &self.receipt.observations[1];
        let exact_start_identity_absent = match darwin_spawn::observe_process(self.pid.as_raw_pid())
        {
            Ok(None) => true,
            Ok(Some(current)) => {
                current.start_time_seconds != exact.start_time_seconds
                    || current.start_time_microseconds != exact.start_time_microseconds
            }
            Err(error) => {
                return MacosNativeObservedHeldAtCleanupOutcome::ReconciliationRequired(
                    reconciliation_required(
                        &self.receipt,
                        self.pid,
                        failure,
                        format!("observe reaped child identity: {error}"),
                    ),
                );
            }
        };
        let cleaned_at_unix_ms = match now_unix_ms() {
            Ok(value) => value,
            Err(error) => {
                return MacosNativeObservedHeldAtCleanupOutcome::ReconciliationRequired(
                    reconciliation_required(&self.receipt, self.pid, failure, error.to_string()),
                );
            }
        };
        let mut receipt = MacosNativeHeldCleanupReceiptV1 {
            schema_version: MACOS_NATIVE_HELD_CLEANUP_SCHEMA_VERSION,
            native_journal_id: self.receipt.native_journal_id.clone(),
            launch_authority_digest: self.receipt.launch_authority_digest.clone(),
            launch_receipt_digest: self.receipt.receipt_digest.clone(),
            pid: self.receipt.pid(),
            start_time_seconds: exact.start_time_seconds,
            start_time_microseconds: exact.start_time_microseconds,
            signal: darwin_spawn::SIGNAL_KILL,
            wait_status: status.as_raw(),
            direct_child_reaped: status.signaled()
                && status.terminating_signal() == Some(darwin_spawn::SIGNAL_KILL),
            exact_start_identity_absent,
            cleaned_at_unix_ms,
            receipt_digest: Digest::sha256(&[]),
        };
        receipt.receipt_digest = match receipt.computed_digest() {
            Ok(digest) => digest,
            Err(error) => {
                return MacosNativeObservedHeldAtCleanupOutcome::ReconciliationRequired(
                    reconciliation_required(&self.receipt, self.pid, failure, error.to_string()),
                );
            }
        };
        if let Err(error) = receipt.canonical_bytes() {
            return MacosNativeObservedHeldAtCleanupOutcome::ReconciliationRequired(
                reconciliation_required(&self.receipt, self.pid, failure, error.to_string()),
            );
        }
        MacosNativeObservedHeldAtCleanupOutcome::Cleaned(receipt)
    }
}

impl Drop for MacosNativeObservedHeldAtChild {
    fn drop(&mut self) {
        if self.cleanup_consumed {
            return;
        }
        // Best-effort process hygiene only; durable proof cannot rely on Drop.
        // Reaping remains bounded even when the child survives.
        let _ = kill_process(self.pid, Signal::KILL);
        let _ = reap_exact_condemned_child(self.pid);
        self.cleanup_consumed = true;
    }
}

#[derive(Clone)]
struct MacosNativeValidatedLaunchInputs {
    native_journal_id: String,
    launch_authority_digest: Digest,
    binding_digest: Digest,
    controller_pid: u32,
    executable: MacosNativePathLocalExecutableObservationV1,
    argv: Vec<String>,
    environment: Vec<MacosNativeEnvironmentEntryV1>,
    working_directory: MacosNativeObjectIdentityV1,
    descriptor_bindings: Vec<MacosNativeDescriptorBindingV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacosNativeLaunchFault {
    None,
    SpawnMustNotBeReached,
    FirstObservation,
    SecondObservation,
    ContinueBeforeSecondObservation,
    ParentValidation,
    ReceiptEncoding,
    ExecutableReobservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacosNativeCleanupFault {
    None,
    BeforeSignal,
    AfterSignal,
    AfterWait,
    ReceiptEncoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MacosNativeLaunchFaults {
    launch: MacosNativeLaunchFault,
    cleanup: MacosNativeCleanupFault,
}

impl MacosNativeLaunchFaults {
    const NONE: Self = Self {
        launch: MacosNativeLaunchFault::None,
        cleanup: MacosNativeCleanupFault::None,
    };
}

/// Performs the one real kernel launch implemented by this tranche and reports
/// only a point-in-time `ObservedHeldAt` result.
#[allow(
    clippy::too_many_lines,
    reason = "the effect boundary keeps validation, receipt-size preflight, fd normalization, spawn, typed cleanup/reconciliation, double observation, and exact receipt sealing in one auditable order"
)]
pub(crate) fn launch_cleanup_only_observed_held_at_child(
    spec: MacosNativeHeldLaunchSpec<'_>,
) -> Result<MacosNativeHeldLaunchOutcome, MacosNativeHeldLaunchError> {
    launch_cleanup_only_observed_held_at_child_inner(spec, MacosNativeLaunchFaults::NONE)
}

#[allow(
    clippy::too_many_lines,
    reason = "see the public crate-private effect boundary"
)]
fn launch_cleanup_only_observed_held_at_child_inner(
    spec: MacosNativeHeldLaunchSpec<'_>,
    faults: MacosNativeLaunchFaults,
) -> Result<MacosNativeHeldLaunchOutcome, MacosNativeHeldLaunchError> {
    spec.launch_authority.validate_retained().map_err(|error| {
        MacosNativeHeldLaunchError::Invalid(format!("ordinary launch authority: {error}"))
    })?;
    validate_identifier(&spec.launch_authority.attempt().native_journal_id)?;
    validate_argv(spec.argv)?;
    let environment = environment_entries(spec.environment)?;
    validate_environment(&environment)?;
    let executable = observe_executable(spec.executable_path)?;
    if !path_local_executable_matches_expected(&executable, spec.launch_authority.executable()) {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "path-local executable differs from the exact retained launch expectation".into(),
        ));
    }
    let working_directory = object_identity(spec.working_directory)?;
    if working_directory.mode & 0o170_000 != 0o040_000 {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "working-directory descriptor is not a directory".into(),
        ));
    }
    let descriptor_bindings = spec
        .descriptors
        .iter()
        .zip(EXPECTED_CHILD_DESCRIPTORS)
        .map(|(descriptor, target_fd)| {
            object_identity(*descriptor).map(|source_identity| MacosNativeDescriptorBindingV1 {
                target_fd,
                source_identity,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let launch_authority_digest = launch_authority_digest(spec.launch_authority)?;
    let controller_pid = u32::try_from(getpid().as_raw_pid()).map_err(|_| {
        MacosNativeHeldLaunchError::Native("controller PID does not fit u32".into())
    })?;
    let mut receipt_size_probe = MacosNativeObservedHeldAtReceiptV1 {
        schema_version: MACOS_NATIVE_HELD_LAUNCH_SCHEMA_VERSION,
        assurance: MacosNativeHeldLaunchAssurance::KernelObservedCleanupOnlyNoServiceAuthority,
        native_journal_id: spec.launch_authority.attempt().native_journal_id.clone(),
        launch_authority_digest: launch_authority_digest.clone(),
        binding_digest: Digest::sha256(&[]),
        controller_pid,
        path_local_executable: executable.clone(),
        argv: spec.argv.to_vec(),
        environment: environment.clone(),
        working_directory: working_directory.clone(),
        descriptor_bindings: descriptor_bindings.clone(),
        spawn_flags: REQUIRED_SPAWN_FLAGS,
        observations: [
            maximum_size_observation(&executable),
            maximum_size_observation(&executable),
        ],
        observed_held_at_unix_ms: u64::MAX,
        receipt_digest: Digest::sha256(&[]),
    };
    receipt_size_probe.binding_digest = receipt_size_probe.computed_binding_digest()?;
    receipt_size_probe.receipt_digest = receipt_size_probe.computed_receipt_digest()?;
    preflight_receipt_size(&receipt_size_probe)?;
    let validated = MacosNativeValidatedLaunchInputs {
        native_journal_id: receipt_size_probe.native_journal_id.clone(),
        launch_authority_digest,
        binding_digest: receipt_size_probe.binding_digest.clone(),
        controller_pid,
        executable,
        argv: spec.argv.to_vec(),
        environment,
        working_directory,
        descriptor_bindings,
    };

    let normalized = spec
        .descriptors
        .iter()
        .map(|descriptor| normalize_descriptor(*descriptor))
        .collect::<Result<Vec<_>, _>>()?;
    let normalized_cwd = normalize_descriptor(spec.working_directory)?;
    let argv = spec
        .argv
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| MacosNativeHeldLaunchError::Invalid("argv contains NUL".into()))?;
    let env = validated
        .environment
        .iter()
        .map(|entry| CString::new(format!("{}={}", entry.name, entry.value)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| MacosNativeHeldLaunchError::Invalid("environment contains NUL".into()))?;
    let executable_c = CString::new(spec.executable_path.as_os_str().as_bytes())
        .map_err(|_| MacosNativeHeldLaunchError::Invalid("executable path contains NUL".into()))?;
    let normalized_raw: [i32; 5] = normalized
        .iter()
        .map(AsRawFd::as_raw_fd)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| MacosNativeHeldLaunchError::Invalid("descriptor count drifted".into()))?;

    assert!(
        faults.launch != MacosNativeLaunchFault::SpawnMustNotBeReached,
        "native spawn was reached after a required pre-spawn refusal"
    );
    let raw_pid = darwin_spawn::spawn_suspended(
        &executable_c,
        &argv,
        &env,
        normalized_cwd.as_raw_fd(),
        normalized_raw,
    )
    .map_err(|error| MacosNativeHeldLaunchError::Native(format!("posix_spawn: {error}")))?;
    let Some(pid) = Pid::from_raw(raw_pid) else {
        let failure = MacosNativePostSpawnFailureV1::new(
            MacosNativePostSpawnFailurePhase::InvalidReturnedPid,
            "posix_spawn returned a nonpositive PID",
        );
        let reconciliation = reconciliation_without_pid(
            &validated,
            failure,
            "no bounded PID was available for direct-child cleanup",
        );
        return Ok(MacosNativeHeldLaunchOutcome::ReconciliationRequired(
            reconciliation,
        ));
    };
    if faults.launch == MacosNativeLaunchFault::FirstObservation {
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::FirstObservation,
                "injected failure before first process observation",
            ),
            faults.cleanup,
        ));
    }
    let first = match observe_exact_held(pid, &validated.executable) {
        Ok(observation) => observation,
        Err(error) => {
            return Ok(post_spawn_failure_outcome(
                &validated,
                pid,
                MacosNativePostSpawnFailureV1::new(
                    MacosNativePostSpawnFailurePhase::FirstObservation,
                    error.to_string(),
                ),
                faults.cleanup,
            ));
        }
    };
    if faults.launch == MacosNativeLaunchFault::ContinueBeforeSecondObservation {
        if let Err(error) = kill_process(pid, Signal::CONT) {
            return Ok(post_spawn_failure_outcome(
                &validated,
                pid,
                MacosNativePostSpawnFailureV1::new(
                    MacosNativePostSpawnFailurePhase::SecondObservation,
                    format!("injected SIGCONT failed: {error}"),
                ),
                faults.cleanup,
            ));
        }
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::SecondObservation,
                "SIGCONT crossed the two-observation stability interval",
            ),
            faults.cleanup,
        ));
    } else if faults.launch == MacosNativeLaunchFault::SecondObservation {
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::SecondObservation,
                "injected failure before second process observation",
            ),
            faults.cleanup,
        ));
    }
    let second = match observe_exact_held(pid, &validated.executable) {
        Ok(observation) => observation,
        Err(error) => {
            return Ok(post_spawn_failure_outcome(
                &validated,
                pid,
                MacosNativePostSpawnFailureV1::new(
                    MacosNativePostSpawnFailurePhase::SecondObservation,
                    error.to_string(),
                ),
                faults.cleanup,
            ));
        }
    };
    if faults.launch == MacosNativeLaunchFault::ParentValidation
        || first.parent_pid != validated.controller_pid
        || second.parent_pid != validated.controller_pid
    {
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::ParentValidation,
                "observed child parent did not match the launching controller",
            ),
            faults.cleanup,
        ));
    }
    let mut receipt = MacosNativeObservedHeldAtReceiptV1 {
        schema_version: MACOS_NATIVE_HELD_LAUNCH_SCHEMA_VERSION,
        assurance: MacosNativeHeldLaunchAssurance::KernelObservedCleanupOnlyNoServiceAuthority,
        native_journal_id: validated.native_journal_id.clone(),
        launch_authority_digest: validated.launch_authority_digest.clone(),
        binding_digest: validated.binding_digest.clone(),
        controller_pid: validated.controller_pid,
        path_local_executable: validated.executable.clone(),
        argv: validated.argv.clone(),
        environment: validated.environment.clone(),
        working_directory: validated.working_directory.clone(),
        descriptor_bindings: validated.descriptor_bindings.clone(),
        spawn_flags: REQUIRED_SPAWN_FLAGS,
        observed_held_at_unix_ms: second.observed_at_unix_ms,
        observations: [first, second],
        receipt_digest: Digest::sha256(&[]),
    };
    receipt.receipt_digest = match receipt.computed_receipt_digest() {
        Ok(digest) => digest,
        Err(error) => {
            return Ok(post_spawn_failure_outcome(
                &validated,
                pid,
                MacosNativePostSpawnFailureV1::new(
                    MacosNativePostSpawnFailurePhase::ReceiptEncoding,
                    error.to_string(),
                ),
                faults.cleanup,
            ));
        }
    };
    if faults.launch == MacosNativeLaunchFault::ReceiptEncoding {
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::ReceiptEncoding,
                "injected failure before canonical receipt encoding",
            ),
            faults.cleanup,
        ));
    }
    if let Err(error) = receipt.canonical_bytes() {
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::ReceiptEncoding,
                error.to_string(),
            ),
            faults.cleanup,
        ));
    }
    if faults.launch == MacosNativeLaunchFault::ExecutableReobservation {
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::ExecutableReobservation,
                "injected failure before executable path re-observation",
            ),
            faults.cleanup,
        ));
    }
    let executable_after = match observe_executable(spec.executable_path) {
        Ok(executable_after) => executable_after,
        Err(error) => {
            return Ok(post_spawn_failure_outcome(
                &validated,
                pid,
                MacosNativePostSpawnFailureV1::new(
                    MacosNativePostSpawnFailurePhase::ExecutableReobservation,
                    error.to_string(),
                ),
                faults.cleanup,
            ));
        }
    };
    if executable_after != receipt.path_local_executable {
        return Ok(post_spawn_failure_outcome(
            &validated,
            pid,
            MacosNativePostSpawnFailureV1::new(
                MacosNativePostSpawnFailurePhase::ExecutableReobservation,
                "path-local executable identity changed across spawn",
            ),
            faults.cleanup,
        ));
    }
    Ok(MacosNativeHeldLaunchOutcome::ObservedHeldAt(Box::new(
        MacosNativeObservedHeldAtChild {
            pid,
            receipt,
            cleanup_consumed: false,
        },
    )))
}

fn maximum_size_observation(
    executable: &MacosNativePathLocalExecutableObservationV1,
) -> MacosNativeHeldProcessObservationV1 {
    MacosNativeHeldProcessObservationV1 {
        pid: u32::MAX,
        parent_pid: u32::MAX,
        process_group_id: u32::MAX,
        session_id: u32::MAX,
        real_uid: u32::MAX,
        effective_uid: u32::MAX,
        saved_uid: u32::MAX,
        real_gid: u32::MAX,
        effective_gid: u32::MAX,
        saved_gid: u32::MAX,
        status: u32::MAX,
        start_time_seconds: u64::MAX,
        start_time_microseconds: u64::MAX,
        open_descriptors: EXPECTED_CHILD_DESCRIPTORS.to_vec(),
        executable_path_bytes: executable.canonical_path_bytes.clone(),
        observed_at_unix_ms: u64::MAX,
    }
}

/// Serializes the exact variable-length inputs plus maximal-width values for
/// every post-spawn numeric field. Therefore an input rejected here has caused
/// no native effect, while any admitted input has enough room for its complete
/// canonical point-in-time receipt.
fn preflight_receipt_size(
    upper_bound: &MacosNativeObservedHeldAtReceiptV1,
) -> Result<(), MacosNativeHeldLaunchError> {
    let json = serde_json::to_vec(upper_bound).map_err(|error| {
        MacosNativeHeldLaunchError::Encoding(format!(
            "preflight maximal held-at receipt encoding: {error}"
        ))
    })?;
    let size = RECEIPT_DOMAIN
        .len()
        .checked_add(json.len())
        .ok_or_else(|| {
            MacosNativeHeldLaunchError::Invalid("held-at receipt size overflow".into())
        })?;
    if size > MAX_RECEIPT_BYTES {
        return Err(MacosNativeHeldLaunchError::Invalid(format!(
            "maximal canonical held-at receipt requires {size} bytes, exceeding {MAX_RECEIPT_BYTES}"
        )));
    }
    Ok(())
}

/// Reaps the exact direct child the caller has already condemned, within
/// [`CONDEMNED_CHILD_REAP_DEADLINE`], re-sending `SIGKILL` between polls.
///
/// This is the only reap production code may use after signalling a
/// `START_SUSPENDED` child. It cannot block indefinitely, so a child that
/// survives becomes a typed refusal the caller turns into reconciliation.
pub(crate) fn reap_exact_condemned_child(pid: Pid) -> Result<WaitStatus, String> {
    reap_exact_child_within(pid, Signal::KILL, CONDEMNED_CHILD_REAP_DEADLINE)
}

/// The bounded, escalating exact-PID reap.
///
/// Production reaches it only through [`reap_exact_condemned_child`], which
/// pins the escalation to `SIGKILL` and the bound to
/// [`CONDEMNED_CHILD_REAP_DEADLINE`]; both are parameters so that the bound and
/// the escalation can be proven separately by test.
///
/// Every wait is `waitpid(exact_pid, WNOHANG)`. A return of `Ok(None)` from
/// that call independently proves this process still owns that exact unreaped
/// direct child, a reused or unrelated PID reports `ECHILD` instead, so the
/// PID cannot have been recycled and each escalation signal reaches the same
/// child the caller condemned and nothing else.
fn reap_exact_child_within(
    pid: Pid,
    escalation: Signal,
    deadline: Duration,
) -> Result<WaitStatus, String> {
    let raw = pid.as_raw_pid();
    let expires_at = Instant::now() + deadline;
    loop {
        match waitpid(Some(pid), WaitOptions::NOHANG) {
            Ok(Some((_, status))) => return Ok(status),
            Ok(None) => {}
            Err(error) => return Err(format!("reap exact direct child {raw}: {error}")),
        }
        if Instant::now() >= expires_at {
            return Err(format!(
                "exact direct child {raw} was still unreaped {} ms after it was condemned and \
                 repeatedly re-signalled; it survives this launch",
                deadline.as_millis()
            ));
        }
        std::thread::sleep(CONDEMNED_CHILD_REAP_POLL_INTERVAL);
        if let Err(error) = kill_process(pid, escalation) {
            return Err(format!("re-signal exact direct child {raw}: {error}"));
        }
    }
}

fn available_start_identity(pid: Pid) -> Option<MacosNativeAvailableStartIdentityV1> {
    darwin_spawn::observe_process(pid.as_raw_pid())
        .ok()
        .flatten()
        .map(|process| MacosNativeAvailableStartIdentityV1 {
            start_time_seconds: process.start_time_seconds,
            start_time_microseconds: process.start_time_microseconds,
        })
}

#[allow(
    clippy::too_many_lines,
    reason = "the post-spawn effect boundary keeps signal, exact wait, receipt sealing, injected cuts, and every reconciliation return in one auditable phase order"
)]
fn post_spawn_failure_outcome(
    validated: &MacosNativeValidatedLaunchInputs,
    pid: Pid,
    failure: MacosNativePostSpawnFailureV1,
    cleanup_fault: MacosNativeCleanupFault,
) -> MacosNativeHeldLaunchOutcome {
    let start_identity = available_start_identity(pid);
    if cleanup_fault == MacosNativeCleanupFault::BeforeSignal {
        return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
            reconciliation_from_validated(
                validated,
                Some(pid),
                start_identity,
                failure,
                "injected cleanup failure before SIGKILL",
            ),
        );
    }
    if let Err(error) = kill_process(pid, Signal::KILL) {
        return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
            reconciliation_from_validated(
                validated,
                Some(pid),
                start_identity,
                failure,
                format!("send SIGKILL after post-spawn failure: {error}"),
            ),
        );
    }
    if cleanup_fault == MacosNativeCleanupFault::AfterSignal {
        return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
            reconciliation_from_validated(
                validated,
                Some(pid),
                start_identity,
                failure,
                "injected cleanup failure after SIGKILL and before wait",
            ),
        );
    }
    let status = match reap_exact_condemned_child(pid) {
        Ok(status) => status,
        Err(detail) => {
            return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
                reconciliation_from_validated(
                    validated,
                    Some(pid),
                    start_identity,
                    failure,
                    format!("reap after post-spawn failure: {detail}"),
                ),
            );
        }
    };
    if cleanup_fault == MacosNativeCleanupFault::AfterWait {
        return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
            reconciliation_from_validated(
                validated,
                Some(pid),
                start_identity,
                failure,
                "injected cleanup failure after exact direct-child wait",
            ),
        );
    }
    let cleaned_at_unix_ms = match now_unix_ms() {
        Ok(value) => value,
        Err(error) => {
            return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
                reconciliation_from_validated(
                    validated,
                    Some(pid),
                    start_identity,
                    failure,
                    error.to_string(),
                ),
            );
        }
    };
    let mut receipt = MacosNativePostSpawnCleanupReceiptV1 {
        schema_version: MACOS_NATIVE_HELD_CLEANUP_SCHEMA_VERSION,
        native_journal_id: validated.native_journal_id.clone(),
        launch_authority_digest: validated.launch_authority_digest.clone(),
        binding_digest: validated.binding_digest.clone(),
        pid: u32::try_from(pid.as_raw_pid()).expect("positive pid_t fits u32"),
        available_start_identity: start_identity,
        failure: failure.clone(),
        signal_requested: darwin_spawn::SIGNAL_KILL,
        wait_status: status.as_raw(),
        direct_child_reaped: status.exited() || status.signaled(),
        cleaned_at_unix_ms,
        receipt_digest: Digest::sha256(&[]),
    };
    receipt.receipt_digest = match receipt.computed_digest() {
        Ok(digest) => digest,
        Err(error) => {
            return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
                reconciliation_from_validated(
                    validated,
                    Some(pid),
                    start_identity,
                    failure,
                    error.to_string(),
                ),
            );
        }
    };
    if cleanup_fault == MacosNativeCleanupFault::ReceiptEncoding {
        return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
            reconciliation_from_validated(
                validated,
                Some(pid),
                start_identity,
                failure,
                "injected cleanup-receipt encoding failure",
            ),
        );
    }
    if let Err(error) = receipt.canonical_bytes() {
        return MacosNativeHeldLaunchOutcome::ReconciliationRequired(
            reconciliation_from_validated(
                validated,
                Some(pid),
                start_identity,
                failure,
                error.to_string(),
            ),
        );
    }
    MacosNativeHeldLaunchOutcome::FailedAfterSpawnCleaned {
        failure,
        cleanup_receipt: receipt,
    }
}

fn reconciliation_without_pid(
    validated: &MacosNativeValidatedLaunchInputs,
    failure: MacosNativePostSpawnFailureV1,
    detail: impl Into<String>,
) -> MacosNativeHeldLaunchReconciliationRequiredV1 {
    reconciliation_from_validated(validated, None, None, failure, detail)
}

fn reconciliation_from_validated(
    validated: &MacosNativeValidatedLaunchInputs,
    pid: Option<Pid>,
    available_start_identity: Option<MacosNativeAvailableStartIdentityV1>,
    failure: MacosNativePostSpawnFailureV1,
    detail: impl Into<String>,
) -> MacosNativeHeldLaunchReconciliationRequiredV1 {
    let reconciliation = MacosNativeHeldLaunchReconciliationRequiredV1 {
        native_journal_id: validated.native_journal_id.clone(),
        launch_authority_digest: validated.launch_authority_digest.clone(),
        binding_digest: validated.binding_digest.clone(),
        observed_held_at_receipt_digest: None,
        pid: pid.map(|value| {
            u32::try_from(value.as_raw_pid()).expect("positive pid_t always fits u32")
        }),
        available_start_identity,
        failure,
        cleanup_failure: bounded_detail(detail),
    };
    debug_assert!(reconciliation.validate().is_ok());
    reconciliation
}

fn reconciliation_required(
    receipt: &MacosNativeObservedHeldAtReceiptV1,
    pid: Pid,
    failure: MacosNativePostSpawnFailureV1,
    detail: impl Into<String>,
) -> MacosNativeHeldLaunchReconciliationRequiredV1 {
    let exact = &receipt.observations[1];
    let reconciliation = MacosNativeHeldLaunchReconciliationRequiredV1 {
        native_journal_id: receipt.native_journal_id.clone(),
        launch_authority_digest: receipt.launch_authority_digest.clone(),
        binding_digest: receipt.binding_digest.clone(),
        observed_held_at_receipt_digest: Some(receipt.receipt_digest.clone()),
        pid: Some(u32::try_from(pid.as_raw_pid()).expect("positive pid_t always fits u32")),
        available_start_identity: Some(MacosNativeAvailableStartIdentityV1 {
            start_time_seconds: exact.start_time_seconds,
            start_time_microseconds: exact.start_time_microseconds,
        }),
        failure,
        cleanup_failure: bounded_detail(detail),
    };
    debug_assert!(reconciliation.validate().is_ok());
    reconciliation
}

fn bounded_detail(detail: impl Into<String>) -> String {
    let mut detail = detail.into().replace('\0', "\\0");
    if detail.is_empty() {
        detail = "unspecified reconciliation condition".into();
    }
    if detail.len() > MAX_FAILURE_DETAIL_BYTES {
        let mut end = MAX_FAILURE_DETAIL_BYTES;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
    }
    detail
}

/// Fail-closed native held-launch error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosNativeHeldLaunchError {
    Invalid(String),
    Encoding(String),
    Native(String),
}

impl Display for MacosNativeHeldLaunchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(formatter, "macOS held launch rejected: {detail}"),
            Self::Encoding(detail) => {
                write!(formatter, "macOS held launch encoding failed: {detail}")
            }
            Self::Native(detail) => write!(
                formatter,
                "macOS held launch native effect failed: {detail}"
            ),
        }
    }
}

impl Error for MacosNativeHeldLaunchError {}

fn validate_identifier(value: &str) -> Result<(), MacosNativeHeldLaunchError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "native journal identity is blank, oversized, or noncanonical".into(),
        ));
    }
    Ok(())
}

fn validate_path_local_executable(
    executable: &MacosNativePathLocalExecutableObservationV1,
) -> Result<(), MacosNativeHeldLaunchError> {
    let object = &executable.object;
    if executable.canonical_path_bytes.is_empty()
        || executable.canonical_path_bytes.len() > 4_096
        || executable.canonical_path_bytes.first() != Some(&b'/')
        || executable.canonical_path_bytes.contains(&0)
        || object.device_id == 0
        || object.inode == 0
        || object.mode & 0o170_000 != 0o100_000
        || object.mode & 0o7_000 != 0
        || object.mode & 0o022 != 0
        || object.mode & 0o111 == 0
        || object.byte_length == 0
        || object.byte_length > MAX_EXECUTABLE_BYTES
        || object.link_count != 1
    {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "path-local executable observation is malformed or unsafe".into(),
        ));
    }
    Ok(())
}

fn path_local_executable_matches_expected(
    executable: &MacosNativePathLocalExecutableObservationV1,
    expected: &MacosRetainedRunnerExecutableExpectation,
) -> bool {
    let identity = expected.descriptor_identity();
    executable.complete_bytes_digest == *expected.binary_digest()
        && executable.object.device_id == identity.device_id
        && executable.object.inode == identity.inode
        && executable.object.byte_length == identity.byte_length
        && executable.object.mode == identity.mode
        && executable.object.owner_uid == identity.owner_uid
        && executable.object.link_count == identity.link_count
}

fn launch_authority_digest(
    authority: &MacosOrdinaryRunnerLaunchAuthority,
) -> Result<Digest, MacosNativeHeldLaunchError> {
    domain_digest(AUTHORITY_DOMAIN, authority)
}

fn validate_argv(argv: &[String]) -> Result<(), MacosNativeHeldLaunchError> {
    if argv.is_empty() || argv.len() > MAX_ARGUMENTS {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "argv is empty or exceeds its count bound".into(),
        ));
    }
    let mut total = 0_usize;
    for value in argv {
        total = total.saturating_add(value.len());
        if value.is_empty()
            || value.len() > MAX_TEXT_BYTES
            || value.as_bytes().contains(&0)
            || value.chars().any(char::is_control)
        {
            return Err(MacosNativeHeldLaunchError::Invalid(
                "argv contains an empty, oversized, NUL, or control-bearing value".into(),
            ));
        }
    }
    if total > 32 * 1_024 {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "aggregate argv bytes exceed the hard bound".into(),
        ));
    }
    Ok(())
}

fn environment_entries(
    environment: &BTreeMap<String, String>,
) -> Result<Vec<MacosNativeEnvironmentEntryV1>, MacosNativeHeldLaunchError> {
    if !environment.is_empty() {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "cleanup-only held launch requires an exactly empty environment".into(),
        ));
    }
    Ok(Vec::new())
}

fn validate_environment(
    environment: &[MacosNativeEnvironmentEntryV1],
) -> Result<(), MacosNativeHeldLaunchError> {
    if !environment.is_empty() {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "cleanup-only held launch requires an exactly empty environment".into(),
        ));
    }
    Ok(())
}

fn normalize_descriptor(descriptor: BorrowedFd<'_>) -> Result<OwnedFd, MacosNativeHeldLaunchError> {
    fcntl_dupfd_cloexec(descriptor, FIRST_NORMALIZED_DESCRIPTOR).map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("normalize inherited descriptor: {error}"))
    })
}

fn object_identity(
    descriptor: BorrowedFd<'_>,
) -> Result<MacosNativeObjectIdentityV1, MacosNativeHeldLaunchError> {
    let stat = fstat(descriptor).map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("inspect retained descriptor: {error}"))
    })?;
    Ok(MacosNativeObjectIdentityV1 {
        // Darwin's Rust ABI exposes `dev_t` through a signed integer even
        // though its bit pattern is an opaque device identifier.
        device_id: u64::from(u32::from_ne_bytes(stat.st_dev.to_ne_bytes())),
        inode: stat.st_ino,
        owner_uid: stat.st_uid,
        owner_gid: stat.st_gid,
        mode: u32::from(stat.st_mode),
        byte_length: u64::try_from(stat.st_size).map_err(|_| {
            MacosNativeHeldLaunchError::Invalid("descriptor length is negative".into())
        })?,
        link_count: u64::from(stat.st_nlink),
    })
}

fn observe_executable(
    path: &Path,
) -> Result<MacosNativePathLocalExecutableObservationV1, MacosNativeHeldLaunchError> {
    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "executable path must be one absolute NUL-free path".into(),
        ));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("canonicalize executable: {error}"))
    })?;
    if canonical != path {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "executable path is not its exact canonical name".into(),
        ));
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("open executable without links: {error}"))
    })?;
    let object = object_identity(descriptor.as_fd())?;
    if object.mode & 0o170_000 != 0o100_000
        || object.mode & 0o7_000 != 0
        || object.mode & 0o022 != 0
        || object.mode & 0o111 == 0
        || object.byte_length == 0
        || object.byte_length > MAX_EXECUTABLE_BYTES
        || object.link_count != 1
    {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "executable is not one bounded, non-setid, non-writable executable regular file".into(),
        ));
    }
    let mut file = File::from(descriptor);
    file.seek(SeekFrom::Start(0))
        .map_err(|error| MacosNativeHeldLaunchError::Native(format!("seek executable: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1_024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            MacosNativeHeldLaunchError::Native(format!("hash executable: {error}"))
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let finalized = hasher.finalize();
    let mut digest = String::with_capacity(64);
    for byte in finalized {
        digest.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        digest.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    Ok(MacosNativePathLocalExecutableObservationV1 {
        canonical_path_bytes: canonical.as_os_str().as_bytes().to_vec(),
        object,
        complete_bytes_digest: Digest::parse(&digest).map_err(|_| {
            MacosNativeHeldLaunchError::Encoding("SHA-256 output was noncanonical".into())
        })?,
    })
}

fn observe_exact_held(
    pid: Pid,
    executable: &MacosNativePathLocalExecutableObservationV1,
) -> Result<MacosNativeHeldProcessObservationV1, MacosNativeHeldLaunchError> {
    let raw = darwin_spawn::observe_process(pid.as_raw_pid())
        .map_err(|error| MacosNativeHeldLaunchError::Native(format!("inspect child: {error}")))?
        .ok_or_else(|| MacosNativeHeldLaunchError::Native("held child disappeared".into()))?;
    let mut descriptors = darwin_spawn::list_descriptors(pid.as_raw_pid()).map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("inspect child descriptor table: {error}"))
    })?;
    descriptors.sort_unstable();
    descriptors.dedup();
    let executable_path_bytes = darwin_spawn::process_path(pid.as_raw_pid()).map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("inspect child executable path: {error}"))
    })?;
    let session_id = getsid(Some(pid)).map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("inspect child session: {error}"))
    })?;
    let pid_u32 = raw.pid;
    if raw.status != darwin_spawn::PROCESS_STATUS_STOPPED
        || descriptors != EXPECTED_CHILD_DESCRIPTORS
        || executable_path_bytes != executable.canonical_path_bytes
    {
        return Err(MacosNativeHeldLaunchError::Invalid(
            "kernel did not report the exact held executable and descriptor allowlist".into(),
        ));
    }
    Ok(MacosNativeHeldProcessObservationV1 {
        pid: pid_u32,
        parent_pid: raw.parent_pid,
        process_group_id: raw.process_group_id,
        session_id: u32::try_from(session_id.as_raw_pid()).map_err(|_| {
            MacosNativeHeldLaunchError::Native("child session ID does not fit u32".into())
        })?,
        real_uid: raw.real_uid,
        effective_uid: raw.effective_uid,
        saved_uid: raw.saved_uid,
        real_gid: raw.real_gid,
        effective_gid: raw.effective_gid,
        saved_gid: raw.saved_gid,
        status: raw.status,
        start_time_seconds: raw.start_time_seconds,
        start_time_microseconds: raw.start_time_microseconds,
        open_descriptors: descriptors,
        executable_path_bytes,
        observed_at_unix_ms: now_unix_ms()?,
    })
}

fn now_unix_ms() -> Result<u64, MacosNativeHeldLaunchError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MacosNativeHeldLaunchError::Native("system clock predates epoch".into()))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| MacosNativeHeldLaunchError::Native("wall-clock millis overflow".into()))
}

fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Digest, MacosNativeHeldLaunchError> {
    let canonical = serde_json::to_vec(value).map_err(|error| {
        MacosNativeHeldLaunchError::Encoding(format!("encode digest preimage: {error}"))
    })?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(Digest::sha256(&bytes))
}

/// The only target-gated unsafe bridge. Its safe surface is fixed to spawn,
/// process-state/fd/path observation, and constants copied from the macOS 15
/// SDK headers. It cannot release, signal, change credentials, or apply policy.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod darwin_spawn {
    use std::ffi::{c_char, c_int, c_short, c_uint, c_void};
    use std::io;
    use std::mem::size_of;
    use std::ptr;

    pub(super) const PROCESS_STATUS_STOPPED: u32 = 4;
    pub(super) const PROCESS_STATUS_ZOMBIE: u32 = 5;
    pub(super) const SIGNAL_KILL: i32 = 9;

    const PROC_PIDLISTFDS: c_int = 1;
    const PROC_PIDTBSDINFO: c_int = 3;
    const PROC_PIDTASKINFO: c_int = 4;
    const MAX_PROCESS_DESCRIPTORS: usize = 64;
    const MAX_PROCESS_PATH_BYTES: usize = 4_096;
    const ESRCH: i32 = 3;
    const SIGNAL_STOP: c_int = 17;

    /// Exit statuses the forked child uses to report the exact stage it failed
    /// at. They are deliberately outside the range any admitted canary program
    /// returns, and the parent maps each one back to a named stage.
    pub(super) const CHILD_STAGE_DUP2: c_int = 121;
    pub(super) const CHILD_STAGE_FCHDIR: c_int = 122;
    pub(super) const CHILD_STAGE_SETSID: c_int = 123;
    pub(super) const CHILD_STAGE_PRESANDBOX_TABLE: c_int = 124;
    pub(super) const CHILD_STAGE_SANDBOX_INIT: c_int = 125;
    pub(super) const CHILD_STAGE_POSTSANDBOX_TABLE: c_int = 126;
    pub(super) const CHILD_STAGE_EXECVE: c_int = 127;

    type PosixSpawnAttr = *mut c_void;
    type PosixSpawnFileActions = *mut c_void;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcBsdInfo {
        pbi_flags: c_uint,
        pbi_status: c_uint,
        pbi_xstatus: c_uint,
        pbi_pid: c_uint,
        pbi_ppid: c_uint,
        pbi_uid: c_uint,
        pbi_gid: c_uint,
        pbi_ruid: c_uint,
        pbi_rgid: c_uint,
        pbi_svuid: c_uint,
        pbi_svgid: c_uint,
        rfu_1: c_uint,
        pbi_comm: [c_char; 16],
        pbi_name: [c_char; 32],
        pbi_nfiles: c_uint,
        pbi_pgid: c_uint,
        pbi_pjobc: c_uint,
        e_tdev: c_uint,
        e_tpgid: c_uint,
        pbi_nice: c_int,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFdInfo {
        proc_fd: c_int,
        proc_fdtype: c_uint,
    }

    /// `struct proc_taskinfo` from the macOS 15 `<sys/proc_info.h>`.
    ///
    /// Only `pti_threadnum` is read. It is the number of threads the task
    /// currently has, which is the one fact that decides whether this process
    /// may legally `fork` and then call a non-async-signal-safe function.
    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(
        clippy::struct_field_names,
        reason = "the field names are copied verbatim from the macOS 15 SDK header so the layout can be checked against it by eye"
    )]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: c_int,
        pti_faults: c_int,
        pti_pageins: c_int,
        pti_cow_faults: c_int,
        pti_messages_sent: c_int,
        pti_messages_received: c_int,
        pti_syscalls_mach: c_int,
        pti_syscalls_unix: c_int,
        pti_csw: c_int,
        pti_threadnum: c_int,
        pti_numrunning: c_int,
        pti_priority: c_int,
    }

    pub(super) struct DarwinProcessInfo {
        pub(super) pid: c_uint,
        pub(super) parent_pid: c_uint,
        pub(super) process_group_id: c_uint,
        pub(super) real_uid: c_uint,
        pub(super) effective_uid: c_uint,
        pub(super) saved_uid: c_uint,
        pub(super) real_gid: c_uint,
        pub(super) effective_gid: c_uint,
        pub(super) saved_gid: c_uint,
        pub(super) status: c_uint,
        pub(super) start_time_seconds: u64,
        pub(super) start_time_microseconds: u64,
    }

    unsafe extern "C" {
        fn posix_spawn(
            pid: *mut c_int,
            path: *const c_char,
            file_actions: *const PosixSpawnFileActions,
            attr: *const PosixSpawnAttr,
            argv: *const *mut c_char,
            envp: *const *mut c_char,
        ) -> c_int;
        fn posix_spawn_file_actions_init(actions: *mut PosixSpawnFileActions) -> c_int;
        fn posix_spawn_file_actions_destroy(actions: *mut PosixSpawnFileActions) -> c_int;
        fn posix_spawn_file_actions_adddup2(
            actions: *mut PosixSpawnFileActions,
            source: c_int,
            target: c_int,
        ) -> c_int;
        fn posix_spawn_file_actions_addinherit_np(
            actions: *mut PosixSpawnFileActions,
            descriptor: c_int,
        ) -> c_int;
        fn posix_spawn_file_actions_addfchdir_np(
            actions: *mut PosixSpawnFileActions,
            descriptor: c_int,
        ) -> c_int;
        fn posix_spawnattr_init(attr: *mut PosixSpawnAttr) -> c_int;
        fn posix_spawnattr_destroy(attr: *mut PosixSpawnAttr) -> c_int;
        fn posix_spawnattr_setflags(attr: *mut PosixSpawnAttr, flags: c_short) -> c_int;
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffer_size: c_int,
        ) -> c_int;
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffer_size: c_uint) -> c_int;
    }

    // The fork-apply-exec surface, kept in its own reviewed block because it is
    // the only place this crate runs code between `fork` and `execve`. Every
    // symbol here except `sandbox_init`/`sandbox_free_error` is on POSIX's
    // async-signal-safe list; the two that are not may only be called after the
    // caller has proved this task has exactly one thread (see
    // [`fork_apply_seatbelt_and_exec`]).
    //
    // `sandbox_init` and `sandbox_free_error` are deprecated in the macOS SDK
    // but present in libSystem on macOS 15 and are the only public way to apply
    // a Seatbelt profile: `sandbox_compile_string`, `sandbox_apply`, and
    // `sandbox_free_profile` were all measured absent from `RTLD_DEFAULT`, so no
    // precompiled profile blob can be handed to `posix_spawn`.
    unsafe extern "C" {
        fn fork() -> c_int;
        fn dup2(source: c_int, target: c_int) -> c_int;
        fn close(descriptor: c_int) -> c_int;
        fn fchdir(descriptor: c_int) -> c_int;
        fn setsid() -> c_int;
        fn raise(signal: c_int) -> c_int;
        fn write(descriptor: c_int, buffer: *const c_void, count: usize) -> isize;
        fn execve(path: *const c_char, argv: *const *mut c_char, envp: *const *mut c_char)
        -> c_int;
        fn _exit(status: c_int) -> !;
        fn sandbox_init(profile: *const c_char, flags: u64, error: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(error: *mut c_char);
    }

    /// Number of threads currently in one task, from `libproc`.
    pub(super) fn task_thread_count(pid: c_int) -> io::Result<u32> {
        let mut info = ProcTaskInfo {
            pti_virtual_size: 0,
            pti_resident_size: 0,
            pti_total_user: 0,
            pti_total_system: 0,
            pti_threads_user: 0,
            pti_threads_system: 0,
            pti_policy: 0,
            pti_faults: 0,
            pti_pageins: 0,
            pti_cow_faults: 0,
            pti_messages_sent: 0,
            pti_messages_received: 0,
            pti_syscalls_mach: 0,
            pti_syscalls_unix: 0,
            pti_csw: 0,
            pti_threadnum: 0,
            pti_numrunning: 0,
            pti_priority: 0,
        };
        let expected = c_int::try_from(size_of::<ProcTaskInfo>())
            .map_err(|_| io::Error::other("proc_taskinfo size overflow"))?;
        // SAFETY: `info` is writable for exactly its reported C-layout size.
        let count =
            unsafe { proc_pidinfo(pid, PROC_PIDTASKINFO, 0, (&raw mut info).cast(), expected) };
        if count != expected {
            return Err(io::Error::other("proc_taskinfo returned a partial record"));
        }
        u32::try_from(info.pti_threadnum)
            .map_err(|_| io::Error::other("proc_taskinfo reported a negative thread count"))
    }

    /// Everything one fork-apply-exec transition needs, prepared before `fork`.
    pub(super) struct ForkApplyPlan<'a> {
        pub(super) executable: &'a std::ffi::CStr,
        pub(super) argv_pointers: &'a [*mut c_char],
        pub(super) environment_pointers: &'a [*mut c_char],
        pub(super) profile: &'a std::ffi::CStr,
        pub(super) working_directory: c_int,
        pub(super) descriptors: [c_int; 3],
        pub(super) descriptor_ceiling: c_int,
    }

    /// Forks, applies the exact Seatbelt profile in the child, proves the
    /// child's descriptor table is exactly `{0, 1, 2}`, stops the child, and
    /// leaves it one `execve` away from the target.
    ///
    /// # Post-fork discipline
    ///
    /// After `fork` the child holds a copy of every lock the parent's other
    /// threads were holding, and those threads do not exist to release them.
    /// The child therefore uses only async-signal-safe primitives, `dup2`,
    /// `close`, `fchdir`, `setsid`, `raise`, `write`, `execve`, `_exit`, with
    /// the single deliberate exception of `sandbox_init`, which allocates. That
    /// exception is legal only because the caller has already proved with
    /// `libproc` that this task has exactly one thread, so no other thread can
    /// have been holding the allocator lock at the instant of the fork. The
    /// caller must not relax that precondition: it is the entire safety
    /// argument for calling a non-async-signal-safe function here.
    ///
    /// Nothing is allocated between `fork` and `execve`. Every C string,
    /// pointer vector, and integer this function needs is built by the caller
    /// before the fork, and no Rust value constructed inside the child branch
    /// has a destructor, because every path out of that branch is `_exit` or
    /// `execve`.
    pub(super) fn fork_apply_and_exec(plan: &ForkApplyPlan<'_>) -> io::Result<c_int> {
        // SAFETY: `fork` has no arguments and no preconditions beyond the
        // single-thread requirement the caller proved.
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid > 0 {
            return Ok(pid);
        }

        // ---- child: async-signal-safe only, except where noted ----
        // SAFETY (whole child branch): every pointer below was produced by the
        // caller before the fork and remains valid in this address space; each
        // call is a direct libSystem entry point; the branch never returns.
        unsafe {
            for (source, target) in plan.descriptors.into_iter().zip(0..=2) {
                if dup2(source, target) < 0 {
                    _exit(CHILD_STAGE_DUP2);
                }
            }
            if fchdir(plan.working_directory) < 0 {
                _exit(CHILD_STAGE_FCHDIR);
            }
            if setsid() < 0 {
                _exit(CHILD_STAGE_SETSID);
            }
            close_above_standard(plan.descriptor_ceiling);
            if !descriptor_table_is_exactly_standard(plan.descriptor_ceiling) {
                _exit(CHILD_STAGE_PRESANDBOX_TABLE);
            }

            // The one non-async-signal-safe call, licensed by the caller's
            // single-thread proof. `flags = 0` selects a literal profile
            // string; the bytes are the caller's, unmodified.
            let mut error: *mut c_char = ptr::null_mut();
            if sandbox_init(plan.profile.as_ptr(), 0, &raw mut error) != 0 {
                report_child_failure(b"sandbox_init: ");
                if !error.is_null() {
                    let mut length = 0_usize;
                    while *error.add(length) != 0 && length < 4_096 {
                        length = length.saturating_add(1);
                    }
                    let _ignored = write(2, error.cast(), length);
                    sandbox_free_error(error);
                }
                report_child_failure(b"\n");
                _exit(CHILD_STAGE_SANDBOX_INIT);
            }

            // Applying a profile must not add descriptors. Close and reprove
            // rather than assume it.
            close_above_standard(plan.descriptor_ceiling);
            if !descriptor_table_is_exactly_standard(plan.descriptor_ceiling) {
                _exit(CHILD_STAGE_POSTSANDBOX_TABLE);
            }

            // The parent's observation point: the table the kernel is about to
            // carry across `execve` is exactly what it reads here.
            raise(SIGNAL_STOP);

            execve(
                plan.executable.as_ptr(),
                plan.argv_pointers.as_ptr(),
                plan.environment_pointers.as_ptr(),
            );
            _exit(CHILD_STAGE_EXECVE);
        }
    }

    /// Closes every descriptor above the standard three. Async-signal-safe.
    ///
    /// # Safety
    ///
    /// Must be called only in a forked child that is about to `execve`.
    unsafe fn close_above_standard(ceiling: c_int) {
        let mut descriptor = 3;
        while descriptor < ceiling {
            // SAFETY: `close` on a closed descriptor is a harmless `EBADF`.
            unsafe { close(descriptor) };
            descriptor = descriptor.saturating_add(1);
        }
    }

    /// Whether exactly descriptors 0, 1, and 2 are open. Async-signal-safe.
    ///
    /// `dup2(fd, fd)` returns `fd` when `fd` is open and fails with `EBADF`
    /// otherwise, without changing anything, so it is an open-ness test built
    /// from a primitive this module already needs.
    ///
    /// # Safety
    ///
    /// Must be called only in a forked child that is about to `execve`.
    unsafe fn descriptor_table_is_exactly_standard(ceiling: c_int) -> bool {
        let mut descriptor = 0;
        while descriptor < ceiling {
            // SAFETY: duplicating a descriptor onto itself is a no-op probe.
            let open = unsafe { dup2(descriptor, descriptor) } >= 0;
            if open != (descriptor < 3) {
                return false;
            }
            descriptor = descriptor.saturating_add(1);
        }
        true
    }

    /// Writes one fixed diagnostic byte string to the child's stderr.
    ///
    /// # Safety
    ///
    /// Must be called only in a forked child that is about to `execve`.
    unsafe fn report_child_failure(message: &[u8]) {
        // SAFETY: the slice is a live borrow of static bytes in this address
        // space and `write` is async-signal-safe.
        let _ignored = unsafe { write(2, message.as_ptr().cast(), message.len()) };
    }

    struct FileActions {
        raw: PosixSpawnFileActions,
        initialized: bool,
    }

    impl FileActions {
        const fn uninitialized() -> Self {
            Self {
                raw: ptr::null_mut(),
                initialized: false,
            }
        }
    }

    impl Drop for FileActions {
        fn drop(&mut self) {
            if !self.initialized {
                return;
            }
            // SAFETY: the constructor returns only after successful init and
            // this owner destroys the opaque object exactly once.
            let _ = unsafe { posix_spawn_file_actions_destroy(&raw mut self.raw) };
            self.initialized = false;
        }
    }

    struct SpawnAttr {
        raw: PosixSpawnAttr,
        initialized: bool,
    }

    impl SpawnAttr {
        const fn uninitialized() -> Self {
            Self {
                raw: ptr::null_mut(),
                initialized: false,
            }
        }
    }

    impl Drop for SpawnAttr {
        fn drop(&mut self) {
            if !self.initialized {
                return;
            }
            // SAFETY: the constructor returns only after successful init and
            // this owner destroys the opaque object exactly once.
            let _ = unsafe { posix_spawnattr_destroy(&raw mut self.raw) };
            self.initialized = false;
        }
    }

    pub(super) fn spawn_suspended(
        executable: &std::ffi::CStr,
        argv: &[std::ffi::CString],
        environment: &[std::ffi::CString],
        working_directory: c_int,
        descriptors: [c_int; 5],
    ) -> io::Result<c_int> {
        let mut actions = FileActions::uninitialized();
        // SAFETY: `actions.raw` is writable local opaque storage. Drop does not
        // call destroy until the successful return is recorded below.
        cvt(unsafe { posix_spawn_file_actions_init(&raw mut actions.raw) })?;
        actions.initialized = true;
        for (source, target) in descriptors.into_iter().zip(0..=4) {
            // SAFETY: the initialized file-action object remains exclusively
            // borrowed; source and target are valid nonnegative descriptors.
            cvt(unsafe { posix_spawn_file_actions_adddup2(&raw mut actions.raw, source, target) })?;
            // SAFETY: marks only the explicit post-dup target as inherited
            // under CLOEXEC_DEFAULT.
            cvt(unsafe { posix_spawn_file_actions_addinherit_np(&raw mut actions.raw, target) })?;
        }
        // SAFETY: the normalized retained directory fd is valid through spawn.
        cvt(unsafe {
            posix_spawn_file_actions_addfchdir_np(&raw mut actions.raw, working_directory)
        })?;

        let mut attr = SpawnAttr::uninitialized();
        // SAFETY: `attr.raw` is writable local opaque storage. Drop does not
        // call destroy until the successful return is recorded below.
        cvt(unsafe { posix_spawnattr_init(&raw mut attr.raw) })?;
        attr.initialized = true;
        // SAFETY: fixed flags are supported by the macOS 15 deployment target.
        cvt(unsafe { posix_spawnattr_setflags(&raw mut attr.raw, super::REQUIRED_SPAWN_FLAGS) })?;

        let mut argv_ptrs = argv
            .iter()
            .map(|value| value.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        argv_ptrs.push(ptr::null_mut());
        let mut env_ptrs = environment
            .iter()
            .map(|value| value.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        env_ptrs.push(ptr::null_mut());
        let mut pid = 0;
        // SAFETY: every C string and pointer vector remains live and NUL
        // terminated for the call; opaque actions/attributes are initialized;
        // the kernel writes one pid_t into `pid` on success.
        cvt(unsafe {
            posix_spawn(
                &raw mut pid,
                executable.as_ptr(),
                &raw const actions.raw,
                &raw const attr.raw,
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            )
        })?;
        Ok(pid)
    }

    /// The three-descriptor development sibling of [`spawn_suspended`].
    ///
    /// It differs in exactly one respect: only descriptors 0, 1, and 2 are
    /// duplicated and marked inherited, so the child holds nothing else under
    /// `POSIX_SPAWN_CLOEXEC_DEFAULT`. Every flag, the descriptor-relative
    /// working directory, and the exact argv/environment vectors are the same.
    pub(super) fn spawn_stdio_suspended(
        executable: &std::ffi::CStr,
        argv: &[std::ffi::CString],
        environment: &[std::ffi::CString],
        working_directory: c_int,
        descriptors: [c_int; 3],
    ) -> io::Result<c_int> {
        let mut actions = FileActions::uninitialized();
        // SAFETY: `actions.raw` is writable local opaque storage. Drop does not
        // call destroy until the successful return is recorded below.
        cvt(unsafe { posix_spawn_file_actions_init(&raw mut actions.raw) })?;
        actions.initialized = true;
        for (source, target) in descriptors.into_iter().zip(0..=2) {
            // SAFETY: the initialized file-action object remains exclusively
            // borrowed; source and target are valid nonnegative descriptors.
            cvt(unsafe { posix_spawn_file_actions_adddup2(&raw mut actions.raw, source, target) })?;
            // SAFETY: marks only the explicit post-dup target as inherited
            // under CLOEXEC_DEFAULT.
            cvt(unsafe { posix_spawn_file_actions_addinherit_np(&raw mut actions.raw, target) })?;
        }
        // SAFETY: the normalized retained directory fd is valid through spawn.
        cvt(unsafe {
            posix_spawn_file_actions_addfchdir_np(&raw mut actions.raw, working_directory)
        })?;

        let mut attr = SpawnAttr::uninitialized();
        // SAFETY: `attr.raw` is writable local opaque storage. Drop does not
        // call destroy until the successful return is recorded below.
        cvt(unsafe { posix_spawnattr_init(&raw mut attr.raw) })?;
        attr.initialized = true;
        // SAFETY: fixed flags are supported by the macOS 15 deployment target.
        cvt(unsafe { posix_spawnattr_setflags(&raw mut attr.raw, super::REQUIRED_SPAWN_FLAGS) })?;

        let mut argv_ptrs = argv
            .iter()
            .map(|value| value.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        argv_ptrs.push(ptr::null_mut());
        let mut env_ptrs = environment
            .iter()
            .map(|value| value.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        env_ptrs.push(ptr::null_mut());
        let mut pid = 0;
        // SAFETY: every C string and pointer vector remains live and NUL
        // terminated for the call; opaque actions/attributes are initialized;
        // the kernel writes one pid_t into `pid` on success.
        cvt(unsafe {
            posix_spawn(
                &raw mut pid,
                executable.as_ptr(),
                &raw const actions.raw,
                &raw const attr.raw,
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            )
        })?;
        Ok(pid)
    }

    pub(super) fn observe_process(pid: c_int) -> io::Result<Option<DarwinProcessInfo>> {
        let mut info = ProcBsdInfo {
            pbi_flags: 0,
            pbi_status: 0,
            pbi_xstatus: 0,
            pbi_pid: 0,
            pbi_ppid: 0,
            pbi_uid: 0,
            pbi_gid: 0,
            pbi_ruid: 0,
            pbi_rgid: 0,
            pbi_svuid: 0,
            pbi_svgid: 0,
            rfu_1: 0,
            pbi_comm: [0; 16],
            pbi_name: [0; 32],
            pbi_nfiles: 0,
            pbi_pgid: 0,
            pbi_pjobc: 0,
            e_tdev: 0,
            e_tpgid: 0,
            pbi_nice: 0,
            pbi_start_tvsec: 0,
            pbi_start_tvusec: 0,
        };
        let expected = c_int::try_from(size_of::<ProcBsdInfo>())
            .map_err(|_| io::Error::other("proc_bsdinfo size overflow"))?;
        // SAFETY: `info` is writable for exactly its reported C-layout size.
        let count =
            unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), expected) };
        if count == 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if count != expected {
            return Err(io::Error::other("proc_bsdinfo returned a partial record"));
        }
        Ok(Some(DarwinProcessInfo {
            pid: info.pbi_pid,
            parent_pid: info.pbi_ppid,
            process_group_id: info.pbi_pgid,
            real_uid: info.pbi_ruid,
            effective_uid: info.pbi_uid,
            saved_uid: info.pbi_svuid,
            real_gid: info.pbi_rgid,
            effective_gid: info.pbi_gid,
            saved_gid: info.pbi_svgid,
            status: info.pbi_status,
            start_time_seconds: info.pbi_start_tvsec,
            start_time_microseconds: info.pbi_start_tvusec,
        }))
    }

    pub(super) fn list_descriptors(pid: c_int) -> io::Result<Vec<c_int>> {
        let mut entries = [ProcFdInfo {
            proc_fd: -1,
            proc_fdtype: 0,
        }; MAX_PROCESS_DESCRIPTORS];
        let capacity = c_int::try_from(size_of::<ProcFdInfo>() * entries.len())
            .map_err(|_| io::Error::other("descriptor buffer size overflow"))?;
        // SAFETY: `entries` is a writable fixed-size C-layout array.
        let count = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                capacity,
            )
        };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(count)
            .map_err(|_| io::Error::other("negative descriptor byte count"))?;
        if count % size_of::<ProcFdInfo>() != 0 || count > size_of_val(&entries) {
            return Err(io::Error::other(
                "descriptor list has an invalid byte count",
            ));
        }
        Ok(entries[..count / size_of::<ProcFdInfo>()]
            .iter()
            .map(|entry| entry.proc_fd)
            .collect())
    }

    pub(super) fn process_path(pid: c_int) -> io::Result<Vec<u8>> {
        let mut buffer = [0_u8; MAX_PROCESS_PATH_BYTES];
        // SAFETY: the buffer is writable for its exact advertised capacity.
        let count = unsafe {
            proc_pidpath(
                pid,
                buffer.as_mut_ptr().cast(),
                c_uint::try_from(buffer.len())
                    .map_err(|_| io::Error::other("process path buffer overflow"))?,
            )
        };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(count)
            .map_err(|_| io::Error::other("process path byte count is negative"))?;
        if count >= buffer.len() || buffer[..count].contains(&0) {
            return Err(io::Error::other(
                "process path is truncated or contains NUL",
            ));
        }
        Ok(buffer[..count].to_vec())
    }

    fn cvt(result: c_int) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result))
        }
    }
}

/// One point-in-time observation of a suspended development child.
///
/// This carries exactly what `libproc` reported at one instant. Like every
/// other observation in this module it makes no continuing claim: a same-UID
/// `SIGCONT` can invalidate `stopped` immediately after the read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosDevelopmentSpawnObservation {
    /// Descriptors the child held, ascending.
    pub(crate) descriptors: Vec<u32>,
    /// Whether the child's session identifier equals its own pid.
    pub(crate) session_leader: bool,
    /// The child's process group, which is the development domain identifier.
    pub(crate) process_group_id: u32,
    /// Whether the child was observed in the stopped state.
    pub(crate) stopped: bool,
    /// Whether the child was observed already terminated and unreaped.
    pub(crate) exited: bool,
}

/// Spawns one suspended child holding exactly descriptors 0, 1, and 2.
///
/// This is the three-descriptor sibling of the five-descriptor held-launch
/// primitive above and reuses the identical Darwin controls:
/// `POSIX_SPAWN_CLOEXEC_DEFAULT` closes everything the caller did not name,
/// `POSIX_SPAWN_SETSID` puts the child in a fresh session and process group,
/// `POSIX_SPAWN_START_SUSPENDED` stops it before its first instruction, and
/// `posix_spawn_file_actions_addfchdir_np` selects the working directory from
/// a retained descriptor rather than a pathname.
///
/// It exists for the development helper, which has no held-control or
/// setup-report descriptor to hand a child because `posix_spawn` cannot run
/// child code between fork and exec. Naming only the three standard
/// descriptors is therefore the honest binding: what the child receives is
/// exactly what the caller passed.
///
/// # Errors
///
/// Fails when a descriptor cannot be normalized above the target range or when
/// any `posix_spawn` operation reports an error number.
pub(crate) fn spawn_stdio_suspended(
    executable: &Path,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    working_directory: BorrowedFd<'_>,
    descriptors: [BorrowedFd<'_>; 3],
) -> std::io::Result<i32> {
    let program = CString::new(executable.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("executable path contains an interior NUL"))?;
    let argv = argv
        .iter()
        .map(|value| {
            CString::new(value.as_bytes())
                .map_err(|_| std::io::Error::other("argument contains an interior NUL"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let environment = environment
        .iter()
        .map(|(name, value)| {
            CString::new(format!("{name}={value}").into_bytes())
                .map_err(|_| std::io::Error::other("environment entry contains an interior NUL"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let normalized = descriptors
        .iter()
        .map(|descriptor| fcntl_dupfd_cloexec(descriptor, FIRST_NORMALIZED_DESCRIPTOR))
        .collect::<Result<Vec<OwnedFd>, _>>()
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    let working_directory = fcntl_dupfd_cloexec(working_directory, FIRST_NORMALIZED_DESCRIPTOR)
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    let raw: [i32; 3] = std::array::from_fn(|index| normalized[index].as_raw_fd());
    darwin_spawn::spawn_stdio_suspended(
        &program,
        &argv,
        &environment,
        working_directory.as_raw_fd(),
        raw,
    )
}

/// Threads currently in this process, read from `libproc`.
///
/// This is the single-thread proof that licenses a `fork` followed by a
/// non-async-signal-safe call. It is measured, never assumed.
///
/// # Errors
///
/// Fails when `proc_pidinfo` cannot return a complete task record.
#[cfg(target_os = "macos")]
pub(crate) fn current_process_thread_count() -> std::io::Result<u32> {
    darwin_spawn::task_thread_count(std::process::id().cast_signed())
}

/// Largest descriptor number this process can hold, for the child's close loop.
#[cfg(target_os = "macos")]
pub(crate) fn descriptor_ceiling() -> i32 {
    const FLOOR: u64 = 64;
    const CAP: u64 = 65_536;
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .unwrap_or(CAP);
    i32::try_from(limit.clamp(FLOOR, CAP)).unwrap_or(4_096)
}

/// Names the exact child setup stage behind one reserved exit status.
#[cfg(target_os = "macos")]
pub(crate) const fn child_setup_stage(status: i32) -> Option<&'static str> {
    match status {
        darwin_spawn::CHILD_STAGE_DUP2 => Some("duplicate the three standard descriptors"),
        darwin_spawn::CHILD_STAGE_FCHDIR => {
            Some("select the working directory from its retained descriptor")
        }
        darwin_spawn::CHILD_STAGE_SETSID => Some("create a new session"),
        darwin_spawn::CHILD_STAGE_PRESANDBOX_TABLE => {
            Some("close every inherited descriptor above the standard three")
        }
        darwin_spawn::CHILD_STAGE_SANDBOX_INIT => Some("apply the Seatbelt profile in process"),
        darwin_spawn::CHILD_STAGE_POSTSANDBOX_TABLE => {
            Some("reprove the descriptor table after applying the profile")
        }
        darwin_spawn::CHILD_STAGE_EXECVE => Some("execute the authenticated target"),
        _ => None,
    }
}

/// Forks, applies the exact Seatbelt profile in the child, and stops the child
/// one `execve` from the target.
///
/// This is the in-process profile applier. It exists because `posix_spawn`
/// cannot run any code between fork and exec, and applying a Seatbelt profile
/// requires running `sandbox_init` inside the process that will become the
/// target: `sandbox_compile_string`/`sandbox_apply`/`sandbox_free_profile` are
/// absent from libSystem on macOS 15, so there is no precompiled profile blob
/// to hand to `posix_spawnattr_setmacpolicyinfo_np`. Delegating to a separate
/// applier program instead, the `/usr/bin/sandbox-exec` shape, leaves the
/// launcher with no observation point at the target's own `execve`, because
/// the applier runs arbitrary code after the launcher's last look at it.
/// Forking is therefore required, not preferred.
///
/// `profile` is passed through byte for byte; this function never re-renders,
/// normalizes, or mutates it.
///
/// # Errors
///
/// Fails when this task has more than one thread (the fork would be unsafe),
/// when any string contains an interior NUL, when a descriptor cannot be
/// normalized above the standard range, or when `fork` itself fails.
#[cfg(target_os = "macos")]
pub(crate) fn fork_apply_seatbelt_and_exec(
    executable: &Path,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    profile: &str,
    working_directory: BorrowedFd<'_>,
    descriptors: [BorrowedFd<'_>; 3],
) -> std::io::Result<i32> {
    let threads = current_process_thread_count()?;
    if threads != 1 {
        return Err(std::io::Error::other(format!(
            "in-process Seatbelt application requires a single-threaded launch component, but \
             this task has {threads} threads"
        )));
    }
    let program = CString::new(executable.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("executable path contains an interior NUL"))?;
    let profile = CString::new(profile.as_bytes())
        .map_err(|_| std::io::Error::other("the Seatbelt profile contains an interior NUL"))?;
    let argv = argv
        .iter()
        .map(|value| {
            CString::new(value.as_bytes())
                .map_err(|_| std::io::Error::other("argument contains an interior NUL"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let environment = environment
        .iter()
        .map(|(name, value)| {
            CString::new(format!("{name}={value}").into_bytes())
                .map_err(|_| std::io::Error::other("environment entry contains an interior NUL"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let normalized = descriptors
        .iter()
        .map(|descriptor| fcntl_dupfd_cloexec(descriptor, FIRST_NORMALIZED_DESCRIPTOR))
        .collect::<Result<Vec<OwnedFd>, _>>()
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    let working_directory = fcntl_dupfd_cloexec(working_directory, FIRST_NORMALIZED_DESCRIPTOR)
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;

    // Every allocation the child could possibly need happens here, before the
    // fork. Nothing below this line allocates in the child.
    let mut argv_pointers = argv
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argv_pointers.push(std::ptr::null_mut());
    let mut environment_pointers = environment
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null_mut());
    let raw: [i32; 3] = std::array::from_fn(|index| normalized[index].as_raw_fd());

    darwin_spawn::fork_apply_and_exec(&darwin_spawn::ForkApplyPlan {
        executable: &program,
        argv_pointers: &argv_pointers,
        environment_pointers: &environment_pointers,
        profile: &profile,
        working_directory: working_directory.as_raw_fd(),
        descriptors: raw,
        descriptor_ceiling: descriptor_ceiling(),
    })
}

/// Waits until one forked child stops itself at the pre-`execve` observation
/// point, then reads its descriptor table.
///
/// Returns `Ok(None)` when the child left without stopping, which means it
/// failed a setup stage and its exit status names which one.
///
/// # Errors
///
/// Fails when the child cannot be observed or does not reach the observation
/// point within `limit`.
#[cfg(target_os = "macos")]
pub(crate) fn await_stopped_child(
    pid: i32,
    limit: Duration,
) -> std::io::Result<Option<MacosDevelopmentSpawnObservation>> {
    let started = Instant::now();
    loop {
        match observe_child_descriptors(pid)? {
            None => return Ok(None),
            Some(observation) if observation.stopped => return Ok(Some(observation)),
            Some(observation) if observation.exited => return Ok(None),
            Some(_) => {}
        }
        if started.elapsed() >= limit {
            return Err(std::io::Error::other(
                "the forked child never reached its pre-exec observation point",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Observes one child's descriptors, session, process group, and stopped state.
///
/// # Errors
///
/// Fails when the process cannot be observed. A process that no longer exists
/// yields `Ok(None)`.
pub(crate) fn observe_child_descriptors(
    pid: i32,
) -> std::io::Result<Option<MacosDevelopmentSpawnObservation>> {
    let Some(info) = darwin_spawn::observe_process(pid)? else {
        return Ok(None);
    };
    let mut descriptors = darwin_spawn::list_descriptors(pid)?
        .into_iter()
        .filter_map(|descriptor| u32::try_from(descriptor).ok())
        .collect::<Vec<_>>();
    descriptors.sort_unstable();
    descriptors.dedup();
    let session_leader = Pid::from_raw(pid)
        .and_then(|pid| getsid(Some(pid)).ok())
        .is_some_and(|session| session.as_raw_pid() == pid);
    Ok(Some(MacosDevelopmentSpawnObservation {
        descriptors,
        session_leader,
        process_group_id: info.process_group_id,
        stopped: info.status == darwin_spawn::PROCESS_STATUS_STOPPED,
        exited: info.status == darwin_spawn::PROCESS_STATUS_ZOMBIE,
    }))
}

/// Resumes one suspended development child.
///
/// # Errors
///
/// Fails when the pid is not a valid process identifier or the signal cannot
/// be delivered.
pub(crate) fn continue_stdio_child(pid: i32) -> std::io::Result<()> {
    let pid = Pid::from_raw(pid)
        .ok_or_else(|| std::io::Error::other("suspended child pid is not valid"))?;
    kill_process(pid, Signal::CONT)
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(test)]
pub(crate) fn inert_system_fixture_authority()
-> Result<MacosOrdinaryRunnerLaunchAuthority, MacosNativeHeldLaunchError> {
    system_fixture_authority(Path::new("/usr/bin/true"))
}

#[cfg(test)]
fn system_fixture_authority(
    path: &Path,
) -> Result<MacosOrdinaryRunnerLaunchAuthority, MacosNativeHeldLaunchError> {
    let executable = observe_executable(path)?;
    let expectation = MacosRetainedRunnerExecutableExpectation::try_new(
        executable.complete_bytes_digest,
        WireBinaryIdentity {
            device_id: executable.object.device_id,
            inode: executable.object.inode,
            byte_length: executable.object.byte_length,
            mode: executable.object.mode,
            owner_uid: executable.object.owner_uid,
            link_count: executable.object.link_count,
        },
    )
    .map_err(|error| {
        MacosNativeHeldLaunchError::Invalid(format!(
            "construct inert executable expectation: {error}"
        ))
    })?;
    Ok(MacosOrdinaryRunnerLaunchAuthority::test_fixture_with_executable(expectation))
}

#[cfg(test)]
pub(crate) fn launch_inert_system_fixture(
    authority: &MacosOrdinaryRunnerLaunchAuthority,
) -> Result<MacosNativeHeldLaunchOutcome, MacosNativeHeldLaunchError> {
    launch_system_fixture_with_faults(
        authority,
        Path::new("/usr/bin/true"),
        &["true".to_owned()],
        MacosNativeLaunchFaults::NONE,
    )
}

#[cfg(test)]
fn launch_system_fixture_with_faults(
    authority: &MacosOrdinaryRunnerLaunchAuthority,
    executable_path: &Path,
    argv: &[String],
    faults: MacosNativeLaunchFaults,
) -> Result<MacosNativeHeldLaunchOutcome, MacosNativeHeldLaunchError> {
    let descriptors = std::array::from_fn::<_, 5, _>(|_| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("open inert descriptor fixture")
    });
    let working_directory = File::open(".").map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("open fixture working directory: {error}"))
    })?;
    let inherited_canary = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|error| {
            MacosNativeHeldLaunchError::Native(format!("open inherited-fd canary: {error}"))
        })?;
    fcntl_setfd(&inherited_canary, FdFlags::empty()).map_err(|error| {
        MacosNativeHeldLaunchError::Native(format!("make inherited-fd canary non-CLOEXEC: {error}"))
    })?;
    let environment = BTreeMap::new();
    let spec = MacosNativeHeldLaunchSpec::new(
        authority,
        executable_path,
        argv,
        &environment,
        working_directory.as_fd(),
        descriptors.each_ref().map(AsFd::as_fd),
    );
    let outcome = launch_cleanup_only_observed_held_at_child_inner(spec, faults)?;
    drop(inherited_canary);
    Ok(outcome)
}

#[cfg(test)]
mod tests;
