//! Append-only state contract for an ordinary macOS runner held launch.
//!
//! This module includes an effect-free validation harness and a crash-safe,
//! descriptor-relative store for the future native service. The store fixes
//! service-owned per-launch namespaces, canonical generation shapes, digest
//! chaining, no-replace publication, synchronized readback, and restart
//! actions. A separate non-admissible, path-local observation records exact
//! executable bytes/inode plus path-based Apple `codesign` output, binds that
//! record to the retained service-state root, and revalidates canonical
//! readback. Path replacement can cross the `codesign` output with the retained
//! descriptor, and no independently anchored approved Grok identity exists.
//! It deliberately has no signed-service authority mint, installer/XPC-owned
//! root anchor, process, release, or cleanup operation, so those observations
//! and filesystem durability cannot be promoted to native evidence.

#![allow(dead_code)] // Activated by the future signed macOS runner-launch adapter.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, File, Metadata, OpenOptions, OpenOptionsExt, Permissions,
    PermissionsExt,
};
use grok_build_core::Digest;
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};

use crate::durable_directory::sync_directory_entries as sync_durable_directory;
use crate::macos_runner_held_protocol::{
    MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION, MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES,
    MacosOrdinaryRunnerHeldEvidence, MacosOrdinaryRunnerHeldProtocolError,
    MacosOrdinaryRunnerLaunchAuthority, MacosOrdinaryRunnerReleaseAuthorization,
    MacosOrdinaryRunnerReleaseAuthorizationRecord, MacosOrdinaryRunnerReleaseEvidence,
};

/// Darwin exposes extended ACL inspection only through the descriptor-based
/// POSIX.1e C API. This module is one of the repository's closed, target-gated
/// unsafe-code allowlist: its public surface is safe, descriptor-only,
/// allocation-bounded, and turns every unknown/unsupported inspection result
/// into refusal.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod darwin_acl {
    use std::ffi::c_void;
    use std::io;
    use std::os::fd::{AsFd, AsRawFd as _};
    use std::ptr;

    type Acl = *mut c_void;
    type AclEntry = *mut c_void;

    const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;
    const ACL_FIRST_ENTRY: i32 = 0;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, acl_type: i32) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: i32, entry: *mut AclEntry) -> i32;
        fn acl_free(object: *mut c_void) -> i32;
    }

    /// Rejects any nonempty macOS extended ACL on the exact retained object.
    pub(super) fn require_no_extended_acl(descriptor: &impl AsFd) -> io::Result<()> {
        inspect_fd(descriptor.as_fd().as_raw_fd())
    }

    #[cfg(test)]
    pub(super) fn inspect_invalid_descriptor_for_test() -> io::Result<()> {
        inspect_fd(-1)
    }

    fn inspect_fd(raw_fd: i32) -> io::Result<()> {
        // SAFETY: `raw_fd` is passed by value and the kernel validates it. On
        // success Darwin returns one independently allocated ACL object owned
        // by this function; on failure it returns null and owns no allocation.
        let acl = unsafe { acl_get_fd_np(raw_fd, ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            // Darwin reports ENOENT specifically when ACL_TYPE_EXTENDED is
            // absent. Every other error (bad descriptor, unsupported
            // filesystem, denied inspection, etc.) remains a refusal.
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            };
        }

        let mut entry: AclEntry = ptr::null_mut();
        // SAFETY: `acl` is the live nonnull allocation just returned by
        // `acl_get_fd_np`; `entry` points to writable local storage. The call
        // does not transfer ownership of either object.
        let entry_status = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
        let entry_error = (entry_status < 0).then(io::Error::last_os_error);
        // SAFETY: this is the exact allocation returned above, it has not been
        // freed or aliased into owning Rust state, and it is freed exactly once.
        let free_status = unsafe { acl_free(acl.cast()) };

        if let Some(error) = entry_error {
            return Err(error);
        }
        if free_status != 0 {
            return Err(io::Error::last_os_error());
        }
        match entry_status {
            0 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained service-state object has a macOS extended ACL",
            )),
            status => Err(io::Error::other(format!(
                "unexpected macOS ACL entry status {status}"
            ))),
        }
    }
}

#[cfg(target_os = "macos")]
fn require_no_macos_extended_acl(descriptor: &impl std::os::fd::AsFd) -> io::Result<()> {
    darwin_acl::require_no_extended_acl(descriptor)
}

#[cfg(not(target_os = "macos"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "half of a platform pair: the macOS arm returns the Darwin ACL inspection result, so the Result is the shared contract, not a redundant wrapper"
)]
fn require_no_macos_extended_acl<T>(_descriptor: &T) -> io::Result<()> {
    Ok(())
}

const JOURNAL_RECORD_DOMAIN: &[u8] = b"grok-build.macos-ordinary-runner-journal.v1\0";
const SERVICE_NAMESPACE_BINDING_DOMAIN: &[u8] =
    b"grok-build.macos-ordinary-runner-service-namespace.v1\0";
const SERVICE_NAMESPACE_RETIREMENT_DOMAIN: &[u8] =
    b"grok-build.macos-ordinary-runner-service-namespace-retirement.v1\0";
const SERVICE_NAMESPACE_KEY_DOMAIN: &[u8] =
    b"grok-build.macos-ordinary-runner-native-journal-id.v1\0";
// Immutable v1 durable-domain spelling. "trust-substrate" is a format label,
// not an admission or code-identity assurance claim.
const SIGNED_SERVICE_TRUST_BINDING_DOMAIN: &[u8] =
    b"grok-build.macos-ordinary-runner-signed-service-trust-substrate.v1\0";
const SIGNED_SERVICE_TRUST_BINDING: &str = "signed-service-trust.binding";
const SIGNED_SERVICE_TRUST_BINDING_TEMPORARY: &str = ".signed-service-trust.binding.tmp";
const SIGNED_SERVICE_TRUST_BINDING_VERSION: u32 = 1;
const MAX_SIGNED_SERVICE_EXECUTABLE_BYTES: u64 = 128 * 1_024 * 1_024;
const MAX_SIGNED_SERVICE_PATH_BYTES: usize = 4_096;
const MAX_CODESIGN_OUTPUT_BYTES: usize = 64 * 1_024;
const MAX_CODESIGN_REQUIREMENT_BYTES: usize = 8 * 1_024;
const MAX_CODESIGN_TEXT_BYTES: usize = 512;
const MAX_CODESIGN_AUTHORITIES: usize = 16;
#[cfg(target_os = "macos")]
const CODESIGN_VERIFY_ARGUMENTS: [&str; 4] =
    ["--verify", "--strict", "--all-architectures", "--verbose=4"];
#[cfg(target_os = "macos")]
const CODESIGN_DISPLAY_ARGUMENTS: [&str; 5] = [
    "--display",
    "--all-architectures",
    "--verbose=4",
    "--requirements",
    "-",
];
const MAX_JOURNAL_GENERATIONS: usize = 4;
const MAX_SERVICE_NAMESPACES: usize = 1_024;
const MAX_SERVICE_NAMESPACE_ENTRIES: usize = (MAX_SERVICE_NAMESPACES * 2) + 2;
const SERVICE_NAMESPACES_DIRECTORY: &str = "macos-ordinary-runner-launches-v1";
const SERVICE_NAMESPACE_INDEX_LOCK: &str = "namespace-index.lock";
const SERVICE_NAMESPACE_BINDING: &str = "namespace.binding";
const SERVICE_NAMESPACE_PREFIX: &str = "launch-";
const SERVICE_NAMESPACE_TEMPORARY_SUFFIX: &str = ".tmp";
const SERVICE_NAMESPACE_RETIREMENT_PREFIX: &str = "retired-";
const SERVICE_NAMESPACE_RETIREMENT_SUFFIX: &str = ".tombstone";
const SERVICE_NAMESPACE_RETIREMENT_TEMPORARY_SUFFIX: &str = ".tmp";
const DURABLE_JOURNAL_DIRECTORY: &str = "macos-ordinary-runner-journal-v1";
const DURABLE_WRITER_LOCK: &str = "writer.lock";
const GENERATION_PREFIX: &str = "generation-";
const GENERATION_SUFFIX: &str = ".record";
const TEMPORARY_SUFFIX: &str = ".tmp";
const MAX_DURABLE_JOURNAL_ENTRIES: usize = MAX_JOURNAL_GENERATIONS + 1;

/// Exact, path-reopened observation of one macOS executable image.
///
/// The digest covers the complete Mach-O bytes. The signing fields are parsed
/// only after `/usr/bin/codesign --verify --strict --all-architectures`
/// succeeds while the retained descriptor and its canonical named reopen keep
/// the same identity and digest. `codesign` still observes a path, not the
/// retained descriptor: a swap-and-restore race can therefore cross the
/// signing fields with different retained bytes. No field is an independently
/// anchored approved Grok service identity, and this type is never authority
/// to execute the image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosOrdinaryRunnerPathLocalSignedImageRecord {
    canonical_path_bytes: Vec<u8>,
    device_id: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
    byte_length: u64,
    link_count: u64,
    executable_bytes_digest: Digest,
    signing_identifier: String,
    team_identifier: Option<String>,
    cdhash: String,
    designated_requirement: String,
    signing_authorities: Vec<String>,
}

impl MacosOrdinaryRunnerPathLocalSignedImageRecord {
    fn validate(&self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        let valid_cdhash = matches!(self.cdhash.len(), 40 | 64)
            && self
                .cdhash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        let authorities_are_unique = self
            .signing_authorities
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == self.signing_authorities.len();
        let apple_platform_without_team = self.team_identifier.is_none()
            && self.signing_identifier.starts_with("com.apple.")
            && self
                .signing_authorities
                .iter()
                .any(|authority| authority == "Apple Root CA");
        if self.canonical_path_bytes.is_empty()
            || self.canonical_path_bytes.len() > MAX_SIGNED_SERVICE_PATH_BYTES
            || self.canonical_path_bytes.first() != Some(&b'/')
            || self.canonical_path_bytes.contains(&0)
            || self.device_id == 0
            || self.inode == 0
            || self.byte_length == 0
            || self.byte_length > MAX_SIGNED_SERVICE_EXECUTABLE_BYTES
            || self.link_count != 1
            || self.mode & 0o111 == 0
            || self.mode & 0o022 != 0
            || self
                .executable_bytes_digest
                .as_str()
                .bytes()
                .all(|byte| byte == b'0')
            || !valid_codesign_text(&self.signing_identifier, MAX_CODESIGN_TEXT_BYTES)
            || !valid_codesign_text(&self.designated_requirement, MAX_CODESIGN_REQUIREMENT_BYTES)
            || !self.designated_requirement.contains("anchor apple")
            || !self
                .designated_requirement
                .contains(&self.signing_identifier)
            || !valid_cdhash
            || self.signing_authorities.is_empty()
            || self.signing_authorities.len() > MAX_CODESIGN_AUTHORITIES
            || !authorities_are_unique
            || self
                .signing_authorities
                .iter()
                .any(|value| !valid_codesign_text(value, MAX_CODESIGN_TEXT_BYTES))
            || self.team_identifier.as_ref().is_some_and(|team| {
                !valid_codesign_text(team, MAX_CODESIGN_TEXT_BYTES) || team == "not set"
            })
            || (self.team_identifier.is_none() && !apple_platform_without_team)
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "validate-signed-service-image-identity",
                "service executable path, inode, bytes, or path-local code-sign display fields are unavailable or invalid",
            ));
        }
        Ok(())
    }
}

fn valid_codesign_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosOrdinaryRunnerServiceStoreRootIdentity {
    device_id: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
}

impl MacosOrdinaryRunnerServiceStoreRootIdentity {
    fn from_durable(identity: DurableDirectoryIdentity) -> Self {
        Self {
            device_id: identity.device_id,
            inode: identity.inode,
            owner_uid: identity.owner_uid,
            mode: identity.mode,
        }
    }

    fn validate(self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        if self.device_id == 0 || self.inode == 0 || self.mode != 0o700 {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "validate-signed-service-store-root-identity",
                "service-state root identity is not an exact retained mode-0700 directory",
            ));
        }
        Ok(())
    }
}

/// Canonical restart binding between one path-local signed-image observation
/// and the exact retained service-store root descriptor.
///
/// Because the record lives inside that root, it does not prove the root's
/// pre-restart inode continuity to an attacker able to replace the whole
/// store. An installer/XPC-owned anchor must bind this canonical record before
/// production admission can consume it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosOrdinaryRunnerPathLocalSignedImageBinding {
    format_version: u32,
    service_image: MacosOrdinaryRunnerPathLocalSignedImageRecord,
    service_store_root: MacosOrdinaryRunnerServiceStoreRootIdentity,
    binding_digest: Digest,
}

#[derive(Serialize)]
struct PathLocalSignedImageBindingPreimage<'a> {
    format_version: u32,
    service_image: &'a MacosOrdinaryRunnerPathLocalSignedImageRecord,
    service_store_root: MacosOrdinaryRunnerServiceStoreRootIdentity,
}

impl MacosOrdinaryRunnerPathLocalSignedImageBinding {
    fn new(
        service_image: MacosOrdinaryRunnerPathLocalSignedImageRecord,
        service_store_root: DurableDirectoryIdentity,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        let mut binding = Self {
            format_version: SIGNED_SERVICE_TRUST_BINDING_VERSION,
            service_image,
            service_store_root: MacosOrdinaryRunnerServiceStoreRootIdentity::from_durable(
                service_store_root,
            ),
            binding_digest: Digest::sha256(&[]),
        };
        binding.binding_digest = binding.computed_digest()?;
        binding.validate(None, Some(service_store_root))?;
        Ok(binding)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, MacosOrdinaryRunnerDurableStoreError> {
        let json = serde_json::to_vec(self).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "encode-signed-service-trust-binding",
                error,
            )
        })?;
        let mut bytes = Vec::with_capacity(SIGNED_SERVICE_TRUST_BINDING_DOMAIN.len() + json.len());
        bytes.extend_from_slice(SIGNED_SERVICE_TRUST_BINDING_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "encode-signed-service-trust-binding",
                "signed-service trust binding exceeds its exact byte bound",
            ));
        }
        Ok(bytes)
    }

    fn decode_canonical(
        bytes: &[u8],
        expected_image: Option<&MacosOrdinaryRunnerPathLocalSignedImageRecord>,
        expected_root: Option<DurableDirectoryIdentity>,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-signed-service-trust-binding",
                "signed-service trust binding is empty or oversized",
            ));
        }
        let json = bytes
            .strip_prefix(SIGNED_SERVICE_TRUST_BINDING_DOMAIN)
            .ok_or_else(|| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "decode-signed-service-trust-binding",
                    "signed-service trust binding domain separator is absent",
                )
            })?;
        let binding: Self = serde_json::from_slice(json).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-signed-service-trust-binding",
                error,
            )
        })?;
        if serde_json::to_vec(&binding).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "reencode-signed-service-trust-binding",
                error,
            )
        })? != json
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-signed-service-trust-binding",
                "signed-service trust binding is not canonical JSON",
            ));
        }
        binding.validate(expected_image, expected_root)?;
        Ok(binding)
    }

    fn computed_digest(&self) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
        let preimage = PathLocalSignedImageBindingPreimage {
            format_version: self.format_version,
            service_image: &self.service_image,
            service_store_root: self.service_store_root,
        };
        let json = serde_json::to_vec(&preimage).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "digest-signed-service-trust-binding",
                error,
            )
        })?;
        let mut bytes = Vec::with_capacity(SIGNED_SERVICE_TRUST_BINDING_DOMAIN.len() + json.len());
        bytes.extend_from_slice(SIGNED_SERVICE_TRUST_BINDING_DOMAIN);
        bytes.extend_from_slice(&json);
        Ok(Digest::sha256(&bytes))
    }

    fn validate(
        &self,
        expected_image: Option<&MacosOrdinaryRunnerPathLocalSignedImageRecord>,
        expected_root: Option<DurableDirectoryIdentity>,
    ) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        self.service_image.validate()?;
        self.service_store_root.validate()?;
        if self.format_version != SIGNED_SERVICE_TRUST_BINDING_VERSION
            || self.binding_digest != self.computed_digest()?
            || expected_image.is_some_and(|expected| expected != &self.service_image)
            || expected_root.is_some_and(|expected| {
                self.service_store_root
                    != MacosOrdinaryRunnerServiceStoreRootIdentity::from_durable(expected)
            })
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "validate-signed-service-trust-binding",
                "signed service image, service-store root, or binding digest is crossed",
            ));
        }
        self.canonical_bytes()?;
        Ok(())
    }
}

/// Non-cloneable, non-admissible path-local signed-image observation.
///
/// It can only re-observe the current executable path and revalidate its
/// retained state-root binding. Path-based `codesign` output is not a dynamic
/// code identity, an independently anchored approved Grok identity, or an
/// observation-to-use lock. This type intentionally carries no journal
/// admission, process, release, cleanup, or namespace-retirement capability.
struct MacosOrdinaryRunnerPathLocalSignedImageObservation {
    service_state_root: Dir,
    service_state_identity: DurableDirectoryIdentity,
    binding_file: File,
    binding_file_identity: DurableFileIdentity,
    binding: MacosOrdinaryRunnerPathLocalSignedImageBinding,
}

/// Canonical, service-owned binding between one opaque native journal ID and
/// the complete externally reconstructed launch authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosOrdinaryRunnerServiceNamespaceBinding {
    protocol_version: u32,
    namespace_key: Digest,
    authority: MacosOrdinaryRunnerLaunchAuthority,
    binding_digest: Digest,
}

#[derive(Serialize)]
struct ServiceNamespaceBindingPreimage<'a> {
    protocol_version: u32,
    namespace_key: &'a Digest,
    authority: &'a MacosOrdinaryRunnerLaunchAuthority,
}

impl MacosOrdinaryRunnerServiceNamespaceBinding {
    fn for_authority(
        authority: MacosOrdinaryRunnerLaunchAuthority,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        authority.validate_retained().map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "validate-namespace-launch-authority",
                error,
            )
        })?;
        let namespace_key = service_namespace_key(&authority);
        let mut binding = Self {
            protocol_version: MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION,
            namespace_key,
            authority,
            binding_digest: Digest::sha256(&[]),
        };
        binding.binding_digest = binding.computed_digest()?;
        binding.validate(None)?;
        Ok(binding)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, MacosOrdinaryRunnerDurableStoreError> {
        let json = serde_json::to_vec(self).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "encode-namespace-binding",
                error,
            )
        })?;
        let mut bytes = Vec::with_capacity(SERVICE_NAMESPACE_BINDING_DOMAIN.len() + json.len());
        bytes.extend_from_slice(SERVICE_NAMESPACE_BINDING_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "encode-namespace-binding",
                "namespace binding exceeds its exact byte bound",
            ));
        }
        Ok(bytes)
    }

    fn decode_canonical(
        bytes: &[u8],
        expected: Option<&MacosOrdinaryRunnerLaunchAuthority>,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-namespace-binding",
                "namespace binding is empty or exceeds its exact byte bound",
            ));
        }
        let json = bytes
            .strip_prefix(SERVICE_NAMESPACE_BINDING_DOMAIN)
            .ok_or_else(|| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "decode-namespace-binding",
                    "namespace binding domain separator is absent",
                )
            })?;
        let binding: Self = serde_json::from_slice(json).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-namespace-binding",
                error,
            )
        })?;
        if serde_json::to_vec(&binding).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "reencode-namespace-binding",
                error,
            )
        })? != json
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-namespace-binding",
                "namespace binding encoding is noncanonical",
            ));
        }
        binding.validate(expected)?;
        Ok(binding)
    }

    fn computed_digest(&self) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
        let preimage = ServiceNamespaceBindingPreimage {
            protocol_version: self.protocol_version,
            namespace_key: &self.namespace_key,
            authority: &self.authority,
        };
        let json = serde_json::to_vec(&preimage).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "digest-namespace-binding",
                error,
            )
        })?;
        let mut bytes = Vec::with_capacity(SERVICE_NAMESPACE_BINDING_DOMAIN.len() + json.len());
        bytes.extend_from_slice(SERVICE_NAMESPACE_BINDING_DOMAIN);
        bytes.extend_from_slice(&json);
        Ok(Digest::sha256(&bytes))
    }

    fn validate(
        &self,
        expected: Option<&MacosOrdinaryRunnerLaunchAuthority>,
    ) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        self.authority.validate_retained().map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-namespace-binding-authority",
                error,
            )
        })?;
        if self.protocol_version != MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION
            || self.namespace_key != service_namespace_key(&self.authority)
            || self.binding_digest != self.computed_digest()?
            || expected.is_some_and(|expected| expected != &self.authority)
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "validate-namespace-binding",
                "namespace key, complete launch authority, or binding digest is crossed",
            ));
        }
        self.canonical_bytes()?;
        Ok(())
    }
}

fn service_namespace_key(authority: &MacosOrdinaryRunnerLaunchAuthority) -> Digest {
    let mut bytes = Vec::with_capacity(
        SERVICE_NAMESPACE_KEY_DOMAIN.len() + authority.attempt().native_journal_id.len(),
    );
    bytes.extend_from_slice(SERVICE_NAMESPACE_KEY_DOMAIN);
    bytes.extend_from_slice(authority.attempt().native_journal_id.as_bytes());
    Digest::sha256(&bytes)
}

fn service_namespace_name(key: &Digest) -> String {
    format!("{SERVICE_NAMESPACE_PREFIX}{}", key.as_str())
}

fn service_namespace_temporary_name(key: &Digest) -> String {
    format!(
        ".{}{SERVICE_NAMESPACE_TEMPORARY_SUFFIX}",
        service_namespace_name(key)
    )
}

fn service_namespace_retirement_name(key: &Digest) -> String {
    format!("{SERVICE_NAMESPACE_RETIREMENT_PREFIX}{key}{SERVICE_NAMESPACE_RETIREMENT_SUFFIX}")
}

fn service_namespace_retirement_temporary_name(key: &Digest) -> String {
    format!(
        ".{}{}",
        service_namespace_retirement_name(key),
        SERVICE_NAMESPACE_RETIREMENT_TEMPORARY_SUFFIX
    )
}

/// Explicit, contract-only readback supplied after the cleanup terminal write.
///
/// It deliberately retains the exact cleanup evidence and terminal-readback
/// bytes rather than treating a success flag or a namespace-local digest as
/// proof. The current ordinary-runner store cannot authenticate that the bytes
/// came from the core ledger: the signed service/ledger bridge is still absent.
/// Consequently this type can only publish a permanent no-reuse tombstone; it
/// never authorizes a native launch, release, cleanup, or namespace deletion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosOrdinaryRunnerNamespaceRetirementReadback {
    protocol_version: u32,
    authority: MacosOrdinaryRunnerLaunchAuthority,
    cleanup_effect_id: String,
    cleanup_terminal_evidence_bytes: Vec<u8>,
    cleanup_terminal_readback_bytes: Vec<u8>,
    retired_at_unix_ms: u64,
    readback_digest: Digest,
}

#[derive(Serialize)]
struct NamespaceRetirementReadbackPreimage<'a> {
    protocol_version: u32,
    authority: &'a MacosOrdinaryRunnerLaunchAuthority,
    cleanup_effect_id: &'a str,
    cleanup_terminal_evidence_bytes: &'a [u8],
    cleanup_terminal_readback_bytes: &'a [u8],
    retired_at_unix_ms: u64,
}

impl MacosOrdinaryRunnerNamespaceRetirementReadback {
    /// Builds a non-admissible retirement readback from the exact cleanup
    /// terminal evidence and separately reopened terminal bytes.
    pub(crate) fn contract_only(
        authority: MacosOrdinaryRunnerLaunchAuthority,
        cleanup_terminal_evidence_bytes: Vec<u8>,
        cleanup_terminal_readback_bytes: Vec<u8>,
        retired_at_unix_ms: u64,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        let mut readback = Self {
            protocol_version: MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION,
            cleanup_effect_id: authority.attempt().cleanup_effect_id.clone(),
            authority,
            cleanup_terminal_evidence_bytes,
            cleanup_terminal_readback_bytes,
            retired_at_unix_ms,
            readback_digest: Digest::sha256(&[]),
        };
        readback.readback_digest = readback.computed_digest()?;
        readback.validate(None)?;
        Ok(readback)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, MacosOrdinaryRunnerDurableStoreError> {
        let json = serde_json::to_vec(self).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "encode-namespace-retirement-readback",
                error,
            )
        })?;
        let mut bytes = Vec::with_capacity(SERVICE_NAMESPACE_RETIREMENT_DOMAIN.len() + json.len());
        bytes.extend_from_slice(SERVICE_NAMESPACE_RETIREMENT_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "encode-namespace-retirement-readback",
                "retirement readback exceeds its exact byte bound",
            ));
        }
        Ok(bytes)
    }

    fn decode_canonical(
        bytes: &[u8],
        expected: Option<&MacosOrdinaryRunnerLaunchAuthority>,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-namespace-retirement-readback",
                "retirement readback is empty or exceeds its exact byte bound",
            ));
        }
        let json = bytes
            .strip_prefix(SERVICE_NAMESPACE_RETIREMENT_DOMAIN)
            .ok_or_else(|| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "decode-namespace-retirement-readback",
                    "retirement readback domain separator is absent",
                )
            })?;
        let readback: Self = serde_json::from_slice(json).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-namespace-retirement-readback",
                error,
            )
        })?;
        if serde_json::to_vec(&readback).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "reencode-namespace-retirement-readback",
                error,
            )
        })? != json
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "decode-namespace-retirement-readback",
                "retirement readback encoding is noncanonical",
            ));
        }
        readback.validate(expected)?;
        Ok(readback)
    }

    fn computed_digest(&self) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
        let preimage = NamespaceRetirementReadbackPreimage {
            protocol_version: self.protocol_version,
            authority: &self.authority,
            cleanup_effect_id: &self.cleanup_effect_id,
            cleanup_terminal_evidence_bytes: &self.cleanup_terminal_evidence_bytes,
            cleanup_terminal_readback_bytes: &self.cleanup_terminal_readback_bytes,
            retired_at_unix_ms: self.retired_at_unix_ms,
        };
        let json = serde_json::to_vec(&preimage).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "digest-namespace-retirement-readback",
                error,
            )
        })?;
        let mut bytes = Vec::with_capacity(SERVICE_NAMESPACE_RETIREMENT_DOMAIN.len() + json.len());
        bytes.extend_from_slice(SERVICE_NAMESPACE_RETIREMENT_DOMAIN);
        bytes.extend_from_slice(&json);
        Ok(Digest::sha256(&bytes))
    }

    fn validate(
        &self,
        expected: Option<&MacosOrdinaryRunnerLaunchAuthority>,
    ) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        self.authority.validate_retained().map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-namespace-retirement-authority",
                error,
            )
        })?;
        if self.protocol_version != MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION
            || self.cleanup_effect_id != self.authority.attempt().cleanup_effect_id
            || self.retired_at_unix_ms < self.authority.attempt().claimed_at_unix_ms
            || self.cleanup_terminal_evidence_bytes.is_empty()
            || self.cleanup_terminal_readback_bytes.is_empty()
            || self.cleanup_terminal_evidence_bytes.len()
                > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES
            || self.cleanup_terminal_readback_bytes.len()
                > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES
            || self.readback_digest != self.computed_digest()?
            || expected.is_some_and(|expected| expected != &self.authority)
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "validate-namespace-retirement-readback",
                "retirement authority, cleanup evidence/readback, timestamp, or digest is crossed",
            ));
        }
        self.canonical_bytes()?;
        Ok(())
    }
}

/// Exact state of one ordinary runner held-launch journal generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosOrdinaryRunnerJournalState {
    PreparationIntended,
    HeldPrepared,
    ReleaseIntended,
    Released,
}

/// Restart behavior selected only from a validated immutable prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacosOrdinaryRunnerRecoveryAction {
    /// No native preparation may be retried; reconcile whether a child exists.
    ReconcilePreparation,
    /// Reconcile core's preparation outcome; never release after restart.
    ReconcileOuterPreparation,
    /// Reconcile the one attempted release; never issue a second release.
    ReconcileRelease,
    /// The launch release is already terminal in this journal.
    None,
}

impl MacosOrdinaryRunnerRecoveryAction {
    /// Recovery is reconciliation-only at every journal state. In particular,
    /// reopening durable bytes never authorizes a release.
    pub(crate) const fn permits_native_release(self) -> bool {
        match self {
            Self::ReconcilePreparation
            | Self::ReconcileOuterPreparation
            | Self::ReconcileRelease
            | Self::None => false,
        }
    }
}

/// One immutable generation in the future service-owned journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosOrdinaryRunnerJournalRecord {
    protocol_version: u32,
    generation: u32,
    previous_record_digest: Option<Digest>,
    state: MacosOrdinaryRunnerJournalState,
    authority: MacosOrdinaryRunnerLaunchAuthority,
    preparation_intended_at_unix_ms: u64,
    held_evidence: Option<MacosOrdinaryRunnerHeldEvidence>,
    release_authorization: Option<MacosOrdinaryRunnerReleaseAuthorizationRecord>,
    release_evidence: Option<MacosOrdinaryRunnerReleaseEvidence>,
    record_digest: Digest,
}

#[derive(Serialize)]
struct JournalRecordPreimage<'a> {
    protocol_version: u32,
    generation: u32,
    previous_record_digest: &'a Option<Digest>,
    state: MacosOrdinaryRunnerJournalState,
    authority: &'a MacosOrdinaryRunnerLaunchAuthority,
    preparation_intended_at_unix_ms: u64,
    held_evidence: &'a Option<MacosOrdinaryRunnerHeldEvidence>,
    release_authorization: &'a Option<MacosOrdinaryRunnerReleaseAuthorizationRecord>,
    release_evidence: &'a Option<MacosOrdinaryRunnerReleaseEvidence>,
}

impl MacosOrdinaryRunnerJournalRecord {
    pub(crate) fn preparation_intent(
        authority: MacosOrdinaryRunnerLaunchAuthority,
        intended_at_unix_ms: u64,
    ) -> Result<Self, MacosOrdinaryRunnerJournalError> {
        authority.validate_retained()?;
        if intended_at_unix_ms < authority.attempt().claimed_at_unix_ms {
            return Err(invalid(
                "preparation intent predates the exact core preparation claim",
            ));
        }
        let expected_authority = authority.clone();
        let mut record = Self {
            protocol_version: MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION,
            generation: 1,
            previous_record_digest: None,
            state: MacosOrdinaryRunnerJournalState::PreparationIntended,
            authority,
            preparation_intended_at_unix_ms: intended_at_unix_ms,
            held_evidence: None,
            release_authorization: None,
            release_evidence: None,
            record_digest: Digest::sha256(&[]),
        };
        record.seal()?;
        record.validate(&expected_authority, None)?;
        Ok(record)
    }

    pub(crate) const fn state(&self) -> MacosOrdinaryRunnerJournalState {
        self.state
    }

    pub(crate) const fn authority(&self) -> &MacosOrdinaryRunnerLaunchAuthority {
        &self.authority
    }

    pub(crate) const fn held_evidence(&self) -> Option<&MacosOrdinaryRunnerHeldEvidence> {
        self.held_evidence.as_ref()
    }

    pub(crate) const fn release_authorization(
        &self,
    ) -> Option<&MacosOrdinaryRunnerReleaseAuthorizationRecord> {
        self.release_authorization.as_ref()
    }

    pub(crate) const fn record_digest(&self) -> &Digest {
        &self.record_digest
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MacosOrdinaryRunnerJournalError> {
        let json = serde_json::to_vec(self).map_err(|error| {
            MacosOrdinaryRunnerJournalError::Encoding(format!(
                "journal record encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(JOURNAL_RECORD_DOMAIN.len() + json.len());
        bytes.extend_from_slice(JOURNAL_RECORD_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(MacosOrdinaryRunnerJournalError::TooLarge {
                bytes: bytes.len(),
                maximum: MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes one record against authority reconstructed independently from
    /// the persisted journal. Successors additionally chain to the prior
    /// already-validated record.
    pub(crate) fn decode_canonical(
        bytes: &[u8],
        expected_authority: &MacosOrdinaryRunnerLaunchAuthority,
        previous: Option<&Self>,
    ) -> Result<Self, MacosOrdinaryRunnerJournalError> {
        if bytes.is_empty() || bytes.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(MacosOrdinaryRunnerJournalError::TooLarge {
                bytes: bytes.len(),
                maximum: MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES,
            });
        }
        let json = bytes
            .strip_prefix(JOURNAL_RECORD_DOMAIN)
            .ok_or_else(|| invalid("journal record domain separator is absent"))?;
        let record: Self = serde_json::from_slice(json).map_err(|error| {
            MacosOrdinaryRunnerJournalError::Encoding(format!(
                "journal record decoding failed: {error}"
            ))
        })?;
        if serde_json::to_vec(&record).map_err(|error| {
            MacosOrdinaryRunnerJournalError::Encoding(format!(
                "journal record re-encoding failed: {error}"
            ))
        })? != json
        {
            return Err(invalid("journal record encoding is noncanonical"));
        }
        record.validate(expected_authority, previous)?;
        Ok(record)
    }

    fn successor(
        &self,
        state: MacosOrdinaryRunnerJournalState,
        held_evidence: Option<MacosOrdinaryRunnerHeldEvidence>,
        release_authorization: Option<MacosOrdinaryRunnerReleaseAuthorizationRecord>,
        release_evidence: Option<MacosOrdinaryRunnerReleaseEvidence>,
    ) -> Result<Self, MacosOrdinaryRunnerJournalError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("journal generation overflow"))?;
        let mut record = Self {
            protocol_version: self.protocol_version,
            generation,
            previous_record_digest: Some(self.record_digest.clone()),
            state,
            authority: self.authority.clone(),
            preparation_intended_at_unix_ms: self.preparation_intended_at_unix_ms,
            held_evidence,
            release_authorization,
            release_evidence,
            record_digest: Digest::sha256(&[]),
        };
        record.seal()?;
        record.validate(&self.authority, Some(self))?;
        Ok(record)
    }

    fn seal(&mut self) -> Result<(), MacosOrdinaryRunnerJournalError> {
        self.record_digest = self.computed_digest()?;
        Ok(())
    }

    fn computed_digest(&self) -> Result<Digest, MacosOrdinaryRunnerJournalError> {
        let preimage = JournalRecordPreimage {
            protocol_version: self.protocol_version,
            generation: self.generation,
            previous_record_digest: &self.previous_record_digest,
            state: self.state,
            authority: &self.authority,
            preparation_intended_at_unix_ms: self.preparation_intended_at_unix_ms,
            held_evidence: &self.held_evidence,
            release_authorization: &self.release_authorization,
            release_evidence: &self.release_evidence,
        };
        let json = serde_json::to_vec(&preimage).map_err(|error| {
            MacosOrdinaryRunnerJournalError::Encoding(format!(
                "journal digest preimage encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(JOURNAL_RECORD_DOMAIN.len() + json.len());
        bytes.extend_from_slice(JOURNAL_RECORD_DOMAIN);
        bytes.extend_from_slice(&json);
        Ok(Digest::sha256(&bytes))
    }

    fn validate(
        &self,
        expected_authority: &MacosOrdinaryRunnerLaunchAuthority,
        previous: Option<&Self>,
    ) -> Result<(), MacosOrdinaryRunnerJournalError> {
        self.validate_integrity_against(expected_authority)?;
        match previous {
            None => {
                if self.generation != 1 || self.previous_record_digest.is_some() {
                    return Err(invalid(
                        "initial journal generation or previous digest is invalid",
                    ));
                }
            }
            Some(previous) => {
                previous.validate_integrity_against(expected_authority)?;
                if self.generation != previous.generation.saturating_add(1)
                    || self.previous_record_digest.as_ref() != Some(&previous.record_digest)
                    || self.authority != previous.authority
                    || self.preparation_intended_at_unix_ms
                        != previous.preparation_intended_at_unix_ms
                    || !valid_successor(previous.state, self.state)
                {
                    return Err(invalid(
                        "journal successor crossed its prefix, authority, or state",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_integrity_against(
        &self,
        expected_authority: &MacosOrdinaryRunnerLaunchAuthority,
    ) -> Result<(), MacosOrdinaryRunnerJournalError> {
        self.validate_shape()?;
        expected_authority.validate_retained()?;
        if self.authority != *expected_authority {
            return Err(invalid(
                "journal authority differs from the externally reconstructed authority",
            ));
        }
        if self.record_digest != self.computed_digest()? {
            return Err(invalid(
                "journal record digest differs from its canonical preimage",
            ));
        }
        self.canonical_bytes()?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), MacosOrdinaryRunnerJournalError> {
        self.authority.validate_retained()?;
        if self.protocol_version != MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION
            || self.preparation_intended_at_unix_ms < self.authority.attempt().claimed_at_unix_ms
        {
            return Err(invalid(
                "journal protocol or preparation-intent time is invalid",
            ));
        }
        if let Some(held) = &self.held_evidence {
            held.validate_for(&self.authority)?;
        }
        if let (Some(held), Some(authorization)) =
            (&self.held_evidence, &self.release_authorization)
        {
            authorization.validate_for(&self.authority, held)?;
        }
        if let (Some(held), Some(authorization), Some(release)) = (
            &self.held_evidence,
            &self.release_authorization,
            &self.release_evidence,
        ) {
            release.validate_for(&self.authority, held, authorization)?;
        }
        let exact_shape = match self.state {
            MacosOrdinaryRunnerJournalState::PreparationIntended => {
                self.generation == 1
                    && self.held_evidence.is_none()
                    && self.release_authorization.is_none()
                    && self.release_evidence.is_none()
            }
            MacosOrdinaryRunnerJournalState::HeldPrepared => {
                self.generation == 2
                    && self.held_evidence.is_some()
                    && self.release_authorization.is_none()
                    && self.release_evidence.is_none()
            }
            MacosOrdinaryRunnerJournalState::ReleaseIntended => {
                self.generation == 3
                    && self.held_evidence.is_some()
                    && self.release_authorization.is_some()
                    && self.release_evidence.is_none()
            }
            MacosOrdinaryRunnerJournalState::Released => {
                self.generation == 4
                    && self.held_evidence.is_some()
                    && self.release_authorization.is_some()
                    && self.release_evidence.is_some()
            }
        };
        if !exact_shape {
            return Err(invalid(
                "journal state fields do not have their exact shape",
            ));
        }
        Ok(())
    }
}

fn valid_successor(
    previous: MacosOrdinaryRunnerJournalState,
    next: MacosOrdinaryRunnerJournalState,
) -> bool {
    matches!(
        (previous, next),
        (
            MacosOrdinaryRunnerJournalState::PreparationIntended,
            MacosOrdinaryRunnerJournalState::HeldPrepared
        ) | (
            MacosOrdinaryRunnerJournalState::HeldPrepared,
            MacosOrdinaryRunnerJournalState::ReleaseIntended
        ) | (
            MacosOrdinaryRunnerJournalState::ReleaseIntended,
            MacosOrdinaryRunnerJournalState::Released
        )
    )
}

/// Non-cloneable release transition retaining the live core authorization.
#[must_use = "release authority must be appended once or dropped"]
pub(crate) struct MacosOrdinaryRunnerLiveReleaseTransition<'claim, 'ledger> {
    record: MacosOrdinaryRunnerJournalRecord,
    authorization: MacosOrdinaryRunnerReleaseAuthorization<'claim, 'ledger>,
}

#[cfg(test)]
#[allow(
    clippy::elidable_lifetime_names,
    reason = "the harness must return the exact two lifetimes retained by the opaque transition"
)]
impl<'claim, 'ledger> MacosOrdinaryRunnerLiveReleaseTransition<'claim, 'ledger> {
    /// Test-harness split only. Production must retain the live authorization
    /// inside one synchronous persist-then-release callback.
    pub(crate) fn into_parts(
        self,
    ) -> (
        MacosOrdinaryRunnerJournalRecord,
        MacosOrdinaryRunnerReleaseAuthorization<'claim, 'ledger>,
    ) {
        (self.record, self.authorization)
    }
}

pub(crate) fn record_held_preparation(
    current: &MacosOrdinaryRunnerJournalRecord,
    held: MacosOrdinaryRunnerHeldEvidence,
) -> Result<MacosOrdinaryRunnerJournalRecord, MacosOrdinaryRunnerJournalError> {
    if current.state != MacosOrdinaryRunnerJournalState::PreparationIntended {
        return Err(invalid(
            "held preparation requires the one preparation-intent generation",
        ));
    }
    held.validate_for(&current.authority)?;
    current.successor(
        MacosOrdinaryRunnerJournalState::HeldPrepared,
        Some(held),
        None,
        None,
    )
}

pub(crate) fn intend_release<'claim, 'ledger>(
    current: &MacosOrdinaryRunnerJournalRecord,
    authorization: MacosOrdinaryRunnerReleaseAuthorization<'claim, 'ledger>,
) -> Result<
    MacosOrdinaryRunnerLiveReleaseTransition<'claim, 'ledger>,
    MacosOrdinaryRunnerJournalError,
> {
    if current.state != MacosOrdinaryRunnerJournalState::HeldPrepared {
        return Err(invalid(
            "release intent requires the one held-prepared generation",
        ));
    }
    let held = current
        .held_evidence
        .as_ref()
        .ok_or_else(|| invalid("held-prepared generation lacks held evidence"))?;
    authorization
        .record()
        .validate_for(&current.authority, held)?;
    let record = current.successor(
        MacosOrdinaryRunnerJournalState::ReleaseIntended,
        Some(held.clone()),
        Some(authorization.record().clone()),
        None,
    )?;
    Ok(MacosOrdinaryRunnerLiveReleaseTransition {
        record,
        authorization,
    })
}

pub(crate) fn record_released(
    current: &MacosOrdinaryRunnerJournalRecord,
    release: MacosOrdinaryRunnerReleaseEvidence,
) -> Result<MacosOrdinaryRunnerJournalRecord, MacosOrdinaryRunnerJournalError> {
    if current.state != MacosOrdinaryRunnerJournalState::ReleaseIntended {
        return Err(invalid(
            "released evidence requires the one release-intended generation",
        ));
    }
    let held = current
        .held_evidence
        .as_ref()
        .ok_or_else(|| invalid("release-intended generation lacks held evidence"))?;
    let authorization = current
        .release_authorization
        .as_ref()
        .ok_or_else(|| invalid("release-intended generation lacks authorization"))?;
    release.validate_for(&current.authority, held, authorization)?;
    current.successor(
        MacosOrdinaryRunnerJournalState::Released,
        Some(held.clone()),
        Some(authorization.clone()),
        Some(release),
    )
}

/// Effect-free host-test harness for exact append-only transition validation.
///
/// The harness deliberately has no callback that performs a native release.
/// A future durable store must consume `MacosOrdinaryRunnerLiveReleaseTransition`
/// only after synchronizing its record, then invoke the native adapter while
/// the embedded live claim remains borrowed.
pub(crate) struct MacosOrdinaryRunnerJournalHarness {
    expected_authority: MacosOrdinaryRunnerLaunchAuthority,
    generations: Vec<MacosOrdinaryRunnerJournalRecord>,
}

impl MacosOrdinaryRunnerJournalHarness {
    pub(crate) fn new(
        authority: MacosOrdinaryRunnerLaunchAuthority,
        intended_at_unix_ms: u64,
    ) -> Result<Self, MacosOrdinaryRunnerJournalError> {
        let initial = MacosOrdinaryRunnerJournalRecord::preparation_intent(
            authority.clone(),
            intended_at_unix_ms,
        )?;
        Ok(Self {
            expected_authority: authority,
            generations: vec![initial],
        })
    }

    pub(crate) fn head(&self) -> &MacosOrdinaryRunnerJournalRecord {
        self.generations
            .last()
            .expect("journal harness always has its initial generation")
    }

    pub(crate) fn append_held(
        &mut self,
        held: MacosOrdinaryRunnerHeldEvidence,
    ) -> Result<(), MacosOrdinaryRunnerJournalError> {
        let next = record_held_preparation(self.head(), held)?;
        self.append(next)
    }

    #[cfg(test)]
    pub(crate) fn append_release_intent_for_test(
        &mut self,
        authorization: MacosOrdinaryRunnerReleaseAuthorization<'_, '_>,
    ) -> Result<(), MacosOrdinaryRunnerJournalError> {
        let transition = intend_release(self.head(), authorization)?;
        let (record, _live_authorization) = transition.into_parts();
        self.append(record)
    }

    pub(crate) fn append_released(
        &mut self,
        release: MacosOrdinaryRunnerReleaseEvidence,
    ) -> Result<(), MacosOrdinaryRunnerJournalError> {
        let next = record_released(self.head(), release)?;
        self.append(next)
    }

    pub(crate) fn canonical_history(
        &self,
    ) -> Result<Vec<Vec<u8>>, MacosOrdinaryRunnerJournalError> {
        validate_history(&self.expected_authority, &self.generations)?;
        self.generations
            .iter()
            .map(MacosOrdinaryRunnerJournalRecord::canonical_bytes)
            .collect()
    }

    fn append(
        &mut self,
        next: MacosOrdinaryRunnerJournalRecord,
    ) -> Result<(), MacosOrdinaryRunnerJournalError> {
        if self.generations.len() >= MAX_JOURNAL_GENERATIONS {
            return Err(invalid("journal generation bound reached"));
        }
        next.validate(&self.expected_authority, Some(self.head()))?;
        self.generations.push(next);
        validate_history(&self.expected_authority, &self.generations)
    }
}

pub(crate) fn validate_history(
    expected_authority: &MacosOrdinaryRunnerLaunchAuthority,
    generations: &[MacosOrdinaryRunnerJournalRecord],
) -> Result<(), MacosOrdinaryRunnerJournalError> {
    if generations.is_empty() || generations.len() > MAX_JOURNAL_GENERATIONS {
        return Err(invalid(
            "journal history is empty or exceeds its hard bound",
        ));
    }
    for (index, record) in generations.iter().enumerate() {
        record.validate(
            expected_authority,
            index.checked_sub(1).map(|previous| &generations[previous]),
        )?;
    }
    Ok(())
}

/// Selects restart behavior only after validating the complete immutable
/// prefix against authority reconstructed outside that prefix.
pub(crate) fn recovery_action(
    expected_authority: &MacosOrdinaryRunnerLaunchAuthority,
    generations: &[MacosOrdinaryRunnerJournalRecord],
) -> Result<MacosOrdinaryRunnerRecoveryAction, MacosOrdinaryRunnerJournalError> {
    validate_history(expected_authority, generations)?;
    let head = generations
        .last()
        .ok_or_else(|| invalid("journal recovery requires a nonempty validated prefix"))?;
    Ok(match head.state {
        MacosOrdinaryRunnerJournalState::PreparationIntended => {
            MacosOrdinaryRunnerRecoveryAction::ReconcilePreparation
        }
        MacosOrdinaryRunnerJournalState::HeldPrepared => {
            MacosOrdinaryRunnerRecoveryAction::ReconcileOuterPreparation
        }
        MacosOrdinaryRunnerJournalState::ReleaseIntended => {
            MacosOrdinaryRunnerRecoveryAction::ReconcileRelease
        }
        MacosOrdinaryRunnerJournalState::Released => MacosOrdinaryRunnerRecoveryAction::None,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableDirectoryIdentity {
    device_id: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableFileIdentity {
    device_id: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
    byte_length: u64,
    link_count: u64,
}

struct DurableJournalScan {
    generations: Vec<MacosOrdinaryRunnerJournalRecord>,
    generation_identities: Vec<DurableFileIdentity>,
    temporary: Option<(String, u32)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableServiceNamespaceIdentity {
    namespace: DurableDirectoryIdentity,
    binding: DurableFileIdentity,
    journal: DurableDirectoryIdentity,
    writer_lock: DurableFileIdentity,
}

struct DurableServiceNamespaceIndexScan {
    namespaces: BTreeMap<String, DurableServiceNamespaceIdentity>,
    namespace_authorities: BTreeMap<String, MacosOrdinaryRunnerLaunchAuthority>,
    retirements: BTreeMap<String, DurableFileIdentity>,
    temporary: Option<String>,
}

struct OpenedServiceNamespace {
    namespace: Dir,
    identity: DurableServiceNamespaceIdentity,
    journal: Dir,
    writer_lock: File,
}

/// Persistence certainty for one service-journal operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacosOrdinaryRunnerDurableFailureClass {
    /// No immutable generation was published by this operation.
    NotPublished,
    /// A temporary or malformed prefix must be reconciled before progress.
    RecoveryRequired,
    /// Publication may have happened; callers must reopen and reconcile.
    Ambiguous,
    /// The exact immutable generation was already present.
    AlreadyPublished,
    /// The requested generation conflicts with an immutable prefix.
    Substitution,
}

/// Fail-closed durable-store error with an explicit persistence class.
#[derive(Debug)]
pub(crate) struct MacosOrdinaryRunnerDurableStoreError {
    class: MacosOrdinaryRunnerDurableFailureClass,
    operation: &'static str,
    detail: String,
}

impl MacosOrdinaryRunnerDurableStoreError {
    pub(crate) const fn class(&self) -> MacosOrdinaryRunnerDurableFailureClass {
        self.class
    }
}

impl Display for MacosOrdinaryRunnerDurableStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ordinary macOS runner durable journal {} failed ({:?}): {}",
            self.operation, self.class, self.detail
        )
    }
}

impl std::error::Error for MacosOrdinaryRunnerDurableStoreError {}

fn durable_failure(
    class: MacosOrdinaryRunnerDurableFailureClass,
    operation: &'static str,
    detail: impl Into<String>,
) -> MacosOrdinaryRunnerDurableStoreError {
    MacosOrdinaryRunnerDurableStoreError {
        class,
        operation,
        detail: detail.into(),
    }
}

fn journal_failure(
    class: MacosOrdinaryRunnerDurableFailureClass,
    operation: &'static str,
    error: impl Display,
) -> MacosOrdinaryRunnerDurableStoreError {
    durable_failure(class, operation, error.to_string())
}

/// Receipt returned only after the exact generation was synchronized,
/// published without replacement, directory-synchronized, and read back.
///
/// This is an operation-local equality witness. It does not retain the named
/// file or directory descriptors and therefore cannot authenticate later
/// filesystem state; later use must reopen through the service authority.
#[derive(Debug)]
pub(crate) struct MacosOrdinaryRunnerDurableCommitReceipt {
    generation: u32,
    record_digest: Digest,
    canonical_bytes_digest: Digest,
    journal_identity: DurableDirectoryIdentity,
    generation_identity: DurableFileIdentity,
}

impl MacosOrdinaryRunnerDurableCommitReceipt {
    pub(crate) fn matches_operation_readback(
        &self,
        record: &MacosOrdinaryRunnerJournalRecord,
    ) -> bool {
        record.canonical_bytes().is_ok_and(|bytes| {
            self.generation == record.generation
                && self.record_digest == record.record_digest
                && self.canonical_bytes_digest == Digest::sha256(&bytes)
                && self.journal_identity.device_id != 0
                && self.journal_identity.inode != 0
                && self.generation_identity.device_id != 0
                && self.generation_identity.inode != 0
        })
    }
}

impl MacosOrdinaryRunnerPathLocalSignedImageObservation {
    /// Reconstructs a path-local signed-image observation from the current
    /// process executable path and binds it to one retained service root.
    ///
    /// This remains a non-admissible substrate. In particular, successfully
    /// opening it does not authenticate an XPC peer or an installer-owned
    /// pre-restart store anchor.
    #[cfg(target_os = "macos")]
    fn from_current_process_path_and_retained_root(
        service_state_root: Dir,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        let current_executable = std::env::current_exe().map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "resolve-current-signed-service-image",
                error,
            )
        })?;
        Self::from_signed_image_path_and_retained_root(service_state_root, &current_executable)
    }

    #[cfg(target_os = "macos")]
    fn from_signed_image_path_and_retained_root(
        service_state_root: Dir,
        signed_service_path: &Path,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        let service_state_identity =
            validate_durable_private_directory(&service_state_root, "service-state root")?;
        let service_image = observe_path_local_signed_image(signed_service_path)?;
        let expected_binding = MacosOrdinaryRunnerPathLocalSignedImageBinding::new(
            service_image,
            service_state_identity,
        )?;
        let namespaces = service_state_root
            .open_dir_nofollow(SERVICE_NAMESPACES_DIRECTORY)
            .map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                    "open-signed-service-binding-lock-root",
                    error,
                )
            })?;
        let namespaces_identity =
            validate_durable_private_directory(&namespaces, "service namespace index")?;
        if namespaces_identity.owner_uid != service_state_identity.owner_uid {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "bind-signed-service-binding-lock-root",
                "namespace-index owner differs from the service-state owner",
            ));
        }
        require_named_durable_directory_identity(
            &service_state_root,
            SERVICE_NAMESPACES_DIRECTORY,
            namespaces_identity,
        )?;
        let index_lock = open_named_durable_writer_lock(
            &namespaces,
            SERVICE_NAMESPACE_INDEX_LOCK,
            "open-signed-service-binding-lock",
        )?;
        let index_lock_identity = validate_durable_private_file(
            &index_lock,
            Path::new(SERVICE_NAMESPACE_INDEX_LOCK),
            Some(0),
        )?;
        if index_lock_identity.owner_uid != service_state_identity.owner_uid {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "bind-signed-service-binding-lock",
                "signed-service binding lock owner differs from the service-state owner",
            ));
        }
        require_named_durable_file_identity(
            &namespaces,
            SERVICE_NAMESPACE_INDEX_LOCK,
            index_lock_identity,
        )?;
        lock_durable_writer(&index_lock)?;
        let result = persist_or_read_signed_service_trust_binding(
            &service_state_root,
            service_state_identity,
            &expected_binding,
        );
        let (binding, binding_file, binding_file_identity) =
            unlock_durable_writer(&index_lock, result)?;
        let substrate = Self {
            service_state_root,
            service_state_identity,
            binding_file,
            binding_file_identity,
            binding,
        };
        substrate.revalidate()?;
        Ok(substrate)
    }

    /// Re-observes the signed-image path and the complete canonical binding.
    /// The binding is descriptor-retained, while `codesign` remains path-based;
    /// no success result is executable or journal-admission authority.
    #[cfg(target_os = "macos")]
    fn revalidate(&self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        let root = validate_durable_private_directory(
            &self.service_state_root,
            "retained signed-service state root",
        )?;
        if root != self.service_state_identity {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "revalidate-signed-service-state-root",
                "retained signed-service state-root descriptor identity drifted",
            ));
        }
        let retained_binding = validate_durable_private_file(
            &self.binding_file,
            Path::new(SIGNED_SERVICE_TRUST_BINDING),
            Some(self.binding_file_identity.byte_length),
        )?;
        if retained_binding != self.binding_file_identity {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "revalidate-signed-service-binding-descriptor",
                "retained signed-service binding descriptor identity drifted",
            ));
        }
        require_named_durable_file_identity(
            &self.service_state_root,
            SIGNED_SERVICE_TRUST_BINDING,
            self.binding_file_identity,
        )?;
        let (bytes, named_identity) = read_stable_durable_file(
            &self.service_state_root,
            Path::new(SIGNED_SERVICE_TRUST_BINDING),
        )?;
        let readback = MacosOrdinaryRunnerPathLocalSignedImageBinding::decode_canonical(
            &bytes,
            Some(&self.binding.service_image),
            Some(self.service_state_identity),
        )?;
        if named_identity != self.binding_file_identity || readback != self.binding {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "revalidate-signed-service-binding-readback",
                "signed-service binding identity or canonical bytes changed",
            ));
        }
        let executable_path =
            signed_service_path_from_bytes(&self.binding.service_image.canonical_path_bytes)?;
        let observed = observe_path_local_signed_image(&executable_path)?;
        if observed != self.binding.service_image {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "revalidate-signed-service-image",
                "current signed-service path, inode, complete bytes, or signing identity is crossed",
            ));
        }
        Ok(())
    }

    /// This path-local observation never authorizes native execution.
    const fn permits_execution() -> bool {
        false
    }
}

/// Non-cloneable state boundary for one long-lived service-owned launch index.
///
/// The descriptor is intentionally not public authority to run a process. A
/// future signed service must call this boundary only after independent peer,
/// code-signature, executable-image, and installation-root authentication.
/// It may then admit multiple exact launch authorities into disjoint,
/// content-addressed `native_journal_id` namespaces.
pub(crate) struct MacosOrdinaryRunnerServiceStateAuthority {
    service_state_root: Dir,
    service_state_identity: DurableDirectoryIdentity,
    namespaces: Dir,
    namespaces_identity: DurableDirectoryIdentity,
    index_lock: File,
    index_lock_identity: DurableFileIdentity,
    retained_namespaces: BTreeMap<String, DurableServiceNamespaceIdentity>,
    retained_retirements: BTreeMap<String, DurableFileIdentity>,
    admitted_namespace_keys: BTreeSet<String>,
}

impl MacosOrdinaryRunnerServiceStateAuthority {
    /// Descriptor-only production-facing validation boundary. This function
    /// authenticates filesystem shape and ACL absence, not the calling
    /// process, code signature, installation, or any right to spawn/release.
    pub(crate) fn from_retained_service_state_root(
        service_state_root: Dir,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        let service_state_identity =
            validate_durable_private_directory(&service_state_root, "service-state root")?;
        let namespaces = service_state_root
            .open_dir_nofollow(SERVICE_NAMESPACES_DIRECTORY)
            .map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                    "open-service-namespace-index",
                    error,
                )
            })?;
        let namespaces_identity =
            validate_durable_private_directory(&namespaces, "service namespace index")?;
        require_named_durable_directory_identity(
            &service_state_root,
            SERVICE_NAMESPACES_DIRECTORY,
            namespaces_identity,
        )?;
        if namespaces_identity.owner_uid != service_state_identity.owner_uid {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "bind-service-namespace-index",
                "service-state and namespace-index roots have different owners",
            ));
        }
        let index_lock = open_named_durable_writer_lock(
            &namespaces,
            SERVICE_NAMESPACE_INDEX_LOCK,
            "open-service-namespace-index-lock",
        )?;
        let index_lock_identity = validate_durable_private_file(
            &index_lock,
            Path::new(SERVICE_NAMESPACE_INDEX_LOCK),
            Some(0),
        )?;
        if index_lock_identity.owner_uid != service_state_identity.owner_uid {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "bind-service-namespace-index-lock",
                "namespace-index lock owner differs from the service-state owner",
            ));
        }
        require_named_durable_file_identity(
            &namespaces,
            SERVICE_NAMESPACE_INDEX_LOCK,
            index_lock_identity,
        )?;
        let mut authority = Self {
            service_state_root,
            service_state_identity,
            namespaces,
            namespaces_identity,
            index_lock,
            index_lock_identity,
            retained_namespaces: BTreeMap::new(),
            retained_retirements: BTreeMap::new(),
            admitted_namespace_keys: BTreeSet::new(),
        };
        lock_durable_writer(&authority.index_lock)?;
        let result = authority.refresh_index_locked();
        unlock_durable_writer(&authority.index_lock, result)?;
        Ok(authority)
    }

    fn validate_retained_roots(&self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        let service = validate_durable_private_directory(
            &self.service_state_root,
            "retained service-state root",
        )?;
        let namespaces = validate_durable_private_directory(
            &self.namespaces,
            "retained service namespace index",
        )?;
        if service != self.service_state_identity
            || namespaces != self.namespaces_identity
            || service.owner_uid != namespaces.owner_uid
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-retained-service-namespace-roots",
                "retained service-state or namespace-index identity drifted",
            ));
        }
        require_named_durable_directory_identity(
            &self.service_state_root,
            SERVICE_NAMESPACES_DIRECTORY,
            self.namespaces_identity,
        )?;
        let index_lock = validate_durable_private_file(
            &self.index_lock,
            Path::new(SERVICE_NAMESPACE_INDEX_LOCK),
            Some(0),
        )?;
        if index_lock != self.index_lock_identity
            || index_lock.owner_uid != self.service_state_identity.owner_uid
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-retained-service-namespace-index-lock",
                "retained namespace-index lock identity drifted",
            ));
        }
        require_named_durable_file_identity(
            &self.namespaces,
            SERVICE_NAMESPACE_INDEX_LOCK,
            self.index_lock_identity,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the bounded index scan must keep namespace, tombstone, temporary, retained-identity, and exact-authority checks in one auditable order"
    )]
    fn scan_index_locked(
        &self,
    ) -> Result<DurableServiceNamespaceIndexScan, MacosOrdinaryRunnerDurableStoreError> {
        self.validate_retained_roots()?;
        let entries = self.namespaces.entries().map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace-index",
                error,
            )
        })?;
        let mut entries_seen = 0_usize;
        let mut namespaces = BTreeMap::new();
        let mut namespace_authorities = BTreeMap::new();
        let mut retirements = BTreeMap::new();
        let mut temporary = None;
        for entry in entries {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_SERVICE_NAMESPACE_ENTRIES {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "scan-service-namespace-index",
                    "service namespace entry count exceeds its hard bound",
                ));
            }
            let entry = entry.map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "scan-service-namespace-index",
                    error,
                )
            })?;
            let name = entry.file_name().into_string().map_err(|_| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "scan-service-namespace-index",
                    "service namespace index contains a non-UTF-8 entry",
                )
            })?;
            if name == SERVICE_NAMESPACE_INDEX_LOCK {
                continue;
            }
            if name.starts_with('.') && name.ends_with(SERVICE_NAMESPACE_TEMPORARY_SUFFIX) {
                if name.starts_with(&format!(".{SERVICE_NAMESPACE_RETIREMENT_PREFIX}")) {
                    parse_service_namespace_retirement_temporary_name(&name)?;
                } else {
                    parse_service_namespace_temporary_name(&name)?;
                }
                if temporary.replace(name).is_some() {
                    return Err(durable_failure(
                        MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                        "scan-service-namespace-index",
                        "multiple unresolved service namespace temporaries are present",
                    ));
                }
                continue;
            }
            if name.starts_with(SERVICE_NAMESPACE_RETIREMENT_PREFIX) {
                let key = parse_service_namespace_retirement_name(&name)?;
                let (bytes, identity) =
                    read_stable_durable_file(&self.namespaces, Path::new(&name))?;
                if identity.owner_uid != self.service_state_identity.owner_uid {
                    return Err(durable_failure(
                        MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                        "read-service-namespace-retirement",
                        "namespace retirement owner differs from the service-state owner",
                    ));
                }
                let retirement =
                    MacosOrdinaryRunnerNamespaceRetirementReadback::decode_canonical(&bytes, None)?;
                if key != service_namespace_key(&retirement.authority)
                    || retirements.insert(name, identity).is_some()
                {
                    return Err(durable_failure(
                        MacosOrdinaryRunnerDurableFailureClass::Substitution,
                        "scan-service-namespace-index",
                        "namespace retirement name, authority, or index entry is crossed",
                    ));
                }
                continue;
            }
            let key = parse_service_namespace_name(&name)?;
            let opened = open_service_namespace(
                &self.namespaces,
                &name,
                self.service_state_identity.owner_uid,
                None,
            )?;
            let (binding, _) = read_service_namespace_binding(
                &opened.namespace,
                self.service_state_identity.owner_uid,
                None,
            )?;
            if binding.namespace_key != key
                || namespaces.insert(name.clone(), opened.identity).is_some()
                || namespace_authorities
                    .insert(name, binding.authority)
                    .is_some()
            {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::Substitution,
                    "scan-service-namespace-index",
                    "namespace name, native journal ID, or index entry is duplicated or crossed",
                ));
            }
        }
        if namespaces.len() > MAX_SERVICE_NAMESPACES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace-index",
                "service namespace count exceeds its hard bound",
            ));
        }
        for (retirement_name, retirement_identity) in &retirements {
            let key = parse_service_namespace_retirement_name(retirement_name)?;
            let namespace_name = service_namespace_name(&key);
            let authority = namespace_authorities.get(&namespace_name).ok_or_else(|| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "bind-service-namespace-retirement",
                    "a retirement tombstone has no retained exact launch namespace",
                )
            })?;
            let (bytes, observed_identity) =
                read_stable_durable_file(&self.namespaces, Path::new(retirement_name))?;
            if observed_identity != *retirement_identity {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "validate-service-namespace-retirement",
                    "retained retirement tombstone identity changed during index scan",
                ));
            }
            MacosOrdinaryRunnerNamespaceRetirementReadback::decode_canonical(
                &bytes,
                Some(authority),
            )?;
        }
        for (name, retained) in &self.retained_namespaces {
            if namespaces.get(name) != Some(retained) {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "validate-retained-service-namespace",
                    "a retained service namespace or one of its fixed objects was replaced",
                ));
            }
        }
        for (name, retained) in &self.retained_retirements {
            if retirements.get(name) != Some(retained) {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "validate-retained-service-namespace-retirement",
                    "a retained namespace retirement tombstone was replaced or disappeared",
                ));
            }
        }
        Ok(DurableServiceNamespaceIndexScan {
            namespaces,
            namespace_authorities,
            retirements,
            temporary,
        })
    }

    fn refresh_index_locked(&mut self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        let scan = self.scan_index_locked()?;
        self.retained_namespaces = scan.namespaces;
        self.retained_retirements = scan.retirements;
        Ok(())
    }

    /// Admits one exact external launch authority into its canonical namespace.
    /// This grants journal-state access only and never permits native effects.
    pub(crate) fn admit_launch(
        &mut self,
        expected_launch_authority: MacosOrdinaryRunnerLaunchAuthority,
    ) -> Result<MacosOrdinaryRunnerDurableStoreAuthority, MacosOrdinaryRunnerDurableStoreError>
    {
        expected_launch_authority
            .validate_retained()
            .map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                    "validate-external-launch-authority",
                    error,
                )
            })?;
        let key = service_namespace_key(&expected_launch_authority);
        let name = service_namespace_name(&key);
        lock_durable_writer(&self.index_lock)?;
        let result = self.admit_launch_locked(expected_launch_authority, &key, &name);
        let result = unlock_durable_writer(&self.index_lock, result);
        if result.is_ok() {
            self.admitted_namespace_keys.insert(name);
        }
        result
    }

    fn admit_launch_locked(
        &mut self,
        expected_launch_authority: MacosOrdinaryRunnerLaunchAuthority,
        key: &Digest,
        name: &str,
    ) -> Result<MacosOrdinaryRunnerDurableStoreAuthority, MacosOrdinaryRunnerDurableStoreError>
    {
        let mut scan = self.scan_index_locked()?;
        let retirement_name = service_namespace_retirement_name(key);
        if scan.retirements.contains_key(&retirement_name) {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished,
                "admit-service-namespace",
                "this native journal ID has an immutable retirement tombstone and cannot be reused",
            ));
        }
        if self.admitted_namespace_keys.contains(name) {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished,
                "admit-service-namespace",
                "this native journal ID is already admitted by the live service boundary",
            ));
        }
        if let Some(temporary) = scan.temporary.as_deref() {
            let expected_temporary = service_namespace_temporary_name(key);
            if temporary != expected_temporary {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "reconcile-service-namespace-temporary",
                    "an unrelated service namespace temporary requires reconciliation",
                ));
            }
            reconcile_service_namespace_temporary(
                &self.namespaces,
                temporary,
                name,
                self.service_state_identity.owner_uid,
                &expected_launch_authority,
            )?;
            scan = self.scan_index_locked()?;
        }
        if !scan.namespaces.contains_key(name) {
            if scan.namespaces.len() >= MAX_SERVICE_NAMESPACES {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                    "admit-service-namespace",
                    "service namespace count reached its hard bound",
                ));
            }
            create_service_namespace(
                &self.namespaces,
                name,
                key,
                self.service_state_identity.owner_uid,
                &expected_launch_authority,
            )?;
            scan = self.scan_index_locked()?;
        }
        let opened = open_service_namespace(
            &self.namespaces,
            name,
            self.service_state_identity.owner_uid,
            Some(&expected_launch_authority),
        )?;
        if scan.namespaces.get(name) != Some(&opened.identity) {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "admit-service-namespace",
                "selected service namespace changed between index scan and retained open",
            ));
        }
        self.retained_namespaces = scan.namespaces;
        self.retained_retirements = scan.retirements;
        MacosOrdinaryRunnerDurableStoreAuthority::from_admitted_namespace(
            self.service_state_root.try_clone().map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                    "clone-service-state-root",
                    error,
                )
            })?,
            self.service_state_identity,
            self.namespaces.try_clone().map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                    "clone-service-namespace-index",
                    error,
                )
            })?,
            self.namespaces_identity,
            name.to_owned(),
            opened,
            expected_launch_authority,
        )
    }

    /// Publishes one permanent, contract-only no-reuse tombstone after a
    /// caller has retained exact cleanup terminal evidence and readback.
    ///
    /// This does not authenticate a signed service or ledger readback and is
    /// therefore deliberately non-admissible for native execution. It does
    /// make reuse of the exact `native_journal_id` impossible even if the
    /// corresponding namespace is later removed outside this boundary.
    pub(crate) fn record_contract_only_retirement(
        &mut self,
        retirement: &MacosOrdinaryRunnerNamespaceRetirementReadback,
    ) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        retirement.validate(None)?;
        lock_durable_writer(&self.index_lock)?;
        let result = self.record_contract_only_retirement_locked(retirement);
        unlock_durable_writer(&self.index_lock, result)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "retirement publication keeps the exact namespace binding, temporary, no-replace, sync, and tombstone readback sequence adjacent for audit"
    )]
    fn record_contract_only_retirement_locked(
        &mut self,
        retirement: &MacosOrdinaryRunnerNamespaceRetirementReadback,
    ) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        let key = service_namespace_key(&retirement.authority);
        let namespace_name = service_namespace_name(&key);
        let final_name = service_namespace_retirement_name(&key);
        let temporary_name = service_namespace_retirement_temporary_name(&key);
        let scan = self.scan_index_locked()?;
        if scan.temporary.is_some() {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "retire-service-namespace",
                "an unresolved namespace or retirement temporary blocks retirement",
            ));
        }
        let expected = scan
            .namespace_authorities
            .get(&namespace_name)
            .ok_or_else(|| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "retire-service-namespace",
                    "retirement requires the exact retained launch namespace",
                )
            })?;
        retirement.validate(Some(expected))?;
        if scan.retirements.contains_key(&final_name) {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished,
                "retire-service-namespace",
                "the exact native journal ID already has an immutable retirement tombstone",
            ));
        }
        let opened = open_service_namespace(
            &self.namespaces,
            &namespace_name,
            self.service_state_identity.owner_uid,
            Some(expected),
        )?;
        let (binding, _) = read_service_namespace_binding(
            &opened.namespace,
            self.service_state_identity.owner_uid,
            Some(expected),
        )?;
        if binding.authority != retirement.authority || binding.namespace_key != key {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "retire-service-namespace",
                "retirement authority differs from the retained namespace binding",
            ));
        }
        drop(opened);

        let bytes = retirement.canonical_bytes()?;
        let mut temporary =
            create_durable_private_file(&self.namespaces, Path::new(&temporary_name))?;
        temporary.write_all(&bytes).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "write-service-namespace-retirement-temporary",
                error,
            )
        })?;
        temporary.sync_all().map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "sync-service-namespace-retirement-temporary",
                error,
            )
        })?;
        let temporary_identity = validate_durable_private_file(
            &temporary,
            Path::new(&temporary_name),
            Some(u64::try_from(bytes.len()).map_err(|_| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "sync-service-namespace-retirement-temporary",
                    "retirement bytes length exceeds u64",
                )
            })?),
        )?;
        if temporary_identity.owner_uid != self.service_state_identity.owner_uid {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "sync-service-namespace-retirement-temporary",
                "retirement temporary owner differs from the service-state owner",
            ));
        }
        require_named_durable_file_identity(&self.namespaces, &temporary_name, temporary_identity)?;
        drop(temporary);
        renameat_with(
            &self.namespaces,
            Path::new(&temporary_name),
            &self.namespaces,
            Path::new(&final_name),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
                "publish-service-namespace-retirement-no-replace",
                error,
            )
        })?;
        sync_durable_directory(&self.namespaces).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
                "sync-service-namespace-retirement-index",
                error,
            )
        })?;
        let (readback_bytes, readback_identity) =
            read_stable_durable_file(&self.namespaces, Path::new(&final_name)).map_err(
                |error| {
                    journal_failure(
                        MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
                        "readback-service-namespace-retirement",
                        error,
                    )
                },
            )?;
        let readback = MacosOrdinaryRunnerNamespaceRetirementReadback::decode_canonical(
            &readback_bytes,
            Some(expected),
        )?;
        if readback_identity != temporary_identity
            || readback_bytes != bytes
            || readback != *retirement
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
                "readback-service-namespace-retirement",
                "retirement tombstone identity, bytes, or authority differs after publication",
            ));
        }
        let settled = self.scan_index_locked()?;
        if settled.retirements.get(&final_name) != Some(&readback_identity) {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
                "readback-service-namespace-retirement",
                "retirement tombstone was not retained by exact index readback",
            ));
        }
        self.retained_namespaces = settled.namespaces;
        self.retained_retirements = settled.retirements;
        Ok(())
    }
}

/// Non-cloneable authority over one exact service-owned launch namespace.
///
/// There is intentionally no signed-service mint. Retained identities detect
/// replacement during this authority's lifetime; a fresh authority proves
/// exact canonical bytes and service-owned naming after restart but cannot
/// prove prior inode continuity without an independent installation anchor.
pub(crate) struct MacosOrdinaryRunnerDurableStoreAuthority {
    service_state_root: Dir,
    service_state_identity: DurableDirectoryIdentity,
    namespaces: Dir,
    namespaces_identity: DurableDirectoryIdentity,
    namespace_name: String,
    namespace: Dir,
    namespace_identity: DurableDirectoryIdentity,
    namespace_binding_identity: DurableFileIdentity,
    journal: Dir,
    journal_identity: DurableDirectoryIdentity,
    writer_lock: File,
    writer_lock_identity: DurableFileIdentity,
    expected_launch_authority: MacosOrdinaryRunnerLaunchAuthority,
    retained_generation_identities: Vec<DurableFileIdentity>,
    #[cfg(test)]
    next_failure: Option<TestDurableFailurePoint>,
}

impl MacosOrdinaryRunnerDurableStoreAuthority {
    /// Explicit test-only mint from a retained service-state descriptor.
    #[cfg(test)]
    fn mint_test_service_authority(
        service_state_root: Dir,
        expected_launch_authority: MacosOrdinaryRunnerLaunchAuthority,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        let mut service = Self::test_service_state_authority(service_state_root)?;
        service.admit_launch(expected_launch_authority)
    }

    #[cfg(test)]
    fn test_service_state_authority(
        service_state_root: Dir,
    ) -> Result<MacosOrdinaryRunnerServiceStateAuthority, MacosOrdinaryRunnerDurableStoreError>
    {
        MacosOrdinaryRunnerServiceStateAuthority::from_retained_service_state_root(
            service_state_root,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor retains every authenticated descriptor/identity link explicitly"
    )]
    fn from_admitted_namespace(
        service_state_root: Dir,
        service_state_identity: DurableDirectoryIdentity,
        namespaces: Dir,
        namespaces_identity: DurableDirectoryIdentity,
        namespace_name: String,
        opened: OpenedServiceNamespace,
        expected_launch_authority: MacosOrdinaryRunnerLaunchAuthority,
    ) -> Result<Self, MacosOrdinaryRunnerDurableStoreError> {
        let mut authority = Self {
            service_state_root,
            service_state_identity,
            namespaces,
            namespaces_identity,
            namespace_name,
            namespace: opened.namespace,
            namespace_identity: opened.identity.namespace,
            namespace_binding_identity: opened.identity.binding,
            journal: opened.journal,
            journal_identity: opened.identity.journal,
            writer_lock: opened.writer_lock,
            writer_lock_identity: opened.identity.writer_lock,
            expected_launch_authority,
            retained_generation_identities: Vec::new(),
            #[cfg(test)]
            next_failure: None,
        };
        authority.reopen_and_reconcile()?;
        Ok(authority)
    }

    fn validate_retained(&self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        self.expected_launch_authority
            .validate_retained()
            .map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "revalidate-external-launch-authority",
                    error,
                )
            })?;
        let service = validate_durable_private_directory(
            &self.service_state_root,
            "retained service-state root",
        )?;
        let namespaces = validate_durable_private_directory(
            &self.namespaces,
            "retained service namespace index",
        )?;
        let namespace = validate_durable_private_directory(
            &self.namespace,
            "retained per-launch service namespace",
        )?;
        let journal = validate_durable_private_directory(
            &self.journal,
            "retained ordinary-runner journal root",
        )?;
        if service != self.service_state_identity
            || namespaces != self.namespaces_identity
            || namespace != self.namespace_identity
            || journal != self.journal_identity
            || service.owner_uid != namespaces.owner_uid
            || service.owner_uid != namespace.owner_uid
            || service.owner_uid != journal.owner_uid
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-retained-roots",
                "retained service-state, namespace index, per-launch namespace, or journal identity drifted",
            ));
        }
        require_named_durable_directory_identity(
            &self.service_state_root,
            SERVICE_NAMESPACES_DIRECTORY,
            self.namespaces_identity,
        )?;
        require_named_durable_directory_identity(
            &self.namespaces,
            &self.namespace_name,
            self.namespace_identity,
        )?;
        let (binding, observed_binding_identity) = read_service_namespace_binding(
            &self.namespace,
            self.service_state_identity.owner_uid,
            Some(&self.expected_launch_authority),
        )?;
        if observed_binding_identity != self.namespace_binding_identity
            || binding.namespace_key != service_namespace_key(&self.expected_launch_authority)
            || self.namespace_name != service_namespace_name(&binding.namespace_key)
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-retained-namespace-binding",
                "retained namespace binding identity or exact launch authority drifted",
            ));
        }
        require_named_durable_directory_identity(
            &self.namespace,
            DURABLE_JOURNAL_DIRECTORY,
            self.journal_identity,
        )?;
        let writer_lock = validate_durable_private_file(
            &self.writer_lock,
            Path::new(DURABLE_WRITER_LOCK),
            Some(0),
        )?;
        if writer_lock != self.writer_lock_identity
            || writer_lock.owner_uid != self.service_state_identity.owner_uid
        {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-retained-writer-lock",
                "retained writer-lock identity drifted",
            ));
        }
        require_named_durable_file_identity(
            &self.journal,
            DURABLE_WRITER_LOCK,
            self.writer_lock_identity,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the bounded scan keeps name, identity, chain, and external-authority checks linear for audit"
    )]
    fn scan_locked(&self) -> Result<DurableJournalScan, MacosOrdinaryRunnerDurableStoreError> {
        self.validate_retained()?;
        let mut entries_seen = 0_usize;
        let mut records = Vec::new();
        let mut temporary = None;
        let entries = self.journal.entries().map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-fixed-journal",
                error,
            )
        })?;
        for entry in entries {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_DURABLE_JOURNAL_ENTRIES {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "scan-fixed-journal",
                    "journal entry count exceeds its hard bound",
                ));
            }
            let entry = entry.map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "scan-fixed-journal",
                    error,
                )
            })?;
            let name = entry.file_name().into_string().map_err(|_| {
                durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "scan-fixed-journal",
                    "journal contains a non-UTF-8 entry",
                )
            })?;
            if name == DURABLE_WRITER_LOCK {
                continue;
            }
            if name.ends_with(TEMPORARY_SUFFIX) {
                let generation = parse_temporary_generation_name(&name)?;
                if temporary.replace((name, generation)).is_some() {
                    return Err(durable_failure(
                        MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                        "scan-fixed-journal",
                        "multiple unresolved generation temporaries are present",
                    ));
                }
                continue;
            }
            let generation = parse_generation_name(&name)?;
            records.push((generation, name));
        }
        records.sort_by_key(|(generation, _)| *generation);
        if records.len() > MAX_JOURNAL_GENERATIONS {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-fixed-journal",
                "published generation count exceeds its hard bound",
            ));
        }
        let mut generations = Vec::with_capacity(records.len());
        let mut generation_identities = Vec::with_capacity(records.len());
        for (index, (named_generation, name)) in records.into_iter().enumerate() {
            let expected_generation = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| {
                    durable_failure(
                        MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                        "scan-fixed-journal",
                        "generation index overflow",
                    )
                })?;
            if named_generation != expected_generation {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "scan-fixed-journal",
                    "published generations are duplicated, missing, or noncontiguous",
                ));
            }
            let (bytes, identity) = read_stable_durable_file(&self.journal, Path::new(&name))?;
            if identity.owner_uid != self.service_state_identity.owner_uid {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "read-published-generation",
                    "published generation owner differs from the service-state owner",
                ));
            }
            if name != generation_name(expected_generation) {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "bind-generation-name",
                    "published generation name is noncanonical",
                ));
            }
            let record = MacosOrdinaryRunnerJournalRecord::decode_canonical(
                &bytes,
                &self.expected_launch_authority,
                generations.last(),
            )
            .map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "decode-published-generation",
                    error,
                )
            })?;
            if record.generation != expected_generation {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "bind-generation-name",
                    "record generation differs from its canonical file name",
                ));
            }
            generations.push(record);
            generation_identities.push(identity);
        }
        if !generations.is_empty() {
            validate_history(&self.expected_launch_authority, &generations).map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "validate-published-prefix",
                    error,
                )
            })?;
        }
        for (retained, observed) in self
            .retained_generation_identities
            .iter()
            .zip(generation_identities.iter())
        {
            if retained != observed {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "validate-retained-generation",
                    "a retained published generation was replaced",
                ));
            }
        }
        if generation_identities.len() < self.retained_generation_identities.len() {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "validate-retained-generation",
                "a retained published generation disappeared",
            ));
        }
        Ok(DurableJournalScan {
            generations,
            generation_identities,
            temporary,
        })
    }

    fn reopen_and_reconcile(&mut self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        lock_durable_writer(&self.writer_lock)?;
        let result = self.reopen_and_reconcile_locked();
        unlock_durable_writer(&self.writer_lock, result)
    }

    fn reopen_and_reconcile_locked(&mut self) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
        let scan = self.scan_locked()?;
        if let Some((name, generation)) = &scan.temporary {
            let expected_generation = u32::try_from(scan.generations.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| {
                    durable_failure(
                        MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                        "reconcile-generation-temporary",
                        "next generation overflow",
                    )
                })?;
            if *generation != expected_generation || expected_generation > 4 {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "reconcile-generation-temporary",
                    "temporary generation is duplicated, stale, or outside the state machine",
                ));
            }
            let (bytes, identity) = read_stable_durable_file(&self.journal, Path::new(name))?;
            if identity.owner_uid != self.service_state_identity.owner_uid {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "reconcile-generation-temporary",
                    "temporary generation owner differs from the service-state owner",
                ));
            }
            let record = MacosOrdinaryRunnerJournalRecord::decode_canonical(
                &bytes,
                &self.expected_launch_authority,
                scan.generations.last(),
            )
            .map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "reconcile-generation-temporary",
                    error,
                )
            })?;
            if record.generation != expected_generation
                || bytes
                    != record.canonical_bytes().map_err(|error| {
                        journal_failure(
                            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                            "reconcile-generation-temporary",
                            error,
                        )
                    })?
            {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "reconcile-generation-temporary",
                    "temporary record differs from the exact canonical successor",
                ));
            }
            self.journal.remove_file(name).map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "remove-generation-temporary",
                    error,
                )
            })?;
            sync_durable_directory(&self.journal).map_err(|error| {
                journal_failure(
                    MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                    "sync-generation-temporary-removal",
                    error,
                )
            })?;
        }
        let settled = self.scan_locked()?;
        if settled.temporary.is_some() {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "reconcile-generation-temporary",
                "temporary generation remained after synchronized reconciliation",
            ));
        }
        sync_durable_directory(&self.journal).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "sync-fixed-journal-root",
                error,
            )
        })?;
        self.retained_generation_identities = settled.generation_identities;
        Ok(())
    }

    fn durable_history(
        &mut self,
    ) -> Result<Vec<MacosOrdinaryRunnerJournalRecord>, MacosOrdinaryRunnerDurableStoreError> {
        self.reopen_and_reconcile()?;
        lock_durable_writer(&self.writer_lock)?;
        let result = self.scan_locked().map(|scan| scan.generations);
        unlock_durable_writer(&self.writer_lock, result)
    }

    fn deterministic_restart_action(
        &mut self,
    ) -> Result<MacosOrdinaryRunnerRecoveryAction, MacosOrdinaryRunnerDurableStoreError> {
        let generations = self.durable_history()?;
        recovery_action(&self.expected_launch_authority, &generations).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "select-restart-action",
                error,
            )
        })
    }

    fn append_generation(
        &mut self,
        record: &MacosOrdinaryRunnerJournalRecord,
    ) -> Result<MacosOrdinaryRunnerDurableCommitReceipt, MacosOrdinaryRunnerDurableStoreError> {
        lock_durable_writer(&self.writer_lock)?;
        let result = persist_generation_locked(self, record);
        unlock_durable_writer(&self.writer_lock, result)
    }

    #[cfg(test)]
    fn inject_next_failure(&mut self, failure: TestDurableFailurePoint) {
        self.next_failure = Some(failure);
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the append path keeps each crash cut and persistence-certainty transition in exact order"
)]
fn persist_generation_locked(
    authority: &mut MacosOrdinaryRunnerDurableStoreAuthority,
    record: &MacosOrdinaryRunnerJournalRecord,
) -> Result<MacosOrdinaryRunnerDurableCommitReceipt, MacosOrdinaryRunnerDurableStoreError> {
    authority.validate_retained()?;
    let scan = authority.scan_locked()?;
    if scan.temporary.is_some() {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "append-generation",
            "an unresolved temporary must be reconciled before append",
        ));
    }
    authority
        .retained_generation_identities
        .clone_from(&scan.generation_identities);
    let next_generation = u32::try_from(scan.generations.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "append-generation",
                "next generation overflow",
            )
        })?;
    if usize::try_from(record.generation).is_ok_and(|generation| {
        generation <= scan.generations.len()
            && scan
                .generations
                .get(generation.saturating_sub(1))
                .is_some_and(|existing| existing == record)
    }) {
        sync_durable_directory(&authority.journal).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
                "sync-exact-retry",
                error,
            )
        })?;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished,
            "append-generation",
            "the exact immutable generation is already published",
        ));
    }
    if record.generation != next_generation || next_generation > 4 {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Substitution,
            "append-generation",
            "candidate generation is duplicate, missing, or outside the state machine",
        ));
    }
    record
        .validate(
            &authority.expected_launch_authority,
            scan.generations.last(),
        )
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::Substitution,
                "validate-generation-successor",
                error,
            )
        })?;
    let bytes = record.canonical_bytes().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "encode-generation",
            error,
        )
    })?;
    let final_name = generation_name(next_generation);
    let temporary_name = temporary_generation_name(next_generation);
    let mut temporary =
        create_durable_private_file(&authority.journal, Path::new(&temporary_name))?;
    temporary.write_all(&bytes).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "write-generation-temporary",
            error,
        )
    })?;

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::BeforeTemporarySync) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-generation-temporary",
            "injected crash before temporary synchronization",
        ));
    }

    temporary.sync_all().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-generation-temporary",
            error,
        )
    })?;
    let temporary_identity = validate_durable_private_file(
        &temporary,
        Path::new(&temporary_name),
        Some(u64::try_from(bytes.len()).map_err(|_| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "sync-generation-temporary",
                "canonical generation length exceeds u64",
            )
        })?),
    )?;
    if temporary_identity.owner_uid != authority.service_state_identity.owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-generation-temporary",
            "temporary generation owner differs from the service-state owner",
        ));
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::AfterTemporarySync) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "publish-generation",
            "injected crash after temporary synchronization",
        ));
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::BeforeRename) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "publish-generation-no-replace",
            "injected crash before no-replace rename",
        ));
    }

    renameat_with(
        &authority.journal,
        Path::new(&temporary_name),
        &authority.journal,
        Path::new(&final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "publish-generation-no-replace",
            error,
        )
    })?;

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::AfterRename) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "publish-generation-no-replace",
            "injected crash after no-replace rename",
        ));
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::BeforeDirectorySync) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "sync-fixed-journal-root",
            "injected crash before directory synchronization",
        ));
    }

    sync_durable_directory(&authority.journal).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "sync-fixed-journal-root",
            error,
        )
    })?;

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::AfterDirectorySync) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "sync-fixed-journal-root",
            "injected lost response after directory synchronization",
        ));
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::BeforeReadback) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "readback-generation",
            "injected refusal before canonical readback",
        ));
    }

    drop(temporary);
    let (readback_bytes, generation_identity) =
        read_stable_durable_file(&authority.journal, Path::new(&final_name)).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
                "readback-generation",
                error,
            )
        })?;
    let readback = MacosOrdinaryRunnerJournalRecord::decode_canonical(
        &readback_bytes,
        &authority.expected_launch_authority,
        scan.generations.last(),
    )
    .map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "readback-generation",
            error,
        )
    })?;
    if generation_identity != temporary_identity
        || readback_bytes != bytes
        || readback != *record
        || readback.generation != next_generation
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "readback-generation",
            "published identity, bytes, or canonical record differ from the synchronized temporary",
        ));
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestDurableFailurePoint::AfterReadback) {
        authority.next_failure = None;
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "readback-generation",
            "injected lost response after canonical readback",
        ));
    }

    authority
        .retained_generation_identities
        .push(generation_identity);
    Ok(MacosOrdinaryRunnerDurableCommitReceipt {
        generation: next_generation,
        record_digest: readback.record_digest.clone(),
        canonical_bytes_digest: Digest::sha256(&readback_bytes),
        journal_identity: authority.journal_identity,
        generation_identity,
    })
}

fn generation_name(generation: u32) -> String {
    format!("{GENERATION_PREFIX}{generation:08}{GENERATION_SUFFIX}")
}

fn temporary_generation_name(generation: u32) -> String {
    format!(".{}{TEMPORARY_SUFFIX}", generation_name(generation))
}

fn parse_generation_name(name: &str) -> Result<u32, MacosOrdinaryRunnerDurableStoreError> {
    let generation = name
        .strip_prefix(GENERATION_PREFIX)
        .and_then(|name| name.strip_suffix(GENERATION_SUFFIX))
        .ok_or_else(|| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "classify-generation-name",
                format!("unknown durable-journal entry {name:?}"),
            )
        })?;
    let parsed = generation.parse::<u32>().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-generation-name",
            error,
        )
    })?;
    if parsed == 0 || parsed > 4 || name != generation_name(parsed) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-generation-name",
            "generation name is zero, out of range, or noncanonical",
        ));
    }
    Ok(parsed)
}

fn parse_temporary_generation_name(
    name: &str,
) -> Result<u32, MacosOrdinaryRunnerDurableStoreError> {
    let generation_name = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(TEMPORARY_SUFFIX))
        .ok_or_else(|| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "classify-generation-temporary",
                "temporary generation name is malformed",
            )
        })?;
    let generation = parse_generation_name(generation_name)?;
    if name != temporary_generation_name(generation) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-generation-temporary",
            "temporary generation name is noncanonical",
        ));
    }
    Ok(generation)
}

fn parse_service_namespace_name(
    name: &str,
) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
    let key = name.strip_prefix(SERVICE_NAMESPACE_PREFIX).ok_or_else(|| {
        durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-service-namespace",
            "service namespace name lacks its canonical prefix",
        )
    })?;
    let key = Digest::parse(key.to_owned()).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-service-namespace",
            error,
        )
    })?;
    if name != service_namespace_name(&key) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-service-namespace",
            "service namespace name is noncanonical",
        ));
    }
    Ok(key)
}

fn parse_service_namespace_temporary_name(
    name: &str,
) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
    let final_name = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(SERVICE_NAMESPACE_TEMPORARY_SUFFIX))
        .ok_or_else(|| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "classify-service-namespace-temporary",
                "service namespace temporary name is malformed",
            )
        })?;
    let key = parse_service_namespace_name(final_name)?;
    if name != service_namespace_temporary_name(&key) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-service-namespace-temporary",
            "service namespace temporary name is noncanonical",
        ));
    }
    Ok(key)
}

fn parse_service_namespace_retirement_name(
    name: &str,
) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
    let key = name
        .strip_prefix(SERVICE_NAMESPACE_RETIREMENT_PREFIX)
        .and_then(|name| name.strip_suffix(SERVICE_NAMESPACE_RETIREMENT_SUFFIX))
        .ok_or_else(|| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "classify-service-namespace-retirement",
                "namespace retirement name is malformed",
            )
        })?;
    let key = Digest::parse(key.to_owned()).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-service-namespace-retirement",
            error,
        )
    })?;
    if name != service_namespace_retirement_name(&key) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-service-namespace-retirement",
            "namespace retirement name is noncanonical",
        ));
    }
    Ok(key)
}

fn parse_service_namespace_retirement_temporary_name(
    name: &str,
) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
    let final_name = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(SERVICE_NAMESPACE_RETIREMENT_TEMPORARY_SUFFIX))
        .ok_or_else(|| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "classify-service-namespace-retirement-temporary",
                "namespace retirement temporary name is malformed",
            )
        })?;
    let key = parse_service_namespace_retirement_name(final_name)?;
    if name != service_namespace_retirement_temporary_name(&key) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "classify-service-namespace-retirement-temporary",
            "namespace retirement temporary name is noncanonical",
        ));
    }
    Ok(key)
}

fn read_service_namespace_binding(
    namespace: &Dir,
    expected_owner_uid: u32,
    expected: Option<&MacosOrdinaryRunnerLaunchAuthority>,
) -> Result<
    (
        MacosOrdinaryRunnerServiceNamespaceBinding,
        DurableFileIdentity,
    ),
    MacosOrdinaryRunnerDurableStoreError,
> {
    let (bytes, identity) =
        read_stable_durable_file(namespace, Path::new(SERVICE_NAMESPACE_BINDING))?;
    if identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "read-service-namespace-binding",
            "namespace binding owner differs from the service-state owner",
        ));
    }
    let binding = MacosOrdinaryRunnerServiceNamespaceBinding::decode_canonical(&bytes, expected)?;
    Ok((binding, identity))
}

fn scan_exact_namespace_entries(
    namespace: &Dir,
) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
    let entries = namespace.entries().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "scan-service-namespace",
            error,
        )
    })?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace",
                error,
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace",
                "service namespace contains a non-UTF-8 entry",
            )
        })?;
        if !names.insert(name) || names.len() > 2 {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace",
                "service namespace entries are duplicated or exceed the exact bound",
            ));
        }
    }
    let expected = BTreeSet::from([
        SERVICE_NAMESPACE_BINDING.to_owned(),
        DURABLE_JOURNAL_DIRECTORY.to_owned(),
    ]);
    if names != expected {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "scan-service-namespace",
            "service namespace does not contain exactly its binding and journal directory",
        ));
    }
    Ok(())
}

fn validate_bounded_journal_object_acls(
    journal: &Dir,
    expected_owner_uid: u32,
) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
    let entries = journal.entries().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "scan-service-namespace-journal-objects",
            error,
        )
    })?;
    let mut entries_seen = 0_usize;
    for entry in entries {
        entries_seen = entries_seen.saturating_add(1);
        if entries_seen > MAX_DURABLE_JOURNAL_ENTRIES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace-journal-objects",
                "journal object count exceeds its hard bound",
            ));
        }
        let entry = entry.map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace-journal-objects",
                error,
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace-journal-objects",
                "journal contains a non-UTF-8 object",
            )
        })?;
        if name == DURABLE_WRITER_LOCK {
            continue;
        }
        if name.ends_with(TEMPORARY_SUFFIX) {
            parse_temporary_generation_name(&name)?;
        } else {
            parse_generation_name(&name)?;
        }
        let (_, identity) = read_stable_durable_file(journal, Path::new(&name))?;
        if identity.owner_uid != expected_owner_uid {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "scan-service-namespace-journal-objects",
                "journal object owner differs from the service-state owner",
            ));
        }
    }
    Ok(())
}

fn open_service_namespace(
    namespaces: &Dir,
    name: &str,
    expected_owner_uid: u32,
    expected: Option<&MacosOrdinaryRunnerLaunchAuthority>,
) -> Result<OpenedServiceNamespace, MacosOrdinaryRunnerDurableStoreError> {
    let namespace = namespaces.open_dir_nofollow(name).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "open-service-namespace",
            error,
        )
    })?;
    let namespace_identity =
        validate_durable_private_directory(&namespace, "per-launch service namespace")?;
    if namespace_identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "open-service-namespace",
            "per-launch namespace owner differs from the service-state owner",
        ));
    }
    require_named_durable_directory_identity(namespaces, name, namespace_identity)?;
    scan_exact_namespace_entries(&namespace)?;
    let (binding, binding_identity) =
        read_service_namespace_binding(&namespace, expected_owner_uid, expected)?;
    let expected_final = service_namespace_name(&binding.namespace_key);
    let expected_temporary = service_namespace_temporary_name(&binding.namespace_key);
    if name != expected_final && name != expected_temporary {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Substitution,
            "bind-service-namespace-name",
            "namespace directory name differs from its exact binding key",
        ));
    }
    let journal = namespace
        .open_dir_nofollow(DURABLE_JOURNAL_DIRECTORY)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "open-fixed-journal-root",
                error,
            )
        })?;
    let journal_identity =
        validate_durable_private_directory(&journal, "ordinary-runner journal root")?;
    require_named_durable_directory_identity(
        &namespace,
        DURABLE_JOURNAL_DIRECTORY,
        journal_identity,
    )?;
    if journal_identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "bind-fixed-journal-root",
            "journal owner differs from the service-state owner",
        ));
    }
    let writer_lock = open_durable_writer_lock(&journal)?;
    let writer_lock_identity =
        validate_durable_private_file(&writer_lock, Path::new(DURABLE_WRITER_LOCK), Some(0))?;
    if writer_lock_identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "bind-writer-lock",
            "writer lock owner differs from the service-state owner",
        ));
    }
    require_named_durable_file_identity(&journal, DURABLE_WRITER_LOCK, writer_lock_identity)?;
    validate_bounded_journal_object_acls(&journal, expected_owner_uid)?;
    Ok(OpenedServiceNamespace {
        namespace,
        identity: DurableServiceNamespaceIdentity {
            namespace: namespace_identity,
            binding: binding_identity,
            journal: journal_identity,
            writer_lock: writer_lock_identity,
        },
        journal,
        writer_lock,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "namespace preparation keeps every descriptor-relative durability and identity cut in auditable order"
)]
fn create_service_namespace(
    namespaces: &Dir,
    final_name: &str,
    key: &Digest,
    expected_owner_uid: u32,
    authority: &MacosOrdinaryRunnerLaunchAuthority,
) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
    if final_name != service_namespace_name(key) || *key != service_namespace_key(authority) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Substitution,
            "create-service-namespace",
            "requested namespace name, key, and launch authority differ",
        ));
    }
    let temporary_name = service_namespace_temporary_name(key);
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    namespaces
        .create_dir_with(&temporary_name, &builder)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "create-service-namespace-temporary",
                error,
            )
        })?;
    let temporary = namespaces
        .open_dir_nofollow(&temporary_name)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "open-service-namespace-temporary",
                error,
            )
        })?;
    temporary
        .set_permissions(Path::new("."), Permissions::from_mode(0o700))
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "set-service-namespace-temporary-mode",
                error,
            )
        })?;
    let temporary_identity =
        validate_durable_private_directory(&temporary, "new service namespace temporary")?;
    if temporary_identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "create-service-namespace-temporary",
            "new namespace owner differs from the service-state owner",
        ));
    }
    require_named_durable_directory_identity(namespaces, &temporary_name, temporary_identity)?;

    let binding = MacosOrdinaryRunnerServiceNamespaceBinding::for_authority(authority.clone())?;
    let binding_bytes = binding.canonical_bytes()?;
    let mut binding_file =
        create_durable_private_file(&temporary, Path::new(SERVICE_NAMESPACE_BINDING))?;
    binding_file.write_all(&binding_bytes).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "write-service-namespace-binding",
            error,
        )
    })?;
    binding_file.sync_all().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-service-namespace-binding",
            error,
        )
    })?;
    let binding_identity = validate_durable_private_file(
        &binding_file,
        Path::new(SERVICE_NAMESPACE_BINDING),
        Some(u64::try_from(binding_bytes.len()).map_err(|_| {
            durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "sync-service-namespace-binding",
                "namespace binding length exceeds u64",
            )
        })?),
    )?;
    if binding_identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-service-namespace-binding",
            "namespace binding owner differs from the service-state owner",
        ));
    }
    require_named_durable_file_identity(&temporary, SERVICE_NAMESPACE_BINDING, binding_identity)?;

    let mut journal_builder = DirBuilder::new();
    journal_builder.mode(0o700);
    temporary
        .create_dir_with(DURABLE_JOURNAL_DIRECTORY, &journal_builder)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "create-fixed-journal-root",
                error,
            )
        })?;
    let journal = temporary
        .open_dir_nofollow(DURABLE_JOURNAL_DIRECTORY)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "open-new-fixed-journal-root",
                error,
            )
        })?;
    journal
        .set_permissions(Path::new("."), Permissions::from_mode(0o700))
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "set-fixed-journal-root-mode",
                error,
            )
        })?;
    let journal_identity =
        validate_durable_private_directory(&journal, "new ordinary-runner journal root")?;
    if journal_identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "create-fixed-journal-root",
            "new journal owner differs from the service-state owner",
        ));
    }
    let writer_lock = create_durable_private_file(&journal, Path::new(DURABLE_WRITER_LOCK))?;
    writer_lock.sync_all().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-new-writer-lock",
            error,
        )
    })?;
    let writer_lock_identity =
        validate_durable_private_file(&writer_lock, Path::new(DURABLE_WRITER_LOCK), Some(0))?;
    if writer_lock_identity.owner_uid != expected_owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "create-writer-lock",
            "new writer lock owner differs from the service-state owner",
        ));
    }
    sync_durable_directory(&journal).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-new-fixed-journal-root",
            error,
        )
    })?;
    sync_durable_directory(&temporary).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-service-namespace-temporary",
            error,
        )
    })?;
    drop(binding_file);
    drop(writer_lock);
    drop(journal);
    let prepared = open_service_namespace(
        namespaces,
        &temporary_name,
        expected_owner_uid,
        Some(authority),
    )?;
    if prepared.identity.namespace != temporary_identity {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "validate-service-namespace-temporary",
            "prepared namespace temporary identity changed before publication",
        ));
    }
    drop(prepared);
    renameat_with(
        namespaces,
        Path::new(&temporary_name),
        namespaces,
        Path::new(final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "publish-service-namespace-no-replace",
            error,
        )
    })?;
    sync_durable_directory(namespaces).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "sync-service-namespace-index",
            error,
        )
    })?;
    let published =
        open_service_namespace(namespaces, final_name, expected_owner_uid, Some(authority))?;
    if published.identity.namespace != temporary_identity
        || published.identity.binding != binding_identity
        || published.identity.journal != journal_identity
        || published.identity.writer_lock != writer_lock_identity
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "readback-service-namespace",
            "published namespace identities differ from the synchronized temporary",
        ));
    }
    Ok(())
}

fn reconcile_service_namespace_temporary(
    namespaces: &Dir,
    temporary_name: &str,
    final_name: &str,
    expected_owner_uid: u32,
    authority: &MacosOrdinaryRunnerLaunchAuthority,
) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
    let key = parse_service_namespace_temporary_name(temporary_name)?;
    if final_name != service_namespace_name(&key) || key != service_namespace_key(authority) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Substitution,
            "reconcile-service-namespace-temporary",
            "namespace temporary differs from the exact requested launch authority",
        ));
    }
    match namespaces.symlink_metadata(final_name) {
        Ok(_) => {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "reconcile-service-namespace-temporary",
                "both final and temporary namespace names are present",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "inspect-final-service-namespace",
                error,
            ));
        }
    }
    let prepared = open_service_namespace(
        namespaces,
        temporary_name,
        expected_owner_uid,
        Some(authority),
    )?;
    sync_durable_directory(&prepared.journal).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-reconciled-service-namespace-journal",
            error,
        )
    })?;
    sync_durable_directory(&prepared.namespace).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-reconciled-service-namespace",
            error,
        )
    })?;
    let identity = prepared.identity;
    drop(prepared);
    renameat_with(
        namespaces,
        Path::new(temporary_name),
        namespaces,
        Path::new(final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "publish-reconciled-service-namespace-no-replace",
            error,
        )
    })?;
    sync_durable_directory(namespaces).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "sync-reconciled-service-namespace-index",
            error,
        )
    })?;
    let published =
        open_service_namespace(namespaces, final_name, expected_owner_uid, Some(authority))?;
    if published.identity != identity {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "readback-reconciled-service-namespace",
            "reconciled namespace identity differs after no-replace publication",
        ));
    }
    Ok(())
}

fn validate_durable_private_directory(
    directory: &Dir,
    label: &str,
) -> Result<DurableDirectoryIdentity, MacosOrdinaryRunnerDurableStoreError> {
    require_no_macos_extended_acl(directory).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "inspect-private-directory-acl",
            format!("{label}: {error}"),
        )
    })?;
    let metadata = directory.dir_metadata().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "inspect-private-directory",
            format!("{label}: {error}"),
        )
    })?;
    let identity = DurableDirectoryIdentity {
        device_id: PortableMetadataExt::dev(&metadata),
        inode: PortableMetadataExt::ino(&metadata),
        owner_uid: OsMetadataExt::uid(&metadata),
        mode: OsMetadataExt::mode(&metadata) & 0o777,
    };
    if !metadata.is_dir()
        || identity.device_id == 0
        || identity.inode == 0
        || identity.mode != 0o700
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "inspect-private-directory",
            format!("{label} is not a retained mode-0700 directory"),
        ));
    }
    Ok(identity)
}

fn require_named_durable_directory_identity(
    parent: &Dir,
    name: &str,
    expected: DurableDirectoryIdentity,
) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
    let directory = parent.open_dir_nofollow(name).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "reopen-fixed-journal-root",
            error,
        )
    })?;
    if validate_durable_private_directory(&directory, name)? != expected {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "reopen-fixed-journal-root",
            "named fixed journal root was replaced",
        ));
    }
    Ok(())
}

fn open_durable_writer_lock(journal: &Dir) -> Result<File, MacosOrdinaryRunnerDurableStoreError> {
    open_named_durable_writer_lock(journal, DURABLE_WRITER_LOCK, "open-writer-lock")
}

fn open_named_durable_writer_lock(
    directory: &Dir,
    name: &str,
    operation: &'static str,
) -> Result<File, MacosOrdinaryRunnerDurableStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    directory.open_with(name, &options).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            operation,
            error,
        )
    })
}

fn create_durable_private_file(
    journal: &Dir,
    name: &Path,
) -> Result<File, MacosOrdinaryRunnerDurableStoreError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let file = journal.open_with(name, &options).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "create-generation-temporary",
            error,
        )
    })?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "set-generation-temporary-mode",
                error,
            )
        })?;
    Ok(file)
}

fn validate_durable_private_file(
    file: &File,
    name: &Path,
    exact_length: Option<u64>,
) -> Result<DurableFileIdentity, MacosOrdinaryRunnerDurableStoreError> {
    require_no_macos_extended_acl(file).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "inspect-private-file-acl",
            format!("{}: {error}", name.display()),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "inspect-private-file",
            format!("{}: {error}", name.display()),
        )
    })?;
    let identity = durable_file_identity(&metadata);
    if !metadata.is_file()
        || identity.device_id == 0
        || identity.inode == 0
        || identity.link_count != 1
        || identity.mode != 0o600
        || exact_length.is_some_and(|length| identity.byte_length != length)
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "inspect-private-file",
            format!(
                "{} is not a singly linked mode-0600 regular file of the exact length",
                name.display()
            ),
        ));
    }
    Ok(identity)
}

fn require_named_durable_file_identity(
    directory: &Dir,
    name: &str,
    expected: DurableFileIdentity,
) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "reopen-private-file",
            error,
        )
    })?;
    if validate_durable_private_file(&file, Path::new(name), Some(expected.byte_length))?
        != expected
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "reopen-private-file",
            format!("named file {name:?} was replaced"),
        ));
    }
    Ok(())
}

fn read_stable_durable_file(
    directory: &Dir,
    name: &Path,
) -> Result<(Vec<u8>, DurableFileIdentity), MacosOrdinaryRunnerDurableStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = directory.open_with(name, &options).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "open-generation-readback",
            error,
        )
    })?;
    let before = validate_durable_private_file(&file, name, None)?;
    let maximum = u64::try_from(MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut first = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum)
        .read_to_end(&mut first)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "read-generation",
                error,
            )
        })?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "rewind-generation",
            error,
        )
    })?;
    let mut second = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum)
        .read_to_end(&mut second)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "reread-generation",
                error,
            )
        })?;
    let after = validate_durable_private_file(&file, name, None)?;
    if first != second
        || before != after
        || u64::try_from(first.len()) != Ok(before.byte_length)
        || first.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "read-generation",
            "generation changed during stable read or exceeds its byte bound",
        ));
    }
    let name = name.to_str().ok_or_else(|| {
        durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "read-generation",
            "generation name is not UTF-8",
        )
    })?;
    require_named_durable_file_identity(directory, name, before)?;
    Ok((first, before))
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::too_many_lines,
    reason = "the one-time binding transaction keeps temp refusal, existing exact readback, create-new sync, no-replace publication, root sync, and descriptor retention adjacent for audit"
)]
fn persist_or_read_signed_service_trust_binding(
    service_state_root: &Dir,
    service_state_identity: DurableDirectoryIdentity,
    expected: &MacosOrdinaryRunnerPathLocalSignedImageBinding,
) -> Result<
    (
        MacosOrdinaryRunnerPathLocalSignedImageBinding,
        File,
        DurableFileIdentity,
    ),
    MacosOrdinaryRunnerDurableStoreError,
> {
    expected.validate(Some(&expected.service_image), Some(service_state_identity))?;
    match service_state_root.symlink_metadata(SIGNED_SERVICE_TRUST_BINDING_TEMPORARY) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "inspect-signed-service-trust-binding-temporary",
                error,
            ));
        }
        Ok(_) => {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "inspect-signed-service-trust-binding-temporary",
                "an unresolved signed-service trust-binding temporary requires reconciliation",
            ));
        }
    }
    let expected_bytes = expected.canonical_bytes()?;
    match service_state_root.symlink_metadata(SIGNED_SERVICE_TRUST_BINDING) {
        Ok(_) => {
            let (bytes, identity) = read_stable_durable_file(
                service_state_root,
                Path::new(SIGNED_SERVICE_TRUST_BINDING),
            )?;
            let binding = MacosOrdinaryRunnerPathLocalSignedImageBinding::decode_canonical(
                &bytes,
                Some(&expected.service_image),
                Some(service_state_identity),
            )?;
            if identity.owner_uid != service_state_identity.owner_uid
                || bytes != expected_bytes
                || binding != *expected
            {
                return Err(durable_failure(
                    MacosOrdinaryRunnerDurableFailureClass::Substitution,
                    "authenticate-signed-service-trust-binding-restart",
                    "restart binding differs from the current signed image or retained store root",
                ));
            }
            let file = open_exact_signed_service_binding(service_state_root, identity)?;
            return Ok((binding, file, identity));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "inspect-signed-service-trust-binding",
                error,
            ));
        }
    }
    let mut temporary = create_durable_private_file(
        service_state_root,
        Path::new(SIGNED_SERVICE_TRUST_BINDING_TEMPORARY),
    )?;
    temporary.write_all(&expected_bytes).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "write-signed-service-trust-binding-temporary",
            error,
        )
    })?;
    temporary.sync_all().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "sync-signed-service-trust-binding-temporary",
            error,
        )
    })?;
    let expected_length = u64::try_from(expected_bytes.len()).map_err(|_| {
        durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "validate-signed-service-trust-binding-temporary",
            "signed-service trust-binding length exceeds u64",
        )
    })?;
    let temporary_identity = validate_durable_private_file(
        &temporary,
        Path::new(SIGNED_SERVICE_TRUST_BINDING_TEMPORARY),
        Some(expected_length),
    )?;
    if temporary_identity.owner_uid != service_state_identity.owner_uid {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "validate-signed-service-trust-binding-temporary",
            "signed-service trust-binding owner differs from the service-state owner",
        ));
    }
    require_named_durable_file_identity(
        service_state_root,
        SIGNED_SERVICE_TRUST_BINDING_TEMPORARY,
        temporary_identity,
    )?;
    drop(temporary);
    renameat_with(
        service_state_root,
        Path::new(SIGNED_SERVICE_TRUST_BINDING_TEMPORARY),
        service_state_root,
        Path::new(SIGNED_SERVICE_TRUST_BINDING),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "publish-signed-service-trust-binding",
            error,
        )
    })?;
    sync_durable_directory(service_state_root).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "sync-signed-service-trust-binding",
            error,
        )
    })?;
    let (readback_bytes, readback_identity) =
        read_stable_durable_file(service_state_root, Path::new(SIGNED_SERVICE_TRUST_BINDING))?;
    let readback = MacosOrdinaryRunnerPathLocalSignedImageBinding::decode_canonical(
        &readback_bytes,
        Some(&expected.service_image),
        Some(service_state_identity),
    )?;
    if readback_identity != temporary_identity
        || readback_identity.owner_uid != service_state_identity.owner_uid
        || readback_bytes != expected_bytes
        || readback != *expected
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "readback-signed-service-trust-binding",
            "published signed-service trust-binding identity, bytes, image, or root differs",
        ));
    }
    let file = open_exact_signed_service_binding(service_state_root, readback_identity)?;
    Ok((readback, file, readback_identity))
}

#[cfg(target_os = "macos")]
fn open_exact_signed_service_binding(
    service_state_root: &Dir,
    expected: DurableFileIdentity,
) -> Result<File, MacosOrdinaryRunnerDurableStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = service_state_root
        .open_with(SIGNED_SERVICE_TRUST_BINDING, &options)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
                "retain-signed-service-trust-binding",
                error,
            )
        })?;
    if validate_durable_private_file(
        &file,
        Path::new(SIGNED_SERVICE_TRUST_BINDING),
        Some(expected.byte_length),
    )? != expected
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "retain-signed-service-trust-binding",
            "signed-service trust-binding changed before its descriptor was retained",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignedServiceExecutableFileIdentity {
    device_id: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
    byte_length: u64,
    link_count: u64,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct ObservedCodesignDisplayFields {
    signing_identifier: String,
    team_identifier: Option<String>,
    cdhash: String,
    designated_requirement: String,
    signing_authorities: Vec<String>,
}

#[cfg(target_os = "macos")]
fn observe_path_local_signed_image(
    requested_path: &Path,
) -> Result<MacosOrdinaryRunnerPathLocalSignedImageRecord, MacosOrdinaryRunnerDurableStoreError> {
    use std::os::unix::ffi::OsStrExt as _;

    let canonical_path = std::fs::canonicalize(requested_path).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "canonicalize-signed-service-image",
            error,
        )
    })?;
    let canonical_path_bytes = canonical_path.as_os_str().as_bytes().to_vec();
    if canonical_path_bytes.is_empty()
        || canonical_path_bytes.len() > MAX_SIGNED_SERVICE_PATH_BYTES
        || canonical_path_bytes.first() != Some(&b'/')
        || canonical_path_bytes.contains(&0)
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "canonicalize-signed-service-image",
            "signed-service image path is not one bounded canonical absolute path",
        ));
    }
    let filesystem_root =
        Dir::open_ambient_dir("/", cap_std::ambient_authority()).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "open-signed-service-filesystem-root",
                error,
            )
        })?;
    let relative = canonical_path
        .strip_prefix(Path::new("/"))
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "relativize-signed-service-image",
                error,
            )
        })?;
    let mut retained = open_signed_service_image(&filesystem_root, relative)?;
    let before = validate_signed_service_executable(&retained)?;
    let before_digest = digest_signed_service_executable(&mut retained, before.byte_length)?;
    let codesign_display = observe_codesign_display_fields(&canonical_path)?;
    let after = validate_signed_service_executable(&retained)?;
    let after_digest = digest_signed_service_executable(&mut retained, after.byte_length)?;
    let mut named = open_signed_service_image(&filesystem_root, relative)?;
    let named_identity = validate_signed_service_executable(&named)?;
    let named_digest = digest_signed_service_executable(&mut named, named_identity.byte_length)?;
    if before != after
        || before != named_identity
        || before_digest != after_digest
        || before_digest != named_digest
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Substitution,
            "observe-signed-service-image",
            "signed-service image identity or complete bytes changed during signature observation",
        ));
    }
    let image = MacosOrdinaryRunnerPathLocalSignedImageRecord {
        canonical_path_bytes,
        device_id: before.device_id,
        inode: before.inode,
        owner_uid: before.owner_uid,
        mode: before.mode,
        byte_length: before.byte_length,
        link_count: before.link_count,
        executable_bytes_digest: before_digest,
        signing_identifier: codesign_display.signing_identifier,
        team_identifier: codesign_display.team_identifier,
        cdhash: codesign_display.cdhash,
        designated_requirement: codesign_display.designated_requirement,
        signing_authorities: codesign_display.signing_authorities,
    };
    image.validate()?;
    Ok(image)
}

#[cfg(target_os = "macos")]
fn open_signed_service_image(
    filesystem_root: &Dir,
    relative: &Path,
) -> Result<File, MacosOrdinaryRunnerDurableStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    filesystem_root
        .open_with(relative, &options)
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "open-signed-service-image",
                error,
            )
        })
}

#[cfg(target_os = "macos")]
fn validate_signed_service_executable(
    file: &File,
) -> Result<SignedServiceExecutableFileIdentity, MacosOrdinaryRunnerDurableStoreError> {
    let metadata = file.metadata().map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "inspect-signed-service-image",
            error,
        )
    })?;
    let identity = SignedServiceExecutableFileIdentity {
        device_id: PortableMetadataExt::dev(&metadata),
        inode: PortableMetadataExt::ino(&metadata),
        owner_uid: OsMetadataExt::uid(&metadata),
        mode: OsMetadataExt::mode(&metadata) & 0o777,
        byte_length: metadata.len(),
        link_count: PortableMetadataExt::nlink(&metadata),
    };
    if !metadata.is_file()
        || identity.device_id == 0
        || identity.inode == 0
        || identity.byte_length == 0
        || identity.byte_length > MAX_SIGNED_SERVICE_EXECUTABLE_BYTES
        || identity.link_count != 1
        || identity.mode & 0o111 == 0
        || identity.mode & 0o022 != 0
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "inspect-signed-service-image",
            "service image is not one bounded, singly linked, executable, non-group/world-writable regular file",
        ));
    }
    Ok(identity)
}

#[cfg(target_os = "macos")]
fn digest_signed_service_executable(
    file: &mut File,
    expected_length: u64,
) -> Result<Digest, MacosOrdinaryRunnerDurableStoreError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    file.seek(SeekFrom::Start(0)).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "rewind-signed-service-image",
            error,
        )
    })?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "read-signed-service-image",
                error,
            )
        })?;
        if read == 0 {
            break;
        }
        observed = observed.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if observed > MAX_SIGNED_SERVICE_EXECUTABLE_BYTES {
            return Err(durable_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "read-signed-service-image",
                "signed-service image exceeded its exact byte bound",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if observed != expected_length {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::Substitution,
            "read-signed-service-image",
            "signed-service image length changed during retained-descriptor hashing",
        ));
    }
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Digest::parse(text).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "encode-signed-service-image-digest",
            error,
        )
    })
}

#[cfg(target_os = "macos")]
fn observe_codesign_display_fields(
    executable: &Path,
) -> Result<ObservedCodesignDisplayFields, MacosOrdinaryRunnerDurableStoreError> {
    // Treat all-architecture codesign output as observation only and refuse
    // duplicate identity fields.
    let verification = Command::new("/usr/bin/codesign")
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args(CODESIGN_VERIFY_ARGUMENTS)
        .arg(executable)
        .output()
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "verify-signed-service-code-signature",
                error,
            )
        })?;
    if !verification.status.success()
        || verification
            .stdout
            .len()
            .saturating_add(verification.stderr.len())
            > MAX_CODESIGN_OUTPUT_BYTES
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "verify-signed-service-code-signature",
            "strict all-architecture code-signature verification failed or produced oversized output",
        ));
    }
    let display = Command::new("/usr/bin/codesign")
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args(CODESIGN_DISPLAY_ARGUMENTS)
        .arg(executable)
        .output()
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "inspect-signed-service-code-signature",
                error,
            )
        })?;
    if !display.status.success()
        || display.stdout.len().saturating_add(display.stderr.len()) > MAX_CODESIGN_OUTPUT_BYTES
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "inspect-signed-service-code-signature",
            "path-local code-signature display failed or produced oversized output",
        ));
    }
    let mut bytes = display.stderr;
    bytes.push(b'\n');
    bytes.extend_from_slice(&display.stdout);
    let text = String::from_utf8(bytes).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "decode-signed-service-code-signature",
            error,
        )
    })?;
    parse_codesign_display_fields(&text)
}

#[cfg(target_os = "macos")]
fn parse_codesign_display_fields(
    text: &str,
) -> Result<ObservedCodesignDisplayFields, MacosOrdinaryRunnerDurableStoreError> {
    // Text shape validation is not Security.framework policy evaluation. In
    // particular, substring checks below do not establish the semantics of a
    // designated requirement or an independently approved Grok identity.
    let lines = text.lines().collect::<Vec<_>>();
    let code_directory_is_ad_hoc = lines.iter().any(|line| {
        (line.starts_with("CodeDirectory ") && line.contains("(adhoc)"))
            || *line == "Signature=adhoc"
    });
    let signature_size = single_codesign_value(&lines, "Signature size=")?
        .parse::<u64>()
        .map_err(|error| {
            journal_failure(
                MacosOrdinaryRunnerDurableFailureClass::NotPublished,
                "parse-signed-service-signature-size",
                error,
            )
        })?;
    if code_directory_is_ad_hoc || signature_size == 0 {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "reject-ad-hoc-signed-service-image",
            "unsigned and ad-hoc code signatures are unavailable as path-local signed-image observations",
        ));
    }
    let signing_identifier = single_codesign_value(&lines, "Identifier=")?;
    let cdhash = single_codesign_value(&lines, "CDHash=")?;
    let designated_requirement = single_codesign_value(&lines, "designated => ")?;
    let raw_team = single_codesign_value(&lines, "TeamIdentifier=")?;
    let team_identifier = (raw_team != "not set").then_some(raw_team);
    let signing_authorities = lines
        .iter()
        .filter_map(|line| line.strip_prefix("Authority="))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let identity = ObservedCodesignDisplayFields {
        signing_identifier,
        team_identifier,
        cdhash,
        designated_requirement,
        signing_authorities,
    };
    Ok(identity)
}

#[cfg(target_os = "macos")]
fn single_codesign_value(
    lines: &[&str],
    prefix: &str,
) -> Result<String, MacosOrdinaryRunnerDurableStoreError> {
    let mut matches = lines.iter().filter_map(|line| line.strip_prefix(prefix));
    let value = matches.next().ok_or_else(|| {
        durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "parse-signed-service-code-signature",
            format!("required code-signature field {prefix:?} is unavailable"),
        )
    })?;
    if matches.next().is_some() || !valid_codesign_text(value, MAX_CODESIGN_REQUIREMENT_BYTES) {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "parse-signed-service-code-signature",
            format!("code-signature field {prefix:?} is duplicated, empty, or oversized"),
        ));
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "macos")]
fn signed_service_path_from_bytes(
    bytes: &[u8],
) -> Result<PathBuf, MacosOrdinaryRunnerDurableStoreError> {
    use std::os::unix::ffi::OsStringExt as _;

    if bytes.is_empty()
        || bytes.len() > MAX_SIGNED_SERVICE_PATH_BYTES
        || bytes.first() != Some(&b'/')
        || bytes.contains(&0)
    {
        return Err(durable_failure(
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired,
            "decode-signed-service-image-path",
            "signed-service image path bytes are not one bounded absolute path",
        ));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

fn durable_file_identity(metadata: &Metadata) -> DurableFileIdentity {
    DurableFileIdentity {
        device_id: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
        owner_uid: OsMetadataExt::uid(metadata),
        mode: OsMetadataExt::mode(metadata) & 0o777,
        byte_length: metadata.len(),
        link_count: PortableMetadataExt::nlink(metadata),
    }
}

fn lock_durable_writer(lock: &File) -> Result<(), MacosOrdinaryRunnerDurableStoreError> {
    flock(lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::NotPublished,
            "lock-fixed-journal",
            error,
        )
    })
}

fn unlock_durable_writer<T>(
    lock: &File,
    primary: Result<T, MacosOrdinaryRunnerDurableStoreError>,
) -> Result<T, MacosOrdinaryRunnerDurableStoreError> {
    let unlock = flock(lock, FlockOperation::Unlock).map_err(|error| {
        journal_failure(
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous,
            "unlock-fixed-journal",
            error,
        )
    });
    match (primary, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(unlock)) => Err(unlock),
        (Err(primary), Err(unlock)) => Err(durable_failure(
            primary.class,
            primary.operation,
            format!(
                "{}; retained writer-lock release also failed: {unlock}",
                primary.detail
            ),
        )),
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestDurableFailurePoint {
    BeforeTemporarySync,
    AfterTemporarySync,
    BeforeRename,
    AfterRename,
    BeforeDirectorySync,
    AfterDirectorySync,
    BeforeReadback,
    AfterReadback,
}

/// Fail-closed ordinary-runner journal contract error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosOrdinaryRunnerJournalError {
    Invalid(String),
    Encoding(String),
    Protocol(MacosOrdinaryRunnerHeldProtocolError),
    TooLarge { bytes: usize, maximum: usize },
}

impl Display for MacosOrdinaryRunnerJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => {
                write!(
                    formatter,
                    "ordinary macOS runner journal rejected: {detail}"
                )
            }
            Self::Encoding(detail) => {
                write!(
                    formatter,
                    "ordinary macOS runner journal encoding failed: {detail}"
                )
            }
            Self::Protocol(error) => Display::fmt(error, formatter),
            Self::TooLarge { bytes, maximum } => write!(
                formatter,
                "ordinary macOS runner journal has {bytes} bytes; maximum is {maximum}"
            ),
        }
    }
}

impl std::error::Error for MacosOrdinaryRunnerJournalError {}

impl From<MacosOrdinaryRunnerHeldProtocolError> for MacosOrdinaryRunnerJournalError {
    fn from(error: MacosOrdinaryRunnerHeldProtocolError) -> Self {
        Self::Protocol(error)
    }
}

fn invalid(detail: impl Into<String>) -> MacosOrdinaryRunnerJournalError {
    MacosOrdinaryRunnerJournalError::Invalid(detail.into())
}

#[cfg(test)]
mod tests;
