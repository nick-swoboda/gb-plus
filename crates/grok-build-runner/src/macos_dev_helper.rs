//! Unprivileged macOS development helper.
//!
//! This path uses separate
//! session and topology types, a private state root, and generation-scoped domains
//! under the invoking UID. Validation requires `dedicated_account_pool == false`;
//! it cannot supply production dedicated-account cleanup evidence.
//!
//! The helper authenticates its UNIX-socket peer, applies Seatbelt, spawns suspended
//! with closed inherited descriptors and a descriptor-relative working directory,
//! drains bounded output, and terminates and enumerates its process group.
//!
//! Without dedicated accounts it cannot impose a per-UID descendant ceiling or
//! prove termination of descendants that leave the process group with `setsid`.
//! Executable selection is by pathname because this path has no descriptor exec.
//! The backend claims only live-proven controls and refuses other requirements.

#![allow(
    dead_code,
    reason = "the development helper's server half is reached through its own bin target rather than the library's call graph"
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, DirBuilder, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use grok_build_core::Digest;
use rustix::process::Pid;
use serde::{Deserialize, Serialize};

use crate::macos_helper_protocol::{
    MACOS_HELPER_PROTOCOL_VERSION, MacosChildDescriptorBinding, MacosChildDescriptorPurpose,
    MacosExecutableIdentity, MacosHelperAttestation, MacosHelperInstallAudit,
    MacosHelperLaunchRequest, MacosHelperNetwork, MacosHelperPreparationBinding,
    MacosHelperProtocolError, descriptor_bindings_digest,
};
use crate::macos_helper_transport::{
    MacosHelperFrameKind, MacosHelperTransportError, MacosPeerCodeRequirement,
    audit_installed_binary, authenticate_peer, code_identity_digest, decode_canonical_payload,
    encode_canonical_payload, observe_peer, read_frame, write_frame,
};
use crate::macos_native_held_launch::{
    await_stopped_child, child_setup_stage, continue_stdio_child, current_process_thread_count,
    fork_apply_seatbelt_and_exec, observe_child_descriptors, reap_exact_condemned_child,
    spawn_stdio_suspended,
};

/// Number of identities the development pool offers.
///
/// Production fixes three otherwise-unused local accounts, matching the
/// coordinator's hard worker ceiling. The development pool keeps the same
/// arity so the reservation arithmetic is the same shape, but its slots are
/// generation directories rather than accounts.
pub(crate) const MACOS_DEVELOPMENT_IDENTITY_COUNT: usize = 3;

/// Hard ceiling on the raw bytes carried by one streamed output chunk frame.
///
/// The transport frame ceiling is the protocol's 64 KiB request bound. Chunk
/// payloads are hex encoded, so the raw ceiling is set well below half of that
/// to leave room for the surrounding canonical JSON.
pub(crate) const MAX_MACOS_DEVELOPMENT_CHUNK_BYTES: usize = 8 * 1_024;

/// Hard ceiling on the Seatbelt profile text carried by one development run.
pub(crate) const MAX_MACOS_DEVELOPMENT_PROFILE_BYTES: usize = 16 * 1_024;

/// Hard ceiling on development runs served by one connection.
///
/// Production admits exactly one launch request per connection. Development
/// must run its canary suite inside the *same* reserved identity generation as
/// the launch it reports on, which is impossible with a one-request
/// connection, so the dev protocol admits a bounded ordered sequence instead.
pub(crate) const MAX_MACOS_DEVELOPMENT_RUNS_PER_SESSION: u32 = 32;

const DEVELOPMENT_SESSION_DOMAIN: &[u8] = b"grok-build.macos-development-helper-session.v1\0";
const DEVELOPMENT_IDENTITY_DOMAIN: &[u8] = b"grok-build.macos-development-identity.v1\0";
const DEVELOPMENT_POOL_DOMAIN: &[u8] = b"grok-build.macos-development-identity-pool.v1\0";
const DEVELOPMENT_EVIDENCE_DOMAIN: &[u8] = b"grok-build.macos-development-run-evidence.v1\0";

/// The topology a helper message belongs to.
///
/// This enum has exactly one variant on purpose. Production messages do not
/// carry a topology field at all, so there is no value of this type that means
/// "production" and no way to spell one. Its canonical encoding is the string
/// `"development"`, which is what makes every dev artifact self-identifying in
/// its own bytes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosHelperTopology {
    /// A separately named, separately rooted, never-signed development build.
    Development,
}

impl Display for MacosHelperTopology {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("development")
    }
}

/// How the development helper's server half is hosted.
///
/// Production always runs a privilege-separated root daemon registered through
/// `SMAppService`. Development has two hosting shapes and records which one
/// served a session in the session's own canonical bytes, so the difference is
/// never silent:
///
/// * `SeparateProcess` is the `grok-build-dev-helper` bin target, spawned by
///   the client and authenticated as the exact child it spawned. This is the
///   shape that mirrors production.
/// * `SameImageThread` serves the connection from a thread of the client's own
///   process. It is used by in-crate tests, where `cargo test --lib` builds no
///   bin target at all. Peer authentication still runs for real against a real
///   kernel audit token and a real code-directory-hash requirement, the peer
///   is simply the same image, which is exactly what the pin then states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosDevelopmentHelperTopology {
    /// The separately named development helper bin target.
    SeparateProcess,
    /// A thread of the client's own process running the identical server.
    SameImageThread,
}

impl Display for MacosDevelopmentHelperTopology {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SeparateProcess => "separate_process",
            Self::SameImageThread => "same_image_thread",
        })
    }
}

/// Authenticated session for an unprivileged helper.
/// The topology tag and generation-pool digest distinguish it from a production
/// account pool; validation requires `dedicated_account_pool == false`.
/// Both paths require code attestation, but only production can supply the
/// `MacosAssignedIdentity` required for terminal evidence. This type offers no
/// conversion to a production session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentHelperSession {
    pub(crate) topology: MacosHelperTopology,
    pub(crate) helper_topology: MacosDevelopmentHelperTopology,
    pub(crate) protocol_version: u32,
    pub(crate) policy_version: u32,
    pub(crate) session_nonce: Digest,
    pub(crate) helper_binary_digest: Digest,
    pub(crate) helper_requirement_digest: Digest,
    pub(crate) client_binary_digest: Digest,
    pub(crate) client_requirement_digest: Digest,
    pub(crate) identity_pool_digest: Digest,
    pub(crate) workspace_grant_hash: Digest,
    pub(crate) execution_policy_hash: Digest,
    pub(crate) command_network: MacosHelperNetwork,
    pub(crate) authenticated_at_unix_ms: u64,
    pub(crate) peer_requirement_matched: bool,
    /// What was verified about this helper's code identity.
    ///
    /// Identical in type and meaning to the production session's field. A
    /// locally built helper is honestly [`MacosHelperAttestation::LocalCodeIdentity`];
    /// if the running image ever does chain to an Apple anchor, the honest
    /// value is the publisher kind and the client checks that claim against the
    /// kernel-resolved peer.
    pub(crate) attestation: MacosHelperAttestation,
    /// Always `false`, and validated to be `false`.
    ///
    /// Creating an otherwise-unused local execution account requires root, so
    /// an unprivileged helper never owns one. This is the field that keeps the
    /// two session contracts disjoint, and it names the real difference rather
    /// than a signing property.
    pub(crate) dedicated_account_pool: bool,
    pub(crate) session_digest: Digest,
}

#[derive(Serialize)]
struct DevelopmentSessionPreimage<'a> {
    topology: MacosHelperTopology,
    helper_topology: MacosDevelopmentHelperTopology,
    protocol_version: u32,
    policy_version: u32,
    session_nonce: &'a Digest,
    helper_binary_digest: &'a Digest,
    helper_requirement_digest: &'a Digest,
    client_binary_digest: &'a Digest,
    client_requirement_digest: &'a Digest,
    identity_pool_digest: &'a Digest,
    workspace_grant_hash: &'a Digest,
    execution_policy_hash: &'a Digest,
    command_network: MacosHelperNetwork,
    authenticated_at_unix_ms: u64,
    peer_requirement_matched: bool,
    attestation: MacosHelperAttestation,
    dedicated_account_pool: bool,
}

impl MacosDevelopmentHelperSession {
    /// Domain-separated digest over every field except itself.
    ///
    /// # Errors
    ///
    /// Fails only when canonical JSON encoding fails.
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosDevelopmentHelperError> {
        let preimage = DevelopmentSessionPreimage {
            topology: self.topology,
            helper_topology: self.helper_topology,
            protocol_version: self.protocol_version,
            policy_version: self.policy_version,
            session_nonce: &self.session_nonce,
            helper_binary_digest: &self.helper_binary_digest,
            helper_requirement_digest: &self.helper_requirement_digest,
            client_binary_digest: &self.client_binary_digest,
            client_requirement_digest: &self.client_requirement_digest,
            identity_pool_digest: &self.identity_pool_digest,
            workspace_grant_hash: &self.workspace_grant_hash,
            execution_policy_hash: &self.execution_policy_hash,
            command_network: self.command_network,
            authenticated_at_unix_ms: self.authenticated_at_unix_ms,
            peer_requirement_matched: self.peer_requirement_matched,
            attestation: self.attestation,
            dedicated_account_pool: self.dedicated_account_pool,
        };
        domain_digest(DEVELOPMENT_SESSION_DOMAIN, &preimage)
    }

    /// Validates code attestation, install-path ownership and the development
    /// session's refusal to claim dedicated execution accounts.
    ///
    /// # Errors
    ///
    /// Fails for invalid versions or timestamps, an unmatched peer requirement,
    /// an unattested or unsafe installation, a dedicated-account claim, or a
    /// digest that differs from the canonical preimage.
    pub(crate) fn validate(&self) -> Result<(), MacosDevelopmentHelperError> {
        if self.protocol_version != MACOS_HELPER_PROTOCOL_VERSION {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_session.protocol_version",
                "unsupported helper protocol version",
            ));
        }
        if self.policy_version == 0 || self.authenticated_at_unix_ms == 0 {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_session.versions",
                "policy version and authentication time must be nonzero",
            ));
        }
        if !self.peer_requirement_matched {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_session.peer_identity",
                "the development peer requirement was not satisfied",
            ));
        }
        self.attestation.validate()?;
        if self.dedicated_account_pool {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_session.dedicated_account_pool",
                "an unprivileged helper cannot own otherwise-unused local execution accounts",
            ));
        }
        if self.session_digest != self.computed_digest()? {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_session.session_digest",
                "session digest does not bind the canonical preimage",
            ));
        }
        Ok(())
    }

    /// Compares durable authority while excluding the per-connection nonce,
    /// authentication time, and the digest computed over them.
    pub(crate) fn same_durable_authority(&self, other: &Self) -> bool {
        self.topology == other.topology
            && self.helper_topology == other.helper_topology
            && self.protocol_version == other.protocol_version
            && self.policy_version == other.policy_version
            && self.helper_binary_digest == other.helper_binary_digest
            && self.helper_requirement_digest == other.helper_requirement_digest
            && self.client_binary_digest == other.client_binary_digest
            && self.client_requirement_digest == other.client_requirement_digest
            && self.identity_pool_digest == other.identity_pool_digest
            && self.workspace_grant_hash == other.workspace_grant_hash
            && self.execution_policy_hash == other.execution_policy_hash
            && self.command_network == other.command_network
            && self.peer_requirement_matched == other.peer_requirement_matched
            && self.attestation == other.attestation
            && self.dedicated_account_pool == other.dedicated_account_pool
    }
}

/// The exact identity one development run was assigned.
///
/// Production's `MacosAssignedIdentity` names an otherwise-unused local
/// account. This type deliberately does not, because no such account exists on
/// an unprivileged development host, and it says so in a field rather than a
/// comment: [`MacosDevelopmentIdentityRecord::dedicated_account`] is always
/// `false` and is validated to be `false`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentIdentityRecord {
    pub(crate) topology: MacosHelperTopology,
    /// Zero-based slot inside the fixed development pool.
    pub(crate) slot: u32,
    /// Unique identifier of one reservation of that slot.
    pub(crate) generation_id: String,
    /// Real UID the child actually runs as: the invoking developer's own.
    pub(crate) real_uid: u32,
    /// Always `false`. An unprivileged host cannot create an execution account.
    pub(crate) dedicated_account: bool,
    /// Digest over the reserved generation's owner-private lease object.
    pub(crate) lease_digest: Digest,
    pub(crate) identity_digest: Digest,
}

#[derive(Serialize)]
struct DevelopmentIdentityPreimage<'a> {
    topology: MacosHelperTopology,
    slot: u32,
    generation_id: &'a str,
    real_uid: u32,
    dedicated_account: bool,
    lease_digest: &'a Digest,
}

impl MacosDevelopmentIdentityRecord {
    /// Domain-separated digest over every field except itself.
    ///
    /// # Errors
    ///
    /// Fails only when canonical JSON encoding fails.
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosDevelopmentHelperError> {
        domain_digest(
            DEVELOPMENT_IDENTITY_DOMAIN,
            &DevelopmentIdentityPreimage {
                topology: self.topology,
                slot: self.slot,
                generation_id: &self.generation_id,
                real_uid: self.real_uid,
                dedicated_account: self.dedicated_account,
                lease_digest: &self.lease_digest,
            },
        )
    }

    /// Validates one assigned development identity.
    ///
    /// # Errors
    ///
    /// Fails for an out-of-range slot, a malformed generation identifier, a
    /// dedicated-account claim, or a digest mismatch.
    pub(crate) fn validate(&self) -> Result<(), MacosDevelopmentHelperError> {
        if usize::try_from(self.slot).unwrap_or(usize::MAX) >= MACOS_DEVELOPMENT_IDENTITY_COUNT {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_identity.slot",
                "slot is outside the fixed development pool",
            ));
        }
        validate_development_identifier("development_identity.generation_id", &self.generation_id)?;
        if self.dedicated_account {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_identity.dedicated_account",
                "a development host cannot create an otherwise-unused execution account",
            ));
        }
        if self.identity_digest != self.computed_digest()? {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_identity.identity_digest",
                "identity digest does not bind the canonical preimage",
            ));
        }
        Ok(())
    }
}

/// Distinguishes two development state roots created in the same process.
static NEXT_DEVELOPMENT_STATE_ROOT: AtomicU64 = AtomicU64::new(0);

/// The owner-private root every development artifact lives under.
///
/// This is deliberately not the production helper's fixed private state root
/// and shares no path component with it. It is created with `O_EXCL`
/// semantics, is verified to be a directory owned by this user with mode
/// `0o700` and no group or other bits, and is removed when the helper exits.
#[derive(Debug)]
pub(crate) struct MacosDevelopmentStateRoot {
    root: PathBuf,
    owned: bool,
}

impl MacosDevelopmentStateRoot {
    /// Creates a fresh owner-private development state root.
    ///
    /// The path is kept short on purpose: a UNIX domain socket address is
    /// bounded by `sun_path`, and the platform temporary directory is already
    /// long enough that nesting inside it can overflow that bound.
    ///
    /// # Errors
    ///
    /// Fails when the root cannot be created exclusively, is not a directory
    /// this user owns, is group or world accessible, or would produce a socket
    /// path longer than the platform allows.
    pub(crate) fn create() -> Result<Self, MacosDevelopmentHelperError> {
        let uid = rustix::process::getuid().as_raw();
        let pid = std::process::id();
        let nanos = unix_time_nanos()?;
        // Combine an atomic counter, PID, and clock value for uniqueness; the
        // clock alone can repeat.
        let sequence = NEXT_DEVELOPMENT_STATE_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!("/tmp/gb-dev-{uid}-{pid}-{nanos:x}-{sequence:x}"));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&root).map_err(|error| {
            MacosDevelopmentHelperError::io("create development state root", &error)
        })?;
        let opened = Self { root, owned: true };
        opened.validate_private()?;
        let socket = opened.socket_path();
        if socket.as_os_str().as_bytes().len() >= MAX_UNIX_SOCKET_PATH_BYTES {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_state_root.socket_path",
                "development socket path exceeds the platform sun_path bound",
            ));
        }
        Ok(opened)
    }

    /// Adopts an existing development state root created by the client.
    ///
    /// # Errors
    ///
    /// Fails when the path is not an owner-private directory.
    pub(crate) fn adopt(root: PathBuf) -> Result<Self, MacosDevelopmentHelperError> {
        let adopted = Self { root, owned: false };
        adopted.validate_private()?;
        Ok(adopted)
    }

    /// The root directory itself.
    pub(crate) fn path(&self) -> &Path {
        &self.root
    }

    /// The development helper's listening socket.
    pub(crate) fn socket_path(&self) -> PathBuf {
        self.root.join("h.sock")
    }

    /// The directory the development identity pool leases live in.
    pub(crate) fn identity_root(&self) -> PathBuf {
        self.root.join("identities")
    }

    /// Re-proves that this root is a directory this user owns privately.
    ///
    /// # Errors
    ///
    /// Fails when the root is missing, is not a directory, is owned by another
    /// user, or grants any group or other permission.
    pub(crate) fn validate_private(&self) -> Result<(), MacosDevelopmentHelperError> {
        let metadata = fs::symlink_metadata(&self.root).map_err(|error| {
            MacosDevelopmentHelperError::io("inspect development state root", &error)
        })?;
        if !metadata.is_dir() {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_state_root.kind",
                "development state root is not a directory",
            ));
        }
        if metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_state_root.owner",
                "development state root is owned by another user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_state_root.mode",
                "development state root is group or world accessible",
            ));
        }
        Ok(())
    }
}

impl Drop for MacosDevelopmentStateRoot {
    fn drop(&mut self) {
        if self.owned {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }
}

/// The fixed development identity pool.
///
/// Reservation is exclusive by `O_CREAT | O_EXCL` on one lease file per slot,
/// so two helpers sharing a state root cannot hold the same slot, and a slot
/// is only returned to the pool after its lease object is removed.
#[derive(Debug)]
pub(crate) struct MacosDevelopmentIdentityPool {
    identity_root: PathBuf,
    pool_digest: Digest,
}

impl MacosDevelopmentIdentityPool {
    /// Prepares the pool directory beneath one development state root.
    ///
    /// # Errors
    ///
    /// Fails when the pool directory cannot be created privately.
    pub(crate) fn open(
        state_root: &MacosDevelopmentStateRoot,
    ) -> Result<Self, MacosDevelopmentHelperError> {
        state_root.validate_private()?;
        let identity_root = state_root.identity_root();
        if !identity_root.exists() {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(&identity_root).map_err(|error| {
                MacosDevelopmentHelperError::io("create development identity root", &error)
            })?;
        }
        let slots = (0..MACOS_DEVELOPMENT_IDENTITY_COUNT)
            .map(|slot| u32::try_from(slot).unwrap_or(u32::MAX))
            .collect::<Vec<_>>();
        let pool_digest = domain_digest(
            DEVELOPMENT_POOL_DOMAIN,
            &DevelopmentPoolPreimage {
                topology: MacosHelperTopology::Development,
                real_uid: rustix::process::getuid().as_raw(),
                dedicated_accounts: false,
                slots: &slots,
            },
        )?;
        Ok(Self {
            identity_root,
            pool_digest,
        })
    }

    /// Digest of the fixed development pool this helper published.
    pub(crate) const fn pool_digest(&self) -> &Digest {
        &self.pool_digest
    }

    /// Reserves the first free slot and returns its assigned identity.
    ///
    /// # Errors
    ///
    /// Fails when every slot is held or a lease object cannot be created.
    pub(crate) fn reserve(
        &self,
        generation_id: &str,
    ) -> Result<MacosDevelopmentReservation, MacosDevelopmentHelperError> {
        validate_development_identifier("development_identity.generation_id", generation_id)?;
        for slot in 0..MACOS_DEVELOPMENT_IDENTITY_COUNT {
            let slot = u32::try_from(slot).unwrap_or(u32::MAX);
            let lease = self.identity_root.join(format!("slot-{slot}.lease"));
            let created = File::options()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&lease);
            match created {
                Ok(mut file) => {
                    let contents = format!("{generation_id}\n");
                    file.write_all(contents.as_bytes()).map_err(|error| {
                        MacosDevelopmentHelperError::io("write development lease", &error)
                    })?;
                    file.sync_all().map_err(|error| {
                        MacosDevelopmentHelperError::io("synchronize development lease", &error)
                    })?;
                    let mut record = MacosDevelopmentIdentityRecord {
                        topology: MacosHelperTopology::Development,
                        slot,
                        generation_id: generation_id.to_owned(),
                        real_uid: rustix::process::getuid().as_raw(),
                        dedicated_account: false,
                        lease_digest: Digest::sha256(contents.as_bytes()),
                        identity_digest: Digest::sha256(&[]),
                    };
                    record.identity_digest = record.computed_digest()?;
                    record.validate()?;
                    return Ok(MacosDevelopmentReservation {
                        record,
                        lease,
                        released: false,
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(MacosDevelopmentHelperError::io(
                        "create development lease",
                        &error,
                    ));
                }
            }
        }
        Err(MacosDevelopmentHelperError::invalid(
            "development_identity_pool.capacity",
            "every development identity slot is already reserved",
        ))
    }
}

#[derive(Serialize)]
struct DevelopmentPoolPreimage<'a> {
    topology: MacosHelperTopology,
    real_uid: u32,
    dedicated_accounts: bool,
    slots: &'a [u32],
}

/// One held development identity slot.
///
/// The slot returns to the pool when this value is dropped, mirroring the
/// production rule that a numeric identity cannot be reassigned until its
/// cleanup evidence exists. Development cannot produce that evidence, so the
/// release is a plain lease removal and says nothing about survivors.
#[derive(Debug)]
pub(crate) struct MacosDevelopmentReservation {
    record: MacosDevelopmentIdentityRecord,
    lease: PathBuf,
    released: bool,
}

impl MacosDevelopmentReservation {
    /// The assigned identity record.
    pub(crate) const fn record(&self) -> &MacosDevelopmentIdentityRecord {
        &self.record
    }
}

impl Drop for MacosDevelopmentReservation {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            let _ignored = fs::remove_file(&self.lease);
        }
    }
}

/// Fail-closed development helper failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosDevelopmentHelperError {
    /// A development contract field is invalid.
    Invalid {
        /// Exact invalid field.
        field: &'static str,
        /// Why the field is invalid.
        reason: &'static str,
    },
    /// An operating-system operation failed.
    Io {
        /// Stage that failed.
        stage: &'static str,
        /// Rendered operating-system error.
        detail: String,
    },
    /// Canonical encoding or decoding failed.
    Encoding(String),
    /// The framed transport failed.
    Transport(String),
    /// The embedded production-protocol payload failed its own validation.
    Protocol(MacosHelperProtocolError),
    /// The helper refused a run before any child existed.
    RefusedBeforeLaunch {
        /// Exact refusal reason returned to the client.
        detail: String,
    },
}

impl MacosDevelopmentHelperError {
    pub(crate) const fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::Invalid { field, reason }
    }

    pub(crate) fn io(stage: &'static str, error: &io::Error) -> Self {
        Self::Io {
            stage,
            detail: error.to_string(),
        }
    }
}

impl Display for MacosDevelopmentHelperError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { field, reason } => {
                write!(
                    formatter,
                    "development helper field {field} is invalid: {reason}"
                )
            }
            Self::Io { stage, detail } => write!(formatter, "{stage}: {detail}"),
            Self::Encoding(detail) => write!(formatter, "development encoding failed: {detail}"),
            Self::Transport(detail) => write!(formatter, "development transport failed: {detail}"),
            Self::Protocol(error) => Display::fmt(error, formatter),
            Self::RefusedBeforeLaunch { detail } => {
                write!(
                    formatter,
                    "development helper refused before launch: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for MacosDevelopmentHelperError {}

impl From<MacosHelperProtocolError> for MacosDevelopmentHelperError {
    fn from(error: MacosHelperProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<MacosHelperTransportError> for MacosDevelopmentHelperError {
    fn from(error: MacosHelperTransportError) -> Self {
        Self::Transport(error.to_string())
    }
}

/// Platform bound on a UNIX domain socket address, including its terminator.
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 104;

fn validate_development_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), MacosDevelopmentHelperError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(MacosDevelopmentHelperError::invalid(
            field,
            "identifier must be nonblank, bounded, and free of path syntax",
        ));
    }
    Ok(())
}

fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Digest, MacosDevelopmentHelperError> {
    let canonical = serde_json::to_vec(value)
        .map_err(|error| MacosDevelopmentHelperError::Encoding(error.to_string()))?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(Digest::sha256(&bytes))
}

fn unix_time_ms() -> Result<u64, MacosDevelopmentHelperError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        MacosDevelopmentHelperError::invalid(
            "development_clock",
            "the system clock is before the UNIX epoch",
        )
    })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        MacosDevelopmentHelperError::invalid(
            "development_clock",
            "the system clock is outside the admitted range",
        )
    })
}

fn unix_time_nanos() -> Result<u128, MacosDevelopmentHelperError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            MacosDevelopmentHelperError::invalid(
                "development_clock",
                "the system clock is before the UNIX epoch",
            )
        })?
        .as_nanos())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

fn from_lower_hex(text: &str) -> Result<Vec<u8>, MacosDevelopmentHelperError> {
    if !text.len().is_multiple_of(2) {
        return Err(MacosDevelopmentHelperError::invalid(
            "development_chunk.hex",
            "hex payloads must have an even length",
        ));
    }
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_value(byte: u8) -> Result<u8, MacosDevelopmentHelperError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(MacosDevelopmentHelperError::invalid(
            "development_chunk.hex",
            "hex payloads admit only lowercase hexadecimal digits",
        )),
    }
}

/// Why one development run exists.
///
/// The purpose is recorded in the run's evidence so a reader can never
/// mistake a permissive control run for the restrictive run it is compared
/// against.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosDevelopmentRunPurpose {
    /// A permissive control that must succeed for the restrictive comparison
    /// to mean anything.
    CanaryControl,
    /// A restrictive canary whose outcome decides one claimed control.
    Canary,
    /// The command the backend was actually asked to contain.
    Command,
}

impl Display for MacosDevelopmentRunPurpose {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CanaryControl => "canary_control",
            Self::Canary => "canary",
            Self::Command => "command",
        })
    }
}

/// One development run request.
///
/// The embedded [`MacosHelperLaunchRequest`] is the *existing* production
/// protocol request, validated with its own `validate_retained`, so the
/// development path exercises the real canonical request contract rather than
/// a private imitation. Only the enclosing envelope is development shaped.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentRunRequest {
    pub(crate) topology: MacosHelperTopology,
    pub(crate) purpose: MacosDevelopmentRunPurpose,
    pub(crate) request: MacosHelperLaunchRequest,
    /// Exact Seatbelt profile text whose digest the request already binds.
    pub(crate) seatbelt_profile: String,
    /// Whether the helper should attempt a descriptor exec before this run.
    pub(crate) probe_descriptor_exec: bool,
}

impl MacosDevelopmentRunRequest {
    /// Validates the envelope and the embedded production request.
    ///
    /// # Errors
    ///
    /// Fails when the profile is empty or oversized, when the profile text
    /// does not hash to the digest the request binds, or when the embedded
    /// request fails its own retained validation.
    pub(crate) fn validate(&self) -> Result<(), MacosDevelopmentHelperError> {
        if self.seatbelt_profile.is_empty()
            || self.seatbelt_profile.len() > MAX_MACOS_DEVELOPMENT_PROFILE_BYTES
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_run.seatbelt_profile",
                "profile text is empty or exceeds the development bound",
            ));
        }
        if Digest::sha256(self.seatbelt_profile.as_bytes()) != self.request.seatbelt_profile_digest
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_run.seatbelt_profile",
                "profile text does not hash to the digest the request binds",
            ));
        }
        self.request.validate_retained()?;
        Ok(())
    }

    /// Validates the run against the authenticated development session.
    ///
    /// # Errors
    ///
    /// Fails when the request's versions, nonce, grant hash, policy hash, or
    /// network authority differ from the authenticated session.
    pub(crate) fn validate_for_session(
        &self,
        session: &MacosDevelopmentHelperSession,
    ) -> Result<(), MacosDevelopmentHelperError> {
        self.validate()?;
        session.validate()?;
        if self.topology != session.topology
            || self.request.protocol_version != session.protocol_version
            || self.request.policy_version != session.policy_version
            || self.request.session_nonce != session.session_nonce
            || self.request.workspace_grant_hash != session.workspace_grant_hash
            || self.request.execution_policy_hash != session.execution_policy_hash
            || self.request.command_network != session.command_network
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_run.session_binding",
                "run differs from its authenticated development session",
            ));
        }
        Ok(())
    }
}

/// Which stream one output chunk came from.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosDevelopmentStream {
    Stdout,
    Stderr,
}

/// One bounded output chunk streamed while a development run is live.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentRunChunk {
    pub(crate) topology: MacosHelperTopology,
    pub(crate) stream: MacosDevelopmentStream,
    pub(crate) sequence: u64,
    /// Lowercase hexadecimal encoding of the raw chunk bytes.
    pub(crate) bytes_hex: String,
}

impl MacosDevelopmentRunChunk {
    /// Decodes the raw chunk bytes.
    ///
    /// # Errors
    ///
    /// Fails for a malformed or oversized hexadecimal payload.
    pub(crate) fn decoded(&self) -> Result<Vec<u8>, MacosDevelopmentHelperError> {
        if self.bytes_hex.len() > MAX_MACOS_DEVELOPMENT_CHUNK_BYTES * 2 {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_chunk.bytes_hex",
                "chunk exceeds the development streaming bound",
            ));
        }
        from_lower_hex(&self.bytes_hex)
    }
}

/// How one development run's leader process ended.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosDevelopmentTermination {
    /// The leader exited normally with this status code.
    Exited(i32),
    /// The leader was terminated by this signal.
    Signaled(i32),
}

/// Complete accounting for one drained stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentStreamEvidence {
    pub(crate) complete_digest: Digest,
    pub(crate) complete_length: u64,
    pub(crate) chunk_count: u64,
    pub(crate) maximum_chunk_bytes: u64,
}

/// Live measurement of whether this platform can execute a held descriptor.
///
/// macOS has no `fexecve` or `execveat`, and the `fdesc` node backing
/// `/dev/fd/N` is not executable, so the honest outcome on macOS 15 is
/// `supported == false` with `errno == EACCES`. The dev helper measures it
/// rather than asserting it, so if a future platform gains the primitive the
/// claim changes by itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentDescriptorExecProbe {
    pub(crate) attempted: bool,
    pub(crate) supported: bool,
    pub(crate) errno: i32,
}

/// How one run's Seatbelt profile reached the contained process.
///
/// The distinction is not cosmetic. With a separate applier program the
/// launcher's last observation of the child is taken *before* that program
/// runs, and the program then executes arbitrary code of its own before
/// `execve`ing the target, so the launcher has no observation point at the
/// target's own exec and cannot prove what the target inherited. With the
/// in-process applier the launcher owns the child from `fork` to `execve` and
/// reads the exact table the kernel is about to carry across the exec.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosDevelopmentProfileApplier {
    /// `/usr/bin/sandbox-exec` applied the profile and then exec'd the target.
    SeparateProgram,
    /// The helper forked, called `sandbox_init` in the child, proved the
    /// child's descriptor table, and exec'd the target itself.
    InProcessFork,
}

impl Display for MacosDevelopmentProfileApplier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SeparateProgram => "separate_program",
            Self::InProcessFork => "in_process_fork",
        })
    }
}

/// What the launcher itself looked like at the instant it created the child.
///
/// `thread_count` is the single-thread proof that licenses `fork` followed by
/// a non-async-signal-safe `sandbox_init`; the in-process applier is refused
/// unless it is exactly 1. `descriptor_count` is the launcher's own open
/// descriptor total at the same instant, which is what makes a child table of
/// exactly `{0, 1, 2}` a measurement rather than a tautology: the child began
/// as a copy of that table.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentLauncherState {
    pub(crate) thread_count: u32,
    pub(crate) descriptor_count: u32,
}

/// Live measurement of the descendant ceiling this host can install.
///
/// `RLIMIT_NPROC` counts every process of a *real UID*. Production spends one
/// otherwise-unused account per command domain, which makes that count equal
/// to the domain's descendant count. A development host has no authority to
/// create such an account, so the child runs under the developer's own UID and
/// this record reports the resulting, deliberately unusable arithmetic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentDescendantCeiling {
    /// Descendant ceiling the request asked for.
    pub(crate) requested_max_processes: u32,
    /// Processes already owned by the shared real UID before launch.
    pub(crate) real_uid_process_count: u32,
    /// Whether a per-UID `RLIMIT_NPROC` equal to the request was installed.
    pub(crate) rlimit_nproc_applied: bool,
    /// Current soft `RLIMIT_NPROC` for this UID, for the record.
    pub(crate) rlimit_nproc_soft: u64,
}

/// Complete evidence for one development run.
///
/// This is not `MacosHeldPreparationEvidence` and cannot be decoded as one:
/// the leading `topology` tag alone defeats that type's
/// `deny_unknown_fields`. Every claim below is something the helper observed
/// during this exact run in the reserved identity generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentRunEvidence {
    pub(crate) topology: MacosHelperTopology,
    pub(crate) purpose: MacosDevelopmentRunPurpose,
    pub(crate) session_nonce: Digest,
    pub(crate) request_digest: Digest,
    pub(crate) identity: MacosDevelopmentIdentityRecord,
    pub(crate) descriptor_bindings_digest: Digest,
    pub(crate) seatbelt_profile_digest: Digest,
    /// How the profile reached the contained process for this run.
    pub(crate) profile_applier: MacosDevelopmentProfileApplier,
    /// The launcher's own thread and descriptor totals at child creation.
    pub(crate) launcher_state: MacosDevelopmentLauncherState,
    /// Absolute path of the image that applied the profile: the separate
    /// applier program, or the helper's own image when it applied it in process.
    pub(crate) launcher_path: String,
    pub(crate) launcher_digest: Digest,
    /// Absolute path of the contained program the applier executed.
    pub(crate) executable_path: String,
    pub(crate) executable_digest: Digest,
    pub(crate) descriptor_exec: MacosDevelopmentDescriptorExecProbe,
    pub(crate) descendant_ceiling: MacosDevelopmentDescendantCeiling,
    pub(crate) launch_pid: u32,
    pub(crate) process_group_id: u32,
    /// Descriptors the leader actually held while still suspended.
    pub(crate) held_child_descriptors: Vec<u32>,
    /// Whether the leader was observed as its own session leader while held.
    pub(crate) held_session_leader: bool,
    pub(crate) argv: Vec<String>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) working_directory: String,
    pub(crate) termination: MacosDevelopmentTermination,
    pub(crate) stdout: MacosDevelopmentStreamEvidence,
    pub(crate) stderr: MacosDevelopmentStreamEvidence,
    /// Whether the supervisor's own monotonic deadline ended the run.
    pub(crate) wall_clock_terminated: bool,
    pub(crate) started_at_unix_ms: u64,
    pub(crate) finished_at_unix_ms: u64,
    /// Processes still sharing the domain's process group after termination.
    pub(crate) domain_survivors: Vec<u32>,
    pub(crate) evidence_digest: Digest,
}

#[derive(Serialize)]
struct DevelopmentEvidencePreimage<'a> {
    topology: MacosHelperTopology,
    purpose: MacosDevelopmentRunPurpose,
    session_nonce: &'a Digest,
    request_digest: &'a Digest,
    identity: &'a MacosDevelopmentIdentityRecord,
    descriptor_bindings_digest: &'a Digest,
    seatbelt_profile_digest: &'a Digest,
    profile_applier: MacosDevelopmentProfileApplier,
    launcher_state: MacosDevelopmentLauncherState,
    launcher_path: &'a str,
    launcher_digest: &'a Digest,
    executable_path: &'a str,
    executable_digest: &'a Digest,
    descriptor_exec: MacosDevelopmentDescriptorExecProbe,
    descendant_ceiling: MacosDevelopmentDescendantCeiling,
    launch_pid: u32,
    process_group_id: u32,
    held_child_descriptors: &'a [u32],
    held_session_leader: bool,
    argv: &'a [String],
    environment: &'a BTreeMap<String, String>,
    working_directory: &'a str,
    termination: MacosDevelopmentTermination,
    stdout: &'a MacosDevelopmentStreamEvidence,
    stderr: &'a MacosDevelopmentStreamEvidence,
    wall_clock_terminated: bool,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    domain_survivors: &'a [u32],
}

impl MacosDevelopmentRunEvidence {
    /// Domain-separated digest over every field except itself.
    ///
    /// # Errors
    ///
    /// Fails only when canonical JSON encoding fails.
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosDevelopmentHelperError> {
        domain_digest(
            DEVELOPMENT_EVIDENCE_DOMAIN,
            &DevelopmentEvidencePreimage {
                topology: self.topology,
                purpose: self.purpose,
                session_nonce: &self.session_nonce,
                request_digest: &self.request_digest,
                identity: &self.identity,
                descriptor_bindings_digest: &self.descriptor_bindings_digest,
                seatbelt_profile_digest: &self.seatbelt_profile_digest,
                profile_applier: self.profile_applier,
                launcher_state: self.launcher_state,
                launcher_path: &self.launcher_path,
                launcher_digest: &self.launcher_digest,
                executable_path: &self.executable_path,
                executable_digest: &self.executable_digest,
                descriptor_exec: self.descriptor_exec,
                descendant_ceiling: self.descendant_ceiling,
                launch_pid: self.launch_pid,
                process_group_id: self.process_group_id,
                held_child_descriptors: &self.held_child_descriptors,
                held_session_leader: self.held_session_leader,
                argv: &self.argv,
                environment: &self.environment,
                working_directory: &self.working_directory,
                termination: self.termination,
                stdout: &self.stdout,
                stderr: &self.stderr,
                wall_clock_terminated: self.wall_clock_terminated,
                started_at_unix_ms: self.started_at_unix_ms,
                finished_at_unix_ms: self.finished_at_unix_ms,
                domain_survivors: &self.domain_survivors,
            },
        )
    }

    /// Validates the evidence against the run it claims to answer.
    ///
    /// # Errors
    ///
    /// Fails when the topology, session nonce, request digest, descriptor
    /// binding digest, profile digest, assigned identity, ordering of the
    /// observed timestamps, or the evidence digest is inconsistent.
    pub(crate) fn validate_for(
        &self,
        session: &MacosDevelopmentHelperSession,
        run: &MacosDevelopmentRunRequest,
    ) -> Result<(), MacosDevelopmentHelperError> {
        session.validate()?;
        self.identity.validate()?;
        if self.topology != MacosHelperTopology::Development
            || self.purpose != run.purpose
            || self.session_nonce != session.session_nonce
            || self.request_digest != run.request.request_digest
            || self.seatbelt_profile_digest != run.request.seatbelt_profile_digest
            || self.descriptor_bindings_digest
                != descriptor_bindings_digest(&run.request.descriptor_bindings)?
            || self.argv != run.request.argv
            || self.environment != run.request.environment
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_evidence.binding",
                "run evidence differs from the run it claims to answer",
            ));
        }
        if self.launch_pid == 0
            || self.process_group_id == 0
            || self.started_at_unix_ms == 0
            || self.finished_at_unix_ms < self.started_at_unix_ms
            || self.started_at_unix_ms < session.authenticated_at_unix_ms
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_evidence.observations",
                "run observations are not ordered or identify no process",
            ));
        }
        if self.evidence_digest != self.computed_digest()? {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_evidence.evidence_digest",
                "evidence digest does not bind the canonical preimage",
            ));
        }
        // The in-process applier's whole safety argument is that the launching
        // task had exactly one thread when it forked. Evidence that claims the
        // applier without that measurement is refused here, so no reader ever
        // has to take the precondition on trust.
        if self.profile_applier == MacosDevelopmentProfileApplier::InProcessFork
            && self.launcher_state.thread_count != 1
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_evidence.profile_applier",
                "in-process profile application requires a single-threaded launch component",
            ));
        }
        Ok(())
    }

    /// Whether the profile was applied inside the process that became the
    /// target, with the launcher observing the descriptor table it inherited.
    pub(crate) fn applied_profile_in_process(&self) -> bool {
        self.profile_applier == MacosDevelopmentProfileApplier::InProcessFork
    }

    /// Whether the leader exited normally with a zero status.
    pub(crate) fn exited_zero(&self) -> bool {
        self.termination == MacosDevelopmentTermination::Exited(0)
    }
}

/// Writes one development payload as a framed canonical message.
fn write_development_frame<T: Serialize>(
    writer: &mut impl Write,
    kind: MacosHelperFrameKind,
    value: &T,
) -> Result<(), MacosDevelopmentHelperError> {
    debug_assert!(kind.development(), "development frames only");
    let payload = encode_canonical_payload(kind, value)?;
    write_frame(writer, kind, &payload)?;
    Ok(())
}

/// Reads exactly one framed development payload of the expected class.
fn read_development_frame<T>(
    reader: &mut impl Read,
    expected: MacosHelperFrameKind,
) -> Result<T, MacosDevelopmentHelperError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let (observed, payload) = read_frame(reader)?;
    if observed != expected {
        return Err(MacosDevelopmentHelperError::Transport(format!(
            "expected a {expected} frame but received a {observed} frame"
        )));
    }
    Ok(decode_canonical_payload(expected, &payload)?)
}

/// The only profile applier the development helper will ever execute.
pub(crate) const MACOS_DEVELOPMENT_PROFILE_APPLIER: &str = "/usr/bin/sandbox-exec";

/// The process enumerator the development helper uses for domain readback.
const MACOS_DEVELOPMENT_PROCESS_ENUMERATOR: &str = "/bin/ps";

const DEVELOPMENT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const DEVELOPMENT_DRAIN_GRACE: Duration = Duration::from_millis(250);
/// How long the launcher waits for a forked child to reach its pre-`execve`
/// observation point before treating the launch as failed. Generous, because
/// exceeding it is a hard refusal rather than a retry.
const DEVELOPMENT_STOP_WAIT: Duration = Duration::from_secs(10);

/// Whether this process may act as a single-threaded launch component.
///
/// The architecture's launch transaction forks "from the helper's
/// single-threaded launch component". This is that predicate, measured through
/// `libproc` rather than assumed: a helper hosted on a thread of a
/// multi-threaded image reports more than one thread and is refused, because
/// after such a fork the child would inherit locks no surviving thread can
/// release and `sandbox_init` allocates.
fn single_threaded_launch_component() -> bool {
    current_process_thread_count().is_ok_and(|threads| threads == 1)
}

/// The fixed development installation manifest.
///
/// Production fixes the Team ID, bundle IDs, protocol and policy versions,
/// private state root, three execution accounts, and allowed client
/// requirement in a notarized installation manifest. This is the development
/// equivalent: the client writes it into the dev state root before starting
/// the helper, and the helper will admit nothing that is not named here. In
/// particular a caller cannot add an executable search root, only the exact
/// entries in `executables` can ever be launched.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosDevelopmentHelperManifest {
    pub(crate) topology: MacosHelperTopology,
    pub(crate) protocol_version: u32,
    pub(crate) policy_version: u32,
    /// Exact code requirement the helper checks against its client's audit
    /// token before a single protocol byte is exchanged.
    pub(crate) client_requirement: String,
    pub(crate) workspace_grant_hash: Digest,
    pub(crate) execution_policy_hash: Digest,
    pub(crate) command_network: MacosHelperNetwork,
    /// Normalized identifier of the one staged workspace this helper serves.
    pub(crate) staged_workspace_id: String,
    /// Absolute path that identifier resolves to.
    pub(crate) staged_workspace_path: String,
    /// Fixed policy-entry identifier to absolute path map. Nothing else runs.
    pub(crate) executables: BTreeMap<String, String>,
}

impl MacosDevelopmentHelperManifest {
    /// Validates the manifest shape.
    ///
    /// # Errors
    ///
    /// Fails for an unsupported protocol version, a zero policy version, a
    /// blank client requirement, a staged workspace identifier containing path
    /// syntax, a relative staged workspace path, or an empty or non-absolute
    /// executable entry.
    pub(crate) fn validate(&self) -> Result<(), MacosDevelopmentHelperError> {
        if self.protocol_version != MACOS_HELPER_PROTOCOL_VERSION || self.policy_version == 0 {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_manifest.versions",
                "manifest versions are outside the admitted range",
            ));
        }
        if self.client_requirement.trim().is_empty() {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_manifest.client_requirement",
                "a development helper still requires an exact client requirement",
            ));
        }
        validate_development_identifier(
            "development_manifest.staged_workspace_id",
            &self.staged_workspace_id,
        )?;
        if !Path::new(&self.staged_workspace_path).is_absolute() {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_manifest.staged_workspace_path",
                "the staged workspace path must be absolute",
            ));
        }
        if self.executables.is_empty() {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_manifest.executables",
                "the executable policy table cannot be empty",
            ));
        }
        for (entry, path) in &self.executables {
            validate_development_identifier("development_manifest.executables", entry)?;
            if !Path::new(path).is_absolute() {
                return Err(MacosDevelopmentHelperError::invalid(
                    "development_manifest.executables",
                    "every admitted executable must be named by an absolute path",
                ));
            }
        }
        Ok(())
    }

    /// Reads and validates the manifest inside one development state root.
    ///
    /// # Errors
    ///
    /// Fails when the manifest is missing, is not canonical JSON, or fails
    /// validation.
    pub(crate) fn read(
        state_root: &MacosDevelopmentStateRoot,
    ) -> Result<Self, MacosDevelopmentHelperError> {
        state_root.validate_private()?;
        let bytes = fs::read(state_root.path().join("manifest.json")).map_err(|error| {
            MacosDevelopmentHelperError::io("read development manifest", &error)
        })?;
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|error| MacosDevelopmentHelperError::Encoding(error.to_string()))?;
        let canonical = serde_json::to_vec(&manifest)
            .map_err(|error| MacosDevelopmentHelperError::Encoding(error.to_string()))?;
        if canonical != bytes {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_manifest.encoding",
                "the manifest is not its unique canonical encoding",
            ));
        }
        manifest.validate()?;
        Ok(manifest)
    }

    /// Writes the manifest into one development state root.
    ///
    /// # Errors
    ///
    /// Fails when the manifest is invalid or cannot be written.
    pub(crate) fn write(
        &self,
        state_root: &MacosDevelopmentStateRoot,
    ) -> Result<(), MacosDevelopmentHelperError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self)
            .map_err(|error| MacosDevelopmentHelperError::Encoding(error.to_string()))?;
        fs::write(state_root.path().join("manifest.json"), &canonical)
            .map_err(|error| MacosDevelopmentHelperError::io("write development manifest", &error))
    }
}

/// One executable the manifest admits, with its observed identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedDevelopmentExecutable {
    path: PathBuf,
    digest: Digest,
}

impl ResolvedDevelopmentExecutable {
    /// Observes one absolute executable path.
    ///
    /// # Errors
    ///
    /// Fails when the path is not an existing regular file or cannot be read.
    pub(crate) fn observe(path: &Path) -> Result<Self, MacosDevelopmentHelperError> {
        let canonical = fs::canonicalize(path).map_err(|error| {
            MacosDevelopmentHelperError::io("canonicalize development executable", &error)
        })?;
        let metadata = fs::symlink_metadata(&canonical).map_err(|error| {
            MacosDevelopmentHelperError::io("inspect development executable", &error)
        })?;
        if !metadata.is_file() {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_executable.kind",
                "an admitted executable must be a regular file",
            ));
        }
        let bytes = fs::read(&canonical).map_err(|error| {
            MacosDevelopmentHelperError::io("read development executable", &error)
        })?;
        Ok(Self {
            path: canonical,
            digest: Digest::sha256(&bytes),
        })
    }

    /// Absolute path of the observed executable.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Complete content digest of the observed executable.
    pub(crate) const fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// The running development helper.
pub(crate) struct MacosDevelopmentHelper {
    helper_topology: MacosDevelopmentHelperTopology,
    state_root: MacosDevelopmentStateRoot,
    manifest: MacosDevelopmentHelperManifest,
    pool: MacosDevelopmentIdentityPool,
    listener: UnixListener,
    launcher: ResolvedDevelopmentExecutable,
    /// The helper's own image, resolved only when this process is a
    /// single-threaded launch component and may therefore apply the profile in
    /// process. `None` means every run falls back to the separate applier.
    own_image: Option<ResolvedDevelopmentExecutable>,
    executables: BTreeMap<String, ResolvedDevelopmentExecutable>,
    workspace_root: PathBuf,
}

impl MacosDevelopmentHelper {
    /// Binds the helper's socket inside an existing development state root.
    ///
    /// # Errors
    ///
    /// Fails when the state root is not owner private, the manifest is
    /// invalid, an admitted executable cannot be observed, or the socket
    /// cannot be bound.
    pub(crate) fn bind(
        root: PathBuf,
        helper_topology: MacosDevelopmentHelperTopology,
    ) -> Result<Self, MacosDevelopmentHelperError> {
        let state_root = MacosDevelopmentStateRoot::adopt(root)?;
        let manifest = MacosDevelopmentHelperManifest::read(&state_root)?;
        let pool = MacosDevelopmentIdentityPool::open(&state_root)?;
        let launcher =
            ResolvedDevelopmentExecutable::observe(Path::new(MACOS_DEVELOPMENT_PROFILE_APPLIER))?;
        let mut executables = BTreeMap::new();
        for (entry, path) in &manifest.executables {
            executables.insert(
                entry.clone(),
                ResolvedDevelopmentExecutable::observe(Path::new(path))?,
            );
        }
        let workspace_root =
            fs::canonicalize(&manifest.staged_workspace_path).map_err(|error| {
                MacosDevelopmentHelperError::io("canonicalize staged workspace", &error)
            })?;
        let socket = state_root.socket_path();
        let listener = UnixListener::bind(&socket).map_err(|error| {
            MacosDevelopmentHelperError::io("bind development helper socket", &error)
        })?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(|error| {
            MacosDevelopmentHelperError::io("restrict development helper socket", &error)
        })?;
        // Resolving the helper's own image reads and digests the whole binary,
        // so it happens once, and only when this process is actually eligible
        // to be a single-threaded launch component. A helper hosted on a thread
        // of a multi-threaded image never becomes eligible, so it never pays
        // the cost and never forks.
        let own_image = if single_threaded_launch_component() {
            std::env::current_exe()
                .ok()
                .and_then(|path| ResolvedDevelopmentExecutable::observe(&path).ok())
        } else {
            None
        };
        Ok(Self {
            helper_topology,
            state_root,
            manifest,
            pool,
            listener,
            launcher,
            own_image,
            executables,
            workspace_root,
        })
    }

    /// Serves exactly one authenticated development connection, then returns.
    ///
    /// # Errors
    ///
    /// Fails when the connection cannot be accepted, the peer does not satisfy
    /// the manifest's client requirement, or the session cannot be published.
    pub(crate) fn serve_one_connection(&self) -> Result<(), MacosDevelopmentHelperError> {
        let (mut stream, _address) = self.listener.accept().map_err(|error| {
            MacosDevelopmentHelperError::io("accept development connection", &error)
        })?;
        let requirement = MacosPeerCodeRequirement::new(&self.manifest.client_requirement)
            .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
        let peer = authenticate_peer(stream.as_fd(), &requirement)
            .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
        let own = own_code_identity()?;
        let helper_requirement =
            MacosPeerCodeRequirement::pinned_to_code_directory_hash(&own.code_directory_hash)
                .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
        let mut session = MacosDevelopmentHelperSession {
            topology: MacosHelperTopology::Development,
            helper_topology: self.helper_topology,
            protocol_version: self.manifest.protocol_version,
            policy_version: self.manifest.policy_version,
            session_nonce: Digest::sha256(
                format!("{}:{:x}", std::process::id(), unix_time_nanos()?).as_bytes(),
            ),
            helper_binary_digest: own.identity_digest.clone(),
            helper_requirement_digest: helper_requirement.digest(),
            client_binary_digest: peer.code_identity_digest(),
            client_requirement_digest: peer.requirement_digest().clone(),
            identity_pool_digest: self.pool.pool_digest().clone(),
            workspace_grant_hash: self.manifest.workspace_grant_hash.clone(),
            execution_policy_hash: self.manifest.execution_policy_hash.clone(),
            command_network: self.manifest.command_network,
            authenticated_at_unix_ms: unix_time_ms()?,
            peer_requirement_matched: true,
            // Pin the loaded image CDHash and filesystem attestation. The client
            // independently verifies the attestation kind.
            attestation: own.attestation_for(audit_installed_binary(&own_program()?)?),
            // Creating an execution account needs root; this helper has none.
            dedicated_account_pool: false,
            session_digest: Digest::sha256(&[]),
        };
        session.session_digest = session.computed_digest()?;
        session.validate()?;
        write_development_frame(
            &mut stream,
            MacosHelperFrameKind::DevelopmentSession,
            &session,
        )?;
        let reservation = self.pool.reserve(&development_generation_id()?)?;
        self.serve_runs(&mut stream, &session, &reservation)
    }

    fn serve_runs(
        &self,
        stream: &mut UnixStream,
        session: &MacosDevelopmentHelperSession,
        reservation: &MacosDevelopmentReservation,
    ) -> Result<(), MacosDevelopmentHelperError> {
        for _served in 0..MAX_MACOS_DEVELOPMENT_RUNS_PER_SESSION {
            let run: MacosDevelopmentRunRequest =
                match read_development_frame(stream, MacosHelperFrameKind::DevelopmentRunRequest) {
                    Ok(run) => run,
                    Err(MacosDevelopmentHelperError::Transport(detail))
                        if detail.contains("ended before") =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
            run.validate_for_session(session)?;
            let evidence = self.execute_run(stream, session, reservation, &run)?;
            write_development_frame(
                stream,
                MacosHelperFrameKind::DevelopmentRunEvidence,
                &evidence,
            )?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one development launch transaction keeps executable resolution, the descriptor-exec probe, the suspended spawn, held readback, bounded draining, deadline enforcement, whole-group termination, and domain enumeration in one auditable order"
    )]
    fn execute_run(
        &self,
        stream: &mut UnixStream,
        session: &MacosDevelopmentHelperSession,
        reservation: &MacosDevelopmentReservation,
        run: &MacosDevelopmentRunRequest,
    ) -> Result<MacosDevelopmentRunEvidence, MacosDevelopmentHelperError> {
        self.state_root.validate_private()?;
        if run.request.staged_workspace_id != self.manifest.staged_workspace_id {
            return Err(MacosDevelopmentHelperError::RefusedBeforeLaunch {
                detail: "the request names a staged workspace this helper does not serve".into(),
            });
        }
        let executable = self.resolve_executable(&run.request.executable_identity)?;
        let program = executable
            .path()
            .to_str()
            .ok_or_else(|| {
                MacosDevelopmentHelperError::invalid(
                    "development_run.executable",
                    "an admitted executable path must be UTF-8",
                )
            })?
            .to_owned();
        if run.request.argv.first().map(String::as_str) != Some(program.as_str()) {
            return Err(MacosDevelopmentHelperError::RefusedBeforeLaunch {
                detail: "argv[0] must be the exact resolved executable path".into(),
            });
        }

        let working_directory = self.open_working_directory(&run.request)?;
        let descriptor_exec = if run.probe_descriptor_exec {
            probe_descriptor_exec(executable.path(), working_directory.as_fd())
        } else {
            MacosDevelopmentDescriptorExecProbe {
                attempted: false,
                supported: false,
                errno: 0,
            }
        };

        let null = File::options()
            .read(true)
            .open("/dev/null")
            .map_err(|error| MacosDevelopmentHelperError::io("open /dev/null", &error))?;
        let (mut parent_out, child_out) = UnixStream::pair()
            .map_err(|error| MacosDevelopmentHelperError::io("create stdout channel", &error))?;
        let (mut parent_err, child_err) = UnixStream::pair()
            .map_err(|error| MacosDevelopmentHelperError::io("create stderr channel", &error))?;

        // Applier selection. In process whenever this helper is a genuinely
        // single-threaded launch component, which is the precondition that
        // makes `fork` followed by `sandbox_init` safe; otherwise the separate
        // applier program, which is safe but unobservable at the target's exec.
        let launcher_state = MacosDevelopmentLauncherState {
            thread_count: current_process_thread_count().map_err(|error| {
                MacosDevelopmentHelperError::io("measure launcher thread count", &error)
            })?,
            descriptor_count: u32::try_from(
                observe_child_descriptors(std::process::id().cast_signed())
                    .map_err(|error| {
                        MacosDevelopmentHelperError::io("observe launcher descriptors", &error)
                    })?
                    .map_or(0, |observation| observation.descriptors.len()),
            )
            .unwrap_or(u32::MAX),
        };
        let in_process = launcher_state.thread_count == 1 && self.own_image.is_some();
        let (profile_applier, applier) = if in_process {
            (
                MacosDevelopmentProfileApplier::InProcessFork,
                self.own_image.as_ref().unwrap_or(&self.launcher),
            )
        } else {
            (
                MacosDevelopmentProfileApplier::SeparateProgram,
                &self.launcher,
            )
        };

        let started_at_unix_ms = unix_time_ms()?;
        let started = Instant::now();
        let pid = if in_process {
            // The profile text is handed through byte for byte: it is the exact
            // string whose digest `validate` already matched against the
            // request's `seatbelt_profile_digest`, never re-rendered here.
            fork_apply_seatbelt_and_exec(
                executable.path(),
                &run.request.argv,
                &run.request.environment,
                &run.seatbelt_profile,
                working_directory.as_fd(),
                [null.as_fd(), child_out.as_fd(), child_err.as_fd()],
            )
            .map_err(|error| {
                MacosDevelopmentHelperError::io("fork the development launch component", &error)
            })?
        } else {
            let mut argv = vec![
                MACOS_DEVELOPMENT_PROFILE_APPLIER.to_owned(),
                "-p".to_owned(),
                run.seatbelt_profile.clone(),
            ];
            argv.extend(run.request.argv.iter().cloned());
            spawn_stdio_suspended(
                Path::new(MACOS_DEVELOPMENT_PROFILE_APPLIER),
                &argv,
                &run.request.environment,
                working_directory.as_fd(),
                [null.as_fd(), child_out.as_fd(), child_err.as_fd()],
            )
            .map_err(|error| MacosDevelopmentHelperError::io("spawn development child", &error))?
        };
        drop(child_out);
        drop(child_err);

        // Both paths hand back a stopped child. `posix_spawn` stops it before
        // its first instruction; the forked child stops itself after applying
        // the profile and proving its own table, which is one instruction
        // before `execve` of the target.
        let held = if in_process {
            await_stopped_child(pid, DEVELOPMENT_STOP_WAIT).map_err(|error| {
                MacosDevelopmentHelperError::io("await the forked development child", &error)
            })?
        } else {
            observe_child_descriptors(pid).map_err(|error| {
                MacosDevelopmentHelperError::io("observe held development child", &error)
            })?
        };
        let (held_child_descriptors, held_session_leader, process_group_id) = match held {
            Some(observation) => (
                observation.descriptors,
                observation.session_leader,
                observation.process_group_id,
            ),
            None => (Vec::new(), false, 0),
        };
        continue_stdio_child(pid)
            .map_err(|error| MacosDevelopmentHelperError::io("resume development child", &error))?;

        parent_out.set_nonblocking(true).map_err(|error| {
            MacosDevelopmentHelperError::io("set stdout channel nonblocking", &error)
        })?;
        parent_err.set_nonblocking(true).map_err(|error| {
            MacosDevelopmentHelperError::io("set stderr channel nonblocking", &error)
        })?;

        let deadline = development_deadline(run.request.deadline_unix_ms, started_at_unix_ms);
        let mut drain = DevelopmentDrain::new(run.request.max_output_bytes);
        let leader = Pid::from_raw(pid).ok_or_else(|| {
            MacosDevelopmentHelperError::invalid(
                "development_run.pid",
                "the spawned pid is not a valid process identifier",
            )
        })?;
        let group = Pid::from_raw(i32::try_from(process_group_id).unwrap_or(pid)).unwrap_or(leader);
        let mut wall_clock_terminated = false;
        let mut reaped = None;
        loop {
            let progressed = drain.pump(stream, &mut parent_out, MacosDevelopmentStream::Stdout)?
                | drain.pump(stream, &mut parent_err, MacosDevelopmentStream::Stderr)?;
            if reaped.is_none() {
                reaped = reap_without_blocking(leader)?;
            }
            if drain.finished() && reaped.is_some() {
                break;
            }
            if started.elapsed() >= deadline || drain.overflowed() {
                wall_clock_terminated = started.elapsed() >= deadline;
                terminate_development_domain(group, leader);
                let grace = Instant::now();
                while grace.elapsed() < DEVELOPMENT_DRAIN_GRACE {
                    let _ignored =
                        drain.pump(stream, &mut parent_out, MacosDevelopmentStream::Stdout)?;
                    let _ignored =
                        drain.pump(stream, &mut parent_err, MacosDevelopmentStream::Stderr)?;
                    if reaped.is_none() {
                        reaped = reap_without_blocking(leader)?;
                    }
                    if reaped.is_some() {
                        break;
                    }
                    std::thread::sleep(DEVELOPMENT_POLL_INTERVAL);
                }
                if reaped.is_none() {
                    reaped = reap_blocking(leader)?;
                }
                break;
            }
            if !progressed {
                std::thread::sleep(DEVELOPMENT_POLL_INTERVAL);
            }
        }
        let termination = reaped.ok_or_else(|| {
            MacosDevelopmentHelperError::invalid(
                "development_run.termination",
                "the development leader produced no terminal status",
            )
        })?;
        // A forked child that failed one of its fixed setup stages exits with a
        // reserved status naming that stage. Surfacing it here keeps the
        // diagnostic instead of letting it degrade into an unexplained
        // zero-process-group evidence rejection later.
        if in_process
            && let MacosDevelopmentTermination::Exited(status) = termination
            && let Some(stage) = child_setup_stage(status)
        {
            return Err(MacosDevelopmentHelperError::RefusedBeforeLaunch {
                detail: format!(
                    "the forked launch component could not {stage} (exit {status}); no project \
                     code ran"
                ),
            });
        }
        let finished_at_unix_ms = unix_time_ms()?;

        // Whole-group termination is always attempted, even for a clean exit,
        // and the enumeration afterwards is what the evidence reports. It is a
        // process-group readback, not the UID-domain readback production
        // requires, which is exactly why the dev backend never claims
        // `DescendantDomainKill`.
        terminate_development_domain(group, leader);
        let domain_survivors = enumerate_process_group(process_group_id)?;

        let (stdout, stderr) = drain.into_stream_evidence();
        let mut evidence = MacosDevelopmentRunEvidence {
            topology: MacosHelperTopology::Development,
            purpose: run.purpose,
            session_nonce: session.session_nonce.clone(),
            request_digest: run.request.request_digest.clone(),
            identity: reservation.record().clone(),
            descriptor_bindings_digest: descriptor_bindings_digest(
                &run.request.descriptor_bindings,
            )?,
            seatbelt_profile_digest: run.request.seatbelt_profile_digest.clone(),
            profile_applier,
            launcher_state,
            launcher_path: applier.path().to_string_lossy().into_owned(),
            launcher_digest: applier.digest().clone(),
            executable_path: program,
            executable_digest: executable.digest().clone(),
            descriptor_exec,
            descendant_ceiling: observe_descendant_ceiling(run.request.max_processes)?,
            launch_pid: u32::try_from(pid).unwrap_or(0),
            process_group_id,
            held_child_descriptors,
            held_session_leader,
            argv: run.request.argv.clone(),
            environment: run.request.environment.clone(),
            working_directory: run.request.relative_working_directory.clone(),
            termination,
            stdout,
            stderr,
            wall_clock_terminated,
            started_at_unix_ms,
            finished_at_unix_ms,
            domain_survivors,
            evidence_digest: Digest::sha256(&[]),
        };
        evidence.evidence_digest = evidence.computed_digest()?;
        evidence.validate_for(session, run)?;
        Ok(evidence)
    }

    fn resolve_executable(
        &self,
        identity: &MacosExecutableIdentity,
    ) -> Result<ResolvedDevelopmentExecutable, MacosDevelopmentHelperError> {
        let (entry, expected) = match identity {
            MacosExecutableIdentity::SystemToolchain {
                policy_entry_id,
                binary_digest,
            } => (policy_entry_id.clone(), binary_digest.clone()),
            MacosExecutableIdentity::StagedWorkspace { .. } => {
                return Err(MacosDevelopmentHelperError::RefusedBeforeLaunch {
                    detail: "the development helper admits only compiled policy executables".into(),
                });
            }
        };
        let resolved = self.executables.get(&entry).ok_or_else(|| {
            MacosDevelopmentHelperError::RefusedBeforeLaunch {
                detail: "the request names an executable outside the compiled dev policy".into(),
            }
        })?;
        let observed = ResolvedDevelopmentExecutable::observe(resolved.path())?;
        if observed.digest() != &expected || observed.digest() != resolved.digest() {
            return Err(MacosDevelopmentHelperError::RefusedBeforeLaunch {
                detail: "the admitted executable's contents changed since the helper started"
                    .into(),
            });
        }
        Ok(observed)
    }

    fn open_working_directory(
        &self,
        request: &MacosHelperLaunchRequest,
    ) -> Result<OwnedFd, MacosDevelopmentHelperError> {
        let mut path = self.workspace_root.clone();
        if request.relative_working_directory != "." {
            path.push(&request.relative_working_directory);
        }
        rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            MacosDevelopmentHelperError::io(
                "open development working directory",
                &io::Error::from_raw_os_error(error.raw_os_error()),
            )
        })
    }
}

struct OwnCodeIdentity {
    identity_digest: Digest,
    code_directory_hash: Vec<u8>,
    apple_anchored: bool,
}

impl OwnCodeIdentity {
    /// The attestation this image can honestly publish for its install audit.
    ///
    /// Mirrors `MacosAuthenticatedPeer::attestation_for` for the case where the
    /// image being described is the running process's own.
    const fn attestation_for(
        &self,
        install_audit: MacosHelperInstallAudit,
    ) -> MacosHelperAttestation {
        if self.apple_anchored {
            MacosHelperAttestation::PublisherCodeIdentity { install_audit }
        } else {
            MacosHelperAttestation::LocalCodeIdentity { install_audit }
        }
    }
}

/// Accumulates one run's two streams while forwarding bounded chunks.
struct DevelopmentDrain {
    maximum_bytes: u64,
    stdout: DevelopmentStreamState,
    stderr: DevelopmentStreamState,
    sequence: u64,
}

#[derive(Default)]
struct DevelopmentStreamState {
    bytes: Vec<u8>,
    length: u64,
    chunks: u64,
    maximum_chunk: u64,
    closed: bool,
}

impl DevelopmentDrain {
    fn new(maximum_bytes: u64) -> Self {
        Self {
            maximum_bytes,
            stdout: DevelopmentStreamState::default(),
            stderr: DevelopmentStreamState::default(),
            sequence: 0,
        }
    }

    fn finished(&self) -> bool {
        self.stdout.closed && self.stderr.closed
    }

    fn overflowed(&self) -> bool {
        self.stdout
            .length
            .saturating_add(self.stderr.length)
            .saturating_sub(self.maximum_bytes)
            > 0
    }

    fn pump(
        &mut self,
        stream: &mut UnixStream,
        source: &mut UnixStream,
        which: MacosDevelopmentStream,
    ) -> Result<bool, MacosDevelopmentHelperError> {
        let state = match which {
            MacosDevelopmentStream::Stdout => &mut self.stdout,
            MacosDevelopmentStream::Stderr => &mut self.stderr,
        };
        if state.closed {
            return Ok(false);
        }
        let mut buffer = [0_u8; MAX_MACOS_DEVELOPMENT_CHUNK_BYTES];
        match source.read(&mut buffer) {
            Ok(0) => {
                state.closed = true;
                Ok(true)
            }
            Ok(count) => {
                let chunk = &buffer[..count];
                state.length = state.length.saturating_add(count as u64);
                state.chunks = state.chunks.saturating_add(1);
                state.maximum_chunk = state.maximum_chunk.max(count as u64);
                state.bytes.extend_from_slice(chunk);
                self.sequence = self.sequence.saturating_add(1);
                write_development_frame(
                    stream,
                    MacosHelperFrameKind::DevelopmentRunChunk,
                    &MacosDevelopmentRunChunk {
                        topology: MacosHelperTopology::Development,
                        stream: which,
                        sequence: self.sequence,
                        bytes_hex: lower_hex(chunk),
                    },
                )?;
                Ok(true)
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => Ok(true),
            Err(_) => {
                state.closed = true;
                Ok(true)
            }
        }
    }

    fn into_stream_evidence(
        self,
    ) -> (
        MacosDevelopmentStreamEvidence,
        MacosDevelopmentStreamEvidence,
    ) {
        (
            MacosDevelopmentStreamEvidence {
                complete_digest: Digest::sha256(&self.stdout.bytes),
                complete_length: self.stdout.length,
                chunk_count: self.stdout.chunks,
                maximum_chunk_bytes: self.stdout.maximum_chunk,
            },
            MacosDevelopmentStreamEvidence {
                complete_digest: Digest::sha256(&self.stderr.bytes),
                complete_length: self.stderr.length,
                chunk_count: self.stderr.chunks,
                maximum_chunk_bytes: self.stderr.maximum_chunk,
            },
        )
    }
}

fn development_deadline(deadline_unix_ms: u64, started_at_unix_ms: u64) -> Duration {
    Duration::from_millis(deadline_unix_ms.saturating_sub(started_at_unix_ms).max(1))
}

fn reap_without_blocking(
    leader: Pid,
) -> Result<Option<MacosDevelopmentTermination>, MacosDevelopmentHelperError> {
    match rustix::process::waitpid(Some(leader), rustix::process::WaitOptions::NOHANG) {
        Ok(Some((_, status))) => Ok(Some(termination_from_wait_status(status))),
        Ok(None) => Ok(None),
        Err(error) => Err(MacosDevelopmentHelperError::io(
            "reap development leader",
            &io::Error::from_raw_os_error(error.raw_os_error()),
        )),
    }
}

fn reap_blocking(
    leader: Pid,
) -> Result<Option<MacosDevelopmentTermination>, MacosDevelopmentHelperError> {
    match rustix::process::waitpid(Some(leader), rustix::process::WaitOptions::empty()) {
        Ok(Some((_, status))) => Ok(Some(termination_from_wait_status(status))),
        Ok(None) => Ok(None),
        Err(error) => Err(MacosDevelopmentHelperError::io(
            "reap development leader",
            &io::Error::from_raw_os_error(error.raw_os_error()),
        )),
    }
}

fn termination_from_wait_status(
    status: rustix::process::WaitStatus,
) -> MacosDevelopmentTermination {
    if let Some(signal) = status.terminating_signal() {
        return MacosDevelopmentTermination::Signaled(signal);
    }
    MacosDevelopmentTermination::Exited(status.exit_status().unwrap_or(-1))
}

fn terminate_development_domain(group: Pid, leader: Pid) {
    let _ignored = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    let _ignored = rustix::process::kill_process(leader, rustix::process::Signal::KILL);
}

/// Enumerates every process currently sharing one process group.
///
/// This is an operating-system readback through `/bin/ps` rather than an
/// in-process flag, but it is a *process-group* readback. Production requires
/// enumeration of an otherwise-unused real UID precisely because a descendant
/// can leave a process group with `setsid`; that is why nothing derived from
/// this function is ever reported as whole-domain cleanup.
fn enumerate_process_group(process_group_id: u32) -> Result<Vec<u32>, MacosDevelopmentHelperError> {
    if process_group_id == 0 {
        return Ok(Vec::new());
    }
    let output = Command::new(MACOS_DEVELOPMENT_PROCESS_ENUMERATOR)
        .args(["-A", "-o", "pid=,pgid="])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| MacosDevelopmentHelperError::io("enumerate process group", &error))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut members = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(member), Some(group)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (Ok(member), Ok(group)) = (member.parse::<u32>(), group.parse::<u32>()) else {
            continue;
        };
        if group == process_group_id {
            members.push(member);
        }
    }
    members.sort_unstable();
    members.dedup();
    Ok(members)
}

/// Measures the descendant ceiling this host can actually install.
fn observe_descendant_ceiling(
    requested_max_processes: u32,
) -> Result<MacosDevelopmentDescendantCeiling, MacosDevelopmentHelperError> {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nproc);
    let output = Command::new(MACOS_DEVELOPMENT_PROCESS_ENUMERATOR)
        .args([
            "-u",
            &rustix::process::getuid().as_raw().to_string(),
            "-o",
            "pid=",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| MacosDevelopmentHelperError::io("enumerate uid processes", &error))?;
    let count = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    Ok(MacosDevelopmentDescendantCeiling {
        requested_max_processes,
        real_uid_process_count: u32::try_from(count).unwrap_or(u32::MAX),
        // A per-UID ceiling is meaningless while the domain shares the
        // developer's own UID, so none is installed and none is claimed.
        rlimit_nproc_applied: false,
        rlimit_nproc_soft: limit.current.unwrap_or(0),
    })
}

/// Live probe for descriptor exec.
///
/// The helper opens the resolved executable, forms `/dev/fd/N`, and asks the
/// kernel to spawn it. On macOS 15 this fails with `EACCES` because the
/// `fdesc` node is not executable and the platform offers no `fexecve`. The
/// probe never runs the target program: a successful spawn is immediately
/// killed and reaped.
fn probe_descriptor_exec(
    executable: &Path,
    working_directory: BorrowedFd<'_>,
) -> MacosDevelopmentDescriptorExecProbe {
    let refused = |errno: i32| MacosDevelopmentDescriptorExecProbe {
        attempted: true,
        supported: false,
        errno,
    };
    let Ok(held) = File::open(executable) else {
        return refused(0);
    };
    let Ok(null) = File::options().read(true).write(true).open("/dev/null") else {
        return refused(0);
    };
    let path = PathBuf::from(format!("/dev/fd/{}", held.as_raw_fd()));
    let argv = vec![
        path.to_string_lossy().into_owned(),
        "--grok-build-descriptor-exec-probe".to_owned(),
    ];
    match spawn_stdio_suspended(
        &path,
        &argv,
        &BTreeMap::new(),
        working_directory,
        [null.as_fd(), null.as_fd(), null.as_fd()],
    ) {
        Ok(pid) => {
            if let Some(pid) = Pid::from_raw(pid) {
                let _ignored = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                // A suspended child may keep one SIGKILL pending. Re-signal and reap within
                // a deadline instead of blocking in `waitpid`.
                let _ignored = reap_exact_condemned_child(pid);
            }
            MacosDevelopmentDescriptorExecProbe {
                attempted: true,
                supported: true,
                errno: 0,
            }
        }
        Err(error) => refused(error.raw_os_error().unwrap_or(0)),
    }
}

fn development_generation_id() -> Result<String, MacosDevelopmentHelperError> {
    Ok(format!(
        "gen-{}-{:x}",
        std::process::id(),
        unix_time_nanos()?
    ))
}

/// Runs the development helper from its bin target.
///
/// The single argument is the development state root the client created and
/// wrote its manifest into.
///
/// # Errors
///
/// Fails when the argument is missing, the state root is not owner private,
/// the manifest is invalid, or the connection cannot be served.
pub(crate) fn run_development_helper_main(
    arguments: &[OsString],
) -> Result<(), MacosDevelopmentHelperError> {
    let root = arguments.first().ok_or_else(|| {
        MacosDevelopmentHelperError::invalid(
            "development_helper.arguments",
            "the development helper requires exactly one state-root argument",
        )
    })?;
    let helper = MacosDevelopmentHelper::bind(
        PathBuf::from(root),
        MacosDevelopmentHelperTopology::SeparateProcess,
    )?;
    helper.serve_one_connection()
}

/// File name of the development helper's bin target.
pub(crate) const MACOS_DEVELOPMENT_HELPER_PROGRAM: &str = "grok-build-dev-helper";

const DEVELOPMENT_SOCKET_WAIT: Duration = Duration::from_secs(10);

/// Everything the client must fix before the helper starts.
#[derive(Clone, Debug)]
pub(crate) struct MacosDevelopmentHelperPlan {
    /// Non-zero policy version the session and every request carry.
    pub(crate) policy_version: u32,
    /// Compiled workspace grant hash the helper binds its session to.
    pub(crate) workspace_grant_hash: Digest,
    /// Compiled execution policy hash the helper binds its session to.
    pub(crate) execution_policy_hash: Digest,
    /// Network authority the compiled policy admits.
    pub(crate) command_network: MacosHelperNetwork,
    /// Normalized identifier of the one staged workspace the helper serves.
    pub(crate) staged_workspace_id: String,
    /// Absolute path that identifier resolves to.
    pub(crate) staged_workspace_path: PathBuf,
    /// Fixed policy-entry identifier to absolute executable path table.
    pub(crate) executables: BTreeMap<String, PathBuf>,
}

/// The client half of one development helper connection.
///
/// Authentication runs in both directions before any protocol byte is
/// exchanged. The client proves the helper is the exact child process it
/// spawned from a content-digested executable, then pins the connection to
/// that process's code-directory hash; the helper independently authenticates
/// the client against the code requirement fixed in the development manifest.
/// Neither direction produces a production-signed peer, and the published
/// session says so in a validated field.
#[derive(Debug)]
pub(crate) struct MacosDevelopmentHelperClient {
    state_root: MacosDevelopmentStateRoot,
    endpoint: MacosDevelopmentHelperTopology,
    child: Option<Child>,
    server: Option<std::thread::JoinHandle<Result<(), MacosDevelopmentHelperError>>>,
    stream: UnixStream,
    session: MacosDevelopmentHelperSession,
    manifest: MacosDevelopmentHelperManifest,
    next_request: u64,
}

impl MacosDevelopmentHelperClient {
    /// Starts a development helper and opens one authenticated session.
    ///
    /// # Errors
    ///
    /// Fails when the helper binary cannot be located next to the running
    /// executable, the dev state root cannot be created privately, the helper
    /// does not begin listening, peer authentication fails in either
    /// direction, or the published session fails the development contract.
    pub(crate) fn start(
        plan: &MacosDevelopmentHelperPlan,
        endpoint: MacosDevelopmentHelperTopology,
    ) -> Result<Self, MacosDevelopmentHelperError> {
        let state_root = MacosDevelopmentStateRoot::create()?;
        let own = own_code_identity()?;
        let client_requirement =
            MacosPeerCodeRequirement::pinned_to_code_directory_hash(&own.code_directory_hash)
                .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
        let mut executables = BTreeMap::new();
        for (entry, path) in &plan.executables {
            let text = path
                .to_str()
                .ok_or_else(|| {
                    MacosDevelopmentHelperError::invalid(
                        "development_plan.executables",
                        "an admitted executable path must be UTF-8",
                    )
                })?
                .to_owned();
            executables.insert(entry.clone(), text);
        }
        let manifest = MacosDevelopmentHelperManifest {
            topology: MacosHelperTopology::Development,
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: plan.policy_version,
            client_requirement: client_requirement.text().to_owned(),
            workspace_grant_hash: plan.workspace_grant_hash.clone(),
            execution_policy_hash: plan.execution_policy_hash.clone(),
            command_network: plan.command_network,
            staged_workspace_id: plan.staged_workspace_id.clone(),
            staged_workspace_path: plan
                .staged_workspace_path
                .to_str()
                .ok_or_else(|| {
                    MacosDevelopmentHelperError::invalid(
                        "development_plan.staged_workspace_path",
                        "the staged workspace path must be UTF-8",
                    )
                })?
                .to_owned(),
            executables,
        };
        manifest.write(&state_root)?;

        let (child, server) = match endpoint {
            MacosDevelopmentHelperTopology::SeparateProcess => {
                let program = locate_development_helper_program()?;
                let child = Command::new(&program)
                    .arg(state_root.path())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|error| {
                        MacosDevelopmentHelperError::io("spawn the development helper", &error)
                    })?;
                (Some(child), None)
            }
            MacosDevelopmentHelperTopology::SameImageThread => {
                let root = state_root.path().to_path_buf();
                let server = std::thread::Builder::new()
                    .name("grok-build-dev-helper".to_owned())
                    .spawn(move || {
                        MacosDevelopmentHelper::bind(
                            root,
                            MacosDevelopmentHelperTopology::SameImageThread,
                        )?
                        .serve_one_connection()
                    })
                    .map_err(|error| {
                        MacosDevelopmentHelperError::io(
                            "start the same-image development helper",
                            &error,
                        )
                    })?;
                (None, Some(server))
            }
        };
        let mut started = Self {
            state_root,
            endpoint,
            child,
            server,
            // Placeholder replaced immediately below; a failure before the
            // replacement drops the whole value and kills the helper.
            stream: UnixStream::pair()
                .map_err(|error| {
                    MacosDevelopmentHelperError::io("create placeholder channel", &error)
                })?
                .0,
            session: unauthenticated_placeholder_session(plan),
            manifest,
            next_request: 0,
        };
        started.connect_and_authenticate()?;
        Ok(started)
    }

    /// The on-disk image the helper this client started was loaded from.
    ///
    /// For the separate-process endpoint that is the helper binary Cargo built
    /// beside this executable; for the same-image endpoint the helper *is* this
    /// executable, so the two audits describe the same file, which is the
    /// honest answer, not a shortcut.
    fn helper_program(&self) -> Result<PathBuf, MacosDevelopmentHelperError> {
        match self.endpoint {
            MacosDevelopmentHelperTopology::SeparateProcess => locate_development_helper_program(),
            MacosDevelopmentHelperTopology::SameImageThread => own_program(),
        }
    }

    fn connect_and_authenticate(&mut self) -> Result<(), MacosDevelopmentHelperError> {
        let socket = self.state_root.socket_path();
        let waited = Instant::now();
        let stream = loop {
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    ) && waited.elapsed() < DEVELOPMENT_SOCKET_WAIT =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    return Err(MacosDevelopmentHelperError::io(
                        "connect to the development helper",
                        &error,
                    ));
                }
            }
        };
        let observed = observe_peer(stream.as_fd())
            .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
        let expected_pid = match (&self.child, self.endpoint) {
            (Some(child), MacosDevelopmentHelperTopology::SeparateProcess) => child.id(),
            (None, MacosDevelopmentHelperTopology::SameImageThread) => std::process::id(),
            _ => {
                return Err(MacosDevelopmentHelperError::invalid(
                    "development_client.endpoint",
                    "the helper endpoint does not match the process that was started",
                ));
            }
        };
        if observed.audit_token().process_id() != expected_pid {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_client.peer",
                "the socket peer is not the development helper this client started",
            ));
        }
        let requirement =
            MacosPeerCodeRequirement::pinned_to_code_directory_hash(observed.code_directory_hash())
                .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
        let peer = authenticate_peer(stream.as_fd(), &requirement)
            .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
        // The client's own filesystem reading of the helper binary it located,
        // taken here so the comparison below is against an independently
        // observed value rather than against the helper's own claim.
        let observed_install_audit = audit_installed_binary(&self.helper_program()?)?;
        self.stream = stream;
        let session: MacosDevelopmentHelperSession =
            read_development_frame(&mut self.stream, MacosHelperFrameKind::DevelopmentSession)
                .map_err(|error| self.server_refusal(&error))?;
        session.validate()?;
        let own = own_code_identity()?;
        if session.attestation.claims_publisher() && !peer.publisher_attested() {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_client.attestation",
                "the helper claims publisher attestation its loaded image cannot substantiate",
            ));
        }
        if session.attestation.install_audit() != Some(&observed_install_audit) {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_client.install_audit",
                "the helper's published install audit differs from this client's own reading",
            ));
        }
        if session.helper_binary_digest != peer.code_identity_digest()
            || session.helper_requirement_digest != requirement.digest()
            || session.client_binary_digest != own.identity_digest
            || session.identity_pool_digest == session.helper_binary_digest
            || session.workspace_grant_hash != self.manifest.workspace_grant_hash
            || session.execution_policy_hash != self.manifest.execution_policy_hash
            || session.command_network != self.manifest.command_network
            || session.policy_version != self.manifest.policy_version
            || session.helper_topology != self.endpoint
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_client.session",
                "the published development session does not bind the authenticated peers",
            ));
        }
        self.session = session;
        Ok(())
    }

    /// Replaces a transport failure with the server's own refusal when it has
    /// one, so a helper that refused before publishing is never reported as a
    /// bare truncated frame.
    fn server_refusal(
        &mut self,
        error: &MacosDevelopmentHelperError,
    ) -> MacosDevelopmentHelperError {
        if let Some(server) = self.server.take() {
            match server.join() {
                Ok(Err(refusal)) => return refusal,
                Ok(Ok(())) => {
                    return MacosDevelopmentHelperError::Transport(
                        "the same-image development helper returned without publishing a session"
                            .to_owned(),
                    );
                }
                Err(_panic) => {
                    return MacosDevelopmentHelperError::Transport(
                        "the same-image development helper panicked".to_owned(),
                    );
                }
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _ignored = child.kill();
            let _ignored = child.wait();
            if let Some(mut errors) = child.stderr.take() {
                let mut rendered = String::new();
                if errors.read_to_string(&mut rendered).is_ok() && !rendered.trim().is_empty() {
                    return MacosDevelopmentHelperError::Transport(rendered.trim().to_owned());
                }
            }
        }
        MacosDevelopmentHelperError::Transport(format!("no server handle was retained: {error}"))
    }

    /// The authenticated development session.
    pub(crate) const fn session(&self) -> &MacosDevelopmentHelperSession {
        &self.session
    }

    /// The development state root this client owns.
    pub(crate) fn state_root(&self) -> &Path {
        self.state_root.path()
    }

    /// Builds one canonical launch request bound to this session.
    ///
    /// # Errors
    ///
    /// Fails when the resulting request does not satisfy the production
    /// protocol's own `validate_retained` contract.
    pub(crate) fn build_request(
        &mut self,
        specification: &MacosDevelopmentRunSpecification<'_>,
    ) -> Result<MacosHelperLaunchRequest, MacosDevelopmentHelperError> {
        self.next_request = self.next_request.saturating_add(1);
        let sequence = self.next_request;
        let claimed_at_unix_ms = unix_time_ms()?;
        let preparation = MacosHelperPreparationBinding {
            contract_version: grok_build_core::CONTRACT_VERSION,
            attempt_id: format!("dev-attempt-{sequence}"),
            sprint_id: specification.sprint_id.to_owned(),
            launch_id: specification.launch_id.to_owned(),
            runner_session_id: specification.runner_session_id.to_owned(),
            cleanup_effect_id: format!("dev-cleanup-{sequence}"),
            input_snapshot: specification.input_snapshot.clone(),
            native_journal_id: format!("dev-native-journal-{sequence}"),
            expected_platform_binding_digest: Digest::sha256(
                format!("development-platform-binding-{sequence}").as_bytes(),
            ),
            claimed_at_unix_ms,
        };
        let mut request = MacosHelperLaunchRequest {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: self.session.policy_version,
            session_nonce: self.session.session_nonce.clone(),
            request_id: format!("dev-request-{sequence}"),
            preparation,
            runner_session_id: specification.runner_session_id.to_owned(),
            effect_id: specification.effect_id.to_owned(),
            workspace_grant_hash: self.session.workspace_grant_hash.clone(),
            execution_policy_hash: self.session.execution_policy_hash.clone(),
            staged_workspace_id: self.manifest.staged_workspace_id.clone(),
            executable_identity: MacosExecutableIdentity::SystemToolchain {
                policy_entry_id: specification.policy_entry_id.to_owned(),
                binary_digest: specification.executable_digest.clone(),
            },
            descriptor_bindings: development_descriptor_bindings(),
            argv: specification.argv.to_vec(),
            relative_working_directory: specification.relative_working_directory.to_owned(),
            environment: specification.environment.clone(),
            deadline_unix_ms: claimed_at_unix_ms.saturating_add(specification.wall_time_ms.max(1)),
            max_output_bytes: specification.max_output_bytes,
            max_processes: specification.max_processes,
            max_memory_bytes: None,
            command_network: self.session.command_network,
            seatbelt_profile_digest: Digest::sha256(specification.seatbelt_profile.as_bytes()),
            request_digest: Digest::sha256(&[]),
        };
        request.request_digest = request.computed_digest()?;
        request.validate_retained()?;
        Ok(request)
    }

    /// Runs one request through the helper and returns its complete evidence.
    ///
    /// The client re-derives both stream digests from the chunks it received,
    /// so the helper cannot report a digest for bytes it did not send.
    ///
    /// # Errors
    ///
    /// Fails on any transport error, on evidence that does not bind the run,
    /// or when a re-derived stream digest differs from the reported one.
    pub(crate) fn run(
        &mut self,
        purpose: MacosDevelopmentRunPurpose,
        request: &MacosHelperLaunchRequest,
        seatbelt_profile: &str,
        probe_descriptor_exec: bool,
    ) -> Result<MacosDevelopmentRunOutcome, MacosDevelopmentHelperError> {
        let run = MacosDevelopmentRunRequest {
            topology: MacosHelperTopology::Development,
            purpose,
            request: request.clone(),
            seatbelt_profile: seatbelt_profile.to_owned(),
            probe_descriptor_exec,
        };
        run.validate_for_session(&self.session)?;
        write_development_frame(
            &mut self.stream,
            MacosHelperFrameKind::DevelopmentRunRequest,
            &run,
        )?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let evidence = loop {
            let (kind, payload) = match read_frame(&mut self.stream) {
                Ok(frame) => frame,
                Err(error) => return Err(self.server_refusal(&error.into())),
            };
            match kind {
                MacosHelperFrameKind::DevelopmentRunChunk => {
                    let chunk: MacosDevelopmentRunChunk = decode_canonical_payload(kind, &payload)?;
                    if chunk.topology != MacosHelperTopology::Development {
                        return Err(MacosDevelopmentHelperError::invalid(
                            "development_chunk.topology",
                            "a development chunk must carry the development topology",
                        ));
                    }
                    let bytes = chunk.decoded()?;
                    match chunk.stream {
                        MacosDevelopmentStream::Stdout => stdout.extend_from_slice(&bytes),
                        MacosDevelopmentStream::Stderr => stderr.extend_from_slice(&bytes),
                    }
                }
                MacosHelperFrameKind::DevelopmentRunEvidence => {
                    break decode_canonical_payload::<MacosDevelopmentRunEvidence>(kind, &payload)?;
                }
                other => {
                    return Err(MacosDevelopmentHelperError::Transport(format!(
                        "unexpected {other} frame during a development run"
                    )));
                }
            }
        };
        evidence.validate_for(&self.session, &run)?;
        if Digest::sha256(&stdout) != evidence.stdout.complete_digest
            || Digest::sha256(&stderr) != evidence.stderr.complete_digest
            || stdout.len() as u64 != evidence.stdout.complete_length
            || stderr.len() as u64 != evidence.stderr.complete_length
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_run.streams",
                "streamed bytes do not reproduce the reported complete digests",
            ));
        }
        if evidence.stdout.maximum_chunk_bytes
            > u64::try_from(MAX_MACOS_DEVELOPMENT_CHUNK_BYTES).unwrap_or(u64::MAX)
            || evidence.stderr.maximum_chunk_bytes
                > u64::try_from(MAX_MACOS_DEVELOPMENT_CHUNK_BYTES).unwrap_or(u64::MAX)
        {
            return Err(MacosDevelopmentHelperError::invalid(
                "development_run.streams",
                "a reported chunk exceeded the bounded streaming ceiling",
            ));
        }
        Ok(MacosDevelopmentRunOutcome {
            evidence,
            stdout,
            stderr,
        })
    }
}

impl Drop for MacosDevelopmentHelperClient {
    fn drop(&mut self) {
        // Closing the connection is what ends a served session; killing is the
        // last resort for a helper that did not observe the close.
        let _ignored = self.stream.shutdown(std::net::Shutdown::Both);
        if let Some(child) = self.child.as_mut() {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
        if let Some(server) = self.server.take() {
            let _ignored = server.join();
        }
    }
}

/// Everything one development run needs, before it becomes a canonical request.
#[derive(Clone, Debug)]
pub(crate) struct MacosDevelopmentRunSpecification<'a> {
    pub(crate) runner_session_id: &'a str,
    pub(crate) effect_id: &'a str,
    pub(crate) sprint_id: &'a str,
    pub(crate) launch_id: &'a str,
    pub(crate) input_snapshot: Digest,
    pub(crate) policy_entry_id: &'a str,
    pub(crate) executable_digest: Digest,
    pub(crate) argv: &'a [String],
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) relative_working_directory: &'a str,
    pub(crate) seatbelt_profile: &'a str,
    pub(crate) wall_time_ms: u64,
    pub(crate) max_output_bytes: u64,
    pub(crate) max_processes: u32,
}

/// One completed development run: its evidence plus the bytes it produced.
#[derive(Clone, Debug)]
pub(crate) struct MacosDevelopmentRunOutcome {
    pub(crate) evidence: MacosDevelopmentRunEvidence,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl MacosDevelopmentRunOutcome {
    /// Whether the leader exited normally with a zero status.
    pub(crate) fn exited_zero(&self) -> bool {
        self.evidence.exited_zero()
    }

    /// Standard output interpreted as UTF-8, lossily, for canary comparison.
    pub(crate) fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

fn development_descriptor_bindings() -> Vec<MacosChildDescriptorBinding> {
    // Development-controller descriptors are not inherited. Report observed
    // descriptors without synthesizing a setup handshake.
    [
        (0_u32, MacosChildDescriptorPurpose::StandardInput, true),
        (1, MacosChildDescriptorPurpose::StandardOutput, true),
        (2, MacosChildDescriptorPurpose::StandardError, true),
        (3, MacosChildDescriptorPurpose::HoldControl, false),
        (4, MacosChildDescriptorPurpose::SetupReport, false),
    ]
    .into_iter()
    .map(
        |(target_fd, purpose, inherited_through_exec)| MacosChildDescriptorBinding {
            target_fd,
            purpose,
            object_digest: Digest::sha256(
                format!("grok-build.development-descriptor.{target_fd}").as_bytes(),
            ),
            inherited_through_exec,
        },
    )
    .collect()
}

fn own_code_identity() -> Result<OwnCodeIdentity, MacosDevelopmentHelperError> {
    let (near, _far) = UnixStream::pair().map_err(|error| {
        MacosDevelopmentHelperError::io("create self-identity socket pair", &error)
    })?;
    let observed = observe_peer(near.as_fd())
        .map_err(|error| MacosDevelopmentHelperError::Transport(error.to_string()))?;
    Ok(OwnCodeIdentity {
        identity_digest: code_identity_digest(observed.code_directory_hash()),
        code_directory_hash: observed.code_directory_hash().to_vec(),
        apple_anchored: observed.apple_anchored(),
    })
}

/// The pathname of the running executable, for its own install audit.
///
/// # Errors
///
/// Fails when the platform cannot resolve the running image's path.
fn own_program() -> Result<PathBuf, MacosDevelopmentHelperError> {
    std::env::current_exe()
        .map_err(|error| MacosDevelopmentHelperError::io("resolve the running executable", &error))
}

fn unauthenticated_placeholder_session(
    plan: &MacosDevelopmentHelperPlan,
) -> MacosDevelopmentHelperSession {
    // Deliberately fails `validate`: `peer_requirement_matched` is false, so a
    // partially constructed client can never be used as an authenticated one.
    MacosDevelopmentHelperSession {
        topology: MacosHelperTopology::Development,
        helper_topology: MacosDevelopmentHelperTopology::SameImageThread,
        protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
        policy_version: plan.policy_version,
        session_nonce: Digest::sha256(b"development-placeholder"),
        helper_binary_digest: Digest::sha256(b"development-placeholder"),
        helper_requirement_digest: Digest::sha256(b"development-placeholder"),
        client_binary_digest: Digest::sha256(b"development-placeholder"),
        client_requirement_digest: Digest::sha256(b"development-placeholder"),
        identity_pool_digest: Digest::sha256(b"development-placeholder"),
        workspace_grant_hash: plan.workspace_grant_hash.clone(),
        execution_policy_hash: plan.execution_policy_hash.clone(),
        command_network: plan.command_network,
        authenticated_at_unix_ms: 0,
        peer_requirement_matched: false,
        attestation: MacosHelperAttestation::Unattested,
        dedicated_account_pool: false,
        session_digest: Digest::sha256(&[]),
    }
}

/// Chooses the helper endpoint available to this process.
///
/// The separately named bin target is preferred whenever Cargo built it beside
/// the running executable. `cargo test --lib` builds no bin target at all, so
/// in-crate tests fall back to the same-image thread, and the choice is
/// recorded in the published session's `helper_topology`, digested into its
/// `session_digest`, and carried in every artifact derived from it, so a reader
/// always knows which shape produced a result.
pub(crate) fn available_development_helper_topology() -> MacosDevelopmentHelperTopology {
    if locate_development_helper_program().is_ok() {
        MacosDevelopmentHelperTopology::SeparateProcess
    } else {
        MacosDevelopmentHelperTopology::SameImageThread
    }
}

/// Locates the development helper next to the running executable.
///
/// There is deliberately no environment variable or configuration file that
/// selects a different helper: the only admitted helper is the one Cargo built
/// beside this test or runner binary.
fn locate_development_helper_program() -> Result<PathBuf, MacosDevelopmentHelperError> {
    let current = std::env::current_exe().map_err(|error| {
        MacosDevelopmentHelperError::io("resolve the running executable", &error)
    })?;
    let mut directory = current.parent();
    for _depth in 0..3 {
        let Some(candidate_root) = directory else {
            break;
        };
        let candidate = candidate_root.join(MACOS_DEVELOPMENT_HELPER_PROGRAM);
        if candidate.is_file() {
            return Ok(candidate);
        }
        directory = candidate_root.parent();
    }
    Err(MacosDevelopmentHelperError::invalid(
        "development_helper.program",
        "the development helper binary was not built beside the running executable",
    ))
}

#[cfg(test)]
mod tests;
