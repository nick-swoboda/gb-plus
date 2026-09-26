//! Authenticated client for the macOS dedicated-identity helper.
//!
//! Carries canonical `macos_helper_protocol` JSON over a UNIX socket with a
//! 64 KiB bound and binds launch requests to the expected Seatbelt digest.
//! The kernel's peer audit token identifies a `SecCode` for requirement checks;
//! path-based signature output is not peer authentication.
//!
//! Runtime admission requires local code identity and an independently audited
//! install path. Optional Apple publisher attestation is verified when claimed.
//! This module neither installs nor starts helpers and grants no execution
//! authority by itself.

#![allow(dead_code)] // Consumed by the macOS backend once the helper binary exists.

use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

use grok_build_core::Digest;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::macos_helper_protocol::{
    MAX_MACOS_HELPER_REQUEST_BYTES, MacosAssignedIdentity, MacosHeldPreparationEvidence,
    MacosHelperAttestation, MacosHelperInstallAudit, MacosHelperLaunchRequest,
    MacosHelperPreparationBinding, MacosHelperProtocolError, MacosHelperSession,
};

/// Fixed magic prefix of every helper transport frame.
pub(crate) const MACOS_HELPER_FRAME_MAGIC: [u8; 4] = *b"GBMH";

/// Bytes consumed by one frame header: magic, kind, then big-endian length.
pub(crate) const MACOS_HELPER_FRAME_HEADER_BYTES: usize = 9;

/// Frames reuse the protocol's canonical request ceiling exactly.
///
/// The helper contract fixes one 64 KiB bound for an admitted request. A
/// framing layer with its own larger bound would let a peer stage bytes the
/// protocol later refuses, so the two ceilings are the same constant.
pub(crate) const MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES: usize = MAX_MACOS_HELPER_REQUEST_BYTES;

/// Payload class of one framed helper message.
///
/// Codes 1 to 4 name existing `macos_helper_protocol` types; the transport
/// adds no production message of its own. Codes 5 to 8 name the separately
/// typed development payloads sanctioned by the architecture document's
/// "Development builds use a separately named helper, identity pool, state
/// root, and requirement". They are distinct codes precisely so a development
/// payload can never be mistaken for its production counterpart at the framing
/// layer, before any field is inspected. An unassigned code remains a protocol
/// violation rather than a forward-compatible extension point.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum MacosHelperFrameKind {
    /// `MacosHelperSession` published by the helper when a connection opens.
    Session,
    /// `MacosHelperLaunchRequest` sent by the client exactly once.
    LaunchRequest,
    /// `MacosHeldPreparationEvidence` returned while the child is still held.
    HeldPreparationEvidence,
    /// `MacosCleanupEvidence` returned after the domain is proved empty.
    CleanupEvidence,
    /// `MacosDevelopmentHelperSession` published by a development helper.
    DevelopmentSession,
    /// `MacosDevelopmentRunRequest` sent by a development client per run.
    DevelopmentRunRequest,
    /// `MacosDevelopmentRunChunk` streaming bounded output during a dev run.
    DevelopmentRunChunk,
    /// `MacosDevelopmentRunEvidence` closing one development run.
    DevelopmentRunEvidence,
}

impl MacosHelperFrameKind {
    /// Wire code for this payload class.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Session => 1,
            Self::LaunchRequest => 2,
            Self::HeldPreparationEvidence => 3,
            Self::CleanupEvidence => 4,
            Self::DevelopmentSession => 5,
            Self::DevelopmentRunRequest => 6,
            Self::DevelopmentRunChunk => 7,
            Self::DevelopmentRunEvidence => 8,
        }
    }

    /// Resolves a wire code, rejecting every unassigned value.
    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Session),
            2 => Some(Self::LaunchRequest),
            3 => Some(Self::HeldPreparationEvidence),
            4 => Some(Self::CleanupEvidence),
            5 => Some(Self::DevelopmentSession),
            6 => Some(Self::DevelopmentRunRequest),
            7 => Some(Self::DevelopmentRunChunk),
            8 => Some(Self::DevelopmentRunEvidence),
            _ => None,
        }
    }

    /// Whether this payload class belongs to the development topology.
    pub(crate) const fn development(self) -> bool {
        matches!(
            self,
            Self::DevelopmentSession
                | Self::DevelopmentRunRequest
                | Self::DevelopmentRunChunk
                | Self::DevelopmentRunEvidence
        )
    }

    /// Stable diagnostic name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::LaunchRequest => "launch_request",
            Self::HeldPreparationEvidence => "held_preparation_evidence",
            Self::CleanupEvidence => "cleanup_evidence",
            Self::DevelopmentSession => "development_session",
            Self::DevelopmentRunRequest => "development_run_request",
            Self::DevelopmentRunChunk => "development_run_chunk",
            Self::DevelopmentRunEvidence => "development_run_evidence",
        }
    }
}

impl Display for MacosHelperFrameKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Writes one complete frame, refusing anything the protocol cannot admit.
///
/// # Errors
///
/// Fails for an empty payload, a payload above
/// [`MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES`], or an underlying write error. No
/// partial frame is produced for the two size refusals: both are checked
/// before the header is written.
pub(crate) fn write_frame(
    writer: &mut impl Write,
    kind: MacosHelperFrameKind,
    payload: &[u8],
) -> Result<(), MacosHelperTransportError> {
    if payload.is_empty() {
        return Err(MacosHelperTransportError::EmptyFrame { kind });
    }
    if payload.len() > MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES {
        return Err(MacosHelperTransportError::FrameTooLarge {
            bytes: payload.len(),
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_ignored| {
        MacosHelperTransportError::FrameTooLarge {
            bytes: payload.len(),
        }
    })?;
    let mut header = [0_u8; MACOS_HELPER_FRAME_HEADER_BYTES];
    header[..4].copy_from_slice(&MACOS_HELPER_FRAME_MAGIC);
    header[4] = kind.code();
    header[5..].copy_from_slice(&length.to_be_bytes());
    writer
        .write_all(&header)
        .map_err(|error| MacosHelperTransportError::io("write frame header", &error))?;
    writer
        .write_all(payload)
        .map_err(|error| MacosHelperTransportError::io("write frame payload", &error))?;
    writer
        .flush()
        .map_err(|error| MacosHelperTransportError::io("flush frame", &error))?;
    Ok(())
}

/// Reads exactly one complete frame.
///
/// The declared length is checked against the 64 KiB ceiling before any buffer
/// is allocated, so an oversize declaration costs one header read rather than
/// the declared allocation.
///
/// # Errors
///
/// Fails for a foreign magic prefix, an unassigned kind code, a zero or
/// oversize declared length, a stream that ends inside the header or payload,
/// or an underlying read error.
pub(crate) fn read_frame(
    reader: &mut impl Read,
) -> Result<(MacosHelperFrameKind, Vec<u8>), MacosHelperTransportError> {
    let mut header = [0_u8; MACOS_HELPER_FRAME_HEADER_BYTES];
    read_exact_frame_bytes(reader, &mut header, "frame header")?;
    let mut magic = [0_u8; 4];
    magic.copy_from_slice(&header[..4]);
    if magic != MACOS_HELPER_FRAME_MAGIC {
        return Err(MacosHelperTransportError::FrameMagic { observed: magic });
    }
    let kind = MacosHelperFrameKind::from_code(header[4])
        .ok_or(MacosHelperTransportError::FrameKind { code: header[4] })?;
    let mut declared = [0_u8; 4];
    declared.copy_from_slice(&header[5..]);
    let declared = usize::try_from(u32::from_be_bytes(declared)).unwrap_or(usize::MAX);
    if declared == 0 {
        return Err(MacosHelperTransportError::EmptyFrame { kind });
    }
    if declared > MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES {
        return Err(MacosHelperTransportError::FrameTooLarge { bytes: declared });
    }
    let mut payload = vec![0_u8; declared];
    read_exact_frame_bytes(reader, &mut payload, "frame payload")?;
    Ok((kind, payload))
}

fn read_exact_frame_bytes(
    reader: &mut impl Read,
    buffer: &mut [u8],
    stage: &'static str,
) -> Result<(), MacosHelperTransportError> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(MacosHelperTransportError::TruncatedFrame {
                stage,
                expected: buffer.len(),
            })
        }
        Err(error) => Err(MacosHelperTransportError::io(stage, &error)),
    }
}

/// Decodes one canonical JSON payload, rejecting every alternate encoding.
///
/// Structural decoding rejects unknown and duplicate fields; exact
/// re-encoding additionally rejects reordered fields and alternate
/// whitespace. This mirrors `decode_canonical_launch_request` so a
/// framed message has exactly one admitted byte representation.
///
/// # Errors
///
/// Fails when the payload does not decode, does not re-encode, or does not
/// re-encode to the received bytes.
pub(crate) fn decode_canonical_payload<T>(
    kind: MacosHelperFrameKind,
    payload: &[u8],
) -> Result<T, MacosHelperTransportError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(payload).map_err(|error| {
        MacosHelperTransportError::Protocol(MacosHelperProtocolError::Decoding(format!(
            "{kind} frame decoding failed: {error}"
        )))
    })?;
    let canonical = serde_json::to_vec(&value).map_err(|error| {
        MacosHelperTransportError::Protocol(MacosHelperProtocolError::Encoding(format!(
            "{kind} frame encoding failed: {error}"
        )))
    })?;
    if canonical != payload {
        return Err(MacosHelperTransportError::NonCanonicalPayload { kind });
    }
    Ok(value)
}

/// Encodes one canonical JSON payload under the shared frame ceiling.
///
/// # Errors
///
/// Fails when the value does not encode or exceeds
/// [`MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES`].
pub(crate) fn encode_canonical_payload<T>(
    kind: MacosHelperFrameKind,
    value: &T,
) -> Result<Vec<u8>, MacosHelperTransportError>
where
    T: Serialize,
{
    let canonical = serde_json::to_vec(value).map_err(|error| {
        MacosHelperTransportError::Protocol(MacosHelperProtocolError::Encoding(format!(
            "{kind} frame encoding failed: {error}"
        )))
    })?;
    if canonical.len() > MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES {
        return Err(MacosHelperTransportError::FrameTooLarge {
            bytes: canonical.len(),
        });
    }
    Ok(canonical)
}

/// Fail-closed helper transport failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosHelperTransportError {
    /// A socket, connect, read, or write operation failed.
    Io {
        /// Transport stage that failed.
        stage: &'static str,
        /// Rendered operating-system error.
        detail: String,
    },
    /// A frame did not start with the fixed magic prefix.
    FrameMagic {
        /// Bytes observed in the magic position.
        observed: [u8; 4],
    },
    /// A frame declared an unassigned payload class.
    FrameKind {
        /// Unassigned wire code.
        code: u8,
    },
    /// A frame carried, or declared, no payload.
    EmptyFrame {
        /// Payload class of the empty frame.
        kind: MacosHelperFrameKind,
    },
    /// A frame exceeded the shared 64 KiB protocol ceiling.
    FrameTooLarge {
        /// Declared or observed payload length.
        bytes: usize,
    },
    /// The stream ended inside a frame.
    TruncatedFrame {
        /// Transport stage that ran out of bytes.
        stage: &'static str,
        /// Bytes the stage required.
        expected: usize,
    },
    /// A frame carried a payload class the caller did not expect here.
    UnexpectedFrameKind {
        /// Payload class the caller required.
        expected: MacosHelperFrameKind,
        /// Payload class actually received.
        observed: MacosHelperFrameKind,
    },
    /// A payload was not the unique canonical encoding of its value.
    NonCanonicalPayload {
        /// Payload class that failed the re-encoding check.
        kind: MacosHelperFrameKind,
    },
    /// The request did not carry the Seatbelt profile the caller rendered.
    SeatbeltProfileDigestMismatch,
    /// The session named a helper requirement this client is not pinned to.
    HelperRequirementDigestMismatch,
    /// The session named a helper binary the authenticated peer is not.
    HelperBinaryDigestMismatch,
    /// The helper claimed an Apple-anchored publisher chain that its
    /// authenticated `SecCode` does not substantiate.
    UnprovenPublisherClaim {
        /// Whether the peer's signature actually chains to an Apple anchor.
        peer_apple_anchored: bool,
    },
    /// The session's install audit differs from the client's own observation.
    InstallAuditMismatch {
        /// Audit the client independently performed on the helper binary.
        observed: MacosHelperInstallAudit,
        /// Audit the session published, if it published one at all.
        claimed: Option<MacosHelperInstallAudit>,
    },
    /// Peer authentication failed.
    PeerAuthentication(MacosPeerAuthenticationError),
    /// The decoded payload failed its own protocol validation.
    Protocol(MacosHelperProtocolError),
}

impl MacosHelperTransportError {
    fn io(stage: &'static str, error: &io::Error) -> Self {
        Self::Io {
            stage,
            detail: error.to_string(),
        }
    }
}

impl From<MacosHelperProtocolError> for MacosHelperTransportError {
    fn from(error: MacosHelperProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<MacosPeerAuthenticationError> for MacosHelperTransportError {
    fn from(error: MacosPeerAuthenticationError) -> Self {
        Self::PeerAuthentication(error)
    }
}

impl Display for MacosHelperTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { stage, detail } => write!(formatter, "{stage}: {detail}"),
            Self::FrameMagic { observed } => write!(
                formatter,
                "frame magic {observed:02x?} is not the helper transport magic \
                 {MACOS_HELPER_FRAME_MAGIC:02x?}"
            ),
            Self::FrameKind { code } => {
                write!(formatter, "frame kind {code} is not an admitted payload")
            }
            Self::EmptyFrame { kind } => write!(formatter, "{kind} frame carries no payload"),
            Self::FrameTooLarge { bytes } => write!(
                formatter,
                "frame uses {bytes} bytes; maximum is {MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES}"
            ),
            Self::TruncatedFrame { stage, expected } => {
                write!(formatter, "{stage} ended before {expected} bytes")
            }
            Self::UnexpectedFrameKind { expected, observed } => write!(
                formatter,
                "expected a {expected} frame but received a {observed} frame"
            ),
            Self::NonCanonicalPayload { kind } => write!(
                formatter,
                "{kind} payload is not the unique canonical encoding"
            ),
            Self::SeatbeltProfileDigestMismatch => formatter.write_str(
                "launch request carries a different Seatbelt profile digest than the caller rendered",
            ),
            Self::HelperRequirementDigestMismatch => formatter
                .write_str("session names a helper requirement this client is not pinned to"),
            Self::HelperBinaryDigestMismatch => formatter
                .write_str("session names a helper binary the authenticated peer is not"),
            Self::UnprovenPublisherClaim {
                peer_apple_anchored,
            } => write!(
                formatter,
                "session claims publisher attestation but the authenticated peer's \
                 Apple-anchored state is {peer_apple_anchored}"
            ),
            Self::InstallAuditMismatch { observed, claimed } => write!(
                formatter,
                "session publishes install audit {claimed:?} but this client observed \
                 {observed:?} on the helper binary"
            ),
            Self::PeerAuthentication(error) => Display::fmt(error, formatter),
            Self::Protocol(error) => Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for MacosHelperTransportError {}

/// Maximum admitted length of a configured code-requirement string.
pub(crate) const MAX_MACOS_PEER_REQUIREMENT_BYTES: usize = 4 * 1_024;

/// Code-directory-hash lengths Apple's requirement language accepts.
const ADMITTED_CODE_DIRECTORY_HASH_BYTES: [usize; 2] = [20, 32];

/// Fixed requirement that separates an Apple-issued signing chain from an
/// ad-hoc signature.
///
/// A Developer ID leaf chains to the Apple Root CA and satisfies this; an
/// ad-hoc signature (`codesign -s -`, or the linker's automatic arm64
/// signature) carries no certificate chain at all and fails it. The transport
/// evaluates it independently of the configured requirement so a peer cannot
/// be reported as production-signed merely because a permissive requirement
/// was configured.
const APPLE_ANCHOR_REQUIREMENT: &str = "anchor apple generic";

const PEER_REQUIREMENT_DOMAIN: &[u8] = b"grok-build.macos-helper-peer-requirement.v1\0";
const PEER_CODE_IDENTITY_DOMAIN: &[u8] = b"grok-build.macos-helper-peer-code-identity.v1\0";

/// Digest identity of one authenticated peer's code directory.
///
/// The code-directory hash is the kernel's own identity for the loaded image,
/// so digesting it produces a stable binary identity that no pathname
/// substitution can influence.
pub(crate) fn code_identity_digest(code_directory_hash: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(PEER_CODE_IDENTITY_DOMAIN.len() + code_directory_hash.len());
    bytes.extend_from_slice(PEER_CODE_IDENTITY_DOMAIN);
    bytes.extend_from_slice(code_directory_hash);
    Digest::sha256(&bytes)
}

/// One configured code requirement the transport pins its peer to.
///
/// An unmatched requirement is always a refusal. A requirement satisfied
/// without an Apple anchor never yields a production-signed peer.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MacosPeerCodeRequirement {
    text: String,
}

impl MacosPeerCodeRequirement {
    /// Admits one requirement string.
    ///
    /// # Errors
    ///
    /// Fails for an empty requirement, a requirement above
    /// [`MAX_MACOS_PEER_REQUIREMENT_BYTES`], or any byte outside printable
    /// ASCII. The requirement language is ASCII, so a non-ASCII byte is a
    /// malformed configuration rather than an exotic identity.
    pub(crate) fn new(text: &str) -> Result<Self, MacosPeerAuthenticationError> {
        if text.is_empty() {
            return Err(MacosPeerAuthenticationError::EmptyRequirement);
        }
        if text.len() > MAX_MACOS_PEER_REQUIREMENT_BYTES {
            return Err(MacosPeerAuthenticationError::RequirementTooLarge { bytes: text.len() });
        }
        if let Some(byte) = text
            .bytes()
            .find(|byte| !byte.is_ascii_graphic() && *byte != b' ')
        {
            return Err(MacosPeerAuthenticationError::RequirementByte { byte });
        }
        Ok(Self {
            text: text.to_owned(),
        })
    }

    /// Builds the development pin for one exact code-directory hash.
    ///
    /// This is the only requirement shape an ad-hoc-signed helper can satisfy.
    /// It binds the peer to exact code bytes but carries no publisher
    /// identity, so a peer admitted this way is never production-signed.
    ///
    /// # Errors
    ///
    /// Fails when the hash length is not one Apple's requirement language
    /// accepts.
    pub(crate) fn pinned_to_code_directory_hash(
        code_directory_hash: &[u8],
    ) -> Result<Self, MacosPeerAuthenticationError> {
        if !ADMITTED_CODE_DIRECTORY_HASH_BYTES.contains(&code_directory_hash.len()) {
            return Err(MacosPeerAuthenticationError::CodeDirectoryHashLength {
                bytes: code_directory_hash.len(),
            });
        }
        let mut text = String::with_capacity(12 + code_directory_hash.len() * 2);
        text.push_str("cdhash H\"");
        for byte in code_directory_hash {
            text.push(char::from(lower_hex_digit(byte >> 4)));
            text.push(char::from(lower_hex_digit(byte & 0x0f)));
        }
        text.push('"');
        Self::new(&text)
    }

    /// Exact configured requirement text.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Domain-separated digest of the requirement text.
    ///
    /// The helper publishes the same digest in its session record, so a
    /// requirement swap between client and helper is detectable without
    /// shipping the text twice.
    pub(crate) fn digest(&self) -> Digest {
        let mut bytes = Vec::with_capacity(PEER_REQUIREMENT_DOMAIN.len() + self.text.len());
        bytes.extend_from_slice(PEER_REQUIREMENT_DOMAIN);
        bytes.extend_from_slice(self.text.as_bytes());
        Digest::sha256(&bytes)
    }
}

const fn lower_hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0'.wrapping_add(nibble),
        _ => b'a'.wrapping_add(nibble.wrapping_sub(10)),
    }
}

/// Kernel-supplied audit token of the socket peer.
///
/// Word order follows Darwin's `audit_token_to_au32` field order
/// (`auid, euid, egid, ruid, rgid, pid, asid, pidversion`). That ordering is
/// asserted at run time against this process's own credentials rather than
/// trusted from the header, because the layout is the one thing here that
/// cannot be checked at compile time.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MacosPeerAuditToken {
    words: [u32; 8],
}

impl MacosPeerAuditToken {
    /// Complete raw token words, for retention as evidence.
    pub(crate) const fn words(&self) -> [u32; 8] {
        self.words
    }

    /// Audit user identifier.
    pub(crate) const fn audit_user_id(&self) -> u32 {
        self.words[0]
    }

    /// Effective user identifier of the peer.
    pub(crate) const fn effective_uid(&self) -> u32 {
        self.words[1]
    }

    /// Effective group identifier of the peer.
    pub(crate) const fn effective_gid(&self) -> u32 {
        self.words[2]
    }

    /// Real user identifier of the peer.
    pub(crate) const fn real_uid(&self) -> u32 {
        self.words[3]
    }

    /// Real group identifier of the peer.
    pub(crate) const fn real_gid(&self) -> u32 {
        self.words[4]
    }

    /// Process identifier of the peer.
    pub(crate) const fn process_id(&self) -> u32 {
        self.words[5]
    }

    /// Audit session identifier of the peer.
    pub(crate) const fn audit_session_id(&self) -> u32 {
        self.words[6]
    }

    /// Process-identifier generation, which distinguishes a reused pid.
    pub(crate) const fn process_id_version(&self) -> u32 {
        self.words[7]
    }
}

/// Peer identity observed without applying the configured requirement.
///
/// This exists so a development installer can record the helper's exact
/// code-directory hash before pinning to it. It is never an admission
/// decision: nothing in this type says the peer is allowed to be spoken to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosObservedPeer {
    audit_token: MacosPeerAuditToken,
    code_directory_hash: Vec<u8>,
    apple_anchored: bool,
}

impl MacosObservedPeer {
    /// Kernel-supplied audit token this observation resolved.
    pub(crate) const fn audit_token(&self) -> &MacosPeerAuditToken {
        &self.audit_token
    }

    /// Code-directory hash of the peer's loaded image.
    pub(crate) fn code_directory_hash(&self) -> &[u8] {
        &self.code_directory_hash
    }

    /// Whether the peer's signature chains to an Apple-issued anchor.
    pub(crate) const fn apple_anchored(&self) -> bool {
        self.apple_anchored
    }
}

/// Peer that satisfied the configured code requirement.
///
/// Constructing this type is the admission decision: it exists only after the
/// Security framework reported that the audit-token-resolved `SecCode`
/// satisfies the configured requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosAuthenticatedPeer {
    observed: MacosObservedPeer,
    requirement_digest: Digest,
}

impl MacosAuthenticatedPeer {
    /// Kernel-supplied audit token that was authenticated.
    pub(crate) const fn audit_token(&self) -> &MacosPeerAuditToken {
        self.observed.audit_token()
    }

    /// Code-directory hash of the authenticated image.
    pub(crate) fn code_directory_hash(&self) -> &[u8] {
        self.observed.code_directory_hash()
    }

    /// Digest identity of the authenticated image.
    pub(crate) fn code_identity_digest(&self) -> Digest {
        code_identity_digest(self.observed.code_directory_hash())
    }

    /// Digest of the requirement this peer was admitted under.
    pub(crate) const fn requirement_digest(&self) -> &Digest {
        &self.requirement_digest
    }

    /// Whether the peer's signature chains to an Apple-issued anchor.
    pub(crate) const fn apple_anchored(&self) -> bool {
        self.observed.apple_anchored()
    }

    /// Checks optional publisher attestation. An ad-hoc `cdhash` pin can satisfy
    /// local identity admission, but cannot establish a publisher chain.
    pub(crate) const fn publisher_attested(&self) -> bool {
        self.observed.apple_anchored()
    }

    /// The attestation this peer honestly supports for one audited install.
    ///
    /// The caller supplies the install audit it performed itself; this function
    /// only chooses the kind, from the kernel-resolved Apple-anchor probe. It
    /// never returns [`MacosHelperAttestation::Unattested`], because
    /// constructing a [`MacosAuthenticatedPeer`] already required the
    /// configured code requirement to be satisfied.
    pub(crate) const fn attestation_for(
        &self,
        install_audit: MacosHelperInstallAudit,
    ) -> MacosHelperAttestation {
        if self.publisher_attested() {
            MacosHelperAttestation::PublisherCodeIdentity { install_audit }
        } else {
            MacosHelperAttestation::LocalCodeIdentity { install_audit }
        }
    }
}

/// Audits the ownership and permissions of one installed helper binary.
///
/// This is the client's *own* observation, taken through the filesystem rather
/// than believed from a message. It is the half of local attestation that the
/// code-directory pin cannot supply: the pin proves which bytes are running,
/// and this proves who was able to put them there.
///
/// # Errors
///
/// Fails when the binary or its containing directory cannot be inspected, or
/// when the binary has no parent directory.
pub(crate) fn audit_installed_binary(
    path: &Path,
) -> Result<MacosHelperInstallAudit, MacosHelperTransportError> {
    let binary = fs::symlink_metadata(path)
        .map_err(|error| MacosHelperTransportError::io("inspect the installed helper", &error))?;
    let directory = path.parent().ok_or_else(|| {
        MacosHelperTransportError::io(
            "resolve the helper install directory",
            &io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    let directory_metadata = fs::symlink_metadata(directory).map_err(|error| {
        MacosHelperTransportError::io("inspect the helper install directory", &error)
    })?;
    Ok(MacosHelperInstallAudit {
        auditing_uid: rustix::process::getuid().as_raw(),
        binary_owner_uid: binary.uid(),
        binary_mode: binary.permissions().mode() & 0o7777,
        directory_owner_uid: directory_metadata.uid(),
        directory_mode: directory_metadata.permissions().mode() & 0o7777,
    })
}

/// Reads the peer's audit token from a connected UNIX domain socket.
///
/// # Errors
///
/// Fails when the socket has no peer token or returns an unexpected token
/// length.
pub(crate) fn peer_audit_token(
    socket: BorrowedFd<'_>,
) -> Result<MacosPeerAuditToken, MacosPeerAuthenticationError> {
    let words = darwin_peer_identity::peer_audit_token(socket.as_raw_fd())?;
    Ok(MacosPeerAuditToken { words })
}

/// Reads the peer's process identifier from a connected UNIX domain socket.
///
/// This is the weaker `LOCAL_PEERPID` reading. It is retained only as
/// corroboration for diagnostics; a pid can be reused, so admission always
/// uses the audit token.
///
/// # Errors
///
/// Fails when the socket has no peer pid.
pub(crate) fn peer_process_id(socket: BorrowedFd<'_>) -> Result<u32, MacosPeerAuthenticationError> {
    darwin_peer_identity::peer_process_id(socket.as_raw_fd())
}

/// Observes the peer's code identity without applying a requirement.
///
/// # Errors
///
/// Fails when the audit token is unavailable, does not resolve to a
/// `SecCode`, carries no signing information, or exposes no code-directory
/// hash.
pub(crate) fn observe_peer(
    socket: BorrowedFd<'_>,
) -> Result<MacosObservedPeer, MacosPeerAuthenticationError> {
    let audit_token = peer_audit_token(socket)?;
    let evaluation =
        darwin_peer_identity::evaluate_audit_token(&audit_token.words, APPLE_ANCHOR_REQUIREMENT)?;
    Ok(MacosObservedPeer {
        audit_token,
        code_directory_hash: evaluation.code_directory_hash,
        apple_anchored: evaluation.requirement_status == 0,
    })
}

/// Authenticates the peer against one configured code requirement.
///
/// # Errors
///
/// Fails when the audit token is unavailable, does not resolve to a
/// `SecCode`, the requirement does not parse, or the requirement is not
/// satisfied. A requirement that is not satisfied is
/// [`MacosPeerAuthenticationError::RequirementRejected`] and never a degraded
/// success.
pub(crate) fn authenticate_peer(
    socket: BorrowedFd<'_>,
    requirement: &MacosPeerCodeRequirement,
) -> Result<MacosAuthenticatedPeer, MacosPeerAuthenticationError> {
    let audit_token = peer_audit_token(socket)?;
    let evaluation =
        darwin_peer_identity::evaluate_audit_token(&audit_token.words, requirement.text())?;
    if evaluation.requirement_status != 0 {
        return Err(MacosPeerAuthenticationError::RequirementRejected {
            status: evaluation.requirement_status,
        });
    }
    let anchor =
        darwin_peer_identity::evaluate_audit_token(&audit_token.words, APPLE_ANCHOR_REQUIREMENT)?;
    Ok(MacosAuthenticatedPeer {
        observed: MacosObservedPeer {
            audit_token,
            code_directory_hash: evaluation.code_directory_hash,
            apple_anchored: anchor.requirement_status == 0,
        },
        requirement_digest: requirement.digest(),
    })
}

/// Fail-closed peer-authentication failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosPeerAuthenticationError {
    /// The socket did not supply a peer credential.
    PeerCredentialUnavailable {
        /// Socket option that failed.
        option: &'static str,
        /// Operating-system error number.
        errno: i32,
    },
    /// The kernel returned a peer credential of unexpected length.
    PeerCredentialLength {
        /// Socket option that returned the unexpected length.
        option: &'static str,
        /// Length the kernel reported.
        bytes: usize,
    },
    /// The audit token did not resolve to a running code object.
    GuestUnavailable {
        /// `OSStatus` returned by `SecCodeCopyGuestWithAttributes`.
        status: i32,
    },
    /// The configured requirement text did not parse.
    RequirementSyntax {
        /// `OSStatus` returned by `SecRequirementCreateWithString`.
        status: i32,
    },
    /// The peer did not satisfy the configured requirement.
    RequirementRejected {
        /// `OSStatus` returned by `SecCodeCheckValidity`.
        status: i32,
    },
    /// The peer exposed no signing information.
    SigningInformationUnavailable {
        /// `OSStatus` returned by `SecCodeCopySigningInformation`.
        status: i32,
    },
    /// The peer exposed no code-directory hash.
    MissingCodeDirectoryHash,
    /// A Core Foundation allocation returned null.
    AllocationFailed {
        /// Object the allocation was for.
        object: &'static str,
    },
    /// The configured requirement was empty.
    EmptyRequirement,
    /// The configured requirement exceeded the admitted length.
    RequirementTooLarge {
        /// Requirement length in bytes.
        bytes: usize,
    },
    /// The configured requirement carried a byte outside printable ASCII.
    RequirementByte {
        /// Offending byte.
        byte: u8,
    },
    /// A code-directory hash had a length the requirement language rejects.
    CodeDirectoryHashLength {
        /// Hash length in bytes.
        bytes: usize,
    },
}

impl Display for MacosPeerAuthenticationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerCredentialUnavailable { option, errno } => {
                write!(formatter, "{option} failed with errno {errno}")
            }
            Self::PeerCredentialLength { option, bytes } => {
                write!(formatter, "{option} returned {bytes} bytes")
            }
            Self::GuestUnavailable { status } => write!(
                formatter,
                "audit token did not resolve to running code (OSStatus {status})"
            ),
            Self::RequirementSyntax { status } => write!(
                formatter,
                "configured code requirement did not parse (OSStatus {status})"
            ),
            Self::RequirementRejected { status } => write!(
                formatter,
                "peer did not satisfy the configured code requirement (OSStatus {status})"
            ),
            Self::SigningInformationUnavailable { status } => write!(
                formatter,
                "peer exposed no signing information (OSStatus {status})"
            ),
            Self::MissingCodeDirectoryHash => {
                formatter.write_str("peer exposed no code-directory hash")
            }
            Self::AllocationFailed { object } => {
                write!(formatter, "allocating {object} returned null")
            }
            Self::EmptyRequirement => formatter.write_str("code requirement is empty"),
            Self::RequirementTooLarge { bytes } => write!(
                formatter,
                "code requirement uses {bytes} bytes; maximum is \
                 {MAX_MACOS_PEER_REQUIREMENT_BYTES}"
            ),
            Self::RequirementByte { byte } => write!(
                formatter,
                "code requirement byte {byte:#04x} is outside printable ASCII"
            ),
            Self::CodeDirectoryHashLength { bytes } => write!(
                formatter,
                "code-directory hash uses {bytes} bytes; admitted lengths are \
                 {ADMITTED_CODE_DIRECTORY_HASH_BYTES:?}"
            ),
        }
    }
}

impl std::error::Error for MacosPeerAuthenticationError {}

/// Authenticated client end of one helper connection.
///
/// The peer is authenticated before any protocol byte is exchanged, so a
/// caller cannot accidentally speak the protocol to an unauthenticated peer.
#[derive(Debug)]
pub(crate) struct MacosHelperTransportClient {
    stream: UnixStream,
    requirement: MacosPeerCodeRequirement,
    peer: MacosAuthenticatedPeer,
}

impl MacosHelperTransportClient {
    /// Connects to the helper socket and authenticates the peer.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot be connected or the peer does not satisfy
    /// the configured requirement.
    pub(crate) fn connect(
        socket_path: &Path,
        requirement: MacosPeerCodeRequirement,
    ) -> Result<Self, MacosHelperTransportError> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|error| MacosHelperTransportError::io("connect helper socket", &error))?;
        Self::authenticated(stream, requirement)
    }

    /// Authenticates the peer of an already-connected stream.
    ///
    /// # Errors
    ///
    /// Fails when the peer does not satisfy the configured requirement.
    pub(crate) fn authenticated(
        stream: UnixStream,
        requirement: MacosPeerCodeRequirement,
    ) -> Result<Self, MacosHelperTransportError> {
        let peer = authenticate_peer(stream.as_fd(), &requirement)?;
        Ok(Self {
            stream,
            requirement,
            peer,
        })
    }

    /// Authenticated peer on the other end of this connection.
    pub(crate) const fn peer(&self) -> &MacosAuthenticatedPeer {
        &self.peer
    }

    /// Requirement this connection was admitted under.
    pub(crate) const fn requirement(&self) -> &MacosPeerCodeRequirement {
        &self.requirement
    }

    /// Validates a helper session against the authenticated peer and local audit.
    /// Check publisher claims, requirement digest, binary identity and the caller's
    /// independent install audit before applying protocol validation.
    ///
    /// # Errors
    ///
    /// Fails for invalid framing, non-canonical payloads, mismatched bindings or
    /// session-validation errors.
    pub(crate) fn receive_session(
        &mut self,
        observed_install_audit: &MacosHelperInstallAudit,
    ) -> Result<MacosHelperSession, MacosHelperTransportError> {
        let payload = self.read_expected_frame(MacosHelperFrameKind::Session)?;
        let session: MacosHelperSession =
            decode_canonical_payload(MacosHelperFrameKind::Session, &payload)?;
        if session.attestation.claims_publisher() && !self.peer.publisher_attested() {
            return Err(MacosHelperTransportError::UnprovenPublisherClaim {
                peer_apple_anchored: self.peer.apple_anchored(),
            });
        }
        if session.helper_requirement_digest != self.requirement.digest() {
            return Err(MacosHelperTransportError::HelperRequirementDigestMismatch);
        }
        if session.helper_binary_digest != self.peer.code_identity_digest() {
            return Err(MacosHelperTransportError::HelperBinaryDigestMismatch);
        }
        if session.attestation.install_audit() != Some(observed_install_audit) {
            return Err(MacosHelperTransportError::InstallAuditMismatch {
                observed: *observed_install_audit,
                claimed: session.attestation.install_audit().copied(),
            });
        }
        session.validate()?;
        Ok(session)
    }

    /// Sends exactly one launch request bound to the caller's Seatbelt profile.
    ///
    /// The profile-digest comparison happens before validation and before any
    /// byte is written, so a request that names a profile the caller did not
    /// render never reaches the socket.
    ///
    /// # Errors
    ///
    /// Fails for a Seatbelt profile digest mismatch, any protocol validation
    /// failure, a canonical encoding above 64 KiB, or a write error.
    pub(crate) fn send_launch_request(
        &mut self,
        request: &MacosHelperLaunchRequest,
        session: &MacosHelperSession,
        expected_preparation: &MacosHelperPreparationBinding,
        expected_seatbelt_profile_digest: &Digest,
        now_unix_ms: u64,
    ) -> Result<(), MacosHelperTransportError> {
        if &request.seatbelt_profile_digest != expected_seatbelt_profile_digest {
            return Err(MacosHelperTransportError::SeatbeltProfileDigestMismatch);
        }
        request.validate_for_preparation(session, expected_preparation, now_unix_ms)?;
        let payload = encode_canonical_payload(MacosHelperFrameKind::LaunchRequest, request)?;
        write_frame(
            &mut self.stream,
            MacosHelperFrameKind::LaunchRequest,
            &payload,
        )
    }

    /// Receives the held-preparation evidence for one issued request.
    ///
    /// # Errors
    ///
    /// Fails for a framing error, a non-canonical payload, or evidence that
    /// does not bind to the authenticated session, the issued request, and the
    /// assigned identity.
    pub(crate) fn receive_held_preparation_evidence(
        &mut self,
        session: &MacosHelperSession,
        request: &MacosHelperLaunchRequest,
        assigned: &MacosAssignedIdentity,
    ) -> Result<MacosHeldPreparationEvidence, MacosHelperTransportError> {
        let payload = self.read_expected_frame(MacosHelperFrameKind::HeldPreparationEvidence)?;
        let evidence: MacosHeldPreparationEvidence =
            decode_canonical_payload(MacosHelperFrameKind::HeldPreparationEvidence, &payload)?;
        evidence.validate_for(session, request, assigned)?;
        Ok(evidence)
    }

    fn read_expected_frame(
        &mut self,
        expected: MacosHelperFrameKind,
    ) -> Result<Vec<u8>, MacosHelperTransportError> {
        let (observed, payload) = read_frame(&mut self.stream)?;
        if observed == expected {
            Ok(payload)
        } else {
            Err(MacosHelperTransportError::UnexpectedFrameKind { expected, observed })
        }
    }
}

/// The only unsafe surface this module owns.
///
/// It is fixed to three operations: reading a kernel-supplied peer credential
/// from a socket, resolving an audit token to a code object, and evaluating a
/// code requirement against that object. It cannot launch, signal, change
/// credentials, open a path, or apply policy, and it returns plain owned Rust
/// data so no Core Foundation reference escapes it.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod darwin_peer_identity {
    use std::ffi::{c_int, c_long, c_uchar, c_void};
    use std::io;
    use std::ptr;
    use std::slice;

    use super::MacosPeerAuthenticationError;

    /// `SOL_LOCAL` from `sys/un.h`.
    const SOL_LOCAL: c_int = 0;
    /// `LOCAL_PEERPID` from `sys/un.h`.
    const LOCAL_PEERPID: c_int = 0x002;
    /// `LOCAL_PEERTOKEN` from `sys/un.h`.
    const LOCAL_PEERTOKEN: c_int = 0x006;
    /// `audit_token_t` is a fixed eight-word structure.
    const AUDIT_TOKEN_WORDS: usize = 8;
    /// `kCFStringEncodingUTF8` from `CFString.h`.
    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    /// `kSecCSDefaultFlags` from `CSCommon.h`.
    const SEC_CS_DEFAULT_FLAGS: usize = 0;
    /// `errSecSuccess` from `SecBase.h`.
    const ERR_SEC_SUCCESS: i32 = 0;

    type CFAllocatorRef = *const c_void;
    type CFTypeRef = *const c_void;
    type CFIndex = c_long;
    type CFTypeID = usize;
    type CFOptionFlags = usize;
    type OSStatus = i32;

    /// `CFDictionaryKeyCallBacks` from `CFDictionary.h`. Only its address is
    /// used, so the callback slots stay opaque pointers.
    #[repr(C)]
    struct CFDictionaryKeyCallBacks {
        version: CFIndex,
        retain: *const c_void,
        release: *const c_void,
        copy_description: *const c_void,
        equal: *const c_void,
        hash: *const c_void,
    }

    /// `CFDictionaryValueCallBacks` from `CFDictionary.h`.
    #[repr(C)]
    struct CFDictionaryValueCallBacks {
        version: CFIndex,
        retain: *const c_void,
        release: *const c_void,
        copy_description: *const c_void,
        equal: *const c_void,
    }

    unsafe extern "C" {
        fn getsockopt(
            socket: c_int,
            level: c_int,
            name: c_int,
            value: *mut c_void,
            length: *mut u32,
        ) -> c_int;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
        fn CFRelease(object: CFTypeRef);
        fn CFGetTypeID(object: CFTypeRef) -> CFTypeID;
        fn CFDataGetTypeID() -> CFTypeID;
        fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFTypeRef;
        fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
        fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
        fn CFStringCreateWithBytes(
            allocator: CFAllocatorRef,
            bytes: *const u8,
            length: CFIndex,
            encoding: u32,
            external_representation: c_uchar,
        ) -> CFTypeRef;
        fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            count: CFIndex,
            key_callbacks: *const CFDictionaryKeyCallBacks,
            value_callbacks: *const CFDictionaryValueCallBacks,
        ) -> CFTypeRef;
        fn CFDictionaryGetValue(dictionary: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecGuestAttributeAudit: CFTypeRef;
        static kSecCodeInfoUnique: CFTypeRef;
        fn SecCodeCopyGuestWithAttributes(
            host: CFTypeRef,
            attributes: CFTypeRef,
            flags: CFOptionFlags,
            guest: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecCodeCopySigningInformation(
            code: CFTypeRef,
            flags: CFOptionFlags,
            information: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecRequirementCreateWithString(
            text: CFTypeRef,
            flags: CFOptionFlags,
            requirement: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecCodeCheckValidity(
            code: CFTypeRef,
            flags: CFOptionFlags,
            requirement: CFTypeRef,
        ) -> OSStatus;
    }

    /// Owns one `CFTypeRef` obtained from a create or copy function.
    struct Owned(CFTypeRef);

    impl Owned {
        fn new(
            object: CFTypeRef,
            label: &'static str,
        ) -> Result<Self, MacosPeerAuthenticationError> {
            if object.is_null() {
                return Err(MacosPeerAuthenticationError::AllocationFailed { object: label });
            }
            Ok(Self(object))
        }

        const fn get(&self) -> CFTypeRef {
            self.0
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) };
        }
    }

    /// One requirement evaluation against an audit-token-resolved code object.
    pub(super) struct PeerEvaluation {
        pub(super) code_directory_hash: Vec<u8>,
        pub(super) requirement_status: i32,
    }

    /// Reads `LOCAL_PEERTOKEN` for one connected socket.
    pub(super) fn peer_audit_token(
        descriptor: c_int,
    ) -> Result<[u32; AUDIT_TOKEN_WORDS], MacosPeerAuthenticationError> {
        let mut words = [0_u32; AUDIT_TOKEN_WORDS];
        let mut length = u32::try_from(size_of_val(&words)).unwrap_or(u32::MAX);
        let result = unsafe {
            getsockopt(
                descriptor,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                (&raw mut words).cast::<c_void>(),
                &raw mut length,
            )
        };
        if result != 0 {
            return Err(MacosPeerAuthenticationError::PeerCredentialUnavailable {
                option: "LOCAL_PEERTOKEN",
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        if usize::try_from(length).unwrap_or(usize::MAX) != size_of_val(&words) {
            return Err(MacosPeerAuthenticationError::PeerCredentialLength {
                option: "LOCAL_PEERTOKEN",
                bytes: usize::try_from(length).unwrap_or(usize::MAX),
            });
        }
        Ok(words)
    }

    /// Reads `LOCAL_PEERPID` for one connected socket.
    pub(super) fn peer_process_id(descriptor: c_int) -> Result<u32, MacosPeerAuthenticationError> {
        let mut pid: c_int = 0;
        let mut length = u32::try_from(size_of_val(&pid)).unwrap_or(u32::MAX);
        let result = unsafe {
            getsockopt(
                descriptor,
                SOL_LOCAL,
                LOCAL_PEERPID,
                (&raw mut pid).cast::<c_void>(),
                &raw mut length,
            )
        };
        if result != 0 {
            return Err(MacosPeerAuthenticationError::PeerCredentialUnavailable {
                option: "LOCAL_PEERPID",
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        if usize::try_from(length).unwrap_or(usize::MAX) != size_of_val(&pid) {
            return Err(MacosPeerAuthenticationError::PeerCredentialLength {
                option: "LOCAL_PEERPID",
                bytes: usize::try_from(length).unwrap_or(usize::MAX),
            });
        }
        u32::try_from(pid).map_err(
            |_ignored| MacosPeerAuthenticationError::PeerCredentialLength {
                option: "LOCAL_PEERPID",
                bytes: 0,
            },
        )
    }

    /// Resolves an audit token to running code and evaluates one requirement.
    pub(super) fn evaluate_audit_token(
        words: &[u32; AUDIT_TOKEN_WORDS],
        requirement: &str,
    ) -> Result<PeerEvaluation, MacosPeerAuthenticationError> {
        let guest = copy_guest(words)?;
        let code_directory_hash = code_directory_hash(&guest)?;
        let requirement_status = check_requirement(&guest, requirement)?;
        Ok(PeerEvaluation {
            code_directory_hash,
            requirement_status,
        })
    }

    fn copy_guest(words: &[u32; AUDIT_TOKEN_WORDS]) -> Result<Owned, MacosPeerAuthenticationError> {
        let mut token_bytes = [0_u8; AUDIT_TOKEN_WORDS * 4];
        for (slot, word) in token_bytes.chunks_exact_mut(4).zip(words.iter()) {
            slot.copy_from_slice(&word.to_ne_bytes());
        }
        let length = CFIndex::try_from(token_bytes.len()).unwrap_or(CFIndex::MAX);
        let token = Owned::new(
            unsafe { CFDataCreate(ptr::null(), token_bytes.as_ptr(), length) },
            "audit token data",
        )?;
        let keys: [CFTypeRef; 1] = [unsafe { kSecGuestAttributeAudit }];
        let values: [CFTypeRef; 1] = [token.get()];
        let attributes = Owned::new(
            unsafe {
                CFDictionaryCreate(
                    ptr::null(),
                    keys.as_ptr(),
                    values.as_ptr(),
                    1,
                    &raw const kCFTypeDictionaryKeyCallBacks,
                    &raw const kCFTypeDictionaryValueCallBacks,
                )
            },
            "guest attribute dictionary",
        )?;
        let mut guest: CFTypeRef = ptr::null();
        let status = unsafe {
            SecCodeCopyGuestWithAttributes(
                ptr::null(),
                attributes.get(),
                SEC_CS_DEFAULT_FLAGS,
                &raw mut guest,
            )
        };
        if status != ERR_SEC_SUCCESS {
            return Err(MacosPeerAuthenticationError::GuestUnavailable { status });
        }
        Owned::new(guest, "guest code object")
    }

    fn code_directory_hash(guest: &Owned) -> Result<Vec<u8>, MacosPeerAuthenticationError> {
        let mut information: CFTypeRef = ptr::null();
        let status = unsafe {
            SecCodeCopySigningInformation(guest.get(), SEC_CS_DEFAULT_FLAGS, &raw mut information)
        };
        if status != ERR_SEC_SUCCESS {
            return Err(MacosPeerAuthenticationError::SigningInformationUnavailable { status });
        }
        let information = Owned::new(information, "signing information")?;
        let unique = unsafe { CFDictionaryGetValue(information.get(), kSecCodeInfoUnique) };
        if unique.is_null() || unsafe { CFGetTypeID(unique) } != unsafe { CFDataGetTypeID() } {
            return Err(MacosPeerAuthenticationError::MissingCodeDirectoryHash);
        }
        let length = usize::try_from(unsafe { CFDataGetLength(unique) }).unwrap_or(0);
        let bytes = unsafe { CFDataGetBytePtr(unique) };
        if length == 0 || bytes.is_null() {
            return Err(MacosPeerAuthenticationError::MissingCodeDirectoryHash);
        }
        Ok(unsafe { slice::from_raw_parts(bytes, length) }.to_vec())
    }

    fn check_requirement(
        guest: &Owned,
        requirement: &str,
    ) -> Result<i32, MacosPeerAuthenticationError> {
        let length = CFIndex::try_from(requirement.len()).unwrap_or(CFIndex::MAX);
        let text = Owned::new(
            unsafe {
                CFStringCreateWithBytes(
                    ptr::null(),
                    requirement.as_ptr(),
                    length,
                    CF_STRING_ENCODING_UTF8,
                    0,
                )
            },
            "requirement text",
        )?;
        let mut parsed: CFTypeRef = ptr::null();
        let status = unsafe {
            SecRequirementCreateWithString(text.get(), SEC_CS_DEFAULT_FLAGS, &raw mut parsed)
        };
        if status != ERR_SEC_SUCCESS {
            return Err(MacosPeerAuthenticationError::RequirementSyntax { status });
        }
        let parsed = Owned::new(parsed, "parsed requirement")?;
        Ok(unsafe { SecCodeCheckValidity(guest.get(), SEC_CS_DEFAULT_FLAGS, parsed.get()) })
    }
}

#[cfg(test)]
mod tests;
