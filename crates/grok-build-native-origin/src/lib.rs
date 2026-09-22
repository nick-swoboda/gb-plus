//! Private lower-layer native-origin mechanism.
//!
//! This crate defines operation-specific, move-only proof shapes for a future
//! authenticated native-service channel. It deliberately contains no channel,
//! operating-system authentication, product contract, persistence, runtime,
//! service, command, or production constructor.
//!
//! The proof shapes are distinct so one authenticated operation cannot be
//! presented at another operation's boundary. Their internals are private, and
//! none implements `Clone` or a serialization API.
//! `operation_sequence` is owned by the authenticated source within one
//! authenticated session and one nominal operation domain. Distinct proof
//! types have distinct operation domains, so the same numeric sequence in two
//! different proof types is not replay and never makes them interchangeable.
//!
//! # Compile-time boundaries
//!
//! Construction is private:
//!
//! ```compile_fail
//! use grok_build_native_origin::AuthenticatedNativePreparationSourceV1;
//!
//! let _ = AuthenticatedNativePreparationSourceV1(panic!("private field"));
//! ```
//!
//! Proofs are move-only:
//!
//! ```compile_fail
//! use grok_build_native_origin::AuthenticatedNativePreparationSourceV1;
//!
//! fn duplicate(proof: AuthenticatedNativePreparationSourceV1) {
//!     let _copy = proof.clone();
//! }
//! ```
//!
//! Proofs expose no serialization method:
//!
//! ```compile_fail
//! use grok_build_native_origin::AuthenticatedCaptureStoreOriginSourceV1;
//!
//! fn serialize(proof: AuthenticatedCaptureStoreOriginSourceV1) {
//!     let _bytes = proof.serialize();
//! }
//! ```
//!
//! Operation types are not interchangeable:
//!
//! ```compile_fail
//! use grok_build_native_origin::{
//!     AuthenticatedCaptureStoreOriginSourceV1,
//!     AuthenticatedNativePreparationSourceV1,
//! };
//!
//! fn consume_capture(_: AuthenticatedCaptureStoreOriginSourceV1) {}
//!
//! fn cross_operation(proof: AuthenticatedNativePreparationSourceV1) {
//!     consume_capture(proof);
//! }
//! ```

use std::fmt::{self, Debug, Formatter};

const IDENTITY_BYTES: usize = 32;

struct AuthenticatedNativeOriginSource {
    authenticated_source_identity: [u8; IDENTITY_BYTES],
    session_identity: [u8; IDENTITY_BYTES],
    operation_sequence: u64,
    canonical_payload: Box<[u8]>,
}

impl AuthenticatedNativeOriginSource {
    const fn authenticated_source_identity(&self) -> &[u8; IDENTITY_BYTES] {
        &self.authenticated_source_identity
    }

    const fn session_identity(&self) -> &[u8; IDENTITY_BYTES] {
        &self.session_identity
    }

    const fn operation_sequence(&self) -> u64 {
        self.operation_sequence
    }

    fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    #[cfg(test)]
    fn from_test_fixture(
        authenticated_source_identity: [u8; IDENTITY_BYTES],
        session_identity: [u8; IDENTITY_BYTES],
        operation_sequence: u64,
        canonical_payload: impl Into<Box<[u8]>>,
    ) -> Self {
        Self {
            authenticated_source_identity,
            session_identity,
            operation_sequence,
            canonical_payload: canonical_payload.into(),
        }
    }
}

fn redacted_debug(
    type_name: &str,
    source: &AuthenticatedNativeOriginSource,
    formatter: &mut Formatter<'_>,
) -> fmt::Result {
    formatter
        .debug_struct(type_name)
        .field("authenticated_source_identity", &"<redacted>")
        .field("session_identity", &"<redacted>")
        .field("operation_sequence", &"<redacted>")
        .field("canonical_payload", &"<redacted>")
        .field("canonical_payload_len", &source.canonical_payload.len())
        .finish()
}

/// Opaque proof that a future fixed native-service channel authenticated one
/// exact native-preparation source.
///
/// No production constructor exists. Possession will become meaningful only
/// when a later platform tranche constructs it after live OS peer and installed
/// identity authentication.
pub struct AuthenticatedNativePreparationSourceV1(AuthenticatedNativeOriginSource);

impl AuthenticatedNativePreparationSourceV1 {
    /// Returns the authenticated source identity for an exact future core join.
    #[must_use]
    pub const fn authenticated_source_identity(&self) -> &[u8; IDENTITY_BYTES] {
        self.0.authenticated_source_identity()
    }

    /// Returns the live authenticated session identity.
    #[must_use]
    pub const fn session_identity(&self) -> &[u8; IDENTITY_BYTES] {
        self.0.session_identity()
    }

    /// Returns the source-owned sequence within this authenticated session and
    /// the nominal native-preparation operation domain.
    ///
    /// The same numeric value in another nominal proof type is not replay.
    #[must_use]
    pub const fn operation_sequence(&self) -> u64 {
        self.0.operation_sequence()
    }

    /// Returns the exact source-produced canonical payload.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        self.0.canonical_payload()
    }
}

impl Debug for AuthenticatedNativePreparationSourceV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        redacted_debug("AuthenticatedNativePreparationSourceV1", &self.0, formatter)
    }
}

/// Opaque proof that a future fixed native-service channel authenticated one
/// exact physical capture-store origin.
///
/// No production constructor exists. A caller-authored acquired anchor, digest,
/// boolean, or serialized message cannot construct this type.
pub struct AuthenticatedCaptureStoreOriginSourceV1(AuthenticatedNativeOriginSource);

impl AuthenticatedCaptureStoreOriginSourceV1 {
    /// Returns the authenticated source identity for an exact future core join.
    #[must_use]
    pub const fn authenticated_source_identity(&self) -> &[u8; IDENTITY_BYTES] {
        self.0.authenticated_source_identity()
    }

    /// Returns the live authenticated session identity.
    #[must_use]
    pub const fn session_identity(&self) -> &[u8; IDENTITY_BYTES] {
        self.0.session_identity()
    }

    /// Returns the source-owned sequence within this authenticated session and
    /// the nominal capture-store-origin operation domain.
    ///
    /// The same numeric value in another nominal proof type is not replay.
    #[must_use]
    pub const fn operation_sequence(&self) -> u64 {
        self.0.operation_sequence()
    }

    /// Returns the exact source-produced canonical payload.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        self.0.canonical_payload()
    }
}

impl Debug for AuthenticatedCaptureStoreOriginSourceV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        redacted_debug(
            "AuthenticatedCaptureStoreOriginSourceV1",
            &self.0,
            formatter,
        )
    }
}

/// Opaque proof that a future fixed native-service channel authenticated one
/// exact V13 initialization source and service-owned protocol identity.
///
/// No production constructor or V13 service route exists in this crate.
pub struct AuthenticatedV13InitializationSourceV1(AuthenticatedNativeOriginSource);

impl AuthenticatedV13InitializationSourceV1 {
    /// Returns the authenticated source identity for an exact future core join.
    #[must_use]
    pub const fn authenticated_source_identity(&self) -> &[u8; IDENTITY_BYTES] {
        self.0.authenticated_source_identity()
    }

    /// Returns the live authenticated session identity.
    #[must_use]
    pub const fn session_identity(&self) -> &[u8; IDENTITY_BYTES] {
        self.0.session_identity()
    }

    /// Returns the source-owned sequence within this authenticated session and
    /// the nominal V13-initialization operation domain.
    ///
    /// The same numeric value in another nominal proof type is not replay.
    #[must_use]
    pub const fn operation_sequence(&self) -> u64 {
        self.0.operation_sequence()
    }

    /// Returns the exact source-produced canonical payload.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        self.0.canonical_payload()
    }
}

impl Debug for AuthenticatedV13InitializationSourceV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        redacted_debug("AuthenticatedV13InitializationSourceV1", &self.0, formatter)
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        AuthenticatedCaptureStoreOriginSourceV1, AuthenticatedNativeOriginSource,
        AuthenticatedNativePreparationSourceV1, AuthenticatedV13InitializationSourceV1,
    };

    const SOURCE_CANARY: [u8; 32] = [0x41; 32];
    const SESSION_CANARY: [u8; 32] = [0x42; 32];
    const PAYLOAD_CANARY: &[u8] = b"native-origin-payload-canary";

    fn source() -> AuthenticatedNativeOriginSource {
        AuthenticatedNativeOriginSource::from_test_fixture(
            SOURCE_CANARY,
            SESSION_CANARY,
            7,
            PAYLOAD_CANARY,
        )
    }

    #[test]
    fn operation_specific_accessors_preserve_exact_test_fixture() {
        let preparation = AuthenticatedNativePreparationSourceV1(source());
        assert_eq!(preparation.authenticated_source_identity(), &SOURCE_CANARY);
        assert_eq!(preparation.session_identity(), &SESSION_CANARY);
        assert_eq!(preparation.operation_sequence(), 7);
        assert_eq!(preparation.canonical_payload(), PAYLOAD_CANARY);

        let capture = AuthenticatedCaptureStoreOriginSourceV1(source());
        assert_eq!(capture.authenticated_source_identity(), &SOURCE_CANARY);
        assert_eq!(capture.session_identity(), &SESSION_CANARY);
        assert_eq!(capture.operation_sequence(), 7);
        assert_eq!(capture.canonical_payload(), PAYLOAD_CANARY);

        let initialization = AuthenticatedV13InitializationSourceV1(source());
        assert_eq!(
            initialization.authenticated_source_identity(),
            &SOURCE_CANARY
        );
        assert_eq!(initialization.session_identity(), &SESSION_CANARY);
        assert_eq!(initialization.operation_sequence(), 7);
        assert_eq!(initialization.canonical_payload(), PAYLOAD_CANARY);
    }

    #[test]
    fn equal_sequences_remain_nominally_distinct_operation_domains() {
        let preparation = AuthenticatedNativePreparationSourceV1(source());
        let capture = AuthenticatedCaptureStoreOriginSourceV1(source());
        let initialization = AuthenticatedV13InitializationSourceV1(source());
        assert_eq!(
            preparation.operation_sequence(),
            capture.operation_sequence()
        );
        assert_eq!(
            capture.operation_sequence(),
            initialization.operation_sequence()
        );

        assert_ne!(
            TypeId::of::<AuthenticatedNativePreparationSourceV1>(),
            TypeId::of::<AuthenticatedCaptureStoreOriginSourceV1>()
        );
        assert_ne!(
            TypeId::of::<AuthenticatedCaptureStoreOriginSourceV1>(),
            TypeId::of::<AuthenticatedV13InitializationSourceV1>()
        );
        assert_ne!(
            TypeId::of::<AuthenticatedNativePreparationSourceV1>(),
            TypeId::of::<AuthenticatedV13InitializationSourceV1>()
        );
    }

    #[test]
    fn debug_is_redacted_for_every_operation() {
        for rendered in [
            format!("{:?}", AuthenticatedNativePreparationSourceV1(source())),
            format!("{:?}", AuthenticatedCaptureStoreOriginSourceV1(source())),
            format!("{:?}", AuthenticatedV13InitializationSourceV1(source())),
        ] {
            assert!(rendered.contains("<redacted>"));
            assert!(rendered.contains("canonical_payload_len: 28"));
            assert!(!rendered.contains("operation_sequence: 7"));
            assert!(!rendered.contains("native-origin-payload-canary"));
            assert!(!rendered.contains(&"41".repeat(32)));
            assert!(!rendered.contains(&"42".repeat(32)));
        }
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("mechanism crate remains under workspace/crates")
            .to_path_buf()
    }

    fn dependency_entries(manifest: &str) -> Vec<&str> {
        let mut dependency_section = false;
        let mut entries = Vec::new();
        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                dependency_section = trimmed == "[dependencies]"
                    || trimmed == "[dev-dependencies]"
                    || trimmed == "[build-dependencies]"
                    || trimmed.starts_with("[target.") && trimmed.ends_with(".dependencies]");
                continue;
            }
            if dependency_section && !trimmed.is_empty() && !trimmed.starts_with('#') {
                entries.push(trimmed);
            }
        }
        entries
    }

    #[test]
    fn source_policy_keeps_mechanism_below_every_product_crate() {
        let crate_manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let crate_manifest =
            fs::read_to_string(crate_manifest_path).expect("read native-origin manifest");
        assert_eq!(dependency_entries(&crate_manifest), Vec::<&str>::new());
        assert!(crate_manifest.contains("publish = false"));

        let workspace_manifest = fs::read_to_string(workspace_root().join("Cargo.toml"))
            .expect("read workspace manifest");
        assert!(workspace_manifest.contains("\"crates/grok-build-native-origin\""));

        for forbidden_product_dependency in [
            "grok-build-core",
            "grok-build-runner",
            "grok-build-providers",
            "grok-build-desktop",
        ] {
            assert!(!crate_manifest.contains(forbidden_product_dependency));
        }
    }
}
