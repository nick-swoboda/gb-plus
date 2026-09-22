use super::{
    GUEST_IMAGE_PIN_V1, GUEST_KERNEL_ACQUISITION_SCRIPT, GUEST_KERNEL_SOURCE_PIN_V1, GuestImagePin,
    GuestImageRole, GuestImageVerification, PublishedArchivePin, VerifiedGuestArtifact,
    VzGuestErrorKind, VzLinuxGuestPlan, committed_pin,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// The placeholder artifacts the fixture writes, pinned exactly the way the
/// product's own artifacts are. A test that could not produce a genuine
/// verification would be testing a different gate than the one that ships.
const FIXTURE_KERNEL_BYTES: &[u8] = b"not a kernel";
const FIXTURE_KERNEL_PIN: GuestImagePin = GuestImagePin {
    role: GuestImageRole::Kernel,
    sha256: "ca5e3e91e7ec9ea017b59edb38e8b10ca1ee0a13207afbdc5caa9aacf414012b",
    byte_length: 12,
};
const FIXTURE_RAMDISK_BYTES: &[u8] = b"not a ramdisk";
const FIXTURE_RAMDISK_PIN: GuestImagePin = GuestImagePin {
    role: GuestImageRole::RootFilesystem,
    sha256: "4e76757f1f1150c9986e24a2b33187d0a6f45cbe18619bcbcb1affd6f1bda8a7",
    byte_length: 13,
};

/// A private directory holding the inert artifacts a plan can name.
struct PlanFixture(PathBuf);

impl PlanFixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "grok-build-vz-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |value| value.as_nanos())
        ));
        fs::create_dir_all(root.join("share")).expect("create the guest plan fixture");
        fs::write(root.join("Image"), FIXTURE_KERNEL_BYTES).expect("write the kernel placeholder");
        fs::write(root.join("initramfs"), FIXTURE_RAMDISK_BYTES)
            .expect("write the ramdisk placeholder");
        Self(root)
    }

    fn verification(&self) -> GuestImageVerification {
        GuestImageVerification::from_parts(
            VerifiedGuestArtifact::verify(FIXTURE_KERNEL_PIN, &self.0.join("Image"))
                .expect("the fixture kernel matches its own pin"),
            VerifiedGuestArtifact::verify(FIXTURE_RAMDISK_PIN, &self.0.join("initramfs"))
                .expect("the fixture ramdisk matches its own pin"),
        )
    }

    fn plan(&self) -> VzLinuxGuestPlan {
        VzLinuxGuestPlan {
            kernel_image: self.0.join("Image"),
            initial_ramdisk: self.0.join("initramfs"),
            shared_directory: self.0.join("share"),
            share_tag: "gbdws".to_owned(),
            command_line: "console=hvc0".to_owned(),
            processor_count: 2,
            memory_bytes: 1024 * 1024 * 1024,
            budget: Duration::from_secs(5),
            verification: self.verification(),
        }
    }
}

impl Drop for PlanFixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

/// An artifact the plan names but the host does not have is refused before any
/// Objective-C object exists, because a framework-side failure there is an
/// uncatchable exception rather than a value.
#[test]
fn a_plan_naming_an_absent_artifact_is_refused_before_any_framework_object() {
    let fixture = PlanFixture::new("absent-artifact");
    let mut plan = fixture.plan();
    plan.kernel_image = fixture.0.join("no-such-kernel");
    let error = plan
        .check_artifacts()
        .expect_err("an absent kernel image is not a bootable plan");
    assert_eq!(*error.kind(), VzGuestErrorKind::MissingBootArtifact);
    assert!(
        error.detail().contains("no-such-kernel"),
        "the refusal must name the artifact: {error}"
    );

    let mut plan = fixture.plan();
    plan.shared_directory = fixture.0.join("Image");
    let error = plan
        .check_artifacts()
        .expect_err("a file is not a shareable directory");
    assert_eq!(*error.kind(), VzGuestErrorKind::MissingBootArtifact);
}

/// The entitlement is the gate and it fails closed.
///
/// `cargo` never signs a test binary, so this process carries no
/// `com.apple.security.virtualization` entitlement — and the only way to
/// obtain a [`VzGuest`] is through `validated`, which converts the framework's
/// refusal into one typed error naming the entitlement. There is no
/// unconfined fallback for the caller to take, and no machine is constructed.
///
/// The plan carries a genuine committed-pin verification of its own artifacts,
/// so the supply-chain gate ahead of the entitlement gate passes and this test
/// still measures the entitlement rather than the pin.
///
/// [`VzGuest`]: super::darwin_virtualization::VzGuest
#[cfg(target_os = "macos")]
#[test]
fn an_unsigned_host_process_is_refused_with_the_exact_entitlement_reason() {
    use super::darwin_virtualization::VzGuest;
    use std::os::fd::OwnedFd;

    let fixture = PlanFixture::new("entitlement");
    let console = OwnedFd::from(fs::File::create(fixture.0.join("console")).expect("console file"));
    let error = VzGuest::validated(&fixture.plan(), &console)
        .err()
        .expect("an unsigned host process cannot configure a guest");
    assert_eq!(
        *error.kind(),
        VzGuestErrorKind::VirtualizationEntitlementMissing,
        "the refusal must be the entitlement one, not a generic failure: {error}"
    );
    assert!(
        error
            .detail()
            .contains("com.apple.security.virtualization"),
        "the refusal must name the entitlement a build-time signature supplies: {error}"
    );
}

/// Verification is a gate, not a checksum computed from whatever was loaded.
///
/// One flipped byte, one appended byte, and one truncated byte each produce a
/// distinct typed refusal naming what was observed against what was pinned. The
/// control is the same artifact unmodified, which verifies — so the refusals
/// are discriminating rather than constant.
#[test]
fn a_corrupted_boot_artifact_is_refused_by_the_committed_pin_with_no_fallback() {
    let fixture = PlanFixture::new("corrupt-artifact");
    let kernel = fixture.0.join("Image");

    // Control: the untouched artifact verifies, and reports what it read.
    let verified = VerifiedGuestArtifact::verify(FIXTURE_KERNEL_PIN, &kernel)
        .expect("the control artifact matches its committed pin");
    assert_eq!(verified.sha256(), FIXTURE_KERNEL_PIN.sha256);
    assert_eq!(verified.byte_length(), FIXTURE_KERNEL_PIN.byte_length);

    // One flipped byte: same length, different digest.
    let mut corrupted = FIXTURE_KERNEL_BYTES.to_vec();
    corrupted[0] ^= 0x01;
    fs::write(&kernel, &corrupted).expect("write the corrupted kernel");
    let error = VerifiedGuestArtifact::verify(FIXTURE_KERNEL_PIN, &kernel)
        .expect_err("a corrupted artifact must never verify");
    assert_eq!(*error.kind(), VzGuestErrorKind::GuestImageDigestMismatch);
    assert!(
        error.detail().contains(FIXTURE_KERNEL_PIN.sha256),
        "the refusal must name the pin it failed against: {error}"
    );

    // One appended byte: the length check names the length rather than leaving
    // a diagnosable truncation to present as a digest mismatch.
    let mut longer = FIXTURE_KERNEL_BYTES.to_vec();
    longer.push(b'!');
    fs::write(&kernel, &longer).expect("write the lengthened kernel");
    let error = VerifiedGuestArtifact::verify(FIXTURE_KERNEL_PIN, &kernel)
        .expect_err("a lengthened artifact must never verify");
    assert_eq!(*error.kind(), VzGuestErrorKind::GuestImageLengthMismatch);

    // Truncated to nothing.
    fs::write(&kernel, b"").expect("truncate the kernel");
    let error = VerifiedGuestArtifact::verify(FIXTURE_KERNEL_PIN, &kernel)
        .expect_err("an empty artifact must never verify");
    assert_eq!(*error.kind(), VzGuestErrorKind::GuestImageLengthMismatch);

    // Absent entirely.
    fs::remove_file(&kernel).expect("remove the kernel");
    let error = VerifiedGuestArtifact::verify(FIXTURE_KERNEL_PIN, &kernel)
        .expect_err("an absent artifact must never verify");
    assert_eq!(*error.kind(), VzGuestErrorKind::MissingBootArtifact);
}

/// A verification cannot be carried from one image to another.
///
/// The plan holds the artifacts it boots and the verification that covers them;
/// crossing the two is refused before any framework object exists, which is
/// what stops a verified image from authorizing the boot of a different one.
#[test]
fn a_verification_for_other_artifacts_does_not_cover_a_plan() {
    let first = PlanFixture::new("cover-first");
    let second = PlanFixture::new("cover-second");
    let verification = first.verification();
    assert!(
        verification.covers(&first.0.join("Image"), &first.0.join("initramfs")),
        "a verification must cover the artifacts it was produced from"
    );
    assert!(
        !verification.covers(&second.0.join("Image"), &second.0.join("initramfs")),
        "a verification must not cover artifacts it never read"
    );
    assert!(
        !verification.covers(&first.0.join("Image"), &second.0.join("initramfs")),
        "a half-crossed pair must not be covered either"
    );
}

/// Every hexadecimal digit in a digest is lowercase, and there are 64 of them.
fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The kernel's source identity is complete and unambiguous.
///
/// A supply-chain pin whose fields are half-filled is worse than none, because
/// it reads as evidence. This asserts the shape of every field the chain
/// depends on: the anchor is a full 40-digit uppercase fingerprint, every
/// digest is a SHA-256, both archives are the pinned architecture at the same
/// version, and each pool path actually names its own package and
/// architecture — so a pin edited to point at another package or another
/// architecture fails here rather than at a download.
#[test]
fn the_committed_kernel_source_pin_is_a_complete_canonical_identity() {
    let pin = GUEST_KERNEL_SOURCE_PIN_V1;

    assert_eq!(pin.key_fingerprint.len(), 40, "an OpenPGP v4 fingerprint");
    assert!(
        pin.key_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)),
        "the anchor is uppercase hexadecimal: {}",
        pin.key_fingerprint
    );
    assert!(is_sha256(pin.key_sha256), "the key digest is a SHA-256");
    assert!(is_sha256(pin.module_sha256), "the module digest is a SHA-256");
    assert!(pin.module_byte_length > 0, "a pinned module has bytes");
    assert!(
        pin.keyring_url.starts_with("https://"),
        "the keyring is fetched over TLS even though its contents are not trusted: {}",
        pin.keyring_url
    );
    assert!(!pin.suite.is_empty() && !pin.component.is_empty());
    assert_eq!(pin.architecture, "arm64", "Apple Silicon guests are arm64");

    for archive in [pin.kernel_archive, pin.module_archive] {
        let PublishedArchivePin {
            package,
            version,
            architecture,
            pool_path,
            sha256,
            byte_length,
        } = archive;
        assert!(is_sha256(sha256), "{package} is pinned by SHA-256");
        assert!(byte_length > 0, "{package} has bytes");
        assert_eq!(
            architecture, pin.architecture,
            "{package} must be the same architecture as the chain"
        );
        assert!(
            pool_path.starts_with("pool/"),
            "{package} must be pinned to an archive pool path: {pool_path}"
        );
        assert!(
            pool_path.contains(package),
            "{package}'s pool path must name it: {pool_path}"
        );
        assert!(
            pool_path.contains(version) && pool_path.ends_with(&format!("_{architecture}.deb")),
            "{package}'s pool path must name its version and architecture: {pool_path}"
        );
    }

    // The kernel release names both the vmlinuz and the module directory, so a
    // module archive from another release could not supply a loadable module.
    assert!(
        pin.kernel_archive.package.contains(pin.kernel_release)
            && pin.module_archive.package.contains(pin.kernel_release),
        "both archives must carry the same kernel release {}",
        pin.kernel_release
    );
}

/// The acquisition step and the runtime gate pin the same bytes.
///
/// Two levels of pin exist — the archive digest Canonical publishes and the
/// digest of the extracted kernel the runtime gate enforces — and they live in
/// two files, so drift between them is the obvious way this could rot into a
/// chain that looks closed and is not. The script is read here and every pinned
/// value is required to appear in it verbatim.
///
/// The second half is a negative check with the same purpose as the runtime
/// gate's "no branch continues": the acquisition step must contain no local
/// fallback, no unauthenticated transport, and no path that reuses a cached
/// artifact, because any of those would let a refused verification still
/// produce a kernel.
#[test]
fn the_guest_kernel_acquisition_script_pins_exactly_what_the_source_constants_pin() {
    let script_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GUEST_KERNEL_ACQUISITION_SCRIPT);
    let script = fs::read_to_string(&script_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", script_path.display()));

    let pin = GUEST_KERNEL_SOURCE_PIN_V1;
    let kernel = committed_pin(GuestImageRole::Kernel);
    let required: Vec<(&str, String)> = vec![
        ("PIN_KEY_FINGERPRINT", pin.key_fingerprint.to_owned()),
        ("PIN_KEY_SHA256", pin.key_sha256.to_owned()),
        ("PIN_KEYRING_URL", pin.keyring_url.to_owned()),
        ("PIN_ARCHIVE_BASE", pin.archive_base.to_owned()),
        ("PIN_SUITE", pin.suite.to_owned()),
        ("PIN_COMPONENT", pin.component.to_owned()),
        ("PIN_ARCHITECTURE", pin.architecture.to_owned()),
        ("PIN_KERNEL_RELEASE", pin.kernel_release.to_owned()),
        ("PIN_KERNEL_PACKAGE", pin.kernel_archive.package.to_owned()),
        ("PIN_KERNEL_VERSION", pin.kernel_archive.version.to_owned()),
        ("PIN_KERNEL_DEB_PATH", pin.kernel_archive.pool_path.to_owned()),
        ("PIN_KERNEL_DEB_SHA256", pin.kernel_archive.sha256.to_owned()),
        (
            "PIN_KERNEL_DEB_BYTES",
            pin.kernel_archive.byte_length.to_string(),
        ),
        ("PIN_KERNEL_SHA256", kernel.sha256.to_owned()),
        ("PIN_KERNEL_BYTES", kernel.byte_length.to_string()),
        ("PIN_MODULE_PACKAGE", pin.module_archive.package.to_owned()),
        ("PIN_MODULE_DEB_PATH", pin.module_archive.pool_path.to_owned()),
        ("PIN_MODULE_DEB_SHA256", pin.module_archive.sha256.to_owned()),
        (
            "PIN_MODULE_DEB_BYTES",
            pin.module_archive.byte_length.to_string(),
        ),
        ("PIN_MODULE_SHA256", pin.module_sha256.to_owned()),
        ("PIN_MODULE_BYTES", pin.module_byte_length.to_string()),
    ];
    for (name, value) in required {
        let assignment = format!("\n{name}={value}\n");
        assert!(
            script.contains(&assignment),
            "{} must pin {name}={value}; the source constant and the script have drifted",
            script_path.display()
        );
    }

    for forbidden in [
        "--insecure",
        "-k ",
        "colima",
        "/lib/modules/$(uname",
        "|| cp ",
        "|| true\nmv",
    ] {
        assert!(
            !script.contains(forbidden),
            "the acquisition step must carry no fallback or unauthenticated transport, found {forbidden:?}"
        );
    }
    assert!(
        script.contains("gpgv --keyring"),
        "the acquisition step must verify the archive signature with the pinned key alone"
    );
}

/// The committed pin set is complete and internally consistent: exactly one pin
/// per role, both digests lowercase hexadecimal SHA-256, both lengths nonzero.
#[test]
fn the_committed_guest_image_pin_set_covers_every_role_exactly_once() {
    assert_eq!(GUEST_IMAGE_PIN_V1.len(), 2);
    for role in [GuestImageRole::Kernel, GuestImageRole::RootFilesystem] {
        let matches = GUEST_IMAGE_PIN_V1
            .iter()
            .filter(|pin| pin.role as u8 == role as u8)
            .count();
        assert_eq!(matches, 1, "exactly one pin per role");
        let pin = committed_pin(role);
        assert_eq!(pin.sha256.len(), 64, "a SHA-256 pin is 64 hex characters");
        assert!(
            pin.sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "a committed pin is lowercase hexadecimal"
        );
        assert!(pin.byte_length > 0, "a pinned artifact has bytes");
    }
}
