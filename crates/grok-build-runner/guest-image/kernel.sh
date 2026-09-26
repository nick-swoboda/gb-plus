#!/bin/sh
# Acquires the guest kernel and its virtiofs module from Canonical's archive,
# along a signature chain whose only trust anchor is a fingerprint pinned in
# this file.
#
# The point is *not* to hash what was downloaded. A digest computed from bytes
# that just arrived proves immutability against the next download, not trust:
# it anchors to whatever the network handed over. What converts this into a
# trust chain is that every digest below is one **Canonical published and
# signed**, and the pinned fingerprint is the only thing believed a priori:
#
#   pinned key fingerprint          (this file, changeable only in a commit)
#     -> OpenPGP signature on InRelease            [gpgv, pinned key only]
#     -> SHA-256 of Packages.xz, taken from InRelease
#     -> SHA-256 and Size of the .deb, taken from Packages
#     -> the .deb's bytes
#     -> the kernel payload carved out of the .deb and decompressed
#     -> the digest the product's runtime gate pins
#
# Each of those is checked, each failure is its own refusal, and no failure has
# a continuation. There is deliberately no cache, no mirror list, no
# "use the local kernel instead", and no unauthenticated transport fallback:
# the output directory's artifacts are removed before the run starts, so a
# refused run cannot leave a previously-verified file behind to be mistaken for
# this run's output.
#
# Network is touched **here only**, this is an image-build step run by a
# developer. The shipped application downloads nothing; it is handed the two
# artifacts by path and verifies them against the constants in
# `crates/grok-build-runner/src/macos_vz_guest/body/part_02.rs`.
#
# Usage:
#   kernel.sh <output-directory>
#
# Output:
#   <out>/Image        raw arm64 kernel image, the artifact the product pins
#   <out>/virtiofs.ko  the matching virtiofs module, input to build.sh
#   <out>/bwrap        the Bubblewrap launcher the Linux command plan names
#   <out>/bwrap.version  its version, read out of the .deb's own control member
#   <out>/digests.txt  every digest and length, for the reviewer
#
# Probe hook, used by the failure-path canaries and by nothing else:
#   GBD_KERNEL_PROBE_CORRUPT=wrong-key|key|signature|release-body|index
#                           |archive|extracted|module-archive|module
#                           |bwrap-archive|bwrap|bwrap-version|unreachable
# corrupts exactly one input at exactly one link so a control run and an
# enforced run differ in one thing.

set -eu

# ---------------------------------------------------------------- the pins
#
# Every value here is Canonical's, except the fingerprint, which is Canonical's
# published identity and the one thing this script does not derive from
# anything else. Reviewers check it against
# <https://ubuntu.com/security/verifications> and the `ubuntu-keyring` package.
# The two `_SHA256` values for the `.deb`s must equal what the signed index
# says; if they ever diverge, that is a refusal, not a resynchronisation.
#
# These must stay equal to `GUEST_KERNEL_SOURCE_PIN_V1` and `GUEST_IMAGE_PIN_V1`
# in `crates/grok-build-runner/src/macos_vz_guest/body/part_02.rs`; the test
# `the_guest_kernel_acquisition_script_pins_exactly_what_the_source_constants_pin`
# fails the build if they drift.

PIN_KEY_FINGERPRINT=F6ECB3762474EDA9D21B7022871920D1991BC93C
PIN_KEY_SHA256=5ebbeeb474034b1fa7e50abbe6f136e177fc826219e01f314b3623f7b3097e96
PIN_KEYRING_URL=https://ports.ubuntu.com/ubuntu-ports/project/ubuntu-archive-keyring.gpg
PIN_ARCHIVE_BASE=http://ports.ubuntu.com/ubuntu-ports
PIN_SUITE=noble-updates
PIN_COMPONENT=main
PIN_ARCHITECTURE=arm64

PIN_KERNEL_PACKAGE=linux-image-6.8.0-117-generic
PIN_KERNEL_VERSION=6.8.0-117.117
PIN_KERNEL_RELEASE=6.8.0-117-generic
PIN_KERNEL_DEB_PATH=pool/main/l/linux-signed/linux-image-6.8.0-117-generic_6.8.0-117.117_arm64.deb
PIN_KERNEL_DEB_SHA256=fcdf0b1cd4529b30e7cdb76325bd0d29344ed23a430598b059da2f180e65b92a
PIN_KERNEL_DEB_BYTES=18280800
PIN_KERNEL_SHA256=ce3cccafc326c6e1cf88a35e2976df1c084f5b1349abc70d0c94f7573181450e
PIN_KERNEL_BYTES=59009416

PIN_MODULE_PACKAGE=linux-modules-6.8.0-117-generic
PIN_MODULE_DEB_PATH=pool/main/l/linux/linux-modules-6.8.0-117-generic_6.8.0-117.117_arm64.deb
PIN_MODULE_DEB_SHA256=42425ac8e58fa2ca9f7bf89105becd94c0bd90908b21889ffffd7132406c5d51
PIN_MODULE_DEB_BYTES=86999232
PIN_MODULE_SHA256=b08fd0a005cbe889d5c5dad82f6100c41e33a4e1638c4af902de29e82361418a
PIN_MODULE_BYTES=55713

# The third package, admitted 2026-08-10. It is not a kernel artifact: `bwrap`
# is the launcher the Linux command plan names in
# `LinuxBinaryIdentitiesV1::bubblewrap`, and it is acquired here because this is
# where the verified chain already is. Nothing about the chain changes to carry
# it, same anchor fingerprint, same keyring, same archive base, same suite,
# same component, same architecture, same `InRelease` signature, same index.
# Only a fourth and fifth per-package pin are added.
#
# `PIN_BWRAP_VERSION` is the package version *as the signed index spells it*,
# and it is used twice: `claim_field` will not match a stanza carrying any other
# version, and the `.deb`'s own `control` member must repeat it. That second
# check is what makes the version the plan commits a **file fact** carried by
# the same signature chain rather than the output of running the binary.
PIN_BWRAP_PACKAGE=bubblewrap
PIN_BWRAP_VERSION=0.9.0-1ubuntu0.1
PIN_BWRAP_DEB_PATH=pool/main/b/bubblewrap/bubblewrap_0.9.0-1ubuntu0.1_arm64.deb
PIN_BWRAP_DEB_SHA256=3fb4ca3a8d2060444836568ed49d6897a403467e4ba29c93440900093fb96a38
PIN_BWRAP_DEB_BYTES=49694
PIN_BWRAP_SHA256=ae27935781511400c65ebcc0b4669775d602f46251b8707c947a1ac1b160c1c8
PIN_BWRAP_BYTES=67816

# ------------------------------------------------------------- refusals
#
# One exit status for the whole script and one refusal line per failure, in the
# same shape as the product's typed errors: kind first, then exactly what was
# observed against exactly what was pinned. No refusal returns.

refuse() {
    kind=$1
    shift
    echo "GBDKS refused kind=$kind detail=$*" >&2
    exit 3
}

report() { echo "GBDKS $*"; }

CORRUPT=${GBD_KERNEL_PROBE_CORRUPT:-none}

digest_of() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        sha256sum "$1" | cut -d' ' -f1
    fi
}

bytes_of() { wc -c < "$1" | tr -d ' '; }

# Flips the final byte of a file. Used only by the probe hook, so an enforced
# run differs from its control by one byte at one link.
corrupt_last_byte() {
    target=$1
    size=$(bytes_of "$target")
    dd if="$target" of="$target.head" bs=1 count=$((size - 1)) 2>/dev/null
    printf '\377' >> "$target.head"
    mv -f "$target.head" "$target"
    report "probe corrupted one byte of $target"
}

# Rewrites one character of the *signed text* of InRelease, the recorded
# digest of the package index, which is the substitution the signature exists
# to stop. The first attempt at this probe flipped the file's last byte
# instead, landed after `-----END PGP SIGNATURE-----`, and the enforced run
# completed: a vacuous probe that the control-versus-enforced discipline
# caught. Length is preserved so nothing else can be what refuses.
corrupt_signed_body() {
    target=$1
    awk '
        /main\/binary-arm64\/Packages\.xz$/ && !done {
            first = substr($0, 2, 1)
            $0 = " " (first == "0" ? "1" : "0") substr($0, 3)
            done = 1
        }
        { print }
    ' "$target" > "$target.tampered"
    mv -f "$target.tampered" "$target"
    report "probe rewrote one character of the signed body of $target"
}

# Rewrites one character inside the armored signature itself.
corrupt_signature_armor() {
    target=$1
    awk '
        /^-----BEGIN PGP SIGNATURE-----$/ { inside = 1 }
        inside && !done && $0 ~ /^[A-Za-z0-9+\/]{40,}$/ {
            first = substr($0, 1, 1)
            $0 = (first == "A" ? "B" : "A") substr($0, 2)
            done = 1
        }
        { print }
    ' "$target" > "$target.tampered"
    mv -f "$target.tampered" "$target"
    report "probe rewrote one character of the armored signature of $target"
}

fetch() {
    # $1 = absolute URL, $2 = destination, $3 = refusal kind for an unreachable
    # or failing transfer. `--fail` so an error page is never mistaken for a
    # payload, `--proto` so a redirect cannot downgrade the scheme set, and
    # nothing anywhere that disables certificate verification, the in-tree
    # test greps this file for exactly those flags.
    curl --silent --show-error --fail --location \
         --proto '=http,https' --max-time 600 \
         --output "$2" "$1" || refuse "$3" "$1 could not be fetched"
}

need() {
    command -v "$1" >/dev/null 2>&1 ||
        refuse ToolMissing "$1 is required to verify the kernel supply chain and is not on PATH"
}

for tool in curl gpg gpgv xz ar tar zstd gzip dd od awk sed grep; do
    need "$tool"
done

OUT=${1:?usage: kernel.sh <output-directory>}
mkdir -p "$OUT"
WORK="$OUT/.acquire"
rm -rf "$WORK"
mkdir -p "$WORK"
# No previously verified artifact may survive a refused run.
rm -f "$OUT/Image" "$OUT/virtiofs.ko" "$OUT/bwrap" "$OUT/bwrap.version" \
      "$OUT/digests.txt"

GNUPGHOME="$WORK/gnupg"
export GNUPGHOME
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

# ------------------------------------------------- link 1: the trust anchor
#
# The keyring is fetched from Canonical, but nothing about the fetch is
# trusted: the single key is exported out of it by fingerprint, and the export
# is then checked twice, its own fingerprint against the pin, and its bytes
# against the pinned digest. A substituted keyring fails both.

fetch "$PIN_KEYRING_URL" "$WORK/keyring.gpg" KeyringUnavailable

# The probe's `wrong-key` half exports a *different* key that the same Canonical
# keyring genuinely contains, the 2012 archive key. Nothing about the transfer
# changes; only which key is offered as the anchor, which is the one input the
# fingerprint pin exists to discriminate.
EXPORT_FINGERPRINT=$PIN_KEY_FINGERPRINT
if [ "$CORRUPT" = wrong-key ]; then
    EXPORT_FINGERPRINT=790BC7277767219C42C86F933B4FE6ACC0B21F32
    report "probe substituted key $EXPORT_FINGERPRINT for the pinned anchor"
fi

gpg --no-default-keyring --keyring "$WORK/keyring.gpg" \
    --export "$EXPORT_FINGERPRINT" > "$WORK/canonical.gpg" 2>/dev/null || true
[ -s "$WORK/canonical.gpg" ] ||
    refuse KeyNotInKeyring \
        "$PIN_KEY_FINGERPRINT is absent from $PIN_KEYRING_URL"

if [ "$CORRUPT" = key ]; then
    corrupt_last_byte "$WORK/canonical.gpg"
fi

OBSERVED_FINGERPRINT=$(
    gpg --no-default-keyring --keyring "$WORK/canonical.gpg" \
        --list-keys --with-colons --fingerprint 2>/dev/null |
        awk -F: '/^fpr:/ { print $10; exit }'
)
[ "$OBSERVED_FINGERPRINT" = "$PIN_KEY_FINGERPRINT" ] ||
    refuse KeyFingerprintMismatch \
        "the exported key is ${OBSERVED_FINGERPRINT:-unreadable}; the committed pin is $PIN_KEY_FINGERPRINT"

OBSERVED_KEY_SHA=$(digest_of "$WORK/canonical.gpg")
[ "$OBSERVED_KEY_SHA" = "$PIN_KEY_SHA256" ] ||
    refuse KeyDigestMismatch \
        "the exported key hashes to $OBSERVED_KEY_SHA; the committed pin is $PIN_KEY_SHA256"

report "key fingerprint=$OBSERVED_FINGERPRINT sha256=$OBSERVED_KEY_SHA VERIFIED"

# ------------------------------------------- link 2: the signed suite index
#
# `gpgv` with `--keyring` holding exactly one key: there is no keyring of
# "keys this machine happens to trust" in the picture, and no web of trust. A
# good signature by any other key is still a refusal, because the status line
# must name the pinned fingerprint.

fetch "$PIN_ARCHIVE_BASE/dists/$PIN_SUITE/InRelease" "$WORK/InRelease" ReleaseUnavailable

if [ "$CORRUPT" = signature ]; then
    corrupt_signature_armor "$WORK/InRelease"
fi
if [ "$CORRUPT" = release-body ]; then
    corrupt_signed_body "$WORK/InRelease"
fi

gpgv --keyring "$WORK/canonical.gpg" --status-fd 3 "$WORK/InRelease" \
    3> "$WORK/gpgv.status" 2> "$WORK/gpgv.err" ||
    refuse ReleaseSignatureInvalid \
        "$(tr '\n' ' ' < "$WORK/gpgv.err")"

grep -q "^\[GNUPG:\] VALIDSIG $PIN_KEY_FINGERPRINT " "$WORK/gpgv.status" ||
    refuse ReleaseSignedByWrongKey \
        "InRelease carries no VALIDSIG from $PIN_KEY_FINGERPRINT: $(tr '\n' ' ' < "$WORK/gpgv.status")"

# The signature says "Canonical signed this file"; these two say "and the file
# is the suite and architecture this build asked for", which a replayed
# InRelease from another suite would fail.
grep -q "^Suite: $PIN_SUITE\$" "$WORK/InRelease" ||
    refuse ReleaseIdentityMismatch "InRelease is not Suite: $PIN_SUITE"
grep -q "^Architectures:.* $PIN_ARCHITECTURE" "$WORK/InRelease" ||
    refuse ReleaseIdentityMismatch "InRelease does not carry architecture $PIN_ARCHITECTURE"

report "InRelease signature=GOOD key=$PIN_KEY_FINGERPRINT suite=$PIN_SUITE VERIFIED"

# ------------------------------------------------ link 3: the package index
#
# The SHA-256 comes out of the *signed* text, so from here on every digest is
# Canonical's claim rather than an observation of the transfer.

INDEX_PATH="$PIN_COMPONENT/binary-$PIN_ARCHITECTURE/Packages.xz"
INDEX_CLAIM=$(
    awk -v want="$INDEX_PATH" '
        /^SHA256:/ { inside = 1; next }
        /^[A-Za-z][A-Za-z0-9-]*:/ { inside = 0 }
        inside && $3 == want { print $1, $2; exit }
    ' "$WORK/InRelease"
)
[ -n "$INDEX_CLAIM" ] ||
    refuse IndexNotInRelease "the signed InRelease records no SHA-256 for $INDEX_PATH"
INDEX_SHA=${INDEX_CLAIM% *}
INDEX_BYTES=${INDEX_CLAIM#* }

fetch "$PIN_ARCHIVE_BASE/dists/$PIN_SUITE/$INDEX_PATH" "$WORK/Packages.xz" IndexUnavailable

if [ "$CORRUPT" = index ]; then
    corrupt_last_byte "$WORK/Packages.xz"
fi

OBSERVED_INDEX_SHA=$(digest_of "$WORK/Packages.xz")
OBSERVED_INDEX_BYTES=$(bytes_of "$WORK/Packages.xz")
[ "$OBSERVED_INDEX_BYTES" = "$INDEX_BYTES" ] ||
    refuse IndexLengthMismatch \
        "$INDEX_PATH is $OBSERVED_INDEX_BYTES bytes; the signed InRelease says $INDEX_BYTES"
[ "$OBSERVED_INDEX_SHA" = "$INDEX_SHA" ] ||
    refuse IndexDigestMismatch \
        "$INDEX_PATH hashes to $OBSERVED_INDEX_SHA; the signed InRelease says $INDEX_SHA"

xz -dc "$WORK/Packages.xz" > "$WORK/Packages" ||
    refuse IndexUnreadable "$INDEX_PATH could not be decompressed"

report "index $INDEX_PATH sha256=$OBSERVED_INDEX_SHA bytes=$OBSERVED_INDEX_BYTES VERIFIED against the signed InRelease"

# ------------------------------------------------------ link 4: the archives
#
# `claim_field` reads one field out of the one stanza naming this package at
# this version for this architecture. A stanza for another architecture cannot
# satisfy it, which is what keeps an arm64 build from silently pinning amd64.

claim_field() {
    awk -v pkg="$1" -v ver="$2" -v arch="$3" -v field="$4" '
        BEGIN { RS = ""; FS = "\n" }
        {
            name = ""; version = ""; architecture = ""; value = ""
            for (line = 1; line <= NF; line++) {
                if (index($line, "Package: ") == 1) { name = substr($line, 10) }
                else if (index($line, "Version: ") == 1) { version = substr($line, 10) }
                else if (index($line, "Architecture: ") == 1) { architecture = substr($line, 15) }
                if (index($line, field ": ") == 1) { value = substr($line, length(field) + 3) }
            }
            if (name == pkg && version == ver && architecture == arch && value != "") {
                print value
                exit
            }
        }
    ' "$WORK/Packages"
}

# $1 package, $2 pinned pool path, $3 pinned sha256, $4 pinned byte length,
# $5 destination, $6 refusal prefix ("" for the kernel, "Module" for the module,
# "Bwrap" for Bubblewrap), $7 pinned package version as the index spells it.
#
# The version was a closed-over `$PIN_KERNEL_VERSION` while both packages came
# from one source release. It is a parameter now because Bubblewrap is versioned
# independently, and a helper that silently reused the kernel's version would
# have looked up a stanza that does not exist and refused with the wrong reason.
acquire_archive() {
    package=$1; pin_path=$2; pin_sha=$3; pin_bytes=$4; destination=$5; prefix=$6
    version=$7

    claimed_path=$(claim_field "$package" "$version" "$PIN_ARCHITECTURE" Filename)
    [ -n "$claimed_path" ] ||
        refuse "${prefix}PackageNotInIndex" \
            "$package $version $PIN_ARCHITECTURE is not in the signed index for $PIN_SUITE"
    claimed_sha=$(claim_field "$package" "$version" "$PIN_ARCHITECTURE" SHA256)
    claimed_bytes=$(claim_field "$package" "$version" "$PIN_ARCHITECTURE" Size)

    # Canonical's claim against the committed pin, before a byte is fetched.
    # This is the check that makes the digest below Canonical's rather than
    # this script's: if the archive ever says something else, the run refuses.
    [ "$claimed_path" = "$pin_path" ] ||
        refuse "${prefix}ArchiveClaimMismatch" \
            "the signed index places $package at $claimed_path; the committed pin is $pin_path"
    [ "$claimed_sha" = "$pin_sha" ] ||
        refuse "${prefix}ArchiveClaimMismatch" \
            "the signed index records $package as $claimed_sha; the committed pin is $pin_sha"
    [ "$claimed_bytes" = "$pin_bytes" ] ||
        refuse "${prefix}ArchiveClaimMismatch" \
            "the signed index records $package as $claimed_bytes bytes; the committed pin is $pin_bytes"

    base=$PIN_ARCHIVE_BASE
    if [ "$CORRUPT" = unreachable ]; then
        base=http://ports.ubuntu.example.invalid/ubuntu-ports
    fi
    fetch "$base/$claimed_path" "$destination" "${prefix}ArchiveUnavailable"

    if [ "$CORRUPT" = archive ] && [ "$prefix" = "" ]; then
        corrupt_last_byte "$destination"
    fi
    if [ "$CORRUPT" = module-archive ] && [ "$prefix" = Module ]; then
        corrupt_last_byte "$destination"
    fi
    if [ "$CORRUPT" = bwrap-archive ] && [ "$prefix" = Bwrap ]; then
        corrupt_last_byte "$destination"
    fi

    observed_bytes=$(bytes_of "$destination")
    observed_sha=$(digest_of "$destination")
    [ "$observed_bytes" = "$claimed_bytes" ] ||
        refuse "${prefix}ArchiveLengthMismatch" \
            "$claimed_path is $observed_bytes bytes; Canonical's signed index says $claimed_bytes"
    [ "$observed_sha" = "$claimed_sha" ] ||
        refuse "${prefix}ArchiveDigestMismatch" \
            "$claimed_path hashes to $observed_sha; Canonical's signed index says $claimed_sha"

    report "archive $claimed_path sha256=$observed_sha bytes=$observed_bytes VERIFIED against the signed index"
}

# Extracts one member of a `.deb`'s data archive to stdout, handling both the
# uncompressed and the zstd-compressed data member Ubuntu ships.
deb_member() {
    archive=$1; member=$2; into=$3
    members=$(ar t "$archive")
    case "$members" in
        *data.tar.zst*)
            ar p "$archive" data.tar.zst | zstd -dcq > "$WORK/data.tar" ;;
        *data.tar.xz*)
            ar p "$archive" data.tar.xz | xz -dc > "$WORK/data.tar" ;;
        *data.tar*)
            ar p "$archive" data.tar > "$WORK/data.tar" ;;
        *)
            refuse ArchiveLayoutUnrecognised "$archive carries no data member: $members" ;;
    esac
    tar -C "$into" -xf "$WORK/data.tar" "$member" ||
        refuse ArchiveMemberMissing "$archive carries no $member"
    rm -f "$WORK/data.tar"
}

# The same, for the `.deb`'s *control* archive. This is deliberately separate
# from `deb_member`: the control member carries the package's own declared
# metadata, and reading a version out of it is the whole reason the Bubblewrap
# version the plan commits does not require executing the binary.
deb_control_member() {
    archive=$1; member=$2; into=$3
    members=$(ar t "$archive")
    case "$members" in
        *control.tar.zst*)
            ar p "$archive" control.tar.zst | zstd -dcq > "$WORK/control.tar" ;;
        *control.tar.xz*)
            ar p "$archive" control.tar.xz | xz -dc > "$WORK/control.tar" ;;
        *control.tar.gz*)
            ar p "$archive" control.tar.gz | gzip -dc > "$WORK/control.tar" ;;
        *control.tar*)
            ar p "$archive" control.tar > "$WORK/control.tar" ;;
        *)
            refuse ArchiveLayoutUnrecognised "$archive carries no control member: $members" ;;
    esac
    tar -C "$into" -xf "$WORK/control.tar" "$member" ||
        refuse ArchiveMemberMissing "$archive carries no control member $member"
    rm -f "$WORK/control.tar"
}

acquire_archive "$PIN_KERNEL_PACKAGE" "$PIN_KERNEL_DEB_PATH" \
    "$PIN_KERNEL_DEB_SHA256" "$PIN_KERNEL_DEB_BYTES" "$WORK/kernel.deb" "" \
    "$PIN_KERNEL_VERSION"

acquire_archive "$PIN_MODULE_PACKAGE" "$PIN_MODULE_DEB_PATH" \
    "$PIN_MODULE_DEB_SHA256" "$PIN_MODULE_DEB_BYTES" "$WORK/modules.deb" Module \
    "$PIN_KERNEL_VERSION"

acquire_archive "$PIN_BWRAP_PACKAGE" "$PIN_BWRAP_DEB_PATH" \
    "$PIN_BWRAP_DEB_SHA256" "$PIN_BWRAP_DEB_BYTES" "$WORK/bubblewrap.deb" Bwrap \
    "$PIN_BWRAP_VERSION"

# --------------------------------------------- link 5: the bootable payload
#
# Virtualization.framework's boot loader wants the raw arm64 `Image`, and a
# distribution ships `vmlinuz`, which is not that. Two shapes exist in the
# wild and both are handled explicitly rather than by trying decompressors
# until one works:
#
#   * a plain gzip stream whose expansion is the `Image`, what Ubuntu's
#     arm64 6.8 kernels are, measured, not assumed; and
#   * an EFI zboot container: a PE/COFF stub with `zimg` at offset 12, the
#     payload offset and length as little-endian u32s at 16 and 20, and the
#     compressor named in 32 bytes at offset 32, what newer arm64 kernels
#     ship, handled here so a future version bump is a measurement rather than
#     a redesign.
#
# Anything else refuses. The result is then checked to be an arm64 `Image`
# (`ARMd` at offset 56) before its digest is compared, so a payload that
# decompressed into something else is named as such.

mkdir -p "$WORK/kernel"
deb_member "$WORK/kernel.deb" "./boot/vmlinuz-$PIN_KERNEL_RELEASE" "$WORK/kernel"
VMLINUZ="$WORK/kernel/boot/vmlinuz-$PIN_KERNEL_RELEASE"
report "payload vmlinuz-$PIN_KERNEL_RELEASE sha256=$(digest_of "$VMLINUZ") bytes=$(bytes_of "$VMLINUZ")"

u32_at() { od -An -tu4 -j "$1" -N 4 "$2" | tr -d ' \n'; }
magic_at() { od -An -c -j "$1" -N "$2" "$3" | tr -d ' \n'; }

GZIP_MAGIC=$(od -An -tx1 -j 0 -N 2 "$VMLINUZ" | tr -d ' \n')
ZBOOT_MAGIC=$(magic_at 12 4 "$VMLINUZ")

if [ "$GZIP_MAGIC" = 1f8b ]; then
    KERNEL_FORMAT=gzip
    gzip -dc "$VMLINUZ" > "$WORK/Image" ||
        refuse KernelPayloadUndecompressible "the gzip payload of vmlinuz did not expand"
elif [ "$ZBOOT_MAGIC" = zimg ]; then
    PAYLOAD_OFFSET=$(u32_at 16 "$VMLINUZ")
    PAYLOAD_BYTES=$(u32_at 20 "$VMLINUZ")
    COMPRESSION=$(od -An -c -j 32 -N 32 "$VMLINUZ" | tr -d ' \n' | sed 's/\\0.*//')
    KERNEL_FORMAT="efi-zboot/$COMPRESSION"
    dd if="$VMLINUZ" of="$WORK/payload" bs=1 \
        skip="$PAYLOAD_OFFSET" count="$PAYLOAD_BYTES" 2>/dev/null
    case "$COMPRESSION" in
        gzip) gzip -dc "$WORK/payload" > "$WORK/Image" ;;
        lzma|xzkern|xz) xz -dc --format=lzma "$WORK/payload" > "$WORK/Image" 2>/dev/null ||
                        xz -dc "$WORK/payload" > "$WORK/Image" ;;
        zstd22|zstd) zstd -dcq "$WORK/payload" > "$WORK/Image" ;;
        *) refuse KernelPayloadUnrecognised \
               "the EFI zboot payload is compressed with '$COMPRESSION', which this build step does not decompress" ;;
    esac
else
    refuse KernelPayloadUnrecognised \
        "vmlinuz is neither a gzip stream nor an EFI zboot container (magic $GZIP_MAGIC / '$ZBOOT_MAGIC')"
fi

if [ "$CORRUPT" = extracted ]; then
    corrupt_last_byte "$WORK/Image"
fi

ARM64_MAGIC=$(magic_at 56 4 "$WORK/Image")
[ "$ARM64_MAGIC" = ARMd ] ||
    refuse NotAnArm64KernelImage \
        "the extracted payload carries '$ARM64_MAGIC' where an arm64 Image carries ARMd at offset 56"

OBSERVED_KERNEL_BYTES=$(bytes_of "$WORK/Image")
OBSERVED_KERNEL_SHA=$(digest_of "$WORK/Image")
[ "$OBSERVED_KERNEL_BYTES" = "$PIN_KERNEL_BYTES" ] ||
    refuse ExtractedKernelLengthMismatch \
        "the extracted kernel is $OBSERVED_KERNEL_BYTES bytes; the committed pin is $PIN_KERNEL_BYTES"
[ "$OBSERVED_KERNEL_SHA" = "$PIN_KERNEL_SHA256" ] ||
    refuse ExtractedKernelDigestMismatch \
        "the extracted kernel hashes to $OBSERVED_KERNEL_SHA; the committed pin is $PIN_KERNEL_SHA256"

report "kernel format=$KERNEL_FORMAT sha256=$OBSERVED_KERNEL_SHA bytes=$OBSERVED_KERNEL_BYTES VERIFIED against the committed runtime pin"

# ------------------------------------------------- link 6: the guest module
#
# The module has to come from the same publisher and the same kernel release
# as the kernel, because PID 1 inserts it with `finit_module` and a mismatched
# vermagic is a boot that half-works. Ubuntu ships modules zstd-compressed; the
# guest's PID 1 has no decompressor, so it is expanded here.

mkdir -p "$WORK/module"
MODULE_MEMBER="./lib/modules/$PIN_KERNEL_RELEASE/kernel/fs/fuse/virtiofs.ko.zst"
deb_member "$WORK/modules.deb" "$MODULE_MEMBER" "$WORK/module"
zstd -dcq "$WORK/module/lib/modules/$PIN_KERNEL_RELEASE/kernel/fs/fuse/virtiofs.ko.zst" \
    > "$WORK/virtiofs.ko" ||
    refuse ModulePayloadUndecompressible "virtiofs.ko.zst did not expand"

if [ "$CORRUPT" = module ]; then
    corrupt_last_byte "$WORK/virtiofs.ko"
fi

OBSERVED_MODULE_BYTES=$(bytes_of "$WORK/virtiofs.ko")
OBSERVED_MODULE_SHA=$(digest_of "$WORK/virtiofs.ko")
[ "$OBSERVED_MODULE_BYTES" = "$PIN_MODULE_BYTES" ] ||
    refuse ExtractedModuleLengthMismatch \
        "virtiofs.ko is $OBSERVED_MODULE_BYTES bytes; the committed pin is $PIN_MODULE_BYTES"
[ "$OBSERVED_MODULE_SHA" = "$PIN_MODULE_SHA256" ] ||
    refuse ExtractedModuleDigestMismatch \
        "virtiofs.ko hashes to $OBSERVED_MODULE_SHA; the committed pin is $PIN_MODULE_SHA256"

report "module virtiofs.ko sha256=$OBSERVED_MODULE_SHA bytes=$OBSERVED_MODULE_BYTES VERIFIED against the committed pin"

# ------------------------------------------------- link 7: the Bubblewrap image
#
# Two things are carved out of this archive and both are file facts under the
# signature chain above:
#
#   * `./usr/bin/bwrap`, the launcher itself, hashed against the committed pin;
#     and
#   * `./control`'s `Version:` field, which is the string the Linux command plan
#     commits as `LinuxBinaryIdentitiesV1::bubblewrap_version`.
#
# The version is read rather than probed **on purpose**. `bwrap --version`
# would be an execution of a freshly downloaded binary on the build host, and
# its answer would be outside the chain, nothing would tie it to the archive
# Canonical signed. The control member is inside the `.deb` whose digest the
# signed index vouched for, so reading it keeps the version at the same level of
# trust as the bytes. It is also the *package* version, which identifies the
# exact build, where `bwrap --version` reports only the upstream release.
#
# No maintainer script runs. `dpkg` is not involved anywhere: the archive is an
# `ar` container and two members are read out of it.

mkdir -p "$WORK/bwrap-data" "$WORK/bwrap-control"
deb_member "$WORK/bubblewrap.deb" "./usr/bin/bwrap" "$WORK/bwrap-data"
deb_control_member "$WORK/bubblewrap.deb" "./control" "$WORK/bwrap-control"
cp "$WORK/bwrap-data/usr/bin/bwrap" "$WORK/bwrap"

if [ "$CORRUPT" = bwrap ]; then
    corrupt_last_byte "$WORK/bwrap"
fi

OBSERVED_BWRAP_VERSION=$(
    awk '/^Version: / { print substr($0, 10); exit }' "$WORK/bwrap-control/control"
)
if [ "$CORRUPT" = bwrap-version ]; then
    OBSERVED_BWRAP_VERSION="${OBSERVED_BWRAP_VERSION}+probe"
    report "probe rewrote the version read out of the control member"
fi
[ "$OBSERVED_BWRAP_VERSION" = "$PIN_BWRAP_VERSION" ] ||
    refuse BubblewrapVersionMismatch \
        "the archive's control member declares '${OBSERVED_BWRAP_VERSION:-nothing}'; the signed index and the committed pin both say $PIN_BWRAP_VERSION"

# The architecture is measured out of the ELF header rather than inferred from
# the pool path, for the same reason the kernel's `ARMd` check exists: a pinned
# filename is a claim about naming, not about content. `e_machine` is a
# little-endian u16 at offset 18, and 183 (0xb7) is EM_AARCH64.
BWRAP_ELF_MAGIC=$(od -An -tx1 -j 0 -N 4 "$WORK/bwrap" | tr -d ' \n')
BWRAP_ELF_CLASS=$(od -An -tu1 -j 4 -N 1 "$WORK/bwrap" | tr -d ' \n')
BWRAP_ELF_MACHINE=$(od -An -tu2 -j 18 -N 2 "$WORK/bwrap" | tr -d ' \n')
{ [ "$BWRAP_ELF_MAGIC" = 7f454c46 ] && [ "$BWRAP_ELF_CLASS" = 2 ] && [ "$BWRAP_ELF_MACHINE" = 183 ]; } ||
    refuse NotAnAarch64BubblewrapImage \
        "bwrap carries magic $BWRAP_ELF_MAGIC class $BWRAP_ELF_CLASS machine $BWRAP_ELF_MACHINE; an ELF64 aarch64 image carries 7f454c46 / 2 / 183"

OBSERVED_BWRAP_BYTES=$(bytes_of "$WORK/bwrap")
OBSERVED_BWRAP_SHA=$(digest_of "$WORK/bwrap")
[ "$OBSERVED_BWRAP_BYTES" = "$PIN_BWRAP_BYTES" ] ||
    refuse ExtractedBubblewrapLengthMismatch \
        "bwrap is $OBSERVED_BWRAP_BYTES bytes; the committed pin is $PIN_BWRAP_BYTES"
[ "$OBSERVED_BWRAP_SHA" = "$PIN_BWRAP_SHA256" ] ||
    refuse ExtractedBubblewrapDigestMismatch \
        "bwrap hashes to $OBSERVED_BWRAP_SHA; the committed pin is $PIN_BWRAP_SHA256"

report "bubblewrap version=$OBSERVED_BWRAP_VERSION sha256=$OBSERVED_BWRAP_SHA bytes=$OBSERVED_BWRAP_BYTES machine=aarch64 VERIFIED against the committed pin"

# ---------------------------------------------------------------- publish
#
# Only now, with every link checked, do the artifacts appear under their final
# names.

mv -f "$WORK/Image" "$OUT/Image"
mv -f "$WORK/virtiofs.ko" "$OUT/virtiofs.ko"
mv -f "$WORK/bwrap" "$OUT/bwrap"
chmod 0755 "$OUT/bwrap"
printf '%s\n' "$OBSERVED_BWRAP_VERSION" > "$OUT/bwrap.version"
{
    echo "$OBSERVED_KERNEL_SHA  Image"
    echo "$OBSERVED_KERNEL_BYTES"
    echo "$OBSERVED_MODULE_SHA  virtiofs.ko"
    echo "$OBSERVED_MODULE_BYTES"
    echo "$OBSERVED_BWRAP_SHA  bwrap"
    echo "$OBSERVED_BWRAP_BYTES"
} > "$OUT/digests.txt"
rm -rf "$WORK"

report "complete out=$OUT kernel=$OBSERVED_KERNEL_SHA module=$OBSERVED_MODULE_SHA bubblewrap=$OBSERVED_BWRAP_SHA"
