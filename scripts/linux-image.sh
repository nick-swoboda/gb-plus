#!/bin/sh
# Build the admitted ARM64 offline verification image from local, pinned inputs.
# No acquisition, package manager or publisher installer runs here. The overlay
# is composed by scripts/linux-image/compose-overlay.py and independently pinned.
# Usage: scripts/linux-image.sh <verified-bwrap> <reviewed-overlay.tar> <gui-overlay.tar> [image-tag]

set -eu

# Must equal `ADMITTED_BUBBLEWRAP_IMAGE_V1` in
# the runner Linux-command admission and the reviewed image record.
PIN_BWRAP_SHA256=ae27935781511400c65ebcc0b4669775d602f46251b8707c947a1ac1b160c1c8
PIN_BWRAP_BYTES=67816
PIN_BWRAP_PATH=/usr/bin/bwrap
PIN_BWRAP_MODE=0755

PIN_BASE_IMAGE=rust@sha256:3928ba262c79a46d18a4d1c125b24c089963ba1e1d6b203bd3bc169924e71f04
PIN_OVERLAY_SHA256=b805c63b0ed41d194b531697b1ef969888b76f04837f830e4f7e4c121eef014b
PIN_OVERLAY_BYTES=52572160
PIN_GUI_OVERLAY_SHA256=022d5d2bb002557005a9a98d248dc1dbda9d08569b5567c9a0f110a913d344c6
PIN_GUI_OVERLAY_BYTES=15503360
DEFAULT_TAG=gbd-linux:1.97.1-reviewed2

refuse() {
    kind=$1
    shift
    echo "GBDIMG refused kind=$kind detail=$*" >&2
    exit 3
}

report() { echo "GBDIMG $*"; }

digest_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

BWRAP=${1:?usage: linux-image.sh <verified-bwrap> <reviewed-overlay.tar> <gui-overlay.tar> [image-tag]}
OVERLAY=${2:?a previously reviewed local overlay.tar is required}
GUI_OVERLAY=${3:?the reviewed GUI build overlay is required}
TAG=${4:-$DEFAULT_TAG}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$GUI_OVERLAY" ] && [ ! -L "$GUI_OVERLAY" ] || refuse GuiOverlayMissing "expected a regular reviewed GUI overlay"
[ "$(wc -c < "$GUI_OVERLAY" | tr -d ' ')" = "$PIN_GUI_OVERLAY_BYTES" ] || refuse GuiOverlayLengthMismatch "GUI overlay differs from admission"
[ "$(digest_of "$GUI_OVERLAY")" = "$PIN_GUI_OVERLAY_SHA256" ] || refuse GuiOverlayDigestMismatch "GUI overlay differs from admission"
[ -f "$OVERLAY" ] && [ ! -L "$OVERLAY" ] || refuse OverlayMissing "expected a regular local overlay"
[ "$(wc -c < "$OVERLAY" | tr -d ' ')" = "$PIN_OVERLAY_BYTES" ] || refuse OverlayLengthMismatch "overlay differs from admission"
[ "$(digest_of "$OVERLAY")" = "$PIN_OVERLAY_SHA256" ] || refuse OverlayDigestMismatch "overlay differs from admission"

[ -f "$BWRAP" ] && [ ! -L "$BWRAP" ] || refuse BubblewrapMissing "$BWRAP is not a regular file"

OBSERVED_BYTES=$(wc -c < "$BWRAP" | tr -d ' ')
OBSERVED_SHA=$(digest_of "$BWRAP")
[ "$OBSERVED_BYTES" = "$PIN_BWRAP_BYTES" ] ||
    refuse BubblewrapLengthMismatch \
        "$BWRAP is $OBSERVED_BYTES bytes; the committed pin is $PIN_BWRAP_BYTES"
[ "$OBSERVED_SHA" = "$PIN_BWRAP_SHA256" ] ||
    refuse BubblewrapDigestMismatch \
        "$BWRAP hashes to $OBSERVED_SHA; the committed pin is $PIN_BWRAP_SHA256"

report "bubblewrap sha256=$OBSERVED_SHA bytes=$OBSERVED_BYTES VERIFIED against the committed pin"

command -v docker >/dev/null 2>&1 ||
    refuse ToolMissing "docker is required to build the Linux command image and is not on PATH"

docker image inspect "$PIN_BASE_IMAGE" >/dev/null 2>&1 ||
    refuse BaseImageMissing \
        "$PIN_BASE_IMAGE is not present locally. Check disk space and review the pinned inputs before preparing an image; see CONTRIBUTING.md."

CONTEXT=$(mktemp -d "${TMPDIR:-/tmp}/gbd-linux-image.XXXXXX")
trap 'rm -rf "$CONTEXT"' EXIT INT TERM
cp "$BWRAP" "$CONTEXT/bwrap"

cp "$OVERLAY" "$CONTEXT/overlay.tar"
cp "$GUI_OVERLAY" "$CONTEXT/gui-overlay.tar"
cp "$SCRIPT_DIR/linux-image/Dockerfile" "$CONTEXT/Dockerfile"
# Recheck the private copies so a changed source cannot reach Docker.
[ "$(digest_of "$CONTEXT/bwrap")" = "$PIN_BWRAP_SHA256" ] || refuse SourceChanged "bwrap changed during copy"
[ "$(digest_of "$CONTEXT/overlay.tar")" = "$PIN_OVERLAY_SHA256" ] || refuse SourceChanged "overlay changed during copy"
[ "$(digest_of "$CONTEXT/gui-overlay.tar")" = "$PIN_GUI_OVERLAY_SHA256" ] || refuse SourceChanged "GUI overlay changed during copy"
report "building $TAG from $PIN_BASE_IMAGE"
docker build --network none --pull=false --force-rm -t "$TAG" "$CONTEXT" ||
    refuse ImageBuildFailed "docker build did not produce $TAG"

# Read the admitted file back out of the built image through a different path
# than the one that put it there, so "the image carries the pinned bwrap" is a
# readback rather than a restatement of the copy above.
READBACK=$(
    docker run --rm --network none "$TAG" \
        sh -c "sha256sum $PIN_BWRAP_PATH | cut -d' ' -f1"
)
[ "$READBACK" = "$PIN_BWRAP_SHA256" ] ||
    refuse ImageReadbackMismatch \
        "$PIN_BWRAP_PATH inside $TAG hashes to $READBACK; the committed pin is $PIN_BWRAP_SHA256"

METADATA=$(
    docker run --rm --network none "$TAG" \
        stat -c '%f %u %g %h %s' "$PIN_BWRAP_PATH"
)

[ "$METADATA" = "81ed 0 0 1 67816" ] || refuse ImageMetadataMismatch "$METADATA"
report "image $TAG bwrap sha256=$READBACK stat(mode uid gid nlink size)=$METADATA VERIFIED by readback"
report "complete tag=$TAG"
