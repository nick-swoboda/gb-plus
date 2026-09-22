#!/bin/sh
# Builds the Grok Build guest root filesystem deterministically.
#
# Inputs, all of which must be pinned for the output digest to mean anything:
#
#   GBD_GUEST_BASE_IMAGE   container image supplying the root filesystem,
#                          named by its image ID (a content digest), not a tag
#   GBD_GUEST_KERNEL_MODULE  path to the virtiofs kernel module matching the
#                          kernel the guest boots — produced by `kernel.sh`,
#                          which acquires it from Canonical's archive along a
#                          signature chain and pins its digest
#
# Output: <out>/initramfs.cpio.gz plus <out>/digests.txt.
#
# The build runs entirely inside a container so that the root filesystem is
# archived by a root process reading a Linux filesystem — file ownership and
# mode survive, which they would not if the tree were staged on the macOS host.
# Nothing is fetched: no package manager runs, and the two C programs are
# compiled by the toolchain already inside the pinned base image.
#
# Determinism is the point. `mkcpio` sorts entries, zeroes every mtime, and
# assigns inode numbers from sorted position; `gzip -n` omits the name and
# timestamp; and the three files docker generates per container
# (/etc/hostname, /etc/hosts, /etc/resolv.conf) are excluded by
# `--one-file-system` and rewritten with fixed contents. Two builds of the same
# inputs are expected to produce the same SHA-256, and `verify.sh` checks it.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?usage: build.sh <output-directory>}
BASE=${GBD_GUEST_BASE_IMAGE:?set GBD_GUEST_BASE_IMAGE to a pinned image ID}
MODULE=${GBD_GUEST_KERNEL_MODULE:?set GBD_GUEST_KERNEL_MODULE to the virtiofs module}

mkdir -p "$OUT"
CONTAINER=gbd-guest-image-build-$$

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker create --name "$CONTAINER" "$BASE" /bin/sh /assets/stage.sh >/dev/null
docker cp "$HERE/." "$CONTAINER:/assets" >/dev/null
docker cp "$MODULE" "$CONTAINER:/assets/virtiofs.ko" >/dev/null
docker start -a "$CONTAINER"
docker cp "$CONTAINER:/build/initramfs.cpio.gz" "$OUT/initramfs.cpio.gz" >/dev/null

shasum -a 256 "$OUT/initramfs.cpio.gz" > "$OUT/digests.txt"
wc -c < "$OUT/initramfs.cpio.gz" >> "$OUT/digests.txt"
cat "$OUT/digests.txt"
