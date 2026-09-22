#!/bin/sh
# Proves the guest root filesystem build is reproducible, and reports the
# digest a reviewer must find in `GUEST_IMAGE_PIN_V1`.
#
# The pin in the source file is only meaningful if the same inputs produce the
# same bytes; this builds twice into separate directories and compares. It is
# the check that turns "we hashed what we built" into "anyone with these inputs
# gets this hash".
#
# Usage: GBD_GUEST_BASE_IMAGE=<image id> GBD_GUEST_KERNEL_MODULE=<virtiofs.ko> \
#            verify.sh <scratch directory>

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SCRATCH=${1:?usage: verify.sh <scratch directory>}

sh "$HERE/build.sh" "$SCRATCH/first" >/dev/null
sh "$HERE/build.sh" "$SCRATCH/second" >/dev/null

FIRST=$(shasum -a 256 "$SCRATCH/first/initramfs.cpio.gz" | cut -d' ' -f1)
SECOND=$(shasum -a 256 "$SCRATCH/second/initramfs.cpio.gz" | cut -d' ' -f1)
BYTES=$(wc -c < "$SCRATCH/first/initramfs.cpio.gz" | tr -d ' ')

if [ "$FIRST" != "$SECOND" ]; then
    echo "guest-image build is NOT reproducible: $FIRST vs $SECOND"
    exit 1
fi
echo "guest-image build is reproducible"
echo "sha256      = $FIRST"
echo "byte_length = $BYTES"
