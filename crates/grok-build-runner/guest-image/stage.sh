#!/bin/sh
# In-container half of the guest root-filesystem build. See `build.sh`.
#
# Runs as root inside the pinned base image, so every mode and owner the
# archive records is the one the guest will see.

set -eu

cc -O2 -static -o /assets/init /assets/init.c
cc -O2 -o /assets/mkcpio /assets/mkcpio.c

mkdir -p /build/root

# `--one-file-system` drops /proc, /sys, /dev and the three files a container
# runtime bind-mounts per container, so none of them can vary the output.
tar -C / --one-file-system \
    --exclude=./build --exclude=./assets --exclude=./.dockerenv \
    -cf - . | tar -C /build/root -xf -

cd /build/root

# The Rust toolchain is 900 MB of the base image and no contained command runs
# a compiler from the guest root filesystem; the command image is staged from
# the share instead.
rm -rf ./usr/local/rustup ./usr/local/cargo
rm -rf ./var/log/* ./var/cache/apt/* ./var/lib/apt/lists/* ./root/.cache
rm -f ./var/lib/dpkg/available-old ./var/lib/dpkg/status-old

# Mount points the guest's PID 1 populates.
mkdir -p ./proc ./sys ./dev/pts ./tmp ./mnt/ws ./stage ./scratch
chmod 1777 ./tmp

# The kernel opens /dev/console for PID 1 before devtmpfs exists.
mknod ./dev/console c 5 1
mknod ./dev/null c 1 3
chmod 600 ./dev/console
chmod 666 ./dev/null

# Fixed contents for the three files the container runtime would otherwise vary.
printf 'gbd-guest\n' > ./etc/hostname
printf '127.0.0.1\tlocalhost\n127.0.0.1\tgbd-guest\n' > ./etc/hosts
: > ./etc/resolv.conf

cp /assets/init ./init
cp /assets/run.sh ./run.sh
cp /assets/virtiofs.ko ./virtiofs.ko
chmod 755 ./init ./run.sh
chmod 644 ./virtiofs.ko

# The guest runs contained commands as an unprivileged identity that must exist
# in the image, because the canary suite reads its own credentials back.
if ! grep -q '^gbd:' ./etc/passwd; then
    printf 'gbd:x:1000:1000::/home/gbd:/bin/sh\n' >> ./etc/passwd
    printf 'gbd:x:1000:\n' >> ./etc/group
    mkdir -p ./home/gbd
    chown 1000:1000 ./home/gbd
fi

/assets/mkcpio /build/root /build/initramfs.cpio
gzip -n -9 -c /build/initramfs.cpio > /build/initramfs.cpio.gz
rm -f /build/initramfs.cpio
