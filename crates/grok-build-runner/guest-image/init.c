/*
 * PID 1 for the Grok Build Virtualization.framework Linux guest.
 *
 * The guest must establish its session, loopback interface, child reaper and
 * virtiofs module before running the canary:
 *
 *   1. **A session.** The kernel hands PID 1 session 0 and process group 0, and
 *      the canary helper's kernel-identity observation asserts `pgid > 0`, so
 *      every canary died before producing a report until PID 1 called
 *      `setsid()`.
 *   2. **A loopback interface.** A fresh guest starts with `lo` DOWN, which
 *      makes the `NetworkPolicy` control half vacuous.
 *   3. **A reaper.** `pids.current` must settle to 0 after `cgroup.kill`, and a
 *      zombie still counts.
 *   4. **The virtiofs module**, which the distribution kernel ships as a module
 *      rather than building in.
 *
 * Items 2 and 4 are done here with `ioctl` and `finit_module` rather than by
 * adding `iproute2` and `kmod` to the image, because every package added to the
 * root filesystem is an unpinned input to the artifact this project pins by
 * digest.
 *
 * This program never executes anything the host did not name: its only child is
 * `/bin/sh /run.sh`, which is part of the same pinned image.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void mount_or_report(const char *source, const char *target, const char *type,
                            unsigned long flags, const char *options) {
    mkdir(target, 0755);
    if (mount(source, target, type, flags, options) != 0) {
        perror(target);
    }
}

static void loopback_up(void) {
    int handle = socket(AF_INET, SOCK_DGRAM, 0);
    if (handle < 0) {
        perror("loopback socket");
        return;
    }
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    strncpy(request.ifr_name, "lo", sizeof(request.ifr_name) - 1);
    if (ioctl(handle, SIOCGIFFLAGS, &request) != 0) {
        perror("SIOCGIFFLAGS lo");
        close(handle);
        return;
    }
    request.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(handle, SIOCSIFFLAGS, &request) != 0) {
        perror("SIOCSIFFLAGS lo");
    }
    close(handle);
}

static void insert_module(const char *path) {
    int handle = open(path, O_RDONLY | O_CLOEXEC);
    if (handle < 0) {
        perror(path);
        return;
    }
    if (syscall(SYS_finit_module, handle, "", 0) != 0) {
        perror("finit_module");
    }
    close(handle);
}

int main(void) {
    /* The kernel hands PID 1 session 0 and process group 0. */
    setsid();

    mount_or_report("proc", "/proc", "proc", 0, NULL);
    mount_or_report("sysfs", "/sys", "sysfs", 0, NULL);
    mount_or_report("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mount_or_report("devpts", "/dev/pts", "devpts", 0, NULL);
    mount_or_report("tmpfs", "/tmp", "tmpfs", 0, "size=3g,mode=1777");
    mount_or_report("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL);

    loopback_up();
    insert_module("/virtiofs.ko");

    pid_t supervisor = fork();
    if (supervisor == 0) {
        execl("/bin/sh", "sh", "/run.sh", (char *)NULL);
        perror("exec /run.sh");
        _exit(127);
    }
    if (supervisor < 0) {
        perror("fork supervisor");
        reboot(RB_POWER_OFF);
        return 1;
    }

    /* Reap everything, including processes reparented here, until the
     * supervisor itself exits. `pids.current` must be able to reach 0, and a
     * zombie still counts against it. */
    for (;;) {
        int status = 0;
        pid_t finished = waitpid(-1, &status, 0);
        if (finished == supervisor) {
            break;
        }
        if (finished < 0) {
            break;
        }
    }

    /* Drain any remaining zombies without blocking, then power off. The host
     * observes `VZVirtualMachineStateStopped` and reports a guest-initiated
     * stop; every other host exit path stops the machine explicitly. */
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
    sync();
    reboot(RB_POWER_OFF);
    return 0;
}
