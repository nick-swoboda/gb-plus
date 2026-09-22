/*
 * Deterministic `newc` cpio writer for the Grok Build guest root filesystem.
 *
 * The guest image must be pinned by content digest, and a digest is only
 * meaningful if the same inputs produce the same bytes. GNU cpio's
 * `--reproducible` would do this, but cpio is absent from both the base image
 * and the host, and adding a package manager fetch to the image build would put
 * an unpinned network input inside the supply chain. This writer is the
 * smallest thing that removes that input.
 *
 * Determinism comes from four choices, each of which is the only source of
 * variation a `find | cpio` pipeline has:
 *
 *   1. entries are emitted in `strcmp` order, never `readdir` order;
 *   2. every mtime is 0;
 *   3. inode numbers are assigned from the sorted position, not from the host;
 *   4. every hard link is written as an independent entry with `nlink = 1`, so
 *      no link-group ordering can leak in.
 *
 * Usage: mkcpio <root-directory> <output-archive>
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct entry {
    char *name; /* archive name, e.g. "." or "./usr/bin/env" */
    char *path; /* host path used for lstat/read */
};

static struct entry *entries;
static size_t entry_count;
static size_t entry_capacity;

static void die(const char *what, const char *detail) {
    fprintf(stderr, "mkcpio: %s: %s: %s\n", what, detail, strerror(errno));
    exit(1);
}

static void push(const char *name, const char *path) {
    if (entry_count == entry_capacity) {
        entry_capacity = entry_capacity ? entry_capacity * 2 : 1024;
        entries = realloc(entries, entry_capacity * sizeof(*entries));
        if (!entries) {
            die("allocate", "entry table");
        }
    }
    entries[entry_count].name = strdup(name);
    entries[entry_count].path = strdup(path);
    if (!entries[entry_count].name || !entries[entry_count].path) {
        die("allocate", "entry name");
    }
    entry_count++;
}

static void walk(const char *root, const char *relative) {
    char path[4096];
    char name[4096];
    DIR *directory;
    struct dirent *item;

    if (relative[0] == '\0') {
        snprintf(path, sizeof(path), "%s", root);
        snprintf(name, sizeof(name), ".");
    } else {
        snprintf(path, sizeof(path), "%s/%s", root, relative);
        snprintf(name, sizeof(name), "./%s", relative);
    }
    push(name, path);

    struct stat status;
    if (lstat(path, &status) != 0) {
        die("lstat", path);
    }
    if (!S_ISDIR(status.st_mode)) {
        return;
    }
    directory = opendir(path);
    if (!directory) {
        die("opendir", path);
    }
    while ((item = readdir(directory)) != NULL) {
        if (strcmp(item->d_name, ".") == 0 || strcmp(item->d_name, "..") == 0) {
            continue;
        }
        char child[4096];
        if (relative[0] == '\0') {
            snprintf(child, sizeof(child), "%s", item->d_name);
        } else {
            snprintf(child, sizeof(child), "%s/%s", relative, item->d_name);
        }
        walk(root, child);
    }
    closedir(directory);
}

static int compare(const void *left, const void *right) {
    const struct entry *first = left;
    const struct entry *second = right;
    return strcmp(first->name, second->name);
}

static FILE *output;
static unsigned long long written;

static void emit(const void *bytes, size_t length) {
    if (fwrite(bytes, 1, length, output) != length) {
        die("write", "archive body");
    }
    written += length;
}

static void pad_to_four(void) {
    static const char zeros[4] = {0, 0, 0, 0};
    size_t remainder = (size_t)(written % 4);
    if (remainder != 0) {
        emit(zeros, 4 - remainder);
    }
}

static void field(char *destination, unsigned long value) {
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%08lX", value & 0xFFFFFFFFUL);
    memcpy(destination, buffer, 8);
}

static void header(unsigned long inode, unsigned long mode, unsigned long uid,
                   unsigned long gid, unsigned long size, unsigned long major_device,
                   unsigned long minor_device, const char *name) {
    char raw[110];
    memcpy(raw, "070701", 6);
    field(raw + 6, inode);
    field(raw + 14, mode);
    field(raw + 22, uid);
    field(raw + 30, gid);
    field(raw + 38, 1);    /* nlink */
    field(raw + 46, 0);    /* mtime */
    field(raw + 54, size);
    field(raw + 62, 0); /* devmajor */
    field(raw + 70, 0); /* devminor */
    field(raw + 78, major_device);
    field(raw + 86, minor_device);
    field(raw + 94, (unsigned long)strlen(name) + 1);
    field(raw + 102, 0); /* check */
    emit(raw, sizeof(raw));
    emit(name, strlen(name) + 1);
    pad_to_four();
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: mkcpio <root-directory> <output-archive>\n");
        return 2;
    }
    walk(argv[1], "");
    qsort(entries, entry_count, sizeof(*entries), compare);

    output = fopen(argv[2], "wb");
    if (!output) {
        die("open", argv[2]);
    }

    for (size_t index = 0; index < entry_count; index++) {
        struct stat status;
        if (lstat(entries[index].path, &status) != 0) {
            die("lstat", entries[index].path);
        }
        unsigned long inode = (unsigned long)index + 1;
        if (S_ISLNK(status.st_mode)) {
            char target[4096];
            ssize_t length = readlink(entries[index].path, target, sizeof(target) - 1);
            if (length < 0) {
                die("readlink", entries[index].path);
            }
            header(inode, (unsigned long)status.st_mode, (unsigned long)status.st_uid,
                   (unsigned long)status.st_gid, (unsigned long)length, 0, 0,
                   entries[index].name);
            emit(target, (size_t)length);
            pad_to_four();
        } else if (S_ISREG(status.st_mode)) {
            FILE *source = fopen(entries[index].path, "rb");
            if (!source) {
                die("open", entries[index].path);
            }
            header(inode, (unsigned long)status.st_mode, (unsigned long)status.st_uid,
                   (unsigned long)status.st_gid, (unsigned long)status.st_size, 0, 0,
                   entries[index].name);
            char buffer[65536];
            unsigned long long copied = 0;
            size_t count;
            while ((count = fread(buffer, 1, sizeof(buffer), source)) > 0) {
                emit(buffer, count);
                copied += count;
            }
            fclose(source);
            if (copied != (unsigned long long)status.st_size) {
                fprintf(stderr, "mkcpio: %s changed size during archiving\n",
                        entries[index].path);
                return 1;
            }
            pad_to_four();
        } else if (S_ISCHR(status.st_mode) || S_ISBLK(status.st_mode)) {
            header(inode, (unsigned long)status.st_mode, (unsigned long)status.st_uid,
                   (unsigned long)status.st_gid, 0, (unsigned long)major(status.st_rdev),
                   (unsigned long)minor(status.st_rdev), entries[index].name);
        } else if (S_ISDIR(status.st_mode) || S_ISFIFO(status.st_mode)) {
            header(inode, (unsigned long)status.st_mode, (unsigned long)status.st_uid,
                   (unsigned long)status.st_gid, 0, 0, 0, entries[index].name);
        } else {
            /* Sockets carry no bytes across a boot; refusing is safer than
             * silently dropping an entry the caller believed was archived. */
            fprintf(stderr, "mkcpio: %s is not an archivable file type\n",
                    entries[index].path);
            return 1;
        }
    }

    header(0, 0, 0, 0, 0, 0, 0, "TRAILER!!!");
    if (fclose(output) != 0) {
        die("close", argv[2]);
    }
    return 0;
}
