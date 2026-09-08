#include "fs.h"
#include "log.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int fs_mkdirs(const char *path) {
    TRACE_BEGIN("fs_mkdirs");
    char buf[4096];
    strncpy(buf, path, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
                int saved = errno;
                attrs_t a; attrs_init(&a); attrs_str(&a, "path", buf); attrs_errno(&a, saved);
                emit(LOG_WARN, "fs.mkdir.failed", &a, "mkdir %s failed: %s", buf, strerror(saved));
            }
            *p = '/';
        }
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
        int saved = errno;
        attrs_t a; attrs_init(&a); attrs_str(&a, "path", buf); attrs_errno(&a, saved);
        emit(LOG_WARN, "fs.mkdir.failed", &a, "mkdir %s failed: %s", buf, strerror(saved));
    }
    TRACE_END("fs_mkdirs", 0);
    return 0;
}

int fs_rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno != ENOENT) {
            int saved = errno;
            attrs_t a; attrs_init(&a); attrs_str(&a, "path", path); attrs_errno(&a, saved);
            emit(LOG_WARN, "fs.remove.stat_failed", &a, "could not inspect %s: %s", path, strerror(saved));
        }
        return 0;
    }
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *e;
            while ((e = readdir(d))) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                char sub[4096];
                snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
                fs_rm_rf(sub);
            }
            closedir(d);
        }
        int rc = rmdir(path);
        if (rc != 0) LOG_ERRNO("fs.remove.failed", "rmdir %s failed: %s", path, strerror(errno));
        return rc;
    }
    int rc = unlink(path);
    if (rc != 0) LOG_ERRNO("fs.remove.failed", "unlink %s failed: %s", path, strerror(errno));
    return rc;
}

int fs_write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_ERRNO("fs.write.failed", "write fd %d failed: %s", fd, strerror(errno));
            return -1;
        }
        if (n == 0) { errno = EIO; LOG_ERRNO("fs.write.failed", "write fd %d made no progress", fd); return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int fs_read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_ERRNO("fs.read.failed", "read fd %d failed: %s", fd, strerror(errno));
            return -1;
        }
        if (n == 0) { errno = EIO; LOG_ERRNO("fs.read.failed", "unexpected EOF on fd %d", fd); return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int fs_copy_file(const char *src, const char *dst) {
    if (log_level_visible(LOG_DEBUG)) {
        attrs_t a; attrs_init(&a); attrs_str(&a, "src", src); attrs_str(&a, "dst", dst);
        emit(LOG_DEBUG, "fs.copy.begin", &a, NULL);
    }
    int in = open(src, O_RDONLY);
    if (in < 0) { LOG_ERRNO("fs.copy.open_source_failed", "open %s failed: %s", src, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(in, &st) != 0) { LOG_ERRNO("fs.copy.stat_failed", "fstat %s failed: %s", src, strerror(errno)); close(in); return -1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, st.st_mode & 0777);
    if (out < 0) { LOG_ERRNO("fs.copy.open_dest_failed", "open %s failed: %s", dst, strerror(errno)); close(in); return -1; }
    char buf[64 * 1024];
    ssize_t n = 0;
    for (;;) {
        n = read(in, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (fs_write_all(out, buf, (size_t)n) != 0) { close(in); close(out); return -1; }
    }
    close(in); close(out);
    if (n < 0) LOG_ERRNO("fs.copy.read_failed", "read %s failed: %s", src, strerror(errno));
    else if (log_level_visible(LOG_DEBUG)) {
        attrs_t a; attrs_init(&a); attrs_str(&a, "src", src); attrs_str(&a, "dst", dst); attrs_uint(&a, "size", (unsigned long long)st.st_size);
        emit(LOG_DEBUG, "fs.copy.done", &a, NULL);
    }
    return n < 0 ? -1 : 0;
}

int fs_copy_tree(const char *src, const char *dst) {
    struct stat st;
    if (lstat(src, &st) != 0) { LOG_ERRNO("fs.tree.stat_failed", "lstat %s failed: %s", src, strerror(errno)); return -1; }
    if (S_ISLNK(st.st_mode)) { errno = ELOOP; LOG_ERRNO("fs.tree.symlink_rejected", "refusing source symlink %s", src); return -1; }
    if (S_ISDIR(st.st_mode)) {
        if (mkdir(dst, st.st_mode & 0777)) { LOG_ERRNO("fs.tree.mkdir_failed", "mkdir %s failed: %s", dst, strerror(errno)); return -1; }
        DIR *d = opendir(src);
        if (!d) { LOG_ERRNO("fs.tree.open_failed", "opendir %s failed: %s", src, strerror(errno)); return -1; }
        struct dirent *e;
        int rc = 0;
        while ((e = readdir(d))) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
            char s[4096], t[4096];
            snprintf(s, sizeof(s), "%s/%s", src, e->d_name);
            snprintf(t, sizeof(t), "%s/%s", dst, e->d_name);
            if (fs_copy_tree(s, t) != 0) rc = -1;
        }
        closedir(d);
        return rc;
    }
    if (link(src, dst) == 0) {
        if (log_level_visible(LOG_DEBUG)) { attrs_t a; attrs_init(&a); attrs_str(&a, "src", src); attrs_str(&a, "dst", dst); emit(LOG_DEBUG, "fs.link.done", &a, NULL); }
        return 0;
    }
    if (log_level_visible(LOG_DEBUG)) { int saved = errno; attrs_t a; attrs_init(&a); attrs_str(&a, "src", src); attrs_str(&a, "dst", dst); attrs_errno(&a, saved); emit(LOG_DEBUG, "fs.link.fallback", &a, NULL); }
    return fs_copy_file(src, dst);
}

int fs_is_macho(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t m = 0;
    ssize_t n = read(fd, &m, sizeof(m));
    close(fd);
    return n == (ssize_t)sizeof(m) &&
        (m == MH_MAGIC || m == MH_MAGIC_64 ||
         m == FAT_MAGIC || m == FAT_CIGAM ||
         m == FAT_MAGIC_64 || m == FAT_CIGAM_64);
}

void fs_ensure_executable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) { LOG_ERRNO("spawn.stat_failed", "stat %s failed: %s", path, strerror(errno)); return; }
    mode_t want = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
    if (want == st.st_mode) return;
    if (chmod(path, want) == 0) {
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "path", path);
        attrs_fmt(&a, "old_mode", "%o", st.st_mode & 0777);
        emit(LOG_DEBUG, "spawn.chmod", &a, "chmod +x %s", path);
    } else {
        LOG_ERRNO("spawn.chmod_failed", "chmod %s failed: %s", path, strerror(errno));
    }
}

int fs_path_equiv(const char *a, const char *b) {
    if (strcmp(a, b) == 0) return 1;
    const char *pre = "/private";
    size_t plen = strlen(pre);
    if (strncmp(a, pre, plen) == 0 && strcmp(a + plen, b) == 0) return 1;
    if (strncmp(b, pre, plen) == 0 && strcmp(b + plen, a) == 0) return 1;
    return 0;
}
