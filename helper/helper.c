#include "args.h"
#include "decrypt.h"
#include "fs.h"
#include "log.h"
#include "operation.h"
#include "process.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef HELPER_VERSION
#define HELPER_VERSION "ipadecrypt-helper (dev)"
#endif

static int is_stdout_target(const char *path) {
    return path && path[0] == '-' && path[1] == '\0';
}

// Stream one Mach-O file as a framed record on stdout. Frame:
//   [u32be plen][plen-byte path][u64be size][size bytes]
static int emit_macho_frame(const char *relpath, const char *abs_path) {
    attrs_t trace; attrs_init(&trace); attrs_str(&trace, "path", relpath); attrs_str(&trace, "source", abs_path);
    emit(LOG_DEBUG, "stream.frame.begin", &trace, NULL);
    int fd = open(abs_path, O_RDONLY);
    if (fd < 0) { LOG_ERRNO("stream.frame.open_failed", "open %s failed: %s", abs_path, strerror(errno)); return -1; }

    struct stat st;
    if (fstat(fd, &st) != 0) { LOG_ERRNO("stream.frame.stat_failed", "fstat %s failed: %s", abs_path, strerror(errno)); close(fd); return -1; }

    uint64_t size = (uint64_t)st.st_size;
    uint32_t plen = (uint32_t)strlen(relpath);

    uint8_t hdr[12];
    hdr[0] = (uint8_t)(plen >> 24);
    hdr[1] = (uint8_t)(plen >> 16);
    hdr[2] = (uint8_t)(plen >> 8);
    hdr[3] = (uint8_t)plen;
    for (int i = 0; i < 8; i++) hdr[4 + i] = (uint8_t)(size >> ((7 - i) * 8));

    if (fs_write_all(1, hdr, 4) != 0) { close(fd); return -1; }
    if (fs_write_all(1, relpath, plen) != 0) { close(fd); return -1; }
    if (fs_write_all(1, hdr + 4, 8) != 0) { close(fd); return -1; }

    char buf[64 * 1024];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) { if (errno == EINTR) continue; LOG_ERRNO("stream.frame.read_failed", "read %s failed: %s", abs_path, strerror(errno)); close(fd); return -1; }
        if (n == 0) break;
        if (fs_write_all(1, buf, (size_t)n) != 0) { close(fd); return -1; }
    }

    close(fd);
    attrs_uint(&trace, "size", size);
    emit(LOG_DEBUG, "stream.frame.done", &trace, NULL);
    return 0;
}

// Walk staging tree, emitting one framed record per Mach-O file we
// actually decrypted. The filter `st_nlink == 1` identifies decrypted
// files: dump.c writes via unlink-then-create, which detaches from the
// fs_copy_tree hardlink and leaves the new file with nlink=1. Pure
// hardlinks-from-source stay at nlink>=2 (source bundle copy +
// staging copy) and are skipped - the host substitutes them from the
// source IPA verbatim.
//
// Per-file errors are best-effort: logged and skipped so a single
// unreadable file doesn't abort the whole stream. A serious I/O error
// inside emit_macho_frame (header write fails) does propagate, since
// after that the stream is desynced and the host can't recover.
static int emit_machos_recursive(const char *root, const char *rel) {
    char abs[4096];
    if (rel[0]) snprintf(abs, sizeof(abs), "%s/%s", root, rel);
    else        snprintf(abs, sizeof(abs), "%s", root);

    struct stat st;
    if (lstat(abs, &st) != 0) { LOG_ERRNO("stream.walk.stat_failed", "lstat %s failed: %s", abs, strerror(errno)); return 0; }

    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(abs);
        if (!d) { LOG_ERRNO("stream.walk.open_failed", "opendir %s failed: %s", abs, strerror(errno)); return 0; }

        struct dirent *e;
        int rc = 0;
        while ((e = readdir(d))) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

            char child[4096];
            if (rel[0]) snprintf(child, sizeof(child), "%s/%s", rel, e->d_name);
            else        snprintf(child, sizeof(child), "%s", e->d_name);

            if (emit_machos_recursive(root, child) != 0) rc = -1;
        }

        closedir(d);
        return rc;
    }

    if (S_ISREG(st.st_mode) && st.st_nlink == 1 && fs_is_macho(abs)) {
        return emit_macho_frame(rel, abs);
    }

    return 0;
}

static int run_decrypt(const decrypt_args_t *a) {
    attrs_t run; attrs_init(&run);
    attrs_str(&run, "bundle_src", a->bundle_src);
    attrs_str(&run, "bundle_id", a->bundle_id ? a->bundle_id : "");
    attrs_str(&run, "output", a->out_ipa ? a->out_ipa : "");
    attrs_int(&run, "skip_appex", a->skip_appex);
    attrs_int(&run, "execs_only", a->execs_only);
    emit(LOG_INFO, "decrypt.begin", &run, "starting helper decryption");
    // Resolve bundle basename for the staging Payload/ layout.
    char src_copy[4096];
    snprintf(src_copy, sizeof(src_copy), "%s", a->bundle_src);
    char *app_name = strrchr(src_copy, '/');
    app_name = app_name ? app_name + 1 : src_copy;
    if (!*app_name || strchr(app_name, '/') != NULL) {
        er("bad bundle path: %s", a->bundle_src);
        return 1;
    }

    char staging[4096];
    if (a->operation_dir) {
        snprintf(staging, sizeof(staging), "%s/dump", a->operation_dir);
        if (mkdir(staging, 0700)) { LOG_ERRNO("staging.mkdir_failed", "mkdir %s failed: %s", staging, strerror(errno)); return 1; }
    } else {
        snprintf(staging, sizeof(staging), "/tmp/ipadecrypt-XXXXXX");
        if (!mkdtemp(staging)) { LOG_ERRNO("staging.mkdtemp_failed", "mkdtemp failed: %s", strerror(errno)); return 1; }
    }
    char payload[4096];
    snprintf(payload, sizeof(payload), "%s/Payload", staging);
    if (mkdir(payload, 0755) != 0) { LOG_ERRNO("staging.payload_failed", "mkdir %s failed: %s", payload, strerror(errno)); fs_rm_rf(staging); return 1; }
    char bundle_dst[4096];
    snprintf(bundle_dst, sizeof(bundle_dst), "%s/%s", payload, app_name);

    {
        attrs_t at; attrs_init(&at);
        attrs_str(&at, "src", a->bundle_src);
        attrs_str(&at, "dst", bundle_dst);
        emit(LOG_DEBUG, "staging.begin", &at,
             "staging %s -> %s", a->bundle_src, bundle_dst);
    }
    if (fs_copy_tree(a->bundle_src, bundle_dst) != 0) {
        er("copy_tree failed");
        fs_rm_rf(staging);
        return 1;
    }

    int decrypt_failed = 0;
    if (a->bundle_id && a->bundle_id[0] &&
        decrypt_bundle(a->bundle_src, bundle_dst, a->bundle_id) != 0)
        decrypt_failed = 1;
    if (!a->skip_appex) {
        if (decrypt_appexes(a->bundle_src, bundle_dst) != 0)
            decrypt_failed = 1;
    }
    if (decrypt_failed) {
        emit(LOG_ERROR, "decrypt.bundle_failed", NULL,
             "one or more bundle targets failed");
        fs_rm_rf(staging);
        return 1;
    }

    if (a->execs_only) {
        emit(LOG_DEBUG, "stream.begin", NULL, "streaming Mach-O frames on stdout");

        int rc = emit_machos_recursive(staging, "");
        fs_rm_rf(staging);

        if (rc != 0) {
            emit(LOG_ERROR, "stream.failed", NULL, "frame emit failed");
            return 1;
        }

        if (!a->operation_dir) emit(LOG_INFO, "done", NULL, "done");
        return 0;
    }

    const char *ipa_label = is_stdout_target(a->out_ipa) ? "stdout" : a->out_ipa;

    if (!is_stdout_target(a->out_ipa)) unlink(a->out_ipa);
    {
        attrs_t at; attrs_init(&at);
        attrs_str(&at, "ipa", a->out_ipa);
        emit(LOG_DEBUG, "pack.begin", &at, "packaging IPA -> %s", ipa_label);
    }
    if (run_zip(staging, a->out_ipa) != 0) {
        attrs_t at; attrs_init(&at);
        attrs_str(&at, "ipa", a->out_ipa);
        emit(LOG_ERROR, "pack.failed", &at, "zip failed for %s", ipa_label);
        fs_rm_rf(staging);
        return 1;
    }
    {
        attrs_t at; attrs_init(&at);
        attrs_str(&at, "ipa", a->out_ipa);
        emit(LOG_INFO, "pack.done", &at, "packaged -> %s", ipa_label);
    }
    fs_rm_rf(staging);
    {
        attrs_t at; attrs_init(&at);
        attrs_str(&at, "ipa", a->out_ipa);
        if (!a->operation_dir) emit(LOG_INFO, "done", &at, "done");
    }
    return 0;
}

int main(int argc, char **argv) {
    // Streaming on stdout (--execs-only frames or `-o -` IPA) would die
    // from default SIGPIPE if the host closes early, skipping fs_rm_rf
    // and leaking /tmp/ipadecrypt-<pid>. Ignore it so write() returns
    // EPIPE and the normal cleanup path runs.
    signal(SIGPIPE, SIG_IGN);

    // Operation subcommands bypass normal argument parsing, but they still
    // need a structured diagnostic when their fail-closed checks reject an
    // operation. Their stdout is captured by the Go caller.
    log_init(0);
    if (argc == 4 && strcmp(argv[1], "cleanup") == 0) {
        int rc = operation_cleanup(argv[2], argv[3]);
        if (rc) emit(LOG_ERROR, "cleanup.failed", NULL,
                     "operation cleanup could not be confirmed");
        return rc;
    }
    if (argc == 5 && strcmp(argv[1], "install") == 0) {
        int rc = operation_app_change(argv[2], argv[3], argv[4], 0);
        if (rc) emit(LOG_ERROR, "install.failed", NULL,
                     "operation install could not be confirmed");
        return rc;
    }
    if (argc == 4 && strcmp(argv[1], "uninstall") == 0) {
        int rc = operation_app_change(argv[2], argv[3], NULL, 1);
        if (rc) emit(LOG_ERROR, "uninstall.failed", NULL,
                     "operation uninstall could not be confirmed");
        return rc;
    }

    global_flags_t globals;
    decrypt_args_t da;
    const char *sub = args_parse(argc, argv, &globals, &da);
    if (!sub) return 2;

    log_init(globals.verbose);

    // When streaming binary on stdout (IPA bytes or framed Mach-O records),
    // route events to stderr so they don't corrupt the data channel.
    if (strcmp(sub, "decrypt") == 0 &&
        (is_stdout_target(da.out_ipa) || da.execs_only)) {
        log_set_stream(stderr);
    }

    if (strcmp(sub, "version") == 0) {
        printf("%s\n", HELPER_VERSION);
        return 0;
    }

    if (strcmp(sub, "decrypt") == 0) {
        attrs_t start; attrs_init(&start); attrs_str(&start, "subcommand", sub);
        attrs_int(&start, "argc", argc); attrs_int(&start, "verbose", globals.verbose);
        emit(LOG_INFO, "helper.start", &start, "running %s", sub);
        if (!da.operation_dir) {
            int rc = run_decrypt(&da);
            if (rc) emit(LOG_ERROR, "decrypt.failed", NULL,
                         "helper decryption failed");
            return rc;
        }
        int d = operation_open(da.operation_dir);
        if (d < 0) {
            emit(LOG_ERROR, "operation.open_failed", NULL,
                 "could not open the operation directory");
            return 1;
        }
        int lock = operation_lock(d);
        if (lock < 0) {
            emit(LOG_ERROR, "operation.lock_failed", NULL,
                 "could not acquire the operation lock");
            close(d); return 1;
        }
        if (has_receipt(d,"sealed") || has_receipt(d,"helper.done")) {
            emit(LOG_ERROR, "operation.rejected", NULL,
                 "operation was already sealed or completed");
            close(lock); close(d); return 1;
        }
        int rc = run_decrypt(&da);
        if (!process_completion_confirmed(da.bundle_src, 1000)) {
            emit(LOG_ERROR, "operation.target_busy", NULL,
                 "target process completion was not confirmed");
            rc = 1;
        } else if (receipt(d,"helper.done")) {
            emit(LOG_ERROR, "operation.receipt_failed", NULL,
                 "could not persist the helper completion receipt");
            rc = 1;
        }
        if (rc) {
            emit(LOG_ERROR, "decrypt.failed", NULL,
                 "helper decryption failed");
        } else {
            emit(LOG_INFO, "done", NULL, "done");
        }
        close(lock); close(d); return rc;
    }

    er("unknown subcommand: %s", sub);
    return 2;
}
