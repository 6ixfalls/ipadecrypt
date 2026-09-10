#include "process.h"
#include "log.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern int proc_listpids(uint32_t, uint32_t, void *, int);
extern int proc_pidpath(int, void *, uint32_t);

#ifndef PROCESS_LISTPIDS
#define PROCESS_LISTPIDS proc_listpids
#endif
#ifndef PROCESS_PIDPATH
#define PROCESS_PIDPATH proc_pidpath
#endif
#ifndef PROCESS_KILL
#define PROCESS_KILL kill
#endif
#ifndef PROCESS_GETPID
#define PROCESS_GETPID getpid
#endif
#ifndef PROCESS_USLEEP
#define PROCESS_USLEEP usleep
#endif
#ifndef PROCESS_WAITPID
#define PROCESS_WAITPID waitpid
#endif

// Each helper invocation runs one operation. A later successful reap or an
// empty process snapshot must not erase uncertainty about an earlier child.
static int owned_reap_failed;

int reap_owned_process(pid_t pid) {
    int status = 0;
    pid_t waited;
    do {
        waited = PROCESS_WAITPID(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited == pid && (WIFEXITED(status) || WIFSIGNALED(status))) return 0;

    int saved = errno;
    owned_reap_failed = 1;
    attrs_t attrs;
    attrs_init(&attrs);
    attrs_int(&attrs, "pid", pid);
    attrs_int(&attrs, "wait_result", waited);
    attrs_hex(&attrs, "status", (unsigned int)status);
    if (waited < 0) attrs_errno(&attrs, saved);
    emit(LOG_ERROR, "target.reap_failed", &attrs,
         "owned ptrace child could not be reaped");
    return -1;
}

int process_completion_confirmed(const char *bundle, int ms_budget) {
    int idle = bundle_processes_idle(bundle, ms_budget);
    if (owned_reap_failed) {
        emit(LOG_ERROR, "operation.reap_unconfirmed", NULL,
             "owned child reaping was not confirmed");
        return 0;
    }
    return idle;
}

static int process_scan(const char *bundle, pid_t *blocked_pid,
                        int *blocked_errno, char *blocked_path,
                        size_t blocked_path_size) {
    int needed = PROCESS_LISTPIDS(1, 0, NULL, 0);
    if (needed <= 0 || needed > 16 * 1024 * 1024) return -1;

    int capacity = needed + 4096;
    pid_t *pids = malloc((size_t)capacity);
    if (!pids) return -2;

    int bytes = PROCESS_LISTPIDS(1, 0, pids, capacity);
    if (bytes <= 0 || bytes >= capacity) {
        free(pids);
        return -3;
    }

    if (strncmp(bundle, "/private/", 9) == 0) bundle += 8;
    size_t bundle_len = strlen(bundle);
    int idle = 1;
    for (int i = 0; i < bytes / (int)sizeof(pid_t); ++i) {
        if (pids[i] <= 0 || pids[i] == PROCESS_GETPID()) continue;

        char process_path[4096];
        errno = 0;
        if (PROCESS_PIDPATH(pids[i], process_path, sizeof(process_path)) <= 0) {
            int path_errno = errno;
            // Darwin's path lookup excludes zombies and returns ESRCH when
            // the executable is gone. kill(pid, 0) may still succeed for
            // these process-table entries; it is not proof of a live target.
            // Other lookup errors remain unconfirmed unless the PID is gone.
            if (path_errno == ESRCH) continue;
            if (PROCESS_KILL(pids[i], 0) == 0 || errno != ESRCH) {
                *blocked_pid = pids[i];
                *blocked_errno = path_errno;
                blocked_path[0] = '\0';
                idle = 0;
                break;
            }
            continue;
        }

        const char *path = process_path;
        if (strncmp(path, "/private/", 9) == 0) path += 8;
        if (strncmp(path, bundle, bundle_len) == 0 && path[bundle_len] == '/') {
            *blocked_pid = pids[i];
            *blocked_errno = 0;
            strncpy(blocked_path, path, blocked_path_size - 1);
            blocked_path[blocked_path_size - 1] = '\0';
            idle = 0;
            break;
        }
    }
    free(pids);
    return idle;
}

int bundle_processes_idle(const char *bundle, int ms_budget) {
    const int interval_ms = 50;
    pid_t blocked_pid = 0;
    int blocked_errno = 0;
    char blocked_path[4096] = {0};
    int result = 0;

    for (int waited = 0;; waited += interval_ms) {
        result = process_scan(bundle, &blocked_pid, &blocked_errno,
                              blocked_path, sizeof(blocked_path));
        if (result == 1) return 1;
        if (result < 0 || waited >= ms_budget) break;
        PROCESS_USLEEP(interval_ms * 1000);
    }

    attrs_t attrs;
    attrs_init(&attrs);
    if (result == -1) {
        attrs_int(&attrs, "err", errno);
        emit(LOG_ERROR, "operation.process_list_failed", &attrs,
             "could not size process list");
    } else if (result == -2) {
        emit(LOG_ERROR, "operation.process_list_oom", NULL,
             "could not allocate process list");
    } else if (result == -3) {
        emit(LOG_ERROR, "operation.process_list_incomplete", NULL,
             "could not capture a complete process list");
    } else if (blocked_path[0]) {
        attrs_int(&attrs, "pid", blocked_pid);
        attrs_str(&attrs, "path", blocked_path);
        attrs_int(&attrs, "budget_ms", ms_budget);
        emit(LOG_WARN, "operation.process_busy", &attrs,
             "bundle process is still running");
    } else {
        attrs_int(&attrs, "pid", blocked_pid);
        attrs_int(&attrs, "err", blocked_errno);
        attrs_int(&attrs, "budget_ms", ms_budget);
        emit(LOG_WARN, "operation.process_unknown", &attrs,
             "live process path could not be inspected");
    }
    return 0;
}
