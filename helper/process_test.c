#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

enum test_mode {
    TRANSIENT_UNKNOWN,
    PERSISTENT_UNKNOWN,
    DEAD_SNAPSHOT,
    MATCHING_BUNDLE,
    UNRELATED_PROCESS,
    EXITED_PATH,
    DENIED_SIGNAL,
};

static enum test_mode mode;
static int scan_count;
static int wait_count;
static int wait_failure;

static int test_listpids(uint32_t type, uint32_t info, void *buffer,
                         int size) {
    (void)type;
    (void)info;
    (void)size;
    if (!buffer) return (int)sizeof(pid_t);
    *(pid_t *)buffer = 42;
    scan_count++;
    return (int)sizeof(pid_t);
}

static int test_pidpath(int pid, void *buffer, uint32_t size) {
    assert(pid == 42);
    const char *path = NULL;
    if (mode == TRANSIENT_UNKNOWN && scan_count > 1)
        path = "/usr/libexec/unrelated";
    else if (mode == MATCHING_BUNDLE)
        path = "/private/var/containers/Bundle/Application/U/Test.app/Test";
    else if (mode == UNRELATED_PROCESS)
        path = "/usr/libexec/unrelated";

    if (!path) {
        errno = mode == EXITED_PATH ? ESRCH : EACCES;
        return 0;
    }
    assert(strlen(path) + 1 <= size);
    strcpy(buffer, path);
    return (int)strlen(path);
}

static int test_kill(pid_t pid, int signal) {
    assert(pid == 42);
    assert(signal == 0);
    if (mode == DENIED_SIGNAL) {
        errno = EPERM;
        return -1;
    }
    if (mode == DEAD_SNAPSHOT) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}

static pid_t test_getpid(void) { return 99; }
static int test_usleep(unsigned int usec) {
    assert(usec == 50000);
    return 0;
}

static pid_t test_waitpid(pid_t pid, int *status, int options) {
    assert(pid == 42);
    assert(options == 0);
    wait_count++;
    if (!wait_failure && wait_count == 1) {
        errno = EINTR;
        return -1;
    }
    if (wait_failure) {
        errno = ECHILD;
        return -1;
    }
    *status = SIGKILL;
    return pid;
}

#define PROCESS_LISTPIDS test_listpids
#define PROCESS_PIDPATH test_pidpath
#define PROCESS_KILL test_kill
#define PROCESS_GETPID test_getpid
#define PROCESS_USLEEP test_usleep
#define PROCESS_WAITPID test_waitpid
#include "process.c"

static int check(enum test_mode next, int budget) {
    mode = next;
    scan_count = 0;
    return bundle_processes_idle(
        "/var/containers/Bundle/Application/U/Test.app", budget);
}

int main(void) {
    assert(check(TRANSIENT_UNKNOWN, 50) == 1);
    assert(scan_count == 2);
    assert(check(PERSISTENT_UNKNOWN, 0) == 0);
    assert(check(DEAD_SNAPSHOT, 0) == 1);
    assert(check(MATCHING_BUNDLE, 0) == 0);
    assert(check(UNRELATED_PROCESS, 0) == 1);
    // Reproduce the device log: path lookup reports ESRCH while a signal
    // probe would still succeed for the lingering process-table entry.
    assert(check(EXITED_PATH, 1000) == 1);
    assert(scan_count == 1);
    assert(check(DENIED_SIGNAL, 50) == 0);
    assert(scan_count == 2);
    mode = UNRELATED_PROCESS;

    wait_count = 0;
    wait_failure = 0;
    assert(reap_owned_process(42) == 0);
    assert(wait_count == 2);
    assert(process_completion_confirmed(
        "/var/containers/Bundle/Application/U/Test.app", 0) == 1);
    mode = MATCHING_BUNDLE;
    assert(process_completion_confirmed(
        "/var/containers/Bundle/Application/U/Test.app", 0) == 0);

    wait_count = 0;
    wait_failure = 1;
    assert(reap_owned_process(42) == -1);
    // An idle scan cannot authorize helper.done after an unconfirmed reap.
    assert(check(DEAD_SNAPSHOT, 0) == 1);
    assert(process_completion_confirmed(
        "/var/containers/Bundle/Application/U/Test.app", 0) == 0);
    // Successfully reaping a later extension must not clear that failure.
    wait_count = 0;
    wait_failure = 0;
    assert(reap_owned_process(42) == 0);
    assert(process_completion_confirmed(
        "/var/containers/Bundle/Application/U/Test.app", 0) == 0);
    return 0;
}
