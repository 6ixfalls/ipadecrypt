#ifndef HELPER_PROCESS_H
#define HELPER_PROCESS_H

#include <sys/types.h>

// Confirm that no executable in bundle is still running. Transient process
// table entries are retried for up to ms_budget. Enumeration uncertainty or a
// persistently live bundle process fails closed.
int bundle_processes_idle(const char *bundle, int ms_budget);

// Reap a ptrace child owned by this helper. Returns zero only after waitpid
// confirms a terminal state.
int reap_owned_process(pid_t pid);

// Completion requires both an idle bundle and successful reaping of every
// owned child. Reap failures remain unconfirmed for this helper invocation.
int process_completion_confirmed(const char *bundle, int ms_budget);

#endif // HELPER_PROCESS_H
