#include "operation.h"
#include <assert.h>
#include <stdlib.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *dir = argv[1];
    assert(mkdir(dir,0700) == 0);
    int d = operation_open(dir);
    assert(d >= 0);
    int lock = operation_lock(d);
    assert(lock >= 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(lock);
        // The parent still holds the lock: cleanup must refuse.
        _exit(operation_cleanup(dir,"h") == 1 ? 0 : 1);
    }
    int status;
    assert(waitpid(child,&status,0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(lock);
    // Missing receipt is uncertain, even with no live lock holder.
    assert(operation_cleanup(dir,"h") == 1);
    assert(has_receipt(d,"sealed"));
    // A delayed launch is permanently rejected after recovery sealed the root.
    assert(operation_app_change(dir,"com.test","unused",0) == 1);
    assert(receipt(d,"helper.done") == 0);
    assert(operation_cleanup(dir,"h") == 0);
    assert(operation_cleanup(dir,"ih") == 1);
    assert(receipt(d,"install.done") == 0);
    assert(operation_cleanup(dir,"ih") == 0);
    assert(operation_cleanup(dir,"ihu") == 1);
    assert(receipt(d,"uninstall.done") == 0);
    assert(operation_cleanup(dir,"ihu") == 0);
    assert(operation_cleanup(dir,"ihu") == 0);
    // Never follow receipt or lock symlinks.
    assert(unlinkat(d,"helper.done",0) == 0);
    assert(symlinkat("install.done",d,"helper.done") == 0);
    assert(operation_cleanup(dir,"h") == 1);
    assert(unlinkat(d,"lock",0) == 0);
    assert(symlinkat("install.done",d,"lock") == 0);
    assert(operation_cleanup(dir,"i") == 1);
    close(d);
    return 0;
}
