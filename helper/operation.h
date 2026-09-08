#ifndef IPADECRYPT_OPERATION_H
#define IPADECRYPT_OPERATION_H
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include "log.h"
#ifndef OPERATION_PREFIX
#define OPERATION_PREFIX "/private/var/mobile/Media/ipadecrypt-op-"
#endif

// The lock remains held for the lifetime of an active helper operation.
// A completion receipt is written only after all work has returned. Recovery
// seals the root while holding the same lock, preventing delayed SSH launches.
static int operation_open(const char *dir) {
    attrs_t begin; attrs_init(&begin); attrs_str(&begin, "dir", dir); emit(LOG_DEBUG, "operation.open.begin", &begin, NULL);
    const char *prefix = OPERATION_PREFIX;
    size_t n = strlen(prefix);
    if (strncmp(dir, prefix, n) || strlen(dir + n) != 64) { attrs_str(&begin, "reason", "invalid_name"); emit(LOG_ERROR, "operation.open.rejected", &begin, "operation directory name is invalid"); return -1; }
    for (const char *p = dir + n; *p; ++p)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) { attrs_str(&begin, "reason", "invalid_hex"); emit(LOG_ERROR, "operation.open.rejected", &begin, "operation directory suffix is invalid"); return -1; }
    // Walk from / using descriptor-relative no-follow opens, including
    // ancestors; O_NOFOLLOW on only the final component is insufficient.
    char copy[4096];
    if (strlen(dir) >= sizeof(copy)) { attrs_str(&begin, "reason", "path_too_long"); emit(LOG_ERROR, "operation.open.rejected", &begin, NULL); return -1; }
    strcpy(copy,dir);
    int fd = open("/", O_RDONLY | O_DIRECTORY);
    if (fd < 0) { LOG_ERRNO("operation.open.root_failed", "open root directory failed: %s", strerror(errno)); return -1; }
    char *save = NULL;
    for (char *part = strtok_r(copy,"/",&save); part; part = strtok_r(NULL,"/",&save)) {
        int next = openat(fd,part,O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        close(fd); fd = next; if (fd < 0) { LOG_ERRNO("operation.open.component_failed", "secure open of %s failed: %s", dir, strerror(errno)); return -1; }
    }
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st)) { LOG_ERRNO("operation.open.stat_failed", "fstat operation directory failed: %s", strerror(errno)); close(fd); return -1; }
    if ((st.st_mode & 0777) != 0700) { attrs_fmt(&begin, "mode", "%o", st.st_mode & 0777); emit(LOG_ERROR, "operation.open.mode_rejected", &begin, "operation directory mode must be 0700"); close(fd); return -1; }
    attrs_int(&begin, "fd", fd); emit(LOG_DEBUG, "operation.open.done", &begin, NULL);
    return fd;
}
static int operation_lock(int dirfd) {
    attrs_t begin; attrs_init(&begin); attrs_int(&begin, "dirfd", dirfd); emit(LOG_DEBUG, "operation.lock.begin", &begin, NULL);
    int fd = openat(dirfd, "lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    struct stat st;
    if (fd < 0) { LOG_ERRNO("operation.lock.open_failed", "open operation lock failed: %s", strerror(errno)); return -1; }
    if (fstat(fd, &st)) { LOG_ERRNO("operation.lock.stat_failed", "fstat operation lock failed: %s", strerror(errno)); close(fd); return -1; }
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1) { attrs_int(&begin, "regular", S_ISREG(st.st_mode)); attrs_uint(&begin, "links", st.st_nlink); emit(LOG_ERROR, "operation.lock.rejected", &begin, "operation lock is not a private regular file"); close(fd); return -1; }
    if (flock(fd, LOCK_EX | LOCK_NB)) {
        LOG_ERRNO("operation.lock.busy", "operation lock acquisition failed: %s", strerror(errno));
        close(fd); return -1;
    }
    attrs_int(&begin, "fd", fd); emit(LOG_DEBUG, "operation.lock.done", &begin, NULL);
    return fd;
}
static int receipt(int dirfd, const char *name) {
    attrs_t begin; attrs_init(&begin); attrs_str(&begin, "name", name); emit(LOG_DEBUG, "operation.receipt.begin", &begin, NULL);
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { LOG_ERRNO("operation.receipt.open_failed", "create receipt %s failed: %s", name, strerror(errno)); return -1; }
    int rc = fsync(fd); close(fd);
    if (rc == 0) rc = fsync(dirfd);
    if (rc != 0) LOG_ERRNO("operation.receipt.sync_failed", "sync receipt %s failed: %s", name, strerror(errno));
    else emit(LOG_DEBUG, "operation.receipt.done", &begin, NULL);
    return rc;
}
static int has_receipt(int dirfd, const char *name) {
    struct stat st;
    int found = fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1;
    if (log_level_visible(LOG_DEBUG)) { attrs_t a; attrs_init(&a); attrs_str(&a, "name", name); attrs_int(&a, "found", found); if (!found) attrs_int(&a, "err", errno); emit(LOG_DEBUG, "operation.receipt.check", &a, NULL); }
    return found;
}
static int operation_cleanup(const char *dir, const char *requirements) {
    attrs_t begin; attrs_init(&begin); attrs_str(&begin, "dir", dir); attrs_str(&begin, "requirements", requirements); emit(LOG_INFO, "cleanup.begin", &begin, "validating operation cleanup");
    int d = operation_open(dir); if (d < 0) return 1;
    int lock = operation_lock(d); if (lock < 0) { close(d); return 1; }
    int rc = 0;
    if (!has_receipt(d, "sealed") && receipt(d, "sealed")) rc = 1;
    if (strchr(requirements, 'i') && !has_receipt(d, "install.done")) rc = 1;
    if (strchr(requirements, 'h') && !has_receipt(d, "helper.done")) rc = 1;
    if (strchr(requirements, 'u') && !has_receipt(d, "uninstall.done")) rc = 1;
    close(lock); close(d); attrs_int(&begin, "result", rc); emit(rc ? LOG_ERROR : LOG_INFO, "cleanup.done", &begin, rc ? "cleanup requirements were not satisfied" : "cleanup confirmed"); return rc;
}
// Use the system installation service directly: appinst has a shared temp
// directory of its own, which cannot be attributed to an operation reliably.
static int system_app_change(const char *value, const char *bundle_id, int remove_app) {
    attrs_t begin; attrs_init(&begin); attrs_str(&begin, "bundle_id", bundle_id); attrs_str(&begin, "action", remove_app ? "uninstall" : "install"); emit(LOG_INFO, "app_change.begin", &begin, "%s %s", remove_app ? "uninstalling" : "installing", bundle_id);
    void *objc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOW);
    void *foundation = dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", RTLD_NOW);
    void *services = dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_NOW);
    if (!objc || !foundation || !services) { attrs_int(&begin, "objc", objc != NULL); attrs_int(&begin, "foundation", foundation != NULL); attrs_int(&begin, "services", services != NULL); const char *detail = dlerror(); if (detail) attrs_str(&begin, "dlerror", detail); emit(LOG_ERROR, "app_change.framework_failed", &begin, NULL); return 1; }
    void *(*get_class)(const char *) = dlsym(objc,"objc_getClass");
    void *(*selector)(const char *) = dlsym(objc,"sel_registerName");
    void *send = dlsym(objc,"objc_msgSend");
    if (!get_class || !selector || !send) { emit(LOG_ERROR, "app_change.objc_symbols_failed", &begin, NULL); return 1; }
    void *cls = get_class("LSApplicationWorkspace");
    if (!cls) { emit(LOG_ERROR, "app_change.workspace_class_failed", &begin, NULL); return 1; }
    void *workspace = ((void *(*)(void *,void *))send)(cls,selector("defaultWorkspace"));
    if (!workspace) { emit(LOG_ERROR, "app_change.workspace_failed", &begin, NULL); return 1; }
    void *method = selector(remove_app ? "uninstallApplication:withOptions:" : "installApplication:withOptions:error:");
    if (!((unsigned char (*)(void *,void *,void *))send)(workspace,selector("respondsToSelector:"),method)) { emit(LOG_ERROR, "app_change.method_unavailable", &begin, NULL); return 1; }
    void *strcls = get_class("NSString");
    void *id = ((void *(*)(void *,void *,const char *))send)(strcls,selector("stringWithUTF8String:"),bundle_id);
    if (!id) { emit(LOG_ERROR, "app_change.bundle_id_failed", &begin, NULL); return 1; }
    if (remove_app) {
        int rc = ((unsigned char (*)(void *,void *,void *,void *))send)(workspace,method,id,NULL) ? 0 : 1;
        attrs_int(&begin, "result", rc); emit(rc ? LOG_ERROR : LOG_INFO, "app_change.done", &begin, NULL); return rc;
    }
    void *file = ((void *(*)(void *,void *,const char *))send)(strcls,selector("stringWithUTF8String:"),value);
    void *url = ((void *(*)(void *,void *,void *))send)(get_class("NSURL"),selector("fileURLWithPath:"),file);
    void *key = ((void *(*)(void *,void *,const char *))send)(strcls,selector("stringWithUTF8String:"),"CFBundleIdentifier");
    void *options = ((void *(*)(void *,void *,void *,void *))send)(get_class("NSDictionary"),selector("dictionaryWithObject:forKey:"),id,key);
    void *error = NULL;
    int rc = ((unsigned char (*)(void *,void *,void *,void *,void **))send)(workspace,method,url,options,&error) ? 0 : 1;
    attrs_int(&begin, "result", rc); attrs_int(&begin, "has_error_object", error != NULL); emit(rc ? LOG_ERROR : LOG_INFO, "app_change.done", &begin, NULL); return rc;
}
static int operation_app_change(const char *dir, const char *bundle_id, const char *ipa, int remove_app) {
    attrs_t begin; attrs_init(&begin); attrs_str(&begin, "dir", dir); attrs_str(&begin, "bundle_id", bundle_id); attrs_str(&begin, "action", remove_app ? "uninstall" : "install"); emit(LOG_INFO, "operation.app_change.begin", &begin, NULL);
    int d = operation_open(dir); if (d < 0) return 1;
    int lock = operation_lock(d); if (lock < 0) { close(d); return 1; }
    const char *done = remove_app ? "uninstall.done" : "install.done";
    if ((!remove_app && has_receipt(d,"sealed")) || (!remove_app && has_receipt(d,done))) { close(lock); close(d); return 1; }
    if (remove_app && unlinkat(d,done,0) && errno != ENOENT) { close(lock); close(d); return 1; }
    int rc = system_app_change(ipa,bundle_id,remove_app);
    if (receipt(d,done)) rc = 1;
    close(lock); close(d); attrs_int(&begin, "result", rc); emit(rc ? LOG_ERROR : LOG_INFO, "operation.app_change.done", &begin, NULL); return rc;
}


#endif
