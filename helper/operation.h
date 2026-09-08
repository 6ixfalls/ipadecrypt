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
#ifndef OPERATION_PREFIX
#define OPERATION_PREFIX "/private/var/mobile/Media/ipadecrypt-op-"
#endif

// The lock remains held for the lifetime of an active helper operation.
// A completion receipt is written only after all work has returned. Recovery
// seals the root while holding the same lock, preventing delayed SSH launches.
static int operation_open(const char *dir) {
    const char *prefix = OPERATION_PREFIX;
    size_t n = strlen(prefix);
    if (strncmp(dir, prefix, n) || strlen(dir + n) != 64) return -1;
    for (const char *p = dir + n; *p; ++p)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return -1;
    // Walk from / using descriptor-relative no-follow opens, including
    // ancestors; O_NOFOLLOW on only the final component is insufficient.
    char copy[4096];
    if (strlen(dir) >= sizeof(copy)) return -1;
    strcpy(copy,dir);
    int fd = open("/", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    char *save = NULL;
    for (char *part = strtok_r(copy,"/",&save); part; part = strtok_r(NULL,"/",&save)) {
        int next = openat(fd,part,O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        close(fd); fd = next; if (fd < 0) return -1;
    }
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || (st.st_mode & 0777) != 0700) { close(fd); return -1; }
    return fd;
}
static int operation_lock(int dirfd) {
    int fd = openat(dirfd, "lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd); return -1;
    }
    return fd;
}
static int receipt(int dirfd, const char *name) {
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    int rc = fsync(fd); close(fd);
    if (rc == 0) rc = fsync(dirfd);
    return rc;
}
static int has_receipt(int dirfd, const char *name) {
    struct stat st;
    return fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1;
}
static int operation_cleanup(const char *dir, const char *requirements) {
    int d = operation_open(dir); if (d < 0) return 1;
    int lock = operation_lock(d); if (lock < 0) { close(d); return 1; }
    int rc = 0;
    if (!has_receipt(d, "sealed") && receipt(d, "sealed")) rc = 1;
    if (strchr(requirements, 'i') && !has_receipt(d, "install.done")) rc = 1;
    if (strchr(requirements, 'h') && !has_receipt(d, "helper.done")) rc = 1;
    if (strchr(requirements, 'u') && !has_receipt(d, "uninstall.done")) rc = 1;
    close(lock); close(d); return rc;
}
// Use the system installation service directly: appinst has a shared temp
// directory of its own, which cannot be attributed to an operation reliably.
static int system_app_change(const char *value, const char *bundle_id, int remove_app) {
    void *objc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOW);
    void *foundation = dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", RTLD_NOW);
    void *services = dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_NOW);
    if (!objc || !foundation || !services) return 1;
    void *(*get_class)(const char *) = dlsym(objc,"objc_getClass");
    void *(*selector)(const char *) = dlsym(objc,"sel_registerName");
    void *send = dlsym(objc,"objc_msgSend");
    if (!get_class || !selector || !send) return 1;
    void *cls = get_class("LSApplicationWorkspace");
    if (!cls) return 1;
    void *workspace = ((void *(*)(void *,void *))send)(cls,selector("defaultWorkspace"));
    if (!workspace) return 1;
    void *method = selector(remove_app ? "uninstallApplication:withOptions:" : "installApplication:withOptions:error:");
    if (!((unsigned char (*)(void *,void *,void *))send)(workspace,selector("respondsToSelector:"),method)) return 1;
    void *strcls = get_class("NSString");
    void *id = ((void *(*)(void *,void *,const char *))send)(strcls,selector("stringWithUTF8String:"),bundle_id);
    if (!id) return 1;
    if (remove_app)
        return ((unsigned char (*)(void *,void *,void *,void *))send)(workspace,method,id,NULL) ? 0 : 1;
    void *file = ((void *(*)(void *,void *,const char *))send)(strcls,selector("stringWithUTF8String:"),value);
    void *url = ((void *(*)(void *,void *,void *))send)(get_class("NSURL"),selector("fileURLWithPath:"),file);
    void *key = ((void *(*)(void *,void *,const char *))send)(strcls,selector("stringWithUTF8String:"),"CFBundleIdentifier");
    void *options = ((void *(*)(void *,void *,void *,void *))send)(get_class("NSDictionary"),selector("dictionaryWithObject:forKey:"),id,key);
    void *error = NULL;
    return ((unsigned char (*)(void *,void *,void *,void *,void **))send)(workspace,method,url,options,&error) ? 0 : 1;
}
static int operation_app_change(const char *dir, const char *bundle_id, const char *ipa, int remove_app) {
    int d = operation_open(dir); if (d < 0) return 1;
    int lock = operation_lock(d); if (lock < 0) { close(d); return 1; }
    const char *done = remove_app ? "uninstall.done" : "install.done";
    if ((!remove_app && has_receipt(d,"sealed")) || (!remove_app && has_receipt(d,done))) { close(lock); close(d); return 1; }
    if (remove_app && unlinkat(d,done,0) && errno != ENOENT) { close(lock); close(d); return 1; }
    int rc = system_app_change(ipa,bundle_id,remove_app);
    if (receipt(d,done)) rc = 1;
    close(lock); close(d); return rc;
}


#endif
