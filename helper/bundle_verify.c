#include "bundle_verify.h"
#include "fs.h"
#include "log.h"
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int verify_tree(const char *dir, const runtime_image_t *runtime, int depth) {
    if (depth > 64) return -1;
    DIR *d = opendir(dir);
    if (!d) return -1;
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(d))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (depth == 0 && (!strcmp(entry->d_name, "PlugIns") ||
                           !strcmp(entry->d_name, "Extensions"))) continue;
        char file[4096];
        int n = snprintf(file, sizeof(file), "%s/%s", dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(file)) { result = -1; break; }
        struct stat st;
        if (lstat(file, &st)) { result = -1; break; }
        if (S_ISDIR(st.st_mode)) {
            if (verify_tree(file, runtime, depth + 1)) result = -1;
        } else if (S_ISREG(st.st_mode) && fs_is_macho(file)) {
            selected_slice_t selected;
            int rc = select_runtime_slice(file, runtime, &selected);
            if (rc < 0 || (rc == 1 && slice_needs_dump(&selected))) {
                attrs_t a; attrs_init(&a); attrs_str(&a, "path", file);
                emit(LOG_ERROR, "image.incomplete", &a,
                     "staged executable is still encrypted or could not be inspected");
                result = -1;
            }
        } else if (!S_ISREG(st.st_mode)) {
            result = -1;
        }
    }
    closedir(d);
    return result;
}

int bundle_verify_decrypted(const char *bundle, const runtime_image_t *runtime) {
    if (!runtime) return -1;
    int result = verify_tree(bundle, runtime, 0);
    if (result) {
        attrs_t a; attrs_init(&a); attrs_str(&a, "bundle", bundle);
        emit(LOG_ERROR, "bundle.incomplete", &a,
             "bundle decryption is incomplete; SpringBoard must launch the app to decrypt embedded frameworks (unlock the device and retry)");
    }
    return result;
}
