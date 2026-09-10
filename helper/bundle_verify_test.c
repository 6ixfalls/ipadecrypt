#include "bundle_verify.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Synthetic Mach-O reader: exercise traversal and completeness policy without
// requiring Darwin headers on the host running go test.
int fs_is_macho(const char *path) { return strstr(path, ".macho") != NULL; }
int select_runtime_slice(const char *path, const runtime_image_t *rt, selected_slice_t *out) {
    (void)rt;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int value = fgetc(f); fclose(f);
    memset(out, 0, sizeof(*out));
    if (value == 'X') return -1;
    out->selected.crypt.cryptid = value == 'E';
    return 1;
}
int slice_needs_dump(const selected_slice_t *slice) { return slice->selected.crypt.cryptid != 0; }
static void put(const char *path, const char *value) {
    FILE *f = fopen(path, "w"); assert(f); assert(fputs(value, f) >= 0); assert(fclose(f) == 0);
}
int main(int argc, char **argv) {
    assert(argc == 2); assert(chdir(argv[1]) == 0);
    assert(mkdir("Test.app", 0700) == 0);
    assert(mkdir("Test.app/Frameworks", 0700) == 0);
    assert(mkdir("Test.app/Frameworks/F.framework", 0700) == 0);
    assert(mkdir("Test.app/PlugIns", 0700) == 0);
    runtime_image_t runtime = {0};
    put("Test.app/Main.macho", "D");
    put("Test.app/Frameworks/F.framework/F.macho", "E");
    // The exact regression: decrypted main + encrypted framework is failure.
    assert(bundle_verify_decrypted("Test.app", &runtime) != 0);
    put("Test.app/Frameworks/F.framework/F.macho", "D");
    assert(bundle_verify_decrypted("Test.app", &runtime) == 0);
    // Extensions are checked in their own decrypt_bundle invocation.
    put("Test.app/PlugIns/Extension.macho", "E");
    assert(bundle_verify_decrypted("Test.app", &runtime) == 0);
    assert(bundle_verify_decrypted("Test.app/PlugIns", &runtime) != 0);
    put("Test.app/Frameworks/F.framework/F.macho", "X");
    assert(bundle_verify_decrypted("Test.app", &runtime) != 0);
    put("Test.app/Frameworks/F.framework/F.macho", "D");
    assert(symlink("Main.macho", "Test.app/link") == 0);
    assert(bundle_verify_decrypted("Test.app", &runtime) != 0);
    assert(bundle_verify_decrypted("missing", &runtime) != 0);
    return 0;
}
