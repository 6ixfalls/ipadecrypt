#ifndef HELPER_BUNDLE_VERIFY_H
#define HELPER_BUNDLE_VERIFY_H
#include "macho.h"

// Check this bundle's staged executables, excluding its separately decrypted
// PlugIns/Extensions. Return zero only when no matching slice needs decryption.
int bundle_verify_decrypted(const char *bundle, const runtime_image_t *runtime);
#endif
