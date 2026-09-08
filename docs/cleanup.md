# Durable device cleanup

Opt in by supplying both `Request.OperationID` and `Request.JournalDir`.
`OperationID` is a **single-use** identifier matching
`[A-Za-z0-9][A-Za-z0-9_-]{0,127}`. Use a new ID for each decryption attempt.
`JournalDir` must be an absolute, private directory (0700), separate from
`StateDir`, disposable workspaces, inputs, and temporary-file storage. Journal
files contain device/app identity and ownership information, but no credentials
or Apple account data. Treat this directory as trusted private application state.

```go
result, decryptErr := ipadecrypt.Decrypt(ctx, ipadecrypt.Request{
    OperationID: jobID,
    JournalDir:  "/srv/ipa-now/device-journal",
    StateDir:    workspace,
    Target:      target,
    Device:      deviceConfig,
    Uninstall:   ipadecrypt.UninstallAuto,
})

// Also call during restart recovery, using fresh credentials and a new context.
cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
report, cleanupErr := ipadecrypt.Cleanup(cleanupCtx, ipadecrypt.CleanupRequest{
    OperationID: jobID,
    JournalDir:  "/srv/ipa-now/device-journal",
    Device:      deviceConfig,
})
confirmed := cleanupErr == nil && report.Confirmed
```

Hold an exclusive **physical-device** lease throughout decryption and cleanup.
The library's nonblocking file lock prevents overlapping calls for the same
operation ID; it does not replace the application's device-wide lease.

`Decrypt` attempts the same public cleanup path on ordinary exits, with a fresh
SSH connection and an independent 30-second context after closing the decryption
connection. Cleanup errors are joined with the decryption error. A successful
artifact/result alone is not proof of successful cleanup. `CleanupReport.Confirmed`
is affirmative only after all required postconditions and the durable clean
marker have been recorded. `Uninstalled` reports the uninstall postcondition;
it does not imply restoration of an earlier build.

## Ownership and recovery

The journal uses exclusive ID reservation, schema validation, atomic replacement,
file sync and directory sync. Corrupt/unsupported/missing records, unsafe paths,
private-directory permission failures, and device endpoint/key mismatches fail
closed. Failed writes abort before their dependent device mutation. A record
reserved before an interrupted initial write remains invalid and needs review;
never overwrite it or reuse its ID. Incomplete atomic-write `.tmp` files are
private journal debris and may be removed only when the service is stopped.

A random operation token determines one exclusive 0700 remote directory beneath
`/private/var/mobile/Media`. The journal records its intent before creation. The
uploaded IPA, helper executable, helper dump tree, locks and receipts live there.
Helper files use exclusive/no-follow opens. Source bundle symlinks are rejected
rather than copied into writable staging. Legacy non-journaled runs retain their
API, but now use randomized helper staging and propagate remote staging deletion
errors; they are not recoverable with `Cleanup`.

Durable installs call LaunchServices from the owned helper. This avoids
`appinst`'s unowned shared temporary directory. Durable uninstalls use the system
uninstall API rather than unregistering and deleting only the bundle directory.
These private iOS APIs and entitlements need validation on the target jailbreak;
unsupported calls fail without falling back to broad filesystem deletion.
The method signatures are consistent with the upstream
[appinst implementation](https://github.com/akemin-dayo/AppSync/blob/master/appinst/appinst.m)
and [IPA Installer](https://github.com/autopear/ipainstaller/blob/master/main.mm).
System-managed caches, shared app groups, and keychain retention are governed by
iOS; cleanup does not scan or wipe those shared resources.

The helper holds an OS lock for each operation and syncs completion receipts.
Cleanup acquires that lock and seals the directory against delayed launches.
A busy lock or missing completion receipt is **unconfirmed**: this implementation
does not kill a process by a saved PID or guess whether an abruptly terminated
helper left targets/system installation work behind. A disconnected helper that
finishes and writes its receipt can be recovered on the next cleanup pass. A
hard-killed helper, or a crash between launch intent and receipt creation, can
require operator review. This conservative fallback is intentional; automatic
termination/recovery of arbitrary interrupted helper/target trees is not provided.

Install intent records preexisting bundle location plus executable and metadata
hashes, expected build hashes, and acknowledged installation location. A lost
install response is recoverable when receipts prove the installer returned and
build ownership is unambiguous. An indistinguishable replacement is not guessed.
`UninstallAuto` preserves unchanged preexisting apps and removes owned installs;
`UninstallNever` verifies preservation; `UninstallAlways` explicitly permits
removing the recorded preexisting app. Uninstall intent is synced before the
system call and absence is checked afterward. Replacing then removing an app
does **not** restore its previous build or data.

After helper quiescence, app cleanup and staging cleanup are attempted
independently. If app cleanup fails, the IPA/dumps can be removed while the helper,
lock and receipts remain available for retry. Keep the device quarantined until
cleanup returns no error and `Confirmed=true`, or an operator explicitly resolves
it. Do not blindly re-decrypt an uncertain operation.

Retain unresolved journals and completed clean markers across restarts. Clean
markers allow replay when device cleanup succeeded before the application's
terminal database write. Remove them only after the corresponding application
job is terminal and no recovery can reference it. `KeepRemoteFiles` is incompatible
with durable cleanup.

## Integration and validation

ipa-now still needs a new fork commit pinned, a dedicated durable journal directory,
and its real adapter wired to `OperationID`/`JournalDir` and `Cleanup`. This repository
change does not modify ipa-now's dependency or enable its production cleaner.

Run `go test ./...`, `go test -race ./pkg/ipadecrypt ./internal/device`,
`golangci-lint run`, and `go build ./...`. The device package compiles and runs
`helper/operation_test.c` when a POSIX C compiler is present; it checks lock
exclusion, missing receipts, permanent sealing, retry and symlink rejection without
an iPhone. Journal/cleanup tests cover replay, invalid ownership, cancelled contexts,
independent errors, lost responses, preservation, and failed persistence.

Rebuild with `./helper/build.sh`, copy its output into
`internal/device/ipadecrypt-helper-arm64`, and verify identical rebuild output.
Hardware-free tests cannot validate private installation APIs, code-signing,
jailbreak permissions, or actual target-process behavior. Before enabling ipa-now's
real cleaner, exercise success, cancellation, disconnect, install/uninstall failure,
and restart recovery on an explicitly authorized test device.
