# ipadecrypt Companion

This package contains the minimum SpringBoard integration required by
ipadecrypt. It provides lock status, a single verified passcode attempt, and a
renewable idle-timer lease over a local Unix socket.

## Build and install

Install Theos, then build a rootless package:

```sh
cd companion
make clean package THEOS_PACKAGE_SCHEME=rootless
```

For a rootful jailbreak:

```sh
make clean package THEOS_PACKAGE_SCHEME=
```

Install the resulting `.deb` on the device and respring. The package installs
`ipadc` into the jailbreak's command path.

The SpringBoard dylib is intentionally limited to `com.apple.springboard`. Its
socket is stored at `/var/mobile/Library/IPADDecrypt/companion.sock` with mode
`0600`. Passcodes are neither persisted nor logged.

The focused implementation was informed by RemoteCompanion's SpringBoard unlock
path. See [THIRD_PARTY_NOTICE.md](THIRD_PARTY_NOTICE.md) for attribution and its
MIT license.

## Protocol

The bundled client supports:

```text
ipadc status
printf '%s\n' PIN | ipadc unlock
ipadc idle-acquire TTL_SECONDS
ipadc idle-renew TOKEN TTL_SECONDS
ipadc idle-release TOKEN
```

Lease TTLs must be between 15 and 300 seconds. ipadecrypt renews its lease while
the on-device helper runs. If the host disappears, the lease expires and the
tweak restores the idle-timer state it found before the first lease.
