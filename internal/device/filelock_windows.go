package device

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockFile(f *os.File) (func() error, error) {
	var overlapped windows.Overlapped
	handle := windows.Handle(f.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return nil, err
	}
	return func() error {
		return windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
	}, nil
}

// TryOperationLock acquires a nonblocking cross-process operation lease.
func TryOperationLock(f *os.File) (func() error, error) {
	var overlapped windows.Overlapped
	handle := windows.Handle(f.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		return nil, err
	}
	return func() error {
		return windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
	}, nil
}
