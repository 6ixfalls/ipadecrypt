//go:build !windows

package device

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(f *os.File) (func() error, error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}

	return func() error {
		return unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}, nil
}

// TryOperationLock acquires a nonblocking cross-process operation lease.
func TryOperationLock(f *os.File) (func() error, error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}

	return func() error {
		return unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}, nil
}
