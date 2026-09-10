package ipadecrypt

import (
	"fmt"
	"strings"
	"time"
)

type unlockDevice interface {
	Run(string) (string, string, int, error)
	RunSudo(string) (string, string, int, error)
}

func unlockQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Attempt the supplied PIN only once. Never expose command output: rc-client may
// echo its arguments, and transport errors may contain the command itself.
func ensureUnlocked(dev unlockDevice, helperPath, pin string) error {
	locked := func() (bool, error) {
		out, _, code, err := dev.RunSudo(unlockQuote(helperPath) + " lock-status")
		if err != nil || code != 0 || (strings.TrimSpace(out) != "0" && strings.TrimSpace(out) != "1") {
			return false, fmt.Errorf("%w: cannot determine device lock state", ErrDeviceLocked)
		}

		return strings.TrimSpace(out) == "1", nil
	}

	isLocked, err := locked()
	if err != nil || !isLocked {
		return err
	}

	_, _, code, err := dev.Run("PATH=/var/jb/usr/bin:/usr/bin:/bin:$PATH rc-client unlock " + unlockQuote(pin))
	if err != nil || code != 0 {
		return fmt.Errorf("%w: RemoteCompanion unlock failed; check the tweak and configured PIN", ErrDeviceLocked)
	}

	for attempt := 0; attempt < 20; attempt++ {
		isLocked, err = locked()
		if err != nil || !isLocked {
			return err
		}

		time.Sleep(250 * time.Millisecond)
	}

	return fmt.Errorf("%w: device remained locked after RemoteCompanion unlock", ErrDeviceLocked)
}
