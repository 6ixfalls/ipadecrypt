package ipadecrypt

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const remoteCompanionPath = "PATH=/var/jb/usr/bin:/usr/bin:/bin:$PATH rc-client "

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

	_, _, code, err := dev.Run(remoteCompanionPath + "unlock " + unlockQuote(pin))
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

// disableAutoLock temporarily disables SpringBoard's idle timer without
// changing the user's saved Auto-Lock timeout. The returned function restores
// the exact runtime state that was active before this call.
func disableAutoLock(dev unlockDevice) (func() error, error) {
	const (
		stateEnabled  = "IPADECRYPT_IDLE_TIMER_DISABLED"
		stateDisabled = "IPADECRYPT_IDLE_TIMER_ENABLED"
		stateSet      = "IPADECRYPT_IDLE_TIMER_SET"
		app           = `objc_call("UIApplication","sharedApplication")`
	)

	query := `local a=` + app + `;if not a then error("IPADECRYPT_NO_APPLICATION") end;` +
		`if objc_call(a,"isIdleTimerDisabled") then error("` + stateEnabled + `") ` +
		`else error("` + stateDisabled + `") end`
	out, _, code, err := dev.Run(remoteCompanionPath + "lua_eval " + unlockQuote(query))
	if err != nil || code != 0 {
		return nil, fmt.Errorf("%w: cannot determine screen auto-lock state", ErrDeviceLocked)
	}

	wasDisabled := strings.Contains(out, stateEnabled)
	if !wasDisabled && !strings.Contains(out, stateDisabled) {
		return nil, fmt.Errorf("%w: cannot determine screen auto-lock state", ErrDeviceLocked)
	}

	if wasDisabled {
		return func() error { return nil }, nil
	}

	setIdleTimer := func(disabled bool) error {
		value := "false"
		if disabled {
			value = "true"
		}

		code := `local a=` + app + `;if not a then error("IPADECRYPT_NO_APPLICATION") end;` +
			`objc_call(a,"setIdleTimerDisabled:",` + value + `);error("` + stateSet + `")`
		out, _, exitCode, runErr := dev.Run(remoteCompanionPath + "lua_eval " + unlockQuote(code))
		if runErr != nil || exitCode != 0 || !strings.Contains(out, stateSet) {
			return fmt.Errorf("%w: cannot set screen auto-lock state", ErrDeviceLocked)
		}

		return nil
	}

	if err := setIdleTimer(true); err != nil {
		return nil, errors.Join(err, setIdleTimer(false))
	}

	return func() error {
		if err := setIdleTimer(false); err != nil {
			return fmt.Errorf("restore screen auto-lock: %w", err)
		}

		return nil
	}, nil
}
