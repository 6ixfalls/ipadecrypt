package ipadecrypt

import (
	"errors"
	"strings"
	"testing"
)

type unlockFake struct {
	state   string
	command string
	failure bool
	checks  int
}

func (f *unlockFake) Run(cmd string) (string, string, int, error) {
	f.command = cmd
	if f.failure {
		return "secret", "secret", 1, errors.New("secret")
	}
	f.state = "0"
	return "", "", 0, nil
}
func (f *unlockFake) RunSudo(string) (string, string, int, error) {
	f.checks++
	return f.state, "", 0, nil
}
func TestEnsureUnlocked(t *testing.T) {
	for _, tc := range []struct {
		name, state                  string
		fail, wantCommand, wantError bool
	}{
		{"already unlocked", "0", false, false, false},
		{"locked", "1", false, true, false},
		{"unknown", "-1", false, false, true},
		{"unlock failure", "1", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &unlockFake{state: tc.state, failure: tc.fail}
			err := ensureUnlocked(f, "/tmp/helper", "secret'$(touch /tmp/unwanted)")
			if (err != nil) != tc.wantError {
				t.Fatalf("error: %v", err)
			}
			if (f.command != "") != tc.wantCommand {
				t.Fatalf("unexpected command invocation")
			}
			if err != nil && (!errors.Is(err, ErrDeviceLocked) || strings.Contains(err.Error(), "secret")) {
				t.Fatalf("unsafe error: %v", err)
			}
			if tc.wantCommand && !strings.Contains(f.command, unlockQuote("secret'$(touch /tmp/unwanted)")) {
				t.Fatal("PIN not quoted")
			}
			if tc.name == "locked" && f.checks != 2 {
				t.Fatal("unlock not verified")
			}
		})
	}
}

type autoLockFake struct {
	disabled   bool
	queryValid bool
	failSets   int
	sets       []bool
}

func (f *autoLockFake) Run(cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "isIdleTimerDisabled") {
		if !f.queryValid {
			return "Lua Error: unknown", "", 0, nil
		}
		if f.disabled {
			return "Lua Error: IPADECRYPT_IDLE_TIMER_DISABLED", "", 0, nil
		}
		return "Lua Error: IPADECRYPT_IDLE_TIMER_ENABLED", "", 0, nil
	}

	if strings.Contains(cmd, "setIdleTimerDisabled:") {
		if f.failSets > 0 {
			f.failSets--
			return "Lua Error: failed", "", 0, nil
		}
		value := strings.Contains(cmd, ",true)")
		f.disabled = value
		f.sets = append(f.sets, value)
		return "Lua Error: IPADECRYPT_IDLE_TIMER_SET", "", 0, nil
	}

	return "", "", 1, errors.New("unexpected command")
}

func (f *autoLockFake) RunSudo(string) (string, string, int, error) {
	return "", "", 1, errors.New("unexpected sudo command")
}

func TestDisableAutoLockRestoresPriorState(t *testing.T) {
	f := &autoLockFake{queryValid: true}
	restore, err := disableAutoLock(f)
	if err != nil {
		t.Fatal(err)
	}
	if !f.disabled || len(f.sets) != 1 || !f.sets[0] {
		t.Fatalf("auto-lock was not disabled: %#v", f.sets)
	}

	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if f.disabled || len(f.sets) != 2 || f.sets[1] {
		t.Fatalf("auto-lock was not restored: %#v", f.sets)
	}
}

func TestDisableAutoLockPreservesExistingOverride(t *testing.T) {
	f := &autoLockFake{disabled: true, queryValid: true}
	restore, err := disableAutoLock(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if !f.disabled || len(f.sets) != 0 {
		t.Fatalf("existing idle-timer override changed: %#v", f.sets)
	}
}

func TestDisableAutoLockFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		fake autoLockFake
	}{
		{name: "unknown prior state", fake: autoLockFake{}},
		{name: "disable failure", fake: autoLockFake{queryValid: true, failSets: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := disableAutoLock(&tc.fake)
			if !errors.Is(err, ErrDeviceLocked) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
