package ipadecrypt

import (
	"errors"
	"strings"
	"testing"
)

type unlockFake struct {
	state   string
	command string
	input   string
	failure bool
	checks  int
}

func (f *unlockFake) Run(cmd string) (string, string, int, error) {
	if strings.HasSuffix(cmd, "ipadc status") {
		f.checks++
		if f.state != "locked" && f.state != "unlocked" {
			return f.state, "", 0, nil
		}
		return f.state, "", 0, nil
	}

	return "", "", 1, errors.New("unexpected command")
}

func (f *unlockFake) RunInput(cmd string, input []byte) (string, string, int, error) {
	f.command = cmd
	f.input = string(input)
	if f.failure {
		return "secret", "secret", 1, errors.New("secret")
	}
	f.state = "unlocked"
	return "unlocked", "", 0, nil
}

func TestEnsureUnlocked(t *testing.T) {
	for _, tc := range []struct {
		name, state                  string
		fail, wantCommand, wantError bool
	}{
		{"already unlocked", "unlocked", false, false, false},
		{"locked", "locked", false, true, false},
		{"unknown", "unknown", false, false, true},
		{"unlock failure", "locked", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &unlockFake{state: tc.state, failure: tc.fail}
			err := ensureUnlocked(f, "secret'$(touch /tmp/unwanted)")
			if (err != nil) != tc.wantError {
				t.Fatalf("error: %v", err)
			}
			if (f.command != "") != tc.wantCommand {
				t.Fatalf("unexpected command invocation")
			}
			if err != nil && (!errors.Is(err, ErrDeviceLocked) || strings.Contains(err.Error(), "secret")) {
				t.Fatalf("unsafe error: %v", err)
			}
			if tc.wantCommand && (strings.Contains(f.command, "secret") ||
				f.input != "secret'$(touch /tmp/unwanted)\n") {
				t.Fatal("PIN was not isolated on stdin")
			}
			if tc.name == "locked" && f.checks != 2 {
				t.Fatal("unlock not verified")
			}
		})
	}
}

type idleLeaseFake struct {
	commands []string
	fail     bool
}

func (f *idleLeaseFake) Run(cmd string) (string, string, int, error) {
	f.commands = append(f.commands, cmd)
	if f.fail {
		return "", "", 1, errors.New("failed")
	}
	if strings.Contains(cmd, "idle-acquire") {
		return "01234567-89ab-cdef-0123-456789abcdef\n", "", 0, nil
	}
	return "released\n", "", 0, nil
}

func (f *idleLeaseFake) RunInput(string, []byte) (string, string, int, error) {
	return "", "", 1, errors.New("unexpected input command")
}

func TestDisableAutoLockAcquiresAndReleasesLease(t *testing.T) {
	f := &idleLeaseFake{}
	restore, err := disableAutoLock(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 2 || !strings.Contains(f.commands[0], "idle-acquire 60") ||
		!strings.Contains(f.commands[1], "idle-release 01234567-89ab-cdef-0123-456789abcdef") {
		t.Fatalf("commands = %#v", f.commands)
	}
	if err := restore(); err != nil || len(f.commands) != 2 {
		t.Fatalf("second restore = %v, commands = %#v", err, f.commands)
	}
}

func TestDisableAutoLockRejectsBadLease(t *testing.T) {
	for _, failure := range []bool{
		true,
		false,
	} {
		_, err := disableAutoLock(&badLeaseFake{failure: failure})
		if !errors.Is(err, ErrDeviceLocked) {
			t.Fatalf("error = %v", err)
		}
	}
}

type badLeaseFake struct{ failure bool }

func (f *badLeaseFake) Run(string) (string, string, int, error) {
	if f.failure {
		return "", "", 1, errors.New("failed")
	}
	return "not-a-token", "", 0, nil
}

func (f *badLeaseFake) RunInput(string, []byte) (string, string, int, error) {
	return "", "", 1, errors.New("unexpected input command")
}
