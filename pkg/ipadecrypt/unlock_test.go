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
