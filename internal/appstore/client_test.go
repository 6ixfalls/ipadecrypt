package appstore

import (
	"path/filepath"
	"testing"
)

func TestNormalizeMACAddress(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "colon separated", input: "02:00:00:AA:BB:CC", want: "02:00:00:aa:bb:cc", ok: true},
		{name: "hyphen separated", input: "02-00-00-AA-BB-CC", want: "02:00:00:aa:bb:cc", ok: true},
		{name: "EUI-64", input: "02:00:00:00:00:00:aa:bb", ok: false},
		{name: "invalid", input: "not-a-mac", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeMACAddress(tt.input)
			if (err == nil) != tt.ok {
				t.Fatalf("NormalizeMACAddress(%q) error = %v, want success=%t", tt.input, err, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("NormalizeMACAddress(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestClientFixedMACAddress(t *testing.T) {
	c, err := New(filepath.Join(t.TempDir(), "cookies"), "02-00-00-AA-BB-CC")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	mac, err := c.macAddress()
	if err != nil {
		t.Fatalf("macAddress() error = %v", err)
	}
	if mac != "02:00:00:aa:bb:cc" {
		t.Fatalf("macAddress() = %q", mac)
	}

	guid, err := c.guid()
	if err != nil {
		t.Fatalf("guid() error = %v", err)
	}
	if guid != "020000AABBCC" {
		t.Fatalf("guid() = %q", guid)
	}
}
