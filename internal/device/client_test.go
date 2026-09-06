package device

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/londek/ipadecrypt/internal/config"
	"golang.org/x/crypto/ssh"
)

func TestKnownHostsTOFURejectsChangedKey(t *testing.T) {
	t.Parallel()
	knownHostsPath := filepath.Join(t.TempDir(), "ssh", "known_hosts")
	callback, err := newHostKeyCallback(config.Device{KnownHostsPath: knownHostsPath, AcceptNewHostKey: true})
	if err != nil {
		t.Fatal(err)
	}

	key1 := testPublicKey(t)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if err := callback("device.example:22", remote, key1); err != nil {
		t.Fatalf("enroll key: %v", err)
	}
	if err := callback("device.example:22", remote, key1); err != nil {
		t.Fatalf("verify enrolled key: %v", err)
	}
	if err := callback("device.example:22", remote, testPublicKey(t)); err == nil {
		t.Fatal("changed key was accepted")
	}

	info, err := os.Stat(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", info.Mode().Perm())
	}
}

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
