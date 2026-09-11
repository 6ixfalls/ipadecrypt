package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/londek/ipadecrypt/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestLimitedBufferCapsRetainedBytes(t *testing.T) {
	t.Parallel()

	var b limitedBuffer
	b.max = 8

	if n, err := b.Write([]byte("123456")); err != nil || n != 6 {
		t.Fatalf("first write = (%d, %v)", n, err)
	}
	if n, err := b.Write([]byte("789abcdef")); err != nil || n != 9 {
		t.Fatalf("second write = (%d, %v)", n, err)
	}
	if got := b.String(); got != "12345678" {
		t.Fatalf("retained %q, want bounded prefix", got)
	}

	var streamed bytes.Buffer
	capture := limitedBuffer{max: 4}
	w := io.MultiWriter(&streamed, &capture)
	_, _ = w.Write([]byte("complete output"))
	if streamed.String() != "complete output" || capture.String() != "comp" {
		t.Fatalf("streamed=%q captured=%q", streamed.String(), capture.String())
	}
}

func TestCapturedStderrUsesFullBufferWhenNotStreaming(t *testing.T) {
	t.Parallel()

	full := bytes.NewBufferString("complete stderr")
	prefix := limitedBuffer{max: 4}
	_, _ = prefix.Write([]byte("comp"))

	if got := capturedStderr(nil, full, &prefix); got != "complete stderr" {
		t.Fatalf("captured stderr = %q, want complete buffer", got)
	}
	if got := capturedStderr(io.Discard, full, &prefix); got != "comp" {
		t.Fatalf("streamed stderr capture = %q, want bounded prefix", got)
	}
}

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

func TestKnownHostsTOFUPreservesUnterminatedLastLine(t *testing.T) {
	t.Parallel()
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	firstKey := testPublicKey(t)
	firstHost := "first.example:22"

	firstLine := knownhosts.Line([]string{knownhosts.Normalize(firstHost)}, firstKey)
	if err := os.WriteFile(knownHostsPath, []byte(firstLine), 0o600); err != nil {
		t.Fatal(err)
	}

	callback, err := newHostKeyCallback(config.Device{
		KnownHostsPath:   knownHostsPath,
		AcceptNewHostKey: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	secondKey := testPublicKey(t)

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 22}
	if err := callback("second.example:22", remote, secondKey); err != nil {
		t.Fatalf("enroll second key: %v", err)
	}

	check, err := knownhosts.New(knownHostsPath)
	if err != nil {
		t.Fatalf("parse updated known_hosts: %v", err)
	}

	if err := check(firstHost, remote, firstKey); err != nil {
		t.Fatalf("verify first key: %v", err)
	}

	if err := check("second.example:22", remote, secondKey); err != nil {
		t.Fatalf("verify second key: %v", err)
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
