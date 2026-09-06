package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const RemoteRoot = "/var/mobile/Media/ipadecrypt"

var ErrSudoPasswordRejected = errors.New("sudo password rejected")

type Client struct {
	cfg  config.Device
	ssh  *ssh.Client
	sftp *sftp.Client
}

var knownHostsMu sync.Mutex

func Connect(ctx context.Context, dev config.Device) (*Client, error) {
	auth, err := sshAuthMethods(dev.Auth)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := newHostKeyCallback(dev)
	if err != nil {
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:            dev.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(dev.Host, strconv.Itoa(dev.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	sshClient := ssh.NewClient(sshConn, chans, reqs)

	sftpClient, err := sftp.NewClient(sshClient,
		sftp.UseConcurrentReads(true),
		sftp.UseConcurrentWrites(true),
		sftp.MaxConcurrentRequestsPerFile(64),
	)
	if err != nil {
		sshClient.Close()
		return nil, fmt.Errorf("sftp open: %w", err)
	}

	return &Client{cfg: dev, ssh: sshClient, sftp: sftpClient}, nil
}

func sshAuthMethods(a config.DeviceAuth) ([]ssh.AuthMethod, error) {
	if a.Kind == "key" {
		path, err := expandUser(a.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("expand key path: %w", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", path, err)
		}

		var signer ssh.Signer
		if a.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(a.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(data)
		}

		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", path, err)
		}

		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}

	return []ssh.AuthMethod{ssh.Password(a.Password)}, nil
}

func expandUser(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
}

func (c *Client) Close() {
	c.sftp.Close()
	c.ssh.Close()
}

// newHostKeyCallback verifies known hosts and optionally performs strict TOFU:
// only an unknown host is enrolled; a changed key is always rejected.
func newHostKeyCallback(dev config.Device) (ssh.HostKeyCallback, error) {
	if dev.KnownHostsPath == "" {
		return nil, errors.New("SSH known-hosts path is required")
	}

	knownHostsPath, err := expandUser(dev.KnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("expand known-hosts path: %w", err)
	}

	if _, err := os.Stat(knownHostsPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) || !dev.AcceptNewHostKey {
			return nil, fmt.Errorf("open known hosts %s: %w", knownHostsPath, err)
		}
		if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
			return nil, fmt.Errorf("create known-hosts directory: %w", err)
		}
		f, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create known hosts %s: %w", knownHostsPath, err)
		}
		if err == nil {
			_ = f.Close()
		}
	}

	check, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("parse known hosts %s: %w", knownHostsPath, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		checkErr := check(hostname, remote, key)
		if checkErr == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !dev.AcceptNewHostKey || !errors.As(checkErr, &keyErr) || len(keyErr.Want) != 0 {
			return checkErr
		}

		knownHostsMu.Lock()
		defer knownHostsMu.Unlock()

		return withLockedFile(knownHostsPath, func(f *os.File) error {
			// Re-read after acquiring the process-wide file lock. Another process
			// may have enrolled this hostname while this connection was starting.
			freshCheck, err := knownhosts.New(knownHostsPath)
			if err != nil {
				return err
			}
			freshErr := freshCheck(hostname, remote, key)
			if freshErr == nil {
				return nil
			}
			var freshKeyErr *knownhosts.KeyError
			if !errors.As(freshErr, &freshKeyErr) || len(freshKeyErr.Want) != 0 {
				return freshErr
			}

			size, err := f.Seek(0, io.SeekEnd)
			if err != nil {
				return fmt.Errorf("seek known hosts: %w", err)
			}
			if size > 0 {
				var last [1]byte
				if _, err := f.ReadAt(last[:], size-1); err != nil {
					return fmt.Errorf("read known hosts terminator: %w", err)
				}
				if last[0] != '\n' {
					if _, err := io.WriteString(f, "\n"); err != nil {
						return fmt.Errorf("terminate known-hosts line: %w", err)
					}
				}
			}

			line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
			if _, err := io.WriteString(f, line); err != nil {
				return fmt.Errorf("write known host: %w", err)
			}
			if err := f.Sync(); err != nil {
				return fmt.Errorf("sync known hosts: %w", err)
			}
			return nil
		})
	}, nil
}

func withLockedFile(path string, fn func(*os.File) error) (retErr error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open known hosts for update: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, f.Close())
	}()

	unlock, err := lockFile(f)
	if err != nil {
		return fmt.Errorf("lock known hosts: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, unlock())
	}()

	return fn(f)
}

// shellQuote wraps s in single quotes for safe interpolation into a POSIX
// shell command. Embedded single quotes are escaped by closing the quote,
// inserting an escaped single quote, and reopening.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (c *Client) Run(cmd string) (string, string, int, error) {
	sess, err := c.ssh.NewSession()
	if err != nil {
		return "", "", -1, fmt.Errorf("new session: %w", err)
	}

	defer sess.Close()

	var so, se bytes.Buffer

	sess.Stdout = &so
	sess.Stderr = &se

	err = sess.Run(cmd)

	exit := 0

	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitStatus()
		} else {
			return so.String(), se.String(), -1, err
		}
	}

	return so.String(), se.String(), exit, nil
}

func (c *Client) RunSudo(cmd string) (string, string, int, error) {
	return c.RunSudoStream(cmd, nil, nil)
}

func (c *Client) RunSudoStream(cmd string, stdoutW, stderrW io.Writer) (string, string, int, error) {
	full := "sudo -S -p '' " + cmd

	sess, err := c.ssh.NewSession()
	if err != nil {
		return "", "", -1, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", "", -1, fmt.Errorf("stdin pipe: %w", err)
	}

	go func() {
		stdin.Write([]byte(c.cfg.Auth.Password + "\n"))
		stdin.Close()
	}()

	// When the caller streams stdout (e.g. binary helper output), don't
	// also accumulate it in soBuf - a 300 MB decrypted IPA would sit in
	// RAM. Stderr stays buffered for the sudo-password rejection check.
	var soBuf, seBuf bytes.Buffer

	if stdoutW != nil {
		sess.Stdout = stdoutW
	} else {
		sess.Stdout = &soBuf
	}

	if stderrW != nil {
		sess.Stderr = io.MultiWriter(stderrW, &seBuf)
	} else {
		sess.Stderr = &seBuf
	}

	err = sess.Run(full)

	exit := 0

	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitStatus()
		} else {
			return soBuf.String(), seBuf.String(), -1, err
		}
	}

	if s := seBuf.String(); strings.Contains(s, "incorrect password") ||
		strings.Contains(s, "try again") {
		return soBuf.String(), s, exit, ErrSudoPasswordRejected
	}

	return soBuf.String(), seBuf.String(), exit, nil
}

func (c *Client) Mkdir(path string) error {
	if err := c.sftp.MkdirAll(path); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}

	return nil
}

func (c *Client) Upload(src io.Reader, dst string, mode os.FileMode) error {
	if err := c.Mkdir(path.Dir(dst)); err != nil {
		return err
	}

	f, err := c.sftp.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}

	if _, err := f.ReadFromWithConcurrency(src, 0); err != nil {
		f.Close()
		c.Remove(dst)

		return fmt.Errorf("upload %s: %w", dst, err)
	}

	if err := f.Close(); err != nil {
		c.Remove(dst)
		return fmt.Errorf("close %s: %w", dst, err)
	}

	if mode != 0 {
		if err := c.sftp.Chmod(dst, mode); err != nil {
			c.Remove(dst)
			return fmt.Errorf("chmod %s: %w", dst, err)
		}
	}

	return nil
}

// Download streams the remote file at src into dst. Caller owns dst (open,
// close, atomic rename if needed). Wrap dst for progress.
func (c *Client) Download(src string, dst io.Writer) error {
	f, err := c.sftp.Open(src)
	if err != nil {
		return fmt.Errorf("open remote %s: %w", src, err)
	}

	defer f.Close()

	if _, err := f.WriteTo(dst); err != nil {
		return fmt.Errorf("download %s: %w", src, err)
	}

	return nil
}

func (c *Client) Stat(p string) (os.FileInfo, error) {
	return c.sftp.Stat(p)
}

func (c *Client) Exists(path string) bool {
	_, err := c.sftp.Stat(path)
	return err == nil
}

func (c *Client) Remove(path string) error {
	return c.sftp.Remove(path)
}
