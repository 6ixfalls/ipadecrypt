package device

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"howett.net/plist"
)

var operationToken = regexp.MustCompile(`^[a-f0-9]{64}$`)

func OperationRoot(token string) string { return "/private/var/mobile/Media/ipadecrypt-op-" + token }
func validOperationRoot(dir string) bool {
	return strings.HasPrefix(dir, "/private/var/mobile/Media/ipadecrypt-op-") && operationToken.MatchString(strings.TrimPrefix(dir, "/private/var/mobile/Media/ipadecrypt-op-"))
}
func (c *Client) HostFingerprint() string { return c.hostFingerprint }

func ValidBundlePath(p string) bool {
	const root = "/var/containers/Bundle/Application/"
	if !strings.HasPrefix(p, root) || path.Clean(p) != p {
		return false
	}

	parts := strings.Split(strings.TrimPrefix(p, root), "/")

	return len(parts) == 2 && parts[0] != "" && parts[0] != "." && parts[0] != ".." && strings.HasSuffix(parts[1], ".app") && parts[1] != ".app"
}

// PrepareOperation creates an exclusive private directory, never reusing a
// preexisting path. The caller durably records this exact path first.
func (c *Client) PrepareOperation(dir string) error {
	if !validOperationRoot(dir) {
		return errors.New("invalid operation root")
	}
	// /private avoids the platform's intentional /var symlink. Check every
	// component we will traverse, and refuse any user-created symlink.
	if err := c.checkOperationAncestors(dir); err != nil {
		return err
	}

	if err := c.sftp.Mkdir(dir); err != nil {
		return err
	}

	if err := c.sftp.Chmod(dir, 0700); err != nil {
		return err
	}

	c.operationDir = dir

	return nil
}
func (c *Client) checkOperationAncestors(dir string) error {
	for p := path.Dir(dir); p != "/"; p = path.Dir(p) {
		st, e := c.sftp.Lstat(p)
		if e != nil {
			return e
		}

		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe operation ancestor")
		}
	}

	return nil
}

func (c *Client) UploadOwned(src io.Reader, dst string, mode os.FileMode) error {
	if c.operationDir == "" || path.Dir(dst) != c.operationDir {
		return errors.New("upload outside operation")
	}

	f, err := c.sftp.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, src)

	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}

	return c.sftp.Chmod(dst, mode)
}
func (c *Client) EnsureOperationHelper() (string, error) {
	p := path.Join(c.operationDir, "helper")
	if err := c.UploadOwned(bytes.NewReader(helperArm64), p, 0700); err != nil {
		return "", err
	}

	return p, nil
}
func (c *Client) operationFlags() string {
	if c.operationDir == "" {
		return ""
	}

	return "--operation-dir " + shellQuote(c.operationDir) + " "
}

// QuiesceOperation only accepts a sealed, idle helper. An interrupted helper
// without a completion receipt may have left a target alive; require review.
func (c *Client) QuiesceOperation(dir string, requirements string) error {
	if !validOperationRoot(dir) {
		return errors.New("invalid operation root")
	}

	if err := c.checkOperationAncestors(dir); err != nil {
		return err
	}

	st, err := c.sftp.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return err
	}

	if !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("unsafe operation directory")
	}

	if requirements == "" {
		return nil
	}

	out, se, code, err := c.RunSudo(shellQuote(path.Join(dir, "helper")) + " cleanup " + shellQuote(dir) + " " + shellQuote(requirements))
	if err != nil {
		return err
	}

	if code != 0 {
		return fmt.Errorf("helper cleanup not confirmed (exit %d): %s%s", code, out, se)
	}

	return nil
}
func (c *Client) RemoveOperation(dir string, retainHelper bool) error {
	if !validOperationRoot(dir) {
		return errors.New("invalid operation root")
	}

	if err := c.checkOperationAncestors(dir); err != nil {
		return err
	}
	// Directory is private and quiesced. rm never follows descendant symlinks.
	if retainHelper {
		// Keep receipts and the helper for a later app-cleanup retry. The
		// upload and dump tree are independent and can still be removed.
		_, _, code, err := c.RunSudo("sh -c " + shellQuote("test ! -L "+shellQuote(dir)+" && rm -rf -- "+shellQuote(path.Join(dir, "dump"))+" "+shellQuote(path.Join(dir, "source.ipa"))))
		if err != nil {
			return err
		}

		if code != 0 {
			return errors.New("partial operation cleanup failed")
		}

		return nil
	}

	script := "test ! -L " + shellQuote(dir) + " && rm -rf -- " + shellQuote(dir) + " && test ! -e " + shellQuote(dir) + " && test ! -L " + shellQuote(dir)

	_, _, code, err := c.RunSudo("sh -c " + shellQuote(script))
	if err != nil {
		return err
	}

	if code != 0 {
		return errors.New("operation removal not verified")
	}

	return nil
}
func (c *Client) InstalledExecutable(bundlePath string) (string, error) {
	if !ValidBundlePath(bundlePath) {
		return "", errors.New("unsafe bundle path")
	}

	out, _, code, err := c.RunSudo("cat " + shellQuote(path.Join(bundlePath, "Info.plist")))
	if err != nil {
		return "", err
	}

	if code != 0 {
		return "", errors.New("read installed metadata failed")
	}

	var info map[string]any
	if _, err = plist.Unmarshal([]byte(out), &info); err != nil {
		return "", err
	}

	name, _ := info["CFBundleExecutable"].(string)
	if name == "" || path.Base(name) != name || name == "." || name == ".." {
		return "", errors.New("unsafe installed executable")
	}

	return name, nil
}

func (c *Client) InstallOperation(bundleID, ipa string) error {
	_, _, code, err := c.RunSudo(shellQuote(path.Join(c.operationDir, "helper")) + " install " + shellQuote(c.operationDir) + " " + shellQuote(bundleID) + " " + shellQuote(ipa))
	if err != nil {
		return err
	}

	if code != 0 {
		return fmt.Errorf("operation install exit %d", code)
	}

	return nil
}
func (c *Client) UninstallOperation(dir, bundleID string) error {
	if !validOperationRoot(dir) {
		return errors.New("invalid operation root")
	}

	_, _, code, err := c.RunSudo(shellQuote(path.Join(dir, "helper")) + " uninstall " + shellQuote(dir) + " " + shellQuote(bundleID))
	if err != nil {
		return err
	}

	if code != 0 {
		return fmt.Errorf("operation uninstall exit %d", code)
	}

	return nil
}
