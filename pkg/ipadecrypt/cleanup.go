package ipadecrypt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"github.com/londek/ipadecrypt/internal/device"
)

// ErrCleanupUnconfirmed means ownership or a cleanup postcondition could not be
// established. Keep the device lease/quarantine and retain the journal.
var ErrCleanupUnconfirmed = errors.New("device cleanup unconfirmed")

type CleanupRequest struct {
	OperationID string
	JournalDir  string
	Device      DeviceConfig
}
type CleanupReport struct {
	Confirmed bool
	// Uninstalled indicates the recorded uninstall postcondition was satisfied.
	Uninstalled bool
}

var operationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var tokenPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type operationRecord struct {
	PreviousExecName                          string
	Policy                                    UninstallPolicy
	Version                                   int
	ID, Token, Host, User                     string
	Port                                      int
	Fingerprint                               string
	RootIntent                                bool
	PreviousInfoHash, ExpectedInfoHash        string
	BundleID, ExecName, ExpectedHash          string
	PreviousPath, PreviousHash, InstalledPath string
	InstallIntent                             bool
	UninstallIntent                           bool
	RemoveApp                                 bool
	HelperIntent                              bool
	Clean                                     bool
}
type operationJournal struct {
	removeInstalled bool
	record          operationRecord
	root            *os.Root
	lock            *os.File
	unlock          func() error
}

func validateOperation(id, dir string) error {
	if !operationIDPattern.MatchString(id) || !filepath.IsAbs(dir) {
		return errors.New("valid operation ID and absolute journal directory required")
	}

	return nil
}

func openJournal(id, dir string, create bool) (*operationJournal, error) {
	if err := validateOperation(id, dir); err != nil {
		return nil, err
	}

	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}

	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}

	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("journal directory must be private and not a symlink")
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}

	j := &operationJournal{root: root}
	fail := func(e error) (*operationJournal, error) { j.close(); return nil, e }
	// Reject symlink lock files, including links within the root.
	if st, e := root.Lstat(id + ".lock"); e == nil && !st.Mode().IsRegular() {
		return fail(errors.New("unsafe journal lock"))
	} else if e != nil && !os.IsNotExist(e) {
		return fail(e)
	}

	j.lock, err = root.OpenFile(id+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fail(err)
	}

	j.unlock, err = device.TryOperationLock(j.lock)
	if err != nil {
		return fail(fmt.Errorf("operation busy: %w", err))
	}

	name := id + ".json"
	if create {
		// Exclusive reservation survives crashes; never reuse an ID, even if the
		// initial durable record was interrupted.
		f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return fail(e)
		}

		if e = f.Close(); e != nil {
			return fail(e)
		}

		var token [32]byte
		if _, e = rand.Read(token[:]); e != nil {
			return fail(e)
		}

		j.record = operationRecord{Version: 1, ID: id, Token: hex.EncodeToString(token[:])}
	} else {
		st, e := root.Lstat(name)
		if e != nil {
			return fail(e)
		}

		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return fail(errors.New("unsafe journal file"))
		}

		f, e := root.Open(name)
		if e != nil {
			return fail(e)
		}

		dec := json.NewDecoder(io.LimitReader(f, 1<<20))
		dec.DisallowUnknownFields()

		e = dec.Decode(&j.record)
		if e == nil {
			var extra any
			if dec.Decode(&extra) != io.EOF {
				e = errors.New("trailing journal data")
			}
		}

		e = errors.Join(e, f.Close())
		if e != nil {
			return fail(e)
		}

		if e = j.validate(id); e != nil {
			return fail(e)
		}
	}

	return j, nil
}
func (j *operationJournal) validate(id string) error {
	r := j.record
	if r.Version != 1 || r.ID != id || !tokenPattern.MatchString(r.Token) || r.Host == "" || r.User == "" || r.Port < 1 || r.Port > 65535 {
		return errors.New("invalid operation journal")
	}

	switch r.Policy {
	case "", UninstallAuto, UninstallAlways, UninstallNever:
	default:
		return errors.New("invalid recorded uninstall policy")
	}

	if !r.RootIntent && (r.InstallIntent || r.HelperIntent || r.UninstallIntent || r.BundleID != "") {
		return errors.New("mutation without root intent")
	}

	if r.PreviousPath != "" && (!tokenPattern.MatchString(r.PreviousHash) || !tokenPattern.MatchString(r.PreviousInfoHash)) {
		return errors.New("invalid preexisting app identity")
	}

	if r.InstallIntent && !tokenPattern.MatchString(r.ExpectedInfoHash) {
		return errors.New("invalid expected app metadata identity")
	}

	if r.RootIntent && r.Fingerprint == "" {
		return errors.New("missing device binding")
	}

	if r.InstallIntent && (r.BundleID == "" || !tokenPattern.MatchString(r.ExpectedHash)) {
		return errors.New("invalid install intent")
	}

	for _, name := range []string{r.ExecName, r.PreviousExecName} {
		if name != "" && (path.Base(name) != name || name == "." || name == "..") {
			return errors.New("unsafe executable name")
		}
	}

	for _, p := range []string{r.PreviousPath, r.InstalledPath} {
		if p != "" && !device.ValidBundlePath(p) {
			return errors.New("unsafe bundle path")
		}
	}

	return nil
}

// Older records used ExecName for both builds.
func (r operationRecord) previousExecutable() string {
	if r.PreviousExecName != "" {
		return r.PreviousExecName
	}
	return r.ExecName
}

func (j *operationJournal) close() {
	if j.unlock != nil {
		_ = j.unlock()
	}

	if j.lock != nil {
		_ = j.lock.Close()
	}

	if j.root != nil {
		_ = j.root.Close()
	}

	j.unlock, j.lock, j.root = nil, nil, nil
}
func (j *operationJournal) save() (retErr error) {
	data, err := json.Marshal(j.record)
	if err != nil {
		return err
	}
	// A unique temp avoids stale partial writes after a crash. os.Root confines
	// all opens/renames to the caller's private journal directory.
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}

	temp := j.record.ID + "." + hex.EncodeToString(nonce[:]) + ".tmp"

	f, err := j.root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		e := j.root.Remove(temp)
		if !os.IsNotExist(e) {
			retErr = errors.Join(retErr, e)
		}
	}()

	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}

	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}

	if err = j.root.Rename(temp, j.record.ID+".json"); err != nil {
		return err
	}

	d, err := j.root.Open(".")
	if err != nil {
		return err
	}

	return errors.Join(d.Sync(), d.Close())
}
func (j *operationJournal) remoteDir() string { return device.OperationRoot(j.record.Token) }

// Cleanup reconnects with fresh credentials/context. The caller must hold its
// exclusive physical-device lease until this call returns. Missing/legacy or
// ambiguous records never confirm cleanup. Clean markers are retained for replay.
func Cleanup(ctx context.Context, req CleanupRequest) (report CleanupReport, returnErr error) {
	defer func() {
		if err := ctx.Err(); err != nil {
			report.Confirmed = false
			returnErr = errors.Join(returnErr, err)
		}
	}()

	j, err := openJournal(req.OperationID, req.JournalDir, false)
	if err != nil {
		return CleanupReport{}, errors.Join(ErrCleanupUnconfirmed, err)
	}
	defer j.close()

	cfg := internalDevice(req.Device)

	r := &j.record
	if cfg.Host != r.Host || cfg.Port != r.Port || cfg.User != r.User {
		return CleanupReport{}, errors.Join(ErrCleanupUnconfirmed, errors.New("device binding mismatch"))
	}

	if err = ctx.Err(); err != nil {
		return CleanupReport{}, err
	}

	if r.Clean {
		return CleanupReport{Confirmed: true, Uninstalled: r.UninstallIntent}, nil
	}

	if !r.RootIntent {
		r.Clean = true
		err = j.save()

		return CleanupReport{Confirmed: err == nil}, err
	}

	dev, err := device.Connect(ctx, cfg)
	if err != nil {
		return CleanupReport{}, err
	}
	defer dev.Close()

	stop := context.AfterFunc(ctx, dev.Close)
	defer stop()

	if dev.HostFingerprint() != r.Fingerprint {
		return CleanupReport{}, errors.Join(ErrCleanupUnconfirmed, errors.New("device key changed"))
	}

	err = cleanupOperation(dev, j)

	err = errors.Join(err, ctx.Err())
	if err != nil {
		return CleanupReport{}, errors.Join(ErrCleanupUnconfirmed, err)
	}

	r.Clean = true

	if err = j.save(); err != nil {
		return CleanupReport{}, err
	}

	return CleanupReport{Confirmed: true, Uninstalled: r.UninstallIntent}, nil
}

type cleanupDevice interface {
	QuiesceOperation(string, string) error
	RemoveOperation(string, bool) error
	FindInstalledByBundleID(string) (string, string, error)
	HashFile(string) (string, error)
	UninstallOperation(string, string) error
}

func cleanupOperation(dev cleanupDevice, j *operationJournal) error {
	r := &j.record
	// Never remove executable/dumps or uninstall while helper ownership is
	// uncertain. The helper seals the operation against delayed launches.
	requirements := ""
	if r.InstallIntent {
		requirements += "i"
	}

	if r.HelperIntent {
		requirements += "h"
	}

	if r.UninstallIntent {
		requirements += "u"
	}

	if err := dev.QuiesceOperation(j.remoteDir(), requirements); err != nil {
		return err
	}

	var appErr error

	if r.BundleID != "" {
		current, _, err := dev.FindInstalledByBundleID(r.BundleID)

		appErr = err
		if err == nil {
			if r.InstallIntent {
				if current == "" && !r.RemoveApp && (r.PreviousPath != "" || r.InstalledPath != "") {
					appErr = errors.New("app preservation not verified")
				}

				if current != "" {
					infoHash, e := dev.HashFile(path.Join(current, "Info.plist"))
					appErr = e
					owned, unchanged := false, false
					if e == nil && infoHash == r.ExpectedInfoHash {
						hash, hashErr := dev.HashFile(path.Join(current, r.ExecName))
						appErr = hashErr
						owned = hashErr == nil && hash == r.ExpectedHash && (r.PreviousPath == "" || hash != r.PreviousHash || infoHash != r.PreviousInfoHash || (r.InstalledPath != "" && current == r.InstalledPath))
					}
					if !owned && e == nil && current == r.PreviousPath && infoHash == r.PreviousInfoHash && (r.ExpectedHash != r.PreviousHash || r.ExpectedInfoHash != r.PreviousInfoHash) && r.InstalledPath == "" {
						hash, hashErr := dev.HashFile(path.Join(current, r.previousExecutable()))
						appErr = errors.Join(appErr, hashErr)
						unchanged = hashErr == nil && hash == r.PreviousHash
					}
					if !owned && !unchanged {
						appErr = errors.Join(appErr, errors.New("installed build ownership uncertain"))
					}

					if (owned || (unchanged && r.Policy == UninstallAlways)) && r.RemoveApp {
						r.UninstallIntent = true

						appErr = j.save()
						if appErr == nil {
							appErr = dev.UninstallOperation(j.remoteDir(), r.BundleID)
						}

						if appErr == nil {
							p, _, e := dev.FindInstalledByBundleID(r.BundleID)

							appErr = e
							if p != "" {
								appErr = errors.Join(appErr, errors.New("uninstall not verified"))
							}
						}
					}
				}
			} else if r.PreviousPath != "" {
				if current == "" && r.RemoveApp && r.UninstallIntent {
					// A prior uninstall may have succeeded before its response was lost.
				} else if current != r.PreviousPath {
					appErr = errors.New("preexisting app changed")
				} else {
					hash, e := dev.HashFile(path.Join(current, r.previousExecutable()))
					infoHash, infoErr := dev.HashFile(path.Join(current, "Info.plist"))
					e = errors.Join(e, infoErr)

					appErr = e
					if hash != r.PreviousHash || infoHash != r.PreviousInfoHash {
						appErr = errors.Join(appErr, errors.New("preexisting app changed"))
					}
				}

				if appErr == nil && r.RemoveApp && current != "" {
					r.UninstallIntent = true

					appErr = j.save()
					if appErr == nil {
						appErr = dev.UninstallOperation(j.remoteDir(), r.BundleID)
					}

					if appErr == nil {
						p, _, e := dev.FindInstalledByBundleID(r.BundleID)

						appErr = e
						if p != "" {
							appErr = errors.Join(appErr, errors.New("uninstall not verified"))
						}
					}
				}
			}
		}
	}
	// App cleanup and staging cleanup are independent. Retain the journal when
	// either fails so a later fresh connection can retry.
	return errors.Join(appErr, dev.RemoveOperation(j.remoteDir(), appErr != nil))
}
