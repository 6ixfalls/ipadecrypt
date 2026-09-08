package ipadecrypt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testJournal(t *testing.T) *operationJournal {
	t.Helper()

	j, e := openJournal("job-1", privateJournalDir(t), true)
	if e != nil {
		t.Fatal(e)
	}

	j.record.Host = "phone"
	j.record.User = "mobile"
	j.record.Port = 22
	j.record.Fingerprint = "SHA256:test"
	j.record.PreviousInfoHash = strings.Repeat("d", 64)
	j.record.ExpectedInfoHash = strings.Repeat("d", 64)

	j.record.RootIntent = true
	if e = j.save(); e != nil {
		t.Fatal(e)
	}

	t.Cleanup(j.close)

	return j
}
func TestJournalReservationAndReplay(t *testing.T) {
	dir := privateJournalDir(t)

	j, e := openJournal("job", dir, true)
	if e != nil {
		t.Fatal(e)
	}

	j.record.Host = "phone"
	j.record.Port = 22

	j.record.User = "mobile"
	if e = j.save(); e != nil {
		t.Fatal(e)
	}

	if _, e = openJournal("job", dir, false); e == nil {
		t.Fatal("concurrent operation acquired lease")
	}

	j.close()

	if _, e = openJournal("job", dir, true); e == nil {
		t.Fatal("ID reused")
	}

	r, e := Cleanup(context.Background(), CleanupRequest{OperationID: "job", JournalDir: dir, Device: DeviceConfig{Host: "phone"}})
	if e != nil || !r.Confirmed {
		t.Fatal(r, e)
	}
	// A durable no-mutation clean marker requires no live connection.
	r, e = Cleanup(context.Background(), CleanupRequest{OperationID: "job", JournalDir: dir, Device: DeviceConfig{Host: "phone"}})
	if e != nil || !r.Confirmed {
		t.Fatal(r, e)
	}

	r, e = Cleanup(context.Background(), CleanupRequest{OperationID: "job", JournalDir: dir, Device: DeviceConfig{Host: "other"}})
	if e == nil || r.Confirmed {
		t.Fatal("device mismatch accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r, e = Cleanup(ctx, CleanupRequest{OperationID: "job", JournalDir: dir, Device: DeviceConfig{Host: "phone"}})
	if !errors.Is(e, context.Canceled) || r.Confirmed {
		t.Fatal("cancelled cleanup confirmed")
	}
}
func TestJournalRejectsUnsafeAndCorruptRecords(t *testing.T) {
	for _, id := range []string{"", "../job", "a/b", "a\\b", "a b", strings.Repeat("a", 129)} {
		if _, e := openJournal(id, privateJournalDir(t), true); e == nil {
			t.Fatalf("accepted ID %q", id)
		}
	}

	for _, data := range []string{"", `{`, `{"Version":99}`, `{"Version":1,"Unknown":true}`, `{} {}`} {
		dir := privateJournalDir(t)
		if e := os.WriteFile(filepath.Join(dir, "job.json"), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}

		r, e := Cleanup(context.Background(), CleanupRequest{OperationID: "job", JournalDir: dir})
		if e == nil || r.Confirmed {
			t.Fatalf("accepted corrupt journal %q", data)
		}
	}

	dir := privateJournalDir(t)
	if e := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(dir, "job.json")); e != nil {
		t.Fatal(e)
	}

	if _, e := openJournal("job", dir, false); e == nil {
		t.Fatal("accepted symlink")
	}

	r, e := Cleanup(context.Background(), CleanupRequest{OperationID: "missing", JournalDir: dir})
	if e == nil || r.Confirmed {
		t.Fatal("missing journal confirmed")
	}
}

type fakeCleanupDevice struct {
	hashes                                         map[string]string
	infoHash                                       string
	path, hash                                     string
	quiesceErr, removeErr, lookupErr, uninstallErr error
	removed, uninstalled                           bool
	requirements                                   string
	afterUninstall                                 string
}

func (f *fakeCleanupDevice) QuiesceOperation(_ string, requirements string) error {
	f.requirements = requirements
	return f.quiesceErr
}
func (f *fakeCleanupDevice) RemoveOperation(string, bool) error { f.removed = true; return f.removeErr }
func (f *fakeCleanupDevice) FindInstalledByBundleID(string) (string, string, error) {
	return f.path, "com.test", f.lookupErr
}
func (f *fakeCleanupDevice) HashFile(p string) (string, error) {
	if f.hashes != nil {
		hash, ok := f.hashes[p]
		if !ok {
			return "", os.ErrNotExist
		}
		return hash, nil
	}
	if filepath.Base(p) == "Info.plist" {
		if f.infoHash != "" {
			return f.infoHash, nil
		}

		return strings.Repeat("d", 64), nil
	}

	return f.hash, nil
}
func (f *fakeCleanupDevice) UninstallOperation(string, string) error {
	f.uninstalled = true
	if f.uninstallErr == nil {
		f.path = f.afterUninstall
	}

	return f.uninstallErr
}

const testBundle = "/var/containers/Bundle/Application/UUID/Test.app"

func TestCleanupLostInstallResponse(t *testing.T) {
	j := testJournal(t)
	j.record.BundleID = "com.test"
	j.record.ExecName = "Test"
	j.record.ExpectedHash = strings.Repeat("a", 64)
	j.record.InstallIntent = true
	j.record.RemoveApp = true
	j.record.HelperIntent = true

	f := &fakeCleanupDevice{path: testBundle, hash: j.record.ExpectedHash}
	if e := cleanupOperation(f, j); e != nil {
		t.Fatal(e)
	}

	if !f.uninstalled || !f.removed || f.requirements != "ih" {
		t.Fatal(f)
	}

	if e := cleanupOperation(f, j); e != nil {
		t.Fatal("not idempotent", e)
	}
}
func TestCleanupPreservesPreexistingAndRejectsAmbiguity(t *testing.T) {
	for _, mode := range []string{"unchanged", "foreign", "metadata-changed", "ambiguous-replacement", "never"} {
		t.Run(mode, func(t *testing.T) {
			j := testJournal(t)
			j.record.BundleID = "com.test"
			j.record.ExecName = "Test"
			j.record.PreviousPath = testBundle
			j.record.PreviousHash = strings.Repeat("a", 64)
			f := &fakeCleanupDevice{path: testBundle, hash: j.record.PreviousHash}

			switch mode {
			case "metadata-changed":
				f.infoHash = strings.Repeat("e", 64)
			case "foreign":
				f.hash = strings.Repeat("b", 64)
			case "ambiguous-replacement":
				j.record.InstallIntent = true
				j.record.ExpectedHash = j.record.PreviousHash
				j.record.RemoveApp = true
			case "never":
				j.record.InstallIntent = true
				j.record.ExpectedHash = strings.Repeat("c", 64)
				f.hash = j.record.ExpectedHash
			}

			e := cleanupOperation(f, j)
			if (mode == "foreign" || mode == "metadata-changed" || mode == "ambiguous-replacement") != (e != nil) {
				t.Fatal(e)
			}

			if f.uninstalled || !f.removed {
				t.Fatal(f)
			}
		})
	}
}
func TestCleanupIndependentFailuresAndQuiescence(t *testing.T) {
	for _, mode := range []string{"busy", "lookup", "uninstall", "remove", "still-installed"} {
		t.Run(mode, func(t *testing.T) {
			j := testJournal(t)
			j.record.BundleID = "com.test"
			j.record.ExecName = "Test"
			j.record.ExpectedHash = strings.Repeat("a", 64)
			j.record.InstallIntent = true
			j.record.RemoveApp = true
			f := &fakeCleanupDevice{path: testBundle, hash: j.record.ExpectedHash}
			sentinel := errors.New("injected")

			switch mode {
			case "busy":
				f.quiesceErr = sentinel
			case "lookup":
				f.lookupErr = sentinel
			case "uninstall":
				f.uninstallErr = sentinel
			case "remove":
				f.removeErr = sentinel
			case "still-installed":
				f.afterUninstall = testBundle
			}

			if e := cleanupOperation(f, j); e == nil {
				t.Fatal("failure ignored")
			}

			if mode == "busy" {
				if f.removed || f.uninstalled {
					t.Fatal("mutated active operation")
				}
			} else if !f.removed {
				t.Fatal("independent resources not attempted")
			}
		})
	}
}
func TestCleanupUninstallIntentSurvivesLostResponse(t *testing.T) {
	j := testJournal(t)
	j.record.BundleID = "com.test"
	j.record.ExecName = "Test"
	j.record.PreviousPath = testBundle
	j.record.PreviousHash = strings.Repeat("a", 64)
	j.record.RemoveApp = true

	f := &fakeCleanupDevice{path: testBundle, hash: j.record.PreviousHash, uninstallErr: errors.New("lost connection")}
	if e := cleanupOperation(f, j); e == nil {
		t.Fatal("lost response ignored")
	}

	if !j.record.UninstallIntent {
		t.Fatal("missing uninstall intent")
	}

	f.path = ""

	f.uninstallErr = nil
	if e := cleanupOperation(f, j); e != nil {
		t.Fatal("could not recover uninstall", e)
	}
}
func TestCleanupDoesNotMutateWhenIntentCannotPersist(t *testing.T) {
	j := testJournal(t)
	j.record.BundleID = "com.test"
	j.record.ExecName = "Test"
	j.record.ExpectedHash = strings.Repeat("a", 64)
	j.record.InstallIntent = true
	j.record.RemoveApp = true
	// Keep the object, but make all subsequent durable writes fail.
	if e := j.root.Close(); e != nil {
		t.Fatal(e)
	}

	f := &fakeCleanupDevice{path: testBundle, hash: j.record.ExpectedHash}
	if e := cleanupOperation(f, j); e == nil {
		t.Fatal("journal failure ignored")
	}

	if f.uninstalled {
		t.Fatal("uninstalled before durable intent")
	}

	if !f.removed {
		t.Fatal("independent cleanup skipped")
	}
}

func privateJournalDir(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "journal")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}

	return dir
}

func TestCleanupRenamedExecutable(t *testing.T) {
	for _, mode := range []string{"before-install", "failed-install", "installed", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			j := testJournal(t)
			r := &j.record
			r.BundleID = "com.test"
			r.ExecName, r.PreviousExecName = "NewExec", "OldExec"
			r.PreviousPath = testBundle
			r.PreviousHash, r.ExpectedHash = strings.Repeat("a", 64), strings.Repeat("b", 64)
			r.ExpectedInfoHash = strings.Repeat("e", 64)
			r.InstallIntent = mode != "before-install"
			r.RemoveApp = r.InstallIntent
			if err := j.save(); err != nil {
				t.Fatal(err)
			}
			dir := j.root.Name()
			j.close()
			var err error
			j, err = openJournal("job-1", dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			r = &j.record
			if r.PreviousExecName != "OldExec" {
				t.Fatal("previous executable not persisted")
			}
			f := &fakeCleanupDevice{path: testBundle, hashes: map[string]string{
				filepath.Join(testBundle, "OldExec"):    r.PreviousHash,
				filepath.Join(testBundle, "Info.plist"): r.PreviousInfoHash,
			}}
			if mode == "installed" {
				delete(f.hashes, filepath.Join(testBundle, "OldExec"))
				f.hashes[filepath.Join(testBundle, "NewExec")] = r.ExpectedHash
				f.hashes[filepath.Join(testBundle, "Info.plist")] = r.ExpectedInfoHash
			}
			if mode == "foreign" {
				f.hashes[filepath.Join(testBundle, "OldExec")] = strings.Repeat("f", 64)
			}
			err = cleanupOperation(f, j)
			if (err != nil) != (mode == "foreign") {
				t.Fatalf("cleanup: %v", err)
			}
			if f.uninstalled != (mode == "installed") {
				t.Fatalf("uninstalled = %v", f.uninstalled)
			}
		})
	}
}

func TestJournalPreviousExecutableValidation(t *testing.T) {
	j := testJournal(t)
	for _, name := range []string{"../OldExec", "dir/OldExec", ".", ".."} {
		j.record.PreviousExecName = name
		if err := j.validate(j.record.ID); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	j.record.PreviousExecName = ""
	j.record.ExecName = "LegacyExec"
	if got := j.record.previousExecutable(); got != "LegacyExec" {
		t.Fatal(got)
	}
}
