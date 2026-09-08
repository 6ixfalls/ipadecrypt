package ipadecrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/pipeline"
)

var (
	ErrAppinstNotFound    = errors.New("appinst not found on device")
	ErrVerificationFailed = errors.New("decrypted IPA verification failed")
)

// Decrypt runs the complete resolve, download, install, decrypt, assemble,
// verify, and cleanup workflow. One physical device must not be used by more
// than one concurrent call; enforcing that lease belongs to the caller.
func Decrypt(ctx context.Context, req Request) (out *Result, returnErr error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}

	var journal *operationJournal

	if req.OperationID != "" {
		var err error

		journal, err = openJournal(req.OperationID, req.JournalDir, true)
		if err != nil {
			return nil, err
		}
		defer journal.close()

		journal.record.Policy = req.Uninstall
		cfg := internalDevice(req.Device)

		journal.record.Host, journal.record.Port, journal.record.User = cfg.Host, cfg.Port, cfg.User
		if err := journal.save(); err != nil {
			return nil, err
		}

		req.operation = journal
	}

	target, err := ParseTarget(req.Target)
	if err != nil {
		return nil, err
	}

	emit := func(event Event) {
		if req.OnEvent != nil {
			req.OnEvent(event)
		}
	}

	stateDir := req.StateDir
	if stateDir == "" {
		stateDir, err = os.MkdirTemp("", "ipadecrypt-state-*")
		if err != nil {
			return nil, fmt.Errorf("create temporary state directory: %w", err)
		}
		defer os.RemoveAll(stateDir)
	} else if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	cleanups := &cleanupStack{}
	defer func() {
		if cleanupErr := cleanups.run(); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}

		if journal != nil {
			// Release the journal lease after decryption/SSH shutdown, then use
			// the public recovery path with an independent cancellation scope.
			journal.close()
			emit(Event{Phase: PhaseCleaning, Action: "cleanup", Message: "verifying operation cleanup"})

			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			report, cleanupErr := Cleanup(cleanupCtx, CleanupRequest{OperationID: req.OperationID, JournalDir: req.JournalDir, Device: req.Device})

			cancel()

			if out != nil && report.Confirmed {
				out.Uninstalled = report.Uninstalled
			}

			if !report.Confirmed {
				cleanupErr = errors.Join(cleanupErr, ErrCleanupUnconfirmed)
			}

			returnErr = errors.Join(returnErr, cleanupErr)
		}

		if returnErr == nil {
			emit(Event{Phase: PhaseComplete, Action: "complete", Message: "decryption complete"})
		}
	}()

	devCfg := internalDevice(req.Device)
	emit(Event{Phase: PhaseConnecting, Action: "connect", Message: fmt.Sprintf("connecting to %s@%s", devCfg.User, devCfg.Host)})

	dev, err := device.Connect(ctx, devCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH connect: %w", err)
	}

	cleanups.push(func() error { dev.Close(); return nil })

	stopCancellationWatch := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			dev.Close()
		case <-stopCancellationWatch:
		}
	}()

	cleanups.push(func() error { close(stopCancellationWatch); return nil })

	emit(Event{Phase: PhaseProbing, Action: "probe", Message: "probing device"})

	probe, err := dev.Probe()
	if err != nil {
		return nil, fmt.Errorf("probe device: %w", err)
	}

	deviceInfo := DeviceInfo{IOSVersion: probe.IOSVersion, Architecture: probe.Arch,
		Model: probe.Model, DeviceFamily: probe.DeviceFamily, Jailbreak: probe.Jailbreak}
	emit(Event{Phase: PhaseProbing, Action: "ready", Message: fmt.Sprintf("iOS %s %s %s (%s)", probe.IOSVersion, probe.Arch, probe.Model, probe.Jailbreak)})

	if journal != nil {
		journal.record.Fingerprint = dev.HostFingerprint()

		journal.record.RootIntent = true
		if err := journal.save(); err != nil {
			return nil, err
		}

		if err := dev.PrepareOperation(journal.remoteDir()); err != nil {
			return nil, err
		}
	}

	prepareHelper := dev.EnsureHelper
	if journal != nil {
		prepareHelper = dev.EnsureOperationHelper
	}

	result := &Result{Device: deviceInfo}

	var uninstallBundlePath string

	cleanups.push(func() error {
		if journal != nil || uninstallBundlePath == "" {
			return nil
		}

		emit(Event{Phase: PhaseCleaning, Action: "uninstall", Message: "uninstalling app"})

		if err := dev.Uninstall(uninstallBundlePath); err != nil {
			return fmt.Errorf("uninstall app: %w", err)
		}

		result.Uninstalled = true

		return nil
	})

	// Bundle-ID requests can use an existing installation without Apple
	// credentials or a source IPA.
	if target.Kind == TargetBundleID && req.Source != SourceAppStore {
		emit(Event{Phase: PhaseResolving, Action: "installed.lookup", Message: "checking installed apps"})

		installedPath, canonicalID, err := dev.FindInstalledByBundleID(target.Value)
		if err != nil {
			return nil, fmt.Errorf("scan installed apps: %w", err)
		}

		if installedPath != "" {
			version, versionErr := dev.InstalledVersion(installedPath)
			if versionErr != nil || version == "" {
				version = "unknown"
			}

			useInstalled := true
			if req.Source == SourceAuto && req.SelectInstalled != nil {
				useInstalled, err = req.SelectInstalled(ctx, InstalledApp{
					BundleID: canonicalID, Version: version, BundlePath: installedPath,
				})
				if err != nil {
					return nil, fmt.Errorf("select installed source: %w", err)
				}
			}

			if useInstalled {
				helperPath, err := prepareHelper()
				if err != nil {
					return nil, fmt.Errorf("prepare helper: %w", err)
				}

				if journal != nil {
					name, e := dev.InstalledExecutable(installedPath)
					if e != nil {
						return nil, e
					}

					hash, e := dev.HashFile(path.Join(installedPath, name))
					if e != nil {
						return nil, e
					}

					journal.record.BundleID, journal.record.ExecName = canonicalID, name
					journal.record.PreviousPath, journal.record.PreviousHash = installedPath, hash
					journal.record.PreviousExecName = name

					journal.record.PreviousInfoHash, e = dev.HashFile(path.Join(installedPath, "Info.plist"))
					if e != nil {
						return nil, e
					}

					journal.record.RemoveApp = shouldUninstall(req.Uninstall, false)
					if e = journal.save(); e != nil {
						return nil, e
					}
				}

				result.BundleID, result.Version = canonicalID, version

				if shouldUninstall(req.Uninstall, false) {
					uninstallBundlePath = installedPath
				}

				if err := decryptBundle(req, emit, dev, helperPath, canonicalID, installedPath, version, "", result); err != nil {
					return nil, err
				}

				return result, nil
			}
		}

		if req.Source == SourceInstalled {
			return nil, fmt.Errorf("installed app %s not found", target.Value)
		}
	} else if req.Source == SourceInstalled {
		return nil, errors.New("installed source requires a bundle-ID target")
	}

	var bundleID, version, encryptedPath string

	fromAppStore := target.Kind != TargetLocalIPA
	if target.Kind == TargetLocalIPA {
		bundleID, version, err = pipeline.AppInfo(target.Value)
		if err != nil {
			return nil, fmt.Errorf("read IPA: %w", err)
		}

		encryptedPath = target.Value
		emit(Event{Phase: PhaseResolving, Action: "local", Message: fmt.Sprintf("using local IPA %s", filepath.Base(target.Value))})
	} else {
		bundleID, version, encryptedPath, err = acquireFromAppStore(ctx, req, stateDir, target, emit)
		if err != nil {
			return nil, err
		}
	}

	result.BundleID, result.Version, result.SourceIPAPath = bundleID, version, encryptedPath

	emit(Event{Phase: PhasePatching, Action: "patch", Message: "preparing IPA for the target device"})

	patch, err := patchSource(encryptedPath, probe.IOSVersion, probe.DeviceFamily, req.PatchDeviceType, stateDir)
	if err != nil {
		return nil, fmt.Errorf("patch IPA for install: %w", err)
	}

	if patch.temporaryPath != "" {
		cleanups.push(func() error { return ignoreNotExist(os.Remove(patch.temporaryPath)) })
	}

	emit(Event{Phase: PhasePatching, Action: "patched", Message: patch.message()})

	plan, err := buildInstallPlan(dev, patch.uploadPath, bundleID, prepareHelper, journal != nil)
	if err != nil {
		return nil, err
	}

	if journal != nil {
		plan.journal = journal
		journal.removeInstalled = shouldUninstall(req.Uninstall, true)
		plan.stagingRemote = path.Join(journal.remoteDir(), "source.ipa")

		name, hash, e := pipeline.MainExecSHA256(patch.uploadPath)
		if e != nil {
			return nil, e
		}

		if path.Base(name) != name || name == "." || name == ".." {
			return nil, errors.New("unsafe executable name")
		}

		journal.record.BundleID, journal.record.ExecName, journal.record.ExpectedHash = bundleID, name, hash

		journal.record.ExpectedInfoHash, e = pipeline.InfoSHA256(patch.uploadPath)
		if e != nil {
			return nil, e
		}

		journal.record.PreviousPath = plan.bundlePath
		if plan.bundlePath != "" {
			journal.record.PreviousInfoHash, e = dev.HashFile(path.Join(plan.bundlePath, "Info.plist"))
			if e != nil {
				return nil, e
			}

			journal.record.PreviousExecName, e = dev.InstalledExecutable(plan.bundlePath)
			if e != nil {
				return nil, e
			}

			journal.record.PreviousHash, e = dev.HashFile(path.Join(plan.bundlePath, journal.record.PreviousExecName))
			if e != nil {
				return nil, e
			}
		}

		journal.record.RemoveApp = shouldUninstall(req.Uninstall, false)
		if e = journal.save(); e != nil {
			return nil, e
		}
	} else if !req.KeepRemoteFiles {
		cleanups.push(func() error { return ignoreNotExist(dev.Remove(plan.stagingRemote)) })
	}

	install, err := ensureInstalled(dev, plan, patch.uploadPath, fromAppStore, func(action, message string) {
		emit(Event{Phase: PhaseInstalling, Action: action, Message: message})
	}, func(current, total int64) {
		emit(Event{Phase: PhaseInstalling, Action: "upload.progress", Message: "uploading IPA", Current: current, Total: total})
	})
	if err != nil {
		return nil, fmt.Errorf("install app: %w", err)
	}

	if journal != nil {
		journal.record.InstalledPath = install.bundlePath

		journal.record.RemoveApp = shouldUninstall(req.Uninstall, install.installed || install.reinstalled)
		if err := journal.save(); err != nil {
			return nil, err
		}
	}

	result.Installed, result.Reinstalled = install.installed, install.reinstalled
	if shouldUninstall(req.Uninstall, install.installed || install.reinstalled) {
		uninstallBundlePath = install.bundlePath
	}

	if err := decryptBundle(req, emit, dev, plan.helperPath, bundleID, install.bundlePath, version, encryptedPath, result); err != nil {
		return nil, err
	}

	return result, nil
}

func validateRequest(req Request) error {
	if req.OperationID != "" || req.JournalDir != "" {
		if err := validateOperation(req.OperationID, req.JournalDir); err != nil {
			return err
		}

		if req.KeepRemoteFiles {
			return errors.New("durable operations cannot keep remote files")
		}

		if req.StateDir != "" {
			state, err := filepath.Abs(req.StateDir)
			if err != nil {
				return err
			}

			rel, err := filepath.Rel(state, req.JournalDir)
			if err != nil {
				return err
			}

			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return errors.New("journal must be outside StateDir")
			}
		}
	}

	if req.Device.Host == "" {
		return errors.New("device host is required")
	}

	if req.Device.KnownHostsPath == "" {
		return errors.New("device known-hosts path is required")
	}

	switch req.Source {
	case "", SourceAuto, SourceAppStore, SourceInstalled:
	default:
		return fmt.Errorf("invalid source policy %q", req.Source)
	}

	switch req.Uninstall {
	case "", UninstallAuto, UninstallAlways, UninstallNever:
	default:
		return fmt.Errorf("invalid uninstall policy %q", req.Uninstall)
	}

	if req.ExtraVerify && req.SkipVerify {
		return errors.New("extra verification cannot be combined with SkipVerify")
	}

	return nil
}

func shouldUninstall(policy UninstallPolicy, installedByUs bool) bool {
	switch policy {
	case UninstallAlways:
		return true
	case UninstallNever:
		return false
	default:
		return installedByUs
	}
}

func acquireFromAppStore(ctx context.Context, req Request, stateDir string, target Target, emit func(Event)) (string, string, string, error) {
	if req.Apple == nil || req.Apple.Email == "" {
		return "", "", "", errors.New("apple account is required for App Store downloads")
	}

	as, err := appstore.New(filepath.Join(stateDir, "cookies"), req.Apple.MACAddress)
	if err != nil {
		return "", "", "", fmt.Errorf("create App Store client: %w", err)
	}

	account := internalAccount(req.Apple)
	if req.Storefront != "" {
		account.StoreFront, err = appstore.ResolveStorefront(req.Storefront)
		if err != nil {
			return "", "", "", fmt.Errorf("resolve storefront: %w", err)
		}
	}

	emit(Event{Phase: PhaseResolving, Action: "app-store.lookup", Message: "resolving app in the App Store"})

	var app appstore.App
	if target.Kind == TargetAppID {
		app, err = as.LookupByAppID(account, target.Value)
	} else {
		app, err = as.LookupByBundleID(account, target.Value)
	}

	if err != nil {
		return "", "", "", fmt.Errorf("app store lookup: %w", err)
	}

	cacheDir := filepath.Join(stateDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", "", "", fmt.Errorf("create IPA cache: %w", err)
	}

	if req.ExternalVersionID == "" {
		cached := filepath.Join(cacheDir, cacheFilename(app.BundleID, app.Version))
		if fileExists(cached) {
			emit(Event{Phase: PhaseDownloading, Action: "cache.hit", Message: "using cached encrypted IPA"})
			return app.BundleID, app.Version, cached, nil
		}
	}

	ticket, err := withAuth(ctx, req, as, app, account, 3, emit, func() (appstore.DownloadTicket, error) {
		return as.PrepareDownload(account, app, req.ExternalVersionID)
	})
	if err != nil {
		return "", "", "", fmt.Errorf("prepare App Store download: %w", err)
	}

	cached := filepath.Join(cacheDir, cacheFilename(app.BundleID, ticket.Version()))
	if fileExists(cached) {
		emit(Event{Phase: PhaseDownloading, Action: "cache.hit", Message: "using cached encrypted IPA"})
		return app.BundleID, ticket.Version(), cached, nil
	}

	emit(Event{Phase: PhaseDownloading, Action: "download", Message: "downloading IPA from the App Store"})

	_, err = as.CompleteDownload(account, ticket, cached, func(current, total int64) {
		emit(Event{Phase: PhaseDownloading, Action: "download.progress", Message: "downloading IPA", Current: current, Total: total})
	})
	if err != nil {
		return "", "", "", fmt.Errorf("download IPA: %w", err)
	}

	return app.BundleID, ticket.Version(), cached, nil
}

func withAuth[T any](ctx context.Context, req Request, as *appstore.Client, app appstore.App, account *appstore.Account, attempts int, emit func(Event), fn func() (T, error)) (T, error) {
	var zero T

	for range attempts {
		if err := ctx.Err(); err != nil {
			return zero, err
		}

		value, err := fn()
		if err == nil {
			return value, nil
		}

		switch {
		case errors.Is(err, appstore.ErrPasswordTokenExpired):
			emit(Event{Phase: PhaseDownloading, Action: "auth.refresh", Message: "refreshing App Store session"})

			if account.Password == "" {
				return zero, errors.New("app store token expired and no password was provided")
			}

			fresh, loginErr := loginWithAuthCode(ctx, as, account.Email, account.Password, req.OnAuthCode)
			if loginErr != nil {
				return zero, fmt.Errorf("refresh App Store session: %w", loginErr)
			}

			if updateErr := acceptFreshAccount(ctx, req, account, fresh); updateErr != nil {
				return zero, updateErr
			}
		case errors.Is(err, appstore.ErrLicenseRequired):
			emit(Event{Phase: PhaseDownloading, Action: "license.acquire", Message: "acquiring App Store license"})

			purchaseErr := as.Purchase(account, app)
			if errors.Is(purchaseErr, appstore.ErrPasswordTokenExpired) {
				fresh, loginErr := loginWithAuthCode(ctx, as, account.Email, account.Password, req.OnAuthCode)
				if loginErr != nil {
					return zero, fmt.Errorf("refresh App Store session: %w", loginErr)
				}

				if updateErr := acceptFreshAccount(ctx, req, account, fresh); updateErr != nil {
					return zero, updateErr
				}

				purchaseErr = as.Purchase(account, app)
			}

			if purchaseErr != nil && !errors.Is(purchaseErr, appstore.ErrLicenseAlreadyExists) {
				return zero, fmt.Errorf("acquire App Store license: %w", purchaseErr)
			}
		default:
			return zero, err
		}
	}

	return zero, errors.New("app store retries exhausted")
}

func loginWithAuthCode(ctx context.Context, client *appstore.Client, email, password string, provide AuthCodeProvider) (*appstore.Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	account, err := client.Login(email, password, "")
	if !errors.Is(err, appstore.ErrAuthCodeRequired) {
		return account, err
	}

	if provide == nil {
		return nil, errors.New("app store authentication code required but no OnAuthCode callback was provided")
	}

	code, err := provide(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain App Store authentication code: %w", err)
	}

	return client.Login(email, password, code)
}

// Login authenticates an Apple account for later use with Decrypt. StateDir
// holds the cookie jar; callers should protect it as secret material.
func Login(ctx context.Context, stateDir, email, password string, provide AuthCodeProvider) (*AppleAccount, error) {
	return LoginWithMACAddress(ctx, stateDir, email, password, "", provide)
}

// LoginWithMACAddress authenticates an Apple account using a fixed App Store
// machine identity. macAddress must be a six-byte MAC address when set.
func LoginWithMACAddress(ctx context.Context, stateDir, email, password, macAddress string, provide AuthCodeProvider) (*AppleAccount, error) {
	if email == "" || password == "" {
		return nil, errors.New("apple email and password are required")
	}
	if macAddress != "" {
		var err error
		macAddress, err = appstore.NormalizeMACAddress(macAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid App Store MAC address: %w", err)
		}
	}

	removeState := false

	var err error
	if stateDir == "" {
		stateDir, err = os.MkdirTemp("", "ipadecrypt-login-*")
		if err != nil {
			return nil, err
		}

		removeState = true
	} else if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}

	if removeState {
		defer os.RemoveAll(stateDir)
	}

	client, err := appstore.New(filepath.Join(stateDir, "cookies"), macAddress)
	if err != nil {
		return nil, err
	}

	account, err := loginWithAuthCode(ctx, client, email, password, provide)
	if err != nil {
		return nil, err
	}

	result := &AppleAccount{}
	setAccount(result, account)
	result.MACAddress = macAddress

	return result, nil
}

func acceptFreshAccount(ctx context.Context, req Request, account, fresh *appstore.Account) error {
	*account = *fresh
	setAccount(req.Apple, fresh)

	if req.OnAccountUpdate != nil {
		if err := req.OnAccountUpdate(ctx, *req.Apple); err != nil {
			return fmt.Errorf("persist refreshed App Store account: %w", err)
		}
	}

	if req.Storefront != "" {
		storefront, err := appstore.ResolveStorefront(req.Storefront)
		if err != nil {
			return fmt.Errorf("restore storefront override: %w", err)
		}

		account.StoreFront = storefront
	}

	return nil
}

func cacheFilename(bundleID, version string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	return fmt.Sprintf("%s_%s.ipa", replacer.Replace(bundleID), replacer.Replace(version))
}

type patchResult struct {
	uploadPath, temporaryPath, previousMinOS string
	watchRemoved                             int
	deviceFamilyExpanded                     bool
	previousDeviceFamily, newDeviceFamily    []int
}

func patchSource(source, iosVersion string, deviceFamily int, patchDeviceType bool, tempDir string) (patchResult, error) {
	file, err := os.CreateTemp(tempDir, "ipadecrypt-patched-*.ipa")
	if err != nil {
		return patchResult{}, err
	}

	temporaryPath := file.Name()
	if err := file.Close(); err != nil {
		return patchResult{}, err
	}

	if err := os.Remove(temporaryPath); err != nil {
		return patchResult{}, err
	}

	patched, err := pipeline.PatchForInstall(source, temporaryPath, iosVersion, deviceFamily, patchDeviceType)
	if err != nil {
		_ = os.Remove(temporaryPath)
		return patchResult{}, err
	}

	if !patched.MinOSChanged && patched.WatchRemoved == 0 && !patched.DeviceFamilyExpanded {
		return patchResult{uploadPath: source}, nil
	}

	return patchResult{uploadPath: temporaryPath, temporaryPath: temporaryPath,
		previousMinOS: patched.PreviousMinOS, watchRemoved: patched.WatchRemoved,
		deviceFamilyExpanded: patched.DeviceFamilyExpanded,
		previousDeviceFamily: patched.PreviousDeviceFamily, newDeviceFamily: patched.NewDeviceFamily}, nil
}

func (p patchResult) message() string {
	var changes []string
	if p.previousMinOS != "" {
		changes = append(changes, "minimum OS adjusted")
	}

	if p.deviceFamilyExpanded {
		changes = append(changes, "device family expanded")
	}

	if p.watchRemoved > 0 {
		changes = append(changes, fmt.Sprintf("%d Watch entries removed", p.watchRemoved))
	}

	if len(changes) == 0 {
		return "IPA requires no install-time patch"
	}

	return strings.Join(changes, ", ")
}

type installPlan struct {
	journal                                                      *operationJournal
	helperPath, appinstPath, bundleID, bundlePath, stagingRemote string
}

type installResult struct {
	bundlePath             string
	installed, reinstalled bool
}

func buildInstallPlan(dev *device.Client, uploadPath, bundleID string, prepareHelper func() (string, error), durable bool) (installPlan, error) {
	helperPath, err := prepareHelper()
	if err != nil {
		return installPlan{}, fmt.Errorf("prepare helper: %w", err)
	}

	appinstPath := ""
	if !durable {
		appinstPath, err = dev.LocateAppinst()
		if err != nil {
			return installPlan{}, fmt.Errorf("locate appinst: %w", err)
		}

		if appinstPath == "" {
			return installPlan{}, ErrAppinstNotFound
		}
	}

	bundlePath, _, err := dev.FindInstalledByBundleID(bundleID)
	if err != nil {
		return installPlan{}, fmt.Errorf("scan installed apps: %w", err)
	}

	return installPlan{helperPath: helperPath, appinstPath: appinstPath, bundleID: bundleID,
		bundlePath: bundlePath, stagingRemote: path.Join(device.RemoteRoot, "staging", filepath.Base(uploadPath))}, nil
}

func ensureInstalled(dev *device.Client, plan installPlan, uploadPath string, fromAppStore bool, notify func(string, string), progress func(int64, int64)) (installResult, error) {
	if plan.bundlePath == "" {
		return uploadAndInstall(dev, plan, uploadPath, false, notify, progress)
	}

	if !fromAppStore {
		notify("hash.local", "computing IPA checksum")

		execName, expected, err := pipeline.MainExecSHA256(uploadPath)
		if err != nil {
			return installResult{}, fmt.Errorf("hash IPA: %w", err)
		}

		notify("hash.installed", "computing installed app checksum")

		actual, err := dev.HashFile(path.Join(plan.bundlePath, execName))
		if err != nil {
			return installResult{}, fmt.Errorf("hash installed app: %w", err)
		}

		if actual == expected {
			return installResult{bundlePath: plan.bundlePath}, nil
		}
	}

	notify("replace", "replacing installed app")

	return uploadAndInstall(dev, plan, uploadPath, true, notify, progress)
}

func uploadAndInstall(dev *device.Client, plan installPlan, uploadPath string, reinstalled bool, notify func(string, string), progress func(int64, int64)) (installResult, error) {
	notify("upload", "uploading IPA to device")

	source, err := os.Open(uploadPath)
	if err != nil {
		return installResult{}, err
	}
	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return installResult{}, err
	}

	reader := &progressReader{r: source, total: info.Size(), onProgress: progress}

	upload := dev.Upload
	if plan.journal != nil {
		upload = dev.UploadOwned
	}

	if err := upload(reader, plan.stagingRemote, 0600); err != nil {
		return installResult{}, err
	}

	if plan.journal != nil {
		plan.journal.record.InstallIntent = true
		// Default policy removes installations made by this operation.
		plan.journal.record.RemoveApp = plan.journal.record.RemoveApp || plan.journal.removeInstalled
		if err := plan.journal.save(); err != nil {
			return installResult{}, err
		}
	}

	notify("appinst", "installing IPA")

	install := func() error { return dev.Install(plan.appinstPath, plan.stagingRemote) }
	if plan.journal != nil {
		install = func() error { return dev.InstallOperation(plan.bundleID, plan.stagingRemote) }
	}

	if err := install(); err != nil {
		return installResult{}, err
	}

	notify("rescan", "locating installed app")

	bundlePath, _, err := dev.FindInstalledByBundleID(plan.bundleID)
	if err != nil {
		return installResult{}, err
	}

	if bundlePath == "" {
		return installResult{}, errors.New("install succeeded but bundle was not found")
	}

	return installResult{bundlePath: bundlePath, installed: true, reinstalled: reinstalled}, nil
}

func decryptBundle(req Request, emit func(Event), dev *device.Client, helperPath, bundleID, bundlePath, version, sourceIPA string, result *Result) (returnErr error) {
	outputPath, err := resolveOutputPath(req.OutputPath, bundleID, version)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open output IPA: %w", err)
	}

	committed := false

	defer func() {
		closeErr := output.Close()

		if !committed {
			_ = os.Remove(outputPath)
		}

		if closeErr != nil {
			returnErr = errors.Join(returnErr, closeErr)
		}
	}()

	if req.operation != nil {
		req.operation.record.HelperIntent = true
		if err := req.operation.save(); err != nil {
			return err
		}
	}

	emit(Event{Phase: PhaseDecrypting, Action: "helper.start", Message: "starting on-device helper"})

	onHelperEvent := func(event device.Event) {
		attrs := make(map[string]string, len(event.Attrs))
		for key, value := range event.Attrs {
			attrs[key] = value
		}

		emit(Event{Phase: PhaseDecrypting, Action: event.Name, Message: event.Attr("msg"), Attributes: attrs})
	}
	written := &countingWriter{w: output, onProgress: func(current int64) {
		emit(Event{Phase: PhaseAssembling, Action: "write.progress", Message: "writing decrypted IPA", Current: current})
	}}

	if sourceIPA != "" {
		emit(Event{Phase: PhaseAssembling, Action: "assemble", Message: "assembling decrypted IPA"})

		err = pipeline.Assemble(sourceIPA, written, func(write pipeline.SubstituteWriter) error {
			code, runErr := dev.RunHelperExecs(helperPath, bundleID, bundlePath, req.Verbose, req.SkipAppex, onHelperEvent,
				func(name string, _ int64, reader io.Reader) error { return write(name, reader) })
			if runErr != nil {
				return runErr
			}

			if code != 0 {
				return fmt.Errorf("helper exited with status %d", code)
			}

			return nil
		})
	} else {
		code, runErr := dev.RunHelper(helperPath, bundleID, bundlePath, req.Verbose, req.SkipAppex, onHelperEvent, written)
		if runErr != nil {
			err = runErr
		} else if code != 0 {
			err = fmt.Errorf("helper exited with status %d", code)
		}
	}

	if err != nil {
		return fmt.Errorf("decrypt bundle: %w", err)
	}

	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync output IPA: %w", err)
	}

	committed = true
	result.OutputPath, result.BytesWritten = outputPath, written.n

	if !req.SkipVerify {
		emit(Event{Phase: PhaseVerifying, Action: "verify", Message: "verifying decrypted Mach-O files"})

		compareSource := ""
		if req.ExtraVerify {
			compareSource = sourceIPA
		}

		verified, err := pipeline.Verify(outputPath, compareSource, req.SkipAppex)
		if err != nil {
			return fmt.Errorf("verify output IPA: %w", err)
		}

		result.Verification = verificationResult(verified)
		if !verified.OK() {
			return fmt.Errorf("%w: %d encrypted, %d zero-filled, %d mismatched", ErrVerificationFailed,
				len(verified.StillEncrypted), len(verified.AllZeroCrypt), len(verified.Mismatches))
		}
	}

	return nil
}

func resolveOutputPath(override, bundleID, version string) (string, error) {
	name := fmt.Sprintf("%s_%s.decrypted.ipa", bundleID, version)

	if override == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}

		return filepath.Join(cwd, name), nil
	}

	abs, err := filepath.Abs(override)
	if err != nil {
		return "", err
	}

	if info, statErr := os.Stat(abs); statErr == nil && info.IsDir() {
		return filepath.Join(abs, name), nil
	}

	return abs, nil
}

type cleanupStack struct {
	mu  sync.Mutex
	fns []func() error
}

func (s *cleanupStack) push(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fns = append(s.fns, fn)
}

func (s *cleanupStack) run() error {
	s.mu.Lock()
	fns := s.fns
	s.fns = nil
	s.mu.Unlock()

	var err error
	for i := len(fns) - 1; i >= 0; i-- {
		err = errors.Join(err, fns[i]())
	}

	return err
}

func fileExists(name string) bool { _, err := os.Stat(name); return err == nil }
func ignoreNotExist(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return err
}
