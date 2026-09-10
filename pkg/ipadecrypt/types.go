// Package ipadecrypt exposes the end-to-end ipadecrypt workflow for embedding
// in services and other Go programs.
package ipadecrypt

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/pipeline"
)

// SourcePolicy controls where an encrypted app is acquired.
type SourcePolicy string

const (
	// SourceAuto uses a local IPA when Target names one, otherwise prefers an
	// already-installed bundle and falls back to the App Store.
	SourceAuto SourcePolicy = "auto"
	// SourceAppStore always downloads and installs an App Store build.
	SourceAppStore SourcePolicy = "app-store"
	// SourceInstalled requires Target to name an app already on the device.
	SourceInstalled SourcePolicy = "installed"
)

// UninstallPolicy controls cleanup of the app on the device.
type UninstallPolicy string

const (
	// UninstallAuto removes an app only when this operation installed or
	// replaced it.
	UninstallAuto   UninstallPolicy = "auto"
	UninstallAlways UninstallPolicy = "always"
	UninstallNever  UninstallPolicy = "never"
)

// Phase is a stable, machine-readable workflow phase.
type Phase string

const (
	PhaseConnecting  Phase = "connecting"
	PhaseProbing     Phase = "probing"
	PhaseResolving   Phase = "resolving"
	PhaseDownloading Phase = "downloading"
	PhasePatching    Phase = "patching"
	PhaseInstalling  Phase = "installing"
	PhaseDecrypting  Phase = "decrypting"
	PhaseAssembling  Phase = "assembling"
	PhaseVerifying   Phase = "verifying"
	PhaseCleaning    Phase = "cleaning"
	PhaseComplete    Phase = "complete"
)

// Event is emitted as an operation advances. Current and Total are byte
// counts for transfer events. Attributes contains raw helper event metadata.
type Event struct {
	Phase      Phase             `json:"phase"`
	Action     string            `json:"action"`
	Message    string            `json:"message,omitempty"`
	Current    int64             `json:"current,omitempty"`
	Total      int64             `json:"total,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// EventHandler receives progress synchronously. It should return quickly.
type EventHandler func(Event)

// AppleAccount contains the App Store session used for downloads. Password
// may be omitted while PasswordToken remains valid, but is needed to recover
// from an expired token.
type AppleAccount struct {
	Email               string
	Name                string
	Password            string
	PasswordToken       string
	DirectoryServicesID string
	StoreFront          string
	Pod                 string
	// MACAddress optionally pins App Store authentication, purchase, and
	// download requests to this six-byte MAC address. When empty, the host's
	// network MAC address is used.
	MACAddress string
}

// AuthCodeProvider returns a current App Store two-factor authentication code.
type AuthCodeProvider func(context.Context) (string, error)

// DeviceAuth contains SSH and sudo authentication. Password doubles as the
// SSH password for password auth and as the sudo password for key auth.
type DeviceAuth struct {
	Kind          string
	Password      string
	KeyPath       string
	KeyPassphrase string
}

// DeviceConfig identifies the jailbroken device. KnownHostsPath and
// AcceptNewHostKey are forwarded to the SSH transport. Callers should use a
// dedicated known-hosts file and review newly enrolled keys out of band.
type DeviceConfig struct {
	// UnlockPIN optionally unlocks a locked device using ipadecrypt Companion.
	UnlockPIN        string
	Host             string
	Port             int
	User             string
	Auth             DeviceAuth
	KnownHostsPath   string
	AcceptNewHostKey bool
}

// Request describes one complete decryption operation.
type Request struct {
	// OperationID and JournalDir enable durable cleanup. IDs are single-use;
	// JournalDir must be private durable storage outside StateDir/workspaces.
	OperationID string
	JournalDir  string
	operation   *operationJournal

	// Target is a bundle ID, numeric App Store ID, App Store URL, or local IPA.
	Target string
	Device DeviceConfig
	Apple  *AppleAccount

	// StateDir stores the cookie jar and encrypted IPA cache. When empty, an
	// operation-scoped temporary directory is used and removed afterward.
	StateDir string
	// OutputPath may be a filename or an existing directory. The default is
	// <bundleID>_<version>.decrypted.ipa in the current directory.
	OutputPath        string
	ExternalVersionID string
	Storefront        string
	Source            SourcePolicy
	Uninstall         UninstallPolicy

	PatchDeviceType bool
	SkipAppex       bool
	KeepRemoteFiles bool
	SkipVerify      bool
	ExtraVerify     bool
	Verbose         bool

	OnEvent EventHandler
	// OnAuthCode is called when App Store authentication requires a two-factor
	// code. It may be nil when the stored session can refresh without 2FA.
	OnAuthCode AuthCodeProvider
	// SelectInstalled is consulted in SourceAuto mode when a matching app is
	// already installed. Nil selects the installed app, which is suitable for
	// non-interactive workers.
	SelectInstalled func(context.Context, InstalledApp) (bool, error)
	// OnAccountUpdate is called after a token refresh. A backend should persist
	// the value in its secret store. Returning an error aborts the operation.
	OnAccountUpdate func(context.Context, AppleAccount) error
}

// InstalledApp describes a matching app found on the device.
type InstalledApp struct {
	BundleID   string
	Version    string
	BundlePath string
}

// DeviceInfo describes the connected device observed during the operation.
type DeviceInfo struct {
	IOSVersion   string `json:"iosVersion"`
	Architecture string `json:"architecture"`
	Model        string `json:"model"`
	DeviceFamily int    `json:"deviceFamily"`
	Jailbreak    string `json:"jailbreak"`
}

// VerificationResult summarizes the post-decryption Mach-O checks.
type VerificationResult struct {
	Scanned        int                    `json:"scanned"`
	Compared       int                    `json:"compared"`
	StillEncrypted []string               `json:"stillEncrypted,omitempty"`
	AllZeroCrypt   []string               `json:"allZeroCrypt,omitempty"`
	Mismatches     []VerificationMismatch `json:"mismatches,omitempty"`
	Missing        []string               `json:"missing,omitempty"`
	Skipped        []string               `json:"skipped,omitempty"`
}

// VerificationMismatch describes a decrypted Mach-O that differs from its
// source outside the expected encrypted region.
type VerificationMismatch struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func (r VerificationResult) OK() bool {
	return len(r.StillEncrypted) == 0 && len(r.AllZeroCrypt) == 0 && len(r.Mismatches) == 0
}

// Result describes a completed operation.
type Result struct {
	BundleID      string             `json:"bundleId"`
	Version       string             `json:"version"`
	OutputPath    string             `json:"outputPath"`
	SourceIPAPath string             `json:"sourceIpaPath,omitempty"`
	Device        DeviceInfo         `json:"device"`
	Installed     bool               `json:"installed"`
	Reinstalled   bool               `json:"reinstalled"`
	Uninstalled   bool               `json:"uninstalled"`
	BytesWritten  int64              `json:"bytesWritten"`
	Verification  VerificationResult `json:"verification"`
}

// TargetKind identifies the parsed form of a target.
type TargetKind string

const (
	TargetBundleID TargetKind = "bundle-id"
	TargetAppID    TargetKind = "app-id"
	TargetLocalIPA TargetKind = "local-ipa"
)

// Target is the normalized representation returned by ParseTarget.
type Target struct {
	Kind  TargetKind
	Value string
}

var appStoreIDPattern = regexp.MustCompile(`/id(\d+)`)

// ParseTarget parses the target formats accepted by Decrypt.
func ParseTarget(raw string) (Target, error) {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil {
			return Target{}, fmt.Errorf("parse URL: %w", err)
		}

		match := appStoreIDPattern.FindStringSubmatch(u.Path)
		if match == nil {
			return Target{}, fmt.Errorf("no /id<digits> in URL %s", raw)
		}

		return Target{Kind: TargetAppID, Value: match[1]}, nil
	}

	if strings.HasSuffix(strings.ToLower(raw), ".ipa") {
		info, err := os.Stat(raw)
		if err != nil {
			return Target{}, fmt.Errorf("local IPA %s: %w", raw, err)
		}

		if info.IsDir() {
			return Target{}, fmt.Errorf("local IPA %s is a directory", raw)
		}

		abs, err := filepath.Abs(raw)
		if err != nil {
			return Target{}, err
		}

		return Target{Kind: TargetLocalIPA, Value: abs}, nil
	}

	if raw != "" {
		allDigits := true

		for _, r := range raw {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}

		if allDigits {
			return Target{Kind: TargetAppID, Value: raw}, nil
		}
	}

	if strings.TrimSpace(raw) == "" {
		return Target{}, errors.New("target is required")
	}

	return Target{Kind: TargetBundleID, Value: raw}, nil
}

// AppInfo reads the bundle ID and version from an IPA.
func AppInfo(path string) (bundleID, version string, err error) {
	return pipeline.AppInfo(path)
}

// Verify performs the same Mach-O verification used by Decrypt.
func Verify(outputIPA, sourceIPA string, skipAppex bool) (VerificationResult, error) {
	r, err := pipeline.Verify(outputIPA, sourceIPA, skipAppex)
	return verificationResult(r), err
}

func verificationResult(r pipeline.VerifyResult) VerificationResult {
	out := VerificationResult{
		Scanned: r.Scanned, Compared: r.Compared, StillEncrypted: r.StillEncrypted,
		AllZeroCrypt: r.AllZeroCrypt, Missing: r.Missing, Skipped: r.Skipped,
		Mismatches: make([]VerificationMismatch, len(r.Mismatches)),
	}
	for i, mismatch := range r.Mismatches {
		out.Mismatches[i] = VerificationMismatch{Name: mismatch.Name, Reason: mismatch.Reason}
	}

	return out
}

func internalAccount(a *AppleAccount) *appstore.Account {
	if a == nil {
		return nil
	}

	return &appstore.Account{Email: a.Email, Name: a.Name, Password: a.Password, PasswordToken: a.PasswordToken,
		DirectoryServicesID: a.DirectoryServicesID, StoreFront: a.StoreFront, Pod: a.Pod}
}

func setAccount(dst *AppleAccount, src *appstore.Account) {
	macAddress := dst.MACAddress
	*dst = AppleAccount{Email: src.Email, Name: src.Name, Password: src.Password, PasswordToken: src.PasswordToken,
		DirectoryServicesID: src.DirectoryServicesID, StoreFront: src.StoreFront, Pod: src.Pod, MACAddress: macAddress}
}

func internalDevice(d DeviceConfig) config.Device {
	port := d.Port
	if port == 0 {
		port = 22
	}

	user := d.User
	if user == "" {
		user = "mobile"
	}

	return config.Device{Host: d.Host, Port: port, User: user,
		KnownHostsPath: d.KnownHostsPath, AcceptNewHostKey: d.AcceptNewHostKey,
		Auth: config.DeviceAuth{Kind: d.Auth.Kind, Password: d.Auth.Password,
			KeyPath: d.Auth.KeyPath, KeyPassphrase: d.Auth.KeyPassphrase}}
}
