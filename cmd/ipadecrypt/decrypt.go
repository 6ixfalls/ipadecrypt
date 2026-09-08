package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/londek/ipadecrypt/internal/updater"
	lib "github.com/londek/ipadecrypt/pkg/ipadecrypt"
	"github.com/spf13/cobra"
)

func decryptHandler(cmd *cobra.Command, args []string) {
	if decryptFromAppStore && decryptUseInstalled {
		tui.Err("--from-appstore and --use-installed are mutually exclusive; pass at most one.")
		return
	}

	if decryptForceUninstall && decryptNoUninstall {
		tui.Err("--force-uninstall and --no-uninstall are mutually exclusive; pass at most one.")
		return
	}

	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	if cfg.Device.Host == "" {
		tui.Err("environment not configured")
		tui.Info("run `ipadecrypt bootstrap` first to prepare your environment")

		return
	}

	upd := updater.Start(context.Background(), Version, cfg)
	defer upd.Wait()

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	source := lib.SourceAuto
	if decryptFromAppStore {
		source = lib.SourceAppStore
	} else if decryptUseInstalled {
		source = lib.SourceInstalled
	}

	uninstall := lib.UninstallAuto
	if decryptForceUninstall {
		uninstall = lib.UninstallAlways
	} else if decryptNoUninstall {
		uninstall = lib.UninstallNever
	}

	account := publicAppleAccount(cfg.Apple)
	live := tui.NewLive()
	lastPhase := lib.Phase("")

	result, err := lib.Decrypt(ctx, lib.Request{
		Target: args[0],
		Device: lib.DeviceConfig{
			Host: cfg.Device.Host, Port: cfg.Device.Port, User: cfg.Device.User,
			KnownHostsPath:   cfg.Device.KnownHostsPath,
			AcceptNewHostKey: cfg.Device.AcceptNewHostKey,
			Auth: lib.DeviceAuth{Kind: cfg.Device.Auth.Kind, Password: cfg.Device.Auth.Password,
				KeyPath: cfg.Device.Auth.KeyPath, KeyPassphrase: cfg.Device.Auth.KeyPassphrase},
		},
		Apple: &account, StateDir: paths.Root, OutputPath: decryptOutput,
		ExternalVersionID: decryptExtVerID, Storefront: decryptStorefront,
		Source: source, Uninstall: uninstall, PatchDeviceType: decryptPatchDevType,
		SkipAppex: decryptSkipAppex, KeepRemoteFiles: decryptNoCleanup,
		SkipVerify: decryptNoVerify, ExtraVerify: decryptExtraVerify, Verbose: decryptVerbose,
		OnEvent: func(event lib.Event) {
			if event.Phase != lastPhase {
				lastPhase = event.Phase
				live = tui.NewLive()
			}

			if event.Message != "" {
				live.Spin("%s", event.Message)
			}

			if event.Total > 0 {
				live.Progress(event.Current, event.Total)
			}
		},
		SelectInstalled: func(_ context.Context, installed lib.InstalledApp) (bool, error) {
			if !tui.IsTTY() {
				return false, fmt.Errorf("%s v%s is already installed; pass --use-installed or --from-appstore", installed.BundleID, installed.Version)
			}

			choice, err := tui.Select(
				fmt.Sprintf("%s v%s is already installed - which build do you want decrypted?", installed.BundleID, installed.Version),
				[]string{fmt.Sprintf("Installed on device v%s", installed.Version), "Latest from App Store (will reinstall)"},
			)

			return choice == 0, err
		},
		OnAuthCode: func(_ context.Context) (string, error) {
			return tui.Prompt("Apple sent a 6-digit code - enter it")
		},
		OnAccountUpdate: func(_ context.Context, updated lib.AppleAccount) error {
			cfg.Apple = internalAppleAccount(updated)
			return cfg.Save()
		},
	})
	if err != nil {
		live.Fail("decrypt failed: %v", err)
		return
	}

	live.OK("decrypted %s v%s (%s → %s)", result.BundleID, result.Version,
		humanBytes(result.BytesWritten), result.OutputPath)
}

func publicAppleAccount(account config.Apple) lib.AppleAccount {
	return lib.AppleAccount{
		Email: account.Email, Password: account.Password, PasswordToken: account.PasswordToken,
		DirectoryServicesID: account.DirectoryServicesIdentifier,
		StoreFront:          account.StoreFront, Pod: account.Pod,
	}
}

func internalAppleAccount(account lib.AppleAccount) config.Apple {
	return config.Apple{
		Email: account.Email, Password: account.Password, PasswordToken: account.PasswordToken,
		DirectoryServicesIdentifier: account.DirectoryServicesID,
		StoreFront:                  account.StoreFront, Pod: account.Pod,
	}
}

func humanBytes(n int64) string {
	const (
		kiB = 1024
		miB = kiB * 1024
		giB = miB * 1024
	)
	switch {
	case n >= giB:
		return fmt.Sprintf("%.2f GB", float64(n)/giB)
	case n >= miB:
		return fmt.Sprintf("%.1f MB", float64(n)/miB)
	case n >= kiB:
		return fmt.Sprintf("%.1f KB", float64(n)/kiB)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
