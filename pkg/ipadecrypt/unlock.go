package ipadecrypt

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	companionPath       = "PATH=/var/jb/usr/bin:/usr/bin:/bin:$PATH ipadc "
	idleLeaseTTL        = 60 * time.Second
	idleLeaseRenewEvery = 20 * time.Second
)

type unlockDevice interface {
	Run(string) (string, string, int, error)
	RunInput(string, []byte) (string, string, int, error)
}

// Attempt the supplied PIN only once. Never expose command output: transport
// errors may contain the command and therefore the PIN.
func ensureUnlocked(dev unlockDevice, pin string) error {
	locked := func() (bool, error) {
		out, _, code, err := dev.Run(companionPath + "status")
		if err != nil || code != 0 || (strings.TrimSpace(out) != "locked" && strings.TrimSpace(out) != "unlocked") {
			return false, fmt.Errorf("%w: cannot determine device lock state", ErrDeviceLocked)
		}

		return strings.TrimSpace(out) == "locked", nil
	}

	isLocked, err := locked()
	if err != nil || !isLocked {
		return err
	}

	_, _, code, err := dev.RunInput(companionPath+"unlock", []byte(pin+"\n"))
	if err != nil || code != 0 {
		return fmt.Errorf("%w: companion unlock failed; check the tweak and configured PIN", ErrDeviceLocked)
	}

	for attempt := 0; attempt < 20; attempt++ {
		isLocked, err = locked()
		if err != nil || !isLocked {
			return err
		}

		time.Sleep(250 * time.Millisecond)
	}

	return fmt.Errorf("%w: device remained locked after companion unlock", ErrDeviceLocked)
}

func validLeaseToken(token string) bool {
	if len(token) != 36 {
		return false
	}
	for index, char := range token {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

// disableAutoLock acquires a renewable, expiring lease from the SpringBoard
// companion. If this process disappears, the tweak restores the prior state
// when the final lease expires.
func disableAutoLock(dev unlockDevice) (func() error, error) {
	ttlSeconds := int(idleLeaseTTL / time.Second)
	out, _, code, err := dev.Run(fmt.Sprintf("%sidle-acquire %d", companionPath, ttlSeconds))
	token := strings.TrimSpace(out)
	if err != nil || code != 0 || !validLeaseToken(token) {
		return nil, fmt.Errorf("%w: cannot acquire screen idle-timer lease", ErrDeviceLocked)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	var renewMu sync.Mutex
	var renewErr error

	go func() {
		defer close(done)
		ticker := time.NewTicker(idleLeaseRenewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _, exitCode, runErr := dev.Run(fmt.Sprintf(
					"%sidle-renew %s %d", companionPath, token, ttlSeconds))
				renewMu.Lock()
				if runErr != nil || exitCode != 0 {
					renewErr = fmt.Errorf("renew screen idle-timer lease")
				} else {
					renewErr = nil
				}
				renewMu.Unlock()
			case <-stop:
				return
			}
		}
	}()

	var once sync.Once
	var restoreErr error
	return func() error {
		once.Do(func() {
			close(stop)
			<-done

			renewMu.Lock()
			restoreErr = renewErr
			renewMu.Unlock()

			_, _, exitCode, runErr := dev.Run(companionPath + "idle-release " + token)
			if runErr != nil || exitCode != 0 {
				restoreErr = errors.Join(restoreErr,
					fmt.Errorf("release screen idle-timer lease"))
			}
		})
		return restoreErr
	}, nil
}
