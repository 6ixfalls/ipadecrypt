package ipadecrypt

import (
	"errors"
	"strings"
	"testing"

	"github.com/londek/ipadecrypt/internal/device"
)

func TestHelperEventError(t *testing.T) {
	for _, tt := range []struct {
		name string
		want error
	}{
		{"device.locked", ErrDeviceLocked},
		{"bundle.incomplete", ErrVerificationFailed},
		{"target.spawn.fallback", nil},
		{"image.done", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := helperEventError(device.Event{Name: tt.name, Attrs: map[string]string{"msg": "actionable device detail"}})
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}

			if err != nil && !strings.Contains(err.Error(), "actionable device detail") {
				t.Fatalf("lost helper diagnostic: %v", err)
			}
		})
	}
}
