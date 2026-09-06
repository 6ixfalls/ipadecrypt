package ipadecrypt

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseTarget(t *testing.T) {
	t.Parallel()
	tmp := filepath.Join(t.TempDir(), "sample.ipa")
	if err := os.WriteFile(tmp, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  Target
	}{
		{"bundle ID", "com.example.App", Target{Kind: TargetBundleID, Value: "com.example.App"}},
		{"app ID", "544007664", Target{Kind: TargetAppID, Value: "544007664"}},
		{"URL", "https://apps.apple.com/us/app/example/id544007664", Target{Kind: TargetAppID, Value: "544007664"}},
		{"local IPA", tmp, Target{Kind: TargetLocalIPA, Value: tmp}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseTarget(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseTargetRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"", "https://apps.apple.com/us/app/no-id", filepath.Join(t.TempDir(), "missing.ipa")} {
		if _, err := ParseTarget(input); err == nil {
			t.Errorf("ParseTarget(%q) unexpectedly succeeded", input)
		}
	}
}

func TestValidateRequest(t *testing.T) {
	t.Parallel()
	valid := Request{Target: "com.example", Device: DeviceConfig{Host: "device", KnownHostsPath: "/tmp/known_hosts"}}
	if err := validateRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	tests := []Request{
		{Target: "com.example", Device: DeviceConfig{KnownHostsPath: "/tmp/known_hosts"}},
		{Target: "com.example", Device: DeviceConfig{Host: "device"}},
		{Target: "com.example", Device: valid.Device, Source: SourcePolicy("invalid")},
		{Target: "com.example", Device: valid.Device, Uninstall: UninstallPolicy("invalid")},
		{Target: "com.example", Device: valid.Device, SkipVerify: true, ExtraVerify: true},
	}
	for i, request := range tests {
		if err := validateRequest(request); err == nil {
			t.Errorf("invalid request %d unexpectedly succeeded", i)
		}
	}
}

func TestCleanupStackIsLIFOAndIdempotent(t *testing.T) {
	t.Parallel()
	var got []int
	stack := &cleanupStack{}
	stack.push(func() error { got = append(got, 1); return nil })
	stack.push(func() error { got = append(got, 2); return errors.New("cleanup") })
	if err := stack.run(); err == nil {
		t.Fatal("expected cleanup error")
	}
	if want := []int{2, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	if err := stack.run(); err != nil {
		t.Fatalf("second run: %v", err)
	}
}

func TestCacheFilenameCannotEscapeDirectory(t *testing.T) {
	t.Parallel()
	name := cacheFilename("../../bundle/name", "../version")
	if filepath.Base(name) != name {
		t.Fatalf("unsafe cache filename %q", name)
	}
}
