package device

import "testing"

func TestShellQuote(t *testing.T) {
	t.Parallel()

	got := shellQuote("hello' $(touch /tmp/nope)")

	want := `'hello'\'' $(touch /tmp/nope)'`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
