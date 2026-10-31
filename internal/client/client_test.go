package client

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckVersion(t *testing.T) {
	var out strings.Builder
	warnTo = &out
	for _, tc := range []struct {
		cli, server string
		warn        bool
	}{
		{"v0.1.0", "v0.1.0", false},
		{"dev", "v0.1.0", false}, // a local build has no version to compare
		{"v0.1.0", "dev", false},
		{"v0.1.0", "", false}, // an old server sends no header
		{"dev-1234567", "dev-89abcde", true},
		{"v0.1.0", "v0.2.0", true},
	} {
		out.Reset()
		Version, warnedVersion = tc.cli, false
		checkVersion(tc.server)
		checkVersion(tc.server) // once per run
		if got := strings.Count(out.String(), "\n"); got != map[bool]int{true: 1, false: 0}[tc.warn] {
			t.Errorf("CLI %q, server %q: %q", tc.cli, tc.server, out.String())
		}
	}
}

// A pin with an http:// URL fails instead of going unverified.
func TestPinNeedsHTTPS(t *testing.T) {
	c := New("http://10.0.0.5:8443", "kd_fake", "sha256:00")
	if _, err := c.Whoami(); !errors.Is(err, ErrPinNeedsHTTPS) {
		t.Fatalf("got %v", err)
	}
}
