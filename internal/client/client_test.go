package client

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/minituff/keydrop/internal/server"
)

func TestCheckVersion(t *testing.T) {
	var out strings.Builder
	warnTo = &out
	hdr := func(srv string, level int) http.Header {
		h := http.Header{}
		if srv != "" {
			h.Set("X-Keydrop-Version", srv)
		}
		h.Set(server.HdrAPILevel, strconv.Itoa(level))
		return h
	}
	run := func(cli string, h http.Header) string {
		out.Reset()
		Version, warnedVersion = cli, false
		checkVersion(h)
		checkVersion(h) // once per run
		return out.String()
	}
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
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		got := run(tc.cli, hdr(tc.server, server.APILevel))
		if strings.Count(got, "\n") != map[bool]int{true: 1, false: 0}[tc.warn] {
			t.Errorf("CLI %q, server %q: %q", tc.cli, tc.server, got)
		}
		if tc.warn && (!strings.Contains(got, "keydrop upgrade") || !strings.Contains(got, "Nothing breaks")) {
			t.Errorf("CLI %q, server %q: the notice doesn't say it's compatible and name the command: %q", tc.cli, tc.server, got)
		}
	}

	// Once a day per server build: a second run stays quiet, a new
	// server build speaks again.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if run("dev-1111111", hdr("dev-2222222", server.APILevel)) == "" {
		t.Fatal("no notice the first time")
	}
	if got := run("dev-1111111", hdr("dev-2222222", server.APILevel)); got != "" {
		t.Fatalf("noticed again within the day: %q", got)
	}
	if run("dev-1111111", hdr("dev-3333333", server.APILevel)) == "" {
		t.Fatal("no notice for a newer server build")
	}
	old := noticeEvery
	noticeEvery = 0
	defer func() { noticeEvery = old }()
	if run("dev-1111111", hdr("dev-3333333", server.APILevel)) == "" {
		t.Fatal("no notice once the day is over")
	}

	// A server at a lower level than this CLI is older: say so instead.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if got := run("dev-1111111", hdr("dev-0000000", server.APILevel-1)); !strings.Contains(got, "older than this CLI") {
		t.Fatalf("older server: %q", got)
	}
}

// A pin with an http:// URL fails instead of going unverified.
func TestPinNeedsHTTPS(t *testing.T) {
	c := New("http://10.0.0.5:8443", "kd_fake", "sha256:00")
	if _, err := c.Whoami(); !errors.Is(err, ErrPinNeedsHTTPS) {
		t.Fatalf("got %v", err)
	}
}
