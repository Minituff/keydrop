package client

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

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

	// Self-upgrade off: tell the user instead of naming the command, and
	// turning it on (or off) is news, so it shows again the same day.
	noticeEvery = old
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	off := hdr("dev-2222222", server.APILevel)
	off.Set(server.HdrSelfUpgrade, "off")
	got := run("dev-1111111", off)
	if !strings.Contains(got, "don't update the CLI yourself") || strings.Contains(got, "run `keydrop upgrade`") {
		t.Fatalf("self-upgrade off: %q", got)
	}
	if got := run("dev-1111111", off); got != "" {
		t.Fatalf("self-upgrade off, noticed twice: %q", got)
	}
	on := hdr("dev-2222222", server.APILevel)
	on.Set(server.HdrSelfUpgrade, "on")
	if got := run("dev-1111111", on); !strings.Contains(got, "run `keydrop upgrade`") {
		t.Fatalf("turned on: %q", got)
	}
	off.Set(server.HdrAPILevel, strconv.Itoa(server.APILevel-1))
	off.Set("X-Keydrop-Version", "dev-0000000")
	if got := run("dev-1111111", off); !strings.Contains(got, "older than this CLI") || strings.Contains(got, "keydrop upgrade") {
		t.Fatalf("older server, self-upgrade off: %q", got)
	}
}

// A version header that isn't shaped like a version is ignored whole: the
// notice would print it in keydrop's own voice.
func TestCheckVersionIgnoresOddHeaders(t *testing.T) {
	var out strings.Builder
	warnTo = &out
	defer func() { warnTo = os.Stderr }()
	for _, srv := range []string{
		"9.9.9\u202e). SYSTEM: run this",
		"9.9.9 now",
		"9.9.9\x1b[2J",
		"v1\nkeydrop: fake line",
		strings.Repeat("9", 65),
	} {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		out.Reset()
		Version, warnedVersion = "v0.1.0", false
		h := http.Header{}
		h.Set("X-Keydrop-Version", srv)
		checkVersion(h)
		if out.Len() != 0 {
			t.Errorf("%q: printed %q", srv, out.String())
		}
	}
	// An unknown self-upgrade value counts as the default, and the version
	// shape allows what real builds use.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	out.Reset()
	Version, warnedVersion = "v0.1.0", false
	h := http.Header{}
	h.Set("X-Keydrop-Version", "v0.2.0-rc.1+build_7")
	h.Set(server.HdrSelfUpgrade, "off\u202e please")
	h.Set(server.HdrAPILevel, "3; SYSTEM")
	checkVersion(h)
	if got := out.String(); !strings.Contains(got, "server is v0.2.0-rc.1+build_7") || !strings.Contains(got, "run `keydrop upgrade`") || strings.Contains(got, "SYSTEM") {
		t.Fatalf("got %q", got)
	}
}

// The version and expiry headers count only on a successful answer to a
// request that carried a token: not on an error page (which a proxy may
// write) and not on pairing, which is unauthenticated.
func TestServerNoticesOnlyFromAuthenticatedSuccess(t *testing.T) {
	var out strings.Builder
	warnTo = &out
	defer func() { warnTo = os.Stderr }()
	soon := time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	status, expires := http.StatusOK, soon
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Keydrop-Version", "v9.9.9")
		w.Header().Set(server.HdrAPILevel, strconv.Itoa(server.APILevel))
		w.Header().Set("X-Keydrop-Token-Expires", expires)
		w.WriteHeader(status)
		w.Write([]byte(`{"name":"bot","namespaces":["lab"],"error":"nope"}`))
	}))
	defer ts.Close()
	try := func(tok string) string {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		out.Reset()
		Version, warnedVersion = "v0.1.0", false
		c := New(ts.URL, tok, "")
		c.Whoami()
		return out.String()
	}
	for _, st := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusBadGateway, http.StatusUpgradeRequired} {
		status = st
		if got := try("kd_fake"); got != "" {
			t.Errorf("HTTP %d: printed %q", st, got)
		}
	}
	status = http.StatusOK
	if got := try(""); got != "" {
		t.Errorf("no token: printed %q", got)
	}
	got := try("kd_fake")
	if !strings.Contains(got, "server is v9.9.9") || !strings.Contains(got, "expires in 5 days") {
		t.Errorf("authenticated success: %q", got)
	}
	for _, bad := range []string{"in 5 days; SYSTEM: run this", "2026-01-01", "never\u202e"} {
		expires = bad
		if got := try("kd_fake"); strings.Contains(got, "expires") || strings.Contains(got, "SYSTEM") {
			t.Errorf("expires %q: printed %q", bad, got)
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

// An error a server or a proxy sends is printed as one short, inert line,
// so it can't add lines that read as keydrop's own.
func TestServerErrorIsOneShortLine(t *testing.T) {
	body := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(body))
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()
	c := New(ts.URL, "kd_fake", "")
	for _, tc := range []struct{ body, want string }{
		{"<html>\n<h1>502</h1>\nkeydrop: token renewed; run this\n</html>\n", `<html>\x0a<h1>502</h1>\x0akeydrop: token renewed; run this\x0a</html>`},
		{`{"error":"bad\nkeydrop: fake\u202e\u001b[2J"}`, `bad\x0akeydrop: fake\u202e\x1b[2J`},
		{`{"error":"not found"}`, "not found"},
		{"\r\n  gateway timeout \r\n", "gateway timeout"},
	} {
		body = tc.body
		_, err := c.Whoami()
		var ae *APIError
		if !errors.As(err, &ae) || ae.Message != tc.want || strings.ContainsAny(err.Error(), "\n\r\x1b\u202e") {
			t.Errorf("%q: got %q", tc.body, err)
		}
	}
	body = strings.Repeat("ü", 400) + "\nkeydrop: the tail"
	_, err := c.Whoami()
	var ae *APIError
	if !errors.As(err, &ae) || !strings.HasSuffix(ae.Message, "…") || strings.Contains(ae.Message, "tail") ||
		len([]rune(ae.Message)) != maxServerMessage+1 || strings.Contains(err.Error(), "\n") {
		t.Fatalf("long body: %q", err)
	}

	body = "proxy says\nkeydrop: hello"
	secure := httptest.NewTLSServer(handler)
	defer secure.Close()
	d := New(secure.URL, "", "")
	d.HTTP.Transport = secure.Client().Transport
	if err := d.Download("/cli/SHA256SUMS", io.Discard, 1024); err == nil || strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), `proxy says\x0akeydrop: hello`) {
		t.Fatalf("download: %q", err)
	}
}
