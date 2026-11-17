package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/server"
)

// Inspect, which `keydrop doctor` uses, changes nothing: a 401 doesn't
// collect the renewed token, and a different server build leaves no
// once-a-day stamp and prints no notice.
func TestInspectHasNoSideEffects(t *testing.T) {
	var out strings.Builder
	warnTo = &out
	defer func() { warnTo = os.Stderr }()
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	Version, warnedVersion = "v0.1.0", false

	var collects atomic.Int32
	ts := fakeRenewed(t, &collects)
	path := filepath.Join(t.TempDir(), "token")
	os.WriteFile(path, []byte(oldTok+"\n"), 0o600)
	c := New(ts.URL, oldTok, "")
	c.TokenPath = path
	var ae *APIError
	if _, _, err := c.Inspect("/api/v1/whoami", true); !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Fatalf("got %v, want the 401 as it is", err)
	}
	if collects.Load() != 0 || readToken(path) != oldTok {
		t.Fatal("Inspect collected the renewed token")
	}

	soon := time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Keydrop-Version", "v9.9.9")
		w.Header().Set(server.HdrAPILevel, strconv.Itoa(server.APILevel))
		w.Header().Set("X-Keydrop-Token-Expires", soon)
		w.Write([]byte(`{"name":"bot"}`))
	}))
	defer ts2.Close()
	h, body, err := New(ts2.URL, "kd_fake", "").Inspect("/api/v1/whoami", true)
	if err != nil || h.Get("X-Keydrop-Version") != "v9.9.9" || string(body) != `{"name":"bot"}` {
		t.Fatalf("got %v, %q, %v", h, body, err)
	}
	if out.String() != "" {
		t.Errorf("Inspect printed %q", out.String())
	}
	if m, _ := filepath.Glob(filepath.Join(cfg, "*", "*")); len(m) != 0 {
		t.Errorf("Inspect wrote %v", m)
	}
	if VersionNotice(h) == "" {
		t.Error("no version notice for a different build")
	}
}

// Inspect without a token sends none.
func TestInspectWithoutToken(t *testing.T) {
	var auth atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization") != "")
		w.Write([]byte("ok\n"))
	}))
	defer ts.Close()
	c := New(ts.URL, "kd_fake", "")
	if _, body, err := c.Inspect("/healthz", false); err != nil || string(body) != "ok\n" || auth.Load() {
		t.Fatalf("got %q, %v, token sent %v", body, err, auth.Load())
	}
	if c.Token != "kd_fake" {
		t.Fatal("Inspect changed the client's token")
	}
}

// A pin mismatch says which certificate the server presented, and the
// request never reaches the server.
func TestPinMismatchError(t *testing.T) {
	var reached atomic.Bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer ts.Close()
	pin := "sha256:" + strings.Repeat("0", 64)
	_, _, err := New(ts.URL, "kd_fake", pin).Inspect("/healthz", true)
	var pm *PinMismatchError
	if !errors.As(err, &pm) || pm.Pin != pin || pm.Got != server.Fingerprint(ts.Certificate().Raw) {
		t.Fatalf("got %v (%+v)", err, pm)
	}
	if !strings.Contains(err.Error(), "server certificate doesn't match KEYDROP_TLS_PIN") {
		t.Errorf("message changed: %v", err)
	}
	if reached.Load() {
		t.Error("the request reached a server whose pin doesn't match")
	}
}
