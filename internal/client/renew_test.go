package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	oldTok = "kd_fake-old-token"
	newTok = "kd_fake-new-token"
)

// fakeRenewed is a server where oldTok was renewed and newTok replaces it.
func fakeRenewed(t *testing.T, collects *atomic.Int32) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case tok == newTok:
			w.Header().Set("X-Keydrop-Token-Expires", "never")
			json.NewEncoder(w).Encode(map[string]any{"name": "bot", "namespaces": []string{"lab"}, "expires_at": nil})
		case tok == oldTok && r.URL.Path == "/api/v1/token/renew":
			json.NewEncoder(w).Encode(map[string]any{"name": "bot", "state": "approved"})
		case tok == oldTok && r.URL.Path == "/api/v1/token/collect":
			collects.Add(1)
			time.Sleep(20 * time.Millisecond)
			json.NewEncoder(w).Encode(map[string]any{"token": newTok})
		default:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid token"}`))
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// Several processes sharing a token file all carry on after a renewal;
// the file is replaced whole, mode 600, and the token never printed.
func TestCollectOnUnauthorized(t *testing.T) {
	var out strings.Builder
	var outMu sync.Mutex
	warnTo = writerFunc(func(p []byte) (int, error) { outMu.Lock(); defer outMu.Unlock(); return out.Write(p) })
	var collects atomic.Int32
	ts := fakeRenewed(t, &collects)
	path := filepath.Join(t.TempDir(), "token")
	os.WriteFile(path, []byte(oldTok+"\n"), 0o600)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := New(ts.URL, oldTok, "")
			c.TokenPath = path
			w, err := c.Whoami()
			if err == nil && w.Name != "bot" {
				err = errors.New("wrong whoami")
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := readToken(path); got != newTok {
		t.Fatal("token file not replaced")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if n := collects.Load(); n != 1 {
		t.Fatalf("collected %d times", n)
	}
	if strings.Contains(out.String(), newTok) || strings.Count(out.String(), "keydrop: token renewed; new token saved to "+path) != 1 {
		t.Fatalf("output: %q", out.String())
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".token-*")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
}

// A token from KEYDROP_TOKEN can't be saved, so it isn't collected.
func TestNoCollectWithoutFile(t *testing.T) {
	var collects atomic.Int32
	ts := fakeRenewed(t, &collects)
	c := New(ts.URL, oldTok, "")
	if _, err := c.Whoami(); !errors.Is(err, ErrRenewedNoFile) || collects.Load() != 0 {
		t.Fatalf("got %v, %d collects", err, collects.Load())
	}
}

func TestExpiredMessage(t *testing.T) {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/token/renew" {
			json.NewEncoder(w).Encode(map[string]any{"name": "bot", "state": "none", "expires_at": at, "expired": true})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer ts.Close()
	_, err := New(ts.URL, oldTok, "").Whoami()
	want := "this token expired on 2026-10-01. Run `keydrop renew`, then ask the admin to approve it in keydrop's Inbox."
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
}

func TestExpiryWarning(t *testing.T) {
	var out strings.Builder
	warnTo = &out
	c := &Client{}
	c.checkExpiry(time.Now().Add(100 * 24 * time.Hour).Format(time.RFC3339))
	c.checkExpiry("never")
	if out.Len() != 0 {
		t.Fatalf("warned early: %q", out.String())
	}
	c.checkExpiry(time.Now().Add(5*24*time.Hour - time.Minute).Format(time.RFC3339))
	c.checkExpiry(time.Now().Add(5 * 24 * time.Hour).Format(time.RFC3339))
	if out.String() != "keydrop: this token expires in 5 days. Run `keydrop renew` to ask the admin to extend it.\n" {
		t.Fatalf("got %q", out.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
