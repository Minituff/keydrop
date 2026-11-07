package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// A login that checked the old credentials mustn't end in a session once
// they've changed. Each change must also move the generation on.
func TestLoginDoesntSurviveACredentialChange(t *testing.T) {
	h := newHarness(t)
	h.setup()
	gen := h.srv.credentialGen()
	if !h.srv.newSessionSince(httptest.NewRecorder(), gen) {
		t.Fatal("no change, but no session")
	}
	code, _ := h.form("/settings/password", url.Values{"current": {"a long enough password"}, "password": {"another long password"}, "password2": {"another long password"}})
	if code >= 400 {
		t.Fatalf("password change: %d", code)
	}
	if h.srv.credentialGen() == gen {
		t.Fatal("changing the password didn't count")
	}
	rec := httptest.NewRecorder()
	if h.srv.newSessionSince(rec, gen) || len(rec.Result().Cookies()) != 0 {
		t.Fatal("a login from before the change got a session")
	}
}

// Rate-limited and malformed calls never reach the store, and still count.
func TestEarlyRefusalsTouchCanary(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "DECOY", []byte("fake-decoy-value"), nil)
	h.st.PutValue("lab", "REAL", []byte("fake-real-value"), nil)
	if err := h.st.SetCanary("lab", "DECOY", true); err != nil {
		t.Fatal(err)
	}
	tok, _ := h.st.CreateToken("writer", []string{"lab"}, store.PermWrite, nil)
	hits := func() int {
		n := 0
		list, _ := h.st.CanaryHits()
		for _, c := range list {
			n += c.Count
		}
		return n
	}
	raw := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, h.ts.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		b.Write(buf[:n])
		return resp.StatusCode, b.String()
	}
	check := func(name, method, suffix, body string) {
		t.Helper()
		before := hits()
		dc, draw := raw(method, "/api/v1/secrets/lab/DECOY"+suffix, body)
		if hits() != before+1 {
			t.Fatalf("%s: not a touch", name)
		}
		rc, rraw := raw(method, "/api/v1/secrets/lab/REAL"+suffix, body)
		if hits() != before+1 {
			t.Fatalf("%s: touched an ordinary secret", name)
		}
		if dc != rc || strings.ReplaceAll(draw, "DECOY", "REAL") != rraw {
			t.Fatalf("%s: a canary answers differently: %d %s / %d %s", name, dc, draw, rc, rraw)
		}
	}
	check("bad JSON on a write", "PUT", "", "{")
	check("empty value", "PUT", "", `{"value":""}`)
	check("bad expiry", "PUT", "", `{"value":"x","expires":"soon"}`)
	check("bad JSON on a flag", "POST", "/flag", "{")
	check("bad JSON on a status", "POST", "/status", "{")
	check("bad JSON on a note", "POST", "/notes", "{")

	h.srv.writes = newRateLimit(0, time.Hour)
	h.srv.annotations = newRateLimit(0, time.Hour)
	check("rate-limited write", "PUT", "", `{"value":"x"}`)
	check("rate-limited flag", "POST", "/flag", `{"reason":"x"}`)
}
