package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/auth"
	"github.com/minituff/keydrop/internal/store"
)

type harness struct {
	t   *testing.T
	srv *Server
	ts  *httptest.Server
	web *http.Client
	st  *store.Store
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	st, err := store.Open(dir, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	al, _ := audit.Open(filepath.Join(dir, "audit.jsonl"))
	srv := New(Config{CookieSecure: false}, st, al)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{t, srv, ts, web, st}
}

func (h *harness) post(path string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.web.PostForm(h.ts.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) get(path string) (int, string) {
	resp, err := h.web.Get(h.ts.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *harness) csrf() string {
	_, body := h.get("/")
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatalf("no csrf token on dashboard: %s", body)
	}
	return m[1]
}

// setup completes first-run setup and leaves the client logged in.
func (h *harness) setup() {
	h.t.Helper()
	tok, seed := h.srv.setupToken, h.srv.setupSeed
	resp := h.post("/setup", url.Values{
		"token": {tok}, "password": {"a long enough password"}, "password2": {"a long enough password"},
		"code": {totpNow(seed, time.Now())},
	})
	if resp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("setup: %d %s", resp.StatusCode, b)
	}
}

func totpNow(seed []byte, t time.Time) string { return auth.Code(seed, t) }

func (h *harness) api(method, path, token string, body any) (int, map[string]any, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m, raw
}

func TestSetupLoginAndCSRF(t *testing.T) {
	h := newHarness(t)
	if code, _ := h.get("/setup?token=wrong"); code != http.StatusForbidden {
		t.Fatalf("bad setup token: %d", code)
	}
	h.setup()
	if h.srv.setupOpen() {
		t.Fatal("setup still open after completion")
	}
	csrf := h.csrf()

	// Missing CSRF is refused.
	resp := h.post("/secrets", url.Values{"namespace": {"lab"}, "name": {"x"}, "value": {"value-123"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-csrf post: %d", resp.StatusCode)
	}
	// Cross-site fetch is refused even with the token.
	req, _ := http.NewRequest("POST", h.ts.URL+"/secrets", strings.NewReader(url.Values{"csrf": {csrf}, "namespace": {"lab"}, "name": {"x"}, "value": {"v-123456"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, _ = h.web.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", resp.StatusCode)
	}

	// Saving works, and the value never appears on any page.
	resp = h.post("/secrets", url.Values{"csrf": {csrf}, "namespace": {"lab"}, "name": {"cf"}, "value": {"  the-real-value-42 \n"}, "description": {"dns token"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	for _, p := range []string{"/", "/secret/lab/cf", "/audit", "/tokens"} {
		if _, body := h.get(p); strings.Contains(body, "the-real-value-42") {
			t.Fatalf("value shown on %s", p)
		}
	}
	if v, _ := h.st.Reveal("lab", "cf", "t"); string(v) != "the-real-value-42" {
		t.Fatalf("whitespace not trimmed: %q", v)
	}

	// A fresh client can't get in without logging in.
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r2, _ := anon.Get(h.ts.URL + "/")
	if r2.StatusCode != http.StatusSeeOther {
		t.Fatalf("anonymous dashboard: %d", r2.StatusCode)
	}
}

func TestLoginLockout(t *testing.T) {
	h := newHarness(t)
	h.setup()
	anon := &http.Client{}
	for i := 0; i < 5; i++ {
		resp, _ := anon.PostForm(h.ts.URL+"/login", url.Values{"password": {"nope"}, "code": {"000000"}})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := anon.PostForm(h.ts.URL+"/login", url.Values{"password": {"a long enough password"}, "code": {"000000"}})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("not locked out: %d", resp.StatusCode)
	}
}

func TestNamespaceIsolation(t *testing.T) {
	h := newHarness(t)
	h.setup()
	lab, _ := h.st.CreateToken("lab-agent", []string{"lab"}, false)
	wed, _ := h.st.CreateToken("wedding-agent", []string{"wedding"}, true)
	h.st.PutValue("lab", "cf", []byte("lab-secret-value"), &store.Meta{Description: "lab only"})
	h.st.PutValue("wedding", "convex", []byte("wedding-secret-value"), nil)

	// Each agent lists only its own namespace.
	_, _, raw := h.api("GET", "/api/v1/secrets", wed, nil)
	if strings.Contains(string(raw), "lab") || !strings.Contains(string(raw), "wedding/convex") {
		t.Fatalf("wedding list: %s", raw)
	}
	// Other namespaces look missing, not forbidden.
	if code, _, _ := h.api("POST", "/api/v1/secrets/lab/cf/reveal", wed, nil); code != http.StatusNotFound {
		t.Fatalf("cross-namespace reveal: %d", code)
	}
	if code, _, _ := h.api("GET", "/api/v1/secrets/lab/cf", wed, nil); code != http.StatusNotFound {
		t.Fatalf("cross-namespace info: %d", code)
	}
	// Reveal works in-namespace and is logged.
	code, m, _ := h.api("POST", "/api/v1/secrets/lab/cf/reveal", lab, nil)
	if code != 200 || m["value"] != "lab-secret-value" {
		t.Fatalf("reveal: %d %v", code, m)
	}
	// Metadata never carries the value.
	_, _, raw = h.api("GET", "/api/v1/secrets/lab/cf", lab, nil)
	if strings.Contains(string(raw), "lab-secret-value") {
		t.Fatal("value in metadata")
	}
	// Writes need the write grant, in an allowed namespace.
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/new", lab, map[string]any{"value": "x-123456"}); code != http.StatusForbidden {
		t.Fatalf("read-only token wrote: %d", code)
	}
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/new", wed, map[string]any{"value": "x-123456"}); code != http.StatusForbidden {
		t.Fatalf("wrote outside namespace: %d", code)
	}
	if code, _, _ := h.api("PUT", "/api/v1/secrets/wedding/gen", wed, map[string]any{"value": "x-123456"}); code != 200 {
		t.Fatalf("write: %d", code)
	}
	if code, _, _ := h.api("PUT", "/api/v1/secrets/wedding/gen", wed, map[string]any{"value": "y-123456"}); code != http.StatusConflict {
		t.Fatalf("silent overwrite: %d", code)
	}
	// Bad and missing tokens.
	if code, _, _ := h.api("GET", "/api/v1/secrets", "kd_nope", nil); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	if code, _, _ := h.api("GET", "/api/v1/secrets", "", nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
}

func TestRequestFlow(t *testing.T) {
	h := newHarness(t)
	h.setup()
	tok, _ := h.st.CreateToken("claude", []string{"lab"}, false)
	code, m, _ := h.api("POST", "/api/v1/requests", tok, map[string]string{"name": "gh-pat", "description": "repo read"})
	if code != http.StatusCreated || m["ref"] != "lab/gh-pat" {
		t.Fatalf("request: %d %v", code, m)
	}
	if code, _, _ := h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "wedding", "name": "x"}); code != http.StatusForbidden {
		t.Fatalf("request outside namespace: %d", code)
	}
	if _, body := h.get("/"); !strings.Contains(body, "Requested by agents") || !strings.Contains(body, "lab/gh-pat") {
		t.Fatal("request not on dashboard")
	}
	resp := h.post("/secret/lab/gh-pat/value", url.Values{"csrf": {h.csrf()}, "value": {"ghp_filled_in"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("fill: %d", resp.StatusCode)
	}
	_, m, _ = h.api("GET", "/api/v1/secrets/lab/gh-pat", tok, nil)
	if m["pending"] != false || m["has_value"] != true || m["new"] != true {
		t.Fatalf("after fill: %v", m)
	}
	h.api("POST", "/api/v1/secrets/lab/gh-pat/ack", tok, nil)
	_, m, _ = h.api("GET", "/api/v1/secrets/lab/gh-pat", tok, nil)
	if m["new"] != false {
		t.Fatalf("ack didn't clear new: %v", m)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	resp, _ := http.Get(h.ts.URL + "/login")
	for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if resp.Header.Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("pages must not be cached")
	}
}
