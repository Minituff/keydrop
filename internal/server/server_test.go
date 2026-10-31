package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
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

// setup completes first-run setup with an authenticator and leaves the
// client logged in.
func (h *harness) setup() {
	h.t.Helper()
	code, seed := h.srv.setupCode, h.srv.setupSeed
	resp := h.post("/setup", url.Values{
		"code": {code}, "password": {"a long enough password"}, "password2": {"a long enough password"},
		"mfa": {"totp"}, "totp": {totpNow(seed, time.Now())},
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
	if code, _ := h.get("/setup?code=WRONG1"); code != http.StatusForbidden {
		t.Fatalf("bad setup code: %d", code)
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
	for _, p := range []string{"/", "/secret/lab/CF", "/audit", "/tokens"} {
		if _, body := h.get(p); strings.Contains(body, "the-real-value-42") {
			t.Fatalf("value shown on %s", p)
		}
	}
	if v, _, _ := h.st.Reveal("lab", "CF", "t"); string(v) != "the-real-value-42" {
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
		resp, _ := anon.PostForm(h.ts.URL+"/login", url.Values{"password": {"nope"}, "totp": {"000000"}})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := anon.PostForm(h.ts.URL+"/login", url.Values{"password": {"a long enough password"}, "totp": {"000000"}})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("not locked out: %d", resp.StatusCode)
	}
}

func TestNamespaceIsolation(t *testing.T) {
	h := newHarness(t)
	h.setup()
	lab, _ := h.st.CreateToken("lab-agent", []string{"lab"}, false, nil)
	wed, _ := h.st.CreateToken("wedding-agent", []string{"wedding"}, true, nil)
	h.st.PutValue("lab", "CF", []byte("lab-secret-value"), &store.Meta{Description: "lab only"})
	h.st.PutValue("wedding", "CONVEX", []byte("wedding-secret-value"), nil)

	// Each agent lists only its own namespace.
	_, _, raw := h.api("GET", "/api/v1/secrets", wed, nil)
	if strings.Contains(string(raw), "lab") || !strings.Contains(string(raw), "wedding/CONVEX") {
		t.Fatalf("wedding list: %s", raw)
	}
	// Other namespaces look missing, not forbidden.
	if code, _, _ := h.api("POST", "/api/v1/secrets/lab/CF/reveal", wed, nil); code != http.StatusNotFound {
		t.Fatalf("cross-namespace reveal: %d", code)
	}
	if code, _, _ := h.api("GET", "/api/v1/secrets/lab/CF", wed, nil); code != http.StatusNotFound {
		t.Fatalf("cross-namespace info: %d", code)
	}
	// Reveal works in-namespace and is logged.
	code, m, _ := h.api("POST", "/api/v1/secrets/lab/CF/reveal", lab, nil)
	if code != 200 || m["value"] != "lab-secret-value" {
		t.Fatalf("reveal: %d %v", code, m)
	}
	// Metadata never carries the value.
	_, _, raw = h.api("GET", "/api/v1/secrets/lab/CF", lab, nil)
	if strings.Contains(string(raw), "lab-secret-value") {
		t.Fatal("value in metadata")
	}
	// Writes need the write grant, in an allowed namespace.
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/NEW", lab, map[string]any{"value": "x-123456"}); code != http.StatusForbidden {
		t.Fatalf("read-only token wrote: %d", code)
	}
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/NEW", wed, map[string]any{"value": "x-123456"}); code != http.StatusForbidden {
		t.Fatalf("wrote outside namespace: %d", code)
	}
	if code, _, _ := h.api("PUT", "/api/v1/secrets/wedding/GEN", wed, map[string]any{"value": "x-123456"}); code != 200 {
		t.Fatalf("write: %d", code)
	}
	if code, _, _ := h.api("PUT", "/api/v1/secrets/wedding/GEN", wed, map[string]any{"value": "y-123456"}); code != http.StatusConflict {
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
	tok, _ := h.st.CreateToken("claude", []string{"lab"}, false, nil)
	code, m, _ := h.api("POST", "/api/v1/requests", tok, map[string]string{"name": "GH_PAT", "description": "repo read"})
	if code != http.StatusCreated || m["ref"] != "lab/GH_PAT" {
		t.Fatalf("request: %d %v", code, m)
	}
	if code, _, _ := h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "wedding", "name": "x"}); code != http.StatusForbidden {
		t.Fatalf("request outside namespace: %d", code)
	}
	if _, body := h.get("/"); !strings.Contains(body, "Requested by agents") || !strings.Contains(body, "lab/GH_PAT") {
		t.Fatal("request not on dashboard")
	}
	resp := h.post("/secret/lab/GH_PAT/value", url.Values{"csrf": {h.csrf()}, "value": {"ghp_filled_in"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("fill: %d", resp.StatusCode)
	}
	_, m, _ = h.api("GET", "/api/v1/secrets/lab/GH_PAT", tok, nil)
	if m["pending"] != false || m["has_value"] != true || m["new"] != true {
		t.Fatalf("after fill: %v", m)
	}
	h.api("POST", "/api/v1/secrets/lab/GH_PAT/ack", tok, nil)
	_, m, _ = h.api("GET", "/api/v1/secrets/lab/GH_PAT", tok, nil)
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

func TestSetupCode(t *testing.T) {
	h := newHarness(t)
	// Before setup, the dashboard and login send you to setup.
	for _, p := range []string{"/", "/login"} {
		resp, _ := h.web.Get(h.ts.URL + p)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
			t.Fatalf("%s before setup: %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	seed := auth.TOTPBase32(h.srv.setupSeed)
	// Without a code, setup asks for one and doesn't show the authenticator
	// key (it would let a bystander copy the admin's second factor).
	code, body := h.get("/setup")
	if code != 200 || !strings.Contains(body, `name="code"`) || strings.Contains(body, seed) {
		t.Fatalf("code step: %d", code)
	}
	if c := h.srv.setupCode; len(c) != 6 || strings.ContainsAny(c, "01OI") {
		t.Fatalf("setup code %q", c)
	}
	// The code is forgiving about case, spaces and the dash.
	typed := strings.ToLower(displayCode(h.srv.setupCode))
	code, body = h.get("/setup?code=" + url.QueryEscape(" "+typed))
	if code != 200 || !strings.Contains(body, seed) || !strings.Contains(body, "<svg") {
		t.Fatalf("account step: %d", code)
	}
	// A wrong code on submit is refused too.
	resp := h.post("/setup", url.Values{"code": {"AAAAAA"}, "password": {"a long enough password"}, "password2": {"a long enough password"}, "mfa": {"none"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong code on submit: %d", resp.StatusCode)
	}
	// Guessing is rate-limited (one wrong guess above, plus these).
	for i := 0; i < 4; i++ {
		h.get("/setup?code=BBBBBB")
	}
	if code, _ := h.get("/setup?code=" + h.srv.setupCode); code != http.StatusTooManyRequests {
		t.Fatalf("not locked out: %d", code)
	}
}

func TestPasswordOnlyAndTOTPSettings(t *testing.T) {
	h := newHarness(t)
	resp := h.post("/setup", url.Values{"code": {h.srv.setupCode}, "password": {"a long enough password"}, "password2": {"a long enough password"}, "mfa": {"none"}})
	if resp.StatusCode != http.StatusSeeOther || h.st.TOTPEnabled() {
		t.Fatalf("password-only setup: %d", resp.StatusCode)
	}
	login := func(totp string) int {
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, _ := c.PostForm(h.ts.URL+"/login", url.Values{"password": {"a long enough password"}, "totp": {totp}})
		return resp.StatusCode
	}
	if _, body := h.get("/login"); strings.Contains(body, `name="totp"`) {
		t.Fatal("login asks for a code with the authenticator off")
	}
	if c := login(""); c != http.StatusSeeOther {
		t.Fatalf("password-only login: %d", c)
	}

	// Turning it on shows a new seed, and only a code from it switches it on.
	csrf := h.csrf()
	h.post("/settings/totp/start", url.Values{"csrf": {csrf}})
	h.srv.mu.Lock()
	var seed []byte
	for _, se := range h.srv.sessions {
		if se.csrf == csrf {
			seed = se.newTOTP
		}
	}
	h.srv.mu.Unlock()
	if seed == nil {
		t.Fatal("no pending seed")
	}
	if resp := h.post("/settings/totp/on", url.Values{"csrf": {csrf}, "totp": {"000000"}}); resp.StatusCode != http.StatusBadRequest || h.st.TOTPEnabled() {
		t.Fatalf("wrong code turned it on: %d", resp.StatusCode)
	}
	if resp := h.post("/settings/totp/on", url.Values{"csrf": {csrf}, "totp": {totpNow(seed, time.Now())}}); resp.StatusCode != http.StatusSeeOther || !h.st.TOTPEnabled() {
		t.Fatalf("turn on: %d", resp.StatusCode)
	}
	if c := login(""); c != http.StatusUnauthorized {
		t.Fatalf("login without code after turning on: %d", c)
	}

	// Turning it off needs the password.
	if resp := h.post("/settings/totp/off", url.Values{"csrf": {csrf}, "password": {"wrong password!"}}); resp.StatusCode != http.StatusUnauthorized || !h.st.TOTPEnabled() {
		t.Fatalf("off with wrong password: %d", resp.StatusCode)
	}
	if resp := h.post("/settings/totp/off", url.Values{"csrf": {csrf}, "password": {"a long enough password"}}); resp.StatusCode != http.StatusSeeOther || h.st.TOTPEnabled() {
		t.Fatalf("turn off: %d", resp.StatusCode)
	}
}

func TestRevealInUI(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "CF", []byte("shown-on-request-42"), nil)
	// Only shown after a deliberate POST with the CSRF token.
	if _, body := h.get("/secret/lab/CF"); strings.Contains(body, "shown-on-request-42") {
		t.Fatal("value shown without asking")
	}
	if resp := h.post("/secret/lab/CF/reveal", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reveal without csrf: %d", resp.StatusCode)
	}
	resp := h.post("/secret/lab/CF/reveal", url.Values{"csrf": {h.csrf()}})
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "shown-on-request-42") {
		t.Fatalf("reveal: %d", resp.StatusCode)
	}
	if _, body := h.get("/audit"); !strings.Contains(body, "secret.reveal") {
		t.Fatal("reveal not in the log")
	}
	if sec, _ := h.st.GetSecret("lab", "CF"); sec.LastReadBy != "admin (web)" {
		t.Fatalf("last read by %q", sec.LastReadBy)
	}
}

func TestSecretNames(t *testing.T) {
	h := newHarness(t)
	h.setup()
	csrf := h.csrf()
	// The UI upper-cases what was typed, so a phone keyboard is fine.
	resp := h.post("/secrets", url.Values{"csrf": {csrf}, "namespace": {"lab"}, "name": {"cf_api_token"}, "value": {"value-123456"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/secret/lab/CF_API_TOKEN?msg=saved" {
		t.Fatalf("lower-case name: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, bad := range []string{"cloudflare-dns", "2FA", "A.B", "A B"} {
		if resp := h.post("/secrets", url.Values{"csrf": {csrf}, "namespace": {"lab"}, "name": {bad}, "value": {"value-123456"}}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: got %d", bad, resp.StatusCode)
		}
	}
	tok, _ := h.st.CreateToken("agent", []string{"lab"}, true, nil)
	if code, _, _ := h.api("POST", "/api/v1/requests", tok, map[string]string{"name": "gh-pat"}); code != http.StatusBadRequest {
		t.Errorf("API request with old-style name: %d", code)
	}
	if code, _, raw := h.api("PUT", "/api/v1/secrets/lab/cf_token", tok, map[string]any{"value": "fake-put-value-1"}); code != http.StatusBadRequest || strings.Contains(string(raw), "fake-put-value-1") {
		t.Errorf("API put with lower-case name: %d %s", code, raw)
	}
}

func TestVariables(t *testing.T) {
	h := newHarness(t)
	h.setup()
	csrf := h.csrf()
	h.post("/secrets", url.Values{"csrf": {csrf}, "namespace": {"lab"}, "name": {"API_URL"}, "kind": {"variable"}, "value": {"https://api.example.test"}})
	h.post("/secrets", url.Values{"csrf": {csrf}, "namespace": {"lab"}, "name": {"API_KEY"}, "value": {"fake-secret-value-77"}})

	// The page shows variables' values in their own section, never secrets'.
	_, body := h.get("/")
	if !strings.Contains(body, "https://api.example.test") || strings.Contains(body, "fake-secret-value-77") {
		t.Fatal("dashboard: variable value missing or secret value shown")
	}
	if i, j := strings.Index(body, "<h1>Variables</h1>"), strings.Index(body, "https://api.example.test"); i < 0 || j < i {
		t.Fatal("variable not under the Variables heading")
	}
	if _, body := h.get("/secret/lab/API_URL"); !strings.Contains(body, "https://api.example.test") {
		t.Fatal("variable page doesn't show the value")
	}

	// The API lists a variable's value, never a secret's.
	tok, _ := h.st.CreateToken("agent", []string{"lab"}, true, nil)
	_, _, raw := h.api("GET", "/api/v1/secrets", tok, nil)
	var list []APISecret
	json.Unmarshal(raw, &list)
	for _, s := range list {
		switch s.Name {
		case "API_URL":
			if s.Kind != "variable" || s.Value == nil || *s.Value != "https://api.example.test" {
				t.Errorf("variable in list: %+v", s)
			}
		case "API_KEY":
			if s.Kind != "secret" || s.Value != nil {
				t.Errorf("secret in list: %+v", s)
			}
		}
	}
	if strings.Contains(string(raw), "fake-secret-value-77") {
		t.Fatal("secret value in list response")
	}

	// Reading a variable isn't logged; reading a secret is.
	before := len(h.srv.audit.Recent(100))
	if _, m, _ := h.api("POST", "/api/v1/secrets/lab/API_URL/reveal", tok, nil); m["kind"] != "variable" {
		t.Fatalf("variable reveal: %v", m)
	}
	if n := len(h.srv.audit.Recent(100)); n != before {
		t.Fatal("variable read was logged")
	}
	if sec, _ := h.st.GetSecret("lab", "API_URL"); sec.LastReadAt != nil {
		t.Fatal("variable read recorded")
	}
	h.api("POST", "/api/v1/secrets/lab/API_KEY/reveal", tok, nil)
	if n := len(h.srv.audit.Recent(100)); n != before+1 {
		t.Fatal("secret read not logged")
	}

	// Agents can store variables, but the kind is never inherited: a value
	// written over a variable without "variable" is a secret (a generated
	// password mustn't end up listed), and the change is logged.
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/DB_USER", tok, map[string]any{"value": "keydrop", "variable": true}); code != 200 {
		t.Fatalf("put variable: %d", code)
	}
	h.api("PUT", "/api/v1/secrets/lab/DB_USER", tok, map[string]any{"value": "fake-generated-pw", "overwrite": true})
	if sec, _ := h.st.GetSecret("lab", "DB_USER"); sec.Variable {
		t.Fatal("a value written over a variable stayed a variable")
	}
	if ev := h.srv.audit.Recent(1); len(ev) != 1 || ev[0].Action != "secret.kind" {
		t.Fatalf("API kind change not logged: %+v", ev)
	}

	// Switching kind in the UI is logged.
	h.post("/secret/lab/API_URL/meta", url.Values{"csrf": {csrf}, "kind": {"secret"}})
	if sec, _ := h.st.GetSecret("lab", "API_URL"); sec.Variable {
		t.Fatal("kind not changed")
	}
	if _, body := h.get("/audit"); !strings.Contains(body, "secret.kind") {
		t.Fatal("kind change not logged")
	}
}

func TestChangePassword(t *testing.T) {
	h := newHarness(t)
	h.post("/setup", url.Values{"code": {h.srv.setupCode}, "password": {"a long enough password"}, "password2": {"a long enough password"}, "mfa": {"none"}})
	jar, _ := cookiejar.New(nil)
	other := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	other.PostForm(h.ts.URL+"/login", url.Values{"password": {"a long enough password"}})
	if resp, _ := other.Get(h.ts.URL + "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("second session: %d", resp.StatusCode)
	}

	csrf := h.csrf()
	change := func(cur, pw, pw2 string) int {
		return h.post("/settings/password", url.Values{"csrf": {csrf}, "current": {cur}, "password": {pw}, "password2": {pw2}}).StatusCode
	}
	if c := change("wrong password!!", "a brand new password", "a brand new password"); c != http.StatusUnauthorized {
		t.Fatalf("wrong current password: %d", c)
	}
	if c := change("a long enough password", "short", "short"); c != http.StatusBadRequest {
		t.Fatalf("short password: %d", c)
	}
	if c := change("a long enough password", "a brand new password", "a different one!!"); c != http.StatusBadRequest {
		t.Fatalf("mismatch: %d", c)
	}
	u, _ := url.Parse(h.ts.URL)
	oldCookies := h.web.Jar.Cookies(u)
	if c := change("a long enough password", "a brand new password", "a brand new password"); c != http.StatusSeeOther {
		t.Fatalf("change: %d", c)
	}
	if code, _ := h.get("/"); code != http.StatusOK {
		t.Fatal("this browser didn't get a new session")
	}
	// The session the change was made from is replaced too, in case it's
	// the one that leaked.
	oldJar, _ := cookiejar.New(nil)
	oldJar.SetCookies(u, oldCookies)
	old := &http.Client{Jar: oldJar, CheckRedirect: other.CheckRedirect}
	if resp, _ := old.Get(h.ts.URL + "/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("the old session cookie still works")
	}
	if resp, _ := other.Get(h.ts.URL + "/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("other session still logged in")
	}
	fresh := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if resp, _ := fresh.PostForm(h.ts.URL+"/login", url.Values{"password": {"a long enough password"}}); resp.StatusCode == http.StatusSeeOther {
		t.Fatal("old password still works")
	}
	if resp, _ := fresh.PostForm(h.ts.URL+"/login", url.Values{"password": {"a brand new password"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("new password: %d", resp.StatusCode)
	}
}

// apiFrom is api() as if from ip, via a trusted proxy header.
func (h *harness) apiFrom(ip, method, path, token, label string, body any) (int, map[string]any) {
	h.srv.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(b))
	req.Header.Set("X-Forwarded-For", ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if label != "" {
		req.Header.Set("X-Keydrop-Agent", label)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestPairing(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "FAKE_KEY", []byte("fake-pair-value-1"), nil)

	code, m := h.apiFrom("10.0.0.5", "POST", "/api/v1/pair", "", "", map[string]string{"host": "Homelab-Agent.lan", "user": "agent<script>"})
	if code != http.StatusCreated {
		t.Fatalf("pair start: %d %v", code, m)
	}
	poll, path, shown := m["poll"].(string), m["path"].(string), m["code"].(string)
	if _, m := h.apiFrom("10.0.0.5", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": poll}); m["state"] != "pending" {
		t.Fatalf("poll before approval: %v", m)
	}
	// The token only goes back to the address that asked; another address
	// is told so (not "expired"), and it's logged.
	if code, _ := h.apiFrom("10.0.0.6", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": poll}); code != http.StatusForbidden {
		t.Fatalf("poll from another address: %d", code)
	}
	if ev := h.srv.audit.Recent(1)[0]; ev.Action != "pair.wrongaddr" || strings.Contains(ev.Detail+ev.Target, poll) {
		t.Fatalf("wrong-address poll not logged, or logged the secret: %+v", ev)
	}

	if _, body := h.get("/tokens"); !strings.Contains(body, shown) || !strings.Contains(body, path) {
		t.Fatal("pending pairing not listed on the Agents page")
	}
	_, body := h.get(path)
	for _, want := range []string{shown, "10.0.0.5", `value="homelab-agent.lan"`, `value="10.0.0.5"`} {
		if !strings.Contains(body, want) {
			t.Errorf("approval page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>") {
		t.Fatal("claimed user not cleaned")
	}

	csrf := h.csrf()
	approve := func(form url.Values) int {
		form.Set("csrf", csrf)
		return h.post(path+"/approve", form).StatusCode
	}
	if c := approve(url.Values{"name": {"box"}, "namespaces": {"lab"}, "sources": {"10.0.0.300"}}); c != http.StatusBadRequest {
		t.Fatalf("bad source accepted: %d", c)
	}
	if c := approve(url.Values{"name": {"box"}, "namespaces": {"lab"}, "sources": {"10.0.0.5"}}); c != http.StatusSeeOther {
		t.Fatalf("approve: %d", c)
	}
	if c, _ := h.get(path); c != http.StatusNotFound {
		t.Fatal("approved request can still be opened")
	}
	if c := approve(url.Values{"name": {"box2"}, "namespaces": {"lab"}}); c != http.StatusNotFound {
		t.Fatal("approved twice")
	}

	_, m = h.apiFrom("10.0.0.5", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": poll})
	tok, _ := m["token"].(string)
	if m["state"] != "approved" || !strings.HasPrefix(tok, "kd_") || m["name"] != "box" {
		t.Fatalf("collect: %v", m)
	}
	if code, _ := h.apiFrom("10.0.0.5", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": poll}); code != http.StatusNotFound {
		t.Fatal("token handed out twice")
	}

	// Allowed sources: the paired address works, others are refused and logged.
	if code, m := h.apiFrom("10.0.0.5", "POST", "/api/v1/secrets/lab/FAKE_KEY/reveal", tok, "claude", nil); code != 200 || m["value"] != "fake-pair-value-1" {
		t.Fatalf("from the paired address: %d %v", code, m)
	}
	if ev := h.srv.audit.Recent(1)[0]; ev.Actor != "token:box (claude)" {
		t.Fatalf("agent label not in the log: %+v", ev)
	}
	code, m = h.apiFrom("10.0.0.6", "POST", "/api/v1/secrets/lab/FAKE_KEY/reveal", tok, "", nil)
	if code != http.StatusForbidden || m["value"] != nil {
		t.Fatalf("from another address: %d %v", code, m)
	}
	if ev := h.srv.audit.Recent(1)[0]; ev.Action != "token.denied" || ev.Actor != "token:box" {
		t.Fatalf("denied use not logged: %+v", ev)
	}
	// A label that isn't a plain name is dropped, not logged verbatim.
	h.apiFrom("10.0.0.5", "GET", "/api/v1/whoami", tok, "evil fake line", nil)
	h.apiFrom("10.0.0.5", "POST", "/api/v1/secrets/lab/FAKE_KEY/ack", tok, "evil)(x", nil)
	if ev := h.srv.audit.Recent(1)[0]; ev.Actor != "token:box" {
		t.Fatalf("bad label logged: %+v", ev)
	}

	// The admin can widen the sources.
	h.post("/tokens/box/sources", url.Values{"csrf": {csrf}, "sources": {"10.0.0.0/24"}})
	if code, _ := h.apiFrom("10.0.0.6", "GET", "/api/v1/whoami", tok, "", nil); code != 200 {
		t.Fatalf("after widening sources: %d", code)
	}
	if r := h.post("/tokens/box/sources", url.Values{"csrf": {csrf}, "sources": {"lan"}}); r.StatusCode != http.StatusBadRequest {
		t.Fatal("bad source saved")
	}

	// Re-pairing under an existing name needs "replace", which revokes the old token.
	_, m = h.apiFrom("10.0.0.5", "POST", "/api/v1/pair", "", "", map[string]string{"host": "box"})
	path = m["path"].(string)
	if c := approve(url.Values{"name": {"box"}, "namespaces": {"lab"}}); c != http.StatusConflict {
		t.Fatalf("existing name without replace: %d", c)
	}
	if c := approve(url.Values{"name": {"box"}, "namespaces": {"lab"}, "replace": {"yes"}}); c != http.StatusSeeOther {
		t.Fatalf("replace: %d", c)
	}
	if code, _ := h.apiFrom("10.0.0.5", "GET", "/api/v1/whoami", tok, "", nil); code != http.StatusUnauthorized {
		t.Fatal("replaced token still works")
	}
	// Replace with a bad namespace is refused before the old token is revoked.
	_, m = h.apiFrom("10.0.0.5", "POST", "/api/v1/pair", "", "", map[string]string{"host": "keep"})
	keepPath, keepPoll := m["path"].(string), m["poll"].(string)
	path = keepPath
	approve(url.Values{"name": {"keep"}, "namespaces": {"lab"}})
	_, m = h.apiFrom("10.0.0.5", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": keepPoll})
	keepTok := m["token"].(string)
	_, m = h.apiFrom("10.0.0.5", "POST", "/api/v1/pair", "", "", map[string]string{"host": "keep"})
	path = m["path"].(string)
	if c := approve(url.Values{"name": {"keep"}, "namespaces": {"Lab"}, "replace": {"yes"}}); c != http.StatusBadRequest {
		t.Fatalf("bad namespace on replace: %d", c)
	}
	if code, _ := h.apiFrom("10.0.0.5", "GET", "/api/v1/whoami", keepTok, "", nil); code != 200 {
		t.Fatal("a refused replace revoked the old token")
	}
	h.post(path+"/deny", url.Values{"csrf": {csrf}})

	// Deny.
	_, m = h.apiFrom("10.0.0.7", "POST", "/api/v1/pair", "", "", map[string]string{"host": "x"})
	h.post(m["path"].(string)+"/deny", url.Values{"csrf": {csrf}})
	if code, _ := h.apiFrom("10.0.0.7", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": m["poll"].(string)}); code != http.StatusNotFound {
		t.Fatal("denied request still pollable")
	}

	// IPv6: the cap counts the /64, and the pre-fill drops the zone.
	for i := 1; i <= 3; i++ {
		h.apiFrom(fmt.Sprintf("2001:db8::%d", i), "POST", "/api/v1/pair", "", "", map[string]string{})
	}
	if code, _ := h.apiFrom("2001:db8::ff", "POST", "/api/v1/pair", "", "", map[string]string{}); code != http.StatusTooManyRequests {
		t.Fatalf("fourth request from one /64: %d", code)
	}
	if got := sourcePrefill("fe80::1%eth0"); got != "fe80::1" {
		t.Fatalf("pre-fill %q", got)
	}
	if got := sourcePrefill("::ffff:10.0.0.5"); got != "10.0.0.5" {
		t.Fatalf("pre-fill %q", got)
	}
	for _, p := range h.srv.pendingPairings() {
		if strings.HasPrefix(p.IP, "2001:db8::") {
			h.post("/pair/"+p.ID+"/deny", url.Values{"csrf": {csrf}})
		}
	}

	// Caps: three waiting per address.
	for i := 0; i < 3; i++ {
		h.apiFrom("10.0.0.9", "POST", "/api/v1/pair", "", "", map[string]string{})
	}
	if code, _ := h.apiFrom("10.0.0.9", "POST", "/api/v1/pair", "", "", map[string]string{}); code != http.StatusTooManyRequests {
		t.Fatalf("fourth request from one address: %d", code)
	}

	// An approved token nobody collects is revoked when the request expires.
	_, m = h.apiFrom("10.0.0.8", "POST", "/api/v1/pair", "", "", map[string]string{"host": "late"})
	path = m["path"].(string)
	approve(url.Values{"name": {"late"}, "namespaces": {"lab"}})
	if _, ok := tokenNamed(h.st.ListTokens(), "late"); !ok {
		t.Fatal("approval didn't create the token")
	}
	h.srv.now = func() time.Time { return time.Now().Add(pairTTL + time.Minute) }
	h.srv.pendingPairings()
	if _, ok := tokenNamed(h.st.ListTokens(), "late"); ok {
		t.Fatal("uncollected token survived expiry")
	}
	if code, _ := h.apiFrom("10.0.0.9", "POST", "/api/v1/pair", "", "", map[string]string{}); code != http.StatusCreated {
		t.Fatal("expired requests still count against the cap")
	}
}

// An uncollected approval mustn't revoke a newer token of the same name,
// and must still be revoked if the server restarts before it expires.
func TestPairingUncollected(t *testing.T) {
	h := newHarness(t)
	h.setup()
	csrf := h.csrf()
	start := time.Now()
	h.srv.now = func() time.Time { return start }
	pair := func(host string, form url.Values) string {
		_, m := h.apiFrom("10.0.0.5", "POST", "/api/v1/pair", "", "", map[string]string{"host": host})
		form.Set("csrf", csrf)
		if c := h.post(m["path"].(string)+"/approve", form).StatusCode; c != http.StatusSeeOther {
			t.Fatalf("approve: %d", c)
		}
		return m["poll"].(string)
	}
	pollA := pair("box", url.Values{"name": {"box"}, "namespaces": {"lab"}})
	h.srv.now = func() time.Time { return start.Add(5 * time.Minute) }
	pollB := pair("box", url.Values{"name": {"box"}, "namespaces": {"lab"}, "replace": {"yes"}})
	_, m := h.apiFrom("10.0.0.5", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": pollB})
	tokB, _ := m["token"].(string)
	if tokB == "" {
		t.Fatalf("collect B: %v", m)
	}
	// A's token was replaced: collecting it fails instead of handing out a dead token.
	if code, _ := h.apiFrom("10.0.0.5", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": pollA}); code != http.StatusNotFound {
		t.Fatalf("collect replaced A: %d", code)
	}
	h.srv.now = func() time.Time { return start.Add(pairTTL + 6*time.Minute) }
	h.srv.pendingPairings()
	if code, _ := h.apiFrom("10.0.0.5", "GET", "/api/v1/whoami", tokB, "", nil); code != 200 {
		t.Fatalf("A's expiry revoked B's collected token: %d", code)
	}

	// Approved, then a restart loses the request: the token is still revoked.
	h.srv.now = time.Now
	pair("gone", url.Values{"name": {"gone"}, "namespaces": {"lab"}})
	h.srv = New(h.srv.cfg, h.st, h.srv.audit) // as after a restart
	h.srv.now = func() time.Time { return time.Now().Add(pairTTL + time.Minute) }
	h.srv.pendingPairings()
	if _, ok := tokenNamed(h.st.ListTokens(), "gone"); ok {
		t.Fatal("uncollected token survived a restart")
	}
	if _, ok := tokenNamed(h.st.ListTokens(), "box"); !ok {
		t.Fatal("collected token revoked")
	}
}
