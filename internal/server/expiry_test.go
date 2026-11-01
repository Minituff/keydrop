package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// clock is a settable time shared by the server and its store.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (h *harness) clock() *clock {
	c := &clock{t: time.Now()}
	h.srv.now = c.now
	h.st.SetClock(c.now)
	return c
}

// tokenWithLifetime makes a token through the Agents form.
func (h *harness) tokenWithLifetime(name, ns, lifetime string) (int, string) {
	h.t.Helper()
	resp := h.post("/tokens", url.Values{"csrf": {h.csrf()}, "name": {name}, "namespaces": {ns}, "lifetime": {lifetime}})
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, tokenRE.FindString(string(b))
}

func (h *harness) auditHas(action, detail string) bool {
	h.t.Helper()
	for _, e := range h.srv.audit.Recent(1000) {
		if e.Action == action && strings.Contains(e.Detail, detail) {
			return true
		}
	}
	return false
}

func TestTokenLifetimeForms(t *testing.T) {
	h := newHarness(t)
	h.setup()
	if code, _ := h.tokenWithLifetime("bad", "lab", "7"); code != http.StatusBadRequest {
		t.Fatalf("7 days: %d", code)
	}
	for life, want := range map[string]int{"0": 0, "30": 30, "365": 365, "": store.DefaultTokenLifetime} {
		name := "t" + life
		if life == "" {
			name = "tdefault"
		}
		code, tok := h.tokenWithLifetime(name, "lab", life)
		if code != http.StatusOK || tok == "" {
			t.Fatalf("lifetime %q: %d", life, code)
		}
		_, m, _ := h.api("GET", "/api/v1/whoami", tok, nil)
		exp, has := m["expires_at"]
		switch {
		case !has:
			t.Fatalf("lifetime %q: no expires_at", life)
		case want == 0 && exp != nil:
			t.Fatalf("never: %v", exp)
		case want != 0:
			at, err := time.Parse(time.RFC3339, exp.(string))
			if err != nil || at.Sub(time.Now()) < time.Duration(want)*24*time.Hour-time.Minute || at.Sub(time.Now()) > time.Duration(want)*24*time.Hour {
				t.Fatalf("lifetime %q: %v", life, exp)
			}
		}
	}
	_, body := h.get("/tokens")
	for _, s := range []string{"no expiry", "expires in 30 days", "expires in 90 days", "Renew"} {
		if !strings.Contains(body, s) {
			t.Fatalf("Agents page lacks %q", s)
		}
	}
}

// An expired token looks exactly like an unknown one, except in the log.
func TestExpiredToken(t *testing.T) {
	h := newHarness(t)
	h.setup()
	c := h.clock()
	_, tok := h.tokenWithLifetime("bot", "lab", "30")
	resp, err := http.DefaultClient.Do(authed("GET", h.ts.URL+"/api/v1/whoami", tok))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Keydrop-Token-Expires") == "" {
		t.Fatal("no expiry header")
	}
	c.add(31 * 24 * time.Hour)
	code, _, expired := h.api("GET", "/api/v1/secrets", tok, nil)
	_, _, unknown := h.api("GET", "/api/v1/secrets", "kd_not-a-real-token", nil)
	if code != http.StatusUnauthorized || string(expired) != string(unknown) {
		t.Fatalf("expired: %d %s, unknown: %s", code, expired, unknown)
	}
	if !h.auditHas("token.expired", "token expired") {
		t.Fatal("expiry not in the log")
	}
	// The renewal endpoints still answer during the grace window.
	if code, m, _ := h.api("GET", "/api/v1/token/renew", tok, nil); code != 200 || m["state"] != "none" {
		t.Fatalf("renew status: %d %v", code, m)
	}
	// Still listed (the admin's session has expired by now, so the view).
	if v := h.srv.tokenViews(); len(v) != 1 || !v[0].Expired || !strings.HasPrefix(v[0].Expiry, "expired ") {
		t.Fatalf("expired token not listed: %+v", v)
	}
	// Past the grace window, nothing.
	c.add(store.RenewalGrace)
	if code, _, _ := h.api("POST", "/api/v1/token/renew", tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("renew past grace: %d", code)
	}
}

func authed(method, u, tok string) *http.Request {
	req, _ := http.NewRequest(method, u, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	return req
}

// webhook is a local alert receiver.
type webhook struct {
	mu     sync.Mutex
	bodies []string
}

func (h *harness) webhook() *webhook {
	wh := &webhook{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		wh.mu.Lock()
		wh.bodies = append(wh.bodies, string(b))
		wh.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	h.t.Cleanup(ts.Close)
	h.srv.alerts = newAlerter(ts.URL)
	return wh
}

func (wh *webhook) all(a *alerter) []string {
	a.wg.Wait()
	wh.mu.Lock()
	defer wh.mu.Unlock()
	return append([]string(nil), wh.bodies...)
}

// The whole renewal: request, approval, collect (repeatable after a lost
// answer, only from the address that asked), first use of the new token.
func TestRenewalFlow(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh := h.webhook()
	h.st.PutValue("lab", "FAKE_KEY", []byte("fake-renew-value-1"), nil)
	_, old := h.tokenWithLifetime("bot", "lab", "30")
	const agentIP, otherIP = "10.0.0.5", "10.0.0.66"
	if code, _ := h.apiFrom(agentIP, "GET", "/api/v1/whoami", old, "", nil); code != 200 {
		t.Fatal("whoami")
	}
	code, m := h.apiFrom(agentIP, "POST", "/api/v1/token/renew", old, "", nil)
	if code != 200 || m["state"] != "pending" || m["created"] != true {
		t.Fatalf("renew: %d %v", code, m)
	}
	if _, m := h.apiFrom(agentIP, "POST", "/api/v1/token/renew", old, "", nil); m["created"] != false {
		t.Fatalf("second request created another: %v", m)
	}
	if !h.auditHas("token.renewal.request", "") {
		t.Fatal("request not audited")
	}
	_, inbox := h.get("/inbox")
	if !strings.Contains(inbox, "Token renewals") || !strings.Contains(inbox, "bot") {
		t.Fatal("renewal not in the Inbox")
	}
	// Approve and decline are admin forms: CSRF required.
	if resp := h.post("/tokens/bot/renew", url.Values{"lifetime": {"90"}, "back": {"inbox"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("approve without csrf: %d", resp.StatusCode)
	}
	if resp := h.post("/tokens/bot/renewal/decline", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("decline without csrf: %d", resp.StatusCode)
	}
	if code, _ := h.form("/tokens/bot/renew", url.Values{"lifetime": {"90"}, "back": {"inbox"}}); code != http.StatusSeeOther {
		t.Fatalf("approve: %d", code)
	}
	if !h.auditHas("token.renewal.approve", "90 days") {
		t.Fatal("approval not audited")
	}
	if _, body := h.get("/tokens"); !strings.Contains(body, "renewed, waiting for the agent to collect") {
		t.Fatal("Agents page doesn't say it's waiting")
	}
	// The old token can only collect now.
	for _, p := range [][2]string{{"GET", "/api/v1/whoami"}, {"GET", "/api/v1/secrets"}, {"POST", "/api/v1/secrets/lab/FAKE_KEY/reveal"}} {
		if code, _ := h.apiFrom(agentIP, p[0], p[1], old, "", nil); code != http.StatusUnauthorized {
			t.Fatalf("old token %s %s: %d", p[0], p[1], code)
		}
	}
	if _, m := h.apiFrom(agentIP, "GET", "/api/v1/token/renew", old, "", nil); m["state"] != "approved" {
		t.Fatalf("status: %v", m)
	}
	// From somewhere else: refused, logged, alerted.
	if code, _ := h.apiFrom(otherIP, "POST", "/api/v1/token/collect", old, "", nil); code != http.StatusForbidden {
		t.Fatalf("collect from another address: %d", code)
	}
	if !h.auditHas("token.collect.refused", "") {
		t.Fatal("refused collect not audited")
	}
	if got := wh.all(h.srv.alerts); len(got) != 1 || !strings.Contains(got[0], otherIP) || strings.Contains(got[0], old) {
		t.Fatalf("alert: %q", got)
	}
	code, m = h.apiFrom(agentIP, "POST", "/api/v1/token/collect", old, "", nil)
	nt, _ := m["token"].(string)
	if code != 200 || !strings.HasPrefix(nt, store.TokenPrefix) || nt == old {
		t.Fatalf("collect: %d", code)
	}
	// The answer was lost: collecting again gives the same token.
	if _, m := h.apiFrom(agentIP, "POST", "/api/v1/token/collect", old, "", nil); m["token"] != nt {
		t.Fatal("second collect gave a different token")
	}
	if !h.auditHas("token.collect", "renewed token collected") || !h.auditHas("token.collect", "collected again") {
		t.Fatal("collects not audited")
	}
	// The new token reads the same secrets; its first use ends the old one.
	if code, m := h.apiFrom(agentIP, "POST", "/api/v1/secrets/lab/FAKE_KEY/reveal", nt, "", nil); code != 200 || m["value"] != "fake-renew-value-1" {
		t.Fatalf("new token: %d", code)
	}
	for _, p := range [][2]string{{"POST", "/api/v1/token/collect"}, {"GET", "/api/v1/token/renew"}, {"POST", "/api/v1/token/renew"}, {"GET", "/api/v1/whoami"}} {
		if code, _ := h.apiFrom(agentIP, p[0], p[1], old, "", nil); code != http.StatusUnauthorized {
			t.Fatalf("old token after the new one was used, %s %s: %d", p[0], p[1], code)
		}
	}
	if _, m := h.apiFrom(agentIP, "GET", "/api/v1/whoami", nt, "", nil); m["name"] != "bot" {
		t.Fatalf("new token whoami: %v", m)
	}
}

func TestRenewalDecline(t *testing.T) {
	h := newHarness(t)
	h.setup()
	_, tok := h.tokenWithLifetime("bot", "lab", "30")
	h.api("POST", "/api/v1/token/renew", tok, nil)
	if code, _ := h.form("/tokens/bot/renewal/decline", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("decline: %d", code)
	}
	if !h.auditHas("token.renewal.decline", "") {
		t.Fatal("decline not audited")
	}
	if _, m, _ := h.api("GET", "/api/v1/token/renew", tok, nil); m["state"] != "none" {
		t.Fatalf("after decline: %v", m)
	}
	// A token that never expires has nothing to renew.
	_, never := h.tokenWithLifetime("forever", "lab", "0")
	if _, m, _ := h.api("POST", "/api/v1/token/renew", never, nil); m["state"] != "never" || m["created"] != false {
		t.Fatalf("never: %v", m)
	}
}

// The admin's Renew button rotates too, and a renewal not collected in
// time revokes the token.
func TestAdminRenewAndCollectWindow(t *testing.T) {
	h := newHarness(t)
	h.setup()
	c := h.clock()
	_, tok := h.tokenWithLifetime("bot", "lab", "90")
	h.api("GET", "/api/v1/whoami", tok, nil)
	if code, _ := h.form("/tokens/bot/renew", url.Values{"lifetime": {"180"}}); code != http.StatusSeeOther {
		t.Fatalf("renew: %d", code)
	}
	if !h.auditHas("token.renew", "180 days") {
		t.Fatal("renew not audited")
	}
	if code, _, _ := h.api("GET", "/api/v1/secrets", tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("old token after renew: %d", code)
	}
	if _, m, _ := h.api("GET", "/api/v1/token/renew", tok, nil); m["state"] != "approved" {
		t.Fatalf("status: %v", m)
	}
	c.add(8 * 24 * time.Hour)
	if code, _, _ := h.api("POST", "/api/v1/token/collect", tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("collect after the window: %d", code)
	}
	h.srv.sweepRotations(c.now())
	if _, ok := tokenNamed(h.st.ListTokens(), "bot"); ok {
		t.Fatal("uncollected token kept")
	}
	if !h.auditHas("token.revoke", "never collected") {
		t.Fatal("revocation not audited")
	}
}

// The agent API shows when a secret was last read only if the caller read
// it: otherwise a canary's reads would give it away.
func TestLastReadOnlyOwn(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "FAKE_KEY", []byte("fake-lastread-1"), nil)
	a := h.createToken("a", "lab")
	b := h.createToken("b", "lab")
	h.api("POST", "/api/v1/secrets/lab/FAKE_KEY/reveal", a, nil)
	if _, m, _ := h.api("GET", "/api/v1/secrets/lab/FAKE_KEY", a, nil); m["last_read_by"] != "a" || m["last_read_at"] == nil {
		t.Fatalf("own read: %v", m)
	}
	_, m, raw := h.api("GET", "/api/v1/secrets/lab/FAKE_KEY", b, nil)
	if _, ok := m["last_read_at"]; ok || strings.Contains(string(raw), "last_read") {
		t.Fatalf("another token's read shown: %s", raw)
	}
	_, _, list := h.api("GET", "/api/v1/secrets", b, nil)
	if strings.Contains(string(list), "last_read") {
		t.Fatalf("list shows another token's read: %s", list)
	}
}

// keysOf is the set of JSON keys, recursively, with values dropped.
func keysOf(t *testing.T, raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var walk func(any) string
	walk = func(v any) string {
		switch x := v.(type) {
		case map[string]any:
			var b strings.Builder
			b.WriteString("{")
			for _, k := range sortedKeys(x) {
				if k == "ref" || k == "name" || k == "updated_at" || k == "value" {
					b.WriteString(k + ",")
					continue
				}
				b.WriteString(k + ":" + walk(x[k]) + ",")
			}
			return b.String() + "}"
		case []any:
			var b strings.Builder
			for _, e := range x {
				b.WriteString(walk(e))
			}
			return "[" + b.String() + "]"
		}
		return "_"
	}
	return walk(v)
}

func sortedKeys(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

func TestCanary(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh := h.webhook()
	h.st.PutValue("lab", "REAL_KEY", []byte("fake-real-value-1"), nil)
	// Made a canary on the Add page.
	if code, _ := h.form("/secrets", url.Values{"namespace": {"lab"}, "name": {"BAIT_KEY"}, "value": {"fake-bait-value-1"}, "canary": {"yes"}}); code != http.StatusSeeOther {
		t.Fatalf("add canary: %d", code)
	}
	if sec, _ := h.st.GetSecret("lab", "BAIT_KEY"); !sec.Canary {
		t.Fatal("not a canary")
	}
	tok := h.createToken("bot", "lab")
	// To the agent it's an ordinary secret: same shape everywhere.
	for _, p := range []string{"/api/v1/secrets/lab/%s", "/api/v1/secrets/lab/%s/reveal"} {
		method := "GET"
		if strings.HasSuffix(p, "reveal") {
			method = "POST"
		}
		code1, _, real := h.api(method, strings.Replace(p, "%s", "REAL_KEY", 1), tok, nil)
		code2, m, bait := h.api(method, strings.Replace(p, "%s", "BAIT_KEY", 1), tok, nil)
		if code1 != code2 || keysOf(t, real) != keysOf(t, bait) {
			t.Fatalf("%s: real %d %s, canary %d %s", p, code1, real, code2, bait)
		}
		if method == "POST" && m["value"] != "fake-bait-value-1" {
			t.Fatal("canary value not returned")
		}
	}
	_, _, list := h.api("GET", "/api/v1/secrets", tok, nil)
	if strings.Contains(strings.ToLower(string(list)), "canary") {
		t.Fatal("list mentions canaries")
	}
	h.api("POST", "/api/v1/secrets/lab/BAIT_KEY/reveal", tok, nil) // a second read: no second alert
	got := wh.all(h.srv.alerts)
	if len(got) != 1 {
		t.Fatalf("alerts: %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(got[0]), &body); err != nil {
		t.Fatal(err)
	}
	content, _ := body["content"].(string)
	if !strings.Contains(content, "lab/BAIT_KEY") || !strings.Contains(content, "bot") || strings.Contains(got[0], "fake-bait-value-1") || strings.Contains(got[0], tok) {
		t.Fatalf("alert body: %s", got[0])
	}
	if am, _ := body["allowed_mentions"].(map[string]any); am == nil || len(am["parse"].([]any)) != 0 {
		t.Fatalf("allowed_mentions: %s", got[0])
	}
	if !h.auditHas("secret.read.canary", "") {
		t.Fatal("canary read not audited as one")
	}
	_, inbox := h.get("/inbox")
	if !strings.Contains(inbox, "lab/BAIT_KEY") || strings.Contains(inbox, "fake-bait-value-1") {
		t.Fatal("Inbox doesn't show the canary read")
	}
	hits, _ := h.st.CanaryHits()
	if len(hits) != 1 || hits[0].Count != 2 {
		t.Fatalf("hits: %+v", hits)
	}
	if resp := h.post("/canary/"+hits[0].ID+"/dismiss", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("dismiss without csrf: %d", resp.StatusCode)
	}
	if code, _ := h.form("/canary/"+hits[0].ID+"/dismiss", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("dismiss: %d", code)
	}
	if hits, _ := h.st.CanaryHits(); len(hits) != 0 {
		t.Fatal("not dismissed")
	}
	// Settings: configured, test alert, revoke on read.
	if _, s := h.get("/settings"); !strings.Contains(s, "Send test alert") || strings.Contains(s, h.srv.alerts.url) {
		t.Fatal("settings")
	}
	if code, _ := h.form("/settings/alert-test", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("test alert: %d", code)
	}
	if got := wh.all(h.srv.alerts); len(got) != 2 || !strings.Contains(got[1], "test alert") {
		t.Fatalf("test alert: %q", got)
	}
	if code, _ := h.form("/settings/canary", url.Values{"revoke": {"yes"}}); code != http.StatusSeeOther {
		t.Fatal("revoke setting")
	}
	tok2 := h.createToken("bot2", "lab")
	h.api("POST", "/api/v1/secrets/lab/BAIT_KEY/reveal", tok2, nil)
	if code, _, _ := h.api("GET", "/api/v1/whoami", tok2, nil); code != http.StatusUnauthorized {
		t.Fatalf("token that read a canary still works: %d", code)
	}
	// The canary form on the secret page is an admin form.
	if resp := h.post("/secret/lab/REAL_KEY/canary", url.Values{"on": {"yes"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("canary without csrf: %d", resp.StatusCode)
	}
	if code, _ := h.form("/secret/lab/REAL_KEY/canary", url.Values{"on": {"yes"}}); code != http.StatusSeeOther {
		t.Fatal("canary on")
	}
}

func TestAlertsNotConfigured(t *testing.T) {
	h := newHarness(t)
	h.setup()
	if code, _ := h.form("/settings/alert-test", url.Values{}); code != http.StatusBadRequest {
		t.Fatalf("test alert with no webhook: %d", code)
	}
	if err := CheckAlertWebhook("ftp://secrets.example.com/hook"); err == nil || strings.Contains(err.Error(), "example") {
		t.Fatalf("bad webhook: %v", err)
	}
}

func TestDuplicateWarning(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "FIRST_KEY", []byte("fake-dup-value-1"), nil)
	code, body := h.form("/secrets", url.Values{"namespace": {"lab"}, "name": {"SECOND_KEY"}, "value": {"fake-dup-value-1"}})
	if code != http.StatusSeeOther {
		t.Fatalf("add: %d", code)
	}
	want := "SECOND_KEY has the same value as lab/FIRST_KEY. If that was a paste mistake, replace it."
	if !strings.Contains(stripTags(body), want) || !strings.Contains(body, `href="/secret/lab/FIRST_KEY"`) {
		t.Fatalf("no warning: %s", body)
	}
	if strings.Contains(body, "fake-dup-value-1") {
		t.Fatal("value echoed")
	}
	if sec, _ := h.st.GetSecret("lab", "SECOND_KEY"); !sec.HasValue() {
		t.Fatal("not saved")
	}
	// Shown once.
	if _, again := h.get("/secret/lab/SECOND_KEY"); strings.Contains(again, "same value as") {
		t.Fatal("warning shown twice")
	}
	// Replacing a value warns too.
	h.st.PutValue("lab", "THIRD_KEY", []byte("fake-other-value"), nil)
	_, body = h.form("/secret/lab/THIRD_KEY/value", url.Values{"value": {"fake-dup-value-1"}})
	if !strings.Contains(stripTags(body), "THIRD_KEY has the same value as lab/") || strings.Contains(body, "fake-dup-value-1") {
		t.Fatalf("replace: no warning")
	}
}

var tagRE = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string { return tagRE.ReplaceAllString(s, "") }
