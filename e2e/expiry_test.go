//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// downgradeV4 runs downgrade-data on data this release wrote, so a release
// before token expiry and canaries can start on it.
func downgradeV4(t *testing.T, in *instance, expiring string) {
	t.Helper()
	out, code := in.command(t, binary, "downgrade-data")
	if code != 0 || !strings.Contains(out, "tokens that no longer expire: ") || !strings.Contains(out, expiring) || strings.Contains(out, "tls.key") {
		t.Fatalf("downgrade-data: exit %d:\n%s", code, out)
	}
}

// moveClock sets how far ahead of real time the clock binary runs.
func moveClock(t *testing.T, file string, d time.Duration) {
	t.Helper()
	if err := os.WriteFile(file, []byte(d.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// alertSink receives the server's webhook alerts.
type alertSink struct {
	mu     sync.Mutex
	bodies []string
}

func newAlertSink(t *testing.T) (*alertSink, string) {
	s := &alertSink{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, string(b))
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	return s, ts.URL + "/webhook"
}

func (s *alertSink) wait(t *testing.T, want string) string {
	t.Helper()
	var got string
	waitFor(t, "an alert naming "+want, 10*time.Second, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, b := range s.bodies {
			if strings.Contains(b, want) {
				got = b
				return true
			}
		}
		return false
	})
	return got
}

var expiresRE = regexp.MustCompile(`expires: (\d{4}-\d\d-\d\d) \(in (\d+) days\)`)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Token expiry, renewal and rotation through the CLI, with the server's and
// the agents' clock moved forward; and a canary read alerting a webhook.
func TestExpiryRenewalAndCanary(t *testing.T) {
	clockFile := filepath.Join(t.TempDir(), "clock")
	moveClock(t, clockFile, 0)
	sink, hook := newAlertSink(t)
	in := newInstance(t, clockBinary)
	in.extra = []string{"KEYDROP_E2E_CLOCK_FILE=" + clockFile, "KEYDROP_ALERT_WEBHOOK=" + hook}
	in.start(t, clockBinary)
	pin := in.pin(t)
	if strings.Contains(in.srv.log.String(), hook) {
		t.Fatal("the server log shows the webhook URL")
	}
	web := setupAndLogin(t, in)
	secret, bait := fakeSecret(t), fakeSecret(t)
	web.addEntry(t, "ex", "KEPT", secret, "secret", "")
	agentFor := func(name string) *agent {
		g := newAgent(t, clockBinary)
		g.extra = []string{"KEYDROP_E2E_CLOCK_FILE=" + clockFile}
		g.login(t, in.url, pin, web.postToken(t, url.Values{"name": {name}, "namespaces": {"ex"}, "permission": {"read"}, "lifetime": {"30"}}))
		return g
	}
	g, late, stale := agentFor("renewer"), agentFor("late"), agentFor("stale")
	never := newAgent(t, clockBinary)
	never.login(t, in.url, pin, web.postToken(t, url.Values{"name": {"forever"}, "namespaces": {"ex"}, "lifetime": {"0"}}))

	w := g.ok(t, "", "whoami")
	m := expiresRE.FindStringSubmatch(w.stdout)
	if m == nil || m[2] != "30" {
		t.Fatalf("whoami: %q", w.stdout)
	}
	expiry := m[1]
	if w := never.ok(t, "", "whoami"); !strings.Contains(w.stdout, "expires: never") {
		t.Fatalf("whoami, never: %q", w.stdout)
	}
	if r := never.ok(t, "", "renew"); !strings.Contains(r.stdout, "this token doesn't expire") {
		t.Fatalf("renew, never: %q", r.stdout)
	}

	// Five days left: every command warns.
	moveClock(t, clockFile, 25*24*time.Hour)
	if r := g.ok(t, "", "secrets"); !strings.Contains(r.stderr, "keydrop: this token expires in 5 days. Run `keydrop renew` to ask the admin to extend it.") {
		t.Fatalf("no warning: %q", r.stderr)
	}

	// Expired.
	moveClock(t, clockFile, 31*24*time.Hour)
	r := g.run(t, "", "secrets")
	if r.code == 0 || !strings.Contains(r.stderr, "keydrop: this token expired on "+expiry+". Run `keydrop renew`, then ask the admin to approve it in keydrop's Inbox.") {
		t.Fatalf("expired: %d %q", r.code, r.stderr)
	}
	if r := g.ok(t, "", "renew"); !strings.Contains(r.stdout, "renewal requested") {
		t.Fatalf("renew: %q", r.stdout)
	}
	if r := g.ok(t, "", "renew"); !strings.Contains(r.stdout, "already waiting") {
		t.Fatalf("renew again: %q", r.stdout)
	}
	tokenFile := filepath.Join(g.configDir(), "token")
	urlBefore, pinBefore := readFile(t, filepath.Join(g.configDir(), "url")), readFile(t, filepath.Join(g.configDir(), "pin"))
	oldToken := strings.TrimSpace(readFile(t, tokenFile))

	web = login(t, in) // the session expired with the clock
	if _, inbox := web.get(t, "/inbox"); !strings.Contains(inbox, "Token renewals") || !strings.Contains(inbox, "renewer") {
		t.Fatal("the renewal isn't in the Inbox")
	}
	web.mustPost(t, "/tokens/renewer/renew", url.Values{"lifetime": {"90"}, "back": {"inbox"}})

	// The old token now only collects.
	old := newBearer(t, in, oldToken)
	for _, p := range []string{"/api/v1/secrets", "/api/v1/whoami"} {
		if code := old.send(t, "GET", p, ""); code != http.StatusUnauthorized {
			t.Fatalf("old token, %s: %d", p, code)
		}
	}
	if code := old.send(t, "POST", "/api/v1/secrets/ex/KEPT/reveal", "{}"); code != http.StatusUnauthorized {
		t.Fatalf("old token, reveal: %d", code)
	}
	r = g.ok(t, "", "renew", "--wait")
	if !strings.Contains(r.stderr, "keydrop: token renewed; new token saved to "+tokenFile) || !strings.Contains(r.stdout, "(in 90 days)") {
		t.Fatalf("renew --wait: %q %q", r.stdout, r.stderr)
	}
	newToken := strings.TrimSpace(readFile(t, tokenFile))
	if newToken == oldToken || !strings.HasPrefix(newToken, "kd_") || strings.Contains(r.all(), newToken) {
		t.Fatal("the token file wasn't swapped, or the token was printed")
	}
	if fi, _ := os.Stat(tokenFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v", fi.Mode())
	}
	if readFile(t, filepath.Join(g.configDir(), "url")) != urlBefore || readFile(t, filepath.Join(g.configDir(), "pin")) != pinBefore {
		t.Fatal("url or pin changed")
	}
	if g.valueHash(t, "KEPT") != sha(secret) {
		t.Fatal("the new token reads a different value")
	}
	for _, c := range []struct{ method, path string }{{"POST", "/api/v1/token/collect"}, {"GET", "/api/v1/token/renew"}, {"POST", "/api/v1/token/renew"}, {"GET", "/api/v1/secrets"}} {
		if code := old.send(t, c.method, c.path, "{}"); code != http.StatusUnauthorized {
			t.Fatalf("old token after the swap, %s %s: %d", c.method, c.path, code)
		}
	}

	// The admin renews from the Agents page; the next command collects.
	web.mustPost(t, "/tokens/renewer/renew", url.Values{"lifetime": {"180"}})
	r = g.ok(t, "", "secrets")
	if !strings.Contains(r.stderr, "keydrop: token renewed; new token saved to "+tokenFile) || !strings.Contains(r.stdout, "ex/KEPT") {
		t.Fatalf("auto-collect: %q %q", r.stdout, r.stderr)
	}
	if strings.TrimSpace(readFile(t, tokenFile)) == newToken {
		t.Fatal("not swapped after the admin's renewal")
	}

	// Renewed but not collected within 7 days: the token is gone.
	web.mustPost(t, "/tokens/late/renew", url.Values{"lifetime": {"90"}})
	moveClock(t, clockFile, 39*24*time.Hour)
	if r := late.run(t, "", "secrets"); r.code == 0 || !strings.Contains(r.stderr, "invalid token") {
		t.Fatalf("late collect: %d %q", r.code, r.stderr)
	}
	web = login(t, in)
	if _, page := web.get(t, "/tokens"); strings.Contains(page, "<strong>late</strong>") {
		t.Fatal("an uncollected renewal's token is still listed")
	}

	// Past the 30-day grace window, renewal is refused.
	moveClock(t, clockFile, 61*24*time.Hour)
	if r := stale.run(t, "", "renew"); r.code == 0 || !strings.Contains(r.stderr, "Pair this machine again") {
		t.Fatalf("renew past grace: %d %q", r.code, r.stderr)
	}

	// A canary: to the agent an ordinary secret; the webhook hears of it.
	web = login(t, in)
	web.mustPost(t, "/secrets", url.Values{"namespace": {"ex"}, "name": {"BAIT"}, "value": {bait}, "kind": {"secret"}, "canary": {"yes"}})
	if g.valueHash(t, "BAIT") != sha(bait) {
		t.Fatal("the canary's value")
	}
	if i := g.ok(t, "", "info", "BAIT"); strings.Contains(strings.ToLower(i.stdout), "canary") {
		t.Fatalf("info shows the canary: %q", i.stdout)
	}
	body := sink.wait(t, "ex/BAIT")
	var msg map[string]any
	if err := json.Unmarshal([]byte(body), &msg); err != nil || !strings.Contains(msg["content"].(string), "renewer") {
		t.Fatalf("alert: %v", err)
	}
	noLeak(t, "the alert", body, bait, secret, strings.TrimSpace(readFile(t, tokenFile)))
	main, unauth := in.auditLines(t)
	if !strings.Contains(unauth, `"token expired"`) {
		t.Fatal("the audit log doesn't record the expired token's use")
	}
	noLeak(t, "the audit log", unauth, oldToken, newToken)
	for _, want := range []string{`"secret.read.canary"`, `"token.renewal.request"`, `"token.renewal.approve"`, `"token.renew"`, `"token.collect"`} {
		if !strings.Contains(main, want) {
			t.Fatalf("the audit log lacks %s", want)
		}
	}
	noLeak(t, "the audit log", main, bait, secret, oldToken, newToken)
	if strings.Contains(main, hook) || strings.Contains(in.srv.log.String(), hook) {
		t.Fatal("the webhook URL was logged")
	}
	in.stop(t)
}

// testRollbackV3 writes data with every expiry, renewal and canary field in
// use. The release before them refuses it until downgrade-data, which
// says what's dropped; then that release starts on it and rewrites it, and
// this one starts again.
func TestRollbackV3(t *testing.T) {
	old := buildOld(t, v3RollbackCommit)

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "rb3", "KEPT", secret, "secret", "")
	web.mustPost(t, "/secrets", url.Values{"namespace": {"rb3"}, "name": {"BAIT"}, "value": {fakeSecret(t)}, "kind": {"secret"}, "canary": {"yes"}})
	web.mustPost(t, "/settings/canary", url.Values{"revoke": {""}})
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.postToken(t, url.Values{"name": {"rb3-agent"}, "namespaces": {"rb3"}, "lifetime": {"30"}}))
	g.ok(t, "", "renew")                                                       // a pending request
	web.mustPost(t, "/tokens/rb3-agent/renew", url.Values{"lifetime": {"90"}}) // approved...
	g.ok(t, "", "secrets")                                                     // ...collected and used
	g.ok(t, "", "renew")                                                       // and asked again
	g.valueHash(t, "BAIT")                                                     // a canary hit
	gone := newAgent(t, binary)
	gone.login(t, in.url, pin, web.postToken(t, url.Values{"name": {"rb3-gone"}, "namespaces": {"rb3"}}))
	web.mustPost(t, "/tokens/rb3-gone/renew", url.Values{"lifetime": {"90"}}) // never collected
	in.stop(t)

	state := filepath.Join(in.dataDir, "keydrop.json")
	before := readFile(t, state)
	out, code := in.command(t, old, "server")
	if code == 0 {
		t.Fatalf("the previous release started on data with expiry in use:\n%s", out)
	}
	if readFile(t, state) != before {
		t.Fatal("the refused start changed keydrop.json")
	}
	out, code = in.command(t, binary, "downgrade-data")
	for _, want := range []string{"tokens that no longer expire: ", "renewal requests dropped: rb3-agent", "tokens deleted (renewed, new token never collected; pair these agents again): rb3-gone", "secrets no longer canaries: rb3/BAIT", "canary alerts dropped from the Inbox: 1"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("downgrade-data lacks %q: exit %d:\n%s", want, code, out)
		}
	}

	in.start(t, old)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("the previous release returns a different value")
	}
	if r := gone.run(t, "", "secrets"); r.code == 0 {
		t.Fatal("an uncollected renewal's token works after downgrade-data")
	}
	web = login(t, in)
	web.addEntry(t, "rb3", "AFTER", "plain-setting", "variable", "")
	in.stop(t)

	in.start(t, binary)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("this release returns a different value after the previous one rewrote the file")
	}
	if w := g.ok(t, "", "whoami"); !strings.Contains(w.stdout, "expires: never") {
		t.Fatalf("whoami after the round trip: %q", w.stdout)
	}
	if v := g.ok(t, "", "vars"); !strings.Contains(v.stdout, "rb3/AFTER=plain-setting") {
		t.Fatalf("vars after the round trip: %q", v.stdout)
	}
	web = login(t, in)
	if _, page := web.get(t, "/secret/rb3/BAIT"); strings.Contains(page, `>canary</span>`) {
		t.Fatal("still a canary after the round trip")
	}
	// The new fields work again.
	web.mustPost(t, "/tokens/rb3-agent/renew", url.Values{"lifetime": {"30"}})
	if r := g.ok(t, "", "whoami"); !strings.Contains(r.stdout, "(in 30 days)") {
		t.Fatalf("renewed after the round trip: %q", r.stdout)
	}
	in.stop(t)
}
