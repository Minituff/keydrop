package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/minituff/keydrop/internal/audit"
)

// hookServer is a webhook that answers status and records what it got.
func hookServer(t *testing.T, status int) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.Method+" "+string(b))
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(ts.Close)
	return ts, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

func TestAlertWebhookSettings(t *testing.T) {
	h := newHarness(t)
	h.setup()
	ok, okGot := hookServer(t, http.StatusNoContent)
	const secretPath = "/hook/fake-webhook-secret-path"

	if _, s := h.get("/settings"); !strings.Contains(s, "not configured") || !strings.Contains(s, `name="webhook"`) || strings.Contains(s, "Send test alert") {
		t.Fatal("Settings without a webhook")
	}
	for _, bad := range []string{"", "ftp://hooks.example.com/x", "not a url"} {
		if code, _ := h.form("/settings/alert-webhook", url.Values{"webhook": {bad}}); code != http.StatusBadRequest {
			t.Fatalf("webhook %q: %d", bad, code)
		}
	}
	// CSRF and an admin session are required.
	if resp := h.post("/settings/alert-webhook", url.Values{"webhook": {ok.URL + secretPath}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("set without csrf: %d", resp.StatusCode)
	}
	if resp := h.post("/settings/alert-webhook/remove", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("remove without csrf: %d", resp.StatusCode)
	}
	if u, _, _ := h.st.AlertWebhook(); u != "" {
		t.Fatal("stored without csrf")
	}

	code, body := h.form("/settings/alert-webhook", url.Values{"webhook": {" " + ok.URL + secretPath + " "}})
	if code != http.StatusSeeOther || !strings.Contains(body, "Webhook saved") {
		t.Fatalf("set: %d", code)
	}
	if u, _, _ := h.st.AlertWebhook(); u != ok.URL+secretPath {
		t.Fatalf("stored %q", u)
	}
	for _, want := range []string{"a webhook at <strong>127.0.0.1</strong>", "Added here", "Remove this webhook", "Send test alert", "Replace the webhook"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Settings lacks %q", want)
		}
	}
	if strings.Contains(body, "fake-webhook-secret-path") {
		t.Fatal("Settings shows the webhook URL")
	}
	if !h.auditHas("settings.alertwebhook", "set (127.0.0.1)") {
		t.Fatal("not audited")
	}

	// The test is sent at once and its result shown.
	code, body = h.form("/settings/alert-test", url.Values{})
	if code != http.StatusSeeOther || !strings.Contains(body, "Test alert delivered") {
		t.Fatalf("test: %d", code)
	}
	if got := okGot(); len(got) != 1 || !strings.Contains(got[0], "test alert") {
		t.Fatalf("webhook got %q", got)
	}
	// A failure says why, without the URL.
	bad, _ := hookServer(t, http.StatusNotFound)
	h.form("/settings/alert-webhook", url.Values{"webhook": {bad.URL + secretPath}})
	code, body = h.form("/settings/alert-test", url.Values{})
	if code != http.StatusBadGateway || !strings.Contains(body, "Test alert not delivered: it answered HTTP 404") || strings.Contains(body, "fake-webhook-secret-path") {
		t.Fatalf("failed test: %d", code)
	}
	if !h.auditHas("alert.test", "failed: it answered HTTP 404") {
		t.Fatal("failed test not audited")
	}

	// A restart uses the stored webhook over KEYDROP_ALERT_WEBHOOK.
	env, envGot := hookServer(t, http.StatusNoContent)
	al, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if s2 := New(Config{AlertWebhook: env.URL}, h.st, al); s2.alerts.webhook() != bad.URL+secretPath {
		t.Fatal("the stored webhook isn't used after a restart")
	}

	// Removing it falls back to the environment variable.
	h.srv.cfg.AlertWebhook = env.URL
	code, body = h.form("/settings/alert-webhook/remove", url.Values{})
	if code != http.StatusSeeOther || !strings.Contains(body, "Set by KEYDROP_ALERT_WEBHOOK") || strings.Contains(body, "Remove this webhook") {
		t.Fatalf("remove: %d", code)
	}
	if u, _, _ := h.st.AlertWebhook(); u != "" || h.srv.alerts.webhook() != env.URL {
		t.Fatal("not removed")
	}
	h.form("/settings/alert-test", url.Values{})
	if len(envGot()) != 1 {
		t.Fatal("the test didn't go to KEYDROP_ALERT_WEBHOOK after removing")
	}

	// The URL is in no log.
	for _, f := range []string{"audit.jsonl", "keydrop.json"} {
		b, _ := os.ReadFile(filepath.Join(h.dir, f))
		if strings.Contains(string(b), "fake-webhook-secret-path") {
			t.Fatalf("%s holds the webhook URL", f)
		}
	}
}

func TestAlertTestBudget(t *testing.T) {
	ok, _ := hookServer(t, http.StatusNoContent)
	a := newAlerter(ok.URL)
	for i := 0; i < alertBurst; i++ {
		if err := a.test("x"); err != nil {
			t.Fatalf("test %d: %v", i, err)
		}
	}
	if err := a.test("x"); !errors.Is(err, errAlertBudget) {
		t.Fatalf("over the budget: %v", err)
	}
}

func TestDiscordWebhookDescribe(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://discord.com/api/webhooks/123/abc-DEF_9":      true,
		"https://discordapp.com/api/v10/webhooks/123/abc":     true,
		"https://ptb.discord.com/api/webhooks/123/abc/":       true,
		"http://discord.com/api/webhooks/123/abc":             false,
		"https://discord.com:8443/api/webhooks/123/abc":       false,
		"https://discord.com.example.com/api/webhooks/1/abc":  false,
		"https://discord.com/api/webhooks/123/abc/slack":      false,
		"https://hooks.example.com/api/webhooks/123/abc-DEF9": false,
	} {
		u, _ := url.Parse(raw)
		if isDiscordWebhook(u) != want {
			t.Errorf("%s: %v", raw, !want)
		}
	}
	name, ch, ok := parseDiscordWebhook([]byte(`{"name":"Lab‮ alerts\u0007","channel_id":"717","guild_id":"42","token":"fake-token"}`))
	if !ok || name != "Lab alerts" || ch != "https://discord.com/channels/42/717" {
		t.Fatalf("parsed %q %q %v", name, ch, ok)
	}
	if _, ch, _ := parseDiscordWebhook([]byte(`{"name":"x","channel_id":"7/../../evil","guild_id":"42"}`)); ch != "" {
		t.Fatalf("bad ids gave a link: %q", ch)
	}
	if name, _, _ := parseDiscordWebhook([]byte(`{"name":"` + strings.Repeat("é", 200) + `"}`)); len([]rune(name)) != 81 {
		t.Fatalf("name not capped: %d", len([]rune(name)))
	}
}
