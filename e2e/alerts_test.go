//go:build e2e

package e2e

import (
	"net/url"
	"strings"
	"testing"
)

// TestRollbackV4 sets the alert webhook in Settings. The release before
// that starts on the data as it is (no downgrade-data), ignores the
// webhook and rewrites the file; this one then starts on what it wrote.
func TestRollbackV4(t *testing.T) {
	old := buildOld(t, v4RollbackCommit)

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "rb4", "KEPT", secret, "secret", "")
	web.mustPost(t, "/settings/alert-webhook", url.Values{"webhook": {"https://hooks.example.com/fake-e2e-webhook-path"}})
	if _, page := web.get(t, "/settings"); !strings.Contains(page, "hooks.example.com") || strings.Contains(page, "fake-e2e-webhook-path") {
		t.Fatal("Settings after setting the webhook")
	}
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.postToken(t, url.Values{"name": {"rb4-agent"}, "namespaces": {"rb4"}, "lifetime": {"30"}}))
	in.stop(t)

	in.start(t, old)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("the previous release returns a different value")
	}
	web = login(t, in)
	if _, page := web.get(t, "/settings"); !strings.Contains(page, "not configured") {
		t.Fatal("the previous release uses the webhook set in Settings")
	}
	web.addEntry(t, "rb4", "AFTER", "plain-setting", "variable", "") // it rewrites the file
	in.stop(t)

	in.start(t, binary)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("this release returns a different value after the previous one rewrote the file")
	}
	web = login(t, in)
	if _, page := web.get(t, "/settings"); !strings.Contains(page, "not configured") {
		t.Fatal("the webhook survived the previous release's rewrite")
	}
	web.mustPost(t, "/settings/alert-webhook", url.Values{"webhook": {"https://hooks.example.com/fake-e2e-webhook-path"}})
	in.stop(t)
	in.start(t, binary) // and it opens with the webhook set again
	in.stop(t)
}

// TestInboxAlerts: with KEYDROP_ALERT_INBOX=true, `keydrop request` sends
// the webhook a notice naming the token and the key; without it, it
// doesn't. The canary read after it is queued behind any notice, so once
// its alert has arrived a notice would have too.
func TestInboxAlerts(t *testing.T) {
	for _, on := range []bool{true, false} {
		sink, hook := newAlertSink(t)
		in := newInstance(t, binary)
		in.extra = []string{"KEYDROP_ALERT_WEBHOOK=" + hook}
		if on {
			in.extra = append(in.extra, "KEYDROP_ALERT_INBOX=true")
		}
		in.start(t, binary)
		if got := strings.Contains(in.srv.log.String(), "Inbox alerts: on"); got != on {
			t.Fatalf("on %v: the log says %v", on, got)
		}
		pin := in.pin(t)
		web := setupAndLogin(t, in)
		web.mustPost(t, "/secrets", url.Values{"namespace": {"ib"}, "name": {"BAIT"}, "value": {fakeSecret(t)}, "kind": {"secret"}, "canary": {"yes"}})
		g := newAgent(t, binary)
		g.login(t, in.url, pin, web.createTokenPerm(t, "asker", "ib", "write"))
		g.ok(t, "", "request", "NEEDED_KEY", "--desc", "fake-e2e-agent-text")
		g.valueHash(t, "BAIT")
		sink.wait(t, "canary `ib/BAIT`")
		sink.mu.Lock()
		all := strings.Join(sink.bodies, "\n")
		sink.mu.Unlock()
		if got := strings.Contains(all, "`asker` is asking for `ib/NEEDED_KEY`"); got != on {
			t.Fatalf("on %v: notice sent %v: %s", on, got, all)
		}
		if strings.Contains(all, "fake-e2e-agent-text") {
			t.Fatal("a notice holds the agent's description")
		}
		in.stop(t)
	}
}

// TestAlertFormatText: with KEYDROP_ALERT_FORMAT=text (ntfy), a canary
// read reaches the webhook as plain text: no JSON, no backticks.
func TestAlertFormatText(t *testing.T) {
	sink, hook := newAlertSink(t)
	in := newInstance(t, binary)
	in.extra = []string{"KEYDROP_ALERT_WEBHOOK=" + hook, "KEYDROP_ALERT_FORMAT=text"}
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	web.mustPost(t, "/secrets", url.Values{"namespace": {"fmt"}, "name": {"BAIT"}, "value": {fakeSecret(t)}, "kind": {"secret"}, "canary": {"yes"}})
	if _, page := web.get(t, "/settings"); !strings.Contains(page, "sent as: <strong>plain text</strong>") {
		t.Fatal("Settings doesn't say alerts go as plain text")
	}
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.createTokenPerm(t, "reader", "fmt", "read"))
	g.valueHash(t, "BAIT")
	got := sink.wait(t, "canary fmt/BAIT was read by token reader")
	sink.mu.Lock()
	ctype := sink.types[0]
	sink.mu.Unlock()
	if strings.ContainsAny(got, "`{}\"") || ctype != "text/plain; charset=utf-8" {
		t.Fatalf("got %q (%s)", got, ctype)
	}
	in.stop(t)
}
