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
