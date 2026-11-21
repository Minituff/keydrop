//go:build e2e

package e2e

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// TestRollbackV6Limits limits a key to one of two agents in a namespace:
// that one runs with it, the other is refused before its command starts,
// with the server's message and a non-zero exit, and the audit log has
// the denied read. The release before limits (v0.1.3) then refuses to
// start on the data (it would hand the key to both); downgrade-data names
// the key it un-limits, v0.1.3 starts and serves it, and this release
// starts again on what v0.1.3 wrote, where the key can be limited again.
func TestRollbackV6Limits(t *testing.T) {
	old := buildOld(t, v6RollbackCommit)

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "rb7", "ROOT_KEY", secret, "secret", "")
	yes, no := newAgent(t, binary), newAgent(t, binary)
	yes.login(t, in.url, pin, web.createToken(t, "rb7-yes", "rb7", false))
	no.login(t, in.url, pin, web.createToken(t, "rb7-no", "rb7", false))
	limit := func() {
		t.Helper()
		web.mustPost(t, "/secret/rb7/ROOT_KEY/limit", url.Values{"only": {"yes"}, "token": {"rb7-yes"}})
	}
	refused := func() {
		t.Helper()
		r := no.run(t, "", "run", "-e", "ROOT_KEY", "--", "sh", "-c", "echo started")
		if r.code == 0 || strings.Contains(r.stdout, "started") || !strings.Contains(r.stderr, "rb7/ROOT_KEY is limited to other agents; ask the admin to allow rb7-no on it") {
			t.Fatalf("run by the agent off the list: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
		noLeak(t, "refused run", r.all(), secret)
	}
	limit()
	if got := yes.valueHash(t, "ROOT_KEY"); got != sha(secret) {
		t.Fatal("the agent on the list got a different value")
	}
	refused()
	if r := no.ok(t, "", "secrets"); !strings.Contains(r.stdout, "rb7/ROOT_KEY  [limited to other agents]") {
		t.Fatalf("secrets: %q", r.stdout)
	}
	if r := yes.ok(t, "", "secrets"); strings.Contains(r.stdout, "limited") {
		t.Fatalf("secrets for the agent on the list: %q", r.stdout)
	}
	if main, _ := in.auditLines(t); !strings.Contains(main, `"secret.read.denied"`) || !strings.Contains(main, "token:rb7-no") {
		t.Fatal("the denied read isn't in the audit log")
	}
	in.stop(t)

	state := filepath.Join(in.dataDir, "keydrop.json")
	before := readFile(t, state)
	out, code := in.command(t, old, "server")
	if code == 0 || !strings.Contains(out, "master key does not match") {
		t.Fatalf("the previous release started on data with a limit: exit %d\n%s", code, out)
	}
	if readFile(t, state) != before {
		t.Fatal("the refused start changed keydrop.json")
	}
	out, code = in.command(t, binary, "downgrade-data")
	if code != 0 || !strings.Contains(out, "keys no longer limited (now usable by every agent with their namespace): rb7/ROOT_KEY\n") {
		t.Fatalf("downgrade-data: exit %d\n%s", code, out)
	}

	in.start(t, old)
	for _, g := range []*agent{yes, no} { // as downgrade-data said
		if got := g.valueHash(t, "ROOT_KEY"); got != sha(secret) {
			t.Fatal("the previous release returns a different value")
		}
	}
	web = login(t, in)
	web.addEntry(t, "rb7", "AFTER", "plain-setting", "variable", "") // it rewrites the file
	in.stop(t)

	in.start(t, binary)
	if got := yes.valueHash(t, "ROOT_KEY"); got != sha(secret) {
		t.Fatal("this release returns a different value after the previous one rewrote the file")
	}
	web = login(t, in)
	if _, page := web.get(t, "/secret/rb7/ROOT_KEY"); strings.Contains(page, `<span class="badge">limited</span>`) {
		t.Fatal("still limited after the round trip")
	}
	limit()
	refused()
	in.stop(t)
}
