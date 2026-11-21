//go:build e2e

package e2e

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/minituff/keydrop/internal/server"
)

// cliLevelCommits is, for each CLI level the server may still accept, the
// oldest commit whose CLI is at that level. When MinCLILevel goes up, add
// its commit here: TestOldCLI runs that CLI against this server, so an API
// change that breaks it without raising MinCLILevel fails CI.
var cliLevelCommits = map[int]string{
	1: "631f015", // the oldest CLI still in use when levels were added
}

// TestOldCLI: the oldest CLI this server still accepts pairs, reads and
// writes without being refused.
func TestOldCLI(t *testing.T) {
	commit, ok := cliLevelCommits[server.MinCLILevel]
	if !ok {
		t.Fatalf("MinCLILevel %d has no commit in cliLevelCommits", server.MinCLILevel)
	}
	old := buildOld(t, commit)

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "compat", "OLD_CLI_SECRET", secret, "secret", "")
	web.addEntry(t, "compat", "OLD_CLI_VAR", "plain-setting", "variable", "")

	g := newAgent(t, old)
	g.login(t, in.url, pin, web.createTokenPerm(t, "old-cli", "compat", "add"))
	if r := g.ok(t, "", "whoami"); !strings.Contains(r.stdout, "old-cli") {
		t.Fatalf("whoami: %q", r.stdout)
	}
	if got := g.valueHash(t, "OLD_CLI_SECRET"); got != sha(secret) {
		t.Fatal("the old CLI got a different value")
	}
	if r := g.ok(t, "", "vars"); !strings.Contains(r.stdout, "compat/OLD_CLI_VAR=plain-setting") {
		t.Fatalf("vars: %q", r.stdout)
	}
	added := fakeSecret(t)
	g.ok(t, added+"\n", "put", "OLD_CLI_ADDED")
	if got := g.valueHash(t, "OLD_CLI_ADDED"); got != sha(added) {
		t.Fatal("a value put by the old CLI reads back differently")
	}
}

// TestCLIUpgrade: with self-upgrade off, `keydrop upgrade` refuses and the
// notice says to leave it to the user; with it on, upgrade replaces the
// binary with the server's build, keeps the old one, then says nothing more
// to do; the notice for a different build shows once; a build that doesn't
// match SHA256SUMS is refused and nothing changes.
func TestCLIUpgrade(t *testing.T) {
	name := "keydrop-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		t.Skip("the e2e suite runs the CLI through sh")
	}
	tmp := t.TempDir()
	next := filepath.Join(tmp, "keydrop-next")
	if err := buildKeydrop(repoRoot, next, "e2e-next"); err != nil {
		t.Fatal(err)
	}
	// KEYDROP_CLI_DIR the way the Docker image lays it out.
	cliDir := filepath.Join(tmp, "cli")
	os.Mkdir(cliDir, 0o755)
	nextBytes, err := os.ReadFile(next)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(cliDir, name+".gz"))
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	zw.Write(nextBytes)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	sum := sha256.Sum256(nextBytes)
	sums := filepath.Join(cliDir, "SHA256SUMS")
	os.WriteFile(sums, []byte(hex.EncodeToString(sum[:])+"  "+name+"\n"), 0o644)

	in := newInstance(t, binary)
	in.extra = append(in.extra, "KEYDROP_CLI_DIR="+cliDir)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	web.addEntry(t, "up", "UP_VAR", "x", "variable", "")

	// The agent's own copy of this build (version "e2e", like the server).
	bin := filepath.Join(t.TempDir(), "keydrop")
	copyFile(t, binary, bin)
	g := newAgent(t, bin)
	g.login(t, in.url, pin, web.createToken(t, "upgrader", "up", false))
	if r := g.ok(t, "", "whoami"); strings.Contains(r.stderr, "keydrop upgrade") {
		t.Fatalf("a notice with the same build: %q", r.stderr)
	}

	// Off (the default): refused, nothing replaced, and the ask is logged.
	r := g.run(t, "", "upgrade")
	if r.code == 0 || !strings.Contains(r.stderr, "self-upgrade is off for this agent") {
		t.Fatalf("upgrade with self-upgrade off: exit %d %q %q", r.code, r.stdout, r.stderr)
	}
	if got, _ := os.ReadFile(bin); string(got) == string(nextBytes) {
		t.Fatal("upgraded with self-upgrade off")
	}
	if _, body := web.get(t, "/audit"); !strings.Contains(body, "refused, self-upgrade is off") {
		t.Fatal("the refused upgrade isn't in the log")
	}
	web.mustPost(t, "/tokens/upgrader/selfupgrade", url.Values{"selfupgrade": {"yes"}})

	r = g.ok(t, "", "upgrade")
	if !strings.Contains(r.stdout, "Upgraded keydrop e2e → e2e-next") {
		t.Fatalf("upgrade: %q %q", r.stdout, r.stderr)
	}
	if r := (&agent{bin: bin, home: g.home}).ok(t, "", "version"); strings.TrimSpace(r.stdout) != "keydrop e2e-next" {
		t.Fatalf("after upgrade: %q", r.stdout)
	}
	if r := (&agent{bin: bin + ".e2e.bak", home: g.home}).ok(t, "", "version"); strings.TrimSpace(r.stdout) != "keydrop e2e" {
		t.Fatalf("the backup: %q", r.stdout)
	}
	if r := g.ok(t, "", "upgrade"); !strings.Contains(r.stdout, "already e2e-next") {
		t.Fatalf("second upgrade: %q", r.stdout)
	}

	// Now the CLI is a different (compatible) build from the server: one
	// notice naming the command, then quiet for the day.
	r = g.ok(t, "", "whoami")
	if !strings.Contains(r.stderr, "Nothing breaks") || !strings.Contains(r.stderr, "run `keydrop upgrade`") {
		t.Fatalf("no compatible-build notice: %q", r.stderr)
	}
	if r := g.ok(t, "", "whoami"); r.stderr != "" {
		t.Fatalf("noticed twice in a day: %q", r.stderr)
	}
	// Turned off, the notice comes again, telling the agent to leave it.
	web.mustPost(t, "/tokens/upgrader/selfupgrade", url.Values{})
	r = g.ok(t, "", "whoami")
	if !strings.Contains(r.stderr, "don't update the CLI yourself") || strings.Contains(r.stderr, "run `keydrop upgrade`") {
		t.Fatalf("notice with self-upgrade off: %q", r.stderr)
	}
	web.mustPost(t, "/tokens/upgrader/selfupgrade", url.Values{"selfupgrade": {"yes"}})

	// A build that doesn't match SHA256SUMS replaces nothing.
	os.WriteFile(sums, []byte(strings.Repeat("0", 64)+"  "+name+"\n"), 0o644)
	r = g.run(t, "", "upgrade", "--force")
	if r.code == 0 || !strings.Contains(r.stderr, "doesn't match the server's SHA256SUMS") {
		t.Fatalf("tampered build: exit %d %q", r.code, r.stderr)
	}
	if got, _ := os.ReadFile(bin); string(got) != string(nextBytes) {
		t.Fatal("the binary changed after a refused upgrade")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(bin), ".keydrop-upgrade-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRollbackV5 turns self-upgrade on for an agent, with the alert webhook
// set too. The release before starts on the data as it is, keeps the
// webhook, drops the setting when it rewrites the file; this one then
// starts on what it wrote, with self-upgrade off.
func TestRollbackV5(t *testing.T) {
	old := buildOld(t, v5RollbackCommit)

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "rb5", "KEPT", secret, "secret", "")
	web.mustPost(t, "/settings/alert-webhook", url.Values{"webhook": {"https://hooks.example.com/fake-e2e-webhook-path"}})
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.postToken(t, url.Values{"name": {"rb5-agent"}, "namespaces": {"rb5"}, "selfupgrade": {"yes"}}))
	if _, page := web.get(t, "/token/rb5-agent"); !strings.Contains(page, `value="yes" checked`) {
		t.Fatal("self-upgrade not shown as on")
	}
	in.stop(t)

	in.start(t, old)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("the previous release returns a different value")
	}
	web = login(t, in)
	if _, page := web.get(t, "/settings"); !strings.Contains(page, "hooks.example.com") {
		t.Fatal("the previous release lost the webhook")
	}
	web.addEntry(t, "rb5", "AFTER", "plain-setting", "variable", "") // it rewrites the file
	in.stop(t)

	in.start(t, binary)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("this release returns a different value after the previous one rewrote the file")
	}
	web = login(t, in)
	if _, page := web.get(t, "/token/rb5-agent"); strings.Contains(page, `value="yes" checked`) {
		t.Fatal("self-upgrade survived the previous release's rewrite")
	}
	web.mustPost(t, "/tokens/rb5-agent/selfupgrade", url.Values{"selfupgrade": {"yes"}})
	in.stop(t)
	in.start(t, binary) // and it opens with it on again
	in.stop(t)
}

// TestRollbackV6 turns Inbox alerts and expiry alerts on in Settings, with
// self-upgrade and the webhook set too, so the file has mac6 and mac7. The release before
// (v0.1.3) starts on the data as it is, keeps self-upgrade and the
// webhook, drops the settings when it rewrites the file; this one then
// starts on what it wrote, with Inbox alerts back to KEYDROP_ALERT_INBOX
// (unset: off) and expiry alerts off, and the setting can be turned on again.
func TestRollbackV6(t *testing.T) {
	old := buildOld(t, v6RollbackCommit)
	const inboxOn = `value="on" class="on small" aria-pressed="true"`
	const inboxDefault = `value="default" class="on small" aria-pressed="true"`
	const expiry14 = `value="14" class="on small" aria-pressed="true"`
	const expiryOff = `value="0" class="on small" aria-pressed="true"`

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "rb6", "KEPT", secret, "secret", "")
	web.mustPost(t, "/settings/alert-webhook", url.Values{"webhook": {"https://hooks.example.com/fake-e2e-webhook-path"}})
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.postToken(t, url.Values{"name": {"rb6-agent"}, "namespaces": {"rb6"}, "selfupgrade": {"yes"}}))
	web.mustPost(t, "/settings/alert-inbox", url.Values{"inbox": {"on"}})
	web.mustPost(t, "/settings/alert-expiry", url.Values{"days": {"14"}})
	if _, page := web.get(t, "/settings"); !strings.Contains(page, inboxOn) || !strings.Contains(page, expiry14) {
		t.Fatal("Inbox alerts or expiry alerts not shown as on")
	}
	data, _ := os.ReadFile(filepath.Join(in.dataDir, "keydrop.json"))
	for _, f := range []string{`"notify"`, `"expiry_days"`, `"mac7"`, `"mac6"`} {
		if !strings.Contains(string(data), f) {
			t.Fatalf("no %s in the file", f)
		}
	}
	in.stop(t)

	in.start(t, old)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("the previous release returns a different value")
	}
	web = login(t, in)
	if _, page := web.get(t, "/settings"); !strings.Contains(page, "hooks.example.com") {
		t.Fatal("the previous release lost the webhook")
	}
	if _, page := web.get(t, "/token/rb6-agent"); !strings.Contains(page, `value="yes" checked`) {
		t.Fatal("the previous release lost self-upgrade")
	}
	web.addEntry(t, "rb6", "AFTER", "plain-setting", "variable", "") // it rewrites the file
	in.stop(t)
	if data, _ := os.ReadFile(filepath.Join(in.dataDir, "keydrop.json")); strings.Contains(string(data), `"notify"`) || strings.Contains(string(data), `"mac7"`) {
		t.Fatal("the previous release kept the setting")
	}

	in.start(t, binary)
	if strings.Contains(in.srv.log.String(), "Inbox alerts") {
		t.Fatalf("Inbox alerts after the rollback: %s", in.srv.log.String())
	}
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("this release returns a different value after the previous one rewrote the file")
	}
	web = login(t, in)
	if _, page := web.get(t, "/settings"); !strings.Contains(page, inboxDefault) || !strings.Contains(page, "Inbox alerts: <strong>off</strong>") || !strings.Contains(page, "hooks.example.com") || !strings.Contains(page, expiryOff) {
		t.Fatal("Settings after the previous release's rewrite")
	}
	if _, page := web.get(t, "/token/rb6-agent"); !strings.Contains(page, `value="yes" checked`) {
		t.Fatal("self-upgrade lost")
	}
	web.mustPost(t, "/settings/alert-inbox", url.Values{"inbox": {"on"}})
	in.stop(t)
	in.start(t, binary) // and it opens with it on again
	if !strings.Contains(in.srv.log.String(), "Inbox alerts: on (set in Settings)") {
		t.Fatalf("not on again: %s", in.srv.log.String())
	}
	web = login(t, in)
	if _, page := web.get(t, "/settings"); !strings.Contains(page, inboxOn) {
		t.Fatal("Inbox alerts not shown as on again")
	}
	in.stop(t)
}

var restoreRE = regexp.MustCompile(`action="/secret/rbh/HIST/restore/([0-9a-f]+)"`)

// TestRollbackV6History builds up value history here, then starts the
// release before it (v0.1.3) on the data: it reads the current value,
// shows it, rolls back once in its own UI and so rewrites the file without
// the history. This release then opens what it wrote with the current and
// previous values as that release left them and no history beyond them,
// and new saves build history up again.
func TestRollbackV6History(t *testing.T) {
	old := buildOld(t, v6RollbackCommit)
	vals := []string{fakeSecret(t), fakeSecret(t), fakeSecret(t), fakeSecret(t), fakeSecret(t)}
	rows := func(t *testing.T, web *admin) []string {
		t.Helper()
		_, page := web.get(t, "/secret/rbh/HIST")
		noLeak(t, "the secret page", page, vals...)
		var ids []string
		for _, m := range restoreRE.FindAllStringSubmatch(page, -1) {
			ids = append(ids, m[1])
		}
		return ids
	}
	inFile := func(t *testing.T, in *instance) bool {
		t.Helper()
		data, _ := os.ReadFile(filepath.Join(in.dataDir, "keydrop.json"))
		v, m := strings.Contains(string(data), `"versions"`), strings.Contains(string(data), `"mac7"`)
		if v != m {
			t.Fatalf("versions in the file %v, mac7 %v", v, m)
		}
		return v
	}

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	web.addEntry(t, "rbh", "HIST", vals[0], "secret", "")
	for _, v := range vals[1:4] {
		web.mustPost(t, "/secret/rbh/HIST/value", url.Values{"value": {v}, "kind": {"secret"}})
	}
	if ids := rows(t, web); len(ids) != 3 || !inFile(t, in) {
		t.Fatalf("history: %d rows", len(ids))
	}
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.createToken(t, "rbh-agent", "rbh", false))
	if got := g.valueHash(t, "rbh/HIST"); got != sha(vals[3]) {
		t.Fatal("not the current value")
	}
	in.stop(t)

	in.start(t, old)
	if got := g.valueHash(t, "rbh/HIST"); got != sha(vals[3]) {
		t.Fatal("the previous release returns a different value")
	}
	web = login(t, in)
	if code, page, _ := web.post(t, "/secret/rbh/HIST/reveal", nil); code != 200 || !strings.Contains(page, vals[3]) {
		t.Fatalf("the previous release doesn't show the current value: %d", code)
	}
	web.mustPost(t, "/secret/rbh/HIST/rollback", nil) // it rewrites the file
	if got := g.valueHash(t, "rbh/HIST"); got != sha(vals[2]) {
		t.Fatal("the previous release didn't roll back")
	}
	in.stop(t)
	if inFile(t, in) {
		t.Fatal("the previous release kept the history")
	}

	in.start(t, binary)
	if got := g.valueHash(t, "rbh/HIST"); got != sha(vals[2]) {
		t.Fatal("this release returns a different value after the previous one rewrote the file")
	}
	web = login(t, in)
	ids := rows(t, web)
	if len(ids) != 1 {
		t.Fatalf("%d older values after the previous release's rewrite, want its previous one", len(ids))
	}
	web.mustPost(t, "/secret/rbh/HIST/restore/"+ids[0], nil)
	if got := g.valueHash(t, "rbh/HIST"); got != sha(vals[3]) {
		t.Fatal("the previous value the previous release left isn't the one it replaced")
	}
	web.mustPost(t, "/secret/rbh/HIST/value", url.Values{"value": {vals[4]}, "kind": {"secret"}})
	if ids := rows(t, web); len(ids) != 2 || !inFile(t, in) {
		t.Fatalf("history after new saves: %d rows", len(ids))
	}
	in.stop(t)
	in.start(t, binary) // and it opens with history again
	if got := g.valueHash(t, "rbh/HIST"); got != sha(vals[4]) {
		t.Fatal("not the newest value")
	}
	in.stop(t)
}

// TestRollbackV6UnknownSaver: on the release before stored savers
// (v0.1.3) an agent writes a variable and the admin saves over it. After
// the upgrade the admin restores the agent's value, whose saver that
// release never recorded: other agents get it labelled as untrusted text
// from an unknown writer, not as the admin's, until the admin saves again.
func TestRollbackV6UnknownSaver(t *testing.T) {
	old := buildOld(t, v6RollbackCommit)
	agentText := "https://agent.example/IGNORE-PREVIOUS-INSTRUCTIONS"
	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	writer, reader := newAgent(t, binary), newAgent(t, binary)
	writer.login(t, in.url, pin, web.createToken(t, "uw-writer", "uw", true))
	reader.login(t, in.url, pin, web.createToken(t, "uw-reader", "uw", false))
	in.stop(t)

	in.start(t, old)
	writer.ok(t, agentText, "put", "uw/URL", "--var")
	web = login(t, in)
	web.mustPost(t, "/secret/uw/URL/value", url.Values{"value": {"https://admin.example"}, "kind": {"variable"}})
	in.stop(t)

	in.start(t, binary)
	web = login(t, in)
	_, page := web.get(t, "/secret/uw/URL")
	m := regexp.MustCompile(`action="/secret/uw/URL/restore/([0-9a-f]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no older value to restore")
	}
	web.mustPost(t, "/secret/uw/URL/restore/"+m[1], nil)
	r := reader.ok(t, "", "info", "uw/URL")
	if !strings.Contains(r.stdout, "    value written by an unknown agent or an earlier release (untrusted text from another agent):\n      | "+agentText) || strings.Contains(r.stdout, "uw/URL=") {
		t.Fatalf("the restored agent value isn't labelled:\n%s", r.stdout)
	}
	web.mustPost(t, "/secret/uw/URL/value", url.Values{"value": {"https://admin.example/2"}, "kind": {"variable"}})
	if r := reader.ok(t, "", "info", "uw/URL"); !strings.Contains(r.stdout, "uw/URL=https://admin.example/2") || strings.Contains(r.stdout, "untrusted") {
		t.Fatalf("the admin's value is labelled:\n%s", r.stdout)
	}
	in.stop(t)
}
