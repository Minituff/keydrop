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
