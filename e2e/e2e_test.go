//go:build e2e

// Package e2e tests the real keydrop binary as users run it: the server as
// a subprocess, the admin through the web forms (no browser), and agents
// through the CLI. Run it with
//
//	go test -tags e2e ./e2e/...
//
// It builds the binary once, and for the upgrade test the release at
// oldFormatCommit (needs git history; skipped in a shallow clone).
package e2e

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// oldFormatCommit is the last commit that writes the data format before
// the integrity check (no HMAC, plaintext tls.key).
const oldFormatCommit = "57fef22"

var (
	binary   string // the keydrop under test, built by TestMain
	repoRoot string
)

func TestMain(m *testing.M) {
	os.Exit(func() int {
		root, err := filepath.Abs("..")
		if err != nil {
			panic(err)
		}
		repoRoot = root
		dir, err := os.MkdirTemp("", "keydrop-e2e-bin-")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		binary = filepath.Join(dir, "keydrop")
		if err := buildKeydrop(root, binary, "e2e"); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			return 1
		}
		return m.Run()
	}())
}

// The subtests share one server and build on each other, in order, the way
// a deployment's life goes: set up, pair, use, restart, rotate. Subtest 09
// has its own data directory.
func TestEndToEnd(t *testing.T) {
	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)

	var (
		web    *admin
		agent1 = newAgent(t, binary) // paired, read-only, namespace e2e
		writer = newAgent(t, binary) // a write token made by hand (04), revoked (05)
		secret = fakeSecret(t)
	)
	const (
		ns     = "e2e"
		varVal = "https://api.example.com/v1"
	)
	// Each step needs the ones before it, so the first failure ends the run.
	step := func(name string, f func(t *testing.T)) {
		t.Helper()
		if !t.Run(name, f) {
			t.FailNow()
		}
	}

	step("01 setup, then pairing approved in the UI; pins agree; whoami", func(t *testing.T) {
		if got := servedPin(t, in.addr); got != pin {
			t.Fatalf("the certificate served hashes to %s, the log says %s", got, pin)
		}
		web = setupAndLogin(t, in)

		// The admin middleware refuses a cross-site POST and a missing CSRF
		// token, before anything changes.
		if code, _, _ := web.postAs(t, "cross-site", "/tokens", url.Values{"name": {"x"}, "namespaces": {ns}}); code != http.StatusForbidden {
			t.Fatalf("cross-site POST: %d, want 403", code)
		}
		if code, _, _ := web.post(t, "/tokens", url.Values{"csrf": {"wrong"}, "name": {"x"}, "namespaces": {ns}}); code != http.StatusForbidden {
			t.Fatalf("POST with a wrong CSRF token: %d, want 403", code)
		}

		out := &syncBuffer{}
		pair := exec.Command(binary, "pair", "--url", in.url, "--pin", pin)
		pair.Env = agent1.env()
		pair.Stdout, pair.Stderr = out, out
		if err := pair.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- pair.Wait() }()
		t.Cleanup(func() { pair.Process.Kill() })

		linkRE := regexp.MustCompile(`/pair/([A-Za-z0-9_-]+)\s`)
		codeRE := regexp.MustCompile(`show the code ([A-Z0-9]{3}-[A-Z0-9]{3})`)
		waitFor(t, "keydrop pair to print its link", 20*time.Second, func() bool {
			return linkRE.MatchString(out.String()) && codeRE.MatchString(out.String())
		})
		id := linkRE.FindStringSubmatch(out.String())[1]
		code := codeRE.FindStringSubmatch(out.String())[1]

		status, page := web.get(t, "/pair/"+id)
		if status != http.StatusOK || !strings.Contains(page, code) || !strings.Contains(page, "127.0.0.1") {
			t.Fatalf("GET /pair/%s: %d, want the code %s and the address:\n%s", id, status, code, page)
		}
		web.mustPost(t, "/pair/"+id+"/approve", url.Values{"name": {"agent1"}, "namespaces": {ns}, "sources": {"127.0.0.1"}})

		select {
		case err := <-done:
			if err != nil || !strings.Contains(out.String(), "Approved as agent1") {
				t.Fatalf("keydrop pair: %v\n%s", err, out)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("keydrop pair didn't collect the token:\n%s", out)
		}
		for _, f := range []string{"url", "token", "pin"} {
			fi, err := os.Stat(filepath.Join(agent1.configDir(), f))
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v, mode %v; want 0600", f, err, fi.Mode())
			}
		}
		if b, _ := os.ReadFile(filepath.Join(agent1.configDir(), "pin")); strings.TrimSpace(string(b)) != pin {
			t.Fatalf("saved pin %q, want the server's", b)
		}
		r := agent1.ok(t, "", "whoami")
		if !strings.Contains(r.stdout, "agent1 @ "+in.url) || !strings.Contains(r.stdout, "namespaces: e2e") || !strings.Contains(r.stdout, "write: false") {
			t.Fatalf("whoami: %q", r.stdout)
		}
	})

	step("02 secrets and vars are listed without the secret's value", func(t *testing.T) {
		web.addEntry(t, ns, "API_TOKEN", secret, "secret", "Test API key for the e2e suite")
		web.addEntry(t, ns, "API_URL", varVal, "variable", "Base URL")
		if _, page := web.get(t, "/"); !strings.Contains(page, "API_TOKEN") {
			t.Fatal("the dashboard doesn't list API_TOKEN")
		} else {
			noLeak(t, "dashboard", page, secret)
		}

		secrets := agent1.ok(t, "", "secrets")
		if !strings.Contains(secrets.stdout, "e2e/API_TOKEN") || strings.Contains(secrets.stdout, "API_URL") {
			t.Fatalf("secrets: %q", secrets.stdout)
		}
		vars := agent1.ok(t, "", "vars")
		if !strings.Contains(vars.stdout, "e2e/API_URL="+varVal) || strings.Contains(vars.stdout, "API_TOKEN") {
			t.Fatalf("vars: %q", vars.stdout)
		}
		info := agent1.ok(t, "", "info", "API_TOKEN")
		if !strings.Contains(info.stdout, "Test API key for the e2e suite") {
			t.Fatalf("info: %q", info.stdout)
		}
		inbox := agent1.ok(t, "", "inbox")
		if !strings.Contains(inbox.stdout, "e2e/API_TOKEN") {
			t.Fatalf("inbox: %q", inbox.stdout)
		}
		get := agent1.run(t, "", "get", "API_TOKEN") // a plain get refuses a secret
		if get.code == 0 || !strings.Contains(get.stderr, "is a secret") {
			t.Fatalf("get of a secret: exit %d, %q", get.code, get.stderr)
		}
		for name, r := range map[string]result{"secrets": secrets, "vars": vars, "info": info, "inbox": inbox, "get": get} {
			noLeak(t, name, r.all(), secret)
		}
	})

	step("03 run masks output, passes the exit code, keeps values out of argv and KEYDROP_* out of the env", func(t *testing.T) {
		g := *agent1
		// Settings a user might have in their environment: run must not
		// pass any of them on.
		g.extra = []string{"KEYDROP_AGENT=e2e", "KEYDROP_TLS_PIN=" + pin, "KEYDROP_URL=" + in.url}

		r := g.run(t, "", "run", "-e", "API_TOKEN", "--", "sh", "-c",
			`echo "$API_TOKEN"; printf %s "$API_TOKEN" | base64; printf %s "user:$API_TOKEN" | base64; exit 7`)
		if r.code != 7 {
			t.Fatalf("exit %d, want the child's 7; stderr: %s", r.code, r.stderr)
		}
		noLeak(t, "run", r.all(), secret)
		lines := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 lines of output, got %d", len(lines))
		}
		for i, l := range lines {
			if !strings.Contains(l, "[keydrop:API_TOKEN]") {
				t.Errorf("line %d isn't masked: %q", i+1, strings.ReplaceAll(l, secret, "<VALUE>"))
			}
		}
		// Basic auth: "user:" shifts the secret off base64's 3-byte grid. Only
		// the characters that mix in a neighbouring byte may stay visible.
		basic := base64.StdEncoding.EncodeToString([]byte("user:" + secret))
		if inner := basic[8 : len(basic)-3]; strings.Contains(r.stdout, inner) {
			t.Fatal("the secret's part of a Basic-auth header got through unmasked")
		}

		// The value goes only into the environment: the child's argv is
		// exactly what was given (unmasked, so a value there would show).
		r = g.ok(t, "", "run", "--no-mask", "-e", "API_TOKEN", "--", "sh", "-c", `printf '<%s>\n' "$0" "$@"`, "arg0", "a b", "API_TOKEN")
		if r.stdout != "<arg0>\n<a b>\n<API_TOKEN>\n" {
			t.Fatalf("child argv: %q", strings.ReplaceAll(r.stdout, secret, "<VALUE>"))
		}

		r = g.ok(t, "", "run", "-e", "API_TOKEN", "-e", "BASE=API_URL", "--", "env")
		var sawSecret, sawVar bool
		for _, l := range strings.Split(r.stdout, "\n") {
			switch {
			case strings.HasPrefix(l, "KEYDROP_"):
				t.Errorf("the child got %s", strings.SplitN(l, "=", 2)[0])
			case l == "API_TOKEN=[keydrop:API_TOKEN]":
				sawSecret = true
			case l == "BASE="+varVal: // variables aren't masked
				sawVar = true
			}
		}
		if !sawSecret || !sawVar {
			t.Fatalf("env: secret masked %v, variable renamed %v", sawSecret, sawVar)
		}
		noLeak(t, "env", r.all(), secret)

		if got := agent1.valueHash(t, "API_TOKEN"); got != sha(secret) {
			t.Fatal("the child got a different value than was stored")
		}
	})

	step("04 read-only token can't put; a write token can; requests can't be taken over", func(t *testing.T) {
		r := agent1.run(t, "generated-value-1234\n", "put", "GENERATED")
		if r.code == 0 || !strings.Contains(r.stderr, "can't write") {
			t.Fatalf("put with a read-only token: exit %d, %q", r.code, r.stderr)
		}

		writer.login(t, in.url, pin, web.createToken(t, "writer", ns, true))
		if w := writer.ok(t, "", "whoami"); !strings.Contains(w.stdout, "write: true") {
			t.Fatalf("whoami: %q", w.stdout)
		}
		generated := fakeSecret(t)
		writer.ok(t, generated+"\n", "put", "GENERATED", "--desc", "made by the writer")
		if s := agent1.ok(t, "", "secrets"); !strings.Contains(s.stdout, "e2e/GENERATED") {
			t.Fatalf("agent1 doesn't see the put: %q", s.stdout)
		}
		if got := agent1.valueHash(t, "GENERATED"); got != sha(generated) {
			t.Fatal("GENERATED reads back different")
		}

		writer.ok(t, "", "request", "NEEDED", "--desc", "asked by the writer")
		r = agent1.run(t, "", "request", "NEEDED", "--desc", "asked by someone else")
		if r.code == 0 || !strings.Contains(r.stderr, "already requested by another agent") {
			t.Fatalf("second request: exit %d, %q", r.code, r.stderr)
		}
		info := agent1.ok(t, "", "info", "NEEDED")
		if !strings.Contains(info.stdout, "asked by the writer") || strings.Contains(info.stdout, "someone else") {
			t.Fatalf("the request's description changed: %q", info.stdout)
		}

		// Revoked here, checked in the next subtest.
		web.mustPost(t, "/tokens/writer/revoke", url.Values{"confirm": {"yes"}})
	})

	step("05 a revoked token gets an auth error", func(t *testing.T) {
		r := writer.run(t, "", "whoami")
		if r.code == 0 || !strings.Contains(r.stderr, "invalid token") || !strings.Contains(r.stderr, "401") {
			t.Fatalf("whoami after revoke: exit %d, %q", r.code, r.stderr)
		}
		if _, page := web.get(t, "/audit"); !strings.Contains(page, "token.revoke") {
			t.Fatal("the revoke isn't in the log")
		}
	})

	step("06 a wrong pin is refused before the token is sent", func(t *testing.T) {
		g := *agent1
		g.extra = []string{"KEYDROP_TLS_PIN=sha256:" + strings.Repeat("0", 64)}
		before, beforeUnauth := in.auditLines(t)
		r := g.run(t, "", "run", "-e", "API_TOKEN", "--", "true")
		if r.code == 0 || !strings.Contains(r.stderr, "doesn't match") {
			t.Fatalf("wrong pin: exit %d, %q", r.code, r.stderr)
		}
		after, afterUnauth := in.auditLines(t)
		if after != before || afterUnauth != beforeUnauth {
			t.Fatalf("the server logged something for a call that should never have reached it:\n%s%s",
				strings.TrimPrefix(after, before), strings.TrimPrefix(afterUnauth, beforeUnauth))
		}
		// The same call with the right pin is logged, so the check above
		// would have seen it.
		agent1.ok(t, "", "run", "-e", "API_TOKEN", "--", "true")
		if after, _ := in.auditLines(t); !strings.Contains(strings.TrimPrefix(after, before), `"secret.read"`) {
			t.Fatal("a secret read with the right pin wasn't logged")
		}
	})

	step("07 get --to-file writes 0600; --force replaces a 0644 file and a symlink without following it", func(t *testing.T) {
		dir := t.TempDir()
		mode := func(p string) os.FileMode {
			fi, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			return fi.Mode()
		}
		content := func(p string) string {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}

		a := filepath.Join(dir, "a")
		r := agent1.ok(t, "", "get", "API_TOKEN", "--to-file", a)
		noLeak(t, "get --to-file", r.all(), secret)
		if m := mode(a); m != 0o600 || content(a) != secret {
			t.Fatalf("new file: mode %v, right content %v", m, content(a) == secret)
		}
		if r := agent1.run(t, "", "get", "API_TOKEN", "--to-file", a); r.code == 0 {
			t.Fatal("an existing file was overwritten without --force")
		}

		loose := filepath.Join(dir, "loose")
		os.WriteFile(loose, []byte("old"), 0o644)
		os.Chmod(loose, 0o644) // whatever the umask
		agent1.ok(t, "", "get", "API_TOKEN", "--to-file", loose, "--force")
		if m := mode(loose); m != 0o600 || content(loose) != secret {
			t.Fatalf("--force over a 0644 file: mode %v, right content %v", m, content(loose) == secret)
		}

		victim, link := filepath.Join(dir, "victim"), filepath.Join(dir, "link")
		os.WriteFile(victim, []byte("untouched"), 0o644)
		os.Chmod(victim, 0o644)
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if r := agent1.run(t, "", "get", "API_TOKEN", "--to-file", link); r.code == 0 {
			t.Fatal("a symlink was written through without --force")
		}
		agent1.ok(t, "", "get", "API_TOKEN", "--to-file", link, "--force")
		if m := mode(link); m != 0o600 || content(link) != secret {
			t.Fatalf("--force over a symlink: mode %v (want a regular 0600 file)", m)
		}
		if m := mode(victim); content(victim) != "untouched" || m != 0o644 {
			t.Fatalf("the symlink's target was changed: mode %v", m)
		}
	})

	step("08 restart on the same data: secrets decrypt, pin unchanged, audit log kept", func(t *testing.T) {
		before, _ := in.auditLines(t)
		in.stop(t)
		in.start(t, binary)
		if got := in.pin(t); got != pin {
			t.Fatalf("pin changed across a restart: %s → %s", pin, got)
		}
		if got := servedPin(t, in.addr); got != pin {
			t.Fatalf("served pin %s, want %s", got, pin)
		}
		if after, _ := in.auditLines(t); !strings.HasPrefix(after, before) || before == "" {
			t.Fatal("the audit log lost entries across the restart")
		}
		if got := agent1.valueHash(t, "API_TOKEN"); got != sha(secret) {
			t.Fatal("API_TOKEN doesn't decrypt to the same value after a restart")
		}
		// Sessions don't survive a restart; the log shown in the UI does.
		web = login(t, in)
		if _, page := web.get(t, "/audit"); !strings.Contains(page, "token.revoke") || !strings.Contains(page, "pair.approve") {
			t.Fatal("the UI's log lost events from before the restart")
		}
	})

	step("09 upgrade from the previous data format, and back", func(t *testing.T) {
		testUpgrade(t)
	})

	step("10 rotate-tls: new pin, the old one refused, re-pin with login", func(t *testing.T) {
		in.stop(t)
		out, code := in.command(t, binary, "rotate-tls")
		m := regexp.MustCompile(`New pin: (sha256:[0-9a-f]{64})`).FindStringSubmatch(out)
		if code != 0 || m == nil {
			t.Fatalf("rotate-tls: exit %d:\n%s", code, out)
		}
		newPin := m[1]
		if newPin == pin {
			t.Fatal("rotate-tls kept the pin")
		}
		baks, _ := filepath.Glob(filepath.Join(in.dataDir, "tls.*.bak"))
		if len(baks) != 2 {
			t.Fatalf("want the old tls.crt and tls.key kept as .bak, got %v", baks)
		}
		in.start(t, binary)
		if got := in.pin(t); got != newPin {
			t.Fatalf("server pin %s, rotate-tls said %s", got, newPin)
		}

		r := agent1.run(t, "", "whoami")
		if r.code == 0 || !strings.Contains(r.stderr, "doesn't match") {
			t.Fatalf("whoami with the old pin: exit %d, %q", r.code, r.stderr)
		}

		// The re-pin command, exactly as rotate-tls printed it.
		repin := regexp.MustCompile(`(?m)^\s*(keydrop login --url .*)$`).FindStringSubmatch(out)
		if repin == nil || !strings.Contains(repin[1], newPin) {
			t.Fatalf("rotate-tls didn't print the re-pin command:\n%s", out)
		}
		sh := exec.Command("sh", "-c", repin[1])
		sh.Env = append(agent1.env(), "PATH="+filepath.Dir(binary)+":"+os.Getenv("PATH"))
		sh.Dir = agent1.home
		var outb bytes.Buffer
		sh.Stdout, sh.Stderr = &outb, &outb
		if err := sh.Run(); err != nil {
			t.Fatalf("%s: %v\n%s", repin[1], err, outb.String())
		}
		if r := agent1.ok(t, "", "whoami"); !strings.Contains(r.stdout, "agent1 @") {
			t.Fatalf("whoami after re-pinning: %q", r.stdout)
		}
		if got := agent1.valueHash(t, "API_TOKEN"); got != sha(secret) {
			t.Fatal("API_TOKEN reads differently after re-pinning")
		}
	})
}

// testUpgrade builds the release before the integrity check, makes data
// with it, and moves that data to this release and back.
func testUpgrade(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git isn't installed, so the old release can't be built")
	}
	if err := exec.Command("git", "-C", repoRoot, "cat-file", "-e", oldFormatCommit+"^{commit}").Run(); err != nil {
		t.Skipf("commit %s isn't in this clone (shallow? fetch with fetch-depth: 0), so the old release can't be built", oldFormatCommit)
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	if out, err := exec.Command("git", "-C", repoRoot, "worktree", "add", "--detach", src, oldFormatCommit).CombinedOutput(); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("git", "-C", repoRoot, "worktree", "remove", "--force", src).Run()
		exec.Command("git", "-C", repoRoot, "worktree", "prune").Run()
	})
	old := filepath.Join(tmp, "keydrop-old")
	if err := buildKeydrop(src, old, "dev"); err != nil {
		t.Fatal(err)
	}

	// Data made by the old release: an admin, a token, a secret, a variable.
	in := newInstance(t, binary)
	in.start(t, old)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "legacy", "OLD_SECRET", secret, "secret", "made by the old release")
	web.addEntry(t, "legacy", "OLD_VAR", "plain-setting", "variable", "")
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.createToken(t, "legacy-agent", "legacy", false))
	if got := g.valueHash(t, "OLD_SECRET"); got != sha(secret) {
		t.Fatal("the old server returns a different value")
	}
	in.stop(t)

	state := filepath.Join(in.dataDir, "keydrop.json")
	stateBefore, _ := os.ReadFile(state)
	out, code := in.command(t, binary, "server")
	if code == 0 || !strings.Contains(out, "keydrop upgrade-data") {
		t.Fatalf("the new server on old data: exit %d, want a refusal naming upgrade-data:\n%s", code, out)
	}
	if b, _ := os.ReadFile(state); !bytes.Equal(b, stateBefore) {
		t.Fatal("the refused start changed keydrop.json")
	}

	out, code = in.command(t, binary, "upgrade-data")
	if code != 0 || !strings.Contains(out, "Certificate pin (unchanged): "+pin) || !strings.Contains(out, "tls.key: sealed") {
		t.Fatalf("upgrade-data: exit %d:\n%s", code, out)
	}
	in.start(t, binary)
	if got := in.pin(t); got != pin {
		t.Fatalf("pin after upgrade-data %s, was %s", got, pin)
	}
	if got := g.valueHash(t, "OLD_SECRET"); got != sha(secret) {
		t.Fatal("the upgraded data returns a different value")
	}
	if r := g.ok(t, "", "vars"); !strings.Contains(r.stdout, "legacy/OLD_VAR=plain-setting") {
		t.Fatalf("vars after upgrade: %q", r.stdout)
	}
	in.stop(t)

	out, code = in.command(t, binary, "downgrade-data")
	if code != 0 || !strings.Contains(out, "tls.key: written back in plaintext") {
		t.Fatalf("downgrade-data: exit %d:\n%s", code, out)
	}
	in.start(t, old)
	if got := in.pin(t); got != pin {
		t.Fatalf("the old release's pin after downgrade-data %s, was %s", got, pin)
	}
	if got := g.valueHash(t, "OLD_SECRET"); got != sha(secret) {
		t.Fatal("the downgraded data returns a different value")
	}
	in.stop(t)
}
