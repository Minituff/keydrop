//go:build e2e

// Package e2e tests the real keydrop binary as users run it: the server as
// a subprocess, the admin through the web forms (no browser), and agents
// through the CLI. Run it with
//
//	go test -tags e2e ./e2e/...
//
// It builds the binary once, and for the upgrade and rollback tests the
// releases at oldFormatCommit, rollbackCommit, v2RollbackCommit, v3RollbackCommit, v4RollbackCommit and v5RollbackCommit (needs git history;
// skipped in a shallow clone).
package e2e

import (
	"bytes"
	"encoding/base64"
	"fmt"
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

// rollbackCommit is the release before history, flags, statuses, notes
// and the add permission. It must still open what this one writes.
const rollbackCommit = "038a737"

// v2RollbackCommit is the release before groups and batch requests. It
// checks mac2 over everything it parses, so it's a separate case.
const v2RollbackCommit = "733cf9f"

// v3RollbackCommit is the release before token expiry, renewal and
// canaries. It refuses data that used them until downgrade-data is run.
const v3RollbackCommit = "b0b9efe"

// v4RollbackCommit is the release before the alert webhook could be set in
// Settings. It opens data with one set, ignoring it.
const v4RollbackCommit = "7b184c1"

// v5RollbackCommit is the release before an agent could be allowed to
// upgrade its own CLI. It opens data with that on, ignoring it.
const v5RollbackCommit = "cf00c92"

var (
	binary   string // the keydrop under test, built by TestMain
	repoRoot string
	// clockBinary is the same build with a clock tests can move
	// (KEYDROP_E2E_CLOCK_FILE), so tokens can expire.
	clockBinary string
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
		clockBinary = filepath.Join(dir, "keydrop-clock")
		if err := buildKeydrop(root, clockBinary, "e2e", "e2eclock"); err != nil {
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

	step("00 /setup.md, fetched with the key pinned like curl, names this server's pins and nothing secret", func(t *testing.T) {
		keyPin := servedKeyPin(t, in.addr)
		code, guide, err := keyPinnedGet(in.url+"/setup.md", keyPin)
		if err != nil || code != http.StatusOK {
			t.Fatalf("GET /setup.md: %d %v", code, err)
		}
		// The pins in it are those of the certificate actually served.
		for _, want := range []string{"keydrop pair --url " + in.url + " --pin " + servedPin(t, in.addr), "Key pin (`curl --pinnedpubkey` checks it): `" + keyPin + "`"} {
			if !strings.Contains(guide, want) {
				t.Fatalf("setup.md lacks %q:\n%s", want, guide)
			}
		}
		if code := in.setupCode(t); strings.Contains(guide, code) || strings.Contains(guide, code[:3]+"-"+code[3:]) {
			t.Fatal("setup.md holds the setup code")
		}
		// Another key pin is refused before anything is read.
		if _, _, err := keyPinnedGet(in.url+"/setup.md", "sha256//"+base64.StdEncoding.EncodeToString(make([]byte, 32))); err == nil {
			t.Fatal("fetched with a wrong key pin")
		}
	})

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
		if !strings.Contains(r.stdout, "agent1 @ "+in.url) || !strings.Contains(r.stdout, "namespaces: e2e") || !strings.Contains(r.stdout, "permission: read") {
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
		history := agent1.ok(t, "", "history", "API_TOKEN")
		if !strings.Contains(history.stdout, "e2e/API_TOKEN  created") || !strings.Contains(history.stdout, "by admin") {
			t.Fatalf("history: %q", history.stdout)
		}
		// The old names stay for one release: inbox runs history, ack does
		// nothing; both say so on stderr.
		inbox := agent1.ok(t, "", "inbox")
		if !strings.Contains(inbox.stdout, "e2e/API_TOKEN") || !strings.Contains(inbox.stderr, "deprecated") {
			t.Fatalf("inbox: %q, stderr %q", inbox.stdout, inbox.stderr)
		}
		if ack := agent1.ok(t, "", "ack", "API_TOKEN"); !strings.Contains(ack.stderr, "deprecated") {
			t.Fatalf("ack: %q", ack.stderr)
		}
		get := agent1.run(t, "", "get", "API_TOKEN") // a plain get refuses a secret
		if get.code == 0 || !strings.Contains(get.stderr, "is a secret") {
			t.Fatalf("get of a secret: exit %d, %q", get.code, get.stderr)
		}
		for name, r := range map[string]result{"secrets": secrets, "vars": vars, "info": info, "history": history, "inbox": inbox, "get": get} {
			noLeak(t, name, r.all(), secret)
		}
	})

	step("03 run masks output, passes the exit code, keeps values out of argv and KEYDROP_* out of the env", func(t *testing.T) {
		// New until this token reads it.
		if s := agent1.ok(t, "", "secrets", "--new"); !strings.Contains(s.stdout, "e2e/API_TOKEN") {
			t.Fatalf("secrets --new before any read: %q", s.stdout)
		}
		if _, page := web.get(t, "/secret/e2e/API_TOKEN"); !strings.Contains(page, "no agent has picked it up yet") {
			t.Fatal("no new badge before any agent read it")
		}
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
		// Read now: no longer new to agent1, nor on the admin's page.
		if s := agent1.ok(t, "", "secrets", "--new"); strings.Contains(s.stdout, "e2e/API_TOKEN") {
			t.Fatalf("secrets --new after run read it: %q", s.stdout)
		}
		if _, page := web.get(t, "/secret/e2e/API_TOKEN"); strings.Contains(page, "no agent has picked it up yet") {
			t.Fatal("still new on the admin's page after an agent read it")
		}
	})

	step("04 read-only token can't put; a write token can; requests can't be taken over", func(t *testing.T) {
		r := agent1.run(t, "generated-value-1234\n", "put", "GENERATED")
		if r.code == 0 || !strings.Contains(r.stderr, "can't write") {
			t.Fatalf("put with a read-only token: exit %d, %q", r.code, r.stderr)
		}

		writer.login(t, in.url, pin, web.createToken(t, "writer", ns, true))
		if w := writer.ok(t, "", "whoami"); !strings.Contains(w.stdout, "permission: write") {
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
		// An agent's description waits for the admin before other agents
		// see it.
		info := agent1.ok(t, "", "info", "NEEDED")
		if !strings.Contains(info.stdout, "description from an agent is awaiting approval") ||
			strings.Contains(info.stdout, "asked by") || strings.Contains(info.stdout, "someone else") {
			t.Fatalf("info of a request: %q", info.stdout)
		}
		if _, page := web.get(t, "/secret/e2e/NEEDED"); !strings.Contains(page, "asked by the writer") || strings.Contains(page, "someone else") {
			t.Fatal("the admin doesn't see the writer's proposed description")
		}
		_, page := web.get(t, "/secret/e2e/NEEDED")
		v := versionRE.FindStringSubmatch(page)
		if v == nil {
			t.Fatal("no proposal version on the page")
		}
		web.mustPost(t, "/secret/e2e/NEEDED/proposal/approve", url.Values{"version": {v[1]}, "description": {"asked by the writer, checked by the admin"}})
		info = agent1.ok(t, "", "info", "NEEDED")
		if !strings.Contains(info.stdout, "| asked by the writer, checked by the admin") || !strings.Contains(info.stdout, "untrusted text from another agent") {
			t.Fatalf("info after approval: %q", info.stdout)
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

	adder := newAgent(t, binary) // an add token (11 on)

	step("11 an add token creates keys and replaces only its own", func(t *testing.T) {
		web = login(t, in) // the browser accepts the rotated certificate
		adder.login(t, in.url, in.pin(t), web.createTokenPerm(t, "adder", ns, "add"))
		if w := adder.ok(t, "", "whoami"); !strings.Contains(w.stdout, "permission: add") {
			t.Fatalf("whoami: %q", w.stdout)
		}
		first, second := fakeSecret(t), fakeSecret(t)
		adder.ok(t, first+"\n", "put", "ADDED")
		if r := adder.run(t, second+"\n", "put", "ADDED"); r.code == 0 {
			t.Fatal("put over an existing value without --overwrite")
		}
		adder.ok(t, second+"\n", "put", "ADDED", "--overwrite")
		if got := agent1.valueHash(t, "ADDED"); got != sha(second) {
			t.Fatal("ADDED reads back different after the add token replaced it")
		}
		if info := agent1.ok(t, "", "info", "ADDED"); !strings.Contains(info.stdout, "created by adder") {
			t.Fatalf("info ADDED: %q", info.stdout)
		}
		r := adder.run(t, first+"\n", "put", "API_TOKEN", "--overwrite")
		if r.code == 0 || !strings.Contains(r.stderr, "only replace values it created") {
			t.Fatalf("an add token replacing the admin's key: exit %d, %q", r.code, r.stderr)
		}
		if got := agent1.valueHash(t, "API_TOKEN"); got != sha(secret) {
			t.Fatal("API_TOKEN changed after a refused put")
		}
		r = agent1.run(t, first+"\n", "put", "OTHER")
		if r.code == 0 || !strings.Contains(r.stderr, "can't write") {
			t.Fatalf("put with a read token: exit %d, %q", r.code, r.stderr)
		}
		// Another token's request isn't the add token's to fill.
		agent1.ok(t, "", "request", "WANTED", "--desc", "asked by agent1")
		for _, args := range [][]string{{"put", "WANTED"}, {"put", "WANTED", "--overwrite"}} {
			r = adder.run(t, first+"\n", args...)
			if r.code == 0 || !strings.Contains(r.stderr, "only replace values it created") {
				t.Fatalf("an add token filling agent1's request: exit %d, %q", r.code, r.stderr)
			}
		}
		if info := agent1.ok(t, "", "info", "WANTED"); !strings.Contains(info.stdout, "waiting for a value") {
			t.Fatalf("WANTED after the refused puts: %q", info.stdout)
		}
	})

	step("12 a flag's text is seen by the admin, not by agents", func(t *testing.T) {
		const reason = "e2e-flag-reason: this key returned 401 twice"
		agent1.ok(t, "", "flag", "API_TOKEN", reason, "--link", "https://example.com/issue/1")
		if r := agent1.run(t, "", "flag", "API_TOKEN", "again"); r.code == 0 || !strings.Contains(r.stderr, "already has an open flag") || !strings.Contains(r.stderr, "409") {
			t.Fatalf("a second open flag by the same token: exit %d, %q", r.code, r.stderr)
		}
		for who, g := range map[string]*agent{"agent1": agent1, "adder": adder} {
			info := g.ok(t, "", "info", "API_TOKEN")
			hist := g.ok(t, "", "history", "API_TOKEN")
			if !strings.Contains(info.stdout, "flagged by agent1 on") || !strings.Contains(hist.stdout, "flagged") {
				t.Fatalf("%s doesn't see the flag: %q %q", who, info.stdout, hist.stdout)
			}
			for _, out := range []string{info.all(), hist.all()} {
				if strings.Contains(out, "e2e-flag-reason") || strings.Contains(out, "example.com/issue") {
					t.Fatalf("%s sees the flag's text: %q", who, out)
				}
			}
		}
		_, dash := web.get(t, "/inbox")
		if !strings.Contains(dash, "e2e-flag-reason") || !strings.Contains(dash, "https://example.com/issue/1") {
			t.Fatal("the dashboard doesn't show the flag")
		}
		_, page := web.get(t, "/secret/e2e/API_TOKEN")
		m := regexp.MustCompile(`/secret/e2e/API_TOKEN/flags/([A-Za-z0-9_-]+)/resolve`).FindStringSubmatch(page)
		if m == nil {
			t.Fatal("no resolve form on the secret's page")
		}
		web.mustPost(t, "/secret/e2e/API_TOKEN/flags/"+m[1]+"/resolve", nil)
		if info := adder.ok(t, "", "info", "API_TOKEN"); strings.Contains(info.stdout, "flagged by") {
			t.Fatalf("a resolved flag still shows: %q", info.stdout)
		}
		if _, dash := web.get(t, "/inbox"); strings.Contains(dash, "e2e-flag-reason") {
			t.Fatal("a resolved flag is still on the dashboard")
		}
		if _, page := web.get(t, "/secret/e2e/API_TOKEN"); !strings.Contains(page, "e2e-flag-reason") {
			t.Fatal("the admin's history lost the flag's text")
		}
	})

	step("13 any token, even read-only, sets a status; run warns but runs; the admin's status is the admin's", func(t *testing.T) {
		agent1.ok(t, "", "status", "API_TOKEN", "leaked")
		r := agent1.run(t, "", "run", "-e", "API_TOKEN", "--", "true")
		if r.code != 0 || !strings.Contains(r.stderr, "API_TOKEN is marked leaked (by token:agent1") {
			t.Fatalf("run on a leaked key: exit %d, %q", r.code, r.stderr)
		}
		noLeak(t, "run", r.all(), secret)
		if info := adder.ok(t, "", "info", "API_TOKEN"); !strings.Contains(info.stdout, "status: leaked (set by token:agent1") {
			t.Fatalf("info: %q", info.stdout)
		}
		if s := adder.ok(t, "", "secrets"); !strings.Contains(s.stdout, "leaked") {
			t.Fatalf("secrets: %q", s.stdout)
		}
		if r := agent1.run(t, "", "status", "API_TOKEN", "replaced-by", "not a name"); r.code == 0 {
			t.Fatal("replaced-by took an invalid name")
		}
		if r := agent1.run(t, "", "status", "API_TOKEN", "replaced-by", "NO_SUCH_KEY"); r.code == 0 || !strings.Contains(r.stderr, "exists in the same namespace") {
			t.Fatalf("replaced-by a missing key: exit %d, %q", r.code, r.stderr)
		}
		if r := agent1.run(t, "", "status", "API_TOKEN", "broken"); r.code == 0 {
			t.Fatal("an unknown status was accepted")
		}
		agent1.ok(t, "", "status", "API_TOKEN", "replaced-by", "ADDED")
		if r := agent1.ok(t, "", "run", "-e", "API_TOKEN", "--", "true"); !strings.Contains(r.stderr, "replaced-by ADDED") {
			t.Fatalf("run on a replaced key: %q", r.stderr)
		}
		// A status the admin sets, no token can clear or change.
		web.mustPost(t, "/secret/e2e/API_TOKEN/status", url.Values{"status": {"leaked"}})
		for _, who := range []*agent{agent1, adder} {
			if r := who.run(t, "", "status", "API_TOKEN", "ok"); r.code == 0 || !strings.Contains(r.stderr, "only the admin can change it") {
				t.Fatalf("a token cleared the admin's status: exit %d, %q", r.code, r.stderr)
			}
		}
		// The admin clears it in the UI.
		web.mustPost(t, "/secret/e2e/API_TOKEN/status", url.Values{"status": {"ok"}})
		if r := agent1.ok(t, "", "run", "-e", "API_TOKEN", "--", "true"); strings.Contains(r.stderr, "marked") {
			t.Fatalf("run warns after the status was cleared: %q", r.stderr)
		}
	})

	step("14 an agent's note waits for the admin, then shows with who approved it", func(t *testing.T) {
		r := adder.ok(t, "", "note", "API_TOKEN", "e2e note: rotate monthly")
		if !strings.Contains(r.stdout, "Note sent") {
			t.Fatalf("note: %q", r.stdout)
		}
		info := agent1.ok(t, "", "info", "API_TOKEN")
		if !strings.Contains(info.stdout, "1 note awaiting approval") || strings.Contains(info.stdout, "rotate monthly") {
			t.Fatalf("info with a pending note: %q", info.stdout)
		}
		_, page := web.get(t, "/secret/e2e/API_TOKEN")
		m := regexp.MustCompile(`/secret/e2e/API_TOKEN/notes/([A-Za-z0-9_-]+)/approve`).FindStringSubmatch(page)
		if m == nil || !strings.Contains(page, "rotate monthly") {
			t.Fatal("the admin doesn't see the pending note")
		}
		web.mustPost(t, "/secret/e2e/API_TOKEN/notes/"+m[1]+"/approve", url.Values{"text": {"e2e note: rotate every month"}})
		info = agent1.ok(t, "", "info", "API_TOKEN")
		if !strings.Contains(info.stdout, "note from agent adder") || !strings.Contains(info.stdout, "edited by the admin") ||
			!strings.Contains(info.stdout, "| e2e note: rotate every month") || strings.Contains(info.stdout, "awaiting approval") {
			t.Fatalf("info after approval: %q", info.stdout)
		}
	})

	step("15 revoking a token drops its request, notes and proposals; a new one of that name starts clean", func(t *testing.T) {
		temp := newAgent(t, binary)
		temp.login(t, in.url, in.pin(t), web.createTokenPerm(t, "temp", ns, "add"))
		temp.ok(t, "", "request", "TEMP_REQ", "--desc", "e2e-temp-proposal")
		temp.ok(t, "", "flag", "API_URL", "e2e-temp-flag")
		temp.ok(t, "", "note", "API_URL", "e2e-temp-note")
		web.mustPost(t, "/tokens/temp/revoke", url.Values{"confirm": {"yes"}})

		info := agent1.ok(t, "", "info", "API_URL")
		if !strings.Contains(info.stdout, "flagged by temp") || !strings.Contains(info.stdout, "since been revoked") || strings.Contains(info.stdout, "awaiting approval") {
			t.Fatalf("API_URL after temp was revoked: %q", info.stdout)
		}
		if info := agent1.ok(t, "", "info", "TEMP_REQ"); strings.Contains(info.stdout, "awaiting approval") {
			t.Fatalf("TEMP_REQ still has temp's proposal: %q", info.stdout)
		}
		if _, page := web.get(t, "/inbox"); !strings.Contains(page, "asked by an agent since revoked") || strings.Contains(page, "e2e-temp-proposal") || strings.Contains(page, "e2e-temp-note") {
			t.Fatal("the dashboard still shows temp's request or note as pending")
		}

		// A new token given the same name: its own flag, but not the old
		// request.
		temp.login(t, in.url, in.pin(t), web.createTokenPerm(t, "temp", ns, "add"))
		temp.ok(t, "", "flag", "API_URL", "e2e-temp-flag again")
		if r := temp.run(t, "filled-by-new-temp\n", "put", "TEMP_REQ"); r.code == 0 || !strings.Contains(r.stderr, "only replace values it created") {
			t.Fatalf("the new temp filled the old one's request: exit %d, %q", r.code, r.stderr)
		}
		if r := temp.run(t, "", "request", "TEMP_REQ", "--desc", "mine now"); r.code == 0 || !strings.Contains(r.stderr, "already requested by another agent") {
			t.Fatalf("the new temp took over the old one's request: exit %d, %q", r.code, r.stderr)
		}

		// The admin saving a value takes an add token's key from it.
		temp.ok(t, "temp-value-1\n", "put", "TEMP_KEY")
		web.mustPost(t, "/secret/e2e/TEMP_KEY/value", url.Values{"value": {"admin-value-1"}, "kind": {"secret"}})
		if r := temp.run(t, "temp-value-2\n", "put", "TEMP_KEY", "--overwrite"); r.code == 0 || !strings.Contains(r.stderr, "only replace values it created") {
			t.Fatalf("the add token replaced the admin's value: exit %d, %q", r.code, r.stderr)
		}
		web.mustPost(t, "/tokens/temp/revoke", url.Values{"confirm": {"yes"}})
	})

	step("16 puts and requests are rate-limited per token; a flood evicts only its own namespace's history", func(t *testing.T) {
		web.addEntry(t, "flood", "SEED", "seed-value", "variable", "")
		// Three tokens at the limit put more events in "flood" than its
		// history keeps.
		for i := 0; i < 3; i++ {
			name := fmt.Sprintf("flood%d", i)
			c := newBearer(t, in, web.createTokenPerm(t, name, "flood", "write"))
			for j := 0; ; j++ {
				code := c.put(t, "flood", "SPAM", fmt.Sprintf("v-%d-%d", i, j))
				if code == http.StatusTooManyRequests {
					if j != writesPerHour {
						t.Fatalf("%s: 429 after %d puts, want %d", name, j, writesPerHour)
					}
					break
				}
				if code != http.StatusOK || j > writesPerHour {
					t.Fatalf("%s put %d: %d", name, j, code)
				}
			}
			if code := c.request(t, "flood", "MORE"); code != http.StatusTooManyRequests {
				t.Fatalf("%s request over the limit: %d", name, code)
			}
		}
		if h := agent1.ok(t, "", "history", "API_TOKEN", "--limit", "1000"); !strings.Contains(h.stdout, "e2e/API_TOKEN  created") {
			t.Fatalf("another namespace's history was evicted: %q", h.stdout)
		}
		if _, page := web.get(t, "/secret/flood/SEED"); !strings.Contains(page, "<strong>created</strong>") {
			t.Fatal("the admin's event in the flooded namespace was evicted")
		}
	})

	step("17 the previous release starts on data this one wrote", func(t *testing.T) {
		testRollback(t)
	})

	step("18 a batch request, filled by pasting the downloaded file, and groups", func(t *testing.T) {
		testBatchAndGroups(t)
	})

	step("19 the release before groups starts on grouped data, and this one opens what it wrote", func(t *testing.T) {
		testRollbackV2(t)
	})
}

var versionRE = regexp.MustCompile(`name="version" value="([0-9a-f]+)"`)

// writesPerHour is the server's per-token limit on puts and requests.
const writesPerHour = 200

// testUpgrade builds the release before the integrity check, makes data
// with it, and moves that data to this release and back.
func testUpgrade(t *testing.T) {
	old := buildOld(t, oldFormatCommit)

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

// buildOld checks out commit in a worktree and builds it.
func buildOld(t *testing.T, commit string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git isn't installed, so the old release can't be built")
	}
	if err := exec.Command("git", "-C", repoRoot, "cat-file", "-e", commit+"^{commit}").Run(); err != nil {
		t.Skipf("commit %s isn't in this clone (shallow? fetch with fetch-depth: 0), so the old release can't be built", commit)
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	if out, err := exec.Command("git", "-C", repoRoot, "worktree", "add", "--detach", src, commit).CombinedOutput(); err != nil {
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
	return old
}

// testRollback writes data with every newer field in use, starts the
// previous release on it, has that release rewrite it, and starts this one
// again.
func testRollback(t *testing.T) {
	old := buildOld(t, rollbackCommit)

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret, added := fakeSecret(t), fakeSecret(t)
	web.addEntry(t, "rb", "KEPT", secret, "secret", "made by the admin")
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.createTokenPerm(t, "rb-agent", "rb", "add"))
	g.ok(t, added+"\n", "put", "ADDED_BY_AGENT", "--desc", "an agent's description")
	g.ok(t, "", "flag", "KEPT", "e2e rollback flag")
	g.ok(t, "", "status", "KEPT", "expired")
	g.ok(t, "", "note", "KEPT", "e2e rollback note")
	useGroups(t, web, g, "rb", "KEPT")
	in.stop(t)

	// Tokens expire by default now, so the data needs downgrade-data first.
	downgradeV4(t, in, "rb-agent")
	in.start(t, old)
	if got := in.pin(t); got != pin {
		t.Fatalf("the old release's pin %s, was %s", got, pin)
	}
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("the old release returns a different value")
	}
	if got := g.valueHash(t, "ADDED_BY_AGENT"); got != sha(added) {
		t.Fatal("the old release returns a different value for the agent's key")
	}
	// A change makes the old release rewrite the file without the newer
	// fields; the add token reads as read-only there.
	web = login(t, in)
	web.addEntry(t, "rb", "AFTER", "plain-setting", "variable", "")
	// That release writes a request's text straight into the description.
	g.ok(t, "", "request", "OLD_REQ", "--desc", "e2e-old-release-request-text")
	in.stop(t)

	in.start(t, binary)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("this release returns a different value after the old one rewrote the file")
	}
	if r := g.ok(t, "", "vars"); !strings.Contains(r.stdout, "rb/AFTER=plain-setting") {
		t.Fatalf("vars after the round trip: %q", r.stdout)
	}
	if w := g.ok(t, "", "whoami"); !strings.Contains(w.stdout, "permission: read") {
		t.Fatalf("whoami after the old release rewrote the file: %q", w.stdout)
	}
	// ...which this release turns back into a proposal for the admin.
	if info := g.ok(t, "", "info", "OLD_REQ"); !strings.Contains(info.stdout, "description from an agent is awaiting approval") || strings.Contains(info.stdout, "e2e-old-release-request-text") {
		t.Fatalf("an old release's request text after the round trip: %q", info.stdout)
	}
	in.stop(t)
}

// useGroups puts every group field in the data: a group with key in it,
// a batch request with a proposed label, and auto groups turned off.
func useGroups(t *testing.T, web *admin, g *agent, ns, key string) {
	t.Helper()
	web.mustPost(t, "/groups", url.Values{"namespace": {ns}, "name": {"Kept group"}, "color": {"teal"}})
	web.mustPost(t, "/secret/"+ns+"/"+key+"/group", url.Values{"group": {"kept-group"}})
	g.ok(t, "", "request", "ASK_ONE", "ASK_TWO", "--group", "Proposed", "--desc", "e2e batch")
	web.mustPost(t, "/settings/autogroups", url.Values{})
	if s := g.ok(t, "", "secrets"); !strings.Contains(s.stdout, "["+ns+": Kept group]\n"+ns+"/"+key) {
		t.Fatalf("grouped list: %q", s.stdout)
	}
}

func testBatchAndGroups(t *testing.T) {
	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.createTokenPerm(t, "batcher", "b", "read"))
	key, sec := fakeSecret(t), fakeSecret(t)

	r := g.ok(t, "", "request", "EXAMPLE_API_KEY", "EXAMPLE_API_SECRET", "EXAMPLE_URL", "--group", "Router", "--desc", "router api pair")
	if !strings.Contains(r.stdout, "Requested 3 keys together") || !strings.Contains(r.stdout, "keydrop wait b/EXAMPLE_URL") {
		t.Fatalf("batch request: %q", r.stdout)
	}
	_, dash := web.get(t, "/inbox")
	for _, want := range []string{`request batch-card`, `id="batch-`, `name="value.EXAMPLE_API_SECRET"`, `class="paste-file"`, `name="groupname" value="Router"`, "agent-written", "Save all"} {
		if !strings.Contains(dash, want) {
			t.Fatalf("the inbox lacks %s", want)
		}
	}
	card := func(extra url.Values) url.Values {
		f := url.Values{"namespace": {"b"}, "name": {"EXAMPLE_API_KEY", "EXAMPLE_API_SECRET", "EXAMPLE_URL"}}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	file := "# from the router\nkey=" + key + "\nsecret=\"" + sec + "\"\n"
	refused := map[string]url.Values{
		"a line that maps to nothing": card(url.Values{"paste": {file + "token=" + key + "\n"}}),
		"the paste and a field":       card(url.Values{"paste": {file}, "value.EXAMPLE_URL": {"https://router.example"}}),
		"a whole line in a field":     card(url.Values{"value.EXAMPLE_API_KEY": {"key=" + key}}),
	}
	for what, form := range refused {
		code, body, _ := web.post(t, "/requests/fill", form)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: %d", what, code)
		}
		noLeak(t, what, body, key, sec)
	}
	if s := g.ok(t, "", "secrets", "--pending"); strings.Count(s.stdout, "waiting for a value") != 3 {
		t.Fatalf("a refused card saved something: %q", s.stdout)
	}
	loc := web.mustPost(t, "/requests/fill", card(url.Values{"paste": {file}, "group": {"yes"}, "groupname": {"Router"}}))
	_, page := web.get(t, loc)
	if !strings.Contains(page, "Saved EXAMPLE_API_KEY, EXAMPLE_API_SECRET.") {
		t.Fatalf("flash after the paste: %q", loc)
	}
	noLeak(t, "the page after the paste", page, key, sec)
	web.mustPost(t, "/requests/fill", url.Values{"namespace": {"b"}, "name": {"EXAMPLE_URL"}, "value.EXAMPLE_URL": {"https://router.example"}, "kind.EXAMPLE_URL": {"variable"}, "group": {"yes"}, "groupname": {"router"}})
	if g.valueHash(t, "EXAMPLE_API_KEY") != sha(key) || g.valueHash(t, "EXAMPLE_API_SECRET") != sha(sec) {
		t.Fatal("the pasted values weren't saved as sent")
	}
	if s := g.ok(t, "", "secrets"); !strings.Contains(s.stdout, "[b: Router]\nb/EXAMPLE_API_KEY\nb/EXAMPLE_API_SECRET") {
		t.Fatalf("secrets: %q", s.stdout)
	}
	if v := g.ok(t, "", "vars"); !strings.Contains(v.stdout, "[b: Router]\nb/EXAMPLE_URL=https://router.example") {
		t.Fatalf("vars: %q", v.stdout)
	}
	if i := g.ok(t, "", "info", "EXAMPLE_API_KEY"); !strings.Contains(i.stdout, "group: Router") {
		t.Fatalf("info: %q", i.stdout)
	}
	// Auto groups, and the guard on the Add form.
	web.addEntry(t, "b", "CF_TOKEN", fakeSecret(t), "secret", "")
	web.addEntry(t, "b", "CF_ZONE", "zone-id", "variable", "")
	web.addEntry(t, "b", "CF_ACCOUNT", "account-id", "variable", "")
	if v := g.ok(t, "", "vars"); !strings.Contains(v.stdout, "[b: CF, auto]\nb/CF_ACCOUNT=account-id") || !strings.Contains(v.stdout, "\nb/CF_ZONE=zone-id") {
		t.Fatalf("auto group: %q", v.stdout)
	}
	if code, body, _ := web.post(t, "/secrets", url.Values{"namespace": {"b"}, "name": {"PASTED"}, "value": {"EXAMPLE_API_KEY=" + key}, "kind": {"secret"}}); code != http.StatusBadRequest || !strings.Contains(body, "whole line") {
		t.Fatalf("whole line on the Add form: %d", code)
	}
	main, _ := in.auditLines(t)
	noLeak(t, "the audit log", main, key, sec)
	for _, want := range []string{`"group.create"`, `"group.assign"`, `"group.propose"`} {
		if !strings.Contains(main, want) {
			t.Fatalf("the audit log lacks %s", want)
		}
	}
	in.stop(t)
}

// testRollbackV2 writes data with every group field in use, starts the
// release before groups on it, has that release rewrite it, and starts
// this one again: the keys survive, the groups don't.
func testRollbackV2(t *testing.T) {
	old := buildOld(t, v2RollbackCommit)

	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "rb2", "KEPT", secret, "secret", "made by the admin")
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.createTokenPerm(t, "rb2-agent", "rb2", "add"))
	g.ok(t, "", "flag", "KEPT", "e2e v2 rollback flag")
	useGroups(t, web, g, "rb2", "KEPT")
	in.stop(t)
	downgradeV4(t, in, "rb2-agent")

	// That release starts on it and reads the keys and annotations.
	in.start(t, old)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("the release before groups returns a different value")
	}
	if i := g.ok(t, "", "info", "KEPT"); !strings.Contains(i.stdout, "flagged by") {
		t.Fatalf("the flag in the release before groups: %q", i.stdout)
	}
	if s := g.ok(t, "", "secrets", "--pending"); !strings.Contains(s.stdout, "rb2/ASK_ONE") {
		t.Fatalf("the batch requests in the release before groups: %q", s.stdout)
	}
	// A change makes it rewrite the file without the group fields.
	web = login(t, in)
	web.addEntry(t, "rb2", "AFTER", "plain-setting", "variable", "")
	in.stop(t)

	in.start(t, binary)
	if got := g.valueHash(t, "KEPT"); got != sha(secret) {
		t.Fatal("this release returns a different value after the old one rewrote the file")
	}
	s := g.ok(t, "", "secrets")
	if strings.Contains(s.stdout, "Kept group") || !strings.Contains(s.stdout, "rb2/KEPT") || !strings.Contains(s.stdout, "rb2/ASK_TWO") {
		t.Fatalf("secrets after the round trip: %q", s.stdout)
	}
	if v := g.ok(t, "", "vars"); !strings.Contains(v.stdout, "rb2/AFTER=plain-setting") {
		t.Fatalf("vars after the round trip: %q", v.stdout)
	}
	if i := g.ok(t, "", "info", "KEPT"); !strings.Contains(i.stdout, "flagged by") {
		t.Fatalf("the flag after the round trip: %q", i.stdout)
	}
	// Groups work again from scratch.
	web = login(t, in)
	if code, page := web.get(t, "/groups"); code != http.StatusOK || strings.Contains(page, "Kept group") {
		t.Fatalf("groups after the round trip: %d", code)
	}
	web.mustPost(t, "/groups", url.Values{"namespace": {"rb2"}, "name": {"Kept group"}, "color": {"teal"}})
	in.stop(t)
}
