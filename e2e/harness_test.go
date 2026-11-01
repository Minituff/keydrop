//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// buildKeydrop compiles ./cmd/keydrop from the module in srcDir into out.
func buildKeydrop(srcDir, out, version string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.version="+version, "-o", out, "./cmd/keydrop")
	cmd.Dir = srcDir
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build in %s: %v\n%s", srcDir, err, b)
	}
	return nil
}

// baseEnv is the environment every subprocess starts from: enough to find
// sh and friends, and nothing of the user running the tests (no KEYDROP_*
// settings, no real ~/.config/keydrop).
func baseEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"LANG=C",
	}
}

// syncBuffer collects a subprocess's output while it runs.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor polls cond until it's true or the timeout passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// newMasterKey writes a key from the binary's own genkey to a 0600 file.
func newMasterKey(t *testing.T, bin, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "master.key")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "genkey")
	cmd.Stdout = f // straight to the file, never through the test's output
	cmd.Env = baseEnv(dir)
	err = cmd.Run()
	f.Close()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return path
}

// instance is one keydrop data directory with its master key, served by
// whichever binary is started on it, always on the same address (agents
// save the URL, so a restart must keep the port).
type instance struct {
	dataDir string
	keyFile string
	addr    string
	url     string

	srv *serverProc
}

func newInstance(t *testing.T, bin string) *instance {
	dir := t.TempDir()
	in := &instance{dataDir: filepath.Join(dir, "data"), keyFile: newMasterKey(t, bin, dir), addr: freePort(t)}
	in.url = "https://" + in.addr
	t.Cleanup(func() { in.stop(t) }) // never leave a server running
	return in
}

// env is the server environment, shared by server and the data commands.
func (in *instance) env() []string {
	return append(baseEnv(filepath.Dir(in.dataDir)),
		"KEYDROP_DATA_DIR="+in.dataDir,
		"KEYDROP_MASTER_KEY_FILE="+in.keyFile,
		"KEYDROP_LISTEN="+in.addr,
		"KEYDROP_TLS_HOSTS=127.0.0.1",
	)
}

type serverProc struct {
	cmd  *exec.Cmd
	log  *syncBuffer
	done chan struct{}
	err  error
}

func (p *serverProc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// start runs `bin server` and waits for /healthz.
func (in *instance) start(t *testing.T, bin string) *serverProc {
	t.Helper()
	if in.srv != nil {
		t.Fatal("a server is already running on this instance")
	}
	p := &serverProc{log: &syncBuffer{}, done: make(chan struct{})}
	p.cmd = exec.Command(bin, "server")
	p.cmd.Env = in.env()
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	in.srv = p

	hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		// Only to see that it's up; everything else checks the pin.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	defer hc.CloseIdleConnections()
	waitFor(t, "the server's /healthz", 20*time.Second, func() bool {
		if p.exited() {
			t.Fatalf("server exited before it was healthy (%v):\n%s", p.err, p.log)
		}
		resp, err := hc.Get(in.url + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return p
}

// stop ends the server (SIGTERM, then SIGKILL) and waits for it.
func (in *instance) stop(t *testing.T) {
	p := in.srv
	if p == nil {
		return
	}
	in.srv = nil
	if !p.exited() {
		p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			p.cmd.Process.Kill()
			<-p.done
		}
	}
}

var pinRE = regexp.MustCompile(`KEYDROP_TLS_PIN=(sha256:[0-9a-f]{64})`)

// pin is the certificate pin the running server printed.
func (in *instance) pin(t *testing.T) string {
	t.Helper()
	m := pinRE.FindStringSubmatch(in.srv.log.String())
	if m == nil {
		t.Fatalf("no pin in the server log:\n%s", in.srv.log)
	}
	return m[1]
}

var setupRE = regexp.MustCompile(`/setup\?code=([A-Z0-9]{6})`)

func (in *instance) setupCode(t *testing.T) string {
	t.Helper()
	m := setupRE.FindStringSubmatch(in.srv.log.String())
	if m == nil {
		t.Fatalf("no setup code in the server log:\n%s", in.srv.log)
	}
	return m[1]
}

// command runs `bin args...` with the server's environment (the offline
// data commands, or a server expected to refuse to start) and returns its
// combined output and exit code.
func (in *instance) command(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = in.env()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s %v didn't finish:\n%s", filepath.Base(bin), args, out)
	}
	return string(out), exitCode(t, err)
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	t.Fatal(err)
	return -1
}

// servedPin connects and computes the pin of the certificate the server
// presents, independently of the CLI: SHA-256 of the leaf certificate.
func servedPin(t *testing.T, addr string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := sha256.Sum256(c.ConnectionState().PeerCertificates[0].Raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// auditLines reads the main and unauthenticated audit logs.
func (in *instance) auditLines(t *testing.T) (main, unauth string) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(in.dataDir, name))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return string(b)
	}
	return read("audit.jsonl"), read("audit-unauth.jsonl")
}

// ---- the admin, in a browser without JavaScript ----

type admin struct {
	base string
	hc   *http.Client
	csrf string
}

// newAdmin is a cookie-jar client that checks the server's pin, like a
// browser that has accepted the certificate. It doesn't follow redirects,
// so each step's status can be checked.
func newAdmin(t *testing.T, base, pin string) *admin {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			h := sha256.Sum256(raw[0])
			if "sha256:"+hex.EncodeToString(h[:]) != pin {
				return fmt.Errorf("unexpected certificate")
			}
			return nil
		},
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &admin{base: base, hc: &http.Client{
		Jar: jar, Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (a *admin) do(t *testing.T, req *http.Request) (int, string, string) {
	t.Helper()
	resp, err := a.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

func (a *admin) get(t *testing.T, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", a.base+path, nil)
	req.Header.Set("Sec-Fetch-Site", "none")
	code, body, _ := a.do(t, req)
	return code, body
}

// postAs posts a form with the given Sec-Fetch-Site, adding the session's
// CSRF token unless the form sets its own.
func (a *admin) postAs(t *testing.T, site, path string, form url.Values) (int, string, string) {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if !form.Has("csrf") && a.csrf != "" {
		form.Set("csrf", a.csrf)
	}
	req, _ := http.NewRequest("POST", a.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", site)
	req.Header.Set("Origin", a.base)
	return a.do(t, req)
}

func (a *admin) post(t *testing.T, path string, form url.Values) (int, string, string) {
	t.Helper()
	return a.postAs(t, "same-origin", path, form)
}

// mustPost posts and expects a redirect (the UI's answer to every
// successful change).
func (a *admin) mustPost(t *testing.T, path string, form url.Values) string {
	t.Helper()
	code, body, loc := a.post(t, path, form)
	if code != http.StatusSeeOther {
		t.Fatalf("POST %s: %d, want 303:\n%s", path, code, body)
	}
	return loc
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// loadCSRF reads the session's CSRF token from a page, as a browser
// submitting one of its forms would.
func (a *admin) loadCSRF(t *testing.T) {
	t.Helper()
	code, body := a.get(t, "/")
	m := csrfRE.FindStringSubmatch(body)
	if code != http.StatusOK || m == nil {
		t.Fatalf("GET /: %d, no CSRF token:\n%s", code, body)
	}
	a.csrf = m[1]
}

const adminPassword = "e2e-admin-password-not-real"

// setupAndLogin claims a fresh install with the setup code from the log,
// then logs in from a new browser.
func setupAndLogin(t *testing.T, in *instance) *admin {
	t.Helper()
	pin := in.pin(t)
	code := in.setupCode(t)
	a := newAdmin(t, in.url, pin)
	if c, body := a.get(t, "/setup?code="+code); c != http.StatusOK || !strings.Contains(body, `name="password2"`) {
		t.Fatalf("GET /setup?code=: %d:\n%s", c, body)
	}
	loc := a.mustPost(t, "/setup", url.Values{"code": {code}, "mfa": {"none"}, "password": {adminPassword}, "password2": {adminPassword}})
	if loc != "/" {
		t.Fatalf("setup redirected to %q", loc)
	}
	return login(t, in)
}

func login(t *testing.T, in *instance) *admin {
	t.Helper()
	a := newAdmin(t, in.url, in.pin(t))
	if loc := a.mustPost(t, "/login", url.Values{"password": {adminPassword}}); loc != "/" {
		t.Fatalf("login redirected to %q", loc)
	}
	a.loadCSRF(t)
	return a
}

// addEntry adds a secret or variable in the UI.
func (a *admin) addEntry(t *testing.T, ns, name, value, kind, desc string) {
	t.Helper()
	a.mustPost(t, "/secrets", url.Values{"namespace": {ns}, "name": {name}, "value": {value}, "kind": {kind}, "description": {desc}})
}

var tokenRE = regexp.MustCompile(`<code class="secret">(kd_[A-Za-z0-9_-]+)</code>`)

// createToken makes a token by hand under Agents and returns it. The
// caller writes it to a file; it's never printed.
func (a *admin) createToken(t *testing.T, name, namespaces string, write bool) string {
	t.Helper()
	form := url.Values{"name": {name}, "namespaces": {namespaces}}
	if write {
		form.Set("write", "yes") // the form field before read/add/write
	}
	return a.postToken(t, form)
}

// createTokenPerm makes a token with a permission: read, add or write.
func (a *admin) createTokenPerm(t *testing.T, name, namespaces, perm string) string {
	t.Helper()
	return a.postToken(t, url.Values{"name": {name}, "namespaces": {namespaces}, "permission": {perm}})
}

func (a *admin) postToken(t *testing.T, form url.Values) string {
	t.Helper()
	code, body, _ := a.post(t, "/tokens", form)
	m := tokenRE.FindStringSubmatch(body)
	if code != http.StatusOK || m == nil {
		t.Fatalf("POST /tokens: %d, no token on the page", code)
	}
	return m[1]
}

// ---- agents: the CLI as a user runs it ----

type agent struct {
	bin   string
	home  string
	extra []string // more environment, e.g. KEYDROP_TLS_PIN
}

func newAgent(t *testing.T, bin string) *agent {
	return &agent{bin: bin, home: t.TempDir()}
}

func (g *agent) configDir() string { return filepath.Join(g.home, ".config", "keydrop") }

func (g *agent) env() []string { return append(baseEnv(g.home), g.extra...) }

type result struct {
	stdout, stderr string
	code           int
}

func (r result) all() string { return r.stdout + r.stderr }

// run runs the CLI with stdin (may be nil) and returns what it printed.
func (g *agent) run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, g.bin, args...)
	cmd.Env = g.env()
	cmd.Dir = g.home
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("keydrop %s didn't finish", args[0])
	}
	return result{out.String(), errb.String(), exitCode(t, err)}
}

// ok runs the CLI and fails the test unless it exits 0.
func (g *agent) ok(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	r := g.run(t, stdin, args...)
	if r.code != 0 {
		t.Fatalf("keydrop %s: exit %d\nstdout: %s\nstderr: %s", args[0], r.code, r.stdout, r.stderr)
	}
	return r
}

// login saves url, token and pin with `keydrop login`, the token on stdin.
func (g *agent) login(t *testing.T, url, pin, token string) {
	t.Helper()
	g.ok(t, token+"\n", "login", "--url", url, "--pin", pin)
}

// valueHash has the CLI hand a secret to a child that prints its SHA-256,
// which proves the value decrypts correctly without it being printed.
func (g *agent) valueHash(t *testing.T, ref string) string {
	t.Helper()
	r := g.ok(t, "", "run", "-e", "V="+ref, "--", "sh", "-c", `printf %s "$V" | sha256sum`)
	f := strings.Fields(r.stdout)
	if len(f) == 0 {
		t.Fatalf("no hash from run: %q", r.stdout)
	}
	return f[0]
}

func sha(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

// noLeak fails if out holds a value in any form masking covers. The
// failure message has every value replaced, so a leak isn't repeated in
// the test log.
func noLeak(t *testing.T, what, out string, values ...string) {
	t.Helper()
	for _, v := range values {
		forms := []string{v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawStdEncoding.EncodeToString([]byte(v)),
			base64.URLEncoding.EncodeToString([]byte(v)), url.QueryEscape(v)}
		for _, f := range forms {
			if strings.Contains(out, f) {
				red := out
				for _, v2 := range values {
					red = strings.ReplaceAll(red, v2, "<VALUE>")
				}
				t.Fatalf("%s: a secret value (or its encoding) appeared in the output:\n%s", what, red)
			}
		}
	}
}

// fakeSecret is a random value that looks like an API key and is
// obviously a test fixture.
func fakeSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "e2e_fake_" + hex.EncodeToString(b)
}

// ---- an agent speaking the API directly, for what the CLI won't do fast ----

// bearer is an HTTP client with a token, pinned to the server's
// certificate. The token is never printed.
type bearer struct {
	a     *admin
	token string
}

func newBearer(t *testing.T, in *instance, token string) *bearer {
	return &bearer{a: newAdmin(t, in.url, in.pin(t)), token: token}
}

func (b *bearer) send(t *testing.T, method, path string, body string) int {
	t.Helper()
	req, _ := http.NewRequest(method, b.a.base+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	code, _, _ := b.a.do(t, req)
	return code
}

func (b *bearer) put(t *testing.T, ns, name, value string) int {
	t.Helper()
	return b.send(t, "PUT", "/api/v1/secrets/"+ns+"/"+name, fmt.Sprintf(`{"value":%q,"overwrite":true}`, value))
}

func (b *bearer) request(t *testing.T, ns, name string) int {
	t.Helper()
	return b.send(t, "POST", "/api/v1/requests", fmt.Sprintf(`{"namespace":%q,"name":%q}`, ns, name))
}
