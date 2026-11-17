package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/client"
	"github.com/minituff/keydrop/internal/server"
)

// doctorToken is planted in every test; it must never be printed.
const doctorMarker = "kd_FAKE-doctor-marker-token-0000"

// fakeDoctor is a keydrop server for doctor's calls. whoami and renew
// answer those endpoints (status, JSON body); hdr adds headers to whoami.
type fakeDoctor struct {
	mu      sync.Mutex
	paths   []string // every request, "auth " marking one with a token
	whoami  func(w http.ResponseWriter)
	renew   func(w http.ResponseWriter)
	healthz string
}

func (f *fakeDoctor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	p := r.URL.Path
	if r.Header.Get("Authorization") != "" {
		p = "auth " + p
		if r.Header.Get("Authorization") != "Bearer "+doctorMarker {
			p += " (wrong token)"
		}
	}
	f.paths = append(f.paths, p)
	f.mu.Unlock()
	switch r.URL.Path {
	case "/healthz":
		w.Write([]byte(f.healthz))
	case "/api/v1/whoami":
		f.whoami(w)
	case "/api/v1/token/renew":
		if f.renew == nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		f.renew(w)
	default:
		http.Error(w, `{"error":"not here"}`, http.StatusNotFound)
	}
}

func (f *fakeDoctor) requests() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.paths, ", ")
}

// goodWhoami answers like a current server, for a token expiring at exp.
func goodWhoami(exp time.Time, version, selfUpgrade string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("X-Keydrop-Version", version)
		w.Header().Set(server.HdrAPILevel, fmt.Sprint(server.APILevel))
		w.Header().Set(server.HdrMinCLI, fmt.Sprint(server.MinCLILevel))
		w.Header().Set(server.HdrSelfUpgrade, selfUpgrade)
		w.Header().Set("X-Keydrop-Token-Expires", exp.UTC().Format(time.RFC3339))
		json.NewEncoder(w).Encode(map[string]any{"name": "box", "namespaces": []string{"lab"}, "write": false, "permission": "read", "expires_at": exp})
	}
}

func newFakeDoctor(t *testing.T, tlsOn bool) (*fakeDoctor, *httptest.Server, string) {
	f := &fakeDoctor{healthz: "ok\n", whoami: goodWhoami(time.Now().Add(90*24*time.Hour), "v1.4.0", "on")}
	var ts *httptest.Server
	pin := ""
	if tlsOn {
		ts = httptest.NewTLSServer(f)
		pin = server.Fingerprint(ts.Certificate().Raw)
	} else {
		ts = httptest.NewServer(f)
	}
	t.Cleanup(ts.Close)
	return f, ts, pin
}

// pairDoctor writes url, token and pin as `keydrop pair` would, under a
// fresh XDG_CONFIG_HOME, and returns that directory.
func pairDoctor(t *testing.T, u, pin string) string {
	for _, k := range []string{"KEYDROP_URL", "KEYDROP_TOKEN", "KEYDROP_TOKEN_FILE", "KEYDROP_TLS_PIN", "KEYDROP_AGENT"} {
		t.Setenv(k, "")
	}
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "keydrop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"url": u, "token": doctorMarker}
	if pin != "" {
		files["pin"] = pin
	}
	for name, v := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// snapshot lists every file under dir with its mode, time and hash.
func snapshot(t *testing.T, dir string) string {
	var b strings.Builder
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, _ := d.Info()
		data, _ := os.ReadFile(p)
		fmt.Fprintf(&b, "%s %v %v %x\n", p, fi.Mode(), fi.ModTime().UnixNano(), sha256.Sum256(data))
		return nil
	})
	return b.String()
}

// runDoctor runs doctor with the config under home and checks what holds
// for every run: no token in the output, nothing written, nothing on
// stderr, and the reveal endpoint never called.
func runDoctor(t *testing.T, home string, f *fakeDoctor) (string, bool) {
	t.Helper()
	before := snapshot(t, home)
	var out strings.Builder
	var ok bool
	start := time.Now()
	_, stderr := captureStd(t, func() { ok = doctor(&out) })
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("doctor took %s", d)
	}
	if strings.Contains(out.String(), doctorMarker) || strings.Contains(stderr, doctorMarker) {
		t.Errorf("the token was printed:\n%s%s", out.String(), stderr)
	}
	if stderr != "" {
		t.Errorf("doctor wrote to stderr (a client notice?): %q", stderr)
	}
	if after := snapshot(t, home); after != before {
		t.Errorf("doctor changed files:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if f != nil {
		if r := f.requests(); strings.Contains(r, "reveal") || strings.Contains(r, "collect") || strings.Contains(r, "/secrets") || strings.Contains(r, "wrong token") {
			t.Errorf("doctor asked for %s", r)
		}
	}
	t.Log("\n" + out.String())
	return out.String(), ok
}

func checkLine(t *testing.T, out, status, check string, want ...string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[1] == check {
			if f[0] != status {
				t.Errorf("%s is %s, want %s:\n%s", check, f[0], status, out)
			}
			for _, w := range want {
				if !strings.Contains(out, w) {
					t.Errorf("%s: no %q in:\n%s", check, w, out)
				}
			}
			return
		}
	}
	t.Errorf("no %s line in:\n%s", check, out)
}

func setVersion(t *testing.T, v string) {
	old := client.Version
	client.Version = v
	t.Cleanup(func() { client.Version = old })
}

func TestDoctorAllOK(t *testing.T) {
	setVersion(t, "v1.4.0")
	f, ts, pin := newFakeDoctor(t, true)
	home := pairDoctor(t, ts.URL, pin)
	out, ok := runDoctor(t, home, f)
	if !ok || strings.Contains(out, "FAIL") || strings.Contains(out, "warn") || strings.Contains(out, "skip") {
		t.Fatalf("not all ok:\n%s", out)
	}
	checkLine(t, out, "ok", "config", "only you can write it")
	checkLine(t, out, "ok", "certificate", "pinned ("+pin+")")
	checkLine(t, out, "ok", "access", "box: namespaces lab, permission read, expires")
	checkLine(t, out, "ok", "version", "this CLI is v1.4.0, the server is v1.4.0")
	checkLine(t, out, "ok", "clock")
	if n := strings.Count(out, "\n"); n != 7 {
		t.Errorf("%d lines, want 7:\n%s", n, out)
	}
	var err error
	captureStd(t, func() { err = cmdDoctor(nil) })
	if err != nil {
		t.Errorf("cmdDoctor: %v, want exit 0", err)
	}
	captureStd(t, func() { err = cmdDoctor([]string{"--json"}) })
	if err != exitCode(2) {
		t.Errorf("cmdDoctor --json: %v, want exit 2", err)
	}
}

func TestDoctorUnpaired(t *testing.T) {
	home := pairDoctor(t, "", "")
	os.RemoveAll(filepath.Join(home, "keydrop"))
	out, ok := runDoctor(t, home, nil)
	if ok {
		t.Fatal("ok while unpaired")
	}
	checkLine(t, out, "FAIL", "config", "not paired", "keydrop pair --url URL")
	checkLine(t, out, "skip", "token")
	var err error
	captureStd(t, func() { err = cmdDoctor(nil) })
	if err != exitCode(1) {
		t.Errorf("cmdDoctor: %v, want exit 1", err)
	}
}

func TestDoctorServerDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	home := pairDoctor(t, "https://"+addr, "sha256:"+strings.Repeat("0", 64))
	out, ok := runDoctor(t, home, nil)
	if ok {
		t.Fatal("ok with the server down")
	}
	checkLine(t, out, "FAIL", "server", "connection refused")
	checkLine(t, out, "skip", "certificate")
	checkLine(t, out, "skip", "token")
}

// A pin mismatch is reported with both pins, and no request at all
// reaches the server: the handshake stops before HTTP.
func TestDoctorWrongPin(t *testing.T) {
	f, ts, pin := newFakeDoctor(t, true)
	wrong := "sha256:" + strings.Repeat("ab", 32)
	home := pairDoctor(t, ts.URL, wrong)
	out, ok := runDoctor(t, home, f)
	if ok {
		t.Fatal("ok with a wrong pin")
	}
	checkLine(t, out, "FAIL", "certificate", wrong, pin, "rotate-tls", "Ask the admin for the new pin")
	checkLine(t, out, "skip", "token")
	if r := f.requests(); r != "" {
		t.Errorf("requests reached a server whose pin doesn't match: %s", r)
	}
	if strings.Contains(out, "keydrop login") || strings.Contains(out, "--pin "+pin) {
		t.Errorf("doctor offers to trust the presented certificate:\n%s", out)
	}
}

// Without a pin, a certificate that doesn't chain to a trusted CA fails.
func TestDoctorUntrustedCertificate(t *testing.T) {
	f, ts, _ := newFakeDoctor(t, true)
	home := pairDoctor(t, ts.URL, "")
	out, ok := runDoctor(t, home, f)
	if ok {
		t.Fatal("ok with an untrusted certificate")
	}
	checkLine(t, out, "FAIL", "certificate", "not trusted", "--pin sha256:…")
	if r := f.requests(); r != "" {
		t.Errorf("requests reached an untrusted server: %s", r)
	}
}

func TestDoctorRefusedToken(t *testing.T) {
	f, ts, pin := newFakeDoctor(t, true)
	f.whoami = func(w http.ResponseWriter) { http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized) }
	home := pairDoctor(t, ts.URL, pin)
	out, ok := runDoctor(t, home, f)
	if ok {
		t.Fatal("ok with a refused token")
	}
	checkLine(t, out, "FAIL", "token", "refused it (401)", "keydrop pair --url "+ts.URL+" --pin "+pin)
	checkLine(t, out, "skip", "access")

	// Expired within the grace window: the renewal status says so.
	exp := time.Now().Add(-48 * time.Hour)
	f.renew = func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(map[string]any{"name": "box", "state": "pending", "expires_at": exp, "expired": true})
	}
	out, _ = runDoctor(t, home, f)
	checkLine(t, out, "FAIL", "token", "expired on "+exp.UTC().Format("2006-01-02"), "keydrop renew --wait")

	// Renewed but not collected: say so, and don't collect it.
	f.renew = func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(map[string]any{"name": "box", "state": "approved", "expires_at": exp, "expired": true})
	}
	out, _ = runDoctor(t, home, f)
	checkLine(t, out, "warn", "token", "hasn't been collected", "Run `keydrop renew`")

	// Refused from this address: a distinct 403.
	f.whoami = func(w http.ResponseWriter) {
		http.Error(w, `{"error":"token box isn't allowed from 10.0.0.9; if that's expected, the admin can add it under Agents"}`, http.StatusForbidden)
	}
	out, _ = runDoctor(t, home, f)
	checkLine(t, out, "FAIL", "token", "(403)", "allowed sources")
}

func TestDoctorTokenExpiresSoon(t *testing.T) {
	f, ts, pin := newFakeDoctor(t, true)
	f.whoami = goodWhoami(time.Now().Add(5*24*time.Hour-time.Hour), "v1.4.0", "on")
	home := pairDoctor(t, ts.URL, pin)
	out, ok := runDoctor(t, home, f)
	if !ok {
		t.Fatalf("a warning failed:\n%s", out)
	}
	checkLine(t, out, "warn", "token", "expires in 5 days", "Run `keydrop renew`")
	f.renew = func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(map[string]any{"name": "box", "state": "pending", "expired": false})
	}
	out, _ = runDoctor(t, home, f)
	checkLine(t, out, "warn", "token", "renewal request is waiting")
}

// The version line is the notice every command shows, worded by the
// token's self-upgrade setting, and doctor leaves no once-a-day stamp.
func TestDoctorVersionMismatch(t *testing.T) {
	setVersion(t, "v1.3.0")
	f, ts, pin := newFakeDoctor(t, true)
	home := pairDoctor(t, ts.URL, pin)
	out, ok := runDoctor(t, home, f)
	if !ok {
		t.Fatalf("a version warning failed:\n%s", out)
	}
	checkLine(t, out, "warn", "version", "the server is v1.4.0", "run `keydrop upgrade` when convenient")
	f.whoami = goodWhoami(time.Now().Add(90*24*time.Hour), "v1.4.0", "off")
	out, _ = runDoctor(t, home, f)
	checkLine(t, out, "warn", "version", "don't update the CLI yourself")
	if strings.Contains(out, "run `keydrop upgrade`") {
		t.Errorf("self-upgrade is off, but doctor says to upgrade:\n%s", out)
	}
}

func TestDoctorClockSkew(t *testing.T) {
	f, ts, pin := newFakeDoctor(t, true)
	good := f.whoami
	f.whoami = func(w http.ResponseWriter) {
		w.Header().Set("Date", time.Now().Add(-10*time.Minute).UTC().Format(http.TimeFormat))
		good(w)
	}
	home := pairDoctor(t, ts.URL, pin)
	out, ok := runDoctor(t, home, f)
	if !ok {
		t.Fatalf("a clock warning failed:\n%s", out)
	}
	checkLine(t, out, "warn", "clock", "ahead of the server's", "NTP")
}

// Plain http to another machine answers, with the warning pair and login
// give. It needs an address that isn't loopback.
func TestDoctorPlainHTTP(t *testing.T) {
	var ip net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			ip = n.IP
			break
		}
	}
	if ip == nil {
		t.Skip("no non-loopback address")
	}
	f := &fakeDoctor{healthz: "ok\n", whoami: goodWhoami(time.Now().Add(90*24*time.Hour), "v1.4.0", "on")}
	l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Skip(err)
	}
	ts := &httptest.Server{Listener: l, Config: &http.Server{Handler: f}}
	ts.Start()
	defer ts.Close()
	home := pairDoctor(t, ts.URL, "")
	out, ok := runDoctor(t, home, f)
	if !ok {
		t.Fatalf("plain http failed:\n%s", out)
	}
	checkLine(t, out, "warn", "server", "plain http", "use the https:// URL")
	checkLine(t, out, "skip", "certificate", "plain http has no certificate")
}

// Something answers, but not keydrop's /healthz.
func TestDoctorNotKeydrop(t *testing.T) {
	f, ts, _ := newFakeDoctor(t, false)
	f.healthz = "<html>hello</html>"
	home := pairDoctor(t, ts.URL, "")
	out, ok := runDoctor(t, home, f)
	if ok {
		t.Fatalf("ok against something that isn't keydrop:\n%s", out)
	}
	checkLine(t, out, "FAIL", "server", "not like keydrop")
	if strings.Contains(f.requests(), "auth") {
		t.Errorf("the token went to something that isn't keydrop: %s", f.requests())
	}
}

// What to do next starts with a capital, by rune: a message that starts
// with a multi-byte character comes out whole.
func TestDoctorNextCapitalised(t *testing.T) {
	for in, want := range map[string]string{
		"couldn't reach it": "Couldn't reach it",
		"élan vital":        "Élan vital",
		"ünïcode":           "Ünïcode",
		"→ arrow":           "→ arrow",
		"Already":           "Already",
		"\xff bad byte":     "\xff bad byte",
	} {
		var b strings.Builder
		r := &report{w: &b}
		r.line("FAIL", "server", "detail", in)
		if got := b.String(); got != "FAIL  server      detail\n      → "+want+"\n" {
			t.Errorf("%q: %q", in, got)
		}
	}
	if capitalise("") != "" {
		t.Error("empty")
	}
}
