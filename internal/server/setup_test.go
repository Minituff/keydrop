package server

import (
	"flag"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the generated section of docs/agent-setup.md")

const (
	docBegin = "<!-- BEGIN agent setup: generated from internal/server/web/agent-setup.md.tmpl; edit that file, then run go test ./internal/server -run TestAgentSetupDoc -update -->\n"
	docEnd   = "<!-- END agent setup -->\n"
)

// docs/agent-setup.md carries the generic rendering of the setup guide, so the
// docs can't drift from what servers hand out.
func TestAgentSetupDoc(t *testing.T) {
	want, err := genericGuide.render()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "agent-setup.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i, j := strings.Index(doc, docBegin), strings.Index(doc, docEnd)
	if i < 0 || j < i {
		t.Fatalf("%s has no generated section between\n%s%s", path, docBegin, docEnd)
	}
	start := i + len(docBegin)
	if doc[start:j] == want {
		return
	}
	if *update {
		if err := os.WriteFile(path, []byte(doc[:start]+want+doc[j:]), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("docs/agent-setup.md doesn't match web/agent-setup.md.tmpl; run: go test ./internal/server -run TestAgentSetupDoc -update")
}

func TestSetupGuideRender(t *testing.T) {
	g, err := genericGuide.render()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"## Set up keydrop", "### 1. Pick a server", "### 2. Install the server", "STOP: the person saves the master key",
		"curl -fsSk --pinnedpubkey '<key-pin>' <server-url>/install.sh | sh", "keydrop pair --url <server-url> --pin <cert-pin>",
		"keydrop whoami", "keydrop history --since 72h --quiet"} {
		if !strings.Contains(g, s) {
			t.Errorf("generic guide lacks %q", s)
		}
	}
	// A server's copy skips installing a server and starts at the CLI.
	s, err := setupGuide{URL: "https://192.168.1.50:8443", CertPin: "sha256:" + strings.Repeat("ab", 32), KeyPin: "sha256//KEY=", CLI: true}.render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Set up keydrop", "## 1. Install the CLI", "curl -fsSk --pinnedpubkey 'sha256//KEY=' https://192.168.1.50:8443/install.sh | sh",
		"keydrop pair --url https://192.168.1.50:8443 --pin sha256:abab", "## 5. Remember it"} {
		if !strings.Contains(s, want) {
			t.Errorf("server guide lacks %q:\n%s", want, s)
		}
	}
	for _, bad := range []string{"<server-url>", "<cert-pin>", "<key-pin>", "Pick a server", "genkey"} {
		if strings.Contains(s, bad) {
			t.Errorf("server guide contains %q", bad)
		}
	}
	// A real certificate: nothing pinned, nothing skipped.
	s, _ = setupGuide{URL: "https://secrets.example.com", CLI: true}.render()
	if strings.Contains(s, "curl -fsSk") || strings.Contains(s, "--pinnedpubkey '") || strings.Contains(s, " --pin <") || strings.Contains(s, " --pin sha") || !strings.Contains(s, "curl -fsS https://secrets.example.com/install.sh | sh") ||
		!strings.Contains(s, "nothing to pin") {
		t.Errorf("real-certificate guide:\n%s", s)
	}
	// No CLI builds: no install.sh command that would 404.
	s, _ = setupGuide{URL: "https://secrets.example.com"}.render()
	if strings.Contains(s, "install.sh") || !strings.Contains(s, "doesn't hand out the CLI") {
		t.Errorf("guide without CLI builds:\n%s", s)
	}
}

func TestSetupGuideServed(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.CertPin, h.srv.cfg.KeyPin = "sha256:"+strings.Repeat("cd", 32), "sha256//KEYPIN="

	// Plain http straight to keydrop: refused, the pins could be swapped.
	code, _, body := fetch(t, http.DefaultClient, h.ts.URL+"/setup.md")
	if code != http.StatusBadRequest || strings.Contains(body, "pin") && strings.Contains(body, "sha256") {
		t.Fatalf("setup.md over http: %d\n%s", code, body)
	}
	// A Host header that isn't a plain host[:port] is refused.
	r := httptest.NewRequest("GET", "/setup.md", nil)
	r.Host = "x`$(id)`"
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad Host: %d", w.Code)
	}

	// Over keydrop's own TLS: its address and both pins, no auth needed,
	// and nothing secret even while setup is open.
	ts := httptest.NewTLSServer(h.srv)
	defer ts.Close()
	code, hdr, body := fetch(t, ts.Client(), ts.URL+"/setup.md")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/markdown") {
		t.Fatalf("setup.md over TLS: %d %s", code, hdr.Get("Content-Type"))
	}
	for _, want := range []string{"Address: `" + ts.URL + "`", "keydrop pair --url " + ts.URL + " --pin " + h.srv.cfg.CertPin, "`sha256//KEYPIN=`"} {
		if !strings.Contains(body, want) {
			t.Errorf("setup.md lacks %q:\n%s", want, body)
		}
	}
	if code := h.srv.setupCode; code == "" || strings.Contains(body, code) || strings.Contains(body, displayCode(code)) {
		t.Fatal("setup.md holds the setup code (or setup isn't open)")
	}
	if strings.Contains(body, "install.sh") {
		t.Error("setup.md offers install.sh on a server without CLI builds")
	}

	// A token made since doesn't show up either.
	h.setup()
	tok := h.createToken("agent", "ns")
	_, _, body = fetch(t, ts.Client(), ts.URL+"/setup.md")
	if strings.Contains(body, tok) || strings.Contains(body, "kd_") {
		t.Fatal("setup.md holds a token")
	}

	// Through a trusted proxy: only with an https public URL, and then the
	// proxy's normal certificate checks, no pins.
	h.srv.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	h.srv.cfg.PublicURL = "http://secrets.example.com"
	if code, _, _ := fetch(t, http.DefaultClient, h.ts.URL+"/setup.md", "X-Forwarded-For", "10.0.0.5", "X-Forwarded-Proto", "https"); code != http.StatusBadRequest {
		t.Fatalf("setup.md via an http proxy URL: %d", code)
	}
	h.srv.cfg.PublicURL = "https://secrets.example.com"
	// The proxy must report https; without it this is a plain-http fetch.
	for _, hdr := range [][]string{{"X-Forwarded-For", "10.0.0.5"}, {"X-Forwarded-For", "10.0.0.5", "X-Forwarded-Proto", "http"}} {
		if code, _, b := fetch(t, http.DefaultClient, h.ts.URL+"/setup.md", hdr...); code != http.StatusBadRequest || strings.Contains(b, "secrets.example.com") {
			t.Fatalf("setup.md via proxy without https %v: %d\n%s", hdr, code, b)
		}
	}
	_, _, body = fetch(t, http.DefaultClient, h.ts.URL+"/setup.md", "X-Forwarded-For", "10.0.0.5", "X-Forwarded-Proto", "https")
	if !strings.Contains(body, "keydrop pair --url https://secrets.example.com\n") || strings.Contains(body, "sha256") || !strings.Contains(body, "nothing to pin") {
		t.Fatalf("setup.md via proxy:\n%s", body)
	}
}

var tokenRE = regexp.MustCompile(`kd_[A-Za-z0-9_-]+`)

// createToken makes a token through the Agents form and returns it.
func (h *harness) createToken(name, ns string) string {
	h.t.Helper()
	resp := h.post("/tokens", url.Values{"csrf": {h.csrf()}, "name": {name}, "namespaces": {ns}})
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	tok := tokenRE.FindString(string(b))
	if resp.StatusCode != http.StatusOK || tok == "" {
		h.t.Fatalf("create token: %d", resp.StatusCode)
	}
	return tok
}

func TestAgentSetupPage(t *testing.T) {
	h := newHarness(t)
	// Admin only: no session, no page.
	if code, _ := h.get("/tokens/setup"); code != http.StatusSeeOther {
		t.Fatalf("without a session: %d, want a redirect", code)
	}
	h.setup()
	// Nothing an agent could check: say what to configure.
	if code, body := h.get("/tokens/setup"); code != http.StatusOK || !strings.Contains(body, "no setup prompt") {
		t.Fatalf("unconfigured: %d\n%s", code, body)
	}

	// Self-signed: the pinned short version and the whole prompt, escaped.
	h.srv.cfg.CertPin, h.srv.cfg.KeyPin = "sha256:"+strings.Repeat("ef", 32), "sha256//KEY+PIN="
	h.srv.cfg.DirectURL = "https://192.168.1.50:8443/<b>"
	code, body := h.get("/tokens/setup") // a GET: no CSRF token needed
	if code != http.StatusOK {
		t.Fatalf("page: %d", code)
	}
	if strings.Contains(body, "<b>") || !strings.Contains(body, "&lt;b&gt;") {
		t.Fatalf("not escaped:\n%s", body)
	}
	h.srv.cfg.DirectURL = "https://192.168.1.50:8443"
	_, body = h.get("/tokens/setup")
	short := "Run `curl -fsSk --pinnedpubkey &#39;sha256//KEY&#43;PIN=&#39; https://192.168.1.50:8443/setup.md` and follow it to set up keydrop."
	for _, want := range []string{short, "keydrop pair --url https://192.168.1.50:8443 --pin " + h.srv.cfg.CertPin, `<pre class="prompt">`,
		"safe to share", "pairing"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<script") {
		t.Error("script on the page")
	}
	// The page shows exactly what the server hands the agent.
	g, _ := setupGuide{URL: "https://192.168.1.50:8443", CertPin: h.srv.cfg.CertPin, KeyPin: h.srv.cfg.KeyPin}.render()
	if i, j := strings.Index(body, `<pre class="prompt">`), strings.LastIndex(body, "</pre>"); i < 0 || j < i ||
		html.UnescapeString(body[i+len(`<pre class="prompt">`):j]) != g {
		t.Errorf("the page's prompt differs from the served one")
	}

	// Linked from the Agents page, and from the dashboard while there are
	// no agents.
	if _, body := h.get("/tokens/new"); !strings.Contains(body, `href="/tokens/setup"`) {
		t.Error("Agents page doesn't link to the setup page")
	}
	if _, body := h.get("/"); !strings.Contains(body, `href="/tokens/setup"`) {
		t.Error("dashboard doesn't link to the setup page")
	}

	// A real certificate behind a proxy: the public short version, no pins.
	h.srv.cfg.CertPin, h.srv.cfg.KeyPin, h.srv.cfg.DirectURL = "", "", ""
	h.srv.cfg.PublicURL = "https://secrets.example.com"
	_, body = h.get("/tokens/setup")
	if !strings.Contains(body, "Run `curl -fsS https://secrets.example.com/setup.md` and follow it") || strings.Contains(body, "--pinnedpubkey &#39;") ||
		!strings.Contains(body, "nothing to pin") {
		t.Errorf("real certificate:\n%s", body)
	}
}

// The setup code is for the person alone: the guide must never have the
// agent read the log unfiltered or pass the code on.
func TestSetupGuideKeepsCodeFromAgent(t *testing.T) {
	for _, g := range []setupGuide{{Generic: true}, {URL: "https://192.168.1.50:8443", CLI: true}} {
		s, err := g.render()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "docker logs keydrop") && !strings.Contains(line, "grep") && !strings.HasPrefix(line, "Don't") {
				t.Errorf("guide has a plain docker logs line: %q", line)
			}
		}
		if g.Generic && (!strings.Contains(s, "the setup code") || !strings.Contains(s, "test") && !strings.Contains(s, "-e master.key")) {
			t.Error("generic guide lacks the setup-code rule or the master.key guard")
		}
	}
}
