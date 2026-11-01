package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/minituff/keydrop/internal/store"
)

func TestInbox(t *testing.T) {
	h := newHarness(t)
	h.setup()
	tok := h.createToken("bot", "lab")
	h.st.PutValue("lab", "CF", []byte("cf-secret-value"), nil)

	// Empty: it teaches how requests arrive, and the dashboard has no bar.
	_, body := h.get("/inbox")
	if !strings.Contains(body, "keydrop request NAME") || strings.Contains(body, `class="n"`) {
		t.Fatal("empty inbox should explain itself and show no count")
	}
	if _, dash := h.get("/"); strings.Contains(dash, "need you") {
		t.Fatal("attention bar with nothing waiting")
	}

	// A request, a batch, and a flag.
	h.api("POST", "/api/v1/requests", tok, map[string]string{"name": "ONE_KEY"})
	h.api("POST", "/api/v1/requests/batch", tok, map[string]any{"namespace": "lab", "names": []string{"ROUTER_KEY", "ROUTER_SECRET"}, "group": "Router"})
	h.api("POST", "/api/v1/secrets/lab/CF/flag", tok, map[string]string{"reason": "returns 401"})

	_, body = h.get("/inbox")
	for _, want := range []string{`name="value.ONE_KEY"`, `name="value.ROUTER_SECRET"`, `name="paste"`, `name="group" value="yes"`, "Save all", "returns 401", "agent-written", `<span class="n">3</span>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("inbox lacks %s", want)
		}
	}

	// The dashboard counts them but no longer carries the fill forms.
	_, dash := h.get("/")
	if !strings.Contains(dash, "3 things need you") || !strings.Contains(dash, `href="/inbox"`) {
		t.Fatal("dashboard lacks the attention bar")
	}
	for _, not := range []string{`name="value.ONE_KEY"`, `name="paste"`, "returns 401"} {
		if strings.Contains(dash, not) {
			t.Fatalf("dashboard still shows %s", not)
		}
	}
	if strings.Contains(dash, "cf-secret-value") {
		t.Fatal("secret value on the dashboard")
	}

	// A failed fill lands back on the inbox with the error.
	code, body := h.form("/requests/fill", url.Values{"namespace": {"lab"}, "name": {"ROUTER_KEY", "ROUTER_SECRET"}, "paste": {"nonsense"}})
	if code != http.StatusBadRequest || !strings.Contains(body, `name="paste"`) {
		t.Fatalf("failed fill: %d", code)
	}
}

func TestInboxAdminOnly(t *testing.T) {
	h := newHarness(t)
	h.setup()
	tok := h.createToken("bot", "lab")
	for _, p := range []string{"/inbox", "/new"} {
		anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := anon.Get(h.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("%s anonymous: %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
		req, _ := http.NewRequest("GET", h.ts.URL+p, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err = anon.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("%s reachable with an agent token", p)
		}
	}
}

func TestNewPageAndSearch(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "ALPHA_KEY", []byte("v1"), &store.Meta{Description: "first"})
	h.st.PutValue("lab", "BETA_KEY", []byte("v2"), nil)
	_, body := h.get("/new")
	if !strings.Contains(body, `action="/secrets"`) || !strings.Contains(body, `name="value"`) {
		t.Fatal("new page lacks the form")
	}
	_, dash := h.get("/")
	if strings.Contains(dash, `action="/secrets"`) {
		t.Fatal("add form still on the dashboard")
	}
	_, found := h.get("/?q=alpha")
	if !strings.Contains(found, "ALPHA_KEY") || strings.Contains(found, "BETA_KEY") {
		t.Fatal("search did not filter")
	}
	if _, none := h.get("/?q=zzz"); !strings.Contains(none, "Nothing matches") {
		t.Fatal("no empty search state")
	}
	if _, empty := (func() (int, string) { h2 := newHarness(t); h2.setup(); return h2.get("/") })(); !strings.Contains(empty, "No secrets yet") {
		t.Fatal("no empty state")
	}
}

// Pages link to the stylesheet by content version, so an upgrade reaches
// browsers that cached the old one; only that exact URL is cached for long.
func TestStylesheetVersioned(t *testing.T) {
	h := newHarness(t)
	h.setup()
	_, body := h.get("/")
	link := `href="/static/style.css?v=` + cssVersion + `"`
	if len(cssVersion) != 12 || !strings.Contains(body, link) {
		t.Fatalf("page lacks %s", link)
	}
	for v, want := range map[string]string{cssVersion: "immutable", "old": "no-cache", "": "no-cache"} {
		resp, err := h.web.Get(h.ts.URL + "/static/style.css?v=" + v)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, want) || resp.StatusCode != http.StatusOK {
			t.Fatalf("v=%q: %d %q, want %s", v, resp.StatusCode, cc, want)
		}
	}
}
