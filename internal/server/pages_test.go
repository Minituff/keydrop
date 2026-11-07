package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/audit"
)

// The Agents page is a list; each agent's settings are on its own page,
// and adding one has its own page too.
func TestAgentPages(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.createToken("bot", "lab")

	_, list := h.get("/tokens")
	if !strings.Contains(list, `href="/token/bot"`) || !strings.Contains(list, `href="/tokens/new"`) ||
		strings.Contains(list, `action="/tokens/bot/`) || strings.Contains(list, `action="/tokens"`) {
		t.Fatal("Agents list: want links only, no forms")
	}
	code, one := h.get("/token/bot")
	for _, s := range []string{"namespaces", "permission", "sources", "renew", "revoke"} {
		if !strings.Contains(one, `action="/tokens/bot/`+s+`"`) {
			t.Fatalf("agent page: no %s form (%d)", s, code)
		}
	}
	if !strings.Contains(one, `aria-current="page">`) || !strings.Contains(one, `href="/tokens"`) {
		t.Fatal("agent page: not under Agents")
	}
	if code, _ := h.get("/token/nobody"); code != http.StatusNotFound {
		t.Fatalf("unknown agent: %d", code)
	}
	if _, add := h.get("/tokens/new"); !strings.Contains(add, `action="/tokens"`) || !strings.Contains(add, `href="/tokens/setup"`) {
		t.Fatal("Add an agent page: no form or setup link")
	}

	// Saving goes back to the agent's page; an error shows there too.
	if code, body := h.form("/tokens/bot/permission", url.Values{"permission": {"add"}}); code != http.StatusSeeOther || !strings.Contains(body, "Permission saved") || !strings.Contains(body, `action="/tokens/bot/revoke"`) {
		t.Fatalf("save: %d", code)
	}
	if code, body := h.form("/tokens/bot/sources", url.Values{"sources": {"not an address"}}); code != http.StatusBadRequest || !strings.Contains(body, "Allowed from:") || !strings.Contains(body, `action="/tokens/bot/revoke"`) {
		t.Fatalf("bad sources: %d", code)
	}
	// A bad new token shows its error on the Add an agent page.
	if code, body := h.form("/tokens", url.Values{"name": {"bot"}, "namespaces": {"lab"}}); code != http.StatusBadRequest || !strings.Contains(body, "already exists") || !strings.Contains(body, `<h1>Add an agent</h1>`) {
		t.Fatalf("duplicate: %d", code)
	}
}

// The Groups pill in the phone's top bar is only on the pages it's about.
func TestGroupsPill(t *testing.T) {
	h := newHarness(t)
	h.setup()
	for path, want := range map[string]bool{"/": true, "/groups": true, "/tokens": false, "/audit": false, "/settings": false, "/inbox": false} {
		if _, body := h.get(path); strings.Contains(body, `class="pill"`) != want {
			t.Errorf("%s: pill %v, want %v", path, !want, want)
		}
	}
}

func TestAuditFilters(t *testing.T) {
	h := newHarness(t)
	h.setup()
	base := time.Now().Add(-time.Hour)
	for i := range 120 {
		e := audit.Event{Time: base.Add(time.Duration(i) * time.Second), Actor: "token:bot", Action: "secret.read", Target: fmt.Sprintf("lab/K%03d", i)}
		if i%2 == 1 {
			e.Actor, e.Action = "admin", "token.create"
		}
		h.srv.audit.Add(e)
	}
	h.srv.audit.Add(audit.Event{Time: base.Add(-time.Minute), Actor: "?", Action: "auth.fail", IP: "10.9.9.9", Unauthenticated: true})

	row := func(body, target string) bool { return strings.Contains(body, "<td>"+target+"</td>") }
	_, body := h.get("/audit")
	if !row(body, "lab/K119") || row(body, "lab/K069") || !strings.Contains(body, `href="/audit?page=2"`) || strings.Contains(body, "← Previous") {
		t.Fatal("first page: newest 50, link to the next")
	}
	if _, body = h.get("/audit?page=2"); !row(body, "lab/K069") || !strings.Contains(body, `href="/audit?page=1"`) {
		t.Fatal("page 2")
	}
	if _, body = h.get("/audit?page=99"); !row(body, "10.9.9.9") {
		t.Fatal("past the end: last page")
	}
	// Oldest first.
	if _, body = h.get("/audit?sort=old"); strings.Index(body, "10.9.9.9") > strings.Index(body, "lab/K000") || !strings.Contains(body, `href="/audit?page=2&amp;sort=old"`) {
		t.Fatal("oldest first")
	}
	// Who, what and text, together; the pager keeps them.
	if _, body = h.get("/audit?who=token%3Abot&what=secret&q=k01"); !row(body, "lab/K010") || row(body, "lab/K011") || row(body, "lab/K020") || !strings.Contains(body, "5 of ") {
		t.Fatal("filters")
	}
	if _, body = h.get("/audit?who=-"); !row(body, "10.9.9.9") || row(body, "lab/K000") {
		t.Fatal("no credential")
	}
	if _, body = h.get("/audit?q=nothing-like-this"); !strings.Contains(body, "Nothing matches.") {
		t.Fatal("no match")
	}
	if _, body = h.get("/audit?what=secret"); !strings.Contains(body, `href="/audit?page=2&amp;what=secret"`) || !strings.Contains(body, `<option value="secret" selected>`) {
		t.Fatal("pager or form lost the filter")
	}
}

// Appearance: System by default; Light or Dark is a cookie for this
// browser, and every page (the login page too) carries it.
func TestTheme(t *testing.T) {
	h := newHarness(t)
	h.setup()
	_, body := h.get("/settings")
	if strings.Contains(body, "data-theme") || !strings.Contains(body, `content="light dark"`) || !strings.Contains(body, `value="system" class="on small" aria-pressed="true"`) {
		t.Fatal("default: want system")
	}
	if code, body := h.form("/settings/theme", url.Values{"theme": {"dark"}}); code != http.StatusSeeOther || !strings.Contains(body, `<html lang="en" data-theme="dark">`) ||
		!strings.Contains(body, `<meta name="color-scheme" content="dark">`) || !strings.Contains(body, `value="dark" class="on small"`) || !strings.Contains(body, "Appearance saved") {
		t.Fatalf("dark: %d", code)
	}
	if _, body = h.get("/login"); !strings.Contains(body, `data-theme="dark"`) {
		t.Fatal("login page ignores the theme")
	}
	if code, _ := h.form("/settings/theme", url.Values{"theme": {"neon"}}); code != http.StatusBadRequest {
		t.Fatalf("bad theme: %d", code)
	}
	if resp := h.post("/settings/theme", url.Values{"theme": {"light"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no csrf: %d", resp.StatusCode)
	}
	if _, body = h.form("/settings/theme", url.Values{"theme": {"system"}}); strings.Contains(body, "data-theme") {
		t.Fatal("system: cookie not cleared")
	}
}
