package server

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

var restoreRE = regexp.MustCompile(`action="/secret/lab/K/restore/([0-9a-f]+)"`)

// The secret page lists older values as rows with a Restore button, never
// a value: an old value is seen only by restoring it and pressing Show
// value, which is logged as ever.
func TestOlderValuesPage(t *testing.T) {
	h := newHarness(t)
	h.setup()
	markers := []string{"marker-old-one-4711", "marker-old-two-4712", "marker-old-three-4713", "marker-current-4714"}
	for i, m := range markers {
		if err := h.st.SetValue("lab", "K", []byte(m), i == 1); err != nil {
			t.Fatal(err)
		}
	}
	noMarker := func(what, body string, except ...string) {
		t.Helper()
		for _, m := range markers {
			if strings.Contains(body, m) && !strings.Contains(strings.Join(except, " "), m) {
				t.Fatalf("%s shows %s", what, m)
			}
		}
	}
	_, page := h.get("/secret/lab/K")
	noMarker("the page", page)
	ids := restoreRE.FindAllStringSubmatch(page, -1)
	if len(ids) != 3 || !strings.Contains(page, "Older values") || !strings.Contains(page, "Previous value") ||
		!strings.Contains(page, "Older value 3") || !strings.Contains(page, "saved by admin · variable") {
		t.Fatalf("older values on the page: %d rows\n%s", len(ids), page)
	}
	// Show value shows the current value only.
	resp := h.post("/secret/lab/K/reveal", url.Values{"csrf": {h.csrf()}})
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), markers[3]) {
		t.Fatal("Show value didn't show the current value")
	}
	noMarker("Show value", string(b), markers[3])

	// Restore needs the CSRF token, and the admin's session.
	if resp := h.post("/secret/lab/K/restore/"+ids[1][1], nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("restore without csrf: %d", resp.StatusCode)
	}
	jar, _ := cookiejar.New(nil)
	anon := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := anon.PostForm(h.ts.URL+"/secret/lab/K/restore/"+ids[1][1], url.Values{"csrf": {h.csrf()}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("restore without a session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if v, _, _ := h.st.Reveal("lab", "K", "test"); string(v) != markers[3] {
		t.Fatal("a refused restore changed the value")
	}

	// An ID that isn't there (any more) is a clean error, and changes nothing.
	resp = h.post("/secret/lab/K/restore/0123456789abcdef", url.Values{"csrf": {h.csrf()}})
	b, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(b), "isn&#39;t kept any more") {
		t.Fatalf("unknown id: %d", resp.StatusCode)
	}
	noMarker("the error page", string(b))
	if v, _, _ := h.st.Reveal("lab", "K", "test"); string(v) != markers[3] {
		t.Fatal("an unknown id changed the value")
	}

	// Restoring older value 2 (the variable) works, is logged with which
	// one it was, and still shows no value.
	resp = h.post("/secret/lab/K/restore/"+ids[1][1], url.Values{"csrf": {h.csrf()}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("restore: %d", resp.StatusCode)
	}
	if v, variable, _ := h.st.Reveal("lab", "K", "test"); string(v) != markers[1] || !variable {
		t.Fatalf("restored %q, variable %v", v, variable)
	}
	if !h.auditHas("secret.rollback", "older value 2 of 3, a variable, replaced ") || !h.auditHas("secret.kind", "") {
		t.Fatal("restore not in the log")
	}
	for _, e := range h.srv.audit.Recent(1000) {
		noMarker("the audit log", e.Detail+e.Target)
	}
	_, page = h.get("/secret/lab/K?msg=restored")
	// A variable's value is on its page, as ever; no other value is.
	noMarker("the page after restoring", page, markers[1])
	if !strings.Contains(page, "Restored.") || len(restoreRE.FindAllString(page, -1)) != 3 {
		t.Fatal("page after restoring")
	}
	// The same page, out of date, can't restore the one it shows there now.
	resp = h.post("/secret/lab/K/restore/"+ids[1][1], url.Values{"csrf": {h.csrf()}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("restoring the current value again: %d", resp.StatusCode)
	}
	// The old rollback route restores the newest.
	resp = h.post("/secret/lab/K/rollback", url.Values{"csrf": {h.csrf()}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rollback: %d", resp.StatusCode)
	}
	if v, _, _ := h.st.Reveal("lab", "K", "test"); string(v) != markers[3] {
		t.Fatalf("rolled back to %q", v)
	}
	if !h.auditHas("secret.rollback", "older value 1 of 3, a secret") {
		t.Fatal("rollback not in the log")
	}
}

// Agents see nothing of the history: what the API returns for a key is
// the same, byte for byte, whether it has history or not, for a canary
// too.
func TestAgentAPIIgnoresHistory(t *testing.T) {
	at := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	responses := func(saves []string, canary bool) string {
		h := newHarness(t)
		h.st.SetClock(func() time.Time { return at })
		tok, err := h.st.CreateToken("reader", []string{"lab"}, store.PermRead, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range saves {
			if err := h.st.SetValue("lab", "K", []byte(v), false); err != nil {
				t.Fatal(err)
			}
		}
		if canary {
			if err := h.st.SetCanary("lab", "K", true); err != nil {
				t.Fatal(err)
			}
		}
		var out []string
		for _, c := range []struct{ method, path string }{
			{"GET", "/api/v1/secrets/lab/K"}, {"GET", "/api/v1/secrets"}, {"GET", "/api/v1/secrets?new=1"},
			{"POST", "/api/v1/secrets/lab/K/reveal"}, {"GET", "/api/v1/secrets/lab/K"},
			{"POST", "/api/v1/secrets/lab/K/ack"}, {"GET", "/api/v1/expiring"},
		} {
			code, _, raw := h.api(c.method, c.path, tok, nil)
			out = append(out, c.method+" "+c.path+" "+http.StatusText(code)+" "+string(raw))
		}
		return strings.Join(out, "\n")
	}
	for _, canary := range []bool{false, true} {
		plain := responses([]string{"final-value"}, canary)
		history := responses([]string{"first", "second", "third", "final-value"}, canary)
		if plain != history {
			t.Fatalf("canary %v: the API differs with history:\n%s\n---\n%s", canary, plain, history)
		}
		if !strings.Contains(plain, "final-value") {
			t.Fatal("reveal didn't return the value")
		}
	}
}
